//! The standalone construction driver: one value built in place from the
//! root of a document it borrows for its whole life, through the engine's
//! root session, and reclaimed through it. What a caller outside the crate
//! constructs with when no scope record holds the value: it never supplies
//! a document and a slot apart, never names a node, and never calls a
//! binding's own methods.
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::ptr::NonNull;

use super::Context;
use super::in_place::{self, Built, InPlace, Session, SessionObservation, Stage};
use super::reclamation::{Custody, Place, Reclaimed, Slot};
use super::stable::Pending;
use crate::bounded::decode::{ConstructResult, DecodeError, Document};
use crate::bounded::{
    Allocator, BoundedError, BoundedResult, Custodial, CustodySink, Failure, Performer,
    PermitsObserved, Resumable, Step, WriteWork, observed_all, total_held,
};

/// A value of `T` built in a destination the driver borrows for its whole
/// life, from the root of `document`, one engine unit per call, with its
/// session held here. The document is borrowed for the driver's whole life,
/// so every step reads the same document; the root is its node 0, so every
/// step binds the same node; and the session refuses a build after its
/// completion or once cleanup began. The destination's place is minted once,
/// at [`Self::new`], and every step's slot is that place with the session,
/// so a place a binding keeps within the value stays valid across steps.
///
/// The driver keeps the value's construction's pending acquisition credit
/// ([`Pending`]) beside the session, outside the value, and supplies it to
/// every step's root context. Its owner is made by the first acquisition
/// entry, under whatever budget performs it ([`Pending::deferred`]), and
/// every later entry is validated against it. Cleanup's first step, and
/// dropping the driver, settle that credit explicitly by origin
/// ([`Pending::settle_all`]). Dropping the driver runs no other cleanup:
/// whatever the value holds is reclaimed only by [`Self::reclaim_step`] to
/// `Done`.
pub struct Standalone<'d, 'a, 'v, T: InPlace<A>, A: Allocator> {
    document: &'d Document<'a, A::Permit>,
    place: Place<T>,
    session: Session<T::State>,
    pending: Pending<A::Origin>,
    execution: Execution,
    /// The destination, borrowed exclusively for the driver's life.
    destination: PhantomData<&'v mut MaybeUninit<T>>,
}

enum Execution {
    Building,
    Failed,
    Finished,
}

impl<'d, 'a, 'v, T: InPlace<A>, A: Allocator> Standalone<'d, 'a, 'v, T, A> {
    /// A driver of nothing built: `value` is treated as uninitialized
    /// whatever it holds, the session starts unbound, and no credit is
    /// pending.
    /// A root declaring a dispatch depth past the limit fails to compile here
    /// (E0080), as a scope record's allocation does
    /// ([`super::reclamation::admitted_depth`]).
    pub fn new(document: &'d Document<'a, A::Permit>, value: &'v mut MaybeUninit<T>) -> Self {
        const { super::reclamation::admitted_depth::<T, A>() };
        Self {
            document,
            // SAFETY: the destination is borrowed exclusively for `'v`, the
            // driver's life, and reached only through this place.
            place: unsafe { Place::root(NonNull::from(value)) },
            session: Session::new(T::INITIAL),
            pending: Pending::deferred(),
            execution: Execution::Building,
            destination: PhantomData,
        }
    }

    /// The value's slot with its session: the one pairing of the two.
    fn slot(&mut self) -> Slot<'_, T, Session<T::State>> {
        // SAFETY: the place is the destination's root, minted once from its
        // exclusive borrow; the session, created with the binding's initial
        // state over a destination treated as uninitialized, is its own, and
        // every access to either is through this slot.
        unsafe { Slot::new(self.place, &mut self.session) }
    }

    /// The root context of one step: the document, the value's slot and the
    /// driver's pending credit, each borrowed for the step alone, branded
    /// for that borrow.
    fn root(&mut self) -> Context<'_, 'd, '_, 'a, T, Session<T::State>, A> {
        // SAFETY: as [`Self::slot`]; the session and the pending credit are
        // disjoint fields of the driver.
        let slot = unsafe { Slot::new(self.place, &mut self.session) };
        Context::root(self.document, slot, &mut self.pending)
    }

    /// One unit of construction of the value as a standalone value from
    /// the document's root ([`in_place::build`]).
    pub fn build_step(&mut self, a: &mut A) -> ConstructResult<Built, A> {
        in_place::build::<T, A>(self.root(), a)
    }

    /// One unit of construction of the value as a present map field from
    /// the document's root ([`in_place::build_present`]).
    pub fn build_present_step(&mut self, a: &mut A) -> ConstructResult<Built, A> {
        in_place::build_present::<T, A>(self.root(), a)
    }

    /// One unit of construction of the value as a map field omitted from
    /// the document's root ([`in_place::build_absent`]).
    pub fn build_absent_step(&mut self, a: &mut A) -> ConstructResult<Built, A> {
        in_place::build_absent::<T, A>(self.root(), a)
    }

    /// One unit of cleanup ([`in_place::reclaim`]), under the cleanup
    /// capability minted here over `a` ([`super::reclamation::Cleanup`],
    /// through [`super::reclamation::with_cleanup`]), the driver's cleanup
    /// dispatch. The pending credit is settled first, by origin, under this
    /// step's performer: the first cleanup step is cleanup's entry and
    /// settles it; every later one, and a retry of a refused one, finds it
    /// idle and settles nothing.
    pub fn reclaim_step(&mut self, a: &mut A) -> BoundedResult<Reclaimed, A> {
        self.pending.settle_all(a.performer());
        let slot = self.slot();
        super::reclamation::with_cleanup(a, |cleanup| in_place::reclaim::<T, A>(slot, cleanup))
    }

    /// The most [`Self::reclaim_step`] calls still to take
    /// ([`in_place::remaining`]); `None` when the count does not fit in
    /// `u64`. Admits nothing and changes nothing.
    pub fn remaining(&mut self) -> Option<u64> {
        in_place::remaining::<T, A>(self.slot().into_observe())
    }

    /// The session's custody observation: its stage and the binding's own.
    pub fn observe(&mut self) -> SessionObservation<<T::State as Custody>::Observation> {
        self.session.observe()
    }

    /// The credit the value's construction holds: work admitted prepaid and
    /// not yet spent or forfeited ([`Custodial::observe_custody`], summed).
    /// `None` when it does not fit in `u64`, or when the observation is not
    /// whole.
    pub fn held_credit(&mut self) -> Option<WriteWork> {
        total_held(|sink| self.observe_custody(sink))
    }

    /// The session's stage.
    pub fn stage(&self) -> Stage {
        self.session.stage()
    }

    /// The value, once construction completed and until cleanup begins.
    pub fn value(&self) -> Option<&T> {
        if !matches!(self.session.stage(), Stage::Built { .. }) {
            return None;
        }
        // SAFETY: a `Built` session's binding reported the destination
        // fully initialized, and no cleanup unit has run since; the session
        // is the place's custody, borrowed shared for the returned borrow.
        Some(unsafe { self.place.get(&self.session) })
    }
}

/// Construction through the shared retained-operation interface. Completion
/// keeps the destination in this driver's custody: callers read it through
/// [`Standalone::value`] and reclaim it through [`Standalone::reclaim_step`].
impl<T: InPlace<A>, A: Allocator> Resumable<A> for Standalone<'_, '_, '_, T, A> {
    type Output = ();
    type Error = DecodeError<A::Refusal>;
    type Position = SessionObservation<<T::State as Custody>::Observation>;

    fn step(&mut self, a: &mut A) -> ConstructResult<Step<()>, A> {
        if matches!(self.execution, Execution::Finished)
            || matches!(self.stage(), Stage::Built { .. } | Stage::Released)
        {
            self.execution = Execution::Finished;
            return Ok(Step::Finished);
        }
        if matches!(self.execution, Execution::Failed) || self.stage() == Stage::Cleaning {
            return match self.reclaim_step(a).map_err(DecodeError::Resource)? {
                Reclaimed::Progress => Ok(Step::Progress),
                Reclaimed::Done => {
                    self.execution = Execution::Finished;
                    Ok(Step::Finished)
                }
                Reclaimed::Waiting => Err(DecodeError::Resource(BoundedError::PlanMismatch)),
            };
        }
        match self.build_step(a) {
            Ok(Built::Progress) => Ok(Step::Progress),
            Ok(Built::Done) => {
                self.execution = Execution::Finished;
                Ok(Step::Complete(()))
            }
            Err(error) => {
                if !error.refused() {
                    self.execution = Execution::Failed;
                }
                Err(error)
            }
        }
    }

    fn position(&mut self) -> Self::Position {
        self.observe()
    }
}

/// The value's construction's custody, one group under the owner its pending
/// stores (`None` before its first acquisition entry made it, when it holds
/// nothing), every acquisition of the value bound under it: the pending's
/// bound acquisition and held obligations, as its own group, the one report
/// of whether an acquisition is bound ([`Pending::observe_custody`]), and the
/// value's permits ([`in_place::observe_permits`], whose independently
/// owning parts nest their own groups). The session's state holds no
/// obligation. Read-only; the completeness of every part, combined.
impl<T: InPlace<A>, A: Allocator> Custodial<A::Permit> for Standalone<'_, '_, '_, T, A> {
    fn observe_custody(&mut self, sink: &mut dyn CustodySink<A::Permit>) -> PermitsObserved {
        sink.begin(self.pending.owner_id());
        let held = self.pending.observe_custody(sink);
        let owned = in_place::observe_permits::<T, A>(self.slot().into_observe(), sink);
        sink.end();
        observed_all([held, owned])
    }
}

/// Dropped: the pending credit settled explicitly, each obligation
/// forfeited by origin with no performing policy, never left to the
/// retained obligations' own drop backstop; the owner then released with the
/// pending. Nothing else is reclaimed.
impl<T: InPlace<A>, A: Allocator> Drop for Standalone<'_, '_, '_, T, A> {
    fn drop(&mut self) {
        self.pending.settle_all(Performer::None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounded::{LimitRefusal, Limits};

    #[test]
    fn resumable_terminal_error_enters_cleanup_and_finishes() {
        let mut policy = Limits::unlimited();
        let document = crate::bounded::decode::decode(&[0xf6], 1, &mut policy).unwrap();
        let mut destination = MaybeUninit::<bool>::uninit();
        let mut driver = Standalone::new(&document, &mut destination);
        assert!(matches!(driver.step(&mut policy), Ok(Step::Progress)));
        assert!(matches!(
            driver.step(&mut policy),
            Err(DecodeError::Invalid(_))
        ));
        policy.refuse_next();
        let position = driver.observe();
        assert!(matches!(
            driver.step(&mut policy),
            Err(DecodeError::Resource(BoundedError::Refused(
                LimitRefusal::Scheduled(_)
            )))
        ));
        assert_eq!(driver.observe(), position);
        policy.clear_refusal();
        assert!(matches!(driver.step(&mut policy), Ok(Step::Progress)));
        assert_eq!(driver.stage(), Stage::Cleaning);
        assert!(matches!(driver.step(&mut policy), Ok(Step::Finished)));
        assert_eq!(driver.stage(), Stage::Released);
        let attempts = policy.attempts();
        assert!(matches!(driver.step(&mut policy), Ok(Step::Finished)));
        assert_eq!(policy.attempts(), attempts);
    }

    #[test]
    fn resumable_completion_keeps_the_destination_until_explicit_cleanup() {
        let mut policy = Limits::unlimited();
        let document = crate::bounded::decode::decode(&[0xf5], 1, &mut policy).unwrap();
        let mut destination = MaybeUninit::<bool>::uninit();
        let mut driver = Standalone::new(&document, &mut destination);
        assert!(matches!(driver.step(&mut policy), Ok(Step::Progress)));
        assert!(matches!(driver.step(&mut policy), Ok(Step::Complete(()))));
        assert_eq!(driver.value(), Some(&true));
        let attempts = policy.attempts();
        assert!(matches!(driver.step(&mut policy), Ok(Step::Finished)));
        assert_eq!(policy.attempts(), attempts);
        assert_eq!(driver.reclaim_step(&mut policy), Ok(Reclaimed::Progress));
        assert!(matches!(driver.step(&mut policy), Ok(Step::Finished)));
        assert_eq!(driver.stage(), Stage::Cleaning);
        assert_eq!(driver.reclaim_step(&mut policy), Ok(Reclaimed::Done));
        assert_eq!(driver.stage(), Stage::Released);
    }
}
