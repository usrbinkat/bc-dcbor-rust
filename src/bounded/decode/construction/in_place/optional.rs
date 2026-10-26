//! Native Option projections through a valid, resource-free placeholder.
extern crate alloc;
use super::*;
use crate::bounded::decode::construction::reclamation::{Admitted, Custody, Reduction};
use crate::bounded::decode::construction::stable::{self, Installed};
use alloc::{string::String, vec::Vec};
use core::mem::MaybeUninit;
use core::ptr::{self, NonNull};

/// A resource-free placeholder whose construction and move fit one quantum.
///
/// # Safety
/// The value must own no resources and require no destructor. Returning it must
/// take bounded work independent of child count. In-place initialization may
/// overwrite this placeholder without running Drop. This is deliberately not a
/// blanket Default implementation: arbitrary defaults do not meet this contract.
pub unsafe trait Placeholder: Sized {
    fn placeholder() -> Self;
}

macro_rules! scalars {
    ($($ty:ty),*) => {$(
        // SAFETY: a scalar zero has no owned resources and constant-size storage.
        unsafe impl Placeholder for $ty { fn placeholder() -> Self { 0 } }
    )*};
}
scalars!(u8, u16, u32, u64, usize, i8, i16, i32, i64);
// SAFETY: empty String and Vec own no allocations; their headers have fixed size.
unsafe impl Placeholder for String {
    fn placeholder() -> Self {
        String::new()
    }
}
unsafe impl<T> Placeholder for Vec<T> {
    fn placeholder() -> Self {
        Vec::new()
    }
}

/// Where a native option's construction or cleanup is: nothing written;
/// `Some` written with its placeholder and the payload under construction;
/// the payload complete; `None` written; then, reclaimed, the metadata's
/// release next.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    Empty,
    Child,
    Complete,
    Absent,
    Release,
}
struct Meta<S, T> {
    child: S,
    place: *mut MaybeUninit<T>,
    phase: Phase,
}

/// The construction state of a native `Option` of payload `T`, whose state
/// is `S`, with permits of `P`: whether it was entered as a present map field
/// (`build_present`), so null is not absence; what its metadata's
/// acquisition has admitted; and its metadata once acquired. Only the
/// option's own construction reads or changes it.
pub struct OptionalState<S, T, P> {
    present: bool,
    admitted: stable::Admitted,
    meta: Option<Installed<Meta<S, T>, P>>,
}

// SAFETY: the metadata's `place` is a projection into the option's own
// destination, which moves with this state in the same record; the state is
// `Send` exactly when the child state, the payload and the permit are.
unsafe impl<S: Send, T: Send, P: Send> Send for OptionalState<S, T, P> {}
// SAFETY: the state has no `&self` method: its observation takes the
// state's exclusive custody (`Custody::observe` takes `&mut self`), so
// shared access reaches no flag, metadata, child state, payload or permit.
unsafe impl<S, T, P> Sync for OptionalState<S, T, P> {}

/// What a native option's construction holds: whether it was entered as a
/// present map field; then no metadata block, with the admissions held
/// toward it, or the block, at a phase, holding the payload's construction
/// state, whose whole observation it carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum OptionalObservation<S> {
    Unallocated {
        present: bool,
        admitted: Admitted,
    },
    Held {
        present: bool,
        phase: Phase,
        child: S,
    },
}

/// The cleanup classes of a native option ([`Reduction`]), `C` its
/// payload's class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum OptionalClass<C> {
    /// No metadata: one unit completes cleanup.
    Unallocated,
    /// Nothing written, or `None` written: one unit reaches `Release`.
    Idle,
    /// `Some` written, its payload of class `C` under construction or
    /// complete: the payload's cleanup units, then `Release`.
    Live(C),
    /// The payload reclaimed: the metadata's release completes cleanup.
    Release,
}

// Cleanup reads the metadata's presence and the phase, grouped as above, and
// steps the payload in `Child` and `Complete` alike; whether the option was
// entered as a present field and what its acquisition admitted never change
// a cleanup unit. The payload's own relation is a simulation of its
// cleanup, and the option leaves `Live` exactly when the payload's cleanup
// reports done, so the relation is a simulation of cleanup.
impl<S: Reduction, T, P> Reduction for OptionalState<S, T, P> {
    type Class = OptionalClass<S::Class>;

    fn class(observation: &Self::Observation) -> Self::Class {
        match observation {
            OptionalObservation::Unallocated { .. } => OptionalClass::Unallocated,
            OptionalObservation::Held { phase, child, .. } => match phase {
                Phase::Empty | Phase::Absent => OptionalClass::Idle,
                Phase::Child | Phase::Complete => OptionalClass::Live(S::class(child)),
                Phase::Release => OptionalClass::Release,
            },
        }
    }
}

impl<S: Custody, T, P> Custody for OptionalState<S, T, P> {
    type Observation = OptionalObservation<S::Observation>;

    fn observe(&mut self) -> Self::Observation {
        let present = self.present;
        let Some(installed) = self.meta.as_mut() else {
            return OptionalObservation::Unallocated {
                present,
                admitted: self.admitted,
            };
        };
        let meta = installed.get();
        OptionalObservation::Held {
            present,
            phase: meta.phase,
            child: meta.child.observe(),
        }
    }
}

fn metadata<T: Reclaim<A>, A: Allocator>(
    state: &mut OptionalState<T::State, T, A::Permit>,
    a: &mut A,
) -> BoundedResult<(), A> {
    // SAFETY: the initializer writes every metadata field.
    unsafe {
        stable::install::<Meta<T::State, T>, A>(
            &mut state.meta,
            &mut state.admitted,
            const { stable::Metadata::whole::<Meta<T::State, T>, A::Permit>() },
            |meta| {
                meta.write(Meta {
                    child: T::INITIAL,
                    place: ptr::null_mut(),
                    phase: Phase::Empty,
                })
            },
            a,
        )
    }
}

// SAFETY: None owns no child; Some retains its child's actual projected address
// and cleanup state. No assumed Option layout or whole-value destructor is used.
unsafe impl<T: Reclaim<A> + Placeholder, A: Allocator> Reclaim<A> for Option<T> {
    const DISPATCH_DEPTH: usize = T::DISPATCH_DEPTH.saturating_add(2);
    type State = OptionalState<T::State, T, A::Permit>;
    const INITIAL: Self::State = OptionalState {
        present: false,
        admitted: stable::Admitted::Nothing,
        meta: None,
    };

    unsafe fn reclaim_step(
        _: NonNull<MaybeUninit<Self>>,
        state: &mut Self::State,
        a: &mut A,
    ) -> BoundedResult<Reclaimed, A> {
        let Some(installed) = state.meta.as_mut() else {
            STEP.admit(a)?;
            state.present = false;
            state.admitted = stable::Admitted::Nothing;
            return Ok(Reclaimed::Done);
        };
        let meta = installed.get();
        match meta.phase {
            Phase::Child | Phase::Complete => {
                let child = NonNull::new(meta.place).ok_or(BoundedError::PlanMismatch)?;
                if unsafe { T::reclaim_step(child, &mut meta.child, a)? } == Reclaimed::Done {
                    meta.phase = Phase::Release;
                }
            }
            Phase::Empty | Phase::Absent => {
                STEP.admit(a)?;
                meta.phase = Phase::Release;
            }
            Phase::Release => {
                // SAFETY: the child, if any, has been reclaimed. The
                // metadata's release was paid for by its acquisition.
                unsafe { stable::uninstall(&mut state.meta) };
                return Ok(Reclaimed::Done);
            }
        }
        Ok(Reclaimed::Progress)
    }

    /// No metadata: one call. Nothing or `None` written: one to `Release`,
    /// one to release. The payload live: its own calls, the last of which
    /// reaches `Release`, then one. `Release`: one.
    unsafe fn remaining(_: NonNull<MaybeUninit<Self>>, state: &mut Self::State) -> u64 {
        let Some(installed) = state.meta.as_mut() else {
            return 1;
        };
        let meta = installed.get();
        match meta.phase {
            Phase::Empty | Phase::Absent => 2,
            Phase::Child | Phase::Complete => match NonNull::new(meta.place) {
                // SAFETY: the payload's projection is retained from `Some`'s
                // write, paired with the payload's own state.
                Some(child) => unsafe { T::remaining(child, &mut meta.child) }.saturating_add(1),
                // Cleanup refuses a missing projection as a defect in one call.
                None => 1,
            },
            Phase::Release => 1,
        }
    }
}

// SAFETY: only bounded, resource-free placeholders are used. Projection occurs
// while Some is valid, before child construction; the raw projection is retained
// instead of forming references through a partially initialized Option later.
unsafe impl<T: InPlace<A> + Placeholder, A: Allocator> InPlace<A> for Option<T> {
    const OPTIONAL: bool = true;

    /// The present-field marker; the metadata block, held for the value's
    /// life; the option's own write; the empty or absent cleanup unit; the
    /// metadata's release. The child is built in the option's own bytes.
    const COST: ConstructionCost = {
        let meta = stable::Metadata::whole::<Meta<T::State, T>, A::Permit>().bytes();
        ConstructionCost::fixed(plus(
            plus(
                plus(
                    STEP_COST,
                    stable::install_cost::<Meta<T::State, T>, A::Permit>(),
                ),
                plus(sized::<Self>().bound(), STEP_COST),
            ),
            plus(stable::release_cost::<A::Permit>(), held(meta)),
        ))
        .plus(T::COST)
    };

    unsafe fn build_present(
        document: &Document<'_, A::Permit>,
        index: usize,
        place: NonNull<MaybeUninit<Self>>,
        state: &mut Self::State,
        a: &mut A,
    ) -> ConstructResult<Built, A> {
        if !state.present {
            STEP.admit(a)?;
            state.present = true;
            return Ok(Built::Progress);
        }
        unsafe { Self::build_step(document, index, place, state, a) }
    }
    unsafe fn build_absent(
        place: NonNull<MaybeUninit<Self>>,
        state: &mut Self::State,
        a: &mut A,
    ) -> ConstructResult<Built, A> {
        let Some(installed) = state.meta.as_mut() else {
            metadata::<T, A>(state, a)?;
            return Ok(Built::Progress);
        };
        let meta = installed.get();
        if meta.phase != Phase::Empty {
            return Err(BoundedError::PlanMismatch.into());
        }
        sized::<Self>().admit(a)?;
        unsafe { place.as_ptr().write(MaybeUninit::new(None)) };
        meta.phase = Phase::Absent;
        Ok(Built::Done)
    }

    unsafe fn build_step(
        document: &Document<'_, A::Permit>,
        index: usize,
        place: NonNull<MaybeUninit<Self>>,
        state: &mut Self::State,
        a: &mut A,
    ) -> ConstructResult<Built, A> {
        let present = state.present;
        let Some(installed) = state.meta.as_mut() else {
            metadata::<T, A>(state, a)?;
            return Ok(Built::Progress);
        };
        let meta = installed.get();
        match meta.phase {
            Phase::Empty => {
                sized::<Self>().admit(a)?;
                let node = node_at(document, index).ok_or_else(wrong_type)?;
                if !present && matches!(node.kind(), Kind::Null) {
                    unsafe { place.as_ptr().write(MaybeUninit::new(None)) };
                    meta.phase = Phase::Absent;
                    return Ok(Built::Done);
                }
                unsafe {
                    place
                        .as_ptr()
                        .write(MaybeUninit::new(Some(T::placeholder())))
                };
                // SAFETY: just initialized Some with a valid resource-free T.
                let value = unsafe { &mut *place.as_ptr().cast::<Option<T>>() };
                meta.place = value.as_mut().ok_or(BoundedError::PlanMismatch)? as *mut T
                    as *mut MaybeUninit<T>;
                meta.phase = Phase::Child;
                Ok(Built::Progress)
            }
            Phase::Child => {
                let child = NonNull::new(meta.place).ok_or(BoundedError::PlanMismatch)?;
                let result = unsafe { T::build_step(document, index, child, &mut meta.child, a)? };
                if result == Built::Done {
                    meta.phase = Phase::Complete;
                }
                Ok(result)
            }
            _ => Err(BoundedError::PlanMismatch.into()),
        }
    }
}
