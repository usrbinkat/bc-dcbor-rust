//! Native Option projections through a valid, resource-free placeholder.
extern crate alloc;
use super::*;
use crate::bounded::decode::construction::reclamation::{Custody, Place, Reduction};
use crate::bounded::decode::construction::stable::{self, Installed, Pending, Ticket};
use crate::sync::{Atomics, Representation};
use alloc::{string::String, vec::Vec};

/// A resource-free placeholder whose construction and move fit one quantum.
///
/// # Safety
/// An implementation keeps two obligations, and the `// SAFETY:` comment on
/// it names each as `label:` (`tests/unsafe_census.rs`, `UNSAFE_TRAITS`,
/// which lists every implementation). In-place initialization may overwrite
/// the placeholder without running Drop. This is deliberately not a blanket
/// Default implementation: arbitrary defaults do not meet this contract.
///
/// - *resources*: the value owns no resources and needs no destructor.
/// - *bounded*: returning it takes bounded work, independent of any child
///   count.
pub unsafe trait Placeholder: Sized {
    fn placeholder() -> Self;
}

macro_rules! scalars {
    ($($ty:ty),*) => {$(
        // SAFETY: resources: a scalar zero owns nothing and has no
        // destructor. bounded: one constant, written in constant work.
        unsafe impl Placeholder for $ty { fn placeholder() -> Self { 0 } }
    )*};
}
scalars!(u8, u16, u32, u64, usize, i8, i16, i32, i64);
// SAFETY: resources: an empty String owns no allocation, so dropping it
// frees nothing. bounded: `String::new` allocates nothing and writes a
// fixed-size header.
unsafe impl Placeholder for String {
    fn placeholder() -> Self {
        String::new()
    }
}
// SAFETY: resources: an empty Vec owns no allocation and no element, so
// dropping it frees nothing. bounded: `Vec::new` allocates nothing and writes
// a fixed-size header, whatever `T`.
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
    /// The payload's cleanup under way: entered by the first cleanup unit
    /// the payload completes without finishing, so no build reaches a
    /// payload being cleaned up.
    Reclaim,
    Release,
}
struct Meta<S, T> {
    child: S,
    /// The payload's place, found once `Some` is written ([`Place::reach`]):
    /// a place stays valid for the option's whole life, so construction,
    /// cleanup and the cleanup count all step the payload through it.
    place: Option<Place<T>>,
    phase: Phase,
}

impl<S, T> Representation for Meta<S, T> {
    type In<F: Atomics> = Self;
}

/// What the metadata block's acquisition admits and holds, its whole value
/// written with the permit ([`stable::Contract`]): the one definition its
/// installation and the option's cost read.
const fn contract<S, T, P>() -> stable::Contract<Meta<S, T>, Meta<S, T>, P> {
    stable::Contract::of()
}

/// The construction state of a native `Option` of payload `T`, whose state
/// is `S`, with permits of `P`: whether it was entered as a present map field
/// (`build_present`), so null is not absence; the ticket of its metadata's
/// acquisition while it is pending ([`Ticket`]), whose credit is the
/// operation's; and its metadata once acquired. Only the option's own
/// construction reads or changes it.
pub struct OptionalState<S, T, P> {
    present: bool,
    ticket: Option<Ticket>,
    meta: Option<Installed<Meta<S, T>, P>>,
}

impl<S, T, P> OptionalState<S, T, P> {
    /// The installed metadata, borrowed from the state: released before the
    /// option's place is accessed under the state, the place's custody.
    fn installed<R>(&mut self) -> Result<&mut Meta<S, T>, BoundedError<R>> {
        self.meta
            .as_mut()
            .map(Installed::get)
            .ok_or(BoundedError::PlanMismatch)
    }
}

// SAFETY: the metadata's place lies within the option's own destination,
// which moves with this state in the same record; the state is `Send`
// exactly when the child state, the payload and the permit are.
unsafe impl<S: Send, T: Send, P: Send> Send for OptionalState<S, T, P> {}
// SAFETY: the state has no `&self` method: its observation takes the
// state's exclusive custody (`Custody::observe` takes `&mut self`), so
// shared access reaches no flag, metadata, child state, payload or permit.
unsafe impl<S, T, P> Sync for OptionalState<S, T, P> {}

/// What a native option's construction holds: whether it was entered as a
/// present map field; then no metadata block, or the block, at a phase,
/// holding the payload's construction state, whose whole observation it
/// carries. Progress alone: an acquisition bound for the block is the root
/// pending's custody (`CustodySink::bound`), never this observation's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum OptionalObservation<S> {
    Unallocated {
        present: bool,
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
#[non_exhaustive]
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
// entered as a present field never changes a cleanup unit. The payload's own
// relation is a simulation of its
// cleanup, and the option leaves `Live` exactly when the payload's cleanup
// reports done, so the relation is a simulation of cleanup.
impl<S: Reduction, T, P> Reduction for OptionalState<S, T, P> {
    type Class = OptionalClass<S::Class>;

    fn class(observation: &Self::Observation) -> Self::Class {
        match observation {
            OptionalObservation::Unallocated { .. } => OptionalClass::Unallocated,
            OptionalObservation::Held { phase, child, .. } => match phase {
                Phase::Empty | Phase::Absent => OptionalClass::Idle,
                Phase::Child | Phase::Complete | Phase::Reclaim => {
                    OptionalClass::Live(S::class(child))
                }
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
            return OptionalObservation::Unallocated { present };
        };
        let meta = installed.get();
        OptionalObservation::Held {
            present,
            phase: meta.phase,
            child: meta.child.observe(),
        }
    }
}

/// The cost of a native option `O` of payload `T` costing `payload`, whose
/// state is `S`, with permits of `P`: the present-field marker; the metadata
/// block, held for the value's life; the option's own write; the empty or
/// absent cleanup unit; the metadata's release. The payload is built in the
/// option's own bytes. None when a quantity does not fit in `u64`.
const fn cost<S, T, O, P>(payload: ConstructionCost) -> Option<ConstructionCost> {
    let meta = contract::<S, T, P>();
    let entered = cost!(STEP_COST.checked_add(meta.write()));
    let written = cost!(sized::<O>().bound().checked_add(STEP_COST));
    let released = cost!(stable::release_cost::<P>().checked_add(held(meta.block())));
    let fixed = cost!(cost!(entered.checked_add(written)).checked_add(released));
    ConstructionCost::fixed(fixed).checked_add(payload)
}

/// The payload's own state, a part of the option's: what the metadata holds.
type Payload<T, A> = <T as Reclaim<A>>::State;

fn metadata<T: Reclaim<A>, A: Allocator>(
    state: &mut OptionalState<Payload<T, A>, T, A::Permit>,
    pending: &mut Pending<A::Origin>,
    a: &mut A,
) -> BoundedResult<(), A> {
    // SAFETY: the header is the whole metadata, every field written.
    unsafe {
        stable::install::<Meta<Payload<T, A>, T>, Meta<Payload<T, A>, T>, A>(
            const { contract::<Payload<T, A>, T, A::Permit>() },
            &mut state.meta,
            pending,
            &mut state.ticket,
            || Meta {
                child: T::INITIAL,
                place: None,
                phase: Phase::Empty,
            },
            |meta| meta,
            a,
        )
    }
}

// SAFETY: initial: not present, no ticket, no metadata. state: the metadata
// block, its phase, the payload's place and the payload's own state record
// everything: None owns no child; Some retains its child's place and its
// state, through which alone the payload is built and cleaned up, as a part.
// admission: each cleanup unit, the option's and the payload's
// (`reclaim_part`), is admitted before it runs, a refusal changing nothing.
// cleanup: no assumed Option layout or whole-value destructor is used; the
// payload is reclaimed by its own binding, then the metadata released,
// allocating nothing and never unwinding. done: `Done` once the payload is
// reclaimed and the metadata released, which leaves the state `INITIAL`.
// order: a step after `Done` reports `Done`; the count and observation read
// only the state and the payload's recorded place. depth: the payload's
// plus two, one more than its counted dispatches, the census recording the
// margin. count: the payload's remaining plus the option's own units.
unsafe impl<T: InPlace<A> + Placeholder, A: Allocator> Reclaim<A> for Option<T> {
    // One level more than its counted dispatches (its own and the
    // payload's, `build_part` and `reclaim_part` straight from its own
    // frame): the placeholder write and the payload's `reach` are no
    // dispatch, so no stack frame accounts for it. Kept for compatibility
    // with every declaration composed over it; the census records the
    // margin (`every_bindings_declaration_exceeds_its_dispatch_by_its_recorded_margin`).
    const DISPATCH_DEPTH: usize = T::DISPATCH_DEPTH.saturating_add(2);
    type State = OptionalState<Payload<T, A>, T, A::Permit>;
    const INITIAL: Self::State = OptionalState {
        present: false,
        ticket: None,
        meta: None,
    };

    fn reclaim_step(
        mut slot: Slot<'_, Self, Self::State>,
        a: &mut Cleanup<'_, A>,
    ) -> BoundedResult<Reclaimed, A> {
        let state = slot.custody();
        let Some(installed) = state.meta.as_mut() else {
            STEP.admit(a)?;
            state.present = false;
            // The metadata's acquisition, if pending, had its credit settled
            // at the operation's cleanup entry: the ticket is forgotten.
            state.ticket = None;
            return Ok(Reclaimed::Done);
        };
        let meta = installed.get();
        match meta.phase {
            Phase::Child | Phase::Complete | Phase::Reclaim => {
                let child = meta.place.ok_or(BoundedError::PlanMismatch)?;
                // SAFETY: the payload's place, kept from `Some`'s write,
                // paired with its own state.
                let payload = unsafe { Slot::new(child, &mut meta.child) };
                // A refused unit returned above, the phase unchanged; one
                // the payload completed moves the option into cleanup, so
                // no build reaches the payload again.
                meta.phase = match reclaim_part::<T, A>(payload, a)? {
                    Reclaimed::Done => Phase::Release,
                    _ => Phase::Reclaim,
                };
            }
            Phase::Empty | Phase::Absent => {
                STEP.admit(a)?;
                meta.phase = Phase::Release;
            }
            Phase::Release => {
                // SAFETY: the child, if any, has been reclaimed. The
                // metadata's release was paid for by its acquisition.
                unsafe { stable::uninstall(&mut state.meta) };
                state.present = false;
                return Ok(Reclaimed::Done);
            }
        }
        Ok(Reclaimed::Progress)
    }

    /// No metadata: one call. Nothing or `None` written: one to `Release`,
    /// one to release. The payload live: its own calls, the last of which
    /// reaches `Release`, then one. `Release`: one.
    fn remaining(mut slot: PeekSlot<'_, Self, Self::State>) -> Option<u64> {
        let Some(installed) = slot.custody().meta.as_mut() else {
            return Some(1);
        };
        let meta = installed.get();
        match meta.phase {
            Phase::Empty | Phase::Absent => Some(2),
            Phase::Child | Phase::Complete | Phase::Reclaim => match meta.place {
                // SAFETY: the payload's place, observed, paired with its own
                // state.
                Some(child) => {
                    remaining_part::<T, A>(unsafe { Slot::new(child.observe(), &mut meta.child) })?
                        .checked_add(1)
                }
                // Cleanup refuses a missing place as a defect in one call.
                None => Some(1),
            },
            Phase::Release => Some(1),
        }
    }

    /// The metadata block's permit, then the payload's own, whenever its
    /// place is kept: a payload built or reclaimed in part reports what it
    /// still holds.
    fn observe_permits(
        mut slot: PeekSlot<'_, Self, Self::State>,
        sink: &mut dyn CustodySink<A::Permit>,
    ) -> PermitsObserved {
        let Some(installed) = slot.custody().meta.as_mut() else {
            return PermitsObserved::Complete;
        };
        sink.permit(installed.permit(), None);
        let meta = installed.get();
        match meta.place {
            // SAFETY: the payload's place, observed, paired with its own
            // state, as the cleanup count reads it.
            Some(child) => {
                observe_part::<T, A>(unsafe { Slot::new(child.observe(), &mut meta.child) }, sink)
            }
            None => PermitsObserved::Complete,
        }
    }
}

// SAFETY: admission: the metadata, the `Some` write and every payload step
// (`build_part`) are admitted before they run. state: each is recorded in
// the option's state before the step returns, on error too; only bounded,
// resource-free placeholders are written (`Placeholder`). done: `Done` once
// the payload is built at its kept place, or `None` written. escape: the
// payload's place is kept in the option's own metadata and never returned.
// provenance: the payload's place is found while Some is valid, before child
// construction, and kept: a place stays valid for the option's whole life,
// so no reference is ever formed through a partially initialized Option.
// order: a build past completion or once cleanup began is refused
// `PlanMismatch`, nothing changed. cost: `cost` of the option's parts plus
// `T::COST`.
unsafe impl<T: InPlace<A> + Placeholder, A: Allocator> InPlace<A> for Option<T> {
    const OPTIONAL: bool = true;

    /// The option's own parts (`cost`) and its payload's.
    const COST: ConstructionCost =
        crate::const_cost!(cost::<Payload<T, A>, T, Self, A::Permit>(T::COST));
    /// Its payload's: an omitted field or a `null` adds no level and no
    /// text.
    const WIRE: crate::bounded::decode::Options = T::WIRE;

    fn build_present<'b>(
        ctx: BindingContext<'b, '_, '_, '_, Self, A>,
        a: &mut A,
    ) -> ConstructResult<Building<'b, Self>, A> {
        let mut ctx = ctx;
        let mut slot = ctx.slot();
        let state = slot.custody();
        if !state.present {
            STEP.admit(a)?;
            state.present = true;
            return Ok(Building::Progress);
        }
        Self::build_step(ctx, a)
    }
    fn build_absent<'b>(
        ctx: BindingContext<'b, '_, '_, '_, Self, A>,
        a: &mut A,
    ) -> ConstructResult<Building<'b, Self>, A> {
        let assembly = ctx.assembly();
        let (mut slot, pending) = ctx.into_acquiring();
        let (place, state) = slot.parts();
        if state.meta.is_none() {
            metadata::<T, A>(state, pending, a)?;
            return Ok(Building::Progress);
        }
        if state.installed()?.phase != Phase::Empty {
            return Err(BoundedError::PlanMismatch.into());
        }
        sized::<Self>().admit(a)?;
        // SAFETY: the slot pairs the place with this state, whose phase says
        // nothing is written yet; the write is admitted above.
        unsafe { place.write(state, None) };
        state.installed()?.phase = Phase::Absent;
        // SAFETY: `None`, the whole value, was written above by an admitted
        // unit, and the phase records it.
        Ok(Building::Done(unsafe { assembly.assemble() }))
    }

    fn build_step<'b>(
        ctx: BindingContext<'b, '_, '_, '_, Self, A>,
        a: &mut A,
    ) -> ConstructResult<Building<'b, Self>, A> {
        let mut ctx = ctx;
        let index = ctx.index();
        let node = ctx.node();
        let assembly = ctx.assembly();
        let (mut slot, pending) = ctx.acquiring();
        let (place, state) = slot.parts();
        let present = state.present;
        if state.meta.is_none() {
            metadata::<T, A>(state, pending, a)?;
            return Ok(Building::Progress);
        }
        match state.installed()?.phase {
            Phase::Empty => {
                sized::<Self>().admit(a)?;
                let node = node.ok_or_else(wrong_type)?;
                if !present && matches!(node.kind(), Kind::Null) {
                    // SAFETY: nothing is written yet; the write is admitted.
                    unsafe { place.write(state, None) };
                    state.installed()?.phase = Phase::Absent;
                    // SAFETY: `None`, the whole value, was written by the
                    // admitted unit above, and the phase records it.
                    return Ok(Building::Done(unsafe { assembly.assemble() }));
                }
                // SAFETY: nothing is written yet; the write is admitted. The
                // placeholder is resource-free, so the payload is then
                // reached through the option, which no place lies within yet,
                // and its place kept for every later step.
                unsafe { place.write(state, Some(T::placeholder())) };
                let child = unsafe { place.reach(state, Option::as_mut) }
                    .ok_or(BoundedError::PlanMismatch)?;
                let meta = state.installed()?;
                meta.place = Some(child);
                meta.phase = Phase::Child;
                Ok(Building::Progress)
            }
            Phase::Child => {
                // The payload is a part from the option's own node, the
                // context's index; the option keeps no index of its own. It
                // is built only in `Child`, which a refused or erroring part
                // leaves unchanged and only the payload's `Done` ends;
                // cleanup moves the option out of it with the payload's
                // first completed unit (`reclaim_step`), and every other
                // phase is refused below.
                // SAFETY: the payload's place, kept from `Some`'s write, and
                // its own state, both held in this option's metadata.
                let payload = unsafe {
                    ctx.part(index, |slot| {
                        let meta = slot.into_parts().1.installed()?;
                        let child = meta.place.ok_or(BoundedError::PlanMismatch)?;
                        Ok::<_, BoundedError<A::Refusal>>(Slot::new(child, &mut meta.child))
                    })
                }?;
                // The payload's record is verified and consumed by the part
                // entry in this step; its `Done` is the coverage `Complete`
                // records, set right after it and nowhere else.
                if build_part::<T, A>(payload, a)? == Built::Progress {
                    return Ok(Building::Progress);
                }
                ctx.slot().custody().installed()?.phase = Phase::Complete;
                // SAFETY: `Some` was written with its placeholder, and the
                // payload over it is done, its record, confined to this step
                // by its brand, verified against the payload's place and
                // consumed here; `Complete` records it.
                Ok(Building::Done(unsafe { assembly.assemble() }))
            }
            _ => Err(BoundedError::PlanMismatch.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounded::decode::decode;
    use crate::bounded::{Budget, Limits};
    use core::mem::MaybeUninit;
    use core::ops::ControlFlow;
    use core::ptr::NonNull;

    /// An option of `T` decoded from `wire`: `Some` written with `T`'s
    /// placeholder, which is `empty`, then `T` built in place over it to
    /// `expected`; then cleanup, within its declared count, releases
    /// everything.
    fn built_over_its_placeholder<T>(name: &str, wire: &[u8], empty: T, expected: T)
    where
        T: InPlace<Limits> + Placeholder + PartialEq + core::fmt::Debug,
    {
        assert_eq!(T::placeholder(), empty, "{name}");
        let mut parser = Limits::unlimited();
        let document = decode(wire, 2, &mut parser).unwrap();
        let mut a = Limits::unlimited();
        let mut value = MaybeUninit::<Option<T>>::uninit();
        let mut session = Session::new(<Option<T> as Reclaim<Limits>>::INITIAL);
        let mut pending = Pending::new(a.owner().expect("an ordinary family mints an owner"));
        // SAFETY: the test owns the destination and pairs it with its
        // initial session; every access to either is through this slot.
        let mut slot = unsafe { Slot::new(Place::root(NonNull::from(&mut value)), &mut session) };
        crate::bounded::within_steps(name, 64, || {
            match build::<Option<T>, Limits>(
                Context::root(&document, slot.reborrow(), &mut pending),
                &mut a,
            )
            .unwrap()
            {
                Built::Done => ControlFlow::Break(()),
                Built::Progress => ControlFlow::Continue(()),
            }
        });
        let (place, built) = slot.parts();
        // SAFETY: construction reported the option written.
        assert_eq!(
            unsafe { place.get(&*built) }.as_ref(),
            Some(&expected),
            "{name}"
        );
        assert!(
            pending.is_idle(),
            "{name}: a completed build left credit pending"
        );
        let declared = remaining::<Option<T>, Limits>(slot.observe())
            .expect("an option's cleanup count fits in u64");
        crate::bounded::within_steps(name, declared, || {
            match reclaim::<Option<T>, Limits>(slot.reborrow(), &mut Cleanup::new(&mut a)).unwrap()
            {
                Reclaimed::Done => ControlFlow::Break(()),
                _ => ControlFlow::Continue(()),
            }
        });
        assert_eq!(a.live_bytes(), 0, "{name}");
    }

    /// Options of a vector and of a byte string each write `Some` with an
    /// empty placeholder owning nothing, then build the payload over it:
    /// `[7]` decodes to `Some([7])`, `h'0102'` to `Some(h'0102')`.
    #[test]
    fn an_option_builds_its_payload_over_its_empty_placeholder() {
        built_over_its_placeholder::<Vec<u64>>(
            "an option of a vector",
            &[0x81, 0x07],
            Vec::new(),
            Vec::from([7]),
        );
        built_over_its_placeholder::<crate::ByteString>(
            "an option of a byte string",
            &[0x42, 0x01, 0x02],
            crate::ByteString::from(Vec::new()),
            crate::ByteString::from(Vec::from([1u8, 2])),
        );
    }
}
