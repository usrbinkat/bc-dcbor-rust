//! Native Option projections through a valid, resource-free placeholder.
extern crate alloc;
use super::*;
use crate::bounded::decode::construction::reclamation::{Admitted, Custody, Place, Reduction};
use crate::bounded::decode::construction::stable::{self, Installed};
use alloc::{string::String, vec::Vec};

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
    /// The payload's place, found once `Some` is written ([`Place::reach`]):
    /// a place stays valid for the option's whole life, so construction,
    /// cleanup and the cleanup count all step the payload through it.
    place: Option<Place<T>>,
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
    // SAFETY: the header is the whole metadata, every field written.
    unsafe {
        stable::install::<Meta<T::State, T>, Meta<T::State, T>, A>(
            &mut state.meta,
            &mut state.admitted,
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

// SAFETY: None owns no child; Some retains its child's place and cleanup
// state. No assumed Option layout or whole-value destructor is used. Every
// cleanup that releases the metadata leaves the state `INITIAL`.
unsafe impl<T: Reclaim<A> + Placeholder, A: Allocator> Reclaim<A> for Option<T> {
    const DISPATCH_DEPTH: usize = T::DISPATCH_DEPTH.saturating_add(2);
    type State = OptionalState<T::State, T, A::Permit>;
    const INITIAL: Self::State = OptionalState {
        present: false,
        admitted: stable::Admitted::Nothing,
        meta: None,
    };

    fn reclaim_step(
        mut slot: Slot<'_, Self, Self::State>,
        a: &mut A,
    ) -> BoundedResult<Reclaimed, A> {
        let state = slot.custody();
        let Some(installed) = state.meta.as_mut() else {
            STEP.admit(a)?;
            state.present = false;
            state.admitted = stable::Admitted::Nothing;
            return Ok(Reclaimed::Done);
        };
        let meta = installed.get();
        match meta.phase {
            Phase::Child | Phase::Complete => {
                let child = meta.place.ok_or(BoundedError::PlanMismatch)?;
                // SAFETY: the payload's place, kept from `Some`'s write,
                // paired with its own state.
                let payload = unsafe { Slot::new(child, &mut meta.child) };
                if T::reclaim_step(payload, a)? == Reclaimed::Done {
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
                state.present = false;
                return Ok(Reclaimed::Done);
            }
        }
        Ok(Reclaimed::Progress)
    }

    /// No metadata: one call. Nothing or `None` written: one to `Release`,
    /// one to release. The payload live: its own calls, the last of which
    /// reaches `Release`, then one. `Release`: one.
    fn remaining(mut slot: PeekSlot<'_, Self, Self::State>) -> u64 {
        let Some(installed) = slot.custody().meta.as_mut() else {
            return 1;
        };
        let meta = installed.get();
        match meta.phase {
            Phase::Empty | Phase::Absent => 2,
            Phase::Child | Phase::Complete => match meta.place {
                // SAFETY: the payload's place, observed, paired with its own
                // state.
                Some(child) => T::remaining(unsafe { Slot::new(child.observe(), &mut meta.child) })
                    .saturating_add(1),
                // Cleanup refuses a missing place as a defect in one call.
                None => 1,
            },
            Phase::Release => 1,
        }
    }
}

// SAFETY: only bounded, resource-free placeholders are used. The payload's
// place is found while Some is valid, before child construction, and kept:
// a place stays valid for the option's whole life, so no reference is ever
// formed through a partially initialized Option.
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

    fn build_present(
        document: &Document<'_, A::Permit>,
        index: usize,
        mut slot: Slot<'_, Self, Self::State>,
        a: &mut A,
    ) -> ConstructResult<Built, A> {
        let state = slot.custody();
        if !state.present {
            STEP.admit(a)?;
            state.present = true;
            return Ok(Built::Progress);
        }
        Self::build_step(document, index, slot, a)
    }
    fn build_absent(mut slot: Slot<'_, Self, Self::State>, a: &mut A) -> ConstructResult<Built, A> {
        let (place, state) = slot.parts();
        if state.meta.is_none() {
            metadata::<T, A>(state, a)?;
            return Ok(Built::Progress);
        }
        if state.installed()?.phase != Phase::Empty {
            return Err(BoundedError::PlanMismatch.into());
        }
        sized::<Self>().admit(a)?;
        // SAFETY: the slot pairs the place with this state, whose phase says
        // nothing is written yet; the write is admitted above.
        unsafe { place.write(state, None) };
        state.installed()?.phase = Phase::Absent;
        Ok(Built::Done)
    }

    fn build_step(
        document: &Document<'_, A::Permit>,
        index: usize,
        mut slot: Slot<'_, Self, Self::State>,
        a: &mut A,
    ) -> ConstructResult<Built, A> {
        let (place, state) = slot.parts();
        let present = state.present;
        if state.meta.is_none() {
            metadata::<T, A>(state, a)?;
            return Ok(Built::Progress);
        }
        match state.installed()?.phase {
            Phase::Empty => {
                sized::<Self>().admit(a)?;
                let node = node_at(document, index).ok_or_else(wrong_type)?;
                if !present && matches!(node.kind(), Kind::Null) {
                    // SAFETY: nothing is written yet; the write is admitted.
                    unsafe { place.write(state, None) };
                    state.installed()?.phase = Phase::Absent;
                    return Ok(Built::Done);
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
                Ok(Built::Progress)
            }
            Phase::Child => {
                let meta = state.installed()?;
                let child = meta.place.ok_or(BoundedError::PlanMismatch)?;
                // SAFETY: the payload's place, kept from `Some`'s write,
                // paired with its own state.
                let payload = unsafe { Slot::new(child, &mut meta.child) };
                let result = T::build_step(document, index, payload, a)?;
                if result == Built::Done {
                    meta.phase = Phase::Complete;
                }
                Ok(result)
            }
            _ => Err(BoundedError::PlanMismatch.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounded::Limits;
    use crate::bounded::decode::decode;
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
        let mut state = <Option<T> as Reclaim<Limits>>::INITIAL;
        // SAFETY: the test owns the destination and pairs it with its
        // initial state; every access to either is through this slot.
        let mut slot = unsafe { Slot::new(Place::root(NonNull::from(&mut value)), &mut state) };
        crate::bounded::within_steps(
            name,
            64,
            || match <Option<T> as InPlace<Limits>>::build_step(
                &document,
                0,
                slot.reborrow(),
                &mut a,
            )
            .unwrap()
            {
                Built::Done => ControlFlow::Break(()),
                Built::Progress => ControlFlow::Continue(()),
            },
        );
        let (place, built) = slot.parts();
        // SAFETY: construction reported the option written.
        assert_eq!(
            unsafe { place.get(&*built) }.as_ref(),
            Some(&expected),
            "{name}"
        );
        let declared = <Option<T> as Reclaim<Limits>>::remaining(slot.observe());
        crate::bounded::within_steps(name, declared, || {
            match <Option<T> as Reclaim<Limits>>::reclaim_step(slot.reborrow(), &mut a).unwrap() {
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
