//! A fixed-length byte string's construction ([`FixedBytes`]): the node's
//! length checked against `N` in every step, before anything is admitted
//! beyond that step's one unit, then the document's bytes copied into the
//! value's own place, inline, in units of at most a quantum, each admitted
//! before it is copied. Nothing is allocated, so nothing is held, and
//! cleanup is one unit whatever was copied: bytes need no destructor.

use super::*;
use crate::bounded::Capped;
use crate::bounded::boundary::{Bound, Predicate};
use crate::bounded::decode::DecodeError;
use crate::bounded::decode::construction::stable;
use crate::{Error, FixedBytes};

/// Copying document bytes into the value: one value and at most a quantum.
const COPY: Capped<Caller> = Capped::new(Caller, 1, stable::QUANTUM as u64);

/// A fixed-length byte string's construction state: the bytes copied into
/// the value's place so far, and whether the copy is complete. Plain data,
/// acquiring nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FixedState {
    copied: usize,
    complete: bool,
}

impl FixedState {
    /// Nothing copied.
    pub const INITIAL: Self = Self {
        copied: 0,
        complete: false,
    };
}

/// What a fixed-length byte string's construction holds: the bytes copied
/// and whether the value is complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FixedObservation {
    pub copied: usize,
    pub complete: bool,
}

impl Custody for FixedState {
    type Observation = FixedObservation;

    fn observe(&mut self) -> FixedObservation {
        FixedObservation {
            copied: self.copied,
            complete: self.complete,
        }
    }
}

/// The cleanup class of a fixed-length byte string: one, since its one
/// cleanup unit reads nothing of the state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum FixedClass {
    /// One unit completes cleanup, from any state.
    Inline,
}

// Cleanup (`reclaim_step`) admits one unit and resets the state, reading
// neither the bytes copied nor completion, so every state is of one class
// and the relation is a simulation of cleanup.
impl Reduction for FixedState {
    type Class = FixedClass;

    fn class(_: &FixedObservation) -> FixedClass {
        FixedClass::Inline
    }
}

// Every state is of the one class, a complete one included.
impl Uniform for FixedState {
    const COMPLETE: FixedClass = FixedClass::Inline;
}

/// The cost of a fixed-length byte string. Fixed: the last copy's value,
/// or the one unit that refuses a node of the wrong kind or length, the
/// larger of the two; and cleanup's one unit. Per byte: every byte copied
/// once, and every copy but the last covers a whole quantum, so its values
/// are at most `PER_BYTE_SCALE / QUANTUM` sixty-fourths per byte, rounded
/// up. Nothing is allocated or held: the bytes are the value's own. None
/// when a quantity does not fit in `u64`.
pub(crate) const fn fixed_cost() -> Option<ConstructionCost> {
    let last = Unit::new(Caller, COPY.values(), 0).bound();
    let build = last.larger(STEP_COST);
    Some(ConstructionCost {
        fixed: cost!(build.checked_add(STEP_COST)),
        per_byte: ResourceBound {
            values: cost!(
                COPY.values()
                    .checked_mul(PER_BYTE_SCALE.div_ceil(COPY.cap()))
            ),
            bytes: PER_BYTE_SCALE,
            allocated: 0,
            peak: 0,
            retained: 0,
        },
    })
}

// SAFETY: initial: `FixedState::INITIAL`, nothing copied, nothing acquired.
// state: the bytes copied and completion record everything; the value owns
// no allocation. admission: the one cleanup unit is admitted before it
// resets the state, a refusal changing nothing. cleanup: bytes own nothing
// and need no destructor, whatever prefix of them was written; cleanup
// only resets the state, allocating nothing and never unwinding. done:
// nothing initialized owns anything, so releasing the outer allocation
// without `Drop` is sound. order: the unit is the same from every state,
// `Done` each time; the count and observation read the state alone. depth:
// a leaf, the default 1. count: one call.
unsafe impl<A: Allocator, const N: usize> Reclaim<A> for FixedBytes<N> {
    type State = FixedState;
    const INITIAL: FixedState = FixedState::INITIAL;

    fn reclaim_step(
        mut slot: Slot<'_, Self, FixedState>,
        cleanup: &mut Cleanup<'_, A>,
    ) -> BoundedResult<Reclaimed, A> {
        STEP.admit(cleanup)?;
        *slot.custody() = FixedState::INITIAL;
        Ok(Reclaimed::Done)
    }

    /// One call, which is `Done`.
    fn remaining(_: PeekSlot<'_, Self, FixedState>) -> Option<u64> {
        Some(1)
    }

    /// Inline bytes own no permit.
    fn observe_permits(
        _: PeekSlot<'_, Self, FixedState>,
        _: &mut dyn CustodySink<A::Permit>,
    ) -> PermitsObserved {
        PermitsObserved::Complete
    }
}

// SAFETY: admission: a node of the wrong kind or length is refused by one
// admitted unit (`rejected`, `STEP`), and each copy is admitted (`COPY`)
// before any byte of it is written. state: `copied` is recorded with each
// copy before the step returns; a refused or rejected step leaves the state
// as it was. done: `Done` only once all `N` bytes are copied, `complete`
// recording it. escape: the place's pointer is used for the copy alone and
// never kept or returned. provenance: the bytes are written through the
// slot's place (`Place::as_ptr`), at offsets within the value, which the
// transparent representation makes its array's. order: a step once
// complete, or one whose copied count lies past the value, is refused
// `PlanMismatch`, nothing changed; every step re-reads the node, so the
// length checked is the bytes copied's. cost: `fixed_cost`.
unsafe impl<A: Allocator, const N: usize> InPlace<A> for FixedBytes<N> {
    const COST: ConstructionCost = crate::const_cost!(fixed_cost());
    const WIRE: crate::bounded::decode::Options = crate::bounded::decode::Options::SCALAR;

    fn build_step<'b>(
        ctx: BindingContext<'b, '_, '_, '_, Self, A>,
        a: &mut A,
    ) -> ConstructResult<Building<'b, Self>, A> {
        let Some(Kind::Bytes(bytes)) = ctx.node().map(|n| n.kind()) else {
            return rejected(a);
        };
        let assembly = ctx.assembly();
        let mut slot = ctx.into_slot();
        let (place, state) = slot.parts();
        if state.complete {
            return Err(BoundedError::PlanMismatch.into());
        }
        if bytes.len() != N {
            STEP.admit(a)?;
            return Err(DecodeError::Invalid(Error::WrongLength {
                expected: N,
                actual: bytes.len(),
            }));
        }
        let start = state.copied;
        if Bound::new(Predicate::Payload, N).exceeded(a, start) {
            return Err(BoundedError::PlanMismatch.into());
        }
        let end = start + Bound::new(Predicate::Quantum, stable::QUANTUM).clamp(a, N - start);
        COPY.admit(a, (end - start) as u64)?;
        // SAFETY: `start..end` lies within both the node's `N` bytes and the
        // value's, which the transparent representation lays out as an
        // array of `N` bytes from the place's start; bytes need no
        // initialization before they are written and no drop when
        // overwritten; the document's bytes and the destination are distinct
        // allocations, and the write is admitted above.
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes[start..end].as_ptr(),
                place.as_ptr(state).cast::<u8>().add(start),
                end - start,
            );
        }
        state.copied = end;
        if end != N {
            return Ok(Building::Progress);
        }
        state.complete = true;
        // SAFETY: every one of the value's `N` bytes was written by an
        // admitted copy, and `complete` records it.
        Ok(Building::Done(unsafe { assembly.assemble() }))
    }
}

// SAFETY: resources: an array of bytes owns nothing and has no destructor.
// bounded: one constant of the type's fixed size, independent of any child
// count; its write extent is checked where an option of it is used
// (`sized`).
unsafe impl<const N: usize> Placeholder for FixedBytes<N> {
    fn placeholder() -> Self {
        FixedBytes::new([0; N])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounded::Limits;

    /// A fixed-length byte string's cost, as its binding evaluates it in a
    /// constant: per byte, each byte copied once and a copy's value per
    /// quantum (64 bytes, so one sixty-fourth a byte), nothing held; fixed,
    /// the last copy or the refusal, and cleanup's unit.
    #[test]
    fn a_fixed_byte_strings_cost_charges_each_byte_once_and_holds_nothing() {
        assert_eq!(COPY.cap(), 64);
        let cost = fixed_cost().expect("the cost fits in u64");
        assert_eq!(cost, <FixedBytes<32> as InPlace<Limits>>::COST);
        assert_eq!(cost, <FixedBytes<4096> as InPlace<Limits>>::COST);
        assert_eq!(
            cost.per_byte,
            ResourceBound {
                values: 1,
                bytes: 64,
                allocated: 0,
                peak: 0,
                retained: 0,
            }
        );
        assert_eq!(
            cost.fixed,
            ResourceBound {
                values: 2,
                bytes: 0,
                allocated: 0,
                peak: 0,
                retained: 0,
            }
        );
    }
}
