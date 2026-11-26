//! A minimal big integer's construction ([`MinimalBigInt`]): its sign
//! written once its node is read and its encoding checked minimal, then its
//! argument's bytes built and reclaimed exactly as a byte string's are, at
//! the magnitude's own place, from the document's byte string for a bignum
//! or from the plain integer's argument, recomputed alike at every step.
//!
//! The checks of a bignum ([`crate::minimal_bigint::bignum`]) read its byte
//! string's length and first byte alone, so they are part of the one unit
//! that writes the sign, as a scalar's range check is part of its write
//! (`in_place.rs`, `integers!`).
//!
//! Every step reads its source again (`read`): the node, a tag's child, the
//! bignum's two checks, or a plain integer's argument bytes, recomputed from
//! its node. That read is constant work, at most two node lookups and a
//! length and a byte compared, independent of the magnitude's length, and it
//! precedes the step's own admission, including a step whose admission is
//! refused and repeated. It is the same dispatch every byte buffer step
//! makes before its unit (`text.rs`, `copy_buffer`'s source and boundary
//! reads), which the engine's per-step bound of one quantum covers: no unit
//! of it scales with the input.

use core::ptr::addr_of_mut;

use super::text::{
    BufferClass, BufferObservation, BufferState, buffer_cost, buffer_permits, buffer_remaining,
    copy_buffer, reclaim_buffer,
};
use super::*;
use crate::bounded::decode::DecodeError;
use crate::bounded::decode::construction::reclamation::{Custody, Mode, Reduction, Uniform};
use crate::minimal_bigint::{argument_bytes, bignum};
use crate::{ByteString, MinimalBigInt};

/// A minimal big integer's construction state: whether its sign is written,
/// then its magnitude, a byte buffer. The sign holds nothing to reclaim.
pub struct MinimalState<P> {
    sign: Written,
    magnitude: BufferState<P>,
}

/// What a minimal big integer's construction holds: whether its sign is
/// written, and its magnitude's own custody.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct MinimalObservation {
    pub sign: Written,
    pub magnitude: BufferObservation,
}

impl<P> Custody for MinimalState<P> {
    type Observation = MinimalObservation;

    fn observe(&mut self) -> MinimalObservation {
        MinimalObservation {
            sign: self.sign,
            magnitude: self.magnitude.observe(),
        }
    }
}

// Cleanup is the magnitude's alone (`reclaim_buffer` over `magnitude`): the
// sign is a `bool`, which no cleanup unit reads or drops. So the magnitude's
// own reduction, applied to its observation, is a simulation of this state's
// cleanup.
impl<P> Reduction for MinimalState<P> {
    type Class = BufferClass;

    fn class(observation: &MinimalObservation) -> BufferClass {
        <BufferState<P> as Reduction>::class(&observation.magnitude)
    }
}

// Construction reports `Done` only when the magnitude's own construction
// does, so its class is the magnitude's complete class.
impl<P> Uniform for MinimalState<P> {
    const COMPLETE: BufferClass = <BufferState<P> as Uniform>::COMPLETE;
}

/// The magnitude inside a minimal big integer's slot, with its own state.
fn magnitude_slot<'c, M: Mode, P>(
    slot: Slot<'c, MinimalBigInt, MinimalState<P>, M>,
) -> Slot<'c, ByteString, BufferState<P>, M> {
    // SAFETY: the magnitude is a field of the value, reached by raw
    // projection alone; its state is its own custody, the state's
    // `magnitude` field.
    unsafe {
        slot.child(
            |value| addr_of_mut!((*value).magnitude),
            |state| &mut state.magnitude,
        )
    }
}

/// The bytes a magnitude is copied from: a plain integer's argument, held
/// here, or a bignum's byte string, borrowed from the document.
enum Magnitude<'d> {
    Argument([u8; 8], usize),
    Bytes(&'d [u8]),
}

impl Magnitude<'_> {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Argument(bytes, start) => &bytes[*start..],
            Self::Bytes(bytes) => bytes,
        }
    }
}

/// The context's node read as a minimal big integer: its sign and its
/// magnitude. An unsigned or negative integer is accepted; a tag 2 or 3
/// around a byte string is refused unless minimal ([`bignum`]); anything
/// else is the wrong type. Reads only the node, and for a tag its content
/// (`ctx.node_at`, the same document's next node).
fn read<'c, T, S, A: Allocator, R>(
    ctx: &Context<'_, 'c, '_, '_, T, S, A>,
) -> Result<(bool, Magnitude<'c>), DecodeError<R>> {
    let index = ctx.index();
    match ctx.node().map(|node| node.kind()) {
        Some(Kind::Unsigned(n)) => {
            let (bytes, start) = argument_bytes(n);
            Ok((false, Magnitude::Argument(bytes, start)))
        }
        // The value is `-1 - n`, so `n` is `!value`, not negative.
        Some(Kind::Negative(value)) => {
            let (bytes, start) = argument_bytes((!value).unsigned_abs());
            Ok((true, Magnitude::Argument(bytes, start)))
        }
        Some(Kind::Tagged(tag)) => {
            let negative = match tag {
                crate::TAG_POSITIVE_BIGNUM => false,
                crate::TAG_NEGATIVE_BIGNUM => true,
                _ => return Err(wrong_type()),
            };
            let child = index.checked_add(1).ok_or(BoundedError::Overflow)?;
            let Some(Kind::Bytes(bytes)) = ctx.node_at(child).map(|node| node.kind()) else {
                return Err(wrong_type());
            };
            bignum(negative, bytes)?;
            Ok((negative, Magnitude::Bytes(bytes)))
        }
        _ => Err(wrong_type()),
    }
}

// SAFETY: initial: the sign unwritten and the magnitude's initial buffer
// state. state: `sign` and the magnitude's buffer state record everything;
// the sign holds nothing. admission, cleanup, done and order: the
// magnitude's units are a byte string's (`reclaim_buffer`), at the
// magnitude's own slot (`magnitude_slot`): admission: each admitted before it
// runs, a refusal changing nothing. cleanup: a byte buffer's, freeing bytes
// with no element destructor, allocating nothing, never unwinding. done:
// `Done` once its buffer and permits are released; the sign owns nothing.
// order: a step after `Done` reports `Done`; the count and observation read
// the state alone. depth: a leaf, the default 1. count: `buffer_remaining`
// of the magnitude.
unsafe impl<A: Allocator> Reclaim<A> for MinimalBigInt {
    type State = MinimalState<A::Permit>;
    const INITIAL: Self::State = MinimalState {
        sign: Written::Empty,
        magnitude: BufferState::INITIAL,
    };

    fn reclaim_step(
        slot: Slot<'_, Self, Self::State>,
        cleanup: &mut Cleanup<'_, A>,
    ) -> BoundedResult<Reclaimed, A> {
        reclaim_buffer::<ByteString, A>(magnitude_slot(slot), cleanup)
    }

    fn remaining(mut slot: PeekSlot<'_, Self, Self::State>) -> Option<u64> {
        buffer_remaining(&mut slot.custody().magnitude)
    }

    /// The magnitude's: the sign holds none.
    fn observe_permits(
        mut slot: PeekSlot<'_, Self, Self::State>,
        sink: &mut dyn CustodySink<A::Permit>,
    ) -> PermitsObserved {
        buffer_permits(&mut slot.custody().magnitude, sink)
    }
}

/// The cost of a minimal big integer: the sign's one write unit, which also
/// reads the node and checks a bignum's length and first byte, then a byte
/// string's ([`buffer_cost`]) over its magnitude. The magnitude never exceeds
/// the bytes of the subtree it is read from: a bignum's is its byte string's
/// content; a plain integer's argument has at most as many bytes as its head
/// (`n < 24` one byte in a head of one, and every longer argument in a head
/// one byte longer than its minimal bytes).
pub(crate) const fn minimal_cost<P>() -> Option<ConstructionCost> {
    let sign = ConstructionCost::fixed(sized::<bool>().bound());
    cost!(buffer_cost::<ByteString, P>()).checked_add(sign)
}

// SAFETY: admission: the sign is written after its one unit is admitted, and
// the magnitude is built by `copy_buffer`, which admits each phase first.
// state: the sign is recorded with its write, only from the state recording
// it unwritten; a node refused leaves the state as it was; every phase of the
// magnitude, failures included, is its own state, which cleanup above
// reclaims. done: `Done` only once the sign is written and every magnitude
// byte copied, both fields initialized. escape: the magnitude's byte vector
// stays in its header. provenance: the sign is a raw projection of the
// slot's place and the magnitude its field's slot (`magnitude_slot`). order:
// the source is equal at every step, since the session binds one node and
// the sign and the magnitude are read from it alike (the document's byte
// string, or the same argument's bytes), and the copy refuses a phase it
// does not continue, nothing changed. cost: `minimal_cost`, the sign's unit
// and a byte string's.
unsafe impl<A: Allocator> InPlace<A> for MinimalBigInt {
    const COST: ConstructionCost = crate::const_cost!(minimal_cost::<A::Permit>());
    /// A plain integer, or a bignum's tag around its byte string: one tag
    /// level, no text.
    const WIRE: crate::bounded::decode::Options = crate::bounded::decode::Options::SCALAR.nested();

    fn build_step<'b>(
        ctx: BindingContext<'b, '_, '_, '_, Self, A>,
        a: &mut A,
    ) -> ConstructResult<Building<'b, Self>, A> {
        let mut ctx = ctx;
        let assembly = ctx.assembly();
        if ctx.slot().custody().sign == Written::Empty {
            sized::<bool>().admit(a)?;
            let (negative, _) = read(&ctx)?;
            let mut slot = ctx.slot();
            let (place, state) = slot.parts();
            // SAFETY: the slot pairs the place with this state, whose sign is
            // unwritten: nothing to drop; the sign is a field of the value,
            // projected raw; the write is admitted above.
            unsafe {
                place
                    .project(|value| addr_of_mut!((*value).negative))
                    .write(state, negative)
            };
            state.sign = Written::Initialized;
            return Ok(Building::Progress);
        }
        let (_, magnitude) = read(&ctx)?;
        let (slot, pending) = ctx.into_acquiring();
        let built =
            copy_buffer::<ByteString, A>(magnitude.bytes(), magnitude_slot(slot), pending, a)?;
        // SAFETY: the sign was written before the magnitude began, and the
        // buffer engine reports `Done` only once every byte of the magnitude
        // is copied into the byte string at its field, its phase `Complete`:
        // the value's two fields are both initialized.
        Ok(unsafe { reported(built, assembly) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounded::{Limits, Reservation};

    /// A minimal big integer costs a byte string's and one write of a `bool`.
    #[test]
    fn a_minimal_big_integers_cost_is_a_byte_strings_and_its_sign() {
        let bytes = <ByteString as InPlace<Limits>>::COST;
        let cost = minimal_cost::<Reservation>().expect("the cost fits in u64");
        assert_eq!(cost, <MinimalBigInt as InPlace<Limits>>::COST);
        assert_eq!(cost.per_byte, bytes.per_byte);
        assert_eq!(
            cost.fixed,
            bytes
                .fixed
                .checked_add(sized::<bool>().bound())
                .expect("the cost fits in u64")
        );
    }
}
