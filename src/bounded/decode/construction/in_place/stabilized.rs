//! A stabilized text's construction ([`StabilizedText`]): the decoded text's
//! code points checked against the pinned Unicode version's assigned set,
//! in windows of at most a quantum, each admitted before it is inspected;
//! then the text built and reclaimed exactly as a `String` is, at the
//! value's own place.
//!
//! dCBOR's decoder has already refused a text not in NFC before any binding
//! sees it, so the check adds only the stabilized-text rule (UAX #15,
//! section 12): a code point the pinned version leaves unassigned is refused
//! as invalid input, [`crate::Error::UnassignedCodePoint`], before the
//! binding allocates anything of its own (the document it reads is already
//! parsed and held by its caller).
//!
//! Every step reads its source again: the node and its kind, a constant
//! lookup, before the step's own admission, including a step whose
//! admission is refused and repeated; a window's scan of its bytes comes only
//! after the window is admitted. The same dispatch every byte buffer step
//! makes (`text.rs`, `copy_buffer`), within the engine's per-step bound of
//! one quantum.

extern crate alloc;
use super::text::{
    self, BufferClass, BufferObservation, BufferState, buffer_cost, buffer_remaining, copy_buffer,
    reclaim_buffer,
};
use super::*;
use crate::StabilizedText;
use crate::bounded::Capped;
use crate::bounded::boundary::{Bound, Predicate, boundary};
use crate::bounded::decode::DecodeError;
use crate::bounded::decode::construction::reclamation::{Custody, Mode, Reduction, Uniform};
use crate::bounded::decode::construction::stable;
use alloc::string::String;

/// Checking a window of the decoded text: one value and at most a quantum,
/// every byte of the window inspected once.
const CHECK: Capped<Caller> = Capped::new(Caller, 1, stable::QUANTUM as u64);

/// The bytes every window but the last covers at least
/// ([`text::scalar_window`]).
const CHECKED: u64 = text::scalar_window(CHECK.cap());

/// A stabilized text's construction state: the bytes of the decoded text
/// checked so far, then the `String` it is built as. Checking completes
/// before the text's construction begins, and its count never changes once
/// it covers the text.
pub struct StabilizedState<P> {
    checked: usize,
    text: BufferState<P>,
}

/// What a stabilized text's construction holds: the bytes checked, and the
/// text's own custody.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct StabilizedObservation {
    pub checked: usize,
    pub text: BufferObservation,
}

impl<P> Custody for StabilizedState<P> {
    type Observation = StabilizedObservation;

    fn observe(&mut self) -> StabilizedObservation {
        StabilizedObservation {
            checked: self.checked,
            text: self.text.observe(),
        }
    }
}

// Cleanup is the text's alone (`reclaim_buffer` over `text`): the bytes
// checked are read by no cleanup unit, acquire nothing and release nothing.
// So the text's own reduction, applied to its observation, is a simulation
// of this state's cleanup.
impl<P> Reduction for StabilizedState<P> {
    type Class = BufferClass;

    fn class(observation: &StabilizedObservation) -> BufferClass {
        <BufferState<P> as Reduction>::class(&observation.text)
    }
}

// Construction reports `Done` only when the text's own construction does, a
// `String` complete, so its class is the text's complete class.
impl<P> Uniform for StabilizedState<P> {
    const COMPLETE: BufferClass = <BufferState<P> as Uniform>::COMPLETE;
}

/// The text inside a stabilized text's slot, with its own state.
fn text_slot<'c, M: Mode, P>(
    slot: Slot<'c, StabilizedText, StabilizedState<P>, M>,
) -> Slot<'c, String, BufferState<P>, M> {
    // SAFETY: `StabilizedText` is transparent over its `String`, so the
    // text lies at the value's own place, reached by a cast alone; the
    // text's state is its own custody, the state's `text` field.
    unsafe { slot.child(|value| value.cast::<String>(), |state| &mut state.text) }
}

// SAFETY: initial: nothing checked and the text's initial buffer state.
// state: `checked` and the text's buffer state record everything; the bytes
// checked hold nothing. admission, cleanup, done and order: every unit is the
// text's (`reclaim_buffer`, `in_place/text.rs`), at the text's own slot
// (`text_slot`): admission: each admitted before it runs, a refusal changing
// nothing. cleanup: a byte buffer's, freeing bytes with no element
// destructor, allocating nothing, never unwinding. done: `Done` once its
// buffer and permits are released. order: a step after `Done` reports
// `Done`; the count and observation read the state alone. depth: a leaf, the
// default 1. count: `buffer_remaining` of the text.
unsafe impl<A: Allocator> Reclaim<A> for StabilizedText {
    type State = StabilizedState<A::Permit>;
    const INITIAL: Self::State = StabilizedState {
        checked: 0,
        text: BufferState::INITIAL,
    };

    fn reclaim_step(
        slot: Slot<'_, Self, Self::State>,
        cleanup: &mut Cleanup<'_, A>,
    ) -> BoundedResult<Reclaimed, A> {
        reclaim_buffer::<String, A>(text_slot(slot), cleanup)
    }

    fn remaining(mut slot: PeekSlot<'_, Self, Self::State>) -> Option<u64> {
        buffer_remaining(&mut slot.custody().text)
    }

    /// The text's: the check holds none.
    fn observe_permits(
        mut slot: PeekSlot<'_, Self, Self::State>,
        sink: &mut dyn CustodySink<A::Permit>,
    ) -> PermitsObserved {
        text::buffer_permits(&mut slot.custody().text, sink)
    }
}

/// The cost of a stabilized text: the text's ([`buffer_cost`]), and the
/// check before it. Fixed: the last window's value. Per byte: every byte
/// inspected once, and every window but the last covering at least
/// [`CHECKED`] bytes, so its values are at most `PER_BYTE_SCALE / CHECKED`
/// sixty-fourths per byte, rounded up. The check holds nothing.
pub(crate) const fn stabilized_cost<P>() -> Option<ConstructionCost> {
    let check = ConstructionCost {
        fixed: Unit::new(Caller, CHECK.values(), 0).bound(),
        per_byte: ResourceBound {
            values: cost!(CHECK.values().checked_mul(PER_BYTE_SCALE.div_ceil(CHECKED))),
            bytes: PER_BYTE_SCALE,
            allocated: 0,
            peak: 0,
            retained: 0,
        },
    };
    cost!(buffer_cost::<String, P>()).checked_add(check)
}

/// Check the next window of `source`, from byte `start`: at most a quantum,
/// ending on a scalar, admitted before any byte of it is inspected. Its end,
/// or the first unassigned code point found within it.
fn check_window<A: Allocator>(source: &str, start: usize, a: &mut A) -> ConstructResult<usize, A> {
    if Bound::new(Predicate::Payload, source.len()).exceeded(a, start)
        || !source.is_char_boundary(start)
    {
        return Err(BoundedError::PlanMismatch.into());
    }
    let remaining = source.len() - start;
    let mut end = start + Bound::new(Predicate::Quantum, stable::QUANTUM).clamp(a, remaining);
    // A boundary is at most three bytes before the end: a scalar is at most
    // four bytes.
    while boundary!(a, Predicate::Payload, end, start).is_gt() && !source.is_char_boundary(end) {
        end -= 1;
    }
    if end == start && remaining != 0 {
        return Err(BoundedError::PlanMismatch.into());
    }
    CHECK.admit(a, (end - start) as u64)?;
    match crate::stabilized_text::first_unassigned(&source[start..end]) {
        Some(c) => Err(DecodeError::Invalid(crate::Error::UnassignedCodePoint(
            u32::from(c),
        ))),
        None => Ok(end),
    }
}

// SAFETY: admission: each window is admitted (`CHECK`) before any byte of it
// is inspected, and the text is then built by `copy_buffer`, which admits
// each phase first. state: checking writes nothing and acquires nothing; a
// refused or rejected window leaves the state as it was, and `checked` is
// recorded before the step returns; every phase of the text, failures
// included, is the text's state, which cleanup above reclaims. done: `Done`
// only once every byte is checked and copied, the phase `Complete`. escape:
// the text's byte vector stays in its header. provenance: the text is built
// at the value's place, which the transparent representation makes the
// text's own (`text_slot`). order: a window off a boundary or past the text
// is refused `PlanMismatch`, and the copy refuses a phase it does not
// continue, nothing changed; a node not a text is refused by one admitted
// unit. cost: `stabilized_cost`, the text's and the check's.
unsafe impl<A: Allocator> InPlace<A> for StabilizedText {
    const COST: ConstructionCost = crate::const_cost!(stabilized_cost::<A::Permit>());

    /// Every window checked and every byte copied come from the context's
    /// one node: the engine hands the binding only its own context, and the
    /// session refuses another node, so the text checked is the text copied.
    fn build_step<'b>(
        ctx: BindingContext<'b, '_, '_, '_, Self, A>,
        a: &mut A,
    ) -> ConstructResult<Building<'b, Self>, A> {
        let Some(Kind::Text(text)) = ctx.node().map(|n| n.kind()) else {
            return rejected(a);
        };
        let assembly = ctx.assembly();
        let (mut slot, pending) = ctx.into_acquiring();
        let checked = slot.custody().checked;
        if checked != text.len() {
            let end = check_window(text, checked, a)?;
            slot.custody().checked = end;
            return Ok(Building::Progress);
        }
        let built = copy_buffer::<String, A>(text, text_slot(slot), pending, a)?;
        // SAFETY: every byte was checked before the copy began, and the
        // buffer engine reports `Done` only once every byte is copied into
        // the text at the value's place (`StabilizedText` is transparent over
        // it), its phase `Complete`.
        Ok(unsafe { reported(built, assembly) })
    }
}

// SAFETY: references: a stabilized text's encoding is its text's
// (`Schema::instruction` delegates to the `str`), immutable storage held by
// its root, as a `String`'s is. cursors: none, no instruction is `Entries`.
// recursion: none, no instruction is a child.
unsafe impl crate::bounded::encoding::TransferableSchema for StabilizedText {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounded::{Limits, Reservation};

    /// A stabilized text costs its `String` and its check: per byte, every
    /// byte inspected once more and a window's value per 61 bytes, at
    /// `ceil(64 / 61) = 2` sixty-fourths, holding nothing more; fixed, the
    /// last window's value.
    #[test]
    fn a_stabilized_texts_cost_is_its_texts_and_one_inspection_per_byte() {
        assert_eq!(CHECKED, 61);
        let text = <String as InPlace<Limits>>::COST;
        let cost = stabilized_cost::<Reservation>().expect("the cost fits in u64");
        assert_eq!(cost, <StabilizedText as InPlace<Limits>>::COST);
        assert_eq!(
            cost.per_byte,
            ResourceBound {
                values: text.per_byte.values + 2,
                bytes: text.per_byte.bytes + 64,
                ..text.per_byte
            }
        );
        assert_eq!(
            cost.fixed,
            ResourceBound {
                values: text.fixed.values + 1,
                ..text.fixed
            }
        );
    }
}
