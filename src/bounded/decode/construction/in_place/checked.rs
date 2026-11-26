//! A checked text's construction ([`CheckedText`]: [`StabilizedText`],
//! [`AsciiText`]): the decoded text checked against the type's rule, in
//! windows of at most a quantum, each admitted before it is inspected; then
//! the text built and reclaimed exactly as a `String` is, at the value's own
//! place. One engine: each type states its rule and its wire profile, and
//! its `Reclaim` and `InPlace` delegate here.
//!
//! dCBOR's decoder has already refused a text not in NFC before any binding
//! sees it, so the check adds only the type's rule: a text the rule refuses
//! is invalid input (the rule's [`crate::Error`]), found before the binding
//! allocates anything of its own (the document it reads is already parsed
//! and held by its caller).
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
use crate::bounded::Capped;
use crate::bounded::boundary::{Bound, Predicate, boundary};
use crate::bounded::decode::DecodeError;
use crate::bounded::decode::construction::reclamation::{Custody, Mode, Reduction, Uniform};
use crate::bounded::decode::construction::stable;
use crate::{AsciiText, StabilizedText};
use alloc::string::String;

/// A refinement of dCBOR text decoded by this engine: a type whose values
/// are the NFC texts its rule does not refuse.
///
/// # Safety
///
/// The type is `#[repr(transparent)]` over a `String`: its text lies at the
/// value's own place (`text_slot`), and a value whose text the engine built
/// is a valid value of the type once every byte of it passed
/// [`Self::refused`]. `refused` inspects each byte of its window a constant
/// number of times, allocates nothing and does not unwind: the check's cost
/// ([`checked_cost`]) is one inspection per byte.
pub(crate) unsafe trait CheckedText: Sized {
    /// The rule's refusal of the first code point of `window` it refuses,
    /// if any. `window` is a whole number of scalars of a text in NFC.
    fn refused(window: &str) -> Option<crate::Error>;
}

// SAFETY: `StabilizedText` is `#[repr(transparent)]` over its `String`;
// `first_unassigned` is one binary search of a constant table per scalar,
// allocation-free and non-unwinding.
unsafe impl CheckedText for StabilizedText {
    fn refused(window: &str) -> Option<crate::Error> {
        crate::stabilized_text::first_unassigned(window)
            .map(|c| crate::Error::UnassignedCodePoint(u32::from(c)))
    }
}

// SAFETY: `AsciiText` is `#[repr(transparent)]` over its `String`;
// `first_non_ascii` compares each scalar once, allocation-free and
// non-unwinding.
unsafe impl CheckedText for AsciiText {
    fn refused(window: &str) -> Option<crate::Error> {
        crate::ascii_text::first_non_ascii(window).map(|c| crate::Error::NonAsciiText(u32::from(c)))
    }
}

/// Checking a window of the decoded text: one value and at most a quantum,
/// every byte of the window inspected once.
const CHECK: Capped<Caller> = Capped::new(Caller, 1, stable::QUANTUM as u64);

/// The bytes every window but the last covers at least
/// ([`text::scalar_window`]).
const CHECKED: u64 = text::scalar_window(CHECK.cap());

/// A checked text's construction state: the bytes of the decoded text
/// checked so far, then the `String` it is built as. Checking completes
/// before the text's construction begins, and its count never changes once
/// it covers the text.
pub struct CheckedState<P> {
    checked: usize,
    text: BufferState<P>,
}

impl<P> CheckedState<P> {
    /// Nothing checked and the text's initial buffer state.
    const INITIAL: Self = Self {
        checked: 0,
        text: BufferState::INITIAL,
    };
}

/// What a checked text's construction holds: the bytes checked, and the
/// text's own custody.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CheckedObservation {
    pub checked: usize,
    pub text: BufferObservation,
}

impl<P> Custody for CheckedState<P> {
    type Observation = CheckedObservation;

    fn observe(&mut self) -> CheckedObservation {
        CheckedObservation {
            checked: self.checked,
            text: self.text.observe(),
        }
    }
}

// Cleanup is the text's alone (`reclaim_buffer` over `text`): the bytes
// checked are read by no cleanup unit, acquire nothing and release nothing.
// So the text's own reduction, applied to its observation, is a simulation
// of this state's cleanup.
impl<P> Reduction for CheckedState<P> {
    type Class = BufferClass;

    fn class(observation: &CheckedObservation) -> BufferClass {
        <BufferState<P> as Reduction>::class(&observation.text)
    }
}

// Construction reports `Done` only when the text's own construction does, a
// `String` complete, so its class is the text's complete class.
impl<P> Uniform for CheckedState<P> {
    const COMPLETE: BufferClass = <BufferState<P> as Uniform>::COMPLETE;
}

/// The text inside a checked text's slot, with its own state.
fn text_slot<'c, T: CheckedText, M: Mode, P>(
    slot: Slot<'c, T, CheckedState<P>, M>,
) -> Slot<'c, String, BufferState<P>, M> {
    // SAFETY: `T` is transparent over its `String` (`CheckedText`), so the
    // text lies at the value's own place, reached by a cast alone; the
    // text's state is its own custody, the state's `text` field.
    unsafe { slot.child(|value| value.cast::<String>(), |state| &mut state.text) }
}

/// A checked text's cleanup step: the text's ([`reclaim_buffer`]).
fn reclaim_checked<T: CheckedText, A: Allocator>(
    slot: Slot<'_, T, CheckedState<A::Permit>>,
    cleanup: &mut Cleanup<'_, A>,
) -> BoundedResult<Reclaimed, A> {
    reclaim_buffer::<String, A>(text_slot(slot), cleanup)
}

/// The cost of a checked text: the text's ([`buffer_cost`]), and the check
/// before it. Fixed: the last window's value. Per byte: every byte
/// inspected once, and every window but the last covering at least
/// [`CHECKED`] bytes, so its values are at most `PER_BYTE_SCALE / CHECKED`
/// sixty-fourths per byte, rounded up. The check holds nothing.
pub(crate) const fn checked_cost<P>() -> Option<ConstructionCost> {
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

/// Check the next window of `source`, from byte `start`, against `T`'s
/// rule: at most a quantum, ending on a scalar, admitted before any byte of
/// it is inspected. Its end, or the rule's refusal of the first code point
/// it refuses within it.
fn check_window<T: CheckedText, A: Allocator>(
    source: &str,
    start: usize,
    a: &mut A,
) -> ConstructResult<usize, A> {
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
    match T::refused(&source[start..end]) {
        Some(refusal) => Err(DecodeError::Invalid(refusal)),
        None => Ok(end),
    }
}

/// A checked text's construction step: the next window checked, or, once
/// every byte is, the text copied ([`copy_buffer`]).
///
/// Every window checked and every byte copied come from the context's one
/// node: the engine hands the binding only its own context, and the session
/// refuses another node, so the text checked is the text copied.
fn build_checked<'b, T, A>(
    ctx: BindingContext<'b, '_, '_, '_, T, A>,
    a: &mut A,
) -> ConstructResult<Building<'b, T>, A>
where
    T: CheckedText + Reclaim<A, State = CheckedState<A::Permit>>,
    A: Allocator,
{
    let Some(Kind::Text(text)) = ctx.node().map(|n| n.kind()) else {
        return rejected(a);
    };
    let assembly = ctx.assembly();
    let (mut slot, pending) = ctx.into_acquiring();
    let checked = slot.custody().checked;
    if checked != text.len() {
        let end = check_window::<T, A>(text, checked, a)?;
        slot.custody().checked = end;
        return Ok(Building::Progress);
    }
    let built = copy_buffer::<String, A>(text, text_slot(slot), pending, a)?;
    // SAFETY: every byte was checked by `T`'s rule before the copy began,
    // and the buffer engine reports `Done` only once every byte is copied
    // into the text at the value's place (`T` is transparent over it), its
    // phase `Complete`.
    Ok(unsafe { reported(built, assembly) })
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
    type State = CheckedState<A::Permit>;
    const INITIAL: Self::State = CheckedState::INITIAL;

    fn reclaim_step(
        slot: Slot<'_, Self, Self::State>,
        cleanup: &mut Cleanup<'_, A>,
    ) -> BoundedResult<Reclaimed, A> {
        reclaim_checked(slot, cleanup)
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

// SAFETY: the engine's, as `StabilizedText`'s above. initial: nothing
// checked and the text's initial buffer state. state: `checked` and the
// text's buffer state record everything; the bytes checked hold nothing.
// admission, cleanup, done and order: every unit is the text's
// (`reclaim_buffer`) at the text's own slot (`text_slot`): admission: each
// admitted before it runs, a refusal changing nothing. cleanup: a byte
// buffer's, freeing bytes with no element destructor, allocating nothing,
// never unwinding. done: `Done` once its buffer and permits are released.
// order: a step after `Done` reports `Done`; the count and observation read
// the state alone. depth: a leaf, the default 1. count: `buffer_remaining`
// of the text.
unsafe impl<A: Allocator> Reclaim<A> for AsciiText {
    type State = CheckedState<A::Permit>;
    const INITIAL: Self::State = CheckedState::INITIAL;

    fn reclaim_step(
        slot: Slot<'_, Self, Self::State>,
        cleanup: &mut Cleanup<'_, A>,
    ) -> BoundedResult<Reclaimed, A> {
        reclaim_checked(slot, cleanup)
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
// unit. cost: `checked_cost`, the text's and the check's.
unsafe impl<A: Allocator> InPlace<A> for StabilizedText {
    const COST: ConstructionCost = crate::const_cost!(checked_cost::<A::Permit>());
    /// Any NFC text may be stabilized: strict validation.
    const WIRE: crate::bounded::decode::Options = crate::bounded::decode::Options::TEXT;

    fn build_step<'b>(
        ctx: BindingContext<'b, '_, '_, '_, Self, A>,
        a: &mut A,
    ) -> ConstructResult<Building<'b, Self>, A> {
        build_checked(ctx, a)
    }
}

// SAFETY: the engine's (`build_checked`), as `StabilizedText`'s above; only
// the rule (`CheckedText::refused`) and the wire profile differ. admission:
// each window is admitted (`CHECK`) before any byte of it is inspected, then
// `copy_buffer` admits each phase first. state: checking writes nothing and
// acquires nothing; a refused or rejected window leaves the state as it
// was, and `checked` is recorded before the step returns; every phase of the
// text is the text's state, which cleanup reclaims. done: `Done` only once
// every byte is checked and copied. escape: the text's byte vector stays in
// its header. provenance: the text is built at the value's place, its own by
// the transparent representation (`text_slot`). order: a window off a
// boundary or past the text is refused `PlanMismatch`, and the copy refuses
// a phase it does not continue; a node not a text is refused by one admitted
// unit. cost: `checked_cost`, the text's and the check's.
unsafe impl<A: Allocator> InPlace<A> for AsciiText {
    const COST: ConstructionCost = crate::const_cost!(checked_cost::<A::Permit>());
    /// Every ASCII text is proven NFC by the quick check, so a text the
    /// quick check does not prove is no ASCII text: refused before any
    /// normalization runs ([`crate::bounded::decode::TextPolicy::QuickOnly`]).
    const WIRE: crate::bounded::decode::Options = crate::bounded::decode::Options::quick_only(0);

    fn build_step<'b>(
        ctx: BindingContext<'b, '_, '_, '_, Self, A>,
        a: &mut A,
    ) -> ConstructResult<Building<'b, Self>, A> {
        build_checked(ctx, a)
    }
}

// SAFETY: resources: an empty text owns no allocation, so dropping it frees
// nothing; it is stabilized, holding no code point. bounded: `String::new`
// allocates nothing and writes a fixed-size header.
unsafe impl Placeholder for StabilizedText {
    fn placeholder() -> Self {
        Self::empty()
    }
}

// SAFETY: resources: an empty text owns no allocation, so dropping it frees
// nothing; it is ASCII, holding no code point. bounded: `String::new`
// allocates nothing and writes a fixed-size header.
unsafe impl Placeholder for AsciiText {
    fn placeholder() -> Self {
        Self::empty()
    }
}

// SAFETY: references: a checked text's encoding is its text's
// (`Schema::instruction` delegates to the `str`), immutable storage held by
// its root, as a `String`'s is. cursors: none, no instruction is `Entries`.
// recursion: none, no instruction is a child.
unsafe impl crate::bounded::encoding::TransferableSchema for StabilizedText {}

// SAFETY: references: an ASCII text's encoding is its text's
// (`Schema::instruction` delegates to the `str`), immutable storage held by
// its root, as a `String`'s is. cursors: none, no instruction is `Entries`.
// recursion: none, no instruction is a child.
unsafe impl crate::bounded::encoding::TransferableSchema for AsciiText {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounded::{Limits, Reservation};

    /// A checked text costs its `String` and its check: per byte, every
    /// byte inspected once more and a window's value per 61 bytes, at
    /// `ceil(64 / 61) = 2` sixty-fourths, holding nothing more; fixed, the
    /// last window's value. Both rules declare the engine's one cost.
    #[test]
    fn a_checked_texts_cost_is_its_texts_and_one_inspection_per_byte() {
        assert_eq!(CHECKED, 61);
        let text = <String as InPlace<Limits>>::COST;
        let cost = checked_cost::<Reservation>().expect("the cost fits in u64");
        assert_eq!(cost, <StabilizedText as InPlace<Limits>>::COST);
        assert_eq!(cost, <AsciiText as InPlace<Limits>>::COST);
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

    /// Each rule refuses what its type excludes and names it, and accepts
    /// what its type holds.
    #[test]
    fn each_rule_refuses_what_its_type_excludes() {
        assert!(<AsciiText as CheckedText>::refused("id-7\u{7F}").is_none());
        assert!(matches!(
            <AsciiText as CheckedText>::refused("a\u{80}"),
            Some(crate::Error::NonAsciiText(0x80))
        ));
        assert!(<StabilizedText as CheckedText>::refused("\u{E9}").is_none());
        assert!(matches!(
            <StabilizedText as CheckedText>::refused("a\u{378}"),
            Some(crate::Error::UnassignedCodePoint(0x378))
        ));
    }

    /// The wire profiles differ as the rules do: U+0301 alone is NFC text
    /// the quick check cannot prove (`NFC_Quick_Check=Maybe`), so a
    /// `String` and a stabilized text normalize to prove it and accept it,
    /// while an ASCII text's quick-only profile refuses it before any
    /// normalization or binding runs; a quick-proven non-ASCII text reaches
    /// the ASCII rule, which refuses it.
    #[test]
    fn an_ascii_text_decodes_quick_only() {
        use crate::bounded::decode::{DecodeError, decode_typed};
        let unproven = crate::CBOR::from("\u{301}").to_cbor_data();
        assert!(decode_typed::<String, _>(&unproven, &mut Limits::unlimited()).is_ok());
        assert!(decode_typed::<StabilizedText, _>(&unproven, &mut Limits::unlimited()).is_ok());
        assert!(
            matches!(
                decode_typed::<AsciiText, _>(&unproven, &mut Limits::unlimited()).map(|_| ()),
                Err(DecodeError::UnprovenText)
            ),
            "an unproven text reached an ASCII text's binding"
        );
        let proven = crate::CBOR::from("\u{e9}").to_cbor_data();
        assert!(matches!(
            decode_typed::<AsciiText, _>(&proven, &mut Limits::unlimited()).map(|_| ()),
            Err(DecodeError::Invalid(crate::Error::NonAsciiText(0xE9)))
        ));
        let ascii = crate::CBOR::from("kappa").to_cbor_data();
        let decoded = decode_typed::<AsciiText, _>(&ascii, &mut Limits::unlimited())
            .expect("an ASCII text decodes");
        assert_eq!(decoded.value().as_str(), "kappa");
    }

    /// The placeholders are valid values: an empty text of each type.
    #[test]
    fn each_placeholder_is_the_empty_text() {
        assert_eq!(StabilizedText::placeholder().as_str(), "");
        assert_eq!(AsciiText::placeholder().as_str(), "");
    }
}
