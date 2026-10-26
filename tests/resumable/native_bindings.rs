//! The retained production operations the suite drives, each constructed
//! under the suite's options; the shared driver exercised on the two
//! allocation-free cursors; and one deliberately non-compliant operation or
//! step per contract check, proving each check rejects what it guards.
use super::harness::*;
use super::support::{checked, contracted, drive, label, pipeline::Refusal, refuse, resume_within};
use core::cmp::Ordering;
use dcbor::bounded::decode::{
    Options, comparison::KeyComparison, cursor::Decoder, header::HeaderCursor,
    string_cursor::StringDecoder,
};
use dcbor::bounded::{BoundedError, Budget, Resumable, Step, WriteWork, text_cursor::TextEncoder};

/// Strict decoding of `input` under a nesting limit of 16.
pub fn decoder(input: &[u8]) -> Decoder<'_, Reservation> {
    Decoder::new(input, Options::normalizing(16))
}

/// Owned string construction from `input` under a nesting limit of 16.
pub fn string_decoder(input: &[u8]) -> StringDecoder<'_, Reservation> {
    StringDecoder::new(input, Options::normalizing(16))
}

/// Canonical text encoding of `source`.
pub fn text_encoder(source: &str) -> TextEncoder<'_, Reservation> {
    TextEncoder::new(source)
}

#[test]
fn shared_driver_resumes_a_real_header_cursor_with_production_offsets() {
    let wire = [0x19, 0x01, 0x00];
    let mut m = meter();
    refuse(&mut m, Refusal::For(0, LimitRefusal::Work));
    let pool = m.share();
    let mut cursor = HeaderCursor::new(&wire);
    assert_eq!(cursor.acquired(), 0);
    let (index, header) = resume_within(
        &mut m,
        &mut cursor,
        LimitRefusal::Work,
        decode_turns(wire.len()),
    );
    assert_eq!(index, 0);
    assert_eq!(header.argument, 256);
    assert_eq!(header.length, 3);
    assert_eq!(cursor.acquired(), 3);
    assert_eq!(m.used(), WriteWork::new(4, 6));
    assert_eq!(m.calls().len(), 5);
    m.assert_units(TURN);
    // The cursor owns no storage and has no destructor; nothing is held.
    assert_eq!(pool.live_bytes(), 0);
}

#[test]
fn shared_driver_resumes_comparison_without_reexamining_its_prefix() {
    let left = [b'a'; 257];
    let mut right = left;
    right[256] = b'b';
    let mut m = meter();
    let pool = m.share();
    let mut comparison = KeyComparison::new(&left, &right);
    assert_eq!(contracted(&mut m, &mut comparison).unwrap(), Step::Progress);
    assert_eq!(comparison.position(), 64);
    refuse(&mut m, Refusal::For(1, LimitRefusal::Work));
    // The remaining pairs complete in one turn per 64 pairs, no more.
    let remaining = left.len() - comparison.position();
    let (index, ordering) = resume_within(
        &mut m,
        &mut comparison,
        LimitRefusal::Work,
        remaining.div_ceil(64),
    );
    assert_eq!(index, 1);
    assert_eq!(ordering, Ordering::Less);
    assert_eq!(comparison.position(), 257);
    assert_eq!(m.used(), WriteWork::new(5, 257));
    assert_eq!(m.calls().len(), 6);
    m.assert_units(TURN);
    // The comparison owns no storage and has no destructor; nothing is held.
    assert_eq!(pool.live_bytes(), 0);
}

/// The contract rule a [`Breaks`] operation violates.
#[derive(Clone, Copy)]
enum Rule {
    /// Reports progress without admitting anything.
    ProgressWithoutAdmission,
    /// Moves its position before its only admission is refused.
    RefusalMovesPosition,
    /// Admits work after it has published.
    AdmitsAfterCompletion,
    /// Reports progress after it has published.
    ProgressAfterCompletion,
}

/// An operation that keeps the contract except for one `rule`.
struct Breaks {
    rule: Rule,
    steps: usize,
    position: usize,
}

impl Breaks {
    fn new(rule: Rule) -> Self {
        Self {
            rule,
            steps: 0,
            position: 0,
        }
    }
}

impl Resumable<Limits> for Breaks {
    type Output = ();
    type Error = BoundedError<LimitRefusal>;
    type Position = usize;

    #[expect(
        clippy::disallowed_methods,
        reason = "a third-party operation admitting its own work, as `Resumable` documents, \
                  each breaking one contract rule"
    )]
    fn step(&mut self, m: &mut Limits) -> Result<Step<()>, Self::Error> {
        self.steps += 1;
        match self.rule {
            Rule::ProgressWithoutAdmission => Ok(Step::Progress),
            Rule::RefusalMovesPosition => {
                self.position += 1;
                m.traverse(1, 0).map_err(BoundedError::Refused)?;
                Ok(Step::Progress)
            }
            Rule::AdmitsAfterCompletion => {
                m.traverse(1, 0).map_err(BoundedError::Refused)?;
                self.position += 1;
                Ok(if self.steps == 1 {
                    Step::Complete(())
                } else {
                    Step::Finished
                })
            }
            Rule::ProgressAfterCompletion => {
                if self.steps == 1 {
                    m.traverse(1, 0).map_err(BoundedError::Refused)?;
                    self.position += 1;
                    Ok(Step::Complete(()))
                } else {
                    Ok(Step::Progress)
                }
            }
        }
    }

    fn position(&mut self) -> usize {
        self.position
    }
}

// Each check must reject its violation. Reaching the `unreachable!` means the
// check accepted it; that panic's message differs from the expected one, so
// the test fails and reports what was accepted.

#[test]
#[should_panic(expected = "progress without an admission")]
fn contract_check_rejects_progress_without_an_admission() {
    let outcome = contracted(
        &mut meter(),
        &mut Breaks::new(Rule::ProgressWithoutAdmission),
    );
    unreachable!("the contract check accepted {}", label(&outcome));
}

#[test]
#[should_panic(expected = "a step whose only admission was refused moved the operation")]
fn contract_check_rejects_a_refused_step_that_moves_the_operation() {
    let mut m = meter();
    refuse(&mut m, Refusal::For(0, LimitRefusal::Work));
    let outcome = contracted(&mut m, &mut Breaks::new(Rule::RefusalMovesPosition));
    unreachable!("the contract check accepted {}", label(&outcome));
}

#[test]
#[should_panic(expected = "a finished operation admitted work")]
fn contract_check_rejects_admission_after_publication() {
    let outcome = drive(&mut meter(), &mut Breaks::new(Rule::AdmitsAfterCompletion));
    unreachable!("the contract check accepted {outcome:?}");
}

#[test]
#[should_panic(expected = "a finished operation stepped to Progress")]
fn contract_check_rejects_progress_after_publication() {
    let outcome = drive(
        &mut meter(),
        &mut Breaks::new(Rule::ProgressAfterCompletion),
    );
    unreachable!("the contract check accepted {outcome:?}");
}

#[test]
#[should_panic(expected = "turn exceeded its quantum")]
#[expect(
    clippy::disallowed_methods,
    reason = "work beyond one quantum admitted straight to the policy, which the turn \
              check must reject"
)]
fn turn_check_rejects_work_beyond_one_quantum() {
    let mut m = meter();
    let outcome = checked(&mut m, |m| {
        // Lift the turn's allowance from inside the step, as a policy that
        // failed to enforce its quantum would.
        m.open();
        m.traverse(TURN.values + 1, 0).unwrap();
        Step::<()>::Progress
    });
    unreachable!("the turn check accepted {outcome:?}");
}

#[test]
#[should_panic(expected = "admitted work refunded")]
#[expect(
    clippy::disallowed_methods,
    reason = "work admitted straight to the policy before a turn, then refunded, which the \
              turn check must reject"
)]
fn turn_check_rejects_refunded_work() {
    let mut m = meter();
    m.traverse(1, 0).unwrap();
    let outcome = checked(&mut m, |m| {
        // Forgetting the unit paid before this turn is a refund.
        m.measure();
        Step::<()>::Progress
    });
    unreachable!("the turn check accepted {outcome:?}");
}
