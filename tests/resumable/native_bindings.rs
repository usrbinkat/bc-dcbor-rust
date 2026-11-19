//! The retained production operations the suite drives, each constructed
//! under the suite's options; the shared driver exercised on the two
//! allocation-free cursors; and one deliberately non-compliant operation or
//! step per contract check, proving each check rejects what it guards.
use super::harness::*;
use super::support::{
    Finding, Labelled, Retirement, Stopped, checked, contracted, label, pipeline,
    pipeline::Refusal, refuse,
};
use core::cmp::Ordering;
use dcbor::bounded::decode::{
    Options, comparison::KeyComparison, cursor::Decoder, header::HeaderCursor,
    string_cursor::StringDecoder,
};
use dcbor::bounded::{
    BoundedError, Budget, Family, Resumable, Step, WriteWork, text_cursor::TextEncoder,
};

/// Strict decoding of `input` under a nesting limit of 16, its held credit
/// settling into a [`Family`] of the suite's policy.
pub fn decoder(input: &[u8]) -> Decoder<'_, Reservation, Family> {
    Decoder::new(input, Options::normalizing(16))
}

/// Owned string construction from `input` under a nesting limit of 16, its
/// held credit settling into a [`Family`] of the suite's policy.
pub fn string_decoder(input: &[u8]) -> StringDecoder<'_, Reservation, Family> {
    StringDecoder::new(input, Options::normalizing(16))
}

/// Canonical text encoding of `source`, its held credit settling into a
/// [`Family`] of the suite's policy.
pub fn text_encoder(source: &str) -> TextEncoder<'_, Reservation, Family> {
    TextEncoder::new(source)
}

#[test]
fn shared_driver_resumes_a_real_header_cursor_with_production_offsets() {
    let wire = [0x19, 0x01, 0x00];
    suite(|run, policy| {
        run.holding(
            HeaderCursor::new(&wire),
            Retirement::Exhausted,
            &pipeline::Unwitnessed,
            |cursor| {
                cursor.with_policy(policy, |cursor, m| {
                    refuse(m, Refusal::For(0, LimitRefusal::Work));
                    assert_eq!(cursor.acquired(), 0);
                    let index = super::support::suspend_within(
                        m,
                        cursor,
                        LimitRefusal::Work,
                        decode_turns(wire.len()),
                        super::support::TurnSchedule::Retained,
                    )?;
                    assert_eq!(index, 0);
                    m.fail_call(None);
                    Ok::<_, Finding>(())
                })?;
                let mut acquired = 0;
                cursor.drive_observed(
                    policy,
                    decode_turns(wire.len()),
                    Retirement::Exhausted,
                    |_, cursor| {
                        acquired = cursor.acquired();
                    },
                    |header| {
                        assert_eq!(header.value().argument, 256);
                        assert_eq!(header.value().length, 3);
                        header.with_policy(policy, |_, m| {
                            assert_eq!(m.used(), WriteWork::new(4, 6));
                            assert_eq!(m.calls().len(), 5);
                            m.assert_units(TURN);
                            assert_eq!(m.live_bytes(), 0);
                        });
                    },
                )?;
                assert_eq!(acquired, 3);
                Ok(())
            },
        )
    });
}

#[test]
fn shared_driver_resumes_comparison_without_reexamining_its_prefix() {
    let left = [b'a'; 257];
    let mut right = left;
    right[256] = b'b';
    suite(|run, policy| {
        run.holding(
            KeyComparison::new(&left, &right),
            Retirement::Exhausted,
            &pipeline::Unwitnessed,
            |comparison| {
                let remaining = comparison.with_policy(policy, |comparison, m| {
                    assert_eq!(contracted(m, comparison).unwrap(), Step::Progress);
                    assert_eq!(KeyComparison::position(comparison), 64);
                    refuse(m, Refusal::For(1, LimitRefusal::Work));
                    // The remaining pairs complete in one turn per 64 pairs, no more.
                    let remaining = left.len() - KeyComparison::position(comparison);
                    let index = super::support::suspend_within(
                        m,
                        comparison,
                        LimitRefusal::Work,
                        remaining.div_ceil(64),
                        super::support::TurnSchedule::Retained,
                    )?;
                    assert_eq!(index, 1);
                    m.fail_call(None);
                    Ok::<_, Finding>(remaining)
                })?;
                let mut position = 0;
                comparison.drive_observed(
                    policy,
                    remaining.div_ceil(64),
                    Retirement::Exhausted,
                    |_, comparison| {
                        position = KeyComparison::position(comparison);
                    },
                    |ordering| {
                        assert_eq!(*ordering.value(), Ordering::Less);
                        ordering.with_policy(policy, |_, m| {
                            assert_eq!(m.used(), WriteWork::new(5, 257));
                            assert_eq!(m.calls().len(), 6);
                            m.assert_units(TURN);
                            assert_eq!(m.live_bytes(), 0);
                        });
                    },
                )?;
                assert_eq!(position, 257);
                Ok(())
            },
        )
    });
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

impl dcbor::bounded::Custodial<Reservation> for Breaks {
    fn observe_custody(
        &mut self,
        _: &mut dyn dcbor::bounded::CustodySink<Reservation>,
    ) -> dcbor::bounded::PermitsObserved {
        dcbor::bounded::PermitsObserved::Complete
    }
}

super::support::terminal!(Exhausted: [] Breaks);

impl Resumable<Limits> for Breaks {
    type Output = ();
    type Error = BoundedError<LimitRefusal>;
    type Position = usize;

    fn step(&mut self, m: &mut Limits) -> Result<Step<()>, Self::Error> {
        self.steps += 1;
        match self.rule {
            Rule::ProgressWithoutAdmission => Ok(Step::Progress),
            Rule::RefusalMovesPosition => {
                self.position += 1;
                dcbor::bounded::decode::construction::in_place::step(m)?;
                Ok(Step::Progress)
            }
            Rule::AdmitsAfterCompletion => {
                dcbor::bounded::decode::construction::in_place::step(m)?;
                self.position += 1;
                Ok(if self.steps == 1 {
                    Step::Complete(())
                } else {
                    Step::Finished
                })
            }
            Rule::ProgressAfterCompletion => {
                if self.steps == 1 {
                    dcbor::bounded::decode::construction::in_place::step(m)?;
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
    let outcome = suite(|run, policy| {
        Ok(run.with_policy(policy, |m| {
            contracted(m, &mut Breaks::new(Rule::ProgressWithoutAdmission))
        }))
    });
    unreachable!("the contract check accepted {}", label(&outcome));
}

#[test]
#[should_panic(expected = "a step whose only admission was refused moved the operation")]
fn contract_check_rejects_a_refused_step_that_moves_the_operation() {
    let outcome = suite(|run, policy| {
        Ok(run.with_policy(policy, |m| {
            refuse(m, Refusal::For(0, LimitRefusal::Work));
            contracted(m, &mut Breaks::new(Rule::RefusalMovesPosition))
        }))
    });
    unreachable!("the contract check accepted {}", label(&outcome));
}

/// The terminal probe after a publication ([`super::support::exhausted`]),
/// broken by `rule`: the drive returns the violation as its stop, the
/// published output kept in it, naming `report`, never a panic that would
/// drop the output in an unwinding frame.
fn publication_probe_reports(rule: Rule, report: &str) {
    suite(|run, policy| {
        let stopped = run.holding(
            Breaks::new(rule),
            Retirement::Exhausted,
            &pipeline::Unwitnessed,
            |operation| {
                operation.drive(policy, super::support::TURNS, Retirement::Exhausted, |_| ())
            },
        );
        match stopped {
            Err(Stopped::Violated {
                output: Some(()),
                outcome: Some(terminal),
                report: found,
                lost: None,
                ..
            }) if found.contains(report)
                && matches!(
                    (rule, terminal.label().as_str()),
                    (Rule::AdmitsAfterCompletion, "Finished")
                        | (Rule::ProgressAfterCompletion, "Progress")
                ) =>
            {
                Ok(())
            }
            other => Err(Finding::Defect(format!(
                "the terminal probe did not report {report:?}: {other:?}"
            ))),
        }
    });
}

#[test]
fn contract_check_rejects_admission_after_publication() {
    publication_probe_reports(
        Rule::AdmitsAfterCompletion,
        "a finished operation admitted work",
    );
}

#[test]
fn contract_check_rejects_progress_after_publication() {
    publication_probe_reports(
        Rule::ProgressAfterCompletion,
        "a finished operation stepped to Progress",
    );
}

#[test]
#[should_panic(expected = "turn exceeded its quantum")]
#[expect(
    clippy::disallowed_methods,
    reason = "work beyond one quantum admitted straight to the policy, which the turn \
              check must reject"
)]
fn turn_check_rejects_work_beyond_one_quantum() {
    let outcome = suite(|run, policy| {
        Ok(run.with_policy(policy, |m| {
            checked(m, |m| {
                // Lift the turn's allowance from inside the step, as a policy
                // that failed to enforce its quantum would.
                m.open();
                m.traverse(TURN.values + 1, 0).unwrap();
                Step::<()>::Progress
            })
        }))
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
    let outcome = suite(|run, policy| {
        Ok(run.with_policy(policy, |m| {
            m.traverse(1, 0).unwrap();
            checked(m, |m| {
                // Forgetting the unit paid before this turn is a refund.
                m.measure();
                Step::<()>::Progress
            })
        }))
    });
    unreachable!("the turn check accepted {outcome:?}");
}
