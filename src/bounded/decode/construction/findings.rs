//! The conclusion of a construction unit test that records sessions of its
//! own. A planted control's detecting assertion must not end the test before
//! the test drops what it holds and finishes every session it made: each
//! check is kept as a finding instead ([`Findings::check`]), the test drops
//! its custody, hands its recorded policies over, each read against its
//! recorded history and dropped ([`Findings::policies`]), through the one
//! comparison every recorded run uses (`dcbor_test_support::history_agrees`,
//! given plain counts), finishes its sessions, and only then concludes
//! ([`Findings::conclude`]), naming for each session what it must finish as
//! ([`Expected`]). Every session is held to its expectation whether or not
//! a finding was kept, and every complete stream is refined by the one
//! checker every recorded run's finalization uses
//! (`dcbor_test_support::refinement_of_words`): the stream crosses as each
//! observation's storage-form words ([`Observed::to_words`]), because the
//! checker links its own build of this crate. The test fails once, naming
//! every finding beside what each session finished as, and passes only
//! when no finding was kept, every session finished as expected, and every
//! complete stream refined the protocol. The integration suites'
//! counterpart is the recorded runner's finalization
//! (`dcbor_test_support::recorded_run`); this is the same authority for a
//! test inside the crate, whose sessions it holds itself.

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Debug;

use crate::bounded::{Answer, Call, HistoryCounts, Incomplete, Limits, Observed, Unreadable};

/// What a policy's history must read as ([`Limits::history`]): readable,
/// then held to the policy's own counters; or unreadable, for exactly the
/// reason named (its session's sticky invalidity, say). Mirrors
/// [`Expected`] for sessions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExpectedHistory {
    Readable,
    Unreadable(Unreadable),
}

/// What a session must finish as: complete evidence, whose stream is then
/// refined; or no evidence, for exactly the reason named (a refused
/// validation's sticky invalidity, say).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Expected {
    Complete,
    Incomplete(Incomplete),
}

/// One finished session as a test concludes it: its name in the report,
/// what it finished as, and what it must finish as.
pub(crate) type Concluded<'a> = (&'a str, &'a Result<Vec<Observed>, Incomplete>, Expected);

/// The findings a test has kept, in order.
#[derive(Default)]
pub(crate) struct Findings(Vec<String>);

impl Findings {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// `holds`, or `finding` kept: a fixed text or one formatted from the
    /// check's values, made only when it fails.
    pub(crate) fn check<F: Into<String>>(&mut self, holds: bool, finding: impl FnOnce() -> F) {
        if !holds {
            self.0.push(finding().into());
        }
    }

    /// `actual` equal to `expected`, or a finding naming `what` and both.
    pub(crate) fn equal<T: PartialEq + Debug>(&mut self, what: &str, actual: T, expected: T) {
        if actual != expected {
            self.0
                .push(format!("{what}: {actual:?}, expected {expected:?}"));
        }
    }

    /// Each of `policies`, by name, its history ([`Limits::history`]) and
    /// counters read before it is dropped here, held to what its history
    /// must read as: a readable history's counts ([`HistoryCounts::of`],
    /// their one derivation) compared with the policy's own counters by the
    /// one comparison every recorded run uses
    /// (`dcbor_test_support::history_agrees`); an unreadable one only for
    /// the reason declared. Every disagreement is kept as a finding. Every
    /// policy a test made is handed over here, after its custody is dropped
    /// and before its sessions are finished.
    pub(crate) fn policies<'a>(
        &mut self,
        policies: impl IntoIterator<Item = (&'a str, Limits, ExpectedHistory)>,
    ) {
        for (name, policy, expected) in policies {
            let counted = dcbor_test_support::Counted {
                attempts: policy.attempts(),
                refusals: policy.refusals(),
                injected: policy.injected_refusals(),
            };
            let history = policy.history();
            drop(policy);
            self.history(name, history, expected, counted);
        }
    }

    /// `history` held to `expected` and, read, to `counted`
    /// ([`Self::policies`]): a readable history is compared with the
    /// counters whatever was expected, and the readability's disagreement
    /// with `expected` is a finding of its own.
    fn history(
        &mut self,
        name: &str,
        history: Result<Vec<(Call, Answer)>, Unreadable>,
        expected: ExpectedHistory,
        counted: dcbor_test_support::Counted,
    ) {
        if let Ok(calls) = &history {
            let counts = HistoryCounts::of(calls);
            let recorded = dcbor_test_support::History {
                calls: counts.calls,
                admitted: counts.admitted,
                refusals: counts.refusals,
                injected: counts.injected,
            };
            if let Err(finding) = dcbor_test_support::history_agrees(recorded, counted) {
                self.0.push(format!("{name}: {finding}"));
            }
        }
        match (history, expected) {
            (Ok(_), ExpectedHistory::Readable) => {}
            (Ok(_), ExpectedHistory::Unreadable(reason)) => self.0.push(format!(
                "{name}: the policy's history is readable, expected unreadable: {reason:?}"
            )),
            (Err(Unreadable::Unrecorded), ExpectedHistory::Readable) => self
                .0
                .push(format!("{name}: the policy records no history")),
            (Err(actual), ExpectedHistory::Readable) => self.0.push(format!(
                "{name}: the policy's history cannot be read: {actual:?}"
            )),
            (Err(actual), ExpectedHistory::Unreadable(reason)) => {
                if actual != reason {
                    self.0.push(format!(
                        "{name}: the policy's history cannot be read: {actual:?}, expected \
                         unreadable: {reason:?}"
                    ));
                }
            }
        }
    }

    /// Hold each of `sessions` to its expectation ([`Self::session`]),
    /// whether or not a finding was kept, then fail naming every finding
    /// beside what each session finished as. Silent only when no finding
    /// was kept, no session finished other than expected, and every complete
    /// stream refined the protocol. The sessions are finished by the caller
    /// once everything holding them is dropped, so their results are the
    /// recording's own.
    pub(crate) fn conclude(mut self, sessions: &[Concluded<'_>]) {
        let outcomes: Vec<String> = sessions
            .iter()
            .map(|&(name, finished, expected)| self.session(name, finished, expected))
            .collect();
        if self.0.is_empty() {
            return;
        }
        panic!(
            "the test found {} finding(s): {}; sessions: {}",
            self.0.len(),
            self.0.join("; "),
            if outcomes.is_empty() {
                "none".to_string()
            } else {
                outcomes.join("; ")
            }
        );
    }

    /// One session held to `expected`, each disagreement kept as a finding:
    /// complete evidence where none was expected, no evidence where complete
    /// evidence was, or no evidence for another reason than the one named.
    /// A complete stream is refined whatever was expected ([`Self::refined`]),
    /// its refusal a finding of its own. Returns what the session finished
    /// as, for the report.
    fn session(
        &mut self,
        name: &str,
        finished: &Result<Vec<Observed>, Incomplete>,
        expected: Expected,
    ) -> String {
        match (finished, expected) {
            (Ok(observed), Expected::Complete) => self.refined(name, observed),
            (Ok(observed), Expected::Incomplete(reason)) => {
                let outcome = self.refined(name, observed);
                self.0.push(format!(
                    "{name}: finished complete, expected no evidence: {reason:?}"
                ));
                outcome
            }
            (Err(actual), Expected::Complete) => {
                self.0.push(format!(
                    "{name}: no evidence ({actual:?}), expected complete evidence"
                ));
                format!("{name} is no evidence: {actual:?}")
            }
            (Err(actual), Expected::Incomplete(reason)) => {
                if *actual != reason {
                    self.0.push(format!(
                        "{name}: no evidence ({actual:?}), expected no evidence: {reason:?}"
                    ));
                }
                format!("{name} is no evidence: {actual:?}")
            }
        }
    }

    /// `observed`, a complete stream, refined once by the one checker
    /// (`dcbor_test_support::refinement_of_words`), crossing as each
    /// observation's storage-form words: an observation with no storage
    /// form, or a stream the checker refuses, kept as a finding. Returns
    /// what the session finished as, for the report.
    fn refined(&mut self, name: &str, observed: &[Observed]) -> String {
        let words = observed
            .iter()
            .enumerate()
            .map(|(index, observation)| observation.to_words().ok_or(index))
            .collect::<Result<Vec<_>, usize>>();
        match words {
            Err(index) => {
                self.0.push(format!(
                    "{name}: observation {index} has no storage form: {:?}",
                    observed[index]
                ));
                format!("{name} finished complete, its stream not refinable")
            }
            Ok(words) => match dcbor_test_support::refinement_of_words(&words) {
                Ok(()) => format!(
                    "{name} finished complete with {} observations and refined the protocol",
                    observed.len()
                ),
                Err(finding) => {
                    self.0.push(format!("{name}: {finding}"));
                    format!("{name} finished complete and does not refine the protocol")
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounded::{Budget, Capacity, Limits, Session};

    /// A recording session of the default capacity.
    fn session() -> Session {
        Session::new(Capacity::DEFAULT)
    }

    /// A kept finding and a session its test left live (a policy of it
    /// still held when it is finished) are both named in the one failure,
    /// the finding never hiding the recording's refusal nor the refusal the
    /// finding. The failure is caught to read both from it, which needs
    /// `std`.
    #[cfg(feature = "std")]
    #[test]
    fn a_finding_is_reported_beside_a_session_left_live() {
        let s = session();
        let policy = Limits::recorded_unlimited(&s);
        let mut findings = Findings::new();
        findings.check(false, || "the planted finding");
        let finished = s.finish();
        let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            findings.conclude(&[("S", &finished, Expected::Complete)]);
        }))
        .expect_err("a test with a finding concluded silently");
        let message = failure
            .downcast_ref::<String>()
            .expect("the conclusion's failure is a formatted message");
        assert!(
            message.contains("the planted finding"),
            "the finding is missing from: {message}"
        );
        assert!(
            message.contains("S is no evidence: Live("),
            "the live session is missing from: {message}"
        );
        drop(policy);
    }

    /// The passing side: no finding kept, and a session whose policy made
    /// an owner and was dropped finishes complete and refines.
    #[test]
    fn a_complete_session_that_refines_concludes_silently() {
        let s = session();
        let mut policy = Limits::recorded_unlimited(&s);
        let owner = policy.owner().expect("a recorded owner");
        drop((owner, policy));
        let finished = s.finish();
        Findings::new().conclude(&[("S", &finished, Expected::Complete)]);
    }

    /// No finding kept, but a session expected complete is no evidence (a
    /// policy of it still held when it is finished): the conclusion fails
    /// on the session alone.
    #[test]
    #[should_panic(expected = "S: no evidence (Live(")]
    fn a_session_expected_complete_that_is_no_evidence_fails_without_findings() {
        let s = session();
        let policy = Limits::recorded_unlimited(&s);
        let finished = s.finish();
        let held = policy;
        Findings::new().conclude(&[("S", &finished, Expected::Complete)]);
        drop(held);
    }

    /// No finding kept, but a complete stream the checker refuses: a work
    /// call admitted by the policy with no admission through the route
    /// after it, refused at quiescence as `Rule::MissingAdmission`
    /// (tests/refinement/src/machine.rs:664-667, rendered by
    /// tests/refinement/src/model.rs:281-285). The conclusion fails on the
    /// refinement alone.
    #[test]
    #[should_panic(expected = "admitted without its admission")]
    #[expect(
        clippy::disallowed_methods,
        reason = "the deliberate unrouted call the refinement must refuse"
    )]
    fn a_complete_stream_that_does_not_refine_fails_without_findings() {
        let s = session();
        let mut policy = Limits::recorded_unlimited(&s);
        policy.traverse(1, 8).expect("an unlimited policy admits");
        drop(policy);
        let finished = s.finish();
        Findings::new().conclude(&[("S", &finished, Expected::Complete)]);
    }

    /// No finding kept, a session expected no evidence that finishes
    /// complete with a stream the checker refuses: its stream is refined
    /// all the same, so the conclusion names both the unexpected
    /// completeness and the refinement's refusal. The failure is caught to
    /// read both from it, which needs `std`.
    #[cfg(feature = "std")]
    #[test]
    #[expect(
        clippy::disallowed_methods,
        reason = "the deliberate unrouted call the refinement must refuse"
    )]
    fn an_unexpected_complete_stream_is_still_refined() {
        let s = session();
        let mut policy = Limits::recorded_unlimited(&s);
        policy.traverse(1, 8).expect("an unlimited policy admits");
        drop(policy);
        let finished = s.finish();
        let failure = std::panic::catch_unwind(|| {
            Findings::new().conclude(&[(
                "S",
                &finished,
                Expected::Incomplete(Incomplete::Exhausted),
            )]);
        })
        .expect_err("an unexpected complete session concluded silently");
        let message = failure
            .downcast_ref::<String>()
            .expect("the conclusion's failure is a formatted message");
        assert!(
            message.contains("S: finished complete, expected no evidence: Exhausted"),
            "the unexpected completeness is missing from: {message}"
        );
        assert!(
            message.contains("admitted without its admission"),
            "the refinement's refusal is missing from: {message}"
        );
    }

    /// A policy declared unreadable whose history is readable, and
    /// disagrees with its counters: both are named, the history compared
    /// whatever was declared, and nothing else is kept.
    #[test]
    fn a_readable_history_declared_unreadable_is_still_compared() {
        let mut findings = Findings::new();
        findings.history(
            "P",
            Ok(Vec::from([(Call::Allocate(8), Answer::Admitted)])),
            ExpectedHistory::Unreadable(Unreadable::Session(Incomplete::Exhausted)),
            dcbor_test_support::Counted {
                attempts: 0,
                refusals: 0,
                injected: 0,
            },
        );
        assert_eq!(findings.0.len(), 2, "{:?}", findings.0);
        assert!(
            findings.0[0].starts_with("P: the recording holds 1 attempts"),
            "{:?}",
            findings.0
        );
        assert_eq!(
            findings.0[1],
            "P: the policy's history is readable, expected unreadable: Session(Exhausted)"
        );
    }

    /// A session with no event slot, invalidated by its first publication
    /// (an owner minted), concludes silently when expected exhausted, and
    /// fails when expected complete or no evidence for another reason.
    #[test]
    fn an_exhausted_session_is_held_to_its_expected_reason() {
        let exhausted = || {
            let s = Session::new(Capacity {
                permits: 0,
                events: 0,
            });
            let mut policy = Limits::recorded_unlimited(&s);
            drop((policy.owner(), policy));
            s.finish()
        };
        let finished = exhausted();
        Findings::new().conclude(&[("S", &finished, Expected::Incomplete(Incomplete::Exhausted))]);
        let mut findings = Findings::new();
        let other = findings.session("S", &finished, Expected::Incomplete(Incomplete::Live(1)));
        let complete = findings.session("S", &finished, Expected::Complete);
        assert_eq!(other, "S is no evidence: Exhausted");
        assert_eq!(complete, other);
        assert_eq!(
            findings.0,
            [
                "S: no evidence (Exhausted), expected no evidence: Live(1)",
                "S: no evidence (Exhausted), expected complete evidence",
            ]
        );
    }

    /// A recorded policy whose counters agree with its history adds no
    /// finding; a policy that records nothing is named; the planted
    /// disagreements (a refusal the history holds and the counters lost, an
    /// injection the counters claim and the history does not hold) are each
    /// named; an unreadable history passes only for its declared reason,
    /// and a readable one declared unreadable is named.
    #[test]
    fn a_policys_history_is_read_against_its_counters() {
        use crate::bounded::LimitRefusal;
        let s = session();
        let mut policy = Limits::recorded_unlimited(&s);
        drop(policy.owner());
        let mut findings = Findings::new();
        findings.policies([
            ("A", policy, ExpectedHistory::Readable),
            ("O", Limits::unlimited(), ExpectedHistory::Readable),
            (
                "U",
                Limits::unlimited(),
                ExpectedHistory::Unreadable(Unreadable::Unrecorded),
            ),
        ]);
        assert_eq!(findings.0, ["O: the policy records no history"]);
        let finished = s.finish();
        Findings::new().conclude(&[("S", &finished, Expected::Complete)]);

        let refused = Answer::Refused {
            refusal: LimitRefusal::Work,
            injected: false,
        };
        let history = || Ok(Vec::from([(Call::Allocate(8), refused)]));
        let counted = |refusals, injected| dcbor_test_support::Counted {
            attempts: 1,
            refusals,
            injected,
        };
        let exhausted = Unreadable::Session(Incomplete::Exhausted);
        let mut findings = Findings::new();
        findings.history(
            "agreeing",
            history(),
            ExpectedHistory::Readable,
            counted(1, 0),
        );
        findings.history(
            "lost refusal",
            history(),
            ExpectedHistory::Readable,
            counted(0, 0),
        );
        findings.history(
            "claimed injection",
            history(),
            ExpectedHistory::Readable,
            counted(1, 1),
        );
        findings.history(
            "declared",
            Err(exhausted),
            ExpectedHistory::Unreadable(exhausted),
            counted(0, 0),
        );
        findings.history(
            "undeclared",
            Err(exhausted),
            ExpectedHistory::Readable,
            counted(0, 0),
        );
        findings.history(
            "readable",
            history(),
            ExpectedHistory::Unreadable(exhausted),
            counted(1, 0),
        );
        assert_eq!(findings.0.len(), 4, "{:?}", findings.0);
        assert!(findings.0[0].starts_with("lost refusal: the recording holds 1 refusals"));
        assert!(findings.0[1].starts_with("claimed injection: the recording holds 0 injected"));
        assert_eq!(
            findings.0[2],
            "undeclared: the policy's history cannot be read: Session(Exhausted)"
        );
        assert_eq!(
            findings.0[3],
            "readable: the policy's history is readable, expected unreadable: \
             Session(Exhausted)"
        );
    }

    /// No finding kept, but a session expected to be no evidence finished
    /// complete: the conclusion fails on the session alone.
    #[test]
    #[should_panic(expected = "S: finished complete, expected no evidence: Exhausted")]
    fn a_complete_session_expected_no_evidence_fails_without_findings() {
        let finished = session().finish();
        Findings::new().conclude(&[("S", &finished, Expected::Incomplete(Incomplete::Exhausted))]);
    }
}
