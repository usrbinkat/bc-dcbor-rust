//! The one taxonomy of what a gate's run produced, and the classifiers that
//! read it from a run's termination and log. Every gate reports through
//! [`Outcome`]; a class added here fails to compile wherever outcomes are
//! matched until each consumer handles it.

use core::fmt;

use dcbor_model_bounds::Checker;

/// What one run produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Outcome {
    /// The run did what its kind requires: its tests ran and passed, or a
    /// scenario that must abort aborted.
    Pass,
    /// A model checker refused the bound it was given: loom's branch store
    /// full, shuttle's step bound reached.
    BoundRefused,
    /// loom's coroutine ran into its stack's guard page: the generator
    /// crate's handler named the overflow, then aborted.
    StackOverflow,
    /// The process was killed by `SIGSEGV`: under shuttle a coroutine
    /// running into its stack's guard page, whose stack allocator installs
    /// no handler, or a memory error; which is decided by the stack's
    /// monotonicity, never here.
    Segfault,
    /// Miri reported undefined behavior.
    UndefinedBehavior,
    /// Miri reported an operation it does not support.
    Unsupported,
    /// Miri reported memory still allocated when the program ended, which it
    /// checks after `main` returns: a run can print a passing test result and
    /// still leak.
    MemoryLeaked,
    /// The program aborted (Miri's abnormal termination, or `SIGABRT`
    /// natively).
    AbnormalTermination,
    /// Anything else: a failed assertion, a panic, a scenario that returned
    /// instead of aborting.
    Failed,
    /// The build of what would have run failed: a compiler refusal, the
    /// outcome a planted defect evaluated at compile time must produce.
    BuildRefused,
    /// The checker ended without a verdict: Kani's CBMC run ran out of
    /// memory, reached the harness timeout, reported unusable results
    /// ([`kani_without_verdict`]), or ended without a complete, consistent
    /// report ([`kani`]). Neither a pass nor a refusal.
    NoVerdict,
    /// The run never started.
    NotRun,
}

impl Outcome {
    pub const ALL: [Self; 12] = [
        Self::Pass,
        Self::BoundRefused,
        Self::StackOverflow,
        Self::Segfault,
        Self::UndefinedBehavior,
        Self::Unsupported,
        Self::MemoryLeaked,
        Self::AbnormalTermination,
        Self::Failed,
        Self::BuildRefused,
        Self::NoVerdict,
        Self::NotRun,
    ];

    /// The outcome's name, as results rows write it.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::BoundRefused => "bound_refused",
            Self::StackOverflow => "stack_overflow",
            Self::Segfault => "segfault",
            Self::UndefinedBehavior => "undefined_behavior",
            Self::Unsupported => "unsupported",
            Self::MemoryLeaked => "memory_leaked",
            Self::AbnormalTermination => "abnormal_termination",
            Self::Failed => "failed",
            Self::BuildRefused => "build_refused",
            Self::NoVerdict => "no_verdict",
            Self::NotRun => "not_run",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|outcome| outcome.name() == text)
    }
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// What the Miri layer decided of a mutant that both native layers missed
/// in a module holding `unsafe`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Judgement {
    /// A test reaching it failed under Miri, under either aliasing model.
    CaughtUnderMiri,
    /// Every test reaching it passed under both models.
    MissedUnderMiri,
    /// A test reaching it has no unmutated pass under both models in the
    /// baseline of the same identity: nothing can be decided.
    NoBaseline,
    /// No test Miri runs reaches it.
    UnreachedUnderMiri,
}

impl Judgement {
    pub const ALL: [Self; 4] = [
        Self::CaughtUnderMiri,
        Self::MissedUnderMiri,
        Self::NoBaseline,
        Self::UnreachedUnderMiri,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::CaughtUnderMiri => "caught_under_miri",
            Self::MissedUnderMiri => "missed_under_miri",
            Self::NoBaseline => "no_baseline",
            Self::UnreachedUnderMiri => "unreached_under_miri",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|judgement| judgement.name() == text)
    }
}

impl fmt::Display for Judgement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The judgement of a mutant from the outcomes of every run of every test
/// reaching it, under every model: caught when any ran and did not pass,
/// missed when all passed, and none when a run never started or produced no
/// verdict (the mutation verdict reports it undecided).
pub fn judged(outcomes: impl IntoIterator<Item = Outcome>) -> Option<Judgement> {
    let outcomes: Vec<Outcome> = outcomes.into_iter().collect();
    if outcomes.is_empty()
        || outcomes
            .iter()
            .any(|outcome| matches!(outcome, Outcome::NotRun | Outcome::NoVerdict))
    {
        None
    } else if outcomes.iter().all(|outcome| *outcome == Outcome::Pass) {
        Some(Judgement::MissedUnderMiri)
    } else {
        Some(Judgement::CaughtUnderMiri)
    }
}

/// How a process ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Termination {
    Exited(i32),
    Signaled(i32),
}

/// `SIGABRT`.
pub const SIGABRT: i32 = 6;
/// `SIGSEGV`.
pub const SIGSEGV: i32 = 11;

/// loom's refusal of its bound (`loom` 0.7.2 `rt/path.rs`,
/// `assert_path_len!`).
pub const LOOM_BOUND: &str = "Model exceeded maximum number of branches";
/// shuttle's refusal of its bound (`shuttle-engine` 0.1.7
/// `runtime/execution.rs`).
pub const SHUTTLE_BOUND: &str = "exceeded max_steps bound";
/// The generator crate's report of a coroutine at its guard page, before it
/// aborts (`generator` 0.8.11 `stack/overflow_unix.rs`).
pub const LOOM_OVERFLOW: &str = "has overflowed its stack";

/// The refusal message of `checker`'s bound.
pub const fn bound_refusal(checker: Checker) -> &'static str {
    match checker {
        Checker::Loom => LOOM_BOUND,
        Checker::Shuttle => SHUTTLE_BOUND,
    }
}

/// How a run on a stack too small for it ends under `checker`.
pub const fn overflow(checker: Checker) -> Outcome {
    match checker {
        Checker::Loom => Outcome::StackOverflow,
        Checker::Shuttle => Outcome::Segfault,
    }
}

/// Whether libtest reports, in `log`, at least one test run and every one
/// passed: a successful empty selection is not qualification.
pub fn executed(log: &str) -> bool {
    log.lines().any(|line| {
        line.strip_prefix("test result: ok. ")
            .and_then(|rest| rest.split(' ').next())
            .and_then(|passed| passed.parse::<usize>().ok())
            .is_some_and(|passed| passed > 0)
    })
}

/// The counts libtest's summary line in `log` reports, `test result: ...`:
/// passed, failed, ignored. None when no summary line is found.
fn summary(log: &str) -> Option<(usize, usize, usize)> {
    log.lines().find_map(|line| {
        let rest = line
            .strip_prefix("test result: ok. ")
            .or_else(|| line.strip_prefix("test result: FAILED. "))?;
        let mut counts = rest.split("; ").map(|part| {
            part.split(' ')
                .next()
                .and_then(|count| count.parse::<usize>().ok())
        });
        Some((counts.next()??, counts.next()??, counts.next()??))
    })
}

/// Whether the run whose libtest report is `log` ran exactly one test, not
/// ignored, to its end: the selection named one test and it executed, so
/// everything the run printed is that test's. An ignored test, an empty
/// selection and a process that never reached its summary are not.
pub fn ran_one(log: &str) -> bool {
    summary(log).is_some_and(|(passed, failed, ignored)| passed + failed == 1 && ignored == 0)
}

/// The outcome of a model run under `checker`: a refusal of the bound only
/// when the checker's own message names it, an overflow only as the
/// checker's stack allocator ends one.
pub fn model(checker: Checker, termination: Termination, log: &str) -> Outcome {
    match termination {
        Termination::Signaled(SIGABRT)
            if checker == Checker::Loom && log.contains(LOOM_OVERFLOW) =>
        {
            Outcome::StackOverflow
        }
        Termination::Signaled(SIGSEGV) => Outcome::Segfault,
        Termination::Signaled(_) => Outcome::Failed,
        Termination::Exited(0) if executed(log) => Outcome::Pass,
        Termination::Exited(_) if log.contains(bound_refusal(checker)) => Outcome::BoundRefused,
        Termination::Exited(_) => Outcome::Failed,
    }
}

/// What a Miri run must do: pass its tests, or, for a scenario that ends its
/// own process, abort.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Test,
    Abort,
}

/// The outcome of a Miri run of `kind`: undefined behavior, an unsupported
/// operation and a leak are each reported first, whatever else the run did
/// (a leak is found after a passing test result); then an abort, which an
/// abort scenario requires; then a pass.
pub fn miri(kind: Kind, termination: Termination, log: &str) -> Outcome {
    if log.contains("Undefined Behavior") {
        Outcome::UndefinedBehavior
    } else if log.contains("unsupported operation") {
        Outcome::Unsupported
    } else if log.contains("memory leaked") {
        Outcome::MemoryLeaked
    } else if log.contains("abnormal termination") {
        match kind {
            Kind::Abort => Outcome::Pass,
            Kind::Test => Outcome::AbnormalTermination,
        }
    } else {
        match (kind, termination) {
            (Kind::Test, Termination::Exited(0)) if executed(log) => Outcome::Pass,
            _ => Outcome::Failed,
        }
    }
}

/// How the test binary a `cargo test` run launched ended, from cargo's exit
/// `status` and its `log`: cargo exits 101 whatever killed the binary, and
/// names the signal in its report (`cargo-util` `exit_status_to_string`,
/// `signal: 6, SIGABRT: process abort signal`).
pub fn under_cargo(status: i32, log: &str) -> Termination {
    log.split("(signal: ")
        .skip(1)
        .find_map(|rest| {
            rest.split_once(',')
                .and_then(|(signal, _)| signal.parse().ok())
        })
        .map_or(Termination::Exited(status), Termination::Signaled)
}

/// Kani's report of a build that failed before any harness was checked
/// (kani-driver 0.68.0 `call_cargo.rs` `run_build`).
pub const KANI_BUILD_FAILED: &str = "Failed to execute cargo (";

/// The counts Kani's final summary line in `log` reports, `Complete - S
/// successfully verified harnesses, F failures, T total.`
/// (kani-driver `harness_runner.rs` `print_final_summary`): verified,
/// failed, total. None unless exactly one well-formed summary line is found.
pub fn kani_summary(log: &str) -> Option<(usize, usize, usize)> {
    let mut summaries = log
        .lines()
        .filter_map(|line| line.strip_prefix("Complete - "));
    let rest = summaries.next()?;
    if summaries.next().is_some() {
        return None;
    }
    let (verified, rest) = rest.split_once(" successfully verified harnesses, ")?;
    let (failed, rest) = rest.split_once(" failures, ")?;
    let total = rest.strip_suffix(" total.")?;
    Some((
        verified.parse().ok()?,
        failed.parse().ok()?,
        total.parse().ok()?,
    ))
}

/// Kani's report of a reachable construct it does not model, whose failure
/// turns every other result undetermined (kani-driver
/// `cbmc_property_renderer.rs` `format_result`, `postprocess_result`).
pub const KANI_UNSUPPORTED: &str =
    "A Rust construct that is not currently supported by Kani was found to be reachable";

/// Kani's report of an unwinding assertion that failed: the bound given did
/// not cover a loop or recursion, and every other result is undetermined
/// (the same renderer).
pub const KANI_UNWINDING: &str = "Verification output shows one or more unwinding failures";

/// The headers of Kani's report of a CBMC run whose results it does not
/// use, each on a line of its own before `VERIFICATION:- FAILED`
/// (kani-driver `call_cbmc.rs` `VerificationResult::render`, its
/// `Err(exit_status)` arm): `CBMC failed` (out of memory, the harness
/// timeout reached) or `CBMC failed with status N`, in 0.68.0 and on main
/// (5d80a64); `CBMC did not finish reporting its results (exit status N)`,
/// main's `IncompleteResults`, a result array without CBMC's overall
/// status. Kani counts such a harness among its failures, though no
/// property's result is read.
pub const KANI_NO_RESULTS: [&str; 2] = ["CBMC failed", "CBMC did not finish reporting its results"];

/// Kani's report that the solver dropped a quantifier it could not encode
/// (kani-driver `call_cbmc.rs` `ignored_quantifiers_error`, 0.68.0 and
/// main): the analysis is unsound, an assumption holding it unenforced, and
/// Kani forces the harness to fail whatever its properties showed.
pub const KANI_UNSOUND: &str = "Kani cannot soundly verify this harness";

/// Whether `report` holds a CBMC run that gave no verdict: one whose
/// results Kani does not use ([`KANI_NO_RESULTS`] opening a line), or one
/// it reports unsound ([`KANI_UNSOUND`]). The one reading of it, for a run
/// ([`kani`]) and for each harness's block (`crate::proofs::checked`).
pub fn kani_without_verdict(report: &str) -> bool {
    report.contains(KANI_UNSOUND)
        || report.lines().any(|line| {
            let line = line.trim_start();
            KANI_NO_RESULTS
                .iter()
                .any(|header| line.starts_with(header))
        })
}

/// The outcome of a Kani run. A fundamental failure is classed first,
/// whatever else the run reports, since it makes every other result
/// undetermined: a CBMC run that produced no results is `NoVerdict`
/// ([`kani_without_verdict`]), a reachable unsupported construct
/// `Unsupported`, a failed unwinding assertion `BoundRefused` (the bound
/// given refused, as a model checker's is). Then a pass when it exited 0 and its summary
/// verified every harness it checked, at least one; failed when it exited 1
/// (Kani's exit on a failing harness) and its summary names a failure; a
/// refused build when cargo failed before any harness was checked. Signals,
/// missing or inconsistent reports, empty selections and contradictory exit
/// statuses provide no verdict. Report completeness is checked by the same
/// parser as the proof suite ([`crate::proofs::checked`]).
pub fn kani(termination: Termination, log: &str) -> Outcome {
    if matches!(termination, Termination::Signaled(_)) || kani_without_verdict(log) {
        return Outcome::NoVerdict;
    }
    if log.contains(KANI_UNSUPPORTED) {
        return Outcome::Unsupported;
    }
    if log.contains(KANI_UNWINDING) {
        return Outcome::BoundRefused;
    }
    if matches!(termination, Termination::Exited(code) if code != 0)
        && !log.contains("Checking harness ")
        && log.contains(KANI_BUILD_FAILED)
    {
        return Outcome::BuildRefused;
    }
    let Ok(results) = crate::proofs::checked(log) else {
        return Outcome::NoVerdict;
    };
    if results.is_empty() {
        return Outcome::NoVerdict;
    }
    match termination {
        Termination::Exited(0) if results.iter().all(|(_, result)| *result == Outcome::Pass) => {
            Outcome::Pass
        }
        Termination::Exited(1) if results.iter().any(|(_, result)| *result == Outcome::Failed) => {
            Outcome::Failed
        }
        _ => Outcome::NoVerdict,
    }
}

/// The outcome of a native run of `kind`: a test run that passed, or an
/// abort scenario killed by `SIGABRT`.
pub fn native(kind: Kind, termination: Termination, log: &str) -> Outcome {
    match (kind, termination) {
        (Kind::Abort, Termination::Signaled(SIGABRT)) => Outcome::Pass,
        (Kind::Test, Termination::Exited(0)) if executed(log) => Outcome::Pass,
        (_, Termination::Signaled(SIGSEGV)) => Outcome::Segfault,
        _ => Outcome::Failed,
    }
}

/// Upstream report fixtures shared by the whole-run and per-harness tests.
/// Literal diagnostics remain independent of the classifier's constants.
#[cfg(test)]
pub(crate) mod fixtures {
    pub(crate) fn kani_no_verdict_blocks(name: &str) -> impl Iterator<Item = String> + '_ {
        [
            (
                "CBMC failed",
                "CBMC timed out. You may want to rerun your proof with a larger timeout or use stubbing to reduce the size of the code the verifier reasons about.\n",
            ),
            (
                "CBMC failed",
                "CBMC appears to have run out of memory. You may want to rerun your proof in an environment with additional memory or use stubbing to reduce the size of the code the verifier reasons about.\n",
            ),
            ("CBMC failed with status 6", ""),
            (
                "CBMC did not finish reporting its results (exit status 6)",
                "CBMC's output ended before its overall verification status, so the results it reported may be incomplete and were not used.\n",
            ),
            (
                "error: the solver backend does not support quantifiers with non-constant bounds and ignored 1 quantifier expression(s), replacing them with unconstrained values.",
                "Kani cannot soundly verify this harness: `kani::assume` calls containing such a quantifier are NOT enforced.\n",
            ),
        ]
        .into_iter()
        .map(move |(header, explanation)| {
            format!("Checking harness {name}...\n\n{header}\nVERIFICATION:- FAILED\n{explanation}")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSED: &str = "test x ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored\n";
    const EMPTY: &str = "test result: ok. 0 passed; 0 failed; 0 ignored\n";

    #[test]
    fn every_outcome_reads_back_its_name() {
        for outcome in Outcome::ALL {
            assert_eq!(Outcome::parse(outcome.name()), Some(outcome));
        }
        assert_eq!(Outcome::parse("caught"), None);
    }

    /// A model run passes only by running a test; the checker's own message
    /// is a refusal of its bound and nothing else is; loom's named guard-page
    /// abort is an overflow, an unnamed abort is not; `SIGSEGV` is a
    /// segfault under either checker, its cause decided elsewhere.
    #[test]
    fn a_model_run_is_classed_by_the_checkers_own_reports() {
        let exit = Termination::Exited;
        assert_eq!(model(Checker::Loom, exit(0), PASSED), Outcome::Pass);
        assert_eq!(model(Checker::Loom, exit(0), EMPTY), Outcome::Failed);
        let refused = format!("panicked: {LOOM_BOUND}. This is often caused");
        assert_eq!(
            model(Checker::Loom, exit(101), &refused),
            Outcome::BoundRefused
        );
        assert_eq!(
            model(Checker::Shuttle, exit(101), &refused),
            Outcome::Failed,
            "loom's message is no refusal of shuttle's bound"
        );
        let stepped = format!("test panicked: {SHUTTLE_BOUND} 7");
        assert_eq!(
            model(Checker::Shuttle, exit(101), &stepped),
            Outcome::BoundRefused
        );
        assert_eq!(
            model(Checker::Loom, exit(101), "assertion failed"),
            Outcome::Failed
        );
        let overflowed = format!("coroutine in thread 'x' {LOOM_OVERFLOW}");
        assert_eq!(
            model(Checker::Loom, Termination::Signaled(SIGABRT), &overflowed),
            Outcome::StackOverflow
        );
        assert_eq!(
            model(Checker::Loom, Termination::Signaled(SIGABRT), "abort"),
            Outcome::Failed
        );
        assert_eq!(
            model(Checker::Shuttle, Termination::Signaled(SIGSEGV), ""),
            Outcome::Segfault
        );
    }

    /// Miri's reports are classed before the run's own result: a leak after
    /// a passing test result is a leak, undefined behavior is reported over
    /// an abort, and an abort is a pass only for an abort scenario.
    #[test]
    fn a_miri_run_is_classed_reports_first() {
        let exit = Termination::Exited;
        assert_eq!(miri(Kind::Test, exit(0), PASSED), Outcome::Pass);
        assert_eq!(miri(Kind::Test, exit(0), EMPTY), Outcome::Failed);
        let leaked = format!("{PASSED}error: memory leaked: alloc1");
        assert_eq!(miri(Kind::Test, exit(1), &leaked), Outcome::MemoryLeaked);
        let both = "error: Undefined Behavior: x\nerror: abnormal termination: y";
        assert_eq!(miri(Kind::Abort, exit(1), both), Outcome::UndefinedBehavior);
        assert_eq!(
            miri(Kind::Test, exit(1), "error: unsupported operation: x"),
            Outcome::Unsupported
        );
        let aborted = "error: abnormal termination: the program aborted";
        assert_eq!(miri(Kind::Abort, exit(1), aborted), Outcome::Pass);
        assert_eq!(
            miri(Kind::Test, exit(1), aborted),
            Outcome::AbnormalTermination
        );
        assert_eq!(miri(Kind::Abort, exit(0), PASSED), Outcome::Failed);
    }

    /// A mutant is caught when any run reaching it ran and did not pass, and
    /// judged not at all when a run never started, produced no verdict, or
    /// none was made; every
    /// judgement reads back its name, an unknown one refused.
    #[test]
    fn a_mutant_is_caught_by_any_run_that_did_not_pass() {
        assert_eq!(
            judged([Outcome::Pass, Outcome::Pass]),
            Some(Judgement::MissedUnderMiri)
        );
        assert_eq!(
            judged([Outcome::Pass, Outcome::UndefinedBehavior]),
            Some(Judgement::CaughtUnderMiri)
        );
        assert_eq!(judged([Outcome::Failed, Outcome::NotRun]), None);
        assert_eq!(judged([Outcome::NoVerdict]), None);
        assert_eq!(judged([Outcome::Pass, Outcome::NoVerdict]), None);
        assert_eq!(judged([Outcome::Failed, Outcome::NoVerdict]), None);
        assert_eq!(judged([]), None);
        for judgement in Judgement::ALL {
            assert_eq!(Judgement::parse(judgement.name()), Some(judgement));
        }
        assert_eq!(Judgement::parse("caught"), None);
    }

    /// One test run to its end, passed or failed, is one; an ignored test,
    /// an empty selection, two tests and a run without a summary are not.
    #[test]
    fn only_a_run_of_exactly_one_executed_test_is_one() {
        assert!(ran_one(PASSED));
        assert!(ran_one(
            "test x ... FAILED\n\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured\n"
        ));
        assert!(!ran_one(EMPTY));
        assert!(!ran_one(
            "test x ... ignored\n\ntest result: ok. 0 passed; 0 failed; 1 ignored; 0 measured\n"
        ));
        assert!(!ran_one(
            "test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured\n"
        ));
        assert!(!ran_one("thread 'main' panicked\n"));
    }

    #[test]
    fn a_native_run_passes_by_its_kinds_requirement() {
        assert_eq!(
            native(Kind::Test, Termination::Exited(0), PASSED),
            Outcome::Pass
        );
        assert_eq!(
            native(Kind::Abort, Termination::Signaled(SIGABRT), ""),
            Outcome::Pass
        );
        assert_eq!(
            native(Kind::Abort, Termination::Exited(0), PASSED),
            Outcome::Failed
        );
        assert_eq!(
            native(Kind::Test, Termination::Exited(101), ""),
            Outcome::Failed
        );
    }

    /// A Kani run is classed by its own summary: every harness verified a
    /// pass, a failure with Kani's exit 1 failed, a cargo failure before any
    /// harness a refused build; a summary that disagrees with the exit, or
    /// none, is no pass.
    #[test]
    fn a_kani_run_is_classed_by_its_summary() {
        let passed = "Checking harness bounded::proofs::x...\nVERIFICATION:- SUCCESSFUL\n\
                      Manual Harness Summary:\n\
                      Complete - 1 successfully verified harnesses, 0 failures, 1 total.\n";
        let failed = "Checking harness bounded::proofs::x...\nVERIFICATION:- FAILED\n\
                      Manual Harness Summary:\nVerification failed for - bounded::proofs::x\n\
                      Complete - 0 successfully verified harnesses, 1 failures, 1 total.\n";
        let exit = Termination::Exited;
        assert_eq!(kani_summary(passed), Some((1, 0, 1)));
        assert_eq!(kani(exit(0), passed), Outcome::Pass);
        assert_eq!(kani(exit(1), failed), Outcome::Failed);
        assert_eq!(
            kani(exit(1), passed),
            Outcome::NoVerdict,
            "a nonzero exit is no pass"
        );
        assert_eq!(
            kani(exit(0), "Manual Harness Summary:\n"),
            Outcome::NoVerdict,
            "no summary is no pass"
        );
        let unbuilt = "error[E0308]: mismatched types\n\
                       error: Failed to execute cargo (exit status: 101). Found 1 compilation errors.\n";
        assert_eq!(kani(exit(1), unbuilt), Outcome::BuildRefused);
        assert_eq!(
            kani(
                exit(0),
                "Complete - 0 successfully verified harnesses, 0 failures, 0 total.\n"
            ),
            Outcome::NoVerdict,
            "an empty run verified nothing"
        );
        for termination in [
            Termination::Signaled(9),
            Termination::Signaled(15),
            Termination::Signaled(SIGSEGV),
            exit(143),
        ] {
            for report in [
                "",
                "Checking harness bounded::proofs::x...\n",
                passed,
                failed,
            ] {
                assert_eq!(
                    kani(termination, report),
                    Outcome::NoVerdict,
                    "an interrupted checker supplied a verdict: {termination:?}"
                );
            }
        }
        for report in [
            failed.replace("VERIFICATION:- FAILED\n", ""),
            failed.replace("1 failures, 1 total", "1 failures, 2 total"),
        ] {
            assert_eq!(
                kani(exit(1), &report),
                Outcome::NoVerdict,
                "an incomplete report supplied a failure verdict"
            );
        }
        // A fundamental failure is classed before the summary: an
        // unsupported construct or a short unwind is never an intended
        // assertion failure, nor a pass.
        let unsupported = format!(
            "{failed}** WARNING: {KANI_UNSUPPORTED}. Check the results for more details.\n"
        );
        assert_eq!(kani(exit(1), &unsupported), Outcome::Unsupported);
        let unwound = format!("{passed}[Kani] info: {KANI_UNWINDING}.\n");
        assert_eq!(kani(exit(0), &unwound), Outcome::BoundRefused);
        // A CBMC run without results, as kani-driver 0.68.0 renders it, is
        // no verdict, though Kani counts it a failure: timed out, out of
        // memory, or another failing status.
        for block in fixtures::kani_no_verdict_blocks("bounded::proofs::x") {
            let ended = format!(
                "{block}Manual Harness Summary:\nVerification failed for - bounded::proofs::x\n\
                 Complete - 0 successfully verified harnesses, 1 failures, 1 total.\n"
            );
            assert_eq!(
                kani(exit(1), &ended),
                Outcome::NoVerdict,
                "a CBMC run without results was judged a verdict: {block}"
            );
        }
    }

    /// A binary cargo reports killed by a signal ended by that signal; any
    /// other cargo run ended with cargo's status, a panic's text naming a
    /// signal included.
    #[test]
    fn a_cargo_run_ends_as_cargo_reports_its_binary() {
        let killed = "error: test failed, to rerun pass `--test x`\n\nCaused by:\n  \
                      process didn't exit successfully: `target/x` (signal: 6, SIGABRT: process abort signal)\n";
        assert_eq!(under_cargo(101, killed), Termination::Signaled(SIGABRT));
        assert_eq!(
            native(Kind::Abort, under_cargo(101, killed), killed),
            Outcome::Pass
        );
        assert_eq!(under_cargo(0, PASSED), Termination::Exited(0));
        assert_eq!(
            under_cargo(101, "panicked: no (signal: given) here"),
            Termination::Exited(101)
        );
    }
}
