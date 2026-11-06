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
    /// The run never started.
    NotRun,
}

impl Outcome {
    pub const ALL: [Self; 10] = [
        Self::Pass,
        Self::BoundRefused,
        Self::StackOverflow,
        Self::Segfault,
        Self::UndefinedBehavior,
        Self::Unsupported,
        Self::MemoryLeaked,
        Self::AbnormalTermination,
        Self::Failed,
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
/// missed when all passed, and none when a run never started, which shows
/// nothing of the mutant (the mutation verdict reports it undecided).
pub fn judged(outcomes: impl IntoIterator<Item = Outcome>) -> Option<Judgement> {
    let outcomes: Vec<Outcome> = outcomes.into_iter().collect();
    if outcomes.is_empty() || outcomes.contains(&Outcome::NotRun) {
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
    /// judged not at all when a run never started or none was made; every
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
        assert_eq!(judged([]), None);
        for judgement in Judgement::ALL {
            assert_eq!(Judgement::parse(judgement.name()), Some(judgement));
        }
        assert_eq!(Judgement::parse("caught"), None);
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
