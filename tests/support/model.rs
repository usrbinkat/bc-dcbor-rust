//! The one configuration of every model a checker build runs: the
//! library's own models (`src/sync/models.rs`) and the declared entry points
//! of the integration tests (`tests/unsafe_census.rs`, `MODEL_ENTRY_POINTS`,
//! which declares these functions too). Each model runs at exactly the bound
//! and on exactly the stack it is given:
//!
//! - `DCBOR_MODEL_BOUND`: loom's branch capacity (the entries one
//!   execution's branch store holds, `rt/path.rs`, `Path::new`), shuttle's
//!   step bound (`MaxSteps::FailAfter`); unset, the recorded least bound
//!   ([`dcbor_model_bounds`]).
//! - `DCBOR_MODEL_STACK`: the bytes of the sized thread's stack; unset, the
//!   recorded least stack. A model on the checker's own stacks takes none.
//!
//! Which values are evidence is the gate's verdict (`tests/gate`): a row with
//! both unset must pass; a probe row one under a recorded value must be
//! refused by that value's own failure; derivation rows search upward. A run
//! here neither searches nor probes.
//!
//! A run's outcome is a function of its declared inputs alone: a `LOOM_*`
//! or `SHUTTLE_*` variable (each checker reads its own at configuration) and
//! a `RUST_BACKTRACE` other than `0` (a backtrace printed on a model's own
//! stack can turn a refusal into an abort) are refused before the model is
//! built, and every field of each checker's configuration is set here.
//!
//! Values recorded under another configuration or another build profile are
//! not this build's: frame sizes and step counts move with the toolchain and
//! its optimizations, so they are refused, naming the derivation.

use dcbor_model_bounds::{Bound, Bounds, Checker, PATH, RECORD_WITH};

/// The bound a model runs at.
pub const BOUND: &str = "DCBOR_MODEL_BOUND";

/// The bytes of a model's sized stack.
pub const STACK: &str = "DCBOR_MODEL_STACK";

/// The prefix a run prints the schedules it explored under, for the gate's
/// derivation.
pub const SCHEDULES: &str = "DCBOR_MODEL_SCHEDULES";

/// Set to `1`, a run only describes its model, running nothing: it prints
/// [`DESCRIPTION`] and whether the model runs on a sized stack. How the gate
/// learns what to derive from the runner each model is built with, never
/// from a list of its own.
pub const DESCRIBE: &str = "DCBOR_MODEL_DESCRIBE";

/// The line a described model prints: this, a tab, then `sized` or
/// `unsized`.
pub const DESCRIPTION: &str = "DCBOR_MODEL";

/// Whether this run only describes its model, `sized` or not, having printed
/// its description.
pub fn described(sized: bool) -> bool {
    match std::env::var(DESCRIBE) {
        Err(std::env::VarError::NotPresent) => false,
        Ok(value) if value == "1" => {
            println!("{DESCRIPTION}\t{}", if sized { "sized" } else { "unsized" });
            true
        }
        other => panic!("{DESCRIBE} must be 1 or unset: {other:?}"),
    }
}

/// This build's profile, as the record tags its values.
pub const PROFILE: &str = if cfg!(debug_assertions) {
    "debug"
} else {
    "release"
};

/// The value `name` declares, or `None` when it is unset.
fn declared(name: &str) -> Option<usize> {
    match std::env::var(name) {
        Ok(value) => Some(
            value
                .parse()
                .unwrap_or_else(|error| panic!("{name}={value}: {error}")),
        ),
        Err(std::env::VarError::NotPresent) => None,
        Err(error) => panic!("{name}: {error}"),
    }
}

/// Refuse every input a run reads besides its declared ones.
pub fn controlled() {
    let undeclared: Vec<String> = std::env::vars_os()
        .filter_map(|(name, _)| name.into_string().ok())
        .filter(|name| name.starts_with("LOOM_") || name.starts_with("SHUTTLE_"))
        .collect();
    assert!(
        undeclared.is_empty(),
        "a model's checker configuration is set here alone; unset {undeclared:?}"
    );
    match std::env::var("RUST_BACKTRACE") {
        Err(std::env::VarError::NotPresent) => {}
        Ok(value) if value == "0" => {}
        other => panic!("RUST_BACKTRACE must be unset or 0 in a model run: {other:?}"),
    }
}

/// The recorded values of `model` of `target` under `checker`, from a record
/// of this configuration and profile.
fn recorded(checker: Checker, target: &str, model: &str) -> Bound {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../data/model-bounds.txt");
    let data = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{PATH}: {error}; derive it with {RECORD_WITH}"));
    let (configuration, bounds) = Bounds::parse(&data).unwrap_or_else(|error| panic!("{error}"));
    let running = dcbor_record::configuration();
    assert_eq!(
        Some(configuration.as_str()),
        running.as_deref(),
        "{PATH} was derived under another configuration; derive it with {RECORD_WITH}"
    );
    assert_eq!(
        bounds.profile, PROFILE,
        "{PATH} was derived under another build profile; derive it with {RECORD_WITH}"
    );
    bounds
        .find(checker, target, model)
        .cloned()
        .unwrap_or_else(|| {
            panic!("{PATH}: no {checker} {target} {model}; derive it with {RECORD_WITH}")
        })
}

/// The values a run of `model` uses: each declared one, or the recorded one
/// when it is unset; and the schedules the run must explore, when the record
/// holds the count and the bound is the recorded one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Values {
    pub bound: usize,
    pub stack: Option<usize>,
    pub schedules: Option<usize>,
}

/// The values every runner of this module resolves before it builds a
/// model of `checker`, on a sized stack when `sized`: the run's inputs
/// controlled first ([`controlled`]).
pub fn values(checker: Checker, target: &str, model: &str, sized: bool) -> Values {
    controlled();
    let (bound, stack) = (declared(BOUND), declared(STACK));
    assert!(
        sized || stack.is_none(),
        "{model} runs on {checker}'s own stacks and takes no {STACK}"
    );
    let record =
        (bound.is_none() || (sized && stack.is_none())).then(|| recorded(checker, target, model));
    let from_record = |what: &str| -> &Bound {
        record
            .as_ref()
            .unwrap_or_else(|| panic!("{model}: no recorded {what}"))
    };
    let values = Values {
        bound: bound.unwrap_or_else(|| from_record("bound").bound),
        stack: if sized {
            Some(stack.unwrap_or_else(|| {
                from_record("stack")
                    .stack
                    .unwrap_or_else(|| panic!("{model}: recorded without a stack"))
            }))
        } else {
            None
        },
        schedules: bound
            .is_none()
            .then(|| from_record("bound").schedules)
            .flatten(),
    };
    assert!(values.bound > 0, "{model}: a bound of 0 admits nothing");
    values
}

/// Every interleaving of `body`, a model of `threads` threads, the main one
/// included, each on loom's own stack: no preemption bound, no permutation
/// or time limit, no checkpoint, so a pass means the whole space was
/// explored.
#[cfg(loom)]
pub fn loom(target: &str, model: &str, threads: usize, body: impl Fn() + Sync + Send + 'static) {
    if described(false) {
        return;
    }
    let values = values(Checker::Loom, target, model, false);
    let mut builder = loom::model::Builder::new();
    builder.max_threads = threads;
    builder.max_branches = values.bound;
    builder.max_permutations = None;
    builder.max_duration = None;
    builder.preemption_bound = None;
    builder.checkpoint_file = None;
    builder.checkpoint_interval = 1;
    builder.expect_explicit_explore = false;
    builder.location = false;
    builder.log = false;
    builder.check(body);
}

/// [`loom`] of `body` on one thread spawned with the model's stack, beside
/// the main one, and joined: loom runs a model's own body on the generator
/// crate's default stack (0x8000 bytes, `generator` 0.8.11 `gen_impl.rs`
/// `DEFAULT_STACK_SIZE`), which it gives no way to size
/// (`rt/scheduler.rs`, `spawn_thread(.., None)`). loom's `stack_size` is
/// handed to the generator crate as a count of words, not bytes
/// (`rt/scheduler.rs` `Gn::new_opt`, `generator` `Stack::new`), and an odd
/// count fills the whole stack with a footprint pattern, so the bytes are
/// converted here and required to be whole pairs of words.
#[cfg(loom)]
pub fn loom_sized(target: &str, model: &str, body: fn()) {
    if described(true) {
        return;
    }
    let values = values(Checker::Loom, target, model, true);
    let bytes = values.stack.expect("a sized model has a stack");
    let word = core::mem::size_of::<usize>();
    assert_eq!(
        bytes % (2 * word),
        0,
        "{STACK}={bytes}: a loom stack is a whole number of word pairs"
    );
    let words = bytes / word;
    let mut builder = loom::model::Builder::new();
    builder.max_threads = 2;
    builder.max_branches = values.bound;
    builder.max_permutations = None;
    builder.max_duration = None;
    builder.preemption_bound = None;
    builder.checkpoint_file = None;
    builder.checkpoint_interval = 1;
    builder.expect_explicit_explore = false;
    builder.location = false;
    builder.log = false;
    builder.check(move || {
        loom::thread::Builder::new()
            .stack_size(words)
            .spawn(body)
            .unwrap_or_else(|error| panic!("the model's thread: {error}"))
            .join()
            .unwrap_or_else(|payload| std::panic::resume_unwind(payload));
    });
}

/// Every schedule of `body` under shuttle, each replayed once and required
/// to reach the same runnable tasks at every step: shuttle's exhaustive
/// depth-first scheduler (`shuttle-schedulers` 0.1.1 `dfs.rs`, no iteration
/// bound, no random data) inside its uncontrolled-nondeterminism check
/// (`uncontrolled_nondeterminism.rs`), which runs each schedule twice. Every
/// task runs on the model's stack. shuttle treats every ordering as
/// `SeqCst`, so the guarantee is exhaustive under sequential consistency.
/// The schedules explored are printed for the gate's derivation, and, at the
/// recorded bound, required to be the recorded count.
#[cfg(all(shuttle, not(loom)))]
pub fn shuttle(target: &str, model: &str, body: impl Fn() + Send + Sync + 'static) {
    use shuttle::scheduler::{DfsScheduler, UncontrolledNondeterminismCheckScheduler};
    if described(true) {
        return;
    }
    let values = values(Checker::Shuttle, target, model, true);
    let mut config = shuttle::Config::new();
    config.stack_size = values.stack.expect("a shuttle model has a stack");
    config.failure_persistence = shuttle::FailurePersistence::None;
    config.max_steps = shuttle::MaxSteps::FailAfter(values.bound);
    config.max_time = None;
    config.silence_warnings = true;
    config.record_steps_in_span = false;
    config.ungraceful_shutdown_config = shuttle::UngracefulShutdownConfig::new();
    let executions = shuttle::Runner::new(
        UncontrolledNondeterminismCheckScheduler::new(DfsScheduler::new(None, false)),
        config,
    )
    .run(body);
    assert_eq!(
        executions % 2,
        0,
        "each schedule runs twice, recorded then replayed"
    );
    let schedules = executions / 2;
    println!("{SCHEDULES}\t{schedules}");
    if let Some(recorded) = values.schedules {
        assert_eq!(
            schedules, recorded,
            "{model} explored {schedules} schedules, {recorded} recorded; derive it with \
             {RECORD_WITH}"
        );
    }
}
