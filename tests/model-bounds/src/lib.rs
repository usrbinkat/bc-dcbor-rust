//! A leaf over the record format (`dcbor_record`): the rows of the one
//! record kind two crates read, the model runner (`dcbor-test-support`) and
//! the gate (`dcbor-gate`), neither of which may depend on the other.
//!
//! The model checkers' derived bounds (`tests/data/model-bounds.txt`): for
//! each model of a checker build, the least bound it completes under and,
//! where it runs on a sized stack, the least stack, each the maximum over
//! the model's tests, with the test that attains it. Read by the model runner
//! (`tests/support/model.rs`), which runs a model at its recorded values
//! unless the gate sets one; derived, written and verified by the gate
//! (`tests/gate`). The one definition of its rows, which both read.
//!
//! The record's first rows tag what the values hold for beyond the
//! configuration: the build profile they were derived under, and the page
//! size their stacks are multiples of. Every row: the checker, the test
//! target, the model, the bound, the stack in bytes (`-` for a model on the
//! checker's own stacks), the schedules one run explores (`-` where the
//! checker explores until its own search ends, as loom's does), and the
//! tests that attain the bound and the stack.

use core::fmt;

/// A function outside the checker seam (`src/sync.rs`, `src/sync/`) that
/// names a model checker in a `cfg`: a model runner, or a test entering a
/// model. The census allows a checker `cfg` there alone
/// (`tests/unsafe_census.rs`); the gate runs each one that is a test as a
/// model (`tests/gate`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntryPoint {
    /// The file, relative to the repository root.
    pub file: &'static str,
    /// The function.
    pub function: &'static str,
    /// The test target and test path, when the function is a test.
    pub test: Option<(&'static str, &'static str)>,
}

/// Every model entry point outside the seam: the one table of which code
/// enters a model checker's execution beside the library's own models.
pub const ENTRY_POINTS: &[EntryPoint] = &[
    EntryPoint {
        file: "tests/resumable/native_traces.rs",
        function: "every_baseline_admits_exactly_its_recorded_calls",
        test: Some((
            "resumable_contract",
            "traces::every_baseline_admits_exactly_its_recorded_calls",
        )),
    },
    EntryPoint {
        file: "tests/support/model.rs",
        function: "loom",
        test: None,
    },
    EntryPoint {
        file: "tests/support/model.rs",
        function: "loom_sized",
        test: None,
    },
    EntryPoint {
        file: "tests/support/model.rs",
        function: "shuttle",
        test: None,
    },
];

/// The library's test target.
pub const LIBRARY: &str = "lib";

/// The library's models of `checker`: the tests under this module of the
/// checker seam (`src/sync/models.rs`).
pub fn library_models(checker: Checker) -> String {
    format!("sync::models::{checker}_models::")
}

/// Whether `test` of `target` is a model of `checker`: one of the library's
/// models, or an entry point's test.
pub fn is_model(checker: Checker, target: &str, test: &str) -> bool {
    (target == LIBRARY && test.starts_with(&library_models(checker)))
        || ENTRY_POINTS
            .iter()
            .any(|entry| entry.test == Some((target, test)))
}

/// The test targets holding models: the library and every entry point's.
pub fn targets() -> Vec<&'static str> {
    let mut targets = vec![LIBRARY];
    for entry in ENTRY_POINTS {
        if let Some((target, _)) = entry.test
            && !targets.contains(&target)
        {
            targets.push(target);
        }
    }
    targets
}

/// How the record is written: by the gate's derivation.
pub const RECORD_WITH: &str = "bash tests/concurrency-models.sh derive";

/// The record's path relative to the repository root.
pub const PATH: &str = "tests/data/model-bounds.txt";

/// A model checker.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Checker {
    Loom,
    Shuttle,
}

impl Checker {
    pub const ALL: [Self; 2] = [Self::Loom, Self::Shuttle];

    /// The checker's name, as its cfg and its record column write it.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Loom => "loom",
            Self::Shuttle => "shuttle",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|checker| checker.name() == text)
    }
}

impl fmt::Display for Checker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// One model's recorded values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bound {
    pub checker: Checker,
    /// The test target holding the model: `lib`, or an integration test.
    pub target: String,
    /// The model, a test's path without a seed: its tests share these
    /// values.
    pub model: String,
    /// The least bound every test of the model completes under: loom's
    /// branch capacity, shuttle's step bound.
    pub bound: usize,
    /// The least stack, in bytes, every test completes on, when the model
    /// runs on a sized stack.
    pub stack: Option<usize>,
    /// The schedules one run explores, when the checker's search is bounded
    /// by the model alone (shuttle's exhaustive DFS).
    pub schedules: Option<usize>,
    /// The test attaining the bound.
    pub bound_witness: String,
    /// The test attaining the stack, when the model has one.
    pub stack_witness: Option<String>,
}

/// The whole record: its tags and its models.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bounds {
    /// The build profile the values were derived under.
    pub profile: String,
    /// The page size every stack is a multiple of.
    pub page: usize,
    pub models: Vec<Bound>,
}

const PROFILE: &str = "#\tprofile\t";
const PAGE: &str = "#\tpage\t";

/// An optional column: its value, or `-`.
fn column(value: Option<&str>) -> &str {
    value.unwrap_or("-")
}

fn number(text: &str, what: &str) -> Result<usize, String> {
    text.parse()
        .map_err(|error| format!("{what} {text:?}: {error}"))
}

fn optional_number(text: &str, what: &str) -> Result<Option<usize>, String> {
    if text == "-" {
        Ok(None)
    } else {
        number(text, what).map(Some)
    }
}

impl Bounds {
    /// The record of these values under `configuration`, its models sorted.
    pub fn render(&self, configuration: &str) -> String {
        let mut models = self.models.clone();
        models.sort_by(|left, right| {
            (left.checker, &left.target, &left.model).cmp(&(
                right.checker,
                &right.target,
                &right.model,
            ))
        });
        let mut rows = vec![
            format!("{PROFILE}{}", self.profile),
            format!("{PAGE}{}", self.page),
        ];
        for model in &models {
            let stack = model.stack.map(|stack| stack.to_string());
            let schedules = model.schedules.map(|schedules| schedules.to_string());
            rows.push(format!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                model.checker,
                model.target,
                model.model,
                model.bound,
                column(stack.as_deref()),
                column(schedules.as_deref()),
                model.bound_witness,
                column(model.stack_witness.as_deref()),
            ));
        }
        dcbor_record::render(configuration, rows.iter().map(String::as_str))
    }

    /// The record `data` read: its configuration and its values. A record
    /// without its tags, a row of another shape, a stack with no witness or a
    /// witness with no stack, and a model recorded twice are each refused,
    /// named by line.
    pub fn parse(data: &str) -> Result<(String, Self), String> {
        let record = dcbor_record::try_read(data)
            .ok_or_else(|| format!("{PATH}:1: not a record; derive it with {RECORD_WITH}"))?;
        let mut rows = record.rows.into_iter();
        let mut tag = |prefix: &str, what: &str| -> Result<String, String> {
            match rows.next() {
                Some((_, row)) => row
                    .strip_prefix(prefix)
                    .map(str::to_string)
                    .ok_or_else(|| format!("{PATH}: no {what} tag: {row:?}")),
                None => Err(format!("{PATH}: no {what} tag")),
            }
        };
        let profile = tag(PROFILE, "profile")?;
        let page = number(&tag(PAGE, "page")?, "page")?;
        let mut models: Vec<Bound> = Vec::new();
        for (at, row) in rows {
            let at = format!("{PATH}:{at}");
            let columns: Vec<&str> = row.split('\t').collect();
            let [
                checker,
                target,
                model,
                bound,
                stack,
                schedules,
                bound_witness,
                stack_witness,
            ] = columns[..]
            else {
                return Err(format!("{at}: not eight columns: {row:?}"));
            };
            let bound = Bound {
                checker: Checker::parse(checker)
                    .ok_or_else(|| format!("{at}: no checker {checker:?}"))?,
                target: target.to_string(),
                model: model.to_string(),
                bound: number(bound, "bound").map_err(|error| format!("{at}: {error}"))?,
                stack: optional_number(stack, "stack").map_err(|error| format!("{at}: {error}"))?,
                schedules: optional_number(schedules, "schedules")
                    .map_err(|error| format!("{at}: {error}"))?,
                bound_witness: bound_witness.to_string(),
                stack_witness: (stack_witness != "-").then(|| stack_witness.to_string()),
            };
            if bound.stack.is_some() != bound.stack_witness.is_some() {
                return Err(format!(
                    "{at}: a stack and its witness are recorded together"
                ));
            }
            if models.iter().any(|recorded| {
                (recorded.checker, &recorded.target, &recorded.model)
                    == (bound.checker, &bound.target, &bound.model)
            }) {
                return Err(format!(
                    "{at}: {checker} {target} {model} is recorded twice"
                ));
            }
            models.push(bound);
        }
        Ok((
            record.configuration.to_string(),
            Self {
                profile,
                page,
                models,
            },
        ))
    }

    /// The recorded values of `model` of `target` under `checker`.
    pub fn find(&self, checker: Checker, target: &str, model: &str) -> Option<&Bound> {
        self.models.iter().find(|bound| {
            bound.checker == checker && bound.target == target && bound.model == model
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bounds() -> Bounds {
        Bounds {
            profile: "release".to_string(),
            page: 4096,
            models: vec![
                Bound {
                    checker: Checker::Shuttle,
                    target: "lib".to_string(),
                    model: "sync::models::shuttle_models::a::workers_5".to_string(),
                    bound: 120,
                    stack: Some(8192),
                    schedules: Some(3),
                    bound_witness: "sync::models::shuttle_models::a::workers_5".to_string(),
                    stack_witness: Some("sync::models::shuttle_models::a::workers_5".to_string()),
                },
                Bound {
                    checker: Checker::Loom,
                    target: "lib".to_string(),
                    model: "sync::models::loom_models::a::workers_1".to_string(),
                    bound: 17,
                    stack: None,
                    schedules: None,
                    bound_witness: "sync::models::loom_models::a::workers_1".to_string(),
                    stack_witness: None,
                },
            ],
        }
    }

    /// The record renders its tags and its models sorted, and reads back to
    /// the same values; each model is found by checker, target and model.
    #[test]
    fn the_bounds_record_reads_back_what_it_renders() {
        let data = bounds().render("this");
        let (configuration, read) = Bounds::parse(&data).expect("the rendered record");
        assert_eq!(configuration, "this");
        assert_eq!(read.profile, "release");
        assert_eq!(read.page, 4096);
        assert_eq!(read.models[0].checker, Checker::Loom, "sorted by checker");
        assert_eq!(
            read.find(
                Checker::Shuttle,
                "lib",
                "sync::models::shuttle_models::a::workers_5"
            )
            .map(|bound| (bound.bound, bound.stack, bound.schedules)),
            Some((120, Some(8192), Some(3)))
        );
        assert_eq!(read.find(Checker::Loom, "lib", "absent"), None);
    }

    /// The library's models and the entry points' tests are models of the
    /// checker they name, and nothing else is.
    #[test]
    fn models_are_the_seams_and_the_entry_points_tests() {
        assert!(is_model(
            Checker::Loom,
            "lib",
            "sync::models::loom_models::a::workers_1"
        ));
        assert!(!is_model(
            Checker::Shuttle,
            "lib",
            "sync::models::loom_models::a::workers_1"
        ));
        assert!(!is_model(Checker::Loom, "lib", "bounded::tests::x"));
        assert!(is_model(
            Checker::Shuttle,
            "resumable_contract",
            "traces::every_baseline_admits_exactly_its_recorded_calls"
        ));
        assert!(!is_model(
            Checker::Loom,
            "resumable_contract",
            "traces::other"
        ));
        assert_eq!(targets(), vec!["lib", "resumable_contract"]);
    }

    /// A record of no tags, a row of another shape, a stack without its
    /// witness and a model recorded twice are each refused.
    #[test]
    fn a_malformed_bounds_record_is_refused() {
        let refused = |data: &str| Bounds::parse(data).expect_err("a malformed record was read");
        assert!(refused("no record\n").contains("not a record"));
        assert!(refused(&dcbor_record::render("c", ["row"])).contains("no profile tag"));
        let tagged =
            |row: &str| dcbor_record::render("c", ["#\tprofile\trelease", "#\tpage\t4096", row]);
        assert!(refused(&tagged("loom\tlib\tm\t1")).contains("not eight columns"));
        assert!(refused(&tagged("loom\tlib\tm\t1\t4096\t-\tm\t-")).contains("recorded together"));
        assert!(refused(&tagged("other\tlib\tm\t1\t-\t-\tm\t-")).contains("no checker"));
        let twice = dcbor_record::render(
            "c",
            [
                "#\tprofile\trelease",
                "#\tpage\t4096",
                "loom\tlib\tm\t1\t-\t-\tm\t-",
                "loom\tlib\tm\t2\t-\t-\tm\t-",
            ],
        );
        assert!(refused(&twice).contains("recorded twice"));
    }
}
