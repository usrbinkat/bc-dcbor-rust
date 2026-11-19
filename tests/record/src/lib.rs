//! The one form of every recorded oracle of this repository: the admission
//! traces (`tests/resumable/native_traces.rs`), the tightness ratios
//! (`src/bounded.rs`, `places`), the matrix costs (`tests/support/rigor.rs`),
//! the recording budgets ([`budgets`], `tests/support/budgets.rs`), the
//! model checkers' derived bounds and the gates' results
//! (`tests/gate`). A record names the configuration it was recorded under on
//! its first line, [`CONFIGURATION_LINE`] and the development shell's
//! `DCBOR_CONFIGURATION` (the toolchain and the standard library it builds
//! against); its rows follow, one per line. A record is published whole:
//! written to a temporary file beside it, then renamed over it, so a failed
//! recording leaves the previous record intact.
//!
//! Each consumer owns its rows' columns and their parse; this crate owns
//! the header, the configuration it names, the publication, the vocabulary
//! of evidence classes rows carry ([`Evidence`]) and the verification layer
//! a run carries ([`Rigor`]), each defined once. It is a leaf: it depends on
//! no crate of the workspace, so neither test instrumentation nor gate
//! tooling reaches a build through it, and the library's own unit tests and
//! the test support crate read the layer through the same definition.

use std::io::Write;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

pub mod budgets;

// Generate both the consuming crate's literal selection and the launch
// inventory from the same rows; neither can introduce a suffix independently.
macro_rules! variants {
    ($(($cfg:meta, $suffix:literal, $features:literal)),* $(,)?) => {
        /// Declare `$name!()` as this build's record suffix, a literal usable
        /// in `concat!` and `include_str!`. Feature selection occurs in the
        /// invoking crate; the launch inventory is [`VARIANTS`].
        #[macro_export]
        macro_rules! declare_variant {
            ($name:ident) => {
                $(
                    #[cfg($cfg)]
                    macro_rules! $name {
                        () => { $suffix };
                    }
                )*
            };
        }

        /// Every record projection's suffix and comma-separated Cargo features.
        /// Generated with [`declare_variant`] from the same projection table.
        pub const VARIANTS: &[(&str, &str)] = &[$(($suffix, $features)),*];
    };
}

variants!(
    (
        all(
            not(feature = "custom-std-collections"),
            not(feature = "num-bigint")
        ),
        "",
        "std,derive,hashbrown,multithreaded"
    ),
    (
        all(
            not(feature = "custom-std-collections"),
            feature = "num-bigint"
        ),
        ".num-bigint",
        "std,derive,hashbrown,multithreaded,num-bigint"
    ),
    (
        all(
            feature = "custom-std-collections",
            not(feature = "num-bigint")
        ),
        ".custom-std",
        "std,derive,hashbrown,multithreaded,custom-std-collections"
    ),
    (
        all(feature = "custom-std-collections", feature = "num-bigint"),
        ".custom-std.num-bigint",
        "std,derive,hashbrown,multithreaded,custom-std-collections,num-bigint"
    ),
);

pub mod capabilities;

/// The variable naming the verification layer a run carries.
pub const RIGOR: &str = "DCBOR_RIGOR";

/// The verification layer a run carries. Both layers apply the same
/// oracles; they differ in what they select, and each test states the claim
/// of each (`tests/support/rigor.rs` for the matrices' schedules; a test
/// over a numeric domain for its patterns). `fast` is the default every
/// developer run carries; the gates run `exhaustive`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rigor {
    Fast,
    Exhaustive,
}

impl Rigor {
    pub const ALL: [Self; 2] = [Self::Fast, Self::Exhaustive];

    /// The layer's name, as [`RIGOR`] and records write it.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::Exhaustive => "exhaustive",
        }
    }
}

/// The layer this run carries: [`RIGOR`] read once, `fast` when unset; any
/// other value is an error naming the two.
pub fn rigor() -> Rigor {
    static LAYER: OnceLock<Rigor> = OnceLock::new();
    *LAYER.get_or_init(|| selected(RIGOR, Rigor::ALL, Rigor::name, Rigor::Fast))
}

/// The variable naming the witness sizes a run carries.
pub const WITNESS: &str = "DCBOR_WITNESS";

/// The witness sizes a run carries: `full`, the default, which the native
/// layers run; or `minimal`, the boundary-minimal size of every class a
/// matrix covers, which the Miri gate and the reach map run
/// (`tests/support/rigor.rs`, `sized`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Witness {
    Full,
    Minimal,
}

impl Witness {
    pub const ALL: [Self; 2] = [Self::Full, Self::Minimal];

    /// The sizes' name, as [`WITNESS`] and records write it.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Minimal => "minimal",
        }
    }
}

/// The witness sizes this run carries: [`WITNESS`] read once, `full` when
/// unset; any other value is an error naming the two.
pub fn witness() -> Witness {
    static SIZES: OnceLock<Witness> = OnceLock::new();
    *SIZES.get_or_init(|| selected(WITNESS, Witness::ALL, Witness::name, Witness::Full))
}

/// The member of `all` that `variable` names by `name`, `default` when it
/// is unset; any other value, or a value that is not Unicode, is an error
/// naming every member. The one reading of a selection variable.
fn selected<T: Copy, const N: usize>(
    variable: &str,
    all: [T; N],
    name: fn(T) -> &'static str,
    default: T,
) -> T {
    match std::env::var(variable) {
        Err(std::env::VarError::NotPresent) => default,
        Ok(value) => all
            .into_iter()
            .find(|member| name(*member) == value)
            .unwrap_or_else(|| panic!("{variable}={value:?}: the values are {:?}", all.map(name))),
        Err(error) => panic!("{variable}: {error}"),
    }
}

/// The variable the development shells export naming the configuration a
/// run is under.
pub const CONFIGURATION: &str = "DCBOR_CONFIGURATION";

/// The first line of every record: this marker, then its configuration.
pub const CONFIGURATION_LINE: &str = "#\tconfiguration\t";

/// The configuration this run is under, when its shell exports one.
pub fn configuration() -> Option<String> {
    std::env::var(CONFIGURATION)
        .ok()
        .filter(|identity| !identity.is_empty())
}

/// The configuration this run is under, required: recording under no named
/// configuration would publish evidence no reader could place.
pub fn recording_configuration() -> String {
    configuration().unwrap_or_else(|| {
        panic!("recording requires {CONFIGURATION}, which the flake's shells export")
    })
}

/// What a recorded row establishes: the one vocabulary of evidence classes,
/// kept apart from the tool that produced the row and the scope it covers.
/// Every gate's results row (`tests/gate`, `rows`) and every tightness ratio
/// (`src/bounded.rs`, `places`) carries one; each writer derives it from what
/// its run was, by one definition per record, and each reader refuses a row
/// claiming another class than its run supports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Evidence {
    /// Checked against the specification's own published data.
    Normative,
    /// Discharged by a proof tool over a stated domain. No proof runner
    /// exists yet, so no writer derives this class and every row claiming it
    /// is refused.
    Proved,
    /// A test run on its inputs passed, natively or under Miri's checks for
    /// undefined behavior.
    Checked,
    /// Sampled: seeded schedules, or measured quantities.
    Observed,
    /// Computed from other evidence or measurement, not itself a check.
    Derived,
    /// Every interleaving of a model explored within a recorded bound.
    Modeled,
    /// The run never started.
    Unverified,
}

impl Evidence {
    pub const ALL: [Self; 7] = [
        Self::Normative,
        Self::Proved,
        Self::Checked,
        Self::Observed,
        Self::Derived,
        Self::Modeled,
        Self::Unverified,
    ];

    /// The class's name, as records write it.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Normative => "normative",
            Self::Proved => "proved",
            Self::Checked => "checked",
            Self::Observed => "observed",
            Self::Derived => "derived",
            Self::Modeled => "modeled",
            Self::Unverified => "unverified",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|class| class.name() == text)
    }
}

impl std::fmt::Display for Evidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// A record of `rows` under `configuration`: the header, then each row and
/// its newline.
pub fn render<'r>(configuration: &str, rows: impl IntoIterator<Item = &'r str>) -> String {
    let mut data = format!("{CONFIGURATION_LINE}{configuration}\n");
    for row in rows {
        data.push_str(row);
        data.push('\n');
    }
    data
}

/// A record read: the configuration it names, and each row with its line
/// number in the record.
#[derive(Debug, PartialEq, Eq)]
pub struct Record<'d> {
    pub configuration: &'d str,
    pub rows: Vec<(usize, &'d str)>,
}

/// `data`, the record at `path`, read: its configuration line required,
/// the rows after it in order. `record_with` names how the record is
/// written, for a reader whose record lacks its configuration line.
pub fn read<'d>(path: &str, data: &'d str, record_with: &str) -> Record<'d> {
    try_read(data).unwrap_or_else(|| {
        panic!(
            "{path}:1: not the configuration it was recorded under; record it with {record_with}"
        )
    })
}

/// `data` read as a record, or `None` when its first line is not a
/// configuration line: how a gate tells a record from any other file.
pub fn try_read(data: &str) -> Option<Record<'_>> {
    let mut lines = data.lines();
    let configuration = lines.next()?.strip_prefix(CONFIGURATION_LINE)?;
    Some(Record {
        configuration,
        rows: lines
            .enumerate()
            .map(|(index, row)| (index + 2, row))
            .collect(),
    })
}

/// Publish `data` as `path` whole: written to a temporary file beside it,
/// then renamed over it, so a failed write leaves the previous record.
pub fn publish(path: &str, data: &str) {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let temporary = format!(
        "{path}.{}.{}.tmp",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .unwrap_or_else(|error| panic!("{temporary}: {error}"));
    let result = file
        .write_all(data.as_bytes())
        .and_then(|_| file.sync_all());
    drop(file);
    if let Err(error) = result.and_then(|_| std::fs::rename(&temporary, path)) {
        // The rename's or the write's error is the one reported; a temporary
        // file that cannot be removed adds nothing to it.
        let _ = std::fs::remove_file(&temporary);
        panic!("{path}: {error}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A record renders its configuration first and its rows in order, is
    /// read back to the same configuration and rows with their line numbers,
    /// and is published whole, leaving no temporary file beside it.
    #[test]
    fn a_record_names_its_configuration_and_is_published_whole() {
        let data = render("toolchain=t std=s", ["one\t1", "two\t2"]);
        assert_eq!(
            data,
            format!("{CONFIGURATION_LINE}toolchain=t std=s\none\t1\ntwo\t2\n")
        );
        let record = read("planted", &data, "planted=1");
        assert_eq!(record.configuration, "toolchain=t std=s");
        assert_eq!(record.rows, vec![(2, "one\t1"), (3, "two\t2")]);
        let directory = std::env::temp_dir().join(format!("dcbor-record-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("a temporary directory");
        let path = directory.join("record.txt");
        let path = path.to_str().expect("a UTF-8 temporary path");
        std::fs::write(path, "previous").expect("the previous record");
        publish(path, &data);
        assert_eq!(std::fs::read_to_string(path).expect("the record"), data);
        assert_eq!(
            std::fs::read_dir(&directory).unwrap().count(),
            1,
            "temporary evidence was not removed"
        );
        std::fs::remove_dir_all(&directory).expect("the temporary directory removed");
    }

    /// Every evidence class reads back its name; another name is none.
    #[test]
    fn every_evidence_class_reads_back_its_name() {
        for class in Evidence::ALL {
            assert_eq!(Evidence::parse(class.name()), Some(class));
            assert_eq!(class.to_string(), class.name());
        }
        assert_eq!(Evidence::parse("verified"), None);
    }

    /// A file whose first line is not a configuration line is no record.
    #[test]
    fn a_file_without_a_configuration_line_is_no_record() {
        assert_eq!(try_read("unrecognized evidence\n"), None);
        assert_eq!(try_read(""), None);
        assert_eq!(
            try_read(&render("c", ["row"])),
            Some(Record {
                configuration: "c",
                rows: vec![(2, "row")],
            })
        );
    }

    /// A record without its configuration line is refused, naming how to
    /// record it.
    #[test]
    #[should_panic(
        expected = "planted:1: not the configuration it was recorded under; record it with planted=1"
    )]
    fn a_record_without_its_configuration_line_is_refused() {
        read("planted", "one\t1\n", "planted=1");
    }
}
