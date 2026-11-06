//! The recorded evidence a configuration must hold, and the one check of
//! whether a file holds a record of it ([`dcbor_record`]).
//!
//! The inventory is explicit: discovering the files present would miss a
//! family whose every variant was removed. Each family is recorded in every
//! variant of the feature projections that change what it measures
//! ([`VARIANTS`]); the families of code compiled only over the forked
//! collections are recorded in the custom-std variants alone. The families
//! are read from the one inventory the library compiles its own variant's
//! records from (`tests/data/tightness/families.rs`).

use std::path::Path;

/// The tightness families, from their one inventory
/// (`tests/data/tightness/families.rs`): [`FAMILIES`], recorded in every
/// variant, and [`CUSTOM_STD_FAMILIES`], code compiled only over the forked
/// collections, recorded in the custom-std variants alone.
macro_rules! families {
    (
        every: [$($every:literal),* $(,)?],
        custom_std: [$($custom:literal),* $(,)?] $(,)?
    ) => {
        pub const FAMILIES: &[&str] = &[$($every),*];
        pub const CUSTOM_STD_FAMILIES: &[&str] = &[$($custom),*];
    };
}

include!("../../data/tightness/families.rs");

/// The record variants: the suffix each feature projection records under,
/// and the projection's features, comma-separated as `--features` takes
/// them. The recorders run each (`tests/record-evidence.sh`, `gate
/// variants`).
pub const VARIANTS: &[(&str, &str)] = &[
    ("", "std,derive,hashbrown,multithreaded"),
    (
        ".num-bigint",
        "std,derive,hashbrown,multithreaded,num-bigint",
    ),
    (
        ".custom-std",
        "std,derive,hashbrown,multithreaded,custom-std-collections",
    ),
    (
        ".custom-std.num-bigint",
        "std,derive,hashbrown,multithreaded,custom-std-collections,num-bigint",
    ),
];

/// Why a file is not a current record.
#[derive(Debug, PartialEq, Eq)]
pub enum Fault {
    /// No file, or an empty one.
    Missing,
    /// Its first line is no configuration line.
    NotARecord,
    /// Recorded under another configuration than the one checked.
    Stale { recorded: String },
    /// A configuration line and nothing measured after it.
    NoRows,
}

impl Fault {
    /// The fault, named for the file it concerns and the configuration it
    /// was checked against.
    pub fn describe(&self, path: &Path, configuration: &str) -> String {
        let path = path.display();
        match self {
            Self::Missing => format!("{path}: missing or empty evidence"),
            Self::NotARecord => format!("{path}: no configuration line; not a record"),
            Self::Stale { recorded } => format!(
                "{path}: stale configuration\n  expected: {configuration}\n  recorded: {recorded}"
            ),
            Self::NoRows => format!("{path}: no measured evidence after the configuration"),
        }
    }
}

/// Whether `data`, a file's contents, is a record of `configuration` with
/// at least one row.
pub fn current(data: &str, configuration: &str) -> Result<(), Fault> {
    if data.is_empty() {
        return Err(Fault::Missing);
    }
    let record = dcbor_record::try_read(data).ok_or(Fault::NotARecord)?;
    if record.configuration != configuration {
        return Err(Fault::Stale {
            recorded: record.configuration.to_string(),
        });
    }
    if record.rows.is_empty() {
        return Err(Fault::NoRows);
    }
    Ok(())
}

/// Whether `data` is a record of `configuration`, whatever its rows: how a
/// gate tells this configuration's evidence from another's, or from a file
/// that is no record, neither of which a run of this configuration may
/// change or prune.
pub fn ours(data: &str, configuration: &str) -> bool {
    dcbor_record::try_read(data).is_some_and(|record| record.configuration == configuration)
}

/// A matrix cost inventory of `configuration`: a record whose first row
/// names the feature projection it was taken under, then the digest of each
/// cost record the projection's matrices produced, as given.
pub fn manifest(configuration: &str, features: &str, digests: &[&str]) -> String {
    let projection = format!("#\tfeatures\t{features}");
    dcbor_record::render(
        configuration,
        core::iter::once(projection.as_str()).chain(digests.iter().copied()),
    )
}

/// [`current`] of the file at `path`; a file that cannot be read is
/// missing.
pub fn current_file(path: &Path, configuration: &str) -> Result<(), Fault> {
    match std::fs::read_to_string(path) {
        Ok(data) => current(&data, configuration),
        Err(_) => Err(Fault::Missing),
    }
}

/// Every record the configuration must hold under `root`, the repository:
/// for each variant, its admission traces and each family's tightness
/// ratios.
pub fn inventory(root: &Path) -> Vec<std::path::PathBuf> {
    let data = root.join("tests").join("data");
    let mut paths = Vec::new();
    for (suffix, _) in VARIANTS {
        paths.push(data.join(format!("admission-traces{suffix}.txt")));
        let custom = suffix.starts_with(".custom-std");
        let families = FAMILIES
            .iter()
            .chain(custom.then_some(CUSTOM_STD_FAMILIES).into_iter().flatten());
        for family in families {
            paths.push(data.join("tightness").join(format!("{family}{suffix}.txt")));
        }
    }
    paths
}

/// Every fault of the inventory under `root` against `configuration`,
/// described: empty when every record is present and current.
pub fn evidence(root: &Path, configuration: &str) -> Vec<String> {
    inventory(root)
        .iter()
        .filter_map(|path| {
            current_file(path, configuration)
                .err()
                .map(|fault| fault.describe(path, configuration))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A record of the configuration with a row is current; a missing or
    /// empty file, a file of no record, a record of another configuration
    /// and a record with no row are each refused as what they are.
    #[test]
    fn only_a_measured_record_of_this_configuration_is_current() {
        let record = dcbor_record::render("this", ["4\t2\tmeasured\tpublished\ta values"]);
        assert_eq!(current(&record, "this"), Ok(()));
        assert_eq!(current("", "this"), Err(Fault::Missing));
        assert_eq!(current("4\t2\n", "this"), Err(Fault::NotARecord));
        assert_eq!(
            current(&record, "that"),
            Err(Fault::Stale {
                recorded: "this".to_string()
            })
        );
        assert_eq!(
            current(&dcbor_record::render("this", []), "this"),
            Err(Fault::NoRows)
        );
    }

    /// A record of this configuration is ours, rows or not; another
    /// configuration's and a file of no record are not. A manifest is a
    /// record of its projection's row, then its digests.
    #[test]
    fn a_manifest_is_a_record_of_its_projection_and_digests() {
        assert!(ours(&dcbor_record::render("this", []), "this"));
        assert!(!ours(&dcbor_record::render("that", ["row"]), "this"));
        assert!(!ours("unrecognized evidence\n", "this"));
        let data = manifest(
            "this",
            "std,derive",
            &["00000000000000aa", "00000000000000bb"],
        );
        assert_eq!(
            data,
            dcbor_record::render(
                "this",
                [
                    "#\tfeatures\tstd,derive",
                    "00000000000000aa",
                    "00000000000000bb"
                ]
            )
        );
        assert_eq!(current(&data, "this"), Ok(()));
    }

    /// The inventory names every family in every variant, the forked
    /// collections' families in the custom-std variants alone, and a tree
    /// holding all of them current passes while one stale, one missing and
    /// one empty record each fail, named.
    #[test]
    fn the_inventory_is_every_family_of_every_variant() {
        let root = std::env::temp_dir().join(format!("dcbor-gate-records-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let paths = inventory(&root);
        assert_eq!(
            paths.len(),
            VARIANTS.len() * (1 + FAMILIES.len()) + 2 * CUSTOM_STD_FAMILIES.len()
        );
        assert!(paths.contains(&root.join("tests/data/tightness/btree.custom-std.txt")));
        assert!(!paths.contains(&root.join("tests/data/tightness/btree.txt")));
        for path in &paths {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, dcbor_record::render("this", ["row"])).unwrap();
        }
        assert_eq!(evidence(&root, "this"), Vec::<String>::new());
        std::fs::write(&paths[0], dcbor_record::render("that", ["row"])).unwrap();
        std::fs::remove_file(&paths[1]).unwrap();
        std::fs::write(&paths[2], "").unwrap();
        let faults = evidence(&root, "this");
        assert_eq!(faults.len(), 3, "{faults:#?}");
        assert!(faults[0].contains("stale configuration"));
        assert!(faults[1].contains("missing or empty evidence"));
        assert!(faults[2].contains("missing or empty evidence"));
        std::fs::remove_dir_all(&root).unwrap();
    }
}
