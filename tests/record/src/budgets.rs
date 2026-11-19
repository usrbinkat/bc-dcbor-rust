//! Recording budgets: the observation storage each budgeted fixture was
//! measured to need, one record per family, representation variant, rigor
//! layer and witness size ([`inventory`], from the families of
//! `tests/data/budgets/families.rs` and [`VARIANTS`]). Rows are `fixture\tevents\tpermits` after the configuration
//! line. The counts size a recording session preallocated before the
//! fixture runs; they are not expected accounting totals. A record's
//! currency against the running configuration is the evidence gate's
//! (`gate evidence`); a reader here checks its form and its completeness.
use crate::{Rigor, VARIANTS, Witness};
use std::collections::{BTreeMap, BTreeSet};

/// Every budgeted family ([`FAMILIES`]), from its one inventory
/// (`tests/data/budgets/families.rs`): its name, its test target, the exact
/// test that measures it, and whether it is compiled only over the forked
/// collections.
macro_rules! families {
    ($(($name:literal, $target:literal, $test:literal, $custom:literal)),* $(,)?) => {
        pub const FAMILIES: &[(&str, &str, &str, bool)] = &[$(($name, $target, $test, $custom)),*];
    };
}

include!("../../data/budgets/families.rs");

/// One budget record to hold: its file name under `tests/data/budgets`, the
/// features of its projection, the test target and the exact test that
/// records and checks it, and the selection it is recorded under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Selection {
    pub name: String,
    pub features: &'static str,
    pub target: &'static str,
    pub test: &'static str,
    pub rigor: Rigor,
    pub witness: Witness,
}

/// The file name of `family`'s record under the projection of `suffix` and
/// the selection of `rigor` and `witness`: the one naming of a record, its
/// recorder's, its embedding's and its reader's.
pub fn record_name(family: &str, suffix: &str, rigor: Rigor, witness: Witness) -> String {
    format!("{family}{suffix}.{}.{}.txt", rigor.name(), witness.name())
}

/// Every record the budget families must hold: each family in every
/// variant it is compiled in, at every layer and witness size.
pub fn inventory() -> impl Iterator<Item = Selection> {
    FAMILIES.iter().flat_map(|&(family, target, test, custom)| {
        VARIANTS
            .iter()
            .filter(move |(suffix, _)| !custom || suffix.starts_with(".custom-std"))
            .flat_map(move |&(suffix, features)| {
                Rigor::ALL.into_iter().flat_map(move |rigor| {
                    Witness::ALL.into_iter().map(move |witness| Selection {
                        name: record_name(family, suffix, rigor, witness),
                        features,
                        target,
                        test,
                        rigor,
                        witness,
                    })
                })
            })
    })
}

/// What a finished recording held: its observations and its permit records
/// (each grant and each split child).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Counts {
    pub events: usize,
    pub permits: usize,
}

impl Counts {
    /// A recording holds at least one observation, and every permit record
    /// is one of its observations.
    fn validate(self) -> Result<Self, String> {
        if self.events == 0 || self.permits > self.events {
            return Err(format!("invalid counts {self:?}"));
        }
        Ok(self)
    }
}

/// Require a nonempty, unambiguous inventory of single-field fixture
/// identities: no identity empty, none holding whitespace (a row's field
/// separator or its line end), none twice.
pub fn validate_inventory(expected: &[String]) -> Result<(), String> {
    if expected.is_empty() {
        return Err("empty budget inventory".into());
    }
    let mut keys = BTreeSet::new();
    for key in expected {
        if key.is_empty() || key.chars().any(char::is_whitespace) {
            return Err(format!("invalid budget fixture identity {key:?}"));
        }
        if !keys.insert(key) {
            return Err(format!("duplicate fixture in budget inventory: {key}"));
        }
    }
    Ok(())
}

/// Whether `measured` is the whole family `expected` declares, every count
/// valid: no fixture missing, none unexpected. The one completeness check
/// of a family, its reader's and its publisher's.
pub fn complete(expected: &[String], measured: &BTreeMap<String, Counts>) -> Result<(), String> {
    validate_inventory(expected)?;
    for (key, counts) in measured {
        counts
            .validate()
            .map_err(|error| format!("{key}: {error}"))?;
    }
    let wanted: BTreeSet<&String> = expected.iter().collect();
    let keys: BTreeSet<&String> = measured.keys().collect();
    if keys != wanted {
        return Err(format!(
            "budget inventory differs: missing {:?}, unexpected {:?}",
            wanted.difference(&keys).collect::<Vec<_>>(),
            keys.difference(&wanted).collect::<Vec<_>>()
        ));
    }
    Ok(())
}

/// `data` read as the complete family `expected`: its configuration line
/// required, each row three fields of a fixture and its two counts, no
/// fixture twice, the family complete ([`complete`]).
pub fn read(data: &str, expected: &[String]) -> Result<BTreeMap<String, Counts>, String> {
    let record = crate::try_read(data).ok_or("budget record has no configuration line")?;
    let mut found = BTreeMap::new();
    for (line, row) in record.rows {
        let fields: Vec<&str> = row.split('\t').collect();
        let [key, events, permits] = fields.as_slice() else {
            return Err(format!(
                "budget line {line}: expected fixture, events, permits"
            ));
        };
        let count = |text: &str| {
            text.parse::<usize>()
                .map_err(|error| format!("budget line {line}: {error}"))
        };
        let counts = Counts {
            events: count(events)?,
            permits: count(permits)?,
        };
        if found.insert((*key).to_string(), counts).is_some() {
            return Err(format!("budget line {line}: duplicate fixture {key}"));
        }
    }
    complete(expected, &found)?;
    Ok(found)
}

/// Publish `measured` at `path` under `configuration`, whole, once it is
/// the complete family `expected` ([`complete`]); an incomplete family is
/// refused and the previous record left intact ([`crate::publish`]).
pub fn publish(
    path: &str,
    configuration: &str,
    expected: &[String],
    measured: &BTreeMap<String, Counts>,
) -> Result<(), String> {
    complete(expected, measured)?;
    let rows: Vec<String> = measured
        .iter()
        .map(|(key, counts)| format!("{key}\t{}\t{}", counts.events, counts.permits))
        .collect();
    crate::publish(
        path,
        &crate::render(configuration, rows.iter().map(String::as_str)),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_duplicate_and_multifield_inventories_are_refused() {
        for expected in [
            vec![],
            vec!["".into()],
            vec!["fixture".into(), "fixture".into()],
            vec!["fixture\tinjected".into()],
            vec!["fixture\ninjected".into()],
        ] {
            assert!(validate_inventory(&expected).is_err(), "{expected:?}");
            assert!(read(&crate::render("control", []), &expected).is_err());
        }
        validate_inventory(&["fixture/one".into(), "fixture/two".into()])
            .expect("distinct fixture identities");
    }

    #[test]
    fn incomplete_publication_preserves_previous_evidence() {
        let directory =
            std::env::temp_dir().join(format!("dcbor-budget-publication-{}", std::process::id()));
        std::fs::create_dir(&directory).expect("unique publication test directory");
        let path = directory.join("budget.txt");
        let path = path.to_str().expect("test path is UTF-8");
        let expected: Vec<String> = vec!["fixture/one".into(), "fixture/two".into()];
        let complete = BTreeMap::from([
            (
                expected[0].clone(),
                Counts {
                    events: 2,
                    permits: 1,
                },
            ),
            (
                expected[1].clone(),
                Counts {
                    events: 3,
                    permits: 0,
                },
            ),
        ]);
        publish(path, "control", &expected, &complete).expect("a complete family publishes");
        let previous = std::fs::read(path).expect("published evidence");
        assert_eq!(
            read(&String::from_utf8(previous.clone()).unwrap(), &expected),
            Ok(complete.clone())
        );
        let mut incomplete = complete;
        incomplete.remove(&expected[1]);
        assert!(publish(path, "control", &expected, &incomplete).is_err());
        assert_eq!(std::fs::read(path).unwrap(), previous);
        std::fs::remove_dir_all(directory).expect("remove publication test directory");
    }

    #[test]
    fn incomplete_ambiguous_and_malformed_budgets_are_refused() {
        let expected = vec!["round-trip/12/0".into(), "construction/144".into()];
        let rows = ["round-trip/12/0\t4211\t119", "construction/144\t9000\t30"];
        let data = crate::render("fork", rows);
        assert_eq!(read(&data, &expected).unwrap().len(), 2);
        for invalid in [
            rows.join("\n"),
            crate::render("fork", [rows[0]]),
            crate::render("fork", [rows[0], rows[1], rows[0]]),
            crate::render("fork", [rows[0], rows[1], "unknown\t1\t1"]),
            data.replace("4211", "invalid"),
            data.replace("4211", "0"),
            data.replace("119", "99999"),
            data.replace("\t119", "\t119\textra"),
        ] {
            assert!(read(&invalid, &expected).is_err(), "{invalid}");
        }
    }
}
