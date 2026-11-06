//! The build domains every gate runs in, defined once: the Miri gate and the
//! reach map build each selection line in its domain
//! (`tests/miri-suites.txt`, `tests/gate-common.sh` `domain_features`), and
//! the mutation campaign draws each domain's mutants from its files and
//! judges them by its tests (`tests/mutation-evidence.sh`).
//!
//! Every feature compiles all but the code written for builds without std,
//! and the code written for builds with neither a hash table's bucket access
//! (`hashbrown`) nor the forked collections: each is a domain of its own, the
//! `no_std` build and the crate's default `std` build. Every `cfg` predicate
//! of the crate is true in some build the gates make (`cfgs`).

/// One build domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Domain {
    pub name: &'static str,
    /// Its cargo feature arguments.
    pub features: &'static [&'static str],
    /// The files its mutants are drawn from, as cargo-mutants' `--file`
    /// takes them.
    pub files: &'static [&'static str],
    /// The test selection that judges its mutants.
    pub tests: &'static [&'static str],
}

/// Every domain.
pub const DOMAINS: &[Domain] = &[
    Domain {
        name: "all-features",
        features: &["--all-features"],
        files: &[
            "src/bounded/decode/storage.rs",
            "src/bounded/decode/construction/stable.rs",
            "src/bounded/decode/construction/in_place/*.rs",
            "src/bounded/decode/construction/in_place/btree/*.rs",
            "src/bounded/decode/construction/reclamation/*.rs",
            "src/bounded/encoding/writer.rs",
            "src/bounded/text_cursor/initialization.rs",
        ],
        tests: &["--workspace", "--all-targets"],
    },
    // The domain's only code compiled without std and never under every
    // feature: the decode scope's abort, in the file that holds it. The
    // derive crate's tests need std, so the package's own targets judge.
    Domain {
        name: "no_std",
        features: &["--no-default-features", "--features", "no_std"],
        files: &["src/bounded/decode/construction/reclamation/owned.rs"],
        tests: &["--package", "dcbor", "--all-targets"],
    },
    // The crate's default build: std with no bucket access and no forked
    // collections, whose preparation charges no bucket traversal
    // (`encoding::bucket_work`) and retains no bucket cursor, code no other
    // domain compiles.
    Domain {
        name: "std",
        features: &["--no-default-features", "--features", "std"],
        files: &["src/bounded/encoding.rs"],
        tests: &["--package", "dcbor", "--all-targets"],
    },
];

/// The domain named `name`; any other name is refused, naming the domains.
pub fn domain(name: &str) -> Result<&'static Domain, String> {
    DOMAINS
        .iter()
        .find(|domain| domain.name == name)
        .ok_or_else(|| format!("unknown domain {name:?}: the domains are {}", names()))
}

/// The domains' names, comma-separated.
pub fn names() -> String {
    DOMAINS
        .iter()
        .map(|domain| domain.name)
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each domain is found by its name and is distinct; an unknown name is
    /// refused naming every domain.
    #[test]
    fn every_domain_is_found_by_its_name_and_no_other_is() {
        for domain in DOMAINS {
            assert_eq!(super::domain(domain.name), Ok(domain));
            assert!(
                !domain.features.is_empty() && !domain.files.is_empty() && !domain.tests.is_empty()
            );
        }
        let names: std::collections::BTreeSet<_> =
            DOMAINS.iter().map(|domain| domain.name).collect();
        assert_eq!(names.len(), DOMAINS.len());
        assert_eq!(
            super::domain("stable"),
            Err("unknown domain \"stable\": the domains are all-features, no_std, std".to_string())
        );
    }
}
