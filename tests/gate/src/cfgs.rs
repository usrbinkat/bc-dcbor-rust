//! Completeness of the crate's `cfg` predicates (G11): every predicate the
//! census records (`dcbor_census::CensusCfg`, every `cfg`, `cfg!` and
//! `cfg_attr` of the crate's sources and tests) holds, as a whole
//! expression, in some build the gates make; a `cfg!` is also false in
//! some, since each of its values is a path. Code under a predicate that
//! holds in no gated build is compiled by no gate: never tested, never
//! interpreted under Miri, never mutated.
//!
//! The builds are every domain ([`domains::DOMAINS`]), with and without
//! `cfg(test)` and under Miri and natively; every record variant
//! ([`records::VARIANTS`]), its library tests; and each model checker's
//! release build of every feature (`process::build`), with and without
//! `cfg(test)`. Each build's features are resolved from the package's
//! feature table as `cargo metadata` reports it, which lists an optional
//! dependency's implicit feature beside the declared ones (cargo
//! `Summary::build_feature_map`); a feature enables what it lists, a
//! `dep/feature` entry the dependency's implicit feature when it has one, a
//! `dep:` or `dep?/feature` entry no feature of this package.
//!
//! A predicate naming an atom no build defines is refused, never taken as
//! false. A predicate that holds in no build by design (the guard that
//! refuses two model checkers at once) is exempted by file and expression
//! with its reason; an exemption that matches nothing is stale.

use std::collections::{BTreeMap, BTreeSet};

use dcbor_census::{CensusCfg, CfgForm};
use dcbor_model_bounds::Checker;

use crate::{domains, records};

/// A `cfg` expression.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expr {
    All(Vec<Expr>),
    Any(Vec<Expr>),
    Not(Box<Expr>),
    /// A name: `test`, `unix`, `loom`.
    Name(String),
    /// A key and its value: `feature = "std"`.
    Pair(String, String),
}

/// The names a build defines or not.
const NAMES: &[&str] = &[
    "test",
    "miri",
    "loom",
    "shuttle",
    "unix",
    "debug_assertions",
];

/// The keys a build gives values.
const KEYS: &[&str] = &["feature", "target_pointer_width"];

/// One token of an expression's rendering.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    Ident(String),
    Text(String),
    Open,
    Close,
    Comma,
    Equals,
}

fn tokens(text: &str) -> Result<Vec<Token>, String> {
    let mut found = Vec::new();
    let mut chars = text.char_indices().peekable();
    while let Some((at, c)) = chars.next() {
        match c {
            ' ' => {}
            '(' => found.push(Token::Open),
            ')' => found.push(Token::Close),
            ',' => found.push(Token::Comma),
            '=' => found.push(Token::Equals),
            '"' => {
                let mut value = String::new();
                loop {
                    match chars.next() {
                        Some((_, '"')) => break,
                        Some((_, '\\')) => return Err(format!("an escape in {text:?}")),
                        Some((_, c)) => value.push(c),
                        None => return Err(format!("an unterminated string in {text:?}")),
                    }
                }
                found.push(Token::Text(value));
            }
            c if c == '_' || c.is_ascii_alphabetic() => {
                let mut name = c.to_string();
                while let Some(&(_, c)) = chars.peek() {
                    if c == '_' || c.is_ascii_alphanumeric() {
                        name.push(c);
                        chars.next();
                    } else {
                        break;
                    }
                }
                found.push(Token::Ident(name));
            }
            other => return Err(format!("{other:?} at {at} of {text:?}")),
        }
    }
    Ok(found)
}

/// The expression `text`, the whole of it; an atom no build defines, or a
/// malformed expression, is refused.
pub fn parse(text: &str) -> Result<Expr, String> {
    let tokens = tokens(text)?;
    let (expr, rest) = expression(&tokens)?;
    if rest.is_empty() {
        Ok(expr)
    } else {
        Err(format!("{text:?}: more after the expression"))
    }
}

fn expression(tokens: &[Token]) -> Result<(Expr, &[Token]), String> {
    match tokens {
        [Token::Ident(name), Token::Open, rest @ ..]
            if matches!(name.as_str(), "all" | "any" | "not") =>
        {
            let mut items = Vec::new();
            let mut rest = rest;
            loop {
                if let [Token::Close, after @ ..] = rest {
                    rest = after;
                    break;
                }
                let (item, after) = expression(rest)?;
                items.push(item);
                rest = match after {
                    [Token::Comma, after @ ..] => after,
                    [Token::Close, ..] => after,
                    other => return Err(format!("{other:?}: not a list of predicates")),
                };
            }
            let expr = match name.as_str() {
                "all" => Expr::All(items),
                "any" => Expr::Any(items),
                _ => match <[Expr; 1]>::try_from(items) {
                    Ok([item]) => Expr::Not(Box::new(item)),
                    Err(items) => return Err(format!("not() of {} predicates", items.len())),
                },
            };
            Ok((expr, rest))
        }
        [
            Token::Ident(key),
            Token::Equals,
            Token::Text(value),
            rest @ ..,
        ] => {
            if !KEYS.contains(&key.as_str()) {
                return Err(format!("an unknown cfg key {key:?}: the keys are {KEYS:?}"));
            }
            Ok((Expr::Pair(key.clone(), value.clone()), rest))
        }
        [Token::Ident(name), rest @ ..] => {
            if !NAMES.contains(&name.as_str()) {
                return Err(format!(
                    "an unknown cfg name {name:?}: the names are {NAMES:?}"
                ));
            }
            Ok((Expr::Name(name.clone()), rest))
        }
        other => Err(format!("{other:?}: not a predicate")),
    }
}

/// One build the gates make: its name, its enabled features and the names
/// it defines. Every build is the host's: `unix`, 64-bit pointers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Build {
    pub name: String,
    pub features: BTreeSet<String>,
    pub names: BTreeSet<&'static str>,
}

impl Build {
    /// Whether `expr` holds in this build.
    pub fn holds(&self, expr: &Expr) -> bool {
        match expr {
            Expr::All(items) => items.iter().all(|item| self.holds(item)),
            Expr::Any(items) => items.iter().any(|item| self.holds(item)),
            Expr::Not(item) => !self.holds(item),
            Expr::Name(name) => self.names.contains(name.as_str()),
            Expr::Pair(key, value) => match key.as_str() {
                "feature" => self.features.contains(value),
                // `KEYS`: the host's pointer width.
                _ => value == "64",
            },
        }
    }
}

/// The package's feature table as `cargo metadata --no-deps
/// --format-version 1` reports it in `metadata`, JSON, for `package`.
pub fn feature_table(
    metadata: &str,
    package: &str,
) -> Result<BTreeMap<String, Vec<String>>, String> {
    let value: serde_json::Value =
        serde_json::from_str(metadata).map_err(|error| format!("not cargo metadata: {error}"))?;
    let found = value["packages"]
        .as_array()
        .ok_or("cargo metadata names no packages")?
        .iter()
        .find(|entry| entry["name"] == package)
        .ok_or_else(|| format!("cargo metadata has no package {package}"))?;
    serde_json::from_value(found["features"].clone())
        .map_err(|error| format!("{package}'s features: {error}"))
}

/// The features `requested` enables in `table`, each followed through what
/// it lists ([`self`]): `dep:x` and `x?/y` enable no feature of this
/// package, `x/y` enables `x` when `x` is a feature. A requested name that is
/// no feature is refused.
pub fn resolve(
    table: &BTreeMap<String, Vec<String>>,
    requested: &[&str],
) -> Result<BTreeSet<String>, String> {
    let mut enabled = BTreeSet::new();
    let mut pending: Vec<String> = Vec::new();
    for name in requested {
        if !table.contains_key(*name) {
            return Err(format!("no feature {name:?}"));
        }
        pending.push((*name).to_string());
    }
    while let Some(name) = pending.pop() {
        if !enabled.insert(name.clone()) {
            continue;
        }
        for entry in &table[&name] {
            if entry.starts_with("dep:") {
                continue;
            }
            let feature = match entry.split_once('/') {
                Some((dependency, _)) if dependency.ends_with('?') => continue,
                Some((dependency, _)) => dependency,
                None => entry.as_str(),
            };
            if table.contains_key(feature) {
                pending.push(feature.to_string());
            } else if !entry.contains('/') {
                return Err(format!("{name} lists {entry:?}, no feature"));
            }
        }
    }
    Ok(enabled)
}

/// The features a cargo selection of `arguments` enables
/// (`--all-features`, `--no-default-features`, `--features a,b`).
fn selected(
    table: &BTreeMap<String, Vec<String>>,
    arguments: &[&str],
) -> Result<BTreeSet<String>, String> {
    if arguments.contains(&"--all-features") {
        return Ok(table.keys().cloned().collect());
    }
    let mut requested: Vec<&str> = Vec::new();
    if !arguments.contains(&"--no-default-features") && table.contains_key("default") {
        requested.push("default");
    }
    let mut at = arguments.iter();
    while let Some(argument) = at.next() {
        if *argument == "--features" {
            let list = at.next().ok_or("--features names no features")?;
            requested.extend(list.split(',').filter(|name| !name.is_empty()));
        } else if !matches!(*argument, "--no-default-features") {
            return Err(format!("{argument:?}: not a feature selection"));
        }
    }
    resolve(table, &requested)
}

/// Every build the gates make ([`self`]), from the package's feature table.
pub fn builds(table: &BTreeMap<String, Vec<String>>) -> Result<Vec<Build>, String> {
    let mut found = Vec::new();
    let build = |name: String, features: &BTreeSet<String>, names: &[&'static str]| Build {
        name,
        features: features.clone(),
        names: ["unix"].into_iter().chain(names.iter().copied()).collect(),
    };
    for domain in domains::DOMAINS {
        let features = selected(table, domain.features)
            .map_err(|error| format!("domain {}: {error}", domain.name))?;
        for (variant, names) in [
            ("", &["debug_assertions"][..]),
            (" tests", &["debug_assertions", "test"][..]),
            (" under Miri", &["debug_assertions", "miri"][..]),
            (
                " tests under Miri",
                &["debug_assertions", "test", "miri"][..],
            ),
        ] {
            found.push(build(format!("{}{variant}", domain.name), &features, names));
        }
    }
    for (suffix, list) in records::VARIANTS {
        let features = selected(table, &["--features", list])
            .map_err(|error| format!("record variant {suffix:?}: {error}"))?;
        found.push(build(
            format!("record variant {list}"),
            &features,
            &["debug_assertions", "test"],
        ));
    }
    let every = selected(table, &["--all-features"])?;
    for checker in Checker::ALL {
        for (variant, test) in [("", false), (" tests", true)] {
            let mut names = vec![checker.name()];
            if test {
                names.push("test");
            }
            found.push(Build {
                name: format!("{checker} release{variant}"),
                features: every.clone(),
                names: ["unix"].into_iter().chain(names).collect(),
            });
        }
    }
    Ok(found)
}

/// The predicates that hold in no gated build by design, each by file,
/// expression and why.
pub const EXEMPTIONS: &[(&str, &str, &str)] = &[(
    "src/sync.rs",
    "all (loom , shuttle)",
    "the guard that refuses building under two model checkers at once (compile_error!)",
)];

/// Every fault of `cfgs` against `builds` and `exemptions`: a predicate that
/// does not parse, a `cfg` or `cfg_attr` predicate holding in no build, a
/// `cfg!` not both true and false across the builds, an exemption without a
/// reason, and a stale exemption.
pub fn faults(
    cfgs: &[CensusCfg],
    builds: &[Build],
    exemptions: &[(&str, &str, &str)],
) -> Vec<String> {
    let mut faults = Vec::new();
    let mut used = vec![false; exemptions.len()];
    for cfg in cfgs {
        let shown = format!(
            "{}:{}: {}({})",
            cfg.file,
            cfg.line,
            cfg.form.name(),
            cfg.predicate
        );
        let expr = match parse(&cfg.predicate) {
            Ok(expr) => expr,
            Err(error) => {
                faults.push(format!("{shown}: {error}"));
                continue;
            }
        };
        let holding = builds.iter().any(|build| build.holds(&expr));
        let failing = builds.iter().any(|build| !build.holds(&expr));
        let complete = match cfg.form {
            CfgForm::Attribute | CfgForm::Attr => holding,
            CfgForm::Macro => holding && failing,
        };
        if complete {
            continue;
        }
        if let Some(at) = exemptions
            .iter()
            .position(|&(file, predicate, _)| file == cfg.file && predicate == cfg.predicate)
        {
            used[at] = true;
            continue;
        }
        faults.push(if holding {
            format!(
                "{shown}: true in every build the gates make, so its false path is compiled by none"
            )
        } else {
            format!("{shown}: holds in no build the gates make")
        });
    }
    for (at, &(file, predicate, reason)) in exemptions.iter().enumerate() {
        if reason.is_empty() {
            faults.push(format!(
                "{file}: {predicate}: an exemption without a reason"
            ));
        }
        if !used[at] {
            faults.push(format!("{file}: {predicate}: a stale exemption"));
        }
    }
    faults
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> BTreeMap<String, Vec<String>> {
        [
            ("default", &["std"][..]),
            ("std", &["half/std", "thiserror/std"][..]),
            ("no_std", &["hashbrown", "thiserror"][..]),
            ("num-bigint", &["dep:num-bigint"][..]),
            ("custom-std-collections", &["std"][..]),
            ("derive", &["dep:dcbor-derive"][..]),
            ("multithreaded", &[][..]),
            ("hashbrown", &["dep:hashbrown"][..]),
            ("thiserror", &["dep:thiserror"][..]),
        ]
        .into_iter()
        .map(|(name, list)| {
            (
                name.to_string(),
                list.iter().map(ToString::to_string).collect(),
            )
        })
        .collect()
    }

    fn set(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(ToString::to_string).collect()
    }

    /// Features resolve as Cargo resolves them: `std` enables the implicit
    /// `thiserror` through `thiserror/std`, `half/std` names no feature,
    /// `dep:` enables none; an unknown feature is refused.
    #[test]
    fn features_resolve_as_cargo_resolves_them() {
        let table = table();
        assert_eq!(resolve(&table, &["std"]), Ok(set(&["std", "thiserror"])));
        assert_eq!(
            selected(&table, &["--no-default-features", "--features", "no_std"]),
            Ok(set(&["hashbrown", "no_std", "thiserror"]))
        );
        assert_eq!(
            selected(&table, &[]),
            Ok(set(&["default", "std", "thiserror"]))
        );
        assert_eq!(
            selected(&table, &["--all-features"]).unwrap().len(),
            table.len()
        );
        assert!(
            resolve(&table, &["serde"])
                .unwrap_err()
                .contains("no feature")
        );
    }

    /// Whole expressions parse and evaluate; an unknown name or key is
    /// refused, never false.
    #[test]
    fn whole_expressions_evaluate_and_unknown_atoms_are_refused() {
        let build = Build {
            name: "b".to_string(),
            features: set(&["std", "hashbrown"]),
            names: ["unix", "test"].into_iter().collect(),
        };
        for (text, holds) in [
            ("test", true),
            ("not (test)", false),
            ("all (test , feature = \"std\")", true),
            (
                "any (feature = \"custom-std-collections\" , feature = \"hashbrown\")",
                true,
            ),
            (
                "not (any (feature = \"hashbrown\" , feature = \"custom-std-collections\"))",
                false,
            ),
            ("all (unix , target_pointer_width = \"64\")", true),
            ("all (shuttle , not (loom))", false),
        ] {
            assert_eq!(build.holds(&parse(text).unwrap()), holds, "{text}");
        }
        assert!(parse("windows").unwrap_err().contains("unknown cfg name"));
        assert!(
            parse("target_os = \"linux\"")
                .unwrap_err()
                .contains("unknown cfg key")
        );
        assert!(
            parse("not (test , unix)")
                .unwrap_err()
                .contains("not() of 2")
        );
        assert!(parse("test unix").unwrap_err().contains("more after"));
    }

    fn cfg(predicate: &str, form: CfgForm) -> CensusCfg {
        CensusCfg {
            file: "src/a.rs".to_string(),
            line: 7,
            form,
            predicate: predicate.to_string(),
        }
    }

    /// The planted controls: a predicate holding in no build, a `cfg!`
    /// true in every build, an unknown atom, an exemption without a reason
    /// and a stale one are each named; a predicate holding somewhere, a
    /// `cfg!` both ways and an exempted guard pass.
    #[test]
    fn a_predicate_no_build_compiles_is_named() {
        let builds = builds(&table()).unwrap();
        assert!(
            builds
                .iter()
                .any(|build| build.name == "std tests under Miri")
        );
        let cfgs = [
            cfg(
                "not (any (feature = \"hashbrown\" , feature = \"custom-std-collections\"))",
                CfgForm::Attribute,
            ),
            cfg("feature = \"num-bigint\"", CfgForm::Macro),
            cfg("all (loom , shuttle)", CfgForm::Attribute),
            cfg(
                "all (feature = \"std\" , not (feature = \"std\"))",
                CfgForm::Attribute,
            ),
            cfg("unix", CfgForm::Macro),
            cfg("windows", CfgForm::Attr),
        ];
        assert_eq!(
            faults(
                &cfgs,
                &builds,
                &[
                    ("src/a.rs", "all (loom , shuttle)", "the guard"),
                    ("src/a.rs", "test", ""),
                ]
            ),
            vec![
                "src/a.rs:7: cfg(all (feature = \"std\" , not (feature = \"std\"))): holds in no build the gates make"
                    .to_string(),
                "src/a.rs:7: cfg!(unix): true in every build the gates make, so its false path is compiled by none"
                    .to_string(),
                "src/a.rs:7: cfg_attr(windows): an unknown cfg name \"windows\": the names are [\"test\", \"miri\", \"loom\", \"shuttle\", \"unix\", \"debug_assertions\"]"
                    .to_string(),
                "src/a.rs: test: an exemption without a reason".to_string(),
                "src/a.rs: test: a stale exemption".to_string(),
            ]
        );
    }
}
