//! The gates' results: one row per run, written as a record
//! ([`dcbor_record`]) under the configuration, its first row the run's
//! identity, its second the columns. Every gate writes and reads its
//! results through this module.

use core::fmt;
use std::path::Path;

use dcbor_model_bounds::Checker;

use crate::miri::MIRI_MODELS;
use crate::outcome::Outcome;

/// The evidence classes, defined once in the record format, which the
/// tightness records carry too.
pub use dcbor_record::Evidence;

/// The test targets whose rows are normative, each with the data its source
/// compiles in: the specification's own published conformance data, parsed
/// by the test itself (`tests/data/README.md`). Each pair is checked against
/// the source by [`normative_faults`], so a target that stops compiling in
/// its data stops being normative.
pub const NORMATIVE: &[(&str, &str)] = &[
    ("appendix_a", "data/dcbor-appendix-a.md"),
    ("normalization", "data/NormalizationTest.txt"),
];

/// What a row's run was for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Purpose {
    /// Evidence at the recorded values: it must pass.
    Normal,
    /// Evidence one under a recorded bound: it must be refused by the bound.
    BoundProbe,
    /// Evidence one page under a recorded stack: it must overflow.
    StackProbe,
    /// Measurement deriving a recorded value: not evidence.
    Derive,
    /// A planted defect: it must be refused as the control names.
    Control,
    /// A suite's verdict over its runs.
    Suite,
}

impl Purpose {
    const ALL: [Self; 6] = [
        Self::Normal,
        Self::BoundProbe,
        Self::StackProbe,
        Self::Derive,
        Self::Control,
        Self::Suite,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::BoundProbe => "bound_probe",
            Self::StackProbe => "stack_probe",
            Self::Derive => "derive",
            Self::Control => "control",
            Self::Suite => "suite",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|purpose| purpose.name() == text)
    }
}

/// Whether a row's run witnessed physical allocation: natively and under
/// Miri it does; inside a model checker it cannot (`src/sync/models.rs`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Physical {
    Witnessed,
    NotApplicable,
}

impl Physical {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Witnessed => "witnessed",
            Self::NotApplicable => "not_applicable",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        [Self::Witnessed, Self::NotApplicable]
            .into_iter()
            .find(|physical| physical.name() == text)
    }
}

/// One run.
#[derive(Clone, Debug, PartialEq)]
pub struct Row {
    /// The build's feature domain.
    pub domain: String,
    /// The selection line or model the run belongs to.
    pub line: String,
    /// What ran it: `native`, a Miri model, a model checker.
    pub runner: String,
    pub test: String,
    /// The Miri seed, where one was set.
    pub seed: Option<u64>,
    pub purpose: Purpose,
    /// `DCBOR_MODEL_BOUND`, where it was set.
    pub bound: Option<usize>,
    /// `DCBOR_MODEL_STACK`, where it was set.
    pub stack: Option<usize>,
    /// The outcome the run must produce to be evidence, planned before it
    /// ran; none for a measurement (`Derive`) and for a planted control,
    /// whose refusal is read from its log.
    pub expected: Option<Outcome>,
    pub outcome: Outcome,
    /// Wall seconds and peak resident kilobytes, where measured.
    pub seconds: Option<String>,
    pub peak_kb: Option<u64>,
    pub physical: Physical,
    /// What the run establishes: always [`supported`] of the row, set by
    /// [`Row::classified`] wherever a row is made, and refused by the
    /// verdict when a published row claims another class.
    pub evidence: Evidence,
}

/// What identifies a run among a gate's rows ([`Row::key`]): its domain,
/// line, runner, test, seed, purpose, bound and stack.
type Key<'a> = (
    &'a str,
    &'a str,
    &'a str,
    &'a str,
    Option<u64>,
    Purpose,
    Option<usize>,
    Option<usize>,
);

/// The columns, in order.
pub const COLUMNS: &str = "domain\tline\trunner\ttest\tseed\tpurpose\tbound\tstack\texpected\toutcome\tseconds\tpeak_kB\tphysical\tevidence";

/// The test target a row's run belongs to: a model checker's row names it
/// in its line; a gate's selection line is its base, `<domain>-<suite>`
/// then `-<filter>` where one is set (`tests/gate-common.sh`,
/// `each_suite`), whose suite is an integration test target, or for a `lib`
/// line the module path its filter names. None for a line of another shape.
pub fn target(row: &Row) -> Option<&str> {
    if Checker::parse(&row.runner).is_some() {
        return Some(&row.line);
    }
    row.line
        .strip_prefix(row.domain.as_str())?
        .strip_prefix('-')?
        .split('-')
        .next()
        .filter(|suite| !suite.is_empty())
}

/// The one definition of what a row's run supports, in order: a run that
/// never started or produced no verdict is unverified; a measurement, and a
/// suite's verdict over its runs, are derived; a model checker's run is
/// modeled (loom exhaustive within its branch bound, shuttle's depth-first
/// search, both within the recorded bound); a seeded Miri run is one sampled schedule of a race
/// suite, observed; a proof harness Kani verified, an evidence run that
/// passed, is proved, over the domain and assumptions its harness states
/// (`crate::proofs`); a run of a [`NORMATIVE`] target is normative; every
/// other run, native or under Miri, a probe and a control (whose refusal
/// checks the check) and a harness that did not verify included, is
/// checked.
pub fn supported(row: &Row) -> Evidence {
    if matches!(row.outcome, Outcome::NotRun | Outcome::NoVerdict) {
        Evidence::Unverified
    } else if matches!(row.purpose, Purpose::Derive | Purpose::Suite) {
        Evidence::Derived
    } else if row.runner == crate::proofs::RUNNER
        && row.purpose == Purpose::Normal
        && row.outcome == Outcome::Pass
    {
        Evidence::Proved
    } else if Checker::parse(&row.runner).is_some() {
        Evidence::Modeled
    } else if MIRI_MODELS.contains(&row.runner.as_str()) && row.seed.is_some() {
        Evidence::Observed
    } else if target(row).is_some_and(|target| NORMATIVE.iter().any(|(name, _)| *name == target)) {
        Evidence::Normative
    } else {
        Evidence::Checked
    }
}

/// Each [`NORMATIVE`] target that does not hold its data: its source,
/// `tests/<target>.rs` under the repository `root`, missing or not Rust, or
/// `compiles_in` refusing it.
pub fn normative_faults(root: &Path) -> Vec<String> {
    let mut faults = Vec::new();
    for (target, data) in NORMATIVE {
        let source = format!("tests/{target}.rs");
        match std::fs::read_to_string(root.join(&source)) {
            Err(error) => faults.push(format!("{source}: a normative target: {error}")),
            Ok(text) => {
                if let Err(fault) = compiles_in(&text, data) {
                    faults.push(format!("{source}: {fault}"));
                }
            }
        }
    }
    faults
}

/// Whether any of `attrs` is a `cfg` or a `cfg_attr`: code a configuration
/// may remove or rewrite.
fn conditional(attrs: &[syn::Attribute]) -> bool {
    attrs
        .iter()
        .any(|attribute| attribute.path().is_ident("cfg") || attribute.path().is_ident("cfg_attr"))
}

/// Whether the Rust `source` compiles in `data` and reads it: a file under
/// no inner `cfg` or `cfg_attr`, holding a top-level `const` or `static`
/// item under no `cfg` or `cfg_attr`, initialized by `include_str!` of
/// exactly that string literal, its name read by a path somewhere else in
/// the file outside any node a `cfg` or `cfg_attr` carries. Parsed, never
/// matched as text, so an include in a comment, in a string, or in code a
/// configuration may remove holds nothing.
///
/// The guarantee is syntactic: a reference outside conditional code, not
/// name resolution (another item of the same name would satisfy it), and
/// not proof that a conformance test executes the vectors. That remains
/// the test's own obligation, reviewed by reading its source.
fn compiles_in(source: &str, data: &str) -> Result<(), String> {
    use syn::visit::Visit;

    /// Whether some path outside the item defining `name`, and outside
    /// every node a `cfg` or `cfg_attr` carries, ends in `name`.
    struct Reads<'n> {
        name: &'n syn::Ident,
        found: bool,
    }

    impl<'ast> Visit<'ast> for Reads<'_> {
        fn visit_item(&mut self, item: &'ast syn::Item) {
            let (attrs, defining) = match item {
                syn::Item::Const(item) => (&item.attrs[..], item.ident == *self.name),
                syn::Item::Static(item) => (&item.attrs[..], item.ident == *self.name),
                syn::Item::Fn(item) => (&item.attrs[..], false),
                syn::Item::Mod(item) => (&item.attrs[..], false),
                syn::Item::Impl(item) => (&item.attrs[..], false),
                syn::Item::Trait(item) => (&item.attrs[..], false),
                syn::Item::Struct(item) => (&item.attrs[..], false),
                syn::Item::Enum(item) => (&item.attrs[..], false),
                syn::Item::Type(item) => (&item.attrs[..], false),
                syn::Item::Use(item) => (&item.attrs[..], false),
                syn::Item::Macro(item) => (&item.attrs[..], false),
                _ => (&[][..], false),
            };
            if !defining && !conditional(attrs) {
                syn::visit::visit_item(self, item);
            }
        }

        fn visit_impl_item(&mut self, item: &'ast syn::ImplItem) {
            let attrs = match item {
                syn::ImplItem::Const(item) => &item.attrs[..],
                syn::ImplItem::Fn(item) => &item.attrs[..],
                syn::ImplItem::Type(item) => &item.attrs[..],
                syn::ImplItem::Macro(item) => &item.attrs[..],
                _ => &[][..],
            };
            if !conditional(attrs) {
                syn::visit::visit_impl_item(self, item);
            }
        }

        fn visit_trait_item(&mut self, item: &'ast syn::TraitItem) {
            let attrs = match item {
                syn::TraitItem::Const(item) => &item.attrs[..],
                syn::TraitItem::Fn(item) => &item.attrs[..],
                syn::TraitItem::Type(item) => &item.attrs[..],
                syn::TraitItem::Macro(item) => &item.attrs[..],
                _ => &[][..],
            };
            if !conditional(attrs) {
                syn::visit::visit_trait_item(self, item);
            }
        }

        fn visit_local(&mut self, local: &'ast syn::Local) {
            if !conditional(&local.attrs) {
                syn::visit::visit_local(self, local);
            }
        }

        fn visit_arm(&mut self, arm: &'ast syn::Arm) {
            if !conditional(&arm.attrs) {
                syn::visit::visit_arm(self, arm);
            }
        }

        fn visit_expr(&mut self, expr: &'ast syn::Expr) {
            let attrs: &[syn::Attribute] = match expr {
                syn::Expr::Array(e) => &e.attrs,
                syn::Expr::Assign(e) => &e.attrs,
                syn::Expr::Async(e) => &e.attrs,
                syn::Expr::Await(e) => &e.attrs,
                syn::Expr::Binary(e) => &e.attrs,
                syn::Expr::Block(e) => &e.attrs,
                syn::Expr::Break(e) => &e.attrs,
                syn::Expr::Call(e) => &e.attrs,
                syn::Expr::Cast(e) => &e.attrs,
                syn::Expr::Closure(e) => &e.attrs,
                syn::Expr::Const(e) => &e.attrs,
                syn::Expr::Continue(e) => &e.attrs,
                syn::Expr::Field(e) => &e.attrs,
                syn::Expr::ForLoop(e) => &e.attrs,
                syn::Expr::Group(e) => &e.attrs,
                syn::Expr::If(e) => &e.attrs,
                syn::Expr::Index(e) => &e.attrs,
                syn::Expr::Let(e) => &e.attrs,
                syn::Expr::Lit(e) => &e.attrs,
                syn::Expr::Loop(e) => &e.attrs,
                syn::Expr::Macro(e) => &e.attrs,
                syn::Expr::Match(e) => &e.attrs,
                syn::Expr::MethodCall(e) => &e.attrs,
                syn::Expr::Paren(e) => &e.attrs,
                syn::Expr::Path(e) => &e.attrs,
                syn::Expr::Range(e) => &e.attrs,
                syn::Expr::Reference(e) => &e.attrs,
                syn::Expr::Repeat(e) => &e.attrs,
                syn::Expr::Return(e) => &e.attrs,
                syn::Expr::Struct(e) => &e.attrs,
                syn::Expr::Try(e) => &e.attrs,
                syn::Expr::TryBlock(e) => &e.attrs,
                syn::Expr::Tuple(e) => &e.attrs,
                syn::Expr::Unary(e) => &e.attrs,
                syn::Expr::Unsafe(e) => &e.attrs,
                syn::Expr::While(e) => &e.attrs,
                syn::Expr::Yield(e) => &e.attrs,
                _ => &[],
            };
            if !conditional(attrs) {
                syn::visit::visit_expr(self, expr);
            }
        }

        fn visit_path(&mut self, path: &'ast syn::Path) {
            if path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == *self.name)
            {
                self.found = true;
            }
            syn::visit::visit_path(self, path);
        }
    }

    let file = syn::parse_file(source).map_err(|error| format!("does not parse: {error}"))?;
    if conditional(&file.attrs) {
        return Err("the whole file is conditional (an inner cfg or cfg_attr)".to_string());
    }
    let mut includes = Vec::new();
    for item in &file.items {
        let (attrs, name, expr) = match item {
            syn::Item::Const(item) => (&item.attrs, &item.ident, &*item.expr),
            syn::Item::Static(item) => (&item.attrs, &item.ident, &*item.expr),
            _ => continue,
        };
        if conditional(attrs) {
            continue;
        }
        let syn::Expr::Macro(invocation) = expr else {
            continue;
        };
        if !invocation.mac.path.is_ident("include_str") {
            continue;
        }
        if invocation
            .mac
            .parse_body::<syn::LitStr>()
            .is_ok_and(|path| path.value() == data)
        {
            includes.push(name);
        }
    }
    if includes.is_empty() {
        return Err(format!(
            "compiles in no include_str!(\"{data}\"), the data its rows are normative of, in a \
             top-level const or static under no cfg or cfg_attr"
        ));
    }
    for name in &includes {
        let mut reads = Reads { name, found: false };
        reads.visit_file(&file);
        if reads.found {
            return Ok(());
        }
    }
    Err(format!(
        "compiles in include_str!(\"{data}\") and never reads it ({})",
        includes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

const IDENTITY: &str = "#\tidentity\t";

fn optional<T: fmt::Display>(value: &Option<T>) -> String {
    value
        .as_ref()
        .map_or_else(|| "-".to_string(), ToString::to_string)
}

fn parsed<T: core::str::FromStr>(text: &str, what: &str) -> Result<Option<T>, String> {
    if text == "-" {
        Ok(None)
    } else {
        text.parse()
            .map(Some)
            .map_err(|_| format!("{what} {text:?} is not a value"))
    }
}

impl Row {
    /// The row with the class its run supports ([`supported`]): every
    /// writer makes its rows through this, whatever class its literal
    /// named, so none computes a class of its own.
    #[must_use]
    pub fn classified(mut self) -> Self {
        self.evidence = supported(&self);
        self
    }

    fn render(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            self.domain,
            self.line,
            self.runner,
            self.test,
            optional(&self.seed),
            self.purpose.name(),
            optional(&self.bound),
            optional(&self.stack),
            optional(&self.expected),
            self.outcome,
            optional(&self.seconds),
            optional(&self.peak_kb),
            self.physical.name(),
            self.evidence.name(),
        )
    }

    /// What identifies the run: every column but its expectation, outcome
    /// and measurement.
    fn key(&self) -> Key<'_> {
        (
            &self.domain,
            &self.line,
            &self.runner,
            &self.test,
            self.seed,
            self.purpose,
            self.bound,
            self.stack,
        )
    }

    fn parse(row: &str) -> Result<Self, String> {
        let columns: Vec<&str> = row.split('\t').collect();
        let [
            domain,
            line,
            runner,
            test,
            seed,
            purpose,
            bound,
            stack,
            expected,
            outcome,
            seconds,
            peak,
            physical,
            evidence,
        ] = columns[..]
        else {
            return Err(format!("not fourteen columns: {row:?}"));
        };
        let expected = match expected {
            "-" => None,
            name => {
                Some(Outcome::parse(name).ok_or_else(|| format!("no expected outcome {name:?}"))?)
            }
        };
        Ok(Self {
            domain: domain.to_string(),
            line: line.to_string(),
            runner: runner.to_string(),
            test: test.to_string(),
            seed: parsed(seed, "seed")?,
            purpose: Purpose::parse(purpose).ok_or_else(|| format!("no purpose {purpose:?}"))?,
            bound: parsed(bound, "bound")?,
            stack: parsed(stack, "stack")?,
            expected,
            outcome: Outcome::parse(outcome).ok_or_else(|| format!("no outcome {outcome:?}"))?,
            seconds: (seconds != "-").then(|| seconds.to_string()),
            peak_kb: parsed(peak, "peak")?,
            physical: Physical::parse(physical)
                .ok_or_else(|| format!("no physical witness {physical:?}"))?,
            evidence: Evidence::parse(evidence)
                .ok_or_else(|| format!("no evidence class {evidence:?}"))?,
        })
    }
}

/// The results of a run of `identity` under `configuration`: a record of the
/// identity, the columns, then every row.
pub fn render(configuration: &str, identity: &str, rows: &[Row]) -> String {
    let identity = format!("{IDENTITY}{identity}");
    let rendered: Vec<String> = rows.iter().map(Row::render).collect();
    dcbor_record::render(
        configuration,
        [identity.as_str(), COLUMNS]
            .into_iter()
            .chain(rendered.iter().map(String::as_str)),
    )
}

/// The one verdict over a gate's rows as published: every evidence row (a
/// normal run, a probe, a suite's verdict) carries the outcome planned for
/// it and produced exactly that; a measurement or a control carries none,
/// its refusal decided from its log; no run is published twice; every row
/// claims exactly the class its run supports ([`supported`]). Each fault
/// is named. A gate adds its own plan's completeness to it.
pub fn verdict(rows: &[Row]) -> Vec<String> {
    let mut faults = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for row in rows {
        let seed = row
            .seed
            .map_or_else(String::new, |seed| format!(", seed {seed}"));
        let named = format!(
            "{} {} {}{seed} ({})",
            row.line,
            row.runner,
            row.test,
            row.purpose.name()
        );
        if !seen.insert(row.key()) {
            faults.push(format!("{named}: published more than once"));
        }
        match (row.purpose, row.expected) {
            (Purpose::Derive | Purpose::Control, None) => {}
            (Purpose::Derive | Purpose::Control, Some(expected)) => {
                faults.push(format!("{named}: no evidence, yet expected {expected}"));
            }
            (_, None) => faults.push(format!("{named}: evidence without an expected outcome")),
            (_, Some(Outcome::NoVerdict)) => {
                faults.push(format!(
                    "{named}: no_verdict cannot be an evidence expectation"
                ));
            }
            (_, Some(expected)) if expected == row.outcome => {}
            (_, Some(expected)) => faults.push(format!(
                "{named}: {}, where {expected} was planned",
                row.outcome
            )),
        }
        if let Some(fault) = misclassified(row) {
            faults.push(format!("{named}: {fault}"));
        }
    }
    faults
}

/// The fault of a row claiming another class than its run supports: every
/// verdict over published rows reports it in these words.
pub fn misclassified(row: &Row) -> Option<String> {
    let supports = supported(row);
    (row.evidence != supports)
        .then(|| format!("claims {}, its run supports {supports}", row.evidence))
}

/// Results read: their configuration, identity and rows.
pub fn parse(data: &str) -> Result<(String, String, Vec<Row>), String> {
    let record = dcbor_record::try_read(data).ok_or("results are not a record")?;
    let mut rows = record.rows.into_iter();
    let identity = rows
        .next()
        .and_then(|(_, row)| row.strip_prefix(IDENTITY))
        .ok_or("results name no identity")?
        .to_string();
    match rows.next() {
        Some((_, columns)) if columns == COLUMNS => {}
        other => return Err(format!("results do not name their columns: {other:?}")),
    }
    let rows = rows
        .map(|(at, row)| Row::parse(row).map_err(|error| format!("results:{at}: {error}")))
        .collect::<Result<_, _>>()?;
    Ok((record.configuration.to_string(), identity, rows))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(purpose: Purpose, bound: Option<usize>, outcome: Outcome) -> Row {
        Row {
            domain: "all-features".to_string(),
            line: "loom lib m".to_string(),
            runner: "loom".to_string(),
            test: "m".to_string(),
            seed: None,
            purpose,
            bound,
            stack: None,
            expected: (purpose != Purpose::Derive).then_some(outcome),
            outcome,
            seconds: Some("1.5".to_string()),
            peak_kb: Some(2048),
            physical: Physical::NotApplicable,
            evidence: Evidence::Unverified,
        }
        .classified()
    }

    /// A Miri gate row of the selection line `line` under Stacked Borrows,
    /// seeded where `seed` is.
    fn miri_row(line: &str, seed: Option<u64>) -> Row {
        Row {
            domain: "all-features".to_string(),
            line: line.to_string(),
            runner: "stacked".to_string(),
            test: "t".to_string(),
            seed,
            purpose: Purpose::Normal,
            bound: None,
            stack: None,
            expected: Some(Outcome::Pass),
            outcome: Outcome::Pass,
            seconds: None,
            peak_kb: None,
            physical: Physical::Witnessed,
            evidence: Evidence::Unverified,
        }
        .classified()
    }

    /// Each kind of run is classed by the one definition: a run that never
    /// started, a measurement, a suite's verdict, a model's run, a seeded
    /// Miri run, a normative target's run, and any other run; a target is
    /// read from a selection line's base and from a model's line.
    #[test]
    fn every_run_is_classed_by_what_it_supports() {
        let modeled = row(Purpose::Normal, None, Outcome::Pass);
        assert_eq!(target(&modeled), Some("loom lib m"));
        assert_eq!(modeled.evidence, Evidence::Modeled);
        assert_eq!(
            row(Purpose::Derive, Some(3), Outcome::Failed).evidence,
            Evidence::Derived
        );
        assert_eq!(
            row(Purpose::Normal, None, Outcome::NotRun).evidence,
            Evidence::Unverified
        );
        let mut suite = miri_row("all-features-owned_input", None);
        suite.purpose = Purpose::Suite;
        assert_eq!(suite.classified().evidence, Evidence::Derived);
        let seeded = miri_row("all-features-owner_concurrency", Some(3));
        assert_eq!(seeded.evidence, Evidence::Observed);
        let normative = miri_row("all-features-appendix_a-every_valid", None);
        assert_eq!(target(&normative), Some("appendix_a"));
        assert_eq!(normative.evidence, Evidence::Normative);
        let checked = miri_row("all-features-owned_input", None);
        assert_eq!(target(&checked), Some("owned_input"));
        assert_eq!(checked.evidence, Evidence::Checked);
        let mut native = miri_row("std-bounded::tests::x-bounded::tests::x", None);
        native.domain = "std".to_string();
        native.runner = "native".to_string();
        assert_eq!(native.classified().evidence, Evidence::Checked);
        let elsewhere = miri_row("other-appendix_a", None);
        assert_eq!(target(&elsewhere), None);
        assert_eq!(elsewhere.evidence, Evidence::Checked);
    }

    /// A verified proof harness is proved; one that did not verify, and a
    /// Miri run claiming it, are not.
    #[test]
    fn only_a_verified_harness_is_proved() {
        let mut harness = miri_row("kani-bounded::proofs", None);
        harness.domain = "kani".to_string();
        harness.runner = crate::proofs::RUNNER.to_string();
        harness.test = "bounded::proofs::checked_add_is_exact".to_string();
        assert_eq!(harness.clone().classified().evidence, Evidence::Proved);
        harness.outcome = Outcome::Failed;
        assert_eq!(harness.clone().classified().evidence, Evidence::Checked);
        harness.outcome = Outcome::NoVerdict;
        assert_eq!(harness.classified().evidence, Evidence::Unverified);
    }

    /// The planted controls of the class check: a row claiming a class its
    /// run does not support is named, the claim and the support both;
    /// [`Evidence::Proved`] is supported by a verified harness alone.
    #[test]
    fn a_row_claiming_another_class_than_its_run_supports_is_named() {
        let classified = vec![
            row(Purpose::Normal, None, Outcome::NotRun),
            row(Purpose::BoundProbe, Some(16), Outcome::BoundRefused),
            row(Purpose::Derive, Some(3), Outcome::Failed),
            miri_row("all-features-appendix_a-x", None),
            miri_row("all-features-owned_input", None),
            miri_row("all-features-owner_concurrency", Some(0)),
        ];
        assert_eq!(verdict(&classified), Vec::<String>::new());
        let mut planted = classified.clone();
        planted[0].evidence = Evidence::Checked;
        planted[1].evidence = Evidence::Checked;
        planted[2].evidence = Evidence::Checked;
        planted[3].evidence = Evidence::Checked;
        planted[4].evidence = Evidence::Normative;
        planted[5].evidence = Evidence::Proved;
        assert_eq!(
            verdict(&planted),
            vec![
                "loom lib m loom m (normal): claims checked, its run supports unverified"
                    .to_string(),
                "loom lib m loom m (bound_probe): claims checked, its run supports modeled"
                    .to_string(),
                "loom lib m loom m (derive): claims checked, its run supports derived".to_string(),
                "all-features-appendix_a-x stacked t (normal): claims checked, its run supports \
                 normative"
                    .to_string(),
                "all-features-owned_input stacked t (normal): claims normative, its run supports \
                 checked"
                    .to_string(),
                "all-features-owner_concurrency stacked t, seed 0 (normal): claims proved, its \
                 run supports observed"
                    .to_string(),
            ]
        );
    }

    /// A temporary tree under the system's temporary directory, removed when
    /// dropped, as the gate's other fixture trees are.
    struct Tree(std::path::PathBuf);

    impl Tree {
        fn new(name: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("dcbor-gate-rows-{name}-{}", std::process::id()));
            if path.exists() {
                std::fs::remove_dir_all(&path).unwrap();
            }
            std::fs::create_dir_all(path.join("tests")).unwrap();
            Self(path)
        }

        fn write(&self, relative: &str, text: &str) {
            std::fs::write(self.0.join(relative), text).unwrap();
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            if !std::thread::panicking() {
                std::fs::remove_dir_all(&self.0).unwrap();
            }
        }
    }

    /// Every normative target compiling in exactly its data and reading it
    /// passes; the planted controls: a target missing, one compiling in no
    /// data, one compiling in another path, the include commented out, the
    /// include under a `cfg` that removes it, the item never read, and the
    /// include only inside a string literal are each named.
    #[test]
    fn a_normative_target_must_compile_in_its_data() {
        let tree = Tree::new("normative");
        let holds = |data: &str| {
            format!(
                "const DATA: &str = include_str!(\"{data}\");\nfn read() -> &'static str {{ DATA }}\n"
            )
        };
        for (target, data) in NORMATIVE {
            tree.write(&format!("tests/{target}.rs"), &holds(data));
        }
        assert_eq!(normative_faults(&tree.0), Vec::<String>::new());
        let (first, data) = NORMATIVE[0];
        let (second, _) = NORMATIVE[1];
        let read = "fn read() -> &'static str { DATA }\n";
        let planted = [
            (
                "no data",
                format!("const DATA: &str = \"\";\n{read}"),
                "compiles in no include_str!",
            ),
            (
                "another path",
                holds("data/other.txt"),
                "compiles in no include_str!",
            ),
            (
                "commented out",
                format!("// const DATA: &str = include_str!(\"{data}\");\n"),
                "compiles in no include_str!",
            ),
            (
                "removed by cfg",
                format!("#[cfg(any())]\nconst DATA: &str = include_str!(\"{data}\");\n{read}"),
                "compiles in no include_str!",
            ),
            (
                "never read",
                format!("const DATA: &str = include_str!(\"{data}\");\n"),
                "and never reads it (DATA)",
            ),
            (
                "only in a string",
                format!("const DATA: &str = \"include_str!(\\\"{data}\\\")\";\n{read}"),
                "compiles in no include_str!",
            ),
            (
                "removed by cfg_attr, read only by removed code",
                format!(
                    "#[cfg_attr(all(), cfg(any()))]\nconst DATA: &str = include_str!(\"{data}\");\n\
                     #[cfg(any())]\nfn read() -> &'static str {{ DATA }}\n"
                ),
                "compiles in no include_str!",
            ),
            (
                "read only by removed code",
                format!(
                    "const DATA: &str = include_str!(\"{data}\");\n\
                     #[cfg(any())]\nfn read() -> &'static str {{ DATA }}\n\
                     fn other() {{ #[cfg(any())] let _ = DATA; }}\n"
                ),
                "and never reads it (DATA)",
            ),
            (
                "the whole file conditional",
                format!("#![cfg(any())]\n{}", holds(data)),
                "the whole file is conditional",
            ),
        ];
        for (what, source, fault) in planted {
            tree.write(&format!("tests/{first}.rs"), &source);
            let faults = normative_faults(&tree.0);
            assert_eq!(faults.len(), 1, "{what}: {faults:#?}");
            assert!(
                faults[0].starts_with(&format!("tests/{first}.rs: ")) && faults[0].contains(fault),
                "{what}: {faults:#?}"
            );
        }
        tree.write(&format!("tests/{second}.rs"), "not rust {");
        let faults = normative_faults(&tree.0);
        assert!(
            faults
                .iter()
                .any(|fault| fault.starts_with(&format!("tests/{second}.rs: does not parse"))),
            "{faults:#?}"
        );
        std::fs::remove_file(tree.0.join(format!("tests/{first}.rs"))).unwrap();
        let faults = normative_faults(&tree.0);
        assert!(
            faults[0].starts_with(&format!("tests/{first}.rs: a normative target:")),
            "{faults:#?}"
        );
    }

    /// The repository's own normative targets compile in their data.
    #[test]
    fn the_repositorys_normative_targets_compile_in_their_data() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        assert_eq!(normative_faults(&root), Vec::<String>::new());
    }

    #[test]
    fn results_read_back_what_they_render() {
        let rows = vec![
            row(Purpose::Normal, None, Outcome::Pass),
            row(Purpose::BoundProbe, Some(16), Outcome::BoundRefused),
        ];
        let data = render("this", "abc", &rows);
        assert_eq!(
            parse(&data),
            Ok(("this".to_string(), "abc".to_string(), rows))
        );
    }

    #[test]
    fn malformed_results_are_refused() {
        assert!(parse("no record").is_err());
        assert!(parse(&dcbor_record::render("c", [COLUMNS])).is_err());
        assert!(parse(&dcbor_record::render("c", ["#\tidentity\ta", "other"])).is_err());
        let short = dcbor_record::render("c", ["#\tidentity\ta", COLUMNS, "x\ty"]);
        assert!(parse(&short).unwrap_err().contains("not fourteen columns"));
        let mut unclassed = render("c", "a", &[row(Purpose::Normal, None, Outcome::Pass)]);
        unclassed = unclassed.replace("\tmodeled\n", "\tverified\n");
        assert!(parse(&unclassed).unwrap_err().contains("no evidence class"));
    }

    /// Rows as planned pass; the planted controls: an outcome other than
    /// planned, evidence with no expectation, a measurement with one, and a
    /// run published twice are each named.
    #[test]
    fn only_rows_with_their_planned_outcomes_are_evidence() {
        for purpose in [
            Purpose::Normal,
            Purpose::BoundProbe,
            Purpose::StackProbe,
            Purpose::Suite,
        ] {
            let inconclusive = row(purpose, None, Outcome::NoVerdict);
            assert_eq!(inconclusive.evidence, Evidence::Unverified);
            let faults = verdict(&[inconclusive]);
            assert_eq!(faults.len(), 1, "{faults:?}");
            assert!(
                faults[0].contains("no_verdict cannot be an evidence expectation"),
                "{faults:?}"
            );
        }
        let rows = vec![
            row(Purpose::Normal, None, Outcome::Pass),
            row(Purpose::BoundProbe, Some(16), Outcome::BoundRefused),
            row(Purpose::Derive, Some(3), Outcome::Failed),
        ];
        assert_eq!(verdict(&rows), Vec::<String>::new());
        let mut planted = rows.clone();
        planted[0].outcome = Outcome::Failed;
        planted[1].expected = None;
        planted[2].expected = Some(Outcome::Pass);
        planted.push(rows[0].clone());
        assert_eq!(
            verdict(&planted),
            vec![
                "loom lib m loom m (normal): failed, where pass was planned".to_string(),
                "loom lib m loom m (bound_probe): evidence without an expected outcome".to_string(),
                "loom lib m loom m (derive): no evidence, yet expected pass".to_string(),
                "loom lib m loom m (normal): published more than once".to_string(),
            ]
        );
    }
}
