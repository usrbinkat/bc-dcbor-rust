//! The gates' results: one row per run, written as a record
//! ([`dcbor_record`]) under the configuration, its first row the run's
//! identity, its second the columns. Every gate writes and reads its
//! results through this module.

use core::fmt;

use crate::outcome::Outcome;

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
pub const COLUMNS: &str = "domain\tline\trunner\ttest\tseed\tpurpose\tbound\tstack\texpected\toutcome\tseconds\tpeak_kB\tphysical";

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
    fn render(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
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
        ] = columns[..]
        else {
            return Err(format!("not thirteen columns: {row:?}"));
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
/// its refusal decided from its log; no run is published twice. Each fault
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
            (_, Some(expected)) if expected == row.outcome => {}
            (_, Some(expected)) => faults.push(format!(
                "{named}: {}, where {expected} was planned",
                row.outcome
            )),
        }
    }
    faults
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
        }
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
        assert!(parse(&short).unwrap_err().contains("not thirteen columns"));
    }

    /// Rows as planned pass; the planted controls: an outcome other than
    /// planned, evidence with no expectation, a measurement with one, and a
    /// run published twice are each named.
    #[test]
    fn only_rows_with_their_planned_outcomes_are_evidence() {
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
