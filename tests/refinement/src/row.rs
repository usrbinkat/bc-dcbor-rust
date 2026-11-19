//! A recorded case's row, and the record's rows read back.

use crate::machine::evidence;
use crate::text::{end_text, parse_run, render_run};
use crate::{Evidence, Outcome, Run, UNGATED};

/// One recorded case: its name, the feature it is compiled under, the
/// outcome it declares, and its run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub name: String,
    pub feature: Option<String>,
    pub outcome: Outcome,
    pub run: Run,
}

impl Row {
    /// The row's text: its name, its feature or [`UNGATED`], its outcome,
    /// its evidence class ([`evidence`]) and its run's three columns
    /// ([`render_run`]: observations, marks, end), separated by tabs.
    /// Refused when its run's end is not its outcome's or the machine
    /// refuses its run: such a run establishes nothing and is never
    /// recorded.
    pub fn render(&self) -> Result<String, String> {
        let class = self.supported()?;
        let (observed, marks, end) = render_run(&self.run);
        Ok(format!(
            "{}\t{}\t{}\t{class}\t{observed}\t{marks}\t{end}",
            self.name,
            self.feature.as_deref().unwrap_or(UNGATED),
            self.outcome.name(),
        ))
    }

    /// The class this row's run supports: its run ends at its outcome, and
    /// the machine accepts it.
    fn supported(&self) -> Result<Evidence, String> {
        if self.run.end != self.outcome.end() {
            return Err(format!(
                "{}: its run ends {}, not at its outcome, {}",
                self.name,
                end_text(self.run.end),
                self.outcome.name()
            ));
        }
        evidence(&self.run).map_err(|divergence| {
            format!(
                "{}: the refinement machine refused its run at {divergence}",
                self.name
            )
        })
    }
}

/// One row from its text, the inverse of [`Row::render`]: seven columns, an
/// outcome a case can declare, its run in canonical text, and the class its
/// run supports ([`evidence`]), a row claiming another refused.
pub fn parse_row(line: &str) -> Result<Row, String> {
    let columns: Vec<&str> = line.split('\t').collect();
    let [name, feature, outcome, class, observed, marks, end] = columns.as_slice() else {
        return Err(format!("not seven columns: {line:?}"));
    };
    let outcome = Outcome::parse(outcome).ok_or_else(|| format!("no outcome {outcome:?}"))?;
    let class = Evidence::parse(class).ok_or_else(|| format!("no evidence class {class:?}"))?;
    let run = parse_run(observed, marks, end).map_err(|error| format!("{name}: {error}"))?;
    let row = Row {
        name: (*name).to_string(),
        feature: (*feature != UNGATED).then(|| (*feature).to_string()),
        outcome,
        run,
    };
    let supported = row.supported()?;
    if class != supported {
        return Err(format!(
            "{name} claims {class}, its row supports {supported}"
        ));
    }
    Ok(row)
}

/// A trace record read: the configuration it names and each row with its
/// line, each name once. `path` names the record in every refusal.
pub fn parse_record(path: &str, data: &str) -> Result<(String, Vec<(usize, Row)>), String> {
    let read = dcbor_record::try_read(data)
        .ok_or_else(|| format!("{path}:1: not the configuration it was recorded under"))?;
    let mut rows: Vec<(usize, Row)> = Vec::with_capacity(read.rows.len());
    for (at, line) in read.rows {
        let row = parse_row(line).map_err(|error| format!("{path}:{at}: {error}"))?;
        if rows.iter().any(|(_, earlier)| earlier.name == row.name) {
            return Err(format!("{path}:{at}: {} is recorded twice", row.name));
        }
        rows.push((at, row));
    }
    Ok((read.configuration.to_string(), rows))
}
