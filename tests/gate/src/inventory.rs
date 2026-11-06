//! A run's inventory: the lines a test reports, with `DCBOR_CLASS_COVERAGE`
//! set, of what its matrices reached (`tests/support/rigor.rs`): each
//! matrix's stop classes (`DCBOR_CLASSES`, `DCBOR_CLASS`) and the boundary
//! predicate valuations its runs reached (`DCBOR_REACHED`, rows of
//! `dcbor::bounded::boundary::Reached::rows`). The one reader of them, and
//! the two comparisons made over them:
//!
//! - native against each Miri model ([`coverage`]): a model's runs of a
//!   line, all together, must reach exactly the inventory the native run
//!   reaches, classes and valuations alike: one reached natively and not
//!   under Miri is a missed unsafe transition, one reached only under Miri a
//!   path the native evidence never took;
//! - full against minimal witness sizes ([`witness_loss`]): a test at the
//!   minimal sizes Miri runs must reach exactly the valuations its full-size
//!   run reaches, matrix names apart, since a matrix may be named by its
//!   fixture, which the sizes change (spec P3).
//!
//! A line is kept from its marker on: a test's output can share a line with
//! another's on the same stream. A valuation row that names no predicate or
//! valuation is a broken run, never an inventory.

use std::collections::BTreeSet;

use dcbor::bounded::boundary::Reached;

/// A matrix's class count.
pub const CLASSES: &str = "DCBOR_CLASSES";
/// One class of a matrix.
pub const CLASS: &str = "DCBOR_CLASS";
/// One boundary valuation a matrix's runs reached.
pub const REACHED: &str = "DCBOR_REACHED";

/// The markers, longest first, so `DCBOR_CLASSES` is never read as
/// `DCBOR_CLASS`.
const MARKERS: [&str; 3] = [CLASSES, CLASS, REACHED];

/// A run's inventory: each line from its marker on, sorted and distinct.
pub type Inventory = BTreeSet<String>;

/// The valuation of a `DCBOR_REACHED` line's fields after its marker: the
/// matrix name, then the row `predicate<TAB>valuation`.
fn valuation(fields: &str) -> Result<String, String> {
    let (_, row) = fields
        .split_once('\t')
        .ok_or_else(|| format!("a reached valuation of no matrix: {fields:?}"))?;
    Reached::parse_row(row)
        .ok_or_else(|| format!("a reached valuation of no predicate or valuation: {row:?}"))?;
    Ok(row.to_string())
}

/// The inventory line `line` holds, if any: from its marker on, a reached
/// valuation checked to name a predicate and a valuation.
fn kept(line: &str) -> Result<Option<String>, String> {
    for marker in MARKERS {
        let tagged = format!("{marker}\t");
        if let Some(at) = line.find(&tagged) {
            let fields = &line[at + tagged.len()..];
            if marker == REACHED {
                valuation(fields)?;
            }
            return Ok(Some(format!("{tagged}{fields}")));
        }
    }
    Ok(None)
}

/// The inventory a run's `log` reports.
pub fn of(log: &str) -> Result<Inventory, String> {
    log.lines()
        .filter_map(|line| kept(line).transpose())
        .collect()
}

/// An inventory as written: one line each, sorted.
pub fn render(inventory: &Inventory) -> String {
    inventory.iter().map(|line| format!("{line}\n")).collect()
}

/// An inventory written by [`render`]; any other line refuses it.
pub fn parse(text: &str) -> Result<Inventory, String> {
    text.lines()
        .map(|line| {
            kept(line)?
                .filter(|kept| kept == line)
                .ok_or_else(|| format!("not an inventory line: {line:?}"))
        })
        .collect()
}

/// The boundary valuations an inventory reached, matrix names apart: each a
/// `predicate<TAB>valuation` row.
pub fn valuations(inventory: &Inventory) -> Result<BTreeSet<String>, String> {
    let tagged = format!("{REACHED}\t");
    inventory
        .iter()
        .filter_map(|line| line.strip_prefix(&tagged))
        .map(valuation)
        .collect()
}

/// What `actual` lacks of `expected`, each `-`, and holds beyond it, each
/// `+`: empty exactly when the two are equal.
pub fn difference(expected: &BTreeSet<String>, actual: &BTreeSet<String>) -> Vec<String> {
    expected
        .difference(actual)
        .map(|line| format!("-{line}"))
        .chain(actual.difference(expected).map(|line| format!("+{line}")))
        .collect()
}

/// A Miri model's inventory over a line, the union of its `runs`, against
/// the native run's: the union, and its difference from `native`.
pub fn coverage(native: &Inventory, runs: &[Inventory]) -> (Inventory, Vec<String>) {
    let union: Inventory = runs.iter().flatten().cloned().collect();
    let difference = difference(native, &union);
    (union, difference)
}

/// The valuations a test's `minimal` run lacks of its `full` run's, and
/// holds beyond them ([`difference`]), matrix names apart.
pub fn witness_loss(minimal: &Inventory, full: &Inventory) -> Result<Vec<String>, String> {
    Ok(difference(&valuations(full)?, &valuations(minimal)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOG: &str = "running 1 test\n\
        [m] stops: 3 of 9 schedules at 1ms\n\
        DCBOR_CLASSES\t\"m\"\t2\n\
        DCBOR_CLASS\t\"m\"\t\"Decode: a\"\n\
        test x ... DCBOR_CLASS\t\"m\"\t\"Decode: b\"\n\
        DCBOR_REACHED\t\"m\"\tbuckets\ttombstone\n\
        DCBOR_REACHED\t\"m\"\tquantum\tat\n\
        DCBOR_REACHED\t\"m\"\tquantum\tat\n\
        test x ... ok\n";

    /// A log's inventory keeps each marked line from its marker on, a
    /// count line as itself, sorted and distinct, and reads back what it
    /// renders; its valuations drop the matrix name.
    #[test]
    fn a_log_yields_its_inventory_and_reads_back() {
        let inventory = of(LOG).unwrap();
        assert_eq!(
            render(&inventory),
            "DCBOR_CLASS\t\"m\"\t\"Decode: a\"\n\
             DCBOR_CLASS\t\"m\"\t\"Decode: b\"\n\
             DCBOR_CLASSES\t\"m\"\t2\n\
             DCBOR_REACHED\t\"m\"\tbuckets\ttombstone\n\
             DCBOR_REACHED\t\"m\"\tquantum\tat\n"
        );
        assert_eq!(parse(&render(&inventory)), Ok(inventory.clone()));
        assert_eq!(
            valuations(&inventory).unwrap(),
            BTreeSet::from(["buckets\ttombstone".to_string(), "quantum\tat".to_string()])
        );
    }

    /// A valuation naming no predicate or valuation, or no matrix, breaks
    /// the run; an unmarked line in a written inventory is refused.
    #[test]
    fn malformed_lines_are_refused() {
        assert!(
            of("DCBOR_REACHED\t\"m\"\tbuckets\tsideways\n")
                .unwrap_err()
                .contains("no predicate")
        );
        // A matrix's row of a predicate and no valuation.
        assert!(
            of("DCBOR_REACHED\t\"m\"\tbuckets\n")
                .unwrap_err()
                .contains("no predicate")
        );
        assert!(
            of("DCBOR_REACHED\tm\n")
                .unwrap_err()
                .contains("of no matrix")
        );
        assert!(
            parse("garbage\n")
                .unwrap_err()
                .contains("not an inventory line")
        );
        assert!(
            parse("x DCBOR_CLASS\t\"m\"\t1\n")
                .unwrap_err()
                .contains("not an inventory line")
        );
    }

    /// A model whose runs together reach the native inventory passes; the
    /// planted controls: a class or a valuation only the native run reached
    /// is named missing, one only the model reached is named extra.
    #[test]
    fn a_model_must_reach_exactly_the_native_inventory() {
        let native = of(LOG).unwrap();
        let split: Vec<Inventory> = native
            .iter()
            .map(|line| Inventory::from([line.clone()]))
            .collect();
        assert_eq!(coverage(&native, &split), (native.clone(), Vec::new()));
        let mut short = native.clone();
        short.remove("DCBOR_REACHED\t\"m\"\tbuckets\ttombstone");
        assert_eq!(
            coverage(&native, &[short.clone()]).1,
            vec!["-DCBOR_REACHED\t\"m\"\tbuckets\ttombstone".to_string()]
        );
        let mut more = native.clone();
        more.insert("DCBOR_CLASS\t\"m\"\t\"Decode: c\"".to_string());
        assert_eq!(
            coverage(&native, &[more]).1,
            vec!["+DCBOR_CLASS\t\"m\"\t\"Decode: c\"".to_string()]
        );
    }

    /// Minimal witnesses reaching the full run's valuations under another
    /// matrix name pass; the planted controls: a valuation the minimal run
    /// misses, and one it alone reaches, are each named.
    #[test]
    fn minimal_witnesses_must_reach_exactly_the_full_valuations() {
        let full =
            of("DCBOR_REACHED\t\"m 300\"\tquantum\tat\nDCBOR_REACHED\t\"m 300\"\tquantum\tpast\n")
                .unwrap();
        let minimal =
            of("DCBOR_REACHED\t\"m 3\"\tquantum\tpast\nDCBOR_REACHED\t\"m 3\"\tquantum\tat\n")
                .unwrap();
        assert_eq!(witness_loss(&minimal, &full), Ok(Vec::new()));
        let short = of("DCBOR_REACHED\t\"m 3\"\tquantum\tat\n").unwrap();
        assert_eq!(
            witness_loss(&short, &full),
            Ok(vec!["-quantum\tpast".to_string()])
        );
        let more = of("DCBOR_REACHED\t\"m 3\"\tquantum\tat\nDCBOR_REACHED\t\"m 3\"\tquantum\tpast\nDCBOR_REACHED\t\"m 3\"\tquantum\tbelow\n").unwrap();
        assert_eq!(
            witness_loss(&more, &full),
            Ok(vec!["+quantum\tbelow".to_string()])
        );
    }
}
