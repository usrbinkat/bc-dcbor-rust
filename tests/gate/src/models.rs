//! The concurrency gate's decisions: each model's bound and stack derived
//! by search, the evidence rows planned at the recorded values, and the
//! verdict over what those rows produced.
//!
//! One variable sets each value a model runs at, `DCBOR_MODEL_BOUND` and
//! `DCBOR_MODEL_STACK` (`tests/support/model.rs`); which values are evidence
//! is decided here alone:
//!
//! - a normal row sets neither, the recorded values apply, and it must
//!   pass;
//! - a bound probe sets the bound one under its recorded value, at the test
//!   attaining it, and must be refused by the checker's own bound;
//! - a stack probe sets the stack one page under its recorded value, at the
//!   test attaining it, and must overflow as the checker's stack allocator
//!   ends one ([`outcome::overflow`]).
//!
//! Every other value in an evidence row fails the verdict. Derivation rows
//! are measurement: the bound is searched upward from 1, doubling until a
//! run passes, then bisecting, in O(log C) runs with no upper bound picked;
//! loom's branch store and shuttle's step bound are each monotone in the
//! bound by construction. A run that overflows its stack meanwhile has its
//! stack doubled and is run again. The least stack is then searched the
//! same way, a page at a time, at the derived bound, and must be monotone:
//! one page less overflows, two, four and eight times it pass, and it
//! passes again. A stack that is not monotone is a defect, not a size: it is
//! refused, naming the Miri race seeds that judge memory errors.

use dcbor_model_bounds::{Bound, Bounds, Checker};

use crate::outcome::{self, Outcome};
use crate::rows::{Purpose, Row};

/// A model a checker build lists: one test of one target.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Listed {
    pub checker: Checker,
    pub target: String,
    pub test: String,
}

/// What one run produced: its outcome, the schedules it explored where the
/// runner reports them, and its measurement.
#[derive(Clone, Debug, PartialEq)]
pub struct Ran {
    pub outcome: Outcome,
    pub schedules: Option<usize>,
    pub seconds: Option<String>,
    pub peak_kb: Option<u64>,
}

/// A derived model: its values, and every run the search made, by the bound
/// and stack each ran at.
#[derive(Debug)]
pub struct Derived {
    pub bound: usize,
    pub stack: Option<usize>,
    pub schedules: Option<usize>,
    pub runs: Vec<(usize, Option<usize>, Ran)>,
}

/// The least bound and, `sized`, the least stack in multiples of `page` a
/// model of `checker` completes under, `run` running it at a bound and a
/// stack. Refused when a run fails otherwise than by its bound or its stack,
/// when no value fits in `usize`, or when the stack is not monotone.
pub fn derive(
    checker: Checker,
    sized: bool,
    page: usize,
    mut run: impl FnMut(usize, Option<usize>) -> Ran,
) -> Result<Derived, String> {
    assert!(page > 0, "a page holds bytes");
    let overflowed = outcome::overflow(checker);
    let mut runs = Vec::new();
    let mut stack = sized.then_some(page);
    // Whether `bound` suffices, the stack doubled whenever a run overflows
    // it: an overflow is reached before the bound is.
    let mut attempt = |bound: usize,
                       stack: &mut Option<usize>,
                       runs: &mut Vec<(usize, Option<usize>, Ran)>|
     -> Result<bool, String> {
        loop {
            let ran = run(bound, *stack);
            let outcome = ran.outcome;
            runs.push((bound, *stack, ran));
            match (outcome, *stack) {
                (outcome, Some(bytes)) if outcome == overflowed => {
                    *stack = Some(bytes.checked_mul(2).ok_or("no stack fits in usize")?);
                }
                (Outcome::Pass, _) => return Ok(true),
                (Outcome::BoundRefused, _) => return Ok(false),
                (other, _) => {
                    return Err(format!(
                        "a run at bound {bound} and stack {stack:?} was {other}: neither its \
                         bound nor its stack"
                    ));
                }
            }
        }
    };
    let mut high = 1usize;
    while !attempt(high, &mut stack, &mut runs)? {
        high = high.checked_mul(2).ok_or("no bound fits in usize")?;
    }
    let mut low = high / 2;
    while high - low > 1 {
        let middle = low + (high - low) / 2;
        if attempt(middle, &mut stack, &mut runs)? {
            high = middle;
        } else {
            low = middle;
        }
    }
    let bound = high;
    let stack = match stack {
        None => None,
        Some(_) => Some(least_stack(checker, bound, page, &mut run, &mut runs)?),
    };
    let schedules = runs
        .iter()
        .rev()
        .find(|(at, on, ran)| *at == bound && *on == stack && ran.outcome == Outcome::Pass)
        .and_then(|(_, _, ran)| ran.schedules);
    Ok(Derived {
        bound,
        stack,
        schedules,
        runs,
    })
}

/// The least stack, in multiples of `page`, a model of `checker` completes
/// on at `bound`, checked monotone.
fn least_stack(
    checker: Checker,
    bound: usize,
    page: usize,
    run: &mut impl FnMut(usize, Option<usize>) -> Ran,
    runs: &mut Vec<(usize, Option<usize>, Ran)>,
) -> Result<usize, String> {
    let overflowed = outcome::overflow(checker);
    let mut on = |pages: usize, runs: &mut Vec<_>| -> Result<Outcome, String> {
        let bytes = pages.checked_mul(page).ok_or("no stack fits in usize")?;
        let ran = run(bound, Some(bytes));
        let outcome = ran.outcome;
        runs.push((bound, Some(bytes), ran));
        Ok(outcome)
    };
    let defect = |what: String| {
        format!(
            "{what}: the stack is not monotone, so the failure is a defect, not a stack size; \
             judge the scenario under its Miri race seeds"
        )
    };
    let mut high = 1usize;
    loop {
        match on(high, runs)? {
            Outcome::Pass => break,
            outcome if outcome == overflowed => {
                high = high.checked_mul(2).ok_or("no stack fits in usize")?;
            }
            other => return Err(defect(format!("{high} pages at bound {bound} ran {other}"))),
        }
    }
    let mut low = high / 2;
    while high - low > 1 {
        let middle = low + (high - low) / 2;
        match on(middle, runs)? {
            Outcome::Pass => high = middle,
            outcome if outcome == overflowed => low = middle,
            other => {
                return Err(defect(format!(
                    "{middle} pages at bound {bound} ran {other}"
                )));
            }
        }
    }
    if high > 1 {
        let below = on(high - 1, runs)?;
        if below != overflowed {
            return Err(defect(format!(
                "{} pages ran {below}, not {overflowed}",
                high - 1
            )));
        }
    }
    for multiple in [2, 4, 8, 1] {
        let pages = high.checked_mul(multiple).ok_or("no stack fits in usize")?;
        let ran = on(pages, runs)?;
        if ran != Outcome::Pass {
            return Err(defect(format!(
                "{pages} pages ran {ran} above the least {high}"
            )));
        }
    }
    high.checked_mul(page)
        .ok_or_else(|| "no stack fits in usize".to_string())
}

/// The record row of a derived model, `listed`, the test attaining each
/// value being the model's own.
pub fn bound_of(listed: &Listed, derived: &Derived) -> Bound {
    Bound {
        checker: listed.checker,
        target: listed.target.clone(),
        model: listed.test.clone(),
        bound: derived.bound,
        stack: derived.stack,
        schedules: derived.schedules,
        bound_witness: listed.test.clone(),
        stack_witness: derived.stack.map(|_| listed.test.clone()),
    }
}

/// One evidence row to run: its model, purpose, values and the outcome it
/// must produce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Planned {
    pub listed: Listed,
    pub purpose: Purpose,
    pub bound: Option<usize>,
    pub stack: Option<usize>,
    pub expected: Outcome,
}

/// What `bounds` and the listed models disagree on: a model listed and not
/// recorded, recorded and not listed, or a witness that is no model.
pub fn completeness(listed: &[Listed], bounds: &Bounds) -> Vec<String> {
    let mut faults = Vec::new();
    for model in listed {
        if bounds
            .find(model.checker, &model.target, &model.test)
            .is_none()
        {
            faults.push(format!(
                "{} {} {}: listed but not recorded; derive it",
                model.checker, model.target, model.test
            ));
        }
    }
    for bound in &bounds.models {
        if !listed.iter().any(|model| {
            (model.checker, &model.target, &model.test)
                == (bound.checker, &bound.target, &bound.model)
        }) {
            faults.push(format!(
                "{} {} {}: recorded but no longer a model; derive the record again",
                bound.checker, bound.target, bound.model
            ));
        }
        if bound.bound_witness != bound.model
            || bound
                .stack_witness
                .as_ref()
                .is_some_and(|witness| *witness != bound.model)
        {
            faults.push(format!(
                "{} {} {}: a witness that is not the model's own test",
                bound.checker, bound.target, bound.model
            ));
        }
    }
    faults
}

/// The evidence rows of every listed model at its recorded values: a normal
/// row; a bound probe one under the bound, unless the bound is 1, under
/// which no run admits anything; a stack probe one page under the stack,
/// unless the stack is one page, the least the allocator maps.
pub fn plan(listed: &[Listed], bounds: &Bounds) -> Vec<Planned> {
    let mut planned = Vec::new();
    for model in listed {
        let Some(bound) = bounds.find(model.checker, &model.target, &model.test) else {
            continue;
        };
        let row = |purpose, bound, stack, expected| Planned {
            listed: model.clone(),
            purpose,
            bound,
            stack,
            expected,
        };
        planned.push(row(Purpose::Normal, None, None, Outcome::Pass));
        if bound.bound > 1 {
            planned.push(row(
                Purpose::BoundProbe,
                Some(bound.bound - 1),
                None,
                Outcome::BoundRefused,
            ));
        }
        if let Some(stack) = bound.stack
            && stack > bounds.page
        {
            planned.push(row(
                Purpose::StackProbe,
                None,
                Some(stack - bounds.page),
                outcome::overflow(model.checker),
            ));
        }
    }
    planned
}

/// The verdict over the evidence `rows` of the `listed` models against
/// `bounds`: every planned row present once with the outcome it must
/// produce; no evidence row at any value but unset, one under the recorded
/// bound, or one page under the recorded stack; the record complete. Empty
/// when the evidence holds.
pub fn verdict(listed: &[Listed], bounds: &Bounds, rows: &[Row]) -> Vec<String> {
    let mut faults = completeness(listed, bounds);
    let evidence: Vec<&Row> = rows
        .iter()
        .filter(|row| {
            matches!(
                row.purpose,
                Purpose::Normal | Purpose::BoundProbe | Purpose::StackProbe
            )
        })
        .collect();
    for row in &evidence {
        let named = format!("{} {} {}", row.runner, row.line, row.test);
        let Some(checker) = Checker::parse(&row.runner) else {
            faults.push(format!("{named}: no checker ran it"));
            continue;
        };
        let Some(recorded) = bounds.find(checker, &row.line, &row.test) else {
            faults.push(format!("{named}: an evidence row of no recorded model"));
            continue;
        };
        let allowed = match row.purpose {
            Purpose::Normal => row.bound.is_none() && row.stack.is_none(),
            Purpose::BoundProbe => {
                row.bound == recorded.bound.checked_sub(1) && row.stack.is_none()
            }
            Purpose::StackProbe => {
                row.bound.is_none()
                    && row.stack.is_some()
                    && row.stack
                        == recorded
                            .stack
                            .and_then(|stack| stack.checked_sub(bounds.page))
            }
            Purpose::Derive | Purpose::Control | Purpose::Suite => false,
        };
        if !allowed {
            faults.push(format!(
                "{named}: a {} row at bound {:?} and stack {:?} is no evidence: only unset \
                 values, the recorded bound {} less one, or the recorded stack {:?} less a page",
                row.purpose.name(),
                row.bound,
                row.stack,
                recorded.bound,
                recorded.stack
            ));
        }
    }
    for planned in plan(listed, bounds) {
        let matching: Vec<&&Row> = evidence
            .iter()
            .filter(|row| {
                row.runner == planned.listed.checker.name()
                    && row.line == planned.listed.target
                    && row.test == planned.listed.test
                    && row.purpose == planned.purpose
                    && row.bound == planned.bound
                    && row.stack == planned.stack
            })
            .collect();
        let named = format!(
            "{} {} {} {}",
            planned.listed.checker,
            planned.listed.target,
            planned.listed.test,
            planned.purpose.name()
        );
        match matching[..] {
            [] => faults.push(format!("{named}: not run")),
            [row] if row.expected != Some(planned.expected) => faults.push(format!(
                "{named}: published expecting {:?}, where the plan expects {}",
                row.expected, planned.expected
            )),
            [row] if row.outcome == planned.expected => {}
            [row] => faults.push(format!(
                "{named}: {}, where only {} is evidence",
                row.outcome, planned.expected
            )),
            _ => faults.push(format!("{named}: run more than once")),
        }
    }
    faults
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rows::Physical;

    fn ran(outcome: Outcome) -> Ran {
        Ran {
            outcome,
            schedules: Some(3),
            seconds: None,
            peak_kb: None,
        }
    }

    /// A model that needs `bound` and `stack`: refused below the bound,
    /// overflowing below the stack (the stack checked first, as a run starts
    /// on its stack before it reaches its bound).
    fn needs(
        checker: Checker,
        bound: usize,
        stack: Option<usize>,
    ) -> impl FnMut(usize, Option<usize>) -> Ran {
        move |at, on| match (stack, on) {
            (Some(needed), Some(given)) if given < needed => ran(outcome::overflow(checker)),
            _ if at < bound => ran(Outcome::BoundRefused),
            _ => ran(Outcome::Pass),
        }
    }

    #[test]
    fn the_least_bound_is_found_upward_from_one() {
        for bound in [1, 2, 3, 17, 64, 1000] {
            let derived = derive(
                Checker::Loom,
                false,
                4096,
                needs(Checker::Loom, bound, None),
            )
            .expect("a monotone model");
            assert_eq!(
                (derived.bound, derived.stack),
                (bound, None),
                "bound {bound}"
            );
            let runs = derived.runs.len();
            assert!(
                runs <= 2 * (bound.ilog2() as usize + 2),
                "{runs} runs for {bound}"
            );
        }
    }

    #[test]
    fn the_least_stack_is_found_in_pages_and_checked_monotone() {
        let derived = derive(
            Checker::Shuttle,
            true,
            4096,
            needs(Checker::Shuttle, 40, Some(5 * 4096)),
        )
        .expect("a monotone model");
        assert_eq!((derived.bound, derived.stack), (40, Some(5 * 4096)));
        assert_eq!(derived.schedules, Some(3));
        for pages in [4, 10, 20, 40] {
            assert!(
                derived
                    .runs
                    .iter()
                    .any(|(_, on, _)| *on == Some(pages * 4096)),
                "{pages} pages were not run"
            );
        }
    }

    /// Planted: a stack that fails above its least size, as a memory error
    /// depending on the schedule would, is refused as a defect.
    #[test]
    fn a_stack_that_is_not_monotone_is_a_defect() {
        let mut model = needs(Checker::Shuttle, 8, Some(2 * 4096));
        let refused = derive(Checker::Shuttle, true, 4096, move |at, on| {
            if on == Some(16 * 4096) {
                ran(Outcome::Segfault)
            } else {
                model(at, on)
            }
        })
        .expect_err("a non-monotone stack was taken as a size");
        assert!(refused.contains("not monotone"), "{refused}");
        assert!(refused.contains("Miri race seeds"), "{refused}");
    }

    /// Planted: a run failing otherwise than by its bound or stack ends the
    /// derivation; loom's overflow is no shuttle's.
    #[test]
    fn any_other_failure_ends_the_derivation() {
        let refused = derive(Checker::Loom, false, 4096, |_, _| ran(Outcome::Failed))
            .expect_err("a failing model was derived");
        assert!(
            refused.contains("neither its bound nor its stack"),
            "{refused}"
        );
        let refused = derive(Checker::Shuttle, true, 4096, |_, _| {
            ran(Outcome::StackOverflow)
        })
        .expect_err("loom's overflow was taken as shuttle's");
        assert!(refused.contains("stack_overflow"), "{refused}");
    }

    fn listed() -> Vec<Listed> {
        vec![
            Listed {
                checker: Checker::Loom,
                target: "lib".to_string(),
                test: "a".to_string(),
            },
            Listed {
                checker: Checker::Shuttle,
                target: "lib".to_string(),
                test: "b".to_string(),
            },
        ]
    }

    fn bounds() -> Bounds {
        let derived = |bound, stack| Derived {
            bound,
            stack,
            schedules: None,
            runs: Vec::new(),
        };
        let models = listed();
        Bounds {
            profile: "release".to_string(),
            page: 4096,
            models: vec![
                bound_of(&models[0], &derived(17, None)),
                bound_of(&models[1], &derived(40, Some(3 * 4096))),
            ],
        }
    }

    fn row_of(planned: &Planned, outcome: Outcome) -> Row {
        Row {
            domain: "all-features".to_string(),
            line: planned.listed.target.clone(),
            runner: planned.listed.checker.name().to_string(),
            test: planned.listed.test.clone(),
            seed: None,
            purpose: planned.purpose,
            bound: planned.bound,
            stack: planned.stack,
            expected: Some(planned.expected),
            outcome,
            seconds: None,
            peak_kb: None,
            physical: Physical::NotApplicable,
        }
    }

    #[test]
    fn the_plan_probes_each_recorded_value_one_under() {
        let planned = plan(&listed(), &bounds());
        let shape: Vec<(Purpose, Option<usize>, Option<usize>, Outcome)> = planned
            .iter()
            .map(|row| (row.purpose, row.bound, row.stack, row.expected))
            .collect();
        assert_eq!(
            shape,
            vec![
                (Purpose::Normal, None, None, Outcome::Pass),
                (Purpose::BoundProbe, Some(16), None, Outcome::BoundRefused),
                (Purpose::Normal, None, None, Outcome::Pass),
                (Purpose::BoundProbe, Some(39), None, Outcome::BoundRefused),
                (Purpose::StackProbe, None, Some(2 * 4096), Outcome::Segfault),
            ]
        );
    }

    #[test]
    fn the_evidence_of_every_planned_row_holds() {
        let rows: Vec<Row> = plan(&listed(), &bounds())
            .iter()
            .map(|planned| row_of(planned, planned.expected))
            .collect();
        assert_eq!(verdict(&listed(), &bounds(), &rows), Vec::<String>::new());
    }

    /// Planted: a probe refused by anything but its bound, a raised bound,
    /// a missing row and a duplicate row each fail the verdict.
    #[test]
    fn only_the_planned_rows_with_their_outcomes_are_evidence() {
        let planned = plan(&listed(), &bounds());
        let mut rows: Vec<Row> = planned
            .iter()
            .map(|planned| row_of(planned, planned.expected))
            .collect();
        rows[1].outcome = Outcome::Failed;
        let faults = verdict(&listed(), &bounds(), &rows);
        assert!(
            faults
                .iter()
                .any(|fault| fault.contains("where only bound_refused")),
            "{faults:#?}"
        );
        rows[1].outcome = Outcome::BoundRefused;
        let mut raised = rows[0].clone();
        raised.bound = Some(1000);
        rows.push(raised);
        let faults = verdict(&listed(), &bounds(), &rows);
        assert!(
            faults.iter().any(|fault| fault.contains("is no evidence")),
            "{faults:#?}"
        );
        rows.pop();
        rows.remove(4);
        let faults = verdict(&listed(), &bounds(), &rows);
        assert!(
            faults
                .iter()
                .any(|fault| fault.contains("stack_probe: not run")),
            "{faults:#?}"
        );
        let mut doubled = rows.clone();
        doubled.push(rows[0].clone());
        let faults = verdict(&listed(), &bounds(), &doubled);
        assert!(
            faults
                .iter()
                .any(|fault| fault.contains("run more than once")),
            "{faults:#?}"
        );
        let mut unplanned = rows.clone();
        unplanned[0].expected = Some(Outcome::Failed);
        let faults = verdict(&listed(), &bounds(), &unplanned);
        assert!(
            faults
                .iter()
                .any(|fault| fault.contains("where the plan expects pass")),
            "{faults:#?}"
        );
    }

    /// Planted: a model listed and not recorded, and one recorded and no
    /// longer listed, each fail completeness.
    #[test]
    fn the_record_is_complete_and_holds_no_stale_model() {
        let mut models = listed();
        models.push(Listed {
            checker: Checker::Loom,
            target: "lib".to_string(),
            test: "new".to_string(),
        });
        let faults = completeness(&models, &bounds());
        assert!(
            faults
                .iter()
                .any(|fault| fault.contains("listed but not recorded"))
        );
        let faults = completeness(&listed()[..1], &bounds());
        assert!(
            faults
                .iter()
                .any(|fault| fault.contains("no longer a model"))
        );
    }
}
