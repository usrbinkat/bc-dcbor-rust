//! Recording budgets: the recording capacity of every fixture whose session
//! outgrows the default ([`crate::CAPACITY`]), measured by its family's own
//! recording run and published as a record ([`dcbor_record::budgets`]),
//! never written into a test. A family is one test's fixtures; its record
//! is one per representation variant, rigor layer and witness size, so every
//! selection a test makes runs against the measurement of exactly the
//! fixtures it runs. The records are compiled in (`build.rs`), so a check
//! needs no filesystem, Miri's host isolation included.
//!
//! A family's [`Budgets`] is the one way its fixtures obtain a capacity: each
//! fixture is measured as it runs ([`Budgets::run`], [`Budgets::construction`],
//! [`Budgets::encode_checked`]),
//! from the evidence its recording finished with, and the family is
//! finished once every fixture it declares has been ([`Budgets::finish`]),
//! which a family dropped unfinished refuses. Under
//! [`RECORD`] naming this selection's record, every fixture runs at the
//! fixed bootstrap capacity (`MEASURING`) and the finished family is
//! published whole; otherwise every fixture runs at the capacity its record
//! states (`crate::measured`). A record absent from the build is refused
//! outside its own recording run.
use crate::{Capacity, Observed, RecordedRun};
use dcbor_record::{self as record, budgets::Counts};
use std::collections::BTreeMap;

include!(concat!(env!("OUT_DIR"), "/budgets.rs"));

/// The variable naming the one budget record a run records
/// (`dcbor_record::budgets::record_name`): unset, every family checks its
/// record; set, only the family of that record and selection records, and
/// any other family it reaches refuses to run.
pub const RECORD: &str = "DCBOR_RECORD_BUDGETS";

/// Only the exact record name authorizes measurement; an absent variable
/// selects checking, and malformed or mismatched values refuse execution.
fn authorized(name: &str, value: Result<String, std::env::VarError>) -> bool {
    match value {
        Err(std::env::VarError::NotPresent) => false,
        Ok(value) if value == name => true,
        other => panic!("{RECORD} must name {name} exactly or be unset: {other:?}"),
    }
}

/// The record `name`'s family `expected` checks against: none while it is
/// recorded; otherwise its compiled record `data`, required present and
/// complete, never a measurement substituted for an absent record.
fn checked(
    name: &str,
    recording: bool,
    data: Option<&str>,
    expected: &[String],
) -> Option<BTreeMap<String, Counts>> {
    if recording {
        return None;
    }
    let data = data.unwrap_or_else(|| {
        panic!("{name}: no record; record it with bash tests/record-evidence.sh record-budgets")
    });
    Some(
        record::budgets::read(data, expected).unwrap_or_else(|error| {
            panic!("{name}: {error}; record it with bash tests/record-evidence.sh record-budgets")
        }),
    )
}

/// The capacity every fixture records into while its family is measured:
/// one fixed preallocation, never grown or retried. A fixture that
/// outgrows it exhausts its session, which refuses its evidence by name.
const MEASURING: Capacity = Capacity {
    events: 1 << 23,
    permits: 1 << 16,
};

/// What a finished recording held: every observation, and every permit
/// record among them, one per grant and one per split child.
pub fn counts(observed: &[Observed]) -> Counts {
    use dcbor::bounded::{Answer, Call, Event};
    Counts {
        events: observed.len(),
        permits: observed
            .iter()
            .filter(|observation| {
                matches!(
                    observation.event,
                    Event::Call(Call::Allocate(_), Answer::Granted(_)) | Event::Split { .. }
                )
            })
            .count(),
    }
}

/// One family's fixtures under this run's selection ([`crate::rigor`]): the
/// fixtures it declares, the record it checks against (`None` while it is
/// recorded), what each fixture measured, the fixture running now, and
/// whether the family was finished.
pub struct Budgets {
    name: String,
    expected: Vec<String>,
    recorded: Option<BTreeMap<String, Counts>>,
    measured: BTreeMap<String, Counts>,
    running: Option<String>,
    finished: bool,
}

impl Budgets {
    /// The family `family` of the fixtures `expected`, under the
    /// representation of `variant` (`dcbor_record::declare_variant`) and
    /// this run's layer and witness sizes: listed in the inventory
    /// (`tests/data/budgets/families.rs`), its fixtures distinct, and,
    /// unless [`RECORD`] names its record, its record compiled in and
    /// complete.
    pub fn new(family: &str, variant: &str, expected: Vec<String>) -> Self {
        record::budgets::validate_inventory(&expected)
            .unwrap_or_else(|error| panic!("budget family {family}: {error}"));
        assert!(
            record::budgets::FAMILIES
                .iter()
                .any(|&(name, ..)| name == family),
            "budget family {family} is not listed in tests/data/budgets/families.rs"
        );
        let name = record::budgets::record_name(
            family,
            variant,
            crate::rigor::rigor(),
            crate::rigor::witness(),
        );
        let &(_, data) = EMBEDDED
            .iter()
            .find(|(embedded, _)| *embedded == name)
            .unwrap_or_else(|| panic!("{name} is no record of the budget inventory"));
        let recorded = checked(
            &name,
            authorized(&name, std::env::var(RECORD)),
            data,
            &expected,
        );
        Self {
            name,
            expected,
            recorded,
            measured: BTreeMap::new(),
            running: None,
            finished: false,
        }
    }

    /// `body` as one recorded run of fixture `key`, finalized by the one
    /// recorded-run finalization at the fixture's capacity, the fixture
    /// measured from the evidence it finished with.
    pub fn run<R>(
        &mut self,
        key: &str,
        body: impl FnOnce(&mut RecordedRun) -> Result<R, crate::Finding>,
    ) -> R {
        self.measure(
            key,
            |capacity| crate::recorded_evidence(capacity, crate::ExpectedVerdict::Accepted, body),
            |(_, observed, _)| observed,
        )
        .0
    }

    /// Construct and reclaim fixture `key` through the observed construction
    /// driver, measuring its finalized recording before returning its report.
    pub fn construction<
        T: dcbor::bounded::decode::construction::in_place::InPlace<dcbor::bounded::Limits>,
    >(
        &mut self,
        key: &str,
        wire: &[u8],
        inspect: impl FnOnce(&T),
    ) -> crate::Constructed<crate::Observation<T>> {
        self.measure(
            key,
            |capacity| crate::construction_in::<T>(wire, capacity, inspect),
            |built| &built.observed,
        )
    }

    /// Round-trip fixture `key` through the owned pipeline's baseline schedule.
    /// The semantic inspection and mandatory finalization precede measurement.
    pub fn encode_checked<T>(
        &mut self,
        key: &str,
        wire: &[u8],
        inspect: impl FnOnce(&T),
    ) -> crate::pipeline::Report
    where
        T: dcbor::bounded::decode::construction::in_place::Transferable<dcbor::bounded::Limits>
            + dcbor::bounded::encoding::TransferableSchema
            + 'static,
    {
        self.measure(
            key,
            |capacity| crate::pipeline::round_trip_in::<T>(wire, capacity, inspect),
            |report| &report.observed,
        )
    }

    /// Only this module selects drivers and their finalized evidence; callers
    /// cannot substitute observations or obtain a budget's raw capacity.
    fn measure<T>(
        &mut self,
        key: &str,
        run: impl FnOnce(Capacity) -> T,
        observed: impl FnOnce(&T) -> &[Observed],
    ) -> T {
        let capacity = self.begin(key);
        let value = run(capacity);
        let counts = counts(observed(&value));
        self.end(key, counts);
        value
    }

    /// The capacity of fixture `key`, which begins running: one the family
    /// declares, not measured yet, and no other fixture still running.
    fn begin(&mut self, key: &str) -> Capacity {
        assert!(
            self.expected.iter().any(|expected| expected == key),
            "{}: fixture {key} is not declared",
            self.name
        );
        assert!(
            !self.measured.contains_key(key),
            "{}: fixture {key} measured twice",
            self.name
        );
        assert!(
            self.running.is_none(),
            "{}: fixture {:?} did not finish before {key} began",
            self.name,
            self.running
        );
        self.running = Some(key.to_owned());
        match &self.recorded {
            None => MEASURING,
            Some(recorded) => {
                let counts = recorded[key];
                crate::measured(counts.events, counts.permits)
            }
        }
    }

    /// Fixture `key`, the one running, finished measuring `counts`.
    fn end(&mut self, key: &str, counts: Counts) {
        assert_eq!(
            self.running.as_deref(),
            Some(key),
            "{}: a measurement of a fixture that is not running",
            self.name
        );
        self.measured.insert(key.to_owned(), counts);
        self.running = None;
    }

    /// The family finished: every fixture it declares measured once, none
    /// still running; while it is recorded, published whole. Reports
    /// `budget finalized: <record>`, the one receipt its recorder requires.
    pub fn finish(mut self) {
        assert!(
            self.running.is_none(),
            "{}: fixture {:?} did not finish",
            self.name,
            self.running
        );
        if self.recorded.is_none() {
            let path = format!(
                "{}/../data/budgets/{}",
                env!("CARGO_MANIFEST_DIR"),
                self.name
            );
            record::budgets::publish(
                &path,
                &record::recording_configuration(),
                &self.expected,
                &self.measured,
            )
        } else {
            record::budgets::complete(&self.expected, &self.measured)
        }
        .unwrap_or_else(|error| panic!("{}: {error}", self.name));
        self.finished = true;
        eprintln!("budget finalized: {}", self.name);
    }
}

/// A family dropped unfinished refuses: its record would be neither checked
/// complete nor published. A family dropped while its test unwinds has
/// already failed.
impl Drop for Budgets {
    fn drop(&mut self) {
        if !self.finished && !std::thread::panicking() {
            panic!("{}: the budget family was dropped unfinished", self.name);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    /// A family of one fixture, recorded at the default capacity.
    fn family() -> Budgets {
        Budgets {
            name: "control".into(),
            expected: vec!["fixture".into()],
            recorded: Some(BTreeMap::from([(
                "fixture".into(),
                Counts {
                    events: 2,
                    permits: 0,
                },
            )])),
            measured: BTreeMap::new(),
            running: None,
            finished: false,
        }
    }

    /// A minimal recorded run: one policy admitting one unit of work through
    /// the route, so its recording holds observations to measure.
    fn trivial(run: &mut RecordedRun) -> Result<(), crate::Finding> {
        let policy = run.policy(u64::MAX);
        run.with_policy(policy, |m| {
            dcbor::bounded::decode::construction::in_place::admit(m, 1)
                .map_err(crate::failed("the admission"))
        })
    }

    /// A family of one fixture whose record states `counts`.
    fn recorded(counts: Counts) -> Budgets {
        let mut budgets = family();
        budgets.recorded = Some(BTreeMap::from([("fixture".into(), counts)]));
        budgets
    }

    /// A fixture runs at the capacity its record states: a run outgrowing the
    /// default ([`crate::CAPACITY`]) finishes under the record of its own
    /// measurement, and is refused, its session exhausted, under a record
    /// within the default. A capacity taken from anywhere but the record
    /// (the default, or the bootstrap's `MEASURING`) fails one of the two.
    #[test]
    fn a_fixture_runs_at_the_capacity_its_record_states() {
        fn outgrowing(run: &mut RecordedRun) -> Result<(), crate::Finding> {
            let policy = run.policy(u64::MAX);
            run.with_policy(policy, |m| {
                for _ in 0..crate::CAPACITY.events {
                    dcbor::bounded::decode::construction::in_place::admit(m, 1)
                        .map_err(crate::failed("an admission"))?;
                }
                Ok(())
            })
        }
        let (_, observed, _) =
            crate::recorded_evidence(MEASURING, crate::ExpectedVerdict::Accepted, outgrowing);
        let measurement = counts(&observed);
        drop(observed);
        assert!(
            measurement.events > crate::CAPACITY.events,
            "the fixture does not outgrow the default: {measurement:?}"
        );
        let mut own = recorded(measurement);
        own.run("fixture", outgrowing);
        assert_eq!(own.measured["fixture"], measurement);
        own.finish();
        let mut within = family();
        let refused = catch_unwind(AssertUnwindSafe(|| within.run("fixture", outgrowing)))
            .expect_err("a run outgrowing its recorded capacity finished");
        assert!(
            crate::panic_report(refused.as_ref()).contains("no evidence: Exhausted"),
            "a run outgrowing its record was not refused by its exhausted session: {}",
            crate::panic_report(refused.as_ref())
        );
        within.finished = true;
    }

    #[test]
    fn a_family_finishes_once_every_fixture_is_measured() {
        let mut budgets = family();
        budgets.run("fixture", trivial);
        assert!(budgets.measured["fixture"].events > 0);
        budgets.finish();
    }

    #[test]
    fn a_failed_evidence_observer_measures_nothing() {
        let mut budgets = family();
        let failure = catch_unwind(AssertUnwindSafe(|| {
            budgets.run("fixture", |run| {
                run.policy(u64::MAX);
                run.inspect_evidence(|_, _| panic!("planted budget observer failure"));
                Ok(())
            });
        }))
        .expect_err("the evidence observer must fail");
        assert!(crate::panic_report(failure.as_ref()).contains("planted budget observer failure"));
        assert!(budgets.measured.is_empty(), "failed evidence was measured");
        let unfinished = catch_unwind(AssertUnwindSafe(|| budgets.finish()))
            .expect_err("a family whose fixture failed finished");
        assert!(crate::panic_report(unfinished.as_ref()).contains("did not finish"));
    }

    #[test]
    fn a_fixture_measured_twice_is_refused_and_keeps_its_measurement() {
        let mut budgets = family();
        budgets.run("fixture", trivial);
        let original = budgets.measured["fixture"];
        let twice = catch_unwind(AssertUnwindSafe(|| budgets.run("fixture", trivial)))
            .expect_err("a fixture was measured twice");
        assert!(crate::panic_report(twice.as_ref()).contains("measured twice"));
        assert_eq!(budgets.measured["fixture"], original);
        budgets.finish();
    }

    #[test]
    fn an_undeclared_or_unmeasured_fixture_is_refused() {
        let mut budgets = family();
        let undeclared = catch_unwind(AssertUnwindSafe(|| budgets.run("other", trivial)))
            .expect_err("an undeclared fixture ran");
        assert!(
            crate::panic_report(undeclared.as_ref()).contains("is not declared"),
            "an undeclared fixture reached capacity selection"
        );
        let incomplete = catch_unwind(AssertUnwindSafe(|| family().finish()))
            .expect_err("a family with an unmeasured fixture finished");
        assert!(crate::panic_report(incomplete.as_ref()).contains("missing"));
        budgets.finished = true;
    }

    #[test]
    fn a_family_dropped_unfinished_is_refused() {
        let dropped = catch_unwind(|| drop(family())).expect_err("an unfinished family dropped");
        assert!(crate::panic_report(dropped.as_ref()).contains("dropped unfinished"));
    }

    /// Outside its recording run a family checks its compiled record: an
    /// absent or incomplete one is refused, never measured in its place;
    /// within it, no record is read.
    #[test]
    fn a_checked_family_requires_its_complete_record() {
        let expected: Vec<String> = vec!["fixture".into()];
        let data = record::render("control", ["fixture\t2\t0"]);
        assert_eq!(
            checked("control", false, Some(&data), &expected),
            Some(BTreeMap::from([(
                "fixture".into(),
                Counts {
                    events: 2,
                    permits: 0,
                },
            )]))
        );
        assert_eq!(checked("control", true, None, &expected), None);
        let absent = catch_unwind(|| checked("control", false, None, &expected))
            .expect_err("a missing record was not refused");
        assert!(
            crate::panic_report(absent.as_ref()).contains("control: no record"),
            "a missing record was not refused: {}",
            crate::panic_report(absent.as_ref())
        );
        let incomplete = record::render("control", ["other\t2\t0"]);
        let refused = catch_unwind(|| checked("control", false, Some(&incomplete), &expected))
            .expect_err("an incomplete record was not refused");
        assert!(crate::panic_report(refused.as_ref()).contains("missing"));
    }

    #[test]
    fn recording_requires_the_exact_selection_name() {
        let name = "control.custom-std.fast.minimal.txt";
        assert!(authorized(name, Ok(name.into())));
        assert!(!authorized(name, Err(std::env::VarError::NotPresent)));
        for value in [
            "",
            "1",
            "other.custom-std.fast.minimal.txt",
            "control.fast.minimal.txt",
            "control.custom-std.exhaustive.minimal.txt",
            "control.custom-std.fast.full.txt",
        ] {
            assert!(
                catch_unwind(|| authorized(name, Ok(value.into()))).is_err(),
                "another selection authorized recording: {value:?}"
            );
        }
        assert!(
            catch_unwind(|| authorized(
                name,
                Err(std::env::VarError::NotUnicode("invalid".into()))
            ))
            .is_err(),
            "a non-Unicode selection authorized recording"
        );
    }
}
