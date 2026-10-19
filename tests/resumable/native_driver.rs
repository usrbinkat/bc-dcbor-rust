//! Test-owned scheduling with bindings to retained production operations.
use super::harness::{Meter, Refusal};

#[derive(Debug, PartialEq, Eq)]
pub enum Step {
    Progress,
    Complete,
    Refused(Refusal),
    Invalid,
    Finished,
}

pub enum Event<T> {
    Progress,
    Complete(T),
    Refused(Refusal),
    Invalid,
    Finished,
}

pub trait Operation<T> {
    fn advance(&mut self, meter: &mut Meter) -> Result<Event<T>, &'static str>;
}

pub struct Driver<O, T> {
    operation: O,
    pub meter: Meter,
    pub output: Option<T>,
    finished: bool,
    pub invocations: usize,
}

impl<O: Operation<T>, T> Driver<O, T> {
    pub fn from_operation(operation: O, meter: Meter) -> Self {
        Self {
            operation,
            meter,
            output: None,
            finished: false,
            invocations: 0,
        }
    }

    pub fn operation(&self) -> &O {
        &self.operation
    }

    pub fn step(&mut self) -> Result<Step, &'static str> {
        if self.finished {
            return Ok(Step::Finished);
        }
        if self.invocations == 0 {
            self.invocations = 1;
        }
        match self.operation.advance(&mut self.meter)? {
            Event::Complete(value) => {
                self.output = Some(value);
                self.finished = true;
                Ok(Step::Complete)
            }
            Event::Progress => Ok(Step::Progress),
            Event::Refused(reason) => Ok(Step::Refused(reason)),
            Event::Invalid => {
                self.finished = true;
                Ok(Step::Invalid)
            }
            Event::Finished => {
                self.finished = true;
                Ok(Step::Finished)
            }
        }
    }
}

/// Observe the injected refusal before continuing the same retained operation.
pub fn resume<F, T>(driver: &mut Driver<F, T>, reason: Refusal)
where
    F: Operation<T>,
{
    resume_with_limit(driver, reason, 4096);
}

pub fn resume_with_limit<F, T>(driver: &mut Driver<F, T>, reason: Refusal, max_steps: usize)
where
    F: Operation<T>,
{
    let mut observed = false;
    for _ in 0..max_steps {
        let before = (driver.meter.values, driver.meter.bytes);
        match driver.step().unwrap() {
            Step::Refused(actual) => {
                assert_eq!(actual, reason);
                observed = true;
                break;
            }
            Step::Progress => {
                assert!(driver.output.is_none());
                assert!(
                    driver.meter.values > before.0 || driver.meter.bytes > before.1,
                    "empty progress before injected refusal"
                );
            }
            other => panic!("target refusal was not reached: {other:?}"),
        }
    }
    assert!(
        observed,
        "target refusal never fired within {max_steps} steps"
    );
    assert!(driver.output.is_none(), "partial value escaped");
    assert!(driver.meter.refused.is_some(), "injection never fired");
    let consumed = (driver.meter.values, driver.meter.bytes);
    driver.meter.fail_at = None;
    finish(driver, max_steps);
    assert_eq!(driver.invocations, 1, "input replayed from its beginning");
    assert!(
        driver.meter.values >= consumed.0 && driver.meter.bytes >= consumed.1,
        "consumed work refunded"
    );
}

/// Common finite multi-step acceptance loop. Only the production binding may
/// report Progress; a missing continuation is a failure, never a retry signal.
pub fn finish<F, T>(driver: &mut Driver<F, T>, max_steps: usize)
where
    F: Operation<T>,
{
    for step in 0..max_steps {
        let before = (
            driver.meter.values,
            driver.meter.bytes,
            driver.meter.calls.len(),
        );
        driver.meter.limit_values = before.0.checked_add(3).expect("work bound overflow");
        driver.meter.limit_bytes = before.1.checked_add(64).expect("work bound overflow");
        // A new scheduler turn permits callbacks again; cumulative consumption
        // and the complete callback history remain intact.
        driver.meter.refused = None;
        let outcome = driver.step();
        let after = (
            driver.meter.values,
            driver.meter.bytes,
            driver.meter.calls.len(),
        );
        assert!(
            after.0 >= before.0 && after.1 >= before.1,
            "consumption refunded"
        );
        assert!(
            after.0 - before.0 <= 3 && after.1 - before.1 <= 64,
            "step {step} exceeded its operation allowance: {before:?} -> {after:?}"
        );
        match outcome {
            Ok(Step::Complete) => {
                assert!(driver.output.is_some());
                return;
            }
            Ok(Step::Progress) => {
                assert!(driver.output.is_none());
                assert!(
                    after.0 > before.0 || after.1 > before.1,
                    "reported progress without executing admitted work"
                );
            }
            other => panic!("step {step}: {other:?}; trace={:?}", driver.meter.calls),
        }
    }
    panic!(
        "no completion within {max_steps} bounded steps; trace={:?}",
        driver.meter.calls
    );
}

#[test]
fn progress_and_refusal_are_distinct_protocol_outcomes() {
    assert_ne!(Step::Progress, Step::Refused(Refusal::Work));
    assert_ne!(Step::Progress, Step::Complete);
}

/// Reach a terminal validation failure under fresh, non-accumulating turns.
/// Invalid data must never become a completed output during this traversal.
pub fn finish_invalid<F, T>(driver: &mut Driver<F, T>, max_steps: usize)
where
    F: Operation<T>,
{
    for step in 0..max_steps {
        let before = (driver.meter.values, driver.meter.bytes);
        driver.meter.limit_values = before.0.checked_add(3).expect("work bound overflow");
        driver.meter.limit_bytes = before.1.checked_add(64).expect("work bound overflow");
        driver.meter.refused = None;
        let outcome = driver.step();
        let after = (driver.meter.values, driver.meter.bytes);
        assert!(
            after.0 >= before.0 && after.1 >= before.1,
            "consumption refunded"
        );
        assert!(
            after.0 - before.0 <= 3 && after.1 - before.1 <= 64,
            "invalid-input step {step} exceeded allowance"
        );
        assert!(driver.output.is_none(), "invalid input published a value");
        match outcome {
            Ok(Step::Invalid) => {
                assert_eq!(driver.invocations, 1);
                assert_eq!(driver.step(), Ok(Step::Finished));
                return;
            }
            Ok(Step::Progress) => assert_ne!(before, after, "empty progress step"),
            other => panic!(
                "invalid-input step {step}: {other:?}; trace={:?}",
                driver.meter.calls
            ),
        }
    }
    panic!(
        "validation never terminated after {max_steps} steps; trace={:?}",
        driver.meter.calls
    );
}
