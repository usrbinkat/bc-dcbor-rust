//! Held operation-local and scope cleanup through one checked schedule.
use dcbor::bounded::decode::construction::reclamation::Reclaimed;
use dcbor::bounded::decode::construction::{Standalone, in_place::InPlace};
use dcbor::bounded::{BoundedResult, Custodial, CustodySink, Failure, Limits, PermitsObserved};

use crate::{
    Finding, Holding, Permit, PolicyId, Retirement, Scope, Scoped, Stopped, TURNS, allowed,
    capture, lost, pipeline, require_evidence, retryable, scope_checked,
};

pub(crate) enum Goal {
    Drained,
    Quiescent,
}

impl<T: InPlace<Limits>, W: pipeline::Physical> Holding<'_, '_, crate::Destination<T>, W> {
    /// Keep the destination outside the consumer's unwinding frame, and finish
    /// its standalone cleanup before releasing the exclusive slot borrow.
    pub(crate) fn standalone<R, V: pipeline::Physical>(
        &mut self,
        document: &dcbor::bounded::decode::Document<'_, Permit>,
        policy: PolicyId,
        turns: usize,
        window: &V,
        body: impl FnOnce(
            &mut Holding<'_, '_, Standalone<'_, '_, '_, T, Limits>, V>,
        ) -> Result<R, Finding>,
    ) -> Result<R, Finding> {
        let driver = Standalone::new(document, &mut self.value.get().0);
        Holding {
            run: &mut *self.run,
            surrounding: &mut *self.surrounding,
            value: crate::Held(Some(driver)),
            retirement: Retirement::Exhausted,
            window,
            publication: None,
        }
        .execute(|held| {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| body(held)));
            let cleanup = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if held.value().stage()
                    == dcbor::bounded::decode::construction::in_place::Stage::Released
                {
                    Ok(())
                } else {
                    let cleanup = held.run.shared_policy(policy);
                    held.reclaim_standalone(cleanup, turns, |_, _, _| {})
                }
            }))
            .unwrap_or_else(|payload| {
                Err(Finding::Defect(format!(
                    "standalone cleanup panicked: {}",
                    crate::panic_report(payload.as_ref())
                )))
            });
            match (outcome, cleanup) {
                (Ok(Ok(value)), Ok(())) => Ok(value),
                (Ok(Ok(_)), Err(error)) => Err(error),
                (Ok(Err(error)), cleanup) => {
                    if let Err(cleanup) = cleanup {
                        held.run.defects.push(cleanup);
                    }
                    Err(error)
                }
                (Err(payload), cleanup) => {
                    if let Err(cleanup) = cleanup {
                        held.run.defects.push(cleanup);
                    }
                    std::panic::resume_unwind(payload)
                }
            }
        })
    }
}

/// The checked cleanup schedule. Custody is borrowed throughout; completion,
/// refusal, observation failure, and recording loss never transfer ownership.
/// A drain continues cleanup after recording loss, retaining its first failure
/// for the caller. Invalid history is never presented to an observer.
pub(crate) fn reclaim_by<C>(
    custody: &mut C,
    m: &mut Limits,
    turns: usize,
    goal: Goal,
    mut observe: impl FnMut(&mut C, &Limits),
    mut step: impl FnMut(&mut C, &mut Limits) -> BoundedResult<Reclaimed, Limits>,
) -> Result<(), Scoped<BoundedResult<Reclaimed, Limits>>> {
    let mut failure = None;
    for at in 0..turns {
        if let Err(error) = require_evidence(m, at) {
            if matches!(goal, Goal::Quiescent) {
                return Err(error);
            }
            failure.get_or_insert(error);
        }
        let injected = m.injected_refusals();
        let result = step(custody, m);
        if let Some(lost) = lost(m, at) {
            let error = Stopped::Lost(lost, result.clone());
            if matches!(goal, Goal::Quiescent) {
                return Err(error);
            }
            failure.get_or_insert(error);
        } else {
            observe(custody, m);
            if let Some(lost) = lost(m, at) {
                let error = Stopped::Lost(lost, result.clone());
                if matches!(goal, Goal::Quiescent) {
                    return Err(error);
                }
                failure.get_or_insert(error);
            }
        }
        match result {
            Ok(Reclaimed::Done) => return failure.map_or(Ok(()), Err),
            Ok(Reclaimed::Waiting) if matches!(goal, Goal::Quiescent) => return Ok(()),
            Ok(Reclaimed::Progress | Reclaimed::Waiting) => {}
            Err(error) if error.refused() && retryable(m, &error, injected) => {}
            Err(error) => {
                return Err(match failure {
                    None => Stopped::Operation(error),
                    Some(first) => Stopped::Violated {
                        output: None,
                        outcome: Some(Err(error)),
                        lost: lost(m, at),
                        report: format!("cleanup failed after {first:?}"),
                    },
                });
            }
        }
    }
    Err(match failure {
        None => Stopped::Exceeded(turns),
        Some(first) => Stopped::Violated {
            output: None,
            outcome: None,
            lost: lost(m, turns),
            report: format!("cleanup exceeded {turns} turns after {first:?}"),
        },
    })
}

/// An owning handle held across every unit of its in-place cleanup.
pub struct Reclaiming<T> {
    slot: Option<T>,
    step: fn(&mut Option<T>, &mut Limits) -> BoundedResult<Reclaimed, Limits>,
}

impl<T> Reclaiming<T> {
    pub fn new(
        value: T,
        step: fn(&mut Option<T>, &mut Limits) -> BoundedResult<Reclaimed, Limits>,
    ) -> Self {
        Self {
            slot: Some(value),
            step,
        }
    }

    /// Read the surviving handle without removing it from held custody.
    pub fn value(&self) -> Option<&T> {
        self.slot.as_ref()
    }

    /// Exercise the production empty-slot contract after completed cleanup.
    pub fn probe_empty(&mut self, m: &mut Limits) -> BoundedResult<Reclaimed, Limits> {
        assert!(self.slot.is_none(), "empty-slot probe still holds a handle");
        (self.step)(&mut self.slot, m)
    }
}

impl<T: Custodial<Permit>> Custodial<Permit> for Reclaiming<T> {
    fn observe_custody(&mut self, sink: &mut dyn CustodySink<Permit>) -> PermitsObserved {
        self.slot
            .as_mut()
            .map_or(PermitsObserved::Complete, |value| {
                value.observe_custody(sink)
            })
    }
}

impl<T: Custodial<Permit>, W: pipeline::Physical> Holding<'_, '_, Reclaiming<T>, W> {
    /// Finish operation-local cleanup, checkpointing the complete holding stack.
    pub fn reclaim(
        &mut self,
        policy: PolicyId,
        turns: usize,
        mut observe: impl FnMut(&T),
    ) -> Result<(), Finding> {
        let run = &mut *self.run;
        let m = &mut run.policies[policy.0];
        let bound = allowed(m, turns);
        let surrounding = &mut *self.surrounding;
        let window = self.window;
        reclaim_by(
            self.value.get(),
            m,
            bound,
            Goal::Drained,
            |slot, _| {
                let before = run.defects.len();
                capture(
                    &run.session,
                    &mut run.checkpoints,
                    &mut run.defects,
                    |sink| {
                        dcbor::bounded::observed_all([
                            surrounding.observe_custody(sink),
                            slot.observe_custody(sink),
                        ])
                    },
                );
                assert_eq!(
                    run.defects.len(),
                    before,
                    "cleanup custody observation failed"
                );
                if let Some(value) = slot.value() {
                    observe(value);
                }
            },
            |slot, m| crate::checked(m, |m| window.window(|| (slot.step)(&mut slot.slot, m))),
        )?;
        assert!(
            self.value.get().slot.is_none(),
            "cleanup completed with a live handle"
        );
        self.retirement = Retirement::Exhausted;
        Ok(())
    }
}

impl<'s, D: Scope<'s>, W: pipeline::Physical> Holding<'_, '_, D, W> {
    /// Drain queued work while leaving admission open and live handles usable.
    pub fn quiesce(&mut self, policy: PolicyId) -> Result<(), Finding> {
        let run = &mut *self.run;
        let m = &mut run.policies[policy.0];
        let surrounding = &mut *self.surrounding;
        let window = self.window;
        reclaim_by(
            self.value.get(),
            m,
            TURNS,
            Goal::Quiescent,
            |scope, _| {
                let before = run.defects.len();
                capture(
                    &run.session,
                    &mut run.checkpoints,
                    &mut run.defects,
                    |sink| {
                        dcbor::bounded::observed_all([
                            surrounding.observe_custody(sink),
                            scope.observe_custody(sink),
                        ])
                    },
                );
                assert_eq!(
                    run.defects.len(),
                    before,
                    "scope custody observation failed"
                );
            },
            |scope, m| scope_checked(m, scope, |scope, m| window.window(|| scope.scope().step(m))),
        )
        .map_err(Finding::from)
    }
}

impl<'d, 'a, 'v, T: InPlace<Limits>, W: pipeline::Physical>
    Holding<'_, '_, Standalone<'d, 'a, 'v, T, Limits>, W>
{
    /// Build while retaining the destination in this holding. A standalone
    /// completion publishes no owning handle; custody remains here for cleanup.
    pub fn build_standalone(
        &mut self,
        policy: PolicyId,
        turns: usize,
        cancel: Option<usize>,
        mut observe: impl FnMut(
            &mut Standalone<'d, 'a, 'v, T, Limits>,
            &Limits,
            &crate::StepOf<Standalone<'d, 'a, 'v, T, Limits>>,
        ),
    ) -> Result<Option<()>, crate::Driven<Standalone<'d, 'a, 'v, T, Limits>>> {
        self.checkpoint();
        let run = &mut *self.run;
        let surrounding = &mut *self.surrounding;
        crate::drive_controlled(
            &mut run.policies[policy.0],
            self.value.get(),
            crate::Pacing::resuming(turns),
            |_, _, at| cancel == Some(at),
            |m, driver, result| {
                let before = run.defects.len();
                capture(
                    &run.session,
                    &mut run.checkpoints,
                    &mut run.defects,
                    |sink| {
                        dcbor::bounded::observed_all([
                            surrounding.observe_custody(sink),
                            driver.observe_custody(sink),
                        ])
                    },
                );
                assert_eq!(
                    run.defects.len(),
                    before,
                    "standalone custody observation failed"
                );
                observe(driver, m, result);
            },
            self.window,
        )
    }

    /// Reclaim the held standalone destination through the shared cleanup
    /// schedule. The destination and document remain borrowed until cleanup
    /// completes; every turn observes the complete surrounding custody.
    pub fn reclaim_standalone(
        &mut self,
        policy: PolicyId,
        turns: usize,
        mut observe: impl FnMut(
            &mut Standalone<'d, 'a, 'v, T, Limits>,
            &Limits,
            &BoundedResult<Reclaimed, Limits>,
        ),
    ) -> Result<(), Finding> {
        let run = &mut *self.run;
        let m = &mut run.policies[policy.0];
        let bound = allowed(m, turns);
        let surrounding = &mut *self.surrounding;
        let window = self.window;
        let result = reclaim_by(
            self.value.get(),
            m,
            bound,
            Goal::Drained,
            |driver, _| {
                let before = run.defects.len();
                capture(
                    &run.session,
                    &mut run.checkpoints,
                    &mut run.defects,
                    |sink| {
                        dcbor::bounded::observed_all([
                            surrounding.observe_custody(sink),
                            driver.observe_custody(sink),
                        ])
                    },
                );
                assert_eq!(
                    run.defects.len(),
                    before,
                    "standalone custody observation failed"
                );
            },
            |driver, m| {
                let result = crate::checked(m, |m| window.window(|| driver.reclaim_step(m)));
                if lost(m, 0).is_none() {
                    observe(driver, m, &result);
                }
                result
            },
        );
        if self.value().stage() == dcbor::bounded::decode::construction::in_place::Stage::Released {
            self.retirement = Retirement::Exhausted;
        }
        result.map_err(Finding::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Destination, Lent, recorded_run, root_bound, turns};
    use dcbor::bounded::{Budget, LimitRefusal, Owner};
    use std::cell::Cell;
    use std::mem::MaybeUninit;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    #[derive(Clone, Copy)]
    enum Exit {
        Error,
        Lost,
        LostUnwind,
    }

    fn standalone_exit(exit: Exit) {
        let wire = dcbor::CBOR::from("retained destination".repeat(16)).to_cbor_data();
        let bound = turns(root_bound::<String>(&wire));
        let reclaimed = Cell::new(false);
        let failure = catch_unwind(AssertUnwindSafe(|| {
            recorded_run(|run| {
                let parsing = run.policy(u64::MAX);
                let document = run.with_policy(parsing, |m| {
                    dcbor::bounded::decode::decode(&wire, 64, m).expect("the fixture parses")
                });
                let policy = run.policy(u64::MAX);
                let outcome = catch_unwind(AssertUnwindSafe(|| {
                    run.holding(
                        document,
                        Retirement::Released,
                        &pipeline::Unwitnessed,
                        |document| {
                            document.lending(Retirement::Exhausted, Lent::new, |document| {
                                let source = document.value().get();
                                document.holding(
                                    Destination(MaybeUninit::<String>::uninit()),
                                    Retirement::Exhausted,
                                    |destination| {
                                        destination.standalone(
                                            source,
                                            policy,
                                            bound,
                                            &pipeline::Unwitnessed,
                                            |driver| {
                                                driver.build_standalone(
                                                    policy,
                                                    bound,
                                                    None,
                                                    |_, _, _| {},
                                                )?;
                                                driver.with_policy(policy, |driver, m| {
                                                    assert!(driver.value().is_some());
                                                    assert!(m.live_bytes() > 0);
                                                    if matches!(exit, Exit::Lost | Exit::LostUnwind)
                                                    {
                                                        assert_eq!(
                                                            m.validate_owner(&Owner::unobserved()),
                                                            Err(LimitRefusal::Unrecorded)
                                                        );
                                                    }
                                                });
                                                if matches!(exit, Exit::LostUnwind) {
                                                    panic!("planted standalone loss unwind");
                                                }
                                                Err::<(), _>(Finding::Defect(
                                                    "planted standalone consumer error".to_owned(),
                                                ))
                                            },
                                        )
                                    },
                                )
                            })
                        },
                    )
                }));
                run.with_policy(policy, |m| {
                    assert_eq!(
                        m.live_bytes(),
                        0,
                        "standalone exit retained payload storage"
                    );
                    assert_eq!(
                        m.credits()
                            .conserved_with(dcbor::bounded::WriteWork::default()),
                        Some(true),
                        "standalone exit left unsettled credit"
                    );
                });
                reclaimed.set(true);
                match outcome {
                    Ok(result) => result,
                    Err(payload) => std::panic::resume_unwind(payload),
                }
            });
        }))
        .expect_err("the planted standalone failure must propagate");
        assert!(
            reclaimed.get(),
            "standalone cleanup did not finish before finalization"
        );
        let report = crate::panic_report(failure.as_ref());
        match exit {
            Exit::Error => {
                assert!(
                    report.contains("planted standalone consumer error"),
                    "{report}"
                );
                assert!(
                    report
                        .ends_with("finalization: the recording finished and refined the protocol"),
                    "{report}"
                );
            }
            Exit::Lost | Exit::LostUnwind => {
                let original = if matches!(exit, Exit::LostUnwind) {
                    "planted standalone loss unwind"
                } else {
                    "planted standalone consumer error"
                };
                assert!(report.contains(original), "{report}");
                assert!(report.contains("ForeignOwner"), "{report}");
                assert!(
                    !report.contains("finished and refined the protocol"),
                    "{report}"
                );
            }
        }
    }

    #[test]
    fn standalone_consumer_error_reclaims_before_finalization() {
        standalone_exit(Exit::Error);
    }

    #[test]
    fn standalone_recording_loss_reclaims_without_accepting_evidence() {
        standalone_exit(Exit::Lost);
    }

    #[test]
    fn standalone_recording_loss_preserves_consumer_unwind() {
        standalone_exit(Exit::LostUnwind);
    }
}
