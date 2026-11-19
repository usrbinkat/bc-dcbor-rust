use super::harness::*;
use super::support::{
    Finding, Retirement, Stopped,
    pipeline::{Refusal, Unwitnessed},
    prepare_turns, recorded_run, refuse, shape,
};
use dcbor::ByteString;
use dcbor::bounded::encoding::{Instruction, Preparation, Schema};
use dcbor::bounded::{BoundedError, Class, Failure, WriteWork, prepare};

/// A counted map whose head declares `self.0` fields and whose source
/// visits one: miscounted unless it declares exactly one.
struct Counted(u64);

impl Schema for Counted {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        match index {
            0 => Instruction::CountedMap(self.0),
            1 => Instruction::Field(0, Some(&true)),
            _ => Instruction::End,
        }
    }
}

/// A source breaking its schema contract is a defect: terminal, never a
/// refusal the caller could resume; the preparation's own cleanup then runs
/// to `Finished` within its bound, releasing its storage.
#[test]
fn a_source_contract_defect_is_terminal_and_never_a_refusal() {
    // The miscounted source has no shape: its walk rejects it. The same map
    // declaring its one field answers the same instructions up to its end,
    // where the miscount is found, so its production bound covers every
    // step before the rejection.
    let bound = prepare_turns(shape(&Counted(1)));
    let source = Counted(2);
    recorded_run(|run| {
        let policy = run.observed_policy(POOL);
        run.holding(
            Preparation::new(&source),
            Retirement::Released,
            &Unwitnessed,
            |operation| {
                let error = match operation.drive(policy, bound, Retirement::Released, |_| {
                    panic!("a miscounted map was published")
                }) {
                    Err(Stopped::Operation(error)) => error,
                    Err(stop) => return Err(Finding::from(stop)),
                    Ok(()) => unreachable!("publication fails inside its holding"),
                };
                assert_eq!(error, BoundedError::PlanMismatch);
                assert_eq!(error.class(), Class::Defect);
                operation.with_policy(policy, |_, m| {
                    assert!(
                        m.first_refusal().is_none(),
                        "a defect was classified as a caller refusal"
                    );
                });
                operation.finish(policy, bound, Retirement::Released)?;
                Ok(())
            },
        )?;
        run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0));
        Ok(())
    });
}

/// A caller's refusal of a write's second segment keeps its own class, the
/// first segment's payment and its bytes, and nothing past them; the same
/// plan then writes in full.
#[test]
fn caller_refusal_within_a_write_keeps_its_class_and_paid_prefix() {
    // A head of two bytes and a hundred payload bytes: segments of 64 and
    // 38 bytes, then the completion.
    let value = ByteString::new(vec![0x5a; 100]);
    super::support::recorded_run(|run| {
        // The plan's reservations are the preparing family's; each write is
        // under a family of its own, of the same recorded run.
        let allocator = run.policy(POOL);
        let prepared = run.with_policy(allocator, |m| prepare(&value, m).unwrap());
        let writes = [
            LimitRefusal::Work,
            LimitRefusal::Storage,
            LimitRefusal::Deadline,
        ]
        .map(|reason| (reason, run.policy(POOL)));
        let writing = run.policy(POOL);
        run.holding(prepared, Retirement::Released, &Unwitnessed, |prepared| {
            assert_eq!(prepared.value().len(), 102);
            for (reason, writing) in writes {
                prepared.with_policy(writing, |prepared, budget| {
                    let mut output = [0xee; 102];
                    refuse(budget, Refusal::For(1, reason));
                    assert_eq!(
                        prepared.encode_into(&mut output, budget),
                        Err(BoundedError::Refused(reason))
                    );
                    assert_eq!(budget.first_refusal(), Some((1, reason)));
                    assert_eq!(budget.used(), WriteWork::new(1, 64));
                    assert_eq!(output[..2], [0x58, 100]);
                    assert!(output[2..64].iter().all(|b| *b == 0x5a));
                    assert!(output[64..].iter().all(|b| *b == 0xee));
                });
            }
            prepared.with_policy(writing, |prepared, budget| {
                let mut output = [0; 102];
                prepared.encode_into(&mut output, budget).unwrap();
                assert_eq!(output[..2], [0x58, 100]);
                assert!(output[2..].iter().all(|b| *b == 0x5a));
                assert_eq!(budget.used(), WriteWork::new(3, 102));
            });
        });
        run.with_policy(allocator, |m| assert_eq!(m.live_bytes(), 0));
        Ok(())
    });
}
