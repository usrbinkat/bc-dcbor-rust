use super::harness::*;
use super::support::{contracted, exhausted, pipeline::Refusal, prepare_turns, refuse, shape};
use dcbor::ByteString;
use dcbor::bounded::encoding::{Instruction, Preparation, Schema};
use dcbor::bounded::{BoundedError, Class, Failure, Step, WriteWork, prepare};

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
/// refusal the caller could resume, and the preparation is finished after it,
/// admitting nothing further. Its storage is released with it.
#[test]
fn a_source_contract_defect_is_terminal_and_never_a_refusal() {
    // The miscounted source has no shape: its walk rejects it. The same map
    // declaring its one field answers the same instructions up to its end,
    // where the miscount is found, so its production bound covers every
    // step before the rejection.
    let bound = prepare_turns(shape(&Counted(1)));
    let mut m = meter();
    let source = Counted(2);
    let mut operation = Preparation::new(&source);
    let mut defect = None;
    for _ in 0..bound {
        match contracted(&mut m, &mut operation) {
            Ok(Step::Progress) => {}
            Err(error) => {
                defect = Some(error);
                break;
            }
            Ok(Step::Complete(_)) => panic!("a miscounted map was published"),
            Ok(Step::Finished) => panic!("finished without an outcome"),
        }
    }
    let error = defect.unwrap_or_else(|| {
        panic!("the miscount was not found within the valid map's {bound} turns")
    });
    assert_eq!(error, BoundedError::PlanMismatch);
    assert_eq!(error.class(), Class::Defect);
    assert!(
        m.first_refusal().is_none(),
        "a defect was classified as a caller refusal"
    );
    exhausted(&mut m, &mut operation);
    drop(operation);
    assert_eq!(m.live_bytes(), 0);
}

/// A caller's refusal of a write's second segment keeps its own class, the
/// first segment's payment and its bytes, and nothing past them; the same
/// plan then writes in full.
#[test]
fn caller_refusal_within_a_write_keeps_its_class_and_paid_prefix() {
    // A head of two bytes and a hundred payload bytes: segments of 64 and
    // 38 bytes, then the completion.
    let value = ByteString::new(vec![0x5a; 100]);
    let mut allocator = meter();
    let prepared = prepare(&value, &mut allocator).unwrap();
    assert_eq!(prepared.len(), 102);
    for reason in [
        LimitRefusal::Work,
        LimitRefusal::Storage,
        LimitRefusal::Deadline,
    ] {
        let mut output = [0xee; 102];
        let mut budget = meter();
        refuse(&mut budget, Refusal::For(1, reason));
        assert_eq!(
            prepared.encode_into(&mut output, &mut budget),
            Err(BoundedError::Refused(reason))
        );
        assert_eq!(budget.first_refusal(), Some((1, reason)));
        assert_eq!(budget.used(), WriteWork::new(1, 64));
        assert_eq!(output[..2], [0x58, 100]);
        assert!(output[2..64].iter().all(|b| *b == 0x5a));
        assert!(output[64..].iter().all(|b| *b == 0xee));
    }
    let mut output = [0; 102];
    let mut budget = meter();
    prepared.encode_into(&mut output, &mut budget).unwrap();
    assert_eq!(output[..2], [0x58, 100]);
    assert!(output[2..].iter().all(|b| *b == 0x5a));
    assert_eq!(budget.used(), WriteWork::new(3, 102));
    drop(prepared);
    assert_eq!(allocator.live_bytes(), 0);
}
