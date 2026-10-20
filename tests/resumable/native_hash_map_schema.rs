use super::harness::*;
use dcbor::bounded::{
    encoding::{Instruction, Preparation, PrepareStep, Schema},
    text_cursor::pipeline::EmitStep,
    BoundedError,
};
use std::hash::{BuildHasherDefault, Hasher};

#[derive(Default)]
struct Collisions;

impl Hasher for Collisions {
    fn finish(&self) -> u64 {
        0
    }
    fn write(&mut self, _: &[u8]) {}
}

#[test]
fn hash_map_deleted_buckets_encode_literal_output_after_every_refusal() {
    let mut map =
        HashMap::with_capacity_and_hasher(64, BuildHasherDefault::<Collisions>::default());
    for key in 0u64..64 {
        map.insert(key, key + 1);
    }
    let buckets = map.num_buckets();
    for key in 0..64 {
        if ![0, 23, 63].contains(&key) {
            map.remove(&key);
        }
    }
    assert_eq!(map.num_buckets(), buckets);
    let expected = [0xa3, 0, 1, 23, 0x18, 24, 0x18, 63, 0x18, 64];
    let run = |stop: Option<usize>| {
        let mut m = meter();
        m.fail_at = stop.map(|i| (i, Refusal::Work));
        let mut operation = Preparation::new(&map);
        let mut refused = false;
        let mut plan = None;
        for _ in 0..16384 {
            m.limit_values = m.values + 3;
            m.limit_bytes = m.bytes + 64;
            match operation.step(&mut m) {
                Ok(PrepareStep::Progress) => {}
                Ok(PrepareStep::Complete(value)) => {
                    plan = Some(value);
                    break;
                }
                Err(BoundedError::Refused(Refusal::Work)) => {
                    assert!(!refused);
                    assert_eq!(m.refused, stop.map(|i| (i, Refusal::Work)));
                    refused = true;
                    let position = operation.position();
                    let consumed = (m.values, m.bytes);
                    for _ in 0..2 {
                        // Each refused turn starts fresh; the harness rejects
                        // any callback made while a refusal is outstanding.
                        m.refused = None;
                        let call = m.calls.len();
                        m.fail_at = Some((call, Refusal::Work));
                        assert!(matches!(
                            operation.step(&mut m),
                            Err(BoundedError::Refused(Refusal::Work))
                        ));
                        assert_eq!(m.refused, Some((call, Refusal::Work)));
                        assert_eq!(operation.position(), position);
                        assert_eq!((m.values, m.bytes), consumed);
                    }
                    m.fail_at = None;
                    m.refused = None;
                }
                _ => panic!("unexpected preparation result"),
            }
        }
        assert_eq!(refused, stop.is_some());
        let plan = plan.expect("input-derived completion bound");
        let trace = m.calls.clone();
        let mut output = [0; 10];
        let mut writer = plan.writer(&mut output);
        let mut complete = false;
        for _ in 0..32 {
            m.limit_values = m.values + 3;
            m.limit_bytes = m.bytes + 64;
            if writer.step(&mut m).unwrap() == EmitStep::Complete {
                complete = true;
                break;
            }
        }
        assert!(complete);
        assert_eq!(writer.emitted_prefix(), expected);
        drop(operation);
        drop(plan);
        assert_eq!(m.pool.live(), 0);
        trace
    };
    let baseline = run(None);
    every_case(baseline.len(), |stop| {
        let mut expected_trace = baseline.clone();
        for _ in 0..3 {
            expected_trace.insert(stop, baseline[stop]);
        }
        assert_eq!(run(Some(stop)), expected_trace);
    });
}

#[test]
fn entry_instruction_cannot_skip_more_than_admitted_controls() {
    struct InvalidAdvance(usize);
    impl Schema for InvalidAdvance {
        fn instruction(&self, index: usize) -> Instruction<'_> {
            if index == 0 {
                Instruction::UnorderedMap
            } else {
                Instruction::Entry {
                    next: self.0,
                    entry: None,
                }
            }
        }
    }
    for next in [1, 66, usize::MAX] {
        let source = InvalidAdvance(next);
        let mut operation = Preparation::new(&source);
        let mut m = meter();
        let mut rejected = false;
        for _ in 0..128 {
            m.limit_values = m.values + 3;
            m.limit_bytes = m.bytes + 64;
            match operation.step(&mut m) {
                Ok(PrepareStep::Progress) => {}
                Err(BoundedError::PlanMismatch) => {
                    rejected = true;
                    break;
                }
                _ => panic!("invalid cursor advance accepted"),
            }
        }
        assert!(rejected);
    }
}
