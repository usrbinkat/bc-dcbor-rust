use super::harness::*;
use dcbor::bounded::{
    BoundedError,
    encoding::{Preparation, PrepareStep, Schema},
    text_cursor::pipeline::EmitStep,
};
use dcbor_derive::CBORResumableEncodable;
use hashbrown::HashTable;

fn table<K, V>(entries: impl IntoIterator<Item = (K, V)>) -> HashTable<(K, V)> {
    let mut result = HashTable::new();
    for (index, entry) in entries.into_iter().enumerate() {
        result.insert_unique(index as u64, entry, |_| 0);
    }
    result
}

fn run(source: &dyn Schema, expected: Option<&[u8]>, stop: Option<usize>, cancel: bool) -> Meter {
    let mut m = meter();
    m.fail_at = stop.map(|i| (i, Refusal::Work));
    let mut operation = Preparation::new(source);
    let mut output = None;
    let mut observed = false;
    let mut done = false;
    for _ in 0..65536 {
        let before = (m.values, m.bytes);
        m.limit_values = before.0 + 3;
        m.limit_bytes = before.1 + 64;
        let result = operation.step(&mut m);
        assert!(m.values - before.0 <= 3 && m.bytes - before.1 <= 64);
        match result {
            Ok(PrepareStep::Progress) => {}
            Ok(PrepareStep::Complete(plan)) => {
                assert!(expected.is_some());
                output = Some(plan);
                done = true;
                break;
            }
            Err(BoundedError::Refused(Refusal::Work)) => {
                assert_eq!(m.refused, stop.map(|i| (i, Refusal::Work)));
                assert!(!observed);
                observed = true;
                m.fail_at = None;
                m.refused = None;
                if cancel {
                    done = true;
                    break;
                }
                let position = operation.position();
                let consumed = (m.values, m.bytes);
                for _ in 0..2 {
                    let call = m.calls.len();
                    m.fail_at = Some((call, Refusal::Work));
                    assert!(matches!(
                        operation.step(&mut m),
                        Err(BoundedError::Refused(Refusal::Work))
                    ));
                    assert_eq!(m.refused, Some((call, Refusal::Work)));
                    assert_eq!(operation.position(), position);
                    assert_eq!((m.values, m.bytes), consumed);
                    m.fail_at = None;
                    m.refused = None;
                }
            }
            Err(BoundedError::DuplicateKey) => {
                assert!(expected.is_none());
                done = true;
                break;
            }
            _ => panic!("unexpected outcome at {:?}", operation.position()),
        }
    }
    assert!(done, "finite bound exceeded at {:?}", operation.position());
    assert_eq!(observed, stop.is_some());
    drop(operation);
    if let Some(plan) = output {
        assert!(m.pool.live() > 0);
        let expected = expected.unwrap();
        let mut bytes = vec![0xee; plan.len()];
        let mut writer = plan.writer(&mut bytes);
        let mut b = meter();
        let mut complete = false;
        for _ in 0..expected.len() * 2 + 16 {
            b.limit_values = b.values + 3;
            b.limit_bytes = b.bytes + 64;
            if writer.step(&mut b).unwrap() == EmitStep::Complete {
                complete = true;
                break;
            }
        }
        assert!(complete);
        assert_eq!(writer.emitted_prefix(), expected);
        assert!(b.calls.iter().all(|c| !matches!(c, Call::Allocate(_))));
        drop(plan);
    }
    assert_eq!(m.pool.live(), 0);
    m
}

fn matrix(source: &dyn Schema, expected: Option<&[u8]>) {
    let baseline = run(source, expected, None, false);
    every_case(baseline.calls.len(), |stop| {
        let resumed = run(source, expected, Some(stop), false);
        let mut trace = baseline.calls.clone();
        for _ in 0..3 {
            trace.insert(stop, baseline.calls[stop]);
        }
        assert_eq!(resumed.calls, trace);
        assert_eq!(
            (resumed.values, resumed.bytes),
            (baseline.values, baseline.bytes)
        );
        let cancelled = run(source, expected, Some(stop), true);
        assert_eq!(cancelled.calls, baseline.calls[..=stop]);
    });
}

#[test]
fn nested_tables_as_keys_and_values_resume_without_replay() {
    let source = table([
        (table([(2u64, 0u64), (1, 0)]), table([(1u64, 2u64)])),
        (table([(0, 1)]), table([(3, 4), (0, 5)])),
    ]);
    matrix(
        &source,
        Some(&[
            0xa2, 0xa1, 0, 1, 0xa2, 0, 5, 3, 4, 0xa2, 1, 0, 2, 0, 0xa1, 1, 2,
        ]),
    );
}

#[derive(CBORResumableEncodable)]
struct Record<T> {
    #[cbor(n = 0)]
    value: T,
    #[cbor(n = 1)]
    absent: Option<u64>,
}

#[test]
fn derived_fields_and_map_keys_compact_nested_header_gaps() {
    let source = Record {
        value: vec![table([
            (
                Record {
                    value: 2u64,
                    absent: Some(7),
                },
                vec![table([(1u64, 2u64)])],
            ),
            (
                Record {
                    value: 1u64,
                    absent: None,
                },
                vec![table([])],
            ),
        ])],
        absent: None,
    };
    matrix(
        &source,
        Some(&[
            0xa1, 0, 0x81, 0xa2, 0xa1, 0, 1, 0x81, 0xa0, 0xa2, 0, 2, 1, 7, 0x81, 0xa1, 1, 2,
        ]),
    );
}

#[test]
fn canonical_collisions_inside_nested_map_keys_are_rejected() {
    let source = vec![table([
        (table([("e\u{301}".to_string(), 0u64)]), 1u64),
        (table([("é".to_string(), 0u64)]), 2u64),
    ])];
    matrix(&source, None);
}

#[test]
fn every_nested_table_physical_allocation_failure_retains_custody() {
    use super::heap::Observation;
    let source = table((0..8u64).map(|n| {
        (
            table([(n, "e\u{301}".repeat(8))]),
            Record {
                value: table([(n, vec![n; 8])]),
                absent: None,
            },
        )
    }));
    let run = |failure| {
        let mut m = meter();
        m.calls.reserve(65536);
        let observation = Observation::begin(failure);
        let mut operation = Preparation::new(&source);
        let mut output = None;
        let mut failed = false;
        for _ in 0..65536 {
            m.limit_values = m.values + 3;
            m.limit_bytes = m.bytes + 64;
            match operation.step(&mut m) {
                Ok(PrepareStep::Progress) => {}
                Ok(PrepareStep::Complete(plan)) => {
                    output = Some(plan);
                    break;
                }
                Err(BoundedError::Allocation { .. }) => {
                    failed = true;
                    break;
                }
                _ => panic!("unexpected allocation matrix outcome"),
            }
            assert!(observation.snapshot().live <= m.pool.live() as usize);
        }
        observation.stop();
        assert!(failed || output.is_some());
        assert_eq!(failed, failure.is_some());
        let stats = observation.snapshot();
        assert_eq!(stats.denied, failure.is_some());
        assert_eq!(stats.unadmitted, 0);
        assert!(!stats.overflow);
        assert!(stats.peak <= m.pool.peak() as usize);
        drop(operation);
        if output.is_some() {
            assert!(m.pool.live() > 0);
        }
        drop(output);
        assert_eq!(m.pool.live(), 0);
        assert_eq!(observation.snapshot().live, 0);
        stats.calls
    };
    every_case(run(None), |index| {
        run(Some(index));
    });
}

enum Chain {
    Leaf(u64),
    Map(HashTable<(u64, Box<Chain>)>),
}

impl Schema for Chain {
    fn instruction(&self, index: usize) -> dcbor::bounded::encoding::Instruction<'_> {
        match self {
            Self::Leaf(value) => value.instruction(index),
            Self::Map(value) => value.instruction(index),
        }
    }
}

fn chain(depth: usize) -> Chain {
    let mut source = Chain::Leaf(7);
    for _ in 0..depth {
        source = Chain::Map(table([(0u64, Box::new(source))]));
    }
    source
}

#[test]
fn deep_tables_have_bounded_all_ready_steps_and_a_finite_completion_bound() {
    for depth in [1usize, 8, 32, 127] {
        let source = chain(depth);
        let mut operation = Preparation::new(&source);
        let mut m = meter();
        let mut output = None;
        // Each ancestor copies at most the remaining 2*depth+1 encoded bytes
        // a fixed number of times. Each one-entry table scans four buckets.
        let bound = 64 * (depth + 1) * (depth + 1) + 4096;
        for _ in 0..bound {
            let before = (m.values, m.bytes, m.calls.len());
            let step = operation.step(&mut m).unwrap();
            assert!(m.values - before.0 <= 3);
            assert!(m.bytes - before.1 <= 64);
            assert!(m.calls.len() > before.2, "progress without an admission");
            if let PrepareStep::Complete(plan) = step {
                output = Some(plan);
                break;
            }
        }
        let plan = output.expect("depth-derived bound exceeded");
        let mut expected = Vec::new();
        for _ in 0..depth {
            expected.extend([0xa1, 0]);
        }
        expected.push(7);
        let mut bytes = vec![0; plan.len()];
        let mut writer = plan.writer(&mut bytes);
        let mut complete = false;
        for _ in 0..expected.len() + 16 {
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
    }
}

#[test]
fn excessive_nested_table_depth_is_terminal_without_publication() {
    let source = chain(128);
    let mut operation = Preparation::new(&source);
    let mut m = meter();
    let mut rejected = false;
    for _ in 0..65536 {
        m.limit_values = m.values + 3;
        m.limit_bytes = m.bytes + 64;
        match operation.step(&mut m) {
            Ok(PrepareStep::Progress) => {}
            Err(BoundedError::DepthLimit) => {
                rejected = true;
                break;
            }
            Err(error) => panic!(
                "unexpected depth outcome: {error:?} at {:?}",
                operation.position()
            ),
            _ => panic!("excessive-depth map was not rejected"),
        }
    }
    assert!(rejected);
    assert!(matches!(operation.step(&mut m), Ok(PrepareStep::Finished)));
    drop(operation);
    assert_eq!(m.pool.live(), 0);
}
