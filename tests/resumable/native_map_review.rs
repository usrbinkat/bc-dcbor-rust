use super::harness::*;
use dcbor::bounded::{
    BoundedError,
    decode::storage::Storage,
    encoding::{
        Instruction, Preparation, PrepareStep, Schema,
        buckets::{BucketCursor, BucketStep},
    },
};
use hashbrown::HashTable;

#[test]
fn vacant_bucket_batches_retain_exact_positions_and_bound_total_steps() {
    let table = HashTable::<u64>::with_capacity(1_000_000);
    let mut cursor = BucketCursor::new(&table);
    let mut m = meter();
    for start in (0..table.num_buckets()).step_by(64) {
        let call = m.calls.len();
        m.fail_at = Some((call, Refusal::Work));
        assert!(matches!(
            cursor.step_batch(&mut m),
            Err(BoundedError::Refused(Refusal::Work))
        ));
        assert_eq!(m.refused, Some((call, Refusal::Work)));
        assert_eq!(cursor.position(), start);
        m.fail_at = None;
        m.refused = None;
        m.limit_values = m.values + 3;
        m.limit_bytes = m.bytes + 64;
        assert_eq!(
            cursor.step_batch(&mut m).unwrap(),
            BucketStep::Vacant { index: start }
        );
        assert_eq!(cursor.position(), (start + 64).min(table.num_buckets()));
    }
    assert_eq!(m.bytes, table.num_buckets() as u64);
    assert_eq!(m.values, table.num_buckets().div_ceil(64) as u64);
    assert_eq!(cursor.step_batch(&mut m).unwrap(), BucketStep::Complete);
}

#[test]
fn plain_data_truncation_is_constant_work_and_retains_the_allocation() {
    let mut storage = Storage::new();
    let mut m = meter();
    for value in 0..1024u64 {
        while !storage.reserve_step(&mut m).unwrap() {}
        storage.push_reserved(value).unwrap();
    }
    let held = m.pool.live();
    let before = (m.values, m.bytes, m.calls.len());
    m.fail_at = Some((before.2, Refusal::Work));
    assert!(matches!(
        storage.truncate_copy_step(1, &mut m),
        Err(BoundedError::Refused(Refusal::Work))
    ));
    assert_eq!(storage.len(), 1024);
    assert_eq!(m.pool.live(), held);
    m.fail_at = None;
    m.refused = None;
    storage.truncate_copy_step(1, &mut m).unwrap();
    assert_eq!(storage.ready(), Some([0u64].as_slice()));
    assert_eq!(m.values, before.0 + 1);
    assert_eq!(m.bytes, before.1);
    assert_eq!(m.pool.live(), held);
    storage.truncate_copy_step(0, &mut m).unwrap();
    assert!(storage.release_step(&mut m).unwrap());
    assert_eq!(m.pool.live(), 0);
}

struct Entries(Vec<(u64, u64)>);

#[test]
fn root_map_emits_descriptors_without_permuting_payload_and_retains_refusals() {
    use dcbor::bounded::encoding::PermutationPhase;
    use dcbor::bounded::text_cursor::pipeline::EmitStep;
    struct Payloads(Vec<(u64, dcbor::ByteString)>);
    impl Schema for Payloads {
        fn instruction(&self, index: usize) -> Instruction<'_> {
            if index == 0 {
                return Instruction::UnorderedMap;
            }
            self.0
                .get(index - 1)
                .map_or(Instruction::End, |(key, value)| Instruction::Entry {
                    next: index + 1,
                    entry: Some((key, value)),
                })
        }
    }
    let source = Payloads(
        (0..20u64)
            .rev()
            .map(|key| {
                (
                    key,
                    dcbor::ByteString::from(vec![key as u8; 65 + key as usize]),
                )
            })
            .collect(),
    );
    let mut expected = vec![0xb4];
    for key in 0..20u8 {
        expected.extend([key, 0x58, 65 + key]);
        expected.extend(vec![key; 65 + key as usize]);
    }
    let mut m = meter();
    let mut operation = Preparation::new(&source);
    let mut output = None;
    for _ in 0..32768 {
        let position = operation.position().dynamic;
        assert_ne!(position.permutation.phase, PermutationPhase::Move);
        assert_eq!(position.permutation.bitmap_bytes, 0);
        m.limit_values = m.values + 3;
        m.limit_bytes = m.bytes + 64;
        if let PrepareStep::Complete(plan) = operation.step(&mut m).unwrap() {
            output = Some(plan);
            break;
        }
    }
    let plan = output.expect("preparation completion bound");
    drop(operation);
    assert!(m.pool.live() > 0);
    let mut bytes = vec![0xee; expected.len()];
    let mut writer = plan.writer(&mut bytes);
    let mut complete = false;
    // Two payload chunks and one descriptor transition per entry, plus
    // root header, header-gap transition, and completion.
    for _ in 0..20 * 3 + 4 {
        let prefix = writer.emitted_prefix().to_vec();
        let consumed = (m.values, m.bytes);
        let live = m.pool.live();
        for _ in 0..3 {
            let call = m.calls.len();
            m.fail_at = Some((call, Refusal::Work));
            assert!(matches!(
                writer.step(&mut m),
                Err(BoundedError::Refused(Refusal::Work))
            ));
            assert_eq!(m.refused, Some((call, Refusal::Work)));
            assert_eq!(writer.emitted_prefix(), prefix);
            assert_eq!((m.values, m.bytes), consumed);
            assert_eq!(m.pool.live(), live);
            m.fail_at = None;
            m.refused = None;
        }
        m.limit_values = m.values + 3;
        m.limit_bytes = m.bytes + 64;
        let calls = m.calls.len();
        let result = writer.step(&mut m).unwrap();
        assert_eq!(m.calls.len(), calls + 1);
        assert!(!matches!(m.calls[calls], Call::Allocate(_)));
        assert_eq!(
            writer.emitted_prefix(),
            &expected[..writer.emitted_prefix().len()]
        );
        if result == EmitStep::Complete {
            complete = true;
            break;
        }
    }
    assert!(complete);
    assert_eq!(writer.emitted_prefix(), expected);
    drop(plan);
    assert_eq!(m.pool.live(), 0);
}

impl Schema for Entries {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        if index == 0 {
            return Instruction::UnorderedMap;
        }
        self.0
            .get(index - 1)
            .map_or(Instruction::End, |(k, v)| Instruction::Entry {
                next: index + 1,
                entry: Some((k, v)),
            })
    }
}

#[test]
fn duplicate_is_rejected_during_the_first_merge_not_after_sorting() {
    let mut entries = vec![(0, 1), (0, 2)];
    entries.extend((1..32).map(|key| (key, 0)));
    let source = Entries(entries);
    let mut operation = Preparation::new(&source);
    let mut m = meter();
    let mut rejected = false;
    for _ in 0..32768 {
        m.limit_values = m.values + 3;
        m.limit_bytes = m.bytes + 64;
        match operation.step(&mut m) {
            Ok(PrepareStep::Progress) => {}
            Err(BoundedError::DuplicateKey) => {
                assert_eq!(operation.position().dynamic.ordering.width, 1);
                assert_eq!(operation.position().dynamic.ordering.run, 0);
                rejected = true;
                break;
            }
            _ => panic!("unexpected duplicate outcome"),
        }
    }
    assert!(rejected);
    drop(operation);
    assert_eq!(m.pool.live(), 0);
}

#[test]
fn merge_scratch_never_contains_more_than_the_shorter_run() {
    for count in [3usize, 5, 9, 17, 33, 64] {
        let source = Entries((0..count as u64).rev().map(|n| (n, 0)).collect());
        let mut operation = Preparation::new(&source);
        let mut m = meter();
        let mut complete = false;
        for _ in 0..32768 {
            let p = operation.position().dynamic.ordering;
            if p.width > 0 && p.run < count {
                let left = p.width.min(count - p.run);
                let right = p.width.min(count - p.run - left);
                assert!(p.scratch <= left.min(right));
            }
            m.limit_values = m.values + 3;
            m.limit_bytes = m.bytes + 64;
            if let PrepareStep::Complete(plan) = operation.step(&mut m).unwrap() {
                drop(plan);
                complete = true;
                break;
            }
        }
        assert!(complete);
        drop(operation);
        assert_eq!(m.pool.live(), 0);
    }
}

struct Nested(Box<dyn Schema>, bool);
impl Schema for Nested {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        match index {
            0 => Instruction::UnorderedMap,
            1 => Instruction::Entry {
                next: 2,
                entry: Some((if self.1 { &1u64 } else { &0u64 }, self.0.as_ref())),
            },
            2 if self.1 => Instruction::Entry {
                next: 3,
                entry: Some((&0u64, &0u64)),
            },
            _ => Instruction::End,
        }
    }
}

#[test]
fn nested_payload_work_is_bounded_by_bytes_times_dynamic_depth() {
    use dcbor::bounded::text_cursor::pipeline::EmitStep;
    for reordered in [false, true] {
        for depth in [1usize, 8, 32] {
            for length in [64usize, 256, 4096] {
                let mut source: Box<dyn Schema> =
                    Box::new(dcbor::ByteString::from(vec![0xaa; length]));
                for _ in 0..depth {
                    source = Box::new(Nested(source, reordered));
                }
                let wire_length = length + 3 + if reordered { 4 * depth } else { 2 * depth };
                // At most two 24-byte descriptor inspections, one four-byte
                // cycle move, and one visited-bit inspection per payload byte
                // for these two-entry maps; include bitmap/arena growth too.
                let byte_bound = 64 * wire_length * (depth + 1) + 512 * (depth + 1);
                let mut operation = Preparation::new(source.as_ref());
                let mut m = meter();
                let mut output = None;
                let mut moves = 0;
                for _ in 0..byte_bound {
                    m.limit_values = m.values + 3;
                    m.limit_bytes = m.bytes + 64;
                    if operation.position().dynamic.permutation.phase
                        == dcbor::bounded::encoding::PermutationPhase::Move
                    {
                        moves += 1;
                    }
                    let step = operation.step(&mut m).unwrap();
                    assert!(operation.position().dynamic.scratch <= wire_length.div_ceil(8));
                    if !reordered {
                        assert_eq!(
                            operation.position().dynamic.scratch,
                            0,
                            "already ordered single-entry maps must not allocate payload scratch"
                        );
                    }
                    if let PrepareStep::Complete(plan) = step {
                        output = Some(plan);
                        break;
                    }
                }
                let plan = output.expect("input-derived step bound exceeded");
                assert!(
                    moves <= wire_length * depth,
                    "a byte moved more than once per dynamic ancestor"
                );
                assert!(
                    m.bytes <= byte_bound as u64,
                    "depth {depth}, length {length}: {}",
                    m.bytes
                );
                let mut expected = Vec::new();
                for _ in 0..depth {
                    if reordered {
                        expected.extend([0xa2, 0, 0, 1]);
                    } else {
                        expected.extend([0xa1, 0]);
                    }
                }
                if length < 256 {
                    expected.extend([0x58, length as u8]);
                } else {
                    expected.extend([0x59, (length >> 8) as u8, length as u8]);
                }
                expected.extend(vec![0xaa; length]);
                let mut bytes = vec![0; plan.len()];
                let mut writer = plan.writer(&mut bytes);
                let mut done = false;
                for _ in 0..expected.len() + 16 {
                    m.limit_values = m.values + 3;
                    m.limit_bytes = m.bytes + 64;
                    if writer.step(&mut m).unwrap() == EmitStep::Complete {
                        done = true;
                        break;
                    }
                }
                assert!(done);
                assert_eq!(writer.emitted_prefix(), expected);
                drop(operation);
                drop(plan);
                assert_eq!(m.pool.live(), 0);
            }
        }
    }
}
