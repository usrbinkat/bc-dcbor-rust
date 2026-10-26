use super::harness::*;
use super::support::{
    checked, contracted, exhausted, label, pipeline::Refusal, prepare_turns, refuse, shape,
};
use dcbor::bounded::{
    BoundedError, Step,
    decode::storage::Storage,
    encoding::{
        Instruction, Preparation, Schema,
        buckets::{BucketCursor, BucketStep},
    },
};
use hashbrown::HashTable;

/// A large table whose one entry lies in its last bucket: every window of
/// vacant buckets before it is admitted, refused and resumed at its exact
/// position; the last window yields the entry; the enumeration then
/// completes, every control byte charged once.
#[test]
fn vacant_bucket_batches_retain_exact_positions_and_bound_total_steps() {
    let mut table = HashTable::<u64>::with_capacity(1_000_000);
    let buckets = table.num_buckets();
    let last = buckets as u64 - 1;
    // Hashed to itself: its home bucket is the last, free as it is inserted.
    table.insert_unique(last, last, |value| *value);
    assert_eq!(table.get_bucket(buckets - 1), Some(&last));
    let mut cursor = BucketCursor::new(&table);
    let mut m = meter();
    for start in (0..buckets).step_by(64) {
        let call = m.attempts();
        refuse(&mut m, Refusal::For(call, LimitRefusal::Work));
        assert!(matches!(
            cursor.step_batch(&mut m),
            Err(BoundedError::Refused(LimitRefusal::Work))
        ));
        assert_eq!(m.first_refusal(), Some((call, LimitRefusal::Work)));
        assert_eq!(cursor.position(), start);
        m.fail_call(None);
        m.turn();
        let expected = if start + 64 >= buckets {
            BucketStep::Entry {
                index: buckets - 1,
                value: &last,
            }
        } else {
            BucketStep::Vacant { index: start }
        };
        assert_eq!(cursor.step_batch(&mut m).unwrap(), expected);
        assert_eq!(cursor.position(), (start + 64).min(buckets));
    }
    assert_eq!(m.used().bytes, buckets as u64);
    assert_eq!(m.used().values, buckets.div_ceil(64) as u64);
    assert_eq!(cursor.step_batch(&mut m).unwrap(), BucketStep::Complete);
}

#[test]
fn plain_data_truncation_is_constant_work_and_retains_the_allocation() {
    let mut storage: Storage<u64, Reservation> = Storage::new();
    let mut m = meter();
    // A push into an arena of `len` elements takes at most a growth's units
    // (`Storage::grow_step`): staging, the grown allocation, publication, one
    // relocation per element, the settlement and the vacated block's
    // release; then the grant.
    for value in 0..1024u64 {
        let units = storage.len() + 6;
        let mut pushed = false;
        for _ in 0..units {
            if let Some(spare) = storage.reserve_step(usize::MAX, &mut m).unwrap() {
                spare.push(value);
                pushed = true;
                break;
            }
        }
        assert!(pushed, "push {value} exceeded its {units} growth units");
    }
    let held = m.live_bytes();
    let before = m.used();
    let call = m.attempts();
    refuse(&mut m, Refusal::For(call, LimitRefusal::Work));
    assert!(matches!(
        storage.truncate_copy_step(1, &mut m),
        Err(BoundedError::Refused(LimitRefusal::Work))
    ));
    assert_eq!(storage.len(), 1024);
    assert_eq!(m.live_bytes(), held);
    m.fail_call(None);
    m.clear_refusal();
    assert!(storage.truncate_copy_step(1, &mut m).unwrap());
    assert_eq!(
        storage.settled().map(|arena| arena.as_slice()),
        Some([0u64].as_slice())
    );
    assert_eq!(m.used().values, before.values + 1);
    assert_eq!(m.used().bytes, before.bytes);
    assert_eq!(m.live_bytes(), held);
    assert!(storage.truncate_copy_step(0, &mut m).unwrap());
    // The allocation's release was paid for by its growth: cleanup frees
    // it, then admits the transition that reports the arena released. An
    // arena of `len` elements cleans up in at most `len + 3` units
    // (`Storage::reclaim_step`): a staged growth's release, one drain per
    // element, the allocation's release, then the completing transition.
    let units = storage.len() + 3;
    let mut released = false;
    for _ in 0..units {
        if storage.reclaim_step(&mut m).unwrap() {
            released = true;
            break;
        }
    }
    assert!(released, "cleanup exceeded its {units} units");
    assert_eq!(m.live_bytes(), 0);
}

struct Entries(Vec<(u64, u64)>);

/// A root unordered map whose source yields its entries in reverse canonical
/// order, each value a byte string longer than a quantum. Its contract, not
/// its mechanism:
///
/// - canonical bytes: the emitted plan is the symbolic encoding;
/// - the permutation and compaction are admitted: every turn is checked
///   (admission before progress, at most a quantum, nothing refunded) within
///   the bound of the source's own shape, the root's keys and values are
///   compacted, and its payload is permuted in place, each byte moved at
///   most once, the visited bitmap a bit per payload byte;
/// - progress is kept across refusals: before every preparation and
///   emission step, three immediate refusals leave the position, the paid
///   work and the live storage unchanged;
/// - nothing is published until the permutation finishes: completion comes
///   only after the moves, with the permutation reset and its bitmap
///   released.
#[test]
fn root_map_is_permuted_in_place_and_published_only_once_canonical() {
    use dcbor::bounded::encoding::{DynamicPhase, PermutationPhase, prepare_bound};
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
    // The symbolic encoding, and the literal it must be: twenty entries in
    // key order, each key a one-byte integer and each value a byte string
    // of 65 + key bytes behind its two-byte head.
    let mut symbolic = dcbor::Map::new();
    for (key, value) in &source.0 {
        symbolic.insert(*key, value.clone());
    }
    let expected = dcbor::CBOR::from(symbolic).to_cbor_data();
    let mut literal = vec![0xb4];
    for key in 0..20u8 {
        literal.extend([key, 0x58, 65 + key]);
        literal.extend(vec![key; 65 + key as usize]);
    }
    assert_eq!(expected, literal);
    // Every byte after the map's one-byte head is its payload.
    let payload = expected.len() - 1;

    let walked = shape(&source);
    let mut m = meter();
    let mut operation = Preparation::new(&source);
    let (mut compacted, mut moves, mut bitmap) = (false, 0usize, 0usize);
    let mut output = None;
    for _ in 0..prepare_turns(walked) {
        let before = operation.position().dynamic;
        // An open compaction records where it reads; none reads at zero,
        // the root's gap lying before every key.
        compacted |= before.compact_source != 0;
        if before.permutation.phase == PermutationPhase::Move {
            moves += 1;
        }
        bitmap = bitmap.max(before.permutation.bitmap_bytes);
        match super::support::repeated_turn(&mut m, &mut operation, 3) {
            Ok(Step::Progress) => {}
            Err(error) if super::support::ordinary_exhaustion(&m, &error) => {}
            Ok(Step::Complete(plan)) => {
                let after = operation.position().dynamic;
                assert!(moves > 0, "published before the payload was permuted");
                assert_eq!(after.permutation.phase, PermutationPhase::Offsets);
                assert_eq!(after.permutation.bitmap_bytes, 0, "the bitmap outlived it");
                assert_eq!(after.phase, DynamicPhase::Order);
                exhausted(&mut m, &mut operation);
                output = Some(plan);
                break;
            }
            other => panic!(
                "preparation stepped to {} at {:?}",
                label(&other),
                operation.position()
            ),
        }
    }
    let plan = output.expect("preparation exceeded the bound of its shape");
    assert!(compacted, "the root's keys and values were never compacted");
    assert!(
        moves <= payload,
        "{moves} moves over a payload of {payload} bytes"
    );
    assert_eq!(
        bitmap,
        payload.div_ceil(8),
        "the bitmap is a bit per payload byte"
    );
    let bound = prepare_bound::<Reservation, LimitRefusal>(walked).unwrap();
    assert!(
        bound.work().covers(&m.used()),
        "{:?} beyond the preparation bound {bound:?}",
        m.used()
    );
    m.assert_units(TURN);
    drop(operation);
    assert!(m.live_bytes() > 0, "the plan holds its arena");

    let requests = m.requests();
    let mut bytes = vec![0xee; expected.len()];
    let mut writer = plan.writer(&mut bytes);
    let mut complete = false;
    for _ in 0..emit_turns(expected.len()) {
        let result = super::support::repeated_turn(&mut m, &mut writer, 3).unwrap();
        assert_eq!(
            writer.emitted_prefix(),
            &expected[..writer.emitted_prefix().len()]
        );
        if result == Step::Complete(()) {
            complete = true;
            break;
        }
    }
    assert!(complete, "emission exceeded the bound of its length");
    exhausted(&mut m, &mut writer);
    assert_eq!(writer.emitted_prefix(), expected);
    assert_eq!(m.requests(), requests, "emission requested storage");
    drop(plan);
    assert_eq!(m.live_bytes(), 0);
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
    // The walk accepts the source: duplicates are found by preparation.
    for _ in 0..prepare_turns(shape(&source)) {
        match checked(&mut m, |m| contracted(m, &mut operation)) {
            Ok(Step::Progress) => {}
            Err(error) if super::support::ordinary_exhaustion(&m, &error) => {}
            Err(BoundedError::DuplicateKey) => {
                assert_eq!(operation.position().dynamic.ordering.width, 1);
                assert_eq!(operation.position().dynamic.ordering.run, 0);
                exhausted(&mut m, &mut operation);
                rejected = true;
                break;
            }
            _ => panic!("unexpected duplicate outcome"),
        }
    }
    assert!(rejected);
    drop(operation);
    assert_eq!(m.live_bytes(), 0);
}

#[test]
fn merge_scratch_never_contains_more_than_the_shorter_run() {
    for count in [3usize, 5, 9, 17, 33, 64] {
        let source = Entries((0..count as u64).rev().map(|n| (n, 0)).collect());
        let mut operation = Preparation::new(&source);
        let mut m = meter();
        let mut complete = false;
        for _ in 0..prepare_turns(shape(&source)) {
            let p = operation.position().dynamic.ordering;
            if p.width > 0 && p.run < count {
                let left = p.width.min(count - p.run);
                let right = p.width.min(count - p.run - left);
                assert!(p.scratch <= left.min(right));
            }
            match checked(&mut m, |m| contracted(m, &mut operation)) {
                Ok(Step::Complete(plan)) => {
                    drop(plan);
                    complete = true;
                    break;
                }
                Ok(Step::Progress) => {}
                Err(error) if super::support::ordinary_exhaustion(&m, &error) => {}
                other => panic!("unexpected merge outcome: {}", label(&other)),
            }
        }
        assert!(complete);
        drop(operation);
        assert_eq!(m.live_bytes(), 0);
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
    for reordered in [false, true] {
        for depth in [1usize, 8, 32] {
            for length in [64usize, 256, 4096] {
                let mut source: Box<dyn Schema> =
                    Box::new(dcbor::ByteString::from(vec![0xaa; length]));
                for _ in 0..depth {
                    source = Box::new(Nested(source, reordered));
                }
                let wire_length = length + 3 + if reordered { 4 * depth } else { 2 * depth };
                // Per payload byte and dynamic ancestor, the in-place
                // permutation of these two-entry maps: at most two 24-byte
                // lookup probes, one four-byte move and its share of the
                // bitmap scan; and the bitmap's and arenas' growth.
                let byte_bound = 64 * wire_length * (depth + 1) + 512 * (depth + 1);
                let turns = prepare_turns(shape(source.as_ref()));
                let mut operation = Preparation::new(source.as_ref());
                let mut m = meter();
                let mut output = None;
                let mut moves = 0;
                for _ in 0..turns {
                    if operation.position().dynamic.permutation.phase
                        == dcbor::bounded::encoding::PermutationPhase::Move
                    {
                        moves += 1;
                    }
                    let step = checked(&mut m, |m| contracted(m, &mut operation));
                    assert!(operation.position().dynamic.scratch <= wire_length.div_ceil(8));
                    if !reordered {
                        assert_eq!(
                            operation.position().dynamic.scratch,
                            0,
                            "already ordered single-entry maps must not allocate payload scratch"
                        );
                    }
                    match step {
                        Ok(Step::Complete(plan)) => {
                            output = Some(plan);
                            break;
                        }
                        Ok(Step::Progress) => {}
                        Err(error) if super::support::ordinary_exhaustion(&m, &error) => {}
                        other => panic!(
                            "depth {depth}, length {length}, reordered {reordered}: {} at {:?}",
                            label(&other),
                            operation.position(),
                        ),
                    }
                }
                let plan = output.expect("preparation exceeded its production turn bound");
                assert!(
                    moves <= wire_length * depth,
                    "a byte moved more than once per dynamic ancestor"
                );
                assert!(
                    m.used().bytes <= byte_bound as u64,
                    "depth {depth}, length {length}: {}",
                    m.used().bytes
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
                emit(&plan, &expected, &mut m);
                drop(operation);
                drop(plan);
                assert_eq!(m.live_bytes(), 0);
            }
        }
    }
}
