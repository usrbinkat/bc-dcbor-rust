use super::harness::*;
use dcbor::bounded::{
    BoundedError,
    encoding::{
        PrepareStep, Schema,
        buckets::{BucketCursor, BucketStep},
        maps::MapPreparation,
    },
    text_cursor::pipeline::EmitStep,
};
use hashbrown::HashTable;

#[test]
fn hash_map_normalized_duplicates_reject_across_every_refusal() {
    let mut map = hashbrown::HashMap::new();
    map.insert("e\u{301}".to_string(), 1u64);
    map.insert("é".to_string(), 2u64);
    let baseline = run(&map, None, false, None);
    every_case(baseline.calls.len(), |stop| {
        let resumed = run(&map, Some(stop), false, None);
        let mut trace = baseline.calls.clone();
        trace.insert(stop, trace[stop]);
        assert_eq!(resumed.calls, trace);
        let cancelled = run(&map, Some(stop), true, None);
        assert_eq!(cancelled.calls, baseline.calls[..=stop]);
    });
}

#[test]
fn sparse_bucket_steps_account_for_every_control_byte_and_repeated_refusal() {
    let mut table = HashTable::with_capacity(8192);
    for n in [0u64, 2000, 6000] {
        table.insert_unique(n, n, |n| *n);
    }
    let mut cursor = BucketCursor::new(&table);
    let mut m = meter();
    let mut found = Vec::new();
    for index in 0..table.num_buckets() {
        assert_eq!(cursor.position(), index);
        if index % 1024 == 0 {
            for _ in 0..3 {
                let stop = m.calls.len();
                m.fail_at = Some((stop, Refusal::Work));
                assert!(matches!(
                    cursor.step(&mut m),
                    Err(BoundedError::Refused(Refusal::Work))
                ));
                assert_eq!(m.refused, Some((stop, Refusal::Work)));
                assert_eq!(cursor.position(), index);
                m.fail_at = None;
                m.refused = None;
            }
        }
        m.limit_values = m.values + 3;
        m.limit_bytes = m.bytes + 64;
        match cursor.step(&mut m).unwrap() {
            BucketStep::Entry {
                index: actual,
                value,
            } => {
                assert_eq!(actual, index);
                found.push(*value);
            }
            BucketStep::Vacant { index: actual } => assert_eq!(actual, index),
            _ => panic!("premature completion"),
        }
    }
    found.sort();
    assert_eq!(found, [0, 2000, 6000]);
    assert_eq!(m.bytes, table.num_buckets() as u64);
    assert_eq!(cursor.step(&mut m).unwrap(), BucketStep::Complete);
    assert_eq!(cursor.step(&mut m).unwrap(), BucketStep::Finished);
    assert_eq!(m.values, table.num_buckets() as u64 + 1);
    assert!(m.calls.iter().all(|c| !matches!(c, Call::Allocate(_))));
}

fn run(table: &dyn Schema, stop: Option<usize>, cancel: bool, expected: Option<&[u8]>) -> Meter {
    let mut m = meter();
    m.fail_at = stop.map(|i| (i, Refusal::Work));
    let mut operation = MapPreparation::new(table);
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
            }
            Err(BoundedError::DuplicateKey) => {
                assert!(expected.is_none());
                done = true;
                break;
            }
            _ => panic!("unexpected outcome at {:?}", operation.position()),
        }
    }
    assert!(done);
    assert_eq!(observed, stop.is_some());
    drop(operation);
    if let Some(plan) = output {
        assert!(m.pool.live() > 0);
        let expected = expected.unwrap();
        assert_eq!(plan.len(), expected.len());
        let mut bytes = vec![0xee; expected.len()];
        let mut writer = plan.writer(&mut bytes);
        let mut b = meter();
        let mut complete = false;
        for _ in 0..expected.len() + 16 {
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

#[test]
fn dynamic_keys_sort_canonically_across_every_refusal_without_replay() {
    let mut table = HashTable::new();
    for (hash, key, value) in [(0, "z", 1), (1, "aa", 2), (2, "a", 3), (3, "e\u{301}", 4)] {
        table.insert_unique(hash, (key.to_string(), value), |(_, value)| *value);
    }
    let expected = [
        0xa4, 0x61, b'a', 3, 0x61, b'z', 1, 0x62, b'a', b'a', 2, 0x62, 0xc3, 0xa9, 4,
    ];
    let baseline = run(&table, None, false, Some(&expected));
    every_case(baseline.calls.len(), |stop| {
        let resumed = run(&table, Some(stop), false, Some(&expected));
        let mut trace = baseline.calls.clone();
        trace.insert(stop, trace[stop]);
        assert_eq!(resumed.calls, trace);
        assert_eq!(
            (resumed.values, resumed.bytes),
            (baseline.values, baseline.bytes)
        );
        let cancelled = run(&table, Some(stop), true, Some(&expected));
        assert_eq!(cancelled.calls, baseline.calls[..=stop]);
    });
}

#[test]
fn normalized_duplicate_keys_reject_after_observed_suspension() {
    let mut table = HashTable::new();
    table.insert_unique(0, ("e\u{301}".to_string(), 1), |(_, v)| *v);
    table.insert_unique(1, ("é".to_string(), 2), |(_, v)| *v);
    let baseline = run(&table, None, false, None);
    every_case(baseline.calls.len(), |stop| {
        let resumed = run(&table, Some(stop), false, None);
        let mut trace = baseline.calls.clone();
        trace.insert(stop, trace[stop]);
        assert_eq!(resumed.calls, trace);
    });
}

#[test]
fn physical_map_preparation_failures_release_flat_arenas_and_reservations() {
    use super::heap::Observation;
    let mut table = HashTable::with_capacity(32);
    for i in 0..16u64 {
        table.insert_unique(i, (format!("{i:02}e\u{301}"), i), |(_, v)| *v);
    }
    let run = |failure| {
        let mut m = meter();
        m.calls.reserve(65536);
        let observation = Observation::begin(failure);
        let mut operation = MapPreparation::new(&table);
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
                _ => panic!("unexpected allocation-failure outcome"),
            }
            assert!(observation.snapshot().live <= m.pool.live() as usize);
        }
        observation.stop();
        assert!(failed || output.is_some());
        assert_eq!(failed, failure.is_some());
        let stats = observation.snapshot();
        assert_eq!(stats.denied, failure.is_some());
        assert!(!stats.overflow);
        assert_eq!(stats.unadmitted, 0);
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
    let count = run(None);
    every_case(count, |index| {
        run(Some(index));
    });
}

#[test]
fn long_key_comparison_retains_exact_offset_across_repeated_refusal() {
    let mut table = HashTable::new();
    for (last, value) in [('b', 1), ('c', 2)] {
        table.insert_unique(
            value,
            (format!("{}{last}", "a".repeat(256)), value),
            |(_, v)| *v,
        );
    }
    let mut operation = MapPreparation::new(&table);
    let mut m = meter();
    let mut interrupted = false;
    let mut output = None;
    for _ in 0..65536 {
        let position = operation.position();
        if !interrupted && position.dynamic.ordering.compared == 64 {
            for _ in 0..3 {
                let stop = m.calls.len();
                m.fail_at = Some((stop, Refusal::Work));
                assert!(matches!(
                    operation.step(&mut m),
                    Err(BoundedError::Refused(Refusal::Work))
                ));
                assert_eq!(m.refused, Some((stop, Refusal::Work)));
                assert_eq!(operation.position(), position);
                m.fail_at = None;
                m.refused = None;
            }
            interrupted = true;
        }
        m.limit_values = m.values + 3;
        m.limit_bytes = m.bytes + 64;
        if let PrepareStep::Complete(plan) = operation.step(&mut m).unwrap() {
            output = Some(plan);
            break;
        }
    }
    assert!(interrupted);
    let plan = output.expect("comparison did not terminate");
    drop(operation);
    let mut expected = vec![0xa2];
    for (last, value) in [(b'b', 1), (b'c', 2)] {
        expected.extend([0x79, 1, 1]);
        expected.extend([b'a'; 256]);
        expected.extend([last, value]);
    }
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
    drop(plan);
    assert_eq!(m.pool.live(), 0);
}

#[test]
fn empty_dynamic_map_has_one_canonical_header() {
    let table = HashTable::<(String, u64)>::new();
    run(&table, None, false, Some(&[0xa0]));
}

#[test]
fn deletion_sparse_cursor_refuses_at_every_bucket_and_terminal_transition() {
    let mut table = HashTable::with_capacity(256);
    for value in 0..256u64 {
        table.insert_unique(value, value, |value| *value);
    }
    let buckets = table.num_buckets();
    for index in 0..buckets {
        if let Ok(entry) = table.get_bucket_entry(index)
            && ![0, 127, 255].contains(entry.get())
        {
            entry.remove();
        }
    }
    assert_eq!(table.num_buckets(), buckets);
    assert_eq!(table.len(), 3);
    let mut cursor = BucketCursor::new(&table);
    let mut m = meter();
    let mut found = Vec::new();
    for index in 0..=buckets {
        for _ in 0..3 {
            let call = m.calls.len();
            let consumed = (m.values, m.bytes);
            m.fail_at = Some((call, Refusal::Work));
            assert!(matches!(
                cursor.step(&mut m),
                Err(BoundedError::Refused(Refusal::Work))
            ));
            assert_eq!(m.refused, Some((call, Refusal::Work)));
            assert_eq!(cursor.position(), index);
            assert_eq!((m.values, m.bytes), consumed);
            m.fail_at = None;
            m.refused = None;
        }
        m.limit_values = m.values + 3;
        m.limit_bytes = m.bytes + 64;
        match cursor.step(&mut m).unwrap() {
            BucketStep::Entry {
                index: actual,
                value,
            } => {
                assert_eq!(actual, index);
                found.push(*value);
            }
            BucketStep::Vacant { index: actual } => assert_eq!(actual, index),
            BucketStep::Complete => assert_eq!(index, buckets),
            BucketStep::Finished => panic!("early terminal state"),
        }
        assert_eq!(cursor.position(), (index + 1).min(buckets));
    }
    found.sort();
    assert_eq!(found, [0, 127, 255]);
    assert_eq!((m.values, m.bytes), (buckets as u64 + 1, buckets as u64));
    let calls = m.calls.len();
    assert_eq!(cursor.step(&mut m).unwrap(), BucketStep::Finished);
    assert_eq!(m.calls.len(), calls);
}

#[test]
fn all_ready_bucket_step_never_scans_past_one_control_byte() {
    let mut table = HashTable::with_capacity(8192);
    table.insert_unique(4096, 7u64, |value| *value);
    let mut cursor = BucketCursor::new(&table);
    let mut m = meter();
    let mut entries = 0;
    for index in 0..table.num_buckets() {
        let before = (m.values, m.bytes, m.calls.len());
        match cursor.step(&mut m).unwrap() {
            BucketStep::Entry {
                index: actual,
                value,
            } => {
                assert_eq!((actual, *value), (index, 7));
                entries += 1;
            }
            BucketStep::Vacant { index: actual } => assert_eq!(actual, index),
            _ => panic!("premature completion"),
        }
        assert_eq!(cursor.position(), index + 1);
        assert_eq!(
            (m.values, m.bytes, m.calls.len()),
            (before.0 + 1, before.1 + 1, before.2 + 1)
        );
    }
    assert_eq!(entries, 1);
    assert_eq!(cursor.step(&mut m).unwrap(), BucketStep::Complete);
}

#[test]
fn structured_keys_and_nested_schema_values_have_literal_canonical_order() {
    let mut table = HashTable::new();
    for (hash, key, value) in [
        (0, vec![24u64], vec![vec![3u64]]),
        (1, vec![1, 2], vec![vec![]]),
        (2, vec![1], vec![vec![1, 2]]),
    ] {
        table.insert_unique(hash, (key, value), |_| 0);
    }
    // Lexicographic encoded-key order: [1], [24], [1, 2].
    let expected = [
        0xa3, 0x81, 1, 0x81, 0x82, 1, 2, 0x81, 0x18, 24, 0x81, 0x81, 3, 0x82, 1, 2, 0x81, 0x80,
    ];
    let baseline = run(&table, None, false, Some(&expected));
    every_case(baseline.calls.len(), |stop| {
        let resumed = run(&table, Some(stop), false, Some(&expected));
        let mut trace = baseline.calls.clone();
        trace.insert(stop, trace[stop]);
        assert_eq!(resumed.calls, trace);
        assert_eq!(
            (resumed.values, resumed.bytes),
            (baseline.values, baseline.bytes)
        );
    });
}

#[test]
fn long_prefix_map_ordering_has_input_derived_n_log_n_work_bound() {
    const PREFIX: usize = 64;
    for count in [16usize, 32, 64, 128] {
        let mut table = HashTable::with_capacity(count);
        for suffix in (0..count).rev() {
            let key = format!("{}{:03}", "a".repeat(PREFIX), suffix);
            table.insert_unique(suffix as u64, (key, 0u64), |_| 0);
        }
        let mut m = meter();
        let mut operation = MapPreparation::new(&table);
        // A merge level compares at most n keys, each at most PREFIX+5 bytes.
        // Include descriptor copies, run transitions, and adjacent duplicate checks.
        let levels = count.ilog2() as usize;
        let ordering_bound = count * (levels + 1) * (PREFIX + 16);
        let total_bound = table.num_buckets() + count * (PREFIX + 16) * 64 + ordering_bound;
        let mut ordering_steps = 0;
        let mut output = None;
        for _ in 0..total_bound {
            if operation.position().dynamic.phase == dcbor::bounded::encoding::DynamicPhase::Order
                && operation.position().dynamic.ordering.width != 0
            {
                ordering_steps += 1;
            }
            let before = (m.values, m.bytes);
            m.limit_values = before.0 + 3;
            m.limit_bytes = before.1 + 64;
            let step = operation.step(&mut m).unwrap();
            assert!(m.values - before.0 <= 3 && m.bytes - before.1 <= 64);
            if let PrepareStep::Complete(plan) = step {
                output = Some(plan);
                break;
            }
        }
        assert!(
            ordering_steps <= ordering_bound,
            "{count}: {ordering_steps}"
        );
        let plan = output.expect("input-derived completion bound exceeded");
        let mut expected = if count < 24 {
            vec![0xa0 | count as u8]
        } else {
            vec![0xb8, count as u8]
        };
        for suffix in 0..count {
            expected.extend([0x78, (PREFIX + 3) as u8]);
            expected.extend([b'a'; PREFIX]);
            expected.extend(format!("{suffix:03}").bytes());
            expected.push(0);
        }
        let mut bytes = vec![0; plan.len()];
        let mut writer = plan.writer(&mut bytes);
        let mut complete = false;
        for _ in 0..expected.len() + 1 {
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
    }
}
