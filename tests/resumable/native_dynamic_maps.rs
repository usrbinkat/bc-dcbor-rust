use super::harness::*;
use super::support::{checked, contracted, prepare_turns, repeated_refusal, shape};
use dcbor::bounded::{
    BoundedError, Step, WriteWork,
    encoding::{
        buckets::{BucketCursor, BucketStep},
        maps::MapPreparation,
    },
};
use hashbrown::HashTable;

#[test]
fn hash_map_normalized_duplicates_reject_across_every_refusal() {
    let mut map = hashbrown::HashMap::new();
    map.insert("e\u{301}".to_string(), 1u64);
    map.insert("\u{e9}".to_string(), 2u64);
    prepare_matrix(&map, Err(BoundedError::DuplicateKey));
}

/// One bucket per step, every control byte up to the last entry accounted
/// for, repeated refusals leaving the position unchanged; the cursor
/// completes after the last entry, scanning no bucket after it.
#[test]
fn sparse_bucket_steps_account_for_every_control_byte_and_repeated_refusal() {
    let mut table = HashTable::with_capacity(8192);
    for n in [0u64, 2000, 6000] {
        table.insert_unique(n, n, |n| *n);
    }
    assert!(
        table.num_buckets() > 6001,
        "buckets lie after the last entry"
    );
    let mut cursor = BucketCursor::new(&table);
    let mut m = meter();
    let mut found = Vec::new();
    for index in 0..=6000 {
        assert_eq!(cursor.position(), index);
        repeated_refusal("sparse bucket scan", &mut m, index, 3, |m| {
            let result = cursor.step(m).map(|_| ());
            (cursor.position(), result)
        });
        m.fresh();
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
    assert_eq!(m.used().bytes, 6001);
    assert_eq!(cursor.step(&mut m).unwrap(), BucketStep::Complete);
    assert_eq!(cursor.position(), 6001, "no bucket after the last entry");
    assert_eq!(cursor.step(&mut m).unwrap(), BucketStep::Finished);
    assert_eq!(m.used().values, 6001 + 1);
    assert!(m.calls().iter().all(|c| !matches!(c, Call::Allocate(_))));
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
    prepare_matrix(&table, Ok(&expected));
}

#[test]
fn normalized_duplicate_keys_reject_after_observed_suspension() {
    let mut table = HashTable::new();
    table.insert_unique(0, ("e\u{301}".to_string(), 1), |(_, v)| *v);
    table.insert_unique(1, ("\u{e9}".to_string(), 2), |(_, v)| *v);
    prepare_matrix(&table, Err(BoundedError::DuplicateKey));
}

#[test]
fn physical_map_preparation_failures_release_flat_arenas_and_reservations() {
    let mut table = HashTable::with_capacity(32);
    for i in 0..16u64 {
        table.insert_unique(i, (format!("{i:02}e\u{301}"), i), |(_, v)| *v);
    }
    prepare_physical_matrix(&table);
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
    // Within the preparation bound of the table's own shape; the repeated
    // refusals below fall inside one turn and take none of their own.
    let turns = prepare_turns(shape(&table));
    let mut operation = MapPreparation::new(&table);
    let mut m = meter();
    let mut interrupted = false;
    let mut output = None;
    for _ in 0..turns {
        let position = operation.position();
        if !interrupted && position.dynamic.ordering.compared == 64 {
            repeated_refusal("long key at comparison byte 64", &mut m, position, 3, |m| {
                let result = contracted(m, &mut operation).map(|_| ());
                (operation.position(), result)
            });
            interrupted = true;
        }
        match checked(&mut m, |m| contracted(m, &mut operation)) {
            Ok(Step::Complete(plan)) => {
                output = Some(plan);
                break;
            }
            Ok(Step::Progress) => {}
            Err(error) if super::support::ordinary_exhaustion(&m, &error) => {}
            other => panic!("comparison failed: {}", super::support::label(&other)),
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
    emit(&plan, &expected, &mut m);
    drop(plan);
    assert_eq!(m.live_bytes(), 0);
}

#[test]
fn empty_dynamic_map_has_one_canonical_header() {
    let table = HashTable::<(String, u64)>::new();
    prepare_matrix(&table, Ok(&[0xa0]));
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
    // The last entry, 255, lies in bucket 255: the cursor completes at the
    // next step, before the buckets after it.
    let last = 255;
    assert_eq!(table.get_bucket(last), Some(&255));
    assert!(buckets > last + 1, "buckets lie after the last entry");
    let mut cursor = BucketCursor::new(&table);
    let mut m = meter();
    let mut found = Vec::new();
    for index in 0..=last + 1 {
        repeated_refusal("deletion-sparse bucket scan", &mut m, index, 3, |m| {
            let result = cursor.step(m).map(|_| ());
            (cursor.position(), result)
        });
        m.fresh();
        match cursor.step(&mut m).unwrap() {
            BucketStep::Entry {
                index: actual,
                value,
            } => {
                assert_eq!(actual, index);
                found.push(*value);
            }
            BucketStep::Vacant { index: actual } => assert_eq!(actual, index),
            BucketStep::Complete => assert_eq!(index, last + 1),
            BucketStep::Finished => panic!("early terminal state"),
        }
        assert_eq!(cursor.position(), (index + 1).min(last + 1));
    }
    found.sort();
    assert_eq!(found, [0, 127, 255]);
    let scanned = last as u64 + 1;
    assert_eq!(m.used(), WriteWork::new(scanned + 1, scanned));
    let calls = m.calls().len();
    assert_eq!(cursor.step(&mut m).unwrap(), BucketStep::Finished);
    assert_eq!(m.calls().len(), calls);
}

#[test]
fn all_ready_bucket_step_never_scans_past_one_control_byte() {
    let mut table = HashTable::with_capacity(8192);
    table.insert_unique(4096, 7u64, |value| *value);
    assert_eq!(table.get_bucket(4096), Some(&7));
    let mut cursor = BucketCursor::new(&table);
    let mut m = meter();
    let mut entries = 0;
    for index in 0..=4096 {
        let before = (m.used(), m.calls().len());
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
            (m.used(), m.calls().len()),
            (
                WriteWork::new(before.0.values + 1, before.0.bytes + 1),
                before.1 + 1
            )
        );
    }
    assert_eq!(entries, 1);
    assert_eq!(cursor.step(&mut m).unwrap(), BucketStep::Complete);
    assert_eq!(cursor.position(), 4097, "no bucket after the entry");
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
    prepare_matrix(&table, Ok(&expected));
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
            match checked(&mut m, |m| contracted(m, &mut operation)) {
                Ok(Step::Complete(plan)) => {
                    output = Some(plan);
                    break;
                }
                Ok(Step::Progress) => {}
                Err(error) if super::support::ordinary_exhaustion(&m, &error) => {}
                other => panic!("ordering failed: {}", super::support::label(&other)),
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
        emit(&plan, &expected, &mut m);
        drop(operation);
        drop(plan);
        assert_eq!(m.live_bytes(), 0);
    }
}
