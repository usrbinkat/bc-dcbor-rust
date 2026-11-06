use super::harness::*;
use super::support::{checked, contracted, prepare_turns, repeated_refusal, shape};
use dcbor::bounded::{
    BoundedError, Step, WriteWork,
    encoding::{
        BUCKET_WINDOW,
        buckets::{BucketCursor, BucketStep, Buckets},
        maps::MapPreparation,
    },
};
use hashbrown::HashTable;

/// `table` enumerated to completion by the engine's one bucket traversal,
/// each call first refused `refusals` times and resumed from exactly where
/// it was, its window's credit included. Every call is checked against the
/// charge rule: one value, and a whole window of controls (the table's last
/// window shorter) exactly when the credit held before it was spent; no
/// control inspected that was not admitted; a vacant call reporting where it
/// began, an entry the bucket it stopped at; the completion one value and no
/// control, its credit forfeited. Returns the entries found with their
/// buckets, in bucket order, the calls made, the completion included, and
/// the completed cursor.
fn enumerate(
    table: &HashTable<(u64, u64)>,
    refusals: usize,
    m: &mut Limits,
) -> (Vec<(usize, u64)>, u64, BucketCursor) {
    let source: &dyn Buckets = table;
    let buckets = table.num_buckets();
    let mut cursor = BucketCursor::new();
    let mut found = Vec::new();
    let mut admitted = 0usize;
    // At most one call per window and one per entry, then the completion.
    for calls in 1..=buckets.div_ceil(BUCKET_WINDOW) + table.len() + 1 {
        if refusals > 0 {
            let position = cursor;
            repeated_refusal("bucket enumeration", m, position, refusals, |m| {
                let result = cursor.step(source, m).map(|_| ());
                (cursor, result)
            });
        }
        m.fresh();
        let (before, used) = (cursor, m.used());
        let step = cursor.step(source, m).unwrap();
        let charged = WriteWork::new(m.used().values - used.values, m.used().bytes - used.bytes);
        if let BucketStep::Complete = step {
            assert_eq!(
                charged,
                WriteWork::new(1, 0),
                "the completion inspected a control"
            );
            assert_eq!(cursor.position(), before.position(), "the completion moved");
            assert_eq!(cursor.held(), 0, "the completion kept its credit");
            assert_eq!(found.len(), table.len(), "completed before every entry");
            assert_eq!(m.used().bytes, admitted as u64);
            return (found, calls as u64, cursor);
        }
        let window = if before.held() == 0 {
            BUCKET_WINDOW.min(buckets - before.position())
        } else {
            0
        };
        assert_eq!(
            charged,
            WriteWork::new(1, window as u64),
            "a call at {} holding {} admitted the wrong controls",
            before.position(),
            before.held()
        );
        admitted += window;
        assert!(
            cursor.position() > before.position()
                && cursor.position() <= before.position() + before.held() + window,
            "a call at {} inspected controls its credit did not cover",
            before.position()
        );
        assert!(
            cursor.position() <= admitted,
            "a control inspected unadmitted"
        );
        match step {
            BucketStep::Vacant { index } => assert_eq!(index, before.position()),
            BucketStep::Entry { index, .. } => {
                assert_eq!(
                    index,
                    cursor.position() - 1,
                    "the entry is not where it stopped"
                );
                let (_, value) = table
                    .get_bucket(index)
                    .expect("an entry's bucket is occupied");
                found.push((index, *value));
            }
            BucketStep::Complete | BucketStep::Finished => {
                unreachable!("the completion returned above; nothing finished before it")
            }
        }
    }
    panic!("the enumeration exceeded a call per window and per entry");
}

#[test]
fn hash_map_normalized_duplicates_reject_across_every_refusal() {
    let mut map = hashbrown::HashMap::new();
    map.insert("e\u{301}".to_string(), 1u64);
    map.insert("\u{e9}".to_string(), 2u64);
    prepare_matrix(&map, Err(BoundedError::DuplicateKey));
}

/// A sparse table enumerated with every call refused three times first: each
/// window of controls up to the last entry's admitted once and none after
/// it, every refusal leaving the cursor and its credit unchanged; the
/// entries found at their buckets; nothing allocated; the finished cursor
/// admitting nothing.
#[test]
fn sparse_bucket_windows_account_for_every_control_byte_and_repeated_refusal() {
    let mut table = HashTable::with_capacity(8192);
    for key in [0u64, 2000, 6000] {
        table.insert_unique(key, (key, key), |pair| pair.0);
    }
    assert!(
        table.num_buckets() > 6001,
        "buckets lie after the last entry"
    );
    let mut m = meter();
    let (found, calls, mut cursor) = enumerate(&table, 3, &mut m);
    assert_eq!(found, [(0, 0), (2000, 2000), (6000, 6000)]);
    // The windows up to the last entry's: each admitted whole once.
    let windows = 6000 / BUCKET_WINDOW + 1;
    assert_eq!(m.used().bytes, (windows * BUCKET_WINDOW) as u64);
    // A call per window, one more for each entry ending its window early
    // but the last, whose window the completion forfeits, and the completion.
    assert_eq!(calls, (windows + 2 + 1) as u64);
    assert_eq!(m.used().values, calls);
    assert!(m.calls().iter().all(|c| !matches!(c, Call::Allocate(_))));
    let attempts = m.attempts();
    assert!(matches!(
        cursor.step(&table as &dyn Buckets, &mut m),
        Ok(BucketStep::Finished)
    ));
    assert_eq!(m.attempts(), attempts, "a finished cursor admitted");
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

/// A table whose removals leave three entries among deleted and vacant
/// buckets, enumerated with every call, the completion included, refused
/// three times first: each refusal leaves the cursor and its credit
/// unchanged; the three entries are found at their buckets; every window up
/// to the last entry's admitted once, none after it; the completion
/// forfeits the rest of that window; the finished cursor admits nothing.
#[test]
fn deletion_sparse_cursor_refuses_at_every_call_and_terminal_transition() {
    let mut table = HashTable::with_capacity(256);
    for key in 0..256u64 {
        table.insert_unique(key, (key, key), |pair| pair.0);
    }
    let buckets = table.num_buckets();
    for index in 0..buckets {
        if let Ok(entry) = table.get_bucket_entry(index)
            && ![0, 127, 255].contains(&entry.get().0)
        {
            entry.remove();
        }
    }
    assert_eq!(table.num_buckets(), buckets);
    assert_eq!(table.len(), 3);
    // The last entry, 255, lies in bucket 255, short of the table's end.
    let last = 255;
    assert_eq!(table.get_bucket(last), Some(&(255, 255)));
    assert!(buckets > last + 1, "buckets lie after the last entry");
    let mut m = meter();
    let (found, calls, mut cursor) = enumerate(&table, 3, &mut m);
    assert_eq!(found, [(0, 0), (127, 127), (255, 255)]);
    assert_eq!(cursor.position(), last + 1, "a bucket after the last entry");
    let windows = last / BUCKET_WINDOW + 1;
    assert_eq!(
        m.used(),
        WriteWork::new(calls, (windows * BUCKET_WINDOW) as u64)
    );
    let attempts = m.attempts();
    assert!(matches!(
        cursor.step(&table as &dyn Buckets, &mut m),
        Ok(BucketStep::Finished)
    ));
    assert_eq!(m.attempts(), attempts, "a finished cursor admitted");
}

/// One entry deep in a large table: every call admits at most one window
/// and inspects nothing its credit does not cover, a call within a window
/// admitting no control again; the entry ends its window's enumeration and
/// the completion follows at once, no bucket after the entry inspected.
#[test]
fn a_call_inspects_only_controls_its_window_admitted() {
    let mut table = HashTable::with_capacity(8192);
    table.insert_unique(4096, (4096u64, 7u64), |pair| pair.0);
    assert_eq!(table.get_bucket(4096), Some(&(4096, 7)));
    let mut m = meter();
    let (found, calls, cursor) = enumerate(&table, 0, &mut m);
    assert_eq!(found, [(4096, 7)]);
    assert_eq!(cursor.position(), 4097, "a bucket after the entry");
    // The entry opens its window: one call per window through it, then the
    // completion.
    let windows = 4096 / BUCKET_WINDOW + 1;
    assert_eq!(calls, windows as u64 + 1);
    assert_eq!(
        m.used(),
        WriteWork::new(calls, (windows * BUCKET_WINDOW) as u64)
    );
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
