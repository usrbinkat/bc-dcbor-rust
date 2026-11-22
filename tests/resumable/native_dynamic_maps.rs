use super::harness::*;
use super::support::{
    Finding, Retirement, pipeline::Unwitnessed, prepare_turns, repeated_refusal, shape,
};
use dcbor::bounded::{
    BoundedError, Family, Owner, WriteWork,
    encoding::{
        BUCKET_WINDOW,
        buckets::{BucketCursor, BucketPosition, BucketStep, Buckets},
        maps::MapPreparation,
    },
};
use hashbrown::HashTable;

fn enumerated_case(
    table: &HashTable<(u64, u64)>,
    refusals: usize,
    inspect: impl FnOnce(Vec<(usize, u64)>, u64, &mut Enumeration, &Owner, &mut Limits),
) {
    suite(|run, policy| {
        let owner = run.with_policy(policy, |m| m.owner().expect("the meter makes an owner"));
        run.holding(
            EnumerationCustody {
                enumeration: (BucketPosition::new(), None, None),
                owner,
            },
            Retirement::Released,
            &Unwitnessed,
            |held| {
                held.with_policy(policy, |held, m| {
                    let (found, calls) =
                        enumerate(table, refusals, m, &mut held.enumeration, &held.owner)?;
                    inspect(found, calls, &mut held.enumeration, &held.owner, m);
                    Ok::<_, Finding>(())
                })
            },
        )
    });
}

/// A cursor over `enumeration`'s three parts.
fn cursor(enumeration: &mut Enumeration) -> BucketCursor<'_, Family> {
    BucketCursor::new(&mut enumeration.0, &mut enumeration.1, &mut enumeration.2)
}

/// What a refusal must leave unchanged: the position, the controls the
/// window holds and the credit it holds. The first refused admission may
/// bind an acquisition; subsequent retries must retain that identity.
fn snapshot(enumeration: &mut Enumeration) -> (BucketPosition, usize, Option<WriteWork>) {
    let position = enumeration.0;
    let cursor = cursor(enumeration);
    (position, cursor.held(), cursor.held_credit())
}

/// One call of the enumeration under `m`, the window's acquisitions owned
/// by `owner`.
fn step<'t>(
    enumeration: &mut Enumeration,
    source: &'t dyn Buckets,
    owner: &Owner,
    m: &mut Limits,
) -> Result<BucketStep<'t>, BoundedError<dcbor::bounded::LimitRefusal>> {
    cursor(enumeration).step(source, owner, m)
}

/// The next index the enumeration inspects.
fn index(enumeration: &mut Enumeration) -> usize {
    cursor(enumeration).position()
}

/// The controls the enumeration's window holds.
fn held(enumeration: &mut Enumeration) -> usize {
    cursor(enumeration).held()
}

/// `table` enumerated to completion by the engine's one bucket traversal,
/// each call first refused `refusals` times and resumed from exactly where
/// it was, its window's credit included. Every call is checked against the
/// charge rule: one value, and a whole window of controls (the table's last
/// window shorter) exactly when the credit held before it was spent; no
/// control inspected that was not admitted; a vacant call reporting where it
/// began, an entry the bucket it stopped at; the completion one value and no
/// control, its credit forfeited. Returns the entries found with their
/// buckets, in bucket order, the calls made, the completion included, the
/// completed enumeration and the owner of its windows; or an unexpected step
/// outcome, or the calls spent without completion, as the run's finding.
fn enumerate(
    table: &HashTable<(u64, u64)>,
    refusals: usize,
    m: &mut Limits,
    enumeration: &mut Enumeration,
    owner: &Owner,
) -> Result<(Vec<(usize, u64)>, u64), Finding> {
    let source: &dyn Buckets = table;
    let buckets = table.num_buckets();
    let mut found = Vec::new();
    let mut admitted = 0usize;
    // At most one call per window and one per entry, then the completion.
    for calls in 1..=buckets.div_ceil(BUCKET_WINDOW) + table.len() + 1 {
        if refusals > 0 {
            let progress = repeated_refusal(m, enumeration, refusals, calls, |m, enumeration| {
                let before = snapshot(enumeration);
                let binding = cursor(enumeration).bound();
                let result =
                    step(enumeration, source, owner, m).map(dcbor::bounded::Step::Complete);
                let after_binding = cursor(enumeration).bound();
                if let Some(binding) = binding {
                    assert_eq!(
                        after_binding,
                        Some(binding),
                        "a refused retry replaced its acquisition"
                    );
                } else if found.len() < table.len() {
                    assert!(
                        after_binding.is_some(),
                        "a refused window lost its acquisition"
                    );
                }
                (before, snapshot(enumeration), (result, None))
            })
            // A bucket step borrows the enumeration and owns no custody: the
            // stop is rendered by reference, nothing published to retire.
            .map_err(|stop| Finding::from(&stop))?;
            if progress.is_some() {
                return Err(Finding::Driver(
                    "bucket enumeration made release progress without an admission".to_owned(),
                ));
            }
        }
        m.fresh();
        let (at, holding, used) = (index(enumeration), held(enumeration), m.used());
        let outcome = step(enumeration, source, owner, m).map_err(|error| {
            Finding::Driver(format!("the enumeration's call {calls} failed: {error:?}"))
        })?;
        let charged = WriteWork::new(m.used().values - used.values, m.used().bytes - used.bytes);
        let position = index(enumeration);
        if let BucketStep::Complete = outcome {
            assert_eq!(
                charged,
                WriteWork::new(1, 0),
                "the completion inspected a control"
            );
            assert_eq!(position, at, "the completion moved");
            assert_eq!(held(enumeration), 0, "the completion kept its credit");
            assert_eq!(found.len(), table.len(), "completed before every entry");
            assert_eq!(m.used().bytes, admitted as u64);
            return Ok((found, calls as u64));
        }
        let window = if holding == 0 {
            BUCKET_WINDOW.min(buckets - at)
        } else {
            0
        };
        assert_eq!(
            charged,
            WriteWork::new(1, window as u64),
            "a call at {at} holding {holding} admitted the wrong controls"
        );
        admitted += window;
        assert!(
            position > at && position <= at + holding + window,
            "a call at {at} inspected controls its credit did not cover"
        );
        assert!(position <= admitted, "a control inspected unadmitted");
        match outcome {
            BucketStep::Vacant { index } => assert_eq!(index, at),
            BucketStep::Entry { index, .. } => {
                assert_eq!(index, position - 1, "the entry is not where it stopped");
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
    Err(Finding::Driver(
        "the enumeration exceeded a call per window and per entry".to_owned(),
    ))
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
    enumerated_case(&table, 3, |found, calls, enumeration, owner, m| {
        assert_eq!(found, [(0, 0), (2000, 2000), (6000, 6000)]);
        // The windows up to the last entry's: each admitted whole once.
        let windows = 6000 / BUCKET_WINDOW + 1;
        assert_eq!(m.used().bytes, (windows * BUCKET_WINDOW) as u64);
        // A call per window, one more for each entry ending its window
        // early but the last, whose window the completion forfeits, and the
        // completion.
        assert_eq!(calls, (windows + 2 + 1) as u64);
        assert_eq!(m.used().values, calls);
        assert!(m.calls().iter().all(|c| !matches!(c, Call::Allocate(_))));
        let attempts = m.attempts();
        assert!(matches!(
            step(enumeration, &table as &dyn Buckets, owner, m),
            Ok(BucketStep::Finished)
        ));
        assert_eq!(m.attempts(), attempts, "a finished cursor admitted");
    });
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

/// The permutation that moves a dynamic map's entries into canonical order,
/// over four entries of unequal lengths on either side of a bitmap byte and
/// a 64-byte initialization boundary, in every order the table may hold
/// them: entry `k` of canonical rank `k` (its key the integer `k`) is placed
/// in bucket `j` where `order[j] == k` (the identity hash), its value a byte
/// string of `lengths[k]` bytes. Each table is prepared through the refusal
/// matrix ([`prepare_matrix`]): every refused run is a recorded run of its
/// own whose admitted calls equal the unrefused baseline's, nothing
/// replayed, its stream and checkpoints refined by the shared runner, and
/// its plan the canonical encoding. The public recorded lifecycle witness of
/// the permutation; the crate's own test keeps the byte-movement oracle over
/// the permutation alone. The fast layer takes the identity order and its
/// reverse; the exhaustive one every order.
#[test]
fn the_permutation_moves_unequal_entries_in_every_order_without_replay() {
    use super::support::rigor::{Rigor, rigor};
    let orders: Vec<[usize; 4]> = match rigor() {
        Rigor::Fast => vec![[0, 1, 2, 3], [3, 2, 1, 0]],
        Rigor::Exhaustive => {
            let mut orders = Vec::new();
            for a in 0..4 {
                for b in 0..4 {
                    for c in 0..4 {
                        for d in 0..4 {
                            let order = [a, b, c, d];
                            if (0..4).all(|i| !order[..i].contains(&order[i])) {
                                orders.push(order);
                            }
                        }
                    }
                }
            }
            orders
        }
    };
    let value = |rank: usize, length: usize| -> Vec<u8> {
        (0..length)
            .map(|offset| (offset * 17 + rank * 31) as u8)
            .collect()
    };
    for lengths in [[1usize, 2, 3, 5], [1, 7, 65, 513]] {
        let mut expected = vec![0xa4];
        for (rank, &length) in lengths.iter().enumerate() {
            expected.push(rank as u8);
            match length {
                0..24 => expected.push(0x40 | length as u8),
                24..256 => expected.extend([0x58, length as u8]),
                _ => expected.extend([0x59, (length >> 8) as u8, length as u8]),
            }
            expected.extend(value(rank, length));
        }
        for order in &orders {
            // Each rank's bucket: the identity hash every insertion and any
            // rehash agree on.
            let mut bucket_of = [0u64; 4];
            for (bucket, &rank) in order.iter().enumerate() {
                bucket_of[rank] = bucket as u64;
            }
            let mut table = HashTable::with_capacity(order.len());
            for &rank in order {
                table.insert_unique(
                    bucket_of[rank],
                    (
                        rank as u64,
                        dcbor::ByteString::from(value(rank, lengths[rank])),
                    ),
                    |(key, _): &(u64, dcbor::ByteString)| bucket_of[*key as usize],
                );
            }
            let held: Vec<u64> = (0..order.len())
                .map(|bucket| table.get_bucket(bucket).map_or(u64::MAX, |entry| entry.0))
                .collect();
            assert_eq!(
                held,
                (*order).map(|rank| rank as u64),
                "lengths {lengths:?}, order {order:?}: an entry is not in its bucket"
            );
            prepare_matrix_named(
                &format!("permutation lengths {lengths:?}, bucket order {order:?}"),
                &table,
                Ok(&expected),
                shape(&table),
            );
        }
    }
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
    suite(|run, policy| {
        let mut expected = vec![0xa2];
        for (last, value) in [(b'b', 1), (b'c', 2)] {
            expected.extend([0x79, 1, 1]);
            expected.extend([b'a'; 256]);
            expected.extend([last, value]);
        }
        run.holding(
            MapPreparation::new(&table),
            Retirement::Released,
            &Unwitnessed,
            |operation| {
                let published = operation.controlled(
                    policy,
                    turns,
                    Retirement::Released,
                    true,
                    |_, operation, _| operation.position().dynamic.ordering.compared == 64,
                    |_| (),
                )?;
                assert!(published.is_none(), "comparison byte 64 was not reached");
                let position = operation.value().position();
                operation.refused(policy, 3, Retirement::Released)?;
                assert_eq!(operation.value().position(), position);
                operation
                    .drive_faulted(
                        policy,
                        turns,
                        Retirement::Released,
                        super::support::Fault::NONE,
                        |_, _| {},
                        |plan| {
                            emit_held(plan, policy, policy, &expected, super::support::Fault::NONE)
                        },
                    )?
                    .transpose()?;
                Ok::<_, Finding>(())
            },
        )?;
        run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0));
        Ok(())
    });
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
    enumerated_case(&table, 3, |found, calls, enumeration, owner, m| {
        assert_eq!(found, [(0, 0), (127, 127), (255, 255)]);
        assert_eq!(
            index(enumeration),
            last + 1,
            "a bucket after the last entry"
        );
        let windows = last / BUCKET_WINDOW + 1;
        assert_eq!(
            m.used(),
            WriteWork::new(calls, (windows * BUCKET_WINDOW) as u64)
        );
        let attempts = m.attempts();
        assert!(matches!(
            step(enumeration, &table as &dyn Buckets, owner, m),
            Ok(BucketStep::Finished)
        ));
        assert_eq!(m.attempts(), attempts, "a finished cursor admitted");
    });
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
    enumerated_case(&table, 0, |found, calls, enumeration, _, m| {
        assert_eq!(found, [(4096, 7)]);
        assert_eq!(index(enumeration), 4097, "a bucket after the entry");
        // The entry opens its window: one call per window through it, then
        // the completion.
        let windows = 4096 / BUCKET_WINDOW + 1;
        assert_eq!(calls, windows as u64 + 1);
        assert_eq!(
            m.used(),
            WriteWork::new(calls, (windows * BUCKET_WINDOW) as u64)
        );
    });
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
        suite(|run, policy| {
            // A merge level compares at most n keys, each at most PREFIX+5 bytes.
            // Include descriptor copies, run transitions, and adjacent duplicate checks.
            let levels = count.ilog2() as usize;
            let ordering_bound = count * (levels + 1) * (PREFIX + 16);
            let total_bound = table.num_buckets() + count * (PREFIX + 16) * 64 + ordering_bound;
            let mut ordering_steps = 0;
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
            run.holding(
                MapPreparation::new(&table),
                Retirement::Released,
                &Unwitnessed,
                |operation| {
                    operation
                        .controlled(
                            policy,
                            total_bound,
                            Retirement::Released,
                            true,
                            |_, operation, _| {
                                let position = operation.position();
                                if position.dynamic.phase
                                    == dcbor::bounded::encoding::DynamicPhase::Order
                                    && position.dynamic.ordering.width != 0
                                {
                                    ordering_steps += 1;
                                }
                                false
                            },
                            |plan| {
                                emit_held(
                                    plan,
                                    policy,
                                    policy,
                                    &expected,
                                    super::support::Fault::NONE,
                                )
                            },
                        )?
                        .expect("the controller never stops")?;
                    Ok::<_, Finding>(())
                },
            )?;
            assert!(
                ordering_steps <= ordering_bound,
                "{count}: {ordering_steps}"
            );
            run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0));
            Ok(())
        });
    }
}
