use super::harness::*;
use super::support::rigor::{Rigor, rigor};
use super::support::{
    Finding, Retirement, Stopped,
    pipeline::{Refusal, Unwitnessed},
    prepare_turns, refuse, shape,
};
use dcbor::bounded::{
    BoundedError, Family,
    encoding::{
        Instruction, Preparation, Schema,
        buckets::{BucketCursor, BucketPosition, BucketStep},
    },
};
use hashbrown::HashTable;

/// A large table whose one entry lies in its last bucket: every window of
/// vacant buckets before it is admitted, refused and resumed at its exact
/// position; the last window yields the entry; the enumeration then
/// completes, every control byte charged once.
#[test]
fn vacant_bucket_batches_retain_exact_positions_and_bound_total_steps() {
    // Multiple vacant windows and the final occupied window in both layers;
    // the million-entry capacity is the exhaustive scan-volume witness.
    let capacity = match rigor() {
        Rigor::Fast => 128,
        Rigor::Exhaustive => 1_000_000,
    };
    let mut table = HashTable::<(u64, u64)>::with_capacity(capacity);
    let buckets = table.num_buckets();
    assert!(buckets > 64, "the scan must cross a vacant window");
    let last = buckets as u64 - 1;
    // Hashed to itself: its home bucket is the last, free as it is inserted.
    table.insert_unique(last, (last, last), |pair| pair.0);
    assert_eq!(table.get_bucket(buckets - 1), Some(&(last, last)));
    let key = format!("buckets/{buckets}/refuse-resume");
    let mut budgets = budgets("vacant-buckets", &[&key]);
    budget_suite(&mut budgets, &key, POOL, |run, policy| {
        let owner = run.with_policy(policy, |m| m.owner().expect("the meter makes an owner"));
        run.holding(
            EnumerationCustody {
                enumeration: (BucketPosition::new(), None, None),
                owner,
            },
            Retirement::Released,
            &Unwitnessed,
            |enumeration| {
                enumeration.with_policy(policy, |enumeration, m| {
                    let owner = &enumeration.owner;
                    let (position, window, acquisition) = &mut enumeration.enumeration;
                    let mut cursor = BucketCursor::new(position, window, acquisition);
                    for start in (0..buckets).step_by(64) {
                        let call = m.attempts();
                        refuse(m, Refusal::For(call, LimitRefusal::Work));
                        assert!(matches!(
                            cursor.step(&table, owner, m),
                            Err(BoundedError::Refused(LimitRefusal::Work))
                        ));
                        assert_eq!(m.first_refusal(), Some((call, LimitRefusal::Work)));
                        assert_eq!(cursor.position(), start);
                        assert_eq!(cursor.held(), 0, "a refused window's credit was kept");
                        m.fail_call(None);
                        m.turn();
                        let outcome = cursor.step(&table, owner, m).map_err(|error| {
                            Finding::Driver(format!("the window at {start} failed: {error:?}"))
                        })?;
                        match outcome {
                            BucketStep::Entry { index, .. } => {
                                assert!(start + 64 >= buckets, "an entry before the last window");
                                assert_eq!(index, buckets - 1);
                            }
                            BucketStep::Vacant { index } => {
                                assert!(start + 64 < buckets, "the last window yielded no entry");
                                assert_eq!(index, start);
                            }
                            BucketStep::Complete | BucketStep::Finished => {
                                return Err(Finding::Driver(
                                    "the enumeration ended before its entry".to_owned(),
                                ));
                            }
                        }
                        assert_eq!(cursor.position(), (start + 64).min(buckets));
                    }
                    // Every control admitted once, one value per window.
                    assert_eq!(m.used().bytes, buckets as u64);
                    assert_eq!(m.used().values, buckets.div_ceil(64) as u64);
                    assert!(matches!(
                        cursor.step(&table, owner, m),
                        Ok(BucketStep::Complete)
                    ));
                    Ok(())
                })
            },
        )
    });
    budgets.finish();
}

#[test]
fn plain_data_truncation_is_constant_work_and_retains_the_allocation() {
    arena_case(|storage, m| {
        // A push into an arena of `len` elements takes at most a growth's units
        // (`Storage::grow_step`): staging, the grown allocation, publication, one
        // relocation per element, the settlement and the vacated block's
        // release; then the grant.
        for value in 0..1024u64 {
            let units = storage.len() + 6;
            let mut pushed = false;
            for _ in 0..units {
                if let Some(spare) = storage
                    .reserve_step(usize::MAX, m)
                    .map_err(failed("a growth unit"))?
                {
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
        refuse(m, Refusal::For(call, LimitRefusal::Work));
        assert!(matches!(
            storage.truncate_copy_step(1, m),
            Err(BoundedError::Refused(LimitRefusal::Work))
        ));
        assert_eq!(storage.len(), 1024);
        assert_eq!(m.live_bytes(), held);
        m.fail_call(None);
        m.clear_refusal();
        assert!(
            storage
                .truncate_copy_step(1, m)
                .map_err(failed("the truncation"))?
        );
        assert_eq!(
            storage.settled().map(|arena| arena.as_slice()),
            Some([0u64].as_slice())
        );
        assert_eq!(m.used().values, before.values + 1);
        assert_eq!(m.used().bytes, before.bytes);
        assert_eq!(m.live_bytes(), held);
        assert!(
            storage
                .truncate_copy_step(0, m)
                .map_err(failed("the empty truncation"))?
        );
        // The allocation's release was paid for by its growth: cleanup frees
        // it, then admits the transition that reports the arena released. An
        // arena of `len` elements cleans up in at most `len + 3` units
        // (`Storage::reclaim_step`): a staged growth's release, one drain per
        // element, the allocation's release, then the completing transition.
        let units = storage.len() + 3;
        let mut released = false;
        for _ in 0..units {
            if storage.reclaim_step(m).map_err(failed("a cleanup unit"))? {
                released = true;
                break;
            }
        }
        assert!(released, "cleanup exceeded its {units} units");
        assert_eq!(m.live_bytes(), 0);
        Ok(())
    });
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
                .map_or(Instruction::End, |(key, value)| {
                    Instruction::Entry(key, value)
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
        symbolic.insert(*key, value.clone()).unwrap();
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
    suite(|run, policy| {
        // Every preparation and emission turn's admission refused three
        // times before it runs, each refusal checked to change nothing, the
        // preparation, its plan and the plan's writer held by the run.
        run.holding(
            Preparation::new(&source),
            Retirement::Released,
            &Unwitnessed,
            |operation| {
                // The position each turn begins at: the preparation's before
                // its first turn, then each turn's after it. Refused attempts
                // move nothing, so these are exactly the positions the
                // schedule's turns start from; the last is the published
                // position, which begins no turn.
                let mut positions = vec![operation.value().position().dynamic];
                operation.repeated(
                    policy,
                    prepare_turns(walked),
                    Retirement::Released,
                    3,
                    |_, operation| positions.push(operation.position().dynamic),
                    |plan| {
                        let requests = plan.with_policy(policy, |_, m| {
                            let bound =
                                prepare_bound::<Reservation, Family, LimitRefusal>(walked).unwrap();
                            assert!(
                                bound.work().covers(&m.used()),
                                "{:?} beyond the preparation bound {bound:?}",
                                m.used()
                            );
                            m.assert_units(TURN);
                            assert!(m.live_bytes() > 0, "the plan holds its arena");
                            m.requests()
                        });
                        let mut bytes = vec![0xee; expected.len()];
                        plan.lending(
                            Retirement::Released,
                            |plan| plan.writer(&mut bytes),
                            |writer| {
                                writer.repeated(
                                    policy,
                                    emit_turns(expected.len()),
                                    Retirement::Released,
                                    3,
                                    |_, writer| {
                                        assert_eq!(
                                            writer.emitted_prefix(),
                                            &expected[..writer.emitted_prefix().len()]
                                        );
                                    },
                                    |_| (),
                                )?;
                                Ok::<_, Finding>(())
                            },
                        )?;
                        assert_eq!(bytes, expected);
                        plan.with_policy(policy, |_, m| {
                            assert_eq!(m.requests(), requests, "emission requested storage");
                        });
                        Ok::<_, Finding>(())
                    },
                )??;
                let (after, starts) = positions
                    .split_last()
                    .expect("the initial position is read");
                let (mut compacted, mut moves, mut bitmap) = (false, 0usize, 0usize);
                for before in starts {
                    // The root's gap precedes every key, so active compaction
                    // reads from a nonzero source.
                    compacted |= before.compact_source != 0;
                    if before.permutation.phase == PermutationPhase::Move {
                        moves += 1;
                    }
                    bitmap = bitmap.max(before.permutation.bitmap_bytes);
                }
                assert!(moves > 0, "published before the payload was permuted");
                assert_eq!(after.permutation.phase, PermutationPhase::Offsets);
                assert_eq!(after.permutation.bitmap_bytes, 0, "the bitmap outlived it");
                assert_eq!(after.phase, DynamicPhase::Order);
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
                Ok::<_, Finding>(())
            },
        )?;
        run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0));
        Ok(())
    });
}

impl Schema for Entries {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        if index == 0 {
            return Instruction::UnorderedMap;
        }
        self.0
            .get(index - 1)
            .map_or(Instruction::End, |(k, v)| Instruction::Entry(k, v))
    }
}

#[test]
fn duplicate_is_rejected_during_the_first_merge_not_after_sorting() {
    let mut entries = vec![(0, 1), (0, 2)];
    entries.extend((1..32).map(|key| (key, 0)));
    let source = Entries(entries);
    suite(|run, policy| {
        run.holding(
            Preparation::new(&source),
            Retirement::Released,
            &Unwitnessed,
            |operation| {
                let result = operation.drive(
                    policy,
                    prepare_turns(shape(&source)),
                    Retirement::Released,
                    |_| (),
                );
                assert!(matches!(
                    result,
                    Err(Stopped::Operation(BoundedError::DuplicateKey))
                ));
                // The rejection is found at the first merge, before the run
                // grows past its first width.
                assert_eq!(operation.value().position().dynamic.ordering.width, 1);
                assert_eq!(operation.value().position().dynamic.ordering.run, 0);
                operation.finish(policy, prepare_turns(shape(&source)), Retirement::Released)
            },
        )?;
        run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0));
        Ok(())
    });
}

#[test]
fn merge_scratch_never_contains_more_than_the_shorter_run() {
    for count in [3usize, 5, 9, 17, 33, 64] {
        let source = Entries((0..count as u64).rev().map(|n| (n, 0)).collect());
        suite(|run, policy| {
            run.holding(
                Preparation::new(&source),
                Retirement::Released,
                &Unwitnessed,
                |operation| {
                    operation
                        .controlled(
                            policy,
                            prepare_turns(shape(&source)),
                            Retirement::Released,
                            true,
                            |_, operation, _| {
                                let p = operation.position().dynamic.ordering;
                                if p.width > 0 && p.run < count {
                                    let left = p.width.min(count - p.run);
                                    let right = p.width.min(count - p.run - left);
                                    assert!(p.scratch <= left.min(right));
                                }
                                false
                            },
                            |_| (),
                        )?
                        .expect("the merge controller never stops");
                    Ok::<_, Finding>(())
                },
            )?;
            run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0));
            Ok(())
        });
    }
}

struct Nested(Box<dyn Schema>, bool);
impl Schema for Nested {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        match index {
            0 => Instruction::UnorderedMap,
            1 => Instruction::Entry(if self.1 { &1u64 } else { &0u64 }, self.0.as_ref()),
            2 if self.1 => Instruction::Entry(&0u64, &0u64),
            _ => Instruction::End,
        }
    }
}

#[test]
fn nested_payload_work_is_bounded_by_bytes_times_dynamic_depth() {
    // Fast covers ordered/reordered maps, single/nested ancestors and both
    // payload head widths. Exhaustive retains the depth and volume stress.
    let (depths, lengths): (&[usize], &[usize]) = match rigor() {
        Rigor::Fast => (&[1, 8], &[64, 256]),
        Rigor::Exhaustive => (&[1, 8, 32], &[64, 256, 4096]),
    };
    let key =
        |reordered, depth, length| format!("reordered/{reordered}/depth/{depth}/bytes/{length}");
    let keys: Vec<String> = [false, true]
        .into_iter()
        .flat_map(|reordered| {
            depths.iter().flat_map(move |&depth| {
                lengths
                    .iter()
                    .map(move |&length| key(reordered, depth, length))
            })
        })
        .collect();
    let mut budgets = budgets(
        "nested-payload",
        &keys.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    for reordered in [false, true] {
        for &depth in depths {
            for &length in lengths {
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
                budget_suite(
                    &mut budgets,
                    &key(reordered, depth, length),
                    POOL,
                    |run, policy| {
                        let mut moves = 0;
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
                        run.holding(Preparation::new(source.as_ref()), Retirement::Released, &Unwitnessed, |operation| {
                        operation.controlled(policy, turns, Retirement::Released, true, |_, operation, _| {
                        if operation.position().dynamic.permutation.phase
                            == dcbor::bounded::encoding::PermutationPhase::Move
                        {
                            moves += 1;
                        }
                        assert!(operation.position().dynamic.scratch <= wire_length.div_ceil(8));
                        if !reordered {
                            assert_eq!(
                                operation.position().dynamic.scratch,
                                0,
                                "already ordered single-entry maps must not allocate payload scratch"
                            );
                        }
                            false
                        }, |plan| {
                            plan.with_policy(policy, |_, m| {
                                assert!(
                                    m.used().bytes <= byte_bound as u64,
                                    "depth {depth}, length {length}: {}",
                                    m.used().bytes
                                );
                            });
                            emit_held(plan, policy, policy, &expected, super::support::Fault::NONE)
                        })?.expect("the payload controller never stops")?;
                        Ok::<_, Finding>(())
                    })?;
                        assert!(
                            moves <= wire_length * depth,
                            "a byte moved more than once per dynamic ancestor"
                        );
                        run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0));
                        Ok(())
                    },
                );
            }
        }
    }
    budgets.finish();
}
