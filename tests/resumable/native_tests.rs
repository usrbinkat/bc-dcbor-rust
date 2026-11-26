use super::bindings::{decoder, text_encoder};
use super::harness::*;
use super::support::{self, Fault, Finding, Retirement, pipeline::Unwitnessed, recorded_run};
use dcbor::bounded::decode::{DecodeError, Kind, decode, decode_typed};
use dcbor::bounded::{BoundedError, WriteWork, encode};

const ARRAY: &[u8] = &[
    0x83, 0x63, b'a', b'b', b'c', 0x63, b'1', b'2', b'3', 0x65, b'h', b'e', b'l', b'l', b'o',
];

#[test]
fn boundary_schedules_preserve_literal_child_order_and_exact_consumption() {
    synchronous_case(
        |m| decode(ARRAY, 8, m),
        |result, m| {
            let doc = result.unwrap();
            assert_eq!(doc.root().kind(), Kind::Array(3));
            let children: Vec<_> = doc.root().children().map(|n| n.kind()).collect();
            assert_eq!(
                children,
                [Kind::Text("abc"), Kind::Text("123"), Kind::Text("hello")]
            );
            assert_eq!(doc.root().encoded(), ARRAY);
            assert!(m.live_bytes() > 0);
        },
    );
    for end in 0..ARRAY.len() {
        synchronous_case(
            |m| decode(&ARRAY[..end], 8, m),
            |result, _| {
                assert!(matches!(result, Err(DecodeError::Invalid(_))));
            },
        );
    }
    let mut trailing = ARRAY.to_vec();
    trailing.push(0);
    synchronous_case(
        |m| decode(&trailing, 8, m),
        |result, _| {
            assert!(matches!(result, Err(DecodeError::Invalid(_))));
        },
    );
}

#[test]
fn every_actual_admission_refusal_is_observed_and_stops_execution() {
    let baseline = synchronous_case(
        |m| decode(ARRAY, 8, m),
        |result, m| {
            assert_eq!(result.unwrap().root().encoded(), ARRAY);
            m.calls()
        },
    );
    // Synchronous decode stops at the first refusal; identical allowance
    // makes the exact attempted prefix its contract, with no resumption.
    support::synchronous_matrix("literal array decode", baseline.len(), |index| {
        let reason = match baseline[index] {
            Call::Work { .. } => LimitRefusal::Work,
            Call::Allocate(_) => LimitRefusal::Storage,
        };
        synchronous_case(
            |m| {
                support::refuse(m, support::pipeline::Refusal::For(index, reason));
                decode(ARRAY, 8, m)
            },
            |result, m| {
                assert!(
                    matches!(result, Err(DecodeError::Resource(BoundedError::Refused(r))) if r == reason)
                );
                assert_eq!(m.first_refusal(), Some((index, reason)));
                assert_eq!(m.calls(), &baseline[..=index]);
                m.reached()
            },
        )
    });
}

#[test]
fn decoder_continuation_retains_completed_arena_on_work_refusal() {
    suite(|run, policy| {
        run.holding(
            decoder(ARRAY),
            Retirement::Released,
            &Unwitnessed,
            |operation| {
                let reached = operation.controlled(
                    policy,
                    decode_turns(ARRAY.len()),
                    Retirement::Released,
                    true,
                    |_, operation, _| operation.position().completed_children == 1,
                    |_| (),
                )?;
                assert!(reached.is_none(), "the first child never completed");
                let position = operation.value().position();
                let held = operation.with_policy(policy, |_, m| m.live_bytes());
                assert!(held > 0);
                operation.refused(policy, 3, Retirement::Released)?;
                assert_eq!(operation.value().position(), position);
                operation.with_policy(policy, |_, m| assert_eq!(m.live_bytes(), held));
                operation.drive(
                    policy,
                    decode_turns(ARRAY.len()),
                    Retirement::Released,
                    |document| {
                        assert_eq!(document.value().root().encoded(), ARRAY);
                    },
                )?;
                Ok::<_, Finding>(())
            },
        )?;
        run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0));
        Ok(())
    });
}

#[test]
fn decoder_payload_operations_fit_three_value_sixty_four_byte_quantum() {
    let wire = text_wire(&"x".repeat(65536));
    let mut budgets = budgets("payload-decode", &["text/65536/quantum"]);
    budget_suite(&mut budgets, "text/65536/quantum", POOL, |run, policy| {
        run.holding(
            decoder(&wire),
            Retirement::Released,
            &Unwitnessed,
            |operation| {
                operation.drive(
                    policy,
                    decode_turns(wire.len()),
                    Retirement::Released,
                    |doc| {
                        doc.with_policy(policy, |doc, m| {
                            assert_eq!(doc.root().encoded(), wire);
                            m.assert_units(TURN);
                        });
                    },
                )
            },
        )?;
        run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0));
        Ok(())
    });
    budgets.finish();
}

#[test]
fn canonical_key_comparison_and_arena_growth_have_bounded_units() {
    let a = "a".repeat(4096);
    let b = format!("{}b", "a".repeat(4095));
    let mut wire = vec![0xa2];
    wire.extend(text_wire(&a));
    wire.push(0);
    wire.extend(text_wire(&b));
    wire.push(1);
    retained_case(
        decoder(&wire),
        decode_turns(wire.len()),
        Fault::NONE,
        |doc, m| {
            assert_eq!(doc.root().kind(), Kind::Map(2));
            assert_eq!(doc.root().encoded(), wire);
            m.assert_units(TURN);
        },
    );
}

#[test]
fn text_semantics_use_literal_composition_reordering_and_hangul_oracles() {
    let fixtures: &[(&str, &[u8])] = &[
        ("a\u{301}", &[0x62, 0xc3, 0xa1]),
        ("\u{301}a", &[0x63, 0xcc, 0x81, b'a']),
        ("\u{1e0b}\u{323}", &[0x65, 0xe1, 0xb8, 0x8d, 0xcc, 0x87]),
        (
            "a\u{300}\u{305}\u{315}\u{5ae}b",
            &[0x69, 0xc3, 0xa0, 0xd6, 0xae, 0xcc, 0x85, 0xcc, 0x95, b'b'],
        ),
        ("\u{1100}\u{1162}", &[0x63, 0xea, 0xb0, 0x9c]),
        ("\u{1111}\u{1171}\u{11b6}", &[0x63, 0xed, 0x93, 0x9b]),
    ];
    for &(source, expected) in fixtures {
        let baseline = synchronous_case(
            |m| encode(&source, m),
            |result, m| {
                let encoded = result.unwrap();
                assert_eq!(encoded.as_ref(), expected);
                m.calls()
            },
        );
        let canonical = std::str::from_utf8(&expected[1..]).unwrap();
        synchronous_case(
            |m| decode(expected, 8, m),
            |result, _| {
                let doc = result.unwrap();
                assert_eq!(doc.root().kind(), Kind::Text(canonical));
            },
        );
        if source != canonical {
            let wire = text_wire(source);
            synchronous_case(
                |m| decode(&wire, 8, m),
                |result, _| assert!(result.is_err()),
            );
        }
        support::synchronous_matrix(
            &format!("literal text encode of {source:?}"),
            baseline.len(),
            |index| {
                let reason = match baseline[index] {
                    Call::Work { .. } => LimitRefusal::Work,
                    Call::Allocate(_) => LimitRefusal::Storage,
                };
                synchronous_case(
                    |m| {
                        support::refuse(m, support::pipeline::Refusal::For(index, reason));
                        encode(&source, m)
                    },
                    |result, m| {
                        assert!(matches!(result, Err(BoundedError::Refused(r)) if r == reason));
                        assert_eq!(m.first_refusal(), Some((index, reason)));
                        m.reached()
                    },
                )
            },
        );
    }
}

#[test]
fn long_normalization_has_bounded_preparation_and_emission_units() {
    let input = format!("q{}", "\u{301}\u{316}".repeat(4096));
    let normal = format!("q{}{}", "\u{316}".repeat(4096), "\u{301}".repeat(4096));
    let mut budgets = budgets("normalization", &["alternating-marks/4096/quantum"]);
    budget_suite(
        &mut budgets,
        "alternating-marks/4096/quantum",
        POOL,
        |run, policy| {
            run.holding(
                text_encoder(&input),
                Retirement::Released,
                &Unwitnessed,
                |operation| {
                    operation.drive(
                        policy,
                        normalize_turns(&input),
                        Retirement::Released,
                        |output| {
                            output.with_policy(policy, |output, m| {
                                assert_eq!(output.as_ref(), text_wire(&normal));
                                m.assert_units(TURN);
                            });
                        },
                    )
                },
            )?;
            run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0));
            Ok(())
        },
    );
    budgets.finish();
}

#[test]
fn typed_output_owns_capacity_after_parser_scratch_release() {
    let text = "\u{1f600}\u{e9}".repeat(1024);
    let wire = text_wire(&text);
    recorded_run(|run| {
        let decoding = run.policy(POOL);
        let value = run
            .with_policy(decoding, |m| decode_typed::<String, _>(&wire, m))
            .map_err(failed("typed output decode"))?;
        run.holding(value, Retirement::LastReference, &Unwitnessed, |value| {
            value.with_policy(decoding, |value, m| {
                assert_eq!(value.value(), &text);
                assert!(m.live_bytes() >= text.len() as u64);
                assert!(m.peak_bytes() >= m.live_bytes());
            });
            // The decoding policy takes no further part and the input is gone:
            // the value alone holds what remains.
            drop(wire);
            assert_eq!(value.value().value(), &text);
            assert!(value.with_policy(decoding, |_, m| m.live_bytes()) >= text.len() as u64);
        });
        assert_eq!(run.with_policy(decoding, |m| m.live_bytes()), 0);
        Ok(())
    });
}

#[test]
fn typed_field_copies_have_bounded_units() {
    use dcbor::bounded::decode::construction::DecodeOwner;
    let text = "\u{1f600}\u{e9}".repeat(1024);
    let wire = text_wire(&text);
    suite(|run, policy| {
        run.holding(
            DecodeOwner::new(),
            Retirement::Scope,
            &Unwitnessed,
            |owner| {
                owner.initialize(policy)?;
                owner
                    .decoded::<String, _>(policy, &wire, |value| {
                        value.with_policy(policy, |value, m| {
                            assert_eq!(value.value(), &text);
                            m.assert_units(TURN);
                        });
                    })?
                    .map_err(failed("typed field decode"))?;
                owner.drain(policy)
            },
        )?;
        run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0));
        Ok(())
    });
}

#[test]
fn shared_pool_thousand_real_decodes_restore_exact_capacity() {
    use support::rigor::{Rigor, rigor};
    // The pool: four elements of eight mebibytes of one tenant.
    const EIGHTH: usize = 8 * 1024 * 1024;
    // Eight workers start together at a barrier, each holding every value it
    // decodes until all have joined. Two decodes per worker reach both of a
    // worker's classes, its first decode and one after a value it holds; the
    // exhaustive layer's 125 per worker, a thousand decodes, stress the same
    // classes.
    let per_worker = match rigor() {
        Rigor::Fast => 2,
        Rigor::Exhaustive => 125,
    };
    let key = format!("workers/8/decodes/{per_worker}");
    let mut budgets = budgets("shared-pool", &[&key]);
    budget_suite(&mut budgets, &key, 4 * EIGHTH as u64, |run, policy| {
        let barrier = std::sync::Barrier::new(8);
        let workers: Vec<_> = (0..8).map(|_| run.shared_policy(policy)).collect();
        run.workers(
            &workers,
            per_worker,
            Retirement::LastReference,
            |_| support::CustodyBatch::with_capacity(per_worker),
            |_, fixture, held, m| {
                if fixture == 0 {
                    barrier.wait();
                }
                let result = decode_typed::<Vec<String>, _>(ARRAY, m)
                    .map_err(failed("worker typed decode"))?;
                let value = held.retain(result);
                assert_eq!(value.value(), &["abc", "123", "hello"]);
                Ok(())
            },
        )?;
        run.with_policy(policy, |pool| assert_eq!(pool.live_bytes(), 0));
        let owner = run.with_policy(policy, |pool| pool.owner().expect("a recorded owner"));
        let all = run.with_policy(policy, |pool| occupy::<EIGHTH>(pool, &owner));
        run.holding(all, Retirement::Released, &Unwitnessed, |all| {
            all.with_policy(policy, |_, pool| refuses_more(pool, &owner));
        });
        drop(owner);
        run.with_policy(policy, |pool| assert_eq!(pool.live_bytes(), 0));
        Ok(())
    });
    budgets.finish();
}

#[test]
fn real_capacity_exhaustion_is_distinct_from_work_and_invalid_input() {
    suite_with(4096, |run, policy| {
        // Another tenant holding the pool's whole 4096 bytes.
        let owner = run.with_policy(policy, |pool| pool.owner().expect("a recorded owner"));
        let held = run.with_policy(policy, |pool| occupy::<1024>(pool, &owner));
        let decoding = run.shared_policy(policy);
        run.holding(held, Retirement::Released, &Unwitnessed, |held| {
            let result = held.with_policy(decoding, |_, m| decode(ARRAY, 8, m));
            match result {
                Err(DecodeError::Resource(BoundedError::Refused(LimitRefusal::Storage))) => {}
                Ok(document) => held.holding(document, Retirement::Released, |_| {
                    panic!("a full pool published a document");
                }),
                Err(error) => panic!("a full pool returned {error:?}"),
            }
            held.with_policy(policy, |_, pool| assert_eq!(pool.live_bytes(), 4096));
        });
        drop(owner);
        run.with_policy(policy, |pool| assert_eq!(pool.live_bytes(), 0));
        let decoding = run.shared_policy_within(
            policy,
            dcbor::bounded::Ceilings {
                work: WriteWork::new(0, u64::MAX),
                ..dcbor::bounded::Ceilings::UNLIMITED
            },
        );
        let result = run.with_policy(decoding, |m| decode(ARRAY, 8, m));
        match result {
            Err(DecodeError::Resource(BoundedError::Refused(LimitRefusal::Work))) => {}
            Ok(document) => run.holding(document, Retirement::Released, &Unwitnessed, |_| {
                panic!("zero work allowance published a document");
            }),
            Err(error) => panic!("zero work allowance returned {error:?}"),
        }
        run.with_policy(decoding, |m| assert_eq!(m.used().values, 0));
        run.with_policy(policy, |pool| assert_eq!(pool.live_bytes(), 0));
        Ok(())
    });
}
