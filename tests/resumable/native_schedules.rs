use super::bindings::{decoder, string_decoder};
use super::harness::*;
use super::support::{
    self, Fault, Finding, RefusalRun, Retirement, Stopped,
    pipeline::{Refusal, Unwitnessed},
    recorded_run, refusal_matrix,
    rigor::rigor,
};
use dcbor::bounded::decode::{DecodeError, Options};
use dcbor::bounded::{BoundedError, Custodial, Step};

#[test]
fn header_and_first_payload_admissions_are_separately_observed() {
    use dcbor::bounded::decode::cursor::Phase;
    let mut wire = vec![0x78, 0x18];
    wire.extend_from_slice(b"abcdefghijklmnopqrstuvwx");
    let baseline = retained_case(
        decoder(&wire),
        decode_turns(wire.len()),
        Fault::NONE,
        |document, _| assert_eq!(document.root().encoded(), wire),
    );
    for (phase, header, payload) in [
        (Phase::Header, 0, 0),
        (Phase::Header, 1, 0),
        (Phase::Interpret, 2, 0),
        (Phase::Utf8, 2, 1),
        (Phase::Utf8, 2, 23),
        (Phase::Complete, 2, 24),
    ] {
        suite(|run, policy| {
            run.holding(
                decoder(&wire),
                Retirement::Released,
                &Unwitnessed,
                |operation| {
                    let published = operation.controlled(
                        policy,
                        decode_turns(wire.len()),
                        Retirement::Released,
                        true,
                        |_, operation, _| {
                            let position = operation.position();
                            (
                                position.phase,
                                position.header_bytes,
                                position.payload_validated,
                            ) == (phase, header, payload)
                        },
                        |_| (),
                    )?;
                    assert!(
                        published.is_none(),
                        "missing boundary {phase:?}/{header}/{payload}"
                    );
                    let stop = operation.with_policy(policy, |_, m| m.attempts());
                    operation.drive_faulted(
                        policy,
                        decode_turns(wire.len()),
                        Retirement::Released,
                        Fault {
                            refusal: Refusal::For(stop, LimitRefusal::Work),
                            cancel: false,
                        },
                        |_, _| {},
                        |document| {
                            document.with_policy(policy, |document, m| {
                                RefusalRun::of(m).resumed(&baseline, stop, LimitRefusal::Work);
                                m.assert_units(TURN);
                                assert_eq!(
                                    document.root().kind(),
                                    dcbor::bounded::decode::Kind::Text("abcdefghijklmnopqrstuvwx")
                                );
                                assert!(m.live_bytes() > 0);
                                assert_eq!(document.root().encoded(), wire);
                            })
                        },
                    )?;
                    Ok::<_, Finding>(())
                },
            )?;
            run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0));
            Ok(())
        });
    }
}

#[test]
fn constructor_failure_at_every_callback_never_touches_parser_storage() {
    use dcbor::bounded::decode::construction::{Construction, DecodeOwner, DocumentDecoder};
    let wire = text_wire("q\u{301}\u{1f600}");
    // Each run parses its own document under `parser`, then constructs from
    // it under its own policy. Construction owns the document: through every
    // step, refusal and cancellation the parser's storage is untouched, and
    // the scope's drain releases both policies' storage completely. The
    // construction's calls are what the matrix compares.
    refusal_matrix(
        "construction from a parsed document",
        rigor(),
        |fault: Fault| {
            recorded_run(|run| {
                let parsing = run.policy(POOL);
                let constructing = run.policy(POOL);
                let parser = run.with_policy(parsing, |m| m.share());
                let construction_calls = run.holding(
                    DecodeOwner::new(),
                    Retirement::Scope,
                    &Unwitnessed,
                    |owner| {
                        owner.initialize(parsing)?;
                        let copying = owner.value().copy_input(&wire);
                        owner.holding(copying, Retirement::Stopped, |copying| {
                            copying.drive_then(
                                parsing,
                                support::turns(
                                    dcbor::bounded::decode::construction::copy_bound::<Limits, ()>(
                                        wire.len() as u64,
                                    )
                                    .expect("copy bound fits"),
                                ),
                                Retirement::Published,
                                |input| DocumentDecoder::parse(input, Options::normalizing(8)),
                                Retirement::Stopped,
                                |parsing_operation| {
                                    parsing_operation.drive_then(
                                        parsing,
                                        support::turns(
                                            dcbor::bounded::decode::construction::parse_bound::<
                                                dcbor::ByteString,
                                                Limits,
                                                (),
                                            >(
                                                wire.len() as u64, Options::normalizing(8)
                                            )
                                            .expect("parse bound fits"),
                                        ),
                                        Retirement::Published,
                                        Construction::<_, String, Limits>::construct,
                                        Retirement::Stopped,
                                        |operation| {
                                            let parser_live = parser.live_bytes();
                                            operation.drive_faulted(
                                                constructing,
                                                typed_turns::<String>(wire.len()),
                                                Retirement::Published,
                                                fault,
                                                |_, _| assert_eq!(parser.live_bytes(), parser_live),
                                                |value| {
                                                    value.with_policy(constructing, |value, m| {
                                                        assert_eq!(
                                                            value.value(),
                                                            "q\u{301}\u{1f600}"
                                                        );
                                                        assert!(
                                                            m.live_bytes()
                                                                >= value.value().len() as u64
                                                        );
                                                    })
                                                },
                                            )?;
                                            assert_eq!(parser.live_bytes(), parser_live);
                                            Ok::<_, Finding>(())
                                        },
                                    )?
                                },
                            )?
                        })?;
                        let calls = owner.with_policy(constructing, |_, m| RefusalRun::of(m));
                        owner.drain(constructing)?;
                        assert_eq!(parser.live_bytes(), 0);
                        owner.with_policy(constructing, |_, m| assert_eq!(m.live_bytes(), 0));
                        Ok::<_, Finding>(calls)
                    },
                )?;
                Ok(construction_calls)
            })
        },
    );
}

/// A text of one scalar decodes under the quick-only policy exactly when the
/// upstream quick check proves it normal, the oracle asserted for each
/// scalar decoded ([`unicode_normalization::is_nfc_quick`]); then texts of
/// several scalars across their boundaries. For one scalar the decode
/// depends on the quick check's answer for it and on its UTF-8 width, so
/// the scalars fall into runs of equal (answer, width), read for every
/// scalar without decoding any. The fast layer decodes the first and last
/// scalar of every run, every place either changes, the surrogate gap's
/// edges among them; the exhaustive layer decodes every scalar
/// ([`support::rigor`]).
#[test]
fn quick_only_matches_upstream_for_all_scalars_and_cross_character_cases() {
    use dcbor::bounded::decode::cursor::Decoder;
    use support::rigor::Rigor;
    use unicode_normalization::{IsNormalized, is_nfc_quick};
    fn check(text: &str) {
        let wire = text_wire(text);
        suite(|run, policy| {
            run.holding(
                Decoder::new(&wire, Options::quick_only(8)),
                Retirement::Released,
                &Unwitnessed,
                |operation| {
                    match operation.drive(
                        policy,
                        decode_turns(wire.len()),
                        Retirement::Released,
                        |document| {
                            assert_eq!(is_nfc_quick(text.chars()), IsNormalized::Yes, "{text:?}");
                            assert_eq!(document.value().root().encoded(), wire);
                        },
                    ) {
                        Ok(()) => {}
                        Err(Stopped::Operation(DecodeError::UnprovenText)) => {
                            assert_ne!(is_nfc_quick(text.chars()), IsNormalized::Yes, "{text:?}");
                        }
                        Err(stop) => return Err(Finding::from(stop)),
                    }
                    Ok::<_, Finding>(())
                },
            )?;
            run.with_policy(policy, |m| {
                m.assert_units(TURN);
                assert_eq!(m.live_bytes(), 0);
            });
            Ok(())
        });
    }
    let scalars: Vec<char> = (0..=0x10ffff).filter_map(char::from_u32).collect();
    let class = |ch: char| (is_nfc_quick(core::iter::once(ch)), ch.len_utf8());
    let selected: Vec<char> = match rigor() {
        Rigor::Exhaustive => scalars.clone(),
        // The first and last scalar of each run of one class.
        Rigor::Fast => scalars
            .iter()
            .enumerate()
            .filter(|&(at, &ch)| {
                let before = at.checked_sub(1).map(|at| scalars[at]);
                let after = scalars.get(at + 1).copied();
                before.is_none_or(|before| class(before) != class(ch))
                    || after.is_none_or(|after| class(after) != class(ch))
            })
            .map(|(_, &ch)| ch)
            .collect(),
    };
    let mut progress = support::rigor::Progress::new("quick-only scalars");
    progress.stage("scalars decoded", selected.len(), scalars.len());
    for ch in selected {
        check(&ch.to_string());
    }
    for text in [
        "",
        "q\u{301}a",
        "q\u{301}\u{316}",
        "\u{301}a",
        "a\u{301}",
        "\u{1100}\u{1162}",
        "\u{e9}\u{1f600}",
    ] {
        check(text);
    }
}

/// Every refusal of a prepared text's emission, resumed or cancelled: the
/// literal prefix, the guards intact and the plan's storage held. Each run
/// prepares its plan under a family of its own and emits it under another,
/// so the run holds every custody it makes.
#[test]
fn writer_refusals_preserve_literal_prefix_guards_and_plan_ownership() {
    use dcbor::bounded::text_cursor::pipeline::TextPreparation;
    let source = "a\u{301}";
    let expected = [0x62, 0xc3, 0xa1];
    refusal_matrix("text writer", rigor(), |fault: Fault| {
        recorded_run(|run| {
            let preparing = run.policy(POOL);
            let writing = run.policy(POOL);
            run.holding(
                TextPreparation::new(source),
                Retirement::Released,
                &Unwitnessed,
                |preparation| {
                    preparation.drive(
                        preparing,
                        normalize_turns(source),
                        Retirement::Released,
                        |prepared| {
                            let live = prepared.with_policy(preparing, |_, m| m.live_bytes());
                            let mut guarded = [0xee; 5];
                            let emitted = prepared.lending(
                                Retirement::Released,
                                |prepared| prepared.writer(&mut guarded[1..4]),
                                |emission| {
                                    emission.drive_faulted(
                                        writing,
                                        text_emit_turns(expected.len()),
                                        Retirement::Released,
                                        fault,
                                        |_, _| {},
                                        |output| {
                                            output.with_policy(writing, |_, m| m.assert_units(TURN))
                                        },
                                    )
                                },
                            )?;
                            // The writer's borrow of `guarded` has ended; it has no destructor.
                            assert_eq!((guarded[0], guarded[4]), (0xee, 0xee));
                            if emitted.is_some() {
                                assert_eq!(guarded[1..4], expected);
                            }
                            let written = guarded[1..4].iter().take_while(|b| **b != 0xee).count();
                            assert_eq!(&guarded[1..1 + written], &expected[..written]);
                            assert!(guarded[1 + written..4].iter().all(|b| *b == 0xee));
                            assert_eq!(
                                prepared.with_policy(preparing, |_, preparation| preparation
                                    .live_bytes()),
                                live
                            );
                            Ok::<_, Finding>(())
                        },
                    )?
                },
            )?;
            assert_eq!(
                run.with_policy(preparing, |preparation| preparation.live_bytes()),
                0
            );
            Ok(run.with_policy(writing, |m| RefusalRun::of(m)))
        })
    });
}

#[test]
fn emission_is_bounded_independently_of_preparation() {
    use dcbor::bounded::text_cursor::pipeline::TextPreparation;
    let source = "x".repeat(65536);
    let mut budgets = budgets("emission", &["text/65536/prepare-emit"]);
    budgets.run("text/65536/prepare-emit", |run| {
        let preparing = run.policy(POOL);
        let emitting = run.policy(POOL);
        run.holding(
            TextPreparation::new(&source),
            Retirement::Released,
            &Unwitnessed,
            |preparation| {
                preparation.drive(
                    preparing,
                    normalize_turns(&source),
                    Retirement::Released,
                    |prepared| {
                        let mut bytes = vec![0; prepared.value().len() as usize];
                        let turns = text_emit_turns(bytes.len());
                        prepared.lending(
                            Retirement::Released,
                            |prepared| prepared.writer(&mut bytes),
                            |emission| {
                                emission.drive(emitting, turns, Retirement::Released, |output| {
                                    output.with_policy(emitting, |_, m| {
                                        assert_eq!(
                                            m.requests(),
                                            0,
                                            "emission requested allocation"
                                        );
                                        m.assert_units(TURN);
                                    });
                                })
                            },
                        )?;
                        assert_eq!(bytes, text_wire(&source));
                        Ok::<_, Finding>(())
                    },
                )?
            },
        )?;
        Ok(())
    });
    budgets.finish();
}

#[test]
fn capacity_pool_survives_concurrent_success_and_every_refused_constructor() {
    // The pool: four elements of eight mebibytes of one tenant.
    const EIGHTH: usize = 8 * 1024 * 1024;
    let wire = text_wire("q\u{301}\u{1f600}");
    let mut budgets = budgets("concurrent-constructors", &["workers/8/refusals/1000"]);
    budgets.run("workers/8/refusals/1000", |run| {
        let unobstructed = run.policy(POOL);
        run.holding(
            string_decoder(&wire),
            Retirement::Released,
            &Unwitnessed,
            |decoder| {
                decoder.drive(
                    unobstructed,
                    string_turns(wire.len()),
                    Retirement::Released,
                    |output| {
                        assert_eq!(output.value().value(), "q\u{301}\u{1f600}");
                    },
                )
            },
        )?;
        let baseline = run.with_policy(unobstructed, |baseline| RefusalRun::of(baseline));
        let boundaries = baseline.calls().len();
        assert!(boundaries > 0);
        // In rounds, every call refused once and as many decodes unrefused,
        // about a thousand decodes in all; the cases are dealt to the
        // workers in turn.
        const WORKERS: usize = 8;
        const DECODES: usize = 1000;
        let rounds = DECODES.div_ceil(2 * boundaries);
        let cases: Vec<Option<usize>> = (0..rounds)
            .flat_map(|_| (0..boundaries).flat_map(|stop| [Some(stop), None]))
            .collect();
        concurrent_string_decodes::<EIGHTH>(
            run,
            WORKERS,
            &wire,
            &cases,
            "q\u{301}\u{1f600}",
            |m, stop| {
                if let Some(stop) = stop {
                    RefusalRun::of(m).resumed(&baseline, stop, LimitRefusal::Work);
                }
            },
        )
    });
    budgets.finish();
}

#[test]
fn storage_refusal_holds_a_retained_decode_until_another_thread_releases_capacity() {
    use dcbor::ByteString;
    let payload = vec![0x5a; 65536];
    let wire = dcbor::CBOR::to_byte_string(&payload).to_cbor_data();
    let turns = typed_turns::<ByteString>(wire.len());
    // The admissions of an unobstructed decode of the same input, and the
    // most it held at once: its scope, its copied input and its output.
    let (baseline, peak) = suite(|run, policy| {
        let trace = run.holding(
            dcbor::bounded::decode::construction::DecodeOwner::new(),
            Retirement::Scope,
            &Unwitnessed,
            |owner| {
                owner.initialize(policy)?;
                let trace = owner.decoder::<_, ByteString, _, _>(
                    policy,
                    support::Copying(&wire),
                    Options::normalizing(8),
                    &Unwitnessed,
                    |operation| {
                        operation.with_policy(policy, |_, m| m.measure());
                        operation.drive(policy, turns, Retirement::Published, |value| {
                            assert_eq!(value.value().value().data(), &payload[..]);
                            value.with_policy(policy, |_, m| m.admitted_calls())
                        })
                    },
                )??;
                owner.drain(policy)?;
                Ok::<_, Finding>(trace)
            },
        )?;
        Ok((trace, run.with_policy(policy, |m| m.peak_bytes())))
    });
    // The bytes the decode holds after its first step, probed.
    let held = suite(|run, policy| {
        run.holding(
            dcbor::bounded::decode::construction::DecodeOwner::new(),
            Retirement::Scope,
            &Unwitnessed,
            |owner| {
                owner.initialize(policy)?;
                let held = owner.decoder::<_, ByteString, _, _>(
                    policy,
                    support::Copying(&wire),
                    Options::normalizing(8),
                    &Unwitnessed,
                    |operation| {
                        operation.with_policy(policy, |_, m| m.measure());
                        let published = operation.controlled(
                            policy,
                            turns,
                            Retirement::Published,
                            true,
                            |_, _, at| at == 1,
                            |_| (),
                        )?;
                        assert!(published.is_none(), "the first decode turn published");
                        Ok::<_, Finding>(operation.with_policy(policy, |_, m| m.live_bytes()))
                    },
                )??;
                owner.drain(policy)?;
                Ok::<_, Finding>(held)
            },
        )
    });
    // The pool: what the first step holds, and another tenant beside it,
    // taken in one acquisition, of 128 KiB: at least what the rest of the
    // decode needs beyond the first step (its 64 KiB output and its
    // records), so the tenant's release is what lets the same decode finish.
    // The unobstructed decode's peak establishes it; a pool short of the
    // decode's peak could never complete it, whatever is released.
    const QUARTER: usize = 32 * 1024;
    let tenant = 4 * QUARTER as u64;
    let capacity = held + tenant;
    assert!(
        capacity >= peak,
        "the pool of {capacity} bytes cannot hold the decode's peak of {peak}: the tenant's \
         release would not let it finish"
    );
    let options = Options::normalizing(8);
    suite_with(capacity, |run, pool| {
        // The decode's policy: a share of the pool, its own trace over the
        // pool's storage.
        let decoding = run.shared_policy(pool);
        let other = run.with_policy(pool, |pool| pool.owner().expect("a recorded owner"));
        run.holding(
            dcbor::bounded::decode::construction::DecodeOwner::new(),
            Retirement::Scope,
            &Unwitnessed,
            |owner| {
                owner.initialize(decoding)?;
                owner.decoder::<_, ByteString, _, _>(
                    decoding,
                    support::Copying(&wire),
                    options,
                    &Unwitnessed,
                    |operation| {
                        operation.with_policy(decoding, |_, m| m.measure());
                        operation.transfer(
                            |decode| Blocked {
                                decode,
                                tenant: None,
                            },
                            Retirement::Stopped,
                            |blocked| {
                                let first = blocked.controlled(
                                    decoding,
                                    turns,
                                    Retirement::Published,
                                    true,
                                    |_, _, at| at == 1,
                                    |_| (),
                                )?;
                                assert!(first.is_none(), "the first decode turn published");
                                blocked.with_policy(pool, |_, pool| {
                                    assert_eq!(pool.live_bytes(), held)
                                });
                                // Another owner takes every remaining byte of
                                // the shared capacity.
                                blocked.with_policy(pool, |blocked, pool| {
                                    blocked.tenant = Some(occupy::<QUARTER>(pool, &other));
                                });
                                let storage_refused = |stop| match stop {
                                    Err(Stopped::Operation(DecodeError::Resource(
                                        BoundedError::Refused(LimitRefusal::Storage),
                                    ))) => Ok(()),
                                    Err(stop) => Err(Finding::from(stop)),
                                    Ok(_) => Err(Finding::Driver(
                                        "no allocation met the exhausted capacity".to_owned(),
                                    )),
                                };
                                let blocked_at = blocked.controlled(
                                    decoding,
                                    turns,
                                    Retirement::Published,
                                    true,
                                    |_, _, _| false,
                                    |_| (),
                                );
                                storage_refused(blocked_at)?;
                                let position =
                                    dcbor::bounded::Resumable::<Limits>::position(blocked.value());
                                let live = blocked.with_policy(pool, |_, pool| pool.live_bytes());
                                assert_eq!(live, capacity);
                                // While the capacity stays held the same
                                // operation is refused at the same unit, and
                                // nothing it holds is released, replayed or
                                // moved: its position, the pool's live bytes
                                // and its grouped custody, owner by owner, are
                                // those of the first refusal.
                                let custody = support::collect(|sink| {
                                    blocked.value().decode.observe_custody(sink)
                                })
                                .expect("the blocked decode's custody is an observation");
                                for _ in 0..3 {
                                    let retried = blocked.controlled(
                                        decoding,
                                        turns,
                                        Retirement::Published,
                                        true,
                                        |_, _, _| false,
                                        |_| (),
                                    );
                                    storage_refused(retried)?;
                                    assert_eq!(
                                        dcbor::bounded::Resumable::<Limits>::position(
                                            blocked.value()
                                        ),
                                        position
                                    );
                                    blocked.with_policy(pool, |_, pool| {
                                        assert_eq!(pool.live_bytes(), live);
                                    });
                                    assert_eq!(
                                        support::collect(|sink| {
                                            blocked.value().decode.observe_custody(sink)
                                        })
                                        .expect("the blocked decode's custody is an observation"),
                                        custody,
                                        "a refused retry moved the blocked decode's custody"
                                    );
                                }
                                // The parent retains custody while the worker
                                // borrows it, joins, then observes its retirement.
                                let tenant =
                                    blocked.value().tenant.take().expect("the tenant is held");
                                blocked.holding(tenant, Retirement::Released, |tenant| {
                                    std::thread::scope(|threads| {
                                        let tenant = tenant.value();
                                        threads
                                            .spawn(move || {
                                                std::hint::black_box(tenant);
                                            })
                                            .join()
                                            .expect("the tenant worker completes");
                                    });
                                });
                                blocked.drive(decoding, turns, Retirement::Published, |value| {
                                    assert_eq!(value.value().value().data(), &payload[..]);
                                    value.with_policy(decoding, |_, m| {
                                        assert_eq!(
                                            m.admitted_calls(),
                                            baseline,
                                            "resumption replayed admitted work"
                                        );
                                    });
                                })?;
                                Ok::<_, Finding>(())
                            },
                        )
                    },
                )??;
                owner.drain(decoding)
            },
        )?;
        run.with_policy(pool, |pool| assert_eq!(pool.live_bytes(), 0));
        // The whole capacity is reacquired exactly, through the same
        // acquisitions, and one byte more is refused.
        run.holding(
            dcbor::bounded::decode::construction::DecodeOwner::new(),
            Retirement::Scope,
            &Unwitnessed,
            |owner| {
                owner.initialize(decoding)?;
                owner.decoder::<_, ByteString, _, _>(
                    decoding,
                    support::Copying(&wire),
                    options,
                    &Unwitnessed,
                    |operation| {
                        let first = operation.controlled(
                            decoding,
                            turns,
                            Retirement::Published,
                            true,
                            |_, _, at| at == 1,
                            |_| (),
                        )?;
                        assert!(first.is_none(), "the first decode turn published");
                        let all =
                            operation.with_policy(pool, |_, pool| occupy::<QUARTER>(pool, &other));
                        operation.holding(all, Retirement::Released, |all| {
                            all.with_policy(pool, |_, pool| {
                                assert_eq!(pool.live_bytes(), capacity);
                                refuses_more(pool, &other);
                            });
                        });
                        Ok::<_, Finding>(())
                    },
                )??;
                owner.drain(decoding)
            },
        )?;
        run.with_policy(pool, |pool| assert_eq!(pool.live_bytes(), 0));
        Ok(())
    });
}

/// The storage-refused decode with the tenant that exhausts its pool, one
/// custody while both are held: the decode stepped as itself, the tenant
/// borrowed by another thread and retired by the parent while the decode stays held.
struct Blocked<D> {
    decode: D,
    tenant: Option<Tenant<{ 32 * 1024 }>>,
}

impl<D: Custodial<Reservation>> Custodial<Reservation> for Blocked<D> {
    fn observe_custody(
        &mut self,
        sink: &mut dyn dcbor::bounded::CustodySink<Reservation>,
    ) -> dcbor::bounded::PermitsObserved {
        dcbor::bounded::observed_all([
            self.decode.observe_custody(sink),
            self.tenant
                .as_mut()
                .map_or(dcbor::bounded::PermitsObserved::Complete, |tenant| {
                    tenant.observe_custody(sink)
                }),
        ])
    }
}

// The tenant is retired by the parent before the decode can publish.
dcbor_test_support::terminal!(Wraps: [D: super::support::Terminal] Blocked<D> => D);

impl<D: dcbor::bounded::Resumable<Limits>> dcbor::bounded::Resumable<Limits> for Blocked<D> {
    type Output = D::Output;
    type Error = D::Error;
    type Position = D::Position;

    fn step(&mut self, m: &mut Limits) -> Result<Step<D::Output>, D::Error> {
        self.decode.step(m)
    }

    fn position(&mut self) -> D::Position {
        self.decode.position()
    }
}

/// The unit assertion's own control: an admission wider than one quantum,
/// made straight to a recorded policy, is rejected by `assert_units` with
/// its exact message (`policy.rs`, `assert_units`), caught so the body
/// returns normally. The run is then finished by the one recorded-run
/// finalizer as a negative control: its correspondence checked, its
/// recording complete, and the machine required to refuse exactly the
/// direct call, a work call of `(1, 256)` admitted with no admission, found
/// at the run's end, nothing following it (`machine.rs`, `MissingAdmission`).
#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "the oversized unit assert_units must reject"
)]
fn bound_assertion_rejects_oversized_instrumentation() {
    use dcbor::bounded::{Budget, Call, WriteWork};
    use dcbor_refinement::{At, Divergence, Rule};
    use std::panic::{AssertUnwindSafe, catch_unwind};
    super::support::recorded_control(
        Divergence {
            at: At::End,
            rule: Rule::MissingAdmission(WriteWork::new(1, 256)),
        },
        |run| {
            let policy = run.policy(POOL);
            run.with_policy(policy, |m| {
                m.traverse(1, 256).unwrap();
                let expected = format!(
                    "indivisible operation 0: {:?} exceeds {:?}",
                    Call::Work {
                        values: 1,
                        bytes: 256,
                    },
                    TURN,
                );
                let payload = catch_unwind(AssertUnwindSafe(|| {
                    m.assert_units(TURN);
                }))
                .expect_err("assert_units accepted an oversized operation");
                let message = payload
                    .downcast_ref::<String>()
                    .map(String::as_str)
                    .or_else(|| payload.downcast_ref::<&str>().copied());
                assert_eq!(
                    message,
                    Some(expected.as_str()),
                    "assert_units must reject the oversized call itself"
                );
            });
            Ok(())
        },
    );
}
