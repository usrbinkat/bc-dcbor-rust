use super::bindings::string_decoder;
use super::harness::*;
use super::support::{
    self, Fault, Finding, Retirement, pipeline::Unwitnessed, refusal_matrix, rigor::rigor,
};
use dcbor::bounded::decode::decode_typed;
use dcbor::bounded::{Allocator, BoundedError, Owned};

// The input, the parse and the value's separate lifetimes, and a refused
// construction's release of its completed fields, are the one typed engine's
// (`ownership_is_accounted_at_every_phase_transition_and_cancellation`,
// `completed_field_values_not_just_permits_survive_later_refusal`, below).

/// Every admission of a string decode refused, resumed and cancelled, in a
/// pool of fixed capacity: after each run, cancelled or published and
/// released, the pool's whole capacity can be reacquired exactly, and one
/// byte more cannot.
#[test]
fn cancellation_at_every_actual_constructor_admission_returns_capacity() {
    let wire = text_wire("q\u{301}\u{1f600}");
    // The pool: four quarter-mebibyte elements of one tenant.
    const QUARTER: usize = 256 * 1024;
    let capacity = 4 * QUARTER as u64;
    refusal_matrix("string decode in a fixed pool", rigor(), |fault: Fault| {
        suite_with(capacity, support::CAPACITY, |run, pool| {
            let decoding = run.shared_policy(pool);
            run.holding(
                string_decoder(&wire),
                Retirement::Released,
                &Unwitnessed,
                |operation| {
                    operation.drive_faulted(
                        decoding,
                        string_turns(wire.len()),
                        Retirement::Released,
                        fault,
                        |_, _| {},
                        |_| (),
                    )?;
                    Ok::<_, Finding>(())
                },
            )?;
            run.with_policy(decoding, |m| m.assert_units(TURN));
            run.with_policy(pool, |m| {
                assert_eq!(m.live_bytes(), 0, "a run kept capacity")
            });
            let calls = run.with_policy(decoding, |m| support::RefusalRun::of(m));
            let owner = run.with_policy(pool, |m| m.owner().expect("a recorded owner"));
            let all = run.with_policy(pool, |m| occupy::<QUARTER>(m, &owner));
            run.holding(all, Retirement::Released, &Unwitnessed, |all| {
                all.with_policy(pool, |_, m| refuses_more(m, &owner));
            });
            run.with_policy(pool, |m| assert_eq!(m.live_bytes(), 0));
            Ok(calls)
        })
    });
}

#[test]
fn completed_field_values_not_just_permits_survive_later_refusal() {
    use dcbor::bounded::decode::construction::in_place::{
        BindingContext, Building, Built, ConstructionCost, InPlace, build_part, reclaim_part,
        remaining_part, reported,
    };
    use dcbor::bounded::decode::construction::reclamation::{
        Cleanup, Mode, PeekSlot, Reclaim, Reclaimed, Slot,
    };
    use dcbor::bounded::decode::{ConstructResult, Options};
    use std::ptr::addr_of_mut;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static CREATED: AtomicUsize = AtomicUsize::new(0);
    static DROPPED: AtomicUsize = AtomicUsize::new(0);
    struct Tracked(String);
    /// The single `String` field's slot, in the record's slot's mode: its
    /// place by compiler field projection alone, and the record's state, which
    /// is the field's own. Construction, cleanup and the cleanup count all
    /// reach it here.
    fn field<A: Allocator, M: Mode>(
        slot: Slot<'_, Tracked, <String as Reclaim<A>>::State, M>,
    ) -> Slot<'_, String, <String as Reclaim<A>>::State, M> {
        // SAFETY: the projection stays within the record and forms no
        // reference; a `Tracked`'s state is its one field's.
        unsafe { slot.child(|value| addr_of_mut!((*value).0), |state| state) }
    }
    // SAFETY: the compiler projection preserves the single String field's final
    // address, and the field's own state is used for construction and
    // reclamation.
    unsafe impl<A: Allocator> InPlace<A> for Tracked {
        // Construction and cleanup are the single String field's.
        const COST: ConstructionCost = <String as InPlace<A>>::COST;

        fn build_step<'b>(
            ctx: BindingContext<'b, '_, '_, '_, Self, A>,
            allocator: &mut A,
        ) -> ConstructResult<Building<'b, Self>, A> {
            let mut ctx = ctx;
            let assembly = ctx.assembly();
            let index = ctx.index();
            // SAFETY: the string field's slot, projected from this record's
            // own slot by [`field`]: a part of the record, from its node.
            let string = match unsafe {
                ctx.part(index, |slot| {
                    Ok::<_, core::convert::Infallible>(field::<A, _>(slot))
                })
            } {
                Ok(string) => string,
                Err(never) => match never {},
            };
            let result = build_part::<String, A>(string, allocator)?;
            if result == Built::Done {
                CREATED.fetch_add(1, Ordering::SeqCst);
            }
            // SAFETY: `Done` is reported only once `build_part` verified the
            // string's record against its field's place, and the string is
            // the record's one field, so the record is initialized whole.
            Ok(unsafe { reported(result, assembly) })
        }
    }
    // SAFETY: only the initialized String field is reclaimed; no Tracked Drop.
    unsafe impl<A: Allocator> Reclaim<A> for Tracked {
        // Its own level and its string field's, dispatched as a part.
        const DISPATCH_DEPTH: usize = <String as Reclaim<A>>::DISPATCH_DEPTH + 1;
        type State = <String as Reclaim<A>>::State;
        const INITIAL: Self::State = <String as Reclaim<A>>::INITIAL;

        fn reclaim_step(
            slot: Slot<'_, Self, Self::State>,
            cleanup: &mut Cleanup<'_, A>,
        ) -> dcbor::bounded::BoundedResult<Reclaimed, A> {
            let result = reclaim_part::<String, A>(field::<A, _>(slot), cleanup)?;
            if result == Reclaimed::Done {
                DROPPED.fetch_add(1, Ordering::SeqCst);
            }
            Ok(result)
        }

        /// The wrapped string's own count, at the same projection.
        fn remaining(slot: PeekSlot<'_, Self, Self::State>) -> Option<u64> {
            remaining_part::<String, A>(field::<A, _>(slot))
        }

        /// The wrapped string's own custody, at the same projection: the
        /// record holds nothing beside its one field.
        fn observe_permits(
            slot: PeekSlot<'_, Self, Self::State>,
            sink: &mut dyn dcbor::bounded::CustodySink<A::Permit>,
        ) -> dcbor::bounded::PermitsObserved {
            <String as Reclaim<A>>::observe_permits(field::<A, _>(slot), sink)
        }
    }
    impl Drop for Tracked {
        fn drop(&mut self) {
            assert!(!self.0.is_empty());
            DROPPED.fetch_add(1, Ordering::SeqCst);
        }
    }
    let wire = [0x82, 0x63, b'a', b'b', b'c', 0x63, b'd', b'e', b'f'];
    let created = CREATED.load(Ordering::SeqCst);
    let dropped = DROPPED.load(Ordering::SeqCst);
    suite(|run, policy| {
        run.holding(
            dcbor::bounded::decode::construction::DecodeOwner::new(),
            Retirement::Scope,
            &Unwitnessed,
            |owner| {
                owner.initialize(policy)?;
                owner.decoder::<_, Vec<Tracked>, _, _>(
                    policy,
                    support::Borrowing(&wire),
                    Options::normalizing(8),
                    &Unwitnessed,
                    |operation| {
                        operation.with_policy(policy, |_, m| m.open());
                        let turns = support::typed_turns::<Vec<Tracked>>(wire.len());
                        let published = operation.controlled(
                            policy,
                            turns,
                            Retirement::Published,
                            true,
                            |_, _, _| CREATED.load(Ordering::SeqCst) == created + 1,
                            |_| (),
                        )?;
                        assert!(published.is_none(), "first-field boundary was skipped");
                        let held = operation.with_policy(policy, |_, m| m.live_bytes());
                        assert!(held > 0);
                        let position = operation.value().position();
                        // The completed field's boundary refused three
                        // times: each refusal leaves the decode where it
                        // was, its work charged once and its storage
                        // held.
                        operation.refused(policy, 3, Retirement::Published)?;
                        assert_eq!(operation.value().position(), position);
                        operation.with_policy(policy, |_, m| {
                            assert_eq!(m.live_bytes(), held, "a refusal changed ownership");
                        });
                        assert_eq!(
                            CREATED.load(Ordering::SeqCst) - created,
                            1,
                            "first field was not completed"
                        );
                        let prematurely_dropped = DROPPED.load(Ordering::SeqCst) - dropped;
                        operation.with_policy(policy, |_, m| assert_eq!(m.live_bytes(), held));
                        // Each later scheduler turn begins after positively observing the
                        // refusal. Consumption and allocation ownership remain cumulative.
                        operation
                            .drive_faulted(
                                policy,
                                turns,
                                Retirement::Published,
                                Fault::NONE,
                                |_, _| {},
                                |output| {
                                    assert_eq!(
                                        output
                                            .value()
                                            .value()
                                            .iter()
                                            .map(|v| v.0.as_str())
                                            .collect::<Vec<_>>(),
                                        ["abc", "def"]
                                    );
                                    assert_eq!(CREATED.load(Ordering::SeqCst) - created, 2);
                                    output.with_policy(policy, |_, m| {
                                        m.assert_units(TURN);
                                        assert!(m.live_bytes() > 0);
                                    });
                                    assert_eq!(DROPPED.load(Ordering::SeqCst), dropped);
                                },
                            )?
                            .expect("the successful continuation publishes");
                        assert_eq!(DROPPED.load(Ordering::SeqCst), dropped);
                        assert_eq!(
                            prematurely_dropped, 0,
                            "completed field value was discarded while its reservation survived"
                        );
                        Ok::<_, Finding>(())
                    },
                )??;
                owner.drain(policy)
            },
        )?;
        run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0));
        assert_eq!(
            CREATED.load(Ordering::SeqCst),
            DROPPED.load(Ordering::SeqCst)
        );
        Ok(())
    });
}

#[test]
fn output_moved_to_another_thread_releases_only_at_the_last_owner() {
    let wire = text_wire("\u{e9}\u{1f600}");
    support::recorded_run(|run| {
        let decoding = run.policy(POOL);
        let output = run.with_policy(decoding, |m| {
            decode_typed::<String, _>(&wire, 8, m)
                .map_err(|error| Finding::Driver(format!("the text did not decode: {error:?}")))
        })?;
        let output = std::cell::RefCell::new(Some(output));
        let held = run.with_policy(decoding, |m| m.live_bytes());
        let worker = run.shared_policy(decoding);
        // The input is gone before the worker receives the published handle.
        // Its custody comes back through the join for parent-side retirement.
        drop(wire);
        run.workers(
            &[worker],
            1,
            Retirement::LastReference,
            |_| {
                output
                    .borrow_mut()
                    .take()
                    .expect("one output for one worker")
            },
            |_, _, output, m| {
                assert!(held >= 6);
                assert_eq!(output.value(), "\u{e9}\u{1f600}");
                assert_eq!(m.live_bytes(), held);
                Ok(())
            },
        )?;
        assert_eq!(run.with_policy(decoding, |m| m.live_bytes()), 0);
        Ok(())
    });
}

// Transfers follow merge and split in tokio/tests/sync_semaphore_owned.rs:
// intermediate ownership is exact, zero-sized and refused transfers change
// nothing, and the final owner releases exactly what it holds. The test
// exercises the policy's own reservations, granted directly, so it runs on
// ordinary, unrecorded pools: a recorded run admits grants only through the
// production acquisition protocol.
#[test]
fn split_merge_zero_and_refused_transfers_preserve_exact_capacity() {
    use dcbor::bounded::TransferRefusal;
    let capacity = 4096;
    let mut pool = Limits::new(u64::MAX, u64::MAX, capacity);
    let mut first = pool.allocate(3).unwrap();
    assert_eq!((pool.live_bytes(), pool.peak_bytes()), (3, 3));
    let mut second = first.split(1).unwrap();
    assert_eq!((first.bytes(), second.bytes()), (2, 1));
    assert_eq!((pool.live_bytes(), pool.peak_bytes()), (3, 3));
    let empty = first.split(0).unwrap();
    assert_eq!(empty.bytes(), 0);
    for requested in [3, u64::MAX] {
        assert_eq!(
            first.split(requested).unwrap_err(),
            TransferRefusal::Insufficient { requested, held: 2 }
        );
        assert_eq!(first.bytes(), 2);
        assert_eq!(pool.live_bytes(), 3);
    }
    first.merge(second).unwrap();
    assert_eq!(first.bytes(), 3);
    assert_eq!(pool.live_bytes(), 3);
    // A reservation of other storage is returned unchanged.
    let mut foreign_pool = Limits::new(u64::MAX, u64::MAX, capacity);
    let foreign = foreign_pool.allocate(5).unwrap();
    let (foreign, refusal) = first.merge(foreign).unwrap_err();
    assert_eq!(refusal, TransferRefusal::Foreign);
    assert_eq!((first.bytes(), foreign.bytes()), (3, 5));
    assert_eq!((pool.live_bytes(), foreign_pool.live_bytes()), (3, 5));
    drop(foreign);
    assert_eq!(foreign_pool.live_bytes(), 0);
    second = first.split(1).unwrap();
    drop(first);
    assert_eq!(pool.live_bytes(), 1);
    let last = second.split(1).unwrap();
    assert_eq!(
        second.split(1).unwrap_err(),
        TransferRefusal::Insufficient {
            requested: 1,
            held: 0
        }
    );
    drop(second);
    drop(empty);
    assert_eq!(pool.live_bytes(), 1);
    drop(last);
    assert_eq!(pool.live_bytes(), 0);
    let all = pool.allocate(capacity).unwrap();
    assert!(pool.allocate(1).is_err());
    drop(all);
    assert_eq!(pool.live_bytes(), 0);
}

/// Where a typed decode's storage is held, as its position reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Held {
    /// The parse record and its arenas.
    ParserScratch,
    /// The construction record and a field under construction.
    PartialField,
    /// The complete value, before publication.
    TypedOutput,
}

fn held(
    position: &dcbor::bounded::decode::construction::TypedPosition<
        dcbor::bounded::decode::construction::in_place::SessionObservation<
            dcbor::bounded::decode::construction::in_place::BufferObservation,
        >,
    >,
) -> Option<Held> {
    use dcbor::bounded::decode::construction::in_place::BufferObservation;
    use dcbor::bounded::decode::construction::{ConstructPhase, TypedPosition};
    match position {
        TypedPosition::Parse(parse) if parse.allocated => Some(Held::ParserScratch),
        TypedPosition::Construct(construct) => match construct.detail.phase {
            // The byte buffer, under its root session, holds its metadata
            // block: a field under construction, its payload acquired or not.
            Some(ConstructPhase::Build)
                if matches!(
                    construct.detail.build,
                    Some(observation) if matches!(observation.inner, BufferObservation::Held(_))
                ) =>
            {
                Some(Held::PartialField)
            }
            Some(ConstructPhase::Detach | ConstructPhase::Publish) => Some(Held::TypedOutput),
            _ => None,
        },
        _ => None,
    }
}

#[test]
fn ownership_is_accounted_at_every_phase_transition_and_cancellation() {
    use dcbor::ByteString;
    use dcbor::bounded::decode::Options;
    use dcbor::bounded::decode::construction::DecodeOwner;
    let payload: Vec<u8> = (0..65536u32).map(|i| (i % 251) as u8).collect();
    let wire = dcbor::CBOR::to_byte_string(&payload).to_cbor_data();
    let len = wire.len() as u64;
    let turns = support::typed_turns::<ByteString>(wire.len());
    for stop in [Held::ParserScratch, Held::PartialField, Held::TypedOutput] {
        for cancel in [false, true] {
            suite(|run, policy| {
                run.holding(
                    DecodeOwner::<'static, Limits>::new(),
                    Retirement::Scope,
                    &Unwitnessed,
                    |owner| {
                        owner.initialize(policy)?;
                        owner.decoder::<_, ByteString, _, _>(
                            policy,
                            support::Copying(&wire),
                            Options::normalizing(8),
                            &Unwitnessed,
                            |operation| {
                                // Input retained: the copy and its record,
                                // before any decoding.
                                let input_live =
                                    operation.with_policy(policy, |_, m| m.live_bytes());
                                assert!(input_live >= len);
                                // What each phase holds, and phases entered in
                                // order, each once: checked before every turn.
                                let mut previous = None;
                                let mut entered = |m: &Limits, phase: Option<Held>| {
                                    match phase {
                                        Some(Held::ParserScratch | Held::PartialField) => {
                                            assert!(m.live_bytes() > input_live);
                                        }
                                        Some(Held::TypedOutput) => {
                                            assert!(m.live_bytes() >= input_live + len);
                                        }
                                        None => {}
                                    }
                                    if phase.is_some() && phase != previous {
                                        assert!(phase > previous, "{phase:?} after {previous:?}");
                                        previous = phase;
                                    }
                                };
                                let reached = operation.controlled(
                                    policy,
                                    turns,
                                    Retirement::Published,
                                    true,
                                    |m, operation, _| {
                                        let phase = held(&operation.position());
                                        entered(m, phase);
                                        phase == Some(stop)
                                    },
                                    |_| (),
                                )?;
                                assert!(reached.is_none(), "{stop:?} was never reached");
                                let live = operation.with_policy(policy, |_, m| m.live_bytes());
                                operation.refused(policy, 3, Retirement::Published)?;
                                operation.with_policy(policy, |_, m| {
                                    assert_eq!(m.live_bytes(), live, "a refusal changed ownership");
                                });
                                if cancel {
                                    operation.value().cancel();
                                    operation.finish(policy, turns, Retirement::Published)?;
                                    return Ok(());
                                }
                                operation
                                    .controlled(
                                        policy,
                                        turns,
                                        Retirement::Published,
                                        true,
                                        |m, operation, _| {
                                            entered(m, held(&operation.position()));
                                            false
                                        },
                                        |value| {
                                            // The decoder retired, its scratch
                                            // queued: the value and its input
                                            // remain.
                                            assert_eq!(value.value().value().data(), &payload[..]);
                                            value.with_policy(policy, |_, m| {
                                                assert!(
                                                    m.live_bytes()
                                                        >= input_live + payload.len() as u64
                                                );
                                            });
                                        },
                                    )?
                                    .expect("an uncontrolled decode publishes");
                                Ok::<_, Finding>(())
                            },
                        )??;
                        owner.drain(policy)
                    },
                )?;
                run.with_policy(policy, |m| {
                    assert_eq!(m.live_bytes(), 0, "leaked at {stop:?}, cancel={cancel}");
                });
                Ok(())
            });
        }
    }
}

#[test]
fn failed_growth_keeps_old_reservation_until_a_successful_replacement() {
    use dcbor::bounded::{Custodial, CustodySink, PermitsObserved};
    struct Growth {
        storage: PublishedArena<u8>,
        blocker: Option<Tenant<1023>>,
    }
    impl Custodial<Reservation> for Growth {
        fn observe_custody(&mut self, sink: &mut dyn CustodySink<Reservation>) -> PermitsObserved {
            dcbor::bounded::observed_all([
                self.storage.observe_custody(sink),
                self.blocker
                    .as_mut()
                    .map_or(PermitsObserved::Complete, |blocker| {
                        blocker.observe_custody(sink)
                    }),
            ])
        }
    }
    suite_with(4096, support::CAPACITY, |run, pool| {
        let owner = run.with_policy(pool, |m| m.owner().expect("a recorded owner"));
        let tenant = run.with_policy(pool, |m| m.owner().expect("a recorded owner"));
        let first = run.shared_policy(pool);
        let next = run.shared_policy(pool);
        run.holding(
            Growth {
                storage: PublishedArena {
                    storage: Owned::new(),
                    owner: Some(owner.id()),
                },
                blocker: None,
            },
            Retirement::Released,
            &Unwitnessed,
            |growth| {
                growth.with_policy(first, |growth, m| {
                    growth.storage.storage.push(7, m, &owner).unwrap();
                    assert_eq!(m.live_bytes(), 4);
                });
                growth.with_policy(pool, |growth, m| {
                    growth.blocker = Some(occupy::<1023>(m, &tenant));
                });
                growth.with_policy(first, |growth, m| {
                    assert!(matches!(
                        growth.storage.storage.reserve(256, m, &owner),
                        Err(BoundedError::Refused(LimitRefusal::Storage))
                    ));
                    assert_eq!(growth.storage.storage.as_slice(), &[7]);
                    assert_eq!(m.live_bytes(), 4096);
                });
                let blocker = growth
                    .value()
                    .blocker
                    .take()
                    .expect("the pool blocker is held");
                growth.holding(blocker, Retirement::Released, |_| ());
                growth.with_policy(pool, |_, m| assert_eq!(m.live_bytes(), 4));
                growth.with_policy(next, |growth, m| {
                    growth.storage.storage.reserve(256, m, &owner).unwrap();
                    assert_eq!(growth.storage.storage.as_slice(), &[7]);
                    assert!(m.live_bytes() > 4);
                });
            },
        );
        run.with_policy(pool, |m| assert_eq!(m.live_bytes(), 0));
        Ok(())
    });
}
