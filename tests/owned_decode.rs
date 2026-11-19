use dcbor::bounded::decode::construction::{
    Acquisition, DecodeOwner, TypedDecoder, TypedValue,
    in_place::{BindingContext, Building, ConstructionCost, InPlace, admit, unit},
    reclamation::{Cleanup, Custody, PeekSlot, Reclaim, Reclaimed, Slot},
};
use dcbor::bounded::decode::{ConstructResult, Options};
use dcbor::bounded::{
    BoundedError, BoundedResult, CustodySink, Limits, PermitsObserved, Reservation,
};
use dcbor_test_support::{
    self as support, CustodyBatch, Finding, Instrumented, Lent, Retirement, instrumented,
    pipeline::Unwitnessed,
};
use std::sync::{Arc, atomic::AtomicUsize};

#[cfg(feature = "custom-std-collections")]
#[path = "owned_pipeline/tree_state.rs"]
mod tree_state;

/// One acquisition refused in the first of two scopes keeps its binding to
/// that scope: the second refuses it as a plan mismatch. Once it acquires
/// its record in the first, its token is reset, scope binding included, and
/// it acquires in the second. Both scopes drain to nothing.
#[test]
fn refused_acquisition_cannot_move_admission_to_another_scope() {
    support::recorded_run(|run| {
        let policy = run.policy(u64::MAX);
        let (refused, mismatch) = run.scoped(policy, &Unwitnessed, |first| {
            first.lending(Retirement::Exhausted, Lent::new, |first| {
                let first_scope = first.value().get();
                first.holding(DecodeOwner::new(), Retirement::Scope, |second| {
                    second.initialize(policy)?;
                    let checked = second.lending(Retirement::Exhausted, Lent::new, |second| {
                        let second_scope = second.value().get();
                        second.holding(
                            Acquisition::<Instrumented, Limits>::new(),
                            Retirement::Stopped,
                            |acquisition| {
                                let checked = acquisition.with_policy(policy, |acquisition, m| {
                                    m.clear_refusal();
                                    m.exhaust();
                                    let refused = matches!(
                                        first_scope.allocate_step(m, acquisition),
                                        Err(BoundedError::Refused(_))
                                    );
                                    m.clear_refusal();
                                    m.fresh();
                                    let mismatch = matches!(
                                        second_scope.allocate_step(m, acquisition),
                                        Err(BoundedError::PlanMismatch)
                                    );
                                    (refused, mismatch)
                                });
                                acquisition.acquire(policy, first_scope, |_| ())?;
                                acquisition.with_policy(policy, |_, m| m.fresh());
                                acquisition.acquire(policy, second_scope, |_| ())?;
                                Ok::<_, Finding>(checked)
                            },
                        )
                    })?;
                    second.drain(policy)?;
                    Ok::<_, Finding>(checked)
                })
            })
        })?;
        assert!(refused, "an exhausted acquisition was not refused");
        assert!(mismatch, "a refused acquisition moved to another scope");
        run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0));
        Ok(())
    });
}

/// A scope whose one record is live waits without spending work, and its
/// shutdown closes admission while it waits: a later acquisition is refused
/// as a plan mismatch. The record is held beside the scope, outside it, so
/// the scope is stepped exclusively while the record lives; once the record
/// retires the scope drains to nothing.
#[test]
fn live_record_waiting_spends_no_work_and_shutdown_closes_admission() {
    support::recorded_run(|run| {
        let policy = run.policy(u64::MAX);
        let (waiting, closing, spent, rejected) = run.holding(
            CustodyBatch::slots(1),
            Retirement::Exhausted,
            &Unwitnessed,
            |records| {
                records.lending(Retirement::Exhausted, Lent::new, |lent| {
                    let records = lent.value().get();
                    lent.holding(DecodeOwner::new(), Retirement::Scope, |owner| {
                        owner.initialize(policy)?;
                        owner.lending(Retirement::Exhausted, Lent::new, |view| {
                            let scope = view.value().get();
                            view.holding(
                                Acquisition::<Instrumented, Limits>::new(),
                                Retirement::Stopped,
                                |acquisition| {
                                    acquisition.with_policy(policy, |_, m| m.fresh());
                                    acquisition
                                        .acquire(policy, scope, |record| record.deposit(records, 0))
                                },
                            )
                        })?;
                        let observed = owner.with_policy(policy, |owner, m| {
                            m.fresh();
                            let allowance = m.remaining();
                            let waiting = owner.step(m);
                            let closing = owner.shutdown_step(m);
                            let spent = m.remaining() == allowance;
                            let rejected = matches!(
                                owner.allocate_step::<Instrumented>(m, &mut Acquisition::new()),
                                Err(BoundedError::PlanMismatch)
                            );
                            (waiting, closing, spent, rejected)
                        });
                        owner.drawn(records, 0, Retirement::Published, |_| ());
                        owner.drain(policy)?;
                        Ok::<_, Finding>(observed)
                    })
                })
            },
        )?;
        assert_eq!(waiting.unwrap(), Reclaimed::Waiting);
        assert_eq!(closing.unwrap(), Reclaimed::Waiting);
        assert!(spent, "a waiting scope spent work");
        assert!(rejected, "a shut-down scope admitted an acquisition");
        run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0));
        Ok(())
    });
}

/// Decode an instrumented input, moving the whole consumer state between
/// turns and cancelling at turn `cancel_at`, as one recorded run. Returns
/// the turns taken, whether the value was published, and the boundary
/// valuations the run reached.
fn run(cancel_at: Option<usize>) -> (usize, bool, dcbor::bounded::boundary::Reached) {
    let wire = [0x62, b'o', b'k'];
    // The decode within its own bound; a cancelled one also reclaims the
    // instrumented input, whose cleanup its acquisition accounts: three
    // units, its bytes, its reservation and its handle.
    let bound =
        support::turns(
            dcbor::bounded::decode::construction::typed_decode_bound::<
                Instrumented,
                String,
                Limits,
                (),
            >(wire.len() as u64, Options::normalizing(8))
            .expect("the typed decode bound of an input held in memory fits in u64"),
        ) + 3;
    support::recorded_run(|run| {
        let policy = run.policy(u64::MAX);
        let released = Arc::new(AtomicUsize::new(0));
        let mut turns = 0;
        let published = run.holding(
            DecodeOwner::new(),
            Retirement::Scope,
            &Unwitnessed,
            |owner| {
                owner.initialize(policy)?;
                let input =
                    owner.with_policy(policy, |owner, m| instrumented(owner, m, &wire, &released));
                let published = owner.holding(input, Retirement::Published, |input| {
                    input.transfer(
                        |input| {
                            TypedDecoder::<_, String, Limits>::new(input, Options::normalizing(8))
                        },
                        Retirement::Stopped,
                        |decoder| {
                            let published = decoder.controlled(
                                policy,
                                bound,
                                Retirement::Published,
                                true,
                                |_, _, turn| {
                                    turns = turn + 1;
                                    cancel_at == Some(turn)
                                },
                                |value| {
                                    let address = value.value().value() as *const String;
                                    value.transfer(
                                        |value| value,
                                        Retirement::Published,
                                        |moved| {
                                            assert_eq!(moved.value().value(), "ok");
                                            assert_eq!(
                                                moved.value().value() as *const String,
                                                address
                                            );
                                            assert_eq!(moved.value().bytes(), wire);
                                        },
                                    );
                                },
                            )?;
                            if published.is_none() {
                                decoder.value().cancel();
                                decoder.finish(policy, bound, Retirement::Published)?;
                            }
                            Ok::<_, Finding>(published.is_some())
                        },
                    )
                })?;
                owner.drain(policy)?;
                Ok::<_, Finding>(published)
            },
        )?;
        run.with_policy(policy, |m| {
            assert_eq!(m.live_bytes(), 0);
            assert_eq!(released.load(std::sync::atomic::Ordering::SeqCst), 1);
            Ok((turns, published, m.reached()))
        })
    })
}

#[test]
fn movable_decode_publication_and_retirement() {
    assert!(run(None).1, "uncancelled decode did not publish");
}

/// The decode cancelled before each of its turns through publication
/// ([`support::stop_matrix`]): cancellation takes effect before that turn's
/// step, so cancelling at any turn up to and including the publishing one
/// prevents publication, and only the stop past it publishes. Every cancelled
/// decode finishes its cleanup and the scope recovers everything ([`run`]).
#[test]
fn cancellation_through_initialization_parse_build_and_publication() {
    let (turns, published, _) = run(None);
    assert!(published, "uncancelled decode did not publish");
    support::stop_matrix("instrumented decode cancelled at a turn", turns, |stop| {
        let (_, published, reached) = run(Some(stop));
        assert_eq!(
            published,
            stop == turns,
            "cancellation before turn {stop} of {turns}"
        );
        reached
    });
}

#[test]
fn cancelled_operation_finishes_while_unrelated_output_remains_live() {
    support::recorded_run(|run| {
        let policy = run.policy(u64::MAX);
        let released = Arc::new(AtomicUsize::new(0));
        run.scoped(policy, &Unwitnessed, |owner| {
            owner.lending(Retirement::Exhausted, Lent::new, |view| {
                let scope = view.value().get();
                let first = view.with_policy(policy, |_, m| {
                    instrumented(scope, m, &[0x62, b'o', b'k'], &released)
                });
                view.holding(first, Retirement::Published, |first| {
                    first.decode::<String, _>(policy, Options::normalizing(8), |output| {
                        let second = output.with_policy(policy, |_, m| {
                            instrumented(scope, m, &[0x62, b'o', b'k'], &released)
                        });
                        output.holding(second, Retirement::Published, |second| {
                            second.transfer(
                                |input| {
                                    TypedDecoder::<_, String, Limits>::new(
                                        input,
                                        Options::normalizing(8),
                                    )
                                },
                                Retirement::Stopped,
                                |cancelled| {
                                    cancelled.value().cancel();
                                    let bound = support::turns(
                                        dcbor::bounded::decode::construction::typed_decode_bound::<
                                            Instrumented,
                                            String,
                                            Limits,
                                            (),
                                        >(
                                            3, Options::normalizing(8)
                                        )
                                        .expect("the literal's typed decode bound fits in u64"),
                                    ) + 3;
                                    cancelled.finish(policy, bound, Retirement::Published)
                                },
                            )
                        })?;
                        assert_eq!(
                            output.value().value(),
                            "ok",
                            "cancellation disturbed an unrelated output",
                        );
                        Ok::<_, Finding>(())
                    })?
                })
            })
        })?;
        run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0));
        assert_eq!(released.load(std::sync::atomic::Ordering::SeqCst), 2);
        Ok(())
    });
}

#[test]
fn shutdown_is_terminal_and_cannot_reopen_admission() {
    support::recorded_run(|run| {
        let policy = run.policy(u64::MAX);
        run.holding(
            DecodeOwner::new(),
            Retirement::Scope,
            &Unwitnessed,
            |owner| {
                owner.initialize(policy)?;
                owner.with_policy(policy, |owner, m| {
                    m.fresh();
                    assert_eq!(owner.shutdown_step(m).unwrap(), Reclaimed::Done);
                    m.fresh();
                    let reopened = owner.initialize_step(m).is_ok();
                    m.fresh();
                    owner.shutdown_step(m).unwrap();
                    assert_eq!(m.live_bytes(), 0);
                    assert!(!reopened, "closed owner accepted initialization again");
                });
                Ok::<_, Finding>(())
            },
        )
    });
}

static PROBE_DROPS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
struct StableProbe {
    bytes: [u8; 256],
    address: usize,
}
impl Drop for StableProbe {
    fn drop(&mut self) {
        PROBE_DROPS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}
/// A [`StableProbe`]'s state: the 64-byte chunks written, then whether its
/// address is.
struct ProbeState {
    chunks: usize,
    addressed: bool,
}
/// The chunks written and whether the address is: the probe's whole custody.
impl Custody for ProbeState {
    type Observation = (usize, bool);

    fn observe(&mut self) -> (usize, bool) {
        (self.chunks, self.addressed)
    }
}
// SAFETY: each admitted step writes only a 64-byte chunk or the address field.
// No initialized field owns resources, so every partial prefix is reclaimable.
unsafe impl InPlace<Limits> for StableProbe {
    // Four 64-byte writes and the address write; one cleanup unit.
    const COST: ConstructionCost = ConstructionCost::fixed(dcbor::const_cost!(
        dcbor::const_cost!(unit(64).checked_mul(4)).checked_add(dcbor::const_cost!(
            unit(core::mem::size_of::<usize>()).checked_add(unit(0))
        ))
    ));

    /// A third-party binding admits its own construction through the one
    /// route ([`admit`]), as `InPlace` documents.
    fn build_step<'b>(
        ctx: BindingContext<'b, '_, '_, '_, Self, Limits>,
        a: &mut Limits,
    ) -> ConstructResult<Building<'b, Self>, Limits> {
        let assembly = ctx.assembly();
        let mut slot = ctx.into_slot();
        let (place, state) = slot.parts();
        // Each field is written by raw projection alone, never through a
        // reference to the partly initialized probe.
        let raw = place.as_ptr(state);
        if state.chunks < 4 {
            admit(a, 64)?;
            // SAFETY: the next 64 bytes of the slot's own destination, within
            // its 256, written by raw projection.
            unsafe {
                core::ptr::addr_of_mut!((*raw).bytes)
                    .cast::<u8>()
                    .add(state.chunks * 64)
                    .write_bytes(0x5a, 64);
            }
            state.chunks += 1;
            Ok(Building::Progress)
        } else {
            admit(a, core::mem::size_of::<usize>())?;
            // SAFETY: a plain field of the slot's own destination, written by
            // raw projection.
            unsafe {
                core::ptr::addr_of_mut!((*raw).address).write(raw as usize);
            }
            state.addressed = true;
            // SAFETY: all four 64-byte chunks and the address are written,
            // each by an admitted unit recorded in this state, and the probe
            // holds no other field; the slot is not reclaimed while it
            // builds.
            Ok(Building::Done(unsafe { assembly.assemble() }))
        }
    }
}
// SAFETY: the probe's fields are plain bytes and an address; one admitted
// unit invalidates whatever prefix the state records, without Drop.
unsafe impl Reclaim<Limits> for StableProbe {
    type State = ProbeState;
    const INITIAL: ProbeState = ProbeState {
        chunks: 0,
        addressed: false,
    };

    /// A third-party binding admits its own cleanup through the one route
    /// ([`admit`]), as `Reclaim` documents.
    fn reclaim_step(
        mut slot: Slot<'_, Self, ProbeState>,
        cleanup: &mut Cleanup<'_, Limits>,
    ) -> BoundedResult<Reclaimed, Limits> {
        admit(cleanup, 0)?;
        *slot.custody() = Self::INITIAL;
        Ok(Reclaimed::Done)
    }

    /// One call, which is `Done`.
    fn remaining(_: PeekSlot<'_, Self, ProbeState>) -> Option<u64> {
        Some(1)
    }

    /// The probe's bytes are inline: it owns no permit.
    fn observe_permits(
        _: PeekSlot<'_, Self, ProbeState>,
        _: &mut dyn CustodySink<Reservation>,
    ) -> PermitsObserved {
        PermitsObserved::Complete
    }
}

#[test]
fn owned_publication_preserves_construction_address_and_never_runs_payload_drop() {
    assert_eq!(
        core::mem::size_of::<TypedValue<'static, Instrumented, StableProbe, Limits>>(),
        core::mem::size_of::<TypedValue<'static, Instrumented, String, Limits>>()
    );
    support::recorded_run(|run| {
        let policy = run.policy(u64::MAX);
        let released = Arc::new(AtomicUsize::new(0));
        run.holding(
            DecodeOwner::<'static, Limits>::new(),
            Retirement::Scope,
            &Unwitnessed,
            |owner| {
                owner.initialize(policy)?;
                let input = owner.with_policy(policy, |owner, m| {
                    instrumented(owner, m, &[0x62, b'o', b'k'], &released)
                });
                owner.holding(input, Retirement::Published, |input| {
                    input.transfer(
                        |input| {
                            TypedDecoder::<_, StableProbe, Limits>::new(
                                input,
                                Options::normalizing(8),
                            )
                        },
                        Retirement::Stopped,
                        |decoder| {
                            decoder.drive(
                                policy,
                                support::turns(
                                    dcbor::bounded::decode::construction::typed_decode_bound::<
                                        Instrumented,
                                        StableProbe,
                                        Limits,
                                        (),
                                    >(
                                        3, Options::normalizing(8)
                                    )
                                    .expect("the literal's typed decode bound fits in u64"),
                                ),
                                Retirement::Published,
                                |output| {
                                    let value = output.value().value();
                                    assert_eq!(value.address, value as *const StableProbe as usize);
                                    assert_eq!(value.bytes, [0x5a; 256]);
                                },
                            )
                        },
                    )
                })?;
                assert_eq!(PROBE_DROPS.load(std::sync::atomic::Ordering::SeqCst), 0);
                owner.drain(policy)
            },
        )?;
        run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0));
        assert_eq!(PROBE_DROPS.load(std::sync::atomic::Ordering::SeqCst), 0);
        Ok(())
    });
}
