//! Shared-owner independence and cross-thread plan retirement through the
//! production owned pipeline, every value held by the run's holdings from
//! its acquisition to its retirement. No test-owned lifecycle substitute is
//! used.
#![cfg(feature = "std")]
#![forbid(unsafe_code)]
use dcbor::ByteString;
use dcbor::bounded::decode::Options;
use dcbor::bounded::decode::construction::DecodeOwner;
use dcbor::bounded::decode::construction::reclamation::Reclaimed;
use dcbor::bounded::encoding::{OwnedPreparation, OwnedPrepared};
use dcbor::bounded::{Answer, Call, Custodial, Event, Limits, Reservation};
use dcbor_test_support::{
    self as support, CustodyBatch, Finding, Holding, Lent, PolicyId, Retirement, Scope,
    pipeline::Unwitnessed,
};

/// A preparation of a decoded text, and the plan it publishes.
type Preparation = OwnedPreparation<'static, ByteString, String, Limits>;
type Plan = OwnedPrepared<'static, ByteString, String, Limits>;

/// The two texts the interleaved preparations encode: the first takes the
/// retained normalization path, the second is plain.
const TEXTS: [&str; 2] = ["\u{301}\u{301}\u{301}", "independent value"];

/// The turns preparing `value` may take: its owned preparation's bound
/// (`encoding::owned_prepare_bound`) of the value's own shape.
fn preparation_turns(value: &impl dcbor::bounded::encoding::Schema) -> usize {
    support::turns(
        dcbor::bounded::encoding::owned_prepare_bound::<ByteString, String, Limits, ()>(
            support::shape(value),
        )
        .expect("the preparation bound of a decoded value fits in u64"),
    )
}

/// The order in which two preparations sharing a scope take their turns,
/// which places the first's retirement relative to the second's life: before
/// it begins, while it is in flight with either leading, or after it
/// publishes. Each preparation's own turns are fixed by its value, so these
/// four orders are every relation the retirement can have to the other
/// operation.
#[derive(Clone, Copy, Debug)]
enum Interleaving {
    /// The first takes every turn it has, then the second: the first is
    /// retired before the second begins.
    FirstThenSecond,
    /// The second publishes, then the first takes its turns: the first is
    /// retired once the second's plan is live.
    SecondThenFirst,
    /// Turn about, the first leading: the first is retired while the second
    /// is in flight.
    AlternatingFirst,
    /// Turn about, the second leading.
    AlternatingSecond,
}

const INTERLEAVINGS: [Interleaving; 4] = [
    Interleaving::FirstThenSecond,
    Interleaving::SecondThenFirst,
    Interleaving::AlternatingFirst,
    Interleaving::AlternatingSecond,
];

impl Interleaving {
    /// Whether the first preparation takes turn `turn`, counted from zero,
    /// given which of the two are still live: always a live one.
    fn first(self, turn: usize, first: bool, second: bool) -> bool {
        match self {
            Self::FirstThenSecond => first,
            Self::SecondThenFirst => !second,
            Self::AlternatingFirst if first && second => turn.is_multiple_of(2),
            Self::AlternatingSecond if first && second => !turn.is_multiple_of(2),
            Self::AlternatingFirst | Self::AlternatingSecond => first,
        }
    }
}

/// What one interleaved run observed: the first preparation's boundaries
/// while it is live, each the cleanup class of its state there
/// (`classes::prepare`), the `k`th observed where a cut of `k` retires it;
/// and the retirement's cleanup: every call admitted during retirement,
/// by the scope's queue steps after the cut, then by its final drain, the survivor's own
/// turns and its plan's emission excluded. An uncut run's cleanup is the
/// drain of the plans alone.
struct Interleaved {
    boundaries: Vec<Option<support::classes::Class>>,
    cleanup: Vec<Call>,
}

/// Disjoint recording intervals owned by retirement and queue cleanup.
/// Survivor execution lies between intervals and is excluded.
struct RetirementTrace {
    boundaries: Vec<Option<support::classes::Class>>,
    intervals: Vec<std::ops::Range<usize>>,
    drain_start: usize,
}

/// Prepare two values in one scope in `interleaving`, retiring the first
/// preparation after its `cut`th turn while the second continues and the
/// scope steps its queue between turns, as one recorded run. The two
/// preparations, and the plans they publish, are held side by side
/// ([`CustodyBatch`]), each turn taken by drawing its preparation and
/// depositing it back, or its plan, so every turn is checkpointed with both
/// in custody ([`Interleaved`]).
fn interleave(cut: Option<usize>, interleaving: Interleaving) -> Interleaved {
    let cleanup = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let boundaries = support::recorded_run(|run| {
        let policy = run.policy(u64::MAX);
        let mut trace = run.scoped(policy, &Unwitnessed, |owner| {
            owner.lending(Retirement::Exhausted, Lent::new, |view| {
                let scope = view.value().get();
                view.holding(
                    CustodyBatch::<Preparation>::slots(2),
                    Retirement::Exhausted,
                    |operations| {
                        operations.lending(Retirement::Exhausted, Lent::new, |operations| {
                            let preparations = operations.value().get();
                            operations.holding(
                                CustodyBatch::<Plan>::slots(2),
                                Retirement::Exhausted,
                                |plans| {
                                    plans.lending(Retirement::Exhausted, Lent::new, |plans| {
                                        let published = plans.value().get();
                                        interleaved(
                                            plans,
                                            policy,
                                            Shared {
                                                scope,
                                                preparations,
                                                plans: published,
                                            },
                                            cut,
                                            interleaving,
                                        )
                                    })
                                },
                            )
                        })
                    },
                )
            })
        })?;
        trace.intervals.push(trace.drain_start..run.boundary());
        let cleanup = cleanup.clone();
        run.inspect_evidence(move |observed, _| {
            let mut previous_end = 0;
            let mut calls = cleanup.borrow_mut();
            for interval in trace.intervals {
                assert!(
                    previous_end <= interval.start && interval.start <= interval.end,
                    "cleanup intervals overlap or run backwards: {interval:?}"
                );
                previous_end = interval.end;
                calls.extend(observed[interval].iter().filter_map(|observation| {
                    match observation.event {
                        Event::Call(_, Answer::Refused { .. }) => None,
                        Event::Call(call, _) => Some(call),
                        _ => None,
                    }
                }));
            }
        });
        Ok(trace.boundaries)
    });
    let cleanup = std::mem::take(&mut *cleanup.borrow_mut());
    Interleaved {
        boundaries,
        cleanup,
    }
}

/// What the interleaved schedule shares from the holdings around it: the
/// scope's authority, the preparations' slots and the plans' slots.
struct Shared<'v> {
    scope: &'v DecodeOwner<'static, Limits>,
    preparations: &'v CustodyBatch<Preparation>,
    plans: &'v CustodyBatch<Plan>,
}

/// [`interleave`]'s schedule, under `holding`, the innermost of the
/// holdings that lend `shared`: both preparations made and deposited, their
/// turns taken in `interleaving`, the first retired at its `cut`th turn, the
/// scope stepped after every turn; then the second's plan emitted to its
/// exact bytes and both plans retired. A driver's stop is the run's
/// finding. Returns the boundaries and disjoint cleanup intervals, followed
/// by the start of the final drain ([`RetirementTrace`]).
fn interleaved<H: Custodial<Reservation>>(
    holding: &mut Holding<'_, '_, H, Unwitnessed>,
    policy: PolicyId,
    shared: Shared<'_>,
    cut: Option<usize>,
    interleaving: Interleaving,
) -> Result<RetirementTrace, Finding> {
    let Shared {
        scope,
        preparations,
        plans,
    } = shared;
    // Every turn advances one live preparation, so their bounds together
    // bound the turns.
    let mut turns = 0;
    // Observe each cut where it executes: after setup and any preceding
    // queue step, before either operation takes the next scheduled turn.
    let mut boundaries = Vec::new();
    for (slot, text) in TEXTS.into_iter().enumerate() {
        let wire = dcbor::CBOR::from(text).to_cbor_data();
        turns += holding.holding(Lent::new(scope), Retirement::Exhausted, |view| {
            view.copied(policy, &wire, |input| {
                input.decode::<String, _>(policy, Options::normalizing(8), |value| {
                    let bound = preparation_turns(value.value().value());
                    value.transfer(
                        OwnedPreparation::prepare,
                        Retirement::Stopped,
                        |preparation| preparation.deposit(preparations, slot),
                    );
                    bound
                })
            })
        })??;
    }
    let mut live = [true, true];
    let mut published = [false, false];
    let mut first_turns = 0;
    let mut intervals = Vec::new();
    let mut retired = false;
    for turn in 0..turns {
        if live[0] && boundaries.len() == first_turns {
            holding.drawn(preparations, 0, Retirement::Stopped, |preparation| {
                boundaries.push(support::classes::prepare(&preparation.value().position()));
                preparation.deposit(preparations, 0);
            });
        }
        if cut == Some(first_turns) && live[0] {
            let before = holding.boundary();
            holding.drawn(preparations, 0, Retirement::Stopped, |preparation| {
                assert_eq!(
                    boundaries.last(),
                    Some(&support::classes::prepare(&preparation.value().position())),
                    "the recorded boundary must describe the state immediately before retirement"
                );
            });
            intervals.push(before..holding.boundary());
            retired = true;
            live[0] = false;
        }
        let slot = if interleaving.first(turn, live[0], live[1]) {
            first_turns += 1;
            0
        } else {
            1
        };
        if live[slot] {
            let publication =
                holding.drawn(preparations, slot, Retirement::Stopped, |preparation| {
                    // One turn: the controller admits the first and stops
                    // before the second.
                    let mut taken = false;
                    let plan = preparation.controlled(
                        policy,
                        2,
                        Retirement::Published,
                        true,
                        |_, _, _| core::mem::replace(&mut taken, true),
                        |plan| plan.deposit(plans, slot),
                    )?;
                    if plan.is_none() {
                        preparation.deposit(preparations, slot);
                    }
                    Ok::<_, Finding>(plan.is_some())
                })?;
            if publication {
                live[slot] = false;
                published[slot] = true;
            }
        }
        // The scope's queue stepped while the other preparation stays live:
        // the first's retired records drain beside it, each call the step
        // admits after the cut the retirement's cleanup.
        holding.holding(Lent::new(scope), Retirement::Exhausted, |view| {
            let before = view.boundary();
            let stepped = view.scope_step(policy, turn, |view, m| view.scope().step(m))?;
            view.with_policy(policy, |_, m| match stepped {
                Ok(Reclaimed::Progress | Reclaimed::Waiting | Reclaimed::Done) => Ok(()),
                Err(error) if support::ordinary_exhaustion(m, &error) => Ok(()),
                Err(error) => Err(Finding::Driver(format!(
                    "interleaved cleanup failed: {error:?}"
                ))),
            })?;
            if retired {
                intervals.push(before..view.boundary());
            }
            view.checkpoint();
            Ok::<_, Finding>(())
        })?;
        if !live[0] && !live[1] {
            break;
        }
    }
    if live[0] || live[1] {
        return Err(Finding::Driver(format!(
            "the shared-owner preparations exceeded their {turns} turns"
        )));
    }
    if retired != cut.is_some() {
        return Err(Finding::Driver(format!(
            "requested retirement {cut:?} was not reached"
        )));
    }
    if !published[1] {
        return Err(Finding::Driver(
            "the second did not publish beside the first's retirement".to_owned(),
        ));
    }
    holding.drawn(plans, 1, Retirement::Published, |plan| {
        let len = plan.value().len();
        plan.transfer(
            OwnedPrepared::into_writer,
            Retirement::Published,
            |writer| {
                let mut bytes = Vec::with_capacity(len);
                if !writer.emit(policy, &mut bytes, len, |_, _, _| false)? {
                    return Err(Finding::Driver("the second's emission stopped".to_owned()));
                }
                assert_eq!(bytes, dcbor::CBOR::from(TEXTS[1]).to_cbor_data());
                Ok(())
            },
        )
    })?;
    if published[0] {
        holding.drawn(plans, 0, Retirement::Published, |_| ());
    }
    // Every survivor operation has ended: what the scope admits from here
    // is its final drain.
    Ok(RetirementTrace {
        boundaries,
        intervals,
        drain_start: holding.boundary(),
    })
}

/// The boundaries a cut retires the first preparation at under `rigor`, of
/// its boundaries' classes `boundaries`: the exhaustive layer every one; the
/// fast layer the first boundary of each class and every boundary of none,
/// as every matrix's fast layer selects its stops ([`support::rigor`]). The
/// reduction is this test's own claim, not the single-pipeline
/// certification `classes::prepare` carries: the exhaustive layer requires
/// every member of a class, in its interleaving, to retire with the same
/// cleanup ([`retiring_each_preparation_boundary_preserves_other_operations`]).
fn cuts(
    rigor: support::rigor::Rigor,
    boundaries: &[Option<support::classes::Class>],
) -> Vec<usize> {
    let mut first = std::collections::BTreeSet::new();
    boundaries
        .iter()
        .enumerate()
        .filter(|(_, class)| {
            rigor == support::rigor::Rigor::Exhaustive
                || class
                    .as_ref()
                    .is_none_or(|class| first.insert(class.clone()))
        })
        .map(|(cut, _)| cut)
        .collect()
}

/// The first preparation retired at its boundaries, in every interleaving
/// with the second: the second publishes its exact bytes and the scope
/// recovers everything. Each boundary is classed by `classes::prepare` of
/// the first preparation's state where the cut retires it, which reads the
/// operation's own fields and the scope's outstanding record count, never
/// the survivor's state or the queue's custody; an interleaving's classes
/// are its own, each classed from its own uncut run. The fast layer retires
/// at the first boundary of each class and at every unclassified one, the
/// exhaustive layer at every boundary ([`cuts`]); the exhaustive layer then
/// requires every member of a class, in one interleaving, to retire with
/// the same cleanup ([`Interleaved::cleanup`], `support::agree`): the
/// evidence the fast layer's reduction rests on. The first preparation has
/// the same boundaries in every interleaving: its turns are its own,
/// whatever the other takes.
#[test]
fn retiring_each_preparation_boundary_preserves_other_operations() {
    let classed: Vec<(Interleaving, Vec<Option<support::classes::Class>>)> = INTERLEAVINGS
        .into_iter()
        .map(|interleaving| (interleaving, interleave(None, interleaving).boundaries))
        .collect();
    let boundaries = classed[0].1.len();
    assert!(boundaries > 0);
    for (interleaving, classes) in &classed {
        assert_eq!(
            classes.len(),
            boundaries,
            "{interleaving:?}: the first preparation's boundaries depend on the other's"
        );
    }
    let selected: Vec<(Interleaving, Vec<usize>)> = classed
        .iter()
        .map(|(interleaving, classes)| (*interleaving, cuts(support::rigor::rigor(), classes)))
        .collect();
    let mut progress = support::rigor::Progress::new("a preparation retired beside another");
    progress.stage(
        "a boundary of each class in every interleaving",
        selected.iter().map(|(_, cuts)| cuts.len()).sum(),
        boundaries * INTERLEAVINGS.len(),
    );
    // Every classed cut's cleanup, keyed by its interleaving and class: the
    // members of a class must clean up alike.
    let mut members = Vec::new();
    for ((interleaving, cuts), (_, classes)) in selected.iter().zip(&classed) {
        for &cut in cuts {
            let at = format!(
                "retired after {cut} turns, {interleaving:?}, class {:?}",
                classes[cut]
            );
            progress.case(&at);
            let retired = interleave(Some(cut), *interleaving);
            assert_eq!(
                retired.boundaries.get(cut),
                classes.get(cut),
                "{interleaving:?}, cut {cut}: retirement class differs from baseline"
            );
            if let Some(class) = &classes[cut] {
                members.push((
                    at,
                    (format!("{interleaving:?}"), class.clone()),
                    retired.cleanup,
                ));
            }
        }
    }
    support::agree("a preparation retired beside another", members);
}

/// A cut at the first preparation's first boundary is observed once both
/// preparations exist, and retires it as every other cut does.
#[test]
fn retirement_zero_is_observed_after_both_preparations_exist() {
    for interleaving in INTERLEAVINGS {
        let baseline = interleave(None, interleaving);
        for cut in [0, 1, 2] {
            let retired = interleave(Some(cut), interleaving);
            assert_eq!(
                retired.boundaries.get(cut),
                baseline.boundaries.get(cut),
                "{interleaving:?}, cut {cut}: baseline sampled another state"
            );
            assert!(
                !retired.cleanup.is_empty(),
                "cut {cut}: cleanup was not recorded"
            );
        }
    }
}

/// A requested cut beyond publication must not silently become an uncut run.
#[test]
#[should_panic(expected = "was not reached")]
fn a_retirement_past_publication_is_rejected() {
    interleave(Some(usize::MAX), Interleaving::FirstThenSecond);
}

/// The comparison the reduction rests on refuses a planted class merging two
/// boundaries whose retirements clean up differently: the first boundary,
/// before the first preparation took a turn, and its last before it
/// publishes, each retired beside the second.
#[test]
#[should_panic(expected = "clean up differently")]
fn a_class_merging_retirements_of_different_cleanup_is_rejected() {
    let boundaries = interleave(None, Interleaving::FirstThenSecond)
        .boundaries
        .len();
    let planted = ("FirstThenSecond".to_owned(), "planted".to_owned());
    support::agree(
        "a planted preparation class",
        [0, boundaries - 1].map(|cut| {
            (
                format!("retired after {cut} turns"),
                planted.clone(),
                interleave(Some(cut), Interleaving::FirstThenSecond).cleanup,
            )
        }),
    );
}

/// The fast layer's cuts are the first boundary of each class and every
/// unclassified boundary; the exhaustive layer's, every boundary.
#[test]
fn the_fast_layer_retires_once_per_class() {
    use support::rigor::Rigor;
    let class = |name: &str| Some(name.to_owned());
    let boundaries = [class("a"), class("a"), None, class("b"), None, class("a")];
    assert_eq!(cuts(Rigor::Fast, &boundaries), [0, 2, 3, 4]);
    assert_eq!(cuts(Rigor::Exhaustive, &boundaries), [0, 1, 2, 3, 4, 5]);
}

/// Two plans of one scope, published and held beside it: a shutdown with
/// them live closes the queue and cannot complete; the authority is then
/// dropped, the scope abandoned to the plans' references
/// ([`Retirement::Abandoned`]); and the two plans are retired at once, each
/// destroyed on a worker thread of its own, the workers released together
/// ([`Holding::retire_concurrently`]), so the two last references race to
/// release the scope, whichever is last draining it terminally
/// ([`Retirement::LastReference`]). In either order of the plans' slots no
/// record or block is released twice: the retirement's rule and the run's
/// refinement hold it, and nothing remains live.
#[test]
fn cross_thread_plan_retirement_races_with_shutdown_without_double_release() {
    for reverse in [false, true] {
        support::recorded_run(|run| {
            let policy = run.policy(u64::MAX);
            run.holding(
                CustodyBatch::<Plan>::slots(2),
                Retirement::LastReference,
                &Unwitnessed,
                |plans| {
                    plans.lending(Retirement::Exhausted, Lent::new, |lent| {
                        let batch = lent.value().get();
                        lent.holding(DecodeOwner::new(), Retirement::Abandoned, |owner| {
                            owner.initialize(policy)?;
                            for (index, text) in ["first", "second"].into_iter().enumerate() {
                                let slot = if reverse { 1 - index } else { index };
                                let wire = dcbor::CBOR::from(text).to_cbor_data();
                                owner.copied(policy, &wire, |input| {
                                    input.decode::<String, _>(
                                        policy,
                                        Options::normalizing(8),
                                        |value| {
                                            value.prepare(policy, |plan| plan.deposit(batch, slot))
                                        },
                                    )
                                })???;
                            }
                            let shutdown =
                                owner.scope_step(policy, 0, |owner, m| owner.shutdown_step(m))?;
                            assert_ne!(
                                shutdown.ok(),
                                Some(Reclaimed::Done),
                                "shutdown completed with live plans"
                            );
                            Ok::<_, Finding>(())
                        })
                    })?;
                    plans.retire_concurrently();
                    Ok::<_, Finding>(())
                },
            )?;
            run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0));
            Ok(())
        });
    }
}

/// `T` decoded from `wire` in a scope of a recorded run, `inspect` reading
/// the value, then prepared with every turn on a worker thread of its own
/// ([`Holding::drive_threaded`]), the preparation read in the parent between
/// turns, and its plan emitted: the bytes emitted, and whether a retained
/// entry cursor and a retained normalization each crossed a worker boundary.
#[cfg(feature = "custom-std-collections")]
fn prepared_across_workers<T>(wire: &[u8], inspect: impl FnOnce(&T)) -> (Vec<u8>, bool, bool)
where
    T: dcbor::bounded::decode::construction::in_place::Transferable<Limits>
        + dcbor::bounded::encoding::TransferableSchema
        + Send
        + 'static,
{
    support::recorded_run(|run| {
        let policy = run.policy(u64::MAX);
        let made = run.scoped(policy, &Unwitnessed, |owner| {
            owner.copied(policy, wire, |input| {
                input.decode::<T, _>(policy, Options::normalizing(16), |value| {
                    inspect(value.value().value());
                    let turns = support::turns(
                        dcbor::bounded::encoding::owned_prepare_bound::<ByteString, T, Limits, ()>(
                            support::shape(value.value().value()),
                        )
                        .expect("the preparation bound of a decoded value fits in u64"),
                    );
                    value.transfer(
                        OwnedPreparation::prepare,
                        Retirement::Stopped,
                        |preparation| {
                            let (mut cursor, mut normalization) = (false, false);
                            let bytes = preparation.drive_threaded(
                                policy,
                                turns,
                                Retirement::Published,
                                |_, preparation| {
                                    if let Some(position) =
                                        preparation.position().detail.preparation
                                    {
                                        cursor |= position.cursors != 0;
                                        normalization |= position.normalizing
                                            && position.normalization.is_some();
                                    }
                                },
                                |plan| {
                                    let len = plan.value().len();
                                    plan.transfer(
                                        OwnedPrepared::into_writer,
                                        Retirement::Published,
                                        |writer| {
                                            let mut bytes = Vec::with_capacity(len);
                                            writer
                                                .emit(policy, &mut bytes, len, |_, _, _| false)?;
                                            Ok::<_, Finding>(bytes)
                                        },
                                    )
                                },
                            )??;
                            Ok::<_, Finding>((bytes, cursor, normalization))
                        },
                    )
                })
            })??
        })?;
        run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0));
        Ok(made)
    })
}

/// Every turn of a map's preparation taken on a worker thread of its own,
/// the suspended preparation moved between them. The test requires a
/// retained entry cursor and a retained normalization each to cross a worker
/// boundary. At minimal witness sizes the map holds 12 entries, the fewest
/// whose tree has an internal node (a full leaf holds 11), each value of 16
/// mark pairs as at full sizes: the reach map requires every region the full
/// sizes execute (`tests/reach-map.sh`), and two entries of four pairs left
/// the tree's internal-node paths, the one-byte text head and the
/// character arena's later growth unexecuted.
#[test]
#[cfg(feature = "custom-std-collections")]
fn suspended_entry_cursors_and_texts_transfer_between_workers() {
    use dcbor_test_support::rigor::sized;
    use std::collections::BTreeMap;
    let (entries, pairs) = sized((16, 16), (12, 16));
    let source: BTreeMap<String, String> = (0..entries)
        .map(|index| {
            (
                format!("key-{index:02}"),
                format!("q{}", "\u{301}\u{316}".repeat(pairs)),
            )
        })
        .collect();
    let mut symbolic = dcbor::Map::new();
    for (key, value) in &source {
        symbolic.insert(key.clone(), value.clone()).unwrap();
    }
    let wire = dcbor::CBOR::from(symbolic).to_cbor_data();
    let (bytes, observed_cursor, observed_normalization) =
        prepared_across_workers::<BTreeMap<String, String>>(&wire, |_| {});
    assert_eq!(bytes, wire);
    assert!(
        observed_cursor,
        "no retained cursor crossed a worker boundary"
    );
    assert!(
        observed_normalization,
        "no retained normalization crossed a worker boundary"
    );
}

/// The derive's generated `TransferableSchema` impl exercised: every turn
/// of a derived record's preparation taken on a worker thread of its own,
/// the suspended preparation moved between them, as the map's above. The
/// record holds a map and a text, so a retained entry cursor reached through
/// the generated field instructions, and a retained normalization of a
/// generated field's text, each cross a worker boundary. The unsafe census
/// lists the generator's impl (`dcbor-derive/src/encoding.rs`, `expand`);
/// this is what that impl does, run under Miri (`tests/miri-suites.txt`).
/// Sizes as the map's: 12 entries at minimal witness sizes, the fewest whose
/// tree has an internal node.
#[test]
#[cfg(all(feature = "derive", feature = "custom-std-collections"))]
fn a_derived_records_preparation_transfers_between_workers() {
    use dcbor_test_support::rigor::sized;
    use std::collections::BTreeMap;

    #[derive(dcbor::CBORBoundedDecodable, dcbor::CBORBoundedEncodable)]
    struct Record {
        #[cbor(n = 1)]
        entries: BTreeMap<String, String>,
        #[cbor(n = 2)]
        text: String,
    }

    let (entries, pairs) = sized((16, 16), (12, 16));
    let marks = || format!("q{}", "\u{301}\u{316}".repeat(pairs));
    let mut symbolic_entries = dcbor::Map::new();
    for index in 0..entries {
        symbolic_entries
            .insert(format!("key-{index:02}"), marks())
            .unwrap();
    }
    let mut symbolic = dcbor::Map::new();
    symbolic.insert(1u64, symbolic_entries).unwrap();
    symbolic.insert(2u64, marks()).unwrap();
    let wire = dcbor::CBOR::from(symbolic).to_cbor_data();
    let (bytes, observed_cursor, observed_normalization) =
        prepared_across_workers::<Record>(&wire, |record| {
            assert_eq!(record.entries.len(), entries);
        });
    assert_eq!(bytes, wire);
    assert!(
        observed_cursor,
        "no retained cursor of the derived record crossed a worker boundary"
    );
    assert!(
        observed_normalization,
        "no retained normalization of the derived record crossed a worker boundary"
    );
}
