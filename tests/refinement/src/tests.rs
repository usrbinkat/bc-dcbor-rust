//! The machine over production-shaped streams: accepted runs, and one
//! planted divergence per rule a recorder or the production transitions
//! could break, each refused by name at its point.

use crate::model::{At, Divergence, Outcome, Rule};
use crate::text::{parse_run, render_run};
use crate::{
    Answer, Call, Cause, Checkpoint, Class, Credit, Custody, Effect, End, Event, Forfeit, Hold,
    Identity, LimitRefusal, Obligation, Observed, Performer, Publication, Row, Run, Settled,
    WriteWork, check, parse_row, settled,
};

fn id(family: u64, sequence: u64) -> Identity {
    Identity::new(family, sequence)
}

fn at(family: u64, policy: Option<u64>, event: Event) -> Observed {
    Observed {
        family,
        by: policy.map_or(Performer::None, Performer::Policy),
        event,
    }
}

fn work(values: u64, bytes: u64) -> Call {
    Call::Work { values, bytes }
}

fn hold(obligation: Obligation, work: WriteWork, sequence: u64, acquisition: Identity) -> Hold {
    Hold {
        obligation,
        work,
        id: id(1, sequence),
        acquisition,
    }
}

fn settlement(hold: Hold, permit: Option<Identity>) -> Settled {
    Settled {
        obligation: hold.obligation,
        work: hold.work,
        id: hold.id,
        acquisition: hold.acquisition,
        permit,
    }
}

const GRANT: WriteWork = WriteWork::new(0, 8);
const RELEASE: WriteWork = WriteWork::new(1, 16);
const OWNER: Identity = Identity::new(1, 1);
const ACQUISITION: Identity = Identity::new(1, 2);
const PERMIT: Identity = Identity::new(1, 5);

fn grant() -> Hold {
    hold(Obligation::Grant, GRANT, 3, ACQUISITION)
}

fn release() -> Hold {
    hold(Obligation::Release, RELEASE, 4, ACQUISITION)
}

/// One acquisition of family 1's policy 1, the production order
/// (`stable.rs` `grant`, `Owned::reserve`): the owner made, the acquisition
/// bound, its grant's work and its release admitted held, the request
/// granted, the release spent at the permit, the reservation made, the
/// grant spent at the permit; the output's permit then dropped; the
/// acquisition's end last (`Pending::complete`, published by family 1,
/// which minted it): every index before it is the acquisition's own.
fn acquired() -> Vec<Observed> {
    let p = Some(1);
    vec![
        at(1, p, Event::Owner(OWNER)),
        at(
            1,
            p,
            Event::Bound {
                acquisition: ACQUISITION,
                owner: OWNER,
            },
        ),
        at(1, p, Event::Call(work(0, 8), Answer::Admitted)),
        at(
            1,
            p,
            Event::Credit(Credit::Admit {
                work: GRANT,
                held: Some(grant()),
            }),
        ),
        at(1, p, Event::Call(work(1, 16), Answer::Admitted)),
        at(
            1,
            p,
            Event::Credit(Credit::Admit {
                work: RELEASE,
                held: Some(release()),
            }),
        ),
        at(
            1,
            p,
            Event::Call(Call::Allocate(32), Answer::Granted(PERMIT)),
        ),
        at(
            1,
            p,
            Event::Credit(Credit::Spend(settlement(release(), Some(PERMIT)))),
        ),
        at(
            1,
            p,
            Event::Effect(Effect::Reserved {
                permit: PERMIT,
                acquisition: ACQUISITION,
            }),
        ),
        at(
            1,
            p,
            Event::Credit(Credit::Spend(settlement(grant(), Some(PERMIT)))),
        ),
        at(1, None, Event::Released(PERMIT)),
        at(
            1,
            p,
            Event::End {
                acquisition: ACQUISITION,
                owner: OWNER,
            },
        ),
    ]
}

/// The end of the fixture acquisition, published by family 1 under `by`.
fn ended(by: Option<u64>) -> Observed {
    at(
        1,
        by,
        Event::End {
            acquisition: ACQUISITION,
            owner: OWNER,
        },
    )
}

/// The fixture owner's custody at a checkpoint before its acquisition's
/// end: the acquisition reported bound, credit or none, as a pending
/// reports it from its bind to its end; `held` and `permits` (ordinary
/// permits, no record block's) as given.
fn custody(held: Vec<Hold>, permits: Vec<Identity>) -> Vec<Custody> {
    vec![Custody {
        owner: OWNER,
        bound: vec![ACQUISITION],
        held,
        permits: permits.into_iter().map(ordinary).collect(),
    }]
}

/// A permit reported as no record block.
fn ordinary(permit: Identity) -> crate::Reported {
    crate::Reported {
        permit,
        record: None,
    }
}

/// [`acquired`], checkpointed with both obligations held and with the
/// permit owned, then published.
fn published() -> Run {
    Run {
        observed: acquired(),
        checkpoints: vec![
            Checkpoint {
                boundary: 6,
                custody: custody(vec![grant(), release()], Vec::new()),
            },
            Checkpoint {
                boundary: 10,
                custody: custody(Vec::new(), vec![PERMIT]),
            },
        ],
        cleaning: None,
        published: Some(Publication {
            boundary: 10,
            permits: vec![PERMIT],
        }),
        end: End::Published,
    }
}

/// The same acquisition cancelled once both obligations are held: cleanup
/// begins, then policy 2 forfeits each into family 1 with no call of
/// policy 1 between, so both checkpoints follow the same two calls of
/// policy 1 and hold different custody.
fn cancelled() -> Run {
    let mut observed = acquired();
    observed.truncate(6);
    for held in [grant(), release()] {
        observed.push(at(
            1,
            Some(2),
            Event::Credit(Credit::Forfeit(settlement(held, None), Forfeit::Cancelled)),
        ));
    }
    observed.push(ended(Some(2)));
    Run {
        observed,
        checkpoints: vec![
            Checkpoint {
                boundary: 6,
                custody: custody(vec![grant(), release()], Vec::new()),
            },
            Checkpoint {
                boundary: 8,
                custody: custody(Vec::new(), Vec::new()),
            },
        ],
        cleaning: Some((6, Cause::Cancel)),
        published: None,
        end: End::Cancelled,
    }
}

fn refused(run: &Run) -> Divergence {
    check(run).expect_err("a planted divergence was accepted")
}

fn rule(run: &Run) -> Rule {
    refused(run).rule
}

#[test]
fn the_production_runs_are_accepted() {
    assert_eq!(check(&published()), Ok(()));
    assert_eq!(check(&cancelled()), Ok(()));
    assert_eq!(settled(&published().observed, &[]), Ok(()));
    assert_eq!(
        settled(&cancelled().observed, &cancelled().checkpoints),
        Ok(())
    );
}

/// Planted control: equal policy call counts, custody moved across the
/// cancellation's settlement. Either checkpoint at the other's boundary is
/// refused; only the stream position, never the call count, places it.
#[test]
fn a_checkpoint_moved_across_a_cancellation_is_refused() {
    let mut early = cancelled();
    early.checkpoints[1].boundary = 6;
    assert_eq!(
        rule(&early),
        Rule::MissingHeld {
            owner: OWNER,
            obligation: grant().id
        }
    );
    let mut late = cancelled();
    late.checkpoints[0].boundary = 8;
    assert_eq!(
        rule(&late),
        Rule::ExtraHeld {
            owner: OWNER,
            obligation: grant().id
        }
    );
}

/// Planted controls: an equal-sized obligation substituted in a checkpoint,
/// its remaining work misreported, and its acquisition changed.
#[test]
fn a_substituted_or_misreported_obligation_is_refused() {
    // The reported obligations are walked first (`Machine::checkpoint`), so
    // the substitute is refused as reported-but-not-held before the
    // obligation it displaced is found unreported.
    let mut substituted = published();
    substituted.checkpoints[0].custody[0].held[0].id = id(1, 9);
    assert_eq!(
        rule(&substituted),
        Rule::ExtraHeld {
            owner: OWNER,
            obligation: id(1, 9)
        }
    );
    let mut misreported = published();
    misreported.checkpoints[0].custody[0].held[1].work = WriteWork::new(1, 15);
    assert_eq!(
        rule(&misreported),
        Rule::HeldMismatch {
            obligation: release().id,
            remaining: RELEASE,
            reported: WriteWork::new(1, 15)
        }
    );
    let mut reassigned = published();
    reassigned.checkpoints[0].custody[0].held[0].acquisition = id(1, 9);
    assert_eq!(
        rule(&reassigned),
        Rule::AcquisitionMismatch {
            obligation: grant().id,
            held: ACQUISITION,
            named: id(1, 9)
        }
    );
}

/// Planted controls of owner-by-owner custody: an owner holding obligations
/// left out of the observation, a published permit no longer reported under
/// the owner whose acquisition paid for it (reported nowhere, or under an
/// owner reported empty), an owner reported twice, and an owner the stream
/// never made. Publication moves who holds a value, not whose custody it is.
#[test]
fn every_owner_holding_custody_is_reported_once_under_its_own_identity() {
    let mut unreported = published();
    unreported.checkpoints[0].custody.clear();
    assert_eq!(
        refused(&unreported),
        Divergence {
            at: At::Checkpoint(0),
            rule: Rule::MissingHeld {
                owner: OWNER,
                obligation: grant().id
            }
        }
    );
    let mut omitted = published();
    omitted.checkpoints[1].custody.clear();
    assert_eq!(
        refused(&omitted),
        Divergence {
            at: At::Checkpoint(1),
            rule: Rule::MissingPermit {
                owner: OWNER,
                permit: PERMIT
            }
        }
    );
    let mut emptied = published();
    emptied.checkpoints[1].custody = custody(Vec::new(), Vec::new());
    assert_eq!(
        rule(&emptied),
        Rule::MissingPermit {
            owner: OWNER,
            permit: PERMIT
        }
    );
    let mut twice = published();
    twice.checkpoints[1].custody.push(Custody {
        owner: OWNER,
        bound: Vec::new(),
        held: Vec::new(),
        permits: Vec::new(),
    });
    assert_eq!(rule(&twice), Rule::Duplicate(OWNER));
    let mut stranger = published();
    stranger.checkpoints[1].custody[0].owner = id(1, 9);
    assert_eq!(rule(&stranger), Rule::UnknownOwner(id(1, 9)));
}

/// Planted controls: a boundary past the stream, checkpoints out of order,
/// and a checkpoint inside the acquisition (granted, release unspent).
#[test]
fn every_misplaced_boundary_is_refused() {
    let mut past = published();
    past.checkpoints[1].boundary = 13;
    assert_eq!(
        refused(&past),
        Divergence {
            at: At::Checkpoint(1),
            rule: Rule::BoundaryPastEnd {
                boundary: 13,
                len: 12
            }
        }
    );
    let mut decreasing = published();
    decreasing.checkpoints.swap(0, 1);
    assert_eq!(
        rule(&decreasing),
        Rule::BoundaryDecreasing {
            boundary: 6,
            previous: 10
        }
    );
    let mut inside = published();
    inside.checkpoints[0] = Checkpoint {
        boundary: 7,
        custody: custody(vec![grant(), release()], Vec::new()),
    };
    assert_eq!(rule(&inside), Rule::MidStep);
}

/// Planted control: a settlement published by a family other than its
/// obligation's origin (`Family::settle` publishes through the origin).
#[test]
fn a_settlement_into_another_family_is_refused() {
    let mut run = published();
    run.observed[7].family = 2;
    assert_eq!(
        refused(&run),
        Divergence {
            at: At::Observation(7),
            rule: Rule::WrongFamily {
                identity: release().id,
                publisher: 2
            }
        }
    );
}

/// Planted controls: a settlement and an outcome naming another acquisition,
/// and a grant spent at a known permit of no acquisition of its own.
#[test]
fn a_wrong_acquisition_or_permit_is_refused() {
    let mut settled_elsewhere = published();
    settled_elsewhere.observed[9] = at(
        1,
        Some(1),
        Event::Credit(Credit::Spend(Settled {
            acquisition: id(1, 9),
            ..settlement(grant(), Some(PERMIT))
        })),
    );
    assert_eq!(
        rule(&settled_elsewhere),
        Rule::AcquisitionMismatch {
            obligation: grant().id,
            held: ACQUISITION,
            named: id(1, 9)
        }
    );
    let mut effect = published();
    effect.observed[8] = at(
        1,
        Some(1),
        Event::Effect(Effect::Reserved {
            permit: PERMIT,
            acquisition: id(1, 9),
        }),
    );
    assert_eq!(
        rule(&effect),
        Rule::PermitAcquisition {
            permit: PERMIT,
            bound: Some(ACQUISITION),
            named: id(1, 9)
        }
    );
    // The stream alone ([`settled`]): the run's marks sit at boundaries the
    // inserted grant shifts, and a checkpoint right after an unpaid grant is
    // refused as mid-step before the settlement this control plants.
    let other = id(1, 6);
    let mut substituted = published();
    substituted.observed.insert(
        9,
        at(
            1,
            Some(1),
            Event::Call(Call::Allocate(32), Answer::Granted(other)),
        ),
    );
    substituted.observed[10] = at(
        1,
        Some(1),
        Event::Credit(Credit::Spend(settlement(grant(), Some(other)))),
    );
    assert_eq!(
        settled(&substituted.observed, &[]).map_err(|divergence| divergence.rule),
        Err(Rule::PermitAcquisition {
            permit: other,
            bound: None,
            named: ACQUISITION
        })
    );
}

/// Planted control: the grant spent with no observed reservation; and a
/// release forfeited at the permit it was spent at.
#[test]
fn a_missing_physical_effect_is_refused() {
    let mut run = published();
    run.observed.remove(8);
    assert_eq!(
        rule(&run),
        Rule::MissingEffect {
            permit: PERMIT,
            required: Outcome::Reserved
        }
    );
    let mut forfeited = published();
    forfeited.observed[7] = at(
        1,
        Some(1),
        Event::Credit(Credit::Forfeit(
            settlement(release(), Some(PERMIT)),
            Forfeit::Cancelled,
        )),
    );
    assert_eq!(
        rule(&forfeited),
        Rule::ReleaseForfeitedAfterGrant(release().id)
    );
}

/// Two complete payload acquisitions of 8 bytes each by owner `1.1`, in the
/// production order (`stable.rs` `allocate_payload`): acquisition `1.2`
/// pays release `1.4` and is granted `p` (`1.5`), acquisition `1.3` pays
/// release `1.6` and is granted `q` (`1.7`), each release spent at its
/// permit and each reservation observed made; both acquisitions ended, then
/// `p` and `q` dropped.
fn two_acquired() -> (Vec<Observed>, Identity, Identity) {
    let (p, q) = (id(1, 5), id(1, 7));
    let pol = Some(1);
    let mut observed = vec![
        at(1, pol, Event::Owner(OWNER)),
        at(
            1,
            pol,
            Event::Bound {
                acquisition: id(1, 2),
                owner: OWNER,
            },
        ),
        at(
            1,
            pol,
            Event::Bound {
                acquisition: id(1, 3),
                owner: OWNER,
            },
        ),
    ];
    for (acquisition, release, permit) in [(id(1, 2), 4, p), (id(1, 3), 6, q)] {
        let held = hold(Obligation::Release, RELEASE, release, acquisition);
        observed.extend([
            at(1, pol, Event::Call(work(1, 16), Answer::Admitted)),
            at(
                1,
                pol,
                Event::Credit(Credit::Admit {
                    work: RELEASE,
                    held: Some(held),
                }),
            ),
            at(
                1,
                pol,
                Event::Call(Call::Allocate(8), Answer::Granted(permit)),
            ),
            at(
                1,
                pol,
                Event::Credit(Credit::Spend(settlement(held, Some(permit)))),
            ),
            at(
                1,
                pol,
                Event::Effect(Effect::Reserved {
                    permit,
                    acquisition,
                }),
            ),
        ]);
    }
    for acquisition in [id(1, 2), id(1, 3)] {
        observed.push(at(
            1,
            pol,
            Event::End {
                acquisition,
                owner: OWNER,
            },
        ));
    }
    observed.extend([
        at(1, None, Event::Released(p)),
        at(1, None, Event::Released(q)),
    ]);
    (observed, p, q)
}

/// Planted controls of exact-once release by identity over complete
/// acquisition streams ([`settled`], the rules every recorded session is
/// held to): the unchanged stream settles; `q`'s release replaced by a
/// second release of `p` (two releases and sixteen bytes released either
/// way, which a count accepts) is refused at the duplicate; `q`'s release
/// dropped leaks `q`; a merged input released, a cross-family split and an
/// unknown release are refused.
#[test]
fn every_release_is_checked_by_identity() {
    let settled = |observed: &[Observed]| crate::settled(observed, &[]);
    let (stream, p, q) = two_acquired();
    let last = stream.len() - 1;
    assert_eq!(settled(&stream), Ok(()));
    let mut duplicate = stream.clone();
    duplicate[last] = at(1, None, Event::Released(p));
    assert_eq!(
        settled(&duplicate),
        Err(Divergence {
            at: At::Observation(last),
            rule: Rule::PermitLife {
                permit: p,
                life: crate::model::Life::Released
            }
        })
    );
    let mut missing = stream.clone();
    missing.truncate(last);
    assert_eq!(
        settled(&missing),
        Err(Divergence {
            at: At::End,
            rule: Rule::Leaked(q)
        })
    );
    let merge = at(
        1,
        None,
        Event::Merge {
            survivor: p,
            retired: q,
            bytes: 8,
        },
    );
    let mut merged = stream.clone();
    merged.truncate(last - 1);
    merged.extend([merge, at(1, None, Event::Released(p))]);
    assert_eq!(settled(&merged), Ok(()));
    let mut merged_released = merged.clone();
    merged_released.push(at(1, None, Event::Released(q)));
    assert_eq!(
        settled(&merged_released).map_err(|d| d.rule),
        Err(Rule::PermitLife {
            permit: q,
            life: crate::model::Life::Retired
        })
    );
    let mut foreign = stream.clone();
    foreign.insert(
        last - 1,
        at(
            1,
            None,
            Event::Split {
                parent: p,
                child: id(2, 1),
                bytes: 4,
            },
        ),
    );
    assert_eq!(
        settled(&foreign).map_err(|d| d.rule),
        Err(Rule::ForeignTransfer {
            left: p,
            right: id(2, 1)
        })
    );
    let mut unknown = stream;
    unknown.push(at(1, None, Event::Released(id(1, 9))));
    assert_eq!(
        settled(&unknown).map_err(|d| d.rule),
        Err(Rule::UnknownPermit(id(1, 9)))
    );
}

/// A whole session is held to the same admission, payment and outcome
/// rules as a recorded run: an admitted call never admitted, a grant whose
/// release is never paid, and a paid grant whose outcome is never observed
/// are each refused by [`settled`] as by [`check`].
#[test]
fn a_session_is_held_to_the_runs_rules() {
    let settled = |observed: &[Observed]| crate::settled(observed, &[]);
    let call = at(1, Some(1), Event::Call(work(1, 0), Answer::Admitted));
    assert_eq!(
        settled(&[call]).map_err(|d| d.rule),
        Err(Rule::MissingAdmission(WriteWork::new(1, 0)))
    );
    let granted = at(
        1,
        Some(1),
        Event::Call(Call::Allocate(8), Answer::Granted(id(1, 1))),
    );
    assert_eq!(
        settled(&[granted, at(1, None, Event::Released(id(1, 1)))]).map_err(|d| d.rule),
        Err(Rule::Unpaid(id(1, 1)))
    );
    let (mut stream, p, _) = two_acquired();
    // `p`'s reservation outcome removed: paid, never observed made.
    stream.remove(7);
    assert_eq!(settled(&stream).map_err(|d| d.rule), Err(Rule::NoEffect(p)));
}

/// In a recorded run a granted permit whose release was never spent is
/// unpaid when it drops; an admission no call made, and a call whose
/// admission never came, are refused.
#[test]
fn admission_and_payment_correspondence_is_checked() {
    let mut unpaid = published();
    unpaid.observed.truncate(7);
    unpaid.observed.push(at(1, None, Event::Released(PERMIT)));
    unpaid.checkpoints.clear();
    unpaid.published = None;
    unpaid.cleaning = Some((7, Cause::Cancel));
    unpaid.end = End::Cancelled;
    assert_eq!(rule(&unpaid), Rule::Unpaid(PERMIT));
    let mut unauthorized = published();
    unauthorized.observed.remove(2);
    assert_eq!(rule(&unauthorized), Rule::UnauthorizedAdmission(GRANT));
    let mut missing = published();
    missing.observed.remove(3);
    assert_eq!(rule(&missing), Rule::MissingAdmission(GRANT));
}

/// The invalid transitions credit conservation is proved without
/// (`src/bounded/policy/proofs.rs`, `legal_transitions_conserve_every_family`):
/// an obligation settled for more than it holds, and one settled again once
/// nothing remains. The machine refuses both by the same rule: a settled
/// obligation is kept with nothing remaining (`machine.rs` `settle`), so a
/// second settlement overdraws it rather than naming an unknown one.
#[test]
fn an_over_settled_or_twice_settled_obligation_is_refused() {
    let settled = |observed: &[Observed]| crate::settled(observed, &[]);
    let mut held = acquired();
    held.truncate(6);
    let mut over = held.clone();
    over.push(at(
        1,
        Some(1),
        Event::Credit(Credit::Forfeit(
            Settled {
                work: WriteWork::new(1, 17),
                ..settlement(release(), None)
            },
            Forfeit::Cancelled,
        )),
    ));
    assert_eq!(
        settled(&over),
        Err(Divergence {
            at: At::Observation(6),
            rule: Rule::Overdrawn {
                obligation: release().id,
                remaining: RELEASE,
                settled: WriteWork::new(1, 17)
            }
        })
    );
    let mut twice = held;
    let forfeit = at(
        1,
        Some(1),
        Event::Credit(Credit::Forfeit(
            settlement(grant(), None),
            Forfeit::Cancelled,
        )),
    );
    twice.extend([forfeit, forfeit]);
    assert_eq!(
        settled(&twice),
        Err(Divergence {
            at: At::Observation(7),
            rule: Rule::Overdrawn {
                obligation: grant().id,
                remaining: WriteWork::default(),
                settled: GRANT
            }
        })
    );
}

/// `run` with every family, performer and identity renamed consistently,
/// across its observations, checkpoints and publication: family 1 to 7,
/// identity `1.n` to `7.(n + 10)`, policy `n` to `n + 4`. A bijection on
/// everything the run names.
fn renamed(run: &Run) -> Run {
    let family = |family: u64| if family == 1 { 7 } else { family };
    let identity =
        |identity: Identity| Identity::new(family(identity.family()), identity.sequence() + 10);
    let hold = |hold: Hold| Hold {
        id: identity(hold.id),
        acquisition: identity(hold.acquisition),
        ..hold
    };
    let settled = |settled: Settled| Settled {
        id: identity(settled.id),
        acquisition: identity(settled.acquisition),
        permit: settled.permit.map(identity),
        ..settled
    };
    let event = |event: Event| match event {
        Event::Call(call, Answer::Granted(permit)) => {
            Event::Call(call, Answer::Granted(identity(permit)))
        }
        Event::Call(call, answer) => Event::Call(call, answer),
        Event::Credit(Credit::Admit { work, held }) => Event::Credit(Credit::Admit {
            work,
            held: held.map(hold),
        }),
        Event::Credit(Credit::Spend(spent)) => Event::Credit(Credit::Spend(settled(spent))),
        Event::Credit(Credit::Forfeit(forfeited, rule)) => {
            Event::Credit(Credit::Forfeit(settled(forfeited), rule))
        }
        Event::Effect(Effect::Reserved {
            permit,
            acquisition,
        }) => Event::Effect(Effect::Reserved {
            permit: identity(permit),
            acquisition: identity(acquisition),
        }),
        Event::Effect(Effect::Failed {
            permit,
            acquisition,
        }) => Event::Effect(Effect::Failed {
            permit: identity(permit),
            acquisition: identity(acquisition),
        }),
        Event::Split {
            parent,
            child,
            bytes,
        } => Event::Split {
            parent: identity(parent),
            child: identity(child),
            bytes,
        },
        Event::Merge {
            survivor,
            retired,
            bytes,
        } => Event::Merge {
            survivor: identity(survivor),
            retired: identity(retired),
            bytes,
        },
        Event::Released(permit) => Event::Released(identity(permit)),
        Event::Owner(owner) => Event::Owner(identity(owner)),
        Event::Bound { acquisition, owner } => Event::Bound {
            acquisition: identity(acquisition),
            owner: identity(owner),
        },
        Event::End { acquisition, owner } => Event::End {
            acquisition: identity(acquisition),
            owner: identity(owner),
        },
        Event::Custody {
            permit,
            owner,
            stage,
        } => Event::Custody {
            permit: identity(permit),
            owner: identity(owner),
            stage,
        },
    };
    Run {
        observed: run
            .observed
            .iter()
            .map(|observed| Observed {
                family: family(observed.family),
                by: match observed.by {
                    Performer::Policy(policy) => Performer::Policy(policy + 4),
                    Performer::None => Performer::None,
                },
                event: event(observed.event),
            })
            .collect(),
        checkpoints: run
            .checkpoints
            .iter()
            .map(|checkpoint| Checkpoint {
                boundary: checkpoint.boundary,
                custody: checkpoint
                    .custody
                    .iter()
                    .map(|custody| Custody {
                        owner: identity(custody.owner),
                        bound: custody.bound.iter().copied().map(identity).collect(),
                        held: custody.held.iter().copied().map(hold).collect(),
                        permits: custody
                            .permits
                            .iter()
                            .map(|reported| crate::Reported {
                                permit: identity(reported.permit),
                                record: reported.record,
                            })
                            .collect(),
                    })
                    .collect(),
            })
            .collect(),
        cleaning: run.cleaning,
        published: run.published.as_ref().map(|publication| Publication {
            boundary: publication.boundary,
            permits: publication.permits.iter().copied().map(identity).collect(),
        }),
        end: run.end,
    }
}

/// A row renders its run canonically and reads back equal. Canonical
/// numbering: the run renamed consistently (families, performers and
/// identities across observations, checkpoints and publication) renders
/// exactly as the original and is accepted alike; a renaming that is not
/// consistent (one observation's family alone) is refused by the machine,
/// and text not canonical is refused by the parser.
#[test]
fn a_row_round_trips_in_canonical_text() {
    let row = Row {
        name: "acquisition".into(),
        feature: None,
        outcome: crate::Outcome::Published,
        run: published(),
    };
    let text = row.render().expect("an accepted run renders");
    assert_eq!(parse_row(&text), Ok(row.clone()));
    let renamed = renamed(&published());
    assert_ne!(renamed, published(), "the renaming changed nothing");
    assert_eq!(check(&renamed), Ok(()));
    assert_eq!(render_run(&renamed), render_run(&published()));
    let mut inconsistent = published();
    inconsistent.observed[0].family = 7;
    assert_eq!(
        rule(&inconsistent),
        Rule::WrongFamily {
            identity: OWNER,
            publisher: 7
        }
    );
    let (observed, marks, end) = render_run(&published());
    assert!(parse_run(&observed.replacen("1 1 ", "2 1 ", 1), &marks, &end).is_err());
    let claimed = text.replace("\tobserved\t", "\tchecked\t");
    assert!(parse_row(&claimed).is_err(), "a row claiming another class");
}

/// The divergence `run` is refused with.
fn divergence(run: &Run) -> Divergence {
    refused(run)
}

/// The divergence a whole session's stream is refused with ([`settled`]).
fn session(observed: &[Observed]) -> Divergence {
    settled(observed, &[]).expect_err("a planted divergence was accepted")
}

fn observation(index: usize, rule: Rule) -> Divergence {
    Divergence {
        at: At::Observation(index),
        rule,
    }
}

/// Planted controls of identity minting (`Machine::mint`): an owner of no
/// recorded family, and an acquisition minted under an identity already
/// minted.
#[test]
fn an_unobserved_or_reissued_identity_is_refused() {
    let mut unobserved = published();
    unobserved.observed[0].event = Event::Owner(Identity::UNOBSERVED);
    assert_eq!(divergence(&unobserved), observation(0, Rule::Unobserved));
    let mut reissued = published();
    reissued.observed[1].event = Event::Bound {
        acquisition: OWNER,
        owner: OWNER,
    };
    assert_eq!(divergence(&reissued), observation(1, Rule::Reissued(OWNER)));
}

/// Planted controls of names a transition must already know: a held part of
/// an acquisition never bound, and a settlement of an obligation never
/// admitted.
#[test]
fn an_unknown_acquisition_or_obligation_is_refused() {
    let stranger = id(1, 9);
    let mut acquisition = published();
    acquisition.observed[3].event = Event::Credit(Credit::Admit {
        work: GRANT,
        held: Some(hold(Obligation::Grant, GRANT, 3, stranger)),
    });
    assert_eq!(
        divergence(&acquisition),
        observation(3, Rule::UnknownAcquisition(stranger))
    );
    let mut obligation = published();
    obligation.observed[9].event = Event::Credit(Credit::Spend(Settled {
        id: stranger,
        ..settlement(grant(), Some(PERMIT))
    }));
    assert_eq!(
        divergence(&obligation),
        observation(9, Rule::UnknownObligation(stranger))
    );
}

/// Planted controls of admission correspondence (`Machine::admission`,
/// `admit_at`): a work call answered with a permit, an admission of other
/// work than its call admitted, an admission no policy performed, and an
/// admission holding more than it admitted.
#[test]
fn every_admission_divergence_is_refused() {
    let mut answer = published();
    answer.observed[2].event = Event::Call(work(0, 8), Answer::Granted(PERMIT));
    assert_eq!(
        divergence(&answer),
        observation(
            2,
            Rule::UnexpectedAnswer(work(0, 8), Answer::Granted(PERMIT))
        )
    );
    let mut mismatched = published();
    mismatched.observed[3].event = Event::Credit(Credit::Admit {
        work: WriteWork::new(0, 9),
        held: Some(grant()),
    });
    assert_eq!(
        divergence(&mismatched),
        observation(
            3,
            Rule::AdmissionMismatch {
                call: GRANT,
                admitted: WriteWork::new(0, 9)
            }
        )
    );
    let mut unperformed = published();
    unperformed.observed[3].by = Performer::None;
    assert_eq!(
        divergence(&unperformed),
        observation(3, Rule::AdmissionWithoutPolicy)
    );
    let mut overheld = published();
    overheld.observed[3].event = Event::Credit(Credit::Admit {
        work: GRANT,
        held: Some(hold(
            Obligation::Grant,
            WriteWork::new(0, 9),
            3,
            ACQUISITION,
        )),
    });
    assert_eq!(divergence(&overheld), observation(3, Rule::Overheld));
}

/// Planted controls of settlement (`Machine::settle`, `Retained::record`): a
/// grant settled as a release, a grant spent in part, a grant forfeited
/// under a rule that does not name it, and a release spent at no permit.
#[test]
fn every_settlement_divergence_is_refused() {
    let mut kind = published();
    kind.observed[9].event = Event::Credit(Credit::Spend(Settled {
        obligation: Obligation::Release,
        ..settlement(grant(), Some(PERMIT))
    }));
    assert_eq!(
        divergence(&kind),
        observation(
            9,
            Rule::KindMismatch {
                obligation: grant().id,
                held: Obligation::Grant,
                named: Obligation::Release
            }
        )
    );
    let mut partial = published();
    partial.observed[9].event = Event::Credit(Credit::Spend(Settled {
        work: WriteWork::new(0, 7),
        ..settlement(grant(), Some(PERMIT))
    }));
    assert_eq!(
        divergence(&partial),
        observation(9, Rule::Partial(grant().id))
    );
    let mut unnamed = cancelled();
    unnamed.observed[6].event = Event::Credit(Credit::Forfeit(
        settlement(grant(), None),
        Forfeit::EnumerationComplete,
    ));
    assert_eq!(
        divergence(&unnamed),
        observation(
            6,
            Rule::UnnamedForfeit(Obligation::Grant, Forfeit::EnumerationComplete)
        )
    );
    let mut unlinked = published();
    unlinked.observed[7].event = Event::Credit(Credit::Spend(settlement(release(), None)));
    assert_eq!(
        divergence(&unlinked),
        observation(7, Rule::PermitLink(release().id))
    );
}

/// Planted controls of the permit lifecycle (`Machine::settle`,
/// `Machine::effect`, the split and merge transitions): a second release
/// spent at a permit already carrying one, a second physical outcome, a
/// permit merged into itself, a split taking more than its parent holds, and
/// a merge passing fewer bytes than its input holds.
#[test]
fn every_permit_lifecycle_divergence_is_refused() {
    let (stream, p, q) = two_acquired();
    let mut bound = stream.clone();
    bound[11].event = Event::Credit(Credit::Spend(settlement(
        hold(Obligation::Release, RELEASE, 6, id(1, 3)),
        Some(p),
    )));
    assert_eq!(session(&bound), observation(11, Rule::PermitBound(p)));
    let mut again = published();
    again.observed.insert(
        9,
        at(
            1,
            Some(1),
            Event::Effect(Effect::Reserved {
                permit: PERMIT,
                acquisition: ACQUISITION,
            }),
        ),
    );
    assert_eq!(
        divergence(&again),
        observation(9, Rule::EffectInvalid(PERMIT))
    );
    let mut itself = acquired();
    itself.insert(
        10,
        at(
            1,
            None,
            Event::Merge {
                survivor: PERMIT,
                retired: PERMIT,
                bytes: 32,
            },
        ),
    );
    assert_eq!(session(&itself), observation(10, Rule::SelfMerge(PERMIT)));
    let mut overdrawn = acquired();
    overdrawn.insert(
        10,
        at(
            1,
            None,
            Event::Split {
                parent: PERMIT,
                child: id(1, 6),
                bytes: 33,
            },
        ),
    );
    assert_eq!(
        session(&overdrawn),
        observation(
            10,
            Rule::SplitOverdrawn {
                permit: PERMIT,
                held: 32,
                taken: 33
            }
        )
    );
    let mut short = stream;
    short.truncate(13);
    short.push(at(
        1,
        None,
        Event::Merge {
            survivor: p,
            retired: q,
            bytes: 7,
        },
    ));
    assert_eq!(
        session(&short),
        observation(
            13,
            Rule::MergeMismatch {
                permit: q,
                held: 8,
                passed: 7
            }
        )
    );
}

/// Planted controls of cleanup (`Machine::clean` and the transitions it
/// gates): a held admission once cleanup began, an allocation once cleanup
/// began, cleanup for a refusal no call returned, and cleanup for a physical
/// failure no permit suffered.
#[test]
fn every_cleanup_divergence_is_refused() {
    let mut held = cancelled();
    held.cleaning = Some((4, Cause::Cancel));
    assert_eq!(divergence(&held), observation(5, Rule::HoldInCleanup));
    let mut allocated = published();
    allocated.cleaning = Some((6, Cause::Cancel));
    assert_eq!(
        divergence(&allocated),
        observation(6, Rule::AllocateInCleanup)
    );
    let refusal = Cause::Error(Class::Refused(LimitRefusal::Work));
    let mut unmatched = cancelled();
    unmatched.cleaning = Some((6, refusal));
    assert_eq!(
        divergence(&unmatched),
        Divergence {
            at: At::Cleaning,
            rule: Rule::RefusalUnmatched {
                cause: refusal,
                outstanding: None
            }
        }
    );
    let mut unfailed = cancelled();
    unfailed.cleaning = Some((6, Cause::Error(Class::Allocation)));
    assert_eq!(
        divergence(&unfailed),
        Divergence {
            at: At::Cleaning,
            rule: Rule::NoFailedPermit
        }
    );
}

/// Planted controls of publication (`Machine::publish`): publication with a
/// refusal outstanding, publication once cleanup began, and a published
/// permit that is not live.
#[test]
fn every_publication_divergence_is_refused() {
    let mut refused_first = published();
    refused_first.observed.insert(
        10,
        at(
            1,
            Some(1),
            Event::Call(
                work(1, 0),
                Answer::Refused {
                    refusal: LimitRefusal::Work,
                    injected: false,
                },
            ),
        ),
    );
    refused_first.published = Some(Publication {
        boundary: 11,
        permits: vec![PERMIT],
    });
    assert_eq!(
        divergence(&refused_first),
        Divergence {
            at: At::Published,
            rule: Rule::PublishedRefused(LimitRefusal::Work)
        }
    );
    let mut cleaned = published();
    cleaned.cleaning = Some((10, Cause::Cancel));
    assert_eq!(
        divergence(&cleaned),
        Divergence {
            at: At::Published,
            rule: Rule::PublishedAfterCleaning
        }
    );
    let stranger = id(1, 9);
    let mut dead = published();
    dead.published = Some(Publication {
        boundary: 10,
        permits: vec![stranger],
    });
    assert_eq!(
        divergence(&dead),
        Divergence {
            at: At::Published,
            rule: Rule::PublishedPermit(stranger)
        }
    );
}

/// Planted controls of the end (`Machine::checkpoint`, `Machine::quiescent`,
/// [`check`]): a permit reported that its owner does not hold, an obligation
/// never settled, an end other than the one the run reached, and a ledger
/// sum past `u64`.
#[test]
fn every_end_and_quantity_divergence_is_refused() {
    let stranger = id(1, 9);
    let mut extra = published();
    extra.checkpoints[1].custody = custody(Vec::new(), vec![PERMIT, stranger]);
    assert_eq!(
        divergence(&extra),
        Divergence {
            at: At::Checkpoint(1),
            rule: Rule::ExtraPermit {
                owner: OWNER,
                permit: stranger
            }
        }
    );
    // The grant's spend removed, with the end it would have preceded: an
    // obligation still holding work once the stream is over.
    let mut unsettled = acquired();
    unsettled.pop();
    unsettled.remove(9);
    assert_eq!(
        session(&unsettled),
        Divergence {
            at: At::End,
            rule: Rule::Outstanding(grant().id)
        }
    );
    let mut ended = published();
    ended.end = End::Cancelled;
    assert_eq!(
        divergence(&ended),
        Divergence {
            at: At::End,
            rule: Rule::EndMismatch {
                end: End::Cancelled,
                reached: Some(End::Published)
            }
        }
    );
    let most = WriteWork::new(u64::MAX, 0);
    let p = Some(1);
    let overflowing = [
        at(1, p, Event::Call(work(u64::MAX, 0), Answer::Admitted)),
        at(
            1,
            p,
            Event::Credit(Credit::Admit {
                work: most,
                held: None,
            }),
        ),
        at(1, p, Event::Call(work(u64::MAX, 0), Answer::Admitted)),
        at(
            1,
            p,
            Event::Credit(Credit::Admit {
                work: most,
                held: None,
            }),
        ),
    ];
    assert_eq!(session(&overflowing), observation(3, Rule::Overflow));
}

/// Planted controls of a checkpoint's bindings (`Machine::checkpoint`): the
/// acquisition reported bound under a second owner, which did not bind it;
/// reported bound twice; and an acquisition the stream never bound reported
/// bound. A binding reported with no credit held is custody, and accepted.
#[test]
fn every_reported_binding_is_its_owners_and_reported_once() {
    let second = id(1, 8);
    // `published` with a second owner made first, every mark one later.
    let with_second = || {
        let mut run = published();
        run.observed.insert(0, at(1, Some(1), Event::Owner(second)));
        for checkpoint in &mut run.checkpoints {
            checkpoint.boundary += 1;
        }
        if let Some(publication) = &mut run.published {
            publication.boundary += 1;
        }
        run
    };
    assert_eq!(check(&with_second()), Ok(()), "the second owner alone");
    let mut elsewhere = with_second();
    elsewhere.checkpoints[0].custody[0].bound.clear();
    // Visit the wrongly attributed binding before the owner now missing it:
    // each owner is checked completely in observation order.
    elsewhere.checkpoints[0].custody.insert(
        0,
        Custody {
            owner: second,
            bound: vec![ACQUISITION],
            held: Vec::new(),
            permits: Vec::new(),
        },
    );
    assert_eq!(
        divergence(&elsewhere),
        Divergence {
            at: At::Checkpoint(0),
            rule: Rule::BindingElsewhere {
                owner: second,
                acquisition: ACQUISITION,
                bound: OWNER
            }
        }
    );
    elsewhere.checkpoints[0].custody.reverse();
    assert_eq!(
        rule(&elsewhere),
        Rule::MissingBinding {
            owner: OWNER,
            acquisition: ACQUISITION
        }
    );
    let mut twice = published();
    twice.checkpoints[0].custody[0].bound.push(ACQUISITION);
    assert_eq!(rule(&twice), Rule::Duplicate(ACQUISITION));
    let mut stranger = published();
    stranger.checkpoints[0].custody[0].bound = vec![id(1, 9)];
    assert_eq!(rule(&stranger), Rule::UnknownAcquisition(id(1, 9)));
    // Bound with nothing held: the acquisition is custody until it ends.
    let idle = published();
    assert!(idle.checkpoints[1].custody[0].held.is_empty());
    assert_eq!(check(&idle), Ok(()), "a binding holding no credit");
}

/// The last index of [`acquired`]: the acquisition's end.
const END: usize = 11;

/// Planted controls of the acquisition's end (`Event::End`,
/// `Machine::end`, `Machine::quiescent`): each mutates one fact of the
/// accepted stream and is refused by its own rule, at its own point.
#[test]
fn every_acquisition_end_divergence_is_refused() {
    let mut deleted = acquired();
    deleted.remove(END);
    assert_eq!(
        session(&deleted),
        Divergence {
            at: At::End,
            rule: Rule::Unended(ACQUISITION)
        }
    );
    // Moved before the grant's spend (index 9): the grant still holds work.
    let mut early = acquired();
    let end = early.remove(END);
    early.insert(9, end);
    assert_eq!(
        session(&early),
        observation(
            9,
            Rule::EndOutstanding {
                acquisition: ACQUISITION,
                obligation: grant().id
            }
        )
    );
    let mut repeated = acquired();
    repeated.push(ended(Some(1)));
    assert_eq!(
        session(&repeated),
        observation(END + 1, Rule::AcquisitionEnded(ACQUISITION))
    );
    let mut owner = acquired();
    owner[END].event = Event::End {
        acquisition: ACQUISITION,
        owner: id(1, 9),
    };
    assert_eq!(
        session(&owner),
        observation(
            END,
            Rule::EndOwner {
                acquisition: ACQUISITION,
                bound: OWNER,
                named: id(1, 9)
            }
        )
    );
    // Published through another family than the one that minted it: a
    // retrying family's origin is no authority over it.
    let mut retrying = acquired();
    retrying[END].family = 2;
    assert_eq!(
        session(&retrying),
        observation(
            END,
            Rule::WrongFamily {
                identity: ACQUISITION,
                publisher: 2
            }
        )
    );
    let mut unknown = acquired();
    unknown[END].event = Event::End {
        acquisition: id(1, 9),
        owner: OWNER,
    };
    assert_eq!(
        session(&unknown),
        observation(END, Rule::UnknownAcquisition(id(1, 9)))
    );
    // An obligation admitted for the ended acquisition.
    let mut admitted = acquired();
    admitted.push(at(1, Some(1), Event::Call(work(1, 16), Answer::Admitted)));
    admitted.push(at(
        1,
        Some(1),
        Event::Credit(Credit::Admit {
            work: RELEASE,
            held: Some(hold(Obligation::Release, RELEASE, 6, ACQUISITION)),
        }),
    ));
    assert_eq!(
        session(&admitted),
        observation(END + 2, Rule::AcquisitionEnded(ACQUISITION))
    );
    // The ended identity bound again.
    let mut rebound = acquired();
    rebound.push(at(
        1,
        Some(1),
        Event::Bound {
            acquisition: ACQUISITION,
            owner: OWNER,
        },
    ));
    assert_eq!(
        session(&rebound),
        observation(END + 1, Rule::Reissued(ACQUISITION))
    );
}

/// Planted controls of a checkpoint's bindings against the stream's active
/// acquisitions (`Machine::checkpoint`): a credit-free binding left out
/// before the end, a binding kept in a checkpoint after the end, and the
/// end moved before a checkpoint that still reports the acquisition bound.
#[test]
fn every_checkpoint_binding_is_exactly_the_active_acquisitions() {
    let mut omitted = published();
    omitted.checkpoints[1].custody[0].bound.clear();
    assert_eq!(
        divergence(&omitted),
        Divergence {
            at: At::Checkpoint(1),
            rule: Rule::MissingBinding {
                owner: OWNER,
                acquisition: ACQUISITION
            }
        }
    );
    let mut stale = published();
    stale.checkpoints[1].boundary = END + 1;
    stale.published = Some(Publication {
        boundary: END + 1,
        permits: Vec::new(),
    });
    stale.checkpoints[1].custody[0].permits.clear();
    assert_eq!(
        divergence(&stale),
        Divergence {
            at: At::Checkpoint(1),
            rule: Rule::StaleBinding {
                owner: OWNER,
                acquisition: ACQUISITION
            }
        }
    );
    // The end moved before checkpoint 1 (boundary 10), which still
    // reports the acquisition bound.
    let mut moved = published();
    let end = moved.observed.remove(END);
    moved.observed.insert(10, end);
    moved.checkpoints[1].boundary = 11;
    moved.published = Some(Publication {
        boundary: 11,
        permits: Vec::new(),
    });
    moved.checkpoints[1].custody[0].permits.clear();
    assert_eq!(
        divergence(&moved),
        Divergence {
            at: At::Checkpoint(1),
            rule: Rule::StaleBinding {
                owner: OWNER,
                acquisition: ACQUISITION
            }
        }
    );
}

/// A record block's whole lifecycle, the production order
/// (`reclamation.rs`): [`acquired`]'s acquisition through its grant's
/// spend, its end (`Pending::complete`), the block classified granted
/// (`Reclaimer::allocate`), its owner stage (`Reclaimer::own`), its
/// retirement into the queue (`enqueue`), its removal (`Reclaimer::step`),
/// its cleanup's completion (`Ending::Free`), and its permit's release.
/// Every record transition is published through the permit's family with
/// no performer.
fn record() -> Vec<Observed> {
    let mut observed = acquired();
    observed.truncate(10);
    observed.push(ended(Some(1)));
    for stage in [
        crate::RecordStage::Granted,
        crate::RecordStage::Handle,
        crate::RecordStage::Queued,
        crate::RecordStage::Active,
        crate::RecordStage::Reclaimed,
    ] {
        observed.push(at(
            1,
            None,
            Event::Custody {
                permit: PERMIT,
                owner: OWNER,
                stage,
            },
        ));
    }
    observed.push(at(1, None, Event::Released(PERMIT)));
    observed
}

/// The index of the record's `stage` transition in [`record`].
const fn record_at(stage: crate::RecordStage) -> usize {
    11 + stage as usize
}

/// The record's lifecycle is accepted, and an unowned block's release
/// (`Reclaimer::release_unowned`, a cancellation before the owner stage)
/// is too; planted controls: a record released before its cleanup
/// completed (payload-free: nothing else would notice), a transition from
/// the wrong predecessor, one repeated, a block made a record with no
/// classification, the owner substituted, and a transition published by
/// another family.
#[test]
fn every_record_lifecycle_divergence_is_refused() {
    use crate::RecordStage::{Active, Granted, Handle, Queued, Reclaimed};
    assert_eq!(settled(&record(), &[]), Ok(()));
    let mut unowned = record();
    unowned.drain(record_at(Handle)..record_at(Reclaimed) + 1);
    assert_eq!(settled(&unowned, &[]), Ok(()), "an unowned block's release");
    let mut premature = record();
    premature.remove(record_at(Reclaimed));
    assert_eq!(
        session(&premature),
        observation(
            record_at(Reclaimed),
            Rule::PrematureRecordRelease {
                permit: PERMIT,
                stage: Active
            }
        )
    );
    let mut skipped = record();
    skipped.remove(record_at(Queued));
    assert_eq!(
        session(&skipped),
        observation(
            record_at(Queued),
            Rule::RecordTransition {
                permit: PERMIT,
                from: Some(Handle),
                to: Active
            }
        )
    );
    let mut repeated = record();
    let again = repeated[record_at(Reclaimed)];
    repeated.insert(record_at(Reclaimed) + 1, again);
    assert_eq!(
        session(&repeated),
        observation(
            record_at(Reclaimed) + 1,
            Rule::RecordTransition {
                permit: PERMIT,
                from: Some(Reclaimed),
                to: Reclaimed
            }
        )
    );
    let mut unclassified = record();
    unclassified.remove(record_at(Granted));
    assert_eq!(
        session(&unclassified),
        observation(
            record_at(Granted),
            Rule::RecordTransition {
                permit: PERMIT,
                from: None,
                to: Handle
            }
        )
    );
    let mut substituted = record();
    substituted[record_at(Queued)].event = Event::Custody {
        permit: PERMIT,
        owner: id(1, 9),
        stage: Queued,
    };
    assert_eq!(
        session(&substituted),
        observation(
            record_at(Queued),
            Rule::RecordOwner {
                permit: PERMIT,
                owner: OWNER,
                named: id(1, 9)
            }
        )
    );
    let mut foreign = record();
    foreign[record_at(Handle)].family = 2;
    assert_eq!(
        session(&foreign),
        observation(
            record_at(Handle),
            Rule::WrongFamily {
                identity: PERMIT,
                publisher: 2
            }
        )
    );
}

/// Planted controls of a record's holder at a checkpoint
/// (`Machine::checkpoint`, `Machine::mid_step`): a queued record reported
/// as its handle's, a record reported as an ordinary permit, and a
/// checkpoint between a record's completion and its block's release.
#[test]
fn every_record_holder_divergence_is_refused() {
    use crate::RecordStage::{Handle, Queued, Reclaimed};
    let checkpoint = |boundary: usize, stage: Option<crate::RecordStage>| Run {
        observed: record(),
        checkpoints: vec![Checkpoint {
            boundary,
            custody: vec![Custody {
                owner: OWNER,
                bound: Vec::new(),
                held: Vec::new(),
                permits: vec![crate::Reported {
                    permit: PERMIT,
                    record: stage,
                }],
            }],
        }],
        cleaning: Some((record().len(), Cause::Cancel)),
        published: None,
        end: End::Cancelled,
    };
    let queued = record_at(Queued) + 1;
    assert_eq!(check(&checkpoint(queued, Some(Queued))), Ok(()));
    assert_eq!(
        divergence(&checkpoint(queued, Some(Handle))),
        Divergence {
            at: At::Checkpoint(0),
            rule: Rule::HolderMismatch {
                permit: PERMIT,
                expected: Some(Queued),
                reported: Some(Handle)
            }
        }
    );
    assert_eq!(
        divergence(&checkpoint(queued, None)),
        Divergence {
            at: At::Checkpoint(0),
            rule: Rule::HolderMismatch {
                permit: PERMIT,
                expected: Some(Queued),
                reported: None
            }
        }
    );
    assert_eq!(
        divergence(&checkpoint(record_at(Reclaimed) + 1, Some(Reclaimed))),
        Divergence {
            at: At::Checkpoint(0),
            rule: Rule::MidStep
        }
    );
}

/// The test that plants each rule's divergence, by rule: exhaustive, with no
/// wildcard, so a rule added to the machine without a planted divergence
/// does not compile.
const fn planted(rule: &Rule) -> &'static str {
    match rule {
        Rule::BoundaryPastEnd { .. } | Rule::BoundaryDecreasing { .. } | Rule::MidStep => {
            "every_misplaced_boundary_is_refused"
        }
        Rule::Unobserved | Rule::Reissued(_) => "an_unobserved_or_reissued_identity_is_refused",
        Rule::WrongFamily { .. } => "a_settlement_into_another_family_is_refused",
        Rule::UnknownOwner(_) | Rule::Duplicate(_) | Rule::MissingPermit { .. } => {
            "every_owner_holding_custody_is_reported_once_under_its_own_identity"
        }
        Rule::UnknownAcquisition(_) | Rule::UnknownObligation(_) => {
            "an_unknown_acquisition_or_obligation_is_refused"
        }
        Rule::UnknownPermit(_)
        | Rule::PermitLife { .. }
        | Rule::ForeignTransfer { .. }
        | Rule::Leaked(_) => "every_release_is_checked_by_identity",
        Rule::UnexpectedAnswer(..)
        | Rule::AdmissionMismatch { .. }
        | Rule::AdmissionWithoutPolicy
        | Rule::Overheld => "every_admission_divergence_is_refused",
        Rule::MissingAdmission(_) | Rule::UnauthorizedAdmission(_) | Rule::Unpaid(_) => {
            "admission_and_payment_correspondence_is_checked"
        }
        Rule::NoEffect(_) => "a_session_is_held_to_the_runs_rules",
        Rule::AcquisitionMismatch { .. } | Rule::PermitAcquisition { .. } => {
            "a_wrong_acquisition_or_permit_is_refused"
        }
        Rule::KindMismatch { .. }
        | Rule::Partial(_)
        | Rule::UnnamedForfeit(..)
        | Rule::PermitLink(_) => "every_settlement_divergence_is_refused",
        Rule::Overdrawn { .. } => "an_over_settled_or_twice_settled_obligation_is_refused",
        Rule::ReleaseForfeitedAfterGrant(_) | Rule::MissingEffect { .. } => {
            "a_missing_physical_effect_is_refused"
        }
        Rule::PermitBound(_)
        | Rule::EffectInvalid(_)
        | Rule::SelfMerge(_)
        | Rule::SplitOverdrawn { .. }
        | Rule::MergeMismatch { .. } => "every_permit_lifecycle_divergence_is_refused",
        Rule::HoldInCleanup
        | Rule::AllocateInCleanup
        | Rule::RefusalUnmatched { .. }
        | Rule::NoFailedPermit => "every_cleanup_divergence_is_refused",
        Rule::PublishedRefused(_) | Rule::PublishedAfterCleaning | Rule::PublishedPermit(_) => {
            "every_publication_divergence_is_refused"
        }
        Rule::MissingHeld { .. } | Rule::ExtraHeld { .. } => {
            "a_checkpoint_moved_across_a_cancellation_is_refused"
        }
        Rule::HeldMismatch { .. } => "a_substituted_or_misreported_obligation_is_refused",
        Rule::BindingElsewhere { .. } => "every_reported_binding_is_its_owners_and_reported_once",
        Rule::ExtraPermit { .. }
        | Rule::Outstanding(_)
        | Rule::EndMismatch { .. }
        | Rule::Overflow => "every_end_and_quantity_divergence_is_refused",
        Rule::AcquisitionEnded(_)
        | Rule::EndOutstanding { .. }
        | Rule::EndOwner { .. }
        | Rule::Unended(_) => "every_acquisition_end_divergence_is_refused",
        Rule::MissingBinding { .. } | Rule::StaleBinding { .. } => {
            "every_checkpoint_binding_is_exactly_the_active_acquisitions"
        }
        Rule::RecordTransition { .. }
        | Rule::RecordOwner { .. }
        | Rule::PrematureRecordRelease { .. } => "every_record_lifecycle_divergence_is_refused",
        Rule::HolderMismatch { .. } => "every_record_holder_divergence_is_refused",
    }
}

/// Every rule names the test planting it: the census above compiles only
/// while it is exhaustive, and each name it gives is one of this module's
/// tests (listed here from the module's `#[test]` functions).
#[test]
fn every_rule_names_its_planted_divergence() {
    const TESTS: &[&str] = &[
        "a_checkpoint_moved_across_a_cancellation_is_refused",
        "a_substituted_or_misreported_obligation_is_refused",
        "every_owner_holding_custody_is_reported_once_under_its_own_identity",
        "every_misplaced_boundary_is_refused",
        "a_settlement_into_another_family_is_refused",
        "a_wrong_acquisition_or_permit_is_refused",
        "a_missing_physical_effect_is_refused",
        "every_release_is_checked_by_identity",
        "a_session_is_held_to_the_runs_rules",
        "admission_and_payment_correspondence_is_checked",
        "an_over_settled_or_twice_settled_obligation_is_refused",
        "an_unobserved_or_reissued_identity_is_refused",
        "an_unknown_acquisition_or_obligation_is_refused",
        "every_admission_divergence_is_refused",
        "every_settlement_divergence_is_refused",
        "every_permit_lifecycle_divergence_is_refused",
        "every_cleanup_divergence_is_refused",
        "every_publication_divergence_is_refused",
        "every_end_and_quantity_divergence_is_refused",
        "every_reported_binding_is_its_owners_and_reported_once",
        "every_acquisition_end_divergence_is_refused",
        "every_checkpoint_binding_is_exactly_the_active_acquisitions",
        "every_record_lifecycle_divergence_is_refused",
        "every_record_holder_divergence_is_refused",
    ];
    let source = include_str!("tests.rs");
    for name in TESTS {
        assert!(
            source.contains(&format!("fn {name}()")),
            "{name} is not a test of this module"
        );
    }
    let stranger = id(1, 9);
    for rule in [
        Rule::Unobserved,
        Rule::Overflow,
        Rule::MidStep,
        Rule::PermitBound(stranger),
        Rule::EndMismatch {
            end: End::Published,
            reached: None,
        },
    ] {
        assert!(
            TESTS.contains(&planted(&rule)),
            "{rule} names an unknown test"
        );
    }
}
