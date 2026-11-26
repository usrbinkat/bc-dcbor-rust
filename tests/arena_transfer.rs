#![cfg(feature = "std")]
//! A parsed document's arena moves from its parser into its record one
//! ownership part per admitted unit: the node storage's parts, the permit
//! last among them, then the identity of the owner the parser's arena
//! stored (`cursor/publication.rs`, `publish_arena_step`). Its custody is
//! reported once at every prefix (`DocumentArena::observe_prefix`): by the
//! parser before the permit moves, by the record's arena under the parser's
//! owner from the permit's part until the owner is written, and under the
//! arena's own owner field after; its cleanup destroys the vector, then
//! releases the permit. These witnesses checkpoint every one of those
//! prefixes in recorded runs, whose finalizer compares every checkpoint
//! owner by owner with the stream before it. A storage discrepancy a run
//! finds is recorded as its defect ([`support::RecordedRun::defect`]) once
//! every capability is dropped, so the run's finalization still reports
//! what its recording finished as beside it.

// The recorded policies witness releases on this thread.
#[global_allocator]
static HEAP: support::heap::Heap = support::heap::Heap;

use dcbor::ByteString;
use dcbor::bounded::decode::construction::{DecodeOwner, DocumentDecoder, ParsePhase, parse_bound};
use dcbor::bounded::decode::{DecodeError, Options};
use dcbor::bounded::{BoundedError, Custodial, Identity, LimitRefusal, Limits};
use dcbor_test_support::{
    self as support, Finding, Holding, PolicyId, Retirement, Stepped, pipeline::Unwitnessed,
};
use std::collections::BTreeSet;

/// The held parse of [`WIRE`].
type Parse<'r, 's> = Holding<'r, 's, DocumentDecoder<'static, ByteString, Limits>, Unwitnessed>;

const OPTIONS: Options = Options::normalizing(8);

/// `[1, 2]`: an array whose parse allocates the parser's node arena, so its
/// transfer moves a live permit.
const WIRE: [u8; 3] = [0x82, 0x01, 0x02];

/// The finding a run records when storage outlives its cleanup.
const OUTLIVED: &str = "the arena's permit outlived its cleanup";

/// The turns the parse of [`WIRE`] takes, its cleanup included.
fn turns() -> usize {
    support::turns(
        parse_bound::<ByteString, Limits, ()>(WIRE.len() as u64, OPTIONS)
            .expect("the parse bound of an input held in memory fits in u64"),
    )
}

/// The owners the parse's custody reports, collected by the run's one
/// collector ([`support::collect`]); `None` when the observation is no
/// observation, which the run's own checkpoint records as its defect.
fn owners(
    decoder: &mut DocumentDecoder<'static, ByteString, Limits>,
) -> Option<BTreeSet<Identity>> {
    support::collect(|sink| decoder.observe_custody(sink))
        .ok()
        .map(|custody| custody.iter().map(|entry| entry.owner).collect())
}

/// Each permit the parse's custody reports, with the owner it is reported
/// under; `None` when the observation is no observation.
fn permits(
    decoder: &mut DocumentDecoder<'static, ByteString, Limits>,
) -> Option<BTreeSet<(Identity, Identity)>> {
    support::collect(|sink| decoder.observe_custody(sink))
        .ok()
        .map(|custody| {
            custody
                .iter()
                .flat_map(|entry| {
                    entry
                        .permits
                        .iter()
                        .map(move |reported| (entry.owner, reported.permit))
                })
                .collect()
        })
}

/// The live bytes each of `policies` still holds, as `run`'s defect when any
/// holds some: read once the run's holdings have retired every capability it
/// made, and recorded without unwinding, so finalization reports it beside
/// what the recording finished as.
fn storage_outlived(run: &mut support::RecordedRun, policies: &[PolicyId]) {
    let live: Vec<u64> = policies
        .iter()
        .map(|&policy| run.with_policy(policy, |m| m.live_bytes()))
        .collect();
    if live.iter().any(|&bytes| bytes != 0) {
        run.defect(format!("{OUTLIVED}: live bytes per policy {live:?}"));
    }
}

/// Every unit of the arena's transfer is first refused under policy `a`,
/// leaving the parse where it was, and checkpointed there; then admitted
/// under policy `b`, a second policy of the same session, and checkpointed
/// again. The refusals fall at every count of parts transferred, from none
/// through the owner's stage, the last, so the run checkpoints the permit
/// moved and its owner not yet written, and the owner stage resumed under
/// another policy than the one refused. The published document is then
/// retired and the scope drained, a checkpoint after every step; nothing
/// is left live in either family.
///
/// The identity order the `arena-permit-under-record-owner` control's
/// divergence rests on is asserted here, from the production traversal:
/// every owner the parse first reports after its record is initialized (the
/// parser's arenas', minted by their first acquisitions) is greater than
/// every owner it reported then (the record's own, minted by its
/// acquisition), the identities of one family numbered in mint order. The
/// machine compares reported owners in identity order, so a moved permit
/// reported inside the record's group is first met as a permit the record's
/// owner does not hold (`ExtraPermit`).
#[test]
fn every_transfer_part_is_refused_checkpointed_and_resumed_under_another_policy() {
    support::recorded_run(|run| {
        let a = run.policy(u64::MAX);
        let b = run.policy(u64::MAX);
        let mut defects = Vec::new();
        run.holding(
            DecodeOwner::<'static, Limits>::new(),
            Retirement::Scope,
            &Unwitnessed,
            |owner| {
                owner.initialize(a)?;
                owner.copied(a, &WIRE, |input| {
                    input.transfer(
                        |input| DocumentDecoder::parse(input, OPTIONS),
                        Retirement::Stopped,
                        |decoder| transferred(decoder, a, b, &mut defects),
                    )
                })??;
                owner.drain(b)
            },
        )?;
        for defect in defects {
            run.defect(defect);
        }
        storage_outlived(run, &[a, b]);
        Ok(())
    });
}

/// The held parse stepped under `a`, every transfer part first refused under
/// `a` exhausted and then admitted under `b`, the holding stack checkpointed
/// after each refusal and each turn; its publication held and retired as a
/// published handle, the parse then checked exhausted. Ordering findings are
/// returned through `defects`, detached.
fn transferred(
    decoder: &mut Parse<'_, '_>,
    a: PolicyId,
    b: PolicyId,
    defects: &mut Vec<String>,
) -> Result<(), Finding> {
    let mut refused_at = Vec::new();
    let mut initialized: Option<BTreeSet<Identity>> = None;
    for at in 0..turns() {
        let detail = decoder.value().position().detail;
        if initialized.is_none() && detail.phase == Some(ParsePhase::Parse) {
            initialized = owners(decoder.value());
            if !initialized
                .as_ref()
                .is_some_and(|owners| !owners.is_empty())
            {
                defects.push("the initialized record reported no owner".to_owned());
            }
        }
        let transferring = detail.phase == Some(ParsePhase::Transfer);
        if transferring {
            // The refused call is the next attempt under the exhausted policy.
            let call = decoder.with_policy(a, |_, m| {
                m.clear_refusal();
                m.exhaust();
                m.attempts()
            });
            assert_eq!(
                decoder.suspend(
                    a,
                    LimitRefusal::Turn,
                    1,
                    support::TurnSchedule::Retained,
                    Retirement::Published
                )?,
                call,
                "the transfer part must refuse its first attempt under the exhausted policy"
            );
            assert_eq!(
                decoder.value().position().detail,
                detail,
                "a refused transfer part moved"
            );
            refused_at.push(detail.transferred);
            if let (Some(before), Some(now)) = (&initialized, owners(decoder.value())) {
                let earliest_new = now.difference(before).next().copied();
                let latest_old = before.iter().next_back().copied();
                if earliest_new.is_none() || earliest_new <= latest_old {
                    defects.push(format!(
                        "an owner minted after the record's sorts before it: \
                         {earliest_new:?} against {latest_old:?}"
                    ));
                }
            }
            decoder.checkpoint();
        }
        let policy = if transferring { b } else { a };
        match decoder.step(
            policy,
            at,
            Retirement::Published,
            |_, _| {},
            |document| document.checkpoint(),
        )? {
            Stepped::Published(()) => {
                assert!(
                    refused_at.len() >= 2,
                    "the transfer took {} parts: no storage part before its owner's",
                    refused_at.len()
                );
                assert_eq!(
                    refused_at,
                    (0..refused_at.len()).collect::<Vec<_>>(),
                    "every part, the owner's last, refused once at its own count"
                );
                return Ok(());
            }
            Stepped::Progress
            | Stepped::Failed(DecodeError::Resource(BoundedError::Refused(_))) => {}
            other => {
                return Err(Finding::Driver(format!("the parse failed: {other:?}")));
            }
        }
        decoder.checkpoint();
    }
    Err(Finding::Driver(
        "the parse did not publish within its bound".to_owned(),
    ))
}

/// What one cancelled parse's cleanup did to the arena's permit: the
/// permits its custody reported, with their owners, at its last checkpoint
/// before the arena's vector is destroyed, its last before the permit is
/// released, and its first after.
struct Cleanup {
    before_vector: BTreeSet<(Identity, Identity)>,
    before_permit: BTreeSet<(Identity, Identity)>,
    after_permit: BTreeSet<(Identity, Identity)>,
}

impl Cleanup {
    /// The permits the arena's release took: reported until its release
    /// part, gone after it.
    fn released(&self) -> BTreeSet<(Identity, Identity)> {
        self.before_permit
            .difference(&self.after_permit)
            .copied()
            .collect()
    }
}

/// The parse cancelled with `cut` parts of its arena transferred, or, for a
/// `cut` past the transfer, once it is whole, its owner written; then its own
/// cleanup driven to `Finished` with a checkpoint after every turn. Whether
/// the cut fell inside the transfer, and what the arena's release did
/// ([`Cleanup`]), read from the parse's custody at each of those
/// checkpoints; a cleanup point no checkpoint reached, or reached with no
/// observation, is the run's defect, recorded once every capability is
/// dropped.
fn cancelled_at(cut: usize) -> (bool, Option<Cleanup>) {
    support::recorded_run(|run| {
        let a = run.policy(u64::MAX);
        let (within, (before_vector, before_permit, after_permit)) =
            run.scoped(a, &Unwitnessed, |owner| {
                owner.copied(a, &WIRE, |input| {
                    input.transfer(
                        |input| DocumentDecoder::parse(input, OPTIONS),
                        Retirement::Stopped,
                        |decoder| {
                            let mut within = None;
                            let published = decoder.controlled(
                                a,
                                turns(),
                                Retirement::Published,
                                true,
                                |_, decoder, _| {
                                    let detail = decoder.position().detail;
                                    let transferring = detail.phase == Some(ParsePhase::Transfer)
                                        && detail.transferred == cut;
                                    let past = matches!(
                                        detail.phase,
                                        Some(ParsePhase::ReleaseParser | ParsePhase::Publish)
                                    );
                                    if transferring || past {
                                        decoder.cancel();
                                        within = Some(transferring);
                                    }
                                    transferring || past
                                },
                                |_| (),
                            )?;
                            if published.is_some() {
                                return Err(Finding::Driver(format!(
                                    "the parse published before its cut {cut}"
                                )));
                            }
                            let within = within.ok_or_else(|| {
                                Finding::Driver(format!("the parse never reached its cut {cut}"))
                            })?;
                            let mut seen = (None, None, None);
                            decoder.finish_observed(
                                a,
                                turns(),
                                Retirement::Published,
                                |decoder| {
                                    let detail = decoder.position().detail;
                                    if detail.phase == Some(ParsePhase::ReclaimArena)
                                        || detail.released > 0
                                    {
                                        let reported = permits(decoder);
                                        match detail.released {
                                            0 => seen.0 = reported,
                                            1 => seen.1 = reported,
                                            _ => {
                                                if seen.2.is_none() {
                                                    seen.2 = reported;
                                                }
                                            }
                                        }
                                    }
                                },
                            )?;
                            Ok((within, seen))
                        },
                    )
                })?
            })?;
        storage_outlived(run, &[a]);
        let cleanup = match (before_vector, before_permit, after_permit) {
            (Some(before_vector), Some(before_permit), Some(after_permit)) => Some(Cleanup {
                before_vector,
                before_permit,
                after_permit,
            }),
            (before_vector, before_permit, after_permit) => {
                run.defect(format!(
                    "cut {cut}: no observed checkpoint at the arena's cleanup entry ({}), \
                     between its vector and its permit ({}), or after its release ({})",
                    before_vector.is_some(),
                    before_permit.is_some(),
                    after_permit.is_some()
                ));
                None
            }
        };
        Ok((within, cleanup))
    })
}

/// The parse cancelled at every count of its arena's parts transferred,
/// from none through the owner's stage, and once more after the whole
/// transfer, every run's cleanup checkpointed after every turn. Destroying
/// the arena's vector moves no permit: every permit the parse reported at
/// its arena's cleanup entry is still reported, under the same owner, after
/// the vector is destroyed. The arena's release releases its permit exactly
/// where the transfer moved it, the storage's last part transferred: then
/// one permit, reported under its owner until that release, is gone after
/// it; with fewer parts transferred the permit is still the parser's, and
/// the arena's release releases none. Which owner each is reported under
/// is checked against the acquisition that bound it by the run's
/// finalization.
#[test]
fn a_parse_cancelled_at_every_transfer_prefix_reports_its_arena_once() {
    let mut runs = Vec::new();
    loop {
        let cut = runs.len();
        // A run whose cleanup was not observed failed at its finalization,
        // naming the missing point, before this is read.
        let (within, cleanup) = cancelled_at(cut);
        runs.push(cleanup.expect("a run that finalized observed its whole cleanup"));
        if !within {
            break;
        }
    }
    // The cuts inside the transfer, the owner's stage the last, and one past.
    let parts = runs.len() - 1;
    assert!(
        parts >= 2,
        "the transfer took {parts} parts: no storage part before its owner's"
    );
    let storage_parts = parts - 1;
    for (cut, run) in runs.iter().enumerate() {
        assert_eq!(
            run.before_permit, run.before_vector,
            "cut {cut}: destroying the arena's vector moved a permit"
        );
        let released = run.released();
        if cut >= storage_parts {
            assert_eq!(
                released.len(),
                1,
                "cut {cut}: the transferred permit was not released by the arena's own release"
            );
        } else {
            assert!(
                released.is_empty(),
                "cut {cut}: the arena released a permit it was never given: {released:?}"
            );
        }
    }
}
