#![cfg(feature = "std")]
//! A record's owner association through recorded checkpoints: a record is
//! grouped under the owner of the acquisition that allocated it, read from
//! the identity its entry stores, while its handle holds it and once the
//! scope's queue holds it, and the refinement machine checks every group
//! against the acquisitions the session bound.

// The recorded policies witness releases on this thread.
#[global_allocator]
static HEAP: support::heap::Heap = support::heap::Heap;

use dcbor::bounded::decode::construction::reclamation::Reclaimed;
use dcbor::bounded::decode::construction::{Acquisition, DecodeOwner};
use dcbor::bounded::{Custodial, CustodySink, Limits, Reservation, observed_all};
use dcbor_test_support as support;

/// A `u64` record, allocated under an acquisition token, checkpointed while
/// its handle holds it and again once retired to the scope's queue: each
/// checkpoint reports the scope authority's custody (its block, then the
/// queue), the token's, and the handle's, and the machine accepts both,
/// the record's block grouped under the token's owner each time. The
/// planted `record-owner-ungrouped` control opens the record's group with
/// no owner, which the collector refuses at the first checkpoint
/// (`a checkpoint's custody is no observation: Unowned`).
#[test]
fn a_record_is_checkpointed_under_its_acquisitions_owner_held_and_queued() {
    support::recorded_run(|run| {
        let policy = run.policy(u64::MAX);
        let mut owner = DecodeOwner::<'static, Limits>::new();
        let mut acquisition = Acquisition::<u64, Limits>::new();
        let mut record = run.with_policy(policy, |m| {
            owner
                .initialize_step(m)
                .expect("an unlimited policy admits the scope");
            owner
                .allocate_step(m, &mut acquisition)
                .expect("an unlimited policy admits the record")
        });
        run.checkpoint(|sink: &mut dyn CustodySink<Reservation>| {
            observed_all([
                owner.observe_custody(sink),
                acquisition.observe_custody(sink),
                record.observe_custody(sink),
            ])
        });
        drop(record);
        run.checkpoint(|sink: &mut dyn CustodySink<Reservation>| {
            observed_all([
                owner.observe_custody(sink),
                acquisition.observe_custody(sink),
            ])
        });
        run.with_policy(policy, |m| {
            for _ in 0..8 {
                if owner
                    .shutdown_step(m)
                    .expect("an unlimited policy admits every cleanup unit")
                    == Reclaimed::Done
                {
                    return;
                }
            }
            panic!("the scope did not shut down");
        });
        drop((acquisition, owner));
        Ok(())
    });
}
