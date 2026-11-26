#![cfg(feature = "std")]

use dcbor::bounded::decode::construction::DecodeOwner;
use dcbor::bounded::decode::construction::in_place::{
    BindingContext, Building, ConstructionCost, InPlace, admit, unit,
};
use dcbor::bounded::decode::construction::reclamation::{
    Cleanup, PeekSlot, Reclaim, Reclaimed, Slot, Written,
};
use dcbor::bounded::decode::{ConstructResult, DecodeError, wrong_type};
use dcbor::bounded::{Allocator, BoundedResult, CustodySink, PermitsObserved};
use dcbor_test_support::{self as support, Retirement, Stopped, pipeline::Unwitnessed};
use std::sync::atomic::{AtomicUsize, Ordering};

static STARTS: AtomicUsize = AtomicUsize::new(0);
static DROPS: AtomicUsize = AtomicUsize::new(0);
static CLEANED: AtomicUsize = AtomicUsize::new(0);

struct Fails;
impl Drop for Fails {
    fn drop(&mut self) {
        DROPS.fetch_add(1, Ordering::SeqCst);
    }
}

// SAFETY: the zero-sized value is initialized in one admitted unit. Its state
// records completion before the later transition intentionally returns an error.
unsafe impl<A: Allocator> InPlace<A> for Fails {
    // Two build units, the second failing, and one cleanup unit.
    const COST: ConstructionCost =
        ConstructionCost::fixed(dcbor::const_cost!(unit(0).checked_mul(3)));

    /// A third-party binding admits its own work through the one route
    /// ([`admit`]), as `InPlace` documents.
    fn build_step<'b>(
        ctx: BindingContext<'b, '_, '_, '_, Self, A>,
        a: &mut A,
    ) -> ConstructResult<Building<'b, Self>, A> {
        let mut slot = ctx.into_slot();
        let (place, state) = slot.parts();
        admit(a, 0)?;
        if *state == Written::Empty {
            // SAFETY: the slot pairs the place with this state, which is
            // empty; the write admitted above.
            unsafe { place.write(state, Self) };
            *state = Written::Initialized;
            STARTS.fetch_add(1, Ordering::SeqCst);
            return Ok(Building::Progress);
        }
        Err(wrong_type())
    }
}

// SAFETY: no child resources; explicit cleanup invalidates the initialized ZST
// exactly once and never invokes its synchronous destructor.
unsafe impl<A: Allocator> Reclaim<A> for Fails {
    type State = Written;
    const INITIAL: Written = Written::Empty;

    /// A third-party binding admits its own cleanup through the one route
    /// ([`admit`]), as `Reclaim` documents.
    fn reclaim_step(
        mut slot: Slot<'_, Self, Written>,
        cleanup: &mut Cleanup<'_, A>,
    ) -> BoundedResult<Reclaimed, A> {
        admit(cleanup, 0)?;
        let state = slot.custody();
        if *state != Written::Empty {
            CLEANED.fetch_add(1, Ordering::SeqCst);
            *state = Written::Empty;
        }
        Ok(Reclaimed::Done)
    }

    /// One call, which is `Done`.
    fn remaining(_: PeekSlot<'_, Self, Written>) -> Option<u64> {
        Some(1)
    }

    /// The zero-sized value owns no permit.
    fn observe_permits(
        _: PeekSlot<'_, Self, Written>,
        _: &mut dyn CustodySink<A::Permit>,
    ) -> PermitsObserved {
        PermitsObserved::Complete
    }
}

/// One recorded run: the decode's terminal error, its cleanup within its
/// bound, the scope drained, the finalizer refining the stream.
#[test]
fn terminal_error_does_not_reinitialize_or_destroy_partial_construction() {
    support::recorded_run(|run| {
        let policy = run.policy(u64::MAX);
        let wire = [0xf6];
        run.holding(
            DecodeOwner::new(),
            Retirement::Scope,
            &Unwitnessed,
            |owner| {
                owner.initialize(policy)?;
                owner.decoder::<_, Fails, _, _>(
                    policy,
                    support::Borrowing(&wire),
                    &Unwitnessed,
                    |decoder| {
                        let held = decoder.with_policy(policy, |_, limits| limits.live_bytes());
                        let bound = support::typed_turns::<Fails>(wire.len());
                        match decoder.drive(policy, bound, Retirement::Published, |_| ()) {
                            Err(Stopped::Operation(DecodeError::Invalid(_))) => {}
                            Err(stop) => return Err(support::Finding::from(stop)),
                            Ok(()) => {
                                return Err(support::Finding::Driver(
                                    "invalid typed construction was published".to_owned(),
                                ));
                            }
                        }
                        assert_eq!(STARTS.load(Ordering::SeqCst), 1);
                        assert_eq!(DROPS.load(Ordering::SeqCst), 0);
                        decoder.with_policy(policy, |_, limits| {
                            assert!(limits.live_bytes() > held);
                        });
                        decoder.finish(policy, bound, Retirement::Published)?;
                        assert_eq!(STARTS.load(Ordering::SeqCst), 1);
                        assert_eq!(CLEANED.load(Ordering::SeqCst), 1);
                        assert_eq!(DROPS.load(Ordering::SeqCst), 0);
                        Ok::<_, support::Finding>(())
                    },
                )??;
                assert_eq!(
                    owner.value().outstanding(),
                    0,
                    "Finished retained operation records"
                );
                owner.drain(policy)
            },
        )?;
        run.with_policy(policy, |limits| assert_eq!(limits.live_bytes(), 0));
        Ok(())
    });
}
