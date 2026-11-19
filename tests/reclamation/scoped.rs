use super::*;

struct Borrowing<'a>(&'a [u8]);

/// A [`Borrowing`]'s state: whether its reference is initialized, and the
/// borrowed bytes cleanup has checked.
struct BorrowingState {
    initialized: bool,
    checked: usize,
}

/// Whether the reference is initialized and how many bytes cleanup has
/// checked: the payload's whole custody.
impl Custody for BorrowingState {
    type Observation = (bool, usize);

    fn observe(&mut self) -> (bool, usize) {
        (self.initialized, self.checked)
    }
}

// SAFETY: the payload owns no allocation. Its input borrow is retained by the
// scope through reclamation, including after the public handle is gone.
unsafe impl Reclaim<Limits> for Borrowing<'_> {
    type State = BorrowingState;
    const INITIAL: BorrowingState = BorrowingState {
        initialized: false,
        checked: 0,
    };

    fn reclaim_step(
        mut slot: Slot<'_, Self, BorrowingState>,
        cleanup: &mut Cleanup<'_, Limits>,
    ) -> BoundedResult<Reclaimed, Limits> {
        let (place, state) = slot.parts();
        // Each unit through the one admission route for a binding outside
        // the crate.
        if !state.initialized {
            admit(cleanup, 0)?;
            return Ok(Reclaimed::Done);
        }
        admit(cleanup, 1)?;
        // SAFETY: the state is committed only after the reference is
        // initialized; the shared read ends before the state advances.
        let (byte, len) = {
            let value = unsafe { place.get(&*state) };
            (value.0[state.checked], value.0.len())
        };
        assert_eq!(byte, b'x');
        state.checked += 1;
        if state.checked == len {
            state.initialized = false;
            Ok(Reclaimed::Done)
        } else {
            Ok(Reclaimed::Progress)
        }
    }

    /// One call per borrowed byte not yet checked, the last reporting
    /// `Done`; one before the reference is initialized.
    fn remaining(mut slot: PeekSlot<'_, Self, BorrowingState>) -> Option<u64> {
        let (place, state) = slot.parts();
        if !state.initialized {
            return Some(1);
        }
        // SAFETY: the state is committed only after the reference is
        // initialized, and nothing writes it while it is counted.
        let value = unsafe { place.get(&*state) };
        // The bytes not yet checked, at least one call: `checked` never
        // passes the length (cleanup reports `Done` at it).
        let unchecked = value.0.len().checked_sub(state.checked)?;
        Some(u64::try_from(unchecked).ok()?.max(1))
    }

    /// A borrow: no permit of its own; the record's block is the record's
    /// to report.
    fn observe_permits(
        _: PeekSlot<'_, Self, BorrowingState>,
        _: &mut dyn CustodySink<<Limits as Releasing>::Permit>,
    ) -> PermitsObserved {
        PermitsObserved::Complete
    }
}

/// A record borrowing bytes that outlive its scope, retired to the queue as
/// a published handle (releasing nothing), keeps its borrow readable
/// through queued cleanup: every cleanup unit, refused once first, checks a
/// byte, and the scope shuts down holding nothing.
#[test]
fn queued_cleanup_keeps_the_input_scope_live() {
    let input = vec![b'x'; 3];
    support::recorded_run(|run| {
        let policy = run.policy(u64::MAX);
        run.holding(
            DecodeOwner::new(),
            Retirement::Scope,
            &Unwitnessed,
            |owner| {
                owner.initialize(policy)?;
                owner.lending(Retirement::Exhausted, Lent::new, |view| {
                    let scope = view.value().get();
                    view.holding(
                        Acquisition::<Borrowing<'_>, Limits>::new(),
                        Retirement::Stopped,
                        |acquisition| {
                            acquisition.with_policy(policy, |_, m| m.fresh());
                            acquisition.acquire(policy, scope, |record| {
                                record.with_policy(policy, |record, m| {
                                    m.fresh();
                                    admit(m, std::mem::size_of::<Borrowing<'_>>()).unwrap();
                                    let mut slot = record.destination();
                                    let (place, state) = slot.parts();
                                    // SAFETY: the record's empty destination;
                                    // input outlives the scope, and its borrow
                                    // remains immutable through queued cleanup.
                                    unsafe { place.write(state, Borrowing(&input)) };
                                    // Initialization is committed after the write.
                                    state.initialized = true;
                                })
                            })
                        },
                    )
                })?;
                owner.with_policy(policy, |owner, m| queued_cleanup(owner, m, input.len()));
                Ok(())
            },
        )
    });
    assert_eq!(input, [b'x'; 3]);
}

/// [`queued_cleanup_keeps_the_input_scope_live`]'s queued cleanup of the
/// record borrowing `len` bytes, under `m`, each unit refused once before
/// it is admitted.
fn queued_cleanup(owner: &mut DecodeOwner<'_, Limits>, m: &mut Limits, len: usize) {
    // The record's removal, the calls its state declares
    // ([`Reclaim::remaining`]: one per borrowed byte, the last releasing the
    // block), then the shutdown that finds the scope empty.
    let bound = len + 2;
    let mut drained = false;
    for _ in 0..bound {
        m.clear_refusal();
        m.exhaust();
        let held = m.live_bytes();
        match owner.step(m) {
            Err(BoundedError::Refused(_)) => assert_eq!(m.live_bytes(), held),
            Ok(Reclaimed::Progress) => assert!(m.live_bytes() < held),
            Ok(Reclaimed::Done) => {}
            other => panic!("unexpected cleanup result: {other:?}"),
        }
        m.clear_refusal();
        m.fresh();
        if owner.shutdown_step(m).unwrap() == Reclaimed::Done {
            drained = true;
            break;
        }
    }
    assert!(drained, "cleanup exceeded its bound of {bound} turns");
    assert_eq!(owner.outstanding(), 0);
    assert_eq!(m.live_bytes(), 0);
}
