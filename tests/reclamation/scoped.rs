use super::*;
use dcbor::bounded::decode::construction::reclamation::Custody;

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

    #[expect(
        clippy::disallowed_methods,
        reason = "a custom resource binding admits its own cleanup, as `Reclaim` documents"
    )]
    unsafe fn reclaim_step(
        place: NonNull<MaybeUninit<Self>>,
        state: &mut BorrowingState,
        a: &mut Limits,
    ) -> BoundedResult<Reclaimed, Limits> {
        if !state.initialized {
            a.traverse(1, 0).map_err(BoundedError::Refused)?;
            return Ok(Reclaimed::Done);
        }
        a.traverse(1, 1).map_err(BoundedError::Refused)?;
        // SAFETY: the state is committed only after the reference is
        // initialized.
        let value = unsafe { place.as_ref().assume_init_ref() };
        assert_eq!(value.0[state.checked], b'x');
        state.checked += 1;
        if state.checked == value.0.len() {
            state.initialized = false;
            Ok(Reclaimed::Done)
        } else {
            Ok(Reclaimed::Progress)
        }
    }

    /// One call per borrowed byte not yet checked, the last reporting
    /// `Done`; one before the reference is initialized.
    unsafe fn remaining(place: NonNull<MaybeUninit<Self>>, state: &mut BorrowingState) -> u64 {
        if !state.initialized {
            return 1;
        }
        // SAFETY: the state is committed only after the reference is
        // initialized.
        let value = unsafe { place.as_ref().assume_init_ref() };
        (value.0.len().saturating_sub(state.checked) as u64).max(1)
    }
}

#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "a custom resource binding admits its record's initialization, as \
              `OwnedRecord::destination` documents"
)]
fn queued_cleanup_keeps_the_input_scope_live() {
    let input = vec![b'x'; 3];
    let mut m = meter();
    let mut owner = scope(&mut m);
    m.fresh();
    let mut record = support::acquire::<Borrowing<'_>>(&owner, &mut m, &mut Acquisition::new());
    m.fresh();
    m.traverse(1, std::mem::size_of::<Borrowing<'_>>() as u64)
        .unwrap();
    // SAFETY: input outlives the scope, and its borrow remains immutable
    // through queued cleanup. Initialization is committed after the write.
    unsafe {
        let (place, state) = record.destination();
        place.as_ptr().write(MaybeUninit::new(Borrowing(&input)));
        state.initialized = true;
    }
    let held = m.live_bytes();
    drop(record);
    assert_eq!(m.live_bytes(), held);
    // The record's removal, the calls its state declares
    // ([`Reclaim::remaining`]: one per borrowed byte, the last releasing the
    // block), then the shutdown that finds the scope empty.
    let bound = input.len() + 2;
    let mut drained = false;
    for _ in 0..bound {
        m.clear_refusal();
        m.exhaust();
        let held = m.live_bytes();
        match owner.step(&mut m) {
            Err(BoundedError::Refused(_)) => assert_eq!(m.live_bytes(), held),
            Ok(Reclaimed::Progress) => assert!(m.live_bytes() < held),
            Ok(Reclaimed::Done) => {}
            other => panic!("unexpected cleanup result: {other:?}"),
        }
        m.clear_refusal();
        m.fresh();
        if owner.shutdown_step(&mut m).unwrap() == Reclaimed::Done {
            drained = true;
            break;
        }
    }
    assert!(drained, "cleanup exceeded its bound of {bound} turns");
    assert_eq!(owner.outstanding(), 0);
    assert_eq!(m.live_bytes(), 0);
    drop(owner);
    assert_eq!(input, [b'x'; 3]);
}
