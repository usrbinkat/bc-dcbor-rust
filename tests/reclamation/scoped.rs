use super::*;
use dcbor::bounded::decode::construction::reclamation::ScopedReclaimer;

struct Borrowed<'a>(&'a [u8]);

// SAFETY: the payload owns no allocation. Its input borrow is retained by the
// scoped owner through reclamation, including after the public handle is gone.
unsafe impl Reclaim<Turn> for Borrowed<'_> {
    unsafe fn reclaim_step(
        place: NonNull<MaybeUninit<Self>>,
        cursor: &mut Cursor,
        a: &mut Turn,
    ) -> BoundedResult<Reclaimed, Turn> {
        if cursor.state == 0 {
            a.traverse(1, 0).map_err(BoundedError::Refused)?;
            return Ok(Reclaimed::Done);
        }
        a.traverse(1, 1).map_err(BoundedError::Refused)?;
        // SAFETY: state is committed only after the reference is initialized.
        let value = unsafe { place.as_ref().assume_init_ref() };
        assert_eq!(value.0[cursor.position], b'x');
        cursor.position += 1;
        if cursor.position == value.0.len() {
            cursor.state = 0;
            Ok(Reclaimed::Done)
        } else {
            Ok(Reclaimed::Progress)
        }
    }
}

#[test]
fn queued_cleanup_keeps_the_input_scope_live() {
    let input = vec![b'x'; 3];
    let owner = ScopedReclaimer::new();
    let mut a = Turn::new();
    let mut record = owner.allocate::<Borrowed<'_>>(&mut a).unwrap();
    a.fresh();
    a.traverse(1, std::mem::size_of::<Borrowed<'_>>() as u64)
        .unwrap();
    // SAFETY: input outlives the scoped owner, and its borrow remains immutable
    // through queued cleanup. Initialization is committed after the write.
    unsafe {
        let (place, cursor) = record.destination();
        place.as_ptr().write(MaybeUninit::new(Borrowed(&input)));
        cursor.state = 1;
    }
    let held = a.live.load(Ordering::SeqCst);
    drop(record);
    assert_eq!(a.live.load(Ordering::SeqCst), held);
    for _ in 0..8 {
        a.values = 0;
        a.bytes = 0;
        assert!(matches!(owner.step(&mut a), Err(BoundedError::Refused(()))));
        a.fresh();
        if owner.shutdown_step(&mut a).unwrap() == Reclaimed::Done {
            break;
        }
    }
    assert_eq!(owner.outstanding(), 0);
    assert_eq!(a.live.load(Ordering::SeqCst), 0);
    drop(owner);
    assert_eq!(input, [b'x'; 3]);
}
