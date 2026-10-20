use super::*;
use dcbor::bounded::decode::construction::in_place::{Destination, Step};
use dcbor::bounded::decode::{DecodeError, decode};

#[test]
fn cancelled_destination_reclaims_without_the_document() {
    let wire = [0x82, 0x61, b'a', 0x61, b'b'];
    let mut reached_publication = false;
    for stop in 0..256 {
        let mut a = Turn::new();
        a.values = u64::MAX;
        a.bytes = u64::MAX;
        let document = decode(&wire, 8, &mut a).unwrap();
        let owner = Reclaimer::new();
        let mut destination = Destination::<Vec<String>, Turn>::new(&owner);
        let mut output = None;
        for _ in 0..stop {
            a.fresh();
            // SAFETY: every step uses this same immutable document and root.
            match unsafe { destination.step(&document, 0, &mut a) }.unwrap() {
                Step::Progress => {}
                Step::Complete(value) => {
                    assert_eq!(value.value(), &["a", "b"]);
                    output = Some(value);
                    reached_publication = true;
                    break;
                }
                Step::Finished => panic!("construction skipped publication"),
            }
        }
        let held = a.live.load(Ordering::SeqCst);
        destination.cancel();
        assert_eq!(a.live.load(Ordering::SeqCst), held);
        // Cleanup must not dereference the document or borrow its arena.
        drop(document);
        let mut done = false;
        for _ in 0..256 {
            a.values = 0;
            a.bytes = 0;
            let held = a.live.load(Ordering::SeqCst);
            match destination.reclaim_step(&mut a) {
                Err(BoundedError::Refused(())) => {
                    assert_eq!(a.live.load(Ordering::SeqCst), held);
                }
                Ok(Reclaimed::Done) => {
                    done = true;
                    break;
                }
                _ => panic!("cleanup advanced without admission"),
            }
            a.fresh();
            if destination.reclaim_step(&mut a).unwrap() == Reclaimed::Done {
                done = true;
                break;
            }
        }
        assert!(done);
        drop(destination);
        drop(output);
        for _ in 0..256 {
            a.fresh();
            if owner.shutdown_step(&mut a).unwrap() == Reclaimed::Done {
                break;
            }
        }
        assert_eq!(owner.outstanding(), 0);
        assert_eq!(a.live.load(Ordering::SeqCst), 0);
        if reached_publication {
            break;
        }
    }
    assert!(reached_publication);
}

#[test]
fn terminal_allocation_error_is_not_replayed() {
    let mut a = Turn::new();
    a.values = u64::MAX;
    a.bytes = u64::MAX;
    let document = decode(&[7], 8, &mut a).unwrap();
    let owner = Reclaimer::new();
    assert_eq!(owner.shutdown_step(&mut a).unwrap(), Reclaimed::Done);
    let mut destination = Destination::<u64, Turn>::new(&owner);
    a.fresh();
    // SAFETY: every call uses the same immutable document and root.
    assert!(matches!(
        unsafe { destination.step(&document, 0, &mut a) },
        Err(DecodeError::Resource(BoundedError::PlanMismatch))
    ));
    a.fresh();
    assert!(matches!(
        unsafe { destination.step(&document, 0, &mut a) },
        Ok(Step::Progress)
    ));
    assert!(matches!(
        unsafe { destination.step(&document, 0, &mut a) },
        Ok(Step::Finished)
    ));
    drop(destination);
    drop(document);
    assert_eq!(a.live.load(Ordering::SeqCst), 0);
}
