#![cfg(feature = "std")]

use dcbor::bounded::decode::construction::in_place::{Built, InPlace};
use dcbor::bounded::decode::construction::reclamation::{Cursor, Reclaim, Reclaimed};
use dcbor::bounded::decode::construction::{DecodeOwner, TypedDecoder, TypedStep};
use dcbor::bounded::decode::{ConstructResult, Document, Options, wrong_type};
use dcbor::bounded::{Allocator, BoundedError, BoundedResult, Limits};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{mem::MaybeUninit, ptr::NonNull};

static STARTS: AtomicUsize = AtomicUsize::new(0);
static DROPS: AtomicUsize = AtomicUsize::new(0);
static CLEANED: AtomicUsize = AtomicUsize::new(0);

struct Fails;
impl Drop for Fails {
    fn drop(&mut self) {
        DROPS.fetch_add(1, Ordering::SeqCst);
    }
}

// SAFETY: the zero-sized value is initialized in one admitted unit. Its cursor
// records completion before the later transition intentionally returns an error.
unsafe impl<A: Allocator> InPlace<A> for Fails {
    unsafe fn build_step(
        _: &Document<'_, A::Permit>,
        _: usize,
        place: NonNull<MaybeUninit<Self>>,
        cursor: &mut Cursor,
        a: &mut A,
    ) -> ConstructResult<Built, A> {
        a.traverse(1, 0).map_err(BoundedError::Refused)?;
        if cursor.state == 0 {
            unsafe {
                place.as_ptr().write(MaybeUninit::new(Self));
            }
            cursor.state = 1;
            STARTS.fetch_add(1, Ordering::SeqCst);
            return Ok(Built::Progress);
        }
        Err(wrong_type())
    }
}

// SAFETY: no child resources; explicit cleanup invalidates the initialized ZST
// exactly once and never invokes its synchronous destructor.
unsafe impl<A: Allocator> Reclaim<A> for Fails {
    unsafe fn reclaim_step(
        _: NonNull<MaybeUninit<Self>>,
        cursor: &mut Cursor,
        a: &mut A,
    ) -> BoundedResult<Reclaimed, A> {
        a.traverse(1, 0).map_err(BoundedError::Refused)?;
        if cursor.state != 0 {
            CLEANED.fetch_add(1, Ordering::SeqCst);
            cursor.state = 0;
        }
        Ok(Reclaimed::Done)
    }
}

#[test]
fn terminal_error_does_not_reinitialize_or_destroy_partial_construction() {
    let mut limits = Limits::new(1_000_000, 1_000_000, 1_000_000);
    let owner = DecodeOwner::new();
    let mut decoder = TypedDecoder::<Fails, _>::new(&owner, &[0xf6], Options::normalizing(8));
    let mut failed = false;
    for _ in 0..256 {
        match decoder.step(&mut limits) {
            Ok(TypedStep::Progress) => {}
            Err(_) => {
                failed = true;
                break;
            }
            _ => panic!("invalid typed construction was published"),
        }
    }
    assert!(failed);
    assert_eq!(STARTS.load(Ordering::SeqCst), 1);
    assert_eq!(DROPS.load(Ordering::SeqCst), 0);
    assert!(limits.live_bytes() > 0);
    let mut finished = false;
    for _ in 0..256 {
        match decoder.step(&mut limits).unwrap() {
            TypedStep::Progress => {}
            TypedStep::Finished => {
                finished = true;
                break;
            }
            TypedStep::Complete(_) => panic!("failed decoder published"),
        }
    }
    assert!(finished);
    assert_eq!(STARTS.load(Ordering::SeqCst), 1);
    assert_eq!(CLEANED.load(Ordering::SeqCst), 1);
    assert_eq!(DROPS.load(Ordering::SeqCst), 0);
    assert_eq!(limits.live_bytes(), 0);
    assert_eq!(owner.outstanding(), 0);
}
