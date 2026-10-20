//! Small, admitted writes into stable, uninitialized internal metadata.
use crate::bounded::{Allocator, BoundedError, BoundedResult};

/// # Safety
/// `place` is aligned, writable, and uninitialized. The factory constructs only
/// resource-free metadata, with bounded execution independent of input length.
/// The caller records this field's initialization before returning.
pub(crate) unsafe fn field<T, A: Allocator>(
    place: *mut T,
    make: impl FnOnce() -> T,
    a: &mut A,
) -> BoundedResult<(), A> {
    let bytes = core::mem::size_of::<T>();
    if bytes > 64 {
        return Err(BoundedError::PlanMismatch);
    }
    a.traverse(1, bytes as u64).map_err(BoundedError::Refused)?;
    unsafe { place.write(make()) };
    Ok(())
}
