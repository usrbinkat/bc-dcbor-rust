//! Small, admitted writes into stable, uninitialized internal metadata.
use super::construction::stable::QUANTUM;
use crate::bounded::{Allocator, BoundedError, BoundedResult, Caller, Unit, WriteWork, mul, widen};

/// Any one field written: one value and at most a quantum of bytes. What a
/// bound counts per field of a type it does not name.
pub(crate) const FIELD: crate::bounded::Capped<Caller> =
    crate::bounded::Capped::new(Caller, 1, QUANTUM as u64);

/// Every field of a `T` written once, in `steps` units: one value each and
/// the fields' own bytes, disjoint parts of a `T`, at most its size
/// together. What a bound counts for the initialization of a type it names.
pub(crate) fn fields<T, R>(steps: usize) -> Result<WriteWork, BoundedError<R>> {
    Ok(WriteWork::new(
        mul(widen(steps)?, FIELD.values())?,
        widen(core::mem::size_of::<T>())?,
    ))
}

/// # Safety
/// `place` is aligned, writable, and uninitialized. The factory constructs only
/// resource-free metadata, with bounded execution independent of input length.
/// The caller records this field's initialization before returning.
pub(crate) unsafe fn field<T, A: Allocator>(
    place: *mut T,
    make: impl FnOnce() -> T,
    a: &mut A,
) -> BoundedResult<(), A> {
    // One field written: one value and the field's bytes. The caller
    // supplies the place.
    const { Unit::<Caller>::written::<T>(Caller) }.admit(a)?;
    unsafe { place.write(make()) };
    Ok(())
}
