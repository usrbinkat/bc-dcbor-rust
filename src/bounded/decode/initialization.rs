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

/// One field written, admitted first: one value and the field's bytes. The
/// factory constructs only resource-free metadata, with bounded execution
/// independent of input length, and the caller records the field's
/// initialization before returning. Writing never reads or drops what the
/// place held: a field written twice leaks its first value, never reads it.
///
/// Every write of a destination initialized field by field goes through a
/// [`Slot`](super::construction::reclamation::Slot) of it and its unit count,
/// by [`init_field!`] or [`init_part!`], which discharge this obligation by
/// field syntax over the slot's place.
///
/// # Safety
/// `place` is valid for a write of a `T` and aligned for it.
pub(crate) unsafe fn field<T, A: Allocator>(
    place: *mut T,
    make: impl FnOnce() -> T,
    a: &mut A,
) -> BoundedResult<(), A> {
    // One field written: one value and the field's bytes. The caller
    // supplies the place.
    const { Unit::<Caller>::written::<T>(Caller) }.admit(a)?;
    // SAFETY: forwarded from the caller.
    unsafe { place.write(make()) };
    Ok(())
}

/// Write field `$field` (a path of field names) of the destination `$slot`,
/// a `Slot<'_, T, usize>` pairing it with its units initialized, in one
/// admitted unit ([`field`]). The caller advances the units.
///
/// Sound for any slot: the slot's place is valid, aligned and writable for
/// its value for the slot's whole borrow ([`Place::root`]), and field syntax
/// on the value's raw pointer reaches a field within it without dereferencing
/// anything or forming a reference, so the write is in bounds and aligned.
///
/// [`Place::root`]: super::construction::reclamation::Place::root
macro_rules! init_field {
    ($slot:expr, $($field:ident).+, $make:expr, $a:expr) => {{
        let (place, units) = $slot.parts();
        let raw = place.as_ptr(units);
        // SAFETY: a field of the slot's own destination, reached by field
        // syntax on its raw pointer: valid and aligned for the write.
        unsafe {
            $crate::bounded::decode::initialization::field(
                ::core::ptr::addr_of_mut!((*raw).$($field).+),
                $make,
                $a,
            )
        }
    }};
}
pub(crate) use init_field;

/// Initialize one unit of the nested part `$field` (a field name) of the
/// destination `$slot`, a `Slot<'_, T, usize>`, whose units `$base` up to
/// `$base` plus the part's own are the part's: `$init`, given the part's slot
/// as `$part` (its place by field syntax, its own units counted from
/// `$base`), initializes it; the parent's units are then `$base` and the
/// part's. Evaluates to `$init`'s value.
///
/// Sound for any slot whose units are at least `$base`: units are initialized
/// in order, so the parent's count less `$base` is exactly what the part
/// holds, its own custody, and its place is a field of the parent's.
macro_rules! init_part {
    ($slot:expr, $field:ident, $base:expr, |$part:ident| $init:expr) => {{
        let (place, units) = $slot.parts();
        let base: usize = $base;
        let mut part_units = units
            .checked_sub(base)
            .ok_or($crate::bounded::BoundedError::PlanMismatch)?;
        let result = {
            // SAFETY: the part's place is a field of the slot's own
            // destination, by field syntax; its units are its own (above).
            let $part = unsafe {
                $crate::bounded::decode::construction::reclamation::Slot::new(
                    place.project(|value| ::core::ptr::addr_of_mut!((*value).$field)),
                    &mut part_units,
                )
            };
            $init
        };
        *units = base + part_units;
        result
    }};
}
pub(crate) use init_part;
