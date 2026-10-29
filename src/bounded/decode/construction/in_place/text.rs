//! String construction and reclamation with per-allocation custody.
extern crate alloc;

use alloc::{string::String, vec::Vec};

use super::*;
use crate::bounded::Capped;
use crate::bounded::decode::construction::reclamation::{Admitted, Custody, Reduction};
use crate::bounded::decode::construction::stable::{self, Installed};

/// Where a byte buffer's construction or cleanup is: its empty header
/// written, its payload's reservation, release and allocation, the copy,
/// completion; then the buffer freed, its payload permit and metadata
/// released next.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    Empty,
    /// The empty header written; the payload's reservation unit is next.
    Initialized,
    /// The reservation unit admitted; the payload's release is next.
    ReleasePayload,
    /// Both admitted; the payload's allocation is next.
    AllocatePayload,
    Copy,
    Complete,
    BufferFreed,
}

/// Custody of one byte buffer: its phase, its payload permit, and the source
/// bytes copied so far. Shared by every in-place byte buffer binding
/// (`String`, `ByteString`). The copy's progress lives here, in the block,
/// rather than in the state: a byte buffer is a scope record's whole payload
/// when an input is copied, and a record's metadata, its state included, is
/// written in one unit of at most a quantum.
pub(crate) struct Meta<P> {
    pub(crate) phase: Phase,
    pub(crate) payload: Option<P>,
    copied: usize,
}

/// The construction state of a byte buffer with permits of `P`: its
/// metadata, once installed, and what that installation has admitted. Only
/// the shared buffer engine reads or changes it.
pub struct BufferState<P> {
    meta: Option<Installed<Meta<P>, P>>,
    admitted: stable::Admitted,
}

impl<P> BufferState<P> {
    /// Nothing installed, nothing copied.
    pub const INITIAL: Self = Self {
        meta: None,
        admitted: stable::Admitted::Nothing,
    };

    /// The installed metadata, borrowed from the state: released before the
    /// header's place is accessed under the state, the place's custody.
    fn installed<R>(&mut self) -> Result<&mut Meta<P>, BoundedError<R>> {
        self.meta
            .as_mut()
            .map(Installed::get)
            .ok_or(BoundedError::PlanMismatch)
    }
}

/// What a byte buffer's construction holds: no metadata block, with the
/// admissions held toward it; or the block.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum BufferObservation {
    Unallocated(Admitted),
    Held(BufferCustody),
}

/// A byte buffer's custody once its metadata is held: the phase, whether
/// its payload permit is held, and the source bytes copied into the payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct BufferCustody {
    pub phase: Phase,
    pub payload: bool,
    pub copied: usize,
}

/// The cleanup classes of a byte buffer ([`Reduction`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum BufferClass {
    /// No metadata: one unit completes cleanup.
    Unallocated,
    /// Nothing written: one unit frees nothing and reaches `Freed` without
    /// a payload.
    Empty,
    /// The header written, in any phase from `Initialized` to `Complete`:
    /// one unit drops the header, freeing the payload's allocation if one
    /// was made, and reaches `Freed`, the payload permit kept.
    Written { payload: bool },
    /// The buffer freed: the permit, if held, and the metadata are released
    /// without admission, completing cleanup.
    Freed { payload: bool },
}

// Cleanup (`reclaim_buffer`) reads the metadata's presence, the phase only
// to separate `Empty`, the written phases and `BufferFreed`, and the payload
// permit's presence; the bytes copied and the admissions held toward an
// unacquired block never change a cleanup unit. Each class above maps to
// one cleanup unit and one successor class, so the relation is a
// simulation of cleanup.
impl<P> Reduction for BufferState<P> {
    type Class = BufferClass;

    fn class(observation: &BufferObservation) -> BufferClass {
        match *observation {
            BufferObservation::Unallocated(_) => BufferClass::Unallocated,
            BufferObservation::Held(BufferCustody { phase, payload, .. }) => match phase {
                Phase::Empty => BufferClass::Empty,
                Phase::BufferFreed => BufferClass::Freed { payload },
                Phase::Initialized
                | Phase::ReleasePayload
                | Phase::AllocatePayload
                | Phase::Copy
                | Phase::Complete => BufferClass::Written { payload },
            },
        }
    }
}

impl<P> Custody for BufferState<P> {
    type Observation = BufferObservation;

    fn observe(&mut self) -> BufferObservation {
        let Some(installed) = self.meta.as_mut() else {
            return BufferObservation::Unallocated(self.admitted);
        };
        let meta = installed.get();
        BufferObservation::Held(BufferCustody {
            phase: meta.phase,
            payload: meta.payload.is_some(),
            copied: meta.copied,
        })
    }
}

/// A byte buffer header the shared engine builds and reclaims in place
/// ([`copy_buffer`], [`reclaim_buffer`]): `String` and `ByteString`.
///
/// # Safety
/// [`Self::empty`] owns no allocation. [`Self::bytes`] returns the header's
/// own byte vector, owned by it alone. Dropping the header frees only that
/// vector's allocation and runs no other code. A vector holding the
/// concatenation of pieces of [`Self::Source`] values, each piece starting
/// and ending where [`Self::boundary`] allows, is a valid header.
pub(crate) unsafe trait Buffer: Sized {
    /// What the header is copied from: a validated text for a `String`,
    /// any bytes for a `ByteString`.
    type Source: ?Sized;
    /// The empty header, written before its bytes are reserved.
    fn empty() -> Self;
    /// The source's bytes.
    fn source(source: &Self::Source) -> &[u8];
    /// Whether a copy may start or end at byte `at` of `source`.
    fn boundary(source: &Self::Source, at: usize) -> bool;
    /// The header's own byte vector.
    ///
    /// # Safety
    /// The vector holds a valid header's bytes ([`Buffer`]) whenever the
    /// header is next used.
    unsafe fn bytes(&mut self) -> &mut Vec<u8>;
}

// SAFETY: an empty String owns no allocation; its vector is its own, and
// dropping it frees only that vector; whole scalars of validated texts
// concatenate to valid UTF-8, and a copy starts and ends only on a scalar
// boundary.
unsafe impl Buffer for String {
    type Source = str;

    fn empty() -> Self {
        String::new()
    }

    fn source(source: &str) -> &[u8] {
        source.as_bytes()
    }

    fn boundary(source: &str, at: usize) -> bool {
        source.is_char_boundary(at)
    }

    unsafe fn bytes(&mut self) -> &mut Vec<u8> {
        // SAFETY: forwarded from the caller: the vector stays valid UTF-8.
        unsafe { self.as_mut_vec() }
    }
}

/// Copying source bytes into the buffer: one value and at most a quantum.
const COPY: Capped<Caller> = Capped::new(Caller, 1, stable::QUANTUM as u64);

/// The bytes every copy but the last covers at least: a quantum less the
/// continuation bytes a text copy backs off to end on a scalar.
const COPIED: u64 = COPY.cap() - (char::MAX.len_utf8() as u64 - 1);

fn allocate_meta<A: Allocator>(
    state: &mut BufferState<A::Permit>,
    a: &mut A,
) -> BoundedResult<(), A> {
    // SAFETY: the header is the whole metadata, every field written.
    unsafe {
        stable::install::<Meta<A::Permit>, Meta<A::Permit>, A>(
            &mut state.meta,
            &mut state.admitted,
            || Meta {
                phase: Phase::Empty,
                payload: None,
                copied: 0,
            },
            |meta| meta,
            a,
        )
    }
}

/// The cost of a byte buffer of header `H`, built by [`copy_buffer`] and
/// reclaimed by [`reclaim_buffer`], shared by every binding. Fixed: the
/// metadata block, held for the value's life; the empty header's write; the
/// payload reservation step and the payload's release, admitted before it
/// is allocated; the last copy's value; then cleanup's header drop and the
/// metadata's release. A node of the wrong kind is refused by one step
/// before any of them. Per byte: every copy but the last covers at least
/// [`COPIED`] bytes, so its values are at most `PER_BYTE_SCALE / COPIED`
/// sixty-fourths per byte, rounded up; every byte copied once; the payload,
/// of at most every byte of the subtree, held.
pub(crate) const fn buffer_cost<H, P>() -> ConstructionCost {
    let meta = stable::Metadata::whole::<Meta<P>, P>().bytes();
    let last = Unit::new(Caller, COPY.values(), 0).bound();
    let build = plus(
        plus(
            plus(
                stable::install_cost::<Meta<P>, P>(),
                stable::release_cost::<P>(),
            ),
            sized::<H>().bound(),
        ),
        plus(plus(STEP_COST, stable::release_cost::<P>()), last),
    );
    let cleanup = buffer_cleanup::<H>();
    ConstructionCost {
        fixed: plus(plus(build, cleanup), held(meta)),
        per_byte: ResourceBound {
            values: COPY.values() * PER_BYTE_SCALE.div_ceil(COPIED),
            bytes: PER_BYTE_SCALE,
            allocated: PER_BYTE_SCALE,
            peak: PER_BYTE_SCALE,
            retained: PER_BYTE_SCALE,
        },
    }
}

/// The cleanup of a complete byte buffer of header `H` ([`reclaim_buffer`]):
/// its header dropped; its payload permit's release and its metadata's were
/// paid for when each was acquired.
pub(crate) const fn buffer_cleanup<H>() -> ResourceBound {
    sized::<H>().bound()
}

/// One admitted unit of byte-buffer cleanup, shared by every binding: the
/// header `H` in `slot`, once written, dropped in place. Releasing the
/// metadata leaves the state `INITIAL`.
pub(crate) fn reclaim_buffer<H: Buffer, A: Allocator>(
    mut slot: Slot<'_, H, BufferState<A::Permit>>,
    a: &mut A,
) -> BoundedResult<Reclaimed, A> {
    let (place, state) = slot.parts();
    if state.meta.is_none() {
        STEP.admit(a)?;
        return Ok(Reclaimed::Done);
    }
    match state.installed()?.phase {
        Phase::Empty => {
            STEP.admit(a)?;
            state.installed()?.phase = Phase::BufferFreed;
        }
        Phase::Initialized
        | Phase::ReleasePayload
        | Phase::AllocatePayload
        | Phase::Copy
        | Phase::Complete => {
            sized::<H>().admit(a)?;
            // SAFETY: the slot pairs the place with this state, whose written
            // phases prove the header initialized; a `Buffer`'s drop frees
            // only its bytes.
            unsafe { place.drop_in_place(state) };
            state.installed()?.phase = Phase::BufferFreed;
        }
        Phase::BufferFreed => {
            // The payload's permit, if one was granted, and the metadata are
            // released: both releases were paid for by their acquisitions.
            drop(state.installed()?.payload.take());
            // SAFETY: the buffer is dropped and owns nothing.
            unsafe { stable::uninstall(&mut state.meta) };
            return Ok(Reclaimed::Done);
        }
    }
    Ok(Reclaimed::Progress)
}

/// The calls byte-buffer cleanup ([`reclaim_buffer`]) still takes from
/// `state`: none installed, one; nothing written, or the header written in
/// any phase, two (the header dropped or the empty buffer marked freed, then
/// the releases); freed, one.
pub(crate) fn buffer_remaining<P>(state: &mut BufferState<P>) -> u64 {
    match state.meta.as_mut().map(|installed| installed.get().phase) {
        None | Some(Phase::BufferFreed) => 1,
        Some(_) => 2,
    }
}

// SAFETY: every initialized String is recorded before returning. String's
// byte buffer has no element destructors. Its storage is freed in one admitted
// step, then its payload permit and the metadata storage and its permit,
// releases their acquisitions paid for.
unsafe impl<A: Allocator> Reclaim<A> for String {
    type State = BufferState<A::Permit>;
    const INITIAL: Self::State = BufferState::INITIAL;

    fn reclaim_step(slot: Slot<'_, Self, Self::State>, a: &mut A) -> BoundedResult<Reclaimed, A> {
        reclaim_buffer::<String, A>(slot, a)
    }

    fn remaining(mut slot: PeekSlot<'_, Self, Self::State>) -> u64 {
        buffer_remaining(slot.custody())
    }
}

/// One admitted unit of byte-buffer construction, shared by every binding:
/// metadata, then the empty header `H` written in `slot`, then one payload
/// reservation, then copies of at most one quantum ([`COPY`]) into the
/// header's byte vector. Each copy starts and ends where the source's
/// [`Buffer::boundary`] allows, so the vector stays a valid header's bytes,
/// and never exceeds the capacity reserved, so it never reallocates: a source
/// that does not continue the copy so far (one copy starting off a boundary,
/// or more bytes than were reserved) is refused before anything is admitted.
/// A header holds no place of its own: its bytes are a separate allocation,
/// so borrowing the header for one call invalidates nothing.
pub(crate) fn copy_buffer<H: Buffer, A: Allocator>(
    source: &H::Source,
    mut slot: Slot<'_, H, BufferState<A::Permit>>,
    a: &mut A,
) -> BoundedResult<Built, A> {
    let (place, state) = slot.parts();
    let bytes = H::source(source);
    if state.meta.is_none() {
        allocate_meta(state, a)?;
        return Ok(Built::Progress);
    }
    match state.installed()?.phase {
        Phase::Empty => {
            sized::<H>().admit(a)?;
            // SAFETY: the slot pairs the place with this state, whose phase
            // says nothing is written yet; the write is admitted above.
            unsafe { place.write(state, H::empty()) };
            state.installed()?.phase = Phase::Initialized;
        }
        Phase::Initialized => {
            STEP.admit(a)?;
            state.installed()?.phase = Phase::ReleasePayload;
        }
        Phase::ReleasePayload => {
            stable::admit_release(a)?;
            state.installed()?.phase = Phase::AllocatePayload;
        }
        Phase::AllocatePayload => {
            if state.installed()?.payload.is_some() {
                // A permit is already held: a step after a failed
                // reservation, refused rather than releasing it unadmitted.
                return Err(BoundedError::PlanMismatch);
            }
            let requested = u64::try_from(bytes.len()).map_err(|_| BoundedError::Overflow)?;
            state.installed()?.payload =
                Some(a.allocate(requested).map_err(BoundedError::Refused)?);
            // SAFETY: Initialized proves a valid empty header, which holds no
            // place; reserving leaves its vector empty, a valid header's
            // bytes.
            unsafe {
                place.with_mut(state, |header| {
                    H::bytes(header).try_reserve_exact(bytes.len())
                })
            }
            .map_err(|_| BoundedError::Allocation { bytes: requested })?;
            state.installed()?.phase = Phase::Copy;
        }
        Phase::Copy => {
            let start = state.installed()?.copied;
            let remaining = bytes
                .len()
                .checked_sub(start)
                .ok_or(BoundedError::PlanMismatch)?;
            if !H::boundary(source, start) {
                return Err(BoundedError::PlanMismatch);
            }
            let mut end = start + remaining.min(stable::QUANTUM);
            // A boundary is at most three bytes before the end: a scalar is
            // at most four bytes.
            while end > start && !H::boundary(source, end) {
                end -= 1;
            }
            if end == start && remaining != 0 {
                return Err(BoundedError::PlanMismatch);
            }
            // SAFETY: Copy proves the header initialized; it holds no place,
            // and reading its capacity leaves its vector unchanged.
            let spare = unsafe {
                place.with_mut(state, |header| {
                    let vector = H::bytes(header);
                    vector.capacity() - vector.len()
                })
            };
            if end - start > spare {
                return Err(BoundedError::PlanMismatch);
            }
            COPY.admit(a, (end - start) as u64)?;
            // SAFETY: Copy proves initialization, and the chunk fits the
            // capacity reserved, so nothing reallocates; the chunk starts and
            // ends on the source's boundaries, so the vector stays a valid
            // header's bytes; the header holds no place.
            unsafe {
                place.with_mut(state, |header| {
                    H::bytes(header).extend_from_slice(&bytes[start..end])
                })
            };
            let meta = state.installed()?;
            meta.copied = end;
            if end == bytes.len() {
                meta.phase = Phase::Complete;
                return Ok(Built::Done);
            }
        }
        _ => return Err(BoundedError::PlanMismatch),
    }
    Ok(Built::Progress)
}

// SAFETY: construction writes the String header directly into its final place,
// reserves its byte allocation once, and appends only admitted UTF-8 chunks.
// All phases, including allocation failures, are understood by Reclaim above.
unsafe impl<A: Allocator> InPlace<A> for String {
    const COST: ConstructionCost = buffer_cost::<String, A::Permit>();

    fn build_step(
        document: &Document<'_, A::Permit>,
        index: usize,
        slot: Slot<'_, Self, Self::State>,
        a: &mut A,
    ) -> ConstructResult<Built, A> {
        let Some(Kind::Text(source)) = node_at(document, index).map(|n| n.kind()) else {
            return rejected(a);
        };
        copy_buffer::<String, A>(source, slot, a).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounded::{Limits, Reservation};

    /// A byte buffer's cost, evaluated at run time as every buffer binding
    /// evaluates it in constants: per byte, every byte copied, allocated,
    /// held and retained once, and the copies' values, each copy but the
    /// last covering at least a quantum less the three continuation bytes a
    /// text copy backs off (61 of 64), at `ceil(64 / 61) = 2` sixty-fourths;
    /// fixed, cleanup's header drop among its parts.
    #[test]
    fn a_buffers_cost_charges_each_byte_once_and_a_copy_per_61_bytes() {
        assert_eq!(COPIED, 61);
        let cost = buffer_cost::<String, Reservation>();
        assert_eq!(cost, <String as InPlace<Limits>>::COST);
        assert_eq!(
            cost.per_byte,
            ResourceBound {
                values: 2,
                bytes: 64,
                allocated: 64,
                peak: 64,
                retained: 64,
            }
        );
        assert_eq!(buffer_cleanup::<String>(), sized::<String>().bound());
    }
}
