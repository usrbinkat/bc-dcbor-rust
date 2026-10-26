//! String construction and reclamation with per-allocation custody.
extern crate alloc;

use alloc::{string::String, vec::Vec};
use core::mem::MaybeUninit;
use core::ptr::{self, NonNull};

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

/// Copying source bytes into the buffer: one value and at most a quantum.
const COPY: Capped<Caller> = Capped::new(Caller, 1, stable::QUANTUM as u64);

/// The bytes every copy but the last covers at least: a quantum less the
/// continuation bytes a text copy backs off to end on a scalar.
const COPIED: u64 = COPY.cap() - (char::MAX.len_utf8() as u64 - 1);

fn allocate_meta<A: Allocator>(
    state: &mut BufferState<A::Permit>,
    a: &mut A,
) -> BoundedResult<(), A> {
    // SAFETY: every metadata field is written.
    unsafe {
        stable::install::<Meta<A::Permit>, A>(
            &mut state.meta,
            &mut state.admitted,
            const { stable::Metadata::whole::<Meta<A::Permit>, A::Permit>() },
            |meta| {
                meta.write(Meta {
                    phase: Phase::Empty,
                    payload: None,
                    copied: 0,
                })
            },
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

/// One admitted unit of byte-buffer cleanup, shared by every binding.
/// `destroy` drops the initialized buffer header `H` in place.
///
/// # Safety
/// `state` was produced by this binding's construction, and `destroy` drops
/// exactly the buffer at the original destination.
pub(crate) unsafe fn reclaim_buffer<H, A: Allocator>(
    state: &mut BufferState<A::Permit>,
    destroy: impl FnOnce(),
    a: &mut A,
) -> BoundedResult<Reclaimed, A> {
    let Some(installed) = state.meta.as_mut() else {
        STEP.admit(a)?;
        return Ok(Reclaimed::Done);
    };
    let meta = installed.get();
    match meta.phase {
        Phase::Empty => {
            STEP.admit(a)?;
            meta.phase = Phase::BufferFreed;
        }
        Phase::Initialized
        | Phase::ReleasePayload
        | Phase::AllocatePayload
        | Phase::Copy
        | Phase::Complete => {
            sized::<H>().admit(a)?;
            destroy();
            meta.phase = Phase::BufferFreed;
        }
        Phase::BufferFreed => {
            // The payload's permit, if one was granted, and the metadata are
            // released: both releases were paid for by their acquisitions.
            drop(meta.payload.take());
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

    unsafe fn reclaim_step(
        place: NonNull<MaybeUninit<Self>>,
        state: &mut Self::State,
        a: &mut A,
    ) -> BoundedResult<Reclaimed, A> {
        // SAFETY: the buffer phases prove String initialization. This is the
        // built-in byte-buffer destructor, not an arbitrary custom Drop.
        unsafe {
            reclaim_buffer::<String, A>(
                state,
                || ptr::drop_in_place(place.as_ptr().cast::<String>()),
                a,
            )
        }
    }

    unsafe fn remaining(_: NonNull<MaybeUninit<Self>>, state: &mut Self::State) -> u64 {
        buffer_remaining(state)
    }
}

/// One admitted unit of byte-buffer construction, shared by every binding:
/// metadata, then the empty header `H` written in place, then one payload
/// reservation, then copies of at most one quantum ([`COPY`]). A `text`
/// source is valid UTF-8 and each copy ends on a scalar boundary.
///
/// # Safety
/// `empty` writes the binding's empty buffer at the original destination;
/// `buffer` returns that buffer's byte vector once it is written. The state
/// and destination are the binding's original construction pair.
pub(crate) unsafe fn copy_buffer<H, A: Allocator>(
    source: &[u8],
    text: bool,
    empty: impl FnOnce(),
    buffer: impl FnOnce() -> *mut Vec<u8>,
    state: &mut BufferState<A::Permit>,
    a: &mut A,
) -> BoundedResult<Built, A> {
    let Some(installed) = state.meta.as_mut() else {
        allocate_meta(state, a)?;
        return Ok(Built::Progress);
    };
    let meta = installed.get();
    match meta.phase {
        Phase::Empty => {
            sized::<H>().admit(a)?;
            empty();
            meta.phase = Phase::Initialized;
        }
        Phase::Initialized => {
            STEP.admit(a)?;
            meta.phase = Phase::ReleasePayload;
        }
        Phase::ReleasePayload => {
            stable::admit_release(a)?;
            meta.phase = Phase::AllocatePayload;
        }
        Phase::AllocatePayload => {
            let bytes = u64::try_from(source.len()).map_err(|_| BoundedError::Overflow)?;
            meta.payload = Some(a.allocate(bytes).map_err(BoundedError::Refused)?);
            // SAFETY: Initialized proves a valid empty buffer.
            unsafe { &mut *buffer() }
                .try_reserve_exact(source.len())
                .map_err(|_| BoundedError::Allocation { bytes })?;
            meta.phase = Phase::Copy;
        }
        Phase::Copy => {
            let start = meta.copied;
            let remaining = source
                .len()
                .checked_sub(start)
                .ok_or(BoundedError::PlanMismatch)?;
            let mut end = start + remaining.min(stable::QUANTUM);
            // A UTF-8 scalar boundary is at most three bytes before the end.
            while text && end < source.len() && source[end] & 0xc0 == 0x80 {
                end -= 1;
            }
            COPY.admit(a, (end - start) as u64)?;
            // SAFETY: Copy proves initialization and reserved capacity; text
            // chunks are whole scalars of a validated source.
            unsafe { &mut *buffer() }.extend_from_slice(&source[start..end]);
            meta.copied = end;
            if end == source.len() {
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

    unsafe fn build_step(
        document: &Document<'_, A::Permit>,
        index: usize,
        place: NonNull<MaybeUninit<Self>>,
        state: &mut Self::State,
        a: &mut A,
    ) -> ConstructResult<Built, A> {
        let Some(Kind::Text(source)) = node_at(document, index).map(|n| n.kind()) else {
            return rejected(a);
        };
        let place = place.as_ptr().cast::<String>();
        // SAFETY: the destination is the original String slot; its vector is
        // reached only after the empty String is written.
        unsafe {
            copy_buffer::<String, A>(
                source.as_bytes(),
                true,
                || place.write(String::new()),
                || (*place).as_mut_vec(),
                state,
                a,
            )
        }
        .map_err(Into::into)
    }
}
