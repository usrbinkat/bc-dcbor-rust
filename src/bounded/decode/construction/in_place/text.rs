//! String construction and reclamation with per-allocation custody.
extern crate alloc;

use alloc::{string::String, vec::Vec};

use super::*;
use crate::bounded::Capped;
use crate::bounded::boundary::{Bound, Predicate, boundary};
use crate::bounded::decode::construction::reclamation::{Custody, Reduction, Uniform};
use crate::bounded::decode::construction::stable::{self, Installed, Pending, Ticket};
use crate::sync::{Atomics, Representation};

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

impl<P> Representation for Meta<P> {
    type In<S: Atomics> = Self;
}

/// What the metadata block's acquisition admits and holds, its whole value
/// written with the permit ([`stable::Contract`]): the one definition its
/// installation and every buffer binding's cost read.
const fn contract<P>() -> stable::Contract<Meta<P>, Meta<P>, P> {
    stable::Contract::of()
}

/// The construction state of a byte buffer with permits of `P`: its
/// metadata, once installed, and the ticket of its acquisition pending, the
/// metadata block's or the payload's ([`Ticket`]); the acquisition's credit
/// is the operation's ([`Pending`]). Only the shared buffer engine reads or
/// changes it. Two words: a record's payload state, its write within the
/// record's one-quantum unit.
pub struct BufferState<P> {
    meta: Option<Installed<Meta<P>, P>>,
    ticket: Option<Ticket>,
}

impl<P> BufferState<P> {
    /// Nothing installed, nothing copied.
    pub const INITIAL: Self = Self {
        meta: None,
        ticket: None,
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

/// What a byte buffer's construction holds: no metadata block, or the
/// block. Progress alone: an acquisition bound for either block is the root
/// pending's custody, reported by its observation (`CustodySink::bound`),
/// never by this one, so a bind that admits nothing changes no progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum BufferObservation {
    Unallocated,
    Held(BufferCustody),
}

/// A byte buffer's custody once its metadata is held: the phase, whether
/// its payload permit is held, and the source bytes copied into the
/// payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct BufferCustody {
    pub phase: Phase,
    pub payload: bool,
    pub copied: usize,
}

/// The cleanup classes of a byte buffer ([`Reduction`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
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

/// A buffer's class is its observation's ([`BufferObservation::class`]),
/// whatever its permit.
impl<P> Reduction for BufferState<P> {
    type Class = BufferClass;

    fn class(observation: &BufferObservation) -> BufferClass {
        observation.class()
    }
}

impl BufferObservation {
    /// This observation's cleanup class ([`BufferClass`]). Cleanup
    /// (`reclaim_buffer`) reads the metadata's presence, the phase only to
    /// separate `Empty`, the written phases and `BufferFreed`, and the
    /// payload permit's presence; the bytes copied and a pending
    /// acquisition, whose credit the operation settles at its cleanup entry,
    /// never change a cleanup unit. Each class maps to one cleanup unit and
    /// one successor class, so the relation is a simulation of cleanup.
    pub fn class(&self) -> BufferClass {
        match *self {
            BufferObservation::Unallocated => BufferClass::Unallocated,
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

// A buffer's construction reports `Done` only from `Copy` once every byte is
// copied, its phase then `Complete`, and only after `AllocatePayload`
// granted its payload's permit, which `Copy` never releases: a complete
// buffer is `Written` with its payload held.
impl<P> Uniform for BufferState<P> {
    const COMPLETE: BufferClass = BufferClass::Written { payload: true };
}

impl<P> Custody for BufferState<P> {
    type Observation = BufferObservation;

    fn observe(&mut self) -> BufferObservation {
        let Some(installed) = self.meta.as_mut() else {
            return BufferObservation::Unallocated;
        };
        let meta = installed.get();
        BufferObservation::Held(BufferCustody {
            phase: meta.phase,
            payload: meta.payload.is_some(),
            copied: meta.copied,
        })
    }
}

/// Report the permits a byte buffer's state owns
/// ([`Reclaim::observe_permits`]), inside the caller's open group: its
/// metadata block's, once installed, and its payload's, once granted. A
/// buffer holds no obligation: its acquisitions' credit is the root
/// pending's ([`Pending::observe_custody`]). Read under the state's
/// custody, admitting and releasing nothing. A buffer holds no nested
/// custody, so its report is always complete.
pub(crate) fn buffer_permits<P>(
    state: &mut BufferState<P>,
    sink: &mut dyn CustodySink<P>,
) -> PermitsObserved {
    if let Some(installed) = state.meta.as_mut() {
        sink.permit(installed.permit(), None);
        if let Some(payload) = installed.get().payload.as_ref() {
            sink.permit(payload, None);
        }
    }
    PermitsObserved::Complete
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

/// The bytes a window of at most `cap` bytes over a text covers at least
/// whenever it is not the text's last: `cap` less the continuation bytes it
/// backs off to end on a scalar. The one definition every windowed pass over
/// a text's bytes ([`COPY`], the stabilized-text check) costs its windows by.
pub(crate) const fn scalar_window(cap: u64) -> u64 {
    cap - (char::MAX.len_utf8() as u64 - 1)
}

/// The bytes every copy but the last covers at least ([`scalar_window`]).
const COPIED: u64 = scalar_window(COPY.cap());

fn allocate_meta<A: Allocator>(
    state: &mut BufferState<A::Permit>,
    pending: &mut Pending<A::Origin>,
    a: &mut A,
) -> BoundedResult<(), A> {
    // SAFETY: the header is the whole metadata, every field written.
    unsafe {
        stable::install::<Meta<A::Permit>, Meta<A::Permit>, A>(
            const { contract::<A::Permit>() },
            &mut state.meta,
            pending,
            &mut state.ticket,
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
/// of at most every byte of the subtree, held. None when a quantity does
/// not fit in `u64`.
pub(crate) const fn buffer_cost<H, P>() -> Option<ConstructionCost> {
    let meta = contract::<P>();
    let last = Unit::new(Caller, COPY.values(), 0).bound();
    let written = cost!(
        cost!(meta.write().checked_add(stable::release_cost::<P>()))
            .checked_add(sized::<H>().bound())
    );
    let payload =
        cost!(cost!(STEP_COST.checked_add(stable::release_cost::<P>())).checked_add(last));
    let build = cost!(written.checked_add(payload));
    let cleanup = buffer_cleanup::<H>();
    Some(ConstructionCost {
        fixed: cost!(cost!(build.checked_add(cleanup)).checked_add(held(meta.block()))),
        per_byte: ResourceBound {
            values: cost!(COPY.values().checked_mul(PER_BYTE_SCALE.div_ceil(COPIED))),
            bytes: PER_BYTE_SCALE,
            allocated: PER_BYTE_SCALE,
            peak: PER_BYTE_SCALE,
            retained: PER_BYTE_SCALE,
        },
    })
}

/// The cleanup of a complete byte buffer of header `H` ([`reclaim_buffer`]):
/// its header dropped; its payload permit's release and its metadata's were
/// paid for when each was acquired.
pub(crate) const fn buffer_cleanup<H>() -> ResourceBound {
    sized::<H>().bound()
}

/// One admitted unit of byte-buffer cleanup, shared by every binding: the
/// header `H` in `slot`, once written, dropped in place. Releasing the
/// metadata leaves the state `INITIAL`. A pending acquisition's credit was
/// settled into its origins at the operation's cleanup entry
/// ([`Pending::settle_all`]); cleanup only forgets the ticket.
pub(crate) fn reclaim_buffer<H: Buffer, A: Allocator>(
    mut slot: Slot<'_, H, BufferState<A::Permit>>,
    a: &mut Cleanup<'_, A>,
) -> BoundedResult<Reclaimed, A> {
    let (place, state) = slot.parts();
    if state.meta.is_none() {
        STEP.admit(a)?;
        state.ticket = None;
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
            // A payload's acquisition pending (`ReleasePayload` admitted,
            // `AllocatePayload` not granted) had its release settled at the
            // operation's cleanup entry: the ticket is forgotten.
            state.ticket = None;
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
pub(crate) fn buffer_remaining<P>(state: &mut BufferState<P>) -> Option<u64> {
    Some(
        match state.meta.as_mut().map(|installed| installed.get().phase) {
            None | Some(Phase::BufferFreed) => 1,
            Some(_) => 2,
        },
    )
}

// SAFETY: initial: `BufferState::INITIAL`, nothing installed or allocated.
// state: every initialized String is recorded before returning: the
// installed metadata, its phase, the bytes copied and the payload's permit.
// admission: each cleanup unit (`reclaim_buffer`) is admitted before it runs,
// a refusal changing nothing. cleanup: String's byte buffer has no element
// destructors; its storage is freed in one admitted step, then its payload
// permit and the metadata storage and its permit, releases their
// acquisitions paid for; nothing is allocated and nothing unwinds. done:
// `Done` once the buffer, the metadata and both permits are released. order:
// a step after `Done` reports `Done`; the count and the observation read the
// state alone. depth: a leaf, the default 1. count: `buffer_remaining`
// counts the units left.
unsafe impl<A: Allocator> Reclaim<A> for String {
    type State = BufferState<A::Permit>;
    const INITIAL: Self::State = BufferState::INITIAL;

    fn reclaim_step(
        slot: Slot<'_, Self, Self::State>,
        cleanup: &mut Cleanup<'_, A>,
    ) -> BoundedResult<Reclaimed, A> {
        reclaim_buffer::<String, A>(slot, cleanup)
    }

    fn remaining(mut slot: PeekSlot<'_, Self, Self::State>) -> Option<u64> {
        buffer_remaining(slot.custody())
    }

    fn observe_permits(
        mut slot: PeekSlot<'_, Self, Self::State>,
        sink: &mut dyn CustodySink<A::Permit>,
    ) -> PermitsObserved {
        buffer_permits(slot.custody(), sink)
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
    pending: &mut Pending<A::Origin>,
    a: &mut A,
) -> BoundedResult<Built, A> {
    let (place, state) = slot.parts();
    let bytes = H::source(source);
    if state.meta.is_none() {
        allocate_meta(state, pending, a)?;
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
            stable::admit_release(pending, &mut state.ticket, a)?;
            state.installed()?.phase = Phase::AllocatePayload;
        }
        Phase::AllocatePayload => {
            let requested = u64::try_from(bytes.len()).map_err(|_| BoundedError::Overflow)?;
            // The ticket moves out of the state for the call, which borrows
            // the state as the payload's custody, and back whatever the call
            // returns.
            let mut ticket = state.ticket.take();
            let allocated = stable::allocate_payload(
                state,
                |state| Ok(&mut state.installed()?.payload),
                requested,
                // SAFETY: Initialized proves a valid empty header, which
                // holds no place; reserving leaves its vector empty, a valid
                // header's bytes.
                |state| {
                    unsafe {
                        place.with_mut(state, |header| {
                            H::bytes(header).try_reserve_exact(bytes.len())
                        })
                    }
                    .is_ok()
                },
                pending,
                &mut ticket,
                a,
            );
            state.ticket = ticket;
            allocated?;
            state.installed()?.phase = Phase::Copy;
        }
        Phase::Copy => {
            let start = state.installed()?.copied;
            if Bound::new(Predicate::Payload, bytes.len()).exceeded(a, start) {
                return Err(BoundedError::PlanMismatch);
            }
            let remaining = bytes.len() - start;
            if !H::boundary(source, start) {
                return Err(BoundedError::PlanMismatch);
            }
            let mut end =
                start + Bound::new(Predicate::Quantum, stable::QUANTUM).clamp(a, remaining);
            // A boundary is at most three bytes before the end: a scalar is
            // at most four bytes.
            while boundary!(a, Predicate::Payload, end, start).is_gt() && !H::boundary(source, end)
            {
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
            if Bound::new(Predicate::ArenaLength, spare).exceeded(a, end - start) {
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

// SAFETY: admission: every phase of `copy_buffer` (metadata, header, release,
// payload allocation, each chunk) is admitted before it runs, the boundary
// and capacity checks made before the chunk's admission. state: each phase
// is recorded before the step returns; every phase, allocation failures
// included, is one the Reclaim above cleans up. done: `Done` only once every
// byte is copied, the phase `Complete`. escape: the byte vector's pointer
// stays in the header the value owns. provenance: construction writes the
// String header directly into its final place, through the slot's, and
// reaches it only through that place. order: a phase it does not continue,
// a chunk off a boundary or beyond the reserved capacity, or a step past
// completion or in cleanup is refused `PlanMismatch` and changes nothing; a
// node not a text is refused by one admitted unit (`rejected`). cost:
// `buffer_cost::<String, A::Permit>()`, the engine's own.
unsafe impl<A: Allocator> InPlace<A> for String {
    const COST: ConstructionCost = crate::const_cost!(buffer_cost::<String, A::Permit>());

    fn build_step<'b>(
        ctx: BindingContext<'b, '_, '_, '_, Self, A>,
        a: &mut A,
    ) -> ConstructResult<Building<'b, Self>, A> {
        let Some(Kind::Text(text)) = ctx.node().map(|n| n.kind()) else {
            return rejected(a);
        };
        let assembly = ctx.assembly();
        let (slot, pending) = ctx.into_acquiring();
        let built = copy_buffer::<String, A>(text, slot, pending, a)?;
        // SAFETY: the buffer engine reports `Done` only once every byte is
        // copied into the header it wrote, its phase `Complete`.
        Ok(unsafe { reported(built, assembly) })
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
        let cost = buffer_cost::<String, Reservation>().expect("a buffer's cost fits in u64");
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
