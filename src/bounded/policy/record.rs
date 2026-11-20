//! A recording session: the evidence capacity of one observed run, made
//! before it begins and never grown inside it.
//!
//! A [`Session`] is a namespace of families and policies and one store of
//! event slots and permit records, all preallocated. Every family recorded
//! in it ([`super::Limits::recorded`]) is numbered from the session (never
//! zero), mints its identities (permits, held obligations, owners,
//! acquisitions) from its own sequence, and keeps one append-only permit
//! record per grant and per split child. Every observation of every family
//! of the session, ordinary policy events, permit releases, physical effects
//! and settlements made by drops or terminal cleanup alike, is published into
//! the one slot store, so their order is one order.
//!
//! # Publication
//!
//! A writer claims a unique slot ([`claim`]), writes the slot's words (the
//! publishing family and performer first), then stores its completion flag
//! with `Release`. The reader ([`Session::finish`]) runs only once it owns
//! the store alone: every family's counters, and so every policy, permit,
//! held obligation and owner that could publish, is gone, which is the
//! quiescence the read needs, established by ownership rather than assumed.
//! It then loads each claimed slot's flag with `Acquire` before its words,
//! and a slot claimed but never completed is refused
//! ([`Incomplete::Unpublished`]). Slot order is observation order: two
//! observations made under no synchronization between them are ordered by
//! their claims, which says nothing about the order of their effects; the
//! checker reads only the order production synchronizes, and each
//! observation names the family that published it and who performed it.
//!
//! # Exhaustion and invalidation
//!
//! Every counter here (families, policies, sequences, permit records, slots)
//! is claimed by [`claim`], a compare-exchange that never passes its limit
//! and never wraps: an exhausted counter stays exhausted, so no identity,
//! record or slot is ever handed out twice. An exhausted claim, and a pairing
//! of a policy and an owner of different sessions
//! ([`crate::bounded::Budget::validate_owner`]), set the session's sticky
//! invalid flag and record nothing more; the operation, its cleanup and every
//! release proceed unchanged. An invalid session is never evidence
//! ([`Incomplete::Exhausted`]), and its recorder rejects every run of it,
//! concurrent ones included. A recorded grant or split that cannot obtain
//! both a record and an identity is refused before anything is granted
//! ([`super::LimitRefusal::Unrecorded`]).
//!
//! # Representation
//!
//! The model-aware facade (`crate::sync`) offers atomics and no shared
//! cell, so a slot is a fixed array of atomic words and an observation is
//! stored through this module's one private codec ([`codec`]). The session
//! hands out typed [`Event`]s, which every consumer reads; the storage form
//! leaves this crate only as whole observations' words
//! ([`Observed::to_words`]), where two builds of this crate meet and the
//! other build reads them back ([`Observed::from_words`]).
//!
//! # Lifetime and allocation
//!
//! The session's storage is reference counted: the recorder's [`Session`],
//! every recorded family's counters and every recorded
//! [`crate::bounded::Owner`] hold it, and every permit and held obligation
//! holds its family's counters, so the storage outlives everything that
//! writes into it; while a run is recorded the recorder's handle is the last
//! one dropped, by [`Session::finish`]. Claiming, publishing, settling and
//! releasing allocate nothing and do not unwind, so drops and terminal
//! cleanup publish; [`Session::new`] allocates the store before the run, and
//! [`Session::finish`] the observations it returns after it.
//!
//! Under a model checker the store's atomics are the model's, and a session
//! is made inside each model execution, so no state crosses executions.

extern crate alloc;
use super::super::{Identity, Owner, Performer};
use super::Event;
use crate::sync::{AtomicU64, Ordering};
use alloc::{boxed::Box, sync::Arc, vec::Vec};

mod codec;
use codec::{WORDS, decode, encode};

/// Claim the next value of `counter` below `limit`: its value before the
/// claim, or none once it has reached `limit`, where it stays. Never wraps.
fn claim(counter: &AtomicU64, limit: u64) -> Option<u64> {
    let mut current = counter.load(Ordering::Acquire);
    loop {
        if current >= limit {
            return None;
        }
        match counter.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Some(current),
            Err(actual) => current = actual,
        }
    }
}

/// Raise `counter` to `to` unless it already holds as much: a prefix only
/// ever grows, whichever of several racing readers raises it last.
fn raise(counter: &AtomicU64, to: u64) {
    let mut current = counter.load(Ordering::Acquire);
    while current < to {
        match counter.compare_exchange_weak(current, to, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return,
            Err(actual) => current = actual,
        }
    }
}

/// One observation, the family that published it, and who performed it: a
/// policy of the session, or no policy (a permit's drop, a held obligation's
/// drop, a terminal path). The family owning an obligation, a permit, an
/// owner or an acquisition is the one its identity names, a separate fact
/// from the publisher's. Decoding a slot checks only its storage form;
/// whether the observation is a legal transition (an allocation answered as
/// admitted work, say) is the refinement checker's to decide.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observed {
    pub family: u64,
    pub by: Performer,
    pub event: Event,
}

/// The words of one observation in a slot's storage form, carried whole: the
/// publishing family, the performer (`0` for no policy, else the policy's
/// number), then its event's codec words (this module's `codec`). The one representation
/// a session stores, given out only where two builds of this crate meet, a
/// test of this crate's own handing its stream to the refinement checker,
/// which links this crate as a dependency of its own: the two builds' types
/// differ, so the stream crosses as words and is read back by the other's
/// [`Observed::from_words`]. Every identity, family and performer is kept.
#[doc(hidden)]
pub const OBSERVED_WORDS: usize = 2 + WORDS;

/// A performer as a slot stores it: `0` for no policy, else the policy's
/// number, which is never 0 ([`Recording::policy`]).
fn performer_word(by: Performer) -> u64 {
    match by {
        Performer::None => 0,
        Performer::Policy(policy) => policy,
    }
}

/// The performer a slot's word names ([`performer_word`]).
fn performer_of(word: u64) -> Performer {
    match word {
        0 => Performer::None,
        policy => Performer::Policy(policy),
    }
}

impl Observed {
    /// This observation's storage form ([`OBSERVED_WORDS`]); none when its
    /// event holds a quantity no word holds, which no session stores either.
    #[doc(hidden)]
    pub fn to_words(&self) -> Option<[u64; OBSERVED_WORDS]> {
        let event = encode(self.event)?;
        let mut words = [0; OBSERVED_WORDS];
        words[0] = self.family;
        words[1] = performer_word(self.by);
        words[2..].copy_from_slice(&event);
        Some(words)
    }

    /// The observation `words` store ([`Self::to_words`]); none when they are
    /// not one's storage form, which the codec checks as it checks a slot.
    #[doc(hidden)]
    pub fn from_words(words: &[u64; OBSERVED_WORDS]) -> Option<Self> {
        let mut event = [0; WORDS];
        event.copy_from_slice(&words[2..]);
        Some(Self {
            family: words[0],
            by: performer_of(words[1]),
            event: decode(&event)?,
        })
    }
}

/// The capacities of a session: how much it can observe completely.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capacity {
    /// Permit records: one per grant and per split child, over every family.
    pub permits: usize,
    /// Event slots, over every family.
    pub events: usize,
}

impl Capacity {
    /// The one default recording capacity: what every recorded run whose
    /// workload fits it records into, the library's own tests and the
    /// shared test support's alike (`dcbor_test_support::CAPACITY`). A
    /// session preallocates all of it before anything runs; an event slot is
    /// 15 words, 120 bytes on a 64-bit target. A recording is sized
    /// otherwise only where the size is what its test checks (an exhausted
    /// or exactly bounded session), or by its measured budget
    /// (`dcbor_test_support::budgets`).
    pub const DEFAULT: Self = Self {
        permits: 1 << 14,
        events: 1 << 16,
    };
}

/// Why a session's observations are not evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Incomplete {
    /// A capacity or a sequence was exhausted, or a policy and an owner of
    /// different sessions were paired: the session is invalid.
    Exhausted,
    /// A reserved slot was never completed.
    Unpublished(usize),
    /// A slot's words name no observation: a defect of this module.
    Malformed(usize),
    /// Something that can still publish holds the session: this many
    /// holders besides the reader.
    Live(usize),
}

/// One permit's record: its bytes, its identity and its lifecycle.
struct PermitRecord {
    bytes: AtomicU64,
    sequence: AtomicU64,
    family: AtomicU64,
    state: AtomicU64,
}

/// A permit record's lifecycle.
const VOID: u64 = 0;
// A session's permit records are allocated zeroed (`zeroed`): the all-zero
// record must be a void one.
const _: () = assert!(VOID == 0, "a zeroed permit record is VOID");
const LIVE: u64 = 1;
const RETIRED: u64 = 2;
const RELEASED: u64 = 3;

struct Slot {
    ready: AtomicU64,
    family: AtomicU64,
    /// 0 for no policy, else the policy's number.
    by: AtomicU64,
    words: [AtomicU64; WORDS],
}

pub(crate) struct Store {
    families: AtomicU64,
    policies: AtomicU64,
    invalid: AtomicU64,
    permits: Box<[PermitRecord]>,
    next_permit: AtomicU64,
    slots: Box<[Slot]>,
    next_slot: AtomicU64,
}

/// A counted reference to a session's store: what the recorder's session,
/// a recorded family's counters and every recorded
/// [`crate::bounded::Owner`] hold.
pub(crate) type Shared = Arc<Store>;

/// Whether two references name one session's store.
pub(crate) fn same(left: &Shared, right: &Shared) -> bool {
    Arc::ptr_eq(left, right)
}

/// What first made a session no evidence ([`Incomplete::Exhausted`]): the
/// namespace, sequence or capacity a claim found exhausted, an observation
/// the codec cannot store, or a pairing of a policy and an owner of
/// different sessions. Kept once: the cause whose compare-exchange first
/// completes, so a consequence that follows it (every later pairing refused,
/// every later claim failing) never masks it. Between threads that is the
/// order the invalidations complete in, not a timestamp of their causes:
/// two causes racing are kept as whichever completes first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Invalidation {
    /// The session's family numbers.
    Families,
    /// The session's policy numbers.
    Policies,
    /// A family's identity sequence.
    Identities,
    /// The permit records ([`Capacity::permits`]).
    Permits,
    /// The event slots ([`Capacity::events`]).
    Events,
    /// An observation holding a quantity no slot word holds.
    Unencodable,
    /// A policy paired with an owner of another session, or a family that
    /// records nothing paired with a recorded owner
    /// ([`crate::bounded::Budget::validate_owner`]).
    ForeignOwner,
    /// An acquisition's end publication naming no acquisition this family
    /// minted: an unidentified acquisition, or one of another family, ending
    /// through this family's origin ([`crate::bounded::Origin::end`]).
    ForeignAcquisition,
    /// Window custody has malformed part structure or capability pairing.
    MalformedWindow,
}

impl Invalidation {
    /// The store's word for it: never 0, which is a valid session.
    const fn word(self) -> u64 {
        match self {
            Self::Families => 1,
            Self::Policies => 2,
            Self::Identities => 3,
            Self::Permits => 4,
            Self::Events => 5,
            Self::Unencodable => 6,
            Self::ForeignOwner => 7,
            Self::ForeignAcquisition => 8,
            Self::MalformedWindow => 9,
        }
    }

    /// The cause a store's word names; none for 0, a valid session.
    const fn of(word: u64) -> Option<Self> {
        match word {
            1 => Some(Self::Families),
            2 => Some(Self::Policies),
            3 => Some(Self::Identities),
            4 => Some(Self::Permits),
            5 => Some(Self::Events),
            6 => Some(Self::Unencodable),
            7 => Some(Self::ForeignOwner),
            8 => Some(Self::ForeignAcquisition),
            9 => Some(Self::MalformedWindow),
            _ => None,
        }
    }
}

/// Make `store`'s session, stickily, no evidence, for `cause`: the first
/// cause is kept, every later one leaves it ([`Invalidation`]).
pub(crate) fn exhaust(store: &Shared, cause: Invalidation) {
    let _ = store
        .invalid
        .compare_exchange(0, cause.word(), Ordering::AcqRel, Ordering::Acquire);
}

/// What first invalidated `store`'s session, if anything has.
fn invalidation(store: &Shared) -> Option<Invalidation> {
    Invalidation::of(store.invalid.load(Ordering::Acquire))
}

/// `len` values each equal to `make()`, allocated whole: a session's permit
/// records or its slots. The shipped build allocates them zeroed in one
/// request: `core`'s `AtomicU64` has the in-memory representation of `u64`,
/// so the all-zero bytes are `AtomicU64::new(0)`; the allocator's zeroed
/// pages are written only as observations are published, and no element is
/// constructed one by one, natively or under Miri. A model checker's atomics
/// (`loom`, `shuttle`) carry state of their own that no zero pattern holds,
/// so those builds construct each element with `make`.
///
/// # Safety
/// The all-zero byte pattern of `T` is a valid `T` equal to `make()`'s.
#[cfg(not(any(loom, shuttle)))]
unsafe fn zeroed<T>(len: usize, _make: impl FnMut() -> T) -> Box<[T]> {
    // SAFETY: forwarded from the caller: all-zero bytes are a valid `T`.
    unsafe { Box::<[T]>::new_zeroed_slice(len).assume_init() }
}

/// [`zeroed`] under a model checker: each element constructed with `make`.
///
/// # Safety
/// None beyond `make`'s own; declared `unsafe` to share the shipped build's
/// signature.
#[cfg(any(loom, shuttle))]
unsafe fn zeroed<T>(len: usize, make: impl FnMut() -> T) -> Box<[T]> {
    core::iter::repeat_with(make).take(len).collect()
}

/// `index`, a claimed slot or record index, as a slice index. Every index
/// passed here was claimed below a slice's length, which is a `usize`, so it
/// fits; none is ever truncated.
fn at(index: u64) -> usize {
    match usize::try_from(index) {
        Ok(at) => at,
        Err(_) => unreachable!("an index claimed below a slice's length fits in usize"),
    }
}

/// A recording session ([`self`]): made before the run, with its capacity,
/// and held by its recorder alone until [`Self::finish`]. Not `Clone`: one
/// handle, the one [`Self::finish`] consumes.
pub struct Session {
    store: Shared,
    /// The slots a boundary has read ready, from slot zero ([`Self::boundary`]):
    /// a slot, once ready, is never unready again (its one store sets it,
    /// [`Recording::publish`]), so each boundary reads only the slots claimed
    /// past this prefix and every checkpoint costs its own publications, not
    /// the whole session's. Raised only, never lowered.
    completed: AtomicU64,
}

impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Session").finish_non_exhaustive()
    }
}

impl Session {
    /// A session able to observe `capacity` completely: all of its storage
    /// is allocated here, before anything is observed.
    pub fn new(capacity: Capacity) -> Self {
        // SAFETY: every field of a permit record is an `AtomicU64` made with
        // 0, `VOID` included (`VOID` is 0): the all-zero record.
        let permits = unsafe {
            zeroed(capacity.permits, || PermitRecord {
                bytes: AtomicU64::new(0),
                sequence: AtomicU64::new(0),
                family: AtomicU64::new(0),
                state: AtomicU64::new(VOID),
            })
        };
        // SAFETY: every field of a slot, each word included, is an
        // `AtomicU64` made with 0: the all-zero slot.
        let slots = unsafe {
            zeroed(capacity.events, || Slot {
                ready: AtomicU64::new(0),
                family: AtomicU64::new(0),
                by: AtomicU64::new(0),
                words: core::array::from_fn(|_| AtomicU64::new(0)),
            })
        };
        Self {
            store: Arc::new(Store {
                families: AtomicU64::new(0),
                policies: AtomicU64::new(0),
                invalid: AtomicU64::new(0),
                permits,
                next_permit: AtomicU64::new(0),
                slots,
                next_slot: AtomicU64::new(0),
            }),
            completed: AtomicU64::new(0),
        }
    }

    /// Every observation of the session, in slot order, once nothing else
    /// holds it ([`self`]): refused while a family, permit, held obligation
    /// or owner of the session lives, when the session is invalid, or when
    /// a claimed slot was never completed.
    pub fn finish(self) -> Result<Vec<Observed>, Incomplete> {
        let store = Arc::try_unwrap(self.store)
            .map_err(|store| Incomplete::Live(Arc::strong_count(&store) - 1))?;
        if store.invalid.load(Ordering::Acquire) != 0 {
            return Err(Incomplete::Exhausted);
        }
        let claimed = usize::try_from(store.next_slot.load(Ordering::Acquire))
            .map_err(|_| Incomplete::Exhausted)?;
        let slots = store.slots.get(..claimed).ok_or(Incomplete::Exhausted)?;
        let mut observed = Vec::with_capacity(slots.len());
        for (index, slot) in slots.iter().enumerate() {
            if slot.ready.load(Ordering::Acquire) == 0 {
                return Err(Incomplete::Unpublished(index));
            }
            observed.push(read(slot).ok_or(Incomplete::Malformed(index))?);
        }
        Ok(observed)
    }

    /// The session's boundary now: the slots claimed so far, every one
    /// completed. A custody snapshot taken here is compared with the
    /// observations before it, `[0, boundary)` of what [`Self::finish`]
    /// returns, which holds at least every boundary taken. Refused
    /// ([`Incomplete::Exhausted`]) when the session is invalid, and
    /// ([`Incomplete::Unpublished`]) when a claimed slot is not yet
    /// completed: a snapshot taken inside a concurrent publication is no
    /// boundary. Valid only for this session.
    pub fn boundary(&self) -> Result<Boundary, Incomplete> {
        let store = &self.store;
        if store.invalid.load(Ordering::Acquire) != 0 {
            return Err(Incomplete::Exhausted);
        }
        let claimed = store.next_slot.load(Ordering::Acquire);
        // The prefix an earlier boundary read ready stays ready; only the
        // slots claimed after it are read.
        let verified = self.completed.load(Ordering::Acquire).min(claimed);
        let (start, end) = (
            usize::try_from(verified).map_err(|_| Incomplete::Exhausted)?,
            usize::try_from(claimed).map_err(|_| Incomplete::Exhausted)?,
        );
        let slots = store.slots.get(start..end).ok_or(Incomplete::Exhausted)?;
        if let Some(offset) = slots
            .iter()
            .position(|slot| slot.ready.load(Ordering::Acquire) == 0)
        {
            return Err(Incomplete::Unpublished(start + offset));
        }
        raise(&self.completed, claimed);
        Ok(Boundary(end))
    }

    /// What first made the session no evidence, if anything has: read
    /// without the store, so a recorder learns the cause before
    /// [`Self::finish`] reports [`Incomplete::Exhausted`].
    pub fn invalidation(&self) -> Option<Invalidation> {
        invalidation(&self.store)
    }

    pub(crate) fn shared(&self) -> &Shared {
        &self.store
    }
}

/// A position in one session's observation order: the count of
/// observations before it, each completed when it was taken
/// ([`Session::boundary`]). Valid only for the session that issued it; no
/// public constructor, so none is made from a count.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Boundary(usize);

impl Boundary {
    /// The observations before it.
    pub fn get(self) -> usize {
        self.0
    }
}

/// A completed slot's observation, or none when its words name none.
fn read(slot: &Slot) -> Option<Observed> {
    let words: [u64; WORDS] =
        core::array::from_fn(|index| slot.words[index].load(Ordering::Relaxed));
    Some(Observed {
        family: slot.family.load(Ordering::Relaxed),
        by: performer_of(slot.by.load(Ordering::Relaxed)),
        event: decode(&words)?,
    })
}

/// One family's part of a session: its number, its sequence and the
/// session's storage.
pub(crate) struct Recording {
    store: Shared,
    family: u64,
    sequence: AtomicU64,
}

impl Recording {
    /// A new family of `session`, numbered from it.
    pub(crate) fn join(session: &Session) -> Self {
        let store = session.store.clone();
        // Families are numbered from 1: 0 names no family. An exhausted
        // namespace gives family 0, whose every claim then refuses, and the
        // session is no evidence.
        let family = match claim(&store.families, u64::MAX) {
            Some(before) => before + 1,
            None => {
                exhaust(&store, Invalidation::Families);
                0
            }
        };
        Self {
            store,
            family,
            sequence: AtomicU64::new(0),
        }
    }

    /// The events `by` performed so far, in slot order: an in-flight view
    /// for a policy's own reports, read by the thread driving that policy,
    /// which has published all of its own observations. It is no evidence
    /// ([`Session::finish`] is). Refused when the session is invalid or a
    /// slot is malformed, never silently short.
    pub(crate) fn view(&self, by: Performer) -> Result<Vec<Event>, Incomplete> {
        let store = &self.store;
        if store.invalid.load(Ordering::Acquire) != 0 {
            return Err(Incomplete::Exhausted);
        }
        let claimed = usize::try_from(store.next_slot.load(Ordering::Acquire))
            .map_err(|_| Incomplete::Exhausted)?;
        let slots = store.slots.get(..claimed).ok_or(Incomplete::Exhausted)?;
        let mut events = Vec::new();
        for (index, slot) in slots.iter().enumerate() {
            // Another performer's slot still being written is not this
            // one's: skip it rather than wait.
            if slot.ready.load(Ordering::Acquire) == 0 {
                continue;
            }
            let observed = read(slot).ok_or(Incomplete::Malformed(index))?;
            if observed.by == by {
                events.push(observed.event);
            }
        }
        Ok(events)
    }

    /// A new owner of this family's session, minted and published `by`;
    /// none, the session invalid, when it has no identity left.
    pub(crate) fn owner(&self, by: Performer) -> Option<Owner> {
        let id = self.mint()?;
        self.publish(by, Event::Owner(id));
        Some(Owner::recorded(id, self.store.clone()))
    }

    /// Whether `owner` was minted in this family's session.
    pub(crate) fn owns(&self, owner: &Owner) -> bool {
        owner.of(&self.store)
    }

    /// Make this family's session, stickily, no evidence, for `cause`.
    pub(crate) fn invalidate(&self, cause: Invalidation) {
        exhaust(&self.store, cause);
    }

    /// Whether the session is still usable as evidence.
    pub(crate) fn valid(&self) -> bool {
        self.store.invalid.load(Ordering::Acquire) == 0
    }

    /// What first made this family's session no evidence, if anything has.
    pub(crate) fn invalidation(&self) -> Option<Invalidation> {
        invalidation(&self.store)
    }

    /// Whether this family belongs to `session`.
    pub(crate) fn of(&self, session: &Session) -> bool {
        same(&self.store, session.shared())
    }

    pub(crate) fn family(&self) -> u64 {
        self.family
    }

    /// The next identity of this family, or none: a family numbered 0 (an
    /// exhausted namespace) or an exhausted sequence names nothing,
    /// invalidates the session, and never hands out an identity again.
    /// Sequences are numbered from 1; they count identities minted, refused
    /// admissions' included, not obligations held.
    pub(crate) fn mint(&self) -> Option<Identity> {
        let minted = (self.family != 0)
            .then(|| claim(&self.sequence, u64::MAX))
            .flatten()
            .map(|before| Identity::new(self.family, before + 1));
        if minted.is_none() {
            // A family numbered 0 names an exhausted family namespace,
            // already recorded as the cause; otherwise its sequence ran out.
            self.invalidate(Invalidation::Identities);
        }
        minted
    }

    /// A new permit record of `bytes` under a fresh identity, not yet live:
    /// its index and identity, or none when the session has no record or no
    /// identity left (the session is then invalid). The record and the
    /// identity are both obtained before anything is granted;
    /// [`Self::commit`] makes it live once the grant is made, and a record
    /// never committed stays void, never handed out again.
    pub(crate) fn reserve(&self, bytes: u64) -> Option<(u64, Identity)> {
        let limit = u64::try_from(self.store.permits.len()).unwrap_or(u64::MAX);
        let Some(index) = claim(&self.store.next_permit, limit) else {
            self.invalidate(Invalidation::Permits);
            return None;
        };
        let id = self.mint()?;
        let record = self.record(index);
        record.bytes.store(bytes, Ordering::Relaxed);
        record.family.store(id.family(), Ordering::Relaxed);
        record.sequence.store(id.sequence(), Ordering::Relaxed);
        Some((index, id))
    }

    /// Make the reserved record `index` live: its permit was granted.
    pub(crate) fn commit(&self, index: u64) {
        self.record(index).state.store(LIVE, Ordering::Release);
    }

    /// The record of `index`, one [`Self::reserve`] claimed below the
    /// records' length.
    fn record(&self, index: u64) -> &PermitRecord {
        &self.store.permits[at(index)]
    }

    pub(crate) fn bytes(&self, index: u64) -> u64 {
        self.record(index).bytes.load(Ordering::Acquire)
    }

    pub(crate) fn set_bytes(&self, index: u64, bytes: u64) {
        self.record(index).bytes.store(bytes, Ordering::Release);
    }

    pub(crate) fn identity(&self, index: u64) -> Identity {
        let record = self.record(index);
        Identity::new(
            record.family.load(Ordering::Acquire),
            record.sequence.load(Ordering::Acquire),
        )
    }

    /// Retire record `index`: a merged input, whose drop releases nothing.
    pub(crate) fn retire(&self, index: u64) {
        self.record(index).state.store(RETIRED, Ordering::Release);
    }

    pub(crate) fn retired(&self, index: u64) -> bool {
        self.record(index).state.load(Ordering::Acquire) == RETIRED
    }

    /// Mark record `index` released, its drop performed.
    pub(crate) fn released(&self, index: u64) {
        self.record(index).state.store(RELEASED, Ordering::Release);
    }

    /// Publish `event`, performed `by`, into the session's one order
    /// ([`self`]); an observation the codec cannot store, or a full store,
    /// invalidates the session instead.
    pub(crate) fn publish(&self, by: Performer, event: Event) {
        let Some(words) = encode(event) else {
            self.invalidate(Invalidation::Unencodable);
            return;
        };
        let limit = u64::try_from(self.store.slots.len()).unwrap_or(u64::MAX);
        let Some(index) = claim(&self.store.next_slot, limit) else {
            self.invalidate(Invalidation::Events);
            return;
        };
        let slot = &self.store.slots[at(index)];
        slot.family.store(self.family, Ordering::Relaxed);
        slot.by.store(performer_word(by), Ordering::Relaxed);
        for (word, value) in slot.words.iter().zip(words) {
            word.store(value, Ordering::Relaxed);
        }
        slot.ready.store(1, Ordering::Release);
    }

    /// A number for one policy of this session (a [`super::Limits`], its
    /// shares and terminal policies each get their own), from 1, so 0 is
    /// never a policy; 0 when the namespace is exhausted, which invalidates
    /// the session.
    pub(crate) fn policy(&self) -> u64 {
        match claim(&self.store.policies, u64::MAX) {
            Some(before) => before + 1,
            None => {
                self.invalidate(Invalidation::Policies);
                0
            }
        }
    }
}

#[cfg(test)]
mod boundary_tests {
    use super::*;

    #[test]
    fn boundaries_retain_the_verified_prefix_without_crossing_publication_gaps() {
        let session = Session::new(Capacity {
            permits: 0,
            events: 4,
        });
        let recording = Recording::join(&session);
        recording.publish(Performer::None, Event::Owner(Identity::new(1, 1)));
        assert_eq!(session.boundary().map(Boundary::get), Ok(1));
        assert_eq!(session.completed.load(Ordering::Acquire), 1);
        let gap = claim(&session.store.next_slot, 4).unwrap();
        recording.publish(Performer::None, Event::Owner(Identity::new(1, 2)));
        for _ in 0..3 {
            assert_eq!(session.boundary(), Err(Incomplete::Unpublished(at(gap))));
            assert_eq!(session.completed.load(Ordering::Acquire), 1);
        }
        session.store.slots[at(gap)]
            .ready
            .store(1, Ordering::Release);
        assert_eq!(session.boundary().map(Boundary::get), Ok(3));
        assert_eq!(session.completed.load(Ordering::Acquire), 3);
        assert_eq!(session.boundary().map(Boundary::get), Ok(3));
        exhaust(session.shared(), Invalidation::Events);
        assert_eq!(session.boundary(), Err(Incomplete::Exhausted));
        drop(recording);
        assert_eq!(session.finish(), Err(Incomplete::Exhausted));
    }

    #[test]
    fn malformed_window_invalidation_preserves_the_first_cause() {
        let session = Session::new(Capacity::DEFAULT);
        exhaust(session.shared(), Invalidation::MalformedWindow);
        exhaust(session.shared(), Invalidation::Events);
        assert_eq!(session.invalidation(), Some(Invalidation::MalformedWindow));
        assert_eq!(session.finish(), Err(Incomplete::Exhausted));
    }

    /// An observation's words read back to the same observation, its family,
    /// its performer (a policy's and none) and its event's every identity;
    /// planted: a performer or family word changed reads back as another
    /// observation, never this one, and words of no event read as none.
    #[test]
    fn an_observation_crosses_as_its_words_whole() {
        let observed = [
            Observed {
                family: 3,
                by: Performer::Policy(5),
                event: Event::Bound {
                    acquisition: Identity::new(3, 7),
                    owner: Identity::new(2, 1),
                },
            },
            Observed {
                family: 2,
                by: Performer::None,
                event: Event::Released(Identity::new(2, 9)),
            },
        ];
        for observation in observed {
            let words = observation.to_words().expect("a storable observation");
            assert_eq!(Observed::from_words(&words), Some(observation));
            let mut performer = words;
            performer[1] ^= 1;
            assert_ne!(Observed::from_words(&performer), Some(observation));
            let mut family = words;
            family[0] += 1;
            assert_ne!(Observed::from_words(&family), Some(observation));
            let mut tag = words;
            tag[2] = 0;
            assert_eq!(Observed::from_words(&tag), None);
        }
    }

    /// A boundary counts every publication, one performed by no policy
    /// included; a session whose claimed slot is not yet completed has no
    /// boundary; an invalid session has none. Every boundary taken is
    /// within what the finished session returns.
    #[test]
    fn a_boundary_counts_every_completed_publication_and_nothing_else() {
        let session = Session::new(Capacity {
            permits: 0,
            events: 8,
        });
        let recording = Recording::join(&session);
        assert_eq!(session.boundary().map(Boundary::get), Ok(0));
        recording.publish(Performer::Policy(1), Event::Owner(Identity::new(1, 1)));
        assert_eq!(session.boundary().map(Boundary::get), Ok(1));
        // A release no policy performs moves it too.
        recording.publish(Performer::None, Event::Released(Identity::new(1, 2)));
        let taken = session.boundary().expect("every claimed slot is complete");
        assert_eq!(taken.get(), 2);
        // A claimed slot not yet completed: no boundary.
        let index = claim(&session.store.next_slot, 8).expect("a slot is free");
        assert_eq!(session.boundary(), Err(Incomplete::Unpublished(at(index))));
        session.store.slots[at(index)]
            .ready
            .store(1, Ordering::Release);
        // Completed, but its words name nothing: finish refuses it, and
        // the boundary before it still stands within the finished length.
        drop(recording);
        assert_eq!(session.finish(), Err(Incomplete::Malformed(2)));

        let session = Session::new(Capacity::DEFAULT);
        let recording = Recording::join(&session);
        recording.publish(Performer::None, Event::Released(Identity::new(1, 1)));
        let taken = session.boundary().expect("a complete publication");
        drop(recording);
        let observed = session
            .finish()
            .unwrap_or_else(|incomplete| panic!("a complete session: {incomplete:?}"));
        assert!(taken.get() <= observed.len(), "a boundary past the session");

        let session = Session::new(Capacity::DEFAULT);
        exhaust(session.shared(), Invalidation::Events);
        // The first cause is kept; a later one leaves it.
        exhaust(session.shared(), Invalidation::Permits);
        assert_eq!(session.invalidation(), Some(Invalidation::Events));
        assert_eq!(session.boundary(), Err(Incomplete::Exhausted));
    }
}
