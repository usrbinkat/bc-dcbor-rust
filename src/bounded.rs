//! Bounded canonical encoding: a value's dCBOR encoding prepared without
//! building a [`CBOR`](crate::CBOR) tree, by one engine whether driven in
//! one call or in retained steps.
//!
//! The symbolic path (`From<T> for CBOR`, then
//! [`CBOR::to_cbor_data`](crate::CBOR::to_cbor_data)) allocates a
//! reference-counted node per value, an encoded key per map entry, an NFC
//! copy per text string and a buffer per nested item. This path describes a
//! value by its [`Schema`], a sequence of constant-work instructions, and
//! prepares its encoding with the retained engine
//! ([`encoding::Preparation`]):
//!
//! 1. [`prepare`] walks the value's shape ([`encoding::Shape::of`]), then
//!    steps the engine to its plan: the encoding in one arena, capped at
//!    the shape's extent, with a gap only where a map's count is not known
//!    when its head is due. Every unit of work is reported to the caller's
//!    [`Budget`] and every allocation requested from its [`Allocator`]
//!    before it is done; storage is released when freed ([`Owned`]).
//! 2. [`Prepared::publish`] closes the gaps in place and publishes the arena
//!    as the encoding ([`Encoded`]), its permit with it: nothing is
//!    allocated or copied for the output. [`Prepared::encode_into`] and
//!    [`Prepared::encode_owned`] instead write it into storage the caller
//!    supplies or admits separately.
//!
//! [`encode`] does both under one policy, and [`encode_bound`] bounds it. A
//! budget's refusal is returned as its own type ([`BoundedError::Refused`]),
//! never as text.
//!
//! The bytes are the bytes the symbolic path produces, by the same rules
//! and the same code where a rule has code: heads ([`Argument`], written
//! by the one head writer the symbolic path uses), float reduction
//! (`float.rs`, shared with the symbolic conversions), NFC through
//! `unicode-normalization`'s own character primitives, maps in the order
//! of their encoded keys. Derived types ([`CBORBoundedEncodable`]) take
//! every representation decision from the same parsed schema as the
//! existing derives.
//!
//! Covered: unsigned and signed integers, `f16`, `f32`, `f64`, `bool`,
//! [`ByteString`], text, arrays (`Vec`, slices, `[T; N]`), pointers to
//! covered types (`&T`, `Box`, `Arc`, `Rc`), and derived maps, newtypes,
//! units and enums. Also covered: standalone nullable `Option<T>`, `BTreeMap`,
//! hash maps, [`crate::Map`], [`CBOR`](crate::CBOR), [`crate::Date`],
//! explicit [`Tagged`](encoding::Tagged) wrappers, and feature-gated
//! `BigInt`/`BigUint`. Sets and deques do not implement this interface.
//!
//! Dynamic Rust maps are ordered by their prepared key bytes in place and
//! reject keys whose canonical encodings collide; trees keyed by their
//! encodings ([`crate::Map`]) are checked in one pass instead. Symbolic
//! traversal admits at most 128 nested frames and rejects out-of-profile
//! negative integers. Constructing an input value is outside the encoding
//! operation's budget.
//!
//! [`decode::decode`] validates and decodes into a borrowed flat document,
//! with admitted arena storage and an explicit depth limit. It never calls the
//! recursive symbolic decoder. The returned view borrows payloads from the input;
//! traversing that view is a separate caller operation.
//!
//! # Before and after: publishing an encoded record
//!
//! ```
//! use dcbor::{CBOR, bounded::{encode, Limits}};
//! let fields = std::collections::BTreeMap::from([("status", "ready")]);
//! // Before: symbolic construction and serialization allocate freely.
//! let before = CBOR::from(fields.clone()).to_cbor_data();
//! // After: preparation and publication share limits; the plan's own
//! // storage becomes the output.
//! let mut limits = Limits::new(10_000, 100_000, 64_000);
//! let after = encode(&fields, &mut limits).unwrap();
//! assert_eq!(after.as_ref(), before);
//! assert!(limits.live_bytes() >= after.as_ref().len() as u64);
//! // Keep `after` alive until the transport/storage operation consumes its bytes.
//! drop(after);
//! assert_eq!(limits.live_bytes(), 0);
//! ```
//!
//! # Caller-owned output
//!
//! Output admission can be separate from preparation. The owner below keeps
//! its own output permit until its vector is freed and publishes bytes only
//! after a successful write. Policy refusal, arithmetic overflow, heap
//! failure and encoding invariant failure retain distinct [`BoundedError`]
//! variants.
//!
//! ```
//! use dcbor::bounded::*;
//! use std::{cell::Cell, rc::Rc};
//! struct Permit(Rc<Cell<u64>>, u64);
//! impl Drop for Permit {
//!     fn drop(&mut self) { self.0.set(self.0.get() - self.1); }
//! }
//! struct Policy { live: Rc<Cell<u64>>, values: u64, bytes: u64, storage: u64 }
//! impl Budget for Policy {
//!     type Refusal = &'static str;
//!     fn traverse(&mut self, values: u64, bytes: u64) -> Result<(), Self::Refusal> {
//!         let v = self.values.checked_sub(values).ok_or("work")?;
//!         let b = self.bytes.checked_sub(bytes).ok_or("work")?;
//!         self.values = v;
//!         self.bytes = b;
//!         Ok(())
//!     }
//! }
//! impl Allocator for Policy {
//!     type Permit = Permit;
//!     fn allocate(&mut self, bytes: u64) -> Result<Permit, Self::Refusal> {
//!         let next = self.live.get().checked_add(bytes).ok_or("storage")?;
//!         if next > self.storage { return Err("storage"); }
//!         self.live.set(next);
//!         Ok(Permit(self.live.clone(), bytes))
//!     }
//! }
//! let live = Rc::new(Cell::new(0));
//! let mut policy = Policy { live: live.clone(), values: 10_000, bytes: 10_000, storage: 1024 };
//! let prepared = prepare(&24u64, &mut policy).unwrap();
//! let output = policy.allocate(prepared.len() as u64).unwrap();
//! let encoded = prepared.encode_owned(output, &mut policy).unwrap();
//! assert_eq!(encoded.as_ref(), [0x18, 0x18]);
//! drop((prepared, encoded));
//! assert_eq!(live.get(), 0);
//! policy.storage = 0; // The plan's first allocation is refused.
//! assert!(matches!(encode(&24u64, &mut policy), Err(BoundedError::Refused("storage"))));
//! assert_eq!(live.get(), 0); // Nothing is held after a refusal.
//! ```
//!
//! [`CBORBoundedEncodable`]: https://docs.rs/dcbor-derive/latest/dcbor_derive/derive.CBORBoundedEncodable.html

import_stdlib!();

use half::f16;

pub use crate::varint::{Argument, MAX_HEAD_LEN, MajorType, head_len};
use crate::{
    ByteString,
    float::{Numeric, convert_f16, convert_f32, convert_f64},
    varint::write_argument,
};

/// The places a summed bound charges, each named once: the enum and its
/// [`Place::ALL`] come from the one list.
macro_rules! places {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident { $($(#[$variant_meta:meta])* $variant:ident),+ $(,)? }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        $vis enum $name {
            $($(#[$variant_meta])* $variant),+
        }

        impl $crate::bounded::Place for $name {
            const ALL: &'static [Self] = &[$(Self::$variant),+];

            #[cfg(test)]
            #[cfg(feature = "std")]
            fn index(self) -> usize {
                self as usize
            }
        }
    };
}

/// One place an operation charges: a part of the operation whose admissions
/// one term of its bound covers.
pub(crate) trait Place: Copy + PartialEq + fmt::Debug + 'static {
    /// Every place of this kind, each once, in declaration order.
    const ALL: &'static [Self];
    /// This place's position in [`Self::ALL`]: how the attribution ledger of
    /// this crate's test builds keys it.
    #[cfg(test)]
    #[cfg(feature = "std")]
    fn index(self) -> usize;
}

/// The place of a charge made by code shared among several places: storage
/// growth and release, comparison, field initialization. The caller supplies
/// the place ([`at`]); a charge of this place is recorded at no place of its
/// own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Caller;

impl Place for Caller {
    const ALL: &'static [Self] = &[Caller];

    #[cfg(test)]
    #[cfg(feature = "std")]
    fn index(self) -> usize {
        0
    }
}

/// Attribute every admission `f` makes to `place`, in this crate's own test
/// builds; in every build, `f()`. How a caller supplies the place of the
/// shared code it calls, or of a nested operation whose own charges carry
/// their own places: exactly the admissions of this one call.
#[inline(always)]
pub(crate) fn at<P: Place, T>(place: P, f: impl FnOnce() -> T) -> T {
    #[cfg(test)]
    #[cfg(feature = "std")]
    let _entered = places::enter(place);
    #[cfg(not(all(test, feature = "std")))]
    let _ = place;
    f()
}

/// Admit `values` and `bytes` at `place`: the one admission route. In this
/// crate's own test builds the admission is marked as routed, and the
/// attribution ledger refuses any that is not.
#[expect(
    clippy::disallowed_methods,
    reason = "the one admission route every charge rule's `admit` goes through"
)]
fn admit_at<P: Place, B: Budget>(
    place: P,
    budget: &mut B,
    values: u64,
    bytes: u64,
) -> BoundedResult<(), B> {
    #[cfg(test)]
    #[cfg(feature = "std")]
    let _routed = places::route();
    at(place, || budget.traverse(values, bytes)).map_err(BoundedError::Refused)
}

/// The bytes one admitted unit stores into retained state, its write
/// extent: at most a quantum, a turn's bytes ([`TURN`]). The one check of a
/// write extent. Every caller evaluates it in a constant, so a unit that
/// would store more than a quantum fails to compile where it is defined.
/// The bytes a unit is charged are a separate quantity: what it scans,
/// copies or emits, each byte once, whether or not it is retained.
pub(crate) const fn write_extent(bytes: usize) -> u64 {
    assert!(
        bytes <= TURN.bytes as usize,
        "one admitted unit stores more than a quantum into retained state"
    );
    bytes as u64
}

/// The most bytes an [`Allocator::Permit`] may take, one limit on every
/// path: a retained arena's whole state, its vector, tracked capacity and
/// permit beside a staged growth, and a decode record's header, state and
/// permit each fit a quantum only with permits this small.
pub const PERMIT_BYTES: usize = 16;

/// The bytes of a permit of `P`: the one check of [`PERMIT_BYTES`]. Every
/// allocation's release unit is defined through it and admitted by the
/// acquisition, each evaluated in a constant, so a larger permit fails to
/// compile wherever an allocation of it is requested.
pub(crate) const fn permit_bytes<P>() -> usize {
    assert!(
        core::mem::size_of::<P>() <= PERMIT_BYTES,
        "a permit takes more than PERMIT_BYTES bytes"
    );
    core::mem::size_of::<P>()
}

/// An admission of exactly `values` and `bytes`, defined once for the engine
/// that makes it and the bound that counts it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Unit<P> {
    place: P,
    values: u64,
    bytes: u64,
}

impl<P: Place> Unit<P> {
    pub(crate) const fn new(place: P, values: u64, bytes: u64) -> Self {
        Self {
            place,
            values,
            bytes,
        }
    }

    /// One unit of a value and the bytes of a `T`.
    pub(crate) const fn of<T>(place: P) -> Self {
        Self::new(place, 1, core::mem::size_of::<T>() as u64)
    }

    /// One unit storing a whole `T` into retained state: one value and its
    /// bytes, a write extent of at most a quantum ([`write_extent`]).
    pub(crate) const fn written<T>(place: P) -> Self {
        Self::new(place, 1, write_extent(core::mem::size_of::<T>()))
    }

    /// The values one unit admits.
    pub(crate) const fn values(self) -> u64 {
        self.values
    }

    /// The bytes one unit admits.
    pub(crate) const fn bytes(self) -> u64 {
        self.bytes
    }

    pub(crate) fn admit<B: Budget>(self, budget: &mut B) -> BoundedResult<(), B> {
        admit_at(self.place, budget, self.values, self.bytes)
    }

    /// `count` of these units.
    pub(crate) fn times<R>(self, count: u64) -> Result<WriteWork, BoundedError<R>> {
        WriteWork::new(self.values, self.bytes).times(count)
    }

    /// One of these units as a [`ResourceBound`]: what a constant cost sums.
    pub(crate) const fn bound(self) -> ResourceBound {
        ResourceBound {
            values: self.values,
            bytes: self.bytes,
            allocated: 0,
            peak: 0,
            retained: 0,
        }
    }
}

/// An admission of `values` and at most `cap` bytes, the bytes those of the
/// part of a larger item one unit covers: a quantum of a payload, a scalar of
/// a text. Admitting more than the cap is an engine defect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Capped<P> {
    place: P,
    values: u64,
    cap: u64,
}

impl<P: Place> Capped<P> {
    pub(crate) const fn new(place: P, values: u64, cap: u64) -> Self {
        Self { place, values, cap }
    }

    /// The most bytes one unit covers.
    pub(crate) const fn cap(self) -> u64 {
        self.cap
    }

    /// The values one unit admits.
    pub(crate) const fn values(self) -> u64 {
        self.values
    }

    pub(crate) fn admit<B: Budget>(self, budget: &mut B, bytes: u64) -> BoundedResult<(), B> {
        if bytes > self.cap {
            return Err(BoundedError::PlanMismatch);
        }
        admit_at(self.place, budget, self.values, bytes)
    }

    /// The units covering `bytes` bytes, each at most the cap, and `items`
    /// more for the last, partial unit of each of that many items.
    pub(crate) fn covering<R>(self, bytes: u64, items: u64) -> Result<WriteWork, BoundedError<R>> {
        let units = add(bytes.div_ceil(self.cap.max(1)), items)?;
        Ok(WriteWork::new(mul(units, self.values)?, bytes))
    }

    /// `count` units of the full cap each.
    pub(crate) fn times<R>(self, count: u64) -> Result<WriteWork, BoundedError<R>> {
        WriteWork::new(self.values, self.cap).times(count)
    }
}

/// One admission of `values` and every byte of a span it examines or copies
/// at once, uncapped: a synchronous operation's whole payload, key or
/// encoding, whose bytes the bound counts from its source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Scan<P> {
    place: P,
    values: u64,
}

impl<P: Place> Scan<P> {
    pub(crate) const fn new(place: P, values: u64) -> Self {
        Self { place, values }
    }

    /// The values one admission admits.
    pub(crate) const fn values(self) -> u64 {
        self.values
    }

    pub(crate) fn admit<B: Budget>(self, budget: &mut B, bytes: u64) -> BoundedResult<(), B> {
        admit_at(self.place, budget, self.values, bytes)
    }

    /// `units` of these admissions over `bytes` bytes in all.
    pub(crate) fn units<R>(self, units: u64, bytes: u64) -> Result<WriteWork, BoundedError<R>> {
        Ok(WriteWork::new(mul(units, self.values)?, bytes))
    }
}

/// An admission of a fixed base and `values` and `bytes` per element of a
/// count known only when it is made: relocated elements, scanned buckets, a
/// pass over digits, a counting pass over its classes and its elements.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Rate<P> {
    place: P,
    base: WriteWork,
    each: WriteWork,
}

impl<P: Place> Rate<P> {
    /// `values` and `bytes` per element, nothing more.
    pub(crate) const fn new(place: P, values: u64, bytes: u64) -> Self {
        Self::based(place, WriteWork::new(0, 0), WriteWork::new(values, bytes))
    }

    /// `base`, and `each` per element.
    pub(crate) const fn based(place: P, base: WriteWork, each: WriteWork) -> Self {
        Self { place, base, each }
    }

    pub(crate) fn admit<B: Budget>(self, budget: &mut B, count: u64) -> BoundedResult<(), B> {
        let work = self.of(count)?;
        admit_at(self.place, budget, work.values, work.bytes)
    }

    /// The work of one admission over `count` elements.
    pub(crate) fn of<R>(self, count: u64) -> Result<WriteWork, BoundedError<R>> {
        self.base.then(self.each.times(count)?)
    }

    /// The work of `admissions` admissions over `count` elements in all.
    pub(crate) fn over<R>(self, admissions: u64, count: u64) -> Result<WriteWork, BoundedError<R>> {
        self.base.times(admissions)?.then(self.each.times(count)?)
    }
}

/// A bound summed over the places its operation charges, one term each, so
/// that each term can be checked against what its place admitted, requested
/// and held.
pub(crate) trait Places {
    type Place: Place;

    /// What this bound charges `place`: its work, its allocation requests,
    /// the most bytes it holds at once, and what it still holds once the
    /// operation publishes.
    fn term(&self, place: Self::Place) -> ResourceBound;

    /// The most bytes the operation holds at once. By default every place's
    /// peak at once; a bound whose places hold storage at different times
    /// composes their peaks itself.
    fn peak<R>(&self) -> Result<u64, BoundedError<R>> {
        let mut peak = 0u64;
        for &place in Self::Place::ALL {
            peak = add(peak, self.term(place).peak)?;
        }
        Ok(peak)
    }

    /// The bound: every place's work, requests and retained bytes summed,
    /// and [`Self::peak`].
    fn bound<R>(&self) -> Result<ResourceBound, BoundedError<R>> {
        let mut bound = ResourceBound::default();
        for &place in Self::Place::ALL {
            let term = self.term(place);
            bound.values = add(bound.values, term.values)?;
            bound.bytes = add(bound.bytes, term.bytes)?;
            bound.allocated = add(bound.allocated, term.allocated)?;
            bound.retained = add(bound.retained, term.retained)?;
        }
        bound.peak = self.peak()?;
        Ok(bound)
    }
}

#[cfg(feature = "num-bigint")]
mod bigint;
pub mod decode;
pub mod encoding;
mod policy;
pub mod text;
pub mod text_cursor;
pub use encoding::Tagged;
pub use policy::{
    Admission, AdmissionTrace, Call, LimitRefusal, Limits, Reservation, TURN, TransferRefusal,
};

/// Why a bounded preparation or write stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoundedError<R> {
    /// The budget refused work before it was done.
    Refused(R),
    /// An encoded length or a work bound does not fit in `u64`.
    Overflow,
    /// A symbolic integer is outside the selected dCBOR profile.
    OutOfRange,
    /// Distinct source keys have the same canonical encoding.
    DuplicateKey,
    /// A symbolic value exceeds the bounded encoder's nesting limit.
    DepthLimit,
    /// An allocation the budget admitted could not be made.
    Allocation { bytes: u64 },
    /// The output given is not the plan's length; nothing was written.
    OutputSize { measured: u64, provided: u64 },
    /// A source answered differently than its schema contract allows (a
    /// counted map's count, an entry window, an encoding past its walked
    /// extent), or a plan's bytes do not account for its length.
    PlanMismatch,
}

impl<R: fmt::Display> fmt::Display for BoundedError<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(refused) => write!(f, "bounded encoding refused: {refused}"),
            Self::Overflow => f.write_str("encoded length or work exceeds u64"),
            Self::OutOfRange => f.write_str("value is outside the dCBOR profile"),
            Self::DuplicateKey => f.write_str("duplicate canonical map key"),
            Self::DepthLimit => f.write_str("symbolic encoding nesting limit exceeded"),
            Self::Allocation { bytes } => write!(f, "an allocation of {bytes} bytes failed"),
            Self::OutputSize { measured, provided } => write!(
                f,
                "bounded encoding measured {measured} bytes, given an output of {provided}"
            ),
            Self::PlanMismatch => f.write_str("bounded encoding diverged from its plan"),
        }
    }
}

impl<R: fmt::Debug + fmt::Display> core::error::Error for BoundedError<R> {}

/// The result of a bounded operation under budget `B`.
pub type BoundedResult<T, B> = Result<T, BoundedError<<B as Budget>::Refusal>>;

/// What bounded work is reported to before it is done. Implemented by the
/// caller; this crate charges nothing itself.
pub trait Budget {
    /// How the budget refuses.
    type Refusal;

    /// Admit before execution. `values` counts value visits (including numeric
    /// conversion and constant-size head emission), derived field inspections,
    /// normalization character processing and ordering comparisons. `bytes`
    /// counts source scans, payload copies, emitted normalization bytes, shifts
    /// of initialized scratch elements and potential relocation on growth.
    /// Repeated passes are counted separately; a conservative aggregate may
    /// admit a whole pass. These units bound reported operations, not CPU time.
    fn traverse(&mut self, values: u64, bytes: u64) -> Result<(), Self::Refusal>;
}

/// A budget that also governs allocation: each allocation is requested in
/// its whole size before it is made, a reallocation's new size while the
/// old allocation is still held, and its [`Self::Permit`] is held for
/// exactly the allocation's life. Dropping the permit releases it, and
/// cannot fail.
///
/// Releasing a permit is the last unit of an allocation's life, admitted by
/// the acquisition that requests it, before the allocation exists, as one
/// value and at most a quantum of bytes; any cleanup path, a stepped one or a
/// terminal one, then performs it unrefused. A permit is in the supported
/// domain only if dropping it does constant work, allocates nothing and
/// does not unwind: the terminal path's bound is one such drop per
/// allocation held. A permit is at most sixteen bytes, checked at compile
/// time wherever a retained arena or a decode record holds one. Owned
/// decode scopes that cross threads require `Permit: Send`.
pub trait Allocator: Budget {
    /// Held while the allocation it was given for exists.
    type Permit;

    /// Admit an allocation of `bytes` requested capacity bytes. This excludes
    /// allocator metadata and allocator rounding; it is not an RSS bound.
    fn allocate(&mut self, bytes: u64) -> Result<Self::Permit, Self::Refusal>;
}

/// A policy that can finish a decode scope after its scheduler has gone away.
///
/// # Safety
/// `terminal` and dropping its result must not allocate or unwind. The returned
/// policy's `traverse` must always succeed, do bounded allocation-free work,
/// and never unwind. Its `allocate` must not allocate: reclamation is forbidden
/// from requesting new storage. The policy must not borrow `permit`.
pub unsafe trait TerminalAllocator: Allocator + Sized {
    fn terminal(permit: &Self::Permit) -> Self;
}

impl<B: Budget + ?Sized> Budget for &mut B {
    type Refusal = B::Refusal;

    #[expect(
        clippy::disallowed_methods,
        reason = "forwards an admission already made through the route"
    )]
    fn traverse(&mut self, values: u64, bytes: u64) -> Result<(), Self::Refusal> {
        (**self).traverse(values, bytes)
    }
}

impl<A: Allocator + ?Sized> Allocator for &mut A {
    type Permit = A::Permit;

    fn allocate(&mut self, bytes: u64) -> Result<Self::Permit, Self::Refusal> {
        (**self).allocate(bytes)
    }
}

/// What one step of a [`Resumable`] operation reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step<O> {
    /// The step admitted and performed work; the operation continues.
    Progress,
    /// The operation published its result; later steps return `Finished`.
    Complete(O),
    /// The operation completed, or finished its cleanup, earlier.
    Finished,
}

/// How a failed step failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class<R> {
    /// The policy refused an admission. All progress is retained; the same
    /// operation resumes on a later step.
    Refused(R),
    /// A physical allocation failed after its admission.
    Allocation,
    /// The input or source is invalid or exceeds the encoding's limits.
    Invalid,
    /// An implementation or caller contract was violated.
    Defect,
}

/// A step's error, classified.
pub trait Failure {
    type Refusal;

    fn class(&self) -> Class<&Self::Refusal>;

    /// A refusal retains all progress; the same operation resumes.
    fn refused(&self) -> bool {
        matches!(self.class(), Class::Refused(_))
    }
}

impl<R> Failure for BoundedError<R> {
    type Refusal = R;

    fn class(&self) -> Class<&R> {
        match self {
            Self::Refused(refusal) => Class::Refused(refusal),
            Self::Allocation { .. } => Class::Allocation,
            // Lengths that do not fit, out-of-profile values, colliding keys
            // and excessive nesting are properties of the input or source.
            Self::Overflow | Self::OutOfRange | Self::DuplicateKey | Self::DepthLimit => {
                Class::Invalid
            }
            Self::OutputSize { .. } | Self::PlanMismatch => Class::Defect,
        }
    }
}

/// A retained bounded operation: one admitted step at a time, its progress
/// held between steps. Every implementation keeps this contract:
///
/// - Each unit of work is admitted to the policy before it is performed.
///   Every allocation's release is admitted by the acquisition that
///   requests it, before the allocation exists, so a release is paid for
///   on every path that performs it.
/// - A refused step keeps every admission it made before the refusal and
///   exactly the progress those admissions paid for; a step whose only
///   admission attempt was refused leaves [`Self::position`] unchanged. The
///   same operation resumes on a later step, retrying the refused unit and
///   repeating no admitted one.
/// - A step that returns [`Step::Progress`] performs only work admitted
///   before it ran: admitted in that step, or a release its acquisition
///   paid for. Every such step lowers the operation's remaining measure,
///   the admissions its bound still allows plus the allocations it still
///   holds: a step that admits nothing releases one allocation, so the
///   measure is well founded and the operation terminates.
/// - Cancelling an operation forfeits the admissions it holds for an
///   acquisition whose allocation was not yet granted: at most one write
///   and one release per acquisition site, counted in its bound. Admitted
///   work is never refunded.
/// - After [`Step::Complete`] or [`Step::Finished`], every step returns
///   [`Step::Finished`] and admits nothing.
/// - After a terminal (non-refused) error, steps perform the operation's
///   own cleanup until they return [`Step::Finished`].
pub trait Resumable<A: Budget> {
    type Output;
    type Error: Failure<Refusal = A::Refusal>;
    /// Allocation-free observation of the retained progress.
    type Position: Clone + PartialEq + fmt::Debug;

    fn step(&mut self, a: &mut A) -> Result<Step<Self::Output>, Self::Error>;

    fn position(&mut self) -> Self::Position;
}

/// `left + right`, refused rather than wrapped.
pub fn add<R>(left: u64, right: u64) -> Result<u64, BoundedError<R>> {
    left.checked_add(right).ok_or(BoundedError::Overflow)
}

/// `left * right`, refused rather than wrapped.
pub fn mul<R>(left: u64, right: u64) -> Result<u64, BoundedError<R>> {
    left.checked_mul(right).ok_or(BoundedError::Overflow)
}

/// A `usize` count or length as `u64`.
pub fn widen<R>(value: usize) -> Result<u64, BoundedError<R>> {
    u64::try_from(value).map_err(|_| BoundedError::Overflow)
}

/// The encoded length of an item of `payload` bytes behind the shortest
/// head carrying `argument`.
pub fn item_len<R>(argument: u64, payload: u64) -> Result<u64, BoundedError<R>> {
    add(widen(head_len(argument))?, payload)
}

/// Releasing one [`Owned`] allocation: the vector rewritten empty and its
/// permit dropped, one value and the vector's own bytes, at most a quantum
/// whatever its element and permit types. Admitted by the growth that
/// requests the allocation ([`Owned::reserve`]).
pub(crate) const RELEASED: Capped<Caller> = Capped::new(Caller, 1, TURN.bytes);

/// A vector whose capacity grows only through its [`Allocator`], doubling
/// from four elements, each growth admitted in its whole new size, and its
/// eventual release, before it is made and its permit held for as long as
/// the allocation; the replaced allocation's permit is released after the
/// new one exists. Its capacity is tracked as requested, not as the
/// allocator rounded it, so two runs over the same input request the same
/// allocations.
pub struct Owned<T, P> {
    items: Vec<T>,
    capacity: usize,
    permit: Option<P>,
}

impl<T, P> Owned<T, P> {
    /// Each initialized element a moving reallocation may copy, or an
    /// insertion shifts: no value and its bytes.
    const MOVE: Rate<Caller> = Rate::new(Caller, 0, core::mem::size_of::<T>() as u64);

    /// The bytes one release of this vector rewrites, its write extent, of
    /// a permit within [`PERMIT_BYTES`].
    pub(crate) const RELEASE_BYTES: u64 = {
        permit_bytes::<P>();
        write_extent(core::mem::size_of::<Self>())
    };

    pub const fn new() -> Self {
        Self {
            items: Vec::new(),
            capacity: 0,
            permit: None,
        }
    }

    pub fn as_slice(&self) -> &[T] {
        &self.items
    }

    /// The elements, writable in place.
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        &mut self.items
    }

    /// Remove the last element: one held value handed back, the allocation
    /// kept.
    pub fn pop(&mut self) -> Option<T> {
        self.items.pop()
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Make room for `additional` more elements.
    pub fn reserve<A: Allocator<Permit = P>>(
        &mut self,
        additional: usize,
        allocator: &mut A,
    ) -> BoundedResult<(), A> {
        let needed = self
            .items
            .len()
            .checked_add(additional)
            .ok_or(BoundedError::Overflow)?;
        while self.capacity < needed {
            let grown = if self.capacity == 0 {
                4
            } else {
                self.capacity.checked_mul(2).ok_or(BoundedError::Overflow)?
            };
            let bytes = mul(widen(grown)?, widen(core::mem::size_of::<T>())?)?;
            // A moving reallocation can copy every initialized element; the
            // new allocation's release is paid for before it is requested.
            Self::MOVE.admit(allocator, widen(self.items.len())?)?;
            RELEASED.admit(allocator, const { Self::RELEASE_BYTES })?;
            let permit = allocator.allocate(bytes).map_err(BoundedError::Refused)?;
            // On failure the new permit drops here, releasing what was
            // admitted for the allocation that did not happen.
            self.items
                .try_reserve_exact(grown - self.items.len())
                .map_err(|_| BoundedError::Allocation { bytes })?;
            self.permit = Some(permit);
            self.capacity = grown;
        }
        Ok(())
    }

    pub fn push<A: Allocator<Permit = P>>(
        &mut self,
        item: T,
        allocator: &mut A,
    ) -> BoundedResult<(), A> {
        self.reserve(1, allocator)?;
        self.items.push(item);
        Ok(())
    }

    /// Insert `item` at `at`, shifting the elements after it.
    pub fn insert<A: Allocator<Permit = P>>(
        &mut self,
        at: usize,
        item: T,
        allocator: &mut A,
    ) -> BoundedResult<(), A> {
        let shifted = self
            .items
            .len()
            .checked_sub(at)
            .ok_or(BoundedError::Overflow)?;
        Self::MOVE.admit(allocator, widen(shifted)?)?;
        self.reserve(1, allocator)?;
        self.items.insert(at, item);
        Ok(())
    }

    /// Remove every element, keeping the allocation and its permit.
    pub fn drain(&mut self) -> impl Iterator<Item = T> + '_ {
        self.items.drain(..)
    }

    /// Whether this vector holds an allocation or its reservation.
    pub(crate) fn holds(&self) -> bool {
        self.capacity != 0 || self.permit.is_some()
    }

    /// Free this vector's allocation, then release its permit: a release its
    /// growth paid for, so nothing is admitted. False when it holds neither.
    /// The vector must be empty or hold plain data: no element destructor is
    /// bounded.
    pub(crate) fn release(&mut self) -> bool {
        if !self.holds() {
            return false;
        }
        *self = Self::new();
        true
    }
}

impl<P> Owned<u8, P> {
    pub fn extend_from_slice<A: Allocator<Permit = P>>(
        &mut self,
        bytes: &[u8],
        allocator: &mut A,
    ) -> BoundedResult<(), A> {
        self.reserve(bytes.len(), allocator)?;
        self.items.extend_from_slice(bytes);
        Ok(())
    }
}

impl<T, P> Default for Owned<T, P> {
    fn default() -> Self {
        Self::new()
    }
}

/// What one [`Owned`] reports and holds, at most, over a life in which it
/// holds at most a given number of elements at once ([`owned_growth`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Growth {
    /// Bytes its growths report to [`Budget::traverse`] as relocation of
    /// initialized elements.
    pub copied: u64,
    /// Its allocations, each of whose release its growth admits.
    pub allocations: u64,
    /// The sum of its allocation requests.
    pub allocated: u64,
    /// Bytes its permit holds once it has grown to hold that many elements.
    pub held: u64,
    /// The most bytes its permits hold at once: the old allocation and the
    /// new one during its last growth.
    pub peak: u64,
}

/// The [`Growth`] of an [`Owned`] of `element_size`-byte elements that holds
/// at most `elements` at once, by the growth policy [`Owned::reserve`]
/// follows: capacity doubles from four elements, each growth reporting the
/// relocation of every initialized element (at most the capacity before it)
/// and requesting its whole new capacity while the old permit is held. One
/// growth passing several capacities requests each of them in turn, as a
/// sequence of single growths does, so the result bounds every order of
/// pushes, inserts and reservations reaching `elements`. Refused, never
/// saturated, when a quantity does not fit in `u64`.
pub fn owned_growth<R>(elements: u64, element_size: u64) -> Result<Growth, BoundedError<R>> {
    let mut growth = Growth::default();
    let mut capacity = 0u64;
    while capacity < elements {
        let grown = if capacity == 0 { 4 } else { mul(capacity, 2)? };
        let previous = mul(capacity, element_size)?;
        let bytes = mul(grown, element_size)?;
        growth.copied = add(growth.copied, previous)?;
        growth.allocations = add(growth.allocations, 1)?;
        growth.allocated = add(growth.allocated, bytes)?;
        growth.peak = add(previous, bytes)?;
        growth.held = bytes;
        capacity = grown;
    }
    Ok(growth)
}

/// The least `x` in `from + 1 ..= to` at which nondecreasing `f` exceeds
/// `level`, or `None` when none does: where a monotone bound next rises,
/// found by binary search in at most `log2(to - from) + 1` evaluations.
/// How a peak taken over every split of an input is reduced to the splits
/// that start each level of the part whose peak rises with its length.
pub(crate) fn next_rise<R>(
    from: u64,
    to: u64,
    level: u64,
    f: &impl Fn(u64) -> Result<u64, BoundedError<R>>,
) -> Result<Option<u64>, BoundedError<R>> {
    if from >= to || f(to)? <= level {
        return Ok(None);
    }
    // `f(low) <= level < f(high)` throughout.
    let (mut low, mut high) = (from, to);
    while high - low > 1 {
        let middle = low + (high - low) / 2;
        if f(middle)? > level {
            high = middle;
        } else {
            low = middle;
        }
    }
    Ok(Some(high))
}

impl Growth {
    /// This growth and `other`'s, every quantity summed: the bound of two
    /// buffers that may exist at once.
    pub fn plus<R>(self, other: Self) -> Result<Self, BoundedError<R>> {
        Ok(Self {
            copied: add(self.copied, other.copied)?,
            allocations: add(self.allocations, other.allocations)?,
            allocated: add(self.allocated, other.allocated)?,
            held: add(self.held, other.held)?,
            peak: add(self.peak, other.peak)?,
        })
    }

    /// The releases its growths admit, one per allocation, each at most a
    /// quantum ([`RELEASED`]).
    pub(crate) fn released<R>(&self) -> Result<WriteWork, BoundedError<R>> {
        RELEASED.times(self.allocations)
    }
}

/// What a retained arena (`decode::storage::Storage`) of `element_size`-byte
/// elements reports and holds over a life in which it holds at most
/// `elements` at once: the [`Growth`] of its grown allocations, by the same
/// doubling policy as [`Owned`], each staged in a block of at most a
/// quantum, the block held beside the old and the grown allocation while
/// the elements relocate; and its work: one admitted unit of an element's
/// bytes per element it relocates, and each growth's writes. Each growth's
/// two allocations, the grown arena's and its block's, admit their releases
/// ([`Growth::released`]). A capped reservation requests no more than this.
pub fn storage_growth<R>(
    elements: u64,
    element_size: u64,
) -> Result<(Growth, WriteWork), BoundedError<R>> {
    let grown = owned_growth(elements, element_size)?;
    let growths = grown.allocations;
    // A staging block holds one arena and its permit, at most a quantum.
    let block = TURN.bytes;
    // Relocated elements are the capacities before each growth: the bytes
    // copied by a growth of one-byte elements.
    let relocated = owned_growth(elements, 1)?.copied;
    let growth = Growth {
        copied: grown.copied,
        allocations: mul(growths, 2)?,
        allocated: add(grown.allocated, mul(growths, block)?)?,
        held: grown.held,
        peak: if growths == 0 {
            0
        } else {
            add(grown.peak, block)?
        },
    };
    let work = WriteWork::new(relocated, grown.copied)
        .then(decode::storage::Storage::<u8, ()>::growth_work(growths)?)?;
    Ok((growth, work))
}

/// What one bounded operation reports and holds at most, for any input its
/// bound admits, on success or at any failure: the work it reports to
/// [`Budget::traverse`], the sum of its allocation requests, the most bytes
/// its permits hold at once while it runs, and the most bytes the permits of
/// what it publishes hold once it completes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResourceBound {
    /// Values reported to [`Budget::traverse`].
    pub values: u64,
    /// Bytes reported to [`Budget::traverse`].
    pub bytes: u64,
    /// The sum of every allocation request.
    pub allocated: u64,
    /// The most bytes the operation's permits hold at once while it runs,
    /// what it retains included.
    pub peak: u64,
    /// The most bytes the permits of what it publishes hold.
    pub retained: u64,
}

impl ResourceBound {
    /// The work this bound reports, as one admission.
    pub const fn work(&self) -> WriteWork {
        WriteWork::new(self.values, self.bytes)
    }

    /// The most steps a [`Resumable`] operation of this bound takes, its
    /// cleanup included: a step admits at least one value or makes an
    /// allocation request of at least one byte, and a step that does neither
    /// releases an allocation, whose acquisition admitted that release as a
    /// value and requested at least a byte. So every step is counted by the
    /// values or the requested bytes. The one step rule of every driver that
    /// bounds a run, in this crate's tests and its integration harness alike.
    /// Refused, never saturated, when the sum does not fit in `u64`.
    pub fn steps<R>(&self) -> Result<u64, BoundedError<R>> {
        add(self.values, self.allocated)
    }

    /// The bound of `work` alone: nothing requested or held.
    pub(crate) const fn of_work(work: WriteWork) -> Self {
        Self {
            values: work.values,
            bytes: work.bytes,
            allocated: 0,
            peak: 0,
            retained: 0,
        }
    }

    /// This operation, then `next` while this one's output is still held:
    /// work and requests add, the peak is the larger of this operation's and
    /// its retained output beside `next`'s peak, and both outputs are
    /// retained.
    pub fn then<R>(self, next: Self) -> Result<Self, BoundedError<R>> {
        Ok(Self {
            values: add(self.values, next.values)?,
            bytes: add(self.bytes, next.bytes)?,
            allocated: add(self.allocated, next.allocated)?,
            peak: self.peak.max(add(self.retained, next.peak)?),
            retained: add(self.retained, next.retained)?,
        })
    }

    /// This operation, then `next` after this one's output was consumed and
    /// released: as [`Self::then`], but only `next`'s output is retained and
    /// nothing of this one's is held beside `next`'s peak.
    pub fn followed_by<R>(self, next: Self) -> Result<Self, BoundedError<R>> {
        Ok(Self {
            values: add(self.values, next.values)?,
            bytes: add(self.bytes, next.bytes)?,
            allocated: add(self.allocated, next.allocated)?,
            peak: self.peak.max(next.peak),
            retained: next.retained,
        })
    }

    /// The bound of `count` operations of this bound, each released before
    /// the next runs.
    pub fn repeated<R>(self, count: u64) -> Result<Self, BoundedError<R>> {
        Ok(Self {
            values: mul(self.values, count)?,
            bytes: mul(self.bytes, count)?,
            allocated: mul(self.allocated, count)?,
            peak: if count == 0 { 0 } else { self.peak },
            retained: if count == 0 { 0 } else { self.retained },
        })
    }

    /// The larger of this bound and `other` in every quantity: a bound of
    /// either operation, whichever runs.
    pub const fn larger(self, other: Self) -> Self {
        const fn max(left: u64, right: u64) -> u64 {
            if left > right { left } else { right }
        }
        Self {
            values: max(self.values, other.values),
            bytes: max(self.bytes, other.bytes),
            allocated: max(self.allocated, other.allocated),
            peak: max(self.peak, other.peak),
            retained: max(self.retained, other.retained),
        }
    }

    /// Whether a run that reported `used`, requested `allocated` bytes in
    /// all, held at most `peak` bytes at once and published output holding
    /// `retained` bytes is within this bound.
    pub const fn covers(&self, used: WriteWork, allocated: u64, peak: u64, retained: u64) -> bool {
        self.work().covers(&used)
            && allocated <= self.allocated
            && peak <= self.peak
            && retained <= self.retained
    }
}

/// The work a write reports at most: values visited and source bytes
/// examined or copied. A write allocates nothing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WriteWork {
    pub values: u64,
    pub bytes: u64,
}

impl WriteWork {
    pub const fn new(values: u64, bytes: u64) -> Self {
        Self { values, bytes }
    }

    /// This work, then `next`.
    pub fn then<R>(self, next: Self) -> Result<Self, BoundedError<R>> {
        Ok(Self {
            values: add(self.values, next.values)?,
            bytes: add(self.bytes, next.bytes)?,
        })
    }

    /// This work `count` times.
    pub fn times<R>(self, count: u64) -> Result<Self, BoundedError<R>> {
        Ok(Self {
            values: mul(self.values, count)?,
            bytes: mul(self.bytes, count)?,
        })
    }

    /// Whether `actual` is within this bound.
    pub const fn covers(&self, actual: &Self) -> bool {
        actual.values <= self.values && actual.bytes <= self.bytes
    }
}

pub use encoding::{Prepared, Schema, encode_bound};

/// Successfully encoded bytes together with the reservation that owns their
/// storage. No API separates the vector from its permit. Fields drop in order:
/// the allocation is freed before its reservation is released.
pub struct Encoded<P> {
    bytes: Vec<u8>,
    _permit: P,
}

impl<P> AsRef<[u8]> for Encoded<P> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// Prepare `value`'s encoding in one call under `allocator`: its shape
/// walked first ([`encoding::Shape::of`]), every instruction and text byte
/// admitted, then the retained engine ([`encoding::Preparation`]) stepped to
/// its plan, its arena capped at the shape's extent and a widest head per
/// map, so the plan it publishes holds the encoding, its gaps and no more.
/// Every allocation is requested from `allocator` before it is made; on
/// every error the preparation's storage is released with it. The bound of
/// both is [`encode_bound`]'s. The preparation takes at most the steps its
/// shape's bound allows ([`ResourceBound::steps`]); one that does not
/// complete within them has diverged from its plan
/// ([`BoundedError::PlanMismatch`]), whatever its policy admits.
pub fn prepare<T: Schema + ?Sized, A: Allocator>(
    value: &T,
    allocator: &mut A,
) -> BoundedResult<Prepared<A::Permit>, A> {
    let source: &dyn Schema = &value;
    let shape = encoding::Shape::of(source, allocator)?;
    let cap = usize::try_from(shape.appended()?).map_err(|_| BoundedError::Overflow)?;
    let steps = encoding::prepare_bound::<A::Permit, A::Refusal>(shape)?.steps()?;
    let mut preparation = encoding::Preparation::capped(source, cap);
    for _ in 0..steps {
        match preparation.step(allocator)? {
            Step::Progress => {}
            Step::Complete(prepared) => return Ok(prepared),
            Step::Finished => return Err(BoundedError::PlanMismatch),
        }
    }
    Err(BoundedError::PlanMismatch)
}

/// Prepare `value`'s encoding ([`prepare`]) and publish its plan in place as
/// the encoding ([`Prepared::publish`]), all under one policy: the plan's
/// arena, its permit with it, becomes the output, so nothing is allocated
/// or copied for it. A caller that prepares under one policy and writes
/// under another (an admitted unit) uses [`prepare`] and
/// [`Prepared::encode_owned`] or [`Prepared::publish`] directly.
pub fn encode<T: Schema + ?Sized, A: Allocator>(
    value: &T,
    allocator: &mut A,
) -> BoundedResult<Encoded<A::Permit>, A> {
    prepare(value, allocator)?.publish(allocator)
}

/// The canonical encoding of integer `value`, which every implementing
/// type's range keeps within `-2^63 ..= 2^64 - 1` (`int.rs`: a negative
/// value `v` is the negative argument `-1 - v`).
const fn integer(value: i128) -> Numeric {
    if value < 0 {
        Numeric::Negative((-1 - value) as u64)
    } else {
        Numeric::Unsigned(value as u64)
    }
}

/// The simple value `null` (22), which a unit struct encodes as
/// (`simple.rs`).
pub const NULL: u64 = 22;

#[cfg(test)]
mod tests;

/// The one bounded driver of this crate's own tests: an operation stepped
/// within the steps its production bound allows ([`ResourceBound::steps`]),
/// so a defect that makes a run spin fails by name instead of running until
/// the machine's memory or the test timeout ends it. Each caller keeps its
/// own oracles in `step`, which returns `Break` with the run's result once
/// it is reached. The integration harness drives by the same rule
/// (`tests/support/lifecycle.rs`, `turns`), which it takes from
/// [`ResourceBound::steps`].
#[cfg(test)]
pub(crate) fn within<T>(
    name: &str,
    bound: ResourceBound,
    step: impl FnMut() -> core::ops::ControlFlow<T>,
) -> T {
    let steps = bound
        .steps::<()>()
        .expect("the step bound of a fixture fits in u64");
    within_steps(name, steps, step)
}

/// [`within`] a step count already derived from a production bound: its
/// [`ResourceBound::steps`] with a policy's refusal allowance
/// ([`Limits::allowed`]) and any further allowance its caller derives and
/// states.
#[cfg(test)]
pub(crate) fn within_steps<T>(
    name: &str,
    steps: u64,
    mut step: impl FnMut() -> core::ops::ControlFlow<T>,
) -> T {
    for _ in 0..steps {
        if let core::ops::ControlFlow::Break(result) = step() {
            return result;
        }
    }
    panic!("{name}: exceeded its bound of {steps} steps");
}

/// Place attribution in this crate's test builds: the places entered around
/// each admission ([`at`]), a policy that records what is admitted, requested
/// and held at the innermost entered place of every kind, and the check that
/// every place is within its term.
#[cfg(test)]
#[cfg(feature = "std")]
pub(crate) mod places {
    use super::*;
    use core::any::TypeId;
    use std::cell::{Cell, RefCell};
    use std::sync::{Arc, Mutex};

    /// A place of any kind: its kind and its index among [`Place::ALL`].
    type Key = (TypeId, usize);

    fn key<P: Place>(place: P) -> Key {
        (TypeId::of::<P>(), place.index())
    }

    /// The place of `P`'s kind at `index`, as its kind and variant: how a
    /// diagnostic names an entered place.
    fn describe<P: Place>(index: usize) -> String {
        format!("{}::{:?}", core::any::type_name::<P>(), P::ALL[index])
    }

    /// One entered place: its key, and how a diagnostic names it.
    struct Frame {
        key: Key,
        describe: fn(usize) -> String,
    }

    std::thread_local! {
        /// The entered places, outermost first.
        static ENTERED: RefCell<Vec<Frame>> = const { RefCell::new(Vec::new()) };
        /// How many admissions through the route ([`super::admit_at`]) are
        /// in progress on this thread.
        static ROUTED: Cell<usize> = const { Cell::new(0) };
    }

    /// An entered place, left when dropped.
    pub(crate) struct Entered {
        depth: usize,
    }

    pub(crate) fn enter<P: Place>(place: P) -> Entered {
        ENTERED.with(|entered| {
            let mut entered = entered.borrow_mut();
            let depth = entered.len();
            entered.push(Frame {
                key: key(place),
                describe: describe::<P>,
            });
            Entered { depth }
        })
    }

    impl Drop for Entered {
        fn drop(&mut self) {
            ENTERED.with(|entered| entered.borrow_mut().truncate(self.depth));
        }
    }

    /// An admission in progress through the route, ended when dropped,
    /// unwinding included, so a panic inside one cannot leave a later
    /// admission on this thread marked as routed.
    pub(crate) struct Routed(());

    /// Mark an admission through the route as in progress. Nested routes,
    /// such as a write's budget forwarding to its caller's, are counted.
    pub(crate) fn route() -> Routed {
        ROUTED.with(|routed| routed.set(routed.get() + 1));
        Routed(())
    }

    impl Drop for Routed {
        fn drop(&mut self) {
            ROUTED.with(|routed| routed.set(routed.get() - 1));
        }
    }

    /// The places entered now, outermost first, by name.
    fn entered() -> Vec<String> {
        ENTERED.with(|entered| {
            entered
                .borrow()
                .iter()
                .map(|frame| (frame.describe)(frame.key.1))
                .collect()
        })
    }

    /// The innermost entered place of each kind, [`Caller`] excluded: the
    /// places an admission made now is recorded at.
    fn innermost() -> Vec<Key> {
        let caller = TypeId::of::<Caller>();
        ENTERED.with(|entered| {
            let entered = entered.borrow();
            entered
                .iter()
                .enumerate()
                .filter(|(at, frame)| {
                    let kind = frame.key.0;
                    kind != caller && !entered[at + 1..].iter().any(|inner| inner.key.0 == kind)
                })
                .map(|(_, frame)| frame.key)
                .collect()
        })
    }

    /// What one place admitted, requested and holds.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    struct Measured {
        work: WriteWork,
        allocated: u64,
        live: u64,
        peak: u64,
    }

    /// What was admitted, requested and held at each place, and by the whole
    /// run; every admission and request with the places it was made at; and
    /// the places and bytes of every allocation still held, by its permit's
    /// id.
    #[derive(Default)]
    pub(crate) struct Ledger {
        places: Vec<(Key, Measured)>,
        total: Measured,
        admissions: Vec<(Vec<Key>, WriteWork)>,
        requests: Vec<(Vec<Key>, u64)>,
        held: Vec<(u64, Vec<Key>, u64)>,
        next: u64,
    }

    impl Ledger {
        fn at(&mut self, key: Key) -> &mut Measured {
            match self.places.iter().position(|(at, _)| *at == key) {
                Some(index) => &mut self.places[index].1,
                None => {
                    self.places.push((key, Measured::default()));
                    &mut self.places.last_mut().expect("just pushed").1
                }
            }
        }

        fn work(&mut self, work: WriteWork) {
            let keys = innermost();
            for &key in &keys {
                let measured = self.at(key);
                measured.work = measured
                    .work
                    .then::<()>(work)
                    .expect("admitted work fits in u64");
            }
            self.total.work = self
                .total
                .work
                .then::<()>(work)
                .expect("admitted work fits in u64");
            self.admissions.push((keys, work));
        }

        /// Record an allocation of `bytes` at the places entered now; the id
        /// its permit releases it by.
        fn allocate(&mut self, bytes: u64) -> u64 {
            let keys = innermost();
            self.requests.push((keys.clone(), bytes));
            for &key in &keys {
                let measured = self.at(key);
                measured.allocated =
                    add::<()>(measured.allocated, bytes).expect("requests fit in u64");
                measured.live = add::<()>(measured.live, bytes).expect("live bytes fit in u64");
                measured.peak = measured.peak.max(measured.live);
            }
            let total = &mut self.total;
            total.allocated = add::<()>(total.allocated, bytes).expect("requests fit in u64");
            total.live = add::<()>(total.live, bytes).expect("live bytes fit in u64");
            total.peak = total.peak.max(total.live);
            let id = self.next;
            self.next += 1;
            self.held.push((id, keys, bytes));
            id
        }

        fn release(&mut self, id: u64) {
            let index = self
                .held
                .iter()
                .position(|(held, _, _)| *held == id)
                .expect("a permit releases what its ledger holds");
            let (_, keys, bytes) = self.held.swap_remove(index);
            for key in keys {
                let measured = self.at(key);
                measured.live = measured
                    .live
                    .checked_sub(bytes)
                    .expect("a place released what it never held");
            }
            self.total.live = self
                .total
                .live
                .checked_sub(bytes)
                .expect("the run released what it never held");
        }

        /// What the whole run admitted, requested and held at once, and what
        /// it holds now.
        pub(crate) fn total(&self) -> ResourceBound {
            ResourceBound {
                values: self.total.work.values,
                bytes: self.total.work.bytes,
                allocated: self.total.allocated,
                peak: self.total.peak,
                retained: self.total.live,
            }
        }

        /// What `place` admitted, requested and held at once, and what it
        /// holds now: what a run published, once its run is over.
        pub(crate) fn measured<P: Place>(&self, place: P) -> ResourceBound {
            let key = key(place);
            let measured = self
                .places
                .iter()
                .find(|(at, _)| *at == key)
                .map_or(Measured::default(), |(_, measured)| *measured);
            ResourceBound {
                values: measured.work.values,
                bytes: measured.work.bytes,
                allocated: measured.allocated,
                peak: measured.peak,
                retained: measured.live,
            }
        }

        /// What was admitted and requested at no place of `P`'s kind: of
        /// everything, or, `within` a place, of what was made at it.
        fn unattributed<P: Place>(&self, within: Option<Key>) -> (WriteWork, u64) {
            let kind = TypeId::of::<P>();
            let counted = |keys: &[Key]| {
                within.is_none_or(|within| keys.contains(&within))
                    && !keys.iter().any(|(at, _)| *at == kind)
            };
            let mut work = WriteWork::default();
            for (keys, admitted) in &self.admissions {
                if counted(keys) {
                    work = work
                        .then::<()>(*admitted)
                        .expect("admitted work fits in u64");
                }
            }
            let mut allocated = 0u64;
            for (keys, bytes) in &self.requests {
                if counted(keys) {
                    allocated = add::<()>(allocated, *bytes).expect("requests fit in u64");
                }
            }
            (work, allocated)
        }
    }

    /// A reservation, released from the live bytes of the places it was
    /// granted at when it drops, wherever that happens. It holds only its
    /// id and its ledger, so it is as small as the engine's records require
    /// of a permit: those records, a decode scope's block among them, and a
    /// permit within each, fit a quantum.
    pub(crate) struct Permit {
        id: u64,
        ledger: Arc<Mutex<Ledger>>,
    }

    impl Drop for Permit {
        fn drop(&mut self) {
            self.ledger
                .lock()
                .expect("the ledger is not poisoned")
                .release(self.id);
        }
    }

    /// An unlimited policy recording every admission and allocation at the
    /// places entered when it is made. It never refuses, and it fails any
    /// admission not made through the route ([`super::admit_at`]): one that
    /// carries no place.
    pub(crate) struct Ledgered {
        ledger: Arc<Mutex<Ledger>>,
        terminal: bool,
    }

    impl Ledgered {
        pub(crate) fn new() -> Self {
            Self {
                ledger: Arc::new(Mutex::new(Ledger::default())),
                terminal: false,
            }
        }

        /// A policy recording into this one's ledger: how one run is checked
        /// against the bounds of several kinds of places.
        pub(crate) fn shared(&self) -> Self {
            Self {
                ledger: self.ledger.clone(),
                terminal: self.terminal,
            }
        }

        /// What has been recorded so far. Permits released later are released
        /// from the ledger this returns.
        pub(crate) fn ledger(&self) -> std::sync::MutexGuard<'_, Ledger> {
            self.ledger.lock().expect("the ledger is not poisoned")
        }
    }

    impl Budget for Ledgered {
        type Refusal = core::convert::Infallible;

        fn traverse(&mut self, values: u64, bytes: u64) -> Result<(), Self::Refusal> {
            if self.terminal {
                return Ok(());
            }
            assert!(
                ROUTED.with(Cell::get) > 0,
                "an admission of {values} values and {bytes} bytes bypassed the attributed \
                 route at places {:?}: admit through a charge rule's `admit` (`Unit`, \
                 `Capped`, `Scan`, `Rate`), or, in derived code, `bounded::decode::visits` \
                 or `bounded::decode::construction::in_place::step`",
                entered()
            );
            self.ledger().work(WriteWork::new(values, bytes));
            Ok(())
        }
    }

    impl Allocator for Ledgered {
        type Permit = Permit;

        fn allocate(&mut self, bytes: u64) -> Result<Permit, Self::Refusal> {
            if self.terminal {
                std::process::abort();
            }
            let id = self.ledger().allocate(bytes);
            Ok(Permit {
                id,
                ledger: self.ledger.clone(),
            })
        }
    }

    // SAFETY: terminal setup only clones the permit's Arc; traversal bypasses
    // the allocating attribution ledger, and allocation attempts abort.
    unsafe impl TerminalAllocator for Ledgered {
        fn terminal(permit: &Permit) -> Self {
            Self {
                ledger: permit.ledger.clone(),
                terminal: true,
            }
        }
    }

    /// One measured run: its name, the policy it ran under, and the bound's
    /// terms at its input.
    pub(crate) struct Run<T> {
        pub(crate) name: String,
        pub(crate) outcome: Outcome,
        pub(crate) policy: Ledgered,
        pub(crate) terms: T,
    }

    /// The declared, checked end of a measured case. Defects are representable
    /// so that the evidence boundary itself can be tested, but never admissible.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Outcome {
        Published,
        Invalid,
        Cancelled,
        Exact,
        Defect,
    }

    impl Outcome {
        fn name(self) -> &'static str {
            match self {
                Self::Published => "published",
                Self::Invalid => "invalid",
                Self::Cancelled => "cancelled",
                Self::Exact => "exact",
                Self::Defect => "defect",
            }
        }

        fn parse(text: &str) -> Option<Self> {
            [
                Self::Published,
                Self::Invalid,
                Self::Cancelled,
                Self::Exact,
                Self::Defect,
            ]
            .into_iter()
            .find(|outcome| outcome.name() == text)
        }

        fn admissible(self, name: &str) {
            assert_ne!(self, Self::Defect, "{name}: refusing Defect-class evidence");
        }
    }

    /// Check a bound's places against measured runs, one per fixture, each
    /// ended: whatever it published still held, everything else released.
    /// Every admission and request was made at some place; each place's
    /// work, requests, peak and retained bytes are within its term; every
    /// place whose term charges anything is exercised by some run. A term
    /// removed or understated fails wherever its place is exercised, whatever
    /// the other terms' slack.
    pub(crate) fn check<T: Places>(runs: &[Run<T>]) {
        verify(runs, Coverage::Whole);
    }

    /// [`check`] for the places of a part of an operation, which apply
    /// within the operation's place `within`: every admission and request
    /// made at `within` was made at some place of the part's kind; what the
    /// operation does outside it is its own bound's to check.
    pub(crate) fn check_within<T: Places, Q: Place>(runs: &[Run<T>], within: Q) {
        verify(runs, Coverage::Within(key(within)));
    }

    /// [`check`] of the terms alone, for places that cover only some of what
    /// their operation's part admits, the rest being shared code's whose
    /// coverage another kind's check establishes.
    pub(crate) fn check_terms<T: Places>(runs: &[Run<T>]) {
        verify(runs, Coverage::Terms);
    }

    /// Which admissions a check requires to be made at some place of its
    /// kind.
    #[derive(Clone, Copy)]
    enum Coverage {
        /// Every admission of the run.
        Whole,
        /// Every admission made at this place.
        Within(Key),
        /// None: the terms alone are checked.
        Terms,
    }

    /// One failure of a run: the place whose term it measured beyond, or
    /// none for admissions made at no place.
    struct Failure<P> {
        place: Option<P>,
        text: String,
    }

    /// What one run violates of `terms` under `coverage`; each place it
    /// exercises and each place `terms` charges is marked.
    fn failures<T: Places>(
        run: &Run<impl Sized>,
        terms: &T,
        coverage: Coverage,
        exercised: &mut [bool],
        charged: &mut [bool],
    ) -> Vec<Failure<T::Place>> {
        let ledger = run.policy.ledger();
        let mut failures = Vec::new();
        let within = match coverage {
            Coverage::Whole => Some(None),
            Coverage::Within(key) => Some(Some(key)),
            Coverage::Terms => None,
        };
        if let Some(within) = within {
            let (work, allocated) = ledger.unattributed::<T::Place>(within);
            if work != WriteWork::default() || allocated != 0 {
                failures.push(Failure {
                    place: None,
                    text: format!(
                        "{}: {work:?} admitted and {allocated} bytes requested at no place",
                        run.name
                    ),
                });
            }
        }
        for &place in T::Place::ALL {
            let measured = ledger.measured(place);
            let term = terms.term(place);
            exercised[place.index()] |= measured != ResourceBound::default();
            charged[place.index()] |= term != ResourceBound::default();
            if !term.covers(
                measured.work(),
                measured.allocated,
                measured.peak,
                measured.retained,
            ) {
                failures.push(Failure {
                    place: Some(place),
                    text: format!(
                        "{}: {place:?} measured {measured:?} beyond its term {term:?}",
                        run.name
                    ),
                });
            }
        }
        failures
    }

    fn verify<T: Places>(runs: &[Run<T>], coverage: Coverage) {
        let all = T::Place::ALL;
        for (at, place) in all.iter().enumerate() {
            assert_eq!(place.index(), at, "{place:?} is out of order");
        }
        let mut exercised = vec![false; all.len()];
        let mut charged = vec![false; all.len()];
        let mut texts = Vec::new();
        for run in runs {
            let found = failures(run, &run.terms, coverage, &mut exercised, &mut charged);
            texts.extend(found.into_iter().map(|failure| failure.text));
        }
        for &place in all {
            if charged[place.index()] && !exercised[place.index()] {
                texts.push(format!("{place:?} is charged but exercised by no run"));
            }
        }
        assert!(texts.is_empty(), "{texts:#?}");
    }

    /// How tight a place's term must be on its witness.
    #[derive(Clone, Copy, Debug)]
    pub(crate) enum Factor {
        /// Within this many times what the witness measured at the place, in
        /// each dimension the term charges: a ceiling, derived, with its
        /// derivation beside it.
        Within(u64),
        /// No derived ceiling: the measured ratio is held by the suite's
        /// ratchet alone ([`Tightness`]).
        Measured,
        /// The term is another operation's whole certified bound, reused
        /// exactly ([`nested`]) and checked tight place by place in the suite
        /// named; its share of the total is [`Tightness::joint`]'s.
        Nested(&'static str),
    }

    /// The assume-guarantee condition of a [`Factor::Nested`] place: its term
    /// is the inner operation's certified bound, exactly, in every dimension,
    /// neither re-derived nor padded.
    pub(crate) fn nested<P: Place>(place: P, term: ResourceBound, inner: ResourceBound) {
        assert_eq!(
            term, inner,
            "{place:?} must charge its nested operation's certified bound exactly"
        );
    }

    /// Rewrites every suite's recorded ratios from the current build when set.
    const RECORD_FACTORS: &str = "DCBOR_RECORD_FACTORS";

    /// The configuration a run is under, exported by the flake's shells: the
    /// toolchain and the standard library it builds against.
    const CONFIGURATION: &str = "DCBOR_CONFIGURATION";

    /// The first line of every record: this marker, then its configuration.
    const CONFIGURATION_LINE: &str = "#\tconfiguration\t";

    /// The configuration this run is under, when its shell exports one.
    fn configuration() -> Option<String> {
        std::env::var(CONFIGURATION)
            .ok()
            .filter(|identity| !identity.is_empty())
    }

    /// Publish `data` as `path` whole: written to a temporary file beside it,
    /// then renamed over it, so a failed write leaves the previous record.
    fn publish(path: &str, data: &str) {
        use std::io::Write;
        use std::sync::atomic::{AtomicUsize, Ordering};
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let temporary = format!(
            "{path}.{}.{}.tmp",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .unwrap_or_else(|error| panic!("{temporary}: {error}"));
        let result = file
            .write_all(data.as_bytes())
            .and_then(|_| file.sync_all());
        drop(file);
        if let Err(error) = result.and_then(|_| std::fs::rename(&temporary, path)) {
            let _ = std::fs::remove_file(&temporary);
            panic!("{path}: {error}");
        }
    }

    /// The features that change what this crate's bounds charge, and so the
    /// ratios its suites record, as the suffix of each record's name: with
    /// bignums, the preparation's record holds a bignum and its witness
    /// encodes them. Each build records and checks its own.
    const VARIANT: &str = match (
        cfg!(feature = "custom-std-collections"),
        cfg!(feature = "num-bigint"),
    ) {
        (false, false) => "",
        (false, true) => ".num-bigint",
        (true, false) => ".custom-std",
        (true, true) => ".custom-std.num-bigint",
    };

    /// One dimension of a [`ResourceBound`], each composed under its own
    /// rule: work and requests summed, the peak the most held at once,
    /// retained what publication holds.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Dimension {
        Values,
        Bytes,
        Allocated,
        Peak,
        Retained,
    }

    /// The work dimensions: what an input maximizing the dominant work term
    /// drives.
    pub(crate) const WORK: &[Dimension] = &[Dimension::Values, Dimension::Bytes];

    /// The storage dimensions: what an input maximizing what is held drives.
    pub(crate) const STORAGE: &[Dimension] =
        &[Dimension::Allocated, Dimension::Peak, Dimension::Retained];

    /// Every dimension: what an input driving work and storage at once, such
    /// as one text at its own shape, drives.
    pub(crate) const EVERY: &[Dimension] = &[
        Dimension::Values,
        Dimension::Bytes,
        Dimension::Allocated,
        Dimension::Peak,
        Dimension::Retained,
    ];

    impl Dimension {
        fn of(self, bound: ResourceBound) -> u64 {
            match self {
                Dimension::Values => bound.values,
                Dimension::Bytes => bound.bytes,
                Dimension::Allocated => bound.allocated,
                Dimension::Peak => bound.peak,
                Dimension::Retained => bound.retained,
            }
        }
    }

    /// The ceiling a recorded ratio is held to: a derived
    /// [`Factor::Within`], none beyond the record ([`Factor::Measured`]),
    /// a joint witness's total ([`Tightness::joint`]), any run's total
    /// ([`Tightness::totals`]), or the exact most of a cost over every
    /// feasible input ([`Tightness::exact`]).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Ceiling {
        Within(u64),
        Measured,
        Joint,
        Total,
        Exact,
    }

    impl fmt::Display for Ceiling {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Ceiling::Within(allowed) => write!(f, "within-{allowed}"),
                Ceiling::Measured => f.write_str("measured"),
                Ceiling::Joint => f.write_str("joint"),
                Ceiling::Total => f.write_str("total"),
                Ceiling::Exact => f.write_str("exact"),
            }
        }
    }

    impl Ceiling {
        /// The ceiling [`fmt::Display`] wrote as `text`.
        fn parse(text: &str) -> Option<Self> {
            match text {
                "measured" => Some(Ceiling::Measured),
                "joint" => Some(Ceiling::Joint),
                "total" => Some(Ceiling::Total),
                "exact" => Some(Ceiling::Exact),
                _ => text
                    .strip_prefix("within-")
                    .and_then(|allowed| allowed.parse().ok())
                    .map(Ceiling::Within),
            }
        }
    }

    /// One recorded ratio, exactly: a bound, what its witness used, and the
    /// ceiling it is held to.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Ratio {
        outcome: Outcome,
        bound: u64,
        used: u64,
        ceiling: Ceiling,
    }

    impl fmt::Display for Ratio {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}/{} ({})", self.bound, self.used, self.ceiling)
        }
    }

    /// The one run of `runs` named `name`: a witness is named, never counted
    /// from the end of its suite, so adding or reordering runs cannot move
    /// a derivation onto another input.
    pub(crate) fn named<'r, T>(runs: &'r [Run<T>], name: &str) -> &'r Run<T> {
        let mut found = runs.iter().filter(|run| run.name == name);
        match (found.next(), found.next()) {
            (Some(run), None) => run,
            (None, _) => panic!(
                "no run is named {name:?}; the runs are {:#?}",
                runs.iter().map(|run| run.name.as_str()).collect::<Vec<_>>()
            ),
            (Some(_), Some(_)) => panic!("more than one run is named {name:?}"),
        }
    }

    /// The tightness evidence of one suite: each witnessed place's term, and
    /// each charged total ([`Places::bound`]), against what its witness
    /// measured, in every dimension the bound charges under its own
    /// composition (work and requests summed, the peak the most held at
    /// once, retained what publication holds). Each ratio is recorded
    /// exactly, the bound and what its witness used as integers with the
    /// ceiling it is held to, in `tests/data/tightness/<suite>.txt`, or
    /// `<suite>.num-bigint.txt` where bignums are encoded ([`VARIANT`]), and held
    /// by a ratchet: any change of a recorded ratio fails, as does a recorded
    /// ratio no longer measured or a measured one not recorded; setting
    /// `DCBOR_RECORD_FACTORS` records the current ratios, so every change to
    /// a bound or its witness is recorded deliberately, with its reason. A
    /// ratio is measured, not chosen; a [`Factor::Within`] ceiling is a
    /// separate target, checked without rounding.
    pub(crate) struct Tightness {
        suite: &'static str,
        ratios: Vec<(String, Ratio)>,
        texts: Vec<String>,
        /// Each dimension some jointly checked total charges, by its index
        /// in [`EVERY`].
        charged: [bool; 5],
        /// Each dimension some joint witness measured.
        covered: [bool; 5],
    }

    impl Tightness {
        pub(crate) fn new(suite: &'static str) -> Self {
            Self {
                suite,
                ratios: Vec::new(),
                texts: Vec::new(),
                charged: [false; 5],
                covered: [false; 5],
            }
        }

        /// `bound` against `used`, as `what`, in `dimensions`: each the
        /// bound charges is a recorded ratio, beyond a [`Ceiling::Within`]
        /// a failure, and charged where its witness never uses it a failure;
        /// a [`Ceiling::Total`] is any run's, not a witness's, so its unused
        /// charge is recorded as it is.
        fn measure(
            &mut self,
            what: &str,
            outcome: Outcome,
            bound: ResourceBound,
            used: ResourceBound,
            ceiling: Ceiling,
            dimensions: &[Dimension],
        ) {
            outcome.admissible(what);
            for &dimension in dimensions {
                let (bound, used) = (dimension.of(bound), dimension.of(used));
                let dimension = format!("{dimension:?}").to_lowercase();
                if bound == 0 {
                    continue;
                }
                if used == 0 && ceiling != Ceiling::Total {
                    self.texts.push(format!(
                        "{what} {dimension}: charges {bound} its witness never uses"
                    ));
                    continue;
                }
                // Widened, so the product of any two `u64`s is exact.
                if let Ceiling::Within(allowed) = ceiling
                    && u128::from(bound) > u128::from(allowed) * u128::from(used)
                {
                    self.texts.push(format!(
                        "{what} {dimension} {bound} exceeds {allowed}x the {used} measured"
                    ));
                }
                self.ratios.push((
                    format!("{what} {dimension}"),
                    Ratio {
                        outcome,
                        bound,
                        used,
                        ceiling,
                    },
                ));
            }
        }

        /// Every witnessed place's term on its witness, within its
        /// [`Factor::Within`] ceiling. A place whose term is a nested
        /// operation's bound is that operation's suite's to measure; its
        /// witness must still charge it. The factors are each suite's own,
        /// one per place by an exhaustive match, so an overstated term fails
        /// as an understated one fails [`check`].
        pub(crate) fn places<T: Places>(
            &mut self,
            runs: &[Run<T>],
            witnesses: &[(usize, T::Place)],
            factor: impl Fn(T::Place) -> Factor,
        ) -> &mut Self {
            for &(index, place) in witnesses {
                let run = &runs[index];
                run.outcome.admissible(&run.name);
                let measured = run.policy.ledger().measured(place);
                match factor(place) {
                    Factor::Within(allowed) => self.measure(
                        &format!("{}: {place:?}", run.name),
                        run.outcome,
                        run.terms.term(place),
                        measured,
                        Ceiling::Within(allowed),
                        EVERY,
                    ),
                    Factor::Measured => self.measure(
                        &format!("{}: {place:?}", run.name),
                        run.outcome,
                        run.terms.term(place),
                        measured,
                        Ceiling::Measured,
                        EVERY,
                    ),
                    Factor::Nested(suite) => {
                        if measured == ResourceBound::default() {
                            self.texts.push(format!(
                                "{}: {place:?}, which {suite} measures, is not charged by its \
                                 witness",
                                run.name
                            ));
                        }
                    }
                }
            }
            self
        }

        /// The total a caller is charged, in `dimensions`, on the run of
        /// `runs` named `name` ([`named`]), which drives them, every place's
        /// measured jointly by the whole run. Work and storage are driven by
        /// different inputs, each dimension composing under its own rule: a
        /// suite has a witness for each. `derivation` states what the run's
        /// input maximizes under the counts its places share, so the
        /// recorded ratio measures the derivation, not the fixture.
        pub(crate) fn joint<T: Places>(
            &mut self,
            runs: &[Run<T>],
            name: &str,
            dimensions: &[Dimension],
            derivation: &str,
        ) -> &mut Self {
            let bound = named(runs, name)
                .terms
                .bound::<()>()
                .expect("the bound fits in u64");
            self.joint_bound(runs, name, "total", bound, dimensions, derivation)
        }

        /// [`Self::joint`] against `bound`, recorded as `what`: the bound a
        /// caller composes from the public bounds of the operations the run
        /// chains, where its places are several operations' summed. The run
        /// must be within `bound` in every dimension, as within its own
        /// terms' total.
        pub(crate) fn joint_bound<T>(
            &mut self,
            runs: &[Run<T>],
            name: &str,
            what: &str,
            bound: ResourceBound,
            dimensions: &[Dimension],
            derivation: &str,
        ) -> &mut Self {
            let run = named(runs, name);
            assert!(
                !derivation.is_empty(),
                "{}: a joint witness states why",
                run.name
            );
            assert!(
                !dimensions.is_empty(),
                "{}: a joint witness drives a dimension",
                run.name
            );
            let measured = run.policy.ledger().total();
            if !bound.covers(
                measured.work(),
                measured.allocated,
                measured.peak,
                measured.retained,
            ) {
                self.texts.push(format!(
                    "{}: measured {measured:?} beyond its {what} {bound:?}",
                    run.name
                ));
            }
            for (index, &dimension) in EVERY.iter().enumerate() {
                self.charged[index] |= dimension.of(bound) != 0;
                self.covered[index] |= dimensions.contains(&dimension);
            }
            self.measure(
                &format!("{}: {what}", run.name),
                run.outcome,
                bound,
                measured,
                Ceiling::Joint,
                dimensions,
            );
            self
        }

        /// `bound` against `attained`, the exact most its cost expression
        /// charges over every feasible input of the size `what` names, in
        /// `dimensions`, each a recorded ratio: how far a bound over shapes
        /// not yet seen lies above the costliest input there is. The bound
        /// must reach the attained most in every dimension.
        pub(crate) fn exact(
            &mut self,
            what: &str,
            bound: ResourceBound,
            attained: ResourceBound,
            dimensions: &[Dimension],
        ) -> &mut Self {
            if !bound.covers(
                attained.work(),
                attained.allocated,
                attained.peak,
                attained.retained,
            ) {
                self.texts
                    .push(format!("{what}: attained {attained:?} beyond {bound:?}"));
            }
            self.measure(
                what,
                Outcome::Exact,
                bound,
                attained,
                Ceiling::Exact,
                dimensions,
            );
            self
        }

        /// Every run's total ([`Places::bound`]) against what the run used,
        /// in `dimensions`, each a recorded ratio the ratchet holds: no
        /// run's bound moves, either way, on any engine path the suite
        /// drives, without being recorded. Unlike [`Self::joint`], a run
        /// here need not maximize anything.
        pub(crate) fn totals<T: Places>(
            &mut self,
            runs: &[Run<T>],
            dimensions: &[Dimension],
        ) -> &mut Self {
            for run in runs {
                let bound = run.terms.bound::<()>().expect("the bound fits in u64");
                let measured = run.policy.ledger().total();
                self.measure(
                    &format!("{}: run", run.name),
                    run.outcome,
                    bound,
                    measured,
                    Ceiling::Total,
                    dimensions,
                );
            }
            self
        }

        /// Every failure so far, a dimension a jointly checked total charges
        /// that no joint witness drives among them, then the ratchet against
        /// the suite's record.
        pub(crate) fn finish(&mut self) {
            for (case, ratio) in &self.ratios {
                ratio.outcome.admissible(case);
            }
            for (index, dimension) in EVERY.iter().enumerate() {
                if self.charged[index] && !self.covered[index] {
                    self.texts.push(format!(
                        "{}: the total charges {dimension:?}, driven by no joint witness",
                        self.suite
                    ));
                }
            }
            let mut measured = self.ratios.clone();
            measured.sort_by(|left, right| left.0.cmp(&right.0));
            for pair in measured.windows(2) {
                if pair[0].0 == pair[1].0 {
                    self.texts
                        .push(format!("{}: measured twice in one suite", pair[0].0));
                }
            }
            assert!(self.texts.is_empty(), "{:#?}", self.texts);
            let directory = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/tightness");
            let recording = std::env::var_os(RECORD_FACTORS).is_some();
            ratchet(
                &format!("{directory}/{}{VARIANT}.txt", self.suite),
                &measured,
                recording.then(|| {
                    configuration().unwrap_or_else(|| {
                        panic!(
                            "recording requires {CONFIGURATION}, which the flake's shells export"
                        )
                    })
                }),
            );
        }
    }

    /// The record at `path` against the `measured` ratios, sorted by key:
    /// rewritten whole under `recording`'s configuration when it is given,
    /// otherwise compared, any change, unrecorded or no longer measured ratio
    /// failing with the configurations the record and the run were taken
    /// under. A record names its configuration on its first line.
    fn ratchet(path: &str, measured: &[(String, Ratio)], recording: Option<String>) {
        for (case, ratio) in measured {
            ratio.outcome.admissible(case);
        }
        if let Some(configuration) = recording {
            if let Some(directory) = std::path::Path::new(path).parent() {
                std::fs::create_dir_all(directory).expect("the record directory is writable");
            }
            let mut data = format!("{CONFIGURATION_LINE}{configuration}\n");
            for (key, ratio) in measured {
                data.push_str(&format!(
                    "{}\t{}\t{}\t{}\t{key}\n",
                    ratio.bound,
                    ratio.used,
                    ratio.ceiling,
                    ratio.outcome.name()
                ));
            }
            publish(path, &data);
            return;
        }
        let data = std::fs::read_to_string(path)
            .unwrap_or_else(|error| panic!("{path}: {error}; record it with {RECORD_FACTORS}=1"));
        let mut lines = data.lines();
        let recorded_under = lines
            .next()
            .and_then(|line| line.strip_prefix(CONFIGURATION_LINE))
            .unwrap_or_else(|| {
                panic!(
                    "{path}:1: not the configuration it was recorded under; record it with \
                     {RECORD_FACTORS}=1"
                )
            })
            .to_string();
        let running_under = configuration().unwrap_or_else(|| "an unnamed configuration".into());
        let mut recorded = std::collections::BTreeMap::new();
        for (number, line) in lines.enumerate() {
            let at = || format!("{path}:{}", number + 2);
            let mut fields = line.splitn(5, '\t');
            let (Some(bound), Some(used), Some(ceiling), Some(outcome), Some(key)) = (
                fields.next(),
                fields.next(),
                fields.next(),
                fields.next(),
                fields.next(),
            ) else {
                panic!(
                    "{}: not a bound, a use, a ceiling, an outcome and a key",
                    at()
                );
            };
            let ratio = Ratio {
                outcome: Outcome::parse(outcome)
                    .unwrap_or_else(|| panic!("{}: {key}: unknown outcome {outcome:?}", at())),
                bound: bound
                    .parse()
                    .unwrap_or_else(|error| panic!("{}: bound: {error}", at())),
                used: used
                    .parse()
                    .unwrap_or_else(|error| panic!("{}: use: {error}", at())),
                ceiling: Ceiling::parse(ceiling)
                    .unwrap_or_else(|| panic!("{}: no ceiling {ceiling:?}", at())),
            };
            ratio.outcome.admissible(key);
            assert!(
                recorded.insert(key.to_string(), ratio).is_none(),
                "{}: {key} recorded twice",
                at()
            );
        }
        let mut texts = Vec::new();
        for (key, ratio) in measured {
            match recorded.remove(key) {
                None => texts.push(format!(
                    "{key}: {ratio}, not recorded; record it with {RECORD_FACTORS}=1"
                )),
                Some(record) if record != *ratio => texts.push(format!(
                    "{key}: changed from {record} to {ratio}; record it with \
                     {RECORD_FACTORS}=1 and state why; outcome {} -> {}",
                    record.outcome.name(),
                    ratio.outcome.name()
                )),
                Some(_) => {}
            }
        }
        texts.extend(
            recorded
                .into_keys()
                .map(|key| format!("{key}: recorded in {path} but no longer measured")),
        );
        assert!(
            texts.is_empty(),
            "{path}, recorded under {recorded_under}, running under {running_under}: {texts:#?}"
        );
    }

    /// The ratchet records the configuration on its record's first line and
    /// publishes the record whole, leaving no temporary file; then refuses a
    /// planted change of a recorded ratio, a planted unrecorded ratio and a
    /// recorded ratio no longer measured, each named, and a record without its
    /// configuration line; and passes the measured ratios unchanged.
    #[test]
    fn the_ratchet_records_its_configuration_and_refuses_planted_changes() {
        let directory =
            std::env::temp_dir().join(format!("dcbor-tightness-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("a temporary directory");
        let path = directory.join("planted.txt");
        let path = path.to_str().expect("a UTF-8 temporary path");
        let ratio = |bound, used| Ratio {
            outcome: Outcome::Published,
            bound,
            used,
            ceiling: Ceiling::Measured,
        };
        let measured = vec![
            ("a values".to_string(), ratio(4, 2)),
            ("b bytes".to_string(), ratio(9, 9)),
        ];
        std::fs::write(path, "previous").expect("the previous record");
        ratchet(path, &measured, Some("toolchain=t std=s".into()));
        assert_eq!(
            std::fs::read_to_string(path).expect("the record"),
            format!(
                "{CONFIGURATION_LINE}toolchain=t std=s\n4\t2\tmeasured\tpublished\ta values\n9\t9\tmeasured\tpublished\tb bytes\n"
            )
        );
        assert_eq!(
            std::fs::read_dir(&directory).unwrap().count(),
            1,
            "temporary evidence was not removed"
        );
        ratchet(path, &measured, None);
        let refused = |planted: Vec<(String, Ratio)>| {
            let path = path.to_string();
            std::panic::catch_unwind(move || ratchet(&path, &planted, None))
                .expect_err("a planted change passed the ratchet")
                .downcast::<String>()
                .map(|text| *text)
                .unwrap_or_default()
        };
        let changed = refused(vec![
            ("a values".to_string(), ratio(5, 2)),
            ("b bytes".to_string(), ratio(9, 9)),
        ]);
        assert!(
            changed.contains("a values: changed from 4/2 (measured) to 5/2 (measured)")
                && changed.contains("recorded under toolchain=t std=s"),
            "{changed}"
        );
        let unrecorded = refused(vec![
            ("a values".to_string(), ratio(4, 2)),
            ("b bytes".to_string(), ratio(9, 9)),
            ("c peak".to_string(), ratio(1, 1)),
        ]);
        assert!(
            unrecorded.contains("c peak: 1/1 (measured), not recorded"),
            "{unrecorded}"
        );
        let dropped = refused(vec![("a values".to_string(), ratio(4, 2))]);
        assert!(dropped.contains("b bytes: recorded in"), "{dropped}");
        std::fs::write(path, "4\t2\tmeasured\ta values\n").expect("a record without its line");
        let unnamed = refused(measured);
        assert!(
            unnamed.contains("not the configuration it was recorded under"),
            "{unnamed}"
        );
        std::fs::remove_dir_all(&directory).expect("the temporary directory removed");
    }

    #[test]
    fn tightness_and_ratchet_refuse_planted_defects_before_publication() {
        let case = "planted preparation defect";
        let defect = Ratio {
            outcome: Outcome::Defect,
            bound: 1,
            used: 1,
            ceiling: Ceiling::Measured,
        };
        let message = |payload: Box<dyn core::any::Any + Send>| {
            *payload
                .downcast::<String>()
                .expect("a named defect diagnostic")
        };
        let failed = std::panic::catch_unwind(|| {
            let mut recorder = Tightness::new("planted-defect");
            recorder.ratios.push((case.into(), defect));
            recorder.finish();
        })
        .expect_err("Tightness accepted a defect");
        assert!(message(failed).contains(case));

        let path = std::env::temp_dir().join(format!("dcbor-defect-{}.txt", std::process::id()));
        std::fs::write(&path, "previous evidence").unwrap();
        for recording in [None, Some("planted configuration".into())] {
            let failed = std::panic::catch_unwind(|| {
                ratchet(path.to_str().unwrap(), &[(case.into(), defect)], recording);
            })
            .expect_err("ratchet accepted a defect");
            assert!(message(failed).contains(case));
            assert_eq!(std::fs::read_to_string(&path).unwrap(), "previous evidence");
        }
        std::fs::remove_file(path).unwrap();
    }

    /// `bound` never decreases in any dimension as its size grows over
    /// `sizes`, in increasing order: a caller admitting at a declared
    /// maximum is charged at least what any shorter input needs.
    pub(crate) fn monotone(
        name: &str,
        sizes: impl IntoIterator<Item = u64>,
        bound: impl Fn(u64) -> ResourceBound,
    ) {
        let mut previous: Option<(u64, ResourceBound)> = None;
        let mut texts = Vec::new();
        for size in sizes {
            let current = bound(size);
            if let Some((at, before)) = previous {
                for &dimension in EVERY {
                    let (before, now) = (dimension.of(before), dimension.of(current));
                    if now < before {
                        texts.push(format!(
                            "{name}: {dimension:?} falls from {before} at {at} to {now} at {size}"
                        ));
                    }
                }
            }
            previous = Some((size, current));
        }
        assert!(texts.is_empty(), "{texts:#?}");
    }

    /// Every public bound indexed by a size is monotone in it, and every
    /// one indexed by a shape in each of the shape's counts, the others held.
    #[test]
    fn every_public_bound_is_monotone_in_its_size() {
        use crate::ByteString;
        use decode::Options;
        use decode::construction::{
            construction_bound, copy_bound, parse_bound, typed_decode_bound,
        };
        use text_cursor::{TextShape, encode_bound, pipeline};
        let sizes = || 0..=4096u64;
        let strict = Options::normalizing(8);
        let quick = Options::quick_only(8);
        monotone("decode_bound", sizes(), |n| {
            decode::decode_bound::<()>(n, 8).unwrap()
        });
        monotone("decode_bound_with quick", sizes(), |n| {
            decode::decode_bound_with::<()>(n, quick).unwrap()
        });
        for options in [strict, quick] {
            monotone("retained_decode_bound", sizes(), |n| {
                decode::cursor::retained_decode_bound::<Reservation, ()>(n, options).unwrap()
            });
            monotone("string_bound", sizes(), |n| {
                decode::string_cursor::string_bound::<Reservation, ()>(n, options).unwrap()
            });
            monotone("parse_bound", sizes(), |n| {
                parse_bound::<ByteString, Limits, ()>(n, options).unwrap()
            });
            monotone("typed_decode_bound", sizes(), |n| {
                typed_decode_bound::<ByteString, Vec<String>, Limits, ()>(n, options).unwrap()
            });
        }
        monotone("construction_bound", sizes(), |n| {
            construction_bound::<ByteString, Vec<String>, Limits, ()>(n).unwrap()
        });
        monotone("copy_bound", sizes(), |n| {
            copy_bound::<Limits, ()>(n).unwrap()
        });
        monotone("validation_bound", sizes(), |n| {
            text::validation_bound::<()>(n).unwrap()
        });
        monotone("header_bound", sizes(), decode::header::header_bound);
        monotone("emit_bound", sizes(), |n| {
            encoding::emit_bound::<()>(n).unwrap()
        });
        monotone("writer_bound", sizes(), |n| {
            pipeline::writer_bound::<()>(n).unwrap()
        });
        monotone("encode_bound of the worst text", sizes(), |n| {
            TextShape::worst_bound(n, encode_bound::<Reservation, ()>).unwrap()
        });
        monotone("preparation_bound of the worst text", sizes(), |n| {
            TextShape::worst_bound(n, pipeline::preparation_bound::<Reservation, ()>).unwrap()
        });
        /// One count of a shape, by name, and how to set it.
        type Count<S> = (&'static str, fn(&mut S, u64));
        let base = TextShape::worst::<()>(64).unwrap();
        let counts: [Count<TextShape>; 8] = [
            ("bytes", |shape, value| shape.bytes = value),
            ("scalars", |shape, value| shape.scalars = value),
            ("parts", |shape, value| shape.parts = value),
            ("part_bytes", |shape, value| shape.part_bytes = value),
            ("combining", |shape, value| shape.combining = value),
            ("runs", |shape, value| shape.runs = value),
            ("sorted_parts", |shape, value| shape.sorted_parts = value),
            ("sorted_runs", |shape, value| shape.sorted_runs = value),
        ];
        for (count, set) in counts {
            monotone(&format!("encode_bound in {count}"), 0..=256, |value| {
                let mut shape = base;
                set(&mut shape, value);
                encode_bound::<Reservation, ()>(shape).unwrap()
            });
            monotone(&format!("preparation_bound in {count}"), 0..=256, |value| {
                let mut shape = base;
                set(&mut shape, value);
                pipeline::preparation_bound::<Reservation, ()>(shape).unwrap()
            });
        }
        let base = encoding::Shape {
            instructions: 64,
            dynamic: 16,
            depth: 4,
            maps: 4,
            unordered: 2,
            entries: 8,
            widest: 4,
            merge_levels: 6,
            merges: 24,
            extent: 64,
            key_merges: 48,
            payloads: 64,
            payload_probes: 192,
            largest_payload: 32,
            unordered_depth: 2,
            texts: 2,
            text_bytes: 32,
            longest_text: TextShape::worst::<()>(16).unwrap(),
            normalization: ResourceBound::default(),
            inspected: 4,
            moves: 12,
            bignums: 1,
            digits: 4,
        };
        let counts: [Count<encoding::Shape>; 21] = [
            ("instructions", |shape, value| shape.instructions = value),
            ("dynamic", |shape, value| shape.dynamic = value),
            ("depth", |shape, value| shape.depth = value),
            ("maps", |shape, value| shape.maps = value),
            ("unordered", |shape, value| shape.unordered = value),
            ("entries", |shape, value| shape.entries = value),
            ("widest", |shape, value| shape.widest = value),
            ("merge_levels", |shape, value| shape.merge_levels = value),
            ("merges", |shape, value| shape.merges = value),
            ("extent", |shape, value| shape.extent = value),
            ("key_merges", |shape, value| shape.key_merges = value),
            ("payloads", |shape, value| shape.payloads = value),
            ("payload_probes", |shape, value| {
                shape.payload_probes = value
            }),
            ("largest_payload", |shape, value| {
                shape.largest_payload = value
            }),
            ("unordered_depth", |shape, value| {
                shape.unordered_depth = value
            }),
            ("texts", |shape, value| shape.texts = value),
            ("text_bytes", |shape, value| shape.text_bytes = value),
            ("longest_text bytes", |shape, value| {
                shape.longest_text.bytes = value
            }),
            ("inspected", |shape, value| shape.inspected = value),
            ("moves", |shape, value| shape.moves = value),
            ("bignums and digits", |shape, value| {
                shape.bignums = value;
                shape.digits = value;
            }),
        ];
        for (count, set) in counts {
            // A shape's instructions include its dynamic ones: they are held
            // at least the dynamic count while either varies.
            monotone(&format!("prepare_bound in {count}"), 0..=256, |value| {
                let mut shape = base;
                set(&mut shape, value);
                shape.instructions = shape.instructions.max(shape.dynamic);
                encoding::prepare_bound::<Reservation, ()>(shape).unwrap()
            });
            monotone(&format!("encode_bound in {count}"), 0..=256, |value| {
                let mut shape = base;
                set(&mut shape, value);
                shape.instructions = shape.instructions.max(shape.dynamic);
                super::encode_bound::<Reservation, ()>(shape).unwrap()
            });
        }
        #[cfg(feature = "hashbrown")]
        for batched in [false, true] {
            monotone("bucket_bound in buckets", sizes(), |buckets| {
                encoding::buckets::bucket_bound::<()>(buckets, 8, batched).unwrap()
            });
            monotone("bucket_bound in entries", sizes(), |entries| {
                encoding::buckets::bucket_bound::<()>(4096, entries, batched).unwrap()
            });
        }
    }

    /// `terms` with one place's term removed: the bound a term's necessity
    /// is checked against.
    struct Without<'t, T: Places> {
        terms: &'t T,
        place: T::Place,
    }

    impl<T: Places> Places for Without<'_, T> {
        type Place = T::Place;

        fn term(&self, place: T::Place) -> ResourceBound {
            if place == self.place {
                ResourceBound::default()
            } else {
                self.terms.term(place)
            }
        }
    }

    /// The route's pass scenario: an admission through a charge rule is
    /// recorded at its place.
    #[test]
    fn an_admission_through_the_route_is_recorded_at_its_place() {
        places! {
            enum Probe { Only }
        }
        let mut policy = Ledgered::new();
        Unit::new(Probe::Only, 2, 3)
            .admit(&mut policy)
            .expect("an unlimited policy admits");
        assert_eq!(
            policy.ledger().measured(Probe::Only),
            ResourceBound::of_work(WriteWork::new(2, 3))
        );
    }

    /// The route's fail scenario: an admission made straight to the policy,
    /// at a place, is refused, naming the place and the route to take.
    #[test]
    #[should_panic(
        expected = "an admission of 1 values and 0 bytes bypassed the attributed route at \
                    places [\"dcbor::bounded::Caller::Caller\"]: admit through a charge rule's"
    )]
    #[expect(
        clippy::disallowed_methods,
        reason = "the bypass whose detection this test shows"
    )]
    fn an_admission_outside_the_route_is_refused() {
        let mut policy = Ledgered::new();
        let Ok(()) = at(Caller, || policy.traverse(1, 0));
    }

    /// The route's scope limit, pinned: allocations are not routed, so the
    /// coverage rule [`check`] applies covers them, and an allocation made at
    /// no place fails it as unattributed.
    #[test]
    fn an_allocation_at_no_place_is_unattributed() {
        places! {
            enum Probe { Only }
        }
        struct Holds;
        impl Places for Holds {
            type Place = Probe;

            fn term(&self, _: Probe) -> ResourceBound {
                ResourceBound {
                    allocated: 8,
                    peak: 8,
                    ..ResourceBound::default()
                }
            }
        }
        let mut policy = Ledgered::new();
        let Ok(permit) = policy.allocate(8);
        drop(permit);
        let run = Run {
            name: "unplaced".to_string(),
            outcome: Outcome::Published,
            policy,
            terms: Holds,
        };
        let (mut exercised, mut charged) = (vec![false], vec![false]);
        let found = failures(
            &run,
            &run.terms,
            Coverage::Whole,
            &mut exercised,
            &mut charged,
        );
        assert!(
            found.iter().any(|failure| failure.place.is_none()
                && failure.text.contains("8 bytes requested at no place")),
            "an unplaced allocation passed coverage"
        );
    }

    /// The route's mark ends with its admission, a panicking one included,
    /// so it cannot excuse a later admission on the same thread.
    #[test]
    fn a_panic_inside_the_route_leaves_no_mark() {
        let unwound = std::panic::catch_unwind(|| {
            let _routed = route();
            panic!("inside the route");
        });
        assert!(unwound.is_err(), "the closure panics");
        assert_eq!(ROUTED.with(Cell::get), 0, "the mark ended with the unwind");
    }

    /// Several operations of one kind in one run, such as a parse and the
    /// input whose record its cleanup releases: each place's terms summed in
    /// every quantity.
    impl<T: Places> Places for Vec<T> {
        type Place = T::Place;

        fn term(&self, place: T::Place) -> ResourceBound {
            let sum = |left: u64, right: u64| add::<()>(left, right).expect("terms fit in u64");
            self.iter().map(|terms| terms.term(place)).fold(
                ResourceBound::default(),
                |total, term| ResourceBound {
                    values: sum(total.values, term.values),
                    bytes: sum(total.bytes, term.bytes),
                    allocated: sum(total.allocated, term.allocated),
                    peak: sum(total.peak, term.peak),
                    retained: sum(total.retained, term.retained),
                },
            )
        }
    }

    /// Every place some run's terms charge has a witness, and each term is
    /// necessary: run `index` of `runs`, the witness of the place paired with
    /// it, checked by the same rule as [`check`] against its terms with that
    /// place's term removed, fails at that place. The passing check and this
    /// failing one are the one rule over the same runs.
    pub(crate) fn witnessed<T: Places>(runs: &[Run<T>], witnesses: &[(usize, T::Place)]) {
        let mut texts = Vec::new();
        for &place in T::Place::ALL {
            let charged = runs
                .iter()
                .any(|run| run.terms.term(place) != ResourceBound::default());
            if charged && !witnesses.iter().any(|(_, witnessed)| *witnessed == place) {
                texts.push(format!("{place:?} has no witness"));
            }
        }
        // Exercise is the passing check's concern; these marks are unread.
        let mut exercised = vec![false; T::Place::ALL.len()];
        let mut charged = vec![false; T::Place::ALL.len()];
        for &(index, place) in witnesses {
            let run = &runs[index];
            let without = Without {
                terms: &run.terms,
                place,
            };
            let found = failures(run, &without, Coverage::Terms, &mut exercised, &mut charged);
            if !found.iter().any(|failure| failure.place == Some(place)) {
                texts.push(format!(
                    "{}: passes without the term of {place:?}, which it witnesses",
                    run.name
                ));
            }
        }
        assert!(texts.is_empty(), "{texts:#?}");
    }
}
