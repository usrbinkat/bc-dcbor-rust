//! Bounded canonical encoding: a value's dCBOR encoding prepared without
//! building a [`CBOR`](crate::CBOR) tree, then written directly into a
//! buffer of exactly its length.
//!
//! The symbolic path (`From<T> for CBOR`, then
//! [`CBOR::to_cbor_data`](crate::CBOR::to_cbor_data)) allocates a
//! reference-counted node per value, an encoded key per map entry, an NFC
//! copy per text string and a buffer per nested item. This path has two
//! passes over the value:
//!
//! 1. [`prepare`] measures it: its exact encoded length, the work writing it
//!    will report ([`WriteWork`]), and a [`Plan`] holding what writing needs
//!    and cannot rediscover cheaply: NFC text and sorted dynamic-map encodings.
//!    Every allocation it makes, the plan's and
//!    normalization scratch alike, is requested from the caller's
//!    [`Allocator`] first and released when it is freed ([`Owned`]).
//! 2. [`Prepared::encode_into`] writes it into an output of exactly the
//!    measured length through an [`Output`] that refuses any write past it,
//!    reporting its work to a [`Budget`]; it allocates nothing.
//!
//! A caller admits the predicted write work and the output between the
//! passes. A budget's refusal is returned as its own type
//! ([`BoundedError::Refused`]), never as text. A failed write may leave a
//! partial encoding in the output, which must not be used.
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
//! `HashMap`, [`crate::Map`], [`CBOR`](crate::CBOR), [`crate::Date`], explicit
//! [`Tagged`] wrappers, and feature-gated `BigInt`/`BigUint`.
//! Sets and deques do not implement this interface. A tagged derived type's
//! untagged representation can be wrapped in [`Tagged`] explicitly.
//!
//! Dynamic Rust maps retain sorted bytes during preparation, reject keys whose
//! canonical encodings collide, and use O(n log n) key comparisons. Comparison
//! bytes, swaps, and hash-table capacity scans are admitted. Symbolic maps
//! already have canonical key order. Symbolic traversal admits at most 128
//! nested CBOR nodes on a path and rejects out-of-profile negative integers.
//! Constructing an input value is outside the encoding operation's budget.
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
//! // After: preparation, output storage, initialization and writing share limits.
//! let mut limits = Limits::new(10_000, 100_000, 64_000);
//! let after = encode(&fields, &mut limits).unwrap();
//! assert_eq!(after.as_ref(), before);
//! assert_eq!(limits.live_bytes(), after.as_ref().len() as u64);
//! // Keep `after` alive until the transport/storage operation consumes its bytes.
//! drop(after);
//! assert_eq!(limits.live_bytes(), 0);
//! ```
//!
//! # Caller-owned output
//!
//! Output admission is separate from scratch admission. The owner below keeps
//! the output permit until its vector is freed and publishes bytes only after
//! a successful write. Initialization is admitted before touching the buffer.
//! Policy refusal, arithmetic overflow, heap failure and encoding invariant
//! failure retain distinct [`BoundedError`] variants.
//!
//! ```
//! use dcbor::bounded::*;
//! struct Encoded<P> { bytes: Vec<u8>, _permit: P }
//! fn encode<T: BoundedEncodable + ?Sized, A: Allocator>(
//!     value: &T, allocator: &mut A,
//! ) -> BoundedResult<Encoded<A::Permit>, A> {
//!     let prepared = prepare(value, allocator)?;
//!     let len = prepared.len();
//!     let size = usize::try_from(len).map_err(|_| BoundedError::Overflow)?;
//!     let permit = allocator.allocate(len).map_err(BoundedError::Refused)?;
//!     let mut bytes = Vec::new();
//!     bytes.try_reserve_exact(size).map_err(|_| BoundedError::Allocation { bytes: len })?;
//!     allocator.traverse(0, len).map_err(BoundedError::Refused)?;
//!     bytes.resize(size, 0);
//!     prepared.encode_into(&mut bytes, allocator)?;
//!     Ok(Encoded { bytes, _permit: permit })
//! }
//! use std::{cell::Cell, rc::Rc};
//! struct Permit(Rc<Cell<u64>>, u64);
//! impl Drop for Permit {
//!     fn drop(&mut self) { self.0.set(self.0.get() - self.1); }
//! }
//! struct Limits { live: Rc<Cell<u64>>, values: u64, bytes: u64 }
//! impl Budget for Limits {
//!     type Refusal = &'static str;
//!     fn traverse(&mut self, values: u64, bytes: u64) -> Result<(), Self::Refusal> {
//!         let v = self.values.checked_sub(values).ok_or("work")?;
//!         let b = self.bytes.checked_sub(bytes).ok_or("work")?;
//!         self.values = v;
//!         self.bytes = b;
//!         Ok(())
//!     }
//! }
//! impl Allocator for Limits {
//!     type Permit = Permit;
//!     fn allocate(&mut self, bytes: u64) -> Result<Permit, Self::Refusal> {
//!         let next = self.live.get().checked_add(bytes).ok_or("storage")?;
//!         if next > 1024 { return Err("storage"); }
//!         self.live.set(next);
//!         Ok(Permit(self.live.clone(), bytes))
//!     }
//! }
//! let live = Rc::new(Cell::new(0));
//! let mut policy = Limits { live: live.clone(), values: 100, bytes: 1024 };
//! let encoded = encode(&24u64, &mut policy).unwrap();
//! assert_eq!(encoded.bytes, [0x18, 0x18]);
//! assert_eq!(live.get(), 2);
//! drop(encoded);
//! assert_eq!(live.get(), 0);
//! policy.values = 1; // Preparation succeeds; writing refuses.
//! assert!(matches!(encode(&24u64, &mut policy), Err(BoundedError::Refused("work"))));
//! assert_eq!(live.get(), 0); // Failed output is discarded with its permit.
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

#[cfg(feature = "num-bigint")]
mod bigint;
pub mod decode;
mod policy;
pub mod text;
mod value;
pub use policy::{LimitRefusal, Limits, Reservation};
pub use value::Tagged;

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
    /// The output given is not the measured length; nothing was written.
    OutputSize { measured: u64, provided: u64 },
    /// A write needed more of the output than remains: the measure is wrong
    /// for what was written. That write wrote nothing.
    Capacity { needed: u64, remaining: u64 },
    /// The write finished at another length than measured.
    Length { measured: u64, written: u64 },
    /// The write did not consume the plan its preparation made, entry for
    /// entry.
    PlanMismatch,
    /// Reported work would exceed the preparation's prediction.
    WorkExceeded {
        predicted: WriteWork,
        attempted: WriteWork,
    },
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
            Self::Capacity { needed, remaining } => write!(
                f,
                "bounded encoding needed {needed} bytes with {remaining} remaining"
            ),
            Self::Length { measured, written } => write!(
                f,
                "bounded encoding wrote {written} bytes, measured {measured}"
            ),
            Self::PlanMismatch => f.write_str("bounded encoding diverged from its plan"),
            Self::WorkExceeded {
                predicted,
                attempted,
            } => write!(
                f,
                "bounded encoding predicted {predicted:?}, attempted {attempted:?}"
            ),
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
pub trait Allocator: Budget {
    /// Held while the allocation it was given for exists.
    type Permit;

    /// Admit an allocation of `bytes` requested capacity bytes. This excludes
    /// allocator metadata and allocator rounding; it is not an RSS bound.
    fn allocate(&mut self, bytes: u64) -> Result<Self::Permit, Self::Refusal>;
}

impl<B: Budget + ?Sized> Budget for &mut B {
    type Refusal = B::Refusal;

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

/// A vector whose capacity grows only through its [`Allocator`], doubling
/// from four elements, each growth admitted in its whole new size before
/// it is made and its permit held for as long as the allocation; the
/// replaced allocation's permit is released after the new one exists. Its
/// capacity is tracked as requested, not as the allocator rounded it, so
/// two runs over the same input request the same allocations.
pub struct Owned<T, P> {
    items: Vec<T>,
    capacity: usize,
    permit: Option<P>,
}

impl<T, P> Owned<T, P> {
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
            // A moving reallocation can copy every initialized element.
            allocator
                .traverse(
                    0,
                    mul(widen(self.items.len())?, widen(core::mem::size_of::<T>())?)?,
                )
                .map_err(BoundedError::Refused)?;
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
        allocator
            .traverse(0, mul(widen(shifted)?, widen(core::mem::size_of::<T>())?)?)
            .map_err(BoundedError::Refused)?;
        self.reserve(1, allocator)?;
        self.items.insert(at, item);
        Ok(())
    }

    /// Remove every element, keeping the allocation and its permit.
    pub fn drain(&mut self) -> impl Iterator<Item = T> + '_ {
        self.items.drain(..)
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

/// The NFC form of one text not already in NFC, prepared for its write.
struct Normalized<P> {
    /// The length of the text it was prepared from, checked at its write.
    source: usize,
    bytes: Owned<u8, P>,
}

/// What a preparation keeps for its write, in the order the write
/// consumes it: normalized text and sorted dynamic-map encodings. Its
/// allocations are released when it drops.
pub struct Plan<P> {
    texts: Owned<Normalized<P>, P>,
    blobs: Owned<Owned<u8, P>, P>,
    depth: usize,
}

impl<P> Plan<P> {
    pub const fn new() -> Self {
        Self {
            texts: Owned::new(),
            blobs: Owned::new(),
            depth: 0,
        }
    }

    pub(crate) fn push_text<A: Allocator<Permit = P>>(
        &mut self,
        source: usize,
        bytes: Owned<u8, P>,
        allocator: &mut A,
    ) -> BoundedResult<(), A> {
        self.texts.push(Normalized { source, bytes }, allocator)
    }

    fn cursor(&self) -> Cursor<'_, P> {
        Cursor {
            texts: self.texts.as_slice(),
            next: 0,
            blobs: self.blobs.as_slice(),
            next_blob: 0,
        }
    }
}

impl<P> Default for Plan<P> {
    fn default() -> Self {
        Self::new()
    }
}

/// A write's position in its plan.
pub struct Cursor<'p, P> {
    texts: &'p [Normalized<P>],
    next: usize,
    blobs: &'p [Owned<u8, P>],
    next_blob: usize,
}

impl<P> Cursor<'_, P> {
    /// The next prepared text, which must have been prepared from a text of
    /// `source` bytes.
    pub(crate) fn next_text<R>(&mut self, source: usize) -> Result<&[u8], BoundedError<R>> {
        let entry = self
            .texts
            .get(self.next)
            .ok_or(BoundedError::PlanMismatch)?;
        if entry.source != source {
            return Err(BoundedError::PlanMismatch);
        }
        self.next += 1;
        Ok(entry.bytes.as_slice())
    }

    fn finished(&self) -> bool {
        self.next == self.texts.len() && self.next_blob == self.blobs.len()
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

/// What preparing a value found: its exact encoded length and the work its
/// write reports at most.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Measure {
    pub len: u64,
    pub write: WriteWork,
}

impl Measure {
    /// One item of `len` bytes whose write visits one value and examines or
    /// copies `bytes` source bytes.
    pub const fn leaf(len: u64, bytes: u64) -> Self {
        Self {
            len,
            write: WriteWork::new(1, bytes),
        }
    }
}

/// The output of a bounded write: a buffer of exactly the measured length,
/// written front to back. Every write is checked against what remains
/// before anything of it is written; nothing grows the buffer.
pub struct Output<'a> {
    bytes: &'a mut [u8],
    position: usize,
}

impl<'a> Output<'a> {
    /// An output over all of `bytes`.
    pub fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    /// Bytes written so far.
    pub fn written(&self) -> usize {
        self.position
    }

    fn room<R>(&self, needed: usize) -> Result<usize, BoundedError<R>> {
        let remaining = self.bytes.len() - self.position;
        if needed > remaining {
            return Err(BoundedError::Capacity {
                needed: widen(needed)?,
                remaining: widen(remaining)?,
            });
        }
        Ok(self.position + needed)
    }

    /// Write one byte.
    pub fn byte<R>(&mut self, byte: u8) -> Result<(), BoundedError<R>> {
        let end = self.room(1)?;
        self.bytes[self.position] = byte;
        self.position = end;
        Ok(())
    }

    /// Write `bytes`.
    pub fn slice<R>(&mut self, bytes: &[u8]) -> Result<(), BoundedError<R>> {
        let end = self.room(bytes.len())?;
        self.bytes[self.position..end].copy_from_slice(bytes);
        self.position = end;
        Ok(())
    }

    /// Write the head of `major_type` carrying `argument`, at the width its
    /// variant fixes.
    pub fn argument<R>(
        &mut self,
        major_type: MajorType,
        argument: Argument,
    ) -> Result<(), BoundedError<R>> {
        let mut head = [0u8; MAX_HEAD_LEN];
        let length = write_argument(major_type, argument, &mut head);
        self.slice(&head[..length])
    }

    /// Write the shortest head of `major_type` carrying `value`.
    pub fn head<R>(&mut self, major_type: MajorType, value: u64) -> Result<(), BoundedError<R>> {
        self.argument(major_type, Argument::Shortest(value))
    }

    /// The write is complete: exactly `measured` bytes were written, all of
    /// the output.
    pub fn finish<R>(self, measured: u64) -> Result<(), BoundedError<R>> {
        let written = widen(self.position)?;
        if written != measured || self.position != self.bytes.len() {
            return Err(BoundedError::Length { measured, written });
        }
        Ok(())
    }
}

/// A value whose canonical dCBOR encoding can be prepared and written
/// without building a symbolic tree (see the module documentation).
///
/// For supported values with a symbolic conversion, its write produces the bytes
/// `CBOR::from(value.clone()).to_cbor_data()` produces, exactly
/// [`Measure::len`] of them, consumes exactly the plan entries its
/// preparation pushed, in order, and reports no more work than
/// [`Measure::write`].
/// Standalone options use null/contained-value semantics. Canonical key
/// collisions in dynamic Rust maps are refused rather than silently replacing
/// an entry as symbolic map construction does. Out-of-profile symbolic negative
/// integers and symbolic paths deeper than 128 nodes are refused.
///
/// Implementations are trusted to report work before performing it, to make
/// no heap allocations in `write`, and to preserve the represented value
/// between measurement and writing, including through interior mutability.
/// The output and reported-work bounds are enforced; these semantic obligations
/// cannot be established by the trait system. `FIXED` is also a trusted promise.
pub trait BoundedEncodable {
    /// The measure every value of this type has, when the type fixes both
    /// its encoded length and its write work and its preparation pushes no
    /// plan entry; `None` otherwise. A container measures elements of such a
    /// type from their count alone.
    const FIXED: Option<Measure> = None;

    /// The exact encoded length and a bound on the write's work, pushing to
    /// `plan` what the write will need, every allocation and every unit of
    /// its own work reported to `allocator` first.
    fn measure<A: Allocator>(
        &self,
        plan: &mut Plan<A::Permit>,
        allocator: &mut A,
    ) -> BoundedResult<Measure, A>;

    /// Write the encoding into `output`, consuming its entries of the plan
    /// through `plan`, its work reported to `budget` first.
    fn write<P, B: Budget>(
        &self,
        plan: &mut Cursor<'_, P>,
        output: &mut Output<'_>,
        budget: &mut B,
    ) -> BoundedResult<(), B>;
}

/// Enforces the prediction independently of the caller's policy. This meters
/// reported work; trait implementations remain responsible for reporting all
/// work before doing it and for making no allocations during writing.
struct WriteBudget<'a, B> {
    inner: &'a mut B,
    predicted: WriteWork,
    used: WriteWork,
}

impl<B: Budget> Budget for WriteBudget<'_, B> {
    type Refusal = BoundedError<B::Refusal>;

    fn traverse(&mut self, values: u64, bytes: u64) -> Result<(), Self::Refusal> {
        let attempted = self.used.then(WriteWork::new(values, bytes))?;
        if !self.predicted.covers(&attempted) {
            return Err(BoundedError::WorkExceeded {
                predicted: self.predicted,
                attempted,
            });
        }
        self.inner
            .traverse(values, bytes)
            .map_err(BoundedError::Refused)?;
        self.used = attempted;
        Ok(())
    }
}

impl<R> BoundedError<BoundedError<R>> {
    fn flatten(self) -> BoundedError<R> {
        match self {
            Self::Refused(error) => error,
            Self::Overflow => BoundedError::Overflow,
            Self::OutOfRange => BoundedError::OutOfRange,
            Self::DuplicateKey => BoundedError::DuplicateKey,
            Self::DepthLimit => BoundedError::DepthLimit,
            Self::Allocation { bytes } => BoundedError::Allocation { bytes },
            Self::OutputSize { measured, provided } => {
                BoundedError::OutputSize { measured, provided }
            }
            Self::Capacity { needed, remaining } => BoundedError::Capacity { needed, remaining },
            Self::Length { measured, written } => BoundedError::Length { measured, written },
            Self::PlanMismatch => BoundedError::PlanMismatch,
            Self::WorkExceeded {
                predicted,
                attempted,
            } => BoundedError::WorkExceeded {
                predicted,
                attempted,
            },
        }
    }
}

/// A value's encoding prepared for writing: the value, borrowed for as long
/// as the preparation lives, its measure, and its plan.
pub struct Prepared<'a, T: ?Sized, P> {
    value: &'a T,
    measure: Measure,
    plan: Plan<P>,
}

/// Prepare `value` for writing under `allocator` (see the module
/// documentation).
pub fn prepare<'a, T, A>(
    value: &'a T,
    allocator: &mut A,
) -> BoundedResult<Prepared<'a, T, A::Permit>, A>
where
    T: BoundedEncodable + ?Sized,
    A: Allocator,
{
    let mut plan = Plan::new();
    let measure = value.measure(&mut plan, allocator)?;
    Ok(Prepared {
        value,
        measure,
        plan,
    })
}

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

/// Prepare, admit output storage and initialization, allocate fallibly, and
/// publish only a complete encoding, all under one policy. On every error all
/// owned permits unwind. A caller that prepares under one policy and writes
/// under another (an admitted unit) uses [`prepare`] and
/// [`Prepared::encode_owned`] directly.
pub fn encode<T: BoundedEncodable + ?Sized, A: Allocator>(
    value: &T,
    allocator: &mut A,
) -> BoundedResult<Encoded<A::Permit>, A> {
    let prepared = prepare(value, allocator)?;
    let permit = allocator
        .allocate(prepared.len())
        .map_err(BoundedError::Refused)?;
    prepared.encode_owned(permit, allocator)
}

impl<T: BoundedEncodable + ?Sized, P> Prepared<'_, T, P> {
    /// The exact encoded length.
    pub const fn len(&self) -> u64 {
        self.measure.len
    }

    /// Whether the measured encoding contains zero bytes, not whether the
    /// source collection is empty. Every valid CBOR item has a head, so a
    /// conforming implementation always produces a nonempty encoding.
    pub const fn is_empty(&self) -> bool {
        self.measure.len == 0
    }

    /// The work the write reports at most.
    pub const fn write_work(&self) -> WriteWork {
        self.measure.write
    }

    /// Write the encoding into storage this call allocates fallibly at
    /// exactly [`Self::len`] bytes, owned with `permit`, the reservation the
    /// caller admitted for that storage; `budget` is told of the output's
    /// initialization (`traverse(0, len)`) before it is touched, then of the
    /// write as [`Self::encode_into`] reports it. The bytes are published only
    /// once the encoding is complete; on every error the storage is freed and
    /// `permit` dropped after it. The budget may differ from the preparation's
    /// allocator: a caller admits the output, its initialization and the
    /// predicted write as one unit and writes on that unit.
    pub fn encode_owned<Q, B: Budget>(
        &self,
        permit: Q,
        budget: &mut B,
    ) -> BoundedResult<Encoded<Q>, B> {
        let len = self.measure.len;
        let size = usize::try_from(len).map_err(|_| BoundedError::Overflow)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(size)
            .map_err(|_| BoundedError::Allocation { bytes: len })?;
        budget.traverse(0, len).map_err(BoundedError::Refused)?;
        bytes.resize(size, 0);
        self.encode_into(&mut bytes, budget)?;
        Ok(Encoded {
            bytes,
            _permit: permit,
        })
    }

    /// Write the encoding into `bytes`, which must be exactly [`Self::len`]
    /// bytes: a wrong-sized output is refused before anything is written,
    /// and a write that does not fill it exactly, or does not consume the
    /// plan exactly, is refused at its end.
    pub fn encode_into<B: Budget>(&self, bytes: &mut [u8], budget: &mut B) -> BoundedResult<(), B> {
        let provided = widen(bytes.len())?;
        if provided != self.measure.len {
            return Err(BoundedError::OutputSize {
                measured: self.measure.len,
                provided,
            });
        }
        let mut output = Output::new(bytes);
        let mut cursor = self.plan.cursor();
        let mut metered = WriteBudget {
            inner: budget,
            predicted: self.measure.write,
            used: WriteWork::default(),
        };
        self.value
            .write(&mut cursor, &mut output, &mut metered)
            .map_err(BoundedError::flatten)?;
        if !cursor.finished() {
            return Err(BoundedError::PlanMismatch);
        }
        output.finish(self.measure.len)
    }
}

/// Forwarding through a pointer: the pointee's representation, borrowed,
/// never cloned.
macro_rules! impl_bounded_forward {
    ($($({$($generics:tt)*})? $type:ty),*) => {$(
        impl<$($($generics)*)?> BoundedEncodable for $type {
            const FIXED: Option<Measure> = T::FIXED;

            fn measure<A: Allocator>(
                &self,
                plan: &mut Plan<A::Permit>,
                allocator: &mut A,
            ) -> BoundedResult<Measure, A> {
                (**self).measure(plan, allocator)
            }

            fn write<P, B: Budget>(
                &self,
                plan: &mut Cursor<'_, P>,
                output: &mut Output<'_>,
                budget: &mut B,
            ) -> BoundedResult<(), B> {
                (**self).write(plan, output, budget)
            }
        }
    )*};
}

impl_bounded_forward!(
    {T: BoundedEncodable + ?Sized} &T,
    {T: BoundedEncodable + ?Sized} Box<T>,
    {T: BoundedEncodable + ?Sized} Arc<T>
);

#[cfg(feature = "std")]
impl_bounded_forward!({T: BoundedEncodable + ?Sized} std::rc::Rc<T>);

/// A number by its prepared canonical encoding (`float.rs`): its head, one
/// value. The value is reported before the number is prepared; preparation
/// itself allocates nothing.
fn measure_numeric<R>(numeric: Numeric) -> Result<Measure, BoundedError<R>> {
    Ok(Measure::leaf(widen(numeric.len())?, 0))
}

fn write_numeric<R>(numeric: Numeric, output: &mut Output<'_>) -> Result<(), BoundedError<R>> {
    let (major_type, argument) = numeric.head();
    output.argument(major_type, argument)
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

macro_rules! impl_bounded_numeric {
    ($($type:ty => $prepare:expr),*) => {$(
        impl BoundedEncodable for $type {
            fn measure<A: Allocator>(
                &self,
                _: &mut Plan<A::Permit>,
                allocator: &mut A,
            ) -> BoundedResult<Measure, A> {
                allocator.traverse(1, 0).map_err(BoundedError::Refused)?;
                measure_numeric($prepare(*self))
            }

            fn write<P, B: Budget>(
                &self,
                _: &mut Cursor<'_, P>,
                output: &mut Output<'_>,
                budget: &mut B,
            ) -> BoundedResult<(), B> {
                budget.traverse(1, 0).map_err(BoundedError::Refused)?;
                write_numeric($prepare(*self), output)
            }
        }
    )*};
}

impl_bounded_numeric!(
    u8 => |n: u8| integer(n as i128),
    u16 => |n: u16| integer(n as i128),
    u32 => |n: u32| integer(n as i128),
    u64 => |n: u64| integer(n as i128),
    usize => |n: usize| integer(n as i128),
    i8 => |n: i8| integer(n as i128),
    i16 => |n: i16| integer(n as i128),
    i32 => |n: i32| integer(n as i128),
    i64 => |n: i64| integer(n as i128),
    f16 => |n: f16| convert_f16(n).prepared(),
    f32 => |n: f32| convert_f32(n).prepared(),
    f64 => |n: f64| convert_f64(n).prepared()
);

/// `false` and `true` are the simple values 20 and 21 (`simple.rs`).
impl BoundedEncodable for bool {
    const FIXED: Option<Measure> = Some(Measure::leaf(1, 0));

    fn measure<A: Allocator>(
        &self,
        _: &mut Plan<A::Permit>,
        allocator: &mut A,
    ) -> BoundedResult<Measure, A> {
        allocator.traverse(1, 0).map_err(BoundedError::Refused)?;
        Ok(Measure::leaf(1, 0))
    }

    fn write<P, B: Budget>(
        &self,
        _: &mut Cursor<'_, P>,
        output: &mut Output<'_>,
        budget: &mut B,
    ) -> BoundedResult<(), B> {
        budget.traverse(1, 0).map_err(BoundedError::Refused)?;
        output.head(MajorType::Simple, if *self { 21 } else { 20 })
    }
}

/// The measure of the byte string holding `bytes`: its head and its bytes
/// (`cbor.rs`), copied by the write. Measuring examines only the length.
pub fn measure_byte_string<A: Allocator>(
    bytes: &[u8],
    allocator: &mut A,
) -> BoundedResult<Measure, A> {
    allocator.traverse(1, 0).map_err(BoundedError::Refused)?;
    let length = widen(bytes.len())?;
    Ok(Measure::leaf(item_len(length, length)?, length))
}

/// Write the byte string holding `bytes`: for types that encode as one.
pub fn write_byte_string<B: Budget>(
    bytes: &[u8],
    output: &mut Output<'_>,
    budget: &mut B,
) -> BoundedResult<(), B> {
    let length = widen(bytes.len())?;
    budget.traverse(1, length).map_err(BoundedError::Refused)?;
    output.head(MajorType::ByteString, length)?;
    output.slice(bytes)
}

impl BoundedEncodable for ByteString {
    fn measure<A: Allocator>(
        &self,
        _: &mut Plan<A::Permit>,
        allocator: &mut A,
    ) -> BoundedResult<Measure, A> {
        measure_byte_string(self.data(), allocator)
    }

    fn write<P, B: Budget>(
        &self,
        _: &mut Cursor<'_, P>,
        output: &mut Output<'_>,
        budget: &mut B,
    ) -> BoundedResult<(), B> {
        write_byte_string(self.data(), output, budget)
    }
}

macro_rules! impl_bounded_text {
    ($($type:ty),*) => {$(
        impl BoundedEncodable for $type {
            fn measure<A: Allocator>(
                &self,
                plan: &mut Plan<A::Permit>,
                allocator: &mut A,
            ) -> BoundedResult<Measure, A> {
                text::measure_text(self, plan, allocator)
            }

            fn write<P, B: Budget>(
                &self,
                plan: &mut Cursor<'_, P>,
                output: &mut Output<'_>,
                budget: &mut B,
            ) -> BoundedResult<(), B> {
                text::write_text(self, plan, output, budget)
            }
        }
    )*};
}

impl_bounded_text!(str, String);

/// The measure of the array of `items` (`array.rs`): its head, one value,
/// then each element. Elements of a type with a fixed measure are measured
/// from their count alone.
pub fn measure_array<T: BoundedEncodable, A: Allocator>(
    items: &[T],
    plan: &mut Plan<A::Permit>,
    allocator: &mut A,
) -> BoundedResult<Measure, A> {
    allocator.traverse(1, 0).map_err(BoundedError::Refused)?;
    let count = widen(items.len())?;
    let elements = match T::FIXED {
        Some(each) => Measure {
            len: mul(each.len, count)?,
            write: each.write.times(count)?,
        },
        None => {
            let mut total = Measure {
                len: 0,
                write: WriteWork::default(),
            };
            for item in items {
                let measured = item.measure(plan, allocator)?;
                total = Measure {
                    len: add(total.len, measured.len)?,
                    write: total.write.then(measured.write)?,
                };
            }
            total
        }
    };
    Ok(Measure {
        len: item_len(count, elements.len)?,
        write: WriteWork::new(1, 0).then(elements.write)?,
    })
}

/// Write the array of `items`.
pub fn write_array<T: BoundedEncodable, P, B: Budget>(
    items: &[T],
    plan: &mut Cursor<'_, P>,
    output: &mut Output<'_>,
    budget: &mut B,
) -> BoundedResult<(), B> {
    budget.traverse(1, 0).map_err(BoundedError::Refused)?;
    output.head(MajorType::Array, widen(items.len())?)?;
    for item in items {
        item.write(plan, output, budget)?;
    }
    Ok(())
}

/// The fixed measure of an array of `count` elements each of fixed measure
/// `each`, when every quantity is representable.
const fn fixed_array(each: Option<Measure>, count: usize) -> Option<Measure> {
    let Some(each) = each else {
        return None;
    };
    let count = count as u64;
    let (Some(payload), Some(values), Some(bytes)) = (
        each.len.checked_mul(count),
        each.write.values.checked_mul(count),
        each.write.bytes.checked_mul(count),
    ) else {
        return None;
    };
    let (Some(len), Some(values)) = (
        payload.checked_add(head_len(count) as u64),
        values.checked_add(1),
    ) else {
        return None;
    };
    Some(Measure {
        len,
        write: WriteWork::new(values, bytes),
    })
}

/// A vector, a slice and an array are each an array of their elements
/// (`array.rs`); bytes are a byte string only as a [`ByteString`].
macro_rules! impl_bounded_sequence {
    ($($({$($generics:tt)*})? $type:ty => $fixed:expr),*) => {$(
        impl<$($($generics)*)?> BoundedEncodable for $type {
            const FIXED: Option<Measure> = $fixed;

            fn measure<A: Allocator>(
                &self,
                plan: &mut Plan<A::Permit>,
                allocator: &mut A,
            ) -> BoundedResult<Measure, A> {
                measure_array(self, plan, allocator)
            }

            fn write<P, B: Budget>(
                &self,
                plan: &mut Cursor<'_, P>,
                output: &mut Output<'_>,
                budget: &mut B,
            ) -> BoundedResult<(), B> {
                write_array(self, plan, output, budget)
            }
        }
    )*};
}

impl_bounded_sequence!(
    {T: BoundedEncodable} Vec<T> => None,
    {T: BoundedEncodable} [T] => None,
    {T: BoundedEncodable, const N: usize} [T; N] => fixed_array(T::FIXED, N)
);

/// The simple value `null` (22), which a unit struct encodes as
/// (`simple.rs`).
pub const NULL: u64 = 22;

#[cfg(test)]
mod tests;
