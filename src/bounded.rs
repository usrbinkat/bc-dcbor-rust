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
//!    allocated or copied for the output. [`Prepared::encode_into`] instead
//!    writes it into storage the caller supplies, and
//!    [`Prepared::encode_owned`] into storage it requests from the writing
//!    policy at exactly the encoding's length.
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
//! explicit [`Tagged`] wrappers, and feature-gated
//! `BigInt`/`BigUint`. Sets and deques do not implement this interface.
//!
//! Dynamic Rust maps are ordered by their prepared key bytes in place and
//! reject keys whose canonical encodings collide; trees keyed by their
//! encodings ([`crate::Map`]) are checked in one pass instead. Symbolic
//! traversal admits at most [`SYMBOLIC_DEPTH`] nested frames and rejects
//! out-of-profile negative integers. Constructing an input value is outside
//! the encoding operation's budget.
//!
//! [`decode::decode`] validates and decodes into a borrowed flat document,
//! with admitted arena storage and an explicit depth limit. It never calls the
//! recursive symbolic decoder. The returned view borrows payloads from the input;
//! traversing that view is a separate caller operation.
//!
//! # Before and after: publishing an encoded record
//!
//! ```
//! use dcbor::{CBOREncodable, bounded::{encode, Limits}};
//! # fn main() -> dcbor::Result<()> {
//! let fields = std::collections::BTreeMap::from([("status", "ready")]);
//! // Before: symbolic construction and serialization allocate freely.
//! let before = fields.encode_cbor_data()?;
//! // After: preparation and publication share limits; the plan's own
//! // storage becomes the output.
//! let mut limits = Limits::new(10_000, 100_000, 64_000);
//! let after = encode(&fields, &mut limits).unwrap();
//! assert_eq!(after.as_ref(), before);
//! assert!(limits.live_bytes() >= after.as_ref().len() as u64);
//! // Keep `after` alive until the transport/storage operation consumes its bytes.
//! drop(after);
//! assert_eq!(limits.live_bytes(), 0);
//! # Ok(())
//! # }
//! ```
//!
//! # Caller-owned output
//!
//! The output can be written under a policy of the caller's own. Writing
//! requests the output's storage from that policy at exactly the encoding's
//! length, holds the permit it grants until the bytes are freed, and
//! publishes the bytes only after a successful write. Policy refusal,
//! arithmetic overflow, heap failure and encoding invariant failure retain
//! distinct [`BoundedError`] variants.
//!
//! ```
//! use dcbor::bounded::*;
//! use std::{cell::Cell, rc::Rc};
//! struct Permit(Rc<Cell<u64>>, u64);
//! impl Drop for Permit {
//!     fn drop(&mut self) { self.0.set(self.0.get() - self.1); }
//! }
//! struct Policy { live: Rc<Cell<u64>>, values: u64, bytes: u64, storage: u64 }
//! // A budget that records nothing: no credit family, no identities, and
//! // only ordinary owners.
//! impl Budget for Policy {
//!     type Refusal = &'static str;
//!     fn traverse(&mut self, values: u64, bytes: u64) -> Result<(), Self::Refusal> {
//!         let v = self.values.checked_sub(values).ok_or("work")?;
//!         let b = self.bytes.checked_sub(bytes).ok_or("work")?;
//!         self.values = v;
//!         self.bytes = b;
//!         Ok(())
//!     }
//!     type Origin = ();
//!     fn origin(&self) {}
//!     fn admitted(&mut self, _: WriteWork) {}
//!     fn identify(&mut self) -> Result<Identity, Self::Refusal> {
//!         Ok(Identity::UNOBSERVED)
//!     }
//!     fn held(&mut self, _: WriteWork, _: Hold) {}
//!     fn effect(&mut self, _: Effect) {}
//!     fn owner(&mut self) -> Result<Owner, Self::Refusal> {
//!         Ok(Owner::unobserved())
//!     }
//!     fn acquisition(&mut self, owner: &Owner) -> Result<Acquisition<()>, Self::Refusal> {
//!         self.validate_owner(owner)?;
//!         Acquisition::unobserved(owner).ok_or("recorded owner")
//!     }
//!     fn validate_owner(&mut self, owner: &Owner) -> Result<(), Self::Refusal> {
//!         if owner.id() == Identity::UNOBSERVED { Ok(()) } else { Err("recorded owner") }
//!     }
//!     fn performer(&self) -> Performer {
//!         Performer::None
//!     }
//! }
//! impl Releasing for Policy {
//!     type Permit = Permit;
//!     fn permit_identity(_: &Permit) -> Identity {
//!         Identity::UNOBSERVED
//!     }
//!     fn custody(_: &Permit, _: Identity, _: RecordStage) {}
//! }
//! impl Allocator for Policy {
//!     fn allocate(&mut self, bytes: u64) -> Result<Permit, Self::Refusal> {
//!         let next = self.live.get().checked_add(bytes).ok_or("storage")?;
//!         if next > self.storage { return Err("storage"); }
//!         self.live.set(next);
//!         Ok(Permit(self.live.clone(), bytes))
//!     }
//! }
//! let live = Rc::new(Cell::new(0));
//! let mut policy = Policy { live: live.clone(), values: 10_000, bytes: 100_000, storage: 64_000 };
//! let prepared = prepare(&24u64, &mut policy).unwrap();
//! let encoded = prepared.encode_owned(&mut policy).unwrap();
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
/// attribution ledger refuses any that is not. Once the policy admits, its
/// disposition is reported ([`Credit::Admit`]): `held`, the part prepaid
/// for an obligation the caller's custody now holds, at most the whole
/// admission, and the rest consumed. A held part is given its identity
/// before it is admitted, minted by the budget ([`Budget::identify`]), and
/// returned in its custody ([`Retained`]); every later spend or forfeit of
/// it names that identity ([`Retained::spend`], [`Retained::forfeit`]). A
/// refused admission reports nothing.
#[expect(
    clippy::disallowed_methods,
    reason = "the one admission route every charge rule's `admit` goes through"
)]
fn traverse_at<P: Place, B: Budget>(
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

/// The route's admission of work consumed at once.
fn admit_at<P: Place, B: Budget>(
    place: P,
    budget: &mut B,
    values: u64,
    bytes: u64,
) -> BoundedResult<(), B> {
    traverse_at(place, budget, values, bytes)?;
    budget.admitted(WriteWork::new(values, bytes));
    Ok(())
}

/// The route's admission of work of which `part` is held for `obligation`
/// by `acquisition` of `owner` (the owning custody's capability, and the
/// acquisition's identity minted once when it was bound,
/// [`Budget::acquisition`]), in this order: the performing budget
/// validated against the owner ([`Budget::validate_owner`]), the
/// obligation's identity minted ([`Budget::identify`]), the work admitted,
/// the hold observed ([`Budget::held`]); its custody, with the budget's
/// origin, returned to the holder. A refusal at any of the first three
/// leaves accounting unchanged (a refused validation makes the recording
/// sticky-invalid). Identity issuance may include admissions refused after
/// it: a family's sequence counts identities minted, not obligations held,
/// and its exhaustion is checked and sticky; no credit is ever admitted
/// without its identity.
fn admit_held_at<P: Place, B: Budget>(
    place: P,
    budget: &mut B,
    values: u64,
    bytes: u64,
    held: (Obligation, WriteWork, &Owner, Identity),
) -> BoundedResult<Retained<B::Origin>, B> {
    let (obligation, part, owner, acquisition) = held;
    if less(WriteWork::new(values, bytes), part).is_none() {
        return Err(BoundedError::PlanMismatch);
    }
    budget
        .validate_owner(owner)
        .map_err(BoundedError::Refused)?;
    // Identified before admitting: a recording budget that cannot identify
    // the obligation refuses with nothing admitted.
    let id = budget.identify().map_err(BoundedError::Refused)?;
    traverse_at(place, budget, values, bytes)?;
    budget.held(
        WriteWork::new(values, bytes),
        Hold {
            obligation,
            work: part,
            id,
            acquisition,
        },
    );
    Ok(Retained {
        origin: budget.origin(),
        sequence: id.sequence(),
        acquisition,
        remaining: part,
        obligation,
    })
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

/// The symbolic nesting profile: the most frames a value nests, the root
/// and each array element, map key, map value and tagged item one frame
/// deeper than its parent, so a scalar inside 127 arrays is 128 frames. The
/// one limit of every symbolic traversal: the bounded encoder's shape walk
/// and its preparation refuse a deeper value
/// ([`BoundedError::DepthLimit`]), and so does the symbolic decoder
/// ([`crate::Error::DepthLimit`]). A value built deeper still serializes
/// through [`CBOR::to_cbor_data`](crate::CBOR::to_cbor_data), which applies
/// no profile; neither the bounded encoder nor the decoder accepts it.
pub const SYMBOLIC_DEPTH: usize = 128;

/// The most bytes a [`Releasing::Permit`] may take, one limit on every
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

    /// Admit this unit prepaid for `obligation`, all of it held
    /// ([`Credit::Admit`]): the obligation's owning custody is returned
    /// ([`Retained`]), for the caller to store at once.
    pub(crate) fn admit_held<B: Budget>(
        self,
        budget: &mut B,
        obligation: Obligation,
        owner: &Owner,
        acquisition: Identity,
    ) -> BoundedResult<Retained<B::Origin>, B> {
        admit_held_at(
            self.place,
            budget,
            self.values,
            self.bytes,
            (obligation, self.work(), owner, acquisition),
        )
    }

    /// The work of one of these units.
    pub(crate) const fn work(self) -> WriteWork {
        WriteWork::new(self.values, self.bytes)
    }

    /// `count` of these units.
    pub(crate) fn times<R>(self, count: u64) -> Result<WriteWork, BoundedError<R>> {
        WriteWork::new(self.values, self.bytes)
            .checked_times(count)
            .ok_or(BoundedError::Overflow)
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
        self.capped(budget, bytes)?;
        admit_at(self.place, budget, self.values, bytes)
    }

    /// Admit one unit of `bytes` prepaid for `obligation`, all of it held
    /// ([`Credit::Admit`]): its owning custody is returned ([`Retained`]).
    pub(crate) fn admit_held<B: Budget>(
        self,
        budget: &mut B,
        bytes: u64,
        obligation: Obligation,
        owner: &Owner,
        acquisition: Identity,
    ) -> BoundedResult<Retained<B::Origin>, B> {
        self.capped(budget, bytes)?;
        admit_held_at(
            self.place,
            budget,
            self.values,
            bytes,
            (obligation, self.work(bytes), owner, acquisition),
        )
    }

    /// The one cap check of a capped unit, before either admission.
    fn capped<B: Budget>(self, budget: &mut B, bytes: u64) -> BoundedResult<(), B> {
        if Bound::new(Predicate::Quantum, self.cap).exceeded(budget, bytes) {
            return Err(BoundedError::PlanMismatch);
        }
        Ok(())
    }

    /// The work of one unit of `bytes`.
    pub(crate) const fn work(self, bytes: u64) -> WriteWork {
        WriteWork::new(self.values, bytes)
    }

    /// The units covering `bytes` bytes, each at most the cap, and `items`
    /// more for the last, partial unit of each of that many items.
    pub(crate) fn covering<R>(self, bytes: u64, items: u64) -> Result<WriteWork, BoundedError<R>> {
        let units = add(bytes.div_ceil(self.cap.max(1)), items)?;
        Ok(WriteWork::new(mul(units, self.values)?, bytes))
    }

    /// `count` units of the full cap each.
    pub(crate) fn times<R>(self, count: u64) -> Result<WriteWork, BoundedError<R>> {
        WriteWork::new(self.values, self.cap)
            .checked_times(count)
            .ok_or(BoundedError::Overflow)
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

    /// Admit one admission over `count` elements, the per-element part
    /// prepaid for `obligation` and held ([`Credit::Admit`]), its owning
    /// custody returned ([`Retained`]); the base consumed.
    pub(crate) fn admit_held<B: Budget>(
        self,
        budget: &mut B,
        count: u64,
        obligation: Obligation,
        owner: &Owner,
        acquisition: Identity,
    ) -> BoundedResult<Retained<B::Origin>, B> {
        let work = self.of(count)?;
        let held = self.held(count)?;
        admit_held_at(
            self.place,
            budget,
            work.values,
            work.bytes,
            (obligation, held, owner, acquisition),
        )
    }

    /// The per-element part of one admission over `count` elements: what
    /// [`Self::admit_held`] holds.
    pub(crate) fn held<R>(self, count: u64) -> Result<WriteWork, BoundedError<R>> {
        self.each.checked_times(count).ok_or(BoundedError::Overflow)
    }

    /// The work of one admission over `count` elements.
    pub(crate) fn of<R>(self, count: u64) -> Result<WriteWork, BoundedError<R>> {
        self.each
            .checked_times(count)
            .and_then(|each| self.base.checked_then(each))
            .ok_or(BoundedError::Overflow)
    }

    /// The work of `admissions` admissions over `count` elements in all.
    pub(crate) fn over<R>(self, admissions: u64, count: u64) -> Result<WriteWork, BoundedError<R>> {
        let (Some(base), Some(each)) = (
            self.base.checked_times(admissions),
            self.each.checked_times(count),
        ) else {
            return Err(BoundedError::Overflow);
        };
        base.checked_then(each).ok_or(BoundedError::Overflow)
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
        concurrent_peak(self)
    }

    /// The bound: every place's work, requests and retained bytes summed
    /// ([`additive`]), and [`Self::peak`], the one composition of the
    /// bound's peak, which a bound whose places hold storage at different
    /// times composes itself. A sum of peaks the bound never reports
    /// refuses nothing, nor does a peak query refuse over work.
    fn bound<R>(&self) -> Result<ResourceBound, BoundedError<R>> {
        Ok(ResourceBound {
            peak: self.peak()?,
            ..additive(self)?
        })
    }
}

/// The additive quantities of every place of `terms` running concurrently:
/// values, bytes, requests and retained bytes, each summed through
/// [`ResourceBound::checked_add`] with every term's peak left out, so only
/// these quantities can refuse ([`BoundedError::Overflow`]); the peak is 0.
pub(crate) fn additive<T: Places + ?Sized, R>(terms: &T) -> Result<ResourceBound, BoundedError<R>> {
    T::Place::ALL
        .iter()
        .try_fold(ResourceBound::default(), |total, &place| {
            total.checked_add(ResourceBound {
                peak: 0,
                ..terms.term(place)
            })
        })
        .ok_or(BoundedError::Overflow)
}

/// Every place's peak at once, the places concurrent: the peaks alone
/// summed, refused as [`BoundedError::Overflow`] only when they do not fit.
pub(crate) fn concurrent_peak<T: Places + ?Sized, R>(terms: &T) -> Result<u64, BoundedError<R>> {
    T::Place::ALL
        .iter()
        .try_fold(0u64, |total, &place| {
            total.checked_add(terms.term(place).peak)
        })
        .ok_or(BoundedError::Overflow)
}

/// The value of a construction cost computed in a constant, the one form
/// every `COST` item takes (`InPlace::COST`, derived bindings included): the
/// cost's composition (`in_place`, `checked_*`) is `None` when a quantity
/// does not fit in `u64`, and this panics in const evaluation, so an
/// overflowing cost fails to compile (E0080) where its binding is first
/// used with a concrete allocator. A run-time composition refuses instead
/// ([`BoundedError::Overflow`]).
#[macro_export]
macro_rules! const_cost {
    ($cost:expr $(,)?) => {
        const {
            match $cost {
                ::core::option::Option::Some(cost) => cost,
                ::core::option::Option::None => {
                    ::core::panic!("a construction cost exceeds u64")
                }
            }
        }
    };
}

#[cfg(feature = "num-bigint")]
mod bigint;
pub mod boundary;
use boundary::{Bound, Predicate};
pub mod decode;
pub mod encoding;
/// Kani harnesses of the arenas' growth recurrence (register item 4):
/// compiled only by `cargo kani`.
#[cfg(kani)]
mod growth_proofs;
mod policy;
/// The Kani harnesses' one stand-in budget: compiled only by `cargo kani`.
#[cfg(kani)]
pub(crate) mod proof_budget;
/// Kani proofs of the bound algebra (register item 4): compiled only by
/// `cargo kani`.
#[cfg(kani)]
mod proofs;
pub mod text;
pub mod text_cursor;
pub use encoding::Tagged;
pub use policy::record::{
    Boundary, Capacity, Incomplete, Invalidation, OBSERVED_WORDS, Observed, Session,
};
pub use policy::{
    Admission, AdmissionTrace, Answer, Call, Credits, Event, Family, HistoryCounts, LimitRefusal,
    Limits, RecordStage, Reservation, TURN, TransferRefusal, Unreadable,
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
    /// counted map's count, an entry where no scanning unordered map takes
    /// one, an encoding past its walked extent), or a plan's bytes do not
    /// account for its length.
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

    /// Observe that a boundary predicate reached a valuation
    /// ([`boundary`]): pure observation, called by the seam in every build
    /// before the comparison's result is used and never able to change it.
    /// It admits nothing, refuses nothing, must not allocate or unwind, and
    /// may run inside cleanup and terminal steps. By default nothing is
    /// recorded.
    fn boundary(&mut self, _boundary: boundary::Boundary) {}

    /// The capability a held obligation admitted through this budget keeps
    /// to settle into this budget's credit family ([`Origin`]), whatever
    /// budget later runs the step that settles it. A budget that records no
    /// credit has `()`.
    type Origin: Origin;

    /// This budget's credit family's capability, obtained without any
    /// admission, request or allocation.
    fn origin(&self) -> Self::Origin;

    /// Observe an admission of `work` through the route, all of it
    /// consumed at once ([`Credit::Admit`]). Called by the route after a
    /// successful [`Self::traverse`] and before the admission returns, so a
    /// refused admission records nothing. Pure observation, as
    /// [`Self::boundary`]: it admits nothing, refuses nothing, must not
    /// allocate or unwind.
    fn admitted(&mut self, work: WriteWork);

    /// Mint the identity of an obligation about to be admitted held: called
    /// by the route before it admits, so a budget that records and cannot
    /// identify it refuses ([`Self::acquisition`]'s refusal) with nothing
    /// admitted. [`Identity::UNOBSERVED`] for a budget that records nothing.
    fn identify(&mut self) -> Result<Identity, Self::Refusal>;

    /// Observe an admission of `work` through the route of which `hold`'s
    /// part is held ([`Hold`], its identity from [`Self::identify`]). Called
    /// as [`Self::admitted`] is, and held to the same contract.
    fn held(&mut self, work: WriteWork, hold: Hold);

    /// Observe a physical effect of an acquisition ([`Effect`]): the
    /// reservation a granted permit pays for made, or failed. Called by the
    /// acquisition right after the reservation's outcome is known, before
    /// its grant's obligation is settled. Held to [`Self::admitted`]'s
    /// contract.
    fn effect(&mut self, effect: Effect);

    /// Mint the identity of a custody that owns acquisitions (an operation
    /// record, a standalone driver, a decode owner, an acquisition token, an
    /// arena), once, when the custody is made, and observe it
    /// ([`Event::Owner`]); [`Identity::UNOBSERVED`] for a budget that records
    /// nothing. A budget that records refuses when it cannot identify the
    /// owner, nothing changed. Otherwise held to [`Self::admitted`]'s
    /// contract.
    ///
    /// The refusal of a recording budget that cannot identify (its session
    /// exhausted, or an owner it did not mint) is sticky: the session is no
    /// evidence from then on, and its recorder rejects every run of it, so
    /// retrying it on the ordinary refusal path proves nothing.
    fn owner(&mut self) -> Result<Owner, Self::Refusal>;

    /// Mint one acquisition `owner` binds, and observe the binding
    /// ([`Event::Bound`]): the capability ([`Acquisition`]) holding the
    /// acquisition's identity, its owner's, and this budget's origin, the
    /// one authority that later publishes its end ([`Acquisition::end`]).
    /// Every obligation admitted for it, and the permit it is granted, name
    /// its identity. Minted once per acquisition, before its first
    /// admission, and kept by its holder across every retry and every change
    /// of policy: the families that later admit its obligations or grant its
    /// permit are their own, named by their identities, not by this one's.
    /// A budget that records nothing returns [`Acquisition::unobserved`]. A
    /// budget that records refuses, before anything is admitted, an
    /// acquisition it cannot identify (its session exhausted) or whose owner
    /// it never identified, so no recorded acquisition is ever unidentified.
    /// Otherwise held to [`Self::admitted`]'s contract.
    fn acquisition(&mut self, owner: &Owner) -> Result<Acquisition<Self::Origin>, Self::Refusal>;

    /// Check, minting and admitting nothing, that this budget may perform
    /// work for `owner`'s acquisitions: an ordinary budget for an ordinary
    /// owner, a recording budget for an owner of its own, still usable,
    /// session. Every other pairing is refused (for [`Limits`],
    /// [`LimitRefusal::Unrecorded`]) and stickily invalidates each recording
    /// session involved, the owner's included. Called on every acquisition
    /// entry, a resumed one included, before anything is admitted, so a
    /// policy of another session never extends an acquisition it did not
    /// bind; [`Self::acquisition`] calls the same check before minting.
    /// Cleanup never calls it: settlement into each obligation's origin and
    /// every release proceed whatever the performing budget.
    fn validate_owner(&mut self, owner: &Owner) -> Result<(), Self::Refusal>;

    /// Who performs a settlement made through this budget's step
    /// ([`Performer`]).
    fn performer(&self) -> Performer;
}

/// The capability a custody that owns acquisitions keeps, made by
/// [`Budget::owner`]: its identity, and for a recording budget the session
/// that minted it. Its fields are private; the one public constructor is
/// [`Self::unobserved`], for a budget that records nothing, which a
/// recording family refuses.
///
/// What is enforced: each owning custody stores its own owner (one per
/// custody, made when the custody is made), and every acquisition entry,
/// a resumed one included, presents it to the performing budget, which
/// validates the pairing before admitting anything
/// ([`Budget::validate_owner`]). Being neither `Clone` nor `Copy` stops the
/// value being duplicated; it does not stop `&Owner` being shared, so the
/// attribution rests on that storage and that check, not on the type alone.
///
/// `Send` and `Sync`: an identity and a counted reference to the session's
/// store, whose shared state is atomics only. Dropping it decrements that
/// count; it neither allocates nor unwinds. The last reference to a store
/// frees it, which is not constant work; while a run is recorded its
/// recorder holds the [`policy::record::Session`] until it finishes
/// ([`policy::record::Session::finish`], which refuses while any owner of
/// the session lives), so no custody's drop or terminal cleanup ever frees
/// the store.
///
/// Its contract representation is [`OWNER_BYTES`]: an identity's two words
/// and the session reference's one, whatever the target; an ordinary owner
/// occupies the same storage.
pub struct Owner {
    id: Identity,
    session: Option<policy::record::Shared>,
}

/// An owner's contract bytes ([`Owner`]): three words, the identity's two
/// and the session reference's one, checked against its representation.
pub const OWNER_BYTES: usize = 24;

const _: () = assert!(
    core::mem::size_of::<Owner>() <= OWNER_BYTES,
    "an owner takes more than OWNER_BYTES bytes"
);

impl Owner {
    /// Invalidate, stickily, the session this owner was minted in, if any:
    /// a pairing refused by [`Budget::validate_owner`] makes it no evidence.
    pub(crate) fn invalidate(&self) {
        self.invalidate_with(Invalidation::ForeignOwner);
    }

    /// Invalidate this custody's recording without admission or allocation.
    /// The session retains its first cause; ordinary custody records nothing.
    pub(crate) fn invalidate_with(&self, cause: Invalidation) {
        if let Some(session) = &self.session {
            policy::record::exhaust(session, cause);
        }
    }

    /// Whether it was minted in a recording session.
    pub(crate) fn recorded_in_any(&self) -> bool {
        self.session.is_some()
    }

    /// An owner of a budget that records nothing: no identity, no session.
    pub const fn unobserved() -> Self {
        Self {
            id: Identity::UNOBSERVED,
            session: None,
        }
    }

    /// The identity it names.
    pub fn id(&self) -> Identity {
        self.id
    }

    /// An owner minted as `id` in `session` (`Limits::owner` only).
    pub(crate) fn recorded(id: Identity, session: policy::record::Shared) -> Self {
        Self {
            id,
            session: Some(session),
        }
    }

    /// Whether it was minted in `session`.
    pub(crate) fn of(&self, session: &policy::record::Shared) -> bool {
        self.session
            .as_ref()
            .is_some_and(|own| policy::record::same(own, session))
    }
}

impl fmt::Debug for Owner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Owner")
            .field("id", &self.id)
            .field("recorded", &self.session.is_some())
            .finish()
    }
}

/// Who performed a settlement: a policy of the session, by its number, or
/// no policy at all (a drop, a terminal path).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Performer {
    Policy(u64),
    None,
}

/// The capability to settle held credit into the credit family that
/// admitted it, and nothing else: no policy, permit or admission can be
/// derived from it, and dropping it releases nothing. Kept by every held
/// obligation ([`Retained`]) so its settlement reaches its origin whichever
/// budget, or none, performs it: a later step's policy, a terminal drain,
/// or the holder's drop.
pub trait Origin: Send + Sync {
    /// The family's identity within its recording session
    /// ([`Identity::family`]); `0` for a family that records nothing.
    fn family(&self) -> u64;

    /// Record one settlement into this family: `settled`'s work of its
    /// obligation consumed (`rule` is `None`) or forfeited under `rule`,
    /// performed `by`. Constant work; it admits nothing, refuses nothing,
    /// and neither allocates nor unwinds, so drops and terminal cleanup may
    /// call it.
    fn settle(&self, settled: Settled, rule: Option<Forfeit>, by: Performer);

    /// Record the end of `acquisition`, which `owner` bound and this family
    /// minted ([`Budget::acquisition`]), performed `by`: its holder settled
    /// every obligation it held and keeps no capability of it. Reached only
    /// through the acquisition's own capability ([`Acquisition::end`]), so
    /// only the minting family publishes it. Held to [`Self::settle`]'s
    /// contract: constant work, admitting, refusing, allocating and
    /// unwinding nothing.
    fn end(&self, acquisition: Identity, owner: Identity, by: Performer);
}

/// A budget that records no credit settles nothing and records no end.
impl Origin for () {
    fn family(&self) -> u64 {
        0
    }

    fn settle(&self, _settled: Settled, _rule: Option<Forfeit>, _by: Performer) {}

    fn end(&self, _acquisition: Identity, _owner: Identity, _by: Performer) {}
}

/// One acquisition's capability, minted by the budget that binds it
/// ([`Budget::acquisition`]): its identity and the minting family's origin,
/// the one authority that publishes its end. Kept by the acquisition's one
/// holder from its bind to its end, across every refusal and every change
/// of policy; obligations, permits, events and checkpoints name it by
/// identity alone ([`Self::id`]), never by this capability. Neither `Copy`
/// nor `Clone`: one acquisition, one holder.
///
/// The owner it was bound for is captured when it is minted and never
/// changes: its end names that owner, and no holder can supply another.
///
/// Its end is explicit ([`Self::end`]), published by its holder once every
/// obligation it held is settled. It has no `Drop` publication: a drop
/// that could run before its obligations settle would publish an end the
/// stream refutes, so a capability dropped without its end leaves the
/// acquisition active, which refinement refuses at finalization.
pub struct Acquisition<O: Origin> {
    origin: O,
    id: Identity,
    owner: Identity,
}

impl Acquisition<()> {
    /// An acquisition of a budget that records nothing, for an ordinary
    /// `owner`: no identity, and an origin that publishes nothing, so no
    /// unidentified end can ever be published. None for a recorded owner,
    /// whose acquisitions only its own session mints.
    pub fn unobserved(owner: &Owner) -> Option<Self> {
        Self::ordinary((), owner)
    }
}

impl<O: Origin> Acquisition<O> {
    /// An acquisition of an ordinary family `origin` for an ordinary
    /// `owner` (`Limits::acquisition` for a family that records nothing,
    /// [`Acquisition::unobserved`]): no identity. None when either records:
    /// an unobserved capability never carries a recorded origin or owner.
    pub(crate) fn ordinary(origin: O, owner: &Owner) -> Option<Self> {
        if owner.recorded_in_any() || origin.family() != 0 {
            return None;
        }
        Some(Self {
            origin,
            id: Identity::UNOBSERVED,
            owner: owner.id(),
        })
    }

    /// An acquisition minted as `id` by the family `origin` is, for the
    /// validated recorded `owner`, its binding published
    /// (`Limits::acquisition` only). None unless `id` is an identity of
    /// `origin`'s family and `owner` is recorded.
    pub(crate) fn minted(origin: O, id: Identity, owner: &Owner) -> Option<Self> {
        if id == Identity::UNOBSERVED
            || id.family() == 0
            || id.family() != origin.family()
            || !owner.recorded_in_any()
        {
            return None;
        }
        Some(Self {
            origin,
            id,
            owner: owner.id(),
        })
    }

    /// The identity it names: a reference, never publication authority.
    pub fn id(&self) -> Identity {
        self.id
    }

    /// End it, `by` the performer of the step that ends it, for the owner
    /// it was minted for: published into the minting family
    /// ([`Origin::end`]), the capability consumed. Admits, allocates,
    /// refuses and unwinds nothing, so terminal paths call it.
    pub fn end(self, by: Performer) {
        self.origin.end(self.id, self.owner, by);
    }
}

impl<O: Origin> fmt::Debug for Acquisition<O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Acquisition")
            .field("id", &self.id)
            .field("owner", &self.owner)
            .finish_non_exhaustive()
    }
}

/// A physical effect of an acquisition: the reservation the permit of
/// `permit` pays for exists, or failed and the permit dropped; the
/// acquisition is the one the permit was granted to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    Reserved {
        permit: Identity,
        acquisition: Identity,
    },
    Failed {
        permit: Identity,
        acquisition: Identity,
    },
}

/// The physical step a granted `permit` pays for, and its outcome: the one
/// definition every acquisition reports its effect by, after spending its
/// release at the permit. `reserve` performs the step. Made, the effect is
/// [`Effect::Reserved`] and the permit is returned beside what `reserve`
/// made, for its caller to hold for the allocation's life. Failed physically
/// ([`Forfeit::AcquisitionFailed`]), the effect is [`Effect::Failed`] and the
/// permit is dropped here, inside the failing step, performing the release
/// spent at it: a failed reservation has no allocation, and a permit lives
/// exactly as long as its allocation ([`Releasing`]), so no failed permit
/// survives the step that failed it. Refused under any other rule, nothing
/// physical happened: no effect is reported, and the permit is dropped alike.
/// The caller then settles what its acquisition still holds by the returned
/// rule and ends the acquisition. Allocation-free on its own side.
pub(crate) fn reserved<A: Allocator, T>(
    allocator: &mut A,
    permit: A::Permit,
    acquisition: Identity,
    reserve: impl FnOnce() -> Result<T, Forfeit>,
) -> Result<(A::Permit, T), Forfeit> {
    let id = A::permit_identity(&permit);
    match reserve() {
        Ok(made) => {
            allocator.effect(Effect::Reserved {
                permit: id,
                acquisition,
            });
            Ok((permit, made))
        }
        Err(rule) => {
            if matches!(rule, Forfeit::AcquisitionFailed) {
                allocator.effect(Effect::Failed {
                    permit: id,
                    acquisition,
                });
            }
            drop(permit);
            Err(rule)
        }
    }
}

/// One held obligation, the one custody of held credit every holder keeps:
/// its originating family's capability, the identity its admission minted,
/// its kind and the work it still holds. Its settlements are this type's
/// alone: a partial spend ([`Self::consume`]), the remainder spent
/// ([`Self::spend`]) or forfeited ([`Self::forfeit`]), each recorded into
/// its origin. Dropped unsettled, it forfeits what it still holds
/// ([`Forfeit::Cancelled`]) into its origin: allocation-free and
/// non-unwinding, so no holder's drop or terminal path leaves credit held
/// with no custody reporting it. It is never `Copy` or `Clone`: one
/// obligation, one custody. Its identity's family is its origin's, so only
/// the sequence is stored; the acquisition it is held for is stored whole,
/// since another family may have bound it.
pub struct Retained<O: Origin> {
    origin: O,
    sequence: u64,
    acquisition: Identity,
    remaining: WriteWork,
    obligation: Obligation,
}

impl<O: Origin> Retained<O> {
    /// The identity its admission minted.
    pub(crate) fn id(&self) -> Identity {
        Identity::new(self.origin.family(), self.sequence)
    }

    /// The acquisition it is held for.
    pub(crate) fn acquisition(&self) -> Identity {
        self.acquisition
    }

    /// What it is held for.
    pub(crate) fn obligation(&self) -> Obligation {
        self.obligation
    }

    /// The work it still holds: its holder's `held_credit` part.
    pub(crate) fn remaining(&self) -> WriteWork {
        self.remaining
    }

    /// The obligation as a custody observation: its kind, the work it still
    /// holds at the observation point, its identity and its acquisition's.
    /// Observation data only, never settlement authority.
    pub(crate) fn observation(&self) -> Hold {
        Hold {
            obligation: self.obligation(),
            work: self.remaining(),
            id: self.id(),
            acquisition: self.acquisition(),
        }
    }

    /// Spend `part` of it, at `permit` when the spend is bound to one, `by`
    /// the performing budget's [`Budget::performer`]: a window's inspected
    /// controls. More than it holds is an engine defect, refused with
    /// nothing changed. Its one caller is the bucket traversal
    /// (`encoding::buckets`), compiled exactly where a hash table is.
    #[cfg(any(feature = "hashbrown", feature = "custom-std-collections"))]
    pub(crate) fn consume<R>(
        &mut self,
        part: WriteWork,
        permit: Option<Identity>,
        by: Performer,
    ) -> Result<(), BoundedError<R>> {
        let remaining = less(self.remaining, part).ok_or(BoundedError::PlanMismatch)?;
        self.record(part, permit, None, by);
        self.remaining = remaining;
        Ok(())
    }

    /// Spend all it still holds, at `permit` when bound to one, `by` its
    /// performer: a release at its permit's grant, a grant once its
    /// reservation exists.
    pub(crate) fn spend(mut self, permit: Option<Identity>, by: Performer) {
        let remaining = core::mem::take(&mut self.remaining);
        self.record(remaining, permit, None, by);
    }

    /// Forfeit all it still holds under `rule`, at `permit` when the
    /// forfeit is a granted permit's (its reservation failed, or its scope
    /// closed under the grant), `by` its performer.
    pub(crate) fn forfeit(mut self, rule: Forfeit, permit: Option<Identity>, by: Performer) {
        let remaining = core::mem::take(&mut self.remaining);
        self.record(remaining, permit, Some(rule), by);
    }

    /// The one record of a settlement into its origin; nothing for none.
    fn record(
        &self,
        work: WriteWork,
        permit: Option<Identity>,
        rule: Option<Forfeit>,
        by: Performer,
    ) {
        if work == WriteWork::default() {
            return;
        }
        self.origin.settle(
            Settled {
                obligation: self.obligation,
                work,
                id: self.id(),
                acquisition: self.acquisition,
                permit,
            },
            rule,
            by,
        );
    }
}

/// Dropped unsettled: an unwinding or abandoned holder's backstop. Every
/// explicit cleanup path settles explicitly, under its performer, before
/// this runs.
impl<O: Origin> Drop for Retained<O> {
    fn drop(&mut self) {
        let remaining = core::mem::take(&mut self.remaining);
        self.record(remaining, None, Some(Forfeit::Cancelled), Performer::None);
    }
}

impl<O: Origin> fmt::Debug for Retained<O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Retained")
            .field("id", &self.id())
            .field("acquisition", &self.acquisition)
            .field("obligation", &self.obligation)
            .field("remaining", &self.remaining)
            .finish_non_exhaustive()
    }
}

/// The one sink of a custody observation.
///
/// A custody observation is a properly nested sequence of groups, one per
/// owning component: `begin(owner)` opens a group under the owner its stored
/// ownership capability names (`None` while deferred); `held` and `permit`
/// belong to the innermost open group; `end` closes it and restores its
/// parent. A component that holds an independently owning component (an
/// arena with its own Pending, a text continuation, a dynamic state) reports
/// it as a child group inside its own. An item outside every group, an
/// unmatched `end`, an unclosed group, or a deferred group holding an item
/// directly (rather than through a child group) is a malformed observation.
/// A `Contended` result invalidates the whole observation, groups already
/// emitted included. Allocation-free on the custody's side; the collector
/// owns any stack.
///
/// Every owning custody has one traversal, returning whether the observation
/// is whole ([`PermitsObserved`]): a holder's is its [`Custodial`]
/// implementation, a component's the one its holder calls from inside its
/// own; each projection below reads that traversal, so no custody keeps a
/// second enumeration of what it owns.
pub trait CustodySink<P> {
    fn begin(&mut self, owner: Option<Identity>);
    /// An acquisition bound by the open group's owner and not yet ended.
    fn bound(&mut self, acquisition: Identity);
    fn held(&mut self, hold: Hold);
    /// A permit the open group's component physically owns, and, for a
    /// record block's, the record stage under which that component holds it
    /// ([`RecordStage`]): `None` for every permit that is no record block.
    /// [`RecordStage::Reclaimed`] is never reported at a quiescent point:
    /// a record's cleanup completes and frees its block in one unit.
    fn permit(&mut self, permit: &P, record: Option<RecordStage>);
    fn end(&mut self);
    /// Custody held jointly by several holders and by none alone, named by
    /// `custody`, the identity of the permit it is held under: a decode
    /// scope whose authority was dropped, kept alive by the counted
    /// reference of every live handle, any of which may be the last. Each
    /// holder reaching it asks first; true reports it now, as groups of its
    /// own owners, false passes it over. A collector of everything the
    /// observation reaches answers true once per identity, so the custody is
    /// reported once whichever holder reaches it first; a projection of one
    /// holder's own custody ([`held_of`], [`permits_of`], [`owners_of`],
    /// [`bound_of`]) answers false, since shared custody is no holder's own.
    fn shared(&mut self, custody: Identity) -> bool;
}

/// A holder of custody with permits of `P`: a value its holder keeps,
/// steps or retires as a whole (an operation, a typed decode, a scope's
/// authority, a record handle, a published value, plan or writer), whose
/// custody is observed through this one contract wherever it is held. Its
/// traversal reports every group it owns into `sink`, its components'
/// through their own traversals, each identity once ([`CustodySink`]).
/// Read-only and allocation-free on the custody's side: it admits, mints,
/// publishes, settles and releases nothing. `&mut self` excludes every
/// reader of the custody, and every borrow out of it, while it is walked.
pub trait Custodial<P> {
    /// This holder's custody, whole or contended ([`PermitsObserved`]).
    fn observe_custody(&mut self, sink: &mut dyn CustodySink<P>) -> PermitsObserved;
}

/// The output of an operation that publishes nothing (a write into a
/// caller's destination) holds no permit.
impl<P> Custodial<P> for () {
    fn observe_custody(&mut self, _: &mut dyn CustodySink<P>) -> PermitsObserved {
        PermitsObserved::Complete
    }
}

/// Whether a custody observation is whole: `Complete` when every part the
/// custody owns was visited; `Contended` when some part (a shared scope
/// queue another caller is stepping) could not be walked, so the visit is no
/// observation of it. A contended observation is not an empty one: its
/// reader discards it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PermitsObserved {
    Complete,
    Contended,
}

/// Whether every observation of `parts` is whole: contended when any is,
/// since a contended part is no observation of what it holds.
pub fn observed_all(parts: impl IntoIterator<Item = PermitsObserved>) -> PermitsObserved {
    let mut whole = PermitsObserved::Complete;
    for part in parts {
        if part == PermitsObserved::Contended {
            whole = PermitsObserved::Contended;
        }
    }
    whole
}

/// The held obligations of a custody observation, in the traversal's order,
/// its groups and permits passed over. Returns the traversal's completeness.
pub fn held_of<P>(
    observe: impl FnOnce(&mut dyn CustodySink<P>) -> PermitsObserved,
    visit: &mut dyn FnMut(Hold),
) -> PermitsObserved {
    struct Held<'v>(&'v mut dyn FnMut(Hold));
    impl<P> CustodySink<P> for Held<'_> {
        fn begin(&mut self, _: Option<Identity>) {}
        fn bound(&mut self, _: Identity) {}
        fn held(&mut self, hold: Hold) {
            (self.0)(hold);
        }
        fn permit(&mut self, _: &P, _: Option<RecordStage>) {}
        fn end(&mut self) {}
        /// One holder's own obligations: shared custody is none of them.
        fn shared(&mut self, _: Identity) -> bool {
            false
        }
    }
    observe(&mut Held(visit))
}

/// The permits of a custody observation, each named by `A`'s identity of it
/// ([`Releasing::permit_identity`]), in the traversal's order. Returns the
/// traversal's completeness: a contended visit is not an empty one.
pub fn permits_of<A: Releasing>(
    observe: impl FnOnce(&mut dyn CustodySink<A::Permit>) -> PermitsObserved,
    visit: &mut dyn FnMut(Identity),
) -> PermitsObserved {
    struct Permits<'v, A>(
        &'v mut dyn FnMut(Identity),
        core::marker::PhantomData<fn() -> A>,
    );
    impl<A: Releasing> CustodySink<A::Permit> for Permits<'_, A> {
        fn begin(&mut self, _: Option<Identity>) {}
        fn bound(&mut self, _: Identity) {}
        fn held(&mut self, _: Hold) {}
        /// Every permit by identity, a record block's stage passed over: the
        /// permit set is the projection, the stage the collector's to check.
        fn permit(&mut self, permit: &A::Permit, _: Option<RecordStage>) {
            (self.0)(A::permit_identity(permit));
        }
        fn end(&mut self) {}
        /// One holder's own permits: shared custody is none of them.
        fn shared(&mut self, _: Identity) -> bool {
            false
        }
    }
    observe(&mut Permits::<A>(visit, core::marker::PhantomData))
}

/// The owners a custody observation's groups name, each group's once its
/// owner is made; a deferred group names none. One owner may head several
/// groups. Returns the traversal's completeness.
pub fn owners_of<P>(
    observe: impl FnOnce(&mut dyn CustodySink<P>) -> PermitsObserved,
    visit: &mut dyn FnMut(Identity),
) -> PermitsObserved {
    struct Owners<'v>(&'v mut dyn FnMut(Identity));
    impl<P> CustodySink<P> for Owners<'_> {
        fn begin(&mut self, owner: Option<Identity>) {
            if let Some(owner) = owner {
                (self.0)(owner);
            }
        }
        fn bound(&mut self, _: Identity) {}
        fn held(&mut self, _: Hold) {}
        fn permit(&mut self, _: &P, _: Option<RecordStage>) {}
        fn end(&mut self) {}
        /// One holder's own owners: shared custody is none of them.
        fn shared(&mut self, _: Identity) -> bool {
            false
        }
    }
    observe(&mut Owners(visit))
}

/// The acquisitions a custody observation reports bound, in the traversal's
/// order, its groups, obligations and permits passed over: the bindings a
/// progress position does not carry. Returns the traversal's completeness.
pub fn bound_of<P>(
    observe: impl FnOnce(&mut dyn CustodySink<P>) -> PermitsObserved,
    visit: &mut dyn FnMut(Identity),
) -> PermitsObserved {
    struct Bound<'v>(&'v mut dyn FnMut(Identity));
    impl<P> CustodySink<P> for Bound<'_> {
        fn begin(&mut self, _: Option<Identity>) {}
        fn bound(&mut self, acquisition: Identity) {
            (self.0)(acquisition);
        }
        fn held(&mut self, _: Hold) {}
        fn permit(&mut self, _: &P, _: Option<RecordStage>) {}
        fn end(&mut self) {}
        /// One holder's own bindings: shared custody is none of them.
        fn shared(&mut self, _: Identity) -> bool {
            false
        }
    }
    observe(&mut Bound(visit))
}

/// The work a custody observation holds: checked addition from zero over
/// its held obligations, allocation-free. `None` when the sum does not fit
/// or the observation is contended, which totals nothing. The one fold every
/// custody's `held_credit` is.
pub fn total_held<P>(
    observe: impl FnOnce(&mut dyn CustodySink<P>) -> PermitsObserved,
) -> Option<WriteWork> {
    let mut total = Some(WriteWork::default());
    let observed = held_of(observe, &mut |held: Hold| {
        total = total.and_then(|total| total.checked_then(held.work));
    });
    match observed {
        PermitsObserved::Complete => total,
        PermitsObserved::Contended => None,
    }
}

/// `left - right` in both quantities, or none when either falls below zero.
const fn less(left: WriteWork, right: WriteWork) -> Option<WriteWork> {
    let (Some(values), Some(bytes)) = (
        left.values.checked_sub(right.values),
        left.bytes.checked_sub(right.bytes),
    ) else {
        return None;
    };
    Some(WriteWork::new(values, bytes))
}

/// What a prepaid admission is held for: work admitted before the event
/// that performs it. Held credit has one source of truth, the custody of
/// the operation that admitted it, which records it as part of its state
/// and reports it through its `held_credit` observation; a policy records
/// only what was admitted, consumed and forfeited ([`Credit`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Obligation {
    /// An allocation's release, admitted by its acquisition before the
    /// allocation is requested ([`Allocator`]). Held until the allocation is
    /// granted, when it is bound to the permit, whose drop performs it
    /// unconditionally: [`Owned::reserve`] within its call; a retained
    /// arena's staged growth across steps (`decode::storage`,
    /// `Admitted::Release`); a text continuation from its `ReleaseOutput`
    /// phase to its grant ([`text_cursor`]); a string decode from its
    /// `Release` phase to its grant (`decode::string_cursor`);
    /// [`Prepared::encode_owned`] within its call.
    Release,
    /// Work an acquisition performs when its allocation is granted, admitted
    /// before it is requested: a retained arena's grown allocation written
    /// into its staging block (`decode::storage`, `Admitted::Write`), and the
    /// relocation of the initialized elements a moving reallocation performs
    /// ([`Owned::reserve`]). Spent at the grant and forfeited under the same
    /// rules as the release beside it.
    Grant,
    /// A bucket window's controls, admitted with the window
    /// (`encoding::buckets::BucketCursor`, where hash tables are built) and
    /// held until each is inspected.
    BucketWindow,
}

/// The named rules under which held credit is forfeited: admitted work that
/// is never performed. Admitted work is never refunded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Forfeit {
    /// The policy refused the request of an acquisition whose operation
    /// keeps no custody of its admission, a synchronous call that a refusal
    /// ends ([`Owned::reserve`], [`Prepared::encode_owned`]): a retry admits
    /// again. A retained acquisition keeps its credit held across a refusal
    /// instead, and its retry's grant spends it.
    AcquisitionRefused,
    /// The physical reservation failed after the request was granted: the
    /// grant's work ([`Obligation::Grant`]) is never performed. The release
    /// was spent at the grant, bound to the permit, which drops at once and
    /// performs it. The failure is terminal ([`Class::Allocation`]).
    AcquisitionFailed,
    /// Cleanup began, or a terminal error ended the operation, while its
    /// custody still held the credit: an admitted release or grant whose
    /// allocation was not granted, or a window's controls not inspected.
    Cancelled,
    /// An enumeration ended with its window's credit unspent: every entry
    /// yielded, or the count its map declared reached.
    EnumerationComplete,
}

/// One credit event: an admission, reported through [`Budget::admitted`] or
/// [`Budget::held`], or a settlement, recorded into the obligation's origin
/// ([`Origin::settle`]) by its custody ([`Retained`]). A policy's ledgers are
/// what was admitted (A), consumed (C) and forfeited (F); what is held (H)
/// is the custody's own (`held_credit`). An operation's credit is
/// conserved when, over every policy instance that served it, `A = C + F +
/// H`. Consumed is work performed, or work irrevocably committed to a
/// granted permit, whose drop performs its release unconditionally: the
/// ledgers do not report how much work has physically executed.
///
/// Every held obligation carries the identity its admission minted
/// ([`Budget::identify`]), and every spend or forfeit names it; a settlement
/// tied to a permit (a release bound at its grant, a grant spent once the
/// physical reservation exists or forfeited when it failed or was
/// abandoned) names that permit's identity too, read from the permit
/// itself ([`Releasing::permit_identity`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Credit {
    /// An admission through the route of `work`, of which `held`, at most
    /// all of it, was prepaid for an obligation, which the admitting
    /// custody now holds; the rest is consumed at once. One event: there is
    /// no window in which held credit is reported consumed.
    Admit { work: WriteWork, held: Option<Hold> },
    /// Held credit spent: the obligation's work performed, or bound to a
    /// granted permit.
    Spend(Settled),
    /// Held credit forfeited under a named rule.
    Forfeit(Settled, Forfeit),
}

/// The identity a policy family gives each permit it grants and each
/// obligation admitted held through it: the family's own identity, minted
/// once per family from one process-wide sequence when its first policy is
/// made, and the family's monotone sequence number, so no two permits or
/// obligations of one process share one, whichever families served them. A
/// budget that observes no credit mints [`Self::UNOBSERVED`] for every one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Identity {
    family: u64,
    sequence: u64,
}

impl Identity {
    /// What a budget observing no credit mints: no identity. No family is
    /// numbered zero.
    pub const UNOBSERVED: Self = Self {
        family: 0,
        sequence: 0,
    };

    /// The identity numbered `sequence` in `family`, as a stream records it.
    pub const fn new(family: u64, sequence: u64) -> Self {
        Self { family, sequence }
    }

    /// The family that minted it.
    pub const fn family(self) -> u64 {
        self.family
    }

    /// Its number in its family.
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
}

/// A held obligation: the obligation it is prepaid for, its work, the
/// identity minted for it, and the acquisition holding it. In an admission
/// event ([`Credit::Admit`]) `work` is the work initially held; in a custody
/// observation ([`CustodySink::held`]) it is the work still held at the
/// observation point. Observation data only, never settlement authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hold {
    pub obligation: Obligation,
    pub work: WriteWork,
    pub id: Identity,
    pub acquisition: Identity,
}

/// A held obligation's settlement: the obligation and its identity, the
/// acquisition that held it, the work settled, and the permit it is
/// settled at, if any.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settled {
    pub obligation: Obligation,
    pub work: WriteWork,
    pub id: Identity,
    pub acquisition: Identity,
    pub permit: Option<Identity>,
}

/// A budget that holds and releases permits of [`Self::Permit`] and names
/// them, and cannot request a new allocation: what cleanup receives
/// (`Cleanup`, in `decode::construction::reclamation`), and the bound of
/// every cleanup path, which may admit work, release what it holds and
/// report permits, never acquire.
///
/// A permit is held for exactly the life of the allocation it was granted
/// for; dropping it releases it, and cannot fail. Releasing a permit is the
/// last unit of an allocation's life, admitted by the acquisition that
/// requests it, before the allocation exists, as one value and at most a
/// quantum of bytes; any cleanup path, a stepped one or a terminal one, then
/// performs it unrefused. A permit is in the supported domain only if
/// dropping it does constant work, allocates nothing and does not unwind:
/// the terminal path's bound is one such drop per allocation held. A permit
/// is at most sixteen bytes, checked at compile time wherever a retained
/// arena or a decode record holds one. Owned decode scopes that cross
/// threads require `Permit: Send`.
pub trait Releasing: Budget {
    /// Held while the allocation it was given for exists.
    type Permit;

    /// The identity of `permit`, read from the permit itself:
    /// [`Identity::UNOBSERVED`] for a permit of a family that records
    /// nothing. Observation only; a physical effect ([`Effect`]) and the
    /// settlement of its release name it.
    fn permit_identity(permit: &Self::Permit) -> Identity;

    /// Observe that `permit`, a record block's, entered `stage` of its
    /// record's lifecycle under `owner`, the owner whose acquisition granted
    /// it ([`Event::Custody`]): published through the permit's own family,
    /// whatever budget performs the step, and with no budget at all where
    /// none exists (a record's retirement into its queue). Nothing for a
    /// permit of a family that records nothing. Observation only: it admits,
    /// allocates, refuses and unwinds nothing.
    fn custody(permit: &Self::Permit, owner: Identity, stage: RecordStage);
}

/// A releasing budget ([`Releasing`]) that also governs allocation: each
/// allocation is requested in its whole size before it is made, a
/// reallocation's new size while the old allocation is still held, and its
/// permit is held for exactly the allocation's life.
pub trait Allocator: Releasing {
    /// Admit an allocation of `bytes` requested capacity bytes. This excludes
    /// allocator metadata and allocator rounding; it is not an RSS bound.
    fn allocate(&mut self, bytes: u64) -> Result<Self::Permit, Self::Refusal>;
}

/// A policy that can finish a decode scope after its scheduler has gone away.
/// Credit its holder can no longer reach a policy to settle is settled by
/// the holder's own [`Retained`] custody into its origin, not through this
/// trait.
///
/// # Safety
/// An implementation keeps four obligations, and the `// SAFETY:` comment on
/// it names each as `label:` (`tests/unsafe_census.rs`, `UNSAFE_TRAITS`,
/// which lists every implementation):
///
/// - *terminal*: `terminal` and dropping its result neither allocate nor
///   unwind.
/// - *traverse*: the returned policy's `traverse` always succeeds, does
///   bounded allocation-free work, and never unwinds.
/// - *allocate*: the returned policy's `allocate` allocates nothing:
///   reclamation is forbidden from requesting new storage.
/// - *borrow*: the returned policy does not borrow `permit`.
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

    fn boundary(&mut self, boundary: boundary::Boundary) {
        (**self).boundary(boundary)
    }

    type Origin = B::Origin;

    fn origin(&self) -> Self::Origin {
        (**self).origin()
    }

    fn admitted(&mut self, work: WriteWork) {
        (**self).admitted(work)
    }

    fn identify(&mut self) -> Result<Identity, Self::Refusal> {
        (**self).identify()
    }

    fn held(&mut self, work: WriteWork, hold: Hold) {
        (**self).held(work, hold)
    }

    fn effect(&mut self, effect: Effect) {
        (**self).effect(effect)
    }

    fn owner(&mut self) -> Result<Owner, Self::Refusal> {
        (**self).owner()
    }

    fn acquisition(&mut self, owner: &Owner) -> Result<Acquisition<Self::Origin>, Self::Refusal> {
        (**self).acquisition(owner)
    }

    fn validate_owner(&mut self, owner: &Owner) -> Result<(), Self::Refusal> {
        (**self).validate_owner(owner)
    }

    fn performer(&self) -> Performer {
        (**self).performer()
    }
}

impl<R: Releasing + ?Sized> Releasing for &mut R {
    type Permit = R::Permit;

    fn permit_identity(permit: &Self::Permit) -> Identity {
        R::permit_identity(permit)
    }

    fn custody(permit: &Self::Permit, owner: Identity, stage: RecordStage) {
        R::custody(permit, owner, stage)
    }
}

impl<A: Allocator + ?Sized> Allocator for &mut A {
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

/// The larger of `left` and `right`, in constants: [`Ord::max`] is not a
/// `const fn`.
const fn larger_of(left: u64, right: u64) -> u64 {
    if left > right { left } else { right }
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

/// The capacity an arena grows to from `capacity`: four from empty,
/// otherwise double; `None` when doubling overflows. The one growth rule
/// [`Owned::reserve`], the staged arena's growth (`decode/storage.rs`
/// `allocate_grown`) and the bound over both ([`owned_growth`]) follow.
pub(crate) const fn grown_capacity(capacity: u64) -> Option<u64> {
    if capacity == 0 {
        Some(4)
    } else {
        capacity.checked_mul(2)
    }
}

/// [`grown_capacity`] over a `usize` capacity, refused
/// [`BoundedError::Overflow`] when it does not fit.
pub(crate) fn grown<R>(capacity: usize) -> Result<usize, BoundedError<R>> {
    grown_capacity(widen(capacity)?)
        .and_then(|grown| usize::try_from(grown).ok())
        .ok_or(BoundedError::Overflow)
}

/// A vector whose capacity grows only through its [`Allocator`], doubling
/// from four elements, each growth admitted in its whole new size, and its
/// eventual release, before it is made and its permit held for as long as
/// the allocation; the replaced allocation's permit is released after the
/// new one exists. Its capacity is tracked as requested, not as the
/// allocator rounded it, so two runs over the same input request the same
/// allocations.
///
/// Fields drop in declaration order, which is the release order
/// `Self::release` and every drop rely on: `items` first, freeing the
/// allocation, then `permit`, releasing its reservation, so no permit is
/// released while the storage it accounts for still exists. Reordering the
/// fields reverses it.
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

    /// The permit of this vector's allocation, read-only: named by its
    /// identity ([`Releasing::permit_identity`]) where a custody reports the
    /// permits it owns. None while it holds no allocation.
    pub fn permit(&self) -> Option<&P> {
        self.permit.as_ref()
    }

    /// Make room for `additional` more elements, each growth an acquisition
    /// of `owner`, the custody that holds this vector. The owner is the
    /// custody's, not the vector's own: storing it here would take the
    /// vector past one write extent ([`write_extent`]).
    pub fn reserve<A: Allocator<Permit = P>>(
        &mut self,
        additional: usize,
        allocator: &mut A,
        owner: &Owner,
    ) -> BoundedResult<(), A> {
        let needed = self
            .items
            .len()
            .checked_add(additional)
            .ok_or(BoundedError::Overflow)?;
        while Bound::new(Predicate::ArenaLength, self.capacity).exceeded(allocator, needed) {
            let grown = grown(self.capacity)?;
            let bytes = mul(widen(grown)?, widen(core::mem::size_of::<T>())?)?;
            let initialized = widen(self.items.len())?;
            // A moving reallocation can copy every initialized element; the
            // new allocation's release is paid for before it is requested.
            // Both are held for the grant, each in its own custody from its
            // admission ([`Retained`]): this call keeps neither across a
            // refusal, which ends it, so a refusal forfeits them and a
            // retry admits them again.
            // Each growth is one acquisition of `owner`, the custody holding
            // this vector, bound here and held for the length of the call:
            // nothing of it is held across a call. Every exit settles what
            // the growth holds, then ends the acquisition, once.
            let acquisition = allocator
                .acquisition(owner)
                .map_err(BoundedError::Refused)?;
            let by = allocator.performer();
            let grant = match Self::MOVE.admit_held(
                allocator,
                initialized,
                Obligation::Grant,
                owner,
                acquisition.id(),
            ) {
                Ok(grant) => grant,
                Err(error) => {
                    acquisition.end(by);
                    return Err(error);
                }
            };
            let release = match RELEASED.admit_held(
                allocator,
                const { Self::RELEASE_BYTES },
                Obligation::Release,
                owner,
                acquisition.id(),
            ) {
                Ok(release) => release,
                Err(error) => {
                    grant.forfeit(Forfeit::AcquisitionRefused, None, by);
                    acquisition.end(by);
                    return Err(error);
                }
            };
            let permit = match allocator.allocate(bytes) {
                Ok(permit) => permit,
                Err(refusal) => {
                    grant.forfeit(Forfeit::AcquisitionRefused, None, by);
                    release.forfeit(Forfeit::AcquisitionRefused, None, by);
                    acquisition.end(by);
                    return Err(BoundedError::Refused(refusal));
                }
            };
            let id = A::permit_identity(&permit);
            // Granted: the permit carries the release, which its drop
            // performs whatever follows.
            release.spend(Some(id), by);
            let additional = grown - self.items.len();
            let items = &mut self.items;
            match reserved(allocator, permit, acquisition.id(), || {
                items
                    .try_reserve_exact(additional)
                    .map_err(|_| Forfeit::AcquisitionFailed)
            }) {
                Ok((permit, ())) => {
                    grant.spend(Some(id), by);
                    acquisition.end(by);
                    self.permit = Some(permit);
                    self.capacity = grown;
                }
                Err(rule) => {
                    // The relocation the grant paid for never happens.
                    grant.forfeit(rule, Some(id), by);
                    acquisition.end(by);
                    return Err(BoundedError::Allocation { bytes });
                }
            }
        }
        Ok(())
    }

    pub fn push<A: Allocator<Permit = P>>(
        &mut self,
        item: T,
        allocator: &mut A,
        owner: &Owner,
    ) -> BoundedResult<(), A> {
        self.reserve(1, allocator, owner)?;
        self.items.push(item);
        Ok(())
    }

    /// Insert `item` at `at`, shifting the elements after it.
    pub fn insert<A: Allocator<Permit = P>>(
        &mut self,
        at: usize,
        item: T,
        allocator: &mut A,
        owner: &Owner,
    ) -> BoundedResult<(), A> {
        let len = self.items.len();
        if Bound::new(Predicate::ArenaLength, len).exceeded(allocator, at) {
            return Err(BoundedError::Overflow);
        }
        Self::MOVE.admit(allocator, widen(len - at)?)?;
        self.reserve(1, allocator, owner)?;
        self.items.insert(at, item);
        Ok(())
    }

    /// Remove every element, keeping the allocation and its permit. The
    /// drain itself admits nothing: its caller admits each element it
    /// handles as it handles it.
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
        owner: &Owner,
    ) -> BoundedResult<(), A> {
        self.reserve(bytes.len(), allocator, owner)?;
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
        let grown = grown_capacity(capacity).ok_or(BoundedError::Overflow)?;
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

    /// What `growths` hold, every one's capacity held at once and one growing
    /// at a time, as a bound of storage alone (no work, no requests): the
    /// alternative ([`ResourceBound::larger`]) over which one grows of the
    /// others' capacities held concurrently ([`ResourceBound::checked_add`])
    /// then its growth ([`ResourceBound::checked_then`]). Its peak is every
    /// capacity held and the largest relocation in progress, never two; it
    /// retains every capacity. Refused when a quantity does not fit.
    pub(crate) fn one_growing<R>(growths: &[Self]) -> Result<ResourceBound, BoundedError<R>> {
        let held = |growth: &Self| ResourceBound {
            peak: growth.held,
            retained: growth.held,
            ..ResourceBound::default()
        };
        let mut most = ResourceBound::default();
        for (growing, growth) in growths.iter().enumerate() {
            let others = growths
                .iter()
                .enumerate()
                .filter(|&(other, _)| other != growing)
                .try_fold(ResourceBound::default(), |total, (_, other)| {
                    total.checked_add(held(other))
                });
            let one = others
                .and_then(|others| {
                    others.checked_then(ResourceBound {
                        peak: growth.peak,
                        retained: growth.held,
                        ..ResourceBound::default()
                    })
                })
                .ok_or(BoundedError::Overflow)?;
            most = most.larger(one);
        }
        Ok(most)
    }

    /// This growth as the bound of the vector it grows: its relocated bytes
    /// reported as work of no values, its requests, its peak, and what it
    /// holds once grown as its retained output. Its releases are composed
    /// onto it by its holder ([`Self::released`]).
    pub(crate) const fn bound(self) -> ResourceBound {
        ResourceBound {
            values: 0,
            bytes: self.copied,
            allocated: self.allocated,
            peak: self.peak,
            retained: self.held,
        }
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
/// (`Growth::released`). A capped reservation requests no more than this.
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
    let work = WriteWork::checked_sequence(&[
        WriteWork::new(relocated, grown.copied),
        decode::storage::Storage::<u8, (), ()>::growth_work(growths)?,
    ])
    .ok_or(BoundedError::Overflow)?;
    Ok((growth, work))
}

/// What one bounded operation reports and holds at most, for any input its
/// bound admits, on success or at any failure: the work it reports to
/// [`Budget::traverse`], the sum of its allocation requests, the most bytes
/// its permits hold at once while it runs, and the most bytes the permits of
/// what it publishes hold once it completes.
///
/// Bounds compose only through six combinators, each a `const fn`
/// returning `None` when a quantity does not fit in `u64`, so one form
/// serves constants (`const_cost!`) and run time
/// (`.ok_or(BoundedError::Overflow)`): sequence with the first's output held
/// ([`Self::checked_then`]), sequence after it is released
/// ([`Self::checked_followed_by`]), concurrent ([`Self::checked_add`]),
/// alternative ([`Self::larger`]), repetition each released first
/// ([`Self::checked_repeated`]) and each held
/// ([`Self::checked_repeated_retained`]); [`Self::checked_mul`] is the
/// concurrent one repeated. Each states its algebra per
/// quantity. A deadline is a constraint on when an operation runs, not a
/// resource it consumes: no field carries one, and none composes.
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

    /// This operation, then `next` while this one's output is still held,
    /// or none when a quantity does not fit in `u64`. Work and requests:
    /// summed. Peak: `max(P_a, R_a + P_b)`, this one's peak, or its retained
    /// output beside `next`'s peak. Retained: `R_a + R_b`, both outputs.
    pub const fn checked_then(self, next: Self) -> Option<Self> {
        let (Some(values), Some(bytes), Some(allocated), Some(held), Some(retained)) = (
            self.values.checked_add(next.values),
            self.bytes.checked_add(next.bytes),
            self.allocated.checked_add(next.allocated),
            self.retained.checked_add(next.peak),
            self.retained.checked_add(next.retained),
        ) else {
            return None;
        };
        Some(Self {
            values,
            bytes,
            allocated,
            peak: larger_of(self.peak, held),
            retained,
        })
    }

    /// This operation, then `next` after this one's output was consumed and
    /// released, or none when a quantity does not fit in `u64`. Work and
    /// requests: summed. Peak: `max(P_a, P_b)`, nothing of this one's held
    /// beside `next`'s. Retained: `R_b`, `next`'s output alone.
    pub const fn checked_followed_by(self, next: Self) -> Option<Self> {
        let (Some(values), Some(bytes), Some(allocated)) = (
            self.values.checked_add(next.values),
            self.bytes.checked_add(next.bytes),
            self.allocated.checked_add(next.allocated),
        ) else {
            return None;
        };
        Some(Self {
            values,
            bytes,
            allocated,
            peak: larger_of(self.peak, next.peak),
            retained: next.retained,
        })
    }

    /// `count` operations of this bound, each one's output released before
    /// the next runs, or none when a quantity does not fit in `u64`: this
    /// bound [`Self::checked_followed_by`] itself `count` times. Work and
    /// requests: `count` times. Peak and retained: this bound's for
    /// `count > 0`, nothing for `count == 0`.
    pub const fn checked_repeated(self, count: u64) -> Option<Self> {
        let (Some(values), Some(bytes), Some(allocated)) = (
            self.values.checked_mul(count),
            self.bytes.checked_mul(count),
            self.allocated.checked_mul(count),
        ) else {
            return None;
        };
        let once = count != 0;
        Some(Self {
            values,
            bytes,
            allocated,
            peak: if once { self.peak } else { 0 },
            retained: if once { self.retained } else { 0 },
        })
    }

    /// `count` operations of this bound, each one's output still held while
    /// every later one runs, or none when a quantity does not fit in `u64`:
    /// this bound [`Self::checked_then`] itself `count` times. Work and
    /// requests: `count` times. Peak: `(count - 1) R + P` for `count > 0`,
    /// the earlier outputs beside the last one's peak (a peak counts what
    /// its operation retains, `R <= P`, so the last run is the highest),
    /// nothing for `count == 0`. Retained: `count R`.
    pub const fn checked_repeated_retained(self, count: u64) -> Option<Self> {
        if count == 0 {
            return Some(Self {
                values: 0,
                bytes: 0,
                allocated: 0,
                peak: 0,
                retained: 0,
            });
        }
        let (Some(values), Some(bytes), Some(allocated), Some(earlier), Some(retained)) = (
            self.values.checked_mul(count),
            self.bytes.checked_mul(count),
            self.allocated.checked_mul(count),
            self.retained.checked_mul(count - 1),
            self.retained.checked_mul(count),
        ) else {
            return None;
        };
        let Some(peak) = earlier.checked_add(self.peak) else {
            return None;
        };
        Some(Self {
            values,
            bytes,
            allocated,
            peak,
            retained,
        })
    }

    /// This bound and `other` running concurrently, or none when a quantity
    /// does not fit in `u64`: every quantity summed, peaks included, both
    /// held at once at worst. The one sum of bounds, which construction
    /// costs compose in constants ([`decode::construction::in_place`]), where
    /// none fails to compile (`const_cost!`), and which a run-time caller
    /// refuses as [`BoundedError::Overflow`].
    pub const fn checked_add(self, other: Self) -> Option<Self> {
        let (Some(values), Some(bytes), Some(allocated), Some(peak), Some(retained)) = (
            self.values.checked_add(other.values),
            self.bytes.checked_add(other.bytes),
            self.allocated.checked_add(other.allocated),
            self.peak.checked_add(other.peak),
            self.retained.checked_add(other.retained),
        ) else {
            return None;
        };
        Some(Self {
            values,
            bytes,
            allocated,
            peak,
            retained,
        })
    }

    /// `count` operations of this bound running concurrently, or none when a
    /// quantity does not fit in `u64`: this bound [`Self::checked_add`]
    /// itself `count` times, every quantity, peak and retained included,
    /// `count` times.
    pub const fn checked_mul(self, count: u64) -> Option<Self> {
        let (Some(values), Some(bytes), Some(allocated), Some(peak), Some(retained)) = (
            self.values.checked_mul(count),
            self.bytes.checked_mul(count),
            self.allocated.checked_mul(count),
            self.peak.checked_mul(count),
            self.retained.checked_mul(count),
        ) else {
            return None;
        };
        Some(Self {
            values,
            bytes,
            allocated,
            peak,
            retained,
        })
    }

    /// The alternative of this bound and `other`, whichever operation runs:
    /// every quantity, work, requests, peak and retained alike, the larger
    /// of the two. Never overflows.
    pub const fn larger(self, other: Self) -> Self {
        Self {
            values: larger_of(self.values, other.values),
            bytes: larger_of(self.bytes, other.bytes),
            allocated: larger_of(self.allocated, other.allocated),
            peak: larger_of(self.peak, other.peak),
            retained: larger_of(self.retained, other.retained),
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

    /// This work, then `next`, or none when a quantity does not fit in
    /// `u64`: summed, as work composes under every sequencing
    /// ([`ResourceBound::checked_then`]).
    pub const fn checked_then(self, next: Self) -> Option<Self> {
        let (Some(values), Some(bytes)) = (
            self.values.checked_add(next.values),
            self.bytes.checked_add(next.bytes),
        ) else {
            return None;
        };
        Some(Self { values, bytes })
    }

    /// `parts` in sequence, [`Self::checked_then`] over them in order, or
    /// none when a quantity does not fit in `u64`; no work for none.
    pub const fn checked_sequence(parts: &[Self]) -> Option<Self> {
        let mut total = Self::new(0, 0);
        let mut at = 0;
        while at < parts.len() {
            total = match total.checked_then(parts[at]) {
                Some(total) => total,
                None => return None,
            };
            at += 1;
        }
        Some(total)
    }

    /// This work `count` times, or none when a quantity does not fit in
    /// `u64`.
    pub const fn checked_times(self, count: u64) -> Option<Self> {
        let (Some(values), Some(bytes)) = (
            self.values.checked_mul(count),
            self.bytes.checked_mul(count),
        ) else {
            return None;
        };
        Some(Self { values, bytes })
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
///
/// The output outlives the operation that produced it, so it carries the
/// identity of the owner whose acquisition granted its permit: fixed at
/// construction from that acquisition's stored owner, never changed, and
/// observational identity only (no capability, no settlement authority), so
/// a custody observation of the output names the owner it was granted under
/// wherever the output has moved ([`CustodySink`]).
pub struct Encoded<P> {
    bytes: Vec<u8>,
    _permit: P,
    owner: Identity,
}

impl<P> Encoded<P> {
    /// The permit the encoding's storage holds, read: an observation naming
    /// it ([`Releasing::permit_identity`]); never moved or released here.
    pub fn permit(&self) -> &P {
        &self._permit
    }

    /// The identity of the owner whose acquisition granted the permit
    /// ([`Self`]): observational identity, read.
    pub fn owner(&self) -> Identity {
        self.owner
    }
}

/// The encoding's custody ([`CustodySink`]): one group, its permit under the
/// owner its acquisition was bound under. It owns no shared queue, so the
/// observation is never contended.
impl<P> Custodial<P> for Encoded<P> {
    fn observe_custody(&mut self, sink: &mut dyn CustodySink<P>) -> PermitsObserved {
        sink.begin(Some(self.owner));
        sink.permit(&self._permit, None);
        sink.end();
        PermitsObserved::Complete
    }
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
    let steps = encoding::prepare_bound::<A::Permit, A::Origin, A::Refusal>(shape)?.steps()?;
    let mut preparation = encoding::Preparation::<A::Permit, A::Origin>::capped(source, cap);
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
/// under another uses [`prepare`] and [`Prepared::encode_owned`] or
/// [`Prepared::publish`] directly.
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
                    .checked_then(work)
                    .expect("admitted work fits in u64");
            }
            self.total.work = self
                .total
                .work
                .checked_then(work)
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
                        .checked_then(*admitted)
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
                 `Capped`, `Scan`, `Rate`), or, in derived code, \
                 `bounded::decode::construction::in_place::step`",
                entered()
            );
            self.ledger().work(WriteWork::new(values, bytes));
            Ok(())
        }

        /// The attribution ledger keeps no credit ledgers: its held
        /// obligations settle into nothing.
        type Origin = ();

        fn origin(&self) {}

        fn admitted(&mut self, _: WriteWork) {}

        fn identify(&mut self) -> Result<Identity, Self::Refusal> {
            Ok(Identity::UNOBSERVED)
        }

        fn held(&mut self, _: WriteWork, _: Hold) {}

        fn effect(&mut self, _: Effect) {}

        fn owner(&mut self) -> Result<Owner, Self::Refusal> {
            Ok(Owner::unobserved())
        }

        /// A recorded owner's session is invalidated by the validation, so
        /// the run is no evidence, and its acquisition is bound for no
        /// identity: the attribution ledger cannot refuse, and its origin
        /// publishes nothing.
        fn acquisition(&mut self, owner: &Owner) -> Result<Acquisition<()>, Self::Refusal> {
            self.validate_owner(owner)?;
            Ok(Acquisition::unobserved(owner)
                .or_else(|| Acquisition::unobserved(&Owner::unobserved()))
                .expect("an ordinary owner binds an unobserved acquisition"))
        }

        /// An ordinary budget, which cannot refuse: an ordinary owner is its
        /// own pairing; a recorded one is a pairing [`Limits`] refuses, so its
        /// session is invalidated, stickily, and is no evidence, as the
        /// contract requires, and the attribution run continues.
        fn validate_owner(&mut self, owner: &Owner) -> Result<(), Self::Refusal> {
            if owner.recorded_in_any() {
                owner.invalidate();
            }
            Ok(())
        }

        fn performer(&self) -> Performer {
            Performer::None
        }
    }

    impl Releasing for Ledgered {
        type Permit = Permit;

        /// The attribution ledger records no identities.
        fn permit_identity(_: &Permit) -> Identity {
            Identity::UNOBSERVED
        }

        /// The attribution ledger records no record lifecycle.
        fn custody(_: &Permit, _: Identity, _: RecordStage) {}
    }

    impl Allocator for Ledgered {
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

    // The one form of every recorded oracle: its configuration line and
    // atomic publication.
    use dcbor_record as record;
    use record::capabilities::{Capabilities, Requirement};

    /// This build's capabilities: which feature-gated cases it compiles, so
    /// which recorded rows it must measure ([`Requirement`]).
    const CAPABILITIES: Capabilities = record::capabilities!();

    // `variant!()`: this build's record suffix, from the one mapping of the
    // projections' features to their suffixes (`record::declare_variant`).
    record::declare_variant!(variant);

    /// This build's variant: [`VARIANT`], the suffix of each record's name,
    /// and [`RECORDS`], every suite's record of that variant compiled in. The
    /// features that change what this crate's bounds charge, and so the
    /// ratios its suites record: with bignums, the preparation's record holds
    /// a bignum and its witness encodes them; over the forked collections,
    /// trees are walked by their stepped cursor and built in place (`btree`,
    /// a suite of those builds alone, compiled only there). Each build records
    /// and checks its own.
    ///
    /// A record is compiled in, not read at run time, so a check needs no
    /// filesystem, the interpreter's host isolation included, and a suite
    /// whose record is missing does not compile. The suites are the one
    /// inventory of them (`tests/data/tightness/families.rs`), which the
    /// gate checks every variant of too; a record rewritten by
    /// [`RECORD_FACTORS`] is compiled into the next build.
    macro_rules! families {
        (
            every: [$($every:literal),* $(,)?],
            custom_std: [$($custom:literal),* $(,)?] $(,)?
        ) => {
            #[cfg(not(feature = "custom-std-collections"))]
            suites!($($every),*);
            #[cfg(feature = "custom-std-collections")]
            suites!($($every,)* $($custom),*);
        };
    }

    /// This build's suites, each with its record of this build's variant.
    macro_rules! suites {
        ($($suite:literal),* $(,)?) => {
            const VARIANT: &str = variant!();
            const RECORDS: &[(&str, &str)] = &[$((
                $suite,
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/data/tightness/",
                    $suite,
                    variant!(),
                    ".txt"
                )),
            )),*];
        };
    }

    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/tightness/families.rs"
    ));

    /// The compiled record of `suite` ([`RECORDS`]).
    fn record(suite: &str) -> &'static str {
        match RECORDS.iter().find(|(name, _)| *name == suite) {
            Some((_, record)) => record,
            None => panic!(
                "{suite}: no record is compiled in for this build: name the suite in \
                 tests/data/tightness/families.rs, then record it with {RECORD_FACTORS}=1"
            ),
        }
    }

    /// What the ratchet does with a suite's measured ratios: rewrite its
    /// record under this configuration, or check them against the record
    /// given.
    enum Ratchet<'r> {
        Record(String),
        Check(&'r str),
    }

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
        /// The evidence class a ratio held to this ceiling establishes, its
        /// one definition: an [`Ceiling::Exact`] ratio is the exact most of a
        /// cost over every feasible input, computed, so derived; every other
        /// ceiling holds what a witness, or a run, measured, so observed.
        fn evidence(self) -> record::Evidence {
            match self {
                Ceiling::Exact => record::Evidence::Derived,
                Ceiling::Within(_) | Ceiling::Measured | Ceiling::Joint | Ceiling::Total => {
                    record::Evidence::Observed
                }
            }
        }

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
        requirement: Requirement,
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
    /// ceiling it is held to and the evidence class that ceiling supports
    /// ([`Ceiling::evidence`]), in `tests/data/tightness/<suite>.txt`, or
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
        requirements: std::collections::BTreeMap<String, Requirement>,
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
                requirements: std::collections::BTreeMap::new(),
                texts: Vec::new(),
                charged: [false; 5],
                covered: [false; 5],
            }
        }

        /// Declare a fixture's eligibility before any of its measurements.
        /// The exact case identity is shared by place, total and joint rows.
        pub(crate) fn requires(&mut self, case: &str, requirement: Requirement) {
            assert!(
                self.ratios.is_empty(),
                "declare eligibility before measurement"
            );
            assert!(
                self.requirements.insert(case.into(), requirement).is_none(),
                "{case}: eligibility declared twice"
            );
        }

        fn requirement(&self, case: &str) -> Requirement {
            self.requirements
                .get(case)
                .copied()
                .unwrap_or(Requirement::Always)
        }

        /// `bound` against `used`, as `what`, in `dimensions`: each the
        /// bound charges is a recorded ratio, beyond a [`Ceiling::Within`]
        /// a failure, and charged where its witness never uses it a failure;
        /// a [`Ceiling::Total`] is any run's, not a witness's, so its unused
        /// charge is recorded as it is.
        fn measure(
            &mut self,
            what: (&str, Requirement),
            outcome: Outcome,
            bound: ResourceBound,
            used: ResourceBound,
            ceiling: Ceiling,
            dimensions: &[Dimension],
        ) {
            let (what, requirement) = what;
            assert!(
                requirement.eligible(CAPABILITIES),
                "{what}: measured without required capability {}",
                requirement.name()
            );
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
                        requirement,
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
                        (
                            &format!("{}: {place:?}", run.name),
                            self.requirement(&run.name),
                        ),
                        run.outcome,
                        run.terms.term(place),
                        measured,
                        Ceiling::Within(allowed),
                        EVERY,
                    ),
                    Factor::Measured => self.measure(
                        (
                            &format!("{}: {place:?}", run.name),
                            self.requirement(&run.name),
                        ),
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
                (
                    &format!("{}: {what}", run.name),
                    self.requirement(&run.name),
                ),
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
                (what, self.requirement(what)),
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
                    (&format!("{}: run", run.name), self.requirement(&run.name)),
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
            let mode = if std::env::var_os(RECORD_FACTORS).is_some() {
                CAPABILITIES.require_complete();
                Ratchet::Record(record::recording_configuration())
            } else {
                Ratchet::Check(record(self.suite))
            };
            ratchet(
                &format!("{directory}/{}{VARIANT}.txt", self.suite),
                &measured,
                mode,
            );
        }
    }

    /// The record of `path` against the `measured` ratios, sorted by key:
    /// rewritten whole at `path` under the configuration a
    /// [`Ratchet::Record`] names, or compared with the record a
    /// [`Ratchet::Check`] gives, any change, unrecorded or no longer measured
    /// ratio failing with the configurations the record and the run were
    /// taken under. A record names its configuration on its first line
    /// ([`record`]).
    fn ratchet(path: &str, measured: &[(String, Ratio)], mode: Ratchet<'_>) {
        ratchet_under(path, measured, mode, CAPABILITIES);
    }

    fn ratchet_under(
        path: &str,
        measured: &[(String, Ratio)],
        mode: Ratchet<'_>,
        available: Capabilities,
    ) {
        for (case, ratio) in measured {
            ratio.outcome.admissible(case);
            assert!(
                ratio.requirement.eligible(available),
                "{case}: measured without required capability {}",
                ratio.requirement.name()
            );
        }
        let data = match mode {
            Ratchet::Record(configuration) => {
                if let Some(directory) = std::path::Path::new(path).parent() {
                    std::fs::create_dir_all(directory).expect("the record directory is writable");
                }
                let rows: Vec<String> = measured
                    .iter()
                    .map(|(key, ratio)| {
                        format!(
                            "{}\t{}\t{}\t{}\t{}\t{}\t{key}",
                            ratio.bound,
                            ratio.used,
                            ratio.ceiling,
                            ratio.ceiling.evidence(),
                            ratio.outcome.name(),
                            ratio.requirement.name()
                        )
                    })
                    .collect();
                record::publish(
                    path,
                    &record::render(&configuration, rows.iter().map(String::as_str)),
                );
                return;
            }
            Ratchet::Check(data) => data,
        };
        let read = record::read(path, data, &format!("{RECORD_FACTORS}=1"));
        let recorded_under = read.configuration;
        let running_under =
            record::configuration().unwrap_or_else(|| "an unnamed configuration".into());
        let mut recorded = std::collections::BTreeMap::new();
        for (number, line) in read.rows {
            let at = || format!("{path}:{number}");
            let mut fields = line.splitn(7, '\t');
            let (
                Some(bound),
                Some(used),
                Some(ceiling),
                Some(class),
                Some(outcome),
                Some(requirement),
                Some(key),
            ) = (
                fields.next(),
                fields.next(),
                fields.next(),
                fields.next(),
                fields.next(),
                fields.next(),
                fields.next(),
            )
            else {
                panic!(
                    "{}: not a bound, a use, a ceiling, an evidence class, an outcome, a requirement and a key",
                    at()
                );
            };
            let ratio = Ratio {
                requirement: Requirement::parse(requirement).unwrap_or_else(|| {
                    panic!("{}: {key}: unknown requirement {requirement:?}", at())
                }),
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
            let class = record::Evidence::parse(class)
                .unwrap_or_else(|| panic!("{}: {key}: no evidence class {class:?}", at()));
            let supports = ratio.ceiling.evidence();
            assert!(
                class == supports,
                "{}: {key}: claims {class}, its ceiling {} supports {supports}",
                at(),
                ratio.ceiling
            );
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
                     {RECORD_FACTORS}=1 and state why; outcome {} -> {}; requirement {} -> {}",
                    record.outcome.name(),
                    ratio.outcome.name(),
                    record.requirement.name(),
                    ratio.requirement.name()
                )),
                Some(_) => {}
            }
        }
        texts.extend(
            recorded
                .into_iter()
                .filter(|(_, ratio)| ratio.requirement.eligible(available))
                .map(|(key, _)| format!("{key}: recorded in {path} but no longer measured")),
        );
        assert!(
            texts.is_empty(),
            "{path}, recorded under {recorded_under}, running under {running_under}: {texts:#?}"
        );
    }

    /// The ratchet records the configuration on its record's first line and
    /// each ratio's evidence class from its ceiling ([`Ceiling::evidence`]),
    /// and publishes the record whole, leaving no temporary file; then
    /// refuses a planted change of a recorded ratio, a planted unrecorded
    /// ratio, a recorded ratio no longer measured, a row claiming another
    /// class than its ceiling supports (measured as derived, exact as
    /// observed), each named, and a record without its configuration line;
    /// and passes the measured ratios unchanged.
    #[test]
    fn the_ratchet_records_its_configuration_and_refuses_planted_changes() {
        let directory =
            std::env::temp_dir().join(format!("dcbor-tightness-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("a temporary directory");
        let path = directory.join("planted.txt");
        let path = path.to_str().expect("a UTF-8 temporary path");
        let ratio = |bound, used| Ratio {
            requirement: Requirement::Always,
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
        ratchet(path, &measured, Ratchet::Record("toolchain=t std=s".into()));
        assert_eq!(
            std::fs::read_to_string(path).expect("the record"),
            record::render(
                "toolchain=t std=s",
                [
                    "4\t2\tmeasured\tobserved\tpublished\t-\ta values",
                    "9\t9\tmeasured\tobserved\tpublished\t-\tb bytes"
                ]
            )
        );
        assert_eq!(
            std::fs::read_dir(&directory).unwrap().count(),
            1,
            "temporary evidence was not removed"
        );
        let recorded = || std::fs::read_to_string(path).expect("the record");
        ratchet(path, &measured, Ratchet::Check(&recorded()));
        let refused = |planted: Vec<(String, Ratio)>| {
            let path = path.to_string();
            let data = recorded();
            std::panic::catch_unwind(move || ratchet(&path, &planted, Ratchet::Check(&data)))
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
        // A row claiming another class than its ceiling supports: a measured
        // ratio recorded as derived, and an exact one recorded as observed.
        let honest = recorded();
        std::fs::write(
            path,
            honest.replacen("\tmeasured\tobserved\t", "\tmeasured\tderived\t", 1),
        )
        .expect("a misclassified record");
        let misclassified = refused(measured.clone());
        assert!(
            misclassified
                .contains("a values: claims derived, its ceiling measured supports observed"),
            "{misclassified}"
        );
        let exact = vec![(
            "a values".to_string(),
            Ratio {
                requirement: Requirement::Always,
                outcome: Outcome::Exact,
                bound: 4,
                used: 2,
                ceiling: Ceiling::Exact,
            },
        )];
        ratchet(path, &exact, Ratchet::Record("toolchain=t std=s".into()));
        assert!(
            recorded().contains("4\t2\texact\tderived\texact\t-\ta values"),
            "{}",
            recorded()
        );
        std::fs::write(
            path,
            recorded().replacen("\texact\tderived\t", "\texact\tobserved\t", 1),
        )
        .expect("a misclassified exact record");
        let observed = refused(exact);
        assert!(
            observed.contains("a values: claims observed, its ceiling exact supports derived"),
            "{observed}"
        );
        std::fs::write(path, "4\t2\tmeasured\tobserved\tpublished\ta values\n")
            .expect("a record without its line");
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
            requirement: Requirement::Always,
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
        let previous = std::fs::read_to_string(&path).unwrap();
        for mode in [
            Ratchet::Check(&previous),
            Ratchet::Record("planted configuration".into()),
        ] {
            let failed = std::panic::catch_unwind(|| {
                ratchet(path.to_str().unwrap(), &[(case.into(), defect)], mode);
            })
            .expect_err("ratchet accepted a defect");
            assert!(message(failed).contains(case));
            assert_eq!(std::fs::read_to_string(&path).unwrap(), "previous evidence");
        }
        std::fs::remove_file(path).unwrap();
    }

    /// Each recorded row is held to its case's eligibility ([`Requirement`]),
    /// whatever build checks it: a build lacking a row's capability neither
    /// measures nor requires it; a build having it must measure it, and a row
    /// of every build must be measured by every build; a changed requirement
    /// is a change; measuring a case its build cannot execute, and a record
    /// naming no known requirement, are refused.
    #[test]
    fn the_ratchet_holds_each_row_to_its_cases_eligibility() {
        use record::capabilities::Capability;
        let path =
            std::env::temp_dir().join(format!("dcbor-eligibility-{}.txt", std::process::id()));
        let path = path.to_str().expect("a UTF-8 temporary path").to_string();
        let full = Capabilities {
            derive: true,
            hashbrown: true,
        };
        let minimal = Capabilities {
            derive: false,
            hashbrown: false,
        };
        let ratio = |requirement| Ratio {
            requirement,
            outcome: Outcome::Published,
            bound: 3,
            used: 1,
            ceiling: Ceiling::Measured,
        };
        let always = ("a values".to_string(), ratio(Requirement::Always));
        let gated = (
            "h values".to_string(),
            ratio(Requirement::Capability(Capability::Hashbrown)),
        );
        ratchet_under(
            &path,
            &[always.clone(), gated.clone()],
            Ratchet::Record("toolchain=t std=s".into()),
            full,
        );
        let data = std::fs::read_to_string(&path).expect("the record");
        assert!(
            data.contains("3\t1\tmeasured\tobserved\tpublished\thashbrown\th values"),
            "{data}"
        );
        let refused = |measured: Vec<(String, Ratio)>, available: Capabilities| {
            let (path, data) = (path.clone(), data.clone());
            std::panic::catch_unwind(move || {
                ratchet_under(&path, &measured, Ratchet::Check(&data), available)
            })
            .expect_err("an eligibility defect passed the ratchet")
            .downcast::<String>()
            .map(|text| *text)
            .unwrap_or_default()
        };
        // Both builds pass with exactly their eligible rows.
        ratchet_under(
            &path,
            &[always.clone(), gated.clone()],
            Ratchet::Check(&data),
            full,
        );
        ratchet_under(
            &path,
            std::slice::from_ref(&always),
            Ratchet::Check(&data),
            minimal,
        );
        let missing = refused(vec![always.clone()], full);
        assert!(missing.contains("h values: recorded in"), "{missing}");
        let unmeasured = refused(Vec::new(), minimal);
        assert!(unmeasured.contains("a values: recorded in"), "{unmeasured}");
        assert!(!unmeasured.contains("h values"), "{unmeasured}");
        let regated = refused(
            vec![
                always.clone(),
                ("h values".to_string(), ratio(Requirement::Always)),
            ],
            full,
        );
        assert!(
            regated.contains("h values: changed") && regated.contains("requirement hashbrown -> -"),
            "{regated}"
        );
        let ineligible = refused(vec![always.clone(), gated.clone()], minimal);
        assert!(
            ineligible.contains("h values: measured without required capability hashbrown"),
            "{ineligible}"
        );
        std::fs::write(&path, data.replacen("\thashbrown\t", "\tnightly\t", 1))
            .expect("a record of an unknown requirement");
        let unknown = {
            let path = path.clone();
            std::panic::catch_unwind(move || {
                let data = std::fs::read_to_string(&path).expect("the record");
                ratchet_under(&path, &[always, gated], Ratchet::Check(&data), full)
            })
            .expect_err("an unknown requirement passed the ratchet")
            .downcast::<String>()
            .map(|text| *text)
            .unwrap_or_default()
        };
        assert!(
            unknown.contains("h values: unknown requirement \"nightly\""),
            "{unknown}"
        );
        std::fs::remove_file(&path).expect("the temporary record removed");
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
                decode::cursor::retained_decode_bound::<Reservation, Family, ()>(n, options)
                    .unwrap()
            });
            monotone("string_bound", sizes(), |n| {
                decode::string_cursor::string_bound::<Reservation, Family, ()>(n, options).unwrap()
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
        monotone("owned_emit_bound", sizes(), |n| {
            encoding::owned_emit_bound::<Reservation, ()>(n).unwrap()
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
            bucket_tables: 1,
            buckets: 64,
            bucket_entries: 8,
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
        let counts: [Count<encoding::Shape>; 23] = [
            ("instructions", |shape, value| shape.instructions = value),
            ("bucket_tables", |shape, value| shape.bucket_tables = value),
            ("buckets", |shape, value| shape.buckets = value),
            ("bucket_entries", |shape, value| {
                shape.bucket_entries = value
            }),
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
            monotone(&format!("prepare_bound in {count}"), 0..=256, |value| {
                let mut shape = base;
                set(&mut shape, value);
                encoding::prepare_bound::<Reservation, Family, ()>(shape).unwrap()
            });
            monotone(&format!("encode_bound in {count}"), 0..=256, |value| {
                let mut shape = base;
                set(&mut shape, value);
                super::encode_bound::<Reservation, Family, ()>(shape).unwrap()
            });
        }
        #[cfg(any(feature = "hashbrown", feature = "custom-std-collections"))]
        {
            monotone("bucket_bound in buckets", sizes(), |buckets| {
                encoding::buckets::bucket_bound::<()>(buckets, 8).unwrap()
            });
            monotone("bucket_bound in entries", sizes(), |entries| {
                encoding::buckets::bucket_bound::<()>(4096, entries).unwrap()
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
            self.iter()
                .map(|terms| terms.term(place))
                .fold(ResourceBound::default(), |total, term| {
                    total.checked_add(term).expect("terms fit in u64")
                })
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
