//! Construction directly into a reclamation-owned stable destination.
use super::reclamation::{PeekSlot, Reclaim, Reclaimed, Slot, Written};
use super::{node_at, wrong_type};
use crate::bounded::decode::{ConstructResult, Document, Kind};
use crate::bounded::{
    Allocator, BoundedError, BoundedResult, Caller, ResourceBound, Unit, add, mul,
};

#[doc(hidden)]
pub mod enumeration;
#[doc(hidden)]
pub mod fields;
mod optional;
mod stable_option;
pub use stable_option::{
    Decision as StableOptionDecision, Phase as StableOptionPhase, StableOption, StableOptionClass,
    StableOptionObservation,
};
mod scalars;
pub use optional::{OptionalClass, OptionalObservation, Phase as OptionalPhase, Placeholder};
#[doc(hidden)]
pub mod tagged;
pub(crate) mod text;
pub use text::{BufferClass, BufferCustody, BufferObservation, Phase as BufferPhase};
mod vector;
pub use vector::{
    ElementObservation, Phase as SequencePhase, SequenceCustody, SequenceObservation,
};
#[cfg(feature = "custom-std-collections")]
mod btree;
#[cfg(feature = "custom-std-collections")]
pub use btree::{
    EntryObservation, Phase as TreePhase, Shape as TreeShape, Sort as TreeSort, TreeCustody,
    TreeKey, TreeKeyView, TreeObservation, TreeProgress,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Built {
    Progress,
    Done,
}

/// What constructing a value in place and its mandatory cleanup report and
/// hold at most, as an affine function of the bytes its subtree encodes:
/// `fixed` once, and `per_byte` sixty-fourths of each quantity per byte,
/// rounded up ([`Self::bound`]). Construction copies and checks in units of
/// several bytes, so whole units per byte would overstate long payloads.
///
/// A container's children each encode at least one byte, so each child's
/// fixed part, and the rounding of its per-byte part, are paid from the
/// container's bytes ([`Self::children`]): costs compose linearly however
/// deeply values nest. `peak` holds everything a construction and its
/// children hold at once; `retained` is what the published value's permits
/// hold until its cleanup. Every operation is checked in const evaluation:
/// a cost that does not fit in `u64` fails to compile.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConstructionCost {
    pub fixed: ResourceBound,
    pub per_byte: ResourceBound,
}

/// The sixty-fourths of a unit per byte a [`ConstructionCost`] counts in.
pub const PER_BYTE_SCALE: u64 = 64;

const fn sum(left: u64, right: u64) -> u64 {
    match left.checked_add(right) {
        Some(total) => total,
        None => panic!("a construction cost exceeds u64"),
    }
}

const fn product(left: u64, right: u64) -> u64 {
    match left.checked_mul(right) {
        Some(total) => total,
        None => panic!("a construction cost exceeds u64"),
    }
}

/// `left` and `right` together, every quantity summed.
pub const fn plus(left: ResourceBound, right: ResourceBound) -> ResourceBound {
    ResourceBound {
        values: sum(left.values, right.values),
        bytes: sum(left.bytes, right.bytes),
        allocated: sum(left.allocated, right.allocated),
        peak: sum(left.peak, right.peak),
        retained: sum(left.retained, right.retained),
    }
}

/// `bound`, every quantity `count` times.
pub const fn times(bound: ResourceBound, count: u64) -> ResourceBound {
    ResourceBound {
        values: product(bound.values, count),
        bytes: product(bound.bytes, count),
        allocated: product(bound.allocated, count),
        peak: product(bound.peak, count),
        retained: product(bound.retained, count),
    }
}

/// The larger of `left` and `right` in every quantity.
pub const fn larger(left: ResourceBound, right: ResourceBound) -> ResourceBound {
    const fn max(left: u64, right: u64) -> u64 {
        if left > right { left } else { right }
    }
    ResourceBound {
        values: max(left.values, right.values),
        bytes: max(left.bytes, right.bytes),
        allocated: max(left.allocated, right.allocated),
        peak: max(left.peak, right.peak),
        retained: max(left.retained, right.retained),
    }
}

/// One admitted unit of one value and `bytes` bytes, as a cost: for an
/// [`InPlace`] implementation outside this crate, which reports its own work.
/// The bindings of this crate and derived bindings cost their admissions
/// from the charge each one makes ([`STEP_COST`]).
pub const fn unit(bytes: usize) -> ResourceBound {
    Unit::new(Caller, 1, bytes as u64).bound()
}

/// One step of one value and no bytes: an inspection, a find or search
/// step, a transition, a rejection, a cleanup unit that frees nothing. The
/// operation driving the construction supplies the place.
const STEP: Unit<Caller> = Unit::new(Caller, 1, 0);

/// What one [`step`] admits.
pub const STEP_COST: ResourceBound = STEP.bound();

/// Admit one step ([`STEP_COST`]): how a derived binding admits its
/// inspections and its cleanup units.
pub fn step<A: Allocator>(allocator: &mut A) -> BoundedResult<(), A> {
    STEP.admit(allocator)
}

/// One unit over a whole `T` in place, writing it or dropping it in place:
/// one value and its bytes, a write extent checked where `T` is used.
pub(crate) const fn sized<T>() -> Unit<Caller> {
    const { Unit::written::<T>(Caller) }
}

/// One unit of each quantity: the rounding of a child's per-byte part, paid
/// from the bytes it encodes ([`ConstructionCost::children`]).
pub(crate) const ROUNDING: ResourceBound = ResourceBound {
    values: 1,
    bytes: 1,
    allocated: 1,
    peak: 1,
    retained: 1,
};

/// An allocation of `bytes` held for the value's life.
pub const fn held(bytes: usize) -> ResourceBound {
    ResourceBound {
        values: 0,
        bytes: 0,
        allocated: bytes as u64,
        peak: bytes as u64,
        retained: bytes as u64,
    }
}

impl ConstructionCost {
    pub const ZERO: Self = Self {
        fixed: ResourceBound {
            values: 0,
            bytes: 0,
            allocated: 0,
            peak: 0,
            retained: 0,
        },
        per_byte: ResourceBound {
            values: 0,
            bytes: 0,
            allocated: 0,
            peak: 0,
            retained: 0,
        },
    };

    /// A cost of `fixed` alone.
    pub const fn fixed(fixed: ResourceBound) -> Self {
        Self {
            fixed,
            per_byte: Self::ZERO.per_byte,
        }
    }

    /// A cost of `whole` units of every quantity per byte, in sixty-fourths.
    pub const fn per_byte(whole: ResourceBound) -> Self {
        Self {
            fixed: Self::ZERO.fixed,
            per_byte: times(whole, PER_BYTE_SCALE),
        }
    }

    /// This cost and `other` for the same bytes.
    pub const fn plus(self, other: Self) -> Self {
        Self {
            fixed: plus(self.fixed, other.fixed),
            per_byte: plus(self.per_byte, other.per_byte),
        }
    }

    /// The larger of this cost and `other` in every quantity: either of two
    /// alternatives.
    pub const fn larger(self, other: Self) -> Self {
        Self {
            fixed: larger(self.fixed, other.fixed),
            per_byte: larger(self.per_byte, other.per_byte),
        }
    }

    /// Children of this cost within a container's bytes, each encoding at
    /// least one byte: every child's fixed part and the rounding of its
    /// per-byte part, one unit of each quantity, are paid per byte.
    pub const fn children(self) -> Self {
        Self {
            fixed: Self::ZERO.fixed,
            per_byte: plus(
                self.per_byte,
                times(plus(self.fixed, ROUNDING), PER_BYTE_SCALE),
            ),
        }
    }

    /// The bound for a value whose subtree encodes `input` bytes. Refused,
    /// never saturated, when a quantity does not fit in `u64`.
    pub fn bound<R>(&self, input: u64) -> Result<ResourceBound, BoundedError<R>> {
        let scaled = |fixed: u64, per_byte: u64| -> Result<u64, BoundedError<R>> {
            add(fixed, mul(per_byte, input)?.div_ceil(PER_BYTE_SCALE))
        };
        Ok(ResourceBound {
            values: scaled(self.fixed.values, self.per_byte.values)?,
            bytes: scaled(self.fixed.bytes, self.per_byte.bytes)?,
            allocated: scaled(self.fixed.allocated, self.per_byte.allocated)?,
            peak: scaled(self.fixed.peak, self.per_byte.peak)?,
            retained: scaled(self.fixed.retained, self.per_byte.retained)?,
        })
    }
}

/// Admit the unit that found a node of the wrong kind, then report it: an
/// invalid input is discovered by admitted work, like every other outcome, and
/// a refusal of that unit reports nothing.
pub(crate) fn rejected<A: Allocator>(a: &mut A) -> ConstructResult<Built, A> {
    STEP.admit(a)?;
    Err(wrong_type())
}

/// Constructs into stable storage and shares its initialization state with
/// mandatory incremental cleanup. Completion carries no value by value.
///
/// The destination is received as a [`Slot`], its place and its state
/// together, so a caller holding one has nothing to promise.
///
/// # Safety
/// Each write must be admitted before execution. [`Reclaim::INITIAL`] means
/// uninitialized storage. Every successful write or acquired resource must be
/// represented in the state before returning, including on error. Done means
/// the destination is fully initialized. No pointer may escape construction;
/// cleanup must be valid after every call. There is no synchronous Drop fallback.
/// The destination is reached only through its slot's place, which keeps its
/// provenance for its whole life: a place a step derives within it stays
/// valid in every later step. Every method is sound for every call a slot's
/// holder can make, in any order: a build from a state it does not continue
/// (completed, cleaning up, or another phase's) is refused with
/// [`BoundedError::PlanMismatch`] and changes nothing.
pub unsafe trait InPlace<A: Allocator>: Reclaim<A> {
    const OPTIONAL: bool = false;

    /// What constructing this value, by any of `build_step`, `build_present`
    /// and `build_absent`, and then its cleanup report and hold at most, on
    /// success or at any failure, for a subtree of any input. Understating
    /// it violates the unsafe implementation contract; every built-in and
    /// derived binding derives it from its own charges.
    const COST: ConstructionCost;

    /// Construct a present map field, distinct from standalone nullable values.
    fn build_present(
        document: &Document<'_, A::Permit>,
        index: usize,
        slot: Slot<'_, Self, Self::State>,
        allocator: &mut A,
    ) -> ConstructResult<Built, A> {
        Self::build_step(document, index, slot, allocator)
    }
    /// Initialize an omitted map field. Required fields reject omission.
    fn build_absent(
        _slot: Slot<'_, Self, Self::State>,
        _allocator: &mut A,
    ) -> ConstructResult<Built, A> {
        Err(crate::bounded::decode::DecodeError::Invalid(
            crate::Error::MissingMapKey,
        ))
    }
    /// One unit of construction of the value in `slot` from the document
    /// node at `index`.
    fn build_step(
        document: &Document<'_, A::Permit>,
        index: usize,
        slot: Slot<'_, Self, Self::State>,
        allocator: &mut A,
    ) -> ConstructResult<Built, A>;
}

/// A value an owned operation builds in a scope record and moves between
/// threads with it: the value and its construction state are both `Send`.
/// Every binding meeting both is one; owned construction, typed decoding and
/// owned preparation state this one bound.
pub trait Transferable<A: Allocator>: InPlace<A, State: Send> + Send {}

impl<T: InPlace<A, State: Send> + Send, A: Allocator> Transferable<A> for T {}

macro_rules! integers {
    ($($ty:ty),* $(,)?) => {$(
        // SAFETY: integer storage owns no child resources and has no destructor.
        unsafe impl<A: Allocator> Reclaim<A> for $ty {
            type State = Written;
            const INITIAL: Written = Written::Empty;

            /// An integer owns nothing, so its one cleanup unit, from either
            /// state, only marks it empty: repeated, it changes nothing.
            fn reclaim_step(
                mut slot: Slot<'_, Self, Written>, a: &mut A,
            ) -> BoundedResult<Reclaimed, A> {
                STEP.admit(a)?;
                *slot.custody() = Written::Empty;
                Ok(Reclaimed::Done)
            }

            /// One call, which is `Done`.
            fn remaining(_: PeekSlot<'_, Self, Written>) -> u64 {
                1
            }
        }
        // SAFETY: one admitted scalar write initializes the complete value,
        // only from the empty state.
        unsafe impl<A: Allocator> InPlace<A> for $ty {
            const COST: ConstructionCost = scalar_cost::<$ty>();

            fn build_step(
                document: &Document<'_, A::Permit>, index: usize,
                mut slot: Slot<'_, Self, Written>, a: &mut A,
            ) -> ConstructResult<Built, A> {
                let (place, state) = slot.parts();
                if *state != Written::Empty { return Err(BoundedError::PlanMismatch.into()); }
                sized::<Self>().admit(a)?;
                let number = match node_at(document, index).map(|node| node.kind()) {
                    Some(Kind::Unsigned(n)) => i128::from(n),
                    Some(Kind::Negative(n)) => i128::from(n),
                    _ => return Err(wrong_type()),
                };
                let value = Self::try_from(number).map_err(|_| crate::bounded::decode::DecodeError::Invalid(crate::Error::OutOfRange))?;
                // SAFETY: the slot pairs the place with this state, which is
                // empty: nothing to drop, the write admitted above.
                unsafe { place.write(state, value) };
                *state = Written::Initialized;
                Ok(Built::Done)
            }
        }
    )*};
}

integers!(u8, u16, u32, u64, usize, i8, i16, i32, i64);

/// The cost of a scalar built by one admitted write of its own bytes, and
/// reclaimed by one step; nothing is allocated. A refused kind or range is
/// found by that same write unit.
pub(crate) const fn scalar_cost<T>() -> ConstructionCost {
    ConstructionCost::fixed(plus(sized::<T>().bound(), STEP_COST))
}

#[cfg(test)]
mod tests {
    use super::super::reclamation::{Build, Place};
    use super::*;
    use crate::bounded::Limits;
    use crate::bounded::decode::DecodeError;
    use core::{mem::MaybeUninit, ptr::NonNull};

    fn bound(values: u64, bytes: u64, allocated: u64, peak: u64, retained: u64) -> ResourceBound {
        ResourceBound {
            values,
            bytes,
            allocated,
            peak,
            retained,
        }
    }

    /// The cost algebra every binding's `COST` is evaluated by in constants,
    /// run at run time with exact values: sums and multiples per quantity,
    /// the larger of each quantity, a unit's one value and its bytes, a held
    /// allocation, and a cost's children paying each fixed part and a
    /// rounding unit per byte, in sixty-fourths.
    #[test]
    fn the_cost_algebra_sums_scales_and_bounds_each_quantity() {
        let a = bound(1, 2, 3, 4, 5);
        let b = bound(10, 1, 30, 2, 50);
        let zero = ResourceBound::default();
        assert_eq!(plus(a, b), bound(11, 3, 33, 6, 55));
        assert_eq!(times(a, 3), bound(3, 6, 9, 12, 15));
        assert_eq!(larger(a, b), bound(10, 2, 30, 4, 50));
        assert_eq!(unit(5), bound(1, 5, 0, 0, 0));
        assert_eq!(held(7), bound(0, 0, 7, 7, 7));
        let fixed = ConstructionCost::fixed(a);
        assert_eq!(
            fixed,
            ConstructionCost {
                fixed: a,
                per_byte: zero
            }
        );
        let per_byte = ConstructionCost::per_byte(b);
        assert_eq!(
            per_byte,
            ConstructionCost {
                fixed: zero,
                per_byte: bound(640, 64, 1920, 128, 3200)
            }
        );
        let both = ConstructionCost {
            fixed: a,
            per_byte: bound(640, 64, 1920, 128, 3200),
        };
        assert_eq!(fixed.plus(per_byte), both);
        assert_eq!(fixed.larger(per_byte), both);
        assert_eq!(
            ConstructionCost::fixed(b).larger(fixed),
            ConstructionCost::fixed(bound(10, 2, 30, 4, 50))
        );
        // Each child's fixed part and one rounding unit, (2, 3, 4, 5, 6),
        // paid at 64 sixty-fourths a byte beside its own per-byte part.
        assert_eq!(
            both.children(),
            ConstructionCost {
                fixed: zero,
                per_byte: bound(768, 256, 2176, 448, 3584)
            }
        );
        // A scalar: one write of its own bytes and one step, nothing held.
        assert_eq!(
            scalar_cost::<u64>(),
            ConstructionCost::fixed(bound(2, 8, 0, 0, 0))
        );
        assert_eq!(scalar_cost::<u64>(), <u64 as InPlace<Limits>>::COST);
    }

    #[test]
    #[should_panic(expected = "a construction cost exceeds u64")]
    fn a_cost_sum_beyond_u64_panics() {
        plus(bound(u64::MAX, 0, 0, 0, 0), bound(1, 0, 0, 0, 0));
    }

    #[test]
    #[should_panic(expected = "a construction cost exceeds u64")]
    fn a_cost_multiple_beyond_u64_panics() {
        times(bound(0, u64::MAX, 0, 0, 0), 2);
    }

    /// A binding that does not implement absence keeps the default: an
    /// omitted field is rejected as a missing key, nothing admitted and the
    /// value left uninitialized.
    #[test]
    fn an_omitted_field_of_a_binding_without_absence_is_a_missing_key() {
        let mut value = MaybeUninit::<u64>::uninit();
        let mut state = <u64 as Reclaim<Limits>>::INITIAL;
        // SAFETY: the test owns the destination and pairs it with its
        // initial state; nothing else reaches either while the slot lives.
        let slot = unsafe {
            Slot::new(
                Place::<u64, Build>::root(NonNull::from(&mut value)),
                &mut state,
            )
        };
        let mut m = Limits::unlimited().logged();
        assert!(matches!(
            <u64 as InPlace<Limits>>::build_absent(slot, &mut m),
            Err(DecodeError::Invalid(crate::Error::MissingMapKey))
        ));
        assert_eq!(state, Written::Empty, "a refused omission initialized");
        assert_eq!(m.attempts(), 0, "a refused omission admitted work");
    }
}
