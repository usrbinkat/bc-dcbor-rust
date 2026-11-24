//! Construction directly into a reclamation-owned stable destination.
use super::reclamation::{
    Cleanup, Custody, PeekSlot, Reclaim, Reclaimed, Reduction, Slot, Uniform, Written,
};
use super::{Context, wrong_type};
use crate::bounded::decode::{ConstructResult, Kind};
use crate::bounded::{
    Allocator, BoundedError, BoundedResult, Budget, Caller, CustodySink, PermitsObserved,
    ResourceBound, Scan, Unit, add, mul, observed_all,
};

/// A step of a cost's composition in a `const fn` returning `Option`: the
/// value of `$cost`, or `None` from the enclosing function when a quantity
/// does not fit in `u64`. What `?` would be, which a `const fn` cannot use.
/// Every cost builder composes through it, and every `COST` item unwraps the
/// result with `const_cost!`.
macro_rules! cost {
    ($cost:expr) => {
        match $cost {
            Some(cost) => cost,
            None => return None,
        }
    };
}

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
mod minimal_bigint;
pub use minimal_bigint::{MinimalObservation, MinimalState};
mod stabilized;
pub use stabilized::{StabilizedObservation, StabilizedState};
#[doc(hidden)]
pub mod tagged;
pub(crate) mod text;
pub use text::{BufferClass, BufferCustody, BufferObservation, Phase as BufferPhase};
mod vector;
pub use vector::{
    ElementObservation, Phase as SequencePhase, SequenceClass, SequenceCustody, SequenceObservation,
};
#[cfg(feature = "custom-std-collections")]
mod btree;
/// Kani harness of the record check (R-C, check-on-consume): compiled only
/// by `cargo kani`.
#[cfg(kani)]
mod proofs;
#[cfg(feature = "custom-std-collections")]
pub use btree::{
    EntryObservation, Occupancy as TreeOccupancy, Phase as TreePhase, Shape as TreeShape,
    Sort as TreeSort, TreeCustody, TreeKey, TreeKeyView, TreeObservation, TreeProgress,
    occupancy as tree_occupancy,
};

/// What an engine entry reports of one unit of construction ([`build`],
/// [`build_part`] and their siblings): more to do, or the value done, the
/// binding's record of it verified against the place the entry projected
/// and the construction's identity, and consumed, in this step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Built {
    Progress,
    Done,
}

/// What a binding's construction step reports ([`InPlace::build_step`]):
/// more to do, or the value at its context's place initialized, with the
/// binding's record of it ([`Initialized`]), branded as its context is
/// (`'b`). A child record is verified and consumed in the step it arrives,
/// by the engine entry that dispatched the step, against the place that
/// entry projected; a mismatch is refused [`BoundedError::PlanMismatch`]
/// with the session's stage unchanged. A parent's coverage (its fields done,
/// its elements committed, its variant selected) is its state's record of
/// verified child records; it mints its own record from that coverage
/// ([`Assembly::assemble`]).
pub enum Building<'b, T> {
    Progress,
    Done(Initialized<'b, T>),
}

/// A context's brand ([`Context`]): a lifetime, invariant, that every
/// record minted from the context bears. A binding's step is generic over
/// it, so no record outlives the step that minted it: one kept in a static,
/// in the binding's state, or across steps, constructions or cleanup does
/// not type-check, and a record of another lifetime is no record of this
/// step. No counter and no shared state: the type system confines it.
#[derive(Clone, Copy)]
pub(crate) struct Brand<'b>(core::marker::PhantomData<fn(&'b ()) -> &'b ()>);

impl Brand<'_> {
    /// A brand: what a root context bears ([`Context::root`]). Any lifetime;
    /// a binding cannot tell which, so it cannot keep a record past its step.
    pub(crate) const fn new() -> Self {
        Self(core::marker::PhantomData)
    }
}

/// A binding's record that the value at one place is initialized: that
/// place's address, whether a session stepped the context it was minted
/// from, and the brand of that context's step (`'b`). Neither `Copy` nor
/// `Clone`, and no field public: a binding mints one only from its own
/// context's [`Assembly`], unsafely, and moves it into the
/// [`Building::Done`] it returns. It is confined to its step by its brand
/// and verified against its projected place on arrival (`verify`).
pub struct Initialized<'b, T> {
    place: usize,
    bound: bool,
    /// The value's type and the step's brand, both only named.
    marker: core::marker::PhantomData<(fn() -> T, Brand<'b>)>,
}

/// What a binding's [`Initialized`] is minted from: its context's place,
/// whether a session stepped it, and its brand ([`Context::assembly`]),
/// read before the context is consumed. Data, not a record of anything: only
/// [`Self::assemble`], whose contract is the binding's coverage, makes a
/// record of it.
pub struct Assembly<'b, T> {
    place: usize,
    bound: bool,
    /// The value's type and the step's brand, both only named.
    marker: core::marker::PhantomData<(fn() -> T, Brand<'b>)>,
}

impl<T> Clone for Assembly<'_, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for Assembly<'_, T> {}

// Written out rather than derived: a derive would bound `T`, the value's
// type, which a record only names.
impl<T> core::fmt::Debug for Initialized<'_, T> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Initialized")
            .field("place", &self.place)
            .field("bound", &self.bound)
            .finish()
    }
}

impl<T> core::fmt::Debug for Building<'_, T> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Progress => formatter.write_str("Progress"),
            Self::Done(record) => formatter.debug_tuple("Done").field(record).finish(),
        }
    }
}

impl<'b, T> Assembly<'b, T> {
    /// The assembly of the value at the place of address `place`, of a
    /// context a session stepped when `bound`: only [`Context::assembly`]
    /// makes one.
    pub(crate) const fn at(place: usize, bound: bool) -> Self {
        Self {
            place,
            bound,
            marker: core::marker::PhantomData,
        }
    }

    /// The binding's record that the value at this assembly's place is
    /// initialized.
    ///
    /// # Safety
    /// The state paired with this assembly's place records the value there
    /// initialized whole: its coverage is total, every unit of it recorded
    /// by the binding's own admitted write or by a child record verified and
    /// consumed in the step it arrived, and the place has not been reclaimed
    /// since.
    pub unsafe fn assemble(self) -> Initialized<'b, T> {
        Initialized {
            place: self.place,
            bound: self.bound,
            marker: core::marker::PhantomData,
        }
    }
}

/// A binding's report of `built`, what a shared engine (a buffer's copy, a
/// field map's, a sequence's) reported for the value at `assembly`'s place:
/// `Done` with the binding's record of it, minted from `assembly`. Generated
/// bindings call it for a newtype's field, built in the newtype's own bytes.
///
/// # Safety
/// When `built` is `Done`, as [`Assembly::assemble`]: the engine that
/// reported it recorded the value at `assembly`'s place initialized whole, in
/// the state paired with that place.
pub unsafe fn reported<'b, T>(built: Built, assembly: Assembly<'b, T>) -> Building<'b, T> {
    match built {
        Built::Progress => Building::Progress,
        // SAFETY: forwarded from the caller.
        Built::Done => Building::Done(unsafe { assembly.assemble() }),
    }
}

impl<'b, T> Initialized<'b, T> {
    /// Verify this record against `expected`, the assembly of the place the
    /// dispatching entry projected for this exact advance, and consume it.
    /// Its brand already confines it to this step. Refused
    /// [`BoundedError::PlanMismatch`], the binding-contract violation, when
    /// either was minted from a context no session stepped, or when the
    /// places differ: one deterministic refusal, never skipped and never a
    /// panic.
    pub(crate) fn verify<R>(self, expected: Assembly<'b, T>) -> Result<(), BoundedError<R>> {
        if !(self.bound && expected.bound) {
            return Err(BoundedError::PlanMismatch);
        }
        if self.place != expected.place {
            return Err(BoundedError::PlanMismatch);
        }
        Ok(())
    }
}

/// What constructing a value in place and its mandatory cleanup report and
/// hold at most, as an affine function of the bytes its subtree encodes:
/// `fixed` once, and `per_byte` sixty-fourths of each quantity per byte,
/// rounded up ([`Self::bound`]). Construction copies and checks in units of
/// several bytes, so whole units per byte would overstate long payloads.
///
/// A container's children each encode at least one byte, so each child's
/// fixed part, and the rounding of its per-byte part, are paid from the
/// container's bytes ([`Self::checked_children`]): costs compose linearly
/// however deeply values nest. `peak` holds everything a construction and
/// its children hold at once; `retained` is what the published value's
/// permits hold until its cleanup. Every composition is checked
/// ([`ResourceBound::checked_add`], [`ResourceBound::checked_mul`]): `None`
/// when a quantity does not fit in `u64`. A `COST` item unwraps its cost
/// with `const_cost!`, so an overflowing cost fails to compile (E0080); a
/// composition at run time refuses with [`BoundedError::Overflow`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConstructionCost {
    pub fixed: ResourceBound,
    pub per_byte: ResourceBound,
}

/// The sixty-fourths of a unit per byte a [`ConstructionCost`] counts in.
pub const PER_BYTE_SCALE: u64 = 64;

/// One admitted unit of one value and `bytes` bytes, as a cost: for an
/// [`InPlace`] implementation outside this crate, which reports its own work.
/// The bindings of this crate and derived bindings cost their admissions
/// from the charge each one makes ([`STEP_COST`]).
pub const fn unit(bytes: usize) -> ResourceBound {
    Unit::new(Caller, 1, bytes as u64).bound()
}

/// A binding's own unit of work: one value and the bytes it spans, given at
/// admission ([`admit`]).
const ADMITTED: Scan<Caller> = Scan::new(Caller, 1);

/// Admit one unit of one value and `bytes` bytes ([`ADMITTED`]): how a
/// binding outside this crate admits the work it reports, through the one
/// route, so its admission is observed ([`crate::bounded::Credit::Admit`])
/// as every engine admission is. Any budget: a construction step's policy,
/// or a cleanup step's capability ([`Cleanup`]).
pub fn admit<B: Budget>(budget: &mut B, bytes: usize) -> BoundedResult<(), B> {
    ADMITTED.admit(budget, bytes as u64)
}

/// One step of one value and no bytes: an inspection, a find or search
/// step, a transition, a rejection, a cleanup unit that frees nothing. The
/// operation driving the construction supplies the place.
const STEP: Unit<Caller> = Unit::new(Caller, 1, 0);

/// What one [`step`] admits.
pub const STEP_COST: ResourceBound = STEP.bound();

/// Admit one step ([`STEP_COST`]): how a derived binding admits its
/// inspections and its cleanup units, under any budget: a construction
/// step's policy, or a cleanup step's capability ([`Cleanup`]).
pub fn step<B: Budget>(budget: &mut B) -> BoundedResult<(), B> {
    STEP.admit(budget)
}

/// One unit over a whole `T` in place, writing it or dropping it in place:
/// one value and its bytes, a write extent checked where `T` is used.
pub(crate) const fn sized<T>() -> Unit<Caller> {
    const { Unit::written::<T>(Caller) }
}

/// One unit of each quantity: the rounding of a child's per-byte part, paid
/// from the bytes it encodes ([`ConstructionCost::checked_children`]).
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

    /// A cost of `whole` units of every quantity per byte, in sixty-fourths,
    /// or none when a quantity does not fit in `u64`.
    pub const fn checked_per_byte(whole: ResourceBound) -> Option<Self> {
        Some(Self {
            fixed: Self::ZERO.fixed,
            per_byte: cost!(whole.checked_mul(PER_BYTE_SCALE)),
        })
    }

    /// This cost and `other` for the same bytes, or none when a quantity
    /// does not fit in `u64`.
    pub const fn checked_add(self, other: Self) -> Option<Self> {
        Some(Self {
            fixed: cost!(self.fixed.checked_add(other.fixed)),
            per_byte: cost!(self.per_byte.checked_add(other.per_byte)),
        })
    }

    /// The larger of this cost and `other` in every quantity: either of two
    /// alternatives.
    pub const fn larger(self, other: Self) -> Self {
        Self {
            fixed: self.fixed.larger(other.fixed),
            per_byte: self.per_byte.larger(other.per_byte),
        }
    }

    /// Children of this cost within a container's bytes, each encoding at
    /// least one byte: every child's fixed part and the rounding of its
    /// per-byte part, one unit of each quantity, are paid per byte. None
    /// when a quantity does not fit in `u64`.
    pub const fn checked_children(self) -> Option<Self> {
        let paid = cost!(cost!(self.fixed.checked_add(ROUNDING)).checked_mul(PER_BYTE_SCALE));
        Some(Self {
            fixed: Self::ZERO.fixed,
            per_byte: cost!(self.per_byte.checked_add(paid)),
        })
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
pub(crate) fn rejected<R, A: Allocator>(a: &mut A) -> ConstructResult<R, A> {
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
/// An implementation keeps seven obligations beside its [`Reclaim`]'s, and
/// the `// SAFETY:` comment on it names each as `label:`
/// (`tests/unsafe_census.rs`, `UNSAFE_TRAITS`, which lists every
/// implementation). There is no synchronous Drop fallback.
///
/// - *admission*: each write is admitted before it executes.
/// - *state*: every successful write or acquired resource is represented in
///   the state before returning, on error too, from [`Reclaim::INITIAL`],
///   uninitialized storage; cleanup is valid after every call.
/// - *done*: `Done` means the destination is fully initialized.
/// - *escape*: no pointer escapes construction.
/// - *provenance*: the destination is reached only through its slot's place,
///   which keeps its provenance for its whole life: a place a step derives
///   within it stays valid in every later step.
/// - *order*: every method is sound for every call a slot's holder can make,
///   in any order: a build from a state it does not continue (completed,
///   cleaning up, or another phase's) is refused with
///   [`BoundedError::PlanMismatch`] and changes nothing.
/// - *cost*: [`Self::COST`] is not understated.
pub unsafe trait InPlace<A: Allocator>: Reclaim<A> {
    const OPTIONAL: bool = false;

    /// What constructing this value, by any of `build_step`, `build_present`
    /// and `build_absent`, and then its cleanup report and hold at most, on
    /// success or at any failure, for a subtree of any input. Understating
    /// it violates the unsafe implementation contract; every built-in and
    /// derived binding derives it from its own charges.
    const COST: ConstructionCost;

    /// Construct a present map field, distinct from standalone nullable
    /// values. Called only by the engine ([`build_present`]), under the
    /// session that binds the context's node entered as a present field.
    fn build_present<'b>(
        ctx: BindingContext<'b, '_, '_, '_, Self, A>,
        allocator: &mut A,
    ) -> ConstructResult<Building<'b, Self>, A> {
        Self::build_step(ctx, allocator)
    }
    /// Initialize an omitted map field, from the context of the map that
    /// omits it. Required fields reject omission.
    fn build_absent<'b>(
        _ctx: BindingContext<'b, '_, '_, '_, Self, A>,
        _allocator: &mut A,
    ) -> ConstructResult<Building<'b, Self>, A> {
        Err(crate::bounded::decode::DecodeError::Invalid(
            crate::Error::MissingMapKey,
        ))
    }
    /// One unit of construction of the value in the context's slot from its
    /// node. Called only by the engine: at the root ([`build`]), under the
    /// session that binds that node, the same node and document on every
    /// call and no call after completion or the start of cleanup; or as a
    /// part of a parent ([`build_part`]), whose own state continues it alike.
    /// A child is built through [`build_part`], its context projected from
    /// this one's slot ([`Context::part`]). `Done` carries the binding's
    /// record of the value initialized at its context's place
    /// ([`Building::Done`]), minted from the context's [`Assembly`]. The
    /// step is generic over the context's brand `'b`, which the record
    /// bears: the record cannot be kept past this step.
    fn build_step<'b>(
        ctx: BindingContext<'b, '_, '_, '_, Self, A>,
        allocator: &mut A,
    ) -> ConstructResult<Building<'b, Self>, A>;
}

/// Where a binding's session stands (ledger 29.64): the engine's record of
/// which node its construction is bound to and whether its cleanup has
/// begun. The binding's own state never moves it; only the engine's
/// transitions ([`build`], [`build_absent`], [`reclaim`]) do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Stage {
    /// Nothing bound, nothing built: the initial stage.
    Unbound,
    /// Bound to the node at `node`, entered as `entry`, construction in
    /// progress. An omitted field (`Entry::Absent`) binds the node of the
    /// map that omits it, the index its context carries: it continues only
    /// under that same map.
    Building { node: usize, entry: Entry },
    /// Construction complete from that node, entered that way.
    Built { node: usize, entry: Entry },
    /// Cleanup begun: no build is accepted again.
    Cleaning,
    /// Cleanup complete: terminal. Every reclaim reports `Done` admitting
    /// nothing; every build is refused.
    Released,
}

/// How a session's construction was entered: as a standalone value
/// ([`InPlace::build_step`]), as a present map field
/// ([`InPlace::build_present`]), or as an omitted one
/// ([`InPlace::build_absent`]). Bound with the node; a step in another mode
/// is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Entry {
    Standalone,
    Present,
    Absent,
}

// The stage is the tag, the entry and one index. Every sequence and B-tree
// record holds a session, and a record is written in one unit of at most a
// quantum ([`super::stable::Contract`]): a larger stage pushes a record of a
// 16-byte permit and a 24-byte binding state past it.
const _: () = assert!(
    core::mem::size_of::<Stage>() <= 16,
    "a session's stage fits the sequence record's write extent"
);

/// A binding's state within its session: the stage and the binding's own
/// state, held together wherever the binding's value is held. Fields are
/// private: only the engine's transitions change the stage.
pub struct Session<S> {
    stage: Stage,
    inner: S,
}

impl<S> Session<S> {
    /// A session of nothing bound over the binding's initial state.
    pub const fn new(inner: S) -> Self {
        Self {
            stage: Stage::Unbound,
            inner,
        }
    }

    /// Where the session stands.
    pub fn stage(&self) -> Stage {
        self.stage
    }
}

/// A session's observation: its stage and its binding's whole observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SessionObservation<O> {
    pub stage: Stage,
    pub inner: O,
}

impl<S: Custody> Custody for Session<S> {
    type Observation = SessionObservation<S::Observation>;

    fn observe(&mut self) -> Self::Observation {
        SessionObservation {
            stage: self.stage,
            inner: self.inner.observe(),
        }
    }
}

/// What a session's cleanup reads of its stage: whether the begin-cleanup
/// unit is still to come, cleanup is under way, or it is complete. The bound
/// node is not read by cleanup, so it is not part of the class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum StageClass {
    /// `Unbound`: one unit, straight to `Released`.
    Unbound,
    /// `Building` or `Built`: the begin-cleanup unit, then the binding's.
    Bound,
    Cleaning,
    Released,
}

/// The stage's cleanup class ([`StageClass`]).
pub const fn stage_class(stage: Stage) -> StageClass {
    match stage {
        Stage::Unbound => StageClass::Unbound,
        Stage::Building { .. } | Stage::Built { .. } => StageClass::Bound,
        Stage::Cleaning => StageClass::Cleaning,
        Stage::Released => StageClass::Released,
    }
}

// Two sessions of one stage class and one binding class clean up alike: the
// session's own cleanup reads only the stage class (one begin unit before
// the binding's, or none, or nothing at all once released), and the
// binding's cleanup is its reduction's, a simulation by its own argument.
impl<S: Reduction> Reduction for Session<S> {
    type Class = (StageClass, S::Class);

    fn class(observation: &Self::Observation) -> Self::Class {
        (stage_class(observation.stage), S::class(&observation.inner))
    }
}

// A complete session is `Built` (class `Bound`) over a complete binding.
impl<S: Uniform> Uniform for Session<S> {
    const COMPLETE: Self::Class = (StageClass::Bound, S::COMPLETE);
}

/// The binding's own slot within its session's: the same place, the inner
/// state as its custody.
fn inner<'s, T, S, M: super::reclamation::Mode>(
    slot: Slot<'s, T, Session<S>, M>,
) -> Slot<'s, T, S, M> {
    // SAFETY: the identity projection keeps the place; the inner state is
    // the binding's own custody of it, which the session wraps and never
    // changes itself.
    unsafe { slot.child(|value| value, |session| &mut session.inner) }
}

/// The session's bind unit and its begin-cleanup unit: one value each,
/// counted in every binding's `COST` ([`SESSION_COST`]).
const TRANSITION: Unit<Caller> = Unit::new(Caller, 1, 0);

/// What a session adds to its binding's cost: the bind unit and the
/// begin-cleanup unit.
pub const SESSION_COST: ResourceBound = ResourceBound {
    values: 2,
    bytes: 0,
    allocated: 0,
    peak: 0,
    retained: 0,
};

/// What a root binding costs, `cost` its own `COST`: that and its root
/// session's two transitions ([`SESSION_COST`]), counted once per root, by
/// the owned root and the standalone driver alike. None when a quantity does
/// not fit in `u64`.
pub const fn root_cost(cost: ConstructionCost) -> Option<ConstructionCost> {
    cost.checked_add(ConstructionCost::fixed(SESSION_COST))
}

/// A binding's context: its brand, its node, its document, its own slot and
/// the construction's pending acquisition.
pub type BindingContext<'b, 'c, 's, 'a, T, A> =
    Context<'b, 'c, 's, 'a, T, <T as Reclaim<A>>::State, A>;

/// A session's context: its brand, its node, its document, the slot of the
/// value with its session and the construction's pending acquisition, what
/// the engine's entry points take.
pub type SessionContext<'b, 'c, 's, 'a, T, A> =
    Context<'b, 'c, 's, 'a, T, Session<<T as Reclaim<A>>::State>, A>;

/// One unit of the session in `ctx`, entered as `entry`: an unbound session
/// binds the context's node (for an omitted field, the map's) and the entry
/// in one admitted unit; a bound one steps its binding (`step`) from the
/// same node entered the same way, the binding's record of its `Done`
/// verified against the session's place and consumed here
/// ([`Initialized::verify`]), completing the session. Any other call,
/// another node, another entry, after completion or once cleanup began, a
/// record that does not verify, is refused [`BoundedError::PlanMismatch`]
/// with the stage unchanged; the binding's refusals and errors leave the
/// stage as it was.
fn enter<'b, T: InPlace<A>, A: Allocator>(
    ctx: SessionContext<'b, '_, '_, '_, T, A>,
    entry: Entry,
    a: &mut A,
    step: impl FnOnce(
        BindingContext<'b, '_, '_, '_, T, A>,
        &mut A,
    ) -> ConstructResult<Building<'b, T>, A>,
) -> ConstructResult<Built, A> {
    let mut ctx = ctx;
    let node = ctx.index();
    // Read apart: a scrutinee's temporaries, the slot's borrow of the
    // context, would live through every arm.
    let stage = ctx.slot().custody().stage;
    match stage {
        Stage::Unbound => {
            TRANSITION.admit(a)?;
            ctx.slot().custody().stage = Stage::Building { node, entry };
            Ok(Built::Progress)
        }
        Stage::Building {
            node: bound,
            entry: entered,
        } if bound == node && entered == entry => {
            ctx.bind();
            // SAFETY: the binding's slot is the session's own slot projected
            // to the state the session wraps ([`inner`]).
            let mut binding = match unsafe {
                ctx.part(node, |slot| Ok::<_, core::convert::Infallible>(inner(slot)))
            } {
                Ok(binding) => binding,
                Err(never) => match never {},
            };
            // The root's own dispatch level, its declaration taken here.
            binding.descend::<A::Refusal>(T::DISPATCH_DEPTH)?;
            let expected = binding.assembly();
            let built = verified::<T, A::Refusal>(step(binding, a)?, expected)?;
            if built == Built::Done {
                ctx.slot().custody().stage = Stage::Built { node, entry };
            }
            Ok(built)
        }
        _ => Err(BoundedError::PlanMismatch.into()),
    }
}

/// One unit of construction of the session in `ctx` as a standalone value:
/// the engine's only entry to a binding's [`InPlace::build_step`] (`enter`).
pub fn build<T: InPlace<A>, A: Allocator>(
    ctx: SessionContext<'_, '_, '_, '_, T, A>,
    a: &mut A,
) -> ConstructResult<Built, A> {
    enter(ctx, Entry::Standalone, a, T::build_step)
}

/// One unit of construction of the session in `ctx` as a present map field:
/// the engine's only entry to [`InPlace::build_present`] (`enter`).
pub fn build_present<T: InPlace<A>, A: Allocator>(
    ctx: SessionContext<'_, '_, '_, '_, T, A>,
    a: &mut A,
) -> ConstructResult<Built, A> {
    enter(ctx, Entry::Present, a, T::build_present)
}

/// One unit of construction of the session in `ctx` as an omitted map
/// field, bound to the node of the map omitting it (the index its context
/// carries): the engine's only entry to
/// [`InPlace::build_absent`] (`enter`). A binding that rejects omission
/// rejects it before binding, nothing admitted.
pub fn build_absent<T: InPlace<A>, A: Allocator>(
    ctx: SessionContext<'_, '_, '_, '_, T, A>,
    a: &mut A,
) -> ConstructResult<Built, A> {
    if !T::OPTIONAL {
        return Err(crate::bounded::decode::DecodeError::Invalid(
            crate::Error::MissingMapKey,
        ));
    }
    enter(ctx, Entry::Absent, a, T::build_absent)
}

/// One unit of cleanup of the session in `slot`: the engine's only entry to
/// a binding's [`Reclaim::reclaim_step`]. An unbound session holds nothing
/// and is released in one admitted unit; a bound one begins cleanup in one
/// admitted unit, after which no build is accepted, then cleans its binding
/// up unit by unit; a released one reports `Done` and admits nothing. The
/// binding's refusals leave the stage as it was. Runs under `cleanup`, the
/// capability its root's driver minted ([`Cleanup`]).
pub fn reclaim<T: InPlace<A>, A: Allocator>(
    mut slot: Slot<'_, T, Session<T::State>>,
    cleanup: &mut Cleanup<'_, A>,
) -> BoundedResult<Reclaimed, A> {
    match slot.custody().stage {
        Stage::Unbound => {
            TRANSITION.admit(cleanup)?;
            slot.custody().stage = Stage::Released;
            Ok(Reclaimed::Done)
        }
        Stage::Building { .. } | Stage::Built { .. } => {
            TRANSITION.admit(cleanup)?;
            slot.custody().stage = Stage::Cleaning;
            Ok(Reclaimed::Progress)
        }
        Stage::Cleaning => {
            // The root's own dispatch level; a root reached by a fresh
            // capability (the standalone driver) declares here, one inside
            // a record continues the record's declaration.
            cleanup.declare(T::DISPATCH_DEPTH);
            let reclaimed =
                cleanup.descend(|cleanup| T::reclaim_step(inner(slot.reborrow()), cleanup))?;
            if reclaimed == Reclaimed::Done {
                slot.custody().stage = Stage::Released;
            }
            Ok(reclaimed)
        }
        Stage::Released => Ok(Reclaimed::Done),
    }
}

/// The most successful [`reclaim`] calls the session in `slot` still takes,
/// the one returning `Done` included: one when unbound or released; the
/// begin-cleanup unit and the binding's own count when bound; the binding's
/// count while cleaning. `None` when the count does not fit in `u64`: a
/// checked count, never saturated. Admits nothing and changes nothing.
pub fn remaining<T: InPlace<A>, A: Allocator>(
    mut slot: PeekSlot<'_, T, Session<T::State>>,
) -> Option<u64> {
    match slot.custody().stage {
        Stage::Unbound | Stage::Released => Some(1),
        Stage::Building { .. } | Stage::Built { .. } => {
            T::remaining(inner(slot.reborrow()))?.checked_add(1)
        }
        Stage::Cleaning => T::remaining(inner(slot.reborrow())),
    }
}

/// The permits the session in `slot` owns, reported inside the caller's
/// open group: its binding's, in every stage ([`Reclaim::observe_permits`]);
/// the session's own transitions hold none.
pub fn observe_permits<T: InPlace<A>, A: Allocator>(
    mut slot: PeekSlot<'_, T, Session<T::State>>,
    sink: &mut dyn CustodySink<A::Permit>,
) -> PermitsObserved {
    T::observe_permits(inner(slot.reborrow()), sink)
}

/// One unit of construction of a part of a parent binding (an element, a
/// field, a payload, an entry's key or value) as a standalone value: the
/// engine's dispatch to [`InPlace::build_step`] for a part. The part has no
/// session of its own: its context is projected from its parent's
/// ([`Context::part`]), whose own state records which node and phase the
/// part is at, and the parent is itself stepped only through the engine, so
/// the root's session guards the whole tree.
pub fn build_part<T: InPlace<A>, A: Allocator>(
    ctx: BindingContext<'_, '_, '_, '_, T, A>,
    a: &mut A,
) -> ConstructResult<Built, A> {
    dispatch_part(ctx, a, T::build_step)
}

/// [`build_part`] for a present map field ([`InPlace::build_present`]).
pub fn build_part_present<T: InPlace<A>, A: Allocator>(
    ctx: BindingContext<'_, '_, '_, '_, T, A>,
    a: &mut A,
) -> ConstructResult<Built, A> {
    dispatch_part(ctx, a, T::build_present)
}

/// [`build_part`] for an omitted map field ([`InPlace::build_absent`]), its
/// context the map's.
pub fn build_part_absent<T: InPlace<A>, A: Allocator>(
    ctx: BindingContext<'_, '_, '_, '_, T, A>,
    a: &mut A,
) -> ConstructResult<Built, A> {
    dispatch_part(ctx, a, T::build_absent)
}

/// The one dispatch of a part's step: one level deeper, refused past the
/// root's declaration; then the part's step, its `Done` record, branded as
/// its parent's context is, verified against the place its parent projected
/// for this exact advance (the context's own) and consumed here, in the
/// step it arrives ([`Initialized::verify`]). The projected place moves on
/// every advance (the next field, the element at the committed count, the
/// selected variant's payload), so a record presented twice cannot advance a
/// parent's coverage twice. A record that does not verify is refused
/// [`BoundedError::PlanMismatch`], and the parent's coverage, which it
/// advances only on `Done`, is unchanged.
fn dispatch_part<'b, T: InPlace<A>, A: Allocator>(
    ctx: BindingContext<'b, '_, '_, '_, T, A>,
    a: &mut A,
    step: impl FnOnce(
        BindingContext<'b, '_, '_, '_, T, A>,
        &mut A,
    ) -> ConstructResult<Building<'b, T>, A>,
) -> ConstructResult<Built, A> {
    let mut ctx = ctx;
    ctx.descend::<A::Refusal>(T::DISPATCH_DEPTH)?;
    let expected = ctx.assembly();
    Ok(verified(step(ctx, a)?, expected)?)
}

/// What a step reported (`building`), its `Done` record verified against
/// `expected`, the assembly of the place the dispatching entry projected for
/// this exact advance, and consumed here ([`Initialized::verify`]): the one
/// check every entry that dispatches a binding's or an engine's step makes
/// ([`enter`], [`dispatch_part`], [`fields::build_payload`]).
pub(crate) fn verified<'b, T, R>(
    building: Building<'b, T>,
    expected: Assembly<'b, T>,
) -> Result<Built, BoundedError<R>> {
    match building {
        Building::Progress => Ok(Built::Progress),
        Building::Done(record) => {
            record.verify(expected)?;
            Ok(Built::Done)
        }
    }
}

/// One unit of cleanup of a part ([`build_part`]): the engine's dispatch to
/// [`Reclaim::reclaim_step`] for a part, one dispatch level deeper, refused
/// past the root's declaration with the part unchanged.
pub fn reclaim_part<T: Reclaim<A>, A: Allocator>(
    slot: Slot<'_, T, T::State>,
    cleanup: &mut Cleanup<'_, A>,
) -> BoundedResult<Reclaimed, A> {
    cleanup.descend(|cleanup| T::reclaim_step(slot, cleanup))
}

/// The calls [`reclaim_part`] still takes from the part in `slot`
/// ([`Reclaim::remaining`]), `None` when they do not fit in `u64`.
pub fn remaining_part<T: Reclaim<A>, A: Allocator>(slot: PeekSlot<'_, T, T::State>) -> Option<u64> {
    T::remaining(slot)
}

/// The permits the part in `slot` owns ([`Reclaim::observe_permits`]): how
/// a parent reports its parts' permits, as it counts their cleanup.
pub fn observe_part<T: Reclaim<A>, A: Allocator>(
    slot: PeekSlot<'_, T, T::State>,
    sink: &mut dyn CustodySink<A::Permit>,
) -> PermitsObserved {
    T::observe_permits(slot, sink)
}

/// A value an owned operation builds in a scope record and moves between
/// threads with it: the value and its construction state are both `Send`.
/// Every binding meeting both is one; owned construction, typed decoding and
/// owned preparation state this one bound.
pub trait Transferable<A: Allocator>: InPlace<A, State: Send> + Send {}

impl<T: InPlace<A, State: Send> + Send, A: Allocator> Transferable<A> for T {}

macro_rules! integers {
    ($($ty:ty),* $(,)?) => {$(
        // SAFETY: initial: `Written::Empty`, nothing written. state: `Written`
        // records whether the integer is written; it acquires nothing.
        // admission: the one cleanup unit is admitted before it marks the
        // state, a refusal changing nothing. cleanup: integer storage owns no
        // child resources and has no destructor; cleanup only marks it empty,
        // allocating nothing and never unwinding. done: nothing initialized
        // owns anything. order: the unit is the same from either state,
        // `Done` each time. depth: a leaf, the default 1. count: one call.
        unsafe impl<A: Allocator> Reclaim<A> for $ty {
            type State = Written;
            const INITIAL: Written = Written::Empty;

            /// An integer owns nothing, so its one cleanup unit, from either
            /// state, only marks it empty: repeated, it changes nothing.
            fn reclaim_step(
                mut slot: Slot<'_, Self, Written>, cleanup: &mut Cleanup<'_, A>,
            ) -> BoundedResult<Reclaimed, A> {
                STEP.admit(cleanup)?;
                *slot.custody() = Written::Empty;
                Ok(Reclaimed::Done)
            }

            /// One call, which is `Done`.
            fn remaining(_: PeekSlot<'_, Self, Written>) -> Option<u64> {
                Some(1)
            }

            /// An integer owns no permit.
            fn observe_permits(
                _: PeekSlot<'_, Self, Written>,
                _: &mut dyn CustodySink<A::Permit>,
            ) -> PermitsObserved {
                PermitsObserved::Complete
            }
        }
        // SAFETY: admission: `sized::<Self>()` is admitted before the only
        // write. state: the state becomes `Initialized` with the write; a
        // wrong kind or an out-of-range value returns with the destination
        // uninitialized and the state empty. done: `Done` follows the whole
        // value's write. escape: nothing derived from the place is returned
        // or kept. provenance: the write goes through the slot's place.
        // order: a build from any state but `Empty` is refused `PlanMismatch`,
        // nothing changed. cost: `scalar_cost::<$ty>()` is the one admitted
        // unit and the cleanup step.
        unsafe impl<A: Allocator> InPlace<A> for $ty {
            const COST: ConstructionCost = crate::const_cost!(scalar_cost::<$ty>());

            fn build_step<'b>(
                ctx: BindingContext<'b, '_, '_, '_, Self, A>, a: &mut A,
            ) -> ConstructResult<Building<'b, Self>, A> {
                let node = ctx.node();
                let assembly = ctx.assembly();
                let mut slot = ctx.into_slot();
                let (place, state) = slot.parts();
                if *state != Written::Empty { return Err(BoundedError::PlanMismatch.into()); }
                sized::<Self>().admit(a)?;
                let number = match node.map(|node| node.kind()) {
                    Some(Kind::Unsigned(n)) => i128::from(n),
                    Some(Kind::Negative(n)) => i128::from(n),
                    _ => return Err(wrong_type()),
                };
                let value = Self::try_from(number).map_err(|_| crate::bounded::decode::DecodeError::Invalid(crate::Error::OutOfRange))?;
                // SAFETY: the slot pairs the place with this state, which is
                // empty: nothing to drop, the write admitted above.
                unsafe { place.write(state, value) };
                *state = Written::Initialized;
                // SAFETY: the whole value was written above, by an admitted
                // unit, and the state records it.
                Ok(Building::Done(unsafe { assembly.assemble() }))
            }
        }
    )*};
}

integers!(u8, u16, u32, u64, usize, i8, i16, i32, i64);

/// The cost of a scalar built by one admitted write of its own bytes, and
/// reclaimed by one step; nothing is allocated. A refused kind or range is
/// found by that same write unit.
pub(crate) const fn scalar_cost<T>() -> Option<ConstructionCost> {
    Some(ConstructionCost::fixed(cost!(
        sized::<T>().bound().checked_add(STEP_COST)
    )))
}

#[cfg(test)]
mod tests {
    use super::super::reclamation::{Build, Place};
    use super::super::stable::Pending;
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
        assert_eq!(a.checked_add(b), Some(bound(11, 3, 33, 6, 55)));
        assert_eq!(a.checked_mul(3), Some(bound(3, 6, 9, 12, 15)));
        assert_eq!(a.larger(b), bound(10, 2, 30, 4, 50));
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
        let per_byte = ConstructionCost::checked_per_byte(b).unwrap();
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
        assert_eq!(fixed.checked_add(per_byte), Some(both));
        assert_eq!(fixed.larger(per_byte), both);
        assert_eq!(
            ConstructionCost::fixed(b).larger(fixed),
            ConstructionCost::fixed(bound(10, 2, 30, 4, 50))
        );
        // Each child's fixed part and one rounding unit, (2, 3, 4, 5, 6),
        // paid at 64 sixty-fourths a byte beside its own per-byte part.
        assert_eq!(
            both.checked_children(),
            Some(ConstructionCost {
                fixed: zero,
                per_byte: bound(768, 256, 2176, 448, 3584)
            })
        );
        // A scalar: one write of its own bytes and one step, nothing held.
        assert_eq!(
            scalar_cost::<u64>(),
            Some(ConstructionCost::fixed(bound(2, 8, 0, 0, 0)))
        );
        assert_eq!(scalar_cost::<u64>(), Some(<u64 as InPlace<Limits>>::COST));
    }

    /// A composition beyond `u64`, in any quantity and by any operation, is
    /// none, evaluated in a constant as at run time, and refused at run time
    /// as an overflow, which classifies as invalid input: no cost operation
    /// panics. In a `COST` item the same none fails to compile
    /// (`const_cost!`; the `compile_fail` cases of `dcbor-derive`'s UI
    /// suite).
    #[test]
    fn a_cost_beyond_u64_is_refused_never_panicking() {
        let most = |at: usize| {
            let mut quantities = [0u64; 5];
            quantities[at] = u64::MAX;
            bound(
                quantities[0],
                quantities[1],
                quantities[2],
                quantities[3],
                quantities[4],
            )
        };
        for at in 0..5 {
            assert_eq!(most(at).checked_add(most(at)), None, "quantity {at}");
            assert_eq!(most(at).checked_mul(2), None, "quantity {at}");
            assert_eq!(
                ConstructionCost::checked_per_byte(most(at)),
                None,
                "quantity {at}"
            );
            let fixed = ConstructionCost::fixed(most(at));
            assert_eq!(fixed.checked_add(fixed), None, "quantity {at}");
            assert_eq!(fixed.checked_children(), None, "quantity {at}");
            let per_byte = ConstructionCost {
                fixed: ResourceBound::default(),
                per_byte: most(at),
            };
            assert_eq!(per_byte.checked_add(per_byte), None, "quantity {at}");
            assert_eq!(per_byte.checked_children(), None, "quantity {at}");
        }
        const OVERFLOWED: Option<ResourceBound> = ResourceBound {
            values: u64::MAX,
            bytes: 0,
            allocated: 0,
            peak: 0,
            retained: 0,
        }
        .checked_add(STEP_COST);
        assert_eq!(OVERFLOWED, None);
        let refused = most(1)
            .checked_mul(2)
            .ok_or(BoundedError::<()>::Overflow)
            .unwrap_err();
        assert_eq!(refused, BoundedError::Overflow);
        assert_eq!(
            crate::bounded::Failure::class(&refused),
            crate::bounded::Class::Invalid
        );
    }

    /// A binding that does not implement absence keeps the default: an
    /// omitted field, entered through the engine, is rejected as a missing
    /// key before its session binds, nothing admitted, the session unbound
    /// and the value left uninitialized.
    #[test]
    fn an_omitted_field_of_a_binding_without_absence_is_a_missing_key() {
        let mut parser = Limits::unlimited();
        let document = crate::bounded::decode::decode(&[0x07], 1, &mut parser).unwrap();
        let mut value = MaybeUninit::<u64>::uninit();
        let mut session = Session::new(<u64 as Reclaim<Limits>>::INITIAL);
        // SAFETY: the test owns the destination and pairs it with its
        // initial session; nothing else reaches either while the slot lives.
        let slot = unsafe {
            Slot::new(
                Place::<u64, Build>::root(NonNull::from(&mut value)),
                &mut session,
            )
        };
        let mut m = Limits::unlimited();
        let mut pending = Pending::deferred();
        assert!(matches!(
            build_absent::<u64, Limits>(Context::root(&document, slot, &mut pending), &mut m),
            Err(DecodeError::Invalid(crate::Error::MissingMapKey))
        ));
        assert!(pending.is_idle(), "a refused omission bound an acquisition");
        assert_eq!(session.stage(), Stage::Unbound, "a refused omission bound");
        assert_eq!(
            session.inner,
            Written::Empty,
            "a refused omission initialized"
        );
        assert_eq!(m.attempts(), 0, "a refused omission admitted work");
    }

    /// The adversarial schedules of the root session (ledger 29.64), each
    /// through the engine's entry points on one destination and its session.
    /// No safe API steps a session with another node or document: a root
    /// context is node 0 of the document its operation holds
    /// ([`Context::root`]), and a part's context is projected from its
    /// parent's ([`Context::part`]). These schedules reach the refusals with
    /// the crate-internal projection, the same session's slot at another
    /// index, the only way to present the session another node at all.
    mod adversarial {
        use super::*;
        use crate::bounded::decode::decode;
        use crate::{MinimalBigInt, StabilizedText};
        use alloc::string::String;

        extern crate alloc;

        /// A destination of `T`, its session, initial, and the pending
        /// credit of its construction, kept apart from both.
        struct Root<T: InPlace<Limits>> {
            value: MaybeUninit<T>,
            session: Session<T::State>,
            pending: Pending<<Limits as crate::bounded::Budget>::Origin>,
        }

        impl<T: InPlace<Limits>> Root<T> {
            fn new() -> Self {
                Self {
                    value: MaybeUninit::uninit(),
                    session: Session::new(T::INITIAL),
                    pending: Pending::deferred(),
                }
            }

            /// The destination's slot with its session.
            fn slot(&mut self) -> Slot<'_, T, Session<T::State>> {
                // SAFETY: the test owns the destination and pairs it with its
                // session, created initial; every access to either is
                // through this slot, minted from the same place each time.
                unsafe {
                    Slot::new(
                        Place::<T, Build>::root(NonNull::from(&mut self.value)),
                        &mut self.session,
                    )
                }
            }

            /// The root context over `document`: the slot and the pending
            /// credit, disjoint fields, each borrowed for the step.
            fn context<'c, 'd>(
                &mut self,
                document: &'c crate::bounded::decode::Document<'d, crate::bounded::Reservation>,
            ) -> Context<'c, 'c, '_, 'd, T, Session<T::State>, Limits> {
                // SAFETY: as [`Self::slot`].
                let slot = unsafe {
                    Slot::new(
                        Place::<T, Build>::root(NonNull::from(&mut self.value)),
                        &mut self.session,
                    )
                };
                Context::root(document, slot, &mut self.pending)
            }
        }

        /// One engine unit of `root` as a standalone value from node `index`
        /// of `document`: the root context, moved to `index` by the
        /// crate-internal projection of the same slot.
        fn step_at<T: InPlace<Limits>>(
            document: &crate::bounded::decode::Document<'_, crate::bounded::Reservation>,
            root: &mut Root<T>,
            index: usize,
            a: &mut Limits,
        ) -> ConstructResult<Built, Limits> {
            let mut ctx = root.context(document);
            // SAFETY: the identity projection: the same session's own slot.
            let moved = match unsafe { ctx.part(index, Ok::<_, core::convert::Infallible>) } {
                Ok(moved) => moved,
                Err(never) => match never {},
            };
            build::<T, Limits>(moved, a)
        }

        /// A refusal of the session's that changed nothing: the session's
        /// observation and the policy's attempts as before.
        fn refused_unchanged<T: InPlace<Limits>>(
            result: ConstructResult<Built, Limits>,
            root: &mut Root<T>,
            before: SessionObservation<<T::State as Custody>::Observation>,
            attempts: usize,
            a: &Limits,
            what: &str,
        ) {
            assert!(
                matches!(
                    result,
                    Err(DecodeError::Resource(BoundedError::PlanMismatch))
                ),
                "{what}: {result:?}"
            );
            assert_eq!(root.session.observe(), before, "{what}: the session moved");
            assert_eq!(a.attempts(), attempts, "{what}: admitted work");
        }

        /// Same document, other node: a session bound to node 1, a text
        /// `"ab"` checked to its end, refuses node 2, an equal-length text
        /// holding U+0378, so the check of one node is never the copy of
        /// another.
        #[test]
        fn a_stabilized_text_bound_to_one_node_refuses_another() {
            // ["ab", "\u{378}"]: two texts of two bytes each.
            let wire = [0x82, 0x62, b'a', b'b', 0x62, 0xcd, 0xb8];
            let mut parser = Limits::unlimited();
            let document = decode(&wire, 2, &mut parser).unwrap();
            let mut a = Limits::unlimited();
            let mut root = Root::<StabilizedText>::new();
            // The bind unit, then the check's window over "ab".
            for _ in 0..2 {
                assert_eq!(
                    step_at(&document, &mut root, 1, &mut a).unwrap(),
                    Built::Progress
                );
            }
            assert!(matches!(
                root.session.stage(),
                Stage::Building { node: 1, .. }
            ));
            let before = root.session.observe();
            let attempts = a.attempts();
            let result = step_at(&document, &mut root, 2, &mut a);
            refused_unchanged(result, &mut root, before, attempts, &a, "another node");
            // The bound node continues, and the text is built from it.
            loop {
                if step_at(&document, &mut root, 1, &mut a).unwrap() == Built::Done {
                    break;
                }
            }
            let (place, session) = root.slot().into_parts();
            // SAFETY: construction reported the text written.
            assert_eq!(unsafe { place.get(&*session) }.as_str(), "ab");
            drain(&mut root, &mut a);
        }

        /// Same document, other node: a minimal big integer whose sign was
        /// read from node 1 (`-1`) refuses to take its magnitude from node 2
        /// (`1`).
        #[test]
        fn a_minimal_big_integer_takes_sign_and_magnitude_from_one_node() {
            // [-1, 1]
            let wire = [0x82, 0x20, 0x01];
            let mut parser = Limits::unlimited();
            let document = decode(&wire, 2, &mut parser).unwrap();
            let mut a = Limits::unlimited();
            let mut root = Root::<MinimalBigInt>::new();
            // The bind unit, then the sign from node 1.
            for _ in 0..2 {
                assert_eq!(
                    step_at(&document, &mut root, 1, &mut a).unwrap(),
                    Built::Progress
                );
            }
            let before = root.session.observe();
            let attempts = a.attempts();
            let result = step_at(&document, &mut root, 2, &mut a);
            refused_unchanged(result, &mut root, before, attempts, &a, "another node");
            loop {
                if step_at(&document, &mut root, 1, &mut a).unwrap() == Built::Done {
                    break;
                }
            }
            let (place, session) = root.slot().into_parts();
            // SAFETY: construction reported the integer written.
            let value = unsafe { place.get(&*session) };
            assert_eq!(crate::CBOR::from(value), crate::CBOR::from(-1i64));
            drain(&mut root, &mut a);
        }

        /// A build after partial cleanup, after `Released`, and after an
        /// unbound session's cleanup is refused, nothing changed; a released
        /// session's cleanup admits nothing.
        #[test]
        fn no_build_follows_the_start_of_cleanup() {
            let wire = [0x62, b'a', b'b'];
            let mut parser = Limits::unlimited();
            let document = decode(&wire, 1, &mut parser).unwrap();
            let mut a = Limits::unlimited();
            // Partial cleanup: a text part built, then cleanup begun.
            let mut root = Root::<String>::new();
            for _ in 0..3 {
                step_at(&document, &mut root, 0, &mut a).unwrap();
            }
            assert_eq!(
                reclaim::<String, Limits>(root.slot(), &mut Cleanup::new(&mut a)).unwrap(),
                Reclaimed::Progress
            );
            assert_eq!(root.session.stage(), Stage::Cleaning);
            let (before, attempts) = (root.session.observe(), a.attempts());
            let result = step_at(&document, &mut root, 0, &mut a);
            refused_unchanged(
                result,
                &mut root,
                before,
                attempts,
                &a,
                "after partial cleanup",
            );
            drain(&mut root, &mut a);
            // Released: refused, and cleanup admits nothing more.
            assert_eq!(root.session.stage(), Stage::Released);
            let (before, attempts) = (root.session.observe(), a.attempts());
            let result = step_at(&document, &mut root, 0, &mut a);
            refused_unchanged(result, &mut root, before, attempts, &a, "after Released");
            assert_eq!(
                reclaim::<String, Limits>(root.slot(), &mut Cleanup::new(&mut a)).unwrap(),
                Reclaimed::Done
            );
            assert_eq!(
                a.attempts(),
                attempts,
                "a released session's cleanup admitted work"
            );
            // Unbound: released in one unit, then refused.
            let mut unbound = Root::<u64>::new();
            let attempts = a.attempts();
            assert_eq!(
                reclaim::<u64, Limits>(unbound.slot(), &mut Cleanup::new(&mut a)).unwrap(),
                Reclaimed::Done
            );
            assert_eq!(a.attempts(), attempts + 1, "one admitted unit");
            assert_eq!(unbound.session.stage(), Stage::Released);
            let (before, attempts) = (unbound.session.observe(), a.attempts());
            let result = step_at(&document, &mut unbound, 0, &mut a);
            refused_unchanged(
                result,
                &mut unbound,
                before,
                attempts,
                &a,
                "after unbound cleanup",
            );
            assert_eq!(a.live_bytes(), 0);
        }

        /// A session entered as a standalone value refuses to continue as a
        /// present map field, and one entered as a present field refuses to
        /// continue standalone: the entry is bound with the node.
        #[test]
        fn a_session_continues_only_as_it_was_entered() {
            let wire = [0x62, b'a', b'b'];
            let mut parser = Limits::unlimited();
            let document = decode(&wire, 1, &mut parser).unwrap();
            let mut a = Limits::unlimited();
            let mut root = Root::<String>::new();
            step_at(&document, &mut root, 0, &mut a).unwrap();
            assert!(matches!(
                root.session.stage(),
                Stage::Building {
                    node: 0,
                    entry: Entry::Standalone
                }
            ));
            let (before, attempts) = (root.session.observe(), a.attempts());
            let result = build_present::<String, Limits>(root.context(&document), &mut a);
            refused_unchanged(
                result,
                &mut root,
                before,
                attempts,
                &a,
                "standalone then present",
            );
            drain(&mut root, &mut a);
            let mut present = Root::<Option<String>>::new();
            build_present::<Option<String>, Limits>(present.context(&document), &mut a).unwrap();
            let (before, attempts) = (present.session.observe(), a.attempts());
            let result = step_at(&document, &mut present, 0, &mut a);
            refused_unchanged(
                result,
                &mut present,
                before,
                attempts,
                &a,
                "present then standalone",
            );
            drain(&mut present, &mut a);
            assert_eq!(a.live_bytes(), 0);
        }

        /// A wrapper dispatching its one `u64` as a part, declaring
        /// `DECLARED` levels: 2 is its true depth (its own and the
        /// scalar's), 1 understates it by one. Transparent, so the scalar is
        /// at the value's start, as its projections state.
        #[repr(transparent)]
        struct Wrapped<const DECLARED: usize>(u64);

        // SAFETY: the value is its one scalar, which the scalar's own state
        // describes; cleanup is the scalar's. `DECLARED` 1 understates the
        // depth on purpose: the run-time check refuses it.
        unsafe impl<A: Allocator, const DECLARED: usize> Reclaim<A> for Wrapped<DECLARED> {
            const DISPATCH_DEPTH: usize = DECLARED;
            type State = Written;
            const INITIAL: Written = Written::Empty;

            fn reclaim_step(
                slot: Slot<'_, Self, Written>,
                cleanup: &mut Cleanup<'_, A>,
            ) -> BoundedResult<Reclaimed, A> {
                // SAFETY: the scalar is the value's only field, at its start.
                let scalar = unsafe { slot.child(|value| value.cast::<u64>(), |state| state) };
                reclaim_part::<u64, A>(scalar, cleanup)
            }

            fn remaining(slot: PeekSlot<'_, Self, Written>) -> Option<u64> {
                // SAFETY: as above.
                let scalar = unsafe { slot.child(|value| value.cast::<u64>(), |state| state) };
                remaining_part::<u64, A>(scalar)
            }

            fn observe_permits(
                _: PeekSlot<'_, Self, Written>,
                _: &mut dyn CustodySink<A::Permit>,
            ) -> PermitsObserved {
                PermitsObserved::Complete
            }
        }

        // SAFETY: construction is the scalar's, at the same place and state.
        unsafe impl<A: Allocator, const DECLARED: usize> InPlace<A> for Wrapped<DECLARED> {
            const COST: ConstructionCost = <u64 as InPlace<A>>::COST;

            fn build_step<'b>(
                ctx: BindingContext<'b, '_, '_, '_, Self, A>,
                a: &mut A,
            ) -> ConstructResult<Building<'b, Self>, A> {
                let mut ctx = ctx;
                let index = ctx.index();
                let assembly = ctx.assembly();
                // SAFETY: the scalar is the value's only field, at its start,
                // with the value's own state: a part of this value.
                let scalar = match unsafe {
                    ctx.part(index, |slot| {
                        Ok::<_, core::convert::Infallible>(
                            slot.child(|value| value.cast::<u64>(), |state| state),
                        )
                    })
                } {
                    Ok(scalar) => scalar,
                    Err(never) => match never {},
                };
                let built = build_part::<u64, A>(scalar, a)?;
                // SAFETY: the value is its one scalar, whose record the part
                // entry verified and consumed in this step.
                Ok(unsafe { reported(built, assembly) })
            }
        }

        /// A binding understating its dispatch depth by one is refused at
        /// construction's dispatch past its declaration, nothing changed and
        /// nothing admitted; the same binding declaring its true depth
        /// builds and cleans up to `Done`. Planted control
        /// `tests/data/controls/depth-unchecked.patch` (the declaration not
        /// compared) builds it, failing "understated build".
        #[test]
        fn a_binding_understating_its_depth_is_refused_on_build() {
            let wire = [0x07];
            let mut parser = Limits::unlimited();
            let document = decode(&wire, 1, &mut parser).unwrap();
            let mut a = Limits::unlimited();
            // The bind unit, then the refused part entry.
            let mut root = Root::<Wrapped<1>>::new();
            assert_eq!(
                step_at(&document, &mut root, 0, &mut a).unwrap(),
                Built::Progress
            );
            let (before, attempts) = (root.session.observe(), a.attempts());
            let result = step_at(&document, &mut root, 0, &mut a);
            refused_unchanged(result, &mut root, before, attempts, &a, "understated build");
            // Its true depth: built from the node and cleaned up to `Done`.
            let mut root = Root::<Wrapped<2>>::new();
            loop {
                if step_at(&document, &mut root, 0, &mut a).unwrap() == Built::Done {
                    break;
                }
            }
            let (place, session) = root.slot().into_parts();
            // SAFETY: construction reported the value written.
            assert_eq!(unsafe { place.get(&*session) }.0, 7);
            drain(&mut root, &mut a);
            assert_eq!(root.session.stage(), Stage::Released);
            assert_eq!(a.live_bytes(), 0);
        }

        /// A binding understating its dispatch depth by one is refused at
        /// cleanup's dispatch past its declaration, the session and the
        /// policy unchanged: its construction bound the node, so its
        /// cleanup begins from `Building`, then dispatches the scalar. A
        /// separate test from construction's refusal, so each fails on its
        /// own. Planted control `tests/data/controls/depth-unchecked.patch`
        /// makes the step complete, failing "understated cleanup".
        #[test]
        fn a_binding_understating_its_depth_is_refused_on_cleanup() {
            let wire = [0x07];
            let mut parser = Limits::unlimited();
            let document = decode(&wire, 1, &mut parser).unwrap();
            let mut a = Limits::unlimited();
            let mut root = Root::<Wrapped<1>>::new();
            // The bind unit: `Building`, the value empty.
            assert_eq!(
                step_at(&document, &mut root, 0, &mut a).unwrap(),
                Built::Progress
            );
            // Cleanup begun, then the refused part entry.
            assert_eq!(
                reclaim::<Wrapped<1>, Limits>(root.slot(), &mut Cleanup::new(&mut a)).unwrap(),
                Reclaimed::Progress
            );
            let (before, attempts) = (root.session.observe(), a.attempts());
            assert_eq!(
                reclaim::<Wrapped<1>, Limits>(root.slot(), &mut Cleanup::new(&mut a)),
                Err(BoundedError::PlanMismatch),
                "understated cleanup"
            );
            assert_eq!(
                root.session.observe(),
                before,
                "understated cleanup: the session moved"
            );
            assert_eq!(a.attempts(), attempts, "understated cleanup: admitted work");
        }

        /// The deepest dispatch level `T` reaches built from `wire` by the
        /// standalone driver, `inspect`ed once built, and cleaned up to
        /// `Done`.
        #[cfg(feature = "std")]
        fn measured<T: InPlace<Limits>>(wire: &[u8], inspect: impl FnOnce(&T)) -> usize {
            use super::super::super::Standalone;
            let mut parser = Limits::unlimited();
            let document = decode(wire, 8, &mut parser).unwrap();
            let mut a = Limits::unlimited();
            let mut value = MaybeUninit::<T>::uninit();
            let deepest = super::super::super::reclamation::deepest_reached(|| {
                let mut driver = Standalone::<T, Limits>::new(&document, &mut value);
                while driver.build_step(&mut a).unwrap() != Built::Done {}
                inspect(driver.value().expect("a value built to `Done` is readable"));
                while driver.reclaim_step(&mut a).unwrap() != Reclaimed::Done {}
            });
            assert_eq!(a.live_bytes(), 0, "{}", core::any::type_name::<T>());
            deepest
        }

        /// Records derived by the crate's own `CBORBoundedDecodable`, the
        /// generated code itself (the crate names itself `dcbor` in its
        /// tests): a record of scalars, records nesting it one and two
        /// levels deeper, and an enum.
        #[cfg(all(feature = "std", feature = "derive"))]
        mod derived {
            use crate::CBORBoundedDecodable;

            #[derive(CBORBoundedDecodable)]
            pub(super) struct Scalars {
                #[cbor(n = 0)]
                pub(super) count: u64,
                #[cbor(n = 1)]
                pub(super) flag: bool,
            }

            #[derive(CBORBoundedDecodable)]
            pub(super) struct Nested {
                #[cbor(n = 0)]
                pub(super) inner: Scalars,
            }

            #[derive(CBORBoundedDecodable)]
            pub(super) struct Deeper {
                #[cbor(n = 0)]
                pub(super) nested: Nested,
            }

            #[derive(CBORBoundedDecodable)]
            #[repr(u8)]
            pub(super) enum Choice {
                #[cbor(n = 0)]
                Empty,
                #[cbor(n = 1)]
                Count(u64),
            }
        }

        /// The declaration census: for every binding of this crate at its
        /// deepest fixture, its declared dispatch depth less the deepest
        /// level its construction and cleanup reach, exactly. 0 for the
        /// leaves, the sequences and the tree; 1 for the two options,
        /// which declare one level more than they dispatch, kept for the
        /// composed declarations; 5 per derived level for derived records
        /// and enums, read from the `DISPATCH_DEPTH` the derive generated,
        /// each built value read back. A change in either direction fails
        /// here and is re-recorded deliberately. Planted control
        /// `tests/data/controls/derive-depth-understated.patch` (the derive
        /// adding 5 over its deepest field) fails "Scalars: declared 6,
        /// measured 2". The records (`Parsed`,
        /// `Constructed`, `Planned`) are measured through their public
        /// steps (`construct`'s census), not the standalone driver.
        #[cfg(feature = "std")]
        #[test]
        fn every_bindings_declaration_exceeds_its_dispatch_by_its_recorded_margin() {
            use super::super::StableOption;
            use crate::{ByteString, MinimalBigInt, StabilizedText};
            fn inspected<T: InPlace<Limits>>(
                wire: &[u8],
                expected: usize,
                inspect: impl FnOnce(&T),
            ) {
                let measured = measured::<T>(wire, inspect);
                assert_eq!(
                    <T as Reclaim<Limits>>::DISPATCH_DEPTH - measured,
                    expected,
                    "{}: declared {}, measured {measured}",
                    core::any::type_name::<T>(),
                    <T as Reclaim<Limits>>::DISPATCH_DEPTH
                );
            }
            fn margin<T: InPlace<Limits>>(wire: &[u8], expected: usize) {
                inspected::<T>(wire, expected, |_| {});
            }
            // Leaves: the root level alone.
            margin::<u64>(&[0x07], 0);
            margin::<bool>(&[0xf5], 0);
            margin::<String>(&[0x62, b'a', b'b'], 0);
            margin::<ByteString>(&[0x42, 1, 2], 0);
            margin::<StabilizedText>(&[0x62, b'a', b'b'], 0);
            margin::<MinimalBigInt>(&[0x07], 0);
            // Sequences: their own level and their element's.
            margin::<Vec<u64>>(&[0x81, 0x07], 0);
            margin::<[u64; 1]>(&[0x81, 0x07], 0);
            margin::<Vec<Vec<String>>>(&[0x81, 0x81, 0x61, b'a'], 0);
            // Options: one level over what they dispatch.
            margin::<Option<u64>>(&[0x07], 1);
            margin::<Option<Vec<u64>>>(&[0x81, 0x07], 1);
            margin::<StableOption<u64, Limits>>(&[0x07], 1);
            // A present option within a sequence: the option's margin.
            margin::<Vec<Option<u64>>>(&[0x81, 0x07], 1);
            // Derived: the generated declaration is its deepest field's and
            // 6, the record or enum dispatching one level over its fields,
            // so 5 over what it dispatches, per derived level.
            #[cfg(feature = "derive")]
            {
                use derived::{Choice, Deeper, Nested, Scalars};
                // {0: 7, 1: true}
                let scalars = [0xa2, 0x00, 0x07, 0x01, 0xf5];
                inspected::<Scalars>(&scalars, 5, |value| {
                    assert_eq!((value.count, value.flag), (7, true));
                });
                // {0: {0: 7, 1: true}}
                let nested = [0xa1, 0x00, 0xa2, 0x00, 0x07, 0x01, 0xf5];
                inspected::<Nested>(&nested, 10, |value| {
                    assert_eq!((value.inner.count, value.inner.flag), (7, true));
                });
                // {0: {0: {0: 7, 1: true}}}
                let deeper = [0xa1, 0x00, 0xa1, 0x00, 0xa2, 0x00, 0x07, 0x01, 0xf5];
                inspected::<Deeper>(&deeper, 15, |value| {
                    let inner = &value.nested.inner;
                    assert_eq!((inner.count, inner.flag), (7, true));
                });
                // [1, 7]: the variant of discriminant 1 and its payload.
                inspected::<Choice>(&[0x82, 0x01, 0x07], 5, |value| {
                    assert!(matches!(value, Choice::Count(7)));
                });
            }
        }

        /// The run-time checks on a binding's record of its value
        /// ([`Initialized`]). Its brand confines a record to the step that
        /// minted it, which the compiler enforces (the `record_*` fixtures
        /// of `dcbor-derive/tests/ui/fail`); within that step, the record is
        /// verified on arrival against the place its dispatching entry
        /// projected, and against a context a session stepped, and anything
        /// else is refused [`BoundedError::PlanMismatch`]. Each check is
        /// reached by a step that forges its record from its own context's
        /// assembly, through each dispatching entry, and each has its
        /// planted control in `tests/data/controls`, named by its test.
        #[cfg(feature = "std")]
        mod records {
            use super::*;

            /// One part dispatch of `root`'s `u8` as `enter` projects it,
            /// the context marked stepped by a session when `bound`, its
            /// step a forger returning a record of the place `offset` bytes
            /// past its own. Nothing is written and nothing admitted: the
            /// record is never used to reach the value.
            fn forged_part(
                document: &crate::bounded::decode::Document<'_, crate::bounded::Reservation>,
                root: &mut Root<u8>,
                a: &mut Limits,
                bound: bool,
                offset: usize,
            ) -> ConstructResult<Built, Limits> {
                let mut ctx = root.context(document);
                if bound {
                    ctx.bind();
                }
                // SAFETY: the session's own slot projected to the state the
                // session wraps, as `enter` projects it.
                let binding = match unsafe {
                    ctx.part(0, |slot| Ok::<_, core::convert::Infallible>(inner(slot)))
                } {
                    Ok(binding) => binding,
                    Err(never) => match never {},
                };
                dispatch_part::<u8, Limits>(binding, a, |ctx, _| {
                    let own = ctx.assembly();
                    // SAFETY: the forged record is never used to reach a
                    // place: the entry under test refuses it, or the test
                    // reads nothing through it.
                    Ok(Building::Done(unsafe {
                        Assembly::at(own.place + offset, own.bound).assemble()
                    }))
                })
            }

            /// One root step of `root`'s session through `enter`, its
            /// binding's step a forger returning a record of the place
            /// `offset` bytes past its own: the first call binds the node,
            /// every later one steps the forger.
            fn forged_root(
                document: &crate::bounded::decode::Document<'_, crate::bounded::Reservation>,
                root: &mut Root<u8>,
                a: &mut Limits,
                offset: usize,
            ) -> ConstructResult<Built, Limits> {
                enter::<u8, Limits>(root.context(document), Entry::Standalone, a, |ctx, _| {
                    let own = ctx.assembly();
                    // SAFETY: as in `forged_part`.
                    Ok(Building::Done(unsafe {
                        Assembly::at(own.place + offset, own.bound).assemble()
                    }))
                })
            }

            /// A part's record of another place, the next byte, is refused
            /// by the part entry, nothing admitted; the same forgery at the
            /// part's own place verifies, so the refusal is the place's.
            /// Planted controls `tests/data/controls/record-place-unchecked.patch`
            /// (the place not compared) and
            /// `tests/data/controls/record-part-unverified.patch` (the part
            /// entry not verifying) accept it, failing "a record of another
            /// place advanced its parent".
            #[test]
            fn a_record_of_another_place_is_refused_by_a_part_entry() {
                let mut parser = Limits::unlimited();
                let document = decode(&[0x07], 1, &mut parser).unwrap();
                let mut a = Limits::unlimited();
                let mut root = Root::<u8>::new();
                let result = forged_part(&document, &mut root, &mut a, true, 1);
                assert!(
                    matches!(
                        result,
                        Err(DecodeError::Resource(BoundedError::PlanMismatch))
                    ),
                    "a record of another place advanced its parent: {result:?}"
                );
                let mut own = Root::<u8>::new();
                let accepted = forged_part(&document, &mut own, &mut a, true, 0);
                assert!(
                    matches!(accepted, Ok(Built::Done)),
                    "a record of its own place was refused: {accepted:?}"
                );
                assert_eq!(a.attempts(), 0, "a forged part admitted work");
            }

            /// A root binding's record of another place is refused by its
            /// session's entry, the session and the policy unchanged; the
            /// same forgery at the root's own place completes the session.
            /// Planted controls `tests/data/controls/record-place-unchecked.patch`
            /// and `tests/data/controls/record-root-unverified.patch` (the
            /// root entry not verifying) accept it, failing "a record of
            /// another place built its session".
            #[test]
            fn a_record_of_another_place_is_refused_by_the_root_entry() {
                let mut parser = Limits::unlimited();
                let document = decode(&[0x07], 1, &mut parser).unwrap();
                let mut a = Limits::unlimited();
                let mut root = Root::<u8>::new();
                assert_eq!(
                    forged_root(&document, &mut root, &mut a, 1).unwrap(),
                    Built::Progress,
                    "the bind unit"
                );
                let (before, attempts) = (root.session.observe(), a.attempts());
                let result = forged_root(&document, &mut root, &mut a, 1);
                refused_unchanged(
                    result,
                    &mut root,
                    before,
                    attempts,
                    &a,
                    "a record of another place built its session",
                );
                let mut own = Root::<u8>::new();
                assert_eq!(
                    forged_root(&document, &mut own, &mut a, 0).unwrap(),
                    Built::Progress
                );
                assert_eq!(
                    forged_root(&document, &mut own, &mut a, 0).unwrap(),
                    Built::Done,
                    "a record of the root's own place was refused"
                );
                assert!(matches!(own.session.stage(), Stage::Built { node: 0, .. }));
            }

            /// A record checked against a context no session stepped is
            /// refused, at the context's own place, nothing admitted.
            /// Planted control
            /// `tests/data/controls/record-unbound-context-accepted.patch`
            /// (the stepped mark not compared) verifies it, failing "a
            /// record verified against a context no session bound".
            #[test]
            fn a_record_against_an_unbound_context_is_refused() {
                let mut parser = Limits::unlimited();
                let document = decode(&[0x07], 1, &mut parser).unwrap();
                let mut a = Limits::unlimited();
                let mut root = Root::<u8>::new();
                let result = forged_part(&document, &mut root, &mut a, false, 0);
                assert!(
                    matches!(
                        result,
                        Err(DecodeError::Resource(BoundedError::PlanMismatch))
                    ),
                    "a record verified against a context no session bound: {result:?}"
                );
                assert_eq!(a.attempts(), 0, "a forged part admitted work");
            }
        }

        /// Cleanup of `root` to `Done` within its declared count, its
        /// pending credit settled by origin at cleanup's entry, as every
        /// custody's cleanup settles it.
        fn drain<T: InPlace<Limits>>(root: &mut Root<T>, a: &mut Limits) {
            root.pending
                .settle_all(crate::bounded::Budget::performer(&*a));
            let declared = remaining::<T, Limits>(root.slot().into_observe())
                .expect("a fixture's cleanup count fits in u64");
            for _ in 0..declared {
                if reclaim::<T, Limits>(root.slot(), &mut Cleanup::new(&mut *a)).unwrap()
                    == Reclaimed::Done
                {
                    return;
                }
            }
            panic!("cleanup exceeded its declared {declared} calls");
        }
    }
}
