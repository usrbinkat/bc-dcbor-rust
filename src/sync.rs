//! The one seam between the library's concurrency primitives and the build:
//! every atomic the library holds, and every plain cell one thread writes
//! and another reads after an atomic publication, is a type of an atomics
//! family ([`Atomics`]), and the types that hold them are generic over the
//! family. The build selects one family, [`Shipped`]:
//!
//! - otherwise [`Core`], `core`'s atomics and `UnsafeCell`;
//! - `cfg(loom)`: [`Loom`], loom's atomics and tracked cells, which explore
//!   every interleaving of the modelled threads and the outcomes acquire and
//!   release orderings permit (loom does not model reordering within one
//!   thread under `Relaxed`);
//! - `cfg(shuttle)`: [`Shuttle`], shuttle's atomics, whose schedulers run
//!   more threads than loom's limit but treat every ordering as `SeqCst`, so
//!   they find schedule defects, never ordering defects.
//!
//! The family changes physical representation and execution only. Every
//! contract quantity (a charge, a write extent, an admitted allocation) is
//! read from the production representation, the types instantiated with
//! [`Core`], which exist in every build: so a checker's larger atomics change
//! what is stored, never what is admitted (I3). `cfg` selects a family here
//! and nowhere else.
//!
//! Each checker is a dependency only under its cfg, which `RUSTFLAGS` alone
//! sets (`--cfg loom`, `--cfg shuttle`), and the family follows the cfg
//! alone: the library is one library in every build of it, its unit tests
//! and every test that links it, so what the models check is what those
//! tests drive. No build of the library selects behaviour on `test`. A
//! checker's atomics exist only inside a model execution: a build under its
//! cfg runs only the tests that enter a model, the library's own
//! ([`models`]) and the declared entry points of its integration tests (the
//! one table of them, `dcbor_model_bounds::ENTRY_POINTS`, which the census
//! checks and the gate runs); every model is configured by the one runner
//! (`tests/support/model.rs`) at the values its record holds
//! (`tests/data/model-bounds.txt`). Nothing in the library builds an atomic
//! in a constant.

#[cfg(all(loom, shuttle))]
compile_error!("cfg(loom) and cfg(shuttle) each select the library's atomics; set one");

pub(crate) use core::sync::atomic::Ordering;

/// A family of concurrency primitives: the types a structure generic over
/// the family holds, and the one unsynchronized read of a counter its holder
/// has exclusively.
pub(crate) trait Atomics {
    /// A flag.
    type Flag;
    /// A count of records.
    type Counter;
    /// A link to a `T`.
    type Link<T>;
    /// A plain value of `T` ordered by an atomic publication ([`Ordered`]).
    type Cell<T: Copy>: Ordered<T>;
    /// A byte total.
    type Total;

    /// The value of a counter its holder has exclusively, read without
    /// synchronization: no other thread can reach it, so every store to it
    /// happened before this read.
    fn exclusive(counter: &mut Self::Counter) -> usize;
}

/// A stored type as a function of the atomics family its primitives come
/// from: `In<Shipped>` is what the build stores, `In<Core>` the production
/// representation every contract quantity of a block is read from
/// (`stable::Contract`). A type generic over a family maps the family it is
/// given; a type that holds no primitive of a family is itself in every
/// family. So the contract a block admits is a property of its type that no
/// build can change.
pub(crate) trait Representation {
    type In<S: Atomics>;
}

/// The production family: `core`'s atomics and `UnsafeCell`, in every
/// build, so every contract quantity can be read from its types.
pub(crate) enum Core {}

impl Atomics for Core {
    type Flag = core::sync::atomic::AtomicBool;
    type Counter = core::sync::atomic::AtomicUsize;
    type Link<T> = core::sync::atomic::AtomicPtr<T>;
    type Cell<T: Copy> = CoreCell<T>;
    type Total = core::sync::atomic::AtomicU64;

    fn exclusive(counter: &mut Self::Counter) -> usize {
        *counter.get_mut()
    }
}

/// loom's family: its atomics, and cells whose every access loom tracks, so
/// a publication whose ordering does not order a write before a read fails
/// the model.
#[cfg(loom)]
pub(crate) enum Loom {}

#[cfg(loom)]
impl Atomics for Loom {
    type Flag = loom::sync::atomic::AtomicBool;
    type Counter = loom::sync::atomic::AtomicUsize;
    type Link<T> = loom::sync::atomic::AtomicPtr<T>;
    type Cell<T: Copy> = LoomCell<T>;
    type Total = loom::sync::atomic::AtomicU64;

    /// loom checks the claim: its `with_mut` fails the model on a store not
    /// ordered before it.
    fn exclusive(counter: &mut Self::Counter) -> usize {
        counter.with_mut(|value| *value)
    }
}

/// shuttle's family: its atomics; it tracks no plain cell, so its cells are
/// `core`'s.
#[cfg(all(shuttle, not(loom)))]
pub(crate) enum Shuttle {}

#[cfg(all(shuttle, not(loom)))]
impl Atomics for Shuttle {
    type Flag = shuttle::sync::atomic::AtomicBool;
    type Counter = shuttle::sync::atomic::AtomicUsize;
    type Link<T> = shuttle::sync::atomic::AtomicPtr<T>;
    type Cell<T: Copy> = CoreCell<T>;
    type Total = shuttle::sync::atomic::AtomicU64;

    fn exclusive(counter: &mut Self::Counter) -> usize {
        *counter.get_mut()
    }
}

/// The family this build stores and executes with.
#[cfg(loom)]
pub(crate) type Shipped = Loom;
/// The family this build stores and executes with.
#[cfg(all(shuttle, not(loom)))]
pub(crate) type Shipped = Shuttle;
/// The family this build stores and executes with.
#[cfg(not(any(loom, shuttle)))]
pub(crate) type Shipped = Core;

pub(crate) type AtomicBool = <Shipped as Atomics>::Flag;
pub(crate) type AtomicUsize = <Shipped as Atomics>::Counter;
pub(crate) type AtomicPtr<T> = <Shipped as Atomics>::Link<T>;
pub(crate) type AtomicU64 = <Shipped as Atomics>::Total;
pub(crate) type Plain<T> = <Shipped as Atomics>::Cell<T>;

#[cfg(all(test, feature = "std", any(loom, shuttle)))]
mod models;

/// A plain value one thread writes and another reads after an atomic
/// publication orders the two: a queued record's custody and cleanup budget,
/// written by the retiring thread before its tail swap and read by the
/// stepper after its acquiring loads. Every family's cell provides it
/// ([`Atomics::Cell`]).
pub(crate) trait Ordered<T: Copy> {
    fn new(value: T) -> Self;

    /// The value.
    ///
    /// # Safety
    /// No write to this value is concurrent with the read: the caller holds
    /// the custody the value describes, or reads before publishing it.
    unsafe fn get(&self) -> T;

    /// Replace the value.
    ///
    /// # Safety
    /// No other access to this value is concurrent with the write.
    unsafe fn set(&self, value: T);
}

/// `core`'s [`Ordered`] cell, laid out as `T`.
#[repr(transparent)]
pub(crate) struct CoreCell<T>(core::cell::UnsafeCell<T>);

impl<T: Copy> Ordered<T> for CoreCell<T> {
    fn new(value: T) -> Self {
        Self(core::cell::UnsafeCell::new(value))
    }

    unsafe fn get(&self) -> T {
        // SAFETY: forwarded from the caller.
        unsafe { *self.0.get() }
    }

    unsafe fn set(&self, value: T) {
        // SAFETY: forwarded from the caller.
        unsafe { *self.0.get() = value };
    }
}

/// loom's [`Ordered`] cell: every access a tracked one, so loom checks the
/// caller's claim that no access is concurrent.
#[cfg(loom)]
pub(crate) struct LoomCell<T>(loom::cell::UnsafeCell<T>);

#[cfg(loom)]
impl<T: Copy> Ordered<T> for LoomCell<T> {
    fn new(value: T) -> Self {
        Self(loom::cell::UnsafeCell::new(value))
    }

    unsafe fn get(&self) -> T {
        // SAFETY: forwarded from the caller; loom checks it.
        self.0.with(|value| unsafe { *value })
    }

    unsafe fn set(&self, value: T) {
        // SAFETY: forwarded from the caller; loom checks it.
        self.0.with_mut(|place| unsafe { *place = value });
    }
}
