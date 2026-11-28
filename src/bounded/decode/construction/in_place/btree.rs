//! Fixed-address B-tree construction. Sort document indices first, allocate
//! the final tree shape, then construct every key and value in its final slot.
extern crate alloc;
mod cleanup;
mod cost;
use super::*;
use crate::bounded::Forfeit;
use crate::bounded::boundary::{Bound, Predicate, Valuation, boundary, units};
use crate::bounded::decode::construction::Nodes;
use crate::bounded::decode::construction::reclamation::{Custody, Place};
use crate::bounded::decode::construction::stable::{self, Installed, Pending, Ticket};
use crate::bounded::decode::initialization::field;
use crate::bounded::decode::storage::{Storage, StoragePosition};
use crate::sync::{Atomics, Representation};
use alloc::collections::{BTreeMap, btree_map::InPlaceNode};
use alloc::string::String;
// Only the test oracle `planned` and the test modules build vectors here.
#[cfg(test)]
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::mem::{ManuallyDrop, MaybeUninit, size_of};
use core::ptr::addr_of_mut;

/// A document key's Rust ordering representation, borrowed without allocation.
pub enum TreeKeyView<'a> {
    Bytes(&'a [u8]),
    Integer(i128),
}

/// A key whose Rust ordering can be established before constructing it.
///
/// # Safety
/// An implementation keeps four obligations, and the `// SAFETY:` comment on
/// it names each as `label:` (`tests/unsafe_census.rs`, `UNSAFE_TRAITS`,
/// which lists every implementation):
///
/// - *view*: `view` does constant work, never unwinds, allocates nothing,
///   and returns a view exactly when the kind can construct this key.
/// - *order*: comparing views agrees with `Self::Ord` for the constructed
///   values: bytes compare lexicographically, integers numerically.
/// - *variant*: a binding always uses the same view variant.
/// - *span*: a byte view borrows the key's own payload and is no longer than
///   its encoded subtree, which the comparison bound requires.
pub unsafe trait TreeKey: Ord {
    fn view(kind: Kind<'_>) -> Option<TreeKeyView<'_>>;
}

// SAFETY: admission: every unit of `build` (gather, sort, plan, allocation,
// each child step, sealing, publication) is admitted before it runs, the
// children's through their own bindings. state: custody records cover every
// initialized prefix: the installed metadata, the node arena and each child
// slot's state, recorded before each step returns, on error too. done: `Done`
// only once every entry's key and value is built and the tree published.
// escape: node and child places stay within the installed blocks; the
// published tree owns them and nothing else keeps one. provenance: children
// are constructed only in their final node slots, reached through places
// derived from the node block's, and publication never moves a child. order:
// a build from any phase past publication, or once cleanup began, is refused
// and changes nothing. cost: `cost::cost::<K, V, A>()` (btree/cost.rs) prices
// every admitted unit, allocation and child cost.
unsafe impl<K: TreeKey + InPlace<A>, V: InPlace<A>, A: Allocator> InPlace<A> for BTreeMap<K, V> {
    const COST: ConstructionCost = crate::const_cost!(cost::cost::<K, V, A>());
    /// A map of `K` keys and `V` values: one level over the deeper of the
    /// two, the stricter text policy.
    const WIRE: crate::bounded::decode::Options = K::WIRE.either(V::WIRE).nested();
    fn build_step<'b>(
        ctx: BindingContext<'b, '_, '_, '_, Self, A>,
        a: &mut A,
    ) -> ConstructResult<Building<'b, Self>, A> {
        build(ctx, a)
    }
}

// SAFETY: initial: no metadata, no ticket, nothing initialized. state: the
// metadata, ticket and initialized count record every acquired block and
// built child. admission: each cleanup unit is admitted before it runs
// (btree/cleanup.rs), a refusal leaving the state unchanged. cleanup: it
// detaches a published tree, reclaims children in reverse construction order
// through their own bindings, then frees nodes without reading their
// reclaimed slots; it allocates nothing, never unwinds and runs no
// destructor. done: `Done` once every child is reclaimed and every block
// released. order: a step once cleanup is done reports `Done` and touches
// nothing; the count reads only the state. depth: one level above the deeper
// of `K` and `V`, exact. count: `cleanup::remaining` counts every unit left.
unsafe impl<K: Reclaim<A>, V: Reclaim<A>, A: Allocator> Reclaim<A> for BTreeMap<K, V> {
    const DISPATCH_DEPTH: usize = if K::DISPATCH_DEPTH > V::DISPATCH_DEPTH {
        K::DISPATCH_DEPTH.saturating_add(1)
    } else {
        V::DISPATCH_DEPTH.saturating_add(1)
    };
    type State = State<K, V, A>;
    const INITIAL: Self::State = State {
        meta: None,
        ticket: None,
        initialized: 0,
    };
    fn reclaim_step(
        slot: Slot<'_, Self, Self::State>,
        cleanup: &mut Cleanup<'_, A>,
    ) -> BoundedResult<Reclaimed, A> {
        cleanup::reclaim(slot, cleanup)
    }

    fn remaining(mut slot: PeekSlot<'_, Self, Self::State>) -> Option<u64> {
        cleanup::remaining(slot.custody())
    }

    fn observe_permits(
        slot: PeekSlot<'_, Self, Self::State>,
        sink: &mut dyn CustodySink<A::Permit>,
    ) -> PermitsObserved {
        permits_tree::<K, V, A>(slot, sink)
    }
}

// SAFETY: view: one match on the kind, allocating nothing and never
// unwinding, `Some` exactly for a text, the kind String's binding constructs.
// order: String construction copies the validated NFC text unchanged, and
// Rust's string order is the lexicographic order of its UTF-8 bytes. variant:
// always `Bytes`. span: the view is the text payload itself, borrowed, no
// longer than its encoded subtree.
unsafe impl TreeKey for String {
    fn view(kind: Kind<'_>) -> Option<TreeKeyView<'_>> {
        match kind {
            Kind::Text(text) => Some(TreeKeyView::Bytes(text.as_bytes())),
            _ => None,
        }
    }
}

// SAFETY: view: one match on the kind, allocating nothing and never
// unwinding, `Some` exactly for a byte string, the kind ByteString's binding
// constructs. order: ByteString preserves its bytes and orders them
// lexicographically. variant: always `Bytes`. span: the view is the byte
// payload itself, borrowed, no longer than its encoded subtree.
unsafe impl TreeKey for crate::ByteString {
    fn view(kind: Kind<'_>) -> Option<TreeKeyView<'_>> {
        match kind {
            Kind::Bytes(bytes) => Some(TreeKeyView::Bytes(bytes)),
            _ => None,
        }
    }
}

macro_rules! integer_keys {
    ($($ty:ty),* $(,)?) => {$ (
        // SAFETY: view: one match and one checked conversion, allocating
        // nothing and never unwinding, `Some` exactly for an integer the type
        // represents, the kinds its binding constructs. order: the type's
        // Rust order is the numeric order of this lossless i128 view.
        // variant: always `Integer`. span: an integer view borrows nothing.
        unsafe impl TreeKey for $ty {
            fn view(kind: Kind<'_>) -> Option<TreeKeyView<'_>> {
                let n = match kind {
                    Kind::Unsigned(n) => i128::from(n),
                    Kind::Negative(n) => i128::from(n),
                    _ => return None,
                };
                <$ty>::try_from(n).ok()?;
                Some(TreeKeyView::Integer(n))
            }
        }
    )*};
}
integer_keys!(u8, u16, u32, u64, usize, i8, i16, i32, i64);

// SAFETY: view: one match on the kind, allocating nothing and never
// unwinding, `Some` exactly for a boolean, the kind bool's binding
// constructs. order: bool construction preserves the source boolean, and
// false (0) sorts before true (1) as in Rust. variant: always `Integer`. span:
// an integer view borrows nothing.
unsafe impl TreeKey for bool {
    fn view(kind: Kind<'_>) -> Option<TreeKeyView<'_>> {
        match kind {
            Kind::Bool(value) => Some(TreeKeyView::Integer(i128::from(value))),
            _ => None,
        }
    }
}

/// Where a tree's construction or cleanup is: the gather and sort of its
/// entries' document indices, the planning and allocation of its nodes,
/// each entry's key and value built in their final slots, the nodes sealed
/// and the tree published; then, reclaiming, each entry's value and key,
/// its record, the nodes and the arenas.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    Header,
    Gather,
    Scratch,
    SortStart,
    Sort,
    SortWrite,
    Height,
    PlanRoot,
    AllocateWrite,
    AllocateRelease,
    Allocate,
    Store,
    Link,
    Expand,
    Entry,
    Key,
    Value,
    Seal,
    Publish,
    Complete,
    ReclaimValue,
    ReclaimKey,
    ReclaimEntry,
    ReleaseNodes,
    ReleaseArenas,
}

/// The merge sort's progress over the entries' document indices: the run
/// width, the two runs being merged and the next output slot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Sort {
    width: usize,
    left: usize,
    mid: usize,
    end: usize,
    i: usize,
    j: usize,
    out: usize,
    offset: usize,
}

/// A planned node: the entries its subtree spans, the first of them, its
/// height, its key count and the edges linked so far.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Shape {
    span: usize,
    first: usize,
    child_max: usize,
    height: u8,
    keys: u8,
    edge: u8,
}

struct Node<K, V, P> {
    raw: InPlaceNode<K, V>,
    permit: P,
    shape: Shape,
}

/// One entry's custody record: its key's and value's places, each rooted at
/// its final slot in a node allocation, and their construction states.
struct Entry<K: Reclaim<A>, V: Reclaim<A>, A: Allocator> {
    key: Place<K>,
    value: Place<V>,
    // Reclaim, rather than Rust Drop, owns the child lifecycle. Even an
    // exhausted user-defined state may have an arbitrary destructor.
    key_state: ManuallyDrop<K::State>,
    value_state: ManuallyDrop<V::State>,
}

/// An arena of the tree's metadata: its own pending acquisition's credit
/// held with its origin ([`Storage`]).
type Arena<T, A> =
    Storage<T, <A as crate::bounded::Releasing>::Permit, <A as crate::bounded::Budget>::Origin>;

struct Meta<K: Reclaim<A>, V: Reclaim<A>, A: Allocator> {
    phase: Phase,
    order: [Arena<usize, A>; 2],
    nodes: Arena<Node<K, V, A::Permit>, A>,
    entries: Arena<Entry<K, V, A>, A>,
    count: usize,
    position: usize,
    source: usize,
    sort: Sort,
    parent: usize,
    slot: usize,
    height: u8,
    maximum: usize,
    pending_shape: Shape,
    pending_node: Option<InPlaceNode<K, V>>,
    pending_permit: Option<A::Permit>,
}

/// Typed custody of a partially constructed or published B-tree: its
/// metadata block, once installed; the ticket of the tree's pending
/// acquisition ([`Ticket`]), the metadata block's and then, one at a time,
/// each node's, whose credit is the operation's; and the metadata prefix
/// written.
pub struct State<K: Reclaim<A>, V: Reclaim<A>, A: Allocator> {
    meta: Option<MetadataBlock<K, V, A>>,
    ticket: Option<Ticket>,
    initialized: u8,
}

type MetadataBlock<K, V, A> =
    Installed<MaybeUninit<Meta<K, V, A>>, <A as crate::bounded::Releasing>::Permit>;

impl<K: Reclaim<A>, V: Reclaim<A>, A: Allocator> Representation for Meta<K, V, A> {
    type In<S: Atomics> = Self;
}

/// What the metadata block's acquisition admits and holds
/// ([`stable::Contract`]): the permit alone written, every field following
/// in a unit of its own; and the whole block. The one definition its
/// installation and the tree's cost read.
const fn contract<K: Reclaim<A>, V: Reclaim<A>, A: Allocator>()
-> stable::Contract<(), MaybeUninit<Meta<K, V, A>>, A::Permit> {
    stable::Contract::of()
}

/// What a tree's construction has reached, by stage: no metadata block; the
/// block held with a prefix of its fields written, each a plain value or an
/// empty arena released with the block; or every field written. An
/// acquisition's binding and credit (the metadata block's, a node's in
/// `AllocateRelease` and `Allocate`) are the operation's custody, reported by
/// the root pending's observation, never this progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[expect(
    clippy::large_enum_variant,
    reason = "custody snapshots include every arena and active child inline; observation must not allocate"
)]
pub enum TreeObservation<K, V> {
    Unallocated,
    Initializing(u8),
    Held(TreeCustody<K, V>),
}

/// A tree's custody once its metadata is written, `K` and `V` its key's and
/// value's observations: the phase; each arena's execution observation, its
/// physical stage and counts (the two index arenas, the nodes, the entry
/// records; [`StoragePosition`], the admissions an arena's growth holds
/// reported by its own custody traversal in `permits_tree`, never here);
/// the entries the map holds and
/// the tree's height; a node allocated with its permit before it enters the
/// node arena; the sort, planning and slot progress that fix every following
/// step; and the newest entry record's key and value, which is the entry
/// under construction or cleanup whenever one is, read wherever its arena
/// holds it, relocation included. Every entry record before the newest holds
/// a complete key and value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TreeCustody<K, V> {
    pub phase: Phase,
    pub order: [StoragePosition; 2],
    pub nodes: StoragePosition,
    pub entries: StoragePosition,
    pub count: usize,
    pub height: u8,
    pub pending_node: bool,
    pub pending_permit: bool,
    pub progress: TreeProgress,
    pub newest: Option<EntryObservation<K, V>>,
}

/// The plain progress of a tree's construction: which index arena holds the
/// current order, the document position, the node and slot reached, the
/// capacity of the planned height, the merge sort, and the node planned
/// next.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TreeProgress {
    pub source: usize,
    pub position: usize,
    pub parent: usize,
    pub slot: usize,
    pub maximum: usize,
    pub sort: Sort,
    pub shape: Shape,
}

/// One entry record's key and value observations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct EntryObservation<K, V> {
    pub key: K,
    pub value: V,
}

impl<K: Reclaim<A>, V: Reclaim<A>, A: Allocator> Custody for State<K, V, A> {
    type Observation =
        TreeObservation<<K::State as Custody>::Observation, <V::State as Custody>::Observation>;

    fn observe(&mut self) -> Self::Observation {
        let Some(block) = self.meta.as_mut() else {
            return TreeObservation::Unallocated;
        };
        if self.initialized < INIT {
            return TreeObservation::Initializing(self.initialized);
        }
        // SAFETY: the complete prefix initializes every metadata field, and
        // the state's custody, held exclusively here, reaches the block.
        let m = unsafe { block.get().assume_init_mut() };
        TreeObservation::Held(TreeCustody {
            phase: m.phase,
            order: [m.order[0].position(), m.order[1].position()],
            nodes: m.nodes.position(),
            entries: m.entries.position(),
            count: m.count,
            height: m.height,
            pending_node: m.pending_node.is_some(),
            pending_permit: m.pending_permit.is_some(),
            progress: TreeProgress {
                source: m.source,
                position: m.position,
                parent: m.parent,
                slot: m.slot,
                maximum: m.maximum,
                sort: m.sort,
                shape: m.pending_shape,
            },
            newest: m.entries.last_mut().map(|entry| EntryObservation {
                key: entry.key_state.observe(),
                value: entry.value_state.observe(),
            }),
        })
    }
}

/// The custody the tree in `slot` holds ([`Reclaim::observe_permits`]),
/// reported inside the caller's open group, the root's whose pending every
/// acquisition of the tree's own binds under: its metadata block's permit;
/// once every metadata unit is written, every node's in the node arena, a
/// node allocated and not yet stored, and each entry record's key's and
/// value's own ([`observe_part`]), read at the places cleanup reads them.
/// Each of the four arenas is an independently owning custody, its own
/// pending's acquisitions bound under its own owner, so each reports as a
/// group of its own nested here ([`Storage::observe_custody`]): its held
/// growth credit and its allocations' permits under the arena's owner,
/// never the root's. A prefix's arenas hold no permit: none acquires before
/// the prefix is complete.
fn permits_tree<K: Reclaim<A>, V: Reclaim<A>, A: Allocator>(
    mut slot: PeekSlot<'_, BTreeMap<K, V>, State<K, V, A>>,
    sink: &mut dyn CustodySink<A::Permit>,
) -> PermitsObserved {
    let state = slot.custody();
    let Some(block) = state.meta.as_mut() else {
        return PermitsObserved::Complete;
    };
    sink.permit(block.permit(), None);
    if state.initialized < INIT {
        return PermitsObserved::Complete;
    }
    // SAFETY: the complete prefix initializes every metadata field, and the
    // state's custody, held exclusively here, reaches the block.
    let m = unsafe { block.get().assume_init_mut() };
    let mut whole = observed_all([
        m.order[0].observe_custody(sink),
        m.order[1].observe_custody(sink),
        m.nodes.observe_custody(sink),
        m.entries.observe_custody(sink),
    ]);
    m.nodes.for_each_mut(|node| sink.permit(&node.permit, None));
    if let Some(permit) = m.pending_permit.as_ref() {
        sink.permit(permit, None);
    }
    m.entries.for_each_mut(|entry| {
        // SAFETY: each record holds its key's and value's stable places in
        // the node it was built in, paired with their own states.
        let (value, key) = unsafe {
            (
                observe_part::<V, A>(
                    Slot::new(entry.value.observe(), &mut *entry.value_state),
                    sink,
                ),
                observe_part::<K, A>(Slot::new(entry.key.observe(), &mut *entry.key_state), sink),
            )
        };
        whole = observed_all([whole, value, key]);
    });
    whole
}

// SAFETY: all pointed-to allocations are exclusively owned by this state.
// Child destinations never move; their states and all permits are Send.
unsafe impl<K: Reclaim<A> + Send, V: Reclaim<A> + Send, A: Allocator> Send for State<K, V, A>
where
    K::State: Send,
    V::State: Send,
    A::Permit: Send,
{
}

/// The units of one arena of the metadata ([`Storage::INIT_STEPS`]): the
/// same for every element, permit and origin type.
const ARENA_STEPS: u8 = Storage::<u8, (), ()>::INIT_STEPS as u8;

/// The metadata's arenas, in field and initialization order: `order[0]`,
/// `order[1]`, `nodes`, `entries`.
const ARENAS: u8 = 4;

/// The first unit after the arenas': the phase is unit 0, then each
/// arena's units in turn.
const PLAIN: u8 = 1 + ARENAS * ARENA_STEPS;

/// Every unit of the metadata ([`initialize`]): the phase, the arenas'
/// units, then the eleven plain fields from `count` to `pending_permit`.
const INIT: u8 = PLAIN + 11;

const COMPARE: crate::bounded::Capped<Caller> = crate::bounded::Capped::new(Caller, 3, 64);

/// One admitted unit of the arena at `raw` ([`Storage::initialize_step`]),
/// its `within`th: the arena's own units in place, its pending credit's
/// owner made by its first acquisition entry.
///
/// # Safety
/// `raw` is valid, aligned and writable for the arena, exactly its first
/// `within` units are written, and nothing else reaches it meanwhile.
unsafe fn arena_unit<T, A: Allocator>(
    raw: *mut Arena<T, A>,
    within: u8,
    a: &mut A,
) -> BoundedResult<(), A> {
    let mut units = usize::from(within);
    // SAFETY: forwarded from the caller; the place roots the arena's own
    // field, the progress its written units.
    let slot = unsafe {
        Slot::new(
            Place::root(core::ptr::NonNull::new_unchecked(
                raw.cast::<MaybeUninit<Arena<T, A>>>(),
            )),
            &mut units,
        )
    };
    Storage::initialize_step(slot, a)?;
    Ok(())
}

/// One unit of the tree's metadata: its block installed, its acquisition's
/// credit held in `pending`, then one field per unit, each recorded in the
/// state's prefix before returning. A call once the prefix is complete is
/// refused.
fn initialize<K: Reclaim<A>, V: Reclaim<A>, A: Allocator>(
    state: &mut State<K, V, A>,
    pending: &mut Pending<A::Origin>,
    a: &mut A,
) -> BoundedResult<bool, A> {
    if state.meta.is_none() {
        // SAFETY: the held value is MaybeUninit and the header is empty, so
        // only the permit is written; each field is then initialized in an
        // admitted unit of its own.
        unsafe {
            stable::install::<MaybeUninit<Meta<K, V, A>>, (), A>(
                const { contract::<K, V, A>() },
                &mut state.meta,
                pending,
                &mut state.ticket,
                // Uninitialized bytes already form a valid MaybeUninit. Do
                // not synthesize or copy the large metadata value here.
                || (),
                |meta| meta.cast::<()>(),
                a,
            )?;
        }
        return Ok(false);
    }
    let raw = state
        .meta
        .as_mut()
        .ok_or(BoundedError::PlanMismatch)?
        .get()
        .as_mut_ptr();
    let unit = state.initialized;
    // SAFETY: the prefix records which units are written, so each unit
    // initializes the next part once, recorded before returning: the phase,
    // each arena's own units in place, then each plain field; the match
    // refuses every unit past the last. No field is read before all are
    // initialized.
    unsafe {
        if unit == 0 {
            field(addr_of_mut!((*raw).phase), || Phase::Header, a)?;
        } else if Bound::new(Predicate::Prefix, PLAIN).below(a, unit) {
            let within = (unit - 1) % ARENA_STEPS;
            match (unit - 1) / ARENA_STEPS {
                0 => arena_unit::<usize, A>(addr_of_mut!((*raw).order[0]), within, a)?,
                1 => arena_unit::<usize, A>(addr_of_mut!((*raw).order[1]), within, a)?,
                2 => arena_unit::<Node<K, V, A::Permit>, A>(addr_of_mut!((*raw).nodes), within, a)?,
                _ => arena_unit::<Entry<K, V, A>, A>(addr_of_mut!((*raw).entries), within, a)?,
            }
        } else {
            match unit - PLAIN {
                0 => field(addr_of_mut!((*raw).count), || 0, a)?,
                1 => field(addr_of_mut!((*raw).position), || 0, a)?,
                2 => field(addr_of_mut!((*raw).source), || 0, a)?,
                3 => field(addr_of_mut!((*raw).sort), Sort::default, a)?,
                4 => field(addr_of_mut!((*raw).parent), || 0, a)?,
                5 => field(addr_of_mut!((*raw).slot), || 0, a)?,
                6 => field(addr_of_mut!((*raw).height), || 0, a)?,
                7 => field(
                    addr_of_mut!((*raw).maximum),
                    || InPlaceNode::<K, V>::CAPACITY,
                    a,
                )?,
                8 => field(addr_of_mut!((*raw).pending_shape), Shape::default, a)?,
                9 => field(addr_of_mut!((*raw).pending_node), || None, a)?,
                10 => field(addr_of_mut!((*raw).pending_permit), || None, a)?,
                _ => return Err(BoundedError::PlanMismatch),
            }
        }
    }
    state.initialized += 1;
    Ok(state.initialized == INIT)
}

/// Drop in place, newest first, every arena of a metadata prefix of
/// `initialized` units: each written in part or whole, owning no allocation
/// and no admitted credit (no arena acquires before the prefix is
/// complete), but holding its own pending credit's owner state, which the
/// custody block, running no destructor, must release. A partly written
/// arena drops its written units ([`Storage::drop_prefix`]), a whole one
/// itself. The other fields of the prefix are plain values, the pending
/// node and permit still `None`. Allocation-free and non-unwinding.
///
/// # Safety
/// `raw` is the metadata of a block whose first `initialized` units (unit 0
/// the phase) are written and hold no admitted credit and no allocation,
/// and nothing reads those fields afterwards.
unsafe fn drop_prefix_arenas<K: Reclaim<A>, V: Reclaim<A>, A: Allocator>(
    raw: *mut Meta<K, V, A>,
    initialized: u8,
) {
    // SAFETY: forwarded from the caller; each projection reaches one
    // arena by field syntax, forming no reference to the rest.
    unsafe {
        for arena in (0..ARENAS).rev() {
            let start = 1 + arena * ARENA_STEPS;
            let written = usize::from(initialized.saturating_sub(start).min(ARENA_STEPS));
            match arena {
                0 => drop_arena::<usize, A>(addr_of_mut!((*raw).order[0]), written),
                1 => drop_arena::<usize, A>(addr_of_mut!((*raw).order[1]), written),
                2 => drop_arena::<Node<K, V, A::Permit>, A>(addr_of_mut!((*raw).nodes), written),
                _ => drop_arena::<Entry<K, V, A>, A>(addr_of_mut!((*raw).entries), written),
            }
        }
    }
}

/// Drop in place the first `written` units of the arena at `raw`: none, a
/// prefix ([`Storage::drop_prefix`]), or the whole arena, its own drop
/// releasing what it holds.
///
/// # Safety
/// `raw` holds an arena whose first `written` units are initialized, owning
/// no allocation and no admitted credit, read by nothing afterwards.
unsafe fn drop_arena<T, A: Allocator>(raw: *mut Arena<T, A>, written: usize) {
    // SAFETY: forwarded from the caller.
    unsafe {
        if written == usize::from(ARENA_STEPS) {
            core::ptr::drop_in_place(raw);
        } else {
            Storage::drop_prefix(raw, written);
        }
    }
}

/// The tree's metadata, borrowed from the state: released before the tree's
/// own place is accessed under the state, the place's custody. Refused
/// unless the state records the whole metadata prefix written.
fn meta<K: Reclaim<A>, V: Reclaim<A>, A: Allocator, R>(
    state: &mut State<K, V, A>,
) -> Result<&mut Meta<K, V, A>, BoundedError<R>> {
    if state.initialized < INIT {
        return Err(BoundedError::PlanMismatch);
    }
    let block = state.meta.as_mut().ok_or(BoundedError::PlanMismatch)?;
    // SAFETY: the complete prefix initializes every metadata field.
    Ok(unsafe { block.get().assume_init_mut() })
}

fn compare<K: TreeKey, A: Allocator>(
    nodes: Nodes<'_, '_, A::Permit>,
    left: usize,
    right: usize,
    offset: &mut usize,
    a: &mut A,
) -> ConstructResult<Option<Ordering>, A> {
    // Both views are constant-work reads. Admission precedes their inspection.
    COMPARE.admit(a, 64)?;
    let left = K::view(nodes.node(left).ok_or_else(wrong_type)?.kind()).ok_or_else(wrong_type)?;
    let right = K::view(nodes.node(right).ok_or_else(wrong_type)?.kind()).ok_or_else(wrong_type)?;
    match (left, right) {
        (TreeKeyView::Integer(l), TreeKeyView::Integer(r)) => Ok(Some(l.cmp(&r))),
        (TreeKeyView::Bytes(l), TreeKeyView::Bytes(r)) => {
            const WINDOW: usize = 32;
            let common = Bound::new(Predicate::Payload, r.len()).clamp(a, l.len());
            if *offset == 0 {
                // The comparison windows the shorter key spans.
                boundary!(a, Predicate::KeySpan => units(common.div_ceil(WINDOW)));
            }
            let end =
                Bound::new(Predicate::Payload, common).clamp(a, offset.saturating_add(WINDOW));
            let ordering = l[*offset..end].cmp(&r[*offset..end]);
            *offset = end;
            Ok(if ordering != Ordering::Equal {
                Some(ordering)
            } else if end == common {
                Some(l.len().cmp(&r.len()))
            } else {
                None
            })
        }
        _ => Err(wrong_type()),
    }
}

/// The most entries a tree one level taller holds than one holding at most
/// `maximum`: a node of `CAPACITY + 1` children of `maximum` each and
/// `CAPACITY` keys between them, `(maximum + 1) * 12 - 1` for this node
/// representation; saturated at `usize::MAX`, which no count exceeds. The one
/// recurrence construction's `Height` phase and [`planned`] raise a tree's
/// height by.
const fn raised(maximum: usize) -> usize {
    match maximum.checked_add(1) {
        Some(n) => match n.checked_mul(12) {
            Some(n) => n - 1,
            None => usize::MAX,
        },
        None => usize::MAX,
    }
}

/// A tree's occupancy class: whether it is empty, and otherwise its height.
/// Every branch planning and building a tree of a count takes is selected
/// by these alone. Construction branches on emptiness (`PlanRoot` publishes
/// an empty map at once), on the height (the `Height` loop, leaf against
/// internal in `shape`, `Shape::rank` and the node's layout) and on root
/// against non-root, which the height fixes per level; every other
/// condition is a loop bound over a node's keys, edges or slots, each taken
/// for every nonempty tree. The fork's node code (`InPlaceNode`) branches
/// only on leaf against internal. The arithmetic within a class, every
/// node's keys, span and ranks for each count, is certified for every count
/// separately (`planned`, its tests), so one tree per class, and the
/// counts on each side of a class's edge, witness every planning path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Occupancy {
    Empty,
    Height(u8),
}

/// The occupancy class of a tree of `count` entries ([`Occupancy`]), from
/// its planned height alone (`height`): no node is planned and nothing is
/// allocated, whatever the count.
pub fn occupancy(count: usize) -> Occupancy {
    if count == 0 {
        Occupancy::Empty
    } else {
        Occupancy::Height(height(count).0)
    }
}

/// The height a tree of `count` entries is planned at, and the most entries
/// a child of its root holds: the height raised by [`raised`] until `count`
/// fits, as construction's `Height` phase raises it one admitted unit at a
/// time. At most a few iterations: each multiplies the capacity by twelve.
fn height(count: usize) -> (u8, usize) {
    let (mut height, mut maximum, mut child_max) = (0u8, InPlaceNode::<(), ()>::CAPACITY, 0);
    while count > maximum {
        child_max = maximum;
        maximum = raised(maximum);
        height += 1;
    }
    (height, child_max)
}

/// The boundary valuation of a tree of `count` entries planned at `height`
/// ([`Predicate::TreeOccupancy`]): its occupancy class ([`Occupancy`]), the
/// event every planning path is selected by.
fn occupancy_valuation(count: usize, height: u8) -> Valuation {
    match (count, height) {
        (0, _) => Valuation::Empty,
        (_, 0) => Valuation::Height0,
        (_, 1) => Valuation::Height1,
        (_, 2) => Valuation::Height2,
        _ => Valuation::Taller,
    }
}

/// The height and every node's shape construction plans for a tree of
/// `count` entries: the height raised by [`raised`] until `count` fits, as
/// the `Height` phase does, then the root planned by [`shape`], as
/// `PlanRoot` does, and each internal node's children by [`Shape::child`],
/// as `Expand` does. The root comes first; the rest follow in a walk of the
/// tree, not construction's breadth-first order, on which nothing here
/// depends. A test oracle only (`plan_tests`): it allocates a shape per
/// node, outside any policy, so no shipped path calls it ([`occupancy`]
/// reads [`height`] alone).
#[cfg(test)]
pub(crate) fn planned(count: usize) -> (u8, Vec<Shape>) {
    let (height, child_max) = height(count);
    let mut shapes = Vec::new();
    if count == 0 {
        return (height, shapes);
    }
    let mut pending = Vec::from([shape(count, 0, height, child_max, true)]);
    while let Some(node) = pending.pop() {
        if node.height > 0 {
            for edge in 0..=usize::from(node.keys) {
                pending.push(node.child(edge));
            }
        }
        shapes.push(node);
    }
    (height, shapes)
}

fn shape(span: usize, first: usize, height: u8, child_max: usize, root: bool) -> Shape {
    let keys = if height == 0 {
        span
    } else {
        span.saturating_add(1)
            .div_ceil(child_max + 1)
            .max(if root { 2 } else { 6 })
            - 1
    };
    Shape {
        span,
        first,
        child_max,
        height,
        keys: keys as u8,
        edge: 0,
    }
}

impl Shape {
    fn child(self, edge: usize) -> Self {
        let branches = usize::from(self.keys) + 1;
        let rest = self.span - usize::from(self.keys);
        let base = rest / branches;
        let extra = rest % branches;
        shape(
            base + usize::from(edge < extra),
            self.first + edge * (base + 1) + edge.min(extra),
            self.height - 1,
            self.child_max.saturating_sub(11) / 12,
            false,
        )
    }

    fn rank(self, slot: usize) -> usize {
        if self.height == 0 {
            self.first + slot
        } else {
            let branches = usize::from(self.keys) + 1;
            let rest = self.span - usize::from(self.keys);
            self.first + (slot + 1) * (rest / branches) + (slot + 1).min(rest % branches) + slot
        }
    }
}

/// One unit of the tree's construction in the context's slot, from the
/// context's node, a map.
///
/// Each entry's key and value are parts ([`build_part`]), built from
/// `m.position`, the one record of which node they continue from: set in
/// `Entry` from the sorted order when the entry's record is pushed, advanced
/// past the key only once the key reports `Done` (`Key` to `Value`), and
/// replaced only by the next entry's `Entry`; a refused or erroring part
/// leaves it, the phase and the record unchanged. No part is built once
/// cleanup began: cleanup ([`cleanup::reclaim`]) first moves the phase to
/// `ReclaimValue`, and every cleanup phase falls to this function's last
/// arm, refused `PlanMismatch`, nothing changed. A tree reclaimed to its end
/// is `INITIAL` again, which a build would restart: only its owner's own
/// phase (a parent's cleanup phase, or the root's released session) keeps
/// it from being built again.
fn build<'b, K: TreeKey + InPlace<A>, V: InPlace<A>, A: Allocator>(
    ctx: Context<'b, '_, '_, '_, BTreeMap<K, V>, State<K, V, A>, A>,
    a: &mut A,
) -> ConstructResult<Building<'b, BTreeMap<K, V>>, A> {
    let mut ctx = ctx;
    let assembly = ctx.assembly();
    let index = ctx.index();
    let nodes = ctx.nodes();
    let (mut slot, pending) = ctx.acquiring();
    let (place, state) = slot.parts();
    if Bound::new(Predicate::Prefix, INIT).below(a, state.initialized) {
        initialize(state, pending, a)?;
        return Ok(Building::Progress);
    }
    let m = meta(state)?;
    match m.phase {
        Phase::Header => {
            STEP.admit(a)?;
            let Kind::Map(count) = nodes.node(index).ok_or_else(wrong_type)?.kind() else {
                return Err(wrong_type());
            };
            m.count = usize::try_from(count).map_err(|_| BoundedError::Overflow)?;
            m.position = index.checked_add(1).ok_or(BoundedError::Overflow)?;
            m.phase = Phase::Gather;
        }
        Phase::Gather => {
            if boundary!(a, Predicate::ArenaLength, m.order[0].len(), m.count).is_eq() {
                STEP.admit(a)?;
                m.sort.width = 1;
                m.phase = Phase::SortStart;
            } else if let Some(spare) = m.order[0].reserve_step(m.count, a)? {
                sized::<usize>().admit(a)?;
                K::view(nodes.node(m.position).ok_or_else(wrong_type)?.kind())
                    .ok_or_else(wrong_type)?;
                let value =
                    super::super::next_index(nodes.node(m.position).ok_or_else(wrong_type)?);
                let next = super::super::next_index(nodes.node(value).ok_or_else(wrong_type)?);
                spare.push(m.position);
                m.position = next;
                m.phase = Phase::Scratch;
            }
        }
        Phase::Scratch => {
            if let Some(spare) = m.order[1].reserve_step(m.count, a)? {
                sized::<usize>().admit(a)?;
                spare.push(0);
                m.phase = Phase::Gather;
            }
        }
        Phase::SortStart => {
            STEP.admit(a)?;
            let runs = Bound::new(Predicate::ArenaLength, m.count);
            if runs.reached(a, m.sort.width) {
                m.phase = Phase::Height;
            } else {
                let s = &mut m.sort;
                s.mid = runs.clamp(a, s.left.saturating_add(s.width));
                s.end = runs.clamp(a, s.mid.saturating_add(s.width));
                s.i = s.left;
                s.j = s.mid;
                s.out = s.left;
                s.offset = 0;
                m.phase = Phase::Sort;
            }
        }
        Phase::Sort => {
            let Some(_) = m.order[0].settle_step(a)? else {
                return Ok(Building::Progress);
            };
            let Some(_) = m.order[1].settle_step(a)? else {
                return Ok(Building::Progress);
            };
            let s = &mut m.sort;
            if s.out == s.end {
                STEP.admit(a)?;
                s.left = s.end;
                if s.left == m.count {
                    m.source ^= 1;
                    s.left = 0;
                    s.width = s.width.saturating_mul(2);
                }
                m.phase = Phase::SortStart;
            } else {
                let input = m.order[m.source]
                    .settled()
                    .ok_or(BoundedError::PlanMismatch)?
                    .as_slice();
                let left = if s.i == s.mid {
                    STEP.admit(a)?;
                    false
                } else if s.j == s.end {
                    STEP.admit(a)?;
                    true
                } else {
                    match compare::<K, A>(nodes, input[s.i], input[s.j], &mut s.offset, a)? {
                        None => return Ok(Building::Progress),
                        Some(Ordering::Equal) => return Err(BoundedError::DuplicateKey.into()),
                        Some(ordering) => ordering == Ordering::Less,
                    }
                };
                m.position = input[if left { s.i } else { s.j }];
                s.offset = usize::from(left);
                m.phase = Phase::SortWrite;
            }
        }
        Phase::SortWrite => {
            let Some(output) = m.order[m.source ^ 1].settle_step(a)? else {
                return Ok(Building::Progress);
            };
            sized::<usize>().admit(a)?;
            output.as_mut_slice()[m.sort.out] = m.position;
            if m.sort.offset != 0 {
                m.sort.i += 1;
            } else {
                m.sort.j += 1;
            }
            m.sort.out += 1;
            m.sort.offset = 0;
            m.phase = Phase::Sort;
        }
        Phase::Height => {
            STEP.admit(a)?;
            if Bound::new(Predicate::TreeOccupancy, m.maximum).admits(a, m.count) {
                m.phase = Phase::PlanRoot;
            } else {
                m.pending_shape.child_max = m.maximum;
                m.maximum = raised(m.maximum);
                m.height += 1;
            }
        }
        Phase::PlanRoot => {
            STEP.admit(a)?;
            boundary!(a, Predicate::TreeOccupancy => occupancy_valuation(m.count, m.height));
            if m.count == 0 {
                m.phase = Phase::Publish;
            } else {
                m.pending_shape = shape(m.count, 0, m.height, m.pending_shape.child_max, true);
                m.phase = Phase::AllocateWrite;
            }
        }
        Phase::AllocateWrite => {
            // Only parent and length are written by the fork's allocation:
            // the grant's work, admitted held in the operation's pending
            // acquisition, under the state's ticket, until the node is
            // granted.
            stable::admit_grant(
                pending,
                &mut state.ticket,
                const { cost::allocate_write::<K, V, A::Permit>() },
                a,
            )?;
            meta(state)?.phase = Phase::AllocateRelease;
        }
        Phase::AllocateRelease => {
            stable::admit_release(pending, &mut state.ticket, a)?;
            meta(state)?.phase = Phase::Allocate;
        }
        Phase::Allocate => {
            let leaf = m.pending_shape.height == 0;
            let bytes = InPlaceNode::<K, V>::layout(leaf).size() as u64;
            // A refused request keeps the grant's work and the release held
            // in the pending acquisition, in this phase; the retry's grant
            // spends them. A physical failure forfeits the grant's work at
            // the permit, which drops performing its release, and ends the
            // acquisition: nothing is held any more (`AllocateWrite` holds
            // nothing), and the failure is terminal: cleanup follows.
            let granted = stable::grant(
                pending,
                &mut state.ticket,
                bytes,
                || InPlaceNode::try_allocate(leaf).map_err(|_| Forfeit::AcquisitionFailed),
                a,
            );
            let m = meta(state)?;
            let (permit, raw) = match granted {
                Ok(granted) => granted,
                Err(error) => {
                    if matches!(error, BoundedError::Allocation { .. }) {
                        m.phase = Phase::AllocateWrite;
                    }
                    return Err(error.into());
                }
            };
            m.pending_permit = Some(permit);
            m.pending_node = Some(raw);
            m.phase = Phase::Store;
        }
        Phase::Store => {
            if let Some(spare) = m.nodes.reserve_step(m.count, a)? {
                sized::<Node<K, V, A::Permit>>().admit(a)?;
                spare.push(Node {
                    raw: m.pending_node.take().ok_or(BoundedError::PlanMismatch)?,
                    permit: m.pending_permit.take().ok_or(BoundedError::PlanMismatch)?,
                    shape: m.pending_shape,
                });
                m.phase = Phase::Link;
            }
        }
        Phase::Link => {
            let Some(nodes) = m.nodes.settle_step(a)? else {
                return Ok(Building::Progress);
            };
            const { cost::link::<K, V>() }.admit(a)?;
            let nodes = nodes.as_mut_slice();
            if boundary!(a, Predicate::ArenaLength, nodes.len(), 1).is_gt() {
                let parent = &nodes[m.parent];
                // SAFETY: the new allocation is unparented and one level below
                // its parent; this edge is initialized exactly once.
                unsafe {
                    parent
                        .raw
                        .link(usize::from(parent.shape.edge), &nodes[nodes.len() - 1].raw);
                }
                nodes[m.parent].shape.edge += 1;
            }
            m.phase = Phase::Expand;
        }
        Phase::Expand => {
            let Some(nodes) = m.nodes.settle_step(a)? else {
                return Ok(Building::Progress);
            };
            STEP.admit(a)?;
            if m.parent == nodes.len() {
                m.parent = 0;
                m.slot = 0;
                m.phase = Phase::Entry;
            } else {
                let node = &nodes.as_slice()[m.parent];
                if node.shape.height == 0
                    || boundary!(
                        a,
                        Predicate::TreeOccupancy,
                        node.shape.edge,
                        node.shape.keys
                    )
                    .is_gt()
                {
                    m.parent += 1;
                } else {
                    m.pending_shape = node.shape.child(usize::from(node.shape.edge));
                    m.phase = Phase::AllocateWrite;
                }
            }
        }
        Phase::Entry => {
            let Some(nodes) = m.nodes.settle_step(a)? else {
                return Ok(Building::Progress);
            };
            if m.parent == nodes.len() {
                STEP.admit(a)?;
                m.parent = 0;
                m.phase = Phase::Seal;
            } else {
                let node = &nodes.as_slice()[m.parent];
                if m.slot == usize::from(node.shape.keys) {
                    STEP.admit(a)?;
                    m.parent += 1;
                    m.slot = 0;
                } else if let Some(spare) = m.entries.reserve_step(m.count, a)? {
                    sized::<Entry<K, V, A>>().admit(a)?;
                    // SAFETY: the final node's slot is unique and not yet built;
                    // it roots the key's and value's provenance, and the entry
                    // record's places are the only access to either until the
                    // tree is published, after which cleanup detaches it first.
                    let (key, value) = unsafe {
                        let (key, value) = node.raw.slot(m.slot);
                        (Place::root(key), Place::root(value))
                    };
                    spare.push(Entry {
                        key,
                        value,
                        key_state: ManuallyDrop::new(K::INITIAL),
                        value_state: ManuallyDrop::new(V::INITIAL),
                    });
                    m.position = m.order[m.source]
                        .settled()
                        .ok_or(BoundedError::PlanMismatch)?
                        .as_slice()[node.shape.rank(m.slot)];
                    m.phase = Phase::Key;
                }
            }
        }
        Phase::Key | Phase::Value => {
            if m.entries.settle_step(a)?.is_none() {
                return Ok(Building::Progress);
            }
            let key_phase = m.phase == Phase::Key;
            let position = m.position;
            // SAFETY: the newest entry record, in the settled entry arena
            // this tree's metadata holds, pairs each final, stable
            // destination, rooted at its node slot, with the state that
            // records its initialized prefix throughout construction and
            // cleanup.
            let done = if key_phase {
                let key = unsafe {
                    ctx.part(position, |slot| {
                        let entry = meta(slot.into_parts().1)?
                            .entries
                            .last_mut()
                            .ok_or(BoundedError::PlanMismatch)?;
                        Ok::<_, BoundedError<A::Refusal>>(Slot::new(
                            entry.key,
                            &mut *entry.key_state,
                        ))
                    })
                }?;
                build_part::<K, A>(key, a)?
            } else {
                let value = unsafe {
                    ctx.part(position, |slot| {
                        let entry = meta(slot.into_parts().1)?
                            .entries
                            .last_mut()
                            .ok_or(BoundedError::PlanMismatch)?;
                        Ok::<_, BoundedError<A::Refusal>>(Slot::new(
                            entry.value,
                            &mut *entry.value_state,
                        ))
                    })
                }?;
                build_part::<V, A>(value, a)?
            };
            if done == Built::Done {
                let mut slot = ctx.slot();
                let m = meta(slot.custody())?;
                if key_phase {
                    m.position =
                        super::super::next_index(nodes.node(position).ok_or_else(wrong_type)?);
                    m.phase = Phase::Value;
                } else {
                    m.slot += 1;
                    m.phase = Phase::Entry;
                }
            }
        }
        Phase::Seal => {
            let Some(nodes) = m.nodes.settle_step(a)? else {
                return Ok(Building::Progress);
            };
            if m.parent == nodes.len() {
                STEP.admit(a)?;
                m.phase = Phase::Publish;
            } else {
                sized::<u16>().admit(a)?;
                let node = &nodes.as_slice()[m.parent];
                // SAFETY: every entry and edge has finished construction.
                unsafe {
                    node.raw.set_len(usize::from(node.shape.keys));
                }
                m.parent += 1;
            }
        }
        Phase::Publish => {
            sized::<BTreeMap<K, V>>().admit(a)?;
            let nodes = m
                .nodes
                .settled()
                .ok_or(BoundedError::PlanMismatch)?
                .as_slice();
            // SAFETY: the balanced shape has uniform leaf depth and minimum
            // occupancy; sorted document ranks produce strictly ordered keys.
            // Every child completed in its final slot. The raw custody records
            // remain inaccessible until reclamation detaches the map.
            let map = unsafe {
                BTreeMap::from_in_place(
                    nodes.first().map(|n| &n.raw),
                    usize::from(m.height),
                    m.count,
                )
            };
            // SAFETY: the slot pairs the place with this state, and in this
            // phase nothing is written to it yet; the write is admitted above.
            unsafe { place.write(state, map) };
            meta(state)?.phase = Phase::Complete;
            // SAFETY: the map is written at the tree's place above. Each of
            // its entries entered it through `Entry` only after its key's and
            // its value's `Done`, each record, confined by its brand to the
            // step that minted it, verified by `build_part` against the node
            // slot this tree projected for that part. `Seal` set every
            // node's length over those entries. The slot is not reclaimed: cleanup moves the
            // phase to `ReclaimValue`, which this function refuses.
            return Ok(Building::Done(unsafe { assembly.assemble() }));
        }
        _ => return Err(BoundedError::PlanMismatch.into()),
    }
    Ok(Building::Progress)
}

/// The plan's certification: for every count, the shapes construction plans
/// form the tree `BTreeMap::from_in_place` requires, so the occupancy
/// classes ([`Occupancy`]) need one witness per class end to end.
#[cfg(test)]
mod plan_tests {
    use super::*;
    use alloc::format;

    /// The fewest keys a node other than the root holds: the standard
    /// occupancy, `B - 1` of a node of `CAPACITY = 2B - 1` keys.
    const MINIMUM: usize = (InPlaceNode::<(), ()>::CAPACITY - 1) / 2;

    /// Every way the plan `(height, shapes)` for `count` entries fails the
    /// tree `from_in_place` requires: the root first, spanning every entry;
    /// every node within capacity, every node but the root at the standard
    /// occupancy and the root holding a key; a leaf's span its keys; an
    /// internal node's children one level lower, contiguous, each key ranked
    /// between the two children beside it, their spans and its keys its own
    /// span; and the keys, over every node, exactly the entries, each ranked
    /// once.
    fn violations(
        count: usize,
        height: u8,
        shapes: &[Shape],
        ranks: &mut Vec<bool>,
    ) -> Vec<String> {
        let mut found = Vec::new();
        ranks.resize(count, false);
        ranks.fill(false);
        let capacity = InPlaceNode::<(), ()>::CAPACITY;
        if count == 0 {
            if !shapes.is_empty() {
                found.push(format!("{count}: an empty tree plans nodes"));
            }
            return found;
        }
        let root = shapes[0];
        if root.span != count || root.first != 0 || root.height != height {
            found.push(format!("{count}: the root is {root:?}"));
        }
        let mut ranked_once = true;
        for (at, node) in shapes.iter().enumerate() {
            let keys = usize::from(node.keys);
            if keys > capacity {
                found.push(format!("{count}: {node:?} exceeds the capacity"));
            }
            if at == 0 && keys == 0 {
                found.push(format!("{count}: the root holds no key"));
            }
            if at != 0 && keys < MINIMUM {
                found.push(format!("{count}: {node:?} is below the standard occupancy"));
            }
            for slot in 0..keys {
                match ranks.get_mut(node.rank(slot)) {
                    Some(seen) => {
                        ranked_once &= !*seen;
                        *seen = true;
                    }
                    None => ranked_once = false,
                }
            }
            if node.height == 0 {
                if node.span != keys {
                    found.push(format!(
                        "{count}: the leaf {node:?} spans other than its keys"
                    ));
                }
                continue;
            }
            let mut spanned = keys;
            let mut next = node.first;
            for edge in 0..=keys {
                let child = node.child(edge);
                if child.height + 1 != node.height || child.first != next {
                    found.push(format!("{count}: {node:?} edge {edge} plans {child:?}"));
                }
                spanned += child.span;
                next = child.first + child.span;
                if edge < keys {
                    if node.rank(edge) != next {
                        found.push(format!(
                            "{count}: {node:?} key {edge} is not ranked after edge {edge}"
                        ));
                    }
                    next += 1;
                }
            }
            if spanned != node.span || next != node.first + node.span {
                found.push(format!(
                    "{count}: {node:?} spans other than its children and keys"
                ));
            }
        }
        if !ranked_once || ranks.contains(&false) {
            found.push(format!("{count}: the keys are not each entry ranked once"));
        }
        found
    }

    /// Every count through 20,000, four heights, plans a tree
    /// `from_in_place` accepts, and its occupancy class is its height; the
    /// height rises exactly where `raised` says.
    #[test]
    fn every_count_plans_a_valid_tree_of_its_occupancy() {
        let mut maximum = InPlaceNode::<(), ()>::CAPACITY;
        let mut height = 0u8;
        let mut ranks = Vec::new();
        for count in 0..=20_000usize {
            if count > maximum {
                maximum = raised(maximum);
                height += 1;
            }
            let (planned_height, shapes) = planned(count);
            let found = violations(count, planned_height, &shapes, &mut ranks);
            assert!(found.is_empty(), "{found:#?}");
            assert_eq!(planned_height, height, "{count}");
            let expected = if count == 0 {
                Occupancy::Empty
            } else {
                Occupancy::Height(height)
            };
            assert_eq!(occupancy(count), expected, "{count}");
        }
        assert_eq!(height, 3, "the counts reach a fourth level");
        assert_eq!(raised(usize::MAX), usize::MAX);
    }

    /// The plan check's planted controls: a root holding a key more than it
    /// spans, a child's span moved to its sibling, and a node below the
    /// standard occupancy are each refused.
    #[test]
    fn a_planted_plan_defect_is_refused() {
        let (height, shapes) = planned(144);
        let mut ranks = Vec::new();
        let mut extra = shapes.clone();
        extra[0].keys += 1;
        assert!(
            !violations(144, height, &extra, &mut ranks).is_empty(),
            "an extra root key"
        );
        let mut moved = shapes.clone();
        moved[0].span -= 1;
        assert!(
            !violations(144, height, &moved, &mut ranks).is_empty(),
            "a span moved"
        );
        let mut sparse = shapes;
        let last = sparse.len() - 1;
        sparse[last].keys = 1;
        sparse[last].span = 1;
        assert!(
            !violations(144, height, &sparse, &mut ranks).is_empty(),
            "a sparse node"
        );
    }
}

/// The tree's declared cost against what its whole construction and cleanup
/// measure, recorded exactly ([`places::Tightness`]): a change to the cost's
/// arithmetic, in either direction, changes a recorded ratio and fails the
/// ratchet. Every admission is made inside the tree's one place, so the
/// check ([`places::check`]) also holds each run within its declared cost.
#[cfg(test)]
#[cfg(feature = "std")]
mod attribution {
    use super::*;
    use crate::bounded::decode::decode;
    use crate::bounded::places::{self, Ledgered, Run};
    use crate::bounded::{Budget, Places, ResourceBound, at};
    use alloc::string::ToString;
    use core::ops::ControlFlow;
    use core::ptr::NonNull;

    places! {
        /// A tree's whole construction and cleanup: the one place its
        /// declared cost covers.
        enum TreePlace {
            Construction,
        }
    }

    /// A tree's declared cost at one input's length: its one place's term.
    struct TreeTerms(ResourceBound);

    impl Places for TreeTerms {
        type Place = TreePlace;

        fn term(&self, _: TreePlace) -> ResourceBound {
            self.0
        }
    }

    /// The map `wire` holds, of keys `K` and integer values, built and then
    /// cleaned up, every admission at the tree's place and each loop within
    /// the steps of the declared cost.
    fn run<K: TreeKey + InPlace<Ledgered>>(name: &str, wire: &[u8]) -> Run<TreeTerms> {
        let mut parser = Ledgered::new();
        let document = decode(wire, 8, &mut parser).expect("the map decodes");
        // The tree's `COST`, evaluated here at run time: the engine evaluates
        // it only in constants, which coverage does not observe. Composed at
        // run time, an overflow is a refusal ([`BoundedError::Overflow`]).
        let cost = cost::cost::<K, u64, Ledgered>()
            .ok_or(BoundedError::<()>::Overflow)
            .and_then(|cost| cost.bound::<()>(wire.len() as u64))
            .expect("the cost of a fixture fits in u64");
        let mut policy = Ledgered::new();
        let mut pending = Pending::new(policy.owner().expect("an ordinary family mints an owner"));
        let mut destination = MaybeUninit::<BTreeMap<K, u64>>::uninit();
        let mut state = <BTreeMap<K, u64> as Reclaim<Ledgered>>::INITIAL;
        // SAFETY: the test owns the destination and pairs it with its initial
        // state; every access to either is through this slot for the run.
        let mut slot =
            unsafe { Slot::new(Place::root(NonNull::from(&mut destination)), &mut state) };
        crate::bounded::within(name, cost, || {
            let built = at(TreePlace::Construction, || {
                // The tree is stepped directly, outside a session, so its
                // root context is marked stepped here: its parts' records
                // verify against it, within this step.
                let mut root = Context::root(&document, slot.reborrow(), &mut pending);
                root.bind();
                build::<K, u64, Ledgered>(root, &mut policy)
            });
            match built.expect("the map builds") {
                Building::Done(_) => ControlFlow::Break(()),
                Building::Progress => ControlFlow::Continue(()),
            }
        });
        let mut steps = 0usize;
        crate::bounded::within(name, cost, || {
            let reclaimed = at(TreePlace::Construction, || {
                // The tree is the root of its cleanup, dispatched as the
                // engine dispatches a record's root (`reclamation.rs`,
                // `advance`): its declared depth taken, then one level
                // entered, so its parts' dispatches are within the
                // declaration.
                let mut cleanup = Cleanup::new(&mut policy);
                cleanup.declare(<BTreeMap<K, u64> as Reclaim<Ledgered>>::DISPATCH_DEPTH);
                cleanup.descend(|cleanup| {
                    cleanup::reclaim::<K, u64, Ledgered>(slot.reborrow(), cleanup)
                })
            });
            steps += 1;
            let reclaimed = reclaimed.unwrap_or_else(|error| {
                panic!("{name}: cleanup step {steps} under an unlimited policy failed: {error:?}")
            });
            match reclaimed {
                Reclaimed::Done => ControlFlow::Break(()),
                Reclaimed::Progress => ControlFlow::Continue(()),
                Reclaimed::Waiting => unreachable!("a tree's own cleanup never waits"),
            }
        });
        Run {
            name: name.to_string(),
            outcome: places::Outcome::Published,
            policy,
            terms: TreeTerms(cost),
        }
    }

    /// A map of `count` integer keys, each its own value.
    fn integers(count: u64) -> Vec<u8> {
        let mut map = crate::Map::new();
        for n in 0..count {
            map.insert(n, n).unwrap();
        }
        crate::CBOR::from(map).to_cbor_data()
    }

    /// A map of `count` text keys, each the hexadecimal of its value.
    fn texts(count: u64) -> Vec<u8> {
        let mut map = crate::Map::new();
        for n in 0..count {
            map.insert(alloc::format!("{n:x}"), n).unwrap();
        }
        crate::CBOR::from(map).to_cbor_data()
    }

    /// Every run of a tree is within its declared cost, and each run's cost
    /// against its measured total is a recorded ratio: an empty tree, one
    /// entry, a full leaf, a root over two leaves, two levels, and text keys
    /// compared byte by byte.
    #[test]
    fn a_trees_cost_is_recorded_against_its_whole_construction() {
        let runs = [
            run::<u64>("empty", &integers(0)),
            run::<u64>("one entry", &integers(1)),
            run::<u64>("a full leaf", &integers(11)),
            run::<u64>("a root over two leaves", &integers(12)),
            run::<u64>("two levels", &integers(144)),
            run::<String>("text keys", &texts(13)),
        ];
        places::check(&runs);
        places::Tightness::new("btree")
            .totals(&runs, places::EVERY)
            .finish();
    }
}
