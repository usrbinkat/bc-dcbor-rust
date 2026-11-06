//! Fixed-address B-tree construction. Sort document indices first, allocate
//! the final tree shape, then construct every key and value in its final slot.
extern crate alloc;
mod cleanup;
mod cost;
use super::*;
use crate::bounded::boundary::{Bound, Predicate, Valuation, boundary, units};
use crate::bounded::decode::construction::reclamation::{Admitted, Custody, Place};
use crate::bounded::decode::construction::stable::{self, Installed};
use crate::bounded::decode::initialization::field;
use crate::bounded::decode::storage::{Storage, StoragePosition};
use crate::sync::{Atomics, Representation};
use alloc::collections::{BTreeMap, btree_map::InPlaceNode};
use alloc::string::String;
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
/// `view` does constant work, never unwinds, allocates nothing, and returns a view exactly
/// when the kind can construct this key. Comparing views must agree with
/// `Self::Ord` for the constructed values. Bytes compare lexicographically;
/// integers compare numerically. A binding must always use the same variant.
/// A byte view borrows the key's own payload and is no longer than its encoded
/// subtree; this is required by the comparison bound.
pub unsafe trait TreeKey: Ord {
    fn view(kind: Kind<'_>) -> Option<TreeKeyView<'_>>;
}

// SAFETY: children are constructed only in their final node slots. Custody
// records cover every initialized prefix. Publication never moves a child.
// A build from any phase past publication is refused and changes nothing.
unsafe impl<K: TreeKey + InPlace<A>, V: InPlace<A>, A: Allocator> InPlace<A> for BTreeMap<K, V> {
    const COST: ConstructionCost = crate::const_cost!(cost::cost::<K, V, A>());
    fn build_step(
        document: &Document<'_, A::Permit>,
        index: usize,
        slot: Slot<'_, Self, Self::State>,
        a: &mut A,
    ) -> ConstructResult<Built, A> {
        build(document, index, slot, a)
    }
}

// SAFETY: cleanup detaches a published tree, reclaims children in reverse
// construction order, then frees nodes without reading their reclaimed slots.
// A step once cleanup is done reports `Done` and touches nothing.
unsafe impl<K: Reclaim<A>, V: Reclaim<A>, A: Allocator> Reclaim<A> for BTreeMap<K, V> {
    const DISPATCH_DEPTH: usize = if K::DISPATCH_DEPTH > V::DISPATCH_DEPTH {
        K::DISPATCH_DEPTH.saturating_add(1)
    } else {
        V::DISPATCH_DEPTH.saturating_add(1)
    };
    type State = State<K, V, A>;
    const INITIAL: Self::State = State {
        meta: None,
        admitted: stable::Admitted::Nothing,
        initialized: 0,
    };
    fn reclaim_step(slot: Slot<'_, Self, Self::State>, a: &mut A) -> BoundedResult<Reclaimed, A> {
        cleanup::reclaim(slot, a)
    }

    fn remaining(mut slot: PeekSlot<'_, Self, Self::State>) -> u64 {
        cleanup::remaining(slot.custody())
    }
}

// SAFETY: String construction copies the validated NFC text unchanged, and
// Rust's string ordering is lexicographic ordering of its UTF-8 bytes.
unsafe impl TreeKey for String {
    fn view(kind: Kind<'_>) -> Option<TreeKeyView<'_>> {
        match kind {
            Kind::Text(text) => Some(TreeKeyView::Bytes(text.as_bytes())),
            _ => None,
        }
    }
}

// SAFETY: ByteString preserves its bytes and orders them lexicographically.
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
        // SAFETY: these bindings accept precisely the representable integers;
        // their Rust order is the numeric order of this lossless i128 view.
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

// SAFETY: bool construction preserves the source boolean; false sorts first.
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

struct Meta<K: Reclaim<A>, V: Reclaim<A>, A: Allocator> {
    phase: Phase,
    order: [Storage<usize, A::Permit>; 2],
    nodes: Storage<Node<K, V, A::Permit>, A::Permit>,
    entries: Storage<Entry<K, V, A>, A::Permit>,
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

/// Typed custody of a partially constructed or published B-tree.
pub struct State<K: Reclaim<A>, V: Reclaim<A>, A: Allocator> {
    meta: Option<MetadataBlock<K, V, A>>,
    admitted: stable::Admitted,
    initialized: u8,
}

type MetadataBlock<K, V, A> = Installed<MaybeUninit<Meta<K, V, A>>, <A as Allocator>::Permit>;

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

/// What a tree's construction holds, by stage: no metadata block, with the
/// admissions held toward it; the block held with a prefix of its fields
/// written, each a plain value or an empty arena released with the block;
/// or every field written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[expect(
    clippy::large_enum_variant,
    reason = "custody snapshots include every arena and active child inline; observation must not allocate"
)]
pub enum TreeObservation<K, V> {
    Unallocated(Admitted),
    Initializing(u8),
    Held(TreeCustody<K, V>),
}

/// A tree's custody once its metadata is written, `K` and `V` its key's and
/// value's observations: the phase; each arena's stage and counts (the two
/// index arenas, the nodes, the entry records); the entries the map holds and
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
            return TreeObservation::Unallocated(self.admitted);
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

// SAFETY: all pointed-to allocations are exclusively owned by this state.
// Child destinations never move; their states and all permits are Send.
unsafe impl<K: Reclaim<A> + Send, V: Reclaim<A> + Send, A: Allocator> Send for State<K, V, A>
where
    K::State: Send,
    V::State: Send,
    A::Permit: Send,
{
}

const INIT: u8 = 16;
const COMPARE: crate::bounded::Capped<Caller> = crate::bounded::Capped::new(Caller, 3, 64);

/// One unit of the tree's metadata: its block installed, then one field per
/// unit, each recorded in the state's prefix before returning. A call once
/// the prefix is complete is refused.
fn initialize<K: Reclaim<A>, V: Reclaim<A>, A: Allocator>(
    state: &mut State<K, V, A>,
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
                &mut state.admitted,
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
    // SAFETY: the prefix records which fields are written, so each unit
    // initializes the next resource-free field once, recorded before
    // returning; the match refuses every unit past the last. No field is
    // read before all are initialized.
    unsafe {
        match state.initialized {
            0 => field(addr_of_mut!((*raw).phase), || Phase::Header, a)?,
            1 => field(addr_of_mut!((*raw).order[0]), Storage::new, a)?,
            2 => field(addr_of_mut!((*raw).order[1]), Storage::new, a)?,
            3 => field(addr_of_mut!((*raw).nodes), Storage::new, a)?,
            4 => field(addr_of_mut!((*raw).entries), Storage::new, a)?,
            5 => field(addr_of_mut!((*raw).count), || 0, a)?,
            6 => field(addr_of_mut!((*raw).position), || 0, a)?,
            7 => field(addr_of_mut!((*raw).source), || 0, a)?,
            8 => field(addr_of_mut!((*raw).sort), Sort::default, a)?,
            9 => field(addr_of_mut!((*raw).parent), || 0, a)?,
            10 => field(addr_of_mut!((*raw).slot), || 0, a)?,
            11 => field(addr_of_mut!((*raw).height), || 0, a)?,
            12 => field(
                addr_of_mut!((*raw).maximum),
                || InPlaceNode::<K, V>::CAPACITY,
                a,
            )?,
            13 => field(addr_of_mut!((*raw).pending_shape), Shape::default, a)?,
            14 => field(addr_of_mut!((*raw).pending_node), || None, a)?,
            15 => field(addr_of_mut!((*raw).pending_permit), || None, a)?,
            _ => return Err(BoundedError::PlanMismatch),
        }
    }
    state.initialized += 1;
    Ok(state.initialized == INIT)
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
    document: &Document<'_, A::Permit>,
    left: usize,
    right: usize,
    offset: &mut usize,
    a: &mut A,
) -> ConstructResult<Option<Ordering>, A> {
    // Both views are constant-work reads. Admission precedes their inspection.
    COMPARE.admit(a, 64)?;
    let left =
        K::view(node_at(document, left).ok_or_else(wrong_type)?.kind()).ok_or_else(wrong_type)?;
    let right =
        K::view(node_at(document, right).ok_or_else(wrong_type)?.kind()).ok_or_else(wrong_type)?;
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
/// internal in [`shape`], [`Shape::rank`] and the node's layout) and on root
/// against non-root, which the height fixes per level; every other
/// condition is a loop bound over a node's keys, edges or slots, each taken
/// for every nonempty tree. The fork's node code (`InPlaceNode`) branches
/// only on leaf against internal. The arithmetic within a class, every
/// node's keys, span and ranks for each count, is certified for every count
/// separately ([`planned`], its tests), so one tree per class, and the
/// counts on each side of a class's edge, witness every planning path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Occupancy {
    Empty,
    Height(u8),
}

/// The occupancy class of a tree of `count` entries ([`Occupancy`]).
pub fn occupancy(count: usize) -> Occupancy {
    if count == 0 {
        Occupancy::Empty
    } else {
        Occupancy::Height(planned(count).0)
    }
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
/// depends.
pub(crate) fn planned(count: usize) -> (u8, Vec<Shape>) {
    let (mut height, mut maximum, mut child_max) = (0u8, InPlaceNode::<(), ()>::CAPACITY, 0);
    while count > maximum {
        child_max = maximum;
        maximum = raised(maximum);
        height += 1;
    }
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

/// One unit of the tree's construction in `slot`.
fn build<K: TreeKey + InPlace<A>, V: InPlace<A>, A: Allocator>(
    document: &Document<'_, A::Permit>,
    index: usize,
    mut slot: Slot<'_, BTreeMap<K, V>, State<K, V, A>>,
    a: &mut A,
) -> ConstructResult<Built, A> {
    let (place, state) = slot.parts();
    if Bound::new(Predicate::Prefix, INIT).below(a, state.initialized) {
        initialize(state, a)?;
        return Ok(Built::Progress);
    }
    let m = meta(state)?;
    match m.phase {
        Phase::Header => {
            STEP.admit(a)?;
            let Kind::Map(count) = node_at(document, index).ok_or_else(wrong_type)?.kind() else {
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
                K::view(node_at(document, m.position).ok_or_else(wrong_type)?.kind())
                    .ok_or_else(wrong_type)?;
                let value =
                    super::super::next_index(node_at(document, m.position).ok_or_else(wrong_type)?);
                let next =
                    super::super::next_index(node_at(document, value).ok_or_else(wrong_type)?);
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
                return Ok(Built::Progress);
            };
            let Some(_) = m.order[1].settle_step(a)? else {
                return Ok(Built::Progress);
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
                    match compare::<K, A>(document, input[s.i], input[s.j], &mut s.offset, a)? {
                        None => return Ok(Built::Progress),
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
                return Ok(Built::Progress);
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
            // Only parent and length are written by the fork's allocation.
            const { cost::allocate_write::<K, V, A::Permit>() }.admit(a)?;
            m.phase = Phase::AllocateRelease;
        }
        Phase::AllocateRelease => {
            stable::admit_release(a)?;
            m.phase = Phase::Allocate;
        }
        Phase::Allocate => {
            let leaf = m.pending_shape.height == 0;
            let bytes = InPlaceNode::<K, V>::layout(leaf).size() as u64;
            let permit = a.allocate(bytes).map_err(BoundedError::Refused)?;
            let raw =
                InPlaceNode::try_allocate(leaf).map_err(|_| BoundedError::Allocation { bytes })?;
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
                return Ok(Built::Progress);
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
                return Ok(Built::Progress);
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
                return Ok(Built::Progress);
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
            let Some(entries) = m.entries.settle_step(a)? else {
                return Ok(Built::Progress);
            };
            let entry = entries
                .as_mut_slice()
                .last_mut()
                .ok_or(BoundedError::PlanMismatch)?;
            // SAFETY: the entry record pairs each final, stable destination,
            // rooted at its node slot, with the state that records its
            // initialized prefix throughout construction and cleanup.
            let done = if m.phase == Phase::Key {
                let key = unsafe { Slot::new(entry.key, &mut *entry.key_state) };
                K::build_step(document, m.position, key, a)?
            } else {
                let value = unsafe { Slot::new(entry.value, &mut *entry.value_state) };
                V::build_step(document, m.position, value, a)?
            };
            if done == Built::Done {
                if m.phase == Phase::Key {
                    m.position = super::super::next_index(
                        node_at(document, m.position).ok_or_else(wrong_type)?,
                    );
                    m.phase = Phase::Value;
                } else {
                    m.slot += 1;
                    m.phase = Phase::Entry;
                }
            }
        }
        Phase::Seal => {
            let Some(nodes) = m.nodes.settle_step(a)? else {
                return Ok(Built::Progress);
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
            return Ok(Built::Done);
        }
        _ => return Err(BoundedError::PlanMismatch.into()),
    }
    Ok(Built::Progress)
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
    fn violations(count: usize, height: u8, shapes: &[Shape]) -> Vec<String> {
        let mut found = Vec::new();
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
        let mut ranks = Vec::new();
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
                ranks.push(node.rank(slot));
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
        ranks.sort_unstable();
        if ranks != (0..count).collect::<Vec<_>>() {
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
        for count in 0..=20_000usize {
            if count > maximum {
                maximum = raised(maximum);
                height += 1;
            }
            let (planned_height, shapes) = planned(count);
            let found = violations(count, planned_height, &shapes);
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
        let mut extra = shapes.clone();
        extra[0].keys += 1;
        assert!(
            !violations(144, height, &extra).is_empty(),
            "an extra root key"
        );
        let mut moved = shapes.clone();
        moved[0].span -= 1;
        assert!(!violations(144, height, &moved).is_empty(), "a span moved");
        let mut sparse = shapes;
        let last = sparse.len() - 1;
        sparse[last].keys = 1;
        sparse[last].span = 1;
        assert!(
            !violations(144, height, &sparse).is_empty(),
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
    use crate::bounded::{Places, ResourceBound, at};
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
        let mut destination = MaybeUninit::<BTreeMap<K, u64>>::uninit();
        let mut state = <BTreeMap<K, u64> as Reclaim<Ledgered>>::INITIAL;
        // SAFETY: the test owns the destination and pairs it with its initial
        // state; every access to either is through this slot for the run.
        let mut slot =
            unsafe { Slot::new(Place::root(NonNull::from(&mut destination)), &mut state) };
        crate::bounded::within(name, cost, || {
            let built = at(TreePlace::Construction, || {
                build::<K, u64, Ledgered>(&document, 0, slot.reborrow(), &mut policy)
            });
            match built.expect("the map builds") {
                Built::Done => ControlFlow::Break(()),
                Built::Progress => ControlFlow::Continue(()),
            }
        });
        crate::bounded::within(name, cost, || {
            let reclaimed = at(TreePlace::Construction, || {
                cleanup::reclaim::<K, u64, Ledgered>(slot.reborrow(), &mut policy)
            });
            match reclaimed.expect("an unlimited policy never refuses") {
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
            map.insert(n, n);
        }
        crate::CBOR::from(map).to_cbor_data()
    }

    /// A map of `count` text keys, each the hexadecimal of its value.
    fn texts(count: u64) -> Vec<u8> {
        let mut map = crate::Map::new();
        for n in 0..count {
            map.insert(alloc::format!("{n:x}"), n);
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
