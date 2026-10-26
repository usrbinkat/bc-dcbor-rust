//! Fixed-address B-tree construction. Sort document indices first, allocate
//! the final tree shape, then construct every key and value in its final slot.
extern crate alloc;
mod cleanup;
mod cost;
use super::*;
use crate::bounded::decode::construction::reclamation::{Admitted, Custody};
use crate::bounded::decode::construction::stable::{self, Installed};
use crate::bounded::decode::initialization::field;
use crate::bounded::decode::storage::{Storage, StoragePosition};
use alloc::collections::{BTreeMap, btree_map::InPlaceNode};
use alloc::string::String;
use core::cmp::Ordering;
use core::mem::{ManuallyDrop, MaybeUninit, size_of};
use core::ptr::{NonNull, addr_of_mut};

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
unsafe impl<K: TreeKey + InPlace<A>, V: InPlace<A>, A: Allocator> InPlace<A> for BTreeMap<K, V> {
    const COST: ConstructionCost = cost::cost::<K, V, A>();
    unsafe fn build_step(
        document: &Document<'_, A::Permit>,
        index: usize,
        place: NonNull<MaybeUninit<Self>>,
        state: &mut Self::State,
        a: &mut A,
    ) -> ConstructResult<Built, A> {
        // SAFETY: forwarded from the InPlace caller.
        unsafe { build(document, index, place, state, a) }
    }
}

// SAFETY: cleanup detaches a published tree, reclaims children in reverse
// construction order, then frees nodes without reading their reclaimed slots.
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
    unsafe fn reclaim_step(
        place: NonNull<MaybeUninit<Self>>,
        state: &mut Self::State,
        a: &mut A,
    ) -> BoundedResult<Reclaimed, A> {
        // SAFETY: forwarded from the Reclaim caller.
        unsafe { cleanup::reclaim(place, state, a) }
    }

    unsafe fn remaining(_: NonNull<MaybeUninit<Self>>, state: &mut Self::State) -> u64 {
        cleanup::remaining(state)
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

struct Entry<K: Reclaim<A>, V: Reclaim<A>, A: Allocator> {
    key: NonNull<MaybeUninit<K>>,
    value: NonNull<MaybeUninit<V>>,
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

unsafe fn initialize<K: Reclaim<A>, V: Reclaim<A>, A: Allocator>(
    state: &mut State<K, V, A>,
    a: &mut A,
) -> BoundedResult<bool, A> {
    if state.meta.is_none() {
        // SAFETY: the held value is MaybeUninit; only its permit is written.
        unsafe {
            stable::install(
                &mut state.meta,
                &mut state.admitted,
                const {
                    stable::Metadata::new::<MaybeUninit<Meta<K, V, A>>, A::Permit>(size_of::<
                        A::Permit,
                    >(
                    ))
                },
                // Uninitialized bytes already form a valid MaybeUninit. Do
                // not synthesize or copy the large metadata value here.
                |_| {},
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
    // SAFETY: each unit initializes one resource-free field, with its prefix
    // recorded before returning. No field is read before all are initialized.
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
            let common = l.len().min(r.len());
            let end = common.min(offset.saturating_add(32));
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

unsafe fn build<K: TreeKey + InPlace<A>, V: InPlace<A>, A: Allocator>(
    document: &Document<'_, A::Permit>,
    index: usize,
    place: NonNull<MaybeUninit<BTreeMap<K, V>>>,
    state: &mut State<K, V, A>,
    a: &mut A,
) -> ConstructResult<Built, A> {
    if state.initialized < INIT {
        // SAFETY: construction owns the destination and its metadata prefix.
        unsafe {
            initialize(state, a)?;
        }
        return Ok(Built::Progress);
    }
    // SAFETY: the complete prefix initializes all metadata fields.
    let m = unsafe {
        state
            .meta
            .as_mut()
            .ok_or(BoundedError::PlanMismatch)?
            .get()
            .assume_init_mut()
    };
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
            if m.order[0].len() == m.count {
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
            if m.sort.width >= m.count {
                m.phase = Phase::Height;
            } else {
                let s = &mut m.sort;
                s.mid = m.count.min(s.left.saturating_add(s.width));
                s.end = m.count.min(s.mid.saturating_add(s.width));
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
            if m.count <= m.maximum {
                m.phase = Phase::PlanRoot;
            } else {
                m.pending_shape.child_max = m.maximum;
                m.maximum = m
                    .maximum
                    .checked_add(1)
                    .and_then(|n| n.checked_mul(12))
                    .and_then(|n| n.checked_sub(1))
                    .unwrap_or(usize::MAX);
                m.height += 1;
            }
        }
        Phase::PlanRoot => {
            STEP.admit(a)?;
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
            if nodes.len() > 1 {
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
                if node.shape.height == 0 || node.shape.edge > node.shape.keys {
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
                    // SAFETY: the final node's slot is unique and not yet built.
                    let (key, value) = unsafe { node.raw.slot(m.slot) };
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
            // SAFETY: the entry record owns these final, stable destinations
            // and records both initialized prefixes throughout construction.
            let done = unsafe {
                if m.phase == Phase::Key {
                    K::build_step(document, m.position, entry.key, &mut entry.key_state, a)?
                } else {
                    V::build_step(document, m.position, entry.value, &mut entry.value_state, a)?
                }
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
            unsafe {
                place
                    .as_ptr()
                    .write(MaybeUninit::new(BTreeMap::from_in_place(
                        nodes.first().map(|n| &n.raw),
                        usize::from(m.height),
                        m.count,
                    )));
            }
            m.phase = Phase::Complete;
            return Ok(Built::Done);
        }
        _ => return Err(BoundedError::PlanMismatch.into()),
    }
    Ok(Built::Progress)
}
