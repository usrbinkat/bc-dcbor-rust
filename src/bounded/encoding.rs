//! Retained schema traversal and canonical byte preparation.
use super::boundary::boundary;
use super::*;
use core::mem::{MaybeUninit, size_of};
use core::ptr::{NonNull, addr_of, addr_of_mut};
use decode::construction::in_place::{InPlace, Transferable};
// The record destination is named `reclamation::Place` here: the bare name is
// the accounting trait `bounded::Place`, which `PreparationPlace::ALL` needs.
// A destination's slot is named `reclamation::Slot` for the same reason: the
// bare name is this module's entry-cursor storage, [`Slot`].
use decode::construction::reclamation::{
    self, Cleanup, PeekSlot, Prefix, Reclaim, Reclaimed, ScopeRef,
};
use decode::construction::{
    DecodeInput, Observed, Operation, OperationTerms, OwnedInitialized, Task, TypedValue,
};
use decode::initialization::field;
use decode::storage::Storage;
use text_cursor::{TextContinuation, TextShape};
#[cfg(any(feature = "hashbrown", feature = "custom-std-collections"))]
pub mod buckets;
#[cfg(any(feature = "hashbrown", feature = "custom-std-collections"))]
use buckets::{BucketCursor, BucketPosition, BucketStep, Buckets};
mod dynamic;
mod permutation;
pub use permutation::{PermutationPhase, PermutationPosition};
pub mod maps;
pub use dynamic::{DynamicPhase, DynamicPosition};
mod values;
pub use values::Tagged;
pub(crate) use values::{tree_next, tree_start, tree_step_moves};
mod writer;
pub use writer::{
    EmitPosition, OwnedEmitPosition, OwnedEmitStep, OwnedWriter, emit_bound, owned_emit_bound,
};
/// Kani harness of the preparation's whole-operation bound (register item
/// 4): compiled only by `cargo kani`.
#[cfg(kani)]
mod preparation_proofs;
/// Kani harnesses of the encoding's count recurrences and its smallest
/// whole-operation bound (register item 4): compiled only by `cargo kani`.
#[cfg(kani)]
mod proofs;

/// One bounded-work schema instruction. Implementations must not scan fields,
/// allocate, or recursively visit children while producing an instruction.
/// An unordered map yields its entries one per instruction
/// ([`Instruction::Entry`]), or hands the engine a cursor
/// ([`Instruction::Entries`]) or, for a hash table, the table itself
/// ([`Instruction::Buckets`]), whose buckets only the engine inspects, each
/// window of controls admitted first.
/// References and representation must remain stable for the preparation borrow.
/// Implementing this safe trait does not authorize transferring retained
/// instructions or cursors between threads. Owned preparation additionally
/// requires the recursive safety contract of [`TransferableSchema`].
pub trait Schema {
    fn instruction(&self, index: usize) -> Instruction<'_>;
}

/// A schema whose complete retained traversal can move between threads.
/// Borrowed preparation needs only `Schema`; owning transferable preparation
/// requires this additional, explicit safety proof.
///
/// # Safety
/// An implementation keeps three obligations, and the `// SAFETY:` comment
/// on it names each as `label:` (`tests/unsafe_census.rs`, `UNSAFE_TRAITS`,
/// which lists every implementation):
///
/// - *references*: every reference returned by every reachable instruction
///   remains valid and safe to access on any thread while the root is
///   retained unchanged: descendants, pending entry values, entry sources,
///   text, bytes and bignum digits, even when the root does not own them
///   directly.
/// - *cursors*: every initialized `Entries` slot reachable from this schema
///   permits thread transfer at every suspension point, and no cursor relies
///   on thread-local state or thread-affine resources.
/// - *recursion*: both hold for every reachable descendant; `Self: Sync`
///   alone does not establish them.
///
/// ```compile_fail,E0277
/// use dcbor::bounded::encoding::{Schema, Instruction, TransferableSchema};
/// struct Root;
/// impl Schema for Root {
///     fn instruction(&self, _: usize) -> Instruction<'_> { Instruction::End }
/// }
/// fn transferable<T: TransferableSchema>() {}
/// // Sync and a safe Schema implementation do not grant transfer authority.
/// transferable::<Root>();
/// ```
///
/// A transferable container cannot promote a safe-only descendant:
/// ```compile_fail,E0277
/// use dcbor::bounded::encoding::{Schema, Instruction, TransferableSchema};
/// struct Child;
/// impl Schema for Child {
///     fn instruction(&self, _: usize) -> Instruction<'_> { Instruction::End }
/// }
/// fn transferable<T: TransferableSchema>() {}
/// transferable::<Vec<Child>>();
/// ```
pub unsafe trait TransferableSchema: Schema + Sync {}

macro_rules! transferable_scalars {
    ($($ty:ty),* $(,)?) => {$(
        // SAFETY: references: a scalar's instructions are heads, retaining
        // no external state; a string's and a byte string's expose only the
        // immutable storage their root holds. cursors: none, no instruction
        // is `Entries`. recursion: none, no instruction is a child.
        unsafe impl TransferableSchema for $ty {}
    )*};
}
transferable_scalars!(
    u8,
    u16,
    u32,
    u64,
    i8,
    i16,
    i32,
    i64,
    bool,
    String,
    str,
    crate::ByteString
);

// SAFETY: references: its instructions are its slice's, a head and a child
// reference to each element the vector holds immutably while retained.
// cursors: none of its own. recursion: every element is `T:
// TransferableSchema`.
unsafe impl<T: TransferableSchema> TransferableSchema for Vec<T> {}
// SAFETY: references: its instructions are its slice's, a head and a child
// reference to each element held inline. cursors: none of its own.
// recursion: every element is `T: TransferableSchema`.
unsafe impl<T: TransferableSchema, const N: usize> TransferableSchema for [T; N] {}
// SAFETY: references: its instructions are its content's, held immutably
// behind the box while retained. cursors: none of its own. recursion: the
// content is `T: TransferableSchema`.
unsafe impl<T: TransferableSchema + ?Sized> TransferableSchema for Box<T> where Box<T>: Schema {}

pub enum Instruction<'a> {
    Head(MajorType, Argument),
    Text(&'a str),
    Bytes(&'a [u8]),
    Child(&'a dyn Schema),
    /// Begin a map whose present fields are counted as they are visited,
    /// its head written into a gap once `End` knows the count.
    Map,
    /// Begin a map of exactly this many present fields, its head written
    /// at once; `End` refuses any other number of fields visited.
    CountedMap(u64),
    Field(u64, Option<&'a dyn Schema>),
    /// Begin a map whose entries are ordered by their prepared key bytes,
    /// its head written into a gap once `End` knows the count.
    UnorderedMap,
    /// Begin a map of exactly this many entries ordered by their prepared
    /// key bytes, its head written at once. The map ends once that many
    /// entries are yielded, its source asked for nothing further; an `End`
    /// before them is refused. A source states the count of the entries it
    /// holds.
    CountedUnorderedMap(u64),
    /// Values the source examines to produce its next instruction, such as
    /// the presence of each optional field a `CountedMap` counts: admitted
    /// before that instruction is requested.
    Inspect(u64),
    /// A bignum: its tag, then the byte string of its magnitude's
    /// big-endian bytes, less one when `negative`, read from its digits a
    /// quantum at a time (`bigint.rs`).
    #[cfg(feature = "num-bigint")]
    Bignum {
        magnitude: &'a num_bigint::BigUint,
        negative: bool,
    },
    /// One entry of the unordered map this source began, its key and its
    /// value: the next instruction is the next index. A source inspects
    /// nothing to produce it.
    Entry(&'a dyn Schema, &'a dyn Schema),
    /// The entries of the unordered map this source began, drawn from a
    /// cursor the engine retains, for collections without positional access.
    /// Valid once per map, before any entry; no further instruction of this
    /// source is requested.
    Entries(&'a dyn Entries),
    /// The hash table whose entries are the unordered map this source
    /// began, enumerated by the engine's one bucket traversal
    /// ([`buckets::BucketCursor`]), a window of controls admitted before it
    /// is inspected. Valid once per map, before any entry; no further
    /// instruction of this source is requested.
    #[cfg(any(feature = "hashbrown", feature = "custom-std-collections"))]
    Buckets(&'a dyn Buckets),
    /// The source value is outside the dCBOR profile; preparation fails with
    /// [`BoundedError::OutOfRange`].
    OutOfRange,
    End,
}

/// Bytes of inline cursor storage an [`Entries`] source may use. The cursor
/// arena's element write-extent assertion checks the slot and source reference
/// together against the quantum on the target toolchain.
pub const SLOT_BYTES: usize = 48;

/// Inline storage for one [`Entries`] cursor, retained in the engine's cursor
/// arena and relocated with it. Nothing stored here is ever dropped.
#[derive(Clone, Copy)]
#[repr(C, align(8))]
pub struct Slot {
    bytes: [MaybeUninit<u8>; SLOT_BYTES],
}

impl Slot {
    const fn new() -> Self {
        Self {
            bytes: [MaybeUninit::uninit(); SLOT_BYTES],
        }
    }

    /// Store `cursor`. It must fit, be no more aligned than the slot, and own
    /// nothing that needs dropping; violations fail to compile.
    pub fn put<C>(&mut self, cursor: C) {
        const {
            assert!(size_of::<C>() <= SLOT_BYTES);
            assert!(core::mem::align_of::<C>() <= core::mem::align_of::<Slot>());
            assert!(!core::mem::needs_drop::<C>());
        }
        // SAFETY: the storage is large and aligned enough for `C`.
        unsafe { self.bytes.as_mut_ptr().cast::<C>().write(cursor) };
    }

    /// # Safety
    /// The slot holds a `C` stored by [`Self::put`].
    pub unsafe fn get<C>(&mut self) -> &mut C {
        // SAFETY: forwarded from the caller.
        unsafe { &mut *self.bytes.as_mut_ptr().cast::<C>() }
    }

    /// The stored cursor, shared: [`Self::get`] for an observation.
    ///
    /// # Safety
    /// The slot holds a `C` stored by [`Self::put`].
    pub unsafe fn peek<C>(&self) -> &C {
        // SAFETY: forwarded from the caller.
        unsafe { &*self.bytes.as_ptr().cast::<C>() }
    }
}

/// What one admitted step of an [`Entries`] cursor reached.
pub enum EntryStep<'a> {
    /// One structural transition, such as a descent or an ascent; no entry.
    Progress,
    /// The next entry.
    Entry(&'a dyn Schema, &'a dyn Schema),
    /// Every entry was yielded.
    End,
}

/// A map source traversed by a cursor it keeps in a [`Slot`] instead of by
/// instruction index. `start` and each `next` perform at most
/// [`Self::moves`] node moves beyond the one transition the engine's
/// instruction admits, and the engine admits those moves first: an ordered
/// tree's stepped cursor makes one transition per call and states none; a
/// tree's iterator states its height's ascent and descent. No call compares
/// keys or searches.
///
/// # Safety
/// An implementation keeps three obligations, and the `// SAFETY:` comment
/// on it names each as `label:`, with the resource obligation below as
/// `moves:` (`tests/unsafe_census.rs`, `UNSAFE_TRAITS`, which lists every
/// implementation):
///
/// - *cursor type*: `start` must [`Slot::put`] a cursor that `next` reads
///   back as the same type.
/// - *self-reference*: the cursor may borrow `self`, which the preparation
///   borrow keeps unchanged; it must not refer to its own storage, because
///   the arena holding it moves.
/// - *transfer*: when reachable from a `TransferableSchema`, the initialized
///   cursor and every reference it yields satisfy that trait's recursive
///   thread-transfer contract at every suspension point. A slot's size and
///   lack of drop glue do not establish it.
///
/// [`Self::ordered`] is no obligation: a source claiming canonical order is
/// checked key by key against the key before it, and one yielding keys out
/// of order is refused [`BoundedError::PlanMismatch`] (`dynamic.rs`,
/// `DynamicPhase::Verify`), so a false claim refuses, never misencodes.
///
/// # Resource obligation
/// Not memory safety, and so not part of the `unsafe` contract above:
/// *moves*: `start` and each `next` make at most [`Self::moves`] node moves
/// beyond their one transition, and [`Self::moves`] is fixed for the
/// borrow. The engine admits that many before each call, but
/// the moves happen inside the cursor's own code and are reported to
/// nothing, so it cannot observe an overspend. The resource bounds (I5)
/// hold for a cursor only under this obligation, which is part of their
/// trusted domain (`tests/resumable/CONTRACT.md`, "Admission route and
/// trusted domain"). The crate's own cursors, the standard tree's
/// (`values.rs`) and [`crate::Map`]'s, keep it: a tree's stepped walk
/// compares no key and moves at most its stated height
/// (`bounded::tests::a_tree_iterators_steps_compare_no_keys`), a map's
/// entries take their encoded-key order in its walk
/// (`bounded::tests::a_maps_iteration_order_is_its_encoded_key_order`), and
/// the preparation's places check every admitted cursor unit against its
/// term (`every_place_of_a_preparation_is_within_its_term`).
pub unsafe trait Entries {
    fn start(&self, slot: &mut Slot);

    /// The most node moves `start` or one `next` makes beyond one
    /// transition, computed in constant time.
    fn moves(&self) -> u64;

    /// Whether the entries come in the canonical order of their encoded
    /// keys, as a tree keyed by those encodings yields them: the engine
    /// checks the order in one pass over adjacent keys instead of sorting.
    fn ordered(&self) -> bool;

    /// One transition of the cursor.
    ///
    /// # Safety
    /// `slot` was started by this source.
    unsafe fn next<'a>(&'a self, slot: &mut Slot) -> EntryStep<'a>;
}

/// The height of a standard-library B-tree of `len` entries, at most: every
/// node but the root holds at least `B - 1 = 5` entries
/// (`alloc::collections::btree::map::MIN_LEN`), so `h` levels hold at least
/// `2 * 6^(h - 1) - 1` entries.
pub const fn tree_height(len: usize) -> u64 {
    let mut height = 1u64;
    // The fewest entries a tree of `height + 1` levels holds.
    let mut fewest = 11u128;
    while fewest <= len as u128 {
        height += 1;
        fewest = (fewest + 1) * 6 - 1;
    }
    height
}

/// The node moves one step of a standard-library B-tree iterator makes at
/// most over a tree of `len` entries: up to the first ancestor holding a
/// next entry, then down to the leftmost leaf beneath it, each at most the
/// height ([`tree_height`]).
pub const fn tree_moves(len: usize) -> u64 {
    2 * tree_height(len)
}

/// One open source of a preparation: plain data, references and counts, so
/// an arena of them is discarded in one admitted unit
/// (`Storage::reclaim_copy_step`).
#[derive(Clone, Copy)]
struct Frame<'a> {
    source: &'a dyn Schema,
    next: usize,
    map: Option<usize>,
    /// Entries come from the top of the cursor arena, not from `source`.
    ordered: bool,
    /// The top cursor is not yet started: its first transition starts it.
    fresh: bool,
    /// The node moves of the top cursor's next transition admitted so far,
    /// in units of at most [`UNIT_VALUES`]: the transition is made once all
    /// are admitted, and the count is kept across refusals.
    moved: u64,
}

/// Where an unordered map's current entry is.
#[derive(Clone, Copy, PartialEq, Eq)]
enum EntryPhase {
    Scan,
    /// Its key is prepared; its value, held beside the phase, is next.
    Key,
    Value,
    Order,
}
#[derive(Clone, Copy)]
enum MapState<'a> {
    Schema {
        fields: u64,
    },
    Dynamic {
        start: usize,
        phase: EntryPhase,
        /// The value of the entry whose key is prepared, while `phase` is
        /// `Key`.
        value: Option<&'a dyn Schema>,
        /// Entries drawn from a cursor that yields them in canonical order.
        ordered: bool,
    },
}
/// How a map's head is written: at once, carrying the count its source
/// stated, or into a gap once `End` knows the count.
#[derive(Clone, Copy)]
enum MapHead {
    Counted(u64),
    /// The gap, by index.
    Gap(usize),
}
/// Whether `map`, open with `entries` entries in the entry arena, is an
/// unordered map whose head declared its count and whose source has yielded
/// that many, the last compacted: no further entry can be in a collection of
/// that count, so the map ends without its source scanning past its last
/// entry, as an iterator over a table stops at its item count. A source
/// yielding fewer before its end is refused at the end
/// ([`BoundedError::PlanMismatch`]); a counted source states its count
/// truthfully (its `Schema` contract), so none yields more. [`Shape::of`]
/// walks the same entries and the same end ([`yielded_all`]).
fn counted_complete(map: &MapFrame<'_>, entries: usize) -> bool {
    match (map.head, &map.state) {
        (
            MapHead::Counted(declared),
            MapState::Dynamic {
                start,
                phase: EntryPhase::Scan,
                ..
            },
        ) => entries
            .checked_sub(*start)
            .and_then(|yielded| u64::try_from(yielded).ok())
            .is_some_and(|yielded| yielded_all(Some(declared), yielded)),
        _ => false,
    }
}

/// Whether an unordered map that `declared` its count, if it did, has
/// yielded that many entries: the one end rule of the preparation
/// ([`counted_complete`]) and of the walk ([`Shape::of`]).
fn yielded_all(declared: Option<u64>, yielded: u64) -> bool {
    declared == Some(yielded)
}

fn check_count<R>(declared: Option<u64>, actual: u64) -> Result<(), BoundedError<R>> {
    if declared.is_some_and(|count| count != actual) {
        return Err(BoundedError::PlanMismatch);
    }
    Ok(())
}

/// An open map: one element of the open-map arena, which relocates an
/// element in one admitted unit, so it fits a quantum (`Storage`). Plain
/// data, so an arena of them is discarded in one admitted unit
/// (`Storage::reclaim_copy_step`).
#[derive(Clone, Copy)]
struct MapFrame<'a> {
    head: MapHead,
    /// The first gap of the map's own payload, by index.
    holes_start: usize,
    /// The first byte of the map's payload, after its head or its gap.
    data_start: usize,
    state: MapState<'a>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Position {
    /// The five traversal and output arenas in their authoritative growth
    /// states. Counts alone do not distinguish a retained growth admission
    /// from an allocated staging block or a relocated arena.
    pub frames: decode::storage::StoragePosition,
    pub bytes: decode::storage::StoragePosition,
    pub holes: decode::storage::StoragePosition,
    pub maps: decode::storage::StoragePosition,
    pub cursor_storage: decode::storage::StoragePosition,
    /// Two custody parts per open cursor: acquisition, then credit.
    pub window_storage: decode::storage::StoragePosition,
    pub finished: bool,
    pub child: bool,
    pub inspect: Option<u64>,
    pub omitted: usize,
    pub capacity_limit: usize,
    /// Presence distinguishes a held empty output from no output.
    pub normalized_output: Option<usize>,
    pub text_initialized: usize,
    pub text_initialization_steps: usize,
    /// Traversal selected normalization rather than the quick-check path.
    pub normalizing: bool,
    pub depth: usize,
    pub instruction: usize,
    pub prepared_bytes: usize,
    pub pending_bytes: usize,
    pub relocated_frames: usize,
    pub relocated_bytes: usize,
    pub relocated_headers: usize,
    pub normalized_bytes_copied: usize,
    /// The bytes of the current text its quick check has read, while it
    /// reads.
    pub quick_checked: Option<usize>,
    pub normalization: Option<text_cursor::Position>,
    /// The node moves admitted toward the top entry cursor's next
    /// transition, kept across refusals.
    pub cursor_moves: u64,
    /// Retained entry cursors, including a cursor waiting for its first step.
    pub cursors: usize,
    pub dynamic: DynamicPosition,
    /// The current bignum's digits read in its pass, and whether its bytes
    /// are being emitted.
    pub bignum: Option<(usize, bool)>,
}

/// Owns only flat arenas and borrowed source references. No source value is
/// cloned or destroyed by cancellation of encoding. A terminal error ends
/// the preparation's work: every later step performs its own cleanup, one
/// admitted unit of [`Self::reclaim_step`] each, until it reports
/// [`Step::Finished`], as every [`Resumable`] operation's does; a cancelled
/// preparation's cleanup is [`Self::reclaim_step`] itself. Publication moves
/// only the plan out: the arenas the preparation walked with stay until its
/// drop, which releases whatever remains.
///
/// ```compile_fail,E0502
/// use dcbor::bounded::encoding::Preparation;
/// let mut source = vec![1u64, 2];
/// let operation = Preparation::<(), ()>::new(&source);
/// source.push(3);
/// drop(operation);
/// ```
pub struct Preparation<'a, P, O: Origin> {
    frames: Storage<Frame<'a>, P, O>,
    bytes: Storage<u8, P, O>,
    holes: Storage<(usize, usize), P, O>,
    child: Option<&'a dyn Schema>,
    staged: Staged,
    payload: &'a [u8],
    /// The normalization of the current text, present exactly when
    /// `text_init` is its whole initialization
    /// ([`TextContinuation::INIT_STEPS`]). A published continuation's arenas
    /// and its output acquisition keep their owners, each holding its
    /// session, so it is destroyed in place at its publication
    /// (`retire_text`), and the next text's initialization writes
    /// uninitialized storage only, never over a live owner. A partial prefix
    /// holds no owned field, so it needs no destruction; nothing reads the
    /// continuation until every unit is written.
    text: MaybeUninit<TextContinuation<(), P, O>>,
    /// The text being normalized.
    text_source: Option<&'a str>,
    /// Initialization units of `text` written since it was last destroyed.
    text_init: usize,
    /// The quick check of `text_source` while it reads: a text it proves
    /// normal is copied as it is; one it leaves unproven, with this `None`,
    /// is normalized.
    text_check: Option<TextCheck>,
    normalized: Option<Encoded<P>>,
    normalized_at: usize,
    omitted: usize,
    end: End,
    dynamic: dynamic::Dynamic<P, O>,
    map_frames: Storage<MapFrame<'a>, P, O>,
    /// The retained cursors of the open [`Instruction::Entries`] and
    /// [`Instruction::Buckets`] maps, innermost last: an entry source and
    /// its cursor's slot, or no source and a slot holding a hash table and
    /// its [`buckets::BucketCursor`]. The reference's niche keeps an element
    /// at a quantum.
    cursors: Storage<(Option<&'a dyn Entries>, Slot), P, O>,
    /// Cursor i owns parts 2*i and 2*i+1, pushed and popped with it.
    /// Entry cursors retain an empty pair. Each part fits one relocation
    /// unit; the capabilities together need not fit a contiguous element.
    windows: Storage<WindowPart<O>, P, O>,
    /// The owner of the preparation's own acquisitions, its bucket windows:
    /// uninitialized until the first window's admission, which makes it
    /// under whatever budget performs it and keeps it for the preparation's
    /// life, never replaced; every window admission validates it
    /// ([`crate::bounded::Rate::admit_held`]).
    owner: decode::construction::stable::OwnerState,
    /// The most bytes the plan's arena grows to: the source's extent when
    /// a shape walk established it, so the published arena holds no more.
    cap: usize,
    /// Values an [`Instruction::Inspect`] announced, admitted before the
    /// next instruction is requested.
    inspect: Option<u64>,
    /// The bignum being read and emitted (`bigint.rs`).
    #[cfg(feature = "num-bigint")]
    bignum: Option<super::bigint::Bignum<'a>>,
}

/// How far a preparation has ended: what its next step does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum End {
    /// Preparing.
    Running,
    /// Its plan completed, moved out or kept in place: later steps report
    /// `Finished`.
    Published,
    /// A terminal error or a cancellation: its cleanup is owed, a step a
    /// unit of it ([`Preparation::reclaim_step`]).
    Failed,
    /// Its cleanup reported `Done`: it holds nothing, and later steps report
    /// `Finished`.
    Reclaimed,
}

/// Distinct authorities of one window, stored as adjacent arena elements.
enum WindowPart<O: Origin> {
    Acquisition(Option<crate::bounded::Acquisition<O>>),
    Credit(Option<Retained<O>>),
}

const WINDOW_PART_FAMILY_FITS_QUANTUM: () = assert!(
    size_of::<WindowPart<Family>>() <= TURN.bytes as usize,
    "WindowPart<Family> must fit one storage relocation unit; window custody uses two parts per cursor"
);

/// An even cap preserves two free slots whenever pairwise insertion leaves
/// any room: growth starts at four and doubles, clamped to this even cap.
const WINDOW_PART_MAXIMUM: usize = usize::MAX - 1;

/// Validate settled adjacency before growth separates pairs. Relocation's
/// unordered traversal validates counts, not adjacency.
fn windows_valid<P, O: Origin>(windows: &Storage<WindowPart<O>, P, O>, cursors: usize) -> bool {
    let settled = windows.settled().is_some();
    let (mut acquisitions, mut credits) = (0usize, 0usize);
    let mut expected_acquisition = true;
    let mut identity = None;
    let mut valid = true;
    windows.for_each(|part| match part {
        WindowPart::Acquisition(acquisition) => {
            acquisitions += 1;
            if settled {
                valid &= expected_acquisition;
                expected_acquisition = false;
                identity = acquisition.as_ref().map(crate::bounded::Acquisition::id);
            }
        }
        WindowPart::Credit(credit) => {
            credits += 1;
            if settled {
                valid &= !expected_acquisition;
                expected_acquisition = true;
                if let Some(credit) = credit {
                    valid &= identity == Some(credit.acquisition());
                }
            }
        }
    });
    valid && acquisitions == cursors && credits == cursors
}

/// Whether the window arena still holds any capability: a credit or an
/// acquisition in some part. Exactly the states in which terminal closure
/// has custody to protect: before the first cleanup entry or destruction,
/// whether the preparation completed, failed or neither. Once closed, every
/// part is empty, and cleanup's later units (the cursor arena cleared, the
/// window arena drained one part at a time) change the counts that
/// [`windows_valid`] relates, legitimately: those states hold nothing.
fn windows_hold_capability<P, O: Origin>(windows: &Storage<WindowPart<O>, P, O>) -> bool {
    let mut held = false;
    windows.for_each(|part| {
        held |= match part {
            WindowPart::Acquisition(acquisition) => acquisition.is_some(),
            WindowPart::Credit(credit) => credit.is_some(),
        };
    });
    held
}

/// Whether terminal closure finds the window custody malformed: only while
/// it still holds a capability ([`windows_hold_capability`]), then by
/// [`windows_valid`] against the cursor count.
fn windows_malformed<P, O: Origin>(windows: &Storage<WindowPart<O>, P, O>, cursors: usize) -> bool {
    windows_hold_capability(windows) && !windows_valid(windows, cursors)
}

fn invalidate_windows(owner: &decode::construction::stable::OwnerState) {
    if let decode::construction::stable::OwnerState::Initialized(owner) = owner {
        owner.invalidate_with(Invalidation::MalformedWindow);
    }
}

/// One cursor's window, borrowed apart from its arena: the credit part and
/// the acquisition part, two disjoint borrows of adjacent elements
/// ([`window_pair`]), in the order [`buckets::BucketCursor::new`] takes them.
type WindowParts<'p, O> = (
    &'p mut Option<Retained<O>>,
    &'p mut Option<crate::bounded::Acquisition<O>>,
);

/// The window parts of cursor `cursor` in `parts`, the arena's settled
/// elements: indices `2 * cursor` (acquisition) and `2 * cursor + 1`
/// (credit), split into disjoint borrows. Overflow of the index is refused
/// `Overflow`; a missing part, a part of the wrong kind, or credit held for
/// another acquisition than the pair's is refused `PlanMismatch`.
fn window_pair<'p, O: Origin, R>(
    parts: &'p mut [WindowPart<O>],
    cursor: usize,
) -> Result<WindowParts<'p, O>, BoundedError<R>> {
    let start = cursor.checked_mul(2).ok_or(BoundedError::Overflow)?;
    let end = start.checked_add(2).ok_or(BoundedError::Overflow)?;
    let pair = parts
        .get_mut(start..end)
        .ok_or(BoundedError::PlanMismatch)?;
    let (first, second) = pair.split_at_mut(1);
    let (WindowPart::Acquisition(acquisition), WindowPart::Credit(credit)) =
        (&mut first[0], &mut second[0])
    else {
        return Err(BoundedError::PlanMismatch);
    };
    if let Some(credit) = credit.as_ref()
        && acquisition.as_ref().map(crate::bounded::Acquisition::id) != Some(credit.acquisition())
    {
        return Err(BoundedError::PlanMismatch);
    }
    Ok((credit, acquisition))
}

/// A window obligation as a custody observation, visited once when it holds
/// anything: the one reading of a window's custody, a bucket cursor's
/// ([`buckets::BucketCursor`]) and a preparation's window arena's alike. A
/// window spent to nothing is taken at once, so a held one is nonzero; one
/// holding nothing is not visited all the same. Allocation-free.
pub(crate) fn window_obligation<O: Origin>(
    window: &Option<Retained<O>>,
    visit: &mut dyn FnMut(Hold),
) {
    if let Some(window) = window
        && window.remaining() != WriteWork::default()
    {
        visit(window.observation());
    }
}

/// Every open cursor's window obligation, each reported once into the
/// group open in `sink`, the preparation's own, under the owner whose
/// acquisitions the windows are: the window arena's elements, which the
/// preparation owns ([`window_obligation`]).
fn window_obligations<P, O: Origin>(
    windows: &Storage<WindowPart<O>, P, O>,
    sink: &mut dyn CustodySink<P>,
) {
    windows.for_each(|part| {
        if let WindowPart::Credit(window) = part {
            window_obligation(window, &mut |hold| sink.held(hold));
        }
    });
}

/// Close every open cursor's window: every window obligation forfeited
/// under `rule` into the family that admitted it, then every window's
/// acquisition ended, `by` the performing budget: cleanup entry's and
/// destruction's settlement of the window arena, before it is
/// reclaimed. Every credit is settled before any acquisition ends, so each
/// window's settlement precedes its end whatever order the arenas visit
/// their elements in ([`Storage::for_each_mut`]). Admits nothing; a window
/// already closed is none in both, so this settles and ends nothing twice.
fn forfeit_windows<P, O: Origin>(
    windows: &mut Storage<WindowPart<O>, P, O>,
    by: Performer,
    rule: Forfeit,
) {
    windows.for_each_mut(|part| {
        if let WindowPart::Credit(window) = part {
            settle_window_credit(window, Some(rule), by);
        }
    });
    windows.for_each_mut(|part| {
        if let WindowPart::Acquisition(acquisition) = part {
            end_window_acquisition(acquisition, by);
        }
    });
}

/// Close a window: its credit, if any, taken and settled whole (spent, for
/// `rule` none, or forfeited under `rule`) into the family that admitted
/// it, then its acquisition, if any, taken and ended, once, `by` the
/// performer; both slots left empty, the window idle. The one closing of a
/// window, by a bucket cursor's completion and end
/// ([`buckets::BucketCursor`]) and by a preparation's ending a cursor at
/// its map's count: settlement always before the end.
pub(crate) fn close_window<O: Origin>(
    window: &mut Option<Retained<O>>,
    acquisition: &mut Option<crate::bounded::Acquisition<O>>,
    rule: Option<Forfeit>,
    by: Performer,
) {
    settle_window_credit(window, rule, by);
    end_window_acquisition(acquisition, by);
}

fn settle_window_credit<O: Origin>(
    window: &mut Option<Retained<O>>,
    rule: Option<Forfeit>,
    by: Performer,
) {
    if let Some(credit) = window.take() {
        match rule {
            None => credit.spend(None, by),
            Some(rule) => credit.forfeit(rule, None, by),
        }
    }
}

fn end_window_acquisition<O: Origin>(
    acquisition: &mut Option<crate::bounded::Acquisition<O>>,
    by: Performer,
) {
    if let Some(acquisition) = acquisition.take() {
        acquisition.end(by);
    }
}

/// The bound acquisitions of the open windows, each reported once into the
/// group open in `sink`, the preparation's own ([`CustodySink::bound`]).
fn window_bindings<P, O: Origin>(
    windows: &Storage<WindowPart<O>, P, O>,
    sink: &mut dyn CustodySink<P>,
) {
    windows.for_each(|part| {
        if let WindowPart::Acquisition(Some(acquisition)) = part {
            sink.bound(acquisition.id());
        }
    });
}

/// The quick check of a text being prepared, one window of whole scalars of
/// at most a quantum per admitted unit ([`TEXT_CHECK`]): the bytes it has
/// read and what it found over them.
#[derive(Debug, PartialEq, Eq)]
struct TextCheck {
    at: usize,
    quick: text::QuickCheck,
}

/// The fewest bytes a quick-check window other than a text's last reads: a
/// quantum less all but one byte of the widest scalar, which the window
/// ends before rather than splitting.
const CHECK_LEAST: u64 =
    (decode::construction::stable::QUANTUM - (char::MAX.len_utf8() - 1)) as u64;

impl TextCheck {
    const fn new() -> Self {
        Self {
            at: 0,
            quick: text::QuickCheck::new(),
        }
    }

    /// One admitted window of `text` after what was read: true once the
    /// check is decided, the text then proven normal or not by
    /// [`Self::proven`]. A window ends at the last scalar boundary within a
    /// quantum; the check stops at the first scalar that leaves it unproven.
    fn step<B: Budget>(&mut self, text: &str, b: &mut B) -> BoundedResult<bool, B> {
        // A window of at most a quantum of what remains (`self.at` is a
        // scalar boundary the last window ended at, never past the text).
        let mut end = self.at
            + Bound::new(Predicate::Quantum, decode::construction::stable::QUANTUM)
                .clamp(b, text.len() - self.at);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        TEXT_CHECK.admit(b, widen(end - self.at)?)?;
        for ch in text[self.at..end].chars() {
            self.quick.scalar(ch);
            if !self.proven() {
                return Ok(true);
            }
        }
        self.at = end;
        Ok(end == text.len())
    }

    /// Whether every scalar read so far is proven normal.
    fn proven(&self) -> bool {
        *self.quick.result() == unicode_normalization::IsNormalized::Yes
    }
}

/// Bytes staged for the plan and drained into it in admitted appends: a
/// head, a map's gap, or a quantum of a bignum's magnitude. Every producer
/// stages here; one path appends.
pub(crate) struct Staged {
    bytes: [u8; decode::construction::stable::QUANTUM],
    at: usize,
    len: usize,
}

impl Staged {
    const fn new() -> Self {
        Self {
            bytes: [0; decode::construction::stable::QUANTUM],
            at: 0,
            len: 0,
        }
    }

    /// Whether every staged byte was appended.
    pub(crate) const fn is_empty(&self) -> bool {
        self.at == self.len
    }

    /// The staged bytes not yet appended.
    fn pending(&self) -> &[u8] {
        &self.bytes[self.at..self.len]
    }

    /// Stage the head of `major` carrying `argument`.
    pub(crate) fn head(&mut self, major: MajorType, argument: Argument) {
        let mut head = [0; MAX_HEAD_LEN];
        let len = write_argument(major, argument, &mut head);
        self.bytes[..len].copy_from_slice(&head[..len]);
        self.at = 0;
        self.len = len;
    }

    /// Stage a map's gap: the widest head's bytes, filled once its count
    /// is known.
    fn gap(&mut self) {
        self.bytes[..MAX_HEAD_LEN].fill(0);
        self.at = 0;
        self.len = MAX_HEAD_LEN;
    }

    /// Stage `bytes`, at most a quantum, once every staged byte was
    /// appended: a bignum's magnitude, the only producer of more than a
    /// head.
    #[cfg(feature = "num-bigint")]
    pub(crate) fn fill<B: Budget>(&mut self, bytes: &[u8], b: &mut B) -> BoundedResult<(), B> {
        // The copy below writes `bytes.len()` of the staged quantum.
        if !self.is_empty()
            || Bound::new(Predicate::Quantum, self.bytes.len()).exceeded(b, bytes.len())
        {
            return Err(BoundedError::PlanMismatch);
        }
        self.bytes[..bytes.len()].copy_from_slice(bytes);
        self.at = 0;
        self.len = bytes.len();
        Ok(())
    }
}

/// A completed plan's bytes and header gaps, wherever they are held: moved
/// into a [`Prepared`] or kept in place by an owned preparation. Every map's
/// entries are in canonical order in the bytes themselves. Emission reads
/// only this view.
#[derive(Clone, Copy)]
struct PlanView<'p> {
    bytes: &'p [u8],
    holes: &'p [(usize, usize)],
    len: usize,
}

/// The owners of a completed plan's two arenas, each read from the owner its
/// own pending custody stores ([`Storage::owner_id`]): the plan bytes and
/// the header gaps are separate arenas, each its own acquisitions' owner.
#[derive(Clone, Copy)]
struct PlanOwners {
    bytes: Option<Identity>,
    holes: Option<Identity>,
}

/// What completing a preparation yields from its plan's arenas, both
/// settled by the unit that completes it: an owned value, so completion
/// hands back no borrow of the preparation.
trait Completion<P> {
    type Output;

    fn complete(
        bytes: &mut Owned<u8, P>,
        holes: &mut Owned<(usize, usize), P>,
        len: usize,
        owners: PlanOwners,
    ) -> Self::Output;
}

/// Completion that moves the plan's arenas into a [`Prepared`], leaving the
/// preparation's empty. Each arena carries the owner whose acquisition
/// granted its permit, `None` exactly when the arena never allocated.
struct Publish;

impl<P> Completion<P> for Publish {
    type Output = Prepared<P>;

    fn complete(
        bytes: &mut Owned<u8, P>,
        holes: &mut Owned<(usize, usize), P>,
        len: usize,
        owners: PlanOwners,
    ) -> Prepared<P> {
        Prepared {
            bytes_owner: bytes.permit().and(owners.bytes),
            holes_owner: holes.permit().and(owners.holes),
            bytes: core::mem::take(bytes),
            holes: core::mem::take(holes),
            len,
        }
    }
}

/// Completion that keeps the plan in place, for an owned preparation that
/// emits it there ([`Preparation::view`]); its arenas stay in the
/// preparation's custody, under their own owners.
struct Kept;

impl<P> Completion<P> for Kept {
    type Output = ();

    fn complete(_: &mut Owned<u8, P>, _: &mut Owned<(usize, usize), P>, _: usize, _: PlanOwners) {}
}

impl<'a, P, O: Origin> Preparation<'a, P, O> {
    const TEXT_STEPS: usize = TextContinuation::<(), P, O>::INIT_STEPS;
    const STORAGE_STEPS: usize = Storage::<u8, P, O>::INIT_STEPS;
    /// The scalar fields [`Self::initialize_step`] writes one per unit, the
    /// staged bytes' three among them, each at most a quantum: the bignum's
    /// only where bignums are encoded.
    const SCALARS: usize = 15 + cfg!(feature = "num-bigint") as usize;

    /// Every unit of [`Self::initialize_step`]: six arenas, the text
    /// normalization, the dynamic map engine, and the scalar fields.
    pub(crate) const INIT_STEPS: usize = 6 * Self::STORAGE_STEPS
        + Self::TEXT_STEPS
        + dynamic::Dynamic::<P, O>::INIT_STEPS
        + Self::SCALARS;

    /// A preparation of `source` whose plan arena grows to at most `cap`
    /// bytes: what [`prepare`] gives a source whose extent
    /// a shape walk established, so the arena it publishes holds the
    /// encoding and its gaps and no more. A cap below what the source
    /// appends is refused as [`BoundedError::PlanMismatch`] at the growth
    /// that would pass it.
    pub fn capped(source: &'a dyn Schema, cap: usize) -> Self {
        let mut preparation = Self::new(source);
        preparation.cap = cap;
        preparation
    }

    pub fn new(source: &'a dyn Schema) -> Self {
        let () = WINDOW_PART_FAMILY_FITS_QUANTUM;
        Self {
            frames: Storage::new(),
            bytes: Storage::new(),
            holes: Storage::new(),
            child: Some(source),
            staged: Staged::new(),
            payload: &[],
            text: MaybeUninit::new(TextContinuation::new(())),
            text_source: None,
            text_init: Self::TEXT_STEPS,
            text_check: None,
            normalized: None,
            normalized_at: 0,
            omitted: 0,
            end: End::Running,
            dynamic: dynamic::Dynamic::new(),
            map_frames: Storage::new(),
            cursors: Storage::new(),
            windows: Storage::new(),
            owner: decode::construction::stable::OwnerState::Uninitialized,
            cap: usize::MAX,
            inspect: None,
            #[cfg(feature = "num-bigint")]
            bignum: None,
        }
    }

    /// Initialize one unit of a preparation of `source` in `slot`, its
    /// stable destination paired with its units initialized: the same state
    /// [`Self::new`] builds, written in admitted units, each nested arena
    /// and engine on its own units. Initialization acquires nothing, so an
    /// incomplete prefix needs no cleanup. Refused once initialized.
    pub(crate) fn initialize_step<A: Allocator<Permit = P, Origin = O>>(
        mut slot: reclamation::Slot<'_, Self, usize>,
        source: &'a dyn Schema,
        a: &mut A,
    ) -> BoundedResult<bool, A> {
        use decode::initialization::{init_field, init_part};
        let mut base = 0;
        // One nested part of `$steps` units at field `$field`, initialized
        // by `$init` over its own slot.
        macro_rules! part {
            ($field:ident, $steps:expr, |$part:ident| $init:expr) => {
                let units = *slot.custody();
                if Bound::new(Predicate::Prefix, base + $steps).below(a, units) {
                    init_part!(slot, $field, base, a, |$part| $init);
                    return Ok(false);
                }
                base += $steps;
            };
        }
        let storage = Self::STORAGE_STEPS;
        part!(frames, storage, |part| Storage::initialize_step(part, a)?);
        part!(bytes, storage, |part| Storage::initialize_step(part, a)?);
        part!(holes, storage, |part| Storage::initialize_step(part, a)?);
        part!(map_frames, storage, |part| Storage::initialize_step(
            part, a
        )?);
        part!(cursors, storage, |part| Storage::initialize_step(part, a)?);
        part!(windows, storage, |part| Storage::initialize_step(part, a)?);
        // The text continuation, a `MaybeUninit` field, projected to its
        // value by cast; its units are the preparation's less `base`, and
        // the `text_init` field written below records them whole.
        let units = *slot.custody();
        if Bound::new(Predicate::Prefix, base + Self::TEXT_STEPS).below(a, units) {
            let (place, units) = slot.parts();
            let mut part_units = units.checked_sub(base).ok_or(BoundedError::PlanMismatch)?;
            // SAFETY: the continuation's place is a field of the slot's own
            // destination, by field syntax, `MaybeUninit` laying out its
            // value at its start; its units are its own: the preparation's
            // are initialized in order, so its count less `base` is what the
            // continuation holds.
            let text = unsafe {
                reclamation::Slot::new(
                    place.project(|value| {
                        addr_of_mut!((*value).text).cast::<TextContinuation<(), P, O>>()
                    }),
                    &mut part_units,
                )
            };
            TextContinuation::initialize_step(text, (), a)?;
            *units = base + part_units;
            return Ok(false);
        }
        base += Self::TEXT_STEPS;
        part!(dynamic, dynamic::Dynamic::<P, O>::INIT_STEPS, |part| {
            dynamic::Dynamic::initialize_step(part, a)?
        });
        match *slot.custody() - base {
            0 => init_field!(slot, child, || Some(source), a)?,
            // The staged bytes, a quantum, then their two offsets: the
            // state `Staged::new` builds.
            1 => init_field!(
                slot,
                staged.bytes,
                || [0; decode::construction::stable::QUANTUM],
                a
            )?,
            2 => init_field!(slot, staged.at, || 0, a)?,
            3 => init_field!(slot, staged.len, || 0, a)?,
            4 => init_field!(slot, payload, || &[][..], a)?,
            5 => init_field!(slot, text_source, || None, a)?,
            6 => init_field!(slot, text_init, || Self::TEXT_STEPS, a)?,
            7 => init_field!(slot, normalized, || None, a)?,
            8 => init_field!(slot, normalized_at, || 0, a)?,
            9 => init_field!(slot, omitted, || 0, a)?,
            10 => init_field!(slot, end, || End::Running, a)?,
            // An owned plan is emitted in place, gaps skipped, never
            // published as an arena: it grows uncapped.
            11 => init_field!(slot, cap, || usize::MAX, a)?,
            12 => init_field!(slot, inspect, || None, a)?,
            13 => init_field!(slot, text_check, || None, a)?,
            // The owner uninitialized: the first window's admission makes it.
            14 => init_field!(
                slot,
                owner,
                || decode::construction::stable::OwnerState::Uninitialized,
                a
            )?,
            #[cfg(feature = "num-bigint")]
            15 => init_field!(slot, bignum, || None, a)?,
            _ => return Err(BoundedError::PlanMismatch),
        }
        let units = slot.custody();
        *units += 1;
        Ok(*units == Self::INIT_STEPS)
    }

    pub fn position(&self) -> Position {
        Position {
            frames: self.frames.position(),
            bytes: self.bytes.position(),
            holes: self.holes.position(),
            maps: self.map_frames.position(),
            cursor_storage: self.cursors.position(),
            window_storage: self.windows.position(),
            finished: self.end != End::Running,
            child: self.child.is_some(),
            inspect: self.inspect,
            omitted: self.omitted,
            capacity_limit: self.cap,
            normalized_output: self.normalized.as_ref().map(|output| output.as_ref().len()),
            text_initialized: self.text_init,
            text_initialization_steps: Self::TEXT_STEPS,
            normalizing: self.text_source.is_some() && self.text_check.is_none(),
            depth: self.frames.len(),
            instruction: self.frames.last().map_or(0, |f| f.next),
            prepared_bytes: self.bytes.len(),
            pending_bytes: self.staged.pending().len() + self.payload.len(),
            relocated_frames: self.frames.relocated(),
            relocated_bytes: self.bytes.relocated(),
            relocated_headers: self.holes.relocated(),
            normalized_bytes_copied: self.normalized_at,
            quick_checked: self.text_check.as_ref().map(|check| check.at),
            // Cleanup can still hold normalizer resources after text_source
            // was cleared. Observe the initialized continuation regardless
            // of whether traversal is currently normalizing a text.
            normalization: self.text().map(TextContinuation::position),
            cursor_moves: self.frames.last().map_or(0, |f| f.moved),
            cursors: self.cursors.len(),
            dynamic: self.dynamic.position(),
            #[cfg(feature = "num-bigint")]
            bignum: self.bignum.as_ref().map(super::bigint::Bignum::position),
            #[cfg(not(feature = "num-bigint"))]
            bignum: None,
        }
    }

    /// One unit appending at most a quantum of `source` to the plan's bytes,
    /// growing them to at most `cap`: the bytes appended, or none when the
    /// unit was the arena's growth or relocation.
    fn append<A: Allocator<Permit = P, Origin = O>>(
        storage: &mut Storage<u8, P, O>,
        cap: usize,
        source: &[u8],
        a: &mut A,
    ) -> BoundedResult<usize, A> {
        let Some(spare) = at(PreparationPlace::PlanBytes, || storage.reserve_step(cap, a))? else {
            return Ok(0);
        };
        let count = Bound::new(Predicate::Quantum, decode::construction::stable::QUANTUM)
            .clamp(a, source.len());
        let count = Bound::new(Predicate::ArenaLength, spare.room()).clamp(a, count);
        APPEND.admit(a, widen(count)?)?;
        Ok(spare.extend(&source[..count], a))
    }

    /// One step, publishing the plan by moving its arenas out; after a
    /// terminal error, one unit of the preparation's own cleanup, until it
    /// reports `Finished`.
    pub fn step<A: Allocator<Permit = P, Origin = O>>(
        &mut self,
        a: &mut A,
    ) -> BoundedResult<Step<Prepared<P>>, A> {
        match self.end {
            End::Published | End::Reclaimed => return Ok(Step::Finished),
            // The cleanup unit that reports `Done` admits the completion,
            // so it is progress; the step after it reports `Finished`.
            End::Failed => return self.reclaim_step(a).map(|_| Step::Progress),
            End::Running => {}
        }
        Ok(match self.prepare_step::<Publish, A>(a)? {
            Some(prepared) => Step::Complete(prepared),
            None => Step::Progress,
        })
    }

    /// One step, completing the plan as `C` does: moved out, or kept in
    /// place, readable through [`Self::view`]. Completion publishes the
    /// preparation; a terminal error fails it, its cleanup owed.
    fn prepare_step<C: Completion<P>, A: Allocator<Permit = P, Origin = O>>(
        &mut self,
        a: &mut A,
    ) -> BoundedResult<Option<C::Output>, A> {
        if self.end != End::Running {
            return Err(BoundedError::PlanMismatch);
        }
        let result = self.advance::<C, A>(a);
        match &result {
            Ok(Some(_)) => self.end = End::Published,
            Err(error) if !error.refused() => self.end = End::Failed,
            Ok(None) | Err(_) => {}
        }
        result
    }

    /// The completed plan's length: its bytes less the header gaps omitted.
    fn plan_len<R>(&self) -> Result<usize, BoundedError<R>> {
        self.bytes
            .len()
            .checked_sub(self.omitted)
            .ok_or(BoundedError::Overflow)
    }

    /// The text continuation, while it is present: every unit of its
    /// initialization written since it was last destroyed (`text`).
    fn text(&self) -> Option<&TextContinuation<(), P, O>> {
        // SAFETY: the continuation is initialized exactly when `text_init`
        // records every unit of it written since its last destruction.
        (self.text_init == Self::TEXT_STEPS).then(|| unsafe { self.text.assume_init_ref() })
    }

    /// [`Self::text`], exclusively.
    fn text_mut(&mut self) -> Option<&mut TextContinuation<(), P, O>> {
        // SAFETY: as `text`.
        (self.text_init == Self::TEXT_STEPS).then(|| unsafe { self.text.assume_init_mut() })
    }

    /// Destroy the present continuation in place, once it published its
    /// encoding or finished its cleanup: its arenas hold no allocation and
    /// their pendings no credit, its output moved out or released, so its
    /// drop frees nothing and records nothing (`Storage`'s `Drop`); what it
    /// releases is its owners' session references. The next text's
    /// initialization then writes uninitialized storage. A continuation not
    /// present is not touched: a partial prefix holds no owned field.
    fn retire_text(&mut self) {
        if self.text_init == Self::TEXT_STEPS {
            // SAFETY: present (above); `text_init` is cleared below, so no
            // read, step or later drop reaches the destroyed value.
            unsafe { self.text.assume_init_drop() };
        }
        self.text_init = 0;
    }

    /// The completed plan, in place; `None` while an arena's elements are in
    /// a grown allocation.
    fn view(&self) -> Option<PlanView<'_>> {
        Some(PlanView {
            bytes: self.bytes.settled()?.as_slice(),
            holes: self.holes.settled()?.as_slice(),
            len: self.plan_len::<()>().ok()?,
        })
    }

    /// One admitted unit of cleanup: the text normalization, the copied
    /// normalized text, then every arena, a plan kept in place included. The
    /// first part still holding anything spends the call; once none does, the
    /// call admits the completion it reports as `Done`, and drops every
    /// borrow of the source the traversal still holds: a reclaimed
    /// preparation refers to nothing, so the source it borrowed may be
    /// released while the preparation is still observed ([`Planned`]).
    /// Bounded on [`Releasing`]: no new allocation through the supplied
    /// cleanup capability.
    pub fn reclaim_step<A: Releasing<Permit = P, Origin = O>>(
        &mut self,
        a: &mut A,
    ) -> BoundedResult<Reclaimed, A> {
        let malformed = windows_malformed(&self.windows, self.cursors.len());
        // Cleanup entry ends the preparation's work: a cancelled one is
        // failed, its cleanup this; a published one stays published.
        if self.end == End::Running {
            self.end = End::Failed;
        }
        // Cleanup entry: every open cursor's window closed, its obligation
        // forfeited into the family that admitted it, then its acquisition
        // ended, before any unit, whatever that unit's outcome; a later call
        // settles and ends nothing again.
        forfeit_windows(&mut self.windows, a.performer(), Forfeit::Cancelled);
        if malformed {
            invalidate_windows(&self.owner);
        }
        let cleanup = PreparationPlace::Cleanup;
        if let Some(text) = self.text_mut()
            && text.position().phase != text_cursor::Phase::Finished
        {
            at(cleanup, || text.reclaim_step(a))?;
        } else if self.normalized.is_some() {
            // The copied encoding's release was paid for by its request.
            self.normalized = None;
        } else if !self.frames.is_released() {
            // Frames and open maps are plain data: settled, each arena is
            // discarded in one unit; cancelled while relocating or staging,
            // drained per element, which the bound counts.
            at(cleanup, || self.frames.reclaim_copy_step(a))?;
        } else if !self.map_frames.is_released() {
            at(cleanup, || self.map_frames.reclaim_copy_step(a))?;
        } else if !self.bytes.is_released() {
            at(cleanup, || self.bytes.reclaim_copy_step(a))?;
        } else if !self.holes.is_released() {
            at(cleanup, || self.holes.reclaim_copy_step(a))?;
        } else if !self.cursors.is_released() {
            // The cursors' windows were settled at entry: their positions
            // are plain data.
            at(cleanup, || self.cursors.reclaim_copy_step(a))?;
        } else if !self.windows.is_released() {
            // Settled at entry, every element is none, but an obligation's
            // type drops, so the arena drains one element per unit.
            at(cleanup, || self.windows.reclaim_step(a))?;
        } else if !self.dynamic.is_released() {
            at(cleanup, || self.dynamic.reclaim_step(a))?;
        } else {
            CLEANUP_DONE.admit(a)?;
            self.release_source();
            if self.end == End::Failed {
                self.end = End::Reclaimed;
            }
            return Ok(Reclaimed::Done);
        }
        Ok(Reclaimed::Progress)
    }

    /// The credit this preparation's custody holds ([`Obligation`]): the
    /// checked total of its [`Custodial`] traversal's obligations, its arenas'
    /// staged growths', its text continuation's, and its open hash tables'
    /// bucket cursors' unspent window credit. Read from its state alone,
    /// allocation-free. `None` when the sum does not fit. The public
    /// conservation observation of the preparation: read beside its
    /// policies' [`Limits::credits`], it is the `held` that
    /// [`crate::bounded::Credits::conserved_with`] checks.
    pub fn held_credit(&mut self) -> Option<WriteWork> {
        total_held(|sink| self.observe_custody(sink))
    }

    /// The identity of the owner of this preparation's own acquisitions, its
    /// bucket windows, read from the owner it stores; `None` until its first
    /// window makes it.
    pub fn owner_id(&self) -> Option<Identity> {
        match &self.owner {
            decode::construction::stable::OwnerState::Initialized(owner) => Some(owner.id()),
            decode::construction::stable::OwnerState::Uninitialized => None,
        }
    }

    /// Drop every borrow of the source outside the arenas, which cleanup has
    /// released: the pending child, the pending payload, the text and its
    /// quick check, and the bignum being read.
    fn release_source(&mut self) {
        self.child = None;
        self.payload = &[];
        self.text_source = None;
        self.text_check = None;
        #[cfg(feature = "num-bigint")]
        {
            self.bignum = None;
        }
    }

    /// The most calls [`Self::reclaim_step`] still takes, the one returning
    /// `Done` included: the text normalization's own count unless finished,
    /// one for a copied normalized text, each arena not yet released, the
    /// dynamic map engine's, then the completion. Admits nothing and changes
    /// nothing. `None` when the count does not fit in `u64`.
    pub(crate) fn reclaim_remaining(&self) -> Option<u64> {
        let text = match self.text() {
            Some(text) if text.position().phase != text_cursor::Phase::Finished => {
                text.reclaim_remaining()?
            }
            _ => 0,
        };
        [
            text,
            u64::from(self.normalized.is_some()),
            self.frames.unreleased_copy_remaining()?,
            self.map_frames.unreleased_copy_remaining()?,
            self.bytes.unreleased_copy_remaining()?,
            self.holes.unreleased_copy_remaining()?,
            self.cursors.unreleased_copy_remaining()?,
            self.windows.unreleased_remaining()?,
            self.dynamic.reclaim_remaining()?,
            1,
        ]
        .into_iter()
        .try_fold(0, u64::checked_add)
    }

    /// One unit of preparation: the plan as `C` completes it, once complete.
    fn advance<C: Completion<P>, A: Allocator<Permit = P, Origin = O>>(
        &mut self,
        a: &mut A,
    ) -> BoundedResult<Option<C::Output>, A> {
        if !self.staged.is_empty() {
            let count = Self::append(&mut self.bytes, self.cap, self.staged.pending(), a)?;
            self.staged.at += count;
            return Ok(None);
        }
        if !self.payload.is_empty() {
            let count = Self::append(&mut self.bytes, self.cap, self.payload, a)?;
            self.payload = &self.payload[count..];
            return Ok(None);
        }
        if let Some(encoded) = &self.normalized {
            if Bound::new(Predicate::Payload, encoded.as_ref().len()).below(a, self.normalized_at) {
                self.normalized_at += Self::append(
                    &mut self.bytes,
                    self.cap,
                    &encoded.as_ref()[self.normalized_at..],
                    a,
                )?;
            } else {
                // The copied encoding's release was paid for by its request.
                self.normalized = None;
                self.normalized_at = 0;
            }
            return Ok(None);
        }
        #[cfg(feature = "num-bigint")]
        if let Some(bignum) = &mut self.bignum {
            // The staged bytes were all appended: stage the next.
            if bignum.step(&mut self.staged, a)? {
                self.bignum = None;
            }
            return Ok(None);
        }
        if let Some(values) = self.inspect {
            // The announced inspections, in units of at most `UNIT_VALUES`;
            // what remains is kept across refusals.
            let count = Bound::new(Predicate::Quantum, UNIT_VALUES).clamp(a, values);
            INSPECTED.admit(a, count)?;
            // `count` is `values` or less: anything left is kept.
            self.inspect = (values != count).then(|| values - count);
            return Ok(None);
        }
        if let Some(text) = self.text_source {
            if let Some(check) = &mut self.text_check {
                if check.step(text, a)? {
                    // A text the quick check proves normal is its own normal
                    // form: its head and its bytes, copied as they are.
                    if check.proven() {
                        self.staged
                            .head(MajorType::Text, Argument::Shortest(widen(text.len())?));
                        self.payload = text.as_bytes();
                        self.text_source = None;
                    }
                    self.text_check = None;
                }
                return Ok(None);
            }
            // The continuation's next unit writes the field its units
            // select into uninitialized storage: a prefix, through the seam.
            if Bound::new(Predicate::Prefix, Self::TEXT_STEPS).below(a, self.text_init) {
                // SAFETY: the continuation's place is rooted at an exclusive
                // borrow of its own `MaybeUninit` field, valid, aligned and
                // writable for it, and no place derived from it outlives this
                // call; its units are `text_init`, which counts exactly the
                // units written since its last destruction (`retire_text`),
                // so every unit it writes is uninitialized and no live owner
                // is overwritten; a partial prefix owns nothing, and nothing
                // reads it as a continuation until every unit is written.
                let continuation = unsafe {
                    reclamation::Slot::new(
                        reclamation::Place::root(NonNull::from(&mut self.text)),
                        &mut self.text_init,
                    )
                };
                at(PreparationPlace::Texts, || {
                    TextContinuation::initialize_step(continuation, (), a)
                })?;
                return Ok(None);
            }
            let continuation = self.text_mut().ok_or(BoundedError::PlanMismatch)?;
            match at(PreparationPlace::Texts, || {
                continuation.step_source(text, a)
            })? {
                Step::Progress => {}
                Step::Complete(value) => {
                    self.normalized = Some(value);
                    self.text_source = None;
                    // Published: its output moved out, its arenas drained;
                    // what remains is its owners, destroyed with it.
                    self.retire_text();
                }
                Step::Finished => return Err(BoundedError::PlanMismatch),
            }
            return Ok(None);
        }
        if let Some(source) = self.child {
            if Bound::new(Predicate::DispatchDepth, SYMBOLIC_DEPTH).reached(a, self.frames.len()) {
                return Err(BoundedError::DepthLimit);
            }
            let frames = &mut self.frames;
            // A growth unit of the frame arena, or a free slot for the frame.
            let Some(spare) = at(PreparationPlace::Frames, || {
                frames.reserve_step(usize::MAX, a)
            })?
            else {
                return Ok(None);
            };
            PUSH.admit(a)?;
            spare.push(Frame {
                source,
                next: 0,
                map: None,
                ordered: false,
                fresh: false,
                moved: 0,
            });
            self.child = None;
            return Ok(None);
        }
        if self.dynamic_step(a)? {
            return Ok(None);
        }
        // Every arena the next instruction may read or extend is settled, or
        // grants a free slot, before the instruction is requested, so a
        // refusal never replays a schema inspection; a unit of growth or
        // relocation is the step's work instead.
        let frames = &mut self.frames;
        let Some(frames) = at(PreparationPlace::Frames, || frames.settle_step(a))? else {
            return Ok(None);
        };
        let Some(frame) = frames.as_mut_slice().last_mut() else {
            // Every frame is closed: the plan completes, its arenas settled.
            // Their owners, read from the owners their pending custodies
            // store before the arenas are borrowed: an arena holding a permit
            // acquired it under an owner made before that acquisition, and
            // settling only finishes a growth already under way, so it makes
            // none.
            let owners = PlanOwners {
                bytes: self.bytes.owner_id(),
                holes: self.holes.owner_id(),
            };
            let bytes = &mut self.bytes;
            let Some(bytes) = at(PreparationPlace::PlanBytes, || bytes.settle_step(a))? else {
                return Ok(None);
            };
            let holes = &mut self.holes;
            let Some(holes) = at(PreparationPlace::Gaps, || holes.settle_step(a))? else {
                return Ok(None);
            };
            DONE.admit(a)?;
            // The published length: the plan's bytes less the gap bytes its
            // heads omitted, which never exceed them.
            if Bound::new(Predicate::Payload, bytes.len()).exceeded(a, self.omitted) {
                return Err(BoundedError::Overflow);
            }
            let len = bytes.len() - self.omitted;
            return Ok(Some(C::complete(bytes, holes, len, owners)));
        };
        let bytes = &mut self.bytes;
        let Some(bytes) = at(PreparationPlace::PlanBytes, || bytes.settle_step(a))? else {
            return Ok(None);
        };
        // Only map starts consume these slots.
        let holes = &mut self.holes;
        let Some(mut holes) = at(PreparationPlace::Gaps, || holes.reserve_step(usize::MAX, a))?
        else {
            return Ok(None);
        };
        let maps = &mut self.map_frames;
        let Some(mut maps) = at(PreparationPlace::OpenMaps, || {
            maps.reserve_step(usize::MAX, a)
        })?
        else {
            return Ok(None);
        };
        // Only entry sources consume this slot.
        // Check adjacency while it is still available. Growth may return
        // before relocation, so check its ready boundary as well; ordinary
        // cursor turns validate only the pair they access.
        let window_position = self.windows.position();
        if (window_position.stage == decode::storage::StorageStage::Ready
            || (window_position.stage == decode::storage::StorageStage::Settled
                && window_position.initialized == window_position.reserved_capacity))
            && !windows_valid(&self.windows, self.cursors.len())
        {
            invalidate_windows(&self.owner);
            return Err(BoundedError::PlanMismatch);
        }
        let cursors = &mut self.cursors;
        let Some(mut cursors) = at(PreparationPlace::Cursors, || {
            cursors.reserve_step(usize::MAX, a)
        })?
        else {
            return Ok(None);
        };
        // Even capacity and pairwise publication leave two free parts
        // whenever reserve_step grants room.
        let windows = &mut self.windows;
        let Some(mut windows) = at(PreparationPlace::Cursors, || {
            windows.reserve_step(WINDOW_PART_MAXIMUM, a)
        })?
        else {
            return Ok(None);
        };
        let parts = cursors.len().checked_mul(2).ok_or(BoundedError::Overflow)?;
        parts.checked_add(2).ok_or(BoundedError::Overflow)?;
        let next = frame.next.checked_add(1).ok_or(BoundedError::Overflow)?;
        if windows.len() != parts || windows.room() < 2 {
            invalidate_windows(&self.owner);
            return Err(BoundedError::PlanMismatch);
        }
        let cursor_index = cursors.len().checked_sub(1);
        let top = match frame.map {
            Some(index) => Some(
                maps.as_slice()
                    .get(index)
                    .ok_or(BoundedError::PlanMismatch)?,
            ),
            None => None,
        };
        let entry_count = self.dynamic.entries.len();
        // A counted unordered map whose source has yielded every entry its
        // head declared, the last one compacted: it ends here, without
        // asking its source to scan further ([`counted_complete`]).
        let complete = top.is_some_and(|map| counted_complete(map, entry_count));
        // A scanning unordered map's next entry is pushed into a slot
        // reserved before the source is asked for it.
        let scanning = top.is_some_and(|map| {
            matches!(
                map.state,
                MapState::Dynamic {
                    phase: EntryPhase::Scan,
                    ..
                }
            )
        });
        let entries = &mut self.dynamic.entries;
        let mut scan = None;
        if scanning && !complete {
            let Some(spare) = at(PreparationPlace::EntryArena, || {
                entries.reserve_step(usize::MAX, a)
            })?
            else {
                return Ok(None);
            };
            scan = Some(spare);
        }
        let source = frame.source;
        let fetched = if complete {
            // The end, admitted as a transition of the map: no cursor
            // transition is made, so no node move and no bucket inspected.
            CURSOR.admit(a)?;
            if frame.ordered {
                // A hash table's cursor ends with its map's count reached:
                // its window's unspent credit is forfeited, then its
                // acquisition ended, before it goes.
                let (window, acquisition) = window_pair(
                    windows.as_mut_slice(),
                    cursor_index.ok_or(BoundedError::PlanMismatch)?,
                )
                .inspect_err(|_| invalidate_windows(&self.owner))?;
                close_window(
                    window,
                    acquisition,
                    Some(Forfeit::EnumerationComplete),
                    a.performer(),
                );
                windows.pop();
                windows.pop();
                cursors.pop();
                frame.ordered = false;
            }
            Some(Instruction::End)
        } else if frame.ordered {
            let (window, acquisition) = window_pair(
                windows.as_mut_slice(),
                cursor_index.ok_or(BoundedError::PlanMismatch)?,
            )
            .inspect_err(|_| invalidate_windows(&self.owner))?;
            let (driver, slot) = cursors
                .as_mut_slice()
                .last_mut()
                .ok_or(BoundedError::PlanMismatch)?;
            match *driver {
                Some(entries) => {
                    if window.is_some() || acquisition.is_some() {
                        invalidate_windows(&self.owner);
                        return Err(BoundedError::PlanMismatch);
                    }
                    // One admitted cursor transition per instruction. The node
                    // moves the cursor states for the transition, twice over
                    // for the one that starts it, are admitted before it in
                    // units of at most `UNIT_VALUES`, so no unit is wider than
                    // a turn whatever the tree's height.
                    let entries: &'a dyn Entries = entries;
                    let moves = if frame.fresh {
                        mul(entries.moves(), 2)?
                    } else {
                        entries.moves()
                    };
                    if frame.moved < moves {
                        let count = Bound::new(Predicate::Quantum, UNIT_VALUES)
                            .clamp(a, moves - frame.moved);
                        MOVED.admit(a, count)?;
                        frame.moved += count;
                        return Ok(None);
                    }
                    CURSOR.admit(a)?;
                    frame.moved = 0;
                    if frame.fresh {
                        entries.start(slot);
                        frame.fresh = false;
                    }
                    // SAFETY: the top cursor was started by this frame's own
                    // source.
                    match unsafe { entries.next(slot) } {
                        EntryStep::Progress => None,
                        EntryStep::Entry(key, value) => Some(Instruction::Entry(key, value)),
                        EntryStep::End => {
                            // An entry cursor holds no window.
                            windows.pop();
                            windows.pop();
                            cursors.pop();
                            frame.ordered = false;
                            Some(Instruction::End)
                        }
                    }
                }
                // A hash table's bucket cursor: the engine's one bucket
                // traversal, which admits its own call and window.
                #[cfg(any(feature = "hashbrown", feature = "custom-std-collections"))]
                None => {
                    // SAFETY: a slot of no entry source holds the table and
                    // its cursor, stored by `Instruction::Buckets` as exactly
                    // this type.
                    let (table, position) =
                        unsafe { slot.get::<(&'a dyn Buckets, BucketPosition)>() };
                    let table: &'a dyn Buckets = *table;
                    // The preparation's owner, made once by its first
                    // window's admission and never replaced.
                    if let decode::construction::stable::OwnerState::Uninitialized = self.owner {
                        self.owner = decode::construction::stable::OwnerState::Initialized(
                            a.owner().map_err(BoundedError::Refused)?,
                        );
                    }
                    let decode::construction::stable::OwnerState::Initialized(owner) = &self.owner
                    else {
                        return Err(BoundedError::PlanMismatch);
                    };
                    let mut cursor = BucketCursor::new(position, window, acquisition);
                    match at(PreparationPlace::Buckets, || cursor.step(table, owner, a))? {
                        BucketStep::Vacant { .. } => None,
                        BucketStep::Entry { key, value, .. } => {
                            Some(Instruction::Entry(key, value))
                        }
                        BucketStep::Complete => {
                            // Completion closed the window: both slots none.
                            windows.pop();
                            windows.pop();
                            cursors.pop();
                            frame.ordered = false;
                            Some(Instruction::End)
                        }
                        BucketStep::Finished => return Err(BoundedError::PlanMismatch),
                    }
                }
                // No bucket cursor exists where no hash table is encoded.
                #[cfg(not(any(feature = "hashbrown", feature = "custom-std-collections")))]
                None => return Err(BoundedError::PlanMismatch),
            }
        } else {
            INDEXED.admit(a)?;
            Some(source.instruction(frame.next))
        };
        frame.next = next;
        // A transition that yielded no entry is its own step's progress.
        let Some(instruction) = fetched else {
            return Ok(None);
        };
        match instruction {
            Instruction::Head(major, argument) => self.staged.head(major, argument),
            Instruction::Inspect(values) => self.inspect = Some(values),
            #[cfg(feature = "num-bigint")]
            Instruction::Bignum {
                magnitude,
                negative,
            } => {
                self.bignum = Some(super::bigint::Bignum::new(
                    magnitude,
                    negative,
                    &mut self.staged,
                ));
            }
            Instruction::Text(text) => {
                // Between texts the continuation is fresh, present and never
                // used, or destroyed at its last publication (`retire_text`),
                // `text_init` then zero: only a destroyed one is initialized
                // again, into uninitialized storage.
                self.text_check = Some(TextCheck::new());
                self.text_source = Some(text);
            }
            Instruction::Bytes(bytes) => self.payload = bytes,
            Instruction::Child(child) => self.child = Some(child),
            Instruction::OutOfRange => return Err(BoundedError::OutOfRange),
            Instruction::Entries(entries) => {
                let map = frame
                    .map
                    .and_then(|index| maps.as_mut_slice().get_mut(index))
                    .ok_or(BoundedError::PlanMismatch)?;
                let MapState::Dynamic {
                    phase: EntryPhase::Scan,
                    ordered,
                    start,
                    ..
                } = &mut map.state
                else {
                    return Err(BoundedError::PlanMismatch);
                };
                if frame.ordered || entry_count != *start {
                    return Err(BoundedError::PlanMismatch);
                }
                *ordered = entries.ordered();
                // The cursor starts with its first transition, whose node
                // moves are admitted with it. An entry cursor holds an empty
                // pair. Publication: the pair appended whole or not at all
                // (two free parts were established before the fetch, so it
                // cannot fail; were it to, nothing is written), then the
                // cursor, an infallible push: no fallible step between the
                // structural writes.
                if windows
                    .push_pair([WindowPart::Acquisition(None), WindowPart::Credit(None)])
                    .is_err()
                {
                    invalidate_windows(&self.owner);
                    return Err(BoundedError::PlanMismatch);
                }
                cursors.push((Some(entries), Slot::new()));
                frame.ordered = true;
                frame.fresh = true;
            }
            #[cfg(any(feature = "hashbrown", feature = "custom-std-collections"))]
            Instruction::Buckets(table) => {
                let map = frame
                    .map
                    .and_then(|index| maps.as_mut_slice().get_mut(index))
                    .ok_or(BoundedError::PlanMismatch)?;
                let MapState::Dynamic {
                    phase: EntryPhase::Scan,
                    ordered,
                    start,
                    ..
                } = &mut map.state
                else {
                    return Err(BoundedError::PlanMismatch);
                };
                if frame.ordered || entry_count != *start {
                    return Err(BoundedError::PlanMismatch);
                }
                // A hash table's order is not canonical key order.
                *ordered = false;
                // The table and its cursor's position, retained in the
                // cursor arena, and its window, none until its first call,
                // in the window arena beside it: what each step resumes
                // from.
                let mut slot = Slot::new();
                slot.put((table, BucketPosition::new()));
                // Publication as an entry cursor's: the empty pair appended
                // whole or not at all, then the cursor, infallibly.
                if windows
                    .push_pair([WindowPart::Acquisition(None), WindowPart::Credit(None)])
                    .is_err()
                {
                    invalidate_windows(&self.owner);
                    return Err(BoundedError::PlanMismatch);
                }
                cursors.push((None, slot));
                frame.ordered = true;
                frame.fresh = false;
            }
            Instruction::Entry(key, value) => {
                // An entry is the instruction of a scanning unordered map,
                // whose slot was reserved for it; any other map's source
                // answered outside its contract.
                let Some(slot) = scan else {
                    return Err(BoundedError::PlanMismatch);
                };
                let map = frame
                    .map
                    .and_then(|index| maps.as_mut_slice().get_mut(index))
                    .ok_or(BoundedError::PlanMismatch)?;
                let MapState::Dynamic {
                    phase,
                    value: pending,
                    ..
                } = &mut map.state
                else {
                    return Err(BoundedError::PlanMismatch);
                };
                slot.push(maps::order::Entry {
                    start: bytes.len(),
                    key_end: 0,
                    end: 0,
                    output: 0,
                });
                *phase = EntryPhase::Key;
                *pending = Some(value);
                self.child = Some(key);
            }
            Instruction::UnorderedMap
            | Instruction::Map
            | Instruction::CountedUnorderedMap(_)
            | Instruction::CountedMap(_) => {
                if frame.map.is_some() {
                    return Err(BoundedError::PlanMismatch);
                }
                let unordered = matches!(
                    instruction,
                    Instruction::UnorderedMap | Instruction::CountedUnorderedMap(_)
                );
                let expected = match instruction {
                    Instruction::CountedMap(count) | Instruction::CountedUnorderedMap(count) => {
                        Some(count)
                    }
                    _ => None,
                };
                let gaps = holes.len();
                let (head, holes_start) = match expected {
                    // The head is known: written at once, no gap.
                    Some(count) => {
                        self.staged.head(MajorType::Map, Argument::Shortest(count));
                        (MapHead::Counted(count), gaps)
                    }
                    // The head waits for the count in a gap of the widest;
                    // the map's own gaps follow it.
                    None => {
                        holes.push((bytes.len(), MAX_HEAD_LEN));
                        self.staged.gap();
                        (MapHead::Gap(gaps), gaps + 1)
                    }
                };
                // The map's payload starts after its staged head or gap.
                let data_start = bytes
                    .len()
                    .checked_add(self.staged.len)
                    .ok_or(BoundedError::Overflow)?;
                frame.map = Some(maps.len());
                maps.push(MapFrame {
                    head,
                    holes_start,
                    data_start,
                    state: if unordered {
                        MapState::Dynamic {
                            start: entry_count,
                            phase: EntryPhase::Scan,
                            value: None,
                            ordered: false,
                        }
                    } else {
                        MapState::Schema { fields: 0 }
                    },
                });
            }
            Instruction::Field(key, value) => {
                let map = frame
                    .map
                    .and_then(|index| maps.as_mut_slice().get_mut(index))
                    .ok_or(BoundedError::PlanMismatch)?;
                let MapState::Schema { fields } = &mut map.state else {
                    return Err(BoundedError::PlanMismatch);
                };
                if let Some(value) = value {
                    *fields = add(*fields, 1)?;
                    self.child = Some(value);
                    self.staged
                        .head(MajorType::Unsigned, Argument::Shortest(key));
                }
            }
            Instruction::End => {
                if let Some(index) = frame.map {
                    let map = maps
                        .as_mut_slice()
                        .get_mut(index)
                        .ok_or(BoundedError::PlanMismatch)?;
                    let count = match &mut map.state {
                        MapState::Schema { fields } => *fields,
                        MapState::Dynamic { start, phase, .. } => {
                            *phase = EntryPhase::Order;
                            widen(entry_count - *start)?
                        }
                    };
                    match map.head {
                        // A counted head was written at the map's start; the
                        // source must have visited exactly that many.
                        MapHead::Counted(expected) => {
                            check_count(Some(expected), count)?;
                        }
                        MapHead::Gap(gap) => {
                            let mut head = [0; MAX_HEAD_LEN];
                            let len = write_argument(
                                MajorType::Map,
                                Argument::Shortest(count),
                                &mut head,
                            );
                            let hole = holes
                                .as_mut_slice()
                                .get_mut(gap)
                                .ok_or(BoundedError::PlanMismatch)?;
                            hole.1 = MAX_HEAD_LEN - len;
                            let start = hole.0 + hole.1;
                            // The head ends within the plan's bytes: the gap
                            // was appended whole before the map's payload.
                            if boundary!(a, Predicate::Payload, start + len, bytes.len()).is_gt() {
                                return Err(BoundedError::PlanMismatch);
                            }
                            bytes.as_mut_slice()[start..start + len].copy_from_slice(&head[..len]);
                            self.omitted = self
                                .omitted
                                .checked_add(hole.1)
                                .ok_or(BoundedError::Overflow)?;
                        }
                    }
                    if matches!(map.state, MapState::Dynamic { .. }) {
                        return Ok(None);
                    }
                    maps.pop();
                }
                frames.pop();
            }
        }
        Ok(None)
    }
}

/// What a source's retained preparation depends on, each at most.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Shape {
    /// The schema instructions it answers and the entry cursor transitions
    /// it makes: every `End` and omitted field included, each inspecting at
    /// most a head.
    pub instructions: u64,
    /// The hash tables it enumerates ([`Instruction::Buckets`]).
    pub bucket_tables: u64,
    /// Their buckets, all together: every control admitted once.
    pub buckets: u64,
    /// Their entries, all together.
    pub bucket_entries: u64,
    /// The most frames open at once: the root and each child within its
    /// parent. The engine refuses more than [`SYMBOLIC_DEPTH`].
    pub depth: u64,
    /// The maps it begins, of either kind: each holds a header gap.
    pub maps: u64,
    /// The unordered maps among them: each is compacted, ordered, checked
    /// and permuted.
    pub unordered: u64,
    /// The entries of all its unordered maps together.
    pub entries: u64,
    /// The most entries `w` of any one unordered map: no lookup probes more
    /// than `floor(log2 w) + 1` entries, which caps the probes of a shape whose
    /// payloads exceed what its length allows.
    pub widest: u64,
    /// Each unordered map's merge levels, at most `floor(log2 e) + 1` for its
    /// `e` entries, all together.
    pub merge_levels: u64,
    /// Each unordered map's entries times its merge levels, all together:
    /// every entry is written at every level of its own map.
    pub merges: u64,
    /// The most bytes its encoding has: heads, byte strings and map heads
    /// exactly, each text at most its decomposed parts' bytes and head, each
    /// bignum at most its digits' bytes. At least its plan's length, which
    /// the walk alone establishes, before anything is prepared.
    pub extent: u64,
    /// Each unordered map's key bytes, at most, times its merge levels, all
    /// together: each map's keys are compared at each of its levels.
    pub key_merges: u64,
    /// The payload bytes of each unordered map, at most, all together: each
    /// map's payload is compacted, scanned and permuted.
    pub payloads: u64,
    /// Each unordered map's payload bytes times its lookup probes, all
    /// together: a permuted byte is looked up among its own map's entries.
    pub payload_probes: u64,
    /// The most payload bytes of any one unordered map: its permutation's
    /// bitmap holds a bit for each.
    pub largest_payload: u64,
    /// The most unordered maps any one value lies within, itself included:
    /// a byte is in the keys, and in the payload, of at most this many.
    pub unordered_depth: u64,
    /// Its source texts.
    pub texts: u64,
    /// The bytes of all its source texts together.
    pub text_bytes: u64,
    /// The larger of its source texts in every count.
    pub longest_text: TextShape,
    /// The sum of each source text's [`text_cursor::normalization_bound`],
    /// one after another, each released before the next: exact per text,
    /// every text's arenas grown from empty.
    pub normalization: ResourceBound,
    /// The values its sources examine for their next instructions
    /// ([`Instruction::Inspect`]), all together.
    pub inspected: u64,
    /// The node moves its entry cursors state, all together: each cursor's
    /// stated moves per transition, twice for the transition that starts
    /// it ([`Entries::moves`]).
    pub moves: u64,
    /// Its bignums.
    pub bignums: u64,
    /// The 64-bit digits of all its bignums together.
    pub digits: u64,
}

impl Shape {
    /// The shape of `source`, walked as the engine walks it: every
    /// instruction requested in order, every child, key and value one frame
    /// deeper, every entry cursor stepped to its end, and a counted unordered
    /// map ended once its declared entries are yielded. One value is admitted
    /// per instruction, per cursor move and per inspection, the moves and
    /// inspections in units of at most a turn's values (`admit_stepped`), and
    /// each source text's bytes once, scanned for its decomposition; nothing
    /// is allocated ([`walk_work`]). Refused beyond [`SYMBOLIC_DEPTH`] frames,
    /// and for an out-of-profile value, as preparation refuses them.
    ///
    /// This is a synchronous walk, not a retained continuation. Refusal returns
    /// without a partial shape; calling it again repeats the walk and its work.
    pub fn of<B: Budget>(source: &dyn Schema, budget: &mut B) -> BoundedResult<Self, B> {
        let mut shape = Self::default();
        shape.extent = shape.walk(source, 1, 0, budget)?;
        Ok(shape)
    }

    /// The most bytes its plan appends: its extent, and a widest head's gap
    /// per map. The cap of the plan's arena ([`Preparation::capped`]), which
    /// publication hands over as the encoding.
    pub fn appended<R>(&self) -> Result<u64, BoundedError<R>> {
        add(self.extent, mul(self.maps, widen(MAX_HEAD_LEN)?)?)
    }

    /// One instruction of the walk, or one entry cursor transition,
    /// admitted and counted.
    fn instruction<B: Budget>(&mut self, budget: &mut B) -> BoundedResult<(), B> {
        WALKED.admit(budget)?;
        self.instructions = add(self.instructions, 1)?;
        Ok(())
    }

    /// `moves` node moves of an entry cursor, admitted before the walk
    /// makes them ([`admit_stepped`]), and counted for the preparation that
    /// makes them again.
    fn moved<B: Budget>(&mut self, moves: u64, budget: &mut B) -> BoundedResult<(), B> {
        admit_stepped(moves, budget)?;
        self.moves = add(self.moves, moves)?;
        Ok(())
    }

    /// One source text, its bytes admitted before they are scanned: its
    /// encoding's extent, at most its parts' bytes behind their head.
    fn text<B: Budget>(&mut self, text: &str, budget: &mut B) -> BoundedResult<u64, B> {
        SCANNED.admit(budget, widen(text.len())?)?;
        let shape = TextShape::of(text);
        self.texts = add(self.texts, 1)?;
        self.text_bytes = add(self.text_bytes, widen(text.len())?)?;
        self.longest_text = self.longest_text.larger(shape);
        self.normalization = self
            .normalization
            .checked_followed_by(text_cursor::normalization_bound(shape)?)
            .ok_or(BoundedError::Overflow)?;
        item_len(shape.part_bytes, shape.part_bytes)
    }

    /// One unordered map, complete, with its entries, the extent of its keys
    /// and of its payload: its merges, comparisons and permutation counted.
    fn merged<R>(&mut self, map: &MapExtent) -> Result<(), BoundedError<R>> {
        let levels = levels(map.entries)?;
        self.widest = self.widest.max(map.entries);
        self.merge_levels = add(self.merge_levels, levels)?;
        self.merges = add(self.merges, mul(map.entries, levels)?)?;
        self.key_merges = add(self.key_merges, mul(map.keys, levels)?)?;
        self.payloads = add(self.payloads, map.payload)?;
        self.payload_probes = add(self.payload_probes, mul(map.payload, levels)?)?;
        self.largest_payload = self.largest_payload.max(map.payload);
        Ok(())
    }

    /// The key and value of one unordered-map entry, each one frame deeper
    /// and within the map's `unordered` enclosing unordered maps, counted
    /// into `map`.
    fn entry<B: Budget>(
        &mut self,
        map: &mut MapExtent,
        (key, value): (&dyn Schema, &dyn Schema),
        depth: u64,
        unordered: u64,
        budget: &mut B,
    ) -> BoundedResult<(), B> {
        self.entries = add(self.entries, 1)?;
        let key = self.walk(key, depth + 1, unordered, budget)?;
        let value = self.walk(value, depth + 1, unordered, budget)?;
        map.entries = add(map.entries, 1)?;
        map.keys = add(map.keys, key)?;
        map.payload = add(map.payload, add(key, value)?)?;
        Ok(())
    }

    /// `source` at frame `depth`, within `unordered` unordered maps: its
    /// encoding's extent.
    fn walk<B: Budget>(
        &mut self,
        source: &dyn Schema,
        depth: u64,
        unordered: u64,
        budget: &mut B,
    ) -> BoundedResult<u64, B> {
        if depth > widen(SYMBOLIC_DEPTH)? {
            return Err(BoundedError::DepthLimit);
        }
        self.depth = self.depth.max(depth);
        // The unordered maps this source's entries lie within: its
        // enclosing ones, and itself once it begins one.
        let mut within = unordered;
        // The map this source began, of either kind: its present fields or
        // its entries, whose count its head carries.
        let mut map: Option<MapExtent> = None;
        // The entries an unordered map's head declared: once yielded, the
        // map ends without asking its source for more, as the preparation
        // ends it (`counted_complete`).
        let mut declared: Option<u64> = None;
        let mut extent = 0;
        let mut index = 0;
        loop {
            self.instruction(budget)?;
            if within > unordered
                && map
                    .as_ref()
                    .is_some_and(|map| yielded_all(declared, map.entries))
            {
                return self.closed(map, true, declared, extent);
            }
            match source.instruction(index) {
                Instruction::End => return self.closed(map, within > unordered, declared, extent),
                Instruction::Head(major, argument) => {
                    let mut head = [0; MAX_HEAD_LEN];
                    let len = write_argument(major, argument, &mut head);
                    extent = add(extent, widen(len)?)?;
                }
                Instruction::Bytes(bytes) => extent = add(extent, widen(bytes.len())?)?,
                Instruction::Text(text) => extent = add(extent, self.text(text, budget)?)?,
                Instruction::Child(child) => {
                    extent = add(extent, self.walk(child, depth + 1, within, budget)?)?
                }
                Instruction::Field(key, Some(child)) => {
                    if within > unordered {
                        return Err(BoundedError::PlanMismatch);
                    }
                    let fields = map.as_mut().ok_or(BoundedError::PlanMismatch)?;
                    fields.entries = add(fields.entries, 1)?;
                    extent = add(extent, item_len(key, 0)?)?;
                    extent = add(extent, self.walk(child, depth + 1, within, budget)?)?;
                }
                Instruction::Field(_, None) => {
                    if map.is_none() || within > unordered {
                        return Err(BoundedError::PlanMismatch);
                    }
                }
                instruction @ (Instruction::Map | Instruction::CountedMap(_)) => {
                    if map.is_some() {
                        return Err(BoundedError::PlanMismatch);
                    }
                    self.maps = add(self.maps, 1)?;
                    map = Some(MapExtent::default());
                    if let Instruction::CountedMap(count) = instruction {
                        declared = Some(count);
                    }
                }
                instruction @ (Instruction::UnorderedMap | Instruction::CountedUnorderedMap(_)) => {
                    if map.is_some() {
                        return Err(BoundedError::PlanMismatch);
                    }
                    self.maps = add(self.maps, 1)?;
                    self.unordered = add(self.unordered, 1)?;
                    within = add(unordered, 1)?;
                    self.unordered_depth = self.unordered_depth.max(within);
                    map = Some(MapExtent::default());
                    if let Instruction::CountedUnorderedMap(count) = instruction {
                        declared = Some(count);
                    }
                }
                Instruction::Inspect(values) => {
                    admit_stepped(values, budget)?;
                    self.inspected = add(self.inspected, values)?;
                }
                #[cfg(feature = "num-bigint")]
                Instruction::Bignum { magnitude, .. } => {
                    // Its tag and its byte string, at most every digit's
                    // bytes: the scan that finds the exact length is the
                    // preparation's.
                    let digits = widen(magnitude.iter_u64_digits().len())?;
                    let bytes = mul(digits, 8)?;
                    self.bignums = add(self.bignums, 1)?;
                    self.digits = add(self.digits, digits)?;
                    extent = add(
                        extent,
                        add(
                            item_len(crate::TAG_NEGATIVE_BIGNUM, 0)?,
                            item_len(bytes, bytes)?,
                        )?,
                    )?;
                }
                Instruction::Entry(key, value) => {
                    if within == unordered {
                        return Err(BoundedError::PlanMismatch);
                    }
                    let entries = map.as_mut().ok_or(BoundedError::PlanMismatch)?;
                    self.entry(entries, (key, value), depth, within, budget)?;
                }
                // The table's buckets enumerated by the engine's one bucket
                // traversal, each window admitted before it is inspected, as
                // the preparation enumerates them again; the map ends once
                // its declared entries are yielded.
                #[cfg(any(feature = "hashbrown", feature = "custom-std-collections"))]
                Instruction::Buckets(table) => {
                    if within == unordered || map.as_ref().is_none_or(|map| map.entries != 0) {
                        return Err(BoundedError::PlanMismatch);
                    }
                    self.bucket_tables = add(self.bucket_tables, 1)?;
                    self.buckets = add(self.buckets, widen(table.num_buckets())?)?;
                    // The walk is the custody of its windows, synchronous:
                    // the owner of their acquisitions, made for this table.
                    let owner = budget.owner().map_err(BoundedError::Refused)?;
                    let mut enumeration = BucketWalk {
                        position: BucketPosition::new(),
                        window: None,
                        acquisition: None,
                        owner,
                        map,
                        declared,
                    };
                    let entries =
                        self.bucket_entries_of(table, &mut enumeration, depth, within, budget);
                    // A walk that ends early, refused or failed, ends the
                    // cursor: its window's unspent credit forfeited, then its
                    // acquisition ended.
                    if entries.is_err() {
                        BucketCursor::new(
                            &mut enumeration.position,
                            &mut enumeration.window,
                            &mut enumeration.acquisition,
                        )
                        .end(budget.performer(), Forfeit::Cancelled);
                    }
                    entries?;
                    return self.closed(enumeration.map, true, declared, extent);
                }
                Instruction::Entries(entries) => {
                    if within == unordered || map.as_ref().is_none_or(|map| map.entries != 0) {
                        return Err(BoundedError::PlanMismatch);
                    }
                    let moves = entries.moves();
                    let mut slot = Slot::new();
                    // The start's moves and the first transition's, as the
                    // preparation admits them with that transition.
                    self.moved(mul(moves, 2)?, budget)?;
                    entries.start(&mut slot);
                    let mut first = true;
                    loop {
                        self.instruction(budget)?;
                        if map
                            .as_ref()
                            .is_some_and(|map| yielded_all(declared, map.entries))
                        {
                            return self.closed(map, true, declared, extent);
                        }
                        if !first {
                            self.moved(moves, budget)?;
                        }
                        first = false;
                        // SAFETY: `start` stored this source's own cursor.
                        match unsafe { entries.next(&mut slot) } {
                            EntryStep::Progress => {}
                            EntryStep::Entry(key, value) => {
                                let entries = map.as_mut().ok_or(BoundedError::PlanMismatch)?;
                                self.entry(entries, (key, value), depth, within, budget)?
                            }
                            EntryStep::End => return self.closed(map, true, declared, extent),
                        }
                    }
                }
                Instruction::OutOfRange => return Err(BoundedError::OutOfRange),
            }
            index = index.checked_add(1).ok_or(BoundedError::Overflow)?;
        }
    }

    /// A hash table's entries, enumerated by the engine's one bucket
    /// traversal as the preparation enumerates them again, each walked into
    /// `map`, until the cursor completes or the map's `declared` entries are
    /// yielded, which ends the cursor, its window's unspent credit forfeited
    /// ([`Forfeit::EnumerationComplete`]).
    #[cfg(any(feature = "hashbrown", feature = "custom-std-collections"))]
    fn bucket_entries_of<B: Budget>(
        &mut self,
        table: &dyn Buckets,
        enumeration: &mut BucketWalk<B::Origin>,
        depth: u64,
        within: u64,
        budget: &mut B,
    ) -> BoundedResult<(), B> {
        let BucketWalk {
            position,
            window,
            acquisition,
            owner,
            map,
            declared,
        } = enumeration;
        loop {
            let mut cursor = BucketCursor::new(position, window, acquisition);
            if map
                .as_ref()
                .is_some_and(|map| yielded_all(*declared, map.entries))
            {
                // The end the preparation admits as a transition of the
                // map, no bucket inspected.
                self.instruction(budget)?;
                cursor.end(budget.performer(), Forfeit::EnumerationComplete);
                return Ok(());
            }
            match cursor.step(table, owner, budget)? {
                BucketStep::Vacant { .. } => {}
                BucketStep::Entry { key, value, .. } => {
                    self.bucket_entries = add(self.bucket_entries, 1)?;
                    let entries = map.as_mut().ok_or(BoundedError::PlanMismatch)?;
                    self.entry(entries, (key, value), depth, within, budget)?
                }
                BucketStep::Complete => return Ok(()),
                BucketStep::Finished => return Err(BoundedError::PlanMismatch),
            }
        }
    }

    /// A source's walk ended with `extent` bytes besides the map it began,
    /// if any: an unordered one's merges counted. Its extent with that map's
    /// head, which carries its count, and its entries' payload.
    fn closed<R>(
        &mut self,
        map: Option<MapExtent>,
        unordered: bool,
        declared: Option<u64>,
        extent: u64,
    ) -> Result<u64, BoundedError<R>> {
        let Some(map) = map else {
            return Ok(extent);
        };
        check_count(declared, map.entries)?;
        if unordered {
            self.merged(&map)?;
        }
        add(add(extent, map.payload)?, item_len(map.entries, 0)?)
    }
}

/// What a walk counts of the map one source begins: its present fields or
/// entries, and an unordered map's key and payload bytes, at most. A field
/// map's fields are counted into its source's extent as they are walked.
#[derive(Default)]
struct MapExtent {
    entries: u64,
    keys: u64,
    payload: u64,
}

/// A walk's enumeration of one hash table's buckets
/// ([`Shape::bucket_entries_of`]): its cursor's position, its window's
/// credit and its window's acquisition, the owner of its windows'
/// acquisitions, the map its entries are counted into, and the entries the
/// map's head declared, if it did.
#[cfg(any(feature = "hashbrown", feature = "custom-std-collections"))]
struct BucketWalk<O: Origin> {
    position: BucketPosition,
    window: Option<Retained<O>>,
    acquisition: Option<crate::bounded::Acquisition<O>>,
    owner: Owner,
    map: Option<MapExtent>,
    declared: Option<u64>,
}

/// The work a walk of a source of `shape` reports ([`Shape::of`]): one value
/// per instruction, per entry cursor move and per inspection, each text's
/// bytes once, and each hash table's enumeration by the bucket cursor
/// (`bucket_work`). A walk allocates nothing.
pub fn walk_work<R>(shape: Shape) -> Result<WriteWork, BoundedError<R>> {
    WriteWork::checked_sequence(&[
        WALKED.times(shape.instructions)?,
        STEPPED.of(add(shape.moves, shape.inspected)?)?,
        SCANNED.units(shape.texts, shape.text_bytes)?,
        bucket_work::<R>(shape)?,
    ])
    .ok_or(BoundedError::Overflow)
}

/// One family of the values a shape's walk admits ([`Shape::of`]), named by
/// the instructions its source answers, with the sizes it declares, its
/// children excluded: each child is a family of its own, so a value's
/// discovery is the sum over its nodes' families. A derived record is no
/// family of its own: its field map, array or tagged form and each field's
/// family compose it. Each family's discovery bound, B_shape, is
/// [`walk_work`] of its declared counts ([`Self::shape`]): one value per
/// instruction its source answers, every `End` included, one per node move
/// or inspection, each text's bytes once, and a hash table's enumeration.
/// The formula of each is at its variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShapeFamily {
    /// A value of one head, an integer, a float or a simple value: `Head`,
    /// `End`. B_shape: 2 values.
    Scalar,
    /// A byte string: `Head`, `Bytes`, `End`, its bytes not scanned.
    /// B_shape: 3 values.
    Bytes,
    /// A text of `bytes` bytes: `Text`, `End`, its bytes scanned once.
    /// B_shape: 2 values and `bytes` bytes.
    Text { bytes: u64 },
    /// An array of `elements` elements: `Head`, a `Child` each, `End`.
    /// B_shape: `elements + 2` values.
    Array { elements: u64 },
    /// A tagged value: `Head`, `Child`, `End`. B_shape: 3 values.
    Tagged,
    /// A value standing for one child, a present option: `Child`, `End`.
    /// B_shape: 2 values.
    Wrapped,
    /// A field map of `fields` fields, present or omitted: `Map` or
    /// `CountedMap`, a `Field` each, `End`. B_shape: `fields + 2` values.
    FieldMap { fields: u64 },
    /// An unordered map yielding its `entries` entries one per instruction:
    /// `UnorderedMap` or `CountedUnorderedMap`, an `Entry` each, and its end.
    /// B_shape: `entries + 2` values.
    EntryMap { entries: u64 },
    /// An unordered map of `entries` entries drawn by an entry cursor that
    /// states `moves` node moves per transition and yields an entry or its
    /// end at each: `UnorderedMap`, `Entries`, a transition per entry and one
    /// to end, the moves of the first transition twice. B_shape: `entries +
    /// 3 + moves (entries + 2)` values.
    CursorMap { entries: u64, moves: u64 },
    /// A hash table of `buckets` buckets and `entries` entries enumerated by
    /// the bucket cursor: `CountedUnorderedMap`, `Buckets`, its end once its
    /// count is yielded. B_shape: 3 values and
    /// [`buckets::bucket_bound`]`(buckets, entries)`'s work. Of no entries,
    /// the map ends at its declared count before `Buckets` is requested, so
    /// no bucket is enumerated: `CountedUnorderedMap` and its end, 2 values.
    #[cfg(any(feature = "hashbrown", feature = "custom-std-collections"))]
    BucketMap { buckets: u64, entries: u64 },
    /// `values` values a source inspects before its next instruction:
    /// `Inspect`. B_shape: `values + 1` values.
    Inspect { values: u64 },
    /// A bignum: `Bignum`, `End`, its digits the preparation's to read.
    /// B_shape: 2 values.
    #[cfg(feature = "num-bigint")]
    Bignum,
}

impl ShapeFamily {
    /// The counts this family declares, those [`walk_work`] reads: its
    /// instructions, node moves, inspections, texts and their bytes, and
    /// hash tables. `None` of the rest.
    pub fn shape<R>(self) -> Result<Shape, BoundedError<R>> {
        let walked = |instructions| Shape {
            instructions,
            ..Shape::default()
        };
        Ok(match self {
            Self::Scalar | Self::Wrapped => walked(2),
            Self::Bytes | Self::Tagged => walked(3),
            Self::Text { bytes } => Shape {
                instructions: 2,
                texts: 1,
                text_bytes: bytes,
                ..Shape::default()
            },
            Self::Array { elements } => walked(add(elements, 2)?),
            Self::FieldMap { fields } => walked(add(fields, 2)?),
            Self::EntryMap { entries } => walked(add(entries, 2)?),
            Self::CursorMap { entries, moves } => Shape {
                instructions: add(entries, 3)?,
                moves: mul(moves, add(entries, 2)?)?,
                ..Shape::default()
            },
            // A counted map of none ends before its table is asked for
            // (`Shape::walk`, `yielded_all`).
            #[cfg(any(feature = "hashbrown", feature = "custom-std-collections"))]
            Self::BucketMap { entries: 0, .. } => walked(2),
            #[cfg(any(feature = "hashbrown", feature = "custom-std-collections"))]
            Self::BucketMap { buckets, entries } => Shape {
                instructions: 3,
                bucket_tables: 1,
                buckets,
                bucket_entries: entries,
                ..Shape::default()
            },
            Self::Inspect { values } => Shape {
                instructions: 1,
                inspected: values,
                ..Shape::default()
            },
            #[cfg(feature = "num-bigint")]
            Self::Bignum => walked(2),
        })
    }

    /// This family's discovery bound, B_shape: [`walk_work`] of its declared
    /// counts ([`Self::shape`]).
    pub fn discovery<R>(self) -> Result<WriteWork, BoundedError<R>> {
        walk_work(self.shape()?)
    }
}

/// `total` with `part`'s walked counts added: the counts [`walk_work`]
/// reads, summed over the families of one value.
fn walked_counts<R>(total: Shape, part: Shape) -> Result<Shape, BoundedError<R>> {
    Ok(Shape {
        instructions: add(total.instructions, part.instructions)?,
        moves: add(total.moves, part.moves)?,
        inspected: add(total.inspected, part.inspected)?,
        texts: add(total.texts, part.texts)?,
        text_bytes: add(total.text_bytes, part.text_bytes)?,
        bucket_tables: add(total.bucket_tables, part.bucket_tables)?,
        buckets: add(total.buckets, part.buckets)?,
        bucket_entries: add(total.bucket_entries, part.bucket_entries)?,
        ..total
    })
}

/// The planning bound of a value's discovery, priced before anything of it
/// is inspected: the work [`Shape::of`] admits walking a value whose nodes
/// are of `families`, from their declared sizes alone ([`walk_work`] of
/// their summed counts, [`ShapeFamily::shape`]). A capability of its own
/// beside the incremental, admitted discovery that [`Shape::of`] is: a
/// caller prices the walk with it before committing to the walk, and
/// [`prepare`] keeps its one entry. Its own work is
/// admitted first, in one unit of a value per family (`PLANNED`).
pub fn discovery_bound<B: Budget>(
    families: &[ShapeFamily],
    budget: &mut B,
) -> BoundedResult<ResourceBound, B> {
    PLANNED.admit(budget, widen(families.len())?)?;
    let mut declared = Shape::default();
    for family in families {
        declared = walked_counts(declared, family.shape()?)?;
    }
    Ok(ResourceBound::of_work(walk_work(declared)?))
}

/// The work of enumerating `shape`'s hash tables, each by the one bucket
/// cursor ([`buckets::bucket_bound`] summed over them): what the walk and
/// the preparation each charge, both enumerating them. None where no hash
/// table is encoded.
fn bucket_work<R>(shape: Shape) -> Result<WriteWork, BoundedError<R>> {
    #[cfg(any(feature = "hashbrown", feature = "custom-std-collections"))]
    {
        buckets::bucket_work::<R>(shape.bucket_tables, shape.buckets, shape.bucket_entries)
    }
    #[cfg(not(any(feature = "hashbrown", feature = "custom-std-collections")))]
    {
        let _ = shape;
        Ok(WriteWork::default())
    }
}

/// `floor(log2 n) + 1` for `n` at least one, and one for none: at least the
/// levels a merge of `n` entries passes (`ceil(log2 n)`), and the probes a
/// binary lookup among them makes.
fn levels<R>(n: u64) -> Result<u64, BoundedError<R>> {
    add(u64::from(n.max(1).ilog2()), 1)
}

/// The [`ResourceBound`] of a [`Preparation`] of a source of `shape`, from
/// its first step to publication or to any failure, and its cleanup
/// ([`Preparation::reclaim_step`]). The shape counts the
/// source's maps, unordered maps, entries, each map's merge levels and
/// texts exactly, and each unordered map's key and payload bytes exactly
/// but for texts, whose encodings it bounds by their parts' bytes; those
/// are capped by `unordered_depth` times the extent each, as a byte lies in
/// the keys, and in the payload, of at most `unordered_depth` unordered
/// maps, as in
/// [`decode::decode_bound`]. Frames, open maps and open entry cursors are at
/// most `depth`. Each term is charged where the engine charges it:
///
/// - each instruction: one unit of one value and `MAX_HEAD_LEN` bytes, or
///   64 bytes within an unordered map its source began; one value per node
///   move an entry cursor states for its transition, twice for the
///   transition that starts it, and one value per presence a source
///   inspects for a counted head, each admitted in units of at most a
///   turn's values ([`TURN`]);
/// - each text's quick check over its bytes, in windows of whole scalars of
///   at most a quantum, each but the last at least a quantum less three
///   bytes; a text it proves normal then copied as it is;
/// - each bignum's digits read twice, scanned for its length and emitted,
///   in units of at most a quantum of their bytes;
/// - each frame: one value to push it, for the root, the child, field or
///   key an instruction names, and each entry's value, which no instruction
///   names: its compacted key sets it; the frame, gap, open-map and cursor
///   arenas ([`storage_growth`]), each holding one more than it uses;
/// - the byte arena of at most the extent and a `MAX_HEAD_LEN` gap per map:
///   each item appended in units of at most 64 bytes, an item cut short at
///   most once by each growth; every byte appended once;
/// - each text: its continuation initialized again, field by field, then
///   normalized and encoded (the shape's sum of each text's
///   [`text_cursor::normalization_bound`], and one publication unit of an
///   encoding per text; its scratch released before the next), then its
///   encoding copied in and released;
/// - each unordered-map key and value compacted once complete: its record
///   opened and closed in a unit of the record's bytes each, the plan's bytes
///   and gaps truncated in a unit of none each, each later byte moved in
///   units of at most a quantum, each gap, of a map of either kind, removed
///   in a unit of its record's bytes;
/// - each unordered map of `e` entries whose source yields them in
///   canonical order ([`Entries::ordered`]) checked key by key against the
///   one before, within the comparisons below; every other one ordered by
///   stable merge (`maps::order`): per merge level of its own, at most
///   `6e + 5` units,
///   every entry written and its scratch copied, and the comparisons' key
///   bytes, at most its keys', in units of at most 64; then checked, and
///   when misordered permuted in place (`permutation`): per payload byte
///   a cycle scan unit, a lookup among its own entries of at most
///   `floor(log2 e) + 1` probes and one move, and a bitmap bit, the bitmap of
///   `b` bytes grown from empty for each such map and released after it:
///   under `2b` bytes relocated and `3b` requested, one bitmap held at a
///   time;
/// - each unordered map's completion: three units of at most a frame's
///   bytes;
/// - cleanup: an interrupted text's continuation's own cleanup, its arenas
///   drained and its output released; the copied text; each of eight arenas
///   of plain data truncated in one unit and released, or, the one arena
///   cancelled while it stages a growth or relocates (the exclusion the
///   peak rests on), drained one element per unit, charged at the most of
///   any arena's elements; the record's transition and the completion.
///
/// The plan's byte and gap arenas are what publication retains. The peak is
/// every kept arena at its held capacity and the largest of what one phase
/// adds beside them: one arena's relocation, a text's normalization, a
/// normalized encoding copied into the relocating plan, or the visited
/// bitmap (`PreparationTerms::peak`).
/// Refused, never saturated, when a quantity does not fit in `u64`. `P` is
/// the policy's permit and `O` its origin ([`Budget::Origin`]): the custody
/// a text's continuation is rewritten with is of both.
pub fn prepare_bound<P, O: Origin, R>(shape: Shape) -> Result<ResourceBound, BoundedError<R>> {
    PreparationTerms::of::<P, O, R>(shape)?.bound()
}

/// The [`ResourceBound`] of [`encode`] of a value of
/// `shape`, with permits of type `P`: its shape's walk ([`walk_work`]), then
/// its preparation ([`prepare_bound`]), its plan capped at the extent and a
/// widest head per map, then its publication in place ([`emit_bound`] of
/// those bytes, at most), which releases the gap records: what the
/// encoding retains is the plan's byte arena alone.
pub fn encode_bound<P, O: Origin, R>(shape: Shape) -> Result<ResourceBound, BoundedError<R>> {
    let terms = PreparationTerms::of::<P, O, R>(shape)?;
    // Publication in place keeps the plan's bytes as the encoding and
    // releases everything else, the gap records among them: what follows is
    // the plan alone, held.
    let plan = terms.term(PreparationPlace::PlanBytes).retained;
    let encoding = ResourceBound {
        peak: plan,
        retained: plan,
        ..ResourceBound::default()
    };
    let emitted = emit_bound::<R>(shape.appended()?)?;
    ResourceBound::of_work(walk_work(shape)?)
        .checked_then(terms.bound()?)
        .and_then(|prepared| prepared.checked_then(emitted))
        .and_then(|published| published.checked_followed_by(encoding))
        .ok_or(BoundedError::Overflow)
}

places! {
    /// The places a [`Preparation`] charges, one term of [`prepare_bound`]
    /// each, and its cleanup ([`Preparation::reclaim_step`]), which the
    /// owned preparation's bound counts ([`owned_prepare_bound`]).
    pub(crate) enum PreparationPlace {
        Instructions,
        Pushes,
        Frames,
        Gaps,
        OpenMaps,
        Cursors,
        EntryArena,
        PlanBytes,
        Appends,
        Texts,
        Compaction,
        Merging,
        Comparisons,
        Scratch,
        Check,
        Permutation,
        Visited,
        /// Hash tables' buckets, enumerated by the bucket cursor.
        Buckets,
        /// Bignum magnitudes' digits, scanned and emitted.
        Digits,
        Completion,
        Cleanup,
    }
}

/// Inspecting one instruction of a source that began no unordered map: one
/// value and at most a head's bytes.
const INDEXED: Unit<PreparationPlace> =
    Unit::new(PreparationPlace::Instructions, 1, MAX_HEAD_LEN as u64);

/// One entry cursor transition, or the end of a counted map reached without
/// one: one value. A transition inspects no bucket control; a hash table's
/// controls are admitted by its bucket cursor ([`buckets::BucketCursor`]).
const CURSOR: Unit<PreparationPlace> = Unit::new(PreparationPlace::Instructions, 1, 0);

/// The node moves an entry cursor states for its transition, one value
/// each, admitted before it in units of at most [`UNIT_VALUES`].
const MOVED: Rate<PreparationPlace> = Rate::new(PreparationPlace::Instructions, 1, 0);

/// The values a source examines for its next instruction
/// ([`Instruction::Inspect`]), admitted in units of at most
/// [`UNIT_VALUES`].
const INSPECTED: Rate<PreparationPlace> = Rate::new(PreparationPlace::Instructions, 1, 0);

/// The most values one unit of node moves or of inspections admits: a
/// turn's quantum ([`TURN`]), so a count of any size is admitted in units a
/// turn can hold, never in one it cannot.
const UNIT_VALUES: u64 = TURN.values;

/// The bucket controls one window of a hash table's enumeration admits
/// ([`buckets::BucketCursor`]): a quantum, the last window of a table
/// shorter. Windows are index-aligned.
pub const BUCKET_WINDOW: usize = decode::construction::stable::QUANTUM;

/// Pushing one frame.
const PUSH: Unit<PreparationPlace> = Unit::new(PreparationPlace::Pushes, 1, 0);

/// Appending one part of an item to the plan's bytes: one value and at most
/// a quantum of bytes.
const APPEND: Capped<PreparationPlace> = Capped::new(
    PreparationPlace::Appends,
    1,
    decode::construction::stable::QUANTUM as u64,
);

/// One window of a text's quick check: one value and at most a quantum of
/// its bytes ([`TextCheck::step`]).
const TEXT_CHECK: Capped<PreparationPlace> = Capped::new(
    PreparationPlace::Texts,
    1,
    decode::construction::stable::QUANTUM as u64,
);

/// Completing the preparation.
const DONE: Unit<PreparationPlace> = Unit::new(PreparationPlace::Completion, 1, 0);

/// Completing the preparation's cleanup.
const CLEANUP_DONE: Unit<PreparationPlace> = Unit::new(PreparationPlace::Cleanup, 1, 0);

/// An owned preparation's record entering its cleanup, or released before
/// its initialization completed.
const PLAN_TRANSITION: Unit<PreparationPlace> = Unit::new(PreparationPlace::Cleanup, 1, 0);

places! {
    /// The places a shape's walk ([`Shape::of`]) charges.
    pub(crate) enum ShapePlace {
        Instructions,
        Texts,
        /// The planning bound priced from declared families
        /// ([`discovery_bound`]).
        Planning,
    }
}

/// Pricing a discovery from its declared families ([`discovery_bound`]): one
/// value per family.
const PLANNED: Rate<ShapePlace> = Rate::new(ShapePlace::Planning, 1, 0);

/// One instruction walked.
const WALKED: Unit<ShapePlace> = Unit::new(ShapePlace::Instructions, 1, 0);

/// One text's bytes scanned for its decomposition.
const SCANNED: Scan<ShapePlace> = Scan::new(ShapePlace::Texts, 0);

/// Values the walk spends beyond an instruction, one each: an entry
/// cursor's node moves, a source's inspections for its next instruction.
const STEPPED: Rate<ShapePlace> = Rate::new(ShapePlace::Instructions, 1, 0);

/// `count` values the walk spends beyond an instruction ([`STEPPED`]),
/// admitted before they are spent in units of at most [`UNIT_VALUES`], as
/// the preparation admits the same moves and inspections: no unit is wider
/// than a turn, and a count of none admits nothing.
fn admit_stepped<B: Budget>(count: u64, budget: &mut B) -> BoundedResult<(), B> {
    let mut left = count;
    while left > 0 {
        let unit = left.min(UNIT_VALUES);
        STEPPED.admit(budget, unit)?;
        left -= unit;
    }
    Ok(())
}

/// The terms [`prepare_bound`] sums, each the bound of one place the engine
/// charges, kept apart so each can be checked against that place alone, as
/// the decoder's are.
struct PreparationTerms {
    terms: [ResourceBound; PreparationPlace::ALL.len()],
    /// The most the preparation holds at once. The engine's phases exclude
    /// one another: an arena that grows relocates in turns of its own, every
    /// other branch of [`Preparation::advance`] waiting until it is ready (a
    /// plan relocates only while bytes are pending, the frame, gap, open-map,
    /// cursor and descriptor arenas before the instruction that needs them,
    /// the merge scratch within its own copy phase); a text is normalized
    /// only when nothing is staged, pending or copied; its encoding is held
    /// only while it is copied into the plan; a map's visited bitmap exists
    /// only within its permutation, released before the map completes; and
    /// every arena but the bitmap keeps its capacity until cleanup, which
    /// allocates nothing. So the peak is every kept arena's held capacity,
    /// and the largest of: one arena's old allocation beside its new one, a
    /// text's normalization peak, a normalized encoding beside the plan's
    /// relocation, and the bitmap at its own peak. That at most one arena, of
    /// the preparation's and its text continuation's, is ever staging a
    /// growth, relocating or relocated is checked at every boundary of every
    /// attribution run (`bound_tests::attribution::draining`); cleanup's
    /// drain rests on it too.
    peak: u64,
}

impl PreparationTerms {
    /// The terms of a preparation with permits of `P` whose retained credit
    /// settles into origins of `O`: each text's continuation, rewritten field
    /// by field, holds custody of both, so its bytes are `O`'s too.
    fn of<P, O: Origin, R>(shape: Shape) -> Result<Self, BoundedError<R>> {
        use core::mem::size_of;
        let Shape {
            instructions,
            // Counted into the bucket cursor's term ([`bucket_work`]).
            bucket_tables: _,
            buckets: _,
            bucket_entries: _,
            depth,
            maps,
            unordered,
            entries,
            widest,
            merge_levels,
            merges,
            extent,
            key_merges,
            payloads,
            payload_probes,
            largest_payload,
            unordered_depth,
            texts,
            text_bytes,
            longest_text,
            normalization,
            inspected,
            moves,
            bignums,
            digits,
        } = shape;
        // The source's own key and payload bytes, each capped by what any
        // source of its extent and unordered nesting has.
        let probes = levels(widest)?;
        let cap = mul(unordered_depth, extent)?;
        let probed = mul(probes, cap)?;
        let key_merges = key_merges.min(probed);
        let payloads = payloads.min(cap);
        let payload_probes = payload_probes.min(probed);
        let largest_payload = largest_payload.min(extent);
        // Frames, open maps and open entry cursors: at most one per frame,
        // and the arena holds one more than it uses.
        let held = add(depth, 1)?;
        let appended = shape.appended()?;
        // Each growth of the plan's arena cuts at most one item short.
        let growths = add(u64::from(appended.max(1).ilog2()), 2)?;
        // An instruction appends at most one item: a head, a payload, a
        // text's encoding or a map's gap; a child, an entry or an end
        // appends none. Each item is at least one byte. A bignum appends
        // its tag, its byte string's head and a quantum of bytes per
        // unit of digits read, its first unit cut short by the leading
        // bytes it drops.
        let items = add(instructions.min(appended), mul(bignums, 3)?)?;
        let children = mul(entries, 2)?;
        let entry = widen(size_of::<maps::order::Entry>())?;
        let bitmap = add(payloads.div_ceil(8), unordered)?;
        let largest = largest_payload.div_ceil(8);
        let bitmap_growths = add(u64::from(largest.max(1).ilog2()), 2)?;
        // An arena of at most `elements` of `size` bytes: each relocated
        // element one unit of its bytes, each growth's writes, and the
        // releases its growths admit; what it holds once published when
        // `published`; and its growth, which the joint peak composes.
        let overflow = || BoundedError::Overflow;
        // Its work runs while its storage is held, the two concurrent; an
        // arena publication does not retain is released after.
        let arena = |elements: u64, size: u64, published: bool| {
            let (growth, growing) = storage_growth::<R>(elements, size)?;
            let work =
                WriteWork::checked_sequence(&[growing, growth.released()?]).ok_or_else(overflow)?;
            let term = ResourceBound::of_work(work).checked_add(ResourceBound {
                allocated: growth.allocated,
                peak: growth.peak,
                retained: growth.held,
                ..ResourceBound::default()
            });
            let term = if published {
                term
            } else {
                term.and_then(|term| term.checked_followed_by(ResourceBound::default()))
            };
            Ok::<_, BoundedError<R>>((term.ok_or_else(overflow)?, growth))
        };
        let work = ResourceBound::of_work;
        let step = |count: u64| Storage::<u8, (), ()>::step_work::<R>(count);
        let mut terms = [ResourceBound::default(); PreparationPlace::ALL.len()];
        let mut set = |place: PreparationPlace, term: ResourceBound| {
            terms[place as usize] = term;
        };
        // Each instruction a source answers, each entry cursor transition and
        // each counted map's end reached without one, at most a source
        // instruction's head each; the node moves cursors state, and the
        // inspections sources announce.
        set(
            PreparationPlace::Instructions,
            work(
                WriteWork::checked_sequence(&[
                    INDEXED.times(instructions)?,
                    MOVED.over(0, moves)?,
                    INSPECTED.over(0, inspected)?,
                ])
                .ok_or_else(overflow)?,
            ),
        );
        // Each hash table's buckets, enumerated by the bucket cursor: every
        // control admitted once with its window.
        set(PreparationPlace::Buckets, work(bucket_work::<R>(shape)?));
        // Each bignum's digits read twice, in its scan and its emission, a
        // unit of at most a quantum of their bytes at a time, each pass's
        // last unit partial.
        #[cfg(feature = "num-bigint")]
        let digit_pass = super::bigint::digits_work::<R>(digits, bignums)?;
        // No bignum is encoded where bignums are not.
        #[cfg(not(feature = "num-bigint"))]
        let digit_pass = {
            let _ = (digits, bignums);
            WriteWork::default()
        };
        set(
            PreparationPlace::Digits,
            work(digit_pass.checked_times(2).ok_or_else(overflow)?),
        );
        // The root, each child, field or key an instruction names, and each
        // entry's value, which its compacted key sets.
        set(
            PreparationPlace::Pushes,
            work(PUSH.times(add(add(instructions, entries)?, 1)?)?),
        );
        let (frames, frames_growth) = arena(held, widen(size_of::<Frame<'static>>())?, false)?;
        set(PreparationPlace::Frames, frames);
        let (gaps, gaps_growth) = arena(add(maps, 1)?, widen(size_of::<(usize, usize)>())?, true)?;
        set(PreparationPlace::Gaps, gaps);
        let (open_maps, open_maps_growth) =
            arena(held, widen(size_of::<MapFrame<'static>>())?, false)?;
        set(PreparationPlace::OpenMaps, open_maps);
        let (cursors, cursors_growth) = arena(
            held,
            widen(size_of::<(Option<&'static dyn Entries>, Slot)>())?,
            false,
        )?;
        // Each cursor retains two whole-element custody parts. Growth
        // rounding applies to the part count, including empty entry pairs.
        let window_parts = mul(held, 2)?;
        let (windows, windows_growth) =
            arena(window_parts, widen(size_of::<WindowPart<O>>())?, false)?;
        set(
            PreparationPlace::Cursors,
            cursors.checked_add(windows).ok_or_else(overflow)?,
        );
        // Every map's descriptors are truncated at its completion and the
        // arena stays with the preparation: publication retains none.
        let (descriptors, descriptors_growth) = arena(add(entries, 1)?, entry, false)?;
        set(PreparationPlace::EntryArena, descriptors);
        let (plan, plan_growth) = arena(add(appended, 1)?, 1, true)?;
        set(PreparationPlace::PlanBytes, plan);
        set(
            PreparationPlace::Appends,
            work(APPEND.covering(appended, add(items, growths)?)?),
        );
        // Each text's quick check over its bytes, in windows of at least
        // `CHECK_LEAST` bytes but its last: a text of `b` bytes in at most
        // `floor(b / CHECK_LEAST) + 1`, so all of them in at most
        // `floor(text_bytes / CHECK_LEAST) + texts`. Then, for a text it
        // leaves unproven, its continuation initialized again, field by
        // field, its normalization, its publication and its encoding's
        // release.
        let windows = add(text_bytes / CHECK_LEAST, texts)?;
        let per_text = |work: WriteWork| work.checked_times(texts).ok_or_else(overflow);
        let texts_work = WriteWork::checked_sequence(&[
            WriteWork::new(mul(windows, TEXT_CHECK.values())?, text_bytes),
            per_text(decode::initialization::fields::<
                TextContinuation<(), P, O>,
                R,
            >(TextContinuation::<(), P, O>::INIT_STEPS)?)?,
            normalization.work(),
            per_text(text_cursor::publication::<P, R>()?)?,
            // Each encoding's release, admitted before it is requested; the
            // preparation drops the copied encoding without admitting again.
            per_text(text_cursor::output_release::<P, R>()?)?,
        ])
        .ok_or_else(overflow)?;
        // The checks and normalizations run while the normalizations hold
        // their storage, the two concurrent; each text's storage released
        // before the next and the last before the preparation completes.
        set(
            PreparationPlace::Texts,
            ResourceBound::of_work(texts_work)
                .checked_add(ResourceBound {
                    allocated: normalization.allocated,
                    peak: normalization.peak,
                    retained: normalization.retained,
                    ..ResourceBound::default()
                })
                .and_then(|texts| texts.checked_followed_by(ResourceBound::default()))
                .ok_or_else(overflow)?,
        );
        // Each unordered-map key and value compacted: its record opened and
        // closed, the plan's bytes and gaps truncated, every payload byte
        // moved once per enclosing unordered map in units of at most a
        // quantum, a run cut short at each child and at each gap, and each
        // gap removed.
        set(
            PreparationPlace::Compaction,
            work(
                WriteWork::checked_sequence(&[
                    dynamic::COMPACT.times(mul(children, 2)?)?,
                    step(mul(children, 2)?)?,
                    dynamic::MOVE.covering(payloads, add(children, maps)?)?,
                    dynamic::GAP.times(maps)?,
                ])
                .ok_or_else(overflow)?,
            ),
        );
        // Each map's merge: per level of its own every entry copied into the
        // scratch and written back, and up to two steps per entry; five per
        // level; two to finish.
        set(
            PreparationPlace::Merging,
            work(
                WriteWork::checked_sequence(&[
                    maps::order::MERGE_MOVE.times(mul(merges, 3)?)?,
                    maps::order::MERGE_STEP.times(add(
                        add(mul(merges, 2)?, mul(merge_levels, 5)?)?,
                        mul(unordered, 2)?,
                    )?)?,
                ])
                .ok_or_else(overflow)?,
            ),
        );
        // Each map's comparisons: at most one per entry written at each of
        // its levels, each in units of at most a quantum of its key bytes,
        // a comparison's last unit partial; one more per level.
        set(
            PreparationPlace::Comparisons,
            work(decode::comparison::COMPARE.covering(key_merges, add(merges, merge_levels)?)?),
        );
        // The merge scratch is truncated after each run and kept for the next
        // map's merge: publication retains none.
        let (scratch, scratch_growth) = arena(add(entries, 1)?, entry, false)?;
        set(PreparationPlace::Scratch, scratch);
        // Each nested map's order check: one unit per entry and one more.
        set(
            PreparationPlace::Check,
            work(dynamic::CHECK.times(add(entries, unordered)?)?),
        );
        // Each misordered map's permutation: an offset per entry, the bitmap
        // filled, per payload byte a cycle scan, a lookup among its own
        // entries and a move, then clearing, releases and completion.
        set(
            PreparationPlace::Permutation,
            work(
                WriteWork::checked_sequence(&[
                    permutation::OFFSET.times(add(entries, unordered)?)?,
                    permutation::FILL.covering(bitmap, add(mul(unordered, 2)?, bitmap_growths)?)?,
                    permutation::SCAN.times(add(
                        add(payloads.div_ceil(permutation::SCAN.cap()), payloads)?,
                        unordered,
                    )?)?,
                    permutation::LOOKUP.times(payload_probes)?,
                    permutation::MOVE.times(payloads)?,
                    step(unordered)?,
                    Storage::<u8, (), ()>::cleanup_work(true)?
                        .checked_times(unordered)
                        .ok_or_else(overflow)?,
                    permutation::PERMUTED.times(unordered)?,
                ])
                .ok_or_else(overflow)?,
            ),
        );
        // Each misordered map's permutation grows a bitmap of its own
        // payload's `b` bytes from empty, capped at `b`, and releases it
        // before the next map's: the capacities before each growth,
        // `4 + 8 + .. + c = 2c - 4` with `c < b`, are relocated one byte a
        // unit, under `2b`; the capacities requested, those and the last of
        // at most `b`, are under `3b`. Over the maps, the sum of their `b` is
        // at most `bitmap`. Each growth, at most `bitmap_growths` per map,
        // stages a block of at most a quantum, writes in its own units and
        // admits the releases of its two allocations. One bitmap is held at
        // a time, at most the largest map's, its block beside it.
        let visited = arena(add(largest, 1)?, 1, false)?.1.peak;
        let bitmap_grown = mul(unordered, bitmap_growths)?;
        let bitmap_work = WriteWork::checked_sequence(&[
            WriteWork::new(mul(bitmap, 2)?, mul(bitmap, 2)?),
            Storage::<u8, (), ()>::growth_work(bitmap_grown)?,
            RELEASED.times(mul(bitmap_grown, 2)?)?,
        ])
        .ok_or_else(overflow)?;
        // Its relocations, staging and releases, while one bitmap at a time
        // is held: the two concurrent, nothing retained.
        set(
            PreparationPlace::Visited,
            ResourceBound::of_work(bitmap_work)
                .checked_add(ResourceBound {
                    allocated: add(mul(bitmap, 3)?, mul(bitmap_grown, TURN.bytes)?)?,
                    peak: visited,
                    ..ResourceBound::default()
                })
                .ok_or_else(overflow)?,
        );
        // Each unordered map's completion: its descriptors truncated, its
        // ordering reset, its frames popped; and the preparation's.
        set(
            PreparationPlace::Completion,
            work(
                WriteWork::checked_sequence(&[
                    step(unordered)?,
                    maps::order::RESET.times(unordered)?,
                    dynamic::COMPLETE.times(unordered)?,
                    DONE.times(1)?,
                ])
                .ok_or_else(overflow)?,
            ),
        );
        // Cleanup ([`Preparation::reclaim_step`]): an interrupted text's
        // continuation's own cleanup, its arenas drained; each of the nine
        // arenas (frames, open maps, bytes, gaps, cursors, window parts,
        // entries, the ordering scratch and the bitmap)
        // truncated and cleaned up; the record's transition and the
        // completion. The window arena holds types that drop, so it is
        // drained one element per unit (`Storage::reclaim_step`) whatever
        // its stage: both parts charged whole. Every other arena is
        // plain data reclaimed by `Storage::reclaim_copy_step`: settled,
        // discarded in one unit; cancelled while relocating or relocated,
        // drained one element per unit. Of those and the text
        // continuation's two, at most one is ever relocating (the exclusion
        // the peak rests on, [`PreparationTerms`], checked at every boundary
        // of every attribution run), so cleanup drains at most one of them
        // one element per unit: charged at the most of any one arena's
        // elements, in values and in bytes apart. The text's own drain is
        // its interrupted cleanup's. The descriptors and the merge scratch
        // are both arenas of at most `entries + 1` descriptors, one entry
        // below. Every release, the copied encoding's and each arena
        // allocation's, was admitted by its acquisition.
        const ARENAS: u64 = 9;
        let window_drains = Storage::<WindowPart<O>, (), O>::element_work(window_parts)?;
        let drained = [
            Storage::<Frame<'static>, (), ()>::element_work(held)?,
            Storage::<MapFrame<'static>, (), ()>::element_work(held)?,
            Storage::<u8, (), ()>::element_work(add(appended, 1)?)?,
            Storage::<(usize, usize), (), ()>::element_work(add(maps, 1)?)?,
            Storage::<(Option<&'static dyn Entries>, Slot), (), ()>::element_work(held)?,
            Storage::<maps::order::Entry, (), ()>::element_work(add(entries, 1)?)?,
            Storage::<u8, (), ()>::element_work(add(largest, 1)?)?,
        ]
        .into_iter()
        // Whichever one arena drains: the alternative of them all.
        .fold(ResourceBound::default(), |most, arena| {
            most.larger(ResourceBound::of_work(arena))
        })
        .work();
        set(
            PreparationPlace::Cleanup,
            work(
                WriteWork::checked_sequence(&[
                    text_cursor::interrupted::<R>(longest_text)?,
                    window_drains,
                    drained,
                    step(ARENAS)?,
                    Storage::<u8, (), ()>::cleanup_work(true)?
                        .checked_times(ARENAS)
                        .ok_or_else(overflow)?,
                    PLAN_TRANSITION.times(1)?,
                    CLEANUP_DONE.times(1)?,
                ])
                .ok_or_else(overflow)?,
            ),
        );
        // The arenas the preparation keeps for its life: each grows to its
        // most and keeps that capacity until cleanup, which allocates nothing.
        let kept = [
            frames_growth,
            gaps_growth,
            open_maps_growth,
            cursors_growth,
            windows_growth,
            descriptors_growth,
            plan_growth,
            scratch_growth,
        ];
        let storage = |peak: u64| ResourceBound {
            peak,
            ..ResourceBound::default()
        };
        // Every kept arena held at once, one of them growing at a time.
        let growing = Growth::one_growing::<R>(&kept)?;
        let held_all = ResourceBound {
            peak: growing.retained,
            retained: growing.retained,
            ..ResourceBound::default()
        };
        // A text's normalized encoding, at most its parts' bytes behind
        // their head, copied into the plan while the plan relocates: the two
        // concurrent.
        let output = if texts == 0 {
            0
        } else {
            item_len(longest_text.part_bytes, longest_text.part_bytes)?
        };
        let copying = storage(output)
            .checked_add(storage(plan_growth.peak - plan_growth.held))
            .ok_or_else(overflow)?;
        // What one other phase adds beside the held arenas, whichever runs:
        // a text's normalization, an encoding copied in, or the bitmap.
        let phase = storage(normalization.peak)
            .larger(copying)
            .larger(storage(visited));
        let peak = held_all
            .checked_then(phase)
            .map(|beside| growing.larger(beside).peak)
            .ok_or_else(overflow)?;
        Ok(Self { terms, peak })
    }
}

impl Places for PreparationTerms {
    type Place = PreparationPlace;

    fn term(&self, place: PreparationPlace) -> ResourceBound {
        self.terms[place as usize]
    }

    /// Every kept arena at its held capacity, and the largest of what one
    /// phase adds beside them ([`PreparationTerms::peak`]).
    fn peak<R>(&self) -> Result<u64, BoundedError<R>> {
        Ok(self.peak)
    }
}

/// The [`ResourceBound`] of an [`OwnedPreparation`] of a published value of
/// `shape`: the plan's record, initialized field by field, the source handle
/// and phase first; the preparation and its cleanup ([`prepare_bound`]).
/// The source value is accounted by its decode. The plan is kept in place,
/// so retained storage is conservatively bounded by the preparation's peak.
/// This includes transient overlap that need not remain at publication; it is
/// not an exact retained-storage measurement. The record's size and
/// initialization do not depend on its scope.
pub fn owned_prepare_bound<I, T, A, R>(shape: Shape) -> Result<ResourceBound, BoundedError<R>>
where
    I: DecodeInput<A>,
    T: InPlace<A>,
    A: Allocator,
{
    owned_prepare_terms::<I, T, A, R>(shape)?.bound()
}

/// The terms of an owned preparation ([`owned_prepare_bound`]): its
/// operation's, whose task is the preparation, every arena it holds at its
/// peak kept in place as what publication retains.
pub(crate) fn owned_prepare_terms<I, T, A, R>(
    shape: Shape,
) -> Result<OperationTerms, BoundedError<R>>
where
    I: DecodeInput<A>,
    T: InPlace<A>,
    A: Allocator,
{
    let preparation = prepare_bound::<A::Permit, A::Origin, R>(shape)?;
    // The plan kept in place: conservatively, everything held at the
    // preparation's peak kept after it.
    let task = preparation
        .checked_followed_by(ResourceBound {
            peak: preparation.peak,
            retained: preparation.peak,
            ..ResourceBound::default()
        })
        .ok_or(BoundedError::Overflow)?;
    OperationTerms::of::<Planned<'static, I, T, A>, A, R>(
        Planned::<'static, I, T, A>::INIT_STEPS,
        task,
    )
}

/// This preparation's custody ([`CustodySink`]): its own group, under the
/// owner its bucket windows are acquisitions of (`None` until its first
/// window makes it), holding each open window's acquisition bound
/// ([`window_bindings`]) and its obligation ([`window_obligations`]); inside
/// it, each independently owning component's group, in field order: its six
/// arenas ([`Storage::observe_custody`]), its dynamic engine's three, its
/// text continuation's ([`TextContinuation::observe_custody`]), and, while
/// it is held, the copied normalized encoding's permit under the owner whose
/// acquisition granted it ([`Encoded::owner`]). Read-only and
/// allocation-free; it admits, mints, publishes and settles nothing.
impl<P, O: Origin> Custodial<P> for Preparation<'_, P, O> {
    fn observe_custody(&mut self, sink: &mut dyn CustodySink<P>) -> PermitsObserved {
        sink.begin(self.owner_id());
        window_bindings(&self.windows, sink);
        window_obligations(&self.windows, sink);
        let mut parts = observed_all([
            self.frames.observe_custody(sink),
            self.bytes.observe_custody(sink),
            self.holes.observe_custody(sink),
            self.map_frames.observe_custody(sink),
            self.cursors.observe_custody(sink),
            self.windows.observe_custody(sink),
            self.dynamic.observe_custody(sink),
            // A continuation not present holds nothing: destroyed once it
            // published, or a partial prefix of no owned field.
            self.text_mut()
                .map_or(PermitsObserved::Complete, |text| text.observe_custody(sink)),
        ]);
        if let Some(normalized) = &mut self.normalized {
            parts = observed_all([parts, normalized.observe_custody(sink)]);
        }
        sink.end();
        parts
    }
}

/// The initialized text continuation must be destroyed explicitly because its
/// `MaybeUninit` field has no drop glue. Its arenas release prepaid storage
/// and its pending acquisitions settle their retained obligations.
impl<P, O: Origin> Drop for Preparation<'_, P, O> {
    /// A preparation dropped with a window open is its windows' destruction:
    /// each window's credit forfeited and its acquisition ended, with no
    /// policy performing it ([`forfeit_windows`]), before the arenas drop.
    fn drop(&mut self) {
        let malformed = windows_malformed(&self.windows, self.cursors.len());
        forfeit_windows(&mut self.windows, Performer::None, Forfeit::Cancelled);
        if malformed {
            invalidate_windows(&self.owner);
        }
        self.retire_text();
    }
}

impl<'a, P, O: Origin, A: Allocator<Permit = P, Origin = O>> Resumable<A>
    for Preparation<'a, P, O>
{
    type Output = Prepared<P>;
    type Error = BoundedError<A::Refusal>;
    type Position = Position;

    fn step(&mut self, a: &mut A) -> BoundedResult<Step<Prepared<P>>, A> {
        Preparation::step(self, a)
    }

    fn position(&mut self) -> Position {
        Preparation::position(self)
    }
}

/// Flat prepared bytes and header-gap metadata, each with its storage permit.
///
/// The plan outlives the preparation that produced it, so each arena carries
/// the identity of the owner whose acquisition granted its permit: the plan
/// bytes and the header gaps were separate arenas of the preparation, each
/// with its own pending custody and so its own owner. Fixed at publication
/// from those custodies' stored owners, never changed, `None` exactly when
/// the arena never allocated; observational identity only (no capability,
/// no settlement authority).
pub struct Prepared<P> {
    bytes: Owned<u8, P>,
    holes: Owned<(usize, usize), P>,
    len: usize,
    bytes_owner: Option<Identity>,
    holes_owner: Option<Identity>,
}

/// The plan's custody ([`CustodySink`]): the plan bytes' permit under the
/// owner whose acquisition granted it, then the header gaps' under theirs,
/// each its own group; an arena that never allocated reports nothing. The
/// plan owns no shared queue, so the observation is whole. The traversal
/// reads the plan only, so it is defined on a shared borrow: a plan lent to
/// its [`Writer`] is observed by its owner through the borrow the writer
/// shares.
impl<P> Custodial<P> for &Prepared<P> {
    fn observe_custody(&mut self, sink: &mut dyn CustodySink<P>) -> PermitsObserved {
        if let Some(permit) = self.bytes.permit() {
            sink.begin(self.bytes_owner);
            sink.permit(permit, None);
            sink.end();
        }
        if let Some(permit) = self.holes.permit() {
            sink.begin(self.holes_owner);
            sink.permit(permit, None);
            sink.end();
        }
        PermitsObserved::Complete
    }
}

/// An owned plan's custody: its shared borrow's traversal.
impl<P> Custodial<P> for Prepared<P> {
    fn observe_custody(&mut self, sink: &mut dyn CustodySink<P>) -> PermitsObserved {
        <&Self as Custodial<P>>::observe_custody(&mut &*self, sink)
    }
}

/// A write's custody: none. It admits each unit as it writes it; the plan it
/// borrows is its owner's to report, through the shared borrow
/// ([`Prepared`]'s traversal), and the destination is the caller's memory.
impl<P> Custodial<P> for Writer<'_, '_, P> {
    fn observe_custody(&mut self, _: &mut dyn CustodySink<P>) -> PermitsObserved {
        PermitsObserved::Complete
    }
}

impl<P> Prepared<P> {
    /// The owner whose acquisition granted the plan bytes' permit, `None`
    /// when the plan holds no bytes allocation: what the published encoding
    /// the bytes move into carries ([`Encoded::owner`]).
    pub(crate) fn owner(&self) -> Option<Identity> {
        self.bytes_owner
    }

    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn writer<'p, 'o>(&'p self, output: &'o mut [u8]) -> Writer<'p, 'o, P> {
        Writer {
            plan: self,
            output,
            at: EmitPosition::default(),
        }
    }

    fn view(&self) -> PlanView<'_> {
        PlanView {
            bytes: self.bytes.as_slice(),
            holes: self.holes.as_slice(),
            len: self.len,
        }
    }

    /// Consume the completed plan into cleanup-only custody. Retirement itself
    /// neither allocates nor releases storage. Emission is no longer available.
    ///
    /// ```compile_fail,E0382
    /// use dcbor::bounded::encoding::Prepared;
    /// fn retired(plan: Prepared<()>, output: &mut [u8]) {
    ///     let cleanup = plan.retire();
    ///     let writer = plan.writer(output);
    /// }
    /// ```
    pub fn retire(self) -> RetiringPrepared<P> {
        RetiringPrepared { plan: self }
    }
}

/// Cleanup-only custody of a retired encoding. This type exposes no plan view,
/// writer, or conversion back to a completed plan.
///
/// ```compile_fail,E0599
/// use dcbor::bounded::encoding::Prepared;
/// fn emit_after_retirement(plan: Prepared<()>, bytes: &mut [u8]) {
///     let retired = plan.retire();
///     retired.writer(bytes);
/// }
/// ```
pub struct RetiringPrepared<P> {
    plan: Prepared<P>,
}

impl<P> RetiringPrepared<P> {
    /// Release one of the plan's allocations and its permit, a release its
    /// growth paid for; once none is held, the call admits the completion it
    /// reports as `Done`.
    pub fn reclaim_step<B: Budget>(&mut self, b: &mut B) -> BoundedResult<Reclaimed, B> {
        if self.plan.bytes.release() || self.plan.holes.release() {
            return Ok(Reclaimed::Progress);
        }
        CLEANUP_DONE.admit(b)?;
        Ok(Reclaimed::Done)
    }
}

/// Retains the plan borrow and exclusive destination borrow across suspension.
///
/// ```compile_fail,E0515
/// use dcbor::bounded::encoding::{Prepared, Writer};
/// fn escape<'a>(plan: Prepared<()>, output: &'a mut [u8]) -> Writer<'a, 'a, ()> {
///     plan.writer(output)
/// }
/// ```
///
/// ```compile_fail,E0506
/// use dcbor::bounded::encoding::Prepared;
/// fn overwrite(plan: &Prepared<()>, output: &mut [u8]) {
///     let writer = plan.writer(output);
///     output[0] = 0;
///     drop(writer);
/// }
/// ```
pub struct Writer<'p, 'o, P> {
    plan: &'p Prepared<P>,
    output: &'o mut [u8],
    at: EmitPosition,
}

/// Where an owned preparation is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlanPhase {
    Prepare,
    Published,
    ReclaimPreparation,
    ReclaimSource,
    Done,
}

/// The record of an owned preparation: the published value it encodes, held
/// in custody until the record is reclaimed, and the preparation over that
/// value, whose arenas hold the plan in place once it completes. Public only
/// as the unnameable state of [`OwnedPreparation`].
pub struct Planned<'s, I: DecodeInput<A>, T: InPlace<A>, A: Allocator> {
    source: Option<TypedValue<'s, I, T, A>>,
    phase: PlanPhase,
    /// Initialized by the record's prefix and held while
    /// [`holds_preparation`]; dropped in place once its cleanup reports
    /// `Done`, since the record's block runs no destructor and each of its
    /// arenas keeps a pending whose owner holds its session's store.
    preparation: MaybeUninit<Preparation<'s, A::Permit, A::Origin>>,
}

/// Whether the plan record still holds its preparation in `phase`: from the
/// end of `ReclaimPreparation` on, its drained preparation has been dropped
/// in place (`Planned`'s `reclaim_step`), so its arenas' and its own owners
/// have released their session references, and nothing reads it again.
const fn holds_preparation(phase: PlanPhase) -> bool {
    !matches!(phase, PlanPhase::ReclaimSource | PlanPhase::Done)
}

// SAFETY: TransferableSchema covers every retained descendant reference and
// cursor, not only the root's Sync bound. This record retains source custody
// until preparation cleanup finishes. The arenas and permits are Send, and the
// source handle is Send because its value and the value's construction state
// are.
unsafe impl<'s, I, T, A> Send for Planned<'s, I, T, A>
where
    I: DecodeInput<A>,
    T: Transferable<A> + TransferableSchema,
    A: Allocator,
    A::Permit: Send,
{
}

impl<'s, I: DecodeInput<A>, T: InPlace<A>, A: Allocator> Planned<'s, I, T, A> {
    const INIT_STEPS: usize = 2 + Preparation::<'s, A::Permit, A::Origin>::INIT_STEPS;

    /// The record's whole custody, for as long as the slot is borrowed:
    /// every field of the record is its own custody (the source handle, the
    /// phase, the preparation); the source value lives in its own record,
    /// behind the handle. Refused unless the slot's progress records every
    /// field initialized.
    fn custody<'p, M: reclamation::Mode, R>(
        slot: &'p mut reclamation::Slot<'_, Self, Prefix, M>,
    ) -> Result<&'p mut Self, BoundedError<R>> {
        let (place, prefix) = slot.parts();
        if prefix.initialized() < Self::INIT_STEPS {
            return Err(BoundedError::PlanMismatch);
        }
        // SAFETY: the slot pairs the record's place with its progress, which
        // records every field initialized; the whole record is custody, no
        // place lies within it, and the source value it holds lies in its own
        // record.
        Ok(unsafe { place.custody(prefix, |record| record) })
    }

    /// The source slot alone, for as long as the slot is borrowed: what the
    /// record holds before its other fields are initialized; `None` before
    /// the source field is.
    fn source<'p, M: reclamation::Mode>(
        slot: &'p mut reclamation::Slot<'_, Self, Prefix, M>,
    ) -> Option<&'p mut Option<TypedValue<'s, I, T, A>>> {
        let (place, prefix) = slot.parts();
        if prefix.initialized() == 0 {
            return None;
        }
        // SAFETY: the slot pairs the record's place with its progress, which
        // records the source field initialized; the projection reaches that
        // field alone.
        Some(unsafe { place.custody(prefix, |record| addr_of_mut!((*record).source)) })
    }

    /// The preparation, while the record holds it ([`holds_preparation`]);
    /// `None` once its drained preparation was dropped in place. A record is
    /// reached whole only once its prefix is complete: through
    /// [`Self::custody`], a shared view taken after the same check
    /// ([`Prepare`]'s `detail`), or a published record's handle.
    fn preparation(&self) -> Option<&Preparation<'s, A::Permit, A::Origin>> {
        // SAFETY: a record reached whole has its complete prefix, the
        // preparation's included, and the preparation is held in this phase.
        holds_preparation(self.phase).then(|| unsafe { self.preparation.assume_init_ref() })
    }

    /// [`Self::preparation`], exclusively: how the record's custody
    /// traversal walks the preparation it holds.
    fn preparation_mut(&mut self) -> Option<&mut Preparation<'s, A::Permit, A::Origin>> {
        // SAFETY: as [`Self::preparation`]; the record is borrowed
        // exclusively.
        holds_preparation(self.phase).then(|| unsafe { self.preparation.assume_init_mut() })
    }

    /// The plan of a published record.
    fn plan(&self) -> PlanView<'_> {
        match self.preparation().and_then(Preparation::view) {
            Some(view) => view,
            None => unreachable!("a published plan is complete in place"),
        }
    }
}

// SAFETY: initial: `Prefix::EMPTY`, no prefix unit initialized. state: the
// prefix is the source handle and the phase, then the preparation's
// resource-free prefix, which needs no cleanup; the preparation's own arenas
// record what it acquired. admission: each cleanup unit, the record's and the
// preparation's (`Preparation::reclaim_step`), is admitted before it runs, a
// refusal changing nothing. cleanup: it releases the preparation's arenas,
// drops the drained preparation in place, which releases its arenas' and its
// own owner capabilities, then releases the source value, in place; no
// arbitrary destructor runs, nothing is allocated and nothing unwinds. done:
// `Done` once the arenas, the preparation's capabilities and the source are
// released, an incomplete prefix's release leaving it released
// (`Prefix::release`); the preparation's `Done` drops every borrow of the
// source it still holds (`Preparation::release_source`). order: a step after
// `Done` reports `Done`, admitting nothing, from `PlanPhase::Done` or a
// released prefix alike; from `ReclaimSource` on nothing reads the dropped
// preparation (`holds_preparation`), an observation of the record reads no
// reference into the value being released, and the count reads only the
// recorded prefix, nothing of a released one. depth: the source handle's
// plus one.
// count: the preparation's remaining and the source's, composed checked.
unsafe impl<'s, I: DecodeInput<A>, T: InPlace<A>, A: Allocator> Reclaim<A>
    for Planned<'s, I, T, A>
{
    const DISPATCH_DEPTH: usize = TypedValue::<'s, I, T, A>::DISPATCH_DEPTH.saturating_add(1);
    type State = Prefix;
    const INITIAL: Prefix = Prefix::EMPTY;

    fn reclaim_step(
        mut slot: reclamation::Slot<'_, Self, Prefix>,
        cleanup: &mut Cleanup<'_, A>,
    ) -> BoundedResult<Reclaimed, A> {
        // Released: terminal, `Done` admitting nothing.
        if slot.custody().released() {
            return Ok(Reclaimed::Done);
        }
        let initialized = slot.custody().initialized();
        if Bound::new(Predicate::Prefix, Self::INIT_STEPS).below(cleanup, initialized) {
            if let Some(source) = Self::source(&mut slot)
                && source.is_some()
            {
                TypedValue::reclaim_under(source, cleanup)?;
                return Ok(Reclaimed::Progress);
            }
            PLAN_TRANSITION.admit(cleanup)?;
            slot.custody().release();
            return Ok(Reclaimed::Done);
        }
        let Planned {
            source,
            phase,
            preparation,
        } = Self::custody(&mut slot)?;
        match *phase {
            PlanPhase::ReclaimPreparation => {
                // SAFETY: the prefix is complete, and the preparation is held
                // until this phase ends (`holds_preparation`).
                let reclaimed = unsafe { preparation.assume_init_mut() }.reclaim_step(cleanup)?;
                if reclaimed == Reclaimed::Done {
                    // The drained preparation dropped in place: the record's
                    // block runs no destructor, and each of its arenas keeps
                    // a pending whose owner holds its session's store until
                    // it drops. Drained, its arenas hold no allocation and
                    // their pendings no credit, its windows are settled, its
                    // copied encoding is released and its text continuation
                    // is finished, so the drop frees nothing, records
                    // nothing, allocates nothing and does not unwind
                    // (`Storage`'s `Drop`).
                    // SAFETY: the preparation is initialized and held in this
                    // phase; the phase moves past it below, and no later
                    // step, count, observation or detail reads it.
                    unsafe { preparation.assume_init_drop() };
                    *phase = PlanPhase::ReclaimSource;
                }
            }
            PlanPhase::ReclaimSource => {
                if TypedValue::reclaim_under(source, cleanup)? == Reclaimed::Done {
                    *phase = PlanPhase::Done;
                    return Ok(Reclaimed::Done);
                }
            }
            PlanPhase::Done => return Ok(Reclaimed::Done),
            PlanPhase::Prepare | PlanPhase::Published => {
                PLAN_TRANSITION.admit(cleanup)?;
                *phase = PlanPhase::ReclaimPreparation;
            }
        }
        Ok(Reclaimed::Progress)
    }

    /// Before initialization completes, the held source's own calls, then the
    /// one releasing the record. After it: the transition into cleanup
    /// unless it has begun, the preparation's own count and the source
    /// slot's.
    fn remaining(mut slot: PeekSlot<'_, Self, Prefix>) -> Option<u64> {
        // Released: the one call reporting `Done`.
        if slot.custody().released() {
            return Some(1);
        }
        if slot.custody().initialized() < Self::INIT_STEPS {
            return match Self::source(&mut slot) {
                Some(source) if source.is_some() => TypedValue::remaining(source)?.checked_add(1),
                _ => Some(1),
            };
        }
        // The source value lives in its own record, behind the handle, and
        // is reached only through that record's count.
        let Ok(Planned {
            source,
            phase,
            preparation,
        }) = Self::custody::<_, ()>(&mut slot)
        else {
            return Some(1);
        };
        let phase = *phase;
        let source = TypedValue::remaining(source)?;
        // The preparation is read only while it is held (`holds_preparation`).
        match phase {
            PlanPhase::Done => return Some(1),
            PlanPhase::ReclaimSource => return Some(source),
            PlanPhase::Prepare | PlanPhase::Published | PlanPhase::ReclaimPreparation => {}
        }
        // SAFETY: a complete prefix includes the preparation's, held in this
        // phase.
        let preparation = unsafe { preparation.assume_init_ref() }
            .reclaim_remaining()?
            .checked_add(source)?;
        match phase {
            PlanPhase::ReclaimPreparation => Some(preparation),
            _ => preparation.checked_add(1),
        }
    }

    /// The record's value's custody, as child groups of the group its
    /// holder has open ([`CustodySink`]): the source value's, behind its
    /// handle once the record holds it, under the owner its own record
    /// carries (its [`Custodial`] traversal); and, once initialization
    /// completes and while the record holds it ([`holds_preparation`]), the
    /// preparation's (its [`Custodial`] traversal). The preparation's
    /// prefix before that is resource-free, so it owns nothing; once dropped
    /// it holds nothing. Read-only; whole exactly when every part's
    /// observation is.
    fn observe_permits(
        mut slot: PeekSlot<'_, Self, Prefix>,
        sink: &mut dyn CustodySink<A::Permit>,
    ) -> PermitsObserved {
        // Released: nothing held, nothing read.
        if slot.custody().released() {
            return PermitsObserved::Complete;
        }
        if slot.custody().initialized() < Self::INIT_STEPS {
            return match Self::source(&mut slot) {
                Some(Some(source)) => source.observe_custody(sink),
                _ => PermitsObserved::Complete,
            };
        }
        let Ok(planned) = Self::custody::<_, ()>(&mut slot) else {
            return PermitsObserved::Complete;
        };
        let source = match &mut planned.source {
            Some(source) => source.observe_custody(sink),
            None => PermitsObserved::Complete,
        };
        match planned.preparation_mut() {
            Some(preparation) => observed_all([source, preparation.observe_custody(sink)]),
            // The preparation dropped once drained: only the source remains.
            None => source,
        }
    }
}

/// Observation of an owned preparation: the record's phase, its
/// preparation's position, and whether the record, or before the record
/// holds it the task, holds the source value, which cleanup reclaims last.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlanDetail {
    pub phase: Option<PlanPhase>,
    pub preparation: Option<Position>,
    pub source: bool,
}

/// The owned preparation task. Public only as the unnameable task of
/// [`OwnedPreparation`].
pub struct Prepare<'s, I: DecodeInput<A>, T: InPlace<A>, A: Allocator> {
    source: Option<TypedValue<'s, I, T, A>>,
}

// SAFETY: prefix: initialization moves the source handle in, writes the
// phase, then the preparation's resource-free prefix over a borrow of the
// source value, whose record this one holds until the preparation is
// reclaimed, one unit each, recorded as it is written; every prefix is
// reclaimable by `Planned`'s cleanup, and past `INIT_STEPS`, or once
// released, it refuses, changing nothing. advance: refused until the prefix
// is whole, a released prefix recording none, and outside `Prepare` before
// the preparation is borrowed; every later
// unit keeps the record reclaimable, and completion is reported only once
// the plan is complete. detail: `detail` and `observe_custody` read only the
// recorded prefix and the preparation's position, changing, admitting and
// allocating nothing. provenance: every field is reached through the
// record's slot place, by raw projection.
unsafe impl<'s, I, T, A> Task<'s, A> for Prepare<'s, I, T, A>
where
    I: DecodeInput<A> + 's,
    T: Transferable<A> + TransferableSchema + 's,
    A: Allocator + 's,
    A::Permit: Send,
{
    type State = Planned<'s, I, T, A>;
    type Output = OwnedPrepared<'s, I, T, A>;
    type Error = BoundedError<A::Refusal>;
    type Detail = PlanDetail;
    const INIT_STEPS: usize = Planned::<'s, I, T, A>::INIT_STEPS;

    fn scope(&self) -> Option<&ScopeRef<'s, A>> {
        self.source.as_ref().map(TypedValue::scope)
    }

    fn initialized(prefix: &Prefix) -> usize {
        prefix.initialized()
    }

    fn initialize(
        &mut self,
        mut slot: reclamation::Slot<'_, Self::State, Prefix>,
        a: &mut A,
    ) -> Result<(), Self::Error> {
        let (place, prefix) = slot.parts();
        // A released record is terminal: nothing is written again.
        if prefix.released()
            || Bound::new(Predicate::Prefix, Self::INIT_STEPS).reached(a, prefix.initialized())
        {
            return Err(BoundedError::PlanMismatch);
        }
        let raw = place.as_ptr(prefix);
        match prefix.initialized() {
            // SAFETY: the slot pairs the record's place with its progress,
            // so the field the progress names next is a field of the
            // record's valid destination, reached by field syntax.
            0 => unsafe { field(addr_of_mut!((*raw).source), || self.source.take(), a)? },
            // SAFETY: as above.
            1 => unsafe { field(addr_of_mut!((*raw).phase), || PlanPhase::Prepare, a)? },
            n => {
                // SAFETY: a progress past its first unit records the source
                // field initialized, read through a shared view of it alone.
                // The value lives at a stable address in its own record,
                // which this record holds until the preparation is
                // reclaimed; the borrow never outlives that.
                let source: &'s dyn Schema = unsafe {
                    let source = (*addr_of!((*raw).source))
                        .as_ref()
                        .ok_or(BoundedError::PlanMismatch)?
                        .value();
                    &*(source as *const T)
                };
                let mut units = n - 2;
                // SAFETY: the preparation's place is a field of the record's
                // destination, by field syntax, `MaybeUninit` laying out its
                // value at its start; its units are its own: the record's
                // units are initialized in order, so its progress less the
                // two fields before it is what the preparation holds.
                let preparation = unsafe {
                    reclamation::Slot::new(
                        place.project(|record| {
                            addr_of_mut!((*record).preparation)
                                .cast::<Preparation<'s, A::Permit, A::Origin>>()
                        }),
                        &mut units,
                    )
                };
                Preparation::initialize_step(preparation, source, a)?;
                prefix.set(units + 2);
                return Ok(());
            }
        }
        prefix.advance();
        Ok(())
    }

    /// The record keeps its own pending custodies, one per arena of its
    /// preparation, each under its own stored owner, and the preparation's
    /// windows under its own: the operation's acquisition custody is left
    /// idle ([`Task::advance`]).
    fn advance(
        &mut self,
        mut slot: reclamation::Slot<'_, Self::State, Prefix>,
        _: &mut decode::construction::stable::Pending<A::Origin>,
        a: &mut A,
    ) -> Result<bool, Self::Error> {
        // The custody is refused until initialization is complete.
        let Planned {
            phase, preparation, ..
        } = Planned::custody(&mut slot)?;
        if *phase != PlanPhase::Prepare {
            return Err(BoundedError::PlanMismatch);
        }
        // SAFETY: the custody's prefix is complete, the preparation's
        // included, and `Prepare` holds it (`holds_preparation`).
        let preparation = unsafe { preparation.assume_init_mut() };
        if preparation.prepare_step::<Kept, A>(a)?.is_some() {
            *phase = PlanPhase::Published;
            return Ok(true);
        }
        Ok(false)
    }

    fn publish(&mut self, record: OwnedInitialized<'s, Self::State, A>) -> Self::Output {
        OwnedPrepared { record }
    }

    fn reclaim_step(&mut self, cleanup: &mut Cleanup<'_, A>) -> BoundedResult<Reclaimed, A> {
        TypedValue::reclaim_under(&mut self.source, cleanup)
    }

    /// The task holds no pending credit of its own: every acquisition the
    /// preparation makes is held in its arenas' and its text continuation's
    /// custody inside the record, settled by their own cleanup entry
    /// (`Storage::reclaim_step`, `TextContinuation::reclaim_step`); the
    /// source handle outside the record holds a published value, no
    /// acquisition. Nothing to settle.
    fn settle(&mut self, _: Performer) {}

    fn detail(&self, record: Observed<'_, 's, Self, A>) -> PlanDetail {
        // Before the record is complete only whether the source is held is
        // known: the record takes it with its first prefix unit; before that,
        // and when no record exists, the task holds it.
        let incomplete = |source| PlanDetail {
            phase: None,
            preparation: None,
            source,
        };
        let Some(mut slot) = record else {
            return incomplete(self.source.is_some());
        };
        let (place, prefix) = slot.parts();
        let initialized = prefix.initialized();
        if initialized < Self::INIT_STEPS {
            return incomplete(if initialized > 0 {
                // SAFETY: a nonempty prefix includes the source field, read
                // through a view of that field alone.
                unsafe {
                    place
                        .project(|record| addr_of_mut!((*record).source))
                        .get(&*prefix)
                        .is_some()
                }
            } else {
                self.source.is_some()
            });
        }
        // SAFETY: a complete prefix initializes the source, the phase and the
        // preparation's resource-free prefix, read through one shared view of
        // the record; the preparation is read only while it is held.
        let planned = unsafe { place.get(&*prefix) };
        PlanDetail {
            phase: Some(planned.phase),
            preparation: planned.preparation().map(Preparation::position),
            source: planned.source.is_some(),
        }
    }

    /// The task's custody outside its record, as a child group of the
    /// operation's ([`CustodySink`]): the source value while the task, not
    /// yet its record, holds it, under the owner its own record carries
    /// (its [`Custodial`] traversal). The task holds no credit of its
    /// own ([`Self::settle`]) and binds no acquisitions. Everything inside
    /// the record (the source once moved in, and the preparation with its
    /// arenas, windows and text) is the record's to report, once, through
    /// [`Planned`]'s [`Reclaim::observe_permits`], so the record is not read
    /// here.
    fn observe_custody(
        &mut self,
        _: Observed<'_, 's, Self, A>,
        sink: &mut dyn CustodySink<A::Permit>,
    ) -> PermitsObserved {
        match &mut self.source {
            Some(source) => source.observe_custody(sink),
            None => PermitsObserved::Complete,
        }
    }
}

/// Owned preparation of a published value's canonical encoding. The value is
/// moved into the plan's record and held until the plan is retired, so a
/// retained operation and its plan borrow nothing from the caller.
pub type OwnedPreparation<'s, I, T, A> = Operation<'s, Prepare<'s, I, T, A>, A>;

impl<'s, I, T, A> OwnedPreparation<'s, I, T, A>
where
    I: DecodeInput<A> + 's,
    T: Transferable<A> + TransferableSchema + 's,
    A: crate::bounded::TerminalAllocator + 's,
    A::Permit: Send,
{
    /// Prepare `value`'s encoding. Construction allocates nothing.
    pub fn prepare(value: TypedValue<'s, I, T, A>) -> Self {
        Operation::new(Prepare {
            source: Some(value),
        })
    }
}

/// A published owned plan. Moving the handle never moves the plan; dropping
/// it, on any thread, retires the record, source value included, to the scope
/// queue.
pub struct OwnedPrepared<'s, I: DecodeInput<A>, T: InPlace<A>, A: Allocator> {
    record: OwnedInitialized<'s, Planned<'s, I, T, A>, A>,
}

impl<'s, I: DecodeInput<A>, T: InPlace<A>, A: Allocator> OwnedPrepared<'s, I, T, A> {
    /// The exact encoded length.
    pub fn len(&self) -> usize {
        self.record.value().plan().len
    }

    /// Whether the encoding has no bytes; every valid CBOR item has a head.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The value the plan encodes.
    pub fn value(&self) -> &T {
        match self.record.value().source.as_ref() {
            Some(source) => source.value(),
            None => unreachable!("a published plan retains its source"),
        }
    }

    /// Emit the plan in chunks borrowed from it, consuming the handle.
    pub fn into_writer(self) -> OwnedWriter<'s, I, T, A> {
        OwnedWriter::new(self.record)
    }

    /// Operation-local cleanup of this plan and its source value, the
    /// cleanup capability minted here over `a`.
    pub fn reclaim_step(slot: &mut Option<Self>, a: &mut A) -> BoundedResult<Reclaimed, A> {
        reclamation::with_cleanup(a, |cleanup| {
            reclamation::reclaim_within(
                slot,
                cleanup,
                |plan| plan.record,
                |record| Self { record },
                OwnedInitialized::reclaim_under,
            )
        })
    }
}

/// The plan's custody: its record's group, under the owner of the
/// acquisition that allocated it, with the source value and, while the
/// record holds it, the preparation inside ([`Planned`]'s
/// [`Reclaim::observe_permits`]), the completeness returned whole.
/// `&mut self` excludes every reader of the plan meanwhile. Read-only.
impl<I: DecodeInput<A>, T: InPlace<A>, A: Allocator> Custodial<A::Permit>
    for OwnedPrepared<'_, I, T, A>
{
    fn observe_custody(&mut self, sink: &mut dyn CustodySink<A::Permit>) -> PermitsObserved {
        self.record.observe_custody(sink)
    }
}

#[cfg(test)]
mod bound_tests {
    use super::*;
    use crate::bounded::{Call, Capacity, Family, Limits, Reservation, Session, within};
    use core::ops::ControlFlow;
    #[cfg(feature = "hashbrown")]
    use dcbor_record::capabilities::Capability;
    use dcbor_record::capabilities::Requirement;

    #[test]
    fn window_pair_rejects_missing_reversed_and_overflowing_parts() {
        let mut pair: [WindowPart<()>; 2] =
            [WindowPart::Acquisition(None), WindowPart::Credit(None)];
        let (credit, acquisition) = window_pair::<_, ()>(&mut pair, 0).unwrap();
        assert!(credit.is_none() && acquisition.is_none());
        assert!(matches!(
            window_pair::<_, ()>(&mut pair[..1], 0),
            Err(BoundedError::PlanMismatch)
        ));
        assert!(matches!(
            window_pair::<_, ()>(&mut pair, 1),
            Err(BoundedError::PlanMismatch)
        ));
        assert!(matches!(
            window_pair::<_, ()>(&mut pair, usize::MAX),
            Err(BoundedError::Overflow)
        ));
        pair.swap(0, 1);
        assert!(matches!(
            window_pair::<_, ()>(&mut pair, 0),
            Err(BoundedError::PlanMismatch)
        ));
    }

    #[test]
    fn malformed_window_destruction_invalidates_its_owners_session() {
        let session = Session::new(Capacity {
            permits: 8,
            events: 128,
        });
        let mut policy = Limits::recorded_unlimited(&session);
        let source = 0u64;
        let mut preparation = Preparation::<Reservation, Family>::new(&source);
        let owner = policy.owner().unwrap();
        let acquisition = policy.acquisition(&owner).unwrap();
        preparation.owner = decode::construction::stable::OwnerState::Initialized(owner);
        let bound = prepare_bound::<Reservation, Family, ()>(
            Shape::of(&source, &mut Limits::unlimited()).unwrap(),
        )
        .unwrap();
        let mut acquisition = Some(acquisition);
        within("malformed window allocation", bound, || {
            match preparation
                .windows
                .reserve_step(WINDOW_PART_MAXIMUM, &mut policy)
                .unwrap()
            {
                Some(spare) => {
                    // A live acquisition with its credit part missing.
                    spare.push(WindowPart::Acquisition(acquisition.take()));
                    ControlFlow::Break(())
                }
                None => ControlFlow::Continue(()),
            }
        });
        drop(preparation);
        assert_eq!(policy.live_bytes(), 0, "malformed custody leaked its arena");
        assert_eq!(session.invalidation(), Some(Invalidation::MalformedWindow));
        drop(policy);
        assert_eq!(session.finish(), Err(Incomplete::Exhausted));
    }

    /// Malformed window custody found after a terminal error (the
    /// preparation finished, its cleanup not begun) is still closed and
    /// still invalidates the session: the terminal check follows the live
    /// capabilities ([`windows_malformed`]), not whether the preparation
    /// ended. Planted control: gate the check on the preparation still
    /// running and this witness reports no invalidation.
    #[test]
    fn malformed_custody_after_a_terminal_error_still_invalidates() {
        let session = Session::new(Capacity {
            permits: 8,
            events: 128,
        });
        let mut policy = Limits::recorded_unlimited(&session);
        let source = 0u64;
        let mut preparation = Preparation::<Reservation, Family>::new(&source);
        let owner = policy.owner().unwrap();
        let acquisition = policy.acquisition(&owner).unwrap();
        preparation.owner = decode::construction::stable::OwnerState::Initialized(owner);
        let bound = prepare_bound::<Reservation, Family, ()>(
            Shape::of(&source, &mut Limits::unlimited()).unwrap(),
        )
        .unwrap();
        let mut acquisition = Some(acquisition);
        within(
            "malformed window after a terminal error",
            bound,
            || match preparation
                .windows
                .reserve_step(WINDOW_PART_MAXIMUM, &mut policy)
                .unwrap()
            {
                Some(spare) => {
                    spare.push(WindowPart::Acquisition(acquisition.take()));
                    ControlFlow::Break(())
                }
                None => ControlFlow::Continue(()),
            },
        );
        // As a terminal error leaves it: failed, cleanup not begun.
        preparation.end = End::Failed;
        let mut cleanup = Limits::unlimited();
        let _ = preparation.reclaim_step(&mut cleanup);
        assert_eq!(
            session.invalidation(),
            Some(Invalidation::MalformedWindow),
            "malformed custody after a terminal error was not invalidated"
        );
        // Closed at cleanup entry: no capability left for destruction.
        assert!(!windows_hold_capability(&preparation.windows));
        drop(preparation);
        drop(policy);
        assert_eq!(session.finish(), Err(Incomplete::Exhausted));
    }

    /// A well-formed preparation holding open entry cursors, cancelled and
    /// cleaned up to completion: no unit of its cleanup (the cursor arena
    /// cleared while the window arena still holds its empty parts, the
    /// window arena drained one part at a time) is taken for malformed
    /// custody, and the session stays evidence.
    #[test]
    fn partial_cleanup_raises_no_false_malformation() {
        let session = Session::new(Capacity {
            permits: 64,
            events: 4096,
        });
        let mut policy = Limits::recorded_unlimited(&session);
        // Nested maps: while an inner map's entry cursor is open, its
        // parent's is too, so two cursors (four parts) are held at a time.
        let mut source = crate::bounded::BTreeMap::new();
        for key in 0..8u64 {
            source.insert(key, crate::bounded::BTreeMap::from([(key, key)]));
        }
        let mut preparation = Preparation::<Reservation, Family>::new(&source);
        // Step until an entry cursor is open, then cancel.
        let mut opened = false;
        for _ in 0..10_000 {
            if preparation.cursors.len() > 1 {
                opened = true;
                break;
            }
            match preparation.step(&mut policy) {
                Ok(Step::Progress) => {}
                Ok(_) => break,
                Err(error) => panic!("an unlimited preparation failed: {error:?}"),
            }
        }
        assert!(opened, "no nested entry cursor was ever open");
        assert_eq!(
            preparation.windows.len(),
            preparation.cursors.len() * 2,
            "two parts per open cursor"
        );
        let mut done = false;
        for _ in 0..10_000 {
            match preparation.reclaim_step(&mut policy) {
                Ok(Reclaimed::Done) => {
                    done = true;
                    break;
                }
                Ok(_) => {}
                Err(error) => panic!("an unlimited cleanup failed: {error:?}"),
            }
            assert_eq!(
                session.invalidation(),
                None,
                "a cleanup unit was taken for malformation"
            );
        }
        assert!(done, "cleanup did not complete");
        drop(preparation);
        drop(policy);
        assert!(session.finish().is_ok(), "the session is no evidence");
    }

    /// Cancel `source`'s preparation after `cut` steps and clean it up, each
    /// call first refused at its first admission, then retried admitted; a
    /// call needing no admission (a prepaid release) counts as it is. At
    /// every cleanup state the declared remaining count bounds the calls
    /// that actually remain, and a refused call moves nothing. `false` when
    /// the preparation completed before the cut.
    fn cleanup_bounded_after(source: &dyn Schema, cut: usize) -> bool {
        let mut a = Limits::unlimited();
        let mut preparation = Preparation::<Reservation, Family>::new(source);
        for step in 0..cut {
            match preparation.step(&mut a) {
                Ok(Step::Progress) => {}
                Ok(Step::Complete(plan)) => {
                    drop(plan);
                    return false;
                }
                Ok(Step::Finished) => panic!("cut {cut}, step {step}: finished with no plan"),
                Err(error) => panic!("cut {cut}, step {step}: {error:?}"),
            }
        }
        let mut declared = Vec::new();
        let mut calls = 0u64;
        loop {
            declared.push((
                calls,
                preparation
                    .reclaim_remaining()
                    .expect("the remaining count fits"),
            ));
            let before = preparation.position();
            let mut refused = Limits::unlimited().refusing(Some(0));
            match preparation.reclaim_step(&mut refused) {
                Ok(Reclaimed::Done) => {
                    calls += 1;
                    break;
                }
                Ok(_) => {
                    calls += 1;
                    continue;
                }
                Err(error) if error.refused() => {
                    // The first call also marks the preparation finished.
                    if before.finished {
                        assert_eq!(
                            preparation.position(),
                            before,
                            "cut {cut}, cleanup call {calls}: a refused call moved"
                        );
                    }
                }
                Err(error) => panic!("cut {cut}, cleanup call {calls}: {error:?}"),
            }
            calls += 1;
            match preparation.reclaim_step(&mut a) {
                Ok(Reclaimed::Done) => break,
                Ok(_) => {}
                Err(error) => panic!("cut {cut}, cleanup call {calls}: {error:?}"),
            }
            assert!(calls < 1 << 20, "cut {cut}: cleanup does not terminate");
        }
        for (at, bound) in declared {
            assert!(
                calls - at <= bound,
                "cut {cut}: {} calls remained after call {at}, {bound} declared",
                calls - at
            );
        }
        drop(preparation);
        assert_eq!(a.live_bytes(), 0, "cut {cut}: cleanup leaked");
        true
    }

    /// The preparation's cleanup count bounds its actual schedule at every
    /// reachable cleanup state: cancelled after every step of a preparation
    /// holding nested entry cursors (each with its empty window pair) and,
    /// where hash tables encode, bucket windows open across their
    /// acquisitions; every arena growth and relocation boundary of the
    /// window arena included. Planted control
    /// (`tests/data/controls/window-cleanup-understated.patch`): count the
    /// window arena as one unit while unreleased, as a plain-data clear
    /// would be, which understates its per-part drains.
    #[test]
    fn preparation_cleanup_is_bounded_at_every_cut() {
        let mut nested = crate::bounded::BTreeMap::new();
        for key in 0..8u64 {
            nested.insert(key, crate::bounded::BTreeMap::from([(key, key)]));
        }
        let mut cut = 0;
        while cleanup_bounded_after(&nested, cut) {
            cut += 1;
        }
        assert!(cut > 0, "the nested source completed in no step");
        #[cfg(feature = "hashbrown")]
        {
            let mut table = hashbrown::HashMap::new();
            for key in 0..64u64 {
                table.insert(key, key);
            }
            let mut cut = 0;
            while cleanup_bounded_after(&table, cut) {
                cut += 1;
            }
            assert!(cut > 0, "the table completed in no step");
        }
    }

    /// Window custody across every relocation boundary of its arena: two
    /// open bucket windows (each a live acquisition and its credit, minted
    /// by the one traversal) fill a window arena of four parts; its growth
    /// is stopped after `cut` reserve units (the staging block, the grown
    /// allocation, the publication, each part's move, the settlement, the
    /// retirement), so a pair straddles the two allocations at some cuts.
    /// At each cut every capability is held exactly once, each credit beside
    /// its own acquisition; the terminal two-pass close then forfeits every
    /// credit, Cancelled, before it ends any acquisition, each once, with no
    /// policy performing it.
    #[cfg(feature = "hashbrown")]
    #[test]
    fn window_custody_is_whole_and_closed_in_order_at_every_relocation_boundary() {
        use crate::bounded::{Credit, Event};
        const CURSORS: usize = 2;
        // Stage, allocate, publish, four part moves, settle, retire.
        const GROWTH_UNITS: usize = 9;
        let hash = |pair: &(u64, u64)| pair.0;
        let mut table = hashbrown::HashTable::new();
        for key in 0..64u64 {
            table.insert_unique(key, (key, key), hash);
        }
        for cut in 0..=GROWTH_UNITS {
            let session = Session::new(Capacity {
                permits: 16,
                events: 1024,
            });
            let mut a = Limits::recorded_unlimited(&session);
            let owner = a.owner().expect("a recorded owner");
            let mut windows = Storage::<WindowPart<Family>, Reservation, Family>::new();
            let mut minted = Vec::new();
            for cursor in 0..CURSORS {
                let (mut position, mut credit, mut acquisition) =
                    (BucketPosition::new(), None, None);
                match BucketCursor::new(&mut position, &mut credit, &mut acquisition)
                    .step(&table, &owner, &mut a)
                {
                    Ok(BucketStep::Entry { .. }) => {}
                    _ => panic!("cut {cut}, cursor {cursor}: the first bucket holds an entry"),
                }
                let id = acquisition.as_ref().map(crate::bounded::Acquisition::id);
                let held = credit
                    .as_ref()
                    .map(|credit| (credit.id(), credit.acquisition()));
                let (Some(id), Some((credit_id, bound))) = (id, held) else {
                    panic!("cut {cut}, cursor {cursor}: the window holds no capability");
                };
                assert_eq!(
                    bound, id,
                    "cut {cut}, cursor {cursor}: credit beside another acquisition"
                );
                minted.push((id, credit_id));
                let mut pair = Some([
                    WindowPart::Acquisition(acquisition),
                    WindowPart::Credit(credit),
                ]);
                for _ in 0..16 {
                    if let Some(spare) = windows.reserve_step(WINDOW_PART_MAXIMUM, &mut a).unwrap()
                    {
                        let parts = pair.take().expect("the pair is pushed once");
                        assert!(
                            spare.push_pair(parts).is_ok(),
                            "cut {cut}: an even arena granted one free part"
                        );
                        break;
                    }
                }
                assert!(
                    pair.is_none(),
                    "cut {cut}, cursor {cursor}: the pair was never pushed"
                );
            }
            assert_eq!(windows.len(), 2 * CURSORS);
            for unit in 0..cut {
                assert!(
                    windows
                        .reserve_step(WINDOW_PART_MAXIMUM, &mut a)
                        .unwrap()
                        .is_none(),
                    "cut {cut}: growth unit {unit} granted room early"
                );
            }
            // Whole custody: each acquisition and each credit exactly once,
            // each credit naming its pair's acquisition.
            let (mut acquisitions, mut credits) = (Vec::new(), Vec::new());
            windows.for_each(|part| match part {
                WindowPart::Acquisition(Some(acquisition)) => acquisitions.push(acquisition.id()),
                WindowPart::Credit(Some(credit)) => {
                    credits.push((credit.acquisition(), credit.id()))
                }
                WindowPart::Acquisition(None) | WindowPart::Credit(None) => {
                    panic!("cut {cut}: an empty part in a fully open arena")
                }
            });
            acquisitions.sort();
            credits.sort();
            let mut expected_acquisitions: Vec<_> = minted.iter().map(|(id, _)| *id).collect();
            expected_acquisitions.sort();
            let mut expected_credits = minted.clone();
            expected_credits.sort();
            assert_eq!(
                acquisitions, expected_acquisitions,
                "cut {cut}: acquisitions"
            );
            assert_eq!(credits, expected_credits, "cut {cut}: credits");
            assert!(
                windows_valid(&windows, CURSORS),
                "cut {cut}: the arena is malformed"
            );
            // Terminal close, then destruction.
            forfeit_windows(&mut windows, Performer::None, Forfeit::Cancelled);
            assert!(
                !windows_hold_capability(&windows),
                "cut {cut}: a capability survived the terminal close"
            );
            drop(windows);
            drop((a, owner));
            let observed = session
                .finish()
                .unwrap_or_else(|incomplete| panic!("cut {cut}: {incomplete:?}"));
            let ids: Vec<_> = minted.iter().map(|(id, _)| *id).collect();
            let forfeits: Vec<(usize, Identity)> = observed
                .iter()
                .enumerate()
                .filter_map(|(at, observed)| match &observed.event {
                    Event::Credit(Credit::Forfeit(settled, Forfeit::Cancelled))
                        if ids.contains(&settled.acquisition) =>
                    {
                        assert_eq!(
                            observed.by,
                            Performer::None,
                            "cut {cut}: a forfeit's performer"
                        );
                        Some((at, settled.id))
                    }
                    _ => None,
                })
                .collect();
            let ends: Vec<(usize, Identity)> = observed
                .iter()
                .enumerate()
                .filter_map(|(at, observed)| match &observed.event {
                    Event::End { acquisition, .. } if ids.contains(acquisition) => {
                        assert_eq!(
                            observed.by,
                            Performer::None,
                            "cut {cut}: an end's performer"
                        );
                        assert_eq!(
                            observed.family,
                            acquisition.family(),
                            "cut {cut}: an end published outside its minting family"
                        );
                        Some((at, *acquisition))
                    }
                    _ => None,
                })
                .collect();
            let mut forfeited: Vec<_> = forfeits.iter().map(|(_, id)| *id).collect();
            forfeited.sort();
            let mut expected_forfeits: Vec<_> = minted.iter().map(|(_, credit)| *credit).collect();
            expected_forfeits.sort();
            assert_eq!(
                forfeited, expected_forfeits,
                "cut {cut}: each credit forfeited once"
            );
            let mut ended: Vec<_> = ends.iter().map(|(_, id)| *id).collect();
            ended.sort();
            assert_eq!(
                ended, expected_acquisitions,
                "cut {cut}: each acquisition ended once"
            );
            let last_forfeit = forfeits.iter().map(|(at, _)| *at).max();
            let first_end = ends.iter().map(|(at, _)| *at).min();
            assert!(
                last_forfeit < first_end,
                "cut {cut}: an acquisition ended before every credit was settled"
            );
        }
    }

    /// A root schema counting the instructions fetched from it.
    struct Fetches<'s> {
        inner: &'s dyn Schema,
        fetched: core::cell::Cell<usize>,
    }

    impl Schema for Fetches<'_> {
        fn instruction(&self, index: usize) -> Instruction<'_> {
            self.fetched.set(self.fetched.get() + 1);
            self.inner.instruction(index)
        }
    }

    /// The parts a storage position holds, relocated or not.
    fn held_elements(position: decode::storage::StoragePosition) -> usize {
        position.initialized + position.relocating_remaining
    }

    /// Cursor publication and its reservation refusal, after every step of
    /// a preparation whose root map opens an entry cursor over nested maps:
    /// at every step boundary the window arena holds exactly two parts per
    /// cursor (the pair published with its cursor, never apart); a step
    /// refused at its first admission fetches no instruction from the root
    /// and moves nothing (the instruction index and every arena's position
    /// unchanged); and a step fetches at most one root instruction.
    #[test]
    fn cursor_publication_is_whole_and_a_refused_reservation_fetches_nothing() {
        let mut nested = crate::bounded::BTreeMap::new();
        for key in 0..8u64 {
            nested.insert(key, crate::bounded::BTreeMap::from([(key, key)]));
        }
        let pairs = |position: Position| {
            assert_eq!(
                held_elements(position.window_storage),
                2 * held_elements(position.cursor_storage),
                "a cursor without its whole window pair: {position:?}"
            );
        };
        let mut cut = 0usize;
        loop {
            let root = Fetches {
                inner: &nested,
                fetched: core::cell::Cell::new(0),
            };
            let mut a = Limits::unlimited();
            let mut preparation = Preparation::<Reservation, Family>::new(&root);
            let mut completed = false;
            for step in 0..cut {
                let before = root.fetched.get();
                match preparation.step(&mut a) {
                    Ok(Step::Progress) => {}
                    Ok(Step::Complete(plan)) => {
                        drop(plan);
                        completed = true;
                        break;
                    }
                    Ok(Step::Finished) => panic!("cut {cut}, step {step}: finished with no plan"),
                    Err(error) => panic!("cut {cut}, step {step}: {error:?}"),
                }
                assert!(
                    root.fetched.get() - before <= 1,
                    "cut {cut}, step {step}: a step fetched more than one root instruction"
                );
                pairs(preparation.position());
            }
            if completed {
                break;
            }
            let (fetched, position) = (root.fetched.get(), preparation.position());
            let mut refused = Limits::unlimited().refusing(Some(0));
            match preparation.step(&mut refused) {
                Err(error) if error.refused() => {
                    assert_eq!(
                        root.fetched.get(),
                        fetched,
                        "cut {cut}: a refused step fetched an instruction"
                    );
                    assert_eq!(
                        preparation.position(),
                        position,
                        "cut {cut}: a refused step moved"
                    );
                }
                Ok(Step::Complete(plan)) => drop(plan),
                Ok(_) => pairs(preparation.position()),
                Err(error) => panic!("cut {cut}: {error:?}"),
            }
            drop(preparation);
            assert_eq!(a.live_bytes(), 0, "cut {cut}: storage leaked");
            cut += 1;
            assert!(cut < 1 << 16, "the preparation never completed");
        }
        assert!(cut > 0, "the nested source completed in no step");
    }

    #[test]
    fn retired_plan_consumes_prepaid_releases_before_admitted_completion() {
        let source = "payload".repeat(128);
        let bound = prepare_bound::<Reservation, Family, ()>(
            Shape::of(&source, &mut Limits::unlimited()).expect("a text has a shape"),
        )
        .expect("the bound of a text fits in u64");
        let mut acquisition = Limits::unlimited();
        let mut preparation = Preparation::<Reservation, Family>::new(&source);
        let plan = within("retired plan's preparation", bound, || {
            match preparation.step(&mut acquisition).unwrap() {
                Step::Progress => ControlFlow::Continue(()),
                Step::Complete(plan) => ControlFlow::Break(plan),
                Step::Finished => panic!("no plan"),
            }
        });
        drop(preparation);
        let held = acquisition.live_bytes();
        let mut retired = plan.retire();
        assert_eq!(
            acquisition.live_bytes(),
            held,
            "retirement released storage"
        );
        let mut no_work = Limits::new(0, 0, 0);
        let mut releases = 0;
        loop {
            let before = acquisition.live_bytes();
            match retired.reclaim_step(&mut no_work) {
                Ok(Reclaimed::Progress) => {
                    assert!(
                        acquisition.live_bytes() < before,
                        "prepaid progress must release custody"
                    );
                    releases += 1;
                }
                Err(error) if error.refused() => break,
                _ => panic!("completion needs its own admission"),
            }
            assert!(releases <= 2, "a plan holds two arenas");
        }
        assert!(releases > 0);
        assert_eq!(acquisition.live_bytes(), 0);
        assert_eq!(no_work.used(), WriteWork::default());
        assert_eq!(
            retired.reclaim_step(&mut acquisition).unwrap(),
            Reclaimed::Done
        );
    }

    /// A preparation of three texts, each needing normalization, under a
    /// recorded session whose finish refuses while any owner of it lives
    /// ([`Session::finish`]): each published text continuation is destroyed
    /// before the next text initializes it again (`retire_text`), so no
    /// initialization writes over a live owner. Run unrefused, so every text
    /// after the first reuses the field; under a refusal of every admission
    /// once, so every unit of each re-initialization is refused and
    /// retried; and cancelled at every step into its cleanup, partial
    /// re-initializations among the cuts, observed after its cleanup: every
    /// session finishes and nothing is held. Planted control
    /// `tests/data/controls/text-continuation-reused-live.patch` (the
    /// continuation left live at its publication) leaves its owners holding
    /// the session.
    #[test]
    fn every_text_continuation_is_destroyed_before_its_next_text() {
        let source = vec!["e\u{301}".to_string(); 3];
        let run = |refusing: bool, cut: Option<usize>| -> usize {
            let what = format!("refusing {refusing}, cut {cut:?}");
            let session = Session::new(Capacity {
                permits: 1 << 10,
                events: 1 << 16,
            });
            let mut limits = Limits::recorded_unlimited(&session);
            if refusing {
                limits = limits.refusing_each();
            }
            let mut preparation = Preparation::<Reservation, Family>::new(&source);
            let mut steps = 0usize;
            let mut plan = None;
            while plan.is_none() && cut != Some(steps) {
                assert!(steps < 1 << 20, "{what}: the preparation did not publish");
                match preparation.step(&mut limits) {
                    Ok(Step::Complete(published)) => plan = Some(published),
                    Ok(Step::Progress) => {}
                    Ok(Step::Finished) => panic!("{what}: finished without a plan"),
                    Err(error) if error.refused() => {}
                    Err(error) => panic!("{what}: preparation: {error:?}"),
                }
                steps += 1;
            }
            if plan.is_none() {
                for call in 0.. {
                    assert!(call < 1 << 20, "{what}: the cleanup did not finish");
                    match preparation.reclaim_step(&mut limits) {
                        Ok(Reclaimed::Done) => break,
                        Ok(_) => {}
                        Err(error) if error.refused() => {}
                        Err(error) => panic!("{what}: cleanup: {error:?}"),
                    }
                }
                // Observed after its cleanup: the continuation, destroyed or
                // a partial prefix, is never read as one.
                let position = preparation.position();
                assert_eq!(
                    preparation.held_credit(),
                    Some(WriteWork::default()),
                    "{what}"
                );
                assert!(
                    position.normalization.is_none()
                        || position.text_initialized == position.text_initialization_steps,
                    "{what}: a partial continuation observed"
                );
            }
            drop((plan, preparation));
            assert_eq!(limits.live_bytes(), 0, "{what}: storage kept");
            drop(limits);
            session.finish().unwrap_or_else(|incomplete| {
                panic!("{what}: the preparation's recording is no evidence: {incomplete:?}")
            });
            steps
        };
        let steps = run(false, None);
        run(true, None);
        for cut in 0..steps {
            run(false, Some(cut));
        }
    }

    /// A preparation whose cleanup reports `Done` holds no borrow of its
    /// source: an owned preparation's record releases the source right
    /// after, while the record is still observed, so a payload pending when
    /// cleanup began is neither reported nor read once the preparation is
    /// reclaimed.
    #[test]
    fn a_reclaimed_preparation_holds_no_borrow_of_its_source() {
        let source = crate::ByteString::from(vec![0x5a; 200]);
        let bound = prepare_bound::<Reservation, Family, ()>(
            Shape::of(&source, &mut Limits::unlimited()).expect("a byte string has a shape"),
        )
        .expect("the bound of a byte string fits in u64");
        let mut limits = Limits::unlimited();
        let mut preparation = Preparation::<Reservation, Family>::new(&source);
        // Prepared until the payload is pending past its head: more bytes
        // pending than any staged head holds.
        within("preparation to its pending payload", bound, || {
            if preparation.position().pending_bytes > MAX_HEAD_LEN {
                return ControlFlow::Break(());
            }
            match preparation.step(&mut limits).unwrap() {
                Step::Progress => ControlFlow::Continue(()),
                Step::Complete(_) | Step::Finished => {
                    panic!("published before its payload was pending")
                }
            }
        });
        within("cleanup of a pending payload", bound, || match preparation
            .reclaim_step(&mut limits)
            .unwrap()
        {
            Reclaimed::Done => ControlFlow::Break(()),
            Reclaimed::Progress | Reclaimed::Waiting => ControlFlow::Continue(()),
        });
        let position = preparation.position();
        assert_eq!(
            position.pending_bytes, 0,
            "a reclaimed preparation still holds its source's payload"
        );
        assert!(
            !position.child,
            "a reclaimed preparation still holds a child"
        );
        assert!(
            !position.normalizing,
            "a reclaimed preparation still holds a text"
        );
        assert_eq!(limits.live_bytes(), 0);
    }

    /// A preparation capped below what its source appends is refused at the
    /// growth that would pass the cap; one capped at exactly what its source
    /// appends grows its plan's arena to the cap and no further, so the
    /// encoding it publishes holds exactly the encoded bytes.
    #[test]
    fn a_capped_preparation_grows_its_plan_to_its_cap_and_no_further() {
        let source = crate::ByteString::from(vec![0x5a; 200]);
        let shape =
            Shape::of(&source, &mut Limits::unlimited()).expect("a byte string has a shape");
        let appended = usize::try_from(shape.appended::<()>().expect("the extent fits in u64"))
            .expect("the extent fits in usize");
        // A two-byte head and 200 bytes; no map, so no gap.
        assert_eq!(appended, 202);
        let bound = prepare_bound::<Reservation, Family, ()>(shape).expect("the bound fits in u64");
        let mut limits = Limits::unlimited();
        let mut short = Preparation::<Reservation, Family>::capped(&source, appended - 1);
        assert_eq!(short.position().capacity_limit, appended - 1);
        let refused = within("preparation capped short", bound, || {
            match short.step(&mut limits) {
                Ok(Step::Progress) => ControlFlow::Continue(()),
                Ok(Step::Complete(_)) => panic!("a plan grew past its cap"),
                Ok(Step::Finished) => panic!("finished without a plan"),
                Err(error) => ControlFlow::Break(error),
            }
        });
        assert_eq!(refused, BoundedError::PlanMismatch);
        drop(short);
        assert_eq!(limits.live_bytes(), 0);
        let mut exact = Preparation::<Reservation, Family>::capped(&source, appended);
        assert_eq!(exact.position().capacity_limit, appended);
        let plan = within("preparation capped exactly", bound, || {
            match exact.step(&mut limits) {
                Ok(Step::Progress) => ControlFlow::Continue(()),
                Ok(Step::Complete(plan)) => ControlFlow::Break(plan),
                Ok(Step::Finished) => panic!("finished without a plan"),
                Err(error) => panic!("an exact cap was refused: {error:?}"),
            }
        });
        drop(exact);
        assert_eq!(plan.len(), appended);
        let encoded = plan
            .publish(&mut limits)
            .expect("an unlimited policy admits publication");
        assert_eq!(encoded.as_ref().len(), appended);
        assert_eq!(
            limits.live_bytes(),
            appended as u64,
            "the published encoding holds more than its capped arena"
        );
        drop(encoded);
        assert_eq!(limits.live_bytes(), 0);
    }

    /// Publication releases the plan's gap records and keeps its bytes as
    /// the encoding, so an encoding retains less than the plan it
    /// publishes, measured and bounded alike: a bound of the encoding that
    /// also retained the gaps would overstate what `encode` keeps.
    #[test]
    fn an_encoding_retains_less_than_the_plan_it_publishes() {
        let source = Pairs((0..32u64).rev().map(|n| (n, vec![n; 4])).collect());
        let shape = Shape::of(&source, &mut Limits::unlimited()).expect("a map has a shape");
        let planned_bound =
            prepare_bound::<Reservation, Family, ()>(shape).expect("the bound fits in u64");
        let encoded_bound =
            encode_bound::<Reservation, Family, ()>(shape).expect("the bound fits in u64");
        let mut limits = Limits::unlimited();
        let plan =
            crate::bounded::prepare(&source, &mut limits).expect("an unlimited policy prepares");
        let planned = limits.live_bytes();
        let encoded = plan
            .publish(&mut limits)
            .expect("an unlimited policy admits publication");
        let kept = limits.live_bytes();
        assert!(
            kept < planned,
            "publication released nothing: plan {planned}, encoding {kept}"
        );
        assert!(
            planned <= planned_bound.retained,
            "plan {planned} beyond its bound {}",
            planned_bound.retained
        );
        assert!(
            kept <= encoded_bound.retained,
            "encoding {kept} beyond its bound {}",
            encoded_bound.retained
        );
        assert!(
            encoded_bound.retained < planned_bound.retained,
            "the encoding's bound retains {} and its plan's {}: the gaps publication releases are still counted",
            encoded_bound.retained,
            planned_bound.retained
        );
        drop(encoded);
        assert_eq!(limits.live_bytes(), 0);
    }

    struct InvalidProtocol(u8);

    impl Schema for InvalidProtocol {
        fn instruction(&self, index: usize) -> Instruction<'_> {
            match (self.0, index) {
                (0, 0) => Instruction::CountedMap(1),
                (1, 0) => Instruction::CountedUnorderedMap(1),
                // An entry offered to a field map, counted or not.
                (2, 0) => Instruction::CountedMap(1),
                (3, 0) => Instruction::Map,
                (2 | 3, 1) => Instruction::Entry(&0u64, &0u64),
                (7, 0) => Instruction::UnorderedMap,
                (4, 0) => Instruction::Field(0, None),
                (5, 0) => Instruction::Entry(&0u64, &0u64),
                (6, 0 | 1) => Instruction::Map,
                (7, 1) => Instruction::Field(0, None),
                (8, 0) => Instruction::CountedUnorderedMap(1),
                (8..=10, 1) => Instruction::Entries(self),
                (9, 0) => Instruction::Map,
                (10, 0) => Instruction::Head(MajorType::Array, Argument::Shortest(0)),
                (11, 0) => Instruction::UnorderedMap,
                (11, 1) => Instruction::Entry(&0u64, &0u64),
                (11, 2) => Instruction::Entries(self),
                (12, 0) => Instruction::CountedMap(0),
                (12, 1) => Instruction::Field(0, Some(&0u64)),
                _ => Instruction::End,
            }
        }
    }

    // SAFETY: the cursor stores a usize, owns nothing, and never yields a
    // reference. Early termination is a protocol error, not memory misuse.
    unsafe impl Entries for InvalidProtocol {
        fn start(&self, slot: &mut Slot) {
            slot.put(0usize);
        }
        fn moves(&self) -> u64 {
            0
        }
        fn ordered(&self) -> bool {
            false
        }
        unsafe fn next<'a>(&'a self, _: &mut Slot) -> EntryStep<'a> {
            EntryStep::End
        }
    }

    #[test]
    fn shape_and_preparation_reject_the_same_invalid_map_protocols() {
        for case in 0..13 {
            let source = InvalidProtocol(case);
            // Finite budgets ensure a backward cursor is a test failure rather
            // than a hung test if the validation regresses.
            let mut walk = Limits::new(10000, 1000000, 1000000);
            assert!(
                matches!(
                    Shape::of(&source, &mut walk),
                    Err(BoundedError::PlanMismatch)
                ),
                "walk case {case}"
            );
            let mut preparation = Preparation::<Reservation, Family>::new(&source);
            // A source the walk rejects has no shape, so no production bound
            // either: the finite budget is the guard, as it is for every
            // caller. Every step admits a value or requests a byte
            // ([`ResourceBound::steps`]), so a run that spins is refused
            // within the budget, and a refusal ends it unrejected.
            let mut budget = Limits::new(10000, 1000000, 1000000);
            let mut rejected = false;
            loop {
                match preparation.step(&mut budget) {
                    Ok(Step::Progress) => {}
                    Err(BoundedError::PlanMismatch) => {
                        rejected = true;
                        break;
                    }
                    _ => break,
                }
            }
            drop(preparation);
            assert!(rejected, "preparation case {case}");
            assert_eq!(budget.live_bytes(), 0);
        }
    }

    /// A field map with no present field.
    struct Empty;

    impl Schema for Empty {
        fn instruction(&self, index: usize) -> Instruction<'_> {
            match index {
                0 => Instruction::Map,
                _ => Instruction::End,
            }
        }
    }

    /// An unordered map of its pairs, in the order given, one entry per
    /// instruction.
    struct Pairs<K, V>(Vec<(K, V)>);

    impl<K: Schema, V: Schema> Schema for Pairs<K, V> {
        fn instruction(&self, index: usize) -> Instruction<'_> {
            match index {
                0 => Instruction::UnorderedMap,
                index => match self.0.get(index - 1) {
                    Some((key, value)) => Instruction::Entry(key, value),
                    None => Instruction::End,
                },
            }
        }
    }

    /// The shape of `source` and what preparing it reported, requested, held
    /// at its peak, and what its published plan holds.
    fn prepared(source: &dyn Schema) -> (Shape, WriteWork, u64, u64, u64) {
        let shape = Shape::of(source, &mut Limits::unlimited()).unwrap();
        let bound = prepare_bound::<Reservation, Family, ()>(shape).unwrap();
        let mut limits = Limits::unlimited();
        let mut preparation = Preparation::<Reservation, Family>::new(source);
        let plan = within("preparation", bound, || {
            match preparation.step(&mut limits).unwrap() {
                Step::Progress => ControlFlow::Continue(()),
                Step::Complete(plan) => ControlFlow::Break(plan),
                Step::Finished => unreachable!("preparation finished without a plan"),
            }
        });
        drop(preparation);
        let retained = limits.live_bytes();
        assert!(shape.extent >= plan.len() as u64, "{shape:?}");
        drop(plan);
        assert_eq!(limits.live_bytes(), 0);
        (
            shape,
            limits.used(),
            limits.requested_bytes(),
            limits.peak_bytes(),
            retained,
        )
    }

    fn covered(source: &dyn Schema) {
        let (shape, used, requested, peak, retained) = prepared(source);
        let bound = prepare_bound::<Reservation, Family, ()>(shape).unwrap();
        assert!(
            bound.covers(used, requested, peak, retained),
            "{shape:?}: used {used:?}, requested {requested}, peak {peak}, retained {retained}; {bound:?}"
        );
    }

    /// Every engine path is prepared within the bound of its shape: long and
    /// disordered texts, many gaps, root and nested unordered maps, keys
    /// that are themselves maps or share long prefixes, misordered nested
    /// maps that are permuted in place, and deep nesting.
    #[test]
    fn the_preparation_bound_covers_every_engine_path() {
        covered(&"x".repeat(70_000));
        covered(&format!("q{}", "\u{301}\u{316}".repeat(1024)));
        covered(&vec!["e\u{301}".to_string(); 64]);
        covered(&(0..300).map(|_| Empty).collect::<Vec<_>>());
        covered(&Pairs((0..200u64).rev().map(|n| (n, n)).collect()));
        // A nested map is checked and, misordered, permuted in place.
        covered(&vec![Pairs(
            (0..64u64).rev().map(|n| (n, vec![n; 4])).collect(),
        )]);
        covered(&vec![Pairs(
            (0..32u64)
                .rev()
                .map(|n| (format!("{}{n:03}", "k".repeat(200)), n))
                .collect(),
        )]);
        // Keys that are maps, nested two unordered levels deep.
        covered(&Pairs(
            (0..16u64)
                .rev()
                .map(|n| (Pairs(vec![(n, n), (n + 100, 0)]), vec![Empty, Empty]))
                .collect(),
        ));
        // A hundred and one frames open at once.
        let mut nested: Box<dyn Schema> = Box::new(7u64);
        for _ in 0..100 {
            nested = Box::new(vec![nested]);
        }
        covered(&nested);
    }

    /// Keys holding gapped maps are compacted in place before they are
    /// compared: compaction opens at a key's first gap, moves the bytes up to
    /// the next gap, removes each gap, then truncates the plan's bytes and
    /// the key's gap records to the compacted key. Only compacted keys order
    /// canonically: `[{}, 1]` (`82 a0 01`) before `[{}, {}]` (`82 a0 a0`),
    /// where the gaps' bytes left in place would put the second key first.
    /// The plan publishes the canonical map exactly, within the bound of its
    /// shape. The smallest source taking each step of compaction, and no other
    /// engine path, so light enough to run under Miri (`tests/miri-suites.txt`).
    #[test]
    fn keys_holding_gapped_maps_are_compacted_before_they_are_ordered() {
        let one: Vec<Box<dyn Schema>> = vec![Box::new(Empty), Box::new(1u64)];
        let two: Vec<Box<dyn Schema>> = vec![Box::new(Empty), Box::new(Empty)];
        let source = Pairs(vec![(two, 0u64), (one, 1u64)]);
        covered(&source);
        let mut limits = Limits::unlimited();
        let plan =
            crate::bounded::prepare(&source, &mut limits).expect("an unlimited policy prepares");
        let encoded = plan
            .publish(&mut limits)
            .expect("an unlimited policy admits publication");
        assert_eq!(
            encoded.as_ref(),
            [0xa2, 0x82, 0xa0, 0x01, 0x01, 0x82, 0xa0, 0xa0, 0x00]
        );
        drop(encoded);
        assert_eq!(limits.live_bytes(), 0);
    }

    /// The composed peak covers a text normalized and copied beside every
    /// arena a permuted map grew, and is at most every place's peak summed:
    /// phases that exclude one another are not counted at once.
    #[test]
    fn the_peak_covers_each_phase_beside_the_kept_arenas() {
        let source: Vec<Box<dyn Schema>> = vec![
            Box::new(Pairs((0..256u64).rev().map(|n| (n, vec![n; 4])).collect())),
            Box::new(format!("q{}", "\u{301}\u{316}".repeat(4096))),
        ];
        covered(&source);
        let shape = Shape::of(&source, &mut Limits::unlimited()).unwrap();
        let terms = PreparationTerms::of::<Reservation, Family, ()>(shape).unwrap();
        let mut summed = 0u64;
        for &place in PreparationPlace::ALL {
            summed = add::<()>(summed, terms.term(place).peak).unwrap();
        }
        let peak = terms.peak::<()>().unwrap();
        assert!(
            peak <= summed,
            "peak {peak} beyond the places' sum {summed}"
        );
        assert!(
            peak >= terms.term(PreparationPlace::Texts).peak,
            "peak {peak} below a text's normalization"
        );
    }

    /// Place attribution, which this crate's tests record under `std`.
    #[cfg(feature = "std")]
    mod attribution {
        use super::*;

        /// An array of two values.
        struct Pair<A, B>(A, B);

        impl<A: Schema, B: Schema> Schema for Pair<A, B> {
            fn instruction(&self, index: usize) -> Instruction<'_> {
                match index {
                    0 => Instruction::Head(MajorType::Array, Argument::Shortest(2)),
                    1 => Instruction::Child(&self.0),
                    2 => Instruction::Child(&self.1),
                    _ => Instruction::End,
                }
            }
        }

        /// A byte string of its bytes.
        struct Raw(Vec<u8>);

        impl Schema for Raw {
            fn instruction(&self, index: usize) -> Instruction<'_> {
                match index {
                    0 => Instruction::Head(
                        MajorType::ByteString,
                        Argument::Shortest(self.0.len() as u64),
                    ),
                    1 => Instruction::Bytes(&self.0),
                    _ => Instruction::End,
                }
            }
        }

        /// A field map whose field `i` holds its `i`th value: the encoding of an
        /// unordered map of the same integer keys, its keys already in order.
        struct Fields(Vec<u64>);

        impl Schema for Fields {
            fn instruction(&self, index: usize) -> Instruction<'_> {
                match index {
                    0 => Instruction::Map,
                    index => match self.0.get(index - 1) {
                        Some(value) => Instruction::Field((index - 1) as u64, Some(value)),
                        None => Instruction::End,
                    },
                }
            }
        }

        /// A field map with one field, `0`, holding its value.
        struct Wrap(Box<dyn Schema>);

        impl Schema for Wrap {
            fn instruction(&self, index: usize) -> Instruction<'_> {
                match index {
                    0 => Instruction::Map,
                    1 => Instruction::Field(0, Some(self.0.as_ref())),
                    _ => Instruction::End,
                }
            }
        }

        /// An unordered map of its pairs drawn by an entry cursor, one entry per
        /// transition, as an ordered tree's stepped cursor yields them.
        struct Stepped<V>(Vec<(u64, V)>);

        impl<V: Schema> Schema for Stepped<V> {
            fn instruction(&self, index: usize) -> Instruction<'_> {
                match index {
                    0 => Instruction::UnorderedMap,
                    1 => Instruction::Entries(self),
                    _ => Instruction::End,
                }
            }
        }

        // SAFETY: `start` stores a `usize` index that `next` reads back; the
        // cursor refers to nothing.
        unsafe impl<V: Schema> Entries for Stepped<V> {
            fn start(&self, slot: &mut Slot) {
                slot.put(0usize);
            }

            /// An index advanced by one: no node moves.
            fn moves(&self) -> u64 {
                0
            }

            /// Keys in the order given, sorted by the engine.
            fn ordered(&self) -> bool {
                false
            }

            unsafe fn next<'a>(&'a self, slot: &mut Slot) -> EntryStep<'a> {
                // SAFETY: `start` stored this cursor's index.
                let at = unsafe { slot.get::<usize>() };
                match self.0.get(*at) {
                    Some((key, value)) => {
                        *at += 1;
                        EntryStep::Entry(key, value)
                    }
                    None => EntryStep::End,
                }
            }
        }

        type LedgeredPlan = (places::Ledgered, Shape, Option<Prepared<places::Permit>>);
        type LedgeredError = (String, Box<Position>);

        /// Where a preparation is cancelled into its cleanup.
        #[derive(Clone, Copy, Debug)]
        enum Cancel {
            /// After this many steps.
            After(usize),
            /// At the first boundary the condition holds of: an arena
            /// relocating, which cleanup then drains one element per unit,
            /// as its term charges; settled, it is discarded in one.
            Draining(fn(&Position) -> bool),
        }

        /// Whether `arena` is relocating at least `least` elements.
        fn relocates(
            arena: crate::bounded::decode::storage::StoragePosition,
            least: usize,
        ) -> bool {
            arena.stage == crate::bounded::decode::storage::StorageStage::Relocating
                && arena.relocating_remaining >= least
        }

        /// Every arena a preparation holds at `position`: its nine, and its
        /// text continuation's two once initialized.
        fn arenas(
            position: &Position,
        ) -> impl Iterator<Item = crate::bounded::decode::storage::StoragePosition> {
            let text = position
                .normalization
                .map(|text| [text.characters, text.ordering_state.scratch]);
            [
                position.frames,
                position.bytes,
                position.holes,
                position.maps,
                position.cursor_storage,
                position.window_storage,
                position.dynamic.entry_storage,
                position.dynamic.merge_storage,
                position.dynamic.bitmap_storage,
            ]
            .into_iter()
            .chain(text.into_iter().flatten())
        }

        /// How many of the preparation's arenas, and its text continuation's,
        /// a cancellation would drain one element per unit: relocating, or
        /// relocated and not yet settled; a settled arena is discarded in one
        /// unit (`Storage::reclaim_copy_step`), whatever its growth's
        /// acquisition holds, since cleanup entry settles that first.
        /// [`PreparationTerms`] charges its peak, and its cleanup's drain,
        /// for at most one; every attribution run checks it at every
        /// boundary ([`ledgered`]).
        fn draining(position: &Position) -> usize {
            use crate::bounded::decode::storage::StorageStage;
            arenas(position)
                .filter(|arena| {
                    matches!(
                        arena.stage,
                        StorageStage::Relocating | StorageStage::Relocated
                    )
                })
                .count()
        }

        /// `source` prepared under a ledgered policy, then, when `cleanup`,
        /// cancelled after `cleanup` steps and its cleanup stepped to `Done`: the
        /// policy, the source's shape and the published plan, held for the check.
        /// The preparation and its cleanup each run within the bound of the
        /// source's shape ([`within`]). A source the walk rejects has no shape,
        /// so it never becomes an attribution run: the walk rejects exactly the
        /// protocols the preparation does
        /// (`shape_and_preparation_reject_the_same_invalid_map_protocols`).
        fn ledgered(
            source: &dyn Schema,
            cleanup: Option<Cancel>,
        ) -> Result<LedgeredPlan, LedgeredError> {
            let mut policy = places::Ledgered::new();
            let mut preparation = Preparation::<places::Permit, ()>::new(source);
            // A cancelled run's shape is its source's, as a completed one's.
            let shape = Shape::of(source, &mut Limits::unlimited()).map_err(|error| {
                (
                    format!("shape: {error:?}"),
                    Box::new(preparation.position()),
                )
            })?;
            let bound = prepare_bound::<places::Permit, (), ()>(shape).map_err(|error| {
                (
                    format!("bound: {error:?}"),
                    Box::new(preparation.position()),
                )
            })?;
            let mut steps = 0usize;
            let plan =
                within("ledgered preparation", bound, || {
                    let position = preparation.position();
                    let arenas = draining(&position);
                    if arenas > 1 {
                        return ControlFlow::Break(Err((
                            format!("{arenas} arenas staging or relocating at once"),
                            Box::new(position),
                        )));
                    }
                    let cancelled = match cleanup {
                        Some(Cancel::After(after)) => after == steps,
                        Some(Cancel::Draining(condition)) => condition(&position),
                        None => false,
                    };
                    if cancelled {
                        return ControlFlow::Break(within("ledgered cleanup", bound, || {
                            match preparation.reclaim_step(&mut policy) {
                                Ok(Reclaimed::Done) => ControlFlow::Break(Ok(None)),
                                Ok(_) => ControlFlow::Continue(()),
                                Err(error) => ControlFlow::Break(Err((
                                    format!("cleanup: {error:?}"),
                                    Box::new(preparation.position()),
                                ))),
                            }
                        }));
                    }
                    steps += 1;
                    match preparation.step(&mut policy) {
                        Ok(Step::Progress) => ControlFlow::Continue(()),
                        Ok(Step::Complete(published)) => ControlFlow::Break(Ok(Some(published))),
                        Ok(Step::Finished) => ControlFlow::Break(Err((
                            "finished without publication".into(),
                            Box::new(preparation.position()),
                        ))),
                        Err(error) => ControlFlow::Break(Err((
                            format!("preparation: {error:?}"),
                            Box::new(preparation.position()),
                        ))),
                    }
                })?;
            Ok((policy, shape, plan))
        }

        #[test]
        fn planted_protocol_defect_cannot_become_an_attribution_run() {
            for case in 0..13 {
                let result = ledgered(&InvalidProtocol(case), None);
                let Err((error, position)) = result else {
                    panic!("planted protocol {case} accepted as evidence");
                };
                assert!(
                    error.contains("PlanMismatch"),
                    "case {case}: {error}, {position:?}"
                );
            }
        }

        /// Under a policy refusing every admission once, a growth's
        /// acquisition retains admissions with no block yet: its block's
        /// write admitted on the retry and its release refused next
        /// (`stable::acquire`). The arena's execution stage stays `Settled`;
        /// the retained admissions are the preparation's acquisition
        /// custody, read through its one traversal
        /// ([`Preparation::observe_custody`]). The attribution runs refuse
        /// nothing, so they never retain; here a map's and a text's
        /// preparation each retain a growth's admissions at some boundary,
        /// and at most one arena relocates at any boundary ([`draining`]).
        #[test]
        fn a_refused_growth_retains_its_admissions_as_custody_not_stage() {
            let sources: [(&str, Box<dyn Schema>); 2] = [
                (
                    "permuted map",
                    Box::new(vec![Pairs(
                        (0..64u64).rev().map(|n| (n, vec![n; 4])).collect(),
                    )]),
                ),
                (
                    "disordered text",
                    Box::new(format!("q{}", "\u{301}\u{316}".repeat(64))),
                ),
            ];
            for (name, source) in sources {
                let mut limits = Limits::unlimited().refusing_each();
                let mut preparation = Preparation::<Reservation, Family>::new(source.as_ref());
                let mut staged = 0usize;
                let mut published = false;
                for _ in 0..1_000_000 {
                    let position = preparation.position();
                    let counted = draining(&position);
                    assert!(
                        counted <= 1,
                        "{name}: {counted} arenas relocating at once: {position:?}"
                    );
                    let mut retained = 0usize;
                    let observed = crate::bounded::held_of(
                        |sink| preparation.observe_custody(sink),
                        &mut |hold| {
                            if matches!(hold.obligation, Obligation::Grant | Obligation::Release) {
                                retained += 1;
                            }
                        },
                    );
                    assert_eq!(observed, PermitsObserved::Complete, "{name}");
                    if retained > 0 {
                        staged += 1;
                    }
                    match preparation.step(&mut limits) {
                        Ok(Step::Complete(plan)) => {
                            drop(plan);
                            published = true;
                            break;
                        }
                        Ok(Step::Progress) => {}
                        Ok(Step::Finished) => panic!("{name}: finished without a plan"),
                        Err(error) if error.refused() => {}
                        Err(error) => panic!("{name}: {error:?}"),
                    }
                }
                assert!(published, "{name}: not published in a million steps");
                assert!(
                    staged > 0,
                    "{name}: no growth's admissions retained under refusals"
                );
                drop(preparation);
                assert_eq!(limits.live_bytes(), 0, "{name}");
            }
        }

        /// A hasher whose hash of a `u64` key is the key: a table's index is
        /// its hash masked to its buckets, so each key below the bucket count
        /// has its own index as its home bucket, and the layout of a table
        /// filled in key order follows from its keys alone, never from hash
        /// values the fixture does not choose.
        #[cfg(feature = "custom-std-collections")]
        #[derive(Default)]
        struct Home(u64);

        #[cfg(feature = "custom-std-collections")]
        impl core::hash::Hasher for Home {
            fn finish(&self) -> u64 {
                self.0
            }

            /// Bytes other than a `u64`'s, folded in order; a `u64` key
            /// takes [`Self::write_u64`].
            fn write(&mut self, bytes: &[u8]) {
                for &byte in bytes {
                    self.0 = (self.0 << 8) | u64::from(byte);
                }
            }

            fn write_u64(&mut self, value: u64) {
                self.0 = value;
            }
        }

        /// A witness: its name, its source, and where it is cancelled into
        /// its cleanup, if it is.
        type WitnessInput = (&'static str, Box<dyn Schema>, Option<Cancel>);
        type Witness = (Requirement, WitnessInput);

        /// The hashbrown table of the bucket witnesses ([`buckets`]): 200
        /// pairs and the key 255 in 256 buckets, each key hashed to itself,
        /// so every key lies in its own home bucket (asserted), enumerated by
        /// the bucket cursor in four windows, an entry ending nearly every
        /// call.
        #[cfg(feature = "hashbrown")]
        fn hashbrown_buckets() -> Option<Witness> {
            let hash = |pair: &(u64, u64)| pair.0;
            let mut table = hashbrown::HashTable::new();
            for key in (0..200u64).chain([255]) {
                table.insert_unique(key, (key, key), hash);
            }
            assert_eq!(table.num_buckets(), 256);
            for key in (0..200u64).chain([255]) {
                assert_eq!(
                    table.get_bucket(key as usize),
                    Some(&(key, key)),
                    "key {key} is not in its home bucket"
                );
            }
            Some((
                Requirement::Capability(Capability::Hashbrown),
                ("hash table", Box::new(table), None),
            ))
        }

        /// No hashbrown table where hashbrown is not built.
        #[cfg(not(feature = "hashbrown"))]
        fn hashbrown_buckets() -> Option<Witness> {
            None
        }

        /// The forked standard library's map of the bucket witnesses
        /// ([`buckets`]): the same 200 pairs and the key 255 in 256 buckets,
        /// each key hashed to itself ([`Home`]), every key in its own home
        /// bucket (asserted).
        #[cfg(feature = "custom-std-collections")]
        fn std_buckets() -> Option<Witness> {
            let map: std::collections::HashMap<u64, u64, std::hash::BuildHasherDefault<Home>> =
                (0..200u64).chain([255]).map(|key| (key, key)).collect();
            assert_eq!(map.num_buckets(), 256);
            for key in (0..200u64).chain([255]) {
                assert_eq!(
                    map.get_bucket(key as usize),
                    Some((&key, &key)),
                    "key {key} is not in its home bucket"
                );
            }
            Some((Requirement::Always, ("std hash map", Box::new(map), None)))
        }

        /// No forked standard library map where the forked collections are
        /// not built.
        #[cfg(not(feature = "custom-std-collections"))]
        fn std_buckets() -> Option<Witness> {
            None
        }

        /// The witnesses of the `Buckets` place: one run for each sealed
        /// bucket table the build compiles, both when both features are
        /// built, so the bucket enumeration of each is witnessed in its own
        /// run; none where neither is built, where nothing charges the
        /// place.
        fn buckets() -> Vec<Witness> {
            [hashbrown_buckets(), std_buckets()]
                .into_iter()
                .flatten()
                .collect()
        }

        /// The sources whose preparation charges `place`, each where it is
        /// cancelled into its cleanup, if it is: a place without a witness
        /// does not compile. One source a place, but for `Buckets`, which
        /// has one per sealed table the build compiles ([`buckets`]); none
        /// only for a place this build never charges.
        fn witness(place: PreparationPlace) -> Vec<Witness> {
            let single: WitnessInput = match place {
                PreparationPlace::Instructions
                | PreparationPlace::Pushes
                | PreparationPlace::Frames
                | PreparationPlace::PlanBytes
                | PreparationPlace::Completion => {
                    ("integers", Box::new((0..1000u64).collect::<Vec<_>>()), None)
                }
                // An item of one byte per instruction pair: a head per value.
                PreparationPlace::Appends => ("zeros", Box::new(vec![0u64; 1000]), None),
                // Ordered entries: the check passes over every one.
                PreparationPlace::Check => (
                    "ordered map",
                    Box::new(vec![Pairs((0..64u64).map(|n| (n, vec![n; 4])).collect())]),
                    None,
                ),
                PreparationPlace::Gaps | PreparationPlace::OpenMaps => (
                    "gaps",
                    Box::new((0..300).map(|_| Empty).collect::<Vec<_>>()),
                    None,
                ),
                PreparationPlace::Cursors => {
                    let mut cursors: Box<dyn Schema> = Box::new(7u64);
                    for n in 0..8 {
                        cursors = Box::new(Stepped(vec![(n, cursors)]));
                    }
                    ("deep cursors", cursors, None)
                }
                PreparationPlace::Texts => {
                    ("texts", Box::new(vec!["e\u{301}".to_string(); 64]), None)
                }
                PreparationPlace::EntryArena
                | PreparationPlace::Compaction
                | PreparationPlace::Merging
                | PreparationPlace::Comparisons
                | PreparationPlace::Scratch
                | PreparationPlace::Permutation
                | PreparationPlace::Visited => (
                    "permuted map",
                    Box::new(vec![Pairs(
                        (0..64u64).rev().map(|n| (n, vec![n; 4])).collect(),
                    )]),
                    None,
                ),
                // Cancelled while its plan's bytes relocate their last
                // growth, so cleanup drains them one per unit, as its term
                // charges. The plan's arena holds 594 bytes: an array head,
                // the map's gap of the widest head (`MAX_HEAD_LEN`, nine
                // bytes, its two-byte head written into it at the end), and
                // per entry a key, an array head and four values, the key
                // and each value one byte below 24 and two from 24 (24
                // entries of 6 bytes, 40 of 11). It fills a capacity of 512
                // and relocates all 512.
                PreparationPlace::Cleanup => (
                    "cancelled map",
                    Box::new(vec![Pairs(
                        (0..64u64).rev().map(|n| (n, vec![n; 4])).collect(),
                    )]),
                    Some(Cancel::Draining(|position| relocates(position.bytes, 512))),
                ),
                // Each sealed bucket table the build compiles, a run of its
                // own; none where none is built.
                PreparationPlace::Buckets => return buckets(),
                // Bignums of many digits each: both passes over every digit,
                // in full units of a quantum but for each pass's last.
                #[cfg(feature = "num-bigint")]
                PreparationPlace::Digits => (
                    "bignums",
                    Box::new(vec![num_bigint::BigUint::from(1u8) << 4095usize; 4]),
                    None,
                ),
                // No bignum is encoded where bignums are not: its term is
                // zero and nothing charges it.
                #[cfg(not(feature = "num-bigint"))]
                PreparationPlace::Digits => return Vec::new(),
            };
            vec![(Requirement::Always, single)]
        }

        /// A generated source nested at most `depth` deep: integers, texts,
        /// bytes, field maps with no field, arrays, unordered maps with their
        /// entries in generated order (some keys maps themselves), field maps
        /// of one value or of integers, and entry cursors. The keys within
        /// one map are distinct, so no canonical collision ends a preparation.
        fn generated(
            generator: &mut crate::bounded::tests::Generator,
            depth: usize,
        ) -> Box<dyn Schema> {
            let kinds = if depth == 0 { 4 } else { 9 };
            match generator.below(kinds) {
                0 => Box::new(generator.below(1 << 40)),
                1 => Box::new(generator.text(24)),
                2 => {
                    let len = generator.below(100) as usize;
                    Box::new(Raw(vec![0x5a; len]))
                }
                3 => Box::new(Empty),
                4 => {
                    let len = generator.below(6);
                    Box::new(
                        (0..len)
                            .map(|_| generated(generator, depth - 1))
                            .collect::<Vec<_>>(),
                    )
                }
                5 => {
                    let len = generator.below(12);
                    let base = generator.below(1000);
                    let entries = (0..len)
                        .map(|n| {
                            let key: Box<dyn Schema> = if generator.below(4) == 0 {
                                Box::new(Pairs(vec![(base + n, 0u64)]))
                            } else {
                                Box::new(base + (n * 37) % 64 + 64 * n)
                            };
                            (key, generated(generator, depth - 1))
                        })
                        .collect();
                    Box::new(Pairs(entries))
                }
                6 => Box::new(Wrap(generated(generator, depth - 1))),
                7 => {
                    let len = generator.below(20);
                    Box::new(Fields((0..len).map(|_| generator.below(1 << 20)).collect()))
                }
                _ => {
                    let len = generator.below(8);
                    let entries = (0..len)
                        .rev()
                        .map(|n| (n, generated(generator, depth - 1)))
                        .collect();
                    Box::new(Stepped(entries))
                }
            }
        }

        /// Every place of a preparation is within its term on generated
        /// sources, every fourth cancelled partway into its cleanup; every
        /// admission and request is made at some place.
        #[test]
        fn every_place_of_a_preparation_is_within_its_term_on_generated_sources() {
            let mut generator = crate::bounded::tests::Generator::new(0x5eed_0003);
            let mut runs = Vec::new();
            let mut plans = Vec::new();
            for index in 0..300usize {
                let source = generated(&mut generator, 4);
                let cancel = (index % 4 == 0).then_some(Cancel::After(index % 40 + 1));
                let (policy, shape, plan) =
                    ledgered(source.as_ref(), cancel).unwrap_or_else(|failure| {
                        panic!("generated {index}, cancelled after {cancel:?}: {failure:?}")
                    });
                runs.push(places::Run {
                    name: format!("generated {index}, cancelled after {cancel:?}"),
                    outcome: if plan.is_some() {
                        places::Outcome::Published
                    } else {
                        places::Outcome::Cancelled
                    },
                    policy,
                    terms: PreparationTerms::of::<places::Permit, (), ()>(shape).unwrap(),
                });
                plans.push(plan);
            }
            places::check(&runs);
            drop(plans);
        }

        #[test]
        fn retained_merge_scratch_growth_is_bounded_across_short_runs() {
            // Successive maps require scratch runs of 1, 2, 3, then larger
            // sizes. Capping each growth at its current run used to turn
            // retained geometric growth into extra short allocations.
            let source: Vec<_> = [2u64, 4, 6, 10, 18, 34]
                .into_iter()
                .map(|count| Pairs((0..count).rev().map(|key| (key, key)).collect()))
                .collect();
            let (policy, shape, plan) = ledgered(&source, None).unwrap();
            assert!(plan.is_some());
            let measured = policy.ledger().measured(PreparationPlace::Scratch);
            // The largest merge copies sixteen entries. Its arena grows
            // through capacities 4, 8 and 16, retaining sixteen entries.
            let element = size_of::<maps::order::Entry>() as u64;
            let block = size_of::<
                decode::construction::stable::Held<
                    Owned<maps::order::Entry, places::Permit>,
                    places::Permit,
                >,
            >() as u64;
            assert_eq!(measured.allocated, (4 + 8 + 16) * element + 3 * block);
            let (cancelled, cancelled_shape, cancelled_plan) =
                ledgered(&source, Some(Cancel::After(1))).unwrap();
            assert!(
                cancelled_plan.is_none(),
                "cancelled scratch fixture published"
            );
            assert_eq!(cancelled.ledger().total().retained, 0);
            places::check(&[
                places::Run {
                    name: "retained scratch across short runs".into(),
                    outcome: places::Outcome::Published,
                    policy,
                    terms: PreparationTerms::of::<places::Permit, (), ()>(shape).unwrap(),
                },
                places::Run {
                    name: "cancelled retained scratch source".into(),
                    outcome: places::Outcome::Cancelled,
                    policy: cancelled,
                    terms: PreparationTerms::of::<places::Permit, (), ()>(cancelled_shape).unwrap(),
                },
            ]);
            drop(plan);
        }

        /// A prepared source: its name, the place it witnesses if any, and
        /// where it is cancelled into its cleanup if it is.
        struct Source {
            name: String,
            requirement: Requirement,
            witnesses: Option<PreparationPlace>,
            schema: Box<dyn Schema>,
            cancel_after: Option<Cancel>,
        }

        /// Every place a preparation charges is within its term on every engine
        /// path, in work, requests, peak and what its plan retains; every
        /// admission and request is made at some place; each place's witness
        /// charges it. Beside the witnesses: long and disordered texts, root and
        /// ordered nested maps, keys that are maps or share long prefixes,
        /// values holding gaps before long payloads, a field map, deep frames,
        /// deep open maps, a wide entry cursor.
        #[test]
        fn every_place_of_a_preparation_is_within_its_term() {
            let mut frames: Box<dyn Schema> = Box::new(7u64);
            for _ in 0..100 {
                frames = Box::new(vec![frames]);
            }
            let mut maps: Box<dyn Schema> = Box::new(7u64);
            for _ in 0..8 {
                maps = Box::new(Wrap(maps));
            }
            let mut sources: Vec<Source> = PreparationPlace::ALL
                .iter()
                .flat_map(|&place| {
                    witness(place).into_iter().map(
                        move |(requirement, (name, schema, cancel_after))| Source {
                            name: format!("{name} ({place:?})"),
                            requirement,
                            witnesses: Some(place),
                            schema,
                            cancel_after,
                        },
                    )
                })
                .collect();
            let others: Vec<(&str, Box<dyn Schema>)> = vec![
                ("text", Box::new("x".repeat(70_000))),
                (
                    "disordered text",
                    Box::new(format!("q{}", "\u{301}\u{316}".repeat(1024))),
                ),
                ("texts", Box::new(vec!["e\u{301}".to_string(); 64])),
                (
                    "gaps",
                    Box::new((0..300).map(|_| Empty).collect::<Vec<_>>()),
                ),
                ("integers", Box::new((0..1000u64).collect::<Vec<_>>())),
                (
                    "root map",
                    Box::new(Pairs((0..200u64).rev().map(|n| (n, n)).collect())),
                ),
                (
                    "ordered map",
                    Box::new(vec![Pairs((0..64u64).map(|n| (n, vec![n; 4])).collect())]),
                ),
                (
                    "permuted map",
                    Box::new(vec![Pairs(
                        (0..64u64).rev().map(|n| (n, vec![n; 4])).collect(),
                    )]),
                ),
                (
                    "long keys",
                    Box::new(vec![Pairs(
                        (0..32u64)
                            .rev()
                            .map(|n| (format!("{}{n:03}", "k".repeat(200)), n))
                            .collect(),
                    )]),
                ),
                (
                    "map keys",
                    Box::new(Pairs(
                        (0..16u64)
                            .rev()
                            .map(|n| (Pairs(vec![(n, n), (n + 100, 0)]), vec![Empty, Empty]))
                            .collect(),
                    )),
                ),
                (
                    "gapped values",
                    Box::new(Pairs(
                        (0..32u64)
                            .rev()
                            .map(|n| (n, Pair(Empty, Raw(vec![n as u8; 4096]))))
                            .collect(),
                    )),
                ),
                ("field map", Box::new(Fields((0..256).collect()))),
                ("deep frames", frames),
                ("deep maps", maps),
                (
                    "wide cursor",
                    Box::new(Stepped((0..40u64).rev().map(|n| (n, n)).collect())),
                ),
                (
                    "large permuted map",
                    Box::new(vec![Pairs(
                        (0..512u64).rev().map(|n| (n, vec![n; 4])).collect(),
                    )]),
                ),
            ];
            for (name, schema) in others {
                sources.push(Source {
                    name: name.into(),
                    requirement: Requirement::Always,
                    witnesses: None,
                    schema,
                    cancel_after: None,
                });
            }
            // Cleanup's term charges the most any one arena drains, in values
            // and in bytes apart: its witness drains the plan's bytes, the
            // most elements; the descriptors, 32 bytes each, are the most
            // bytes. Cancelled while they relocate their last growth: an
            // uncounted map reserves a descriptor's slot before asking for
            // each instruction after its scan began, so the reservation
            // before its `End` grows the full arena of 64 and relocates all
            // 64.
            sources.push(Source {
                name: "cancelled descriptors".into(),
                requirement: Requirement::Always,
                witnesses: None,
                schema: Box::new(vec![Pairs(
                    (0..64u64).rev().map(|n| (n, vec![n; 4])).collect(),
                )]),
                cancel_after: Some(Cancel::Draining(|position| {
                    relocates(position.dynamic.entry_storage, 64)
                })),
            });
            let mut runs = Vec::new();
            let mut witnesses = Vec::new();
            let mut plans = Vec::new();
            let mut tightness = places::Tightness::new("preparation");
            for source in &sources {
                tightness.requires(&source.name, source.requirement);
                let (policy, shape, plan) = ledgered(source.schema.as_ref(), source.cancel_after)
                    .unwrap_or_else(|failure| panic!("{}: {failure:?}", source.name));
                assert_eq!(
                    plan.is_some(),
                    source.cancel_after.is_none(),
                    "{}: declared outcome not reached",
                    source.name
                );
                if let Some(place) = source.witnesses {
                    witnesses.push((runs.len(), place));
                }
                runs.push(places::Run {
                    name: source.name.clone(),
                    outcome: if source.cancel_after.is_some() {
                        places::Outcome::Cancelled
                    } else {
                        places::Outcome::Published
                    },
                    policy,
                    terms: PreparationTerms::of::<places::Permit, (), ()>(shape).unwrap(),
                });
                plans.push(plan);
            }
            places::check(&runs);
            places::witnessed(&runs, &witnesses);
            // The bound is at the source's own shape, so one source drives its
            // work and its storage together: every arena it grows is the one
            // its work fills, and its plan is what publication retains.
            let derivation = "a reversed unordered map nested in an array: every entry \
                              compacted, merged at every level of its map, compared, checked \
                              and permuted in place, the plan's bytes appended once and held";
            // The preparation's first phase, its shape's walk, against each
            // family's planning bound ([`discovery_bound`]) at its size edges
            // and an interior size: one run per discovery witness.
            let mut walks = Vec::new();
            let mut bounds = Vec::new();
            for (requirement, (name, source, families)) in super::discovery_cases() {
                let mut policy = places::Ledgered::new();
                Shape::of(source.as_ref(), &mut policy).expect("a witness has a shape");
                let name = format!("discovery {name}");
                tightness.requires(&name, requirement);
                bounds.push((
                    name.clone(),
                    discovery_bound(&families, &mut Limits::unlimited())
                        .expect("a witness's bound fits"),
                ));
                walks.push(places::Run {
                    name,
                    outcome: places::Outcome::Published,
                    policy,
                    terms: (),
                });
            }
            for (name, bound) in &bounds {
                tightness.joint_bound(
                    &walks,
                    name,
                    "discovery",
                    *bound,
                    places::WORK,
                    "one value of one family at a size, its children scalars: every \
                     instruction its source answers walked, its texts' bytes scanned and its \
                     cursor's moves and inspections stepped, priced from its declared sizes",
                );
            }
            tightness
                .places(&runs, &witnesses, |place| match place {
                    PreparationPlace::Instructions
                    | PreparationPlace::Pushes
                    | PreparationPlace::Frames
                    | PreparationPlace::Gaps
                    | PreparationPlace::OpenMaps
                    | PreparationPlace::Cursors
                    | PreparationPlace::EntryArena
                    | PreparationPlace::PlanBytes
                    | PreparationPlace::Appends
                    | PreparationPlace::Texts
                    | PreparationPlace::Compaction
                    | PreparationPlace::Merging
                    | PreparationPlace::Comparisons
                    | PreparationPlace::Scratch
                    | PreparationPlace::Check
                    | PreparationPlace::Permutation
                    | PreparationPlace::Visited
                    | PreparationPlace::Buckets
                    | PreparationPlace::Digits
                    | PreparationPlace::Completion
                    | PreparationPlace::Cleanup => places::Factor::Measured,
                })
                .joint(
                    &runs,
                    "permuted map (Permutation)",
                    places::EVERY,
                    derivation,
                )
                .joint(&runs, "large permuted map", places::EVERY, derivation)
                // Every engine path's bound at its own shape, recorded: a
                // term charged for what a source does not have moves a
                // record, as an understated one fails the check above.
                .totals(&runs, places::WORK)
                .finish();
            drop(plans);
        }
    }

    /// A walk admits one value per instruction and each text's bytes, counts
    /// the source's maps, entries and texts, and refuses what preparation
    /// refuses: more than 128 frames.
    #[test]
    fn a_shape_walk_admits_each_instruction_and_refuses_excess_depth() {
        let source = vec![vec![1u64, 2], vec![]];
        let mut limits = Limits::unlimited();
        let shape = Shape::of(&source, &mut limits).unwrap();
        // The outer array: head, two children, end; the first inner array:
        // head, two children, end; each integer: head, end; the empty inner
        // array: head, end.
        assert_eq!(shape.instructions, 4 + 4 + 2 + 2 + 2);
        assert_eq!(shape.depth, 3);
        // 0x82 0x82 0x01 0x02 0x80.
        assert_eq!(shape.extent, 5);
        assert_eq!(limits.used(), WriteWork::new(shape.instructions, 0));
        assert_eq!(
            (
                shape.bucket_tables,
                shape.maps,
                shape.unordered,
                shape.entries,
                shape.merges,
                shape.unordered_depth,
                shape.texts
            ),
            (0, 0, 0, 0, 0, 0, 0)
        );
        // An unordered map of two entries whose first key is itself an
        // unordered map of one entry, beside a field map holding a text.
        let keys = Pairs(vec![
            (Pairs(vec![(1u64, 2u64)]), "e\u{301}".to_string()),
            (Pairs(Vec::new()), "x".to_string()),
        ]);
        let source: Vec<Box<dyn Schema>> = vec![Box::new(keys), Box::new(Empty)];
        let mut limits = Limits::unlimited();
        let shape = Shape::of(&source, &mut limits).unwrap();
        // Entries yielded one per instruction enumerate no hash table.
        assert_eq!(
            (shape.bucket_tables, shape.buckets, shape.bucket_entries),
            (0, 0, 0)
        );
        assert_eq!(shape.maps, 4);
        assert_eq!(shape.unordered, 3);
        assert_eq!(shape.entries, 3);
        // Two entries merge over two levels, one over one, none over one.
        assert_eq!(shape.widest, 2);
        assert_eq!(shape.merge_levels, 2 + 1 + 1);
        assert_eq!(shape.merges, 2 * 2 + 1);
        // The outer map: its head, the key {1: 2} of three bytes, the text
        // of at most its parts' three bytes and head, the key {} and the
        // text "x". The field map and the array each a head.
        assert_eq!(shape.extent, 1 + (1 + 3 + 4 + 1 + 2) + 1);
        assert_eq!(shape.payloads, (3 + 4 + 1 + 2) + 2);
        assert_eq!(shape.largest_payload, 3 + 4 + 1 + 2);
        assert_eq!(shape.key_merges, (3 + 1) * 2 + 1);
        assert_eq!(shape.payload_probes, (3 + 4 + 1 + 2) * 2 + 2);
        assert_eq!(shape.unordered_depth, 2);
        assert_eq!(shape.texts, 2);
        assert_eq!(shape.longest_text, TextShape::of("e\u{301}"));
        assert_eq!(
            shape.normalization,
            text_cursor::normalization_bound::<()>(TextShape::of("e\u{301}"))
                .unwrap()
                .checked_followed_by(
                    text_cursor::normalization_bound::<()>(TextShape::of("x")).unwrap()
                )
                .expect("two small texts' normalization bounds fit in u64")
        );
        assert_eq!(limits.used(), WriteWork::new(shape.instructions, 3 + 1));
        let mut nested: Box<dyn Schema> = Box::new(7u64);
        for _ in 0..128 {
            nested = Box::new(vec![nested]);
        }
        assert_eq!(
            Shape::of(&nested, &mut Limits::unlimited()),
            Err(BoundedError::DepthLimit)
        );
    }

    /// The keys and values a [`Moving`] cursor yields.
    static MOVING: [u64; 2] = [1, 2];

    /// An unordered map of two entries drawn by a cursor that states its
    /// count of node moves per transition, after an inspection of as many
    /// values.
    struct Moving(u64);

    impl Schema for Moving {
        fn instruction(&self, index: usize) -> Instruction<'_> {
            match index {
                0 => Instruction::Inspect(self.0),
                1 => Instruction::UnorderedMap,
                2 => Instruction::Entries(self),
                _ => Instruction::End,
            }
        }
    }

    // SAFETY: `start` stores a `usize` index that `next` reads back; the
    // cursor refers to nothing.
    unsafe impl Entries for Moving {
        fn start(&self, slot: &mut Slot) {
            slot.put(0usize);
        }

        fn moves(&self) -> u64 {
            self.0
        }

        fn ordered(&self) -> bool {
            false
        }

        unsafe fn next<'a>(&'a self, slot: &mut Slot) -> EntryStep<'a> {
            // SAFETY: `start` stored this cursor's index.
            let at = unsafe { slot.get::<usize>() };
            match MOVING.get(*at) {
                Some(key) => {
                    *at += 1;
                    EntryStep::Entry(key, key)
                }
                None => EntryStep::End,
            }
        }
    }

    /// A walk admits a cursor's stated node moves and a source's
    /// inspections in units of at most a turn's values, as the preparation
    /// does, and a count of none in no unit: its work is still one value per
    /// move and per inspection ([`walk_work`]).
    #[test]
    fn a_shape_walk_admits_moves_and_inspections_within_a_turn() {
        for moves in [0u64, 1, 3, 7] {
            let session = Session::new(Capacity {
                permits: 16,
                events: 4096,
            });
            let mut limits = Limits::recorded_unlimited(&session);
            let shape = Shape::of(&Moving(moves), &mut limits).unwrap();
            // Twice for the start and the first transition, once for each
            // transition after it: the second entry and the end.
            assert_eq!(shape.moves, 4 * moves, "{moves} moves");
            assert_eq!(shape.inspected, moves, "{moves} moves");
            assert_eq!(shape.entries, 2, "{moves} moves");
            limits.assert_units(TURN);
            assert!(
                !limits.calls().contains(&Call::Work {
                    values: 0,
                    bytes: 0
                }),
                "{moves} moves: an empty unit admitted: {:?}",
                limits.calls()
            );
            assert_eq!(
                limits.used(),
                walk_work::<()>(shape).unwrap(),
                "{moves} moves"
            );
            drop(limits);
            session.finish().unwrap_or_else(|incomplete| {
                panic!("{moves} moves: the walk's recording is incomplete: {incomplete:?}")
            });
        }
    }

    /// A field map whose field `i` holds its `i`th value.
    struct FieldsOf(Vec<u64>);

    impl Schema for FieldsOf {
        fn instruction(&self, index: usize) -> Instruction<'_> {
            match index {
                0 => Instruction::Map,
                index => match self.0.get(index - 1) {
                    Some(value) => Instruction::Field((index - 1) as u64, Some(value)),
                    None => Instruction::End,
                },
            }
        }
    }

    /// One discovery witness: its name, a source of one family at a size,
    /// its children scalars, and the families of its nodes, children
    /// included.
    type DiscoveryInput = (String, Box<dyn Schema>, Vec<ShapeFamily>);
    type Discovery = (Requirement, DiscoveryInput);

    /// A source of every family at its size edges and one interior size,
    /// each child a scalar: the family, then a scalar per child.
    fn discovery_cases() -> Vec<Discovery> {
        let scalars = |count: u64| vec![ShapeFamily::Scalar; count as usize];
        let with = |head: ShapeFamily, children: u64| {
            let mut families = vec![head];
            families.extend(scalars(children));
            families
        };
        let mut cases: Vec<DiscoveryInput> = vec![(
            "scalar".into(),
            Box::new(7u64),
            with(ShapeFamily::Scalar, 0),
        )];
        for len in [0usize, 1, 4096] {
            cases.push((
                format!("bytes of {len}"),
                Box::new(crate::ByteString::from(vec![0x5a; len])),
                with(ShapeFamily::Bytes, 0),
            ));
        }
        for len in [0u64, 1, 64, 65, 1000] {
            cases.push((
                format!("text of {len}"),
                Box::new("x".repeat(len as usize)),
                with(ShapeFamily::Text { bytes: len }, 0),
            ));
        }
        for elements in [0u64, 1, 23, 24, 100] {
            cases.push((
                format!("array of {elements}"),
                Box::new(vec![0u64; elements as usize]),
                with(ShapeFamily::Array { elements }, elements),
            ));
        }
        cases.push((
            "tagged".into(),
            Box::new(Tagged {
                tag: 42,
                value: 7u64,
            }),
            with(ShapeFamily::Tagged, 1),
        ));
        cases.push((
            "wrapped".into(),
            Box::new(Some(7u64)),
            with(ShapeFamily::Wrapped, 1),
        ));
        for fields in [0u64, 1, 5] {
            cases.push((
                format!("field map of {fields}"),
                Box::new(FieldsOf((0..fields).collect())),
                with(ShapeFamily::FieldMap { fields }, fields),
            ));
        }
        for entries in [0u64, 1, 5] {
            cases.push((
                format!("entry map of {entries}"),
                Box::new(Pairs((0..entries).map(|n| (n, n)).collect())),
                with(ShapeFamily::EntryMap { entries }, 2 * entries),
            ));
        }
        // An inspection, then a cursor of two entries stating its moves.
        for moves in [0u64, 1, 3, 7] {
            let mut families = vec![
                ShapeFamily::Inspect { values: moves },
                ShapeFamily::CursorMap { entries: 2, moves },
            ];
            families.extend(scalars(4));
            cases.push((
                format!("cursor of {moves} moves"),
                Box::new(Moving(moves)),
                families,
            ));
        }
        // A bignum is part of the representation projection (`.num-bigint`),
        // measured by every build of it: no capability gates it.
        #[cfg(feature = "num-bigint")]
        cases.push((
            "bignum".into(),
            Box::new(num_bigint::BigUint::from(1u8) << 4095usize),
            with(ShapeFamily::Bignum, 0),
        ));
        let cases = cases.into_iter().map(|case| (Requirement::Always, case));
        // A hash table is a case only a build with hashbrown executes.
        #[cfg(feature = "hashbrown")]
        let cases = cases.chain([0u64, 1, 5].map(|entries| {
            let mut table = hashbrown::HashTable::new();
            for key in 0..entries {
                table.insert_unique(key, (key, key), |pair: &(u64, u64)| pair.0);
            }
            let buckets = table.num_buckets() as u64;
            (
                Requirement::Capability(Capability::Hashbrown),
                (
                    format!("hash table of {entries}"),
                    Box::new(table) as Box<dyn Schema>,
                    with(ShapeFamily::BucketMap { buckets, entries }, 2 * entries),
                ),
            )
        }));
        cases.collect()
    }

    /// The work [`Shape::of`] admits walking `source`.
    fn walked(source: &dyn Schema) -> WriteWork {
        let mut limits = Limits::unlimited();
        Shape::of(source, &mut limits).expect("a witness has a shape");
        limits.used()
    }

    /// Every family's planning bound covers what [`Shape::of`] admits at its
    /// size edges and an interior size, its children's families summed
    /// beside it ([`discovery_bound`]), which admits a value per family
    /// itself; each family's own bound is [`walk_work`] of its counts.
    #[test]
    fn every_familys_discovery_bound_covers_its_walk() {
        for (_, (name, source, families)) in discovery_cases() {
            let mut planning = Limits::unlimited();
            let bound = discovery_bound(&families, &mut planning).expect("a witness's bound fits");
            assert_eq!(
                planning.used(),
                WriteWork::new(families.len() as u64, 0),
                "{name}: planning admitted other than a value per family"
            );
            let walk = walked(source.as_ref());
            assert!(
                bound.work().covers(&walk),
                "{name}: walked {walk:?} beyond its bound {bound:?}"
            );
            assert_eq!(
                families[0].discovery::<()>().unwrap(),
                walk_work::<()>(families[0].shape::<()>().unwrap()).unwrap(),
                "{name}: a family's bound is not walk_work of its counts"
            );
        }
    }

    /// Planted control: a planning bound undercounting a text by one byte
    /// is refused by the witness of every text of at least one byte.
    #[test]
    fn an_undercounted_text_family_fails_its_witness() {
        let undercounted = |families: &[ShapeFamily]| -> WriteWork {
            let families: Vec<ShapeFamily> = families
                .iter()
                .map(|family| match *family {
                    ShapeFamily::Text { bytes } if bytes > 0 => {
                        ShapeFamily::Text { bytes: bytes - 1 }
                    }
                    other => other,
                })
                .collect();
            discovery_bound(&families, &mut Limits::unlimited())
                .expect("a witness's bound fits")
                .work()
        };
        let mut refused = 0;
        for (_, (name, source, families)) in discovery_cases() {
            let Some(ShapeFamily::Text { bytes }) = families.first().copied() else {
                continue;
            };
            if bytes == 0 {
                continue;
            }
            let walk = walked(source.as_ref());
            assert!(
                !undercounted(&families).covers(&walk),
                "{name}: an undercounted bound covered its walk"
            );
            refused += 1;
        }
        assert!(refused > 0, "no text witness of a byte or more");
    }

    /// An integer whose source inspects as many values before its head: no
    /// map and no cursor, so no unit but the inspection's admits several
    /// values and no bytes.
    struct Inspected(u64);

    impl Schema for Inspected {
        fn instruction(&self, index: usize) -> Instruction<'_> {
            match index {
                0 => Instruction::Inspect(self.0),
                1 => Instruction::Head(MajorType::Unsigned, Argument::Shortest(self.0)),
                _ => Instruction::End,
            }
        }
    }

    /// A preparation admits an announced inspection of more values than a
    /// turn holds in units of at most a turn's values, the remainder kept
    /// between them: seven values as three, three and one, consecutively,
    /// before the instruction that follows; then the integer encodes exactly.
    #[test]
    fn a_preparation_admits_a_wide_inspection_a_turn_at_a_time() {
        let source = Inspected(7);
        let shape = Shape::of(&source, &mut Limits::unlimited()).expect("an integer has a shape");
        let bound = prepare_bound::<Reservation, Family, ()>(shape).expect("the bound fits in u64");
        let session = Session::new(Capacity {
            permits: 64,
            events: 4096,
        });
        let mut limits = Limits::recorded_unlimited(&session);
        let mut preparation = Preparation::<Reservation, Family>::new(&source);
        let plan = within(
            "a wide inspection's preparation",
            bound,
            || match preparation.step(&mut limits).unwrap() {
                Step::Progress => ControlFlow::Continue(()),
                Step::Complete(plan) => ControlFlow::Break(plan),
                Step::Finished => panic!("finished without a plan"),
            },
        );
        limits.assert_units(TURN);
        let unit = |values| Call::Work { values, bytes: 0 };
        assert!(
            limits
                .calls()
                .windows(3)
                .any(|calls| calls == [unit(3), unit(3), unit(1)]),
            "seven inspected values not admitted as 3, 3, 1: {:?}",
            limits.calls()
        );
        let mut bytes = vec![0; plan.len()];
        plan.encode_into(&mut bytes, &mut Limits::unlimited())
            .expect("an unlimited policy admits the write");
        assert_eq!(bytes, [0x07]);
        // The plan's permits are the session's records: everything holding
        // them drops before the session finishes.
        drop((plan, preparation, limits));
        session.finish().unwrap_or_else(|incomplete| {
            panic!("the preparation's recording is incomplete: {incomplete:?}")
        });
    }

    /// A bignum being prepared is observed through the preparation's
    /// position: the digits its scan has read, a quantum's eight at a time,
    /// then, its head staged, the digits its emission has read, from none
    /// again; and nothing once its bytes are staged.
    #[cfg(feature = "num-bigint")]
    #[test]
    fn a_bignums_passes_are_observed_digit_unit_by_digit_unit() {
        // 2^4095: 64 digits, eight units per pass.
        let source = num_bigint::BigUint::from(1u8) << 4095usize;
        let shape = Shape::of(&source, &mut Limits::unlimited()).expect("a bignum has a shape");
        let bound = prepare_bound::<Reservation, Family, ()>(shape).expect("the bound fits in u64");
        let mut limits = Limits::unlimited();
        let mut preparation = Preparation::<Reservation, Family>::new(&source);
        let mut observed: Vec<(usize, bool)> = Vec::new();
        let plan = within("a bignum's preparation", bound, || {
            if let Some(position) = preparation.position().bignum
                && observed.last() != Some(&position)
            {
                observed.push(position);
            }
            match preparation.step(&mut limits).unwrap() {
                Step::Progress => ControlFlow::Continue(()),
                Step::Complete(plan) => ControlFlow::Break(plan),
                Step::Finished => panic!("finished without a plan"),
            }
        });
        assert_eq!(preparation.position().bignum, None);
        let expected: Vec<(usize, bool)> = [false, true]
            .into_iter()
            .flat_map(|emitting| (0..64).step_by(8).map(move |read| (read, emitting)))
            .collect();
        assert_eq!(observed, expected);
        // Tag 2, a byte string of 512 bytes: a one, then zeros.
        assert_eq!(plan.len(), 1 + 3 + 512);
    }

    #[test]
    fn overflowing_preparation_bounds_are_typed_errors() {
        let shape = Shape {
            extent: u64::MAX,
            instructions: 1,
            depth: 1,
            ..Shape::default()
        };
        assert_eq!(
            prepare_bound::<Reservation, Family, ()>(shape),
            Err(BoundedError::Overflow)
        );
    }
}

/// The plan record's cleanup ([`Planned`]), driven record by record under a
/// recorded session, whose finish refuses while any owner, family, permit or
/// held obligation of it lives ([`Session::finish`]): the drained
/// preparation is dropped in place, so its arenas' and its own owners
/// release their session references exactly once. Planted control
/// `tests/data/controls/plan-preparation-undropped.patch` (the drained
/// preparation left in the record) keeps the session live.
#[cfg(all(test, feature = "std"))]
mod plan_record {
    use super::*;
    use crate::ByteString;
    use crate::bounded::decode::Options;
    use crate::bounded::decode::construction::cuts::{completed, every_cut, scope};
    use crate::bounded::decode::construction::{Construction, DecodeOwner, DocumentDecoder};
    use crate::bounded::{Capacity, Limits, Session};

    /// The text "first", canonical.
    const TEXT: [u8; 6] = [0x65, b'f', b'i', b'r', b's', b't'];

    /// An initialized scope of `a` and the text decoded into a value it
    /// holds.
    fn decoded(
        a: &mut Limits,
    ) -> (
        DecodeOwner<'static, Limits>,
        TypedValue<'static, ByteString, String, Limits>,
    ) {
        let owner = scope(a);
        let input = completed(owner.copy_input(&TEXT), a);
        let document = completed(DocumentDecoder::parse(input, Options::normalizing(8)), a);
        let value = completed(
            Construction::<'static, ByteString, String, Limits>::construct(document),
            a,
        );
        assert_eq!(value.value(), "first");
        (owner, value)
    }

    /// The record published and cleaned up, then cancelled at every step of
    /// its task, its initialization prefix in part and whole and its
    /// preparation under way ([`every_cut`]): every capability released
    /// exactly once, and after `Done`, released prefix or `PlanPhase::Done`,
    /// nothing admitted, initialization and advance refused, and no
    /// preparation observed: a complete record's dropped, a released one's
    /// never read.
    #[test]
    fn a_plan_records_cleanup_releases_every_capability_and_admits_nothing_after_done() {
        every_cut(
            "a plan record",
            |a| {
                let (owner, value) = decoded(a);
                (
                    owner,
                    Prepare {
                        source: Some(value),
                    },
                )
            },
            |detail: &PlanDetail, released, what| {
                assert_eq!(
                    detail.preparation, None,
                    "{what}: a preparation observed after Done"
                );
                if released {
                    assert_eq!(detail.phase, None, "{what}: a released record's phase read");
                } else {
                    assert_eq!(detail.phase, Some(PlanPhase::Done), "{what}");
                    assert!(!detail.source, "{what}: the released source observed");
                }
            },
        );
    }

    /// A published plan dropped, its record queued in the scope, and the
    /// scope abandoned: the authority's drop releases the last reference
    /// and the terminal drain reclaims the record, every capability released
    /// exactly once.
    #[test]
    fn a_dropped_plan_is_released_by_its_scopes_terminal_drain() {
        let session = Session::new(Capacity {
            permits: 1 << 10,
            events: 1 << 14,
        });
        let mut a = Limits::recorded_unlimited(&session);
        let (owner, value) = decoded(&mut a);
        let plan = completed(OwnedPreparation::prepare(value), &mut a);
        assert_eq!(plan.len(), TEXT.len());
        drop(plan);
        drop(owner);
        assert_eq!(a.live_bytes(), 0, "storage kept");
        drop(a);
        session.finish().unwrap_or_else(|incomplete| {
            panic!("the terminal drain's recording is no evidence: {incomplete:?}")
        });
    }
}
