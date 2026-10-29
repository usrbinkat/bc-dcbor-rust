//! Retained schema traversal and canonical byte preparation.
use super::*;
use core::mem::{MaybeUninit, size_of};
use core::ptr::{NonNull, addr_of, addr_of_mut};
use decode::construction::in_place::{InPlace, Transferable};
// The record destination is named `reclamation::Place` here: the bare name is
// the accounting trait `bounded::Place`, which `PreparationPlace::ALL` needs.
// A destination's slot is named `reclamation::Slot` for the same reason: the
// bare name is this module's entry-cursor storage, [`Slot`].
use decode::construction::reclamation::{self, PeekSlot, Prefix, Reclaim, Reclaimed, ScopeRef};
use decode::construction::{
    DecodeInput, Observed, Operation, OperationTerms, OwnedInitialized, Task, TypedValue,
};
use decode::initialization::field;
use decode::storage::Storage;
use text_cursor::{TextContinuation, TextShape};
#[cfg(feature = "hashbrown")]
pub mod buckets;
mod dynamic;
mod permutation;
pub use permutation::{PermutationPhase, PermutationPosition};
pub mod maps;
pub use dynamic::{DynamicPhase, DynamicPosition};
mod values;
pub use values::Tagged;
#[cfg(not(feature = "custom-std-collections"))]
pub(crate) use values::ranged;
#[cfg(feature = "custom-std-collections")]
pub(crate) use values::stepped;
mod writer;
pub use writer::{EmitPosition, OwnedEmitPosition, OwnedEmitStep, OwnedWriter, emit_bound};

/// One bounded-work schema instruction. Implementations must not scan fields,
/// allocate, or recursively visit children while producing an instruction.
/// Dynamic map entries may inspect at most [`BUCKET_WINDOW`] indexed bucket
/// controls, yielding at most one entry. `Entry::next` advances by 1 through
/// [`BUCKET_WINDOW`] instructions.
/// The engine validates this advance; implementations remain responsible for
/// bounding the actual work performed before returning the instruction.
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
/// Every reference returned by every reachable instruction must remain valid
/// and safe to access on any thread while the root is retained unchanged.
/// This includes descendants, pending entry values, entry sources, text, bytes,
/// and bignum digits, even when they are not owned directly by the root.
/// Every initialized `Entries` slot reachable from this schema must likewise
/// permit thread transfer at every suspension point. No cursor may rely on
/// thread-local state or thread-affine resources. These obligations apply
/// recursively; `Self: Sync` alone does not establish them.
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
        // SAFETY: scalar instructions retain no external state. Strings and
        // byte strings expose only immutable storage held by their root.
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

// SAFETY: traversal delegates only to elements covered by the same recursive
// contract, and retains no thread-affine cursor state.
unsafe impl<T: TransferableSchema> TransferableSchema for Vec<T> {}
unsafe impl<T: TransferableSchema, const N: usize> TransferableSchema for [T; N] {}
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
    /// Up to [`BUCKET_WINDOW`] inspected buckets, yielding at most one entry.
    /// `next` is the instruction index after the last inspected bucket,
    /// including vacancies.
    Entry {
        next: usize,
        entry: Option<(&'a dyn Schema, &'a dyn Schema)>,
    },
    /// The entries of the unordered map this source began, drawn from a
    /// cursor the engine retains, for collections without positional access.
    /// Valid once per map, before any entry; no further instruction of this
    /// source is requested.
    Entries(&'a dyn Entries),
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
/// `start` must [`Slot::put`] a cursor that `next` reads back as the same type.
/// The cursor may borrow `self`, which the preparation borrow keeps unchanged;
/// it must not refer to its own storage, because the arena holding it moves.
/// [`Self::moves`] bounds the moves of every call and is fixed for the
/// borrow.
/// When reachable from a `TransferableSchema`, the initialized cursor and
/// every reference it yields must additionally satisfy that trait's recursive
/// thread-transfer contract at every suspension point. A slot's size and lack
/// of drop glue do not establish that contract.
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

fn check_entry_next<R>(after: usize, next: usize) -> Result<(), BoundedError<R>> {
    if next < after || next - after >= BUCKET_WINDOW {
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
/// cloned or destroyed by cancellation of encoding. A terminal error finishes
/// the preparation; [`Self::reclaim_step`] then releases its arenas in
/// admitted units, and dropping it releases whatever remains.
///
/// ```compile_fail,E0502
/// use dcbor::bounded::encoding::Preparation;
/// let mut source = vec![1u64, 2];
/// let operation = Preparation::<()>::new(&source);
/// source.push(3);
/// drop(operation);
/// ```
pub struct Preparation<'a, P> {
    frames: Storage<Frame<'a>, P>,
    bytes: Storage<u8, P>,
    holes: Storage<(usize, usize), P>,
    child: Option<&'a dyn Schema>,
    staged: Staged,
    payload: &'a [u8],
    /// The normalization of the current text. It holds nothing between texts
    /// and is initialized again, in admitted units, for each text after the
    /// first.
    text: TextContinuation<(), P>,
    /// The text being normalized.
    text_source: Option<&'a str>,
    /// Initialization units of `text` performed for `text_source`.
    text_init: usize,
    /// The quick check of `text_source` while it reads: a text it proves
    /// normal is copied as it is; one it leaves unproven, with this `None`,
    /// is normalized.
    text_check: Option<TextCheck>,
    normalized: Option<Encoded<P>>,
    normalized_at: usize,
    omitted: usize,
    finished: bool,
    dynamic: dynamic::Dynamic<P>,
    map_frames: Storage<MapFrame<'a>, P>,
    /// The retained cursors of the open [`Instruction::Entries`] maps,
    /// innermost last.
    cursors: Storage<(&'a dyn Entries, Slot), P>,
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
        let mut end = text
            .len()
            .min(self.at + decode::construction::stable::QUANTUM);
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
    pub(crate) fn fill<R>(&mut self, bytes: &[u8]) -> Result<(), BoundedError<R>> {
        if !self.is_empty() || bytes.len() > self.bytes.len() {
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

/// What completing a preparation yields from its plan's arenas, both
/// settled by the unit that completes it: an owned value, so completion
/// hands back no borrow of the preparation.
trait Completion<P> {
    type Output;

    fn complete(
        bytes: &mut Owned<u8, P>,
        holes: &mut Owned<(usize, usize), P>,
        len: usize,
    ) -> Self::Output;
}

/// Completion that moves the plan's arenas into a [`Prepared`], leaving the
/// preparation's empty.
struct Publish;

impl<P> Completion<P> for Publish {
    type Output = Prepared<P>;

    fn complete(
        bytes: &mut Owned<u8, P>,
        holes: &mut Owned<(usize, usize), P>,
        len: usize,
    ) -> Prepared<P> {
        Prepared {
            bytes: core::mem::take(bytes),
            holes: core::mem::take(holes),
            len,
        }
    }
}

/// Completion that keeps the plan in place, for an owned preparation that
/// emits it there ([`Preparation::view`]).
struct Kept;

impl<P> Completion<P> for Kept {
    type Output = ();

    fn complete(_: &mut Owned<u8, P>, _: &mut Owned<(usize, usize), P>, _: usize) {}
}

impl<'a, P> Preparation<'a, P> {
    const TEXT_STEPS: usize = TextContinuation::<(), P>::INIT_STEPS;
    const STORAGE_STEPS: usize = Storage::<u8, P>::INIT_STEPS;
    /// The scalar fields [`Self::initialize_step`] writes one per unit, the
    /// staged bytes' three among them, each at most a quantum: the bignum's
    /// only where bignums are encoded.
    const SCALARS: usize = 14 + cfg!(feature = "num-bigint") as usize;

    /// Every unit of [`Self::initialize_step`]: five arenas, the text
    /// normalization, the dynamic map engine, and the scalar fields.
    pub(crate) const INIT_STEPS: usize = 5 * Self::STORAGE_STEPS
        + Self::TEXT_STEPS
        + dynamic::Dynamic::<P>::INIT_STEPS
        + Self::SCALARS;

    /// A preparation of `source` whose plan arena grows to at most `cap`
    /// bytes: what [`prepare`](super::prepare) gives a source whose extent
    /// a shape walk established, so the arena it publishes holds the
    /// encoding and its gaps and no more. A cap below what the source
    /// appends is refused as [`BoundedError::PlanMismatch`] at the growth
    /// that would pass it.
    pub fn capped(source: &'a dyn Schema, cap: usize) -> Self {
        Self {
            cap,
            ..Self::new(source)
        }
    }

    pub fn new(source: &'a dyn Schema) -> Self {
        Self {
            frames: Storage::new(),
            bytes: Storage::new(),
            holes: Storage::new(),
            child: Some(source),
            staged: Staged::new(),
            payload: &[],
            text: TextContinuation::new(()),
            text_source: None,
            text_init: Self::TEXT_STEPS,
            text_check: None,
            normalized: None,
            normalized_at: 0,
            omitted: 0,
            finished: false,
            dynamic: dynamic::Dynamic::new(),
            map_frames: Storage::new(),
            cursors: Storage::new(),
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
    pub(crate) fn initialize_step<A: Allocator<Permit = P>>(
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
                if *slot.custody() < base + $steps {
                    init_part!(slot, $field, base, |$part| $init);
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
        part!(text, Self::TEXT_STEPS, |part| {
            TextContinuation::initialize_step(part, (), a)?
        });
        part!(dynamic, dynamic::Dynamic::<P>::INIT_STEPS, |part| {
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
            10 => init_field!(slot, finished, || false, a)?,
            // An owned plan is emitted in place, gaps skipped, never
            // published as an arena: it grows uncapped.
            11 => init_field!(slot, cap, || usize::MAX, a)?,
            12 => init_field!(slot, inspect, || None, a)?,
            13 => init_field!(slot, text_check, || None, a)?,
            #[cfg(feature = "num-bigint")]
            14 => init_field!(slot, bignum, || None, a)?,
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
            finished: self.finished,
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
            normalization: (self.text_init == Self::TEXT_STEPS).then(|| self.text.position()),
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
    fn append<A: Allocator<Permit = P>>(
        storage: &mut Storage<u8, P>,
        cap: usize,
        source: &[u8],
        a: &mut A,
    ) -> BoundedResult<usize, A> {
        let Some(spare) = at(PreparationPlace::PlanBytes, || storage.reserve_step(cap, a))? else {
            return Ok(0);
        };
        let count = source
            .len()
            .min(decode::construction::stable::QUANTUM)
            .min(spare.room());
        APPEND.admit(a, widen(count)?)?;
        Ok(spare.extend(&source[..count]))
    }

    /// One step, publishing the plan by moving its arenas out.
    pub fn step<A: Allocator<Permit = P>>(
        &mut self,
        a: &mut A,
    ) -> BoundedResult<Step<Prepared<P>>, A> {
        if self.finished {
            return Ok(Step::Finished);
        }
        Ok(match self.prepare_step::<Publish, A>(a)? {
            Some(prepared) => Step::Complete(prepared),
            None => Step::Progress,
        })
    }

    /// One step, completing the plan as `C` does: moved out, or kept in
    /// place, readable through [`Self::view`]. A terminal error or completion
    /// finishes the preparation.
    fn prepare_step<C: Completion<P>, A: Allocator<Permit = P>>(
        &mut self,
        a: &mut A,
    ) -> BoundedResult<Option<C::Output>, A> {
        if self.finished {
            return Err(BoundedError::PlanMismatch);
        }
        let result = self.advance::<C, A>(a);
        if matches!(&result, Ok(Some(_))) || matches!(&result, Err(e) if !e.refused()) {
            self.finished = true;
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
    pub fn reclaim_step<A: Allocator<Permit = P>>(
        &mut self,
        a: &mut A,
    ) -> BoundedResult<Reclaimed, A> {
        self.finished = true;
        let cleanup = PreparationPlace::Cleanup;
        if self.text.position().phase != text_cursor::Phase::Finished {
            at(cleanup, || self.text.reclaim_step(a))?;
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
            at(cleanup, || self.cursors.reclaim_copy_step(a))?;
        } else if !self.dynamic.is_released() {
            at(cleanup, || self.dynamic.reclaim_step(a))?;
        } else {
            CLEANUP_DONE.admit(a)?;
            self.release_source();
            return Ok(Reclaimed::Done);
        }
        Ok(Reclaimed::Progress)
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
    /// nothing.
    pub(crate) fn reclaim_remaining(&self) -> u64 {
        let text = if self.text.position().phase != text_cursor::Phase::Finished {
            self.text.reclaim_remaining()
        } else {
            0
        };
        [
            text,
            u64::from(self.normalized.is_some()),
            self.frames.unreleased_remaining(),
            self.map_frames.unreleased_remaining(),
            self.bytes.unreleased_remaining(),
            self.holes.unreleased_remaining(),
            self.cursors.unreleased_remaining(),
            self.dynamic.reclaim_remaining(),
            1,
        ]
        .into_iter()
        .fold(0, u64::saturating_add)
    }

    /// One unit of preparation: the plan as `C` completes it, once complete.
    fn advance<C: Completion<P>, A: Allocator<Permit = P>>(
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
            if self.normalized_at < encoded.as_ref().len() {
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
            let count = values.min(UNIT_VALUES);
            INSPECTED.admit(a, count)?;
            self.inspect = (values > count).then(|| values - count);
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
            if self.text_init < Self::TEXT_STEPS {
                // SAFETY: the continuation's place is rooted at an exclusive
                // borrow of this field, valid, aligned and writable for it,
                // and no place derived from it outlives this call; its units
                // are `text_init`, which counts exactly the fields rewritten
                // for this text. The previous text published, so the
                // continuation holds nothing; each unit rewrites one
                // resource-free field.
                let continuation = unsafe {
                    reclamation::Slot::new(
                        reclamation::Place::root(NonNull::from(&mut self.text).cast()),
                        &mut self.text_init,
                    )
                };
                at(PreparationPlace::Texts, || {
                    TextContinuation::initialize_step(continuation, (), a)
                })?;
                return Ok(None);
            }
            match at(PreparationPlace::Texts, || self.text.step_source(text, a))? {
                Step::Progress => {}
                Step::Complete(value) => {
                    self.normalized = Some(value);
                    self.text_source = None;
                }
                Step::Finished => return Err(BoundedError::PlanMismatch),
            }
            return Ok(None);
        }
        if let Some(source) = self.child {
            if self.frames.len() >= 128 {
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
            let bytes = &mut self.bytes;
            let Some(bytes) = at(PreparationPlace::PlanBytes, || bytes.settle_step(a))? else {
                return Ok(None);
            };
            let holes = &mut self.holes;
            let Some(holes) = at(PreparationPlace::Gaps, || holes.settle_step(a))? else {
                return Ok(None);
            };
            DONE.admit(a)?;
            let len = bytes
                .len()
                .checked_sub(self.omitted)
                .ok_or(BoundedError::Overflow)?;
            return Ok(Some(C::complete(bytes, holes, len)));
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
        let cursors = &mut self.cursors;
        let Some(mut cursors) = at(PreparationPlace::Cursors, || {
            cursors.reserve_step(usize::MAX, a)
        })?
        else {
            return Ok(None);
        };
        let top = match frame.map {
            Some(index) => Some(
                maps.as_slice()
                    .get(index)
                    .ok_or(BoundedError::PlanMismatch)?,
            ),
            None => None,
        };
        let dynamic = top.is_some_and(|map| matches!(map.state, MapState::Dynamic { .. }));
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
        let instruction = if complete {
            // The end, admitted as any instruction of the map: no cursor
            // transition is made, so no node move.
            CURSOR.admit(a)?;
            if frame.ordered {
                cursors.pop();
                frame.ordered = false;
            }
            Instruction::End
        } else if frame.ordered {
            // One admitted cursor transition per instruction, as an indexed
            // entry advancing by exactly one; a structural transition is a
            // vacant entry. The node moves the cursor states for the
            // transition, twice over for the one that starts it, are
            // admitted before it in units of at most `UNIT_VALUES`, so no
            // unit is wider than a turn whatever the tree's height.
            let (entries, slot) = cursors
                .as_mut_slice()
                .last_mut()
                .ok_or(BoundedError::PlanMismatch)?;
            let entries: &'a dyn Entries = *entries;
            let moves = if frame.fresh {
                mul(entries.moves(), 2)?
            } else {
                entries.moves()
            };
            if frame.moved < moves {
                let count = (moves - frame.moved).min(UNIT_VALUES);
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
            let next = frame.next.checked_add(1).ok_or(BoundedError::Overflow)?;
            // SAFETY: the top cursor was started by this frame's own source.
            match unsafe { entries.next(slot) } {
                EntryStep::Progress => Instruction::Entry { next, entry: None },
                EntryStep::Entry(key, value) => Instruction::Entry {
                    next,
                    entry: Some((key, value)),
                },
                EntryStep::End => {
                    cursors.pop();
                    frame.ordered = false;
                    Instruction::End
                }
            }
        } else {
            if dynamic {
                CURSOR.admit(a)?;
            } else {
                INDEXED.admit(a)?;
            }
            source.instruction(frame.next)
        };
        frame.next = frame.next.checked_add(1).ok_or(BoundedError::Overflow)?;
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
                // Between texts the continuation is fresh or published; only a
                // published one is initialized again.
                self.text_init = if self.text.position().phase == text_cursor::Phase::Read {
                    Self::TEXT_STEPS
                } else {
                    0
                };
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
                // moves are admitted with it.
                cursors.push((entries, Slot::new()));
                frame.ordered = true;
                frame.fresh = true;
            }
            Instruction::Entry { next, entry } => {
                // frame.next already includes the one-instruction increment.
                // Subtraction avoids overflow at the upper index boundary.
                check_entry_next(frame.next, next)?;
                frame.next = next;
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
                if let Some((key, value)) = entry {
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
    /// The schema instructions it answers: every `End`, omitted field,
    /// vacant bucket range and cursor transition included.
    pub instructions: u64,
    /// The instructions among them answered after their source began an
    /// unordered map: each may inspect up to 64 bytes of bucket controls,
    /// where any other inspects at most a head.
    pub dynamic: u64,
    /// The most frames open at once: the root and each child within its
    /// parent. The engine refuses more than 128.
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
    /// inspections in units of at most a turn's values ([`admit_stepped`]), and
    /// each source text's bytes once, scanned for its decomposition; nothing
    /// is allocated ([`walk_work`]). Refused beyond the engine's 128 frames,
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

    /// One instruction of the walk, admitted and counted; `dynamic` when its
    /// source began an unordered map before it.
    fn instruction<B: Budget>(&mut self, dynamic: bool, budget: &mut B) -> BoundedResult<(), B> {
        WALKED.admit(budget)?;
        self.instructions = add(self.instructions, 1)?;
        self.dynamic = add(self.dynamic, u64::from(dynamic))?;
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
            .followed_by(text_cursor::normalization_bound(shape)?)?;
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
        if depth > 128 {
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
            self.instruction(within > unordered, budget)?;
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
                Instruction::Entry { next, entry } => {
                    check_entry_next(index.checked_add(1).ok_or(BoundedError::Overflow)?, next)?;
                    if within == unordered {
                        return Err(BoundedError::PlanMismatch);
                    }
                    let entries = map.as_mut().ok_or(BoundedError::PlanMismatch)?;
                    if let Some(entry) = entry {
                        self.entry(entries, entry, depth, within, budget)?;
                    }
                    index = next;
                    continue;
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
                        self.instruction(true, budget)?;
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

/// The work a walk of a source of `shape` reports ([`Shape::of`]): one value
/// per instruction, per entry cursor move and per inspection, and each
/// text's bytes once. A walk allocates nothing.
pub fn walk_work<R>(shape: Shape) -> Result<WriteWork, BoundedError<R>> {
    WALKED
        .times(shape.instructions)?
        .then(STEPPED.of(add(shape.moves, shape.inspected)?)?)?
        .then(SCANNED.units(shape.texts, shape.text_bytes)?)
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
///   stable merge ([`maps::order`]): per merge level of its own, at most
///   `6e + 5` units,
///   every entry written and its scratch copied, and the comparisons' key
///   bytes, at most its keys', in units of at most 64; then checked, and
///   when misordered permuted in place ([`permutation`]): per payload byte
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
/// bitmap ([`PreparationTerms::peak`]).
/// Refused, never saturated, when a quantity does not fit in `u64`.
pub fn prepare_bound<P, R>(shape: Shape) -> Result<ResourceBound, BoundedError<R>> {
    PreparationTerms::of::<P, R>(shape)?.bound()
}

/// The [`ResourceBound`] of [`encode`](super::encode) of a value of
/// `shape`, with permits of type `P`: its shape's walk ([`walk_work`]), then
/// its preparation ([`prepare_bound`]), its plan capped at the extent and a
/// widest head per map, then its publication in place ([`emit_bound`] of
/// those bytes, at most), which releases the gap records: what the
/// encoding retains is the plan's byte arena alone.
pub fn encode_bound<P, R>(shape: Shape) -> Result<ResourceBound, BoundedError<R>> {
    let terms = PreparationTerms::of::<P, R>(shape)?;
    let bound = ResourceBound::of_work(walk_work(shape)?)
        .then(terms.bound()?)?
        .then(emit_bound::<R>(shape.appended()?)?)?;
    Ok(ResourceBound {
        retained: terms.term(PreparationPlace::PlanBytes).retained,
        ..bound
    })
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

/// Inspecting one instruction of a source that began an unordered map, or
/// making one entry cursor transition: one value and up to a window of
/// bucket controls.
const CURSOR: Unit<PreparationPlace> =
    Unit::new(PreparationPlace::Instructions, 1, BUCKET_WINDOW as u64);

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

/// The most bucket controls one [`Instruction::Entry`] inspects, and so the
/// most its `next` may advance past the instruction's own index: a quantum.
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
    }
}

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
    fn of<P, R>(shape: Shape) -> Result<Self, BoundedError<R>> {
        use core::mem::size_of;
        let Shape {
            instructions,
            dynamic,
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
        let indexed = instructions
            .checked_sub(dynamic)
            .ok_or(BoundedError::Overflow)?;
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
        let arena = |elements: u64, size: u64, published: bool| {
            let (growth, growing) = storage_growth::<R>(elements, size)?;
            let work = growing.then(growth.released()?)?;
            Ok::<_, BoundedError<R>>((
                ResourceBound {
                    values: work.values,
                    bytes: work.bytes,
                    allocated: growth.allocated,
                    peak: growth.peak,
                    retained: if published { growth.held } else { 0 },
                },
                growth,
            ))
        };
        let work = ResourceBound::of_work;
        let step = |count: u64| Storage::<u8, ()>::step_work::<R>(count);
        let mut terms = [ResourceBound::default(); PreparationPlace::ALL.len()];
        let mut set = |place: PreparationPlace, term: ResourceBound| {
            terms[place as usize] = term;
        };
        // Each instruction, an entry cursor's transitions among the dynamic
        // ones with the node moves they state, and the inspections sources
        // announce.
        set(
            PreparationPlace::Instructions,
            work(
                INDEXED
                    .times(indexed)?
                    .then(CURSOR.times(dynamic)?)?
                    .then(MOVED.over(0, moves)?)?
                    .then(INSPECTED.over(0, inspected)?)?,
            ),
        );
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
        set(PreparationPlace::Digits, work(digit_pass.times(2)?));
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
            widen(size_of::<(&'static dyn Entries, Slot)>())?,
            false,
        )?;
        set(PreparationPlace::Cursors, cursors);
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
        let texts_work = WriteWork::new(mul(windows, TEXT_CHECK.values())?, text_bytes)
            .then(
                decode::initialization::fields::<TextContinuation<(), P>, R>(
                    TextContinuation::<(), P>::INIT_STEPS,
                )?
                .times(texts)?,
            )?
            .then(normalization.work())?
            .then(text_cursor::publication::<P, R>()?.times(texts)?)?
            // Each encoding's release, admitted before it is requested; the
            // preparation drops the copied encoding without admitting again.
            .then(text_cursor::output_release::<P, R>()?.times(texts)?)?;
        set(
            PreparationPlace::Texts,
            ResourceBound {
                values: texts_work.values,
                bytes: texts_work.bytes,
                allocated: normalization.allocated,
                peak: normalization.peak,
                retained: 0,
            },
        );
        // Each unordered-map key and value compacted: its record opened and
        // closed, the plan's bytes and gaps truncated, every payload byte
        // moved once per enclosing unordered map in units of at most a
        // quantum, a run cut short at each child and at each gap, and each
        // gap removed.
        set(
            PreparationPlace::Compaction,
            work(
                dynamic::COMPACT
                    .times(mul(children, 2)?)?
                    .then(step(mul(children, 2)?)?)?
                    .then(dynamic::MOVE.covering(payloads, add(children, maps)?)?)?
                    .then(dynamic::GAP.times(maps)?)?,
            ),
        );
        // Each map's merge: per level of its own every entry copied into the
        // scratch and written back, and up to two steps per entry; five per
        // level; two to finish.
        set(
            PreparationPlace::Merging,
            work(maps::order::MERGE_MOVE.times(mul(merges, 3)?)?.then(
                maps::order::MERGE_STEP.times(add(
                    add(mul(merges, 2)?, mul(merge_levels, 5)?)?,
                    mul(unordered, 2)?,
                )?)?,
            )?),
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
                permutation::OFFSET
                    .times(add(entries, unordered)?)?
                    .then(
                        permutation::FILL
                            .covering(bitmap, add(mul(unordered, 2)?, bitmap_growths)?)?,
                    )?
                    .then(permutation::SCAN.times(add(
                        add(payloads.div_ceil(permutation::SCAN.cap()), payloads)?,
                        unordered,
                    )?)?)?
                    .then(permutation::LOOKUP.times(payload_probes)?)?
                    .then(permutation::MOVE.times(payloads)?)?
                    .then(
                        step(unordered)?
                            .then(Storage::<u8, ()>::cleanup_work(true)?.times(unordered)?)?
                            .then(permutation::PERMUTED.times(unordered)?)?,
                    )?,
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
        let staging = Storage::<u8, ()>::growth_work(bitmap_grown)?
            .then(RELEASED.times(mul(bitmap_grown, 2)?)?)?;
        set(
            PreparationPlace::Visited,
            ResourceBound {
                values: add(mul(bitmap, 2)?, staging.values)?,
                bytes: add(mul(bitmap, 2)?, staging.bytes)?,
                allocated: add(mul(bitmap, 3)?, mul(bitmap_grown, TURN.bytes)?)?,
                peak: visited,
                retained: 0,
            },
        );
        // Each unordered map's completion: its descriptors truncated, its
        // ordering reset, its frames popped; and the preparation's.
        set(
            PreparationPlace::Completion,
            work(
                step(unordered)?
                    .then(maps::order::RESET.times(unordered)?)?
                    .then(dynamic::COMPLETE.times(unordered)?)?
                    .then(DONE.times(1)?)?,
            ),
        );
        // Cleanup ([`Preparation::reclaim_step`]): an interrupted text's
        // continuation's own cleanup, its arenas drained; each of the eight
        // arenas (frames, open maps, bytes, gaps, cursors, entries, the
        // ordering scratch and the bitmap) truncated and cleaned up; the
        // record's transition and the completion. Every arena is plain data
        // reclaimed by `Storage::reclaim_copy_step`: settled with no growth
        // staged, discarded in one unit; cancelled while staging a growth,
        // relocating or relocated, drained one element per unit. Of these
        // eight and the text continuation's two, at most one is ever in one
        // of those stages (the exclusion the peak rests on,
        // [`PreparationTerms`], checked at every boundary of every
        // attribution run), so cleanup drains at most one arena one element
        // per unit: charged at the most of any one arena's elements, in
        // values and in bytes apart. The text's own drain is its interrupted
        // cleanup's. The descriptors and the merge scratch are both arenas of
        // at most `entries + 1` descriptors, one entry below. Every release,
        // the copied encoding's and each arena allocation's, was admitted by
        // its acquisition.
        const ARENAS: u64 = 8;
        let drained = [
            Storage::<Frame<'static>, ()>::element_work(held)?,
            Storage::<MapFrame<'static>, ()>::element_work(held)?,
            Storage::<u8, ()>::element_work(add(appended, 1)?)?,
            Storage::<(usize, usize), ()>::element_work(add(maps, 1)?)?,
            Storage::<(&'static dyn Entries, Slot), ()>::element_work(held)?,
            Storage::<maps::order::Entry, ()>::element_work(add(entries, 1)?)?,
            Storage::<u8, ()>::element_work(add(largest, 1)?)?,
        ]
        .into_iter()
        .fold(WriteWork::default(), |most, arena| {
            WriteWork::new(most.values.max(arena.values), most.bytes.max(arena.bytes))
        });
        set(
            PreparationPlace::Cleanup,
            work(
                text_cursor::interrupted::<R>(longest_text)?
                    .then(drained)?
                    .then(step(ARENAS)?)?
                    .then(Storage::<u8, ()>::cleanup_work(true)?.times(ARENAS)?)?
                    .then(PLAN_TRANSITION.times(1)?)?
                    .then(CLEANUP_DONE.times(1)?)?,
            ),
        );
        // The arenas the preparation keeps for its life: each grows to its
        // most and keeps that capacity until cleanup, which allocates nothing.
        let kept = [
            frames_growth,
            gaps_growth,
            open_maps_growth,
            cursors_growth,
            descriptors_growth,
            plan_growth,
            scratch_growth,
        ];
        let mut held_all = 0u64;
        let mut overlap = 0u64;
        for growth in kept {
            held_all = add(held_all, growth.held)?;
            overlap = overlap.max(growth.peak - growth.held);
        }
        // A text's normalized encoding, at most its parts' bytes behind
        // their head, copied into the plan while the plan relocates.
        let output = if texts == 0 {
            0
        } else {
            item_len(longest_text.part_bytes, longest_text.part_bytes)?
        };
        let copying = add(output, plan_growth.peak - plan_growth.held)?;
        let peak = add(
            held_all,
            overlap.max(normalization.peak).max(copying).max(visited),
        )?;
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
    let preparation = prepare_bound::<A::Permit, R>(shape)?;
    let task = ResourceBound {
        retained: preparation.peak,
        ..preparation
    };
    OperationTerms::of::<Planned<'static, I, T, A>, A, R>(
        Planned::<'static, I, T, A>::INIT_STEPS,
        task,
    )
}

impl<'a, P, A: Allocator<Permit = P>> Resumable<A> for Preparation<'a, P> {
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
pub struct Prepared<P> {
    bytes: Owned<u8, P>,
    holes: Owned<(usize, usize), P>,
    len: usize,
}

impl<P> Prepared<P> {
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
    preparation: Preparation<'s, A::Permit>,
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
    const INIT_STEPS: usize = 2 + Preparation::<'s, A::Permit>::INIT_STEPS;

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

    /// The plan of a published record.
    fn plan(&self) -> PlanView<'_> {
        match self.preparation.view() {
            Some(view) => view,
            None => unreachable!("a published plan is complete in place"),
        }
    }
}

// SAFETY: the prefix is the source handle and the phase, then the
// preparation's resource-free prefix, which needs no cleanup. Cleanup releases
// the preparation's arenas, then the source value, in place; no destructor runs.
// The preparation's `Done` drops every borrow of the source it still holds
// (`Preparation::release_source`), so from `ReclaimSource` on an observation
// of the record reads no reference into the value being released.
unsafe impl<'s, I: DecodeInput<A>, T: InPlace<A>, A: Allocator> Reclaim<A>
    for Planned<'s, I, T, A>
{
    const DISPATCH_DEPTH: usize = TypedValue::<'s, I, T, A>::DISPATCH_DEPTH.saturating_add(1);
    type State = Prefix;
    const INITIAL: Prefix = Prefix::EMPTY;

    fn reclaim_step(
        mut slot: reclamation::Slot<'_, Self, Prefix>,
        a: &mut A,
    ) -> BoundedResult<Reclaimed, A> {
        if slot.custody().initialized() < Self::INIT_STEPS {
            if let Some(source) = Self::source(&mut slot)
                && source.is_some()
            {
                TypedValue::reclaim_step(source, a)?;
                return Ok(Reclaimed::Progress);
            }
            PLAN_TRANSITION.admit(a)?;
            *slot.custody() = Prefix::EMPTY;
            return Ok(Reclaimed::Done);
        }
        let Planned {
            source,
            phase,
            preparation,
        } = Self::custody(&mut slot)?;
        match *phase {
            PlanPhase::ReclaimPreparation => {
                if preparation.reclaim_step(a)? == Reclaimed::Done {
                    *phase = PlanPhase::ReclaimSource;
                }
            }
            PlanPhase::ReclaimSource => {
                if TypedValue::reclaim_step(source, a)? == Reclaimed::Done {
                    *phase = PlanPhase::Done;
                    return Ok(Reclaimed::Done);
                }
            }
            PlanPhase::Done => return Ok(Reclaimed::Done),
            PlanPhase::Prepare | PlanPhase::Published => {
                PLAN_TRANSITION.admit(a)?;
                *phase = PlanPhase::ReclaimPreparation;
            }
        }
        Ok(Reclaimed::Progress)
    }

    /// Before initialization completes, the held source's own calls, then the
    /// one releasing the record. After it: the transition into cleanup
    /// unless it has begun, the preparation's own count and the source
    /// slot's.
    fn remaining(mut slot: PeekSlot<'_, Self, Prefix>) -> u64 {
        if slot.custody().initialized() < Self::INIT_STEPS {
            return match Self::source(&mut slot) {
                Some(source) if source.is_some() => TypedValue::remaining(source).saturating_add(1),
                _ => 1,
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
            return 1;
        };
        let phase = *phase;
        let source = TypedValue::remaining(source);
        let preparation = preparation.reclaim_remaining().saturating_add(source);
        match phase {
            PlanPhase::Done => 1,
            PlanPhase::ReclaimSource => source,
            PlanPhase::ReclaimPreparation => preparation,
            PlanPhase::Prepare | PlanPhase::Published => preparation.saturating_add(1),
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

// SAFETY: initialization moves the source handle in, writes the phase, then
// the preparation's resource-free prefix over a borrow of the source value,
// whose record this one holds until the preparation is reclaimed. Every later
// unit keeps the record reclaimable.
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
        if prefix.initialized() >= Self::INIT_STEPS {
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
                // destination, by field syntax; its units are its own: the
                // record's units are initialized in order, so its progress
                // less the two fields before it is what the preparation
                // holds.
                let preparation = unsafe {
                    reclamation::Slot::new(
                        place.project(|record| addr_of_mut!((*record).preparation)),
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

    fn advance(
        &mut self,
        mut slot: reclamation::Slot<'_, Self::State, Prefix>,
        a: &mut A,
    ) -> Result<bool, Self::Error> {
        // The custody is refused until initialization is complete.
        let Planned {
            phase, preparation, ..
        } = Planned::custody(&mut slot)?;
        if *phase != PlanPhase::Prepare {
            return Err(BoundedError::PlanMismatch);
        }
        if preparation.prepare_step::<Kept, A>(a)?.is_some() {
            *phase = PlanPhase::Published;
            return Ok(true);
        }
        Ok(false)
    }

    fn publish(&mut self, record: OwnedInitialized<'s, Self::State, A>) -> Self::Output {
        OwnedPrepared { record }
    }

    fn reclaim_step(&mut self, a: &mut A) -> BoundedResult<Reclaimed, A> {
        TypedValue::reclaim_step(&mut self.source, a)
    }

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
        // the record.
        let planned = unsafe { place.get(&*prefix) };
        PlanDetail {
            phase: Some(planned.phase),
            preparation: Some(planned.preparation.position()),
            source: planned.source.is_some(),
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
    A: Allocator + 's,
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

    /// Operation-local cleanup of this plan and its source value.
    pub fn reclaim_step(slot: &mut Option<Self>, a: &mut A) -> BoundedResult<Reclaimed, A> {
        reclamation::reclaim_within(
            slot,
            a,
            |plan| plan.record,
            |record| Self { record },
            OwnedInitialized::reclaim_step,
        )
    }
}

#[cfg(test)]
mod bound_tests {
    use super::*;
    use crate::bounded::{Call, Limits, Reservation, within};
    use core::ops::ControlFlow;

    #[test]
    fn retired_plan_consumes_prepaid_releases_before_admitted_completion() {
        let source = "payload".repeat(128);
        let bound = prepare_bound::<Reservation, ()>(
            Shape::of(&source, &mut Limits::unlimited()).expect("a text has a shape"),
        )
        .expect("the bound of a text fits in u64");
        let mut acquisition = Limits::unlimited();
        let mut preparation = Preparation::<Reservation>::new(&source);
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

    /// A preparation whose cleanup reports `Done` holds no borrow of its
    /// source: an owned preparation's record releases the source right
    /// after, while the record is still observed, so a payload pending when
    /// cleanup began is neither reported nor read once the preparation is
    /// reclaimed.
    #[test]
    fn a_reclaimed_preparation_holds_no_borrow_of_its_source() {
        let source = crate::ByteString::from(vec![0x5a; 200]);
        let bound = prepare_bound::<Reservation, ()>(
            Shape::of(&source, &mut Limits::unlimited()).expect("a byte string has a shape"),
        )
        .expect("the bound of a byte string fits in u64");
        let mut limits = Limits::unlimited();
        let mut preparation = Preparation::<Reservation>::new(&source);
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
        let bound = prepare_bound::<Reservation, ()>(shape).expect("the bound fits in u64");
        let mut limits = Limits::unlimited();
        let mut short = Preparation::<Reservation>::capped(&source, appended - 1);
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
        let mut exact = Preparation::<Reservation>::capped(&source, appended);
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
        let planned_bound = prepare_bound::<Reservation, ()>(shape).expect("the bound fits in u64");
        let encoded_bound = encode_bound::<Reservation, ()>(shape).expect("the bound fits in u64");
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
                (2 | 3 | 7, 0) => Instruction::UnorderedMap,
                (2, 1) => Instruction::Entry {
                    next: 1,
                    entry: None,
                },
                (3, 1) => Instruction::Entry {
                    next: 2 + BUCKET_WINDOW,
                    entry: None,
                },
                (4, 0) => Instruction::Field(0, None),
                (5, 0) => Instruction::Entry {
                    next: 1,
                    entry: None,
                },
                (6, 0 | 1) => Instruction::Map,
                (7, 1) => Instruction::Field(0, None),
                (8, 0) => Instruction::CountedUnorderedMap(1),
                (8..=10, 1) => Instruction::Entries(self),
                (9, 0) => Instruction::Map,
                (10, 0) => Instruction::Head(MajorType::Array, Argument::Shortest(0)),
                (11, 0) => Instruction::UnorderedMap,
                (11, 1) => Instruction::Entry {
                    next: 2,
                    entry: Some((&0u64, &0u64)),
                },
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
            let mut preparation = Preparation::<Reservation>::new(&source);
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
                    Some((key, value)) => Instruction::Entry {
                        next: index + 1,
                        entry: Some((key, value)),
                    },
                    None => Instruction::End,
                },
            }
        }
    }

    /// The shape of `source` and what preparing it reported, requested, held
    /// at its peak, and what its published plan holds.
    fn prepared(source: &dyn Schema) -> (Shape, WriteWork, u64, u64, u64) {
        let shape = Shape::of(source, &mut Limits::unlimited()).unwrap();
        let bound = prepare_bound::<Reservation, ()>(shape).unwrap();
        let mut limits = Limits::unlimited();
        let mut preparation = Preparation::<Reservation>::new(source);
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
        let bound = prepare_bound::<Reservation, ()>(shape).unwrap();
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
        let terms = PreparationTerms::of::<Reservation, ()>(shape).unwrap();
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

        /// Every arena a preparation holds at `position`: its eight, and its
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
                position.dynamic.entry_storage,
                position.dynamic.merge_storage,
                position.dynamic.bitmap_storage,
            ]
            .into_iter()
            .chain(text.into_iter().flatten())
        }

        /// How many of the preparation's arenas, and its text continuation's,
        /// a cancellation would drain one element per unit: staging a
        /// growth whose acquisition was refused (`Storage::reclaim_settled`),
        /// relocating, or relocated and not yet settled; a settled arena
        /// with no growth staged is discarded in one unit
        /// (`Storage::reclaim_copy_step`). [`PreparationTerms`] charges its
        /// peak, and its cleanup's drain, for at most one; every attribution
        /// run checks it at every boundary ([`ledgered`]).
        fn draining(position: &Position) -> usize {
            use crate::bounded::decode::storage::StorageStage;
            arenas(position)
                .filter(|arena| {
                    matches!(
                        arena.stage,
                        StorageStage::Staging(_)
                            | StorageStage::Relocating
                            | StorageStage::Relocated
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
            let mut preparation = Preparation::<places::Permit>::new(source);
            // A cancelled run's shape is its source's, as a completed one's.
            let shape = Shape::of(source, &mut Limits::unlimited()).map_err(|error| {
                (
                    format!("shape: {error:?}"),
                    Box::new(preparation.position()),
                )
            })?;
            let bound = prepare_bound::<places::Permit, ()>(shape).map_err(|error| {
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

        /// Under a policy refusing every admission once, a growth stages: its
        /// block's write is admitted on the retry and its release refused next
        /// (`stable::acquire`), leaving the arena `Staging`, which cleanup
        /// drains one element per unit (`Storage::reclaim_settled`). The
        /// attribution runs refuse nothing, so they never stage; here every
        /// staging arena of a map's and a text's preparation is counted by
        /// [`draining`], and at most one arena stages or relocates at any
        /// boundary.
        #[test]
        fn a_refused_growth_stages_one_arena_and_is_counted_draining() {
            use crate::bounded::decode::storage::StorageStage;
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
                let mut preparation = Preparation::<Reservation>::new(source.as_ref());
                let mut staged = 0usize;
                let mut published = false;
                for _ in 0..1_000_000 {
                    let position = preparation.position();
                    let staging = arenas(&position)
                        .filter(|arena| matches!(arena.stage, StorageStage::Staging(_)))
                        .count();
                    let counted = draining(&position);
                    assert!(
                        counted <= 1,
                        "{name}: {counted} arenas staging or relocating at once: {position:?}"
                    );
                    if staging > 0 {
                        staged += 1;
                        assert_eq!(
                            counted, staging,
                            "{name}: a staging arena not counted draining: {position:?}"
                        );
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
                assert!(staged > 0, "{name}: no growth staged under refusals");
                drop(preparation);
                assert_eq!(limits.live_bytes(), 0, "{name}");
            }
        }

        /// A source whose preparation charges `place`, and where it is
        /// cancelled into its cleanup, if it is: a place without a witness
        /// does not compile. `None` only for a place this build never charges.
        fn witness(
            place: PreparationPlace,
        ) -> Option<(&'static str, Box<dyn Schema>, Option<Cancel>)> {
            Some(match place {
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
                PreparationPlace::Digits => return None,
            })
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
                    terms: PreparationTerms::of::<places::Permit, ()>(shape).unwrap(),
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
                    terms: PreparationTerms::of::<places::Permit, ()>(shape).unwrap(),
                },
                places::Run {
                    name: "cancelled retained scratch source".into(),
                    outcome: places::Outcome::Cancelled,
                    policy: cancelled,
                    terms: PreparationTerms::of::<places::Permit, ()>(cancelled_shape).unwrap(),
                },
            ]);
            drop(plan);
        }

        /// A prepared source: its name, the place it witnesses if any, and
        /// where it is cancelled into its cleanup if it is.
        struct Source {
            name: String,
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
                .filter_map(|&place| {
                    let (name, schema, cancel_after) = witness(place)?;
                    Some(Source {
                        name: format!("{name} ({place:?})"),
                        witnesses: Some(place),
                        schema,
                        cancel_after,
                    })
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
            for source in &sources {
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
                    terms: PreparationTerms::of::<places::Permit, ()>(shape).unwrap(),
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
            places::Tightness::new("preparation")
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
                shape.dynamic,
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
        // After each unordered map's own instruction: the outer map's two
        // entries and end, the inner key map's entry and end, the empty key
        // map's end. The field map's are not.
        assert_eq!(shape.dynamic, 3 + 2 + 1);
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
                .followed_by::<()>(
                    text_cursor::normalization_bound::<()>(TextShape::of("x")).unwrap()
                )
                .unwrap()
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
            let mut limits = Limits::unlimited().logged();
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
        }
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
        let bound = prepare_bound::<Reservation, ()>(shape).expect("the bound fits in u64");
        let mut limits = Limits::unlimited().logged();
        let mut preparation = Preparation::<Reservation>::new(&source);
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
        let bound = prepare_bound::<Reservation, ()>(shape).expect("the bound fits in u64");
        let mut limits = Limits::unlimited();
        let mut preparation = Preparation::<Reservation>::new(&source);
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
            prepare_bound::<Reservation, ()>(shape),
            Err(BoundedError::Overflow)
        );
    }
}
