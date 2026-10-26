use super::*;
use crate::{CBOR, CBORCase, Date, Simple};

/// An explicit tag around a bounded value. This does not call the allocating
/// `CBORTaggedEncodable` interface. Derived tagged types encode their
/// untagged representation unless wrapped here.
pub struct Tagged<T> {
    pub tag: u64,
    pub value: T,
}

/// The instruction at `index` of a hash map of `len` entries over
/// `buckets` bucket indices: its counted head, then one window of at most
/// [`BUCKET_WINDOW`] bucket controls per instruction, the window's first
/// occupied bucket, if any, found by `first` (the map's `next_full_bucket`,
/// a group of controls at a time) and its entry read by `entry`. The engine
/// admits each window before asking for it, and ends the map once `len`
/// entries are yielded, so no window past the last entry is asked for.
#[cfg(any(feature = "hashbrown", feature = "custom-std-collections"))]
fn bucket_window<'a>(
    index: usize,
    len: usize,
    buckets: usize,
    first: impl FnOnce(usize, usize) -> Option<usize>,
    entry: impl FnOnce(usize) -> Option<(&'a dyn Schema, &'a dyn Schema)>,
) -> Instruction<'a> {
    if index == 0 {
        return Instruction::CountedUnorderedMap(len as u64);
    }
    let start = index - 1;
    if start >= buckets {
        return Instruction::End;
    }
    let end = start + (buckets - start).min(BUCKET_WINDOW);
    match first(start, end) {
        Some(bucket) => Instruction::Entry {
            next: bucket + 2,
            entry: entry(bucket),
        },
        None => Instruction::Entry {
            next: end + 1,
            entry: None,
        },
    }
}

#[cfg(feature = "custom-std-collections")]
impl<K: Schema, V: Schema, S> Schema for std::collections::HashMap<K, V, S> {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        bucket_window(
            index,
            self.len(),
            self.num_buckets(),
            |start, end| self.next_full_bucket(start, end),
            |bucket| {
                self.get_bucket(bucket)
                    .map(|(key, value)| (key as &dyn Schema, value as &dyn Schema))
            },
        )
    }
}

#[cfg(feature = "hashbrown")]
impl<K: Schema, V: Schema, S> Schema for hashbrown::HashMap<K, V, S> {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        bucket_window(
            index,
            self.len(),
            self.num_buckets(),
            |start, end| self.next_full_bucket(start, end),
            |bucket| {
                self.get_bucket(bucket)
                    .map(|(key, value)| (key as &dyn Schema, value as &dyn Schema))
            },
        )
    }
}

#[cfg(feature = "hashbrown")]
impl<K: Schema, V: Schema> Schema for hashbrown::HashTable<(K, V)> {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        bucket_window(
            index,
            self.len(),
            self.num_buckets(),
            |start, end| self.next_full_bucket(start, end),
            |bucket| {
                self.get_bucket(bucket)
                    .map(|(key, value)| (key as &dyn Schema, value as &dyn Schema))
            },
        )
    }
}

/// One transition of a tree's stepped cursor (`btree_stepped_cursor`), its
/// work already admitted with the engine's instruction; `entry` presents a
/// yielded key and value as schemas.
#[cfg(feature = "custom-std-collections")]
pub(crate) fn stepped<'a, K: 'a, V: 'a>(
    cursor: &mut std::collections::btree_map::SteppedCursor<'a, K, V>,
    entry: impl FnOnce(&'a K, &'a V) -> (&'a dyn Schema, &'a dyn Schema),
) -> EntryStep<'a> {
    use std::collections::btree_map::SteppedCursorStep;
    match cursor.step(|| Ok::<(), core::convert::Infallible>(())) {
        Ok(SteppedCursorStep::Progress) => EntryStep::Progress,
        Ok(SteppedCursorStep::Entry(key, value)) => {
            let (key, value) = entry(key, value);
            EntryStep::Entry(key, value)
        }
        Ok(SteppedCursorStep::Complete | SteppedCursorStep::Finished) => EntryStep::End,
        Err(never) => match never {},
    }
}

/// One step of a tree's standard iterator over its whole range, which
/// compares no keys: one entry, its node moves at most
/// [`tree_moves`] of the tree's length, stated by the source and admitted
/// with the transition.
#[cfg(not(feature = "custom-std-collections"))]
pub(crate) fn ranged<'a, K: 'a, V: 'a>(
    range: &mut BTreeMapRange<'a, K, V>,
    entry: impl FnOnce(&'a K, &'a V) -> (&'a dyn Schema, &'a dyn Schema),
) -> EntryStep<'a> {
    match range.next() {
        Some((key, value)) => {
            let (key, value) = entry(key, value);
            EntryStep::Entry(key, value)
        }
        None => EntryStep::End,
    }
}

/// Rust key order is not canonical key order, so entries are ordered by their
/// prepared key bytes like any unordered map. The tree is walked by its
/// stepped cursor on the bounded-collection standard library, one
/// transition per instruction, and by its standard iterator elsewhere; it
/// is never searched.
impl<K: Schema + Ord, V: Schema> Schema for BTreeMap<K, V> {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        match index {
            0 => Instruction::CountedUnorderedMap(self.len() as u64),
            1 => Instruction::Entries(self),
            _ => Instruction::End,
        }
    }
}

// SAFETY: the cursor is the map's stepped cursor, which borrows the tree,
// owns nothing, and never refers to itself.
#[cfg(feature = "custom-std-collections")]
unsafe impl<K: Schema + Ord, V: Schema> Entries for BTreeMap<K, V> {
    fn start(&self, slot: &mut Slot) {
        slot.put(self.stepped_cursor());
    }

    /// One transition per call.
    fn moves(&self) -> u64 {
        0
    }

    fn ordered(&self) -> bool {
        false
    }

    unsafe fn next<'a>(&'a self, slot: &mut Slot) -> EntryStep<'a> {
        // SAFETY: `start` stored this map's stepped cursor.
        let cursor = unsafe { slot.get::<std::collections::btree_map::SteppedCursor<'a, K, V>>() };
        stepped(cursor, |key, value| {
            (key as &dyn Schema, value as &dyn Schema)
        })
    }
}

// SAFETY: the cursor is the map's whole range, which borrows the tree, owns
// nothing, has no destructor, and never refers to itself; creating it over
// the unbounded range and stepping it compare no keys.
#[cfg(not(feature = "custom-std-collections"))]
unsafe impl<K: Schema + Ord, V: Schema> Entries for BTreeMap<K, V> {
    fn start(&self, slot: &mut Slot) {
        slot.put(self.range::<K, _>(..));
    }

    fn moves(&self) -> u64 {
        tree_moves(self.len())
    }

    fn ordered(&self) -> bool {
        false
    }

    unsafe fn next<'a>(&'a self, slot: &mut Slot) -> EntryStep<'a> {
        // SAFETY: `start` stored this map's range.
        let range = unsafe { slot.get::<BTreeMapRange<'a, K, V>>() };
        ranged(range, |key, value| {
            (key as &dyn Schema, value as &dyn Schema)
        })
    }
}

/// A number's canonical head (`float.rs`), its only instruction.
fn numeric(value: Numeric, index: usize) -> Instruction<'static> {
    if index != 0 {
        return Instruction::End;
    }
    let (major, argument) = value.head();
    Instruction::Head(major, argument)
}

/// The simple value `value` (`simple.rs`), its only instruction.
fn simple(value: u64, index: usize) -> Instruction<'static> {
    if index != 0 {
        return Instruction::End;
    }
    Instruction::Head(MajorType::Simple, Argument::Shortest(value))
}

/// Tag `tag` around `value`.
fn tagged(tag: u64, value: &dyn Schema, index: usize) -> Instruction<'_> {
    match index {
        0 => Instruction::Head(MajorType::Tagged, Argument::Shortest(tag)),
        1 => Instruction::Child(value),
        _ => Instruction::End,
    }
}

/// The same representation the symbolic value's conversion writes,
/// including its refusal of out-of-profile negative integers. Nesting deeper
/// than the engine's frame limit is refused there. Symbolic maps are walked
/// by their tree's cursor, in canonical order already.
impl Schema for CBOR {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        match self.as_case() {
            CBORCase::Unsigned(n) => numeric(integer(i128::from(*n)), index),
            CBORCase::Negative(n) if *n <= i64::MAX as u64 => {
                numeric(integer(-1 - i128::from(*n)), index)
            }
            CBORCase::Negative(_) => Instruction::OutOfRange,
            CBORCase::ByteString(bytes) => bytes.instruction(index),
            CBORCase::Text(text) => text.instruction(index),
            CBORCase::Array(values) => values.instruction(index),
            CBORCase::Map(map) => map.instruction(index),
            CBORCase::Tagged(tag, value) => tagged(tag.value(), value, index),
            CBORCase::Simple(value) => value.instruction(index),
        }
    }
}

/// Tag 1 around the date's timestamp in seconds, reduced as the symbolic
/// conversion reduces it (`date.rs`, `float.rs`).
impl Schema for Date {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        match index {
            0 => Instruction::Head(MajorType::Tagged, Argument::Shortest(crate::TAG_DATE)),
            1 => {
                let (major, argument) = convert_f64(self.timestamp()).prepared().head();
                Instruction::Head(major, argument)
            }
            _ => Instruction::End,
        }
    }
}

impl Schema for Simple {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        match self {
            Self::False => simple(20, index),
            Self::True => simple(21, index),
            Self::Null => simple(NULL, index),
            Self::Float(value) => value.instruction(index),
        }
    }
}

macro_rules! numbers {
    ($($ty:ty => $convert:expr),* $(,)?) => {$(
        impl Schema for $ty {
            fn instruction(&self, index: usize) -> Instruction<'_> {
                numeric(($convert)(*self), index)
            }
        }
    )*};
}
numbers!(
    u8 => |v| integer(v as i128), u16 => |v| integer(v as i128),
    u32 => |v| integer(v as i128), u64 => |v| integer(v as i128),
    usize => |v| integer(v as i128), i8 => |v| integer(v as i128),
    i16 => |v| integer(v as i128), i32 => |v| integer(v as i128),
    i64 => |v| integer(v as i128),
    f16 => |v| convert_f16(v).prepared(),
    f32 => |v| convert_f32(v).prepared(),
    f64 => |v| convert_f64(v).prepared(),
);
impl Schema for bool {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        simple(if *self { 21 } else { 20 }, index)
    }
}
impl Schema for str {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        if index == 0 {
            Instruction::Text(self)
        } else {
            Instruction::End
        }
    }
}
impl Schema for String {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        self.as_str().instruction(index)
    }
}
impl Schema for ByteString {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        match index {
            0 => Instruction::Head(
                MajorType::ByteString,
                Argument::Shortest(self.data().len() as u64),
            ),
            1 => Instruction::Bytes(self.data()),
            _ => Instruction::End,
        }
    }
}
impl<T: Schema> Schema for [T] {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        if index == 0 {
            return Instruction::Head(MajorType::Array, Argument::Shortest(self.len() as u64));
        }
        self.get(index - 1)
            .map_or(Instruction::End, |v| Instruction::Child(v))
    }
}
impl<T: Schema> Schema for Vec<T> {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        self.as_slice().instruction(index)
    }
}
impl<T: Schema, const N: usize> Schema for [T; N] {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        self.as_slice().instruction(index)
    }
}
/// A standalone optional value: `null`, or the contained value itself. As
/// with other nullable wire formats, `Some(null)` and `None` are not
/// distinct; derived optional map fields keep their omission semantics.
fn optional<'a>(value: Option<&'a dyn Schema>, index: usize) -> Instruction<'a> {
    match value {
        None => simple(NULL, index),
        Some(value) if index == 0 => Instruction::Child(value),
        Some(_) => Instruction::End,
    }
}
impl<T: Schema> Schema for Option<T> {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        optional(self.as_ref().map(|v| v as &dyn Schema), index)
    }
}
impl<T: Schema, A: Allocator> Schema for decode::construction::in_place::StableOption<T, A> {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        optional(self.as_ref().map(|v| v as &dyn Schema), index)
    }
}
impl<T: Schema + ?Sized> Schema for &T {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        (**self).instruction(index)
    }
}

impl<T: Schema + ?Sized> Schema for Box<T> {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        (**self).instruction(index)
    }
}
impl<T: Schema + ?Sized> Schema for Arc<T> {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        (**self).instruction(index)
    }
}
#[cfg(feature = "std")]
impl<T: Schema + ?Sized> Schema for std::rc::Rc<T> {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        (**self).instruction(index)
    }
}
impl<T: Schema> Schema for Tagged<T> {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        tagged(self.tag, &self.value, index)
    }
}

// SAFETY: these bindings return only immutable parts of the retained root or
// descendants carrying the same recursive contract. Tree cursors borrow only
// that tree; bucket traversal retains no cursor with independent ownership.
unsafe impl<T: TransferableSchema> TransferableSchema for [T] {}
unsafe impl<T: TransferableSchema> TransferableSchema for Option<T> {}
unsafe impl<T: TransferableSchema + ?Sized> TransferableSchema for &T {}
unsafe impl<T: TransferableSchema + Send + ?Sized> TransferableSchema for Arc<T> {}
unsafe impl<T: TransferableSchema> TransferableSchema for Tagged<T> {}
unsafe impl<K: TransferableSchema + Ord, V: TransferableSchema> TransferableSchema
    for BTreeMap<K, V>
{
}
unsafe impl<T: TransferableSchema, A: Allocator> TransferableSchema
    for decode::construction::in_place::StableOption<T, A>
where
    decode::construction::in_place::StableOption<T, A>: Sync,
{
}
#[cfg(feature = "custom-std-collections")]
unsafe impl<K: TransferableSchema, V: TransferableSchema, S: Sync> TransferableSchema
    for std::collections::HashMap<K, V, S>
{
}
#[cfg(feature = "hashbrown")]
unsafe impl<K: TransferableSchema, V: TransferableSchema, S: Sync> TransferableSchema
    for hashbrown::HashMap<K, V, S>
{
}
#[cfg(feature = "hashbrown")]
unsafe impl<K: TransferableSchema, V: TransferableSchema> TransferableSchema
    for hashbrown::HashTable<(K, V)>
{
}
unsafe impl TransferableSchema for Date {}
unsafe impl TransferableSchema for Simple {}
unsafe impl TransferableSchema for usize {}
unsafe impl TransferableSchema for f16 {}
unsafe impl TransferableSchema for f32 {}
unsafe impl TransferableSchema for f64 {}

// SAFETY: symbolic nodes are immutable and their tree cursors refer only to
// retained nodes. Their shared backing is transferable in multithreaded builds.
#[cfg(feature = "multithreaded")]
unsafe impl TransferableSchema for CBOR {}
#[cfg(feature = "multithreaded")]
unsafe impl TransferableSchema for crate::Map {}
#[cfg(feature = "num-bigint")]
unsafe impl TransferableSchema for num_bigint::BigUint {}
#[cfg(feature = "num-bigint")]
unsafe impl TransferableSchema for num_bigint::BigInt {}
