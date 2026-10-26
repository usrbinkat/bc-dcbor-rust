//! Strict bounded decoding into a flat, borrowed document. The input owns text
//! and byte payloads; the document owns admitted node storage. Parsing and drop
//! are iterative, so nesting never consumes the native call stack. The caller
//! supplies a maximum nesting depth as well as work and live-storage policy.
//!
//! ```
//! use dcbor::{CBOR, bounded::{Limits, decode::{decode, Kind}}};
//! let input = [0x82, 0x01, 0x62, b'o', b'k'];
//! // Before: owned symbolic tree, followed by allocating typed extraction.
//! let before = CBOR::try_from_data(input).unwrap();
//! assert_eq!(before.diagnostic(), "[1, \"ok\"]");
//! // After: validated borrowed payloads and an admitted flat node arena.
//! let mut limits = Limits::new(100, 10_000, 10_000);
//! let document = decode(&input, 8, &mut limits).unwrap();
//! let mut children = document.root().children();
//! assert_eq!(children.next().unwrap().kind(), Kind::Unsigned(1));
//! assert_eq!(children.next().unwrap().kind(), Kind::Text("ok"));
//! drop(document);
//! assert_eq!(limits.live_bytes(), 0);
//! ```
use super::*;
pub mod comparison;
pub mod construction;
pub mod cursor;
pub mod header;
pub(crate) mod initialization;
pub mod storage;
pub mod string_cursor;
mod utf8;
use crate::{
    Error, ExactFrom,
    float::{validate_canonical_f16, validate_canonical_f32, validate_canonical_f64},
};

/// Resource refusal is distinct from malformed input and nesting refusal.
#[derive(Debug)]
pub enum DecodeError<R> {
    Resource(BoundedError<R>),
    Invalid(Error),
    DepthLimit {
        limit: usize,
    },
    /// A text the NFC quick check does not prove normal, refused under
    /// [`TextPolicy::QuickOnly`] before any normalization runs. The text may
    /// be canonical; the decoding's policy admits no text whose proof needs
    /// normalization.
    UnprovenText,
}

/// How [`decode_with`] validates a text's Unicode normalization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextPolicy {
    /// Strict NFC validation: text the quick check cannot prove normal is
    /// normalized and compared ([`text::validation_bound`]).
    Normalize,
    /// Only text the quick check proves normal is admitted; any other text is
    /// refused as [`DecodeError::UnprovenText`] at one value and its bytes.
    /// For schemas whose every text is ASCII or otherwise always proven by
    /// the quick check: such a schema refuses nothing it accepts under
    /// [`TextPolicy::Normalize`], and its decoding's work no longer scales
    /// with normalization.
    QuickOnly,
}

/// What [`decode_with`] admits: the nesting limit, counting array, map and
/// tag ancestors, and the text policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    pub max_depth: usize,
    pub text: TextPolicy,
}

impl Options {
    /// Strict NFC validation under `max_depth`: what [`decode`] admits.
    pub const fn normalizing(max_depth: usize) -> Self {
        Self {
            max_depth,
            text: TextPolicy::Normalize,
        }
    }

    /// Quick-check-proven text only under `max_depth`
    /// ([`TextPolicy::QuickOnly`]).
    pub const fn quick_only(max_depth: usize) -> Self {
        Self {
            max_depth,
            text: TextPolicy::QuickOnly,
        }
    }
}
impl<R> From<BoundedError<R>> for DecodeError<R> {
    fn from(error: BoundedError<R>) -> Self {
        Self::Resource(error)
    }
}

impl<R> Failure for DecodeError<R> {
    type Refusal = R;

    fn class(&self) -> Class<&R> {
        match self {
            Self::Resource(error) => error.class(),
            Self::Invalid(_) | Self::DepthLimit { .. } | Self::UnprovenText => Class::Invalid,
        }
    }
}
impl<R> From<Error> for DecodeError<R> {
    fn from(error: Error) -> Self {
        Self::Invalid(error)
    }
}

impl<R: fmt::Display> fmt::Display for DecodeError<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resource(error) => fmt::Display::fmt(error, f),
            Self::Invalid(error) => fmt::Display::fmt(error, f),
            Self::DepthLimit { limit } => write!(f, "decoding exceeds nesting limit {limit}"),
            Self::UnprovenText => {
                f.write_str("text not proven NFC by the quick check is refused by this decoding")
            }
        }
    }
}
impl<R: fmt::Debug + fmt::Display> core::error::Error for DecodeError<R> {}

/// Immediate value, with array/map/tag children available through [`Node::children`].
/// Map children alternate keys and values in validated canonical key order.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Kind<'a> {
    Unsigned(u64),
    Negative(i64),
    Bytes(&'a [u8]),
    Text(&'a str),
    Array(u64),
    Map(u64),
    Tagged(u64),
    Bool(bool),
    Null,
    Float(f64),
}

// Payload ranges are private to the document that owns the matching input.
// Keeping the arena borrow-free also lets owned operations retain it between
// turns without manufacturing references into their own input storage.
#[derive(Clone, Copy)]
enum StoredKind {
    Unsigned(u64),
    Negative(i64),
    Bytes { start: usize, end: usize },
    Text { start: usize, end: usize },
    Array(u64),
    Map(u64),
    Tagged(u64),
    Bool(bool),
    Null,
    Float(f64),
}

impl StoredKind {
    // Both parsers supply the position immediately following the payload.
    fn retain(kind: Kind<'_>, end: usize) -> Self {
        match kind {
            Kind::Unsigned(n) => Self::Unsigned(n),
            Kind::Negative(n) => Self::Negative(n),
            Kind::Bytes(bytes) => Self::Bytes {
                start: end - bytes.len(),
                end,
            },
            Kind::Text(text) => Self::Text {
                start: end - text.len(),
                end,
            },
            Kind::Array(n) => Self::Array(n),
            Kind::Map(n) => Self::Map(n),
            Kind::Tagged(n) => Self::Tagged(n),
            Kind::Bool(value) => Self::Bool(value),
            Kind::Null => Self::Null,
            Kind::Float(value) => Self::Float(value),
        }
    }

    fn borrow(self, input: &[u8]) -> Kind<'_> {
        match self {
            Self::Unsigned(n) => Kind::Unsigned(n),
            Self::Negative(n) => Kind::Negative(n),
            Self::Bytes { start, end } => Kind::Bytes(&input[start..end]),
            Self::Text { start, end } => {
                // SAFETY: both parsers validate UTF-8 before creating a text
                // entry. Entries and their immutable input remain paired.
                Kind::Text(unsafe { core::str::from_utf8_unchecked(&input[start..end]) })
            }
            Self::Array(n) => Kind::Array(n),
            Self::Map(n) => Kind::Map(n),
            Self::Tagged(n) => Kind::Tagged(n),
            Self::Bool(value) => Kind::Bool(value),
            Self::Null => Kind::Null,
            Self::Float(value) => Kind::Float(value),
        }
    }
}

struct Entry {
    kind: StoredKind,
    start: usize,
    end: usize,
    next: usize,
}

/// Owns the node arena and its reservations, while borrowing the original input.
pub struct Document<'a, P> {
    input: &'a [u8],
    entries: Owned<Entry, P>,
}

/// Borrow-free arena retained by an owned decoding record.
pub(crate) struct DocumentArena<P> {
    entries: Owned<Entry, P>,
}

impl<P> DocumentArena<P> {
    /// The root value of this arena over its own input.
    pub(crate) fn root<'d, 'a>(&'d self, input: &'a [u8]) -> Node<'d, 'a> {
        Node {
            input,
            entries: self.entries.as_slice(),
            index: 0,
        }
    }

    pub(crate) fn with_document<R>(
        &self,
        input: &[u8],
        f: impl FnOnce(&Document<'_, P>) -> R,
    ) -> R {
        // SAFETY: this read creates a temporary shared view of the ownership
        // header, not a second owner. ManuallyDrop prevents releasing the arena
        // or permit, including during unwinding. Only &Document escapes into f;
        // its borrow cannot escape this call through R.
        let view = core::mem::ManuallyDrop::new(Document {
            input,
            entries: unsafe { core::ptr::read(&self.entries) },
        });
        f(&view)
    }
}
impl<'a, P> Document<'a, P> {
    /// The single validated top-level value.
    pub fn root(&self) -> Node<'_, 'a> {
        Node {
            input: self.input,
            entries: self.entries.as_slice(),
            index: 0,
        }
    }
    /// Number of values in the flat arena, including keys and container nodes.
    pub fn node_count(&self) -> usize {
        self.entries.len()
    }
}

/// A constant-size view into the document; copying a view does not copy payloads.
#[derive(Clone, Copy)]
pub struct Node<'d, 'a> {
    input: &'a [u8],
    entries: &'d [Entry],
    index: usize,
}
impl<'d, 'a> Node<'d, 'a> {
    /// Value kind and borrowed payload, without walking descendants.
    pub fn kind(self) -> Kind<'a> {
        self.entries[self.index].kind.borrow(self.input)
    }
    /// Original canonical wire bytes for this value and all its descendants.
    pub fn encoded(self) -> &'a [u8] {
        let entry = &self.entries[self.index];
        &self.input[entry.start..entry.end]
    }
    /// Immediate children; each iterator step skips a whole subtree in O(1).
    pub fn children(self) -> Children<'d, 'a> {
        Children {
            input: self.input,
            entries: self.entries,
            next: self.index + 1,
            end: self.entries[self.index].next,
        }
    }
}

/// Non-allocating iterator over immediate children in wire order.
pub struct Children<'d, 'a> {
    input: &'a [u8],
    entries: &'d [Entry],
    next: usize,
    end: usize,
}
impl<'d, 'a> Iterator for Children<'d, 'a> {
    type Item = Node<'d, 'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.next >= self.end {
            return None;
        }
        let index = self.next;
        self.next = self.entries[index].next;
        Some(Node {
            input: self.input,
            entries: self.entries,
            index,
        })
    }
}

struct Frame {
    node: usize,
    remaining: u64,
    map: bool,
    key: bool,
    previous_key: Option<(usize, usize)>,
}

/// Decode exactly one canonical item. No symbolic CBOR nodes, strings, or map
/// keys are allocated. All arena/stack/normalization allocations are fallible
/// and admitted. `max_depth` counts array/map/tag ancestors; a scalar has depth
/// zero. Traversing the returned immutable view is a separate caller operation.
/// Tags are structurally decoded; application-specific tag semantics, including
/// bignum magnitude rules and date interpretation, are not validated here.
/// Text is validated strictly ([`TextPolicy::Normalize`]).
pub fn decode<'a, A: Allocator>(
    input: &'a [u8],
    max_depth: usize,
    allocator: &mut A,
) -> Result<Document<'a, A::Permit>, DecodeError<A::Refusal>> {
    decode_with(input, Options::normalizing(max_depth), allocator)
}

/// [`decode`] under `options`: its nesting limit and its text policy.
pub fn decode_with<'a, A: Allocator>(
    input: &'a [u8],
    options: Options,
    allocator: &mut A,
) -> Result<Document<'a, A::Permit>, DecodeError<A::Refusal>> {
    let Options { max_depth, text } = options;
    let mut entries: Owned<Entry, A::Permit> = Owned::new();
    let mut stack: Owned<Frame, A::Permit> = Owned::new();
    let mut pos = 0usize;
    loop {
        if stack.len() > max_depth {
            return Err(DecodeError::DepthLimit { limit: max_depth });
        }
        let start = pos;
        HEAD.admit(
            allocator,
            widen(input.len().saturating_sub(pos).min(MAX_HEAD_LEN))?,
        )?;
        let (major, argument, head) = crate::decode::parse_header_varint(&input[pos..])?;
        pos = pos.checked_add(head).ok_or(BoundedError::Overflow)?;
        let mut children = 0;
        let kind = match major {
            MajorType::Unsigned => Kind::Unsigned(argument),
            MajorType::Negative => {
                if argument > i64::MAX as u64 {
                    return Err(Error::OutOfRange.into());
                }
                Kind::Negative(-1 - argument as i64)
            }
            MajorType::ByteString | MajorType::Text => {
                if argument > widen(input.len() - pos)? {
                    return Err(Error::Underrun.into());
                }
                let len = usize::try_from(argument).map_err(|_| BoundedError::Overflow)?;
                let end = pos.checked_add(len).ok_or(BoundedError::Overflow)?;
                let bytes = input.get(pos..end).ok_or(Error::Underrun)?;
                PAYLOAD.admit(allocator, argument)?;
                pos = end;
                if matches!(major, MajorType::Text) {
                    let payload = core::str::from_utf8(bytes).map_err(Error::InvalidUtf8)?;
                    match text {
                        TextPolicy::Normalize => {
                            if !at(DecodePlace::Text, || {
                                text::is_normalized(payload, allocator)
                            })? {
                                return Err(Error::NonCanonicalString.into());
                            }
                        }
                        TextPolicy::QuickOnly => {
                            if !at(DecodePlace::Text, || {
                                text::is_proven_normal(payload, allocator)
                            })? {
                                return Err(DecodeError::UnprovenText);
                            }
                        }
                    }
                    Kind::Text(payload)
                } else {
                    Kind::Bytes(bytes)
                }
            }
            MajorType::Array => {
                children = argument;
                Kind::Array(argument)
            }
            MajorType::Map => {
                if argument > widen((input.len() - pos) / 2)? {
                    return Err(Error::Underrun.into());
                }
                children = argument.checked_mul(2).ok_or(BoundedError::Overflow)?;
                Kind::Map(argument)
            }
            MajorType::Tagged => {
                children = 1;
                Kind::Tagged(argument)
            }
            MajorType::Simple => match head {
                3 => {
                    let n = f16::from_bits(argument as u16);
                    validate_canonical_f16(n)?;
                    Kind::Float(n.to_f64())
                }
                5 => {
                    let n = f32::from_bits(argument as u32);
                    validate_canonical_f32(n)?;
                    Kind::Float(f64::from(n))
                }
                9 => {
                    let n = f64::from_bits(argument);
                    validate_canonical_f64(n)?;
                    Kind::Float(n)
                }
                _ => match argument {
                    20 => Kind::Bool(false),
                    21 => Kind::Bool(true),
                    22 => Kind::Null,
                    _ => return Err(Error::InvalidSimpleValue.into()),
                },
            },
        };
        // Every child needs at least a one-byte head. Refuse impossible lengths
        // before reserving any arena capacity for the advertised container.
        if children > widen(input.len() - pos)? {
            return Err(Error::Underrun.into());
        }
        if children > 0 && stack.len() >= max_depth {
            return Err(DecodeError::DepthLimit { limit: max_depth });
        }
        let index = entries.len();
        let entry = Entry {
            kind: StoredKind::retain(kind, pos),
            start,
            end: pos,
            next: index + 1,
        };
        at(DecodePlace::Arena, || entries.push(entry, allocator))?;
        if children > 0 {
            let frame = Frame {
                node: index,
                remaining: children,
                map: matches!(major, MajorType::Map),
                key: true,
                previous_key: None,
            };
            at(DecodePlace::Stack, || stack.push(frame, allocator))?;
            continue;
        }
        let mut completed = index;
        loop {
            let Some(parent) = stack.items.last_mut() else {
                if pos != input.len() {
                    return Err(Error::UnusedData(input.len() - pos).into());
                }
                return Ok(Document { input, entries });
            };
            COMPLETION.admit(allocator)?;
            if parent.map && parent.key {
                let entry = &entries.items[completed];
                if let Some((previous_start, previous_end)) = parent.previous_key {
                    let previous = &input[previous_start..previous_end];
                    let key = &input[entry.start..entry.end];
                    KEY.admit(allocator, widen(previous.len().min(key.len()))?)?;
                    match previous.cmp(key) {
                        core::cmp::Ordering::Equal => return Err(Error::DuplicateMapKey.into()),
                        core::cmp::Ordering::Greater => return Err(Error::MisorderedMapKey.into()),
                        core::cmp::Ordering::Less => {}
                    }
                }
                parent.previous_key = Some((entry.start, entry.end));
            }
            parent.key = !parent.key;
            parent.remaining -= 1;
            if parent.remaining != 0 {
                break;
            }
            completed = parent.node;
            let next = entries.len();
            entries.items[completed].end = pos;
            entries.items[completed].next = next;
            stack.items.pop();
        }
    }
}

/// The [`ResourceBound`] of [`decode`] of any input of at most `input` bytes
/// under `max_depth`, whatever its contents, malformed inputs included:
/// every quantity is monotone in the input length, so the bound of the
/// longest input admitted bounds every shorter one.
///
/// Every value has at least a one-byte head, so an input of `n` bytes has at
/// most `n` nodes and at most `n + 1` header examinations (the last may
/// fail). The terms, each charged where `decode` charges it:
///
/// - each header examination: one value and at most [`MAX_HEAD_LEN`] bytes;
/// - byte and text payloads: their bytes, disjoint, at most `n` in all;
/// - each completed child: one value, at most `n`;
/// - each map key after the first of its map: one value, and the shorter of
///   it and the previous key's encoded bytes. Each key has a value beside
///   it, each a node of at least one byte, so there are at most `n / 2`
///   keys. A byte lies in the encoded keys of at most one map per nesting
///   level, so the key bytes compared are at most `min(max_depth, n) * n`;
/// - the node arena of at most `n` entries and the stack of at most
///   `min(max_depth, n)` frames ([`owned_growth`]);
/// - strict NFC validation of the text payloads
///   ([`text::validation_bound`]), whose scratch exists only while one text
///   is validated.
///
/// The stack and the validation scratch are released before `decode`
/// returns; the arena is the document's ([`ResourceBound::retained`]): what a
/// value constructed from it ([`decode_typed`]) is built beside.
///
/// The peak is the most held at once, not the sum of each part's most. The
/// arena or the stack grows only between texts, beside the other's held
/// capacity; a text's validation scratch is released before its node is
/// pushed, so it is held beside the nodes and open frames before it, which
/// the input's other bytes hold: a text of `m` bytes, its head included,
/// leaves `n - m` for them. Those shrink as `m` grows and the validation's
/// peak only rises with `m`, so the most is at the least `m` of each of the
/// validation's peak levels ([`next_rise`]). Refused, never saturated, when
/// a quantity does not fit in `u64`.
pub fn decode_bound<R>(input: u64, max_depth: usize) -> Result<ResourceBound, BoundedError<R>> {
    decode_bound_with(input, Options::normalizing(max_depth))
}

/// The [`ResourceBound`] of [`decode_with`] under `options`, by the same terms
/// as [`decode_bound`]; under [`TextPolicy::QuickOnly`] the text term is the
/// quick checks alone ([`text::quick_validation_bound`]).
pub fn decode_bound_with<R>(
    input: u64,
    options: Options,
) -> Result<ResourceBound, BoundedError<R>> {
    Terms::of::<R>(input, options)?.bound()
}

/// Examining a head: one value and the head's bytes, at most
/// [`MAX_HEAD_LEN`], fewer where the input ends.
const HEAD: Capped<DecodePlace> = Capped::new(DecodePlace::Heads, 1, MAX_HEAD_LEN as u64);

/// A byte or text payload, its bytes examined at once.
const PAYLOAD: Scan<DecodePlace> = Scan::new(DecodePlace::Payload, 0);

/// Completing one child of its parent.
const COMPLETION: Unit<DecodePlace> = Unit::new(DecodePlace::Completions, 1, 0);

/// Comparing a map key with its map's previous key: one value and the
/// shorter key's encoded bytes.
const KEY: Scan<DecodePlace> = Scan::new(DecodePlace::Keys, 1);

/// The terms [`decode_bound`] sums, each the bound of one place `decode`
/// charges, kept apart so each can be checked against that place alone.
struct Terms {
    /// Header examinations: one per node and one the input may end inside.
    heads: WriteWork,
    /// Payload bytes, disjoint: at most the input's.
    payload: WriteWork,
    /// Completed children: at most one per node.
    completions: WriteWork,
    /// Map keys after the first of their map, at most one per two nodes,
    /// since each has a value beside it, and the key bytes compared: a byte
    /// lies in the keys of at most one map per nesting level.
    keys: WriteWork,
    arena: Growth,
    /// The releases the arena's growths admit.
    arena_released: WriteWork,
    stack: Growth,
    /// The releases the stack's growths admit.
    stack_released: WriteWork,
    /// Text validation ([`text::validation_bound`] or
    /// [`text::quick_validation_bound`]), which retains nothing.
    text: ResourceBound,
    /// The most held at once ([`Terms::peak_of`]).
    peak: u64,
}

impl Terms {
    fn of<R>(input: u64, options: Options) -> Result<Self, BoundedError<R>> {
        let depth = widen(options.max_depth)?.min(input);
        let arena = owned_growth(input, widen(core::mem::size_of::<Entry>())?)?;
        let stack = owned_growth(depth, widen(core::mem::size_of::<Frame>())?)?;
        Ok(Self {
            heads: HEAD.times(add(input, 1)?)?,
            payload: PAYLOAD.units(0, input)?,
            completions: COMPLETION.times(input)?,
            keys: KEY.units(input / 2, mul(depth, input)?)?,
            arena,
            arena_released: arena.released()?,
            stack,
            stack_released: stack.released()?,
            text: match options.text {
                TextPolicy::Normalize => text::validation_bound(input)?,
                TextPolicy::QuickOnly => text::quick_validation_bound(input),
            },
            peak: Self::peak_of::<R>(input, depth, options.text, arena, stack)?,
        })
    }

    /// The most `decode_with` holds at once over an input of `input` bytes
    /// and `depth` open frames at most ([`decode_bound`]): the arena growing
    /// beside the stack held, or the stack growing beside the arena held, no
    /// text being validated; or, under strict validation, one text of `m`
    /// bytes validated beside the arena and the stack held for the `input -
    /// m` bytes before it, at the least `m` of each level of the
    /// validation's peak. The quick check holds nothing.
    fn peak_of<R>(
        input: u64,
        depth: u64,
        policy: TextPolicy,
        arena: Growth,
        stack: Growth,
    ) -> Result<u64, BoundedError<R>> {
        let entry = widen(core::mem::size_of::<Entry>())?;
        let frame = widen(core::mem::size_of::<Frame>())?;
        let mut peak = add(arena.peak, stack.held)?.max(add(arena.held, stack.peak)?);
        if policy == TextPolicy::QuickOnly {
            return Ok(peak);
        }
        let validation = |m: u64| text::validation_bound::<R>(m).map(|bound| bound.peak);
        // The least text holds its head alone.
        let mut m = 1;
        while m <= input {
            let level = validation(m)?;
            let rest = input - m;
            let beside = add(
                owned_growth::<R>(rest, entry)?.held,
                owned_growth::<R>(depth.min(rest), frame)?.held,
            )?;
            peak = peak.max(add(beside, level)?);
            match next_rise(m, input, level, &validation)? {
                Some(next) => m = next,
                None => break,
            }
        }
        Ok(peak)
    }
}

places! {
    /// The places [`decode_with`] charges, one term of [`decode_bound_with`]
    /// each.
    pub(crate) enum DecodePlace {
        Heads,
        Payload,
        Completions,
        Keys,
        Arena,
        Stack,
        Text,
    }
}

impl Places for Terms {
    type Place = DecodePlace;

    fn term(&self, place: DecodePlace) -> ResourceBound {
        match place {
            DecodePlace::Heads => ResourceBound::of_work(self.heads),
            DecodePlace::Payload => ResourceBound::of_work(self.payload),
            DecodePlace::Completions => ResourceBound::of_work(self.completions),
            DecodePlace::Keys => ResourceBound::of_work(self.keys),
            // A growth reports its relocated bytes as one admission of no
            // values, and its allocation's release ([`Owned::reserve`]); the
            // arena is what the document holds once published.
            DecodePlace::Arena => ResourceBound {
                values: self.arena_released.values,
                bytes: self.arena.copied + self.arena_released.bytes,
                allocated: self.arena.allocated,
                peak: self.arena.peak,
                retained: self.arena.held,
            },
            DecodePlace::Stack => ResourceBound {
                values: self.stack_released.values,
                bytes: self.stack.copied + self.stack_released.bytes,
                allocated: self.stack.allocated,
                peak: self.stack.peak,
                retained: 0,
            },
            DecodePlace::Text => self.text,
        }
    }

    /// The most held at once ([`Terms::peak_of`]), not every place's at once.
    fn peak<R>(&self) -> Result<u64, BoundedError<R>> {
        Ok(self.peak)
    }
}

/// Each term of the bound checked against the one place it bounds, that
/// place's cost isolated by decoding two inputs of one length that differ
/// only in it. A term removed or understated fails its test.
#[cfg(test)]
mod terms_tests {
    use super::*;
    use crate::{ByteString, CBOR, Map};

    /// What decoding `input` reported and requested, and what the
    /// document held, with `max_depth` admitting it.
    fn measured(input: &[u8], max_depth: usize) -> (u64, u64, u64, u64) {
        let mut limits = Limits::unlimited();
        let document = decode(input, max_depth, &mut limits).unwrap();
        let held = limits.live_bytes();
        drop(document);
        assert_eq!(limits.live_bytes(), 0);
        let used = limits.used();
        (used.values, used.bytes, limits.requested_bytes(), held)
    }

    fn entry() -> u64 {
        core::mem::size_of::<Entry>() as u64
    }

    fn frame() -> u64 {
        core::mem::size_of::<Frame>() as u64
    }

    /// A flat array of zeros: one header per node, one completion per
    /// child, an arena of every node and a stack of one frame, exactly.
    #[test]
    fn heads_completions_and_the_arena_are_exact() {
        for count in [0u64, 1, 3, 4, 5, 22, 23, 24, 1000, 70_000] {
            let input = CBOR::from(vec![0u64; count as usize]).to_cbor_data();
            let n = input.len() as u64;
            let (values, _, requested, held) = measured(&input, 1);
            let arena = owned_growth::<()>(count + 1, entry()).unwrap();
            let stack = owned_growth::<()>(u64::from(count > 0), frame()).unwrap();
            let releases = arena.allocations + stack.allocations;
            assert_eq!(values, (count + 1) + count + releases, "{count} zeros");
            assert_eq!(
                requested,
                arena.allocated + stack.allocated,
                "{count} zeros"
            );
            assert_eq!(held, arena.held, "{count} zeros");
            let terms = Terms::of::<()>(n, Options::normalizing(1)).unwrap();
            assert!(terms.heads.values + terms.completions.values >= values - releases);
            assert!(terms.arena_released.values + terms.stack_released.values >= releases);
            assert!(terms.arena.allocated >= arena.allocated);
            assert!(terms.arena.held >= held);
        }
    }

    /// Nested arrays against a flat array of the same length and node
    /// count: the difference is the stack's growth, exactly.
    #[test]
    fn the_stack_term_covers_nesting() {
        for depth in [1u64, 4, 5, 9, 17, 23] {
            let mut nested = CBOR::from(0u64);
            for _ in 0..depth {
                nested = CBOR::from(vec![nested]);
            }
            let nested = nested.to_cbor_data();
            let flat = CBOR::from(vec![0u64; depth as usize]).to_cbor_data();
            assert_eq!(nested.len(), flat.len());
            let (_, nested_bytes, nested_requested, _) = measured(&nested, depth as usize);
            let (_, flat_bytes, flat_requested, _) = measured(&flat, depth as usize);
            let deep = owned_growth::<()>(depth, frame()).unwrap();
            let one = owned_growth::<()>(1, frame()).unwrap();
            assert_eq!(
                nested_requested - flat_requested,
                deep.allocated - one.allocated
            );
            let release_bytes = core::mem::size_of::<Owned<Frame, Reservation>>() as u64;
            assert_eq!(
                nested_bytes - flat_bytes,
                deep.copied - one.copied + (deep.allocations - one.allocations) * release_bytes
            );
            let terms =
                Terms::of::<()>(nested.len() as u64, Options::normalizing(depth as usize)).unwrap();
            assert!(terms.stack.allocated >= deep.allocated);
            assert!(terms.stack.copied >= deep.copied);
            assert!(terms.stack.peak >= deep.peak);
        }
    }

    /// A map against an array of the same items in the same order: the
    /// difference is the key comparisons, exactly one value and the shorter
    /// key's encoded bytes per key after the first.
    #[test]
    fn the_key_terms_cover_comparisons() {
        let keys: Vec<ByteString> = (0..11u8).map(|i| ByteString::new(vec![i; 200])).collect();
        let mut map = Map::new();
        let mut items = Vec::new();
        for key in &keys {
            map.insert(key.clone(), 0u64);
            items.push(CBOR::from(key.clone()));
            items.push(CBOR::from(0u64));
        }
        let map = CBOR::from(map).to_cbor_data();
        let array = CBOR::from(items).to_cbor_data();
        assert_eq!(map.len(), array.len());
        let (map_values, map_bytes, _, _) = measured(&map, 1);
        let (array_values, array_bytes, _, _) = measured(&array, 1);
        assert_eq!(map_values - array_values, 10);
        assert_eq!(map_bytes - array_bytes, 10 * 202);
        let terms = Terms::of::<()>(map.len() as u64, Options::normalizing(1)).unwrap();
        assert!(terms.keys.values >= 10);
        assert!(terms.keys.bytes >= 10 * 202);
    }

    /// Keys holding maps whose keys hold maps: every byte of an inner key
    /// is compared again at each level that holds it, so the comparisons
    /// pass the input's length and need the depth factor.
    #[test]
    fn the_key_term_covers_nested_keys_at_every_level() {
        let levels = 5;
        let (mut map, mut array) = (CBOR::from(0u64), CBOR::from(0u64));
        for _ in 0..levels {
            let mut next = Map::new();
            next.insert(CBOR::from(vec![CBOR::from(0u64), map.clone()]), 0u64);
            next.insert(CBOR::from(vec![CBOR::from(1u64), map.clone()]), 0u64);
            map = CBOR::from(next);
            array = CBOR::from(vec![
                CBOR::from(vec![CBOR::from(0u64), array.clone()]),
                CBOR::from(0u64),
                CBOR::from(vec![CBOR::from(1u64), array.clone()]),
                CBOR::from(0u64),
            ]);
        }
        let (map, array) = (map.to_cbor_data(), array.to_cbor_data());
        assert_eq!(map.len(), array.len());
        let depth = 2 * levels;
        let (_, map_bytes, _, _) = measured(&map, depth);
        let (_, array_bytes, _, _) = measured(&array, depth);
        let compared = map_bytes - array_bytes;
        let n = map.len() as u64;
        assert!(compared > n, "{compared} key bytes over {n} input bytes");
        assert!(
            Terms::of::<()>(n, Options::normalizing(depth))
                .unwrap()
                .keys
                .bytes
                >= compared
        );
    }

    /// A text against a byte string of the same payload: the difference is
    /// strict NFC validation, within the text term.
    #[test]
    fn the_text_term_covers_validation_in_place() {
        for text in [
            format!("\u{301}{}", "\u{e9}".repeat(2000)),
            format!("\u{301}{}", "\u{1d5}".repeat(2000)),
            "q\u{316}\u{301}".repeat(500),
        ] {
            let as_text = CBOR::from(text.as_str()).to_cbor_data();
            let as_bytes = CBOR::from(ByteString::new(text.as_bytes())).to_cbor_data();
            assert_eq!(as_text.len(), as_bytes.len());
            let (text_values, text_bytes, text_requested, _) = measured(&as_text, 0);
            let (bytes_values, bytes_bytes, bytes_requested, _) = measured(&as_bytes, 0);
            let terms = Terms::of::<()>(as_text.len() as u64, Options::normalizing(0)).unwrap();
            let values = text_values - bytes_values;
            assert!(values > 0);
            assert!(
                terms.text.values >= values,
                "{values} > {}",
                terms.text.values
            );
            assert!(terms.text.bytes >= text_bytes - bytes_bytes);
            assert!(terms.text.allocated >= text_requested - bytes_requested);
        }
    }

    /// The peak covers what decoding holds at once at every split of an
    /// input between nodes before a text and the text: precomposed letters
    /// behind a leading mark, which the quick check leaves unproven and
    /// strict validation normalizes, beside the arena of the nodes before
    /// it, at counts on each side of the arena's and the buffers'
    /// capacities; and the peak is no more than the sum of each place's.
    #[test]
    fn the_peak_covers_a_text_beside_the_nodes_before_it() {
        for nodes in [0usize, 3, 4, 5, 63, 64, 65, 700] {
            for letters in [0usize, 1, 3, 4, 5, 31, 32, 33, 700] {
                let mut items = vec![CBOR::from(0u64); nodes];
                items.push(CBOR::from(
                    format!("\u{301}{}", "\u{e9}".repeat(letters)).as_str(),
                ));
                let input = CBOR::from(items).to_cbor_data();
                let mut limits = Limits::unlimited();
                let document = decode(&input, 1, &mut limits).unwrap();
                drop(document);
                let bound = decode_bound::<()>(input.len() as u64, 1).unwrap();
                assert!(
                    limits.peak_bytes() <= bound.peak,
                    "{nodes} nodes, {letters} letters: held {} beyond {}",
                    limits.peak_bytes(),
                    bound.peak
                );
                let terms = Terms::of::<()>(input.len() as u64, Options::normalizing(1)).unwrap();
                let summed = DecodePlace::ALL.iter().try_fold(0u64, |total, &place| {
                    add::<()>(total, terms.term(place).peak)
                });
                assert!(
                    bound.peak <= summed.unwrap(),
                    "{nodes} nodes, {letters} letters"
                );
            }
        }
    }

    /// What decoding `input` under `options` reported and requested, and
    /// whether it decoded.
    fn measured_with(input: &[u8], options: Options) -> (u64, u64, u64, bool) {
        let mut limits = Limits::unlimited();
        let decoded = decode_with(input, options, &mut limits).is_ok();
        assert_eq!(limits.live_bytes(), 0);
        let used = limits.used();
        (used.values, used.bytes, limits.requested_bytes(), decoded)
    }

    /// Under the quick-only policy a text costs exactly its quick check over
    /// a byte string of the same payload: one value, its bytes, nothing
    /// allocated; text the quick check proves normal decodes as under strict
    /// validation, and text it does not is refused before normalization.
    #[test]
    fn quick_only_text_costs_its_quick_check_alone() {
        let proven = ["", "sha256:00ff", "ordinary text", "\u{e9}t\u{e9}"];
        let unproven = ["e\u{301}", "q\u{301}", "\u{1100}\u{1161}"];
        for text in proven.iter().chain(unproven.iter()) {
            let as_text = {
                let mut input = vec![0x60 | text.len() as u8];
                input.extend_from_slice(text.as_bytes());
                input
            };
            let as_bytes = CBOR::from(ByteString::new(text.as_bytes())).to_cbor_data();
            assert_eq!(as_text.len(), as_bytes.len());
            let quick = Options::quick_only(0);
            let (text_values, text_bytes, text_requested, decoded) = measured_with(&as_text, quick);
            let (bytes_values, bytes_bytes, bytes_requested, _) = measured_with(&as_bytes, quick);
            // Rejected text never acquires its node arena. The byte-string
            // control does, including prepayment of that arena's release.
            let skipped_release = u64::from(!decoded);
            let release_bytes = core::mem::size_of::<Owned<Entry, Reservation>>() as u64;
            assert_eq!(text_values + skipped_release, bytes_values + 1, "{text:?}");
            assert_eq!(
                text_bytes + skipped_release * release_bytes,
                bytes_bytes + text.len() as u64,
                "{text:?}"
            );
            assert_eq!(decoded, proven.contains(text), "{text:?}");
            if decoded {
                assert_eq!(text_requested, bytes_requested, "{text:?}");
            } else {
                assert_eq!(text_requested, 0, "{text:?} refused before its node exists");
            }
            let terms = Terms::of::<()>(as_text.len() as u64, quick).unwrap();
            assert!(terms.text.values >= 1 && terms.text.bytes >= text.len() as u64);
            assert_eq!(
                (terms.text.allocated, terms.text.peak),
                (0, 0),
                "the quick check allocates nothing"
            );
        }
        let mut limits = Limits::unlimited();
        assert!(matches!(
            decode_with(
                &CBOR::from("q\u{301}").to_cbor_data(),
                Options::quick_only(0),
                &mut limits
            ),
            Err(DecodeError::UnprovenText)
        ));
    }

    /// An input whose decode charges `place`, and the options it is decoded
    /// under: a place without a witness does not compile.
    fn witness(place: DecodePlace) -> (&'static str, CBOR, Options) {
        match place {
            DecodePlace::Heads | DecodePlace::Completions | DecodePlace::Arena => (
                "flat array",
                CBOR::from(vec![0u64; 1000]),
                Options::normalizing(1),
            ),
            DecodePlace::Payload => (
                "bytes",
                CBOR::from(ByteString::new(vec![0x5a; 4096])),
                Options::normalizing(0),
            ),
            // Short keys, most of the input's nodes, each compared over most
            // of its bytes.
            DecodePlace::Keys => {
                let mut keys = Map::new();
                for key in 0..1000u64 {
                    keys.insert(key, 0u64);
                }
                ("many keys", CBOR::from(keys), Options::normalizing(1))
            }
            DecodePlace::Stack => {
                let mut nested = CBOR::from(0u64);
                for _ in 0..23 {
                    nested = CBOR::from(vec![nested]);
                }
                ("nested arrays", nested, Options::normalizing(23))
            }
            // A leading mark keeps the quick check from proving the text
            // normal, so strict validation normalizes it.
            DecodePlace::Text => (
                "normalized text",
                CBOR::from(format!("\u{301}{}", "\u{e9}".repeat(2000)).as_str()),
                Options::normalizing(0),
            ),
        }
    }

    /// Every place a decode charges is within its term in work, requests,
    /// peak and the bytes its document retains; every admission and request
    /// is made at some place; and each place's witness charges it. Beside
    /// the witnesses: keys that are maps, text the quick check proves
    /// normal, and text under the quick-only policy.
    #[cfg(feature = "std")]
    #[test]
    fn every_place_of_a_decode_is_within_its_term() {
        use crate::bounded::places::{self, Factor, Ledgered, Run, STORAGE, WORK};
        let mut key_maps = CBOR::from(0u64);
        for _ in 0..5 {
            let mut next = Map::new();
            next.insert(CBOR::from(vec![CBOR::from(0u64), key_maps.clone()]), 0u64);
            next.insert(CBOR::from(vec![CBOR::from(1u64), key_maps.clone()]), 0u64);
            key_maps = CBOR::from(next);
        }
        let mut long_keys = Map::new();
        for i in 0..11u8 {
            long_keys.insert(ByteString::new(vec![i; 200]), 0u64);
        }
        let mut inputs: Vec<(String, Option<DecodePlace>, Vec<u8>, Options)> = DecodePlace::ALL
            .iter()
            .map(|&place| {
                let (name, value, options) = witness(place);
                (
                    format!("{name} ({place:?})"),
                    Some(place),
                    value.to_cbor_data(),
                    options,
                )
            })
            .collect();
        inputs.extend([
            (
                "long keys".to_string(),
                None,
                CBOR::from(long_keys).to_cbor_data(),
                Options::normalizing(1),
            ),
            (
                "key maps".to_string(),
                None,
                key_maps.to_cbor_data(),
                Options::normalizing(10),
            ),
            (
                "normal text".to_string(),
                None,
                CBOR::from("x".repeat(4096).as_str()).to_cbor_data(),
                Options::normalizing(0),
            ),
            (
                "quick text".to_string(),
                None,
                CBOR::from("x".repeat(4096).as_str()).to_cbor_data(),
                Options::quick_only(0),
            ),
            // A node per byte: the most the arena holds and the document
            // retains.
            (
                "large flat array".to_string(),
                None,
                CBOR::from(vec![0u64; 4096]).to_cbor_data(),
                Options::normalizing(1),
            ),
            // Precomposed letters behind a leading mark, at a larger size
            // than the text witness: what strict validation charges most
            // for, besides its heads and payload.
            (
                "long letters".to_string(),
                None,
                CBOR::from(format!("\u{301}{}", "\u{e9}".repeat(8192)).as_str()).to_cbor_data(),
                Options::normalizing(0),
            ),
        ]);
        let mut runs = Vec::new();
        let mut witnesses = Vec::new();
        for (name, place, input, options) in &inputs {
            let mut policy = Ledgered::new();
            // The document is held until the check: what it retains is
            // checked against the retained terms.
            let document = decode_with(input, *options, &mut policy).unwrap();
            let terms = Terms::of::<()>(input.len() as u64, *options).unwrap();
            let validation = match options.text {
                TextPolicy::Normalize => text::validation_bound::<()>(input.len() as u64).unwrap(),
                TextPolicy::QuickOnly => text::quick_validation_bound(input.len() as u64),
            };
            places::nested(DecodePlace::Text, terms.term(DecodePlace::Text), validation);
            if let Some(place) = place {
                witnesses.push((runs.len(), *place));
            }
            runs.push((
                Run {
                    outcome: places::Outcome::Published,
                    name: name.clone(),
                    policy,
                    terms,
                },
                document,
            ));
        }
        let (runs, documents): (Vec<_>, Vec<_>) = runs.into_iter().unzip();
        places::check(&runs);
        places::witnessed(&runs, &witnesses);
        let work = "one text of precomposed letters behind a leading mark: its strict \
                    validation, the dominant term, a counting pass per two bytes and three \
                    parts per two bytes; its one head and payload";
        let storage = "a flat array of one-byte items: a node per byte, the most the arena \
                       holds and the document retains";
        places::Tightness::new("decode")
            .places(&runs, &witnesses, |place| match place {
                DecodePlace::Heads
                | DecodePlace::Payload
                | DecodePlace::Completions
                | DecodePlace::Keys
                | DecodePlace::Arena
                | DecodePlace::Stack => Factor::Measured,
                DecodePlace::Text => Factor::Nested("text::tests"),
            })
            .joint(&runs, "normalized text (Text)", WORK, work)
            .joint(&runs, "long letters", WORK, work)
            .joint(&runs, "flat array (Arena)", STORAGE, storage)
            .joint(&runs, "large flat array", STORAGE, storage)
            .finish();
        drop(documents);
    }

    /// The quick-only inspection bound is at most four values per input
    /// byte and one. Each arena and stack growth additionally prepays one
    /// release; check those terms exactly rather than hiding them in the
    /// inspection coefficient.
    #[test]
    fn the_quick_only_bound_is_four_values_per_byte_plus_prepaid_releases() {
        for input in [0u64, 1, 2, 100, 4096, 1 << 20] {
            let bound = decode_bound_with::<()>(input, Options::quick_only(1)).unwrap();
            let terms = Terms::of::<()>(input, Options::quick_only(1)).unwrap();
            let releases = terms.arena.allocations + terms.stack.allocations;
            assert_eq!(
                terms.arena_released.values + terms.stack_released.values,
                releases
            );
            assert_eq!(
                bound.values,
                terms.heads.values
                    + terms.completions.values
                    + terms.keys.values
                    + terms.text.values
                    + releases
            );
            assert!(
                bound.values - releases <= 4 * input + 1,
                "{input}: {}",
                bound.values
            );
            let strict = decode_bound_with::<()>(input, Options::normalizing(1)).unwrap();
            assert!(bound.values <= strict.values && bound.bytes <= strict.bytes);
        }
    }
}

/// The result of constructing a typed value from a decoded document.
pub type ConstructResult<T, A> = Result<T, DecodeError<<A as Budget>::Refusal>>;

/// A typed value constructed from a decoded document ([`decode_typed`]),
/// owned together with the permit of every heap allocation it holds. No API
/// separates the value from its permits. Fields drop in order: the value's
/// storage is freed before its permits are released.
pub struct Constructed<T, P> {
    value: T,
    _permits: Owned<P, P>,
}

impl<T, P> Constructed<T, P> {
    /// The constructed value, borrowed for as long as its storage is held.
    pub const fn value(&self) -> &T {
        &self.value
    }
}

/// A type constructed from one node of a decoded document under the same
/// representation its symbolic conversion (`TryFrom<CBOR>`) reads, field
/// keys, discriminants, omission and tags included. Every unit of
/// examination is reported to `allocator` before it is done, and every heap
/// allocation the value holds is requested from it in its whole size before
/// it is made, its permit pushed to `permits`, which outlive the value
/// ([`Constructed`]). Derived types generate it from their schema
/// (`CBORBoundedDecodable`).
pub trait BoundedDecodable: Sized {
    fn construct<A: Allocator>(
        node: Node<'_, '_>,
        permits: &mut Owned<A::Permit, A::Permit>,
        allocator: &mut A,
    ) -> ConstructResult<Self, A>;
}

places! {
    /// The places synchronous typed construction ([`BoundedDecodable`],
    /// [`decode_typed_with`]) charges, derived bindings' included.
    pub(crate) enum TypedPlace {
        /// Values examined.
        Values,
        /// Payload bytes copied into owned storage.
        Copies,
        /// Storage the value holds, and the permits recording it.
        Holds,
    }
}

/// One value examined.
const VISIT: Unit<TypedPlace> = Unit::new(TypedPlace::Values, 1, 0);

/// Values examined at once: a derived binding's fields and tags.
const VISITS: Rate<TypedPlace> = Rate::new(TypedPlace::Values, 1, 0);

/// A payload's bytes copied into owned storage at once.
const COPY: Scan<TypedPlace> = Scan::new(TypedPlace::Copies, 0);

/// Request `bytes` of storage for a value under construction from
/// `allocator`, its release admitted first, its permit held by `permits`.
pub fn hold<A: Allocator>(
    bytes: u64,
    permits: &mut Owned<A::Permit, A::Permit>,
    allocator: &mut A,
) -> ConstructResult<(), A> {
    at(TypedPlace::Holds, || {
        construction::stable::admit_release(allocator)?;
        let permit = allocator.allocate(bytes).map_err(BoundedError::Refused)?;
        permits.push(permit, allocator)
    })?;
    Ok(())
}

/// Report one value examined to `allocator`.
pub fn visit<A: Allocator>(allocator: &mut A) -> ConstructResult<(), A> {
    VISIT.admit(allocator)?;
    Ok(())
}

/// Report `count` values examined to `allocator` at once, as a derived
/// binding examines its fields and tags.
pub fn visits<A: Allocator>(count: u64, allocator: &mut A) -> ConstructResult<(), A> {
    VISITS.admit(allocator, count)?;
    Ok(())
}

/// A node of an unexpected kind: the error the symbolic conversion gives.
pub fn wrong_type<R>() -> DecodeError<R> {
    DecodeError::Invalid(Error::WrongType)
}

/// Decode `input` strictly ([`decode`]) and construct `T` from its root, on
/// one allocator: the document's arena is released once the value is built,
/// and the value is returned with the permits of what it holds.
pub fn decode_typed<T: BoundedDecodable, A: Allocator>(
    input: &[u8],
    max_depth: usize,
    allocator: &mut A,
) -> ConstructResult<Constructed<T, A::Permit>, A> {
    decode_typed_with(input, Options::normalizing(max_depth), allocator)
}

/// [`decode_typed`] under `options` ([`decode_with`]).
pub fn decode_typed_with<T: BoundedDecodable, A: Allocator>(
    input: &[u8],
    options: Options,
    allocator: &mut A,
) -> ConstructResult<Constructed<T, A::Permit>, A> {
    let document = decode_with(input, options, allocator)?;
    let mut permits = Owned::new();
    let value = T::construct(document.root(), &mut permits, allocator)?;
    drop(document);
    Ok(Constructed {
        value,
        _permits: permits,
    })
}

/// Integers by value, refused outside the target type's range, as
/// `TryFrom<CBOR>` for each does (`int.rs`).
macro_rules! impl_construct_integer {
    ($($type:ty),*) => {$(
        impl BoundedDecodable for $type {
            fn construct<A: Allocator>(
                node: Node<'_, '_>,
                _: &mut Owned<A::Permit, A::Permit>,
                allocator: &mut A,
            ) -> ConstructResult<Self, A> {
                visit(allocator)?;
                let value = match node.kind() {
                    Kind::Unsigned(n) => i128::from(n),
                    Kind::Negative(n) => i128::from(n),
                    _ => return Err(wrong_type()),
                };
                <$type>::try_from(value).map_err(|_| DecodeError::Invalid(Error::OutOfRange))
            }
        }
    )*};
}

impl_construct_integer!(u8, u16, u32, u64, usize, i8, i16, i32, i64);

/// Floats from a float or an integer exactly representable in the target,
/// as `TryFrom<CBOR>` for each does (`float.rs`).
macro_rules! impl_construct_float {
    ($($type:ty),*) => {$(
        impl BoundedDecodable for $type {
            fn construct<A: Allocator>(
                node: Node<'_, '_>,
                _: &mut Owned<A::Permit, A::Permit>,
                allocator: &mut A,
            ) -> ConstructResult<Self, A> {
                visit(allocator)?;
                let value = match node.kind() {
                    Kind::Float(n) => <$type>::exact_from_f64(n),
                    Kind::Unsigned(n) => <$type>::exact_from_u64(n),
                    Kind::Negative(n) => <$type>::exact_from_i128(i128::from(n)),
                    _ => return Err(wrong_type()),
                };
                value.ok_or(DecodeError::Invalid(Error::OutOfRange))
            }
        }
    )*};
}

impl_construct_float!(f16, f32, f64);

impl BoundedDecodable for bool {
    fn construct<A: Allocator>(
        node: Node<'_, '_>,
        _: &mut Owned<A::Permit, A::Permit>,
        allocator: &mut A,
    ) -> ConstructResult<Self, A> {
        visit(allocator)?;
        match node.kind() {
            Kind::Bool(value) => Ok(value),
            _ => Err(wrong_type()),
        }
    }
}

/// `bytes` copied into storage requested from `allocator` and allocated
/// fallibly at exactly their length: the one owned copy construction makes.
pub fn copy_bytes<A: Allocator>(
    bytes: &[u8],
    permits: &mut Owned<A::Permit, A::Permit>,
    allocator: &mut A,
) -> ConstructResult<Vec<u8>, A> {
    let length = widen(bytes.len())?;
    COPY.admit(allocator, length)?;
    hold(length, permits, allocator)?;
    let mut out = Vec::new();
    out.try_reserve_exact(bytes.len())
        .map_err(|_| BoundedError::Allocation { bytes: length })?;
    out.extend_from_slice(bytes);
    Ok(out)
}

impl BoundedDecodable for String {
    fn construct<A: Allocator>(
        node: Node<'_, '_>,
        permits: &mut Owned<A::Permit, A::Permit>,
        allocator: &mut A,
    ) -> ConstructResult<Self, A> {
        visit(allocator)?;
        let Kind::Text(text) = node.kind() else {
            return Err(wrong_type());
        };
        let bytes = copy_bytes(text.as_bytes(), permits, allocator)?;
        // The bytes are the validated text's own.
        String::from_utf8(bytes)
            .map_err(|error| DecodeError::Invalid(Error::InvalidUtf8(error.utf8_error())))
    }
}

impl BoundedDecodable for ByteString {
    fn construct<A: Allocator>(
        node: Node<'_, '_>,
        permits: &mut Owned<A::Permit, A::Permit>,
        allocator: &mut A,
    ) -> ConstructResult<Self, A> {
        visit(allocator)?;
        let Kind::Bytes(bytes) = node.kind() else {
            return Err(wrong_type());
        };
        Ok(ByteString::from(copy_bytes(bytes, permits, allocator)?))
    }
}

/// An array of its elements, its storage requested at its whole capacity
/// before it is allocated.
impl<T: BoundedDecodable> BoundedDecodable for Vec<T> {
    fn construct<A: Allocator>(
        node: Node<'_, '_>,
        permits: &mut Owned<A::Permit, A::Permit>,
        allocator: &mut A,
    ) -> ConstructResult<Self, A> {
        visit(allocator)?;
        let Kind::Array(count) = node.kind() else {
            return Err(wrong_type());
        };
        let length = usize::try_from(count).map_err(|_| BoundedError::Overflow)?;
        let bytes = mul(count, widen(core::mem::size_of::<T>())?)?;
        hold(bytes, permits, allocator)?;
        let mut out = Vec::new();
        out.try_reserve_exact(length)
            .map_err(|_| BoundedError::Allocation { bytes })?;
        for child in node.children() {
            out.push(T::construct(child, permits, allocator)?);
        }
        Ok(out)
    }
}
