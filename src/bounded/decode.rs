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
use crate::{
    Error, ExactFrom,
    float::{validate_canonical_f16, validate_canonical_f32, validate_canonical_f64},
};

/// Resource refusal is distinct from malformed input and nesting refusal.
#[derive(Debug)]
pub enum DecodeError<R> {
    Resource(BoundedError<R>),
    Invalid(Error),
    DepthLimit { limit: usize },
}
impl<R> From<BoundedError<R>> for DecodeError<R> {
    fn from(error: BoundedError<R>) -> Self {
        Self::Resource(error)
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

struct Entry<'a> {
    kind: Kind<'a>,
    start: usize,
    end: usize,
    next: usize,
}

/// Owns the node arena and its reservations, while borrowing the original input.
pub struct Document<'a, P> {
    input: &'a [u8],
    entries: Owned<Entry<'a>, P>,
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
    entries: &'d [Entry<'a>],
    index: usize,
}
impl<'d, 'a> Node<'d, 'a> {
    /// Value kind and borrowed payload, without walking descendants.
    pub fn kind(self) -> Kind<'a> {
        self.entries[self.index].kind
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
    entries: &'d [Entry<'a>],
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
pub fn decode<'a, A: Allocator>(
    input: &'a [u8],
    max_depth: usize,
    allocator: &mut A,
) -> Result<Document<'a, A::Permit>, DecodeError<A::Refusal>> {
    let mut entries: Owned<Entry<'a>, A::Permit> = Owned::new();
    let mut stack: Owned<Frame, A::Permit> = Owned::new();
    let mut pos = 0usize;
    loop {
        if stack.len() > max_depth {
            return Err(DecodeError::DepthLimit { limit: max_depth });
        }
        let start = pos;
        allocator
            .traverse(1, widen(input.len().saturating_sub(pos).min(MAX_HEAD_LEN))?)
            .map_err(BoundedError::Refused)?;
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
                allocator
                    .traverse(0, argument)
                    .map_err(BoundedError::Refused)?;
                pos = end;
                if matches!(major, MajorType::Text) {
                    let text = core::str::from_utf8(bytes).map_err(Error::InvalidUtf8)?;
                    if !text::is_normalized(text, allocator)? {
                        return Err(Error::NonCanonicalString.into());
                    }
                    Kind::Text(text)
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
        entries.push(
            Entry {
                kind,
                start,
                end: pos,
                next: index + 1,
            },
            allocator,
        )?;
        if children > 0 {
            stack.push(
                Frame {
                    node: index,
                    remaining: children,
                    map: matches!(major, MajorType::Map),
                    key: true,
                    previous_key: None,
                },
                allocator,
            )?;
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
            allocator.traverse(1, 0).map_err(BoundedError::Refused)?;
            if parent.map && parent.key {
                let entry = &entries.items[completed];
                if let Some((previous_start, previous_end)) = parent.previous_key {
                    let previous = &input[previous_start..previous_end];
                    let key = &input[entry.start..entry.end];
                    allocator
                        .traverse(1, widen(previous.len().min(key.len()))?)
                        .map_err(BoundedError::Refused)?;
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

/// What [`decode`] reports and holds at most for one input, on success or
/// at any failure ([`decode_bound`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DecodeBound {
    /// Values reported to [`Budget::traverse`].
    pub values: u64,
    /// Bytes reported to [`Budget::traverse`].
    pub bytes: u64,
    /// The sum of every allocation request.
    pub allocated: u64,
    /// The most bytes the decoder's permits hold at once while it runs.
    pub peak: u64,
    /// The most bytes the returned [`Document`]'s permits hold: what a value
    /// constructed from it ([`decode_typed`]) is built beside.
    pub retained: u64,
}

/// The [`DecodeBound`] of [`decode`] of any input of at most `input` bytes
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
///   it and the previous key's encoded bytes. A byte lies in the encoded
///   keys of at most one map per nesting level, so the key bytes compared
///   are at most `min(max_depth, n) · n`;
/// - the node arena of at most `n` entries and the stack of at most
///   `min(max_depth, n)` frames ([`owned_growth`]);
/// - strict NFC validation of the text payloads
///   ([`text::validation_bound`]), whose scratch exists only while one text
///   is validated.
///
/// The stack and the validation scratch are released before `decode`
/// returns; the arena is the document's ([`DecodeBound::retained`]). Refused,
/// never saturated, when a quantity does not fit in `u64`.
pub fn decode_bound<R>(input: u64, max_depth: usize) -> Result<DecodeBound, BoundedError<R>> {
    let terms = Terms::of::<R>(input, max_depth)?;
    let values = add(
        add(terms.heads, terms.completions)?,
        add(terms.keys, terms.text.values)?,
    )?;
    let bytes = add(
        add(add(terms.head_bytes, terms.payload)?, terms.key_bytes)?,
        add(
            add(terms.arena.copied, terms.stack.copied)?,
            terms.text.bytes,
        )?,
    )?;
    Ok(DecodeBound {
        values,
        bytes,
        allocated: add(
            add(terms.arena.allocated, terms.stack.allocated)?,
            terms.text.allocated,
        )?,
        peak: add(add(terms.arena.peak, terms.stack.peak)?, terms.text.peak)?,
        retained: terms.arena.held,
    })
}

/// The terms [`decode_bound`] sums, each the bound of one place `decode`
/// charges, kept apart so each can be checked against that place alone.
struct Terms {
    /// Values of the header examinations.
    heads: u64,
    /// Bytes of the header examinations.
    head_bytes: u64,
    /// Bytes of the byte and text payloads.
    payload: u64,
    /// Values of the completed children.
    completions: u64,
    /// Values of the map key comparisons.
    keys: u64,
    /// Bytes of the map key comparisons.
    key_bytes: u64,
    arena: Growth,
    stack: Growth,
    text: text::ValidationBound,
}

impl Terms {
    fn of<R>(input: u64, max_depth: usize) -> Result<Self, BoundedError<R>> {
        let depth = widen(max_depth)?.min(input);
        let heads = add(input, 1)?;
        Ok(Self {
            heads,
            head_bytes: mul(heads, widen(MAX_HEAD_LEN)?)?,
            payload: input,
            completions: input,
            keys: input,
            key_bytes: mul(depth, input)?,
            arena: owned_growth(input, widen(core::mem::size_of::<Entry<'static>>())?)?,
            stack: owned_growth(depth, widen(core::mem::size_of::<Frame>())?)?,
            text: text::validation_bound(input)?,
        })
    }
}

/// Each term of the bound checked against the one place it bounds, that
/// place's cost isolated by decoding two inputs of one length that differ
/// only in it. A term removed or understated fails its test.
#[cfg(test)]
mod terms_tests {
    use super::super::tests::Tally;
    use super::*;
    use crate::{ByteString, CBOR, Map};

    /// What decoding `input` reported and requested, and what the
    /// document held, with `max_depth` admitting it.
    fn measured(input: &[u8], max_depth: usize) -> (u64, u64, u64, u64) {
        let mut tally = Tally::unlimited();
        let document = decode(input, max_depth, &mut tally).unwrap();
        let held = tally.live();
        drop(document);
        assert_eq!(tally.live(), 0);
        (tally.values, tally.bytes, tally.requested, held)
    }

    fn entry() -> u64 {
        core::mem::size_of::<Entry<'static>>() as u64
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
            assert_eq!(values, (count + 1) + count, "{count} zeros");
            assert_eq!(
                requested,
                arena.allocated + stack.allocated,
                "{count} zeros"
            );
            assert_eq!(held, arena.held, "{count} zeros");
            let terms = Terms::of::<()>(n, 1).unwrap();
            assert!(terms.heads + terms.completions >= values);
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
            assert_eq!(nested_bytes - flat_bytes, deep.copied - one.copied);
            let terms = Terms::of::<()>(nested.len() as u64, depth as usize).unwrap();
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
        let terms = Terms::of::<()>(map.len() as u64, 1).unwrap();
        assert!(terms.keys >= 10);
        assert!(terms.key_bytes >= 10 * 202);
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
        assert!(Terms::of::<()>(n, depth).unwrap().key_bytes >= compared);
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
            let terms = Terms::of::<()>(as_text.len() as u64, 0).unwrap();
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

/// Request `bytes` of storage for a value under construction from
/// `allocator`, its permit held by `permits`.
pub fn hold<A: Allocator>(
    bytes: u64,
    permits: &mut Owned<A::Permit, A::Permit>,
    allocator: &mut A,
) -> ConstructResult<(), A> {
    let permit = allocator.allocate(bytes).map_err(BoundedError::Refused)?;
    permits.push(permit, allocator)?;
    Ok(())
}

/// Report one value examined to `allocator`.
pub fn visit<A: Allocator>(allocator: &mut A) -> ConstructResult<(), A> {
    allocator.traverse(1, 0).map_err(BoundedError::Refused)?;
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
    let document = decode(input, max_depth, allocator)?;
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
    allocator
        .traverse(0, length)
        .map_err(BoundedError::Refused)?;
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
