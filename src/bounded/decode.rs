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
    Error,
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
