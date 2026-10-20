//! Retained schema traversal and canonical byte preparation.
use super::*;
use decode::storage::Storage;
use text_cursor::{TextEncoder, TextStep};
#[cfg(feature = "hashbrown")]
pub mod buckets;
mod dynamic;
mod permutation;
pub use permutation::{PermutationPhase, PermutationPosition};
pub mod maps;
pub use dynamic::{DynamicPhase, DynamicPosition};
mod values;
mod writer;

/// One bounded-work schema instruction. Implementations must not scan fields,
/// allocate, or recursively visit children while producing an instruction.
/// Dynamic map entries may inspect at most 64 indexed bucket controls, yielding
/// at most one entry. `Entry::next` advances by 1 through 64 instructions.
/// The engine validates this advance; implementations remain responsible for
/// bounding the actual work performed before returning the instruction.
/// References and representation must remain stable for the preparation borrow.
pub trait Schema {
    fn instruction(&self, index: usize) -> Instruction<'_>;
}

pub enum Instruction<'a> {
    Head(MajorType, Argument),
    Text(&'a str),
    Bytes(&'a [u8]),
    Child(&'a dyn Schema),
    /// Begin a map whose present fields are counted as they are visited.
    Map,
    Field(u64, Option<&'a dyn Schema>),
    /// Begin a map whose entries are ordered by their prepared key bytes.
    UnorderedMap,
    /// Up to 64 inspected buckets, yielding at most one entry. `next` is the
    /// instruction index after the last inspected bucket, including vacancies.
    Entry {
        next: usize,
        entry: Option<(&'a dyn Schema, &'a dyn Schema)>,
    },
    End,
}

struct Frame<'a> {
    source: &'a dyn Schema,
    next: usize,
    map: Option<usize>,
}

enum EntryPhase<'a> {
    Scan,
    Key(&'a dyn Schema),
    Value,
    Order,
}
enum MapState<'a> {
    Schema { fields: u64 },
    Dynamic { start: usize, phase: EntryPhase<'a> },
}
struct MapFrame<'a> {
    hole: usize,
    state: MapState<'a>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Position {
    pub depth: usize,
    pub instruction: usize,
    pub prepared_bytes: usize,
    pub pending_bytes: usize,
    pub relocated_frames: usize,
    pub relocated_bytes: usize,
    pub relocated_headers: usize,
    pub normalized_bytes_copied: usize,
    pub normalization: Option<text_cursor::Position>,
    pub dynamic: DynamicPosition,
}

pub enum PrepareStep<P> {
    Progress,
    Complete(Prepared<P>),
    Finished,
}

/// Owns only flat arenas and borrowed source references. No source value is
/// cloned or destroyed by cancellation of encoding.
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
    head: [u8; MAX_HEAD_LEN],
    head_at: usize,
    head_len: usize,
    payload: &'a [u8],
    text: Option<TextEncoder<'a, P>>,
    normalized: Option<Encoded<P>>,
    normalized_at: usize,
    omitted: usize,
    finished: bool,
    dynamic: dynamic::Dynamic<P>,
    map_frames: Storage<MapFrame<'a>, P>,
    root_payload: Option<usize>,
}

impl<'a, P> Preparation<'a, P> {
    pub fn new(source: &'a dyn Schema) -> Self {
        Self {
            frames: Storage::new(),
            bytes: Storage::new(),
            holes: Storage::new(),
            child: Some(source),
            head: [0; MAX_HEAD_LEN],
            head_at: 0,
            head_len: 0,
            payload: &[],
            text: None,
            normalized: None,
            normalized_at: 0,
            omitted: 0,
            finished: false,
            dynamic: dynamic::Dynamic::new(),
            map_frames: Storage::new(),
            root_payload: None,
        }
    }

    pub fn position(&self) -> Position {
        Position {
            depth: self.frames.len(),
            instruction: self
                .frames
                .ready()
                .and_then(|s| s.last())
                .map_or(0, |f| f.next),
            prepared_bytes: self.bytes.len(),
            pending_bytes: self.head_len - self.head_at + self.payload.len(),
            relocated_frames: self.frames.relocated(),
            relocated_bytes: self.bytes.relocated(),
            relocated_headers: self.holes.relocated(),
            normalized_bytes_copied: self.normalized_at,
            normalization: self.text.as_ref().map(TextEncoder::position),
            dynamic: self.dynamic.position(),
        }
    }

    fn head(&mut self, major: MajorType, argument: Argument) {
        self.head_len = write_argument(major, argument, &mut self.head);
        self.head_at = 0;
    }

    fn append<A: Allocator<Permit = P>>(
        storage: &mut Storage<u8, P>,
        source: &[u8],
        a: &mut A,
    ) -> BoundedResult<usize, A> {
        // Relocation is its own turn, including the last relocated byte.
        if storage.ready().is_none() {
            storage.reserve_step(a)?;
            return Ok(0);
        }
        if !storage.reserve_step(a)? {
            return Ok(0);
        }
        let count = source.len().min(64).min(storage.spare_ready());
        a.traverse(1, widen(count)?)
            .map_err(BoundedError::Refused)?;
        storage
            .extend_reserved(&source[..count])
            .map_err(|_| BoundedError::PlanMismatch)?;
        Ok(count)
    }

    pub fn step<A: Allocator<Permit = P>>(
        &mut self,
        a: &mut A,
    ) -> BoundedResult<PrepareStep<P>, A> {
        if self.finished {
            return Ok(PrepareStep::Finished);
        }
        let result = self.advance(a);
        if matches!(&result, Err(e) if !matches!(e, BoundedError::Refused(_))) {
            self.finished = true;
        }
        result
    }

    fn advance<A: Allocator<Permit = P>>(&mut self, a: &mut A) -> BoundedResult<PrepareStep<P>, A> {
        if self.head_at < self.head_len {
            self.head_at +=
                Self::append(&mut self.bytes, &self.head[self.head_at..self.head_len], a)?;
            return Ok(PrepareStep::Progress);
        }
        if !self.payload.is_empty() {
            let count = Self::append(&mut self.bytes, self.payload, a)?;
            self.payload = &self.payload[count..];
            return Ok(PrepareStep::Progress);
        }
        if let Some(encoded) = &self.normalized {
            if self.normalized_at < encoded.as_ref().len() {
                self.normalized_at +=
                    Self::append(&mut self.bytes, &encoded.as_ref()[self.normalized_at..], a)?;
            } else {
                a.traverse(1, 0).map_err(BoundedError::Refused)?;
                self.normalized = None;
                self.normalized_at = 0;
            }
            return Ok(PrepareStep::Progress);
        }
        if let Some(text) = &mut self.text {
            match text.step(a)? {
                TextStep::Progress => {}
                TextStep::Complete(value) => {
                    self.normalized = Some(value);
                    self.text = None;
                }
                TextStep::Finished => return Err(BoundedError::PlanMismatch),
            }
            return Ok(PrepareStep::Progress);
        }
        if let Some(source) = self.child {
            if self.frames.len() >= 128 {
                return Err(BoundedError::DepthLimit);
            }
            if self.frames.ready().is_none() {
                self.frames.reserve_step(a)?;
                return Ok(PrepareStep::Progress);
            }
            if !self.frames.reserve_step(a)? {
                return Ok(PrepareStep::Progress);
            }
            a.traverse(1, 0).map_err(BoundedError::Refused)?;
            self.frames
                .push_reserved(Frame {
                    source,
                    next: 0,
                    map: None,
                })
                .map_err(|_| BoundedError::PlanMismatch)?;
            self.child = None;
            return Ok(PrepareStep::Progress);
        }
        if self.map_frames.ready().is_none() {
            self.map_frames.reserve_step(a)?;
            return Ok(PrepareStep::Progress);
        }
        if self.dynamic_step(a)? {
            return Ok(PrepareStep::Progress);
        }
        if self.frames.is_empty() {
            a.traverse(1, 0).map_err(BoundedError::Refused)?;
            let len = self
                .bytes
                .len()
                .checked_sub(self.omitted)
                .ok_or(BoundedError::Overflow)?;
            let bytes = core::mem::take(&mut self.bytes)
                .into_owned()
                .map_err(|_| BoundedError::PlanMismatch)?;
            let holes = core::mem::take(&mut self.holes)
                .into_owned()
                .map_err(|_| BoundedError::PlanMismatch)?;
            let entries = core::mem::take(&mut self.dynamic.entries)
                .into_owned()
                .map_err(|_| BoundedError::PlanMismatch)?;
            self.finished = true;
            return Ok(PrepareStep::Complete(Prepared {
                bytes,
                holes,
                len,
                entries,
                root_payload: self.root_payload,
            }));
        }
        // Reserve metadata before inspecting an instruction so refusal never
        // causes schema inspection to replay. Only map starts consume this slot.
        if self.holes.ready().is_none() {
            self.holes.reserve_step(a)?;
            return Ok(PrepareStep::Progress);
        }
        if !self.holes.reserve_step(a)? {
            return Ok(PrepareStep::Progress);
        }
        if self.map_frames.ready().is_none() {
            self.map_frames.reserve_step(a)?;
            return Ok(PrepareStep::Progress);
        }
        if !self.map_frames.reserve_step(a)? {
            return Ok(PrepareStep::Progress);
        }
        let dynamic = self
            .frames
            .ready()
            .and_then(|s| s.last())
            .and_then(|f| f.map)
            .and_then(|i| self.map_frames.ready().and_then(|s| s.get(i)))
            .is_some_and(|m| matches!(m.state, MapState::Dynamic { .. }));
        a.traverse(1, if dynamic { 64 } else { MAX_HEAD_LEN as u64 })
            .map_err(BoundedError::Refused)?;
        let frame = self
            .frames
            .ready_mut()
            .and_then(|s| s.last_mut())
            .ok_or(BoundedError::PlanMismatch)?;
        let source = frame.source;
        let instruction = source.instruction(frame.next);
        frame.next = frame.next.checked_add(1).ok_or(BoundedError::Overflow)?;
        match instruction {
            Instruction::Head(major, argument) => self.head(major, argument),
            Instruction::Text(text) => self.text = Some(TextEncoder::new(text)),
            Instruction::Bytes(bytes) => self.payload = bytes,
            Instruction::Child(child) => self.child = Some(child),
            Instruction::Entry { next, entry } => {
                // frame.next already includes the one-instruction increment.
                // Subtraction avoids overflow at the upper index boundary.
                if next < frame.next || next - frame.next >= 64 {
                    return Err(BoundedError::PlanMismatch);
                }
                frame.next = next;
                let map = self
                    .map_frames
                    .ready_mut()
                    .and_then(|s| frame.map.and_then(|i| s.get_mut(i)))
                    .ok_or(BoundedError::PlanMismatch)?;
                let MapState::Dynamic { phase, .. } = &mut map.state else {
                    return Err(BoundedError::PlanMismatch);
                };
                if !matches!(phase, EntryPhase::Scan) {
                    return Err(BoundedError::PlanMismatch);
                }
                if let Some((key, value)) = entry {
                    self.dynamic
                        .entries
                        .push_reserved(maps::order::Entry {
                            start: self.bytes.len(),
                            key_end: 0,
                            end: 0,
                            output: 0,
                        })
                        .map_err(|_| BoundedError::PlanMismatch)?;
                    *phase = EntryPhase::Key(value);
                    self.child = Some(key);
                }
            }
            Instruction::UnorderedMap | Instruction::Map => {
                if frame.map.is_some() {
                    return Err(BoundedError::PlanMismatch);
                }
                frame.map = Some(self.map_frames.len());
                self.map_frames
                    .push_reserved(MapFrame {
                        hole: self.holes.len(),
                        state: if matches!(instruction, Instruction::Map) {
                            MapState::Schema { fields: 0 }
                        } else {
                            MapState::Dynamic {
                                start: self.dynamic.entries.len(),
                                phase: EntryPhase::Scan,
                            }
                        },
                    })
                    .map_err(|_| BoundedError::PlanMismatch)?;
                self.holes
                    .push_reserved((self.bytes.len(), MAX_HEAD_LEN))
                    .map_err(|_| BoundedError::PlanMismatch)?;
                self.head = [0; MAX_HEAD_LEN];
                self.head_at = 0;
                self.head_len = MAX_HEAD_LEN;
            }
            Instruction::Field(key, value) => {
                let map = self
                    .map_frames
                    .ready_mut()
                    .and_then(|s| frame.map.and_then(|i| s.get_mut(i)))
                    .ok_or(BoundedError::PlanMismatch)?;
                let MapState::Schema { fields } = &mut map.state else {
                    return Err(BoundedError::PlanMismatch);
                };
                if let Some(value) = value {
                    *fields = add(*fields, 1)?;
                    self.child = Some(value);
                    self.head(MajorType::Unsigned, Argument::Shortest(key));
                }
            }
            Instruction::End => {
                if let Some(index) = frame.map {
                    let map = self
                        .map_frames
                        .ready_mut()
                        .and_then(|s| s.get_mut(index))
                        .ok_or(BoundedError::PlanMismatch)?;
                    let count = match &mut map.state {
                        MapState::Schema { fields } => *fields,
                        MapState::Dynamic { start, phase } => {
                            *phase = EntryPhase::Order;
                            widen(self.dynamic.entries.len() - *start)?
                        }
                    };
                    let mut head = [0; MAX_HEAD_LEN];
                    let len = write_argument(MajorType::Map, Argument::Shortest(count), &mut head);
                    let hole = self
                        .holes
                        .ready_mut()
                        .and_then(|s| s.get_mut(map.hole))
                        .ok_or(BoundedError::PlanMismatch)?;
                    hole.1 = MAX_HEAD_LEN - len;
                    let start = hole.0 + hole.1;
                    self.bytes.ready_mut().ok_or(BoundedError::PlanMismatch)?[start..start + len]
                        .copy_from_slice(&head[..len]);
                    self.omitted = self
                        .omitted
                        .checked_add(hole.1)
                        .ok_or(BoundedError::Overflow)?;
                    if matches!(map.state, MapState::Dynamic { .. }) {
                        return Ok(PrepareStep::Progress);
                    }
                    self.map_frames.pop_ready();
                }
                self.frames.pop_ready();
            }
        }
        Ok(PrepareStep::Progress)
    }
}

/// Flat prepared bytes and header-gap metadata, each with its storage permit.
pub struct Prepared<P> {
    bytes: Owned<u8, P>,
    holes: Owned<(usize, usize), P>,
    len: usize,
    entries: Owned<maps::order::Entry, P>,
    root_payload: Option<usize>,
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
            source: 0,
            hole: 0,
            written: 0,
            finished: false,
            entry: 0,
            entry_offset: 0,
        }
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
    source: usize,
    hole: usize,
    written: usize,
    finished: bool,
    entry: usize,
    entry_offset: usize,
}
