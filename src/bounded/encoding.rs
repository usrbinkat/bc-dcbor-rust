//! Retained schema traversal and canonical byte preparation.
use super::*;
use decode::storage::Storage;
use text_cursor::{TextEncoder, TextStep};
mod values;

/// One constant-work schema instruction. Implementations must not scan fields,
/// allocate, or recursively visit children while producing an instruction.
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
    End,
}

struct Frame<'a> {
    source: &'a dyn Schema,
    next: usize,
    hole: Option<usize>,
    fields: u64,
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
        }
    }

    fn head(&mut self, major: MajorType, argument: Argument) {
        self.head_len = write_argument(major, argument, &mut self.head);
        self.head_at = 0;
    }

    fn append<A: Allocator<Permit = P>>(&mut self, byte: u8, a: &mut A) -> BoundedResult<bool, A> {
        // Relocation is its own turn, including the last relocated byte.
        if self.bytes.ready().is_none() {
            self.bytes.reserve_step(a)?;
            return Ok(false);
        }
        if !self.bytes.reserve_step(a)? {
            return Ok(false);
        }
        a.traverse(1, 1).map_err(BoundedError::Refused)?;
        self.bytes
            .push_reserved(byte)
            .map_err(|_| BoundedError::PlanMismatch)?;
        Ok(true)
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
            if self.append(self.head[self.head_at], a)? {
                self.head_at += 1;
            }
            return Ok(PrepareStep::Progress);
        }
        if let Some(byte) = self.payload.first().copied() {
            if self.append(byte, a)? {
                self.payload = &self.payload[1..];
            }
            return Ok(PrepareStep::Progress);
        }
        if let Some(encoded) = &self.normalized {
            if let Some(byte) = encoded.as_ref().get(self.normalized_at).copied() {
                if self.append(byte, a)? {
                    self.normalized_at += 1;
                }
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
                    hole: None,
                    fields: 0,
                })
                .map_err(|_| BoundedError::PlanMismatch)?;
            self.child = None;
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
            self.finished = true;
            return Ok(PrepareStep::Complete(Prepared { bytes, holes, len }));
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
        a.traverse(1, MAX_HEAD_LEN as u64)
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
            Instruction::Map => {
                if frame.hole.is_some() {
                    return Err(BoundedError::PlanMismatch);
                }
                frame.hole = Some(self.holes.len());
                self.holes
                    .push_reserved((self.bytes.len(), MAX_HEAD_LEN))
                    .map_err(|_| BoundedError::PlanMismatch)?;
                self.head = [0; MAX_HEAD_LEN];
                self.head_at = 0;
                self.head_len = MAX_HEAD_LEN;
            }
            Instruction::Field(key, value) => {
                if frame.hole.is_none() {
                    return Err(BoundedError::PlanMismatch);
                }
                if let Some(value) = value {
                    frame.fields = add(frame.fields, 1)?;
                    self.child = Some(value);
                    self.head(MajorType::Unsigned, Argument::Shortest(key));
                }
            }
            Instruction::End => {
                if let Some(index) = frame.hole {
                    let mut head = [0; MAX_HEAD_LEN];
                    let len =
                        write_argument(MajorType::Map, Argument::Shortest(frame.fields), &mut head);
                    let hole =
                        &mut self.holes.ready_mut().ok_or(BoundedError::PlanMismatch)?[index];
                    hole.1 = MAX_HEAD_LEN - len;
                    let start = hole.0 + hole.1;
                    self.bytes.ready_mut().ok_or(BoundedError::PlanMismatch)?[start..start + len]
                        .copy_from_slice(&head[..len]);
                    self.omitted = self
                        .omitted
                        .checked_add(hole.1)
                        .ok_or(BoundedError::Overflow)?;
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
}

impl<P> Writer<'_, '_, P> {
    pub fn emitted_prefix(&self) -> &[u8] {
        &self.output[..self.written]
    }
    pub fn step<B: Budget>(
        &mut self,
        b: &mut B,
    ) -> BoundedResult<text_cursor::pipeline::EmitStep, B> {
        use text_cursor::pipeline::EmitStep;
        if self.finished {
            return Ok(EmitStep::Finished);
        }
        if self.output.len() != self.plan.len {
            return Err(BoundedError::OutputSize {
                measured: widen(self.plan.len)?,
                provided: widen(self.output.len())?,
            });
        }
        if let Some(&(start, skip)) = self.plan.holes.as_slice().get(self.hole)
            && self.source == start
        {
            b.traverse(1, 0).map_err(BoundedError::Refused)?;
            self.source += skip;
            self.hole += 1;
            return Ok(EmitStep::Progress);
        }
        if self.source == self.plan.bytes.len() {
            b.traverse(1, 0).map_err(BoundedError::Refused)?;
            if self.written != self.plan.len {
                return Err(BoundedError::PlanMismatch);
            }
            self.finished = true;
            return Ok(EmitStep::Complete);
        }
        let boundary = self
            .plan
            .holes
            .as_slice()
            .get(self.hole)
            .map_or(self.plan.bytes.len(), |h| h.0);
        let count = (boundary - self.source).min(64);
        b.traverse(1, widen(count)?)
            .map_err(BoundedError::Refused)?;
        self.output[self.written..self.written + count]
            .copy_from_slice(&self.plan.bytes.as_slice()[self.source..self.source + count]);
        self.source += count;
        self.written += count;
        Ok(EmitStep::Progress)
    }
}
