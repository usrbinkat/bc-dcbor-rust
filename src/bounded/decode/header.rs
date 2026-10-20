//! Retained header acquisition and canonical varint validation.
use super::{BoundedError, Budget, DecodeError, MajorType, WriteWork};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub major: MajorType,
    pub argument: u64,
    pub length: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderStep {
    Progress,
    Complete(Header),
    Finished,
}

/// Borrows complete immutable input. The cursor reads at most one new header
/// byte per acquisition turn and validates the at-most-nine-byte header in a
/// separate admitted turn. Refusal preserves both the bytes and their offset.
/// Payload validation and semantic float checks belong to the enclosing parser.
///
/// The retained input cannot be mutated while the cursor can still read it:
///
/// ```compile_fail,E0502
/// use dcbor::bounded::{Limits, decode::header::HeaderCursor};
/// let mut input = vec![0x18, 0x18];
/// let mut cursor = HeaderCursor::new(&input);
/// input[1] = 0;
/// let mut budget = Limits::new(3, 64, 0);
/// let _ = cursor.step(&mut budget);
/// ```
pub struct HeaderCursor<'a> {
    input: &'a [u8],
    state: HeaderState,
}

/// Borrow-free acquisition state. The enclosing operation supplies its own
/// immutable input on each turn; this type is deliberately crate-private.
pub(crate) struct HeaderState {
    bytes: [u8; 9],
    acquired: usize,
    needed: usize,
    finished: bool,
}

impl<'a> HeaderCursor<'a> {
    pub const fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            state: HeaderState::new(),
        }
    }

    pub const fn acquired(&self) -> usize {
        self.state.acquired()
    }

    pub fn next_work(&self) -> Option<WriteWork> {
        self.state.next_work(self.input.len())
    }

    pub fn step<B: Budget>(
        &mut self,
        budget: &mut B,
    ) -> Result<HeaderStep, DecodeError<B::Refusal>> {
        self.state.step(self.input, budget)
    }
}

impl HeaderState {
    pub(crate) const fn new() -> Self {
        Self {
            bytes: [0; 9],
            acquired: 0,
            needed: 1,
            finished: false,
        }
    }

    /// Actual copied header bytes; this is not inferred from admitted work.
    pub const fn acquired(&self) -> usize {
        self.acquired
    }

    pub fn next_work(&self, input_len: usize) -> Option<WriteWork> {
        if self.finished {
            return None;
        }
        let bytes = if self.acquired == self.needed || self.acquired == input_len {
            self.acquired as u64
        } else {
            1
        };
        Some(WriteWork::new(1, bytes))
    }

    pub fn step<B: Budget>(
        &mut self,
        input: &[u8],
        budget: &mut B,
    ) -> Result<HeaderStep, DecodeError<B::Refusal>> {
        let Some(work) = self.next_work(input.len()) else {
            return Ok(HeaderStep::Finished);
        };
        budget
            .traverse(work.values, work.bytes)
            .map_err(BoundedError::Refused)?;
        if self.acquired == self.needed || self.acquired == input.len() {
            // Terminal invalidity is published once, just like a valid header.
            self.finished = true;
            let (major, argument, length) =
                crate::decode::parse_header_varint(&self.bytes[..self.acquired])?;
            return Ok(HeaderStep::Complete(Header {
                major,
                argument,
                length,
            }));
        }
        let byte = input[self.acquired];
        self.bytes[self.acquired] = byte;
        self.acquired += 1;
        if self.acquired == 1 {
            self.needed = match byte & 31 {
                24 => 2,
                25 => 3,
                26 => 5,
                27 => 9,
                _ => 1,
            };
        }
        Ok(HeaderStep::Progress)
    }
}
