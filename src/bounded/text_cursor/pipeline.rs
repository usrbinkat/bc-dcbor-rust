//! Separately retained preparation and allocation-free destination emission.
use super::*;

pub struct PreparedText<P> {
    chars: Owned<char, P>,
    count: usize,
    header: [u8; MAX_HEAD_LEN],
    header_len: usize,
    length: u64,
}

impl<P> PreparedText<P> {
    pub fn len(&self) -> u64 {
        self.length
    }
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    pub fn writer<'p, 'o>(&'p self, output: &'o mut [u8]) -> TextWriter<'p, 'o, P> {
        TextWriter {
            plan: self,
            output,
            position: 0,
            scalar: 0,
            finished: false,
        }
    }
}

pub enum PrepareStep<P> {
    Progress,
    Complete(PreparedText<P>),
    Finished,
}

pub struct TextPreparation<'a, P> {
    cursor: TextEncoder<'a, P>,
    finished: bool,
}

impl<'a, P> TextPreparation<'a, P> {
    pub fn new(source: &'a str) -> Self {
        Self {
            cursor: TextEncoder::new(source),
            finished: false,
        }
    }

    pub fn position(&self) -> Position {
        self.cursor.position()
    }

    pub fn step<A: Allocator<Permit = P>>(
        &mut self,
        allocator: &mut A,
    ) -> BoundedResult<PrepareStep<P>, A> {
        if self.finished {
            return Ok(PrepareStep::Finished);
        }
        match self.cursor.step(allocator)? {
            TextStep::Progress => {}
            _ => return Err(BoundedError::PlanMismatch),
        }
        if self.cursor.phase == Phase::Allocate {
            let length = add(self.cursor.payload_len, self.cursor.header_len as u64)?;
            let chars = core::mem::take(&mut self.cursor.chars)
                .into_owned()
                .map_err(|_| BoundedError::PlanMismatch)?;
            self.finished = true;
            self.cursor.phase = Phase::Finished;
            return Ok(PrepareStep::Complete(PreparedText {
                chars,
                count: self.cursor.written,
                header: self.cursor.header,
                header_len: self.cursor.header_len,
                length,
            }));
        }
        Ok(PrepareStep::Progress)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum EmitStep {
    Progress,
    Complete,
    Finished,
}

/// Borrows both owners for its entire lifetime; no allocation or normalization
/// occurs during writing. A refused step leaves the destination prefix intact.
///
/// The destination remains exclusively borrowed while a writer can resume.
///
/// ```compile_fail,E0506
/// use dcbor::bounded::text_cursor::pipeline::PreparedText;
/// fn overwrite(plan: &PreparedText<()>, output: &mut [u8]) {
///     let writer = plan.writer(output);
///     output[0] = 0;
///     drop(writer);
/// }
/// ```
///
/// A writer cannot outlive the plan owning its normalized scalars.
///
/// ```compile_fail,E0515
/// use dcbor::bounded::text_cursor::pipeline::{PreparedText, TextWriter};
/// fn escape<'a>(plan: PreparedText<()>, output: &'a mut [u8]) -> TextWriter<'a, 'a, ()> {
///     plan.writer(output)
/// }
/// ```
pub struct TextWriter<'p, 'o, P> {
    plan: &'p PreparedText<P>,
    output: &'o mut [u8],
    position: usize,
    scalar: usize,
    finished: bool,
}

impl<P> TextWriter<'_, '_, P> {
    pub fn position(&self) -> usize {
        self.position
    }
    pub fn emitted_prefix(&self) -> &[u8] {
        &self.output[..self.position]
    }

    pub fn step<B: Budget>(&mut self, budget: &mut B) -> BoundedResult<EmitStep, B> {
        if self.finished {
            return Ok(EmitStep::Finished);
        }
        if widen(self.output.len())? != self.plan.length {
            return Err(BoundedError::OutputSize {
                measured: self.plan.length,
                provided: widen(self.output.len())?,
            });
        }
        if self.position == 0 {
            budget
                .traverse(1, self.plan.header_len as u64)
                .map_err(BoundedError::Refused)?;
            self.output[..self.plan.header_len]
                .copy_from_slice(&self.plan.header[..self.plan.header_len]);
            self.position = self.plan.header_len;
        } else if self.scalar < self.plan.count {
            let ch = self.plan.chars.as_slice()[self.scalar];
            budget
                .traverse(1, ch.len_utf8() as u64)
                .map_err(BoundedError::Refused)?;
            let mut bytes = [0; 4];
            let encoded = ch.encode_utf8(&mut bytes).as_bytes();
            let end = self.position + encoded.len();
            self.output[self.position..end].copy_from_slice(encoded);
            self.position = end;
            self.scalar += 1;
        } else {
            budget.traverse(1, 0).map_err(BoundedError::Refused)?;
            self.finished = true;
            return Ok(EmitStep::Complete);
        }
        Ok(EmitStep::Progress)
    }
}
