//! Retained parsing and owned UTF-8 construction with an exact output permit.
use super::cursor::{DecodeStep, Decoder};
use super::*;

/// The value's allocation is destroyed before its reservation.
pub struct OwnedString<P> {
    value: String,
    _permit: P,
}

impl<P> OwnedString<P> {
    pub fn value(&self) -> &String {
        &self.value
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Parse,
    Inspect,
    Allocate,
    Copy,
    Publish,
    Finished,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Position {
    pub phase: Phase,
    pub parser: super::cursor::Position,
    pub copied_bytes: usize,
}

pub enum StringStep<P> {
    Progress,
    Complete(OwnedString<P>),
    Finished,
}

/// Holds parser storage until construction completes. Source text is borrowed
/// from immutable input, while the completed string owns its copied payload.
pub struct StringDecoder<'a, P> {
    parser: Decoder<'a, P>,
    document: Option<Document<'a, P>>,
    source: &'a str,
    value: String,
    permit: Option<P>,
    phase: Phase,
}

impl<'a, P> StringDecoder<'a, P> {
    pub fn new(input: &'a [u8], options: Options) -> Self {
        Self {
            parser: Decoder::new(input, options),
            document: None,
            source: "",
            value: String::new(),
            permit: None,
            phase: Phase::Parse,
        }
    }

    pub fn position(&self) -> Position {
        Position {
            phase: self.phase,
            parser: self.parser.position(),
            copied_bytes: self.value.len(),
        }
    }

    pub fn step<A: Allocator<Permit = P>>(
        &mut self,
        allocator: &mut A,
    ) -> ConstructResult<StringStep<P>, A> {
        let result = self.advance(allocator);
        if matches!(&result, Err(error) if !matches!(error, DecodeError::Resource(BoundedError::Refused(_))))
        {
            self.value = String::new();
            self.permit = None;
            self.document = None;
            self.phase = Phase::Finished;
        }
        result
    }

    fn advance<A: Allocator<Permit = P>>(
        &mut self,
        allocator: &mut A,
    ) -> ConstructResult<StringStep<P>, A> {
        match self.phase {
            Phase::Parse => match self.parser.step(allocator)? {
                DecodeStep::Progress => {}
                DecodeStep::Complete(document) => {
                    self.document = Some(document);
                    self.phase = Phase::Inspect;
                }
                DecodeStep::Finished => return Err(BoundedError::PlanMismatch.into()),
            },
            Phase::Inspect => {
                allocator.traverse(1, 0).map_err(BoundedError::Refused)?;
                let document = self.document.as_ref().ok_or(BoundedError::PlanMismatch)?;
                let Kind::Text(source) = document.root().kind() else {
                    return Err(wrong_type());
                };
                self.source = source;
                self.phase = Phase::Allocate;
            }
            Phase::Allocate => {
                let bytes = widen(self.source.len())?;
                let permit = allocator.allocate(bytes).map_err(BoundedError::Refused)?;
                self.value
                    .try_reserve_exact(self.source.len())
                    .map_err(|_| BoundedError::Allocation { bytes })?;
                self.permit = Some(permit);
                self.phase = Phase::Copy;
                return self.advance(allocator);
            }
            Phase::Copy => {
                let start = self.value.len();
                let mut end = start + (self.source.len() - start).min(64);
                // A UTF-8 boundary is at most three bytes before this endpoint.
                while !self.source.is_char_boundary(end) {
                    end -= 1;
                }
                allocator
                    .traverse(1, widen(end - start)?)
                    .map_err(BoundedError::Refused)?;
                self.value.push_str(&self.source[start..end]);
                if end == self.source.len() {
                    self.phase = Phase::Publish;
                }
            }
            Phase::Publish => {
                allocator.traverse(1, 0).map_err(BoundedError::Refused)?;
                let permit = self.permit.take().ok_or(BoundedError::PlanMismatch)?;
                self.document = None;
                self.phase = Phase::Finished;
                return Ok(StringStep::Complete(OwnedString {
                    value: core::mem::take(&mut self.value),
                    _permit: permit,
                }));
            }
            Phase::Finished => return Ok(StringStep::Finished),
        }
        Ok(StringStep::Progress)
    }
}
