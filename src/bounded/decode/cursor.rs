//! Retained iterative canonical parser over a complete immutable input.
use super::comparison::{ComparisonStep, KeyComparison};
use super::header::{Header, HeaderCursor, HeaderStep};
use super::storage::Storage;
use super::utf8::Utf8;
use super::*;
use crate::bounded::text_cursor::{TextEncoder, TextStep};
use core::cmp::Ordering;
use core::mem::MaybeUninit;
use unicode_normalization::IsNormalized;
mod initialization;
mod observation;
mod publication;
pub use observation::Resources;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Header,
    Interpret,
    Utf8,
    InitializeNormalizer,
    Normalize,
    CheckText,
    ReleaseText,
    Entry,
    Frame,
    Complete,
    Compare,
    Attach,
    ReleaseStack,
    Publish,
    ReclaimNormalizer,
    ReclaimNormalized,
    ReclaimEntries,
    ReclaimStack,
    Finished,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Position {
    pub phase: Phase,
    pub input: usize,
    pub header_bytes: usize,
    pub payload_validated: usize,
    pub compared_bytes: usize,
    pub completed_children: usize,
    pub nodes: usize,
    pub arena_relocated: usize,
    pub stack_relocated: usize,
}

pub enum DecodeStep<'a, P> {
    Progress,
    Complete(Document<'a, P>),
    Finished,
}

pub struct Decoder<'a, P> {
    input: &'a [u8],
    options: Options,
    entries: Storage<Entry<'a>, P>,
    stack: Storage<Frame, P>,
    phase: Phase,
    header: HeaderCursor<'a>,
    parsed: Option<Header>,
    start: usize,
    position: usize,
    payload_end: usize,
    kind: Kind<'a>,
    children: u64,
    completed: usize,
    child_count: usize,
    utf8: Option<Utf8<'a>>,
    normalizer: MaybeUninit<TextEncoder<'a, P>>,
    normalizer_init: usize,
    normalized: Option<Encoded<P>>,
    text_compared: usize,
    comparison: Option<KeyComparison<'a>>,
}

impl<'a, P> Decoder<'a, P> {
    pub fn new(input: &'a [u8], options: Options) -> Self {
        Self {
            input,
            options,
            entries: Storage::new(),
            stack: Storage::new(),
            phase: Phase::Header,
            header: HeaderCursor::new(input),
            parsed: None,
            start: 0,
            position: 0,
            payload_end: 0,
            kind: Kind::Null,
            children: 0,
            completed: 0,
            child_count: 0,
            utf8: None,
            normalizer: MaybeUninit::uninit(),
            normalizer_init: 0,
            normalized: None,
            text_compared: 0,
            comparison: None,
        }
    }

    pub fn position(&self) -> Position {
        Position {
            phase: self.phase,
            input: self.position,
            header_bytes: self.header.acquired(),
            payload_validated: self.utf8.as_ref().map_or(0, |text| text.position),
            compared_bytes: self
                .comparison
                .as_ref()
                .map_or(self.text_compared, KeyComparison::position),
            completed_children: self.child_count,
            nodes: self.entries.len(),
            arena_relocated: self.entries.relocated(),
            stack_relocated: self.stack.relocated(),
        }
    }

    pub fn step<A: Allocator<Permit = P>>(
        &mut self,
        allocator: &mut A,
    ) -> Result<DecodeStep<'a, P>, DecodeError<A::Refusal>> {
        let result = self.advance(allocator);
        if matches!(&result, Err(error) if !matches!(error, DecodeError::Resource(BoundedError::Refused(_))))
        {
            self.phase = Phase::ReclaimNormalizer;
        }
        result
    }

    /// Close parser admission and reclaim one resource unit. Terminal errors
    /// enter this same path, retaining partial relocation and normalization.
    pub fn reclaim_step<A: Allocator<Permit = P>>(
        &mut self,
        allocator: &mut A,
    ) -> BoundedResult<bool, A> {
        match self.phase {
            Phase::ReclaimNormalizer => {
                if self.normalizer_init == TextEncoder::<P>::INIT_STEPS {
                    // SAFETY: all resource-free metadata fields were initialized
                    // before the normalizer could acquire any resources.
                    let normalizer = unsafe { self.normalizer.assume_init_mut() };
                    if !normalizer.reclaim_step(allocator)? {
                        return Ok(false);
                    }
                }
                allocator.traverse(1, 0).map_err(BoundedError::Refused)?;
                self.normalizer_init = 0;
                self.phase = Phase::ReclaimNormalized;
            }
            Phase::ReclaimNormalized => {
                allocator
                    .traverse(1, core::mem::size_of::<Encoded<P>>() as u64)
                    .map_err(BoundedError::Refused)?;
                self.normalized = None;
                self.phase = Phase::ReclaimEntries;
            }
            Phase::ReclaimEntries => {
                if self.entries.drain_step(allocator)?.is_none()
                    && self.entries.release_transition_step(allocator)?
                {
                    self.phase = Phase::ReclaimStack;
                }
            }
            Phase::ReclaimStack => {
                if self.stack.drain_step(allocator)?.is_none()
                    && self.stack.release_transition_step(allocator)?
                {
                    self.phase = Phase::Finished;
                    return Ok(true);
                }
            }
            Phase::Finished => return Ok(true),
            _ => {
                allocator.traverse(1, 0).map_err(BoundedError::Refused)?;
                self.phase = Phase::ReclaimNormalizer;
            }
        }
        Ok(false)
    }

    fn next_header(&mut self) {
        self.start = self.position;
        self.header = HeaderCursor::new(&self.input[self.position..]);
        self.parsed = None;
        self.children = 0;
        self.utf8 = None;
        self.comparison = None;
        self.phase = Phase::Header;
    }

    fn advance<A: Allocator<Permit = P>>(
        &mut self,
        allocator: &mut A,
    ) -> Result<DecodeStep<'a, P>, DecodeError<A::Refusal>> {
        match self.phase {
            Phase::Header => match self.header.step(allocator)? {
                HeaderStep::Progress => {}
                HeaderStep::Complete(header) => {
                    self.position += header.length;
                    self.parsed = Some(header);
                    self.phase = Phase::Interpret;
                }
                HeaderStep::Finished => return Err(BoundedError::PlanMismatch.into()),
            },
            Phase::Interpret => {
                allocator.traverse(1, 9).map_err(BoundedError::Refused)?;
                let header = self.parsed.ok_or(BoundedError::PlanMismatch)?;
                self.phase = Phase::Entry;
                self.kind = match header.major {
                    MajorType::Unsigned => Kind::Unsigned(header.argument),
                    MajorType::Negative => {
                        if header.argument > i64::MAX as u64 {
                            return Err(Error::OutOfRange.into());
                        }
                        Kind::Negative(-1 - header.argument as i64)
                    }
                    MajorType::ByteString | MajorType::Text => {
                        if header.argument > widen(self.input.len() - self.position)? {
                            return Err(Error::Underrun.into());
                        }
                        let length =
                            usize::try_from(header.argument).map_err(|_| BoundedError::Overflow)?;
                        let end = self
                            .position
                            .checked_add(length)
                            .ok_or(BoundedError::Overflow)?;
                        let bytes = self.input.get(self.position..end).ok_or(Error::Underrun)?;
                        if header.major == MajorType::Text {
                            self.payload_end = end;
                            self.utf8 = Some(Utf8::new(bytes));
                            self.phase = Phase::Utf8;
                            Kind::Null
                        } else {
                            // Byte-string payload is opaque: validation is the
                            // checked extent, not an artificial whole-byte scan.
                            self.position = end;
                            Kind::Bytes(bytes)
                        }
                    }
                    MajorType::Array => {
                        self.children = header.argument;
                        Kind::Array(header.argument)
                    }
                    MajorType::Map => {
                        if header.argument > widen((self.input.len() - self.position) / 2)? {
                            return Err(Error::Underrun.into());
                        }
                        self.children = header
                            .argument
                            .checked_mul(2)
                            .ok_or(BoundedError::Overflow)?;
                        Kind::Map(header.argument)
                    }
                    MajorType::Tagged => {
                        self.children = 1;
                        Kind::Tagged(header.argument)
                    }
                    MajorType::Simple => match header.length {
                        3 => {
                            let n = f16::from_bits(header.argument as u16);
                            validate_canonical_f16(n)?;
                            Kind::Float(n.to_f64())
                        }
                        5 => {
                            let n = f32::from_bits(header.argument as u32);
                            validate_canonical_f32(n)?;
                            Kind::Float(f64::from(n))
                        }
                        9 => {
                            let n = f64::from_bits(header.argument);
                            validate_canonical_f64(n)?;
                            Kind::Float(n)
                        }
                        _ => match header.argument {
                            20 => Kind::Bool(false),
                            21 => Kind::Bool(true),
                            22 => Kind::Null,
                            _ => return Err(Error::InvalidSimpleValue.into()),
                        },
                    },
                };
                if self.children > widen(self.input.len() - self.position)? {
                    return Err(Error::Underrun.into());
                }
                if self.children > 0 && self.stack.len() >= self.options.max_depth {
                    return Err(DecodeError::DepthLimit {
                        limit: self.options.max_depth,
                    });
                }
            }
            Phase::Utf8 => {
                let validator = self.utf8.as_mut().ok_or(BoundedError::PlanMismatch)?;
                if let Some(text) = validator.step(allocator)? {
                    self.kind = Kind::Text(text);
                    self.position = self.payload_end;
                    match (&validator.quick, self.options.text) {
                        (IsNormalized::Yes, _) => self.phase = Phase::Entry,
                        (_, TextPolicy::QuickOnly) => return Err(DecodeError::UnprovenText),
                        (IsNormalized::No, _) => return Err(Error::NonCanonicalString.into()),
                        (IsNormalized::Maybe, _) => {
                            self.normalizer_init = 0;
                            self.phase = Phase::InitializeNormalizer;
                        }
                    }
                }
            }
            Phase::InitializeNormalizer => {
                let Kind::Text(source) = self.kind else {
                    return Err(BoundedError::PlanMismatch.into());
                };
                // SAFETY: this final-location slot is not exposed until every
                // initialization step has committed. Its prefix owns no resources.
                if unsafe {
                    TextEncoder::initialize_step(
                        self.normalizer.as_mut_ptr(),
                        source,
                        &mut self.normalizer_init,
                        allocator,
                    )?
                } {
                    self.phase = Phase::Normalize;
                }
            }
            Phase::Normalize => {
                if self.normalizer_init != TextEncoder::<P>::INIT_STEPS {
                    return Err(BoundedError::PlanMismatch.into());
                }
                let normalizer = unsafe { self.normalizer.assume_init_mut() };
                match normalizer.step(allocator)? {
                    TextStep::Progress => {}
                    TextStep::Complete(bytes) => {
                        self.normalized = Some(bytes);
                        // Completion has already drained the normalizer scratch
                        // and transferred its output reservation. The old slot
                        // may now be reused without a whole-state destructor.
                        self.normalizer_init = 0;
                        self.text_compared = 0;
                        self.phase = Phase::CheckText;
                    }
                    TextStep::Finished => return Err(BoundedError::PlanMismatch.into()),
                }
            }
            Phase::CheckText => {
                let canonical = self
                    .normalized
                    .as_ref()
                    .ok_or(BoundedError::PlanMismatch)?
                    .as_ref();
                let original = &self.input[self.start..self.position];
                let remaining = canonical.len().min(original.len()) - self.text_compared;
                let count = remaining.min(64);
                allocator
                    .traverse(1, count as u64)
                    .map_err(BoundedError::Refused)?;
                let end = self.text_compared + count;
                if canonical[self.text_compared..end] != original[self.text_compared..end] {
                    return Err(Error::NonCanonicalString.into());
                }
                self.text_compared = end;
                if end == canonical.len().min(original.len()) {
                    if canonical.len() != original.len() {
                        return Err(Error::NonCanonicalString.into());
                    }
                    self.phase = Phase::ReleaseText;
                }
            }
            Phase::ReleaseText => {
                allocator
                    .traverse(1, core::mem::size_of::<Encoded<P>>() as u64)
                    .map_err(BoundedError::Refused)?;
                self.normalized = None;
                self.phase = Phase::Entry;
            }
            Phase::Entry => {
                if !self.entries.reserve_step(allocator)? {
                    if self.entries.relocated() == 0 {
                        self.entries.reserve_step(allocator)?;
                    }
                    return Ok(DecodeStep::Progress);
                }
                allocator.traverse(1, 0).map_err(BoundedError::Refused)?;
                self.completed = self.entries.len();
                self.entries
                    .push_reserved(Entry {
                        kind: self.kind,
                        start: self.start,
                        end: self.position,
                        next: self.completed + 1,
                    })
                    .map_err(|_| BoundedError::PlanMismatch)?;
                self.phase = if self.children > 0 {
                    Phase::Frame
                } else {
                    Phase::Complete
                };
            }
            Phase::Frame => {
                if !self.stack.reserve_step(allocator)? {
                    if self.stack.relocated() == 0 {
                        self.stack.reserve_step(allocator)?;
                    }
                    return Ok(DecodeStep::Progress);
                }
                allocator.traverse(1, 0).map_err(BoundedError::Refused)?;
                self.stack
                    .push_reserved(Frame {
                        node: self.completed,
                        remaining: self.children,
                        map: matches!(self.kind, Kind::Map(_)),
                        key: true,
                        previous_key: None,
                    })
                    .map_err(|_| BoundedError::PlanMismatch)?;
                self.next_header();
            }
            Phase::Complete => {
                allocator.traverse(1, 0).map_err(BoundedError::Refused)?;
                let stack = self.stack.ready().ok_or(BoundedError::PlanMismatch)?;
                let Some(parent) = stack.last() else {
                    if self.position != self.input.len() {
                        return Err(Error::UnusedData(self.input.len() - self.position).into());
                    }
                    self.phase = Phase::ReleaseStack;
                    return Ok(DecodeStep::Progress);
                };
                self.phase = Phase::Attach;
                if parent.map
                    && parent.key
                    && let Some((start, end)) = parent.previous_key
                {
                    let entries = self.entries.ready().ok_or(BoundedError::PlanMismatch)?;
                    let entry = &entries[self.completed];
                    self.comparison = Some(KeyComparison::new(
                        &self.input[start..end],
                        &self.input[entry.start..entry.end],
                    ));
                    self.phase = Phase::Compare;
                }
            }
            Phase::ReleaseStack => {
                if self.stack.release_transition_step(allocator)? {
                    self.phase = Phase::Publish;
                }
            }
            Phase::Publish => {
                allocator.traverse(1, 0).map_err(BoundedError::Refused)?;
                let entries = core::mem::take(&mut self.entries)
                    .into_owned()
                    .map_err(|_| BoundedError::PlanMismatch)?;
                self.phase = Phase::Finished;
                return Ok(DecodeStep::Complete(Document {
                    input: self.input,
                    entries,
                }));
            }
            Phase::Compare => {
                match self
                    .comparison
                    .as_mut()
                    .ok_or(BoundedError::PlanMismatch)?
                    .step(allocator)?
                {
                    ComparisonStep::Progress => {}
                    ComparisonStep::Complete(Ordering::Less) => self.phase = Phase::Attach,
                    ComparisonStep::Complete(Ordering::Equal) => {
                        return Err(Error::DuplicateMapKey.into());
                    }
                    ComparisonStep::Complete(Ordering::Greater) => {
                        return Err(Error::MisorderedMapKey.into());
                    }
                    ComparisonStep::Finished => return Err(BoundedError::PlanMismatch.into()),
                }
            }
            Phase::Attach => {
                allocator.traverse(1, 0).map_err(BoundedError::Refused)?;
                let parent = self
                    .stack
                    .ready_mut()
                    .and_then(|stack| stack.last_mut())
                    .ok_or(BoundedError::PlanMismatch)?;
                let entries = self.entries.ready_mut().ok_or(BoundedError::PlanMismatch)?;
                if parent.map && parent.key {
                    let entry = &entries[self.completed];
                    parent.previous_key = Some((entry.start, entry.end));
                }
                parent.key = !parent.key;
                parent.remaining -= 1;
                self.child_count += 1;
                if parent.remaining == 0 {
                    self.completed = parent.node;
                    let next = entries.len();
                    entries[self.completed].end = self.position;
                    entries[self.completed].next = next;
                    self.stack.pop_ready();
                    self.phase = Phase::Complete;
                } else {
                    self.next_header();
                }
            }
            Phase::ReclaimNormalizer
            | Phase::ReclaimNormalized
            | Phase::ReclaimEntries
            | Phase::ReclaimStack => {
                self.reclaim_step(allocator)?;
            }
            Phase::Finished => return Ok(DecodeStep::Finished),
        }
        Ok(DecodeStep::Progress)
    }
}
