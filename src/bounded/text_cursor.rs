//! Retained NFC preparation and canonical text emission over immutable input.
use super::decode::storage::Storage;
use super::*;
use unicode_normalization::char::{canonical_combining_class, compose, decompose_canonical};
mod initialization;
mod ordering;
pub use ordering::OrderingPosition;
pub mod pipeline;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Read,
    Append,
    Order,
    ReleaseOrdering,
    Compose,
    Measure,
    Allocate,
    Header,
    Emit,
    ReleaseChars,
    Publish,
    ReclaimOrdering,
    ReclaimChars,
    ReclaimBytes,
    ReclaimPermit,
    Finished,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Position {
    pub phase: Phase,
    pub source_bytes: usize,
    pub ordering_index: usize,
    pub ordering_state: OrderingPosition,
    pub composed_input: usize,
    pub composed_output: usize,
    pub measured_scalars: usize,
    pub relocated_scalars: usize,
    pub emitted_bytes: usize,
}

pub enum TextStep<P> {
    Progress,
    Complete(Encoded<P>),
    Finished,
}

/// Each step performs one scalar decomposition, one ordering comparison/swap,
/// one composition, one storage relocation, or one scalar emission. All
/// intermediate values and their reservations remain owned across refusal.
pub type TextEncoder<'a, P> = TextContinuation<&'a str, P>;

/// Normalization progress with an explicit source attachment. Owned decoding
/// uses `()` here and supplies a temporary source borrow to each turn.
#[doc(hidden)]
pub struct TextContinuation<S, P> {
    source: S,
    chars: Storage<char, P>,
    phase: Phase,
    source_at: usize,
    pending: [char; 18],
    pending_len: usize,
    pending_at: usize,
    ordering: ordering::Ordering<P>,
    read: usize,
    written: usize,
    starter: Option<usize>,
    last_class: u8,
    measure_at: usize,
    payload_len: u64,
    header: [u8; MAX_HEAD_LEN],
    header_len: usize,
    emit_at: usize,
    bytes: Vec<u8>,
    permit: Option<P>,
}

impl<P> TextEncoder<'_, P> {
    pub fn step<A: Allocator<Permit = P>>(
        &mut self,
        allocator: &mut A,
    ) -> BoundedResult<TextStep<P>, A> {
        self.step_source(self.source, allocator)
    }
}

impl<S, P> TextContinuation<S, P> {
    pub const fn new(source: S) -> Self {
        Self {
            source,
            chars: Storage::new(),
            phase: Phase::Read,
            source_at: 0,
            pending: ['\0'; 18],
            pending_len: 0,
            pending_at: 0,
            ordering: ordering::Ordering::new(),
            read: 0,
            written: 0,
            starter: None,
            last_class: 0,
            measure_at: 0,
            payload_len: 0,
            header: [0; MAX_HEAD_LEN],
            header_len: 0,
            emit_at: 0,
            bytes: Vec::new(),
            permit: None,
        }
    }

    pub fn position(&self) -> Position {
        Position {
            phase: self.phase,
            source_bytes: self.source_at,
            ordering_index: self.ordering.position(),
            ordering_state: self.ordering.state(),
            composed_input: self.read,
            composed_output: self.written,
            measured_scalars: self.measure_at,
            relocated_scalars: self.chars.relocated(),
            emitted_bytes: self.bytes.len(),
        }
    }

    /// Incomplete bytes are observation only, never a published CBOR value.
    pub fn emitted_prefix(&self) -> &[u8] {
        &self.bytes
    }

    /// Cancel and release one retained resource unit. Admission closes before
    /// cleanup starts; subsequent calls cannot resume text production.
    pub fn reclaim_step<A: Allocator<Permit = P>>(
        &mut self,
        allocator: &mut A,
    ) -> BoundedResult<bool, A> {
        match self.phase {
            Phase::ReclaimOrdering => {
                if self.ordering.reclaim_step(allocator)? {
                    self.phase = Phase::ReclaimChars;
                }
            }
            Phase::ReclaimChars => {
                if self.chars.drain_step(allocator)?.is_none()
                    && self.chars.release_transition_step(allocator)?
                {
                    self.phase = Phase::ReclaimBytes;
                }
            }
            Phase::ReclaimBytes => {
                allocator
                    .traverse(1, core::mem::size_of::<Vec<u8>>() as u64)
                    .map_err(BoundedError::Refused)?;
                self.bytes = Vec::new();
                self.phase = Phase::ReclaimPermit;
            }
            Phase::ReclaimPermit => {
                allocator
                    .traverse(1, core::mem::size_of::<P>() as u64)
                    .map_err(BoundedError::Refused)?;
                self.permit = None;
                self.phase = Phase::Finished;
                return Ok(true);
            }
            Phase::Finished => return Ok(true),
            _ => {
                allocator.traverse(1, 0).map_err(BoundedError::Refused)?;
                self.phase = Phase::ReclaimOrdering;
            }
        }
        Ok(false)
    }

    pub(crate) fn step_source<A: Allocator<Permit = P>>(
        &mut self,
        source: &str,
        allocator: &mut A,
    ) -> BoundedResult<TextStep<P>, A> {
        match self.phase {
            Phase::Read => {
                allocator.traverse(1, 4).map_err(BoundedError::Refused)?;
                let Some(ch) = source[self.source_at..].chars().next() else {
                    self.phase = Phase::Order;
                    return Ok(TextStep::Progress);
                };
                let mut count = 0usize;
                decompose_canonical(ch, |part| {
                    if let Some(slot) = self.pending.get_mut(count) {
                        *slot = part;
                    }
                    count += 1;
                });
                // Unicode's scalar decomposition is bounded independently of
                // input length. Refuse a future table exceeding our scratch.
                if count > self.pending.len() {
                    return Err(BoundedError::OutOfRange);
                }
                self.pending_len = count;
                self.pending_at = 0;
                self.source_at += ch.len_utf8();
                self.phase = Phase::Append;
            }
            Phase::Append => {
                if !self.chars.reserve_step(allocator)? {
                    // Allocation alone does not claim execution progress. Make
                    // one actual relocation, retaining its offset on refusal.
                    if self.chars.relocated() == 0 {
                        self.chars.reserve_step(allocator)?;
                    }
                    return Ok(TextStep::Progress);
                }
                allocator.traverse(1, 4).map_err(BoundedError::Refused)?;
                let ch = self.pending[self.pending_at];
                self.chars
                    .push_reserved(ch)
                    .map_err(|_| BoundedError::PlanMismatch)?;
                self.pending_at += 1;
                self.phase = if self.pending_at == self.pending_len {
                    Phase::Read
                } else {
                    Phase::Append
                };
            }
            Phase::Order => {
                let chars = self.chars.ready_mut().ok_or(BoundedError::PlanMismatch)?;
                if self.ordering.step(chars, allocator)? {
                    self.phase = Phase::ReleaseOrdering;
                }
            }
            Phase::ReleaseOrdering => {
                if self.ordering.reclaim_step(allocator)? {
                    self.phase = Phase::Compose;
                }
            }
            Phase::Compose => {
                allocator.traverse(2, 8).map_err(BoundedError::Refused)?;
                let chars = self.chars.ready_mut().ok_or(BoundedError::PlanMismatch)?;
                if self.read == chars.len() {
                    self.phase = Phase::Measure;
                    return Ok(TextStep::Progress);
                }
                let ch = chars[self.read];
                let class = canonical_combining_class(ch);
                let combined = self.starter.and_then(|at| {
                    if self.last_class == 0 || self.last_class < class {
                        compose(chars[at], ch)
                    } else {
                        None
                    }
                });
                if let Some(combined) = combined {
                    if let Some(at) = self.starter {
                        chars[at] = combined;
                    }
                } else {
                    if class == 0 {
                        self.starter = Some(self.written);
                    }
                    chars[self.written] = ch;
                    self.written += 1;
                    self.last_class = class;
                }
                self.read += 1;
            }
            Phase::Measure => {
                allocator.traverse(1, 4).map_err(BoundedError::Refused)?;
                if self.measure_at == self.written {
                    self.header_len = write_argument(
                        MajorType::Text,
                        Argument::Shortest(self.payload_len),
                        &mut self.header,
                    );
                    self.phase = Phase::Allocate;
                } else {
                    let chars = self.chars.ready().ok_or(BoundedError::PlanMismatch)?;
                    self.payload_len =
                        add(self.payload_len, chars[self.measure_at].len_utf8() as u64)?;
                    self.measure_at += 1;
                }
            }
            Phase::Allocate => {
                let length = add(self.payload_len, self.header_len as u64)?;
                let size = usize::try_from(length).map_err(|_| BoundedError::Overflow)?;
                let permit = allocator.allocate(length).map_err(BoundedError::Refused)?;
                self.bytes
                    .try_reserve_exact(size)
                    .map_err(|_| BoundedError::Allocation { bytes: length })?;
                self.permit = Some(permit);
                self.phase = Phase::Header;
                // Continue to actual emission; a refusal retains the newly
                // allocated output and never repeats allocation admission.
                return self.step_source(source, allocator);
            }
            Phase::Header => {
                allocator
                    .traverse(1, self.header_len as u64)
                    .map_err(BoundedError::Refused)?;
                self.bytes
                    .extend_from_slice(&self.header[..self.header_len]);
                self.phase = Phase::Emit;
            }
            Phase::Emit => {
                allocator.traverse(1, 4).map_err(BoundedError::Refused)?;
                if self.emit_at == self.written {
                    self.phase = Phase::ReleaseChars;
                    return Ok(TextStep::Progress);
                }
                let chars = self.chars.ready().ok_or(BoundedError::PlanMismatch)?;
                let mut encoded = [0; 4];
                self.bytes
                    .extend_from_slice(chars[self.emit_at].encode_utf8(&mut encoded).as_bytes());
                self.emit_at += 1;
            }
            Phase::ReleaseChars => {
                if self.chars.drain_step(allocator)?.is_none()
                    && self.chars.release_transition_step(allocator)?
                {
                    self.phase = Phase::Publish;
                }
            }
            Phase::Publish => {
                allocator
                    .traverse(1, core::mem::size_of::<Encoded<P>>() as u64)
                    .map_err(BoundedError::Refused)?;
                let permit = self.permit.take().ok_or(BoundedError::PlanMismatch)?;
                self.phase = Phase::Finished;
                return Ok(TextStep::Complete(Encoded {
                    bytes: core::mem::take(&mut self.bytes),
                    _permit: permit,
                }));
            }
            Phase::ReclaimOrdering
            | Phase::ReclaimChars
            | Phase::ReclaimBytes
            | Phase::ReclaimPermit => {
                self.reclaim_step(allocator)?;
            }
            Phase::Finished => return Ok(TextStep::Finished),
        }
        Ok(TextStep::Progress)
    }
}
