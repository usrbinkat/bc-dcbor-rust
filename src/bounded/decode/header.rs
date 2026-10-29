//! Retained header acquisition and canonical varint validation.
use super::{
    BoundedError, Budget, Caller, Capped, DecodeError, MAX_HEAD_LEN, MajorType, Places,
    ResourceBound, Resumable, Step, Unit, WriteWork, add, at, mul,
};

/// Acquiring one head byte. The operation running the cursor supplies the
/// place.
pub(crate) const ACQUIRE: Unit<Caller> = Unit::new(Caller, 1, 1);

/// Validating a head of its acquired bytes, at most [`MAX_HEAD_LEN`].
pub(crate) const VALIDATE: Capped<Caller> = Capped::new(Caller, 1, MAX_HEAD_LEN as u64);

places! {
    /// The places a [`HeaderCursor`] charges, one term of [`header_bound`]
    /// each.
    pub(crate) enum HeaderPlace {
        Acquisition,
        Validation,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub major: MajorType,
    pub argument: u64,
    pub length: usize,
}

/// Retained header progress: bytes acquired and the next turn's admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Position {
    pub acquired: usize,
    pub next_work: Option<WriteWork>,
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

    pub fn position(&self) -> Position {
        Position {
            acquired: self.acquired(),
            next_work: self.next_work(),
        }
    }

    pub fn step<B: Budget>(
        &mut self,
        budget: &mut B,
    ) -> Result<Step<Header>, DecodeError<B::Refusal>> {
        let place = if self.state.acquired == self.state.needed
            || self.state.acquired == self.input.len()
        {
            HeaderPlace::Validation
        } else {
            HeaderPlace::Acquisition
        };
        at(place, || self.state.step(self.input, budget))
    }
}

/// The [`ResourceBound`] of acquiring and validating one head from an input
/// of `input` bytes ([`HeaderCursor`]): one unit of one byte per head byte
/// acquired, at most [`MAX_HEAD_LEN`], and one unit to validate them;
/// nothing is allocated or retained.
pub fn header_bound(input: u64) -> ResourceBound {
    let terms = HeaderTerms::of(input);
    ResourceBound::of_work(WriteWork::new(
        terms.acquisition.values + terms.validation.values,
        terms.acquisition.bytes + terms.validation.bytes,
    ))
}

/// The terms [`header_bound`] sums, one per [`HeaderPlace`]: at most
/// [`MAX_HEAD_LEN`] acquisitions of one value and one byte, and one
/// validation of one value, so no quantity can overflow.
struct HeaderTerms {
    acquisition: WriteWork,
    validation: WriteWork,
}

impl HeaderTerms {
    fn of(input: u64) -> Self {
        const { assert!(ACQUIRE.values() == 1 && ACQUIRE.bytes() == 1 && VALIDATE.values() == 1) };
        let acquired = input.min(MAX_HEAD_LEN as u64);
        Self {
            acquisition: WriteWork::new(acquired, acquired),
            validation: WriteWork::new(1, acquired),
        }
    }
}

impl Places for HeaderTerms {
    type Place = HeaderPlace;

    fn term(&self, place: HeaderPlace) -> ResourceBound {
        match place {
            HeaderPlace::Acquisition => ResourceBound::of_work(self.acquisition),
            HeaderPlace::Validation => ResourceBound::of_work(self.validation),
        }
    }
}

/// The work of acquiring and validating every head of an input of `input`
/// bytes: each input byte acquired at most once, and one validation per
/// node and one of a head the input ends inside, over at most the input's
/// bytes in all.
pub(crate) fn heads_work<R>(input: u64) -> Result<WriteWork, BoundedError<R>> {
    ACQUIRE.times(input)?.then(WriteWork::new(
        mul(add(input, 1)?, VALIDATE.values())?,
        input,
    ))
}

impl<B: Budget> Resumable<B> for HeaderCursor<'_> {
    type Output = Header;
    type Error = DecodeError<B::Refusal>;
    type Position = Position;

    fn step(&mut self, budget: &mut B) -> Result<Step<Header>, Self::Error> {
        HeaderCursor::step(self, budget)
    }

    fn position(&mut self) -> Position {
        HeaderCursor::position(self)
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
        Some(
            if self.acquired == self.needed || self.acquired == input_len {
                WriteWork::new(VALIDATE.values(), self.acquired as u64)
            } else {
                WriteWork::new(ACQUIRE.values(), ACQUIRE.bytes())
            },
        )
    }

    pub fn step<B: Budget>(
        &mut self,
        input: &[u8],
        budget: &mut B,
    ) -> Result<Step<Header>, DecodeError<B::Refusal>> {
        if self.finished {
            return Ok(Step::Finished);
        }
        let complete = self.acquired == self.needed || self.acquired == input.len();
        if complete {
            VALIDATE.admit(budget, self.acquired as u64)?;
        } else {
            ACQUIRE.admit(budget)?;
        }
        if complete {
            // Terminal invalidity is published once, just like a valid header;
            // either way the cursor is finished.
            self.finished = true;
            let (major, argument, length) =
                crate::decode::parse_header_varint(&self.bytes[..self.acquired])?;
            return Ok(Step::Complete(Header {
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
        Ok(Step::Progress)
    }
}

/// Place attribution of a head's acquisition, which this crate's tests
/// record under `std`.
#[cfg(test)]
#[cfg(feature = "std")]
mod attribution {
    use super::*;
    use crate::bounded::Place;
    use crate::bounded::places::{self, Factor, Ledgered, Run, WORK};

    /// A head whose acquisition charges `place`: a place without a witness
    /// does not compile.
    fn witness(place: HeaderPlace) -> &'static [u8] {
        match place {
            HeaderPlace::Acquisition | HeaderPlace::Validation => &[0x19, 0x01, 0x00],
        }
    }

    /// Every place a head's acquisition charges is within its term; each
    /// place's witness charges it. Beside the witnesses: a head of the most
    /// bytes, an input that ends inside a head, and a reserved head. Each
    /// input reaches the outcome it states, a valid head or an invalid one;
    /// any other outcome fails, naming the input.
    #[test]
    fn every_place_of_a_head_is_within_its_term() {
        let mut inputs: Vec<(String, Option<HeaderPlace>, &[u8], bool)> = HeaderPlace::ALL
            .iter()
            .map(|&place| {
                (
                    format!("witness of {place:?}"),
                    Some(place),
                    witness(place),
                    true,
                )
            })
            .collect();
        inputs.extend([
            (
                "widest".to_string(),
                None,
                &[0x1b, 0, 0, 0, 1, 0, 0, 0, 0][..],
                true,
            ),
            ("truncated".to_string(), None, &[0x1a, 0, 0][..], false),
            ("reserved".to_string(), None, &[0x1c][..], false),
        ]);
        let mut runs = Vec::new();
        let mut witnesses = Vec::new();
        for (name, place, input, valid) in inputs {
            let mut policy = Ledgered::new();
            let mut cursor = HeaderCursor::new(input);
            let outcome = crate::bounded::within(&name, header_bound(input.len() as u64), || {
                match cursor.step(&mut policy) {
                    Ok(Step::Progress) => core::ops::ControlFlow::Continue(()),
                    Ok(Step::Complete(header)) => core::ops::ControlFlow::Break(Ok(header)),
                    Ok(Step::Finished) => panic!("{name}: finished without an outcome"),
                    Err(DecodeError::Invalid(error)) => core::ops::ControlFlow::Break(Err(error)),
                    Err(error) => panic!("{name}: {error:?}"),
                }
            });
            assert_eq!(outcome.is_ok(), valid, "{name}: {outcome:?}");
            if let Some(place) = place {
                witnesses.push((runs.len(), place));
            }
            runs.push(Run {
                outcome: if valid {
                    places::Outcome::Published
                } else {
                    places::Outcome::Invalid
                },
                name,
                policy,
                terms: HeaderTerms::of(input.len() as u64),
            });
        }
        places::check(&runs);
        places::witnessed(&runs, &witnesses);
        // Both terms are exact on a head the input holds whole: each byte
        // acquired once, then one validation over them.
        places::Tightness::new("header")
            .places(&runs, &witnesses, |place| match place {
                HeaderPlace::Acquisition | HeaderPlace::Validation => Factor::Within(1),
            })
            .joint(
                &runs,
                "widest",
                WORK,
                "a head of the most bytes: every byte acquired, then all validated at once",
            )
            .finish();
    }
}
