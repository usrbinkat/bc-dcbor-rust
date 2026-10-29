//! Retained parsing and owned UTF-8 construction with an exact output permit.
use super::cursor::Decoder;
use super::*;

places! {
    /// The places a [`StringDecoder`] charges, one term of [`string_bound`]
    /// each.
    pub(crate) enum StringPlace {
        /// The retained parse ([`super::cursor::retained_decode_bound`]).
        Parse,
        Inspection,
        /// The string's allocation and its copies.
        Copies,
        Publication,
    }
}

/// Inspecting the parsed root.
const INSPECT: Unit<StringPlace> = Unit::new(StringPlace::Inspection, 1, 0);

/// Copying the source into the string: one value and at most a quantum of
/// bytes, at most a scalar's continuation bytes fewer to end on a boundary.
const COPY: Capped<StringPlace> = Capped::new(
    StringPlace::Copies,
    1,
    super::construction::stable::QUANTUM as u64,
);

/// The fewest bytes a copy before the last covers: a quantum less a
/// scalar's continuation bytes.
const COPIED: u64 = COPY.cap() - (char::MAX.len_utf8() as u64 - 1);

/// Publishing the string.
const PUBLISH: Unit<StringPlace> = Unit::new(StringPlace::Publication, 1, 0);

/// Releasing the string with permits of `P`: its bytes freed and its permit
/// dropped, one value and the bytes of both. Admitted before the string is
/// requested, so its release, by a terminal error or by whoever drops the
/// published string, is paid for.
const fn string_released<P>() -> Unit<StringPlace> {
    const { Unit::written::<(String, Option<P>)>(StringPlace::Copies) }
}

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
    /// The source text is known; the string's release is admitted next,
    /// before it is requested.
    Release,
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
    ) -> ConstructResult<Step<OwnedString<P>>, A> {
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
    ) -> ConstructResult<Step<OwnedString<P>>, A> {
        match self.phase {
            Phase::Parse => match at(StringPlace::Parse, || self.parser.step(allocator))? {
                Step::Progress => {}
                Step::Complete(document) => {
                    self.document = Some(document);
                    self.phase = Phase::Inspect;
                }
                Step::Finished => return Err(BoundedError::PlanMismatch.into()),
            },
            Phase::Inspect => {
                INSPECT.admit(allocator)?;
                let document = self.document.as_ref().ok_or(BoundedError::PlanMismatch)?;
                let Kind::Text(source) = document.root().kind() else {
                    return Err(wrong_type());
                };
                self.source = source;
                self.phase = Phase::Release;
            }
            Phase::Release => {
                string_released::<P>().admit(allocator)?;
                self.phase = Phase::Allocate;
            }
            Phase::Allocate => {
                let bytes = widen(self.source.len())?;
                let permit = at(StringPlace::Copies, || allocator.allocate(bytes))
                    .map_err(BoundedError::Refused)?;
                self.value
                    .try_reserve_exact(self.source.len())
                    .map_err(|_| BoundedError::Allocation { bytes })?;
                self.permit = Some(permit);
                self.phase = Phase::Copy;
                return self.advance(allocator);
            }
            Phase::Copy => {
                let start = self.value.len();
                let mut end =
                    start + (self.source.len() - start).min(super::construction::stable::QUANTUM);
                // A UTF-8 boundary is at most three bytes before this endpoint.
                while !self.source.is_char_boundary(end) {
                    end -= 1;
                }
                COPY.admit(allocator, widen(end - start)?)?;
                self.value.push_str(&self.source[start..end]);
                if end == self.source.len() {
                    self.phase = Phase::Publish;
                }
            }
            Phase::Publish => {
                PUBLISH.admit(allocator)?;
                let permit = self.permit.take().ok_or(BoundedError::PlanMismatch)?;
                self.document = None;
                self.phase = Phase::Finished;
                return Ok(Step::Complete(OwnedString {
                    value: core::mem::take(&mut self.value),
                    _permit: permit,
                }));
            }
            Phase::Finished => return Ok(Step::Finished),
        }
        Ok(Step::Progress)
    }
}

/// The [`ResourceBound`] of decoding a text of an input of at most `input`
/// bytes into an owned string ([`StringDecoder`]) under `options`: the
/// retained parse ([`super::cursor::retained_decode_bound`]), whose document
/// is held throughout; the inspection; the string's release, admitted before
/// it is requested, and its allocation of at most every input byte; its
/// copies in units of at least 61 bytes (64 less a scalar's continuation
/// bytes), every byte once; and publication. A terminal error releases
/// everything at once, each release paid for by its acquisition. The string
/// is what publication retains.
pub fn string_bound<P, R>(input: u64, options: Options) -> Result<ResourceBound, BoundedError<R>> {
    StringTerms::of::<P, R>(input, options)?.bound()
}

/// The terms [`string_bound`] sums, one per [`StringPlace`].
struct StringTerms {
    parse: ResourceBound,
    inspection: WriteWork,
    copies: ResourceBound,
    publication: WriteWork,
}

impl StringTerms {
    fn of<P, R>(input: u64, options: Options) -> Result<Self, BoundedError<R>> {
        // Every copy before the last covers at most a scalar's continuation
        // bytes short of a quantum; the last is partial.
        let copies = add(input.div_ceil(COPIED), 1)?;
        let released = string_released::<P>().times(1)?;
        Ok(Self {
            parse: super::cursor::retained_decode_bound::<P, R>(input, options)?,
            inspection: INSPECT.times(1)?,
            copies: ResourceBound {
                values: add(mul(copies, COPY.values())?, released.values)?,
                bytes: add(input, released.bytes)?,
                allocated: input,
                peak: input,
                retained: input,
            },
            publication: PUBLISH.times(1)?,
        })
    }
}

impl Places for StringTerms {
    type Place = StringPlace;

    fn term(&self, place: StringPlace) -> ResourceBound {
        match place {
            // Publication drops the document: the string is all it retains.
            // The document held beside the copies is [`Self::peak`]'s.
            StringPlace::Parse => ResourceBound {
                retained: 0,
                ..self.parse
            },
            StringPlace::Inspection => ResourceBound::of_work(self.inspection),
            StringPlace::Copies => self.copies,
            StringPlace::Publication => ResourceBound::of_work(self.publication),
        }
    }

    /// The document is held throughout: the string is built beside it.
    fn peak<R>(&self) -> Result<u64, BoundedError<R>> {
        self.parse.then::<R>(self.copies).map(|bound| bound.peak)
    }
}

impl<'a, P, A: Allocator<Permit = P>> Resumable<A> for StringDecoder<'a, P> {
    type Output = OwnedString<P>;
    type Error = DecodeError<A::Refusal>;
    type Position = Position;

    fn step(&mut self, allocator: &mut A) -> ConstructResult<Step<OwnedString<P>>, A> {
        StringDecoder::step(self, allocator)
    }

    fn position(&mut self) -> Position {
        StringDecoder::position(self)
    }
}

/// Place attribution of a string decode, which this crate's tests record
/// under `std`.
#[cfg(test)]
#[cfg(feature = "std")]
mod attribution {
    use super::*;
    use crate::CBOR;
    use crate::bounded::places::{self, Dimension, Factor, Ledgered, Permit, Run, WORK};
    use crate::bounded::within;
    use core::ops::ControlFlow;

    /// An input whose string decode charges `place`: a place without a
    /// witness does not compile. Scalars of several bytes cross the copies'
    /// quantum boundaries.
    fn witness(place: StringPlace) -> Vec<u8> {
        match place {
            StringPlace::Parse
            | StringPlace::Inspection
            | StringPlace::Copies
            | StringPlace::Publication => {
                CBOR::from("\u{1f600}\u{e9}".repeat(200).as_str()).to_cbor_data()
            }
        }
    }

    /// Every place a string decode charges is within its term, the string it
    /// publishes held until the check; each place's witness charges it.
    /// Beside the witnesses: an empty text, and inputs of the wrong type.
    /// Each input reaches the outcome it states, a published string or the
    /// wrong type; any other outcome fails, naming the input.
    #[test]
    fn every_place_of_a_string_decode_is_within_its_term() {
        let mut inputs: Vec<(String, Option<StringPlace>, Vec<u8>, bool)> = StringPlace::ALL
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
        inputs.push(("empty".into(), None, CBOR::from("").to_cbor_data(), true));
        inputs.push((
            "wrong type".into(),
            None,
            CBOR::from(7u64).to_cbor_data(),
            false,
        ));
        // A node per byte, then the wrong type: the parse's arena at its most.
        inputs.push((
            "flat array".into(),
            None,
            CBOR::from(vec![0u64; 4096]).to_cbor_data(),
            false,
        ));
        // A string of every input byte but its head's: what publication
        // retains at its most.
        inputs.push((
            "long text".into(),
            None,
            CBOR::from("x".repeat(4096).as_str()).to_cbor_data(),
            true,
        ));
        // An undecided text whose marks run unbroken: the parse normalizes
        // it, ordering every mark at every merge level, then the copy.
        inputs.push((
            "undecided text".into(),
            None,
            CBOR::from(format!("q{}", "\u{316}\u{301}".repeat(200)).as_str()).to_cbor_data(),
            true,
        ));
        let options = Options::normalizing(4);
        let mut runs = Vec::new();
        let mut witnesses = Vec::new();
        let mut strings = Vec::new();
        for (name, place, input, text) in &inputs {
            let mut policy = Ledgered::new();
            let mut decoder = StringDecoder::<Permit>::new(input, options);
            let bound = string_bound::<Permit, ()>(input.len() as u64, options).unwrap();
            within(name, bound, || match decoder.step(&mut policy) {
                Ok(Step::Progress) => ControlFlow::Continue(()),
                Ok(Step::Complete(string)) => {
                    assert!(*text, "{name}: published a string");
                    strings.push(string);
                    ControlFlow::Break(())
                }
                Err(DecodeError::Invalid(crate::Error::WrongType)) if !*text => {
                    ControlFlow::Break(())
                }
                Ok(Step::Finished) => panic!("{name}: finished without an outcome"),
                Err(error) => panic!("{name}: {error:?}"),
            });
            if let Some(place) = place {
                witnesses.push((runs.len(), *place));
            }
            let terms = StringTerms::of::<Permit, ()>(input.len() as u64, options).unwrap();
            places::nested(
                StringPlace::Parse,
                terms.parse,
                super::super::cursor::retained_decode_bound::<Permit, ()>(
                    input.len() as u64,
                    options,
                )
                .unwrap(),
            );
            runs.push(Run {
                outcome: if *text {
                    places::Outcome::Published
                } else {
                    places::Outcome::Invalid
                },
                name: name.clone(),
                policy,
                terms,
            });
        }
        places::check(&runs);
        places::witnessed(&runs, &witnesses);
        places::Tightness::new("string_decode")
            .places(&runs, &witnesses, |place| match place {
                StringPlace::Parse => Factor::Nested("decode::cursor::attribution"),
                StringPlace::Inspection | StringPlace::Copies | StringPlace::Publication => {
                    Factor::Measured
                }
            })
            .joint(
                &runs,
                "undecided text",
                WORK,
                "one undecided text of the whole input: its parse's normalization, the \
                 dominant term, and its copy, every byte once",
            )
            .joint(
                &runs,
                "flat array",
                &[Dimension::Allocated, Dimension::Peak],
                "a flat array of one-byte items: a node per byte, the most the parse's \
                 arena holds, refused as the wrong type before any string",
            )
            .joint(
                &runs,
                "long text",
                &[Dimension::Retained],
                "one text of the whole input: the string publication retains holds every \
                 payload byte",
            )
            .finish();
        drop(strings);
    }
}
