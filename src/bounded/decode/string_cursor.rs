//! Retained parsing and owned UTF-8 construction with an exact output permit.
use super::cursor::Decoder;
use super::*;
use crate::bounded::Custodial;

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

/// The value's allocation is destroyed before its reservation. It carries
/// the identity of the owner its acquisition was bound under, immutable for
/// its life: observational identity only, never settlement authority.
pub struct OwnedString<P> {
    value: String,
    _permit: P,
    owner: Identity,
}

impl<P> OwnedString<P> {
    pub fn value(&self) -> &String {
        &self.value
    }

    /// The permit its storage holds, read: an observation naming it
    /// ([`crate::bounded::Releasing::permit_identity`]); never moved or
    /// released here.
    pub fn permit(&self) -> &P {
        &self._permit
    }

    /// The owner its acquisition was bound under.
    pub fn owner(&self) -> Identity {
        self.owner
    }
}

impl<P> Custodial<P> for OwnedString<P> {
    /// Its custody, observed ([`CustodySink`]): one group under its owner,
    /// holding its permit. Never contended.
    fn observe_custody(&mut self, sink: &mut dyn CustodySink<P>) -> PermitsObserved {
        sink.begin(Some(self.owner));
        sink.permit(&self._permit, None);
        sink.end();
        PermitsObserved::Complete
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
    /// The parse ended in a terminal error: its own cleanup reclaims what
    /// it holds, one of its units per step, before the decode finishes.
    ReclaimParser,
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
///
/// The decode is the custody of its string's one acquisition. Made with no
/// policy, it takes its owner ([`Owner`]) at that acquisition's first entry
/// (`Release`), minted by the policy that enters it and kept for the
/// decode's life; the acquisition's identity is minted once, at the same
/// entry, and kept across every refused request and every change of policy
/// until the grant. Every later entry (`Allocate`) validates the performing
/// policy against that owner before requesting anything
/// ([`Budget::validate_owner`]). The release admitted for the string is held
/// here ([`Retained`], its origin the family that admitted it) from
/// `Release` until the grant spends it at the permit, or a terminal error
/// forfeits it.
pub struct StringDecoder<'a, P, O: Origin> {
    parser: Decoder<'a, P, O>,
    document: Option<Document<'a, P>>,
    source: &'a str,
    value: String,
    permit: Option<P>,
    owner: Option<Owner>,
    acquisition: Option<Acquisition<O>>,
    release: Option<Retained<O>>,
    phase: Phase,
}

/// A decode dropped with its acquisition still bound is that acquisition's
/// destruction: the release it holds forfeited into its origin, then the
/// acquisition ended, both with no policy performing them
/// (`StringDecoder::cancel_acquisition`). Allocation-free, non-unwinding.
impl<P, O: Origin> Drop for StringDecoder<'_, P, O> {
    fn drop(&mut self) {
        self.cancel_acquisition(Performer::None);
    }
}

impl<'a, P, O: Origin> StringDecoder<'a, P, O> {
    pub fn new(input: &'a [u8], options: Options) -> Self {
        Self {
            parser: Decoder::new(input, options),
            document: None,
            source: "",
            value: String::new(),
            permit: None,
            owner: None,
            acquisition: None,
            release: None,
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
}

impl<P, O: Origin> Custodial<P> for StringDecoder<'_, P, O> {
    /// The decode's custody, observed once ([`CustodySink`]): its own group
    /// under the owner of its string's acquisition (deferred until that
    /// acquisition's first entry takes it), holding the string's release from
    /// `Release` until its grant and the string's permit from its grant
    /// until publication; inside it, the parser's components
    /// ([`super::cursor::ParserContinuation::observe_custody`]) and the
    /// parsed document while it is held ([`Document::observe_custody`]),
    /// each under its own stored owner. Read from its state alone: it
    /// allocates, admits, mints, publishes and settles nothing. Never
    /// contended.
    fn observe_custody(&mut self, sink: &mut dyn CustodySink<P>) -> PermitsObserved {
        sink.begin(self.owner.as_ref().map(Owner::id));
        // The bound acquisition, credit or none, from its bind to its end.
        if let Some(acquisition) = &self.acquisition {
            sink.bound(acquisition.id());
        }
        if let Some(release) = &self.release
            && release.remaining() != WriteWork::default()
        {
            sink.held(release.observation());
        }
        if let Some(permit) = &self.permit {
            sink.permit(permit, None);
        }
        let mut observed = self.parser.observe_custody(sink);
        if let Some(document) = &mut self.document {
            observed = observed_all([observed, document.observe_custody(sink)]);
        }
        sink.end();
        observed
    }
}

impl<P, O: Origin> StringDecoder<'_, P, O> {
    /// The credit this decode's custody holds: the checked fold of its
    /// observation ([`Self::observe_custody`], [`total_held`]). `None` when
    /// the sum does not fit. The public conservation observation of the
    /// decode: read beside its policies' [`crate::bounded::Limits::credits`],
    /// it is the `held` that [`crate::bounded::Credits::conserved_with`]
    /// checks.
    pub fn held_credit(&mut self) -> Option<WriteWork> {
        total_held(|sink| self.observe_custody(sink))
    }

    pub fn step<A: Allocator<Permit = P, Origin = O>>(
        &mut self,
        allocator: &mut A,
    ) -> ConstructResult<Step<OwnedString<P>>, A> {
        let entered = self.phase;
        let result = self.advance(allocator);
        if matches!(&result, Err(error) if !matches!(error, DecodeError::Resource(BoundedError::Refused(_))))
        {
            // A terminal error before the string's grant forfeits the release
            // held for it into its origin, then ends its acquisition; a
            // granted one spent it and ended it already.
            self.cancel_acquisition(allocator.performer());
            self.value = String::new();
            self.permit = None;
            self.document = None;
            // A parse that failed still holds its arenas, left to its own
            // cleanup; once it has published, it holds nothing.
            self.phase = match entered {
                Phase::Parse | Phase::ReclaimParser => Phase::ReclaimParser,
                _ => Phase::Finished,
            };
        }
        result
    }

    /// The bound acquisition cancelled, `by` the performer: its release, if
    /// held, forfeited ([`Forfeit::Cancelled`]) into its origin, then its
    /// capability ended, once; nothing when none is bound. The one
    /// cancellation of a terminal error and of a drop.
    fn cancel_acquisition(&mut self, by: Performer) {
        if let Some(release) = self.release.take() {
            release.forfeit(Forfeit::Cancelled, None, by);
        }
        if let Some(acquisition) = self.acquisition.take() {
            acquisition.end(by);
        }
    }

    fn advance<A: Allocator<Permit = P, Origin = O>>(
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
                // The decode's owner, taken at its first acquisition entry and
                // kept; the acquisition's identity, minted once and kept across
                // a refused admission below, so a retry never mints again.
                if self.owner.is_none() {
                    self.owner = Some(allocator.owner().map_err(BoundedError::Refused)?);
                }
                let owner = self.owner.as_ref().ok_or(BoundedError::PlanMismatch)?;
                let acquisition = match &self.acquisition {
                    Some(acquisition) => acquisition.id(),
                    None => {
                        let minted = allocator
                            .acquisition(owner)
                            .map_err(BoundedError::Refused)?;
                        let id = minted.id();
                        self.acquisition = Some(minted);
                        id
                    }
                };
                // Held from here until the grant: this decode is its custody
                // across a refused request ([`Self::held_credit`]). The route
                // validates the performing policy against the owner first.
                let release = string_released::<P>().admit_held(
                    allocator,
                    Obligation::Release,
                    owner,
                    acquisition,
                )?;
                self.release = Some(release);
                self.phase = Phase::Allocate;
            }
            Phase::Allocate => {
                // A resumed entry, possibly under another policy: validated
                // against the decode's owner before anything is requested.
                let owner = self.owner.as_ref().ok_or(BoundedError::PlanMismatch)?;
                allocator
                    .validate_owner(owner)
                    .map_err(BoundedError::Refused)?;
                let acquisition = self
                    .acquisition
                    .as_ref()
                    .ok_or(BoundedError::PlanMismatch)?
                    .id();
                let bytes = widen(self.source.len())?;
                let permit = at(StringPlace::Copies, || allocator.allocate(bytes))
                    .map_err(BoundedError::Refused)?;
                let id = A::permit_identity(&permit);
                let by = allocator.performer();
                // Granted: the release is spent at the permit, which carries
                // it and whose drop performs it on every path below.
                self.release
                    .take()
                    .ok_or(BoundedError::PlanMismatch)?
                    .spend(Some(id), by);
                // A failed reservation's permit is dropped inside this step
                // ([`reserved`]).
                let (value, length) = (&mut self.value, self.source.len());
                let reservation = reserved(allocator, permit, acquisition, || {
                    value
                        .try_reserve_exact(length)
                        .map_err(|_| Forfeit::AcquisitionFailed)
                });
                // The acquisition ends with its physical outcome, its one
                // obligation spent: `cancel_acquisition` finds no release.
                self.cancel_acquisition(by);
                let Ok((permit, ())) = reservation else {
                    // The decode holds nothing any more and ends.
                    self.phase = Phase::Finished;
                    return Err(BoundedError::Allocation { bytes }.into());
                };
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
                // The string carries the owner its acquisition was bound
                // under, the one this decode stored at its first entry.
                let owner = self.owner.as_ref().ok_or(BoundedError::PlanMismatch)?.id();
                let permit = self.permit.take().ok_or(BoundedError::PlanMismatch)?;
                self.document = None;
                self.phase = Phase::Finished;
                return Ok(Step::Complete(OwnedString {
                    value: core::mem::take(&mut self.value),
                    _permit: permit,
                    owner,
                }));
            }
            // The parse's cleanup, a term of the parse's own bound
            // ([`super::cursor::retained_decode_bound`] covers any failure
            // and the cleanup after it).
            Phase::ReclaimParser => {
                if at(StringPlace::Parse, || self.parser.reclaim_step(allocator))? {
                    self.phase = Phase::Finished;
                }
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
/// bytes), every byte once; and publication. A terminal error releases the
/// document and the string at once, each release paid for by its
/// acquisition; one of the parse is followed by the parse's own cleanup,
/// within the parse's term. The string
/// is what publication retains. `O` is the policy's credit origin
/// ([`Budget::Origin`]), of which the parse's custody holds credit
/// ([`super::cursor::retained_decode_bound`]).
pub fn string_bound<P, O: Origin, R>(
    input: u64,
    options: Options,
) -> Result<ResourceBound, BoundedError<R>> {
    StringTerms::of::<P, O, R>(input, options)?.bound()
}

/// The terms [`string_bound`] sums, one per [`StringPlace`].
struct StringTerms {
    parse: ResourceBound,
    inspection: WriteWork,
    copies: ResourceBound,
    publication: WriteWork,
}

impl StringTerms {
    fn of<P, O: Origin, R>(input: u64, options: Options) -> Result<Self, BoundedError<R>> {
        // Every copy before the last covers at most a scalar's continuation
        // bytes short of a quantum; the last is partial.
        let copies = add(input.div_ceil(COPIED), 1)?;
        let released = string_released::<P>().times(1)?;
        // The string's release admitted, then the string requested at every
        // input byte, held and kept, and copied into.
        let string = ResourceBound {
            values: mul(copies, COPY.values())?,
            bytes: input,
            allocated: input,
            peak: input,
            retained: input,
        };
        Ok(Self {
            parse: super::cursor::retained_decode_bound::<P, O, R>(input, options)?,
            inspection: INSPECT.times(1)?,
            copies: ResourceBound::of_work(released)
                .checked_then(string)
                .ok_or(BoundedError::Overflow)?,
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
        self.parse
            .checked_then(self.copies)
            .map(|bound| bound.peak)
            .ok_or(BoundedError::Overflow)
    }
}

impl<'a, P, O: Origin, A: Allocator<Permit = P, Origin = O>> Resumable<A>
    for StringDecoder<'a, P, O>
{
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

/// Kani harness of the string decode's whole-operation bound (register item
/// 4): compiled only by `cargo kani`.
#[cfg(kani)]
mod proofs;

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
            let mut decoder = StringDecoder::<Permit, ()>::new(input, options);
            let bound = string_bound::<Permit, (), ()>(input.len() as u64, options).unwrap();
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
            let terms = StringTerms::of::<Permit, (), ()>(input.len() as u64, options).unwrap();
            places::nested(
                StringPlace::Parse,
                terms.parse,
                super::super::cursor::retained_decode_bound::<Permit, (), ()>(
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
