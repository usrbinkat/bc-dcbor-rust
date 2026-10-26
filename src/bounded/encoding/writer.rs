//! Emission of a completed plan. One segment routine walks the plan; the
//! borrowed writer copies each segment into its destination, and the owned
//! writer hands each segment out, borrowed from the plan itself.
use super::*;

/// Retained emission progress: the plan offset, header gaps passed, and
/// bytes emitted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EmitPosition {
    pub source: usize,
    pub hole: usize,
    pub written: usize,
    pub finished: bool,
}

places! {
    /// The places emission ([`Writer`], [`OwnedWriter`], and publication
    /// in place, [`Prepared::publish`]) charges, one term of [`emit_bound`]
    /// each.
    pub(crate) enum EmitPlace {
        /// Segments of the plan's bytes.
        Bytes,
        /// Header gaps passed.
        Boundaries,
        Completion,
        /// A caller-owned output's initialization before it is written
        /// ([`Prepared::encode_owned`]).
        Initialization,
    }
}

/// An output's bytes initialized before it is written.
const INITIALIZED: Scan<EmitPlace> = Scan::new(EmitPlace::Initialization, 0);

/// Emitting one segment: one value and at most a quantum of the plan's
/// bytes.
const SEGMENT: Capped<EmitPlace> = Capped::new(
    EmitPlace::Bytes,
    1,
    decode::construction::stable::QUANTUM as u64,
);

/// Passing one header gap.
const BOUNDARY: Unit<EmitPlace> = Unit::new(EmitPlace::Boundaries, 1, 0);

/// Completing the emission.
const COMPLETE: Unit<EmitPlace> = Unit::new(EmitPlace::Completion, 1, 0);

/// One admitted unit of emission.
enum Segment<'p> {
    /// A header gap passed; no bytes.
    Skip,
    /// At most 64 plan bytes, the next of the encoding.
    Bytes(&'p [u8]),
    /// Every byte was emitted; the emission is finished.
    Complete,
}

impl<'p> PlanView<'p> {
    /// The next unit of emission after `at`, its work admitted before `at`
    /// changes. A plan whose bytes do not account for its length is a terminal
    /// error.
    fn segment<B: Budget>(
        &self,
        at: &mut EmitPosition,
        b: &mut B,
    ) -> BoundedResult<Segment<'p>, B> {
        if let Some(&(start, skip)) = self.holes.get(at.hole)
            && at.source == start
        {
            BOUNDARY.admit(b)?;
            at.source += skip;
            at.hole += 1;
            return Ok(Segment::Skip);
        }
        if at.source == self.bytes.len() {
            return self.complete(at, b);
        }
        let boundary = self
            .holes
            .get(at.hole)
            .map_or(self.bytes.len(), |hole| hole.0);
        let count = boundary
            .checked_sub(at.source)
            .ok_or(BoundedError::PlanMismatch)?
            .min(decode::construction::stable::QUANTUM);
        let bytes = self
            .bytes
            .get(at.source..at.source + count)
            .ok_or(BoundedError::PlanMismatch)?;
        SEGMENT.admit(b, widen(count)?)?;
        at.source += count;
        at.written += count;
        Ok(Segment::Bytes(bytes))
    }

    fn complete<B: Budget>(
        &self,
        at: &mut EmitPosition,
        b: &mut B,
    ) -> BoundedResult<Segment<'p>, B> {
        COMPLETE.admit(b)?;
        if at.written != self.len {
            return Err(BoundedError::PlanMismatch);
        }
        at.finished = true;
        Ok(Segment::Complete)
    }
}

impl<P> Prepared<P> {
    /// Publish the plan as its encoding in place: every segment of its
    /// bytes moved forward over the gaps before it, by the same segment
    /// routine and units as a [`Writer`] ([`emit_bound`]), the destination
    /// never past the source as gaps only shorten the encoding; then the
    /// gap records released, a release their arena's growth paid for, and
    /// the bytes truncated to the encoding, which keeps the arena's
    /// allocation and permit. Nothing is allocated or copied out. A refusal
    /// discards the plan and its storage with it. At most the steps
    /// [`emit_bound`] allows are taken ([`ResourceBound::steps`]); a plan
    /// that does not complete within them has diverged
    /// ([`BoundedError::PlanMismatch`]).
    pub fn publish<B: Budget>(mut self, b: &mut B) -> BoundedResult<Encoded<P>, B> {
        let steps = emit_bound::<B::Refusal>(widen(self.len)?)?.steps()?;
        let mut position = EmitPosition::default();
        let mut complete = false;
        for _ in 0..steps {
            let (source, destination) = (position.source, position.written);
            let moved = match self.view().segment(&mut position, b)? {
                Segment::Skip => 0,
                Segment::Bytes(bytes) => bytes.len(),
                Segment::Complete => {
                    complete = true;
                    break;
                }
            };
            self.bytes
                .items
                .copy_within(source..source + moved, destination);
        }
        if !complete {
            return Err(BoundedError::PlanMismatch);
        }
        self.holes.release();
        self.bytes.items.truncate(self.len);
        let permit = self.bytes.permit.take().ok_or(BoundedError::PlanMismatch)?;
        Ok(Encoded {
            bytes: core::mem::take(&mut self.bytes.items),
            _permit: permit,
        })
    }

    /// The work writing the encoding reports at most ([`emit_bound`]):
    /// what a caller admits for [`Self::encode_into`].
    pub fn write_work<R>(&self) -> Result<WriteWork, BoundedError<R>> {
        Ok(emit_bound::<R>(widen(self.len)?)?.work())
    }

    /// Write the encoding into `output`, which must be exactly
    /// [`Self::len`] bytes, by a [`Writer`] to its completion: a wrong-sized
    /// output is refused before anything is written. At most the steps
    /// [`emit_bound`] allows are taken ([`ResourceBound::steps`]); a write
    /// that does not complete within them has diverged from its plan
    /// ([`BoundedError::PlanMismatch`]).
    pub fn encode_into<B: Budget>(&self, output: &mut [u8], b: &mut B) -> BoundedResult<(), B> {
        let steps = emit_bound::<B::Refusal>(widen(self.len)?)?.steps()?;
        let mut writer = self.writer(output);
        for _ in 0..steps {
            match writer.step(b)? {
                Step::Progress => {}
                Step::Complete(()) => return Ok(()),
                Step::Finished => return Err(BoundedError::PlanMismatch),
            }
        }
        Err(BoundedError::PlanMismatch)
    }

    /// Write the encoding into storage this call allocates fallibly at
    /// exactly [`Self::len`] bytes, owned with `permit`, the reservation the
    /// caller admitted for that storage: its initialization admitted before
    /// it is touched, then the write ([`Self::encode_into`]). The bytes are
    /// published only once complete; on every error the storage is freed
    /// and `permit` dropped after it. The budget may differ from the
    /// preparation's allocator: a caller admits the output, its
    /// initialization and [`Self::write_work`] as one unit and writes on it.
    pub fn encode_owned<Q, B: Budget>(&self, permit: Q, b: &mut B) -> BoundedResult<Encoded<Q>, B> {
        let len = widen(self.len)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(self.len)
            .map_err(|_| BoundedError::Allocation { bytes: len })?;
        INITIALIZED.admit(b, len)?;
        bytes.resize(self.len, 0);
        self.encode_into(&mut bytes, b)?;
        Ok(Encoded {
            bytes,
            _permit: permit,
        })
    }
}

impl<P> Writer<'_, '_, P> {
    pub fn emitted_prefix(&self) -> &[u8] {
        &self.output[..self.at.written]
    }

    pub fn position(&self) -> EmitPosition {
        self.at
    }

    /// One step. A wrong-sized destination or a plan the bytes do not match
    /// is a terminal error; the writer is finished after it.
    pub fn step<B: Budget>(&mut self, b: &mut B) -> BoundedResult<Step<()>, B> {
        if self.at.finished {
            return Ok(Step::Finished);
        }
        let result = self.advance(b);
        if matches!(&result, Err(error) if !error.refused()) {
            self.at.finished = true;
        }
        result
    }

    fn advance<B: Budget>(&mut self, b: &mut B) -> BoundedResult<Step<()>, B> {
        let plan = self.plan.view();
        if self.output.len() != plan.len {
            return Err(BoundedError::OutputSize {
                measured: widen(plan.len)?,
                provided: widen(self.output.len())?,
            });
        }
        let start = self.at.written;
        Ok(match plan.segment(&mut self.at, b)? {
            Segment::Skip => Step::Progress,
            Segment::Bytes(bytes) => {
                self.output
                    .get_mut(start..start + bytes.len())
                    .ok_or(BoundedError::PlanMismatch)?
                    .copy_from_slice(bytes);
                Step::Progress
            }
            Segment::Complete => Step::Complete(()),
        })
    }
}

impl<P, B: Budget> Resumable<B> for Writer<'_, '_, P> {
    type Output = ();
    type Error = BoundedError<B::Refusal>;
    type Position = EmitPosition;

    fn step(&mut self, b: &mut B) -> BoundedResult<Step<()>, B> {
        Writer::step(self, b)
    }

    fn position(&mut self) -> EmitPosition {
        Writer::position(self)
    }
}

/// The [`ResourceBound`] of emitting a completed plan of `len` bytes, by a
/// [`Writer`], an [`OwnedWriter`] or [`Prepared::publish`], which share one
/// segment routine:
///
/// - each byte is reported once, in segments of at most 64 bytes: `len`
///   bytes in all;
/// - a segment never crosses a header gap, so each ends at most one segment
///   early, and passing each is its own unit of one value;
/// - completion is one value; publication's release of the gap records was
///   paid for by their arena's growth.
///
/// Every map whose head waits for its count has a head of at least one byte
/// and one gap, so a plan of `len` bytes has at most `len` gaps. Emission
/// allocates nothing and retains nothing. Refused, never saturated, when a
/// quantity does not fit in `u64`.
pub fn emit_bound<R>(len: u64) -> Result<ResourceBound, BoundedError<R>> {
    EmitTerms::of::<R>(len)?.bound()
}

/// The terms [`emit_bound`] sums, one per [`EmitPlace`].
struct EmitTerms {
    bytes: WriteWork,
    boundaries: WriteWork,
    completion: WriteWork,
    initialization: WriteWork,
}

impl EmitTerms {
    /// The terms of emitting a plan of `len` bytes.
    fn of<R>(len: u64) -> Result<Self, BoundedError<R>> {
        // At most `len` gaps, each ending at most one segment early.
        Ok(Self {
            bytes: SEGMENT.covering(len, len)?,
            boundaries: BOUNDARY.times(len)?,
            completion: COMPLETE.times(1)?,
            // A caller-owned output's every byte, initialized once.
            initialization: INITIALIZED.units(1, len)?,
        })
    }
}

impl Places for EmitTerms {
    type Place = EmitPlace;

    fn term(&self, place: EmitPlace) -> ResourceBound {
        match place {
            EmitPlace::Bytes => ResourceBound::of_work(self.bytes),
            EmitPlace::Boundaries => ResourceBound::of_work(self.boundaries),
            EmitPlace::Completion => ResourceBound::of_work(self.completion),
            EmitPlace::Initialization => ResourceBound::of_work(self.initialization),
        }
    }
}

/// What one step of an [`OwnedWriter`] reached.
#[derive(Debug, PartialEq, Eq)]
pub enum OwnedEmitStep<'w> {
    /// A header gap or entry boundary was passed; no bytes.
    Progress,
    /// The next at most 64 bytes of the encoding, borrowed from the plan.
    Chunk(&'w [u8]),
    /// Every byte was emitted; later steps return `Finished`.
    Complete,
    /// The emission completed, or failed terminally, earlier.
    Finished,
}

/// Emission of an owned plan in chunks borrowed from the plan itself: nothing
/// is copied or allocated, and the caller's sink consumes each chunk before
/// the next step. Dropping the writer, on any thread, retires the plan record
/// to the scope queue.
pub struct OwnedWriter<'s, I: DecodeInput<A>, T: InPlace<A>, A: Allocator> {
    record: OwnedInitialized<'s, Planned<'s, I, T, A>, A>,
    at: EmitPosition,
}

/// Emission progress together with the plan record's retained custody.
/// Completing emission does not release the plan or its source; explicit
/// reclamation and retirement therefore remain observable after completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnedEmitPosition {
    pub emission: EmitPosition,
    pub plan: PlanDetail,
}

impl<'s, I: DecodeInput<A>, T: InPlace<A>, A: Allocator> OwnedWriter<'s, I, T, A> {
    pub(super) fn new(record: OwnedInitialized<'s, Planned<'s, I, T, A>, A>) -> Self {
        Self {
            record,
            at: EmitPosition::default(),
        }
    }

    pub fn position(&self) -> OwnedEmitPosition {
        let record = self.record.value();
        OwnedEmitPosition {
            emission: self.at,
            plan: PlanDetail {
                phase: Some(record.phase),
                preparation: Some(record.preparation.position()),
                source: record.source.is_some(),
            },
        }
    }

    /// One step. A plan whose bytes do not account for its length is a
    /// terminal error; the writer is finished after it.
    pub fn step<B: Budget>(&mut self, b: &mut B) -> BoundedResult<OwnedEmitStep<'_>, B> {
        if self.at.finished {
            return Ok(OwnedEmitStep::Finished);
        }
        let result = self.record.value().plan().segment(&mut self.at, b);
        if matches!(&result, Err(error) if !error.refused()) {
            self.at.finished = true;
        }
        Ok(match result? {
            Segment::Skip => OwnedEmitStep::Progress,
            Segment::Bytes(bytes) => OwnedEmitStep::Chunk(bytes),
            Segment::Complete => OwnedEmitStep::Complete,
        })
    }

    /// Operation-local cleanup of the plan and its source value.
    pub fn reclaim_step(slot: &mut Option<Self>, a: &mut A) -> BoundedResult<Reclaimed, A> {
        let at = slot
            .as_ref()
            .map_or(EmitPosition::default(), |writer| writer.at);
        reclamation::reclaim_within(
            slot,
            a,
            |writer| writer.record,
            |record| Self { record, at },
            OwnedInitialized::reclaim_step,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounded::{Limits, within};
    use core::ops::ControlFlow;

    /// A field map with no present field: one header gap, one head byte.
    struct Empty;

    impl Schema for Empty {
        fn instruction(&self, index: usize) -> Instruction<'_> {
            match index {
                0 => Instruction::Map,
                _ => Instruction::End,
            }
        }
    }

    /// An unordered map of its pairs, one entry per instruction.
    struct Pairs(Vec<(u64, u64)>);

    impl Schema for Pairs {
        fn instruction(&self, index: usize) -> Instruction<'_> {
            match index {
                0 => Instruction::UnorderedMap,
                index => match self.0.get(index - 1) {
                    Some((key, value)) => Instruction::Entry {
                        next: index + 1,
                        entry: Some((key, value)),
                    },
                    None => Instruction::End,
                },
            }
        }
    }

    /// One of the three emissions sharing the segment routine.
    #[derive(Clone, Copy, Debug)]
    enum Emission {
        /// A [`Writer`] into a borrowed destination.
        Written,
        /// [`Prepared::encode_owned`]: the destination's initialization, then
        /// the write.
        Owned,
        /// [`Prepared::publish`]: the plan's bytes moved over its gaps in
        /// place, then the gap records released.
        Published,
    }

    const EMISSIONS: [Emission; 3] = [Emission::Written, Emission::Owned, Emission::Published];

    /// `source`'s plan, prepared under an unlimited policy.
    fn planned(source: &dyn Schema) -> Prepared<crate::bounded::Reservation> {
        let shape = Shape::of(source, &mut Limits::unlimited()).expect("a fixture has a shape");
        let bound = prepare_bound::<crate::bounded::Reservation, ()>(shape)
            .expect("the bound of a fixture fits in u64");
        let mut limits = Limits::unlimited();
        let mut preparation = Preparation::new(source);
        within("preparation", bound, || {
            match preparation.step(&mut limits).unwrap() {
                Step::Progress => ControlFlow::Continue(()),
                Step::Complete(plan) => ControlFlow::Break(plan),
                Step::Finished => unreachable!("preparation finished without a plan"),
            }
        })
    }

    /// `plan` emitted by `emission` under `budget`: its length and the bytes
    /// emitted.
    fn emit<B: Budget>(
        plan: Prepared<crate::bounded::Reservation>,
        emission: Emission,
        budget: &mut B,
    ) -> (u64, Vec<u8>)
    where
        B::Refusal: fmt::Debug,
    {
        let len = plan.len() as u64;
        let bytes = match emission {
            Emission::Written => {
                let bound = emit_bound::<()>(len).expect("the bound of a plan fits in u64");
                let mut bytes = vec![0; plan.len()];
                let mut writer = plan.writer(&mut bytes);
                within("emission", bound, || match writer.step(budget) {
                    Ok(Step::Progress) => ControlFlow::Continue(()),
                    Ok(Step::Complete(())) => ControlFlow::Break(()),
                    other => panic!("emission failed: {other:?}"),
                });
                bytes
            }
            Emission::Owned => match plan.encode_owned((), budget) {
                Ok(encoded) => encoded.as_ref().to_vec(),
                Err(error) => panic!("emission failed: {error:?}"),
            },
            Emission::Published => match plan.publish(budget) {
                Ok(encoded) => encoded.as_ref().to_vec(),
                Err(error) => panic!("emission failed: {error:?}"),
            },
        };
        (len, bytes)
    }

    /// Long payloads, many gaps, unordered maps at the root and nested are
    /// each emitted by every emission within the bound, the same bytes by
    /// each, every byte reported exactly once by the segments and nothing
    /// requested.
    #[test]
    fn the_emission_bound_covers_every_plan_shape() {
        let text = "x".repeat(70_000);
        let maps: Vec<Empty> = (0..300).map(|_| Empty).collect();
        let pairs = Pairs((0..200).map(|n| (n, n)).collect());
        let nested = vec![Pairs(vec![(1, 2), (0, 3)]), Pairs(Vec::new())];
        for source in [&text as &dyn Schema, &maps, &pairs, &nested] {
            let mut emitted = Vec::new();
            for emission in EMISSIONS {
                let mut budget = Limits::unlimited();
                let (len, bytes) = emit(planned(source), emission, &mut budget);
                let used = budget.used();
                let bound = emit_bound::<()>(len).unwrap();
                assert!(
                    bound.work().covers(&used),
                    "{emission:?}: {used:?} exceeds {bound:?}"
                );
                // Beside the plan's bytes: a caller's own output's bytes
                // initialized. Publication's release of the gap records was
                // paid for by their growth.
                let beside = match emission {
                    Emission::Owned => len,
                    Emission::Published | Emission::Written => 0,
                };
                assert_eq!(
                    used.bytes,
                    len + beside,
                    "{emission:?}: every byte is reported once"
                );
                assert_eq!(
                    budget.requested_bytes(),
                    0,
                    "{emission:?}: emission requested storage"
                );
                assert_eq!(bytes.len() as u64, len);
                emitted.push(bytes);
            }
            assert!(
                emitted.windows(2).all(|pair| pair[0] == pair[1]),
                "the emissions disagree"
            );
        }
        assert_eq!(emit_bound::<()>(u64::MAX), Err(BoundedError::Overflow));
    }

    /// A source whose plan's emission charges `place`, maximizing it, and the
    /// emission that charges it: a place without a witness does not compile.
    /// A plan of empty maps passes a gap before every head byte, the most
    /// boundaries per byte a plan can have, each cutting a segment short;
    /// written to a caller's own storage, every byte is also initialized.
    /// Only publication releases the gap records at its completion.
    fn witness(place: EmitPlace) -> (Box<dyn Schema>, Emission) {
        match place {
            EmitPlace::Bytes | EmitPlace::Boundaries | EmitPlace::Initialization => (
                Box::new((0..4096).map(|_| Empty).collect::<Vec<_>>()),
                Emission::Owned,
            ),
            EmitPlace::Completion => (Box::new("x".repeat(70_000)), Emission::Published),
        }
    }

    /// Every place emission charges is within its term on every plan shape
    /// and every emission, every admission is made at some place, and each
    /// place's witness charges it and is within its stated factor of its
    /// term: an understated term fails coverage, an overstated one
    /// tightness. Beside the witnesses: a long text, a root map's entries
    /// and nested unordered maps, each by every emission.
    #[cfg(feature = "std")]
    #[test]
    fn every_place_of_an_emission_is_within_its_term() {
        use crate::bounded::places::{self, Factor, Ledgered, Run, WORK};
        /// A source's name, the place it witnesses if any, the source and
        /// its emission.
        type Source = (String, Option<EmitPlace>, Box<dyn Schema>, Emission);
        let mut sources: Vec<Source> = EmitPlace::ALL
            .iter()
            .map(|&place| {
                let (source, emission) = witness(place);
                (
                    format!("witness of {place:?}"),
                    Some(place),
                    source,
                    emission,
                )
            })
            .collect();
        for emission in EMISSIONS {
            sources.push((
                format!("text, {emission:?}"),
                None,
                Box::new("x".repeat(70_000)),
                emission,
            ));
            sources.push((
                format!("root map, {emission:?}"),
                None,
                Box::new(Pairs((0..200).map(|n| (n, n)).collect())),
                emission,
            ));
            sources.push((
                format!("nested maps, {emission:?}"),
                None,
                Box::new(vec![Pairs(vec![(1, 2), (0, 3)]), Pairs(Vec::new())]),
                emission,
            ));
        }
        let mut runs = Vec::new();
        let mut witnesses = Vec::new();
        for (name, place, source, emission) in &sources {
            let mut policy = Ledgered::new();
            let (len, _) = emit(planned(source.as_ref()), *emission, &mut policy);
            if let Some(place) = place {
                witnesses.push((runs.len(), *place));
            }
            runs.push(Run {
                outcome: places::Outcome::Published,
                name: name.clone(),
                policy,
                terms: EmitTerms::of::<()>(len).unwrap(),
            });
        }
        places::check(&runs);
        places::witnessed(&runs, &witnesses);
        places::Tightness::new("emission")
            .places(&runs, &witnesses, |place| match place {
                EmitPlace::Bytes | EmitPlace::Boundaries => Factor::Within(2),
                EmitPlace::Completion | EmitPlace::Initialization => Factor::Within(1),
            })
            .joint(
                &runs,
                "witness of Boundaries",
                WORK,
                "empty maps written to a caller's own storage: every byte initialized, a gap \
                 before every head byte, each passed in its own unit and cutting a segment \
                 short, the most boundaries a plan's bytes allow",
            )
            .finish();
    }
}
