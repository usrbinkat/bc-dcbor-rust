//! Emission of a completed plan. One segment routine walks the plan; the
//! borrowed writer copies each segment into its destination, and the owned
//! writer hands each segment out, borrowed from the plan itself.
use super::*;

/// Retained emission progress: the plan offset, header gaps passed, and
/// bytes emitted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
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
        /// A caller-owned output's storage, requested in its whole length
        /// and held by the encoding it publishes ([`Prepared::encode_owned`]).
        Output,
    }
}

/// An output's bytes initialized before it is written.
const INITIALIZED: Scan<EmitPlace> = Scan::new(EmitPlace::Initialization, 0);

/// Releasing an owned output ([`Prepared::encode_owned`]): one value and
/// the bytes dropping its published record ([`Encoded`]) rewrites, of a
/// permit within [`PERMIT_BYTES`]. Admitted by the acquisition before the
/// storage is requested, and forfeited, never refunded, when the request is
/// refused or the allocation fails.
const fn encoded_released<P>() -> Unit<EmitPlace> {
    permit_bytes::<P>();
    Unit::written::<Encoded<P>>(EmitPlace::Output)
}

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
        // The segment ends at the next gap or the plan's end, never before
        // where emission stands, and spans at most a quantum.
        if Bound::new(Predicate::Payload, boundary).exceeded(b, at.source) {
            return Err(BoundedError::PlanMismatch);
        }
        let count = Bound::new(Predicate::Quantum, decode::construction::stable::QUANTUM)
            .clamp(b, boundary - at.source);
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
        // The encoding carries the owner its bytes arena's acquisitions were
        // bound under, which the plan carried from its preparation: the
        // bytes, and that arena's permit, move into the encoding. A plan
        // holding a permit always names one.
        let owner = self.owner().ok_or(BoundedError::PlanMismatch)?;
        Ok(Encoded {
            bytes: core::mem::take(&mut self.bytes.items),
            _permit: permit,
            owner,
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

    /// Write the encoding into storage of exactly [`Self::len`] bytes that
    /// this call requests from `a` and then allocates fallibly: the permit
    /// `a` grants is minted here for exactly that length and published with
    /// the bytes ([`Encoded`]), so no caller can pair the storage with a
    /// permit of another size. The storage's release is admitted before it
    /// is requested, as every acquisition's is ([`Allocator`]): held for the
    /// grant ([`Obligation::Release`]), forfeited if the request is refused
    /// ([`Forfeit::AcquisitionRefused`]), and spent at the grant, bound to the
    /// permit, whose drop performs it on every path after. The physical
    /// reservation's outcome is reported as the permit's effect
    /// ([`Effect`]). Then the output's initialization is admitted on `a`
    /// before it is touched, and the write ([`Self::encode_into`]). The bytes
    /// are published only once complete; on every error the storage is freed
    /// and its permit released after it. One policy both grants the storage
    /// and admits the work: a refusal of either is that policy's
    /// ([`BoundedError::Refused`]). The policy may differ from the
    /// preparation's. Its bound is [`owned_emit_bound`].
    ///
    /// The call is the custody of its one acquisition, made and ended within
    /// it and keeping nothing across a refusal: its owner and its acquisition
    /// are minted for it ([`Budget::owner`], [`Budget::acquisition`]), so a
    /// recording policy that cannot identify them refuses before anything is
    /// admitted, and a retry is a new acquisition.
    ///
    /// The storage is the call's own; a caller cannot supply a permit:
    ///
    /// ```compile_fail,E0061
    /// use dcbor::bounded::{Allocator, Limits, prepare};
    /// let mut limits = Limits::unlimited();
    /// let prepared = prepare(&24u64, &mut limits).unwrap();
    /// let undersized = limits.allocate(1).unwrap();
    /// let _ = prepared.encode_owned(undersized, &mut limits);
    /// ```
    pub fn encode_owned<A: Allocator>(&self, a: &mut A) -> BoundedResult<Encoded<A::Permit>, A> {
        let len = widen(self.len)?;
        // This call is the custody of its one acquisition: its owner and
        // acquisition minted here, each refused before anything is admitted
        // when a recording policy cannot identify it.
        let owner = a.owner().map_err(BoundedError::Refused)?;
        let acquisition = a.acquisition(&owner).map_err(BoundedError::Refused)?;
        // The release is held for the grant within this call, which keeps no
        // custody of it across a refusal: a refusal ends the call and
        // forfeits it into its origin, and a retry is a new acquisition.
        // Every exit settles the release, then ends the acquisition, once:
        // it ends with its physical outcome, before the write that follows.
        let release = match const { encoded_released::<A::Permit>() }.admit_held(
            a,
            Obligation::Release,
            &owner,
            acquisition.id(),
        ) {
            Ok(release) => release,
            Err(error) => {
                acquisition.end(a.performer());
                return Err(error);
            }
        };
        let permit = match at(EmitPlace::Output, || a.allocate(len)) {
            Ok(permit) => permit,
            Err(refusal) => {
                release.forfeit(Forfeit::AcquisitionRefused, None, a.performer());
                acquisition.end(a.performer());
                return Err(BoundedError::Refused(refusal));
            }
        };
        let id = A::permit_identity(&permit);
        // Granted: the release is spent at the permit, which carries it and
        // whose drop performs it on every path below.
        release.spend(Some(id), a.performer());
        let mut bytes = Vec::new();
        let reservation = reserved(a, permit, acquisition.id(), || {
            bytes
                .try_reserve_exact(self.len)
                .map_err(|_| Forfeit::AcquisitionFailed)
        });
        acquisition.end(a.performer());
        let Ok((permit, ())) = reservation else {
            return Err(BoundedError::Allocation { bytes: len });
        };
        // The storage and its permit held together from the reservation on,
        // in the encoding that publishes them, whose fields drop the bytes
        // before the permit: every exit below frees the storage, then
        // releases its permit. The encoding carries this call's owner, under
        // which its one acquisition was bound; the acquisition ended at its
        // outcome above.
        let mut encoded = Encoded {
            bytes,
            _permit: permit,
            owner: owner.id(),
        };
        INITIALIZED.admit(a, len)?;
        encoded.bytes.resize(self.len, 0);
        self.encode_into(&mut encoded.bytes, a)?;
        Ok(encoded)
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

/// The [`ResourceBound`] of [`Prepared::encode_owned`] of a completed plan
/// of `len` bytes under a policy granting permits of `P`: [`emit_bound`]'s
/// terms, and the output's: its release admitted, one value and the bytes
/// its published record ([`Encoded`]) rewrites when it drops, then its
/// storage of `len` bytes requested once, held while it is written, and
/// retained by the encoding it publishes. Refused, never saturated, when a
/// quantity does not fit in `u64`.
pub fn owned_emit_bound<P, R>(len: u64) -> Result<ResourceBound, BoundedError<R>> {
    EmitTerms::owned::<P, R>(len)?.bound()
}

/// The terms [`emit_bound`] sums, one per [`EmitPlace`].
struct EmitTerms {
    bytes: WriteWork,
    boundaries: WriteWork,
    completion: WriteWork,
    initialization: WriteWork,
    /// The owned output's storage: none for a borrowed write or a
    /// publication in place, which allocate nothing ([`Self::owned`]).
    output: ResourceBound,
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
            output: ResourceBound::default(),
        })
    }

    /// The terms of [`Prepared::encode_owned`] of a plan of `len` bytes
    /// under a policy granting permits of `P`: [`Self::of`], and its
    /// output: the storage's release admitted ([`encoded_released`]), then
    /// `len` bytes requested once, held while they are written and retained
    /// by the encoding ([`owned_emit_bound`]).
    fn owned<P, R>(len: u64) -> Result<Self, BoundedError<R>> {
        // The release admitted, then the storage requested, held while it
        // is written and kept by the encoding.
        let output = encoded_released::<P>()
            .bound()
            .checked_then(ResourceBound {
                allocated: len,
                peak: len,
                retained: len,
                ..ResourceBound::default()
            })
            .ok_or(BoundedError::Overflow)?;
        Ok(Self {
            output,
            ..Self::of(len)?
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
            EmitPlace::Output => self.output,
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

/// Emission progress together with the plan record's retained custody, `N`
/// its source's input observation and `O` its source value's
/// ([`PlanDetail`]). Completing emission does not release the plan or its
/// source; explicit reclamation and retirement therefore remain observable
/// after completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct OwnedEmitPosition<N, O> {
    pub emission: EmitPosition,
    pub plan: PlanDetail<N, O>,
}

/// What an emission's cleanup admits, `D` its source's input class and `C`
/// its source value's: its plan record's ([`PlanClass`]),
/// marked as an emission's, so a plan record at an emission boundary is
/// never one class with one at a preparation boundary, whose operation's
/// cleanup differs. The emission's own progress is not read: every stop at
/// an emission boundary retires the writer, which hands its record to the
/// scope's drain, and the drain reads only the record; an emission step
/// writes only the writer's own progress ([`OwnedWriter::step`]), which the
/// writer's own cleanup carries only to rebuild itself
/// ([`OwnedWriter::reclaim_step`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub struct EmitClass<D, C>(pub PlanClass<D, C>);

/// What a writer holds: its position ([`OwnedWriter::position`]).
impl<I: DecodeInput<A>, T: InPlace<A>, A: Allocator> decode::construction::Custody
    for OwnedWriter<'_, I, T, A>
{
    type Observation = OwnedEmitPosition<InputObservation<I, A>, ValueObservation<T, A>>;

    fn observe(&mut self) -> Self::Observation {
        self.position()
    }
}

impl<N, O> OwnedEmitPosition<N, O> {
    /// An emission's class ([`EmitClass`]), its source's input by `D`, the
    /// input state's reduction, and its source value by `S`, the value's
    /// session's. Two positions of one class take each unit alike and land
    /// again in one class.
    pub fn class<D, S>(&self) -> EmitClass<D::Class, S::Class>
    where
        D: decode::construction::Reduction<Observation = N>,
        S: decode::construction::Reduction<Observation = O>,
    {
        EmitClass(self.plan.class::<D, S>())
    }
}

/// An emission's class is its position's ([`OwnedEmitPosition::class`]),
/// its source's input by the input state's reduction and its source value
/// by the value's session's.
impl<I: DecodeInput<A>, T: InPlace<A>, A: Allocator> decode::construction::Reduction
    for OwnedWriter<'_, I, T, A>
where
    decode::construction::in_place::Session<T::State>: decode::construction::Reduction,
{
    type Class = EmitClass<
        InputClassOf<I, A>,
        <decode::construction::in_place::Session<T::State> as decode::construction::Reduction>::Class,
    >;

    fn class(position: &Self::Observation) -> Self::Class {
        position.class::<I::State, decode::construction::in_place::Session<T::State>>()
    }
}

impl<'s, I: DecodeInput<A>, T: InPlace<A>, A: Allocator> OwnedWriter<'s, I, T, A> {
    pub(super) fn new(record: OwnedInitialized<'s, Planned<'s, I, T, A>, A>) -> Self {
        Self {
            record,
            at: EmitPosition::default(),
        }
    }

    /// The emission's progress and its plan record observed
    /// (`Planned::detail`): the record's source is read through its
    /// exclusive custody, its cleanup being the record's. `&mut self`
    /// excludes every borrowed chunk meanwhile; nothing is changed, admitted
    /// or allocated.
    pub fn position(
        &mut self,
    ) -> OwnedEmitPosition<InputObservation<I, A>, ValueObservation<T, A>> {
        OwnedEmitPosition {
            emission: self.at,
            plan: Planned::detail(&mut self.record.destination(), None),
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

    /// Operation-local cleanup of the plan and its source value, the cleanup
    /// capability minted here over `a`.
    pub fn reclaim_step(slot: &mut Option<Self>, a: &mut A) -> BoundedResult<Reclaimed, A> {
        let at = slot
            .as_ref()
            .map_or(EmitPosition::default(), |writer| writer.at);
        reclamation::with_cleanup(a, |cleanup| {
            reclamation::reclaim_within(
                slot,
                cleanup,
                |writer| writer.record,
                |record| Self { record, at },
                OwnedInitialized::reclaim_under,
            )
        })
    }
}

/// The writer's custody: the plan record it emits from, under the owner of
/// the acquisition that allocated it (its record's [`Custodial`] traversal).
/// Emission position is no custody: completing the emission releases
/// nothing, so the record stays reported until it is reclaimed or retired.
/// `&mut self` excludes every borrowed chunk meanwhile. Read-only.
impl<I: DecodeInput<A>, T: InPlace<A>, A: Allocator> Custodial<A::Permit>
    for OwnedWriter<'_, I, T, A>
{
    fn observe_custody(&mut self, sink: &mut dyn CustodySink<A::Permit>) -> PermitsObserved {
        self.record.observe_custody(sink)
    }
}

/// Kani harnesses of the emission's whole-operation bound (register item 4):
/// compiled only by `cargo kani`.
#[cfg(kani)]
mod proofs;

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
                    Some((key, value)) => Instruction::Entry(key, value),
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
        // The preparation runs under `Limits`, whose held credit settles
        // into its `Family`: the bound is of that origin's custody.
        let bound = prepare_bound::<crate::bounded::Reservation, crate::bounded::Family, ()>(shape)
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

    /// `plan` emitted by `emission` under `budget`: its length, the bytes
    /// emitted, and the encoding an owned emission publishes, its storage
    /// and permit still held, which only that emission allocates.
    fn emit<A: Allocator>(
        plan: Prepared<crate::bounded::Reservation>,
        emission: Emission,
        budget: &mut A,
    ) -> (u64, Vec<u8>, Option<Encoded<A::Permit>>)
    where
        A::Refusal: fmt::Debug,
    {
        let len = plan.len() as u64;
        let (bytes, held) = match emission {
            Emission::Written => {
                let bound = emit_bound::<()>(len).expect("the bound of a plan fits in u64");
                let mut bytes = vec![0; plan.len()];
                let mut writer = plan.writer(&mut bytes);
                within("emission", bound, || match writer.step(budget) {
                    Ok(Step::Progress) => ControlFlow::Continue(()),
                    Ok(Step::Complete(())) => ControlFlow::Break(()),
                    other => panic!("emission failed: {other:?}"),
                });
                (bytes, None)
            }
            Emission::Owned => match plan.encode_owned(budget) {
                Ok(encoded) => (encoded.as_ref().to_vec(), Some(encoded)),
                Err(error) => panic!("emission failed: {error:?}"),
            },
            Emission::Published => match plan.publish(budget) {
                Ok(encoded) => (encoded.as_ref().to_vec(), None),
                Err(error) => panic!("emission failed: {error:?}"),
            },
        };
        (len, bytes, held)
    }

    /// The terms `emission` of a plan of `len` bytes under a policy granting
    /// permits of `P` is checked against: only an owned emission's include
    /// its output, its release and its storage.
    fn terms<P>(len: u64, emission: Emission) -> EmitTerms {
        match emission {
            Emission::Owned => EmitTerms::owned::<P, ()>(len),
            Emission::Written | Emission::Published => EmitTerms::of::<()>(len),
        }
        .expect("the terms of a plan fit in u64")
    }

    /// Long payloads, many gaps, unordered maps at the root and nested are
    /// each emitted by every emission within its terms, the same bytes by
    /// each, every byte reported exactly once by the segments, and nothing
    /// requested but an owned emission's output, its release admitted
    /// first, requested once at exactly the encoding's length, held with the
    /// encoding and released with it.
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
                let (len, bytes, held) = emit(planned(source), emission, &mut budget);
                let used = budget.used();
                let bound = terms::<crate::bounded::Reservation>(len, emission)
                    .bound::<()>()
                    .unwrap();
                let public = match emission {
                    Emission::Owned => owned_emit_bound::<crate::bounded::Reservation, ()>(len),
                    Emission::Written | Emission::Published => emit_bound::<()>(len),
                };
                assert_eq!(public, Ok(bound), "{emission:?}: its public bound");
                assert!(
                    bound.work().covers(&used),
                    "{emission:?}: {used:?} exceeds {bound:?}"
                );
                // Beside the plan's bytes: a caller's own output, its bytes
                // initialized, its release admitted and its storage
                // requested. Publication's release of the gap records was
                // paid for by their growth.
                let released = encoded_released::<crate::bounded::Reservation>().bytes();
                let (beside, output, requests) = match emission {
                    Emission::Owned => (len + released, len, 1),
                    Emission::Published | Emission::Written => (0, 0, 0),
                };
                assert_eq!(
                    used.bytes,
                    len + beside,
                    "{emission:?}: every byte is reported once"
                );
                assert_eq!(
                    (
                        budget.requests(),
                        budget.requested_bytes(),
                        budget.live_bytes()
                    ),
                    (requests, output, output),
                    "{emission:?}: only an owned output is requested, and held"
                );
                assert_eq!(held.is_some(), requests == 1);
                drop(held);
                assert_eq!(budget.live_bytes(), 0, "{emission:?}: released with it");
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
    /// written to a caller's own storage, every byte is also initialized and
    /// its whole length requested. Only publication releases the gap records
    /// at its completion. Its one caller is the `std` attribution test.
    #[cfg(feature = "std")]
    fn witness(place: EmitPlace) -> (Box<dyn Schema>, Emission) {
        match place {
            EmitPlace::Bytes
            | EmitPlace::Boundaries
            | EmitPlace::Initialization
            | EmitPlace::Output => (
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
        use crate::bounded::places::{self, Factor, Ledgered, Run, STORAGE, WORK};
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
        // Each owned encoding is held until the check: what it retains is
        // checked against its output's retained term.
        let mut held = Vec::new();
        for (name, place, source, emission) in &sources {
            let mut policy = Ledgered::new();
            let (len, _, encoded) = emit(planned(source.as_ref()), *emission, &mut policy);
            if let Some(place) = place {
                witnesses.push((runs.len(), *place));
            }
            runs.push(Run {
                outcome: places::Outcome::Published,
                name: name.clone(),
                policy,
                terms: terms::<places::Permit>(len, *emission),
            });
            held.push(encoded);
        }
        places::check(&runs);
        places::witnessed(&runs, &witnesses);
        places::Tightness::new("emission")
            .places(&runs, &witnesses, |place| match place {
                EmitPlace::Bytes | EmitPlace::Boundaries => Factor::Within(2),
                EmitPlace::Completion | EmitPlace::Initialization | EmitPlace::Output => {
                    Factor::Within(1)
                }
            })
            .joint(
                &runs,
                "witness of Boundaries",
                WORK,
                "empty maps written to a caller's own storage: every byte initialized, a gap \
                 before every head byte, each passed in its own unit and cutting a segment \
                 short, the most boundaries a plan's bytes allow",
            )
            .joint(
                &runs,
                "witness of Output",
                STORAGE,
                "a caller-owned output: its whole length requested once, held while it is \
                 written and retained by the encoding it publishes, the only storage an \
                 emission requests",
            )
            .finish();
        drop(held);
    }
}
