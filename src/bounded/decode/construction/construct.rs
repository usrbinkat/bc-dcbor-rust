//! Typed construction from an owned document, and typed decoding as parse
//! followed by construction.
//!
//! The constructed value is built in its final stable record. After it is
//! complete the document's input handle moves into the record without copying
//! (identity and signature checks keep the original bytes), and the document's
//! record, holding only its arena, is retired to the scope queue.
use core::mem::MaybeUninit;
use core::ptr::addr_of_mut;

use super::in_place::{Built, InPlace, Transferable};
use super::input::DecodeInput;
use super::operation::{Observed, Operation, OperationTerms, Position, Task};
use super::parse::{DocumentDecoder, OwnedDocument, ParseDetail};
use super::reclamation::{
    Custody, EMPTIED, Mode, OwnedInitialized, PeekSlot, Place, Prefix, Reclaim, Reclaimed,
    ScopeRef, Slot, reclaim_within, slot_place,
};
use crate::bounded::decode::initialization::field;
use crate::bounded::decode::{ConstructResult, DecodeError, Options};
use crate::bounded::{
    Allocator, BoundedError, BoundedResult, Places, ResourceBound, Resumable, Step, Unit,
    WriteWork, at,
};

places! {
    /// The places a construction's task charges ([`Construction`]), one term
    /// of [`construction_bound`]'s task each.
    pub(crate) enum ConstructPlace {
        /// The value's construction and cleanup ([`InPlace::COST`]).
        Build,
        Detach,
        Publish,
        /// The record's cleanup: its transition and its emptied slots.
        Cleanup,
        /// The document the record holds until detachment, accounted by its
        /// parse ([`super::parse_bound`]).
        Document,
        /// The input the record holds after detachment, accounted by its
        /// acquisition ([`super::copy_bound`], [`super::borrow_bound`]).
        Input,
    }
}

/// Detaching the document's input.
const DETACH: Unit<ConstructPlace> = Unit::new(ConstructPlace::Detach, 1, 0);

/// Publishing the value.
const PUBLISH: Unit<ConstructPlace> = Unit::new(ConstructPlace::Publish, 1, 0);

/// A construction record entering its cleanup, or released before its
/// initialization completed.
const CLEANUP: Unit<ConstructPlace> = Unit::new(ConstructPlace::Cleanup, 1, 0);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConstructPhase {
    Build,
    Detach,
    Publish,
    Published,
    ReclaimValue,
    ReclaimDocument,
    ReclaimInput,
    Done,
}

/// The construction record. Public only as the unnameable state of
/// [`Construct`].
pub struct Constructed<'s, I: DecodeInput<A>, T: Reclaim<A>, A: Allocator> {
    /// Everything the record holds besides the value.
    custody: ConstructCustody<'s, I, T, A>,
    value: MaybeUninit<T>,
}

/// A construction record's own custody ([`Place::custody`]): the document
/// it holds until detachment, the input it holds after, the value's
/// construction state and the phase. Initialized field by field; reached
/// whole, once initialized, through one exclusive borrow of the record's
/// progress, its fields then borrowing disjointly.
struct ConstructCustody<'s, I: DecodeInput<A>, T: Reclaim<A>, A: Allocator> {
    document: Option<OwnedDocument<'s, I, A>>,
    input: Option<OwnedInitialized<'s, I, A>>,
    /// The value's own construction state.
    build: T::State,
    phase: ConstructPhase,
}

impl<'s, I: DecodeInput<A>, T: Reclaim<A>, A: Allocator> Constructed<'s, I, T, A> {
    const INIT_STEPS: usize = 4;

    /// The value's place within the record's, in the record's mode: the one
    /// projection its construction, its cleanup and its count share.
    fn value<M: Mode>(slot: &mut Slot<'_, Self, Prefix, M>) -> Place<T, M> {
        let (place, _) = slot.parts();
        // SAFETY: a field projection by raw pointer within the slot's own
        // record, forming no reference; `MaybeUninit<T>` lays out a `T` at
        // its start.
        unsafe { place.project(|record| addr_of_mut!((*record).value).cast::<T>()) }
    }

    /// The record's whole custody, for as long as the slot is borrowed;
    /// refused unless its progress records every custody field initialized.
    fn custody<'p, M: Mode, R>(
        slot: &'p mut Slot<'_, Self, Prefix, M>,
    ) -> Result<&'p mut ConstructCustody<'s, I, T, A>, BoundedError<R>> {
        let (place, prefix) = slot.parts();
        if prefix.initialized() < Self::INIT_STEPS {
            return Err(BoundedError::PlanMismatch);
        }
        // SAFETY: the slot pairs the record's place with its progress, which
        // records every custody field initialized; the custody field is
        // disjoint from the value, no place lies within it, and no reader
        // of the published value borrows it.
        Ok(unsafe { place.custody(prefix, |record| addr_of_mut!((*record).custody)) })
    }

    /// The document slot alone, for as long as the slot is borrowed: what
    /// the record holds before its other custody fields are initialized;
    /// `None` before the document field is.
    fn document<'p, M: Mode>(
        slot: &'p mut Slot<'_, Self, Prefix, M>,
    ) -> Option<&'p mut Option<OwnedDocument<'s, I, A>>> {
        let (place, prefix) = slot.parts();
        if prefix.initialized() == 0 {
            return None;
        }
        // SAFETY: the slot pairs the record's place with its progress, which
        // records the document field initialized; the projection reaches that
        // field alone.
        Some(unsafe { place.custody(prefix, |record| addr_of_mut!((*record).custody.document)) })
    }
}

// SAFETY: the prefix is the document handle, the input slot, the value's
// initial construction state and the phase. Cleanup reclaims the value
// through its own state, then the document and the input in place; no
// destructor of T runs.
unsafe impl<I: DecodeInput<A>, T: InPlace<A>, A: Allocator> Reclaim<A>
    for Constructed<'_, I, T, A>
{
    const DISPATCH_DEPTH: usize = {
        let value = T::DISPATCH_DEPTH.saturating_add(1);
        let input = I::DISPATCH_DEPTH.saturating_add(3);
        if value > input { value } else { input }
    };
    type State = Prefix;
    const INITIAL: Prefix = Prefix::EMPTY;

    fn reclaim_step(mut slot: Slot<'_, Self, Prefix>, a: &mut A) -> BoundedResult<Reclaimed, A> {
        if slot.custody().initialized() < Self::INIT_STEPS {
            if let Some(document) = Self::document(&mut slot)
                && document.is_some()
            {
                at(ConstructPlace::Document, || {
                    OwnedDocument::reclaim_step(document, a)
                })?;
                return Ok(Reclaimed::Progress);
            }
            // The rest of the prefix is resource-free: the empty input slot,
            // the value's initial state and the phase.
            CLEANUP.admit(a)?;
            *slot.custody() = Prefix::EMPTY;
            return Ok(Reclaimed::Done);
        }
        let value = Self::value(&mut slot);
        let ConstructCustody {
            document,
            input,
            build,
            phase,
        } = Self::custody(&mut slot)?;
        match *phase {
            ConstructPhase::ReclaimValue => {
                // SAFETY: the value's place, paired with its construction
                // state, which the record keeps beside it and which describes
                // every initialized part.
                if at(ConstructPlace::Build, || {
                    T::reclaim_step(unsafe { Slot::new(value, &mut *build) }, a)
                })? == Reclaimed::Done
                {
                    *phase = ConstructPhase::ReclaimDocument;
                }
            }
            ConstructPhase::ReclaimDocument => {
                let charge =
                    slot_place(document, ConstructPlace::Document, ConstructPlace::Cleanup);
                if at(charge, || OwnedDocument::reclaim_step(document, a))? == Reclaimed::Done {
                    *phase = ConstructPhase::ReclaimInput;
                }
            }
            ConstructPhase::ReclaimInput => {
                let charge = slot_place(input, ConstructPlace::Input, ConstructPlace::Cleanup);
                if at(charge, || OwnedInitialized::reclaim_step(input, a))? == Reclaimed::Done {
                    *phase = ConstructPhase::Done;
                    return Ok(Reclaimed::Done);
                }
            }
            ConstructPhase::Done => return Ok(Reclaimed::Done),
            _ => {
                CLEANUP.admit(a)?;
                *phase = ConstructPhase::ReclaimValue;
            }
        }
        Ok(Reclaimed::Progress)
    }

    /// Before initialization completes, the held document's own calls, then
    /// the one releasing the record. After it: the transition into cleanup
    /// unless it has begun, the value's own count, the document slot's and
    /// the input slot's.
    fn remaining(mut slot: PeekSlot<'_, Self, Prefix>) -> u64 {
        if slot.custody().initialized() < Self::INIT_STEPS {
            return match Self::document(&mut slot) {
                Some(document) if document.is_some() => {
                    OwnedDocument::remaining(document).saturating_add(1)
                }
                _ => 1,
            };
        }
        // The value, which a reader of the published record may hold
        // borrowed, is never reborrowed: its place is observed.
        let value = Self::value(&mut slot);
        let Ok(ConstructCustody {
            document,
            input,
            build,
            phase,
        }) = Self::custody::<_, ()>(&mut slot)
        else {
            return 1;
        };
        let phase = *phase;
        let input = OwnedInitialized::remaining(input);
        let document = OwnedDocument::remaining(document).saturating_add(input);
        // SAFETY: the value's place, observed, paired with its own state, as
        // its cleanup steps it.
        let value = T::remaining(unsafe { Slot::new(value, build) }).saturating_add(document);
        match phase {
            ConstructPhase::Done => 1,
            ConstructPhase::ReclaimInput => input,
            ConstructPhase::ReclaimDocument => document,
            ConstructPhase::ReclaimValue => value,
            _ => value.saturating_add(1),
        }
    }
}

/// Observation of a construction, `O` its value's custody observation: the
/// record's phase; whether the record, or before the record holds it the
/// task, holds the document; whether the record holds the detached input;
/// and the value's construction state, observed whole, once the record's
/// prefix is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ConstructDetail<O> {
    pub phase: Option<ConstructPhase>,
    pub document: bool,
    pub input: bool,
    pub build: Option<O>,
}

pub struct Construct<'s, I: DecodeInput<A>, T, A: Allocator> {
    document: Option<OwnedDocument<'s, I, A>>,
    marker: core::marker::PhantomData<fn() -> T>,
}

// SAFETY: initialization moves the document handle in and writes three
// resource-free fields; every later phase is recorded before it acquires.
unsafe impl<'s, I, T, A> Task<'s, A> for Construct<'s, I, T, A>
where
    I: DecodeInput<A> + 's,
    T: Transferable<A> + 's,
    A: Allocator + 's,
    A::Permit: Send,
{
    type State = Constructed<'s, I, T, A>;
    type Output = TypedValue<'s, I, T, A>;
    type Error = DecodeError<A::Refusal>;
    type Detail = ConstructDetail<<T::State as Custody>::Observation>;
    const INIT_STEPS: usize = Constructed::<'s, I, T, A>::INIT_STEPS;

    fn scope(&self) -> Option<&ScopeRef<'s, A>> {
        self.document.as_ref().map(OwnedDocument::scope)
    }

    fn initialized(prefix: &Prefix) -> usize {
        prefix.initialized()
    }

    fn initialize(
        &mut self,
        mut slot: Slot<'_, Self::State, Prefix>,
        a: &mut A,
    ) -> Result<(), Self::Error> {
        let (place, prefix) = slot.parts();
        let raw = place.as_ptr(prefix);
        // SAFETY: the slot pairs the record's place with its progress, so the
        // unit the progress names next is uninitialized; each unit writes
        // that one custody field by raw projection, forming no reference to
        // the rest, and every unit past the last is refused.
        unsafe {
            match prefix.initialized() {
                0 => field(
                    addr_of_mut!((*raw).custody.document),
                    || self.document.take(),
                    a,
                )?,
                1 => field(addr_of_mut!((*raw).custody.input), || None, a)?,
                2 => field(addr_of_mut!((*raw).custody.build), || T::INITIAL, a)?,
                3 => field(
                    addr_of_mut!((*raw).custody.phase),
                    || ConstructPhase::Build,
                    a,
                )?,
                _ => return Err(BoundedError::PlanMismatch.into()),
            }
        }
        prefix.advance();
        Ok(())
    }

    fn advance(
        &mut self,
        mut slot: Slot<'_, Self::State, Prefix>,
        a: &mut A,
    ) -> Result<bool, Self::Error> {
        // The value is reached only through its place; the custody is refused
        // until initialization is complete.
        let value = Constructed::value(&mut slot);
        let ConstructCustody {
            document,
            input,
            build,
            phase,
        } = Constructed::custody(&mut slot)?;
        match *phase {
            ConstructPhase::Build => {
                let document = document.as_ref().ok_or(BoundedError::PlanMismatch)?;
                // SAFETY: the value's place and its construction state, kept
                // in the record's custody, are retained across every call; the
                // document view ends with this call.
                let built = at(ConstructPlace::Build, || {
                    document.with_document(|view| {
                        T::build_step(view, 0, unsafe { Slot::new(value, &mut *build) }, a)
                    })
                })?;
                if built == Built::Done {
                    *phase = ConstructPhase::Detach;
                }
            }
            ConstructPhase::Detach => {
                DETACH.admit(a)?;
                let document = document.take().ok_or(BoundedError::PlanMismatch)?;
                // The input moves without copying; the document's arena and
                // parser record is retired to the scope queue.
                *input = Some(document.into_input());
                *phase = ConstructPhase::Publish;
            }
            ConstructPhase::Publish => {
                PUBLISH.admit(a)?;
                *phase = ConstructPhase::Published;
                return Ok(true);
            }
            _ => return Err(BoundedError::PlanMismatch.into()),
        }
        Ok(false)
    }

    fn publish(&mut self, record: OwnedInitialized<'s, Self::State, A>) -> Self::Output {
        TypedValue { record }
    }

    fn reclaim_step(&mut self, a: &mut A) -> BoundedResult<Reclaimed, A> {
        let place = slot_place(
            &self.document,
            ConstructPlace::Document,
            ConstructPlace::Cleanup,
        );
        at(place, || OwnedDocument::reclaim_step(&mut self.document, a))
    }

    fn detail(&self, record: Observed<'_, 's, Self, A>) -> Self::Detail {
        let Some(mut slot) = record else {
            return ConstructDetail {
                phase: None,
                document: self.document.is_some(),
                input: false,
                build: None,
            };
        };
        let (place, prefix) = slot.parts();
        let initialized = prefix.initialized();
        // SAFETY: the slot pairs the record's place with its progress; each
        // custody field is read only once the prefix records it written,
        // through a view of that field alone, the prefix borrowed for each
        // read; the value's construction state is observed under the prefix's
        // exclusive borrow; the value is never read.
        unsafe {
            ConstructDetail {
                document: if initialized > 0 {
                    place
                        .project(|record| addr_of_mut!((*record).custody.document))
                        .get(&*prefix)
                        .is_some()
                } else {
                    self.document.is_some()
                },
                input: initialized > 1
                    && place
                        .project(|record| addr_of_mut!((*record).custody.input))
                        .get(&*prefix)
                        .is_some(),
                build: (initialized > 2).then(|| {
                    place
                        .custody(&mut *prefix, |record| addr_of_mut!((*record).custody.build))
                        .observe()
                }),
                phase: (initialized > 3).then(|| {
                    *place
                        .project(|record| addr_of_mut!((*record).custody.phase))
                        .get(&*prefix)
                }),
            }
        }
    }
}

/// A published typed value with its original input. Moving the handle never
/// moves the value; dropping it queues the record for scope cleanup.
pub struct TypedValue<'s, I: DecodeInput<A>, T: InPlace<A>, A: Allocator> {
    record: OwnedInitialized<'s, Constructed<'s, I, T, A>, A>,
}

impl<'s, I: DecodeInput<A>, T: InPlace<A>, A: Allocator> TypedValue<'s, I, T, A> {
    /// The dispatch depth of the construction record behind this handle.
    pub(crate) const DISPATCH_DEPTH: usize =
        <Constructed<'s, I, T, A> as Reclaim<A>>::DISPATCH_DEPTH;

    /// The scope holding this value's record.
    pub(crate) fn scope(&self) -> &ScopeRef<'s, A> {
        self.record.scope()
    }

    pub fn value(&self) -> &T {
        // SAFETY: publication follows a completed build.
        unsafe { self.record.value().value.assume_init_ref() }
    }

    /// The original input the value was decoded from.
    pub fn input(&self) -> &I {
        match self.record.value().custody.input.as_ref() {
            Some(input) => input.value(),
            None => unreachable!("a published value retains its input"),
        }
    }

    /// The original input bytes the value was decoded from. Identity and
    /// signature checks run over these, never over a re-encoding, which may
    /// differ when decoding skipped unknown fields.
    pub fn bytes(&self) -> &[u8] {
        self.input().bytes()
    }

    /// Operation-local cleanup of this value and its input.
    pub fn reclaim_step(slot: &mut Option<Self>, a: &mut A) -> BoundedResult<Reclaimed, A> {
        reclaim_within(
            slot,
            a,
            |value| value.record,
            |record| Self { record },
            OwnedInitialized::reclaim_step,
        )
    }

    /// The calls [`Self::reclaim_step`] still takes from `slot`
    /// ([`OwnedInitialized::remaining`]).
    pub(crate) fn remaining(slot: &mut Option<Self>) -> u64 {
        let mut record = slot.take().map(|value| value.record);
        let remaining = OwnedInitialized::remaining(&mut record);
        *slot = record.map(|record| Self { record });
        remaining
    }
}

/// The [`ResourceBound`] of constructing `T` from an owned document of at
/// most `len` bytes ([`Construction`]): the record, initialized in four
/// fields; `T`'s own construction and cleanup ([`InPlace::COST`], its subtree
/// at most the input); the document's detachment and publication; and the
/// record's cleanup units around the value: its transition and the empty
/// document and input slots. The document and the input are accounted by
/// their own operations. The value and its record are what publication
/// retains.
pub fn construction_bound<I, T, A, R>(len: u64) -> Result<ResourceBound, BoundedError<R>>
where
    I: DecodeInput<A>,
    T: InPlace<A>,
    A: Allocator,
{
    construct_terms::<I, T, A, R>(len, ResourceBound::default(), ResourceBound::default())?
        .0
        .bound()
}

/// The terms of a construction ([`construction_bound`]): its operation's,
/// whose task is the second's, the record holding a document whose own
/// cleanup is `document` and an input whose own cleanup is `input`. The
/// record's size and initialization do not depend on its scope.
pub(crate) fn construct_terms<I, T, A, R>(
    len: u64,
    document: ResourceBound,
    input: ResourceBound,
) -> Result<(OperationTerms, ConstructTerms), BoundedError<R>>
where
    I: DecodeInput<A>,
    T: InPlace<A>,
    A: Allocator,
{
    let task = ConstructTerms::of::<T, A, R>(len, document, input)?;
    let operation = OperationTerms::of::<Constructed<'static, I, T, A>, A, R>(
        Constructed::<'static, I, T, A>::INIT_STEPS,
        task.bound()?,
    )?;
    Ok((operation, task))
}

/// The terms of a construction's task, one per [`ConstructPlace`].
pub(crate) struct ConstructTerms {
    build: ResourceBound,
    detach: WriteWork,
    publish: WriteWork,
    cleanup: WriteWork,
    document: ResourceBound,
    input: ResourceBound,
}

impl ConstructTerms {
    /// The task of constructing `T` from a document of at most `len` bytes,
    /// the record holding a document whose own cleanup is `document` and an
    /// input whose own cleanup is `input`.
    pub(crate) fn of<T: InPlace<A>, A: Allocator, R>(
        len: u64,
        document: ResourceBound,
        input: ResourceBound,
    ) -> Result<Self, BoundedError<R>> {
        Ok(Self {
            build: T::COST.bound(len)?,
            detach: DETACH.times(1)?,
            publish: PUBLISH.times(1)?,
            // The record's transition, or its release before initialization
            // completed; then two emptied slots: the record never holds both
            // the document and the input, and the task's document moved into
            // the record at its first initialization unit.
            cleanup: CLEANUP.times(1)?.then(EMPTIED.times(2)?)?,
            document,
            input,
        })
    }
}

impl Places for ConstructTerms {
    type Place = ConstructPlace;

    fn term(&self, place: ConstructPlace) -> ResourceBound {
        match place {
            ConstructPlace::Build => self.build,
            ConstructPlace::Detach => ResourceBound::of_work(self.detach),
            ConstructPlace::Publish => ResourceBound::of_work(self.publish),
            ConstructPlace::Cleanup => ResourceBound::of_work(self.cleanup),
            ConstructPlace::Document => self.document,
            ConstructPlace::Input => self.input,
        }
    }
}

/// The [`ResourceBound`] of decoding `T` from an input handle of at most
/// `len` bytes under `options` ([`TypedDecoder`]): the parse
/// ([`super::parse::parse_bound`]), then the construction while the document
/// is still held ([`construction_bound`]). Both records are what
/// publication retains until the scope reclaims the document's.
pub fn typed_decode_bound<I, T, A, R>(
    len: u64,
    options: Options,
) -> Result<ResourceBound, BoundedError<R>>
where
    I: DecodeInput<A>,
    T: InPlace<A>,
    A: Allocator,
{
    super::parse::parse_bound::<I, A, R>(len, options)?.then(construction_bound::<I, T, A, R>(len)?)
}

/// Construction from an owned document.
pub type Construction<'s, I, T, A> = Operation<'s, Construct<'s, I, T, A>, A>;

impl<'s, I, T, A> Construction<'s, I, T, A>
where
    I: DecodeInput<A> + 's,
    T: Transferable<A> + 's,
    A: Allocator + 's,
    A::Permit: Send,
{
    /// Construct `T` from `document`'s root. Construction allocates nothing.
    pub fn construct(document: OwnedDocument<'s, I, A>) -> Self {
        Operation::new(Construct {
            document: Some(document),
            marker: core::marker::PhantomData,
        })
    }
}

/// Where a typed decode is, `O` its value's custody observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[expect(
    clippy::large_enum_variant,
    reason = "custody snapshots preserve the complete continuation inline; observation must not allocate"
)]
pub enum TypedPosition<O> {
    Parse(Position<ParseDetail>),
    Construct(Position<ConstructDetail<O>>),
    Finished,
}

impl<O> TypedPosition<O> {
    /// This position with the value's custody observation elided, whatever
    /// the value's type: what a record of positions of any typed decode,
    /// kept in fixed storage, holds.
    pub fn outline(self) -> TypedPosition<()> {
        match self {
            Self::Parse(position) => TypedPosition::Parse(position),
            Self::Construct(position) => TypedPosition::Construct(Position {
                allocated: position.allocated,
                initialized: position.initialized,
                initialization_steps: position.initialization_steps,
                cancelling: position.cancelling,
                finished: position.finished,
                outstanding: position.outstanding,
                detail: ConstructDetail {
                    phase: position.detail.phase,
                    document: position.detail.document,
                    input: position.detail.input,
                    build: position.detail.build.map(|_| ()),
                },
            }),
            Self::Finished => TypedPosition::Finished,
        }
    }
}

enum Stage<'s, I, T, A>
where
    I: DecodeInput<A> + 's,
    T: Transferable<A> + 's,
    A: Allocator + 's,
    A::Permit: Send,
{
    Parse(DocumentDecoder<'s, I, A>),
    Construct(Construction<'s, I, T, A>),
    Finished,
}

/// Typed decoding: a parse, then construction from the parsed document.
pub struct TypedDecoder<'s, I, T, A>
where
    I: DecodeInput<A>,
    T: Transferable<A>,
    A: Allocator,
    A::Permit: Send,
{
    stage: Stage<'s, I, T, A>,
}

impl<'s, I, T, A> TypedDecoder<'s, I, T, A>
where
    I: DecodeInput<A> + 's,
    T: Transferable<A> + 's,
    A: Allocator + 's,
    A::Permit: Send,
{
    /// A typed decode of `input`. Construction allocates nothing.
    pub fn new(input: OwnedInitialized<'s, I, A>, options: Options) -> Self {
        Self {
            stage: Stage::Parse(DocumentDecoder::parse(input, options)),
        }
    }

    pub fn cancel(&mut self) {
        match &mut self.stage {
            Stage::Parse(operation) => operation.cancel(),
            Stage::Construct(operation) => operation.cancel(),
            Stage::Finished => {}
        }
    }

    pub fn position(&mut self) -> TypedPosition<<T::State as Custody>::Observation> {
        match &mut self.stage {
            Stage::Parse(operation) => TypedPosition::Parse(operation.position()),
            Stage::Construct(operation) => TypedPosition::Construct(operation.position()),
            Stage::Finished => TypedPosition::Finished,
        }
    }

    /// One step of the decode. A construction record whose dispatch depth
    /// exceeds the limit fails to compile where this decoder is used
    /// ([`super::reclamation::MAX_DISPATCH_DEPTH`]), so no step can reach it.
    pub fn step(&mut self, a: &mut A) -> ConstructResult<Step<TypedValue<'s, I, T, A>>, A> {
        match &mut self.stage {
            Stage::Parse(operation) => match operation.step(a)? {
                Step::Complete(document) => {
                    self.stage = Stage::Construct(Construction::construct(document));
                    Ok(Step::Progress)
                }
                Step::Progress => Ok(Step::Progress),
                Step::Finished => {
                    self.stage = Stage::Finished;
                    Ok(Step::Finished)
                }
            },
            Stage::Construct(operation) => match operation.step(a)? {
                Step::Complete(value) => {
                    self.stage = Stage::Finished;
                    Ok(Step::Complete(value))
                }
                Step::Progress => Ok(Step::Progress),
                Step::Finished => {
                    self.stage = Stage::Finished;
                    Ok(Step::Finished)
                }
            },
            Stage::Finished => Ok(Step::Finished),
        }
    }
}

impl<'s, I, T, A> Resumable<A> for TypedDecoder<'s, I, T, A>
where
    I: DecodeInput<A> + 's,
    T: Transferable<A> + 's,
    A: Allocator + 's,
    A::Permit: Send,
{
    type Output = TypedValue<'s, I, T, A>;
    type Error = DecodeError<A::Refusal>;
    type Position = TypedPosition<<T::State as Custody>::Observation>;

    fn step(&mut self, a: &mut A) -> Result<Step<TypedValue<'s, I, T, A>>, Self::Error> {
        TypedDecoder::step(self, a)
    }

    fn position(&mut self) -> Self::Position {
        TypedDecoder::position(self)
    }
}
