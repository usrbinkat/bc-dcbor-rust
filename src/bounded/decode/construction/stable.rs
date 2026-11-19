//! The single stable-block primitive.
//!
//! Every fixed metadata record, child custody record, lifecycle record and
//! owned scope is one allocation acquired and released by this module, with the
//! same units: admission of the bytes written and of the block's eventual
//! release, a permit for the whole block, a fallible physical allocation,
//! initialization in place; later, the block freed and then its permit
//! released, which its acquisition paid for. No destructor of the held value
//! ever runs: its owner must have made it resource-free first.
extern crate alloc;

use alloc::alloc::{alloc, dealloc};
use core::alloc::Layout;
use core::marker::PhantomData;
use core::mem::{MaybeUninit, size_of};
use core::ptr::{self, NonNull};

use super::reclamation::Place;
use crate::bounded::{
    Acquisition, Allocator, BoundedError, BoundedResult, Budget, Caller, Capped, CustodySink,
    Forfeit, Identity, Obligation, Origin, Owner, Performer, PermitsObserved, ResourceBound,
    Retained, TURN, Unit, WriteWork, reserved, total_held,
};
use crate::sync::{Atomics, Core, Representation};

/// The largest unit of bytes any single admission may cover: the bytes of
/// one turn's quantum ([`TURN`]).
pub const QUANTUM: usize = TURN.bytes as usize;

/// Writing a block's value: one value and its bytes, at most a quantum. The
/// block's owner supplies the place.
const WRITE: Capped<Caller> = Capped::new(Caller, 1, TURN.bytes);

/// Releasing a block or a reservation held with permits of `P`: one value
/// and the permit's bytes. Admitted by the acquisition, before the
/// allocation exists, so the release is paid for on every path that frees
/// it, a metered cleanup step or a terminal one.
const fn released<P>() -> Unit<Caller> {
    Unit::new(Caller, 1, crate::bounded::permit_bytes::<P>() as u64)
}

/// The acquisition `holder` names resumed on `pending`, or a new one bound
/// with a fresh ticket the holder keeps and an acquisition identity `a`
/// mints under the pending's owner ([`Pending::bind`]): the one way a
/// holder enters its acquisition. Refused, nothing changed, while another
/// acquisition is pending.
fn bound<B: Budget>(
    pending: &mut Pending<B::Origin>,
    holder: &mut Option<Ticket>,
    a: &mut B,
) -> BoundedResult<Ticket, B> {
    let ticket = pending.bind(*holder, a)?;
    *holder = Some(ticket);
    Ok(ticket)
}

/// The acquisition `ticket` ended, its credit all settled: its capability
/// ended `by` the step's performer, `pending` idle again and the holder's
/// ticket cleared.
fn finished<O: Origin, R>(
    pending: &mut Pending<O>,
    holder: &mut Option<Ticket>,
    ticket: Ticket,
    by: Performer,
) -> Result<(), BoundedError<R>> {
    pending.complete(ticket, by)?;
    *holder = None;
    Ok(())
}

/// The one held admission of an acquisition: the acquisition `holder` names
/// entered (bound now if it is new, validated if resumed, [`bound`]), its
/// admissions so far one of `after`, then `admit` run with the pending's
/// owner and the acquisition's recorded identity, and the obligation it
/// returns, keeping its origin, held in `pending` at once
/// ([`Pending::hold`]). Refused [`BoundedError::PlanMismatch`] before any
/// admission when the acquisition has admitted anything else. Every held
/// admission of an acquisition on a [`Pending`], a construction's or an
/// arena's, goes through here.
pub(crate) fn admit_obligation<A: Allocator>(
    pending: &mut Pending<A::Origin>,
    holder: &mut Option<Ticket>,
    after: &[Admitted],
    admit: impl FnOnce(&mut A, &Owner, Identity) -> BoundedResult<Retained<A::Origin>, A>,
    a: &mut A,
) -> BoundedResult<(), A> {
    // The obligation's work is admitted once, by `admit`; storing the
    // custody it returns into its slot follows with no fallible step
    // between, and admits nothing further: it is one of Pending's fixed-field
    // operations, bounded enforcement overhead ([`Pending`]), not a charged
    // operation ([`Budget::traverse`] defines what is charged). The slot's
    // representation is bounded by its initialization unit's extent
    // ([`initialize_pending`]).
    let ticket = bound(pending, holder, a)?;
    if !after.contains(&pending.admitted(ticket)?) {
        return Err(BoundedError::PlanMismatch);
    }
    let (owner, acquisition) = pending.acquiring(ticket)?;
    let held = admit(a, owner, acquisition)?;
    pending.hold(ticket, held)
}

/// Admit the grant's work `grant` of an allocation, the acquisition's first
/// admission, for the acquisition `holder` names (bound now): held
/// ([`Obligation::Grant`]) in `pending` until the allocation's grant spends
/// it, or its failure or cleanup entry forfeits it ([`grant`],
/// [`Pending::settle_all`]). Its release follows ([`admit_release`]).
#[cfg(any(test, feature = "custom-std-collections"))]
pub(crate) fn admit_grant<A: Allocator>(
    pending: &mut Pending<A::Origin>,
    holder: &mut Option<Ticket>,
    grant: Unit<Caller>,
    a: &mut A,
) -> BoundedResult<(), A> {
    admit_obligation(
        pending,
        holder,
        &[Admitted::Nothing],
        |a, owner, acquisition| grant.admit_held(a, Obligation::Grant, owner, acquisition),
        a,
    )
}

/// Admit the release of an allocation with permits of `A::Permit` before
/// acquiring it, for the acquisition `holder` names (bound now if it is
/// new): what every acquisition admits for the allocation it is about to
/// request ([`released`]), first (a payload's, [`allocate_payload`]) or
/// after its grant's work ([`admit_grant`], [`acquire`]), its permit checked
/// against [`crate::bounded::PERMIT_BYTES`] where the acquisition is used.
/// Admitted held ([`Obligation::Release`]): the obligation the admission
/// returns, keeping its origin, is held in `pending` at once, until the
/// allocation is granted, when its grant spends it, or cleanup entry
/// forfeits it ([`Pending::settle_all`]).
pub(crate) fn admit_release<A: Allocator>(
    pending: &mut Pending<A::Origin>,
    holder: &mut Option<Ticket>,
    a: &mut A,
) -> BoundedResult<(), A> {
    admit_obligation(
        pending,
        holder,
        &[Admitted::Nothing, Admitted::Write],
        |a, owner, acquisition| {
            const { released::<A::Permit>() }.admit_held(a, Obligation::Release, owner, acquisition)
        },
        a,
    )
}

/// An allocation's grant, the one definition every acquisition holding its
/// grant's work and its release uses ([`admit_grant`], [`admit_release`]),
/// for the acquisition `holder` names, resumed and validated ([`bound`]):
/// the permit for `bytes` requested; at its grant, the release spent at the
/// permit in the family that admitted it; then `make` performs the physical
/// step the permit pays for. Made, its effect is reported reserved and the
/// grant's work spent; refused by `make` under a rule, the effect reported
/// failed for a physical failure ([`Forfeit::AcquisitionFailed`]), the
/// permit dropped (performing its release), and the grant's work forfeited
/// under the rule. The acquisition ends either way, `pending` idle and the
/// holder's ticket cleared; a refused request ends nothing, both
/// obligations kept for the retry. Refused [`BoundedError::PlanMismatch`],
/// nothing requested, without a held acquisition holding both.
pub(crate) fn grant<A: Allocator, T>(
    pending: &mut Pending<A::Origin>,
    holder: &mut Option<Ticket>,
    bytes: u64,
    make: impl FnOnce() -> Result<T, Forfeit>,
    a: &mut A,
) -> BoundedResult<(A::Permit, T), A> {
    // A resume only, as [`allocate_payload`]'s: no ticket, no acquisition.
    if holder.is_none() {
        return Err(BoundedError::PlanMismatch);
    }
    let ticket = bound(pending, holder, a)?;
    if pending.admitted(ticket)? != Admitted::Release || pending.grant.is_none() {
        return Err(BoundedError::PlanMismatch);
    }
    let acquisition = pending.acquisition(ticket)?;
    let permit = a.allocate(bytes).map_err(BoundedError::Refused)?;
    let id = A::permit_identity(&permit);
    let by = a.performer();
    // Granted: the permit carries the release, which its drop performs
    // whatever follows.
    pending.spend_release(ticket, id, by)?;
    match reserved(a, permit, acquisition, make) {
        Ok((permit, made)) => {
            pending.settle_grant(ticket, id, None, by)?;
            finished(pending, holder, ticket, by)?;
            Ok((permit, made))
        }
        // The permit was dropped inside this step; the work the grant paid
        // for never happens.
        Err(rule) => {
            pending.settle_grant(ticket, id, Some(rule), by)?;
            finished(pending, holder, ticket, by)?;
            Err(if matches!(rule, Forfeit::AcquisitionFailed) {
                BoundedError::Allocation { bytes }
            } else {
                BoundedError::PlanMismatch
            })
        }
    }
}

/// The release credit an acquisition of an allocation with permits of `P`
/// holds once [`admit_release`] admitted it and before its grant.
#[cfg(test)]
pub(crate) const fn release_credit<P>() -> WriteWork {
    released::<P>().work()
}

/// A payload's allocation, the one definition every buffer and sequence
/// uses after admitting the payload's reservation unit and its release
/// ([`admit_release`]), for the acquisition `holder` names: the permit for
/// `bytes` granted into the slot `payload` selects in `custody`, its release
/// spent at the permit in the family that admitted it, then the physical
/// reservation `reserve` makes, its outcome reported as the permit's effect.
/// The acquisition ends either way, `pending` idle and the holder's ticket
/// cleared. The permit enters the payload slot only once its reservation
/// exists; a failed reservation's permit is dropped inside this step
/// ([`reserved`]), performing the release its admission prepaid, and the
/// failure is reported as [`BoundedError::Allocation`] with the slot
/// empty. The failure is terminal: the operation's driver routes it to
/// cleanup, which finds no payload permit to release, and no build follows
/// (one that did would find no release held and be refused
/// [`BoundedError::PlanMismatch`], nothing changed, never granted again).
pub(crate) fn allocate_payload<A: Allocator, C: ?Sized>(
    custody: &mut C,
    payload: impl Fn(&mut C) -> BoundedResult<&mut Option<A::Permit>, A>,
    bytes: u64,
    reserve: impl FnOnce(&mut C) -> bool,
    pending: &mut Pending<A::Origin>,
    holder: &mut Option<Ticket>,
    a: &mut A,
) -> BoundedResult<(), A> {
    // A resume only: with no ticket held there is no acquisition to resume,
    // refused before `bound` could bind and mint a new one. The resume
    // validates the performing budget against the pending's owner, so an
    // allocation is never requested under an incompatible policy.
    if holder.is_none() {
        return Err(BoundedError::PlanMismatch);
    }
    let ticket = bound(pending, holder, a)?;
    // A payload's acquisition holds its release alone; one holding a
    // grant's work is a block's or a node's ([`grant`]).
    if pending.admitted(ticket)? != Admitted::Release
        || pending.grant.is_some()
        || payload(custody)?.is_some()
    {
        return Err(BoundedError::PlanMismatch);
    }
    // A refused request keeps the release held in `pending`; the retry's
    // grant spends it.
    let acquisition = pending.acquisition(ticket)?;
    let permit = a.allocate(bytes).map_err(BoundedError::Refused)?;
    let id = A::permit_identity(&permit);
    // Granted: the permit carries the release, which its drop performs
    // whatever follows.
    let by = a.performer();
    pending.spend_release(ticket, id, by)?;
    let reservation = reserved(a, permit, acquisition, || {
        if reserve(custody) {
            Ok(())
        } else {
            Err(Forfeit::AcquisitionFailed)
        }
    });
    finished(pending, holder, ticket, by)?;
    let (permit, ()) = reservation.map_err(|_| BoundedError::Allocation { bytes })?;
    *payload(custody)? = Some(permit);
    Ok(())
}

/// The admissions an acquisition has made toward a block, kept across a
/// refused or failed allocation so no admitted unit is repeated: none, the
/// block's write, or its write and its release. Its holder keeps it with the
/// slot the block will occupy. Part of every custody observation of an
/// acquisition in progress: it fixes what the acquisition's next step
/// admits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum Admitted {
    #[default]
    Nothing,
    Write,
    Release,
}

/// The local token of one acquisition bound to a [`Pending`]: issued when
/// the acquisition binds ([`Pending::bind`]), never reused by that pending,
/// and kept by its holder, in place of its admissions, until the acquisition
/// completes, fails or is cancelled. Every operation on the pending credit
/// names it, so no other acquisition can resume, consume or cancel it. A
/// nonzero sequence, so a holder's `Option<Ticket>` is one word.
///
/// Local only: every pending issues `1` first, so two pendings' tickets
/// collide. It is never a recorded identity; the acquisition's recorded
/// identity is the session-qualified [`Identity`] its binding mints under
/// the pending's owner ([`Budget::acquisition`]), which the pending keeps
/// beside the ticket and every obligation admitted for it carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Ticket(core::num::NonZeroU64);

/// Whether a [`Pending`]'s owner has been made, kept apart from whether it
/// records: an owner made under an ordinary budget is initialized, and its
/// unobserved identity never makes it eligible for replacement. A custody
/// whose owner is minted when the custody is made starts initialized; one
/// made with no budget at hand (an arena) starts uninitialized, and its
/// first acquisition entry, under any budget, makes and stores the owner
/// ([`Pending::bind`]), which every later entry validates against.
pub(crate) enum OwnerState {
    Uninitialized,
    Initialized(Owner),
}

/// What a [`Pending`] holds besides its owner and its credit, written in
/// one unit: the tickets it has issued and the acquisition bound now, its
/// local ticket and its capability ([`Binding`]). What that acquisition has
/// admitted is read from the credit slots ([`Pending::admitted`]). Its
/// unit's write extent is checked against the quantum where it is written
/// ([`initialize_pending`]): the issued count, the ticket and the
/// capability (its origin and its identity), at most a quantum for every
/// origin this crate builds.
struct PendingHead<O: Origin> {
    issued: u64,
    active: Option<Binding<O>>,
}

/// The acquisition a [`Pending`] has bound: its local ticket and its
/// capability, together, so neither exists without the other. The one
/// stored record of which acquisition is bound.
struct Binding<O: Origin> {
    ticket: Ticket,
    acquisition: Acquisition<O>,
}

impl<O: Origin> PendingHead<O> {
    /// Idle, no ticket issued.
    const IDLE: Self = Self {
        issued: 0,
        active: None,
    };
}

/// The credit of the one acquisition a construction holds pending: which
/// acquisition it is (its local [`Ticket`] and its recorded [`Identity`]),
/// what it has admitted, and the obligations its admissions returned
/// ([`Retained`]), its block's grant (its write) and its release, each
/// keeping the origin and identity its admission gave it and naming the
/// acquisition, so its spend, its forfeit, its cancel and its drop reach the
/// family that admitted it, whichever policy performs them, and stay the
/// same acquisition's whichever families served it. Kept by the operation's
/// own custody (or a standalone construction's driver), outside every child
/// state; a holder keeps only its ticket.
///
/// A construction holds at most one acquisition pending at any time, and
/// this type enforces it: an acquisition binds only an idle pending
/// ([`Self::bind`]), and every later operation names its ticket; a
/// conflicting use is refused [`BoundedError::PlanMismatch`] before any
/// admission or change. Completion ([`Self::complete`]) returns it to idle;
/// publication requires idle ([`Self::is_idle`]).
///
/// Held in a stable block, where no destructor runs: the holder settles it
/// explicitly at cleanup entry ([`Self::settle_all`]). Its fields are
/// initialized one unit each ([`initialize_pending`]).
///
/// Its operations are bounded enforcement overhead, charged no work of
/// their own: each touches a fixed set of its own fields, and none traverses
/// a payload, a capacity or a history. The work an acquisition charges is
/// its obligations' own (its grant's write and its release), admitted once
/// each through the one route ([`admit_obligation`]) and never again on a
/// retry; this custody only records who holds it. Per operation:
/// - [`Self::bind`], resuming: the active ticket, and the owner validated.
/// - [`Self::bind`], new: the owner's state once (made if deferred), then
///   the tickets issued, the active ticket and the acquisition identity. An
///   intentional lifecycle transition before any work admission: observed
///   ([`Budget::acquisition`]), bounded, counted among a step's attempts,
///   and retained progress when the admission after it refuses, never an
///   effect.
/// - [`Self::hold`]: the active ticket, the acquisition identity and one
///   slot.
/// - [`Self::held_credit`]: two slots and one checked addition.
/// - [`Self::spend_release`], [`Self::settle_grant`]: the active ticket, one
///   slot taken, one settlement into its origin.
/// - [`Self::complete`]: the active ticket, two empty-slot checks, the
///   acquisition's metadata cleared.
/// - [`Self::settle_all`]: at most two settlements, the acquisition's
///   metadata cleared.
///
/// Public only as an unnameable parameter of the sealed operation
/// interface (`Task::advance`): its module is the crate's own, its fields
/// and every method crate-private.
pub struct Pending<O: Origin> {
    owner: OwnerState,
    head: PendingHead<O>,
    grant: Option<Retained<O>>,
    release: Option<Retained<O>>,
}

/// The units initializing a [`Pending`]: its four fields, the owner's state
/// ([`OwnerState`]), `PendingHead`, the grant slot and the release slot, one
/// field unit each, four in all. Each is written whole by
/// [`super::super::initialization::field`], which admits one value and the
/// field's whole size, discriminant and alignment padding included, and
/// whose `Unit::written` refuses at compile time a field larger than a
/// quantum: the contract is that assertion, evaluated for the build's
/// origin type; no layout is stated here. The owner's state is a unit of
/// its own because its discriminant, beside the owner's own optional
/// session reference, leaves no room for the head beside it in one
/// quantum. A `Pending` held inside a parent initialized field by field is
/// initialized by that parent's own units, these four among them.
pub(crate) const PENDING_UNITS: usize = 4;

/// Write unit `unit` of the pending credit at `raw`, empty and idle, its
/// owner's unit (unit 0) initialized with `owner` when given (the custody's
/// capability, minted when that custody is made, [`Budget::owner`]) and
/// uninitialized otherwise (made by its first acquisition entry,
/// [`Pending::bind`]), in one admitted unit of its own field's bytes. A
/// refused admission drops the owner it was given: the custody mints
/// another for the retry, and the family's owner sequence counts both
/// ([`Budget::owner`] counts identities minted, not custodies made).
///
/// # Safety
/// `raw` is valid for writes of a `Pending<O>` and aligned for it, and units
/// below `unit` are written; each unit is written once.
pub(crate) unsafe fn initialize_pending<O: Origin, A: Allocator>(
    raw: *mut Pending<O>,
    unit: usize,
    owner: Option<Owner>,
    a: &mut A,
) -> BoundedResult<(), A> {
    use crate::bounded::decode::initialization::field;
    // SAFETY: forwarded from the caller; each projection reaches one field
    // by field syntax, forming no reference.
    unsafe {
        match unit {
            0 => field(
                ptr::addr_of_mut!((*raw).owner),
                || match owner {
                    Some(owner) => OwnerState::Initialized(owner),
                    None => OwnerState::Uninitialized,
                },
                a,
            ),
            1 => field(ptr::addr_of_mut!((*raw).head), || PendingHead::IDLE, a),
            2 => field(ptr::addr_of_mut!((*raw).grant), || None, a),
            3 => field(ptr::addr_of_mut!((*raw).release), || None, a),
            _ => Err(BoundedError::PlanMismatch),
        }
    }
}

/// Drop in place the first `written` units of the pending credit at `raw`
/// (the units [`initialize_pending`] wrote), newest first: the custody block
/// holding it runs no destructor, so its final release, and the cleanup of a
/// partially initialized prefix, call this so the owner capability's
/// session reference is released. A fully written pending is settled first
/// ([`Pending::settle_all`]), so its grant and release are empty and their
/// drops record nothing; a prefix short of them holds no admitted credit,
/// since no acquisition binds before every unit is written. Allocation-free
/// on the custody's side, non-unwinding, admitting nothing: legal on
/// terminal paths. The owner's drop releases one session reference; the
/// last one held destroys the session's store, which its holder (the
/// recording session's creator) is expected to outlive
/// ([`crate::bounded::Owner`]).
///
/// # Safety
/// `raw` is valid and aligned for a `Pending<O>`, exactly its first
/// `written` units are initialized, and nothing reads them afterwards.
pub(crate) unsafe fn drop_pending<O: Origin>(raw: *mut Pending<O>, written: usize) {
    // SAFETY: forwarded from the caller; a whole pending is dropped as one
    // value, its destructor settling and ending what it holds
    // ([`Pending::drop`]); a prefix's projections each reach one initialized
    // field by field syntax, forming no reference to the whole, and a prefix
    // holds no admitted credit and no binding.
    unsafe {
        if written == PENDING_UNITS {
            ptr::drop_in_place(raw);
            return;
        }
        if written > 3 {
            ptr::drop_in_place(ptr::addr_of_mut!((*raw).release));
        }
        if written > 2 {
            ptr::drop_in_place(ptr::addr_of_mut!((*raw).grant));
        }
        // The head holds the bound acquisition's capability, if any, and
        // through it its origin's counted reference. A capability still held
        // drops unended: no drop publishes an end, so the acquisition stays
        // active and refinement refuses it; every settled path ends it first.
        if written > 1 {
            ptr::drop_in_place(ptr::addr_of_mut!((*raw).head));
        }
        if written > 0 {
            ptr::drop_in_place(ptr::addr_of_mut!((*raw).owner));
        }
    }
}

impl<O: Origin> Pending<O> {
    /// Idle, empty and owned by `owner`, the capability its holder's custody
    /// minted when it was made ([`Budget::owner`]): a standalone
    /// construction's driver holds one whole.
    #[cfg(test)]
    pub(crate) const fn new(owner: Owner) -> Self {
        Self {
            owner: OwnerState::Initialized(owner),
            head: PendingHead::IDLE,
            grant: None,
            release: None,
        }
    }

    /// Idle, empty, its owner not yet made: for a custody made with no
    /// budget at hand, whose first acquisition entry makes it
    /// ([`Self::bind`]).
    pub(crate) const fn deferred() -> Self {
        Self {
            owner: OwnerState::Uninitialized,
            head: PendingHead::IDLE,
            grant: None,
            release: None,
        }
    }

    /// The owner, once made.
    fn owner<R>(&self) -> Result<&Owner, BoundedError<R>> {
        self.owner_ref().ok_or(BoundedError::PlanMismatch)
    }

    /// The owner, once made; none while it is not yet made
    /// ([`OwnerState::Uninitialized`]). The one read of the stored owner.
    pub(crate) fn owner_ref(&self) -> Option<&Owner> {
        match &self.owner {
            OwnerState::Initialized(owner) => Some(owner),
            OwnerState::Uninitialized => None,
        }
    }

    /// The identity of this pending's owner, the custody whose acquisitions
    /// it holds, read from the owner it stores ([`Owner::id`]); none while
    /// the owner is not yet made ([`OwnerState::Uninitialized`]). Minting
    /// nothing: the observation key of this custody's held obligations.
    pub(crate) fn owner_id(&self) -> Option<Identity> {
        self.owner_ref().map(Owner::id)
    }

    /// Whether no acquisition is bound and no credit held: what publication
    /// and cleanup's end require.
    pub(crate) fn is_idle(&self) -> bool {
        self.head.active.is_none() && self.grant.is_none() && self.release.is_none()
    }

    /// The acquisition `held` names resumed, or, for none, a new one bound
    /// to an idle pending with a fresh ticket and the recorded identity `a`
    /// mints for it under this pending's owner ([`Budget::acquisition`]),
    /// which every obligation admitted for it carries, whichever families
    /// later serve it: minted once here, never on a resume, so a retry
    /// under another policy keeps it. Refused [`BoundedError::PlanMismatch`],
    /// the pending unchanged and nothing minted: a ticket this pending does
    /// not have bound, or a new acquisition while another is bound; refused
    /// [`BoundedError::Overflow`] when the tickets run out. Every entry, a
    /// resume included, first validates the performing budget against this
    /// pending's owner ([`Budget::validate_owner`]; a new bind through
    /// [`Budget::acquisition`], which runs the same validation before it
    /// mints): an incompatible budget (another session, a crossing between
    /// recorded and unrecorded, or a session that cannot record more) is
    /// refused ([`BoundedError::Refused`]) with the pending and resource
    /// accounting unchanged and no ticket issued, while recording validity
    /// becomes sticky-invalid.
    ///
    /// A pending whose owner is not yet made ([`OwnerState::Uninitialized`])
    /// has it made by its first new bind, under whatever budget performs it,
    /// and stored before the acquisition is minted under it: an ordinary
    /// budget makes an initialized ordinary owner, never later replaced, so a
    /// later recorded budget is refused by its validation as any crossing is.
    /// A refused making leaves the owner uninitialized, nothing bound.
    pub(crate) fn bind<B: Budget<Origin = O>>(
        &mut self,
        held: Option<Ticket>,
        a: &mut B,
    ) -> BoundedResult<Ticket, B> {
        let active = self.head.active.as_ref().map(|binding| binding.ticket);
        match (held, active) {
            (Some(ticket), Some(active)) if ticket == active => {
                // A resume, possibly under another policy than the one that
                // bound it: the performing budget is validated against the
                // owner it was bound for, minting nothing, so the original
                // acquisition identity is kept across compatible policies
                // and an incompatible one (another session, or a crossing
                // between recorded and unrecorded) is refused here, before
                // any admission: the pending and resource accounting
                // unchanged, recording validity sticky-invalid.
                a.validate_owner(self.owner()?)
                    .map_err(BoundedError::Refused)?;
                Ok(ticket)
            }
            (None, None) if self.grant.is_none() && self.release.is_none() => {
                let issued = self
                    .head
                    .issued
                    .checked_add(1)
                    .ok_or(BoundedError::Overflow)?;
                let ticket =
                    Ticket(core::num::NonZeroU64::new(issued).ok_or(BoundedError::Overflow)?);
                if let OwnerState::Uninitialized = self.owner {
                    self.owner = OwnerState::Initialized(a.owner().map_err(BoundedError::Refused)?);
                }
                let acquisition = a
                    .acquisition(self.owner()?)
                    .map_err(BoundedError::Refused)?;
                self.head.issued = issued;
                self.head.active = Some(Binding {
                    ticket,
                    acquisition,
                });
                Ok(ticket)
            }
            _ => Err(BoundedError::PlanMismatch),
        }
    }

    /// What every admission for the acquisition `ticket` presents
    /// ([`crate::bounded::Unit::admit_held`]): the capability of the custody
    /// that owns this pending, shared only for the call (the one stored copy
    /// is this pending's head), and the acquisition's recorded identity.
    pub(crate) fn acquiring<R>(
        &self,
        ticket: Ticket,
    ) -> Result<(&Owner, Identity), BoundedError<R>> {
        Ok((self.owner()?, self.bound(ticket)?))
    }

    /// The recorded identity of the acquisition `ticket`, which its
    /// admissions name ([`crate::bounded::Unit::admit_held`]).
    pub(crate) fn acquisition<R>(&self, ticket: Ticket) -> Result<Identity, BoundedError<R>> {
        self.bound(ticket)
    }

    /// The identity of the acquisition bound now, refused unless `ticket`
    /// is its ticket.
    fn bound<R>(&self, ticket: Ticket) -> Result<Identity, BoundedError<R>> {
        match &self.head.active {
            Some(binding) if binding.ticket == ticket => Ok(binding.acquisition.id()),
            _ => Err(BoundedError::PlanMismatch),
        }
    }

    /// Refused unless `ticket` is the acquisition bound now.
    fn check<R>(&self, ticket: Ticket) -> Result<(), BoundedError<R>> {
        self.bound(ticket).map(|_| ())
    }

    /// The binding now, read for a witness: its ticket and its identity,
    /// or none and the unobserved identity when idle.
    #[cfg(test)]
    fn binding(&self) -> (Option<Ticket>, Identity) {
        match &self.head.active {
            Some(binding) => (Some(binding.ticket), binding.acquisition.id()),
            None => (None, Identity::UNOBSERVED),
        }
    }

    /// What the acquisition `ticket` has admitted, read from the credit
    /// slots: the release held, `Release`; the grant's work alone, `Write`;
    /// neither, `Nothing`.
    pub(crate) fn admitted<R>(&self, ticket: Ticket) -> Result<Admitted, BoundedError<R>> {
        self.check(ticket)?;
        Ok(self.held_phase())
    }

    /// The admissions the credit slots hold. Sound as an acquisition's
    /// progress because no partly settled acquisition is ever observed: the
    /// settlement helpers ([`Self::spend_release`], [`Self::settle_grant`],
    /// [`Self::complete`]) run only inside [`grant`]'s and
    /// [`allocate_payload`]'s continuous sequence, one exclusive borrow of
    /// the pending from the allocation to the completion, which clears the
    /// active acquisition; and [`Self::settle_all`] clears it with the
    /// slots. So an active acquisition with both slots empty is always
    /// bound with nothing admitted yet, never partly settled.
    pub(crate) fn held_phase(&self) -> Admitted {
        match (self.grant.is_some(), self.release.is_some()) {
            (_, true) => Admitted::Release,
            (true, false) => Admitted::Write,
            (false, false) => Admitted::Nothing,
        }
    }

    /// Hold `held`, the obligation its admission just returned, for the
    /// acquisition `ticket`, in its own slot, which advances what it has
    /// admitted. Refused, `held` dropped and so forfeited into its own
    /// origin, for another ticket, an obligation admitted for another
    /// acquisition, or an occupied slot: all engine defects.
    pub(crate) fn hold<R>(
        &mut self,
        ticket: Ticket,
        held: Retained<O>,
    ) -> Result<(), BoundedError<R>> {
        if held.acquisition() != self.bound(ticket)? {
            return Err(BoundedError::PlanMismatch);
        }
        let slot = match held.obligation() {
            Obligation::Grant => &mut self.grant,
            Obligation::Release => &mut self.release,
            Obligation::BucketWindow => return Err(BoundedError::PlanMismatch),
        };
        if slot.is_some() {
            return Err(BoundedError::PlanMismatch);
        }
        *slot = Some(held);
        Ok(())
    }

    /// This pending's custody, one group under its stored owner (`None`
    /// while the owner is not yet made, [`OwnerState::Uninitialized`]): each
    /// obligation it owns and still holds work for, as its custody
    /// observation ([`Retained::observation`]), its grant's write, then its
    /// release. A pending owns no permit: the permit its grant makes is its
    /// holder's. Read-only: it allocates, admits, mints, publishes and
    /// settles nothing, and an emptied or exhausted slot is not reported.
    /// The one traversal of a pending's custody; nothing else reports its
    /// obligations, and every child state borrowing it reports none.
    pub(crate) fn observe_custody<P>(&self, sink: &mut dyn CustodySink<P>) -> PermitsObserved {
        sink.begin(self.owner_id());
        // The bound acquisition, credit or none: its identity is retained
        // custody from its bind to its end, which no progress position
        // carries ([`CustodySink::bound`]).
        if let Some(binding) = &self.head.active {
            sink.bound(binding.acquisition.id());
        }
        for held in [&self.grant, &self.release].into_iter().flatten() {
            if held.remaining() != WriteWork::default() {
                sink.held(held.observation());
            }
        }
        sink.end();
        PermitsObserved::Complete
    }

    /// What the pending acquisition holds ([`Self::observe_custody`],
    /// summed): its grant's write and its release together. `None` when the
    /// sum does not fit.
    pub(crate) fn held_credit(&self) -> Option<WriteWork> {
        total_held(|sink: &mut dyn CustodySink<()>| self.observe_custody(sink))
    }

    /// The release of the acquisition `ticket` spent at the grant of
    /// `permit`, which carries it, `by` the step's performer: its drop
    /// performs the release unconditionally. Nothing for no release.
    pub(crate) fn spend_release<R>(
        &mut self,
        ticket: Ticket,
        permit: Identity,
        by: Performer,
    ) -> Result<(), BoundedError<R>> {
        self.check(ticket)?;
        if let Some(release) = self.release.take() {
            release.spend(Some(permit), by);
        }
        Ok(())
    }

    /// The grant's work of the acquisition `ticket` spent once the
    /// reservation `permit` pays for exists, or forfeited under `rule` at
    /// `permit` when it failed or its scope closed under the grant, `by` the
    /// step's performer. Nothing for no grant.
    pub(crate) fn settle_grant<R>(
        &mut self,
        ticket: Ticket,
        permit: Identity,
        rule: Option<Forfeit>,
        by: Performer,
    ) -> Result<(), BoundedError<R>> {
        self.check(ticket)?;
        if let Some(grant) = self.grant.take() {
            match rule {
                None => grant.spend(Some(permit), by),
                Some(rule) => grant.forfeit(rule, Some(permit), by),
            }
        }
        Ok(())
    }

    /// The acquisition `ticket` ended, granted or failed, its credit all
    /// settled: its capability ended `by` the step's performer, and the
    /// pending idle again. Refused, nothing changed and nothing ended,
    /// while it still holds credit.
    pub(crate) fn complete<R>(
        &mut self,
        ticket: Ticket,
        by: Performer,
    ) -> Result<(), BoundedError<R>> {
        self.check(ticket)?;
        if self.grant.is_some() || self.release.is_some() {
            return Err(BoundedError::PlanMismatch);
        }
        self.idle(by);
        Ok(())
    }

    /// No acquisition bound: the bound acquisition's capability, if any,
    /// taken from the head and ended `by` the performer, once; the owner and
    /// the tickets issued kept. Called only once every obligation of the
    /// acquisition is settled, so the end follows its settlements.
    fn idle(&mut self, by: Performer) {
        if let Some(binding) = self.head.active.take() {
            binding.acquisition.end(by);
        }
    }

    /// Cleanup entry of the operation that keeps this pending: whatever
    /// acquisition is bound is abandoned, everything it holds forfeited,
    /// [`Forfeit::Cancelled`], into its own origins, `by` the performer (a
    /// stepped cleanup's policy; [`Performer::None`] for a drop or a
    /// terminal drain), and the pending idle. Each obligation is taken and
    /// forfeited explicitly here, ordered with the clear and observable at
    /// cleanup entry; [`Retained`]'s own drop forfeit is the backstop of an
    /// unwind only, never this path. Allocation-free and non-unwinding, so a
    /// terminal drain may call it.
    pub(crate) fn settle_all(&mut self, by: Performer) {
        if let Some(grant) = self.grant.take() {
            grant.forfeit(Forfeit::Cancelled, None, by);
        }
        if let Some(release) = self.release.take() {
            release.forfeit(Forfeit::Cancelled, None, by);
        }
        // Every obligation settled first: the end follows them.
        self.idle(by);
    }
}

/// A pending dropped with an acquisition still bound is that acquisition's
/// destruction: everything it holds forfeited ([`Forfeit::Cancelled`]) into
/// its own origins, then the acquisition ended, with no policy performing
/// it ([`Pending::settle_all`]). After an explicit cleanup or completion it
/// holds nothing and is bound to nothing, so its drop settles and ends
/// nothing a second time. Allocation-free and non-unwinding.
impl<O: Origin> Drop for Pending<O> {
    fn drop(&mut self) {
        self.settle_all(Performer::None);
    }
}

/// The contract quantities of acquiring a block of `M` with permits of `P`
/// whose acquisition writes a header `W`: the bytes written, the permit and
/// the header, one typed value written whole, at most a quantum together, so
/// the write is one admitted unit ([`Self::write`]); and the block's bytes,
/// requested from the allocator and held until the block is freed
/// ([`Self::block`]). Padding the write does not reach, between the value
/// and the permit or past the header, is storage the block holds, not bytes
/// written.
///
/// The one definition of both: [`acquire`] admits exactly the contract it
/// is given, whose type names what it stores, and every cost term of a
/// block reads the same contract, so a block's charge and its bound cannot
/// diverge. `W` and `M` are the types the build stores; the quantities are
/// read from their production representation
/// ([`Representation::In<Core>`](Representation)), so they are the same in
/// every build whatever atomics a model checker substitutes, while
/// [`acquire`] stores and frees `M`'s physical layout. Built only by
/// [`Self::of`], which every caller evaluates in a constant (`const { .. }`
/// or an associated constant), so a write beyond a quantum fails to compile
/// where the block's type is used and [`acquire`] holds no run-time check.
pub(crate) struct Contract<W, M, P> {
    written: usize,
    block: usize,
    stored: PhantomData<Describes<W, M, P>>,
}

/// The types a [`Contract`] describes, named without being held: a contract
/// is two numbers about them, so it owns none of them and is `Copy`, `Send`
/// and `Sync` whatever they are.
type Describes<W, M, P> = fn() -> (W, M, P);

impl<W, M, P> Clone for Contract<W, M, P> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<W, M, P> Copy for Contract<W, M, P> {}

impl<W: Representation, M: Representation, P> Contract<W, M, P> {
    /// The contract of a block storing `M`, whose acquisition writes `W`,
    /// with permits of `P`: read from their production representation.
    pub(crate) const fn of() -> Self {
        Self {
            written: crate::bounded::write_extent(
                size_of::<W::In<Core>>() + crate::bounded::permit_bytes::<P>(),
            ) as usize,
            block: size_of::<Held<M::In<Core>, P>>(),
            stored: PhantomData,
        }
    }
}

impl<W, M, P> Contract<W, M, P> {
    /// What the acquisition admits for its write: one [`WRITE`] of its
    /// bytes. Its release ([`release_cost`]) is admitted with it.
    pub(crate) const fn write(self) -> ResourceBound {
        Unit::new(Caller, WRITE.values(), self.written as u64).bound()
    }

    /// The block's bytes: the allocation requested and held.
    pub(crate) const fn block(self) -> usize {
        self.block
    }

    /// The grant's work the acquisition admits held before requesting the
    /// block ([`Obligation::Grant`]): its write, one value and its bytes.
    #[cfg(test)]
    pub(crate) const fn grant(self) -> WriteWork {
        WRITE.work(self.written as u64)
    }
}

// A stored type that holds no primitive of an atomics family is itself in
// every family: the empty header of a block written in later units, an
// uninitialized value of such a type, and a child custody record.
impl Representation for () {
    type In<S: Atomics> = ();
}

impl<T: Representation> Representation for MaybeUninit<T> {
    type In<S: Atomics> = MaybeUninit<T::In<S>>;
}

impl<S, P> Representation for Child<S, P> {
    type In<F: Atomics> = Self;
}

/// What one release unit admits, with permits of `P`, by the acquisition it
/// pays for ([`admit_release`], [`acquire`]).
pub(crate) const fn release_cost<P>() -> ResourceBound {
    released::<P>().bound()
}

/// A held value followed by the permit for its whole allocation. `value` is
/// first, so a pointer to the block is a pointer to the value's first field.
#[repr(C)]
pub(crate) struct Held<M, P> {
    pub(crate) value: M,
    permit: P,
}

impl<M, P> Held<M, P> {
    pub(crate) fn permit(&self) -> &P {
        &self.permit
    }
}

/// Acquire one stable block of `M` whose acquisition writes the permit and
/// the header `head` makes, a `W` written whole at the place `project` names
/// in the value, for the acquisition `holder` names on `pending` (bound now
/// if it is new). What is admitted is `contract`'s ([`Contract`], evaluated
/// in a constant by the caller, its type naming what is stored): its write,
/// then the block's release, each admitted once, before its allocation is
/// requested, each obligation the admission returns held in `pending` at
/// once with the origin that admitted it, across a refused request. At the
/// grant the release is spent at the permit in the family that admitted it;
/// the grant's write is spent in its own family once the block exists, or
/// forfeited there when the allocation fails ([`Forfeit::AcquisitionFailed`])
/// or the scope closed under the grant ([`Forfeit::Cancelled`]); the
/// physical outcome is reported as the permit's effect. Then the
/// acquisition ends: `pending` idle, the holder's ticket cleared. What is
/// stored is `M`'s physical layout, which beneath a model checker's atomics
/// exceeds the contract's block. `open` is consulted after the permit is
/// granted and before memory is touched, because allocator callbacks may
/// close the owning scope. The header is made only once the block exists.
///
/// # Safety
/// `project` must return the address of a `W` within the value it is given,
/// aligned for `W`, without reading or writing memory. The header must be
/// every part of the value that later code reads before initializing more
/// in admitted units of its own. Neither `head` nor `project` may unwind,
/// allocate, or read uninitialized memory.
pub(crate) unsafe fn acquire<M, W, A: Allocator>(
    contract: Contract<W, M, A::Permit>,
    pending: &mut Pending<A::Origin>,
    holder: &mut Option<Ticket>,
    open: impl Fn() -> bool,
    head: impl FnOnce() -> W,
    project: impl FnOnce(*mut M) -> *mut W,
    a: &mut A,
) -> BoundedResult<NonNull<Held<M, A::Permit>>, A> {
    const {
        assert!(
            size_of::<Held<M, A::Permit>>() > 0,
            "a stable block occupies memory"
        )
    };
    let layout = Layout::new::<Held<M, A::Permit>>();
    let bytes = u64::try_from(contract.block).map_err(|_| BoundedError::Overflow)?;
    if !open() {
        return Err(BoundedError::PlanMismatch);
    }
    // Bound now if new, validated if resumed: one acquisition identity from
    // the binding to the end, whichever policies admit, grant or settle for
    // it. The write and the release are admitted held, each obligation kept
    // in `pending` from its admission across a refused request, which the
    // retry's grant spends.
    let ticket = bound(pending, holder, a)?;
    if pending.admitted(ticket)? == Admitted::Nothing {
        let written = contract.written as u64;
        admit_obligation(
            pending,
            holder,
            &[Admitted::Nothing],
            |a, owner, acquisition| {
                WRITE.admit_held(a, written, Obligation::Grant, owner, acquisition)
            },
            a,
        )?;
    }
    if pending.admitted(ticket)? == Admitted::Write {
        admit_release(pending, holder, a)?;
    }
    let (permit, raw) = grant(
        pending,
        holder,
        bytes,
        || {
            if !open() {
                // The scope closed under the grant: the write is never made.
                return Err(Forfeit::Cancelled);
            }
            // SAFETY: the layout is nonzero (asserted above); a null result
            // is a physical failure.
            NonNull::new(unsafe { alloc(layout) }.cast::<Held<M, A::Permit>>())
                .ok_or(Forfeit::AcquisitionFailed)
        },
        a,
    )?;
    // SAFETY: the block is unique and aligned. The permit is written before
    // the header, so the block is always releasable once the header is; the
    // caller guarantees `project` names an aligned `W` within the value.
    unsafe {
        ptr::addr_of_mut!((*raw.as_ptr()).permit).write(permit);
        project(ptr::addr_of_mut!((*raw.as_ptr()).value)).write(head());
    }
    Ok(raw)
}

/// Free a block and release its permit, a release its acquisition paid for:
/// the storage freed first, then the permit dropped.
///
/// # Safety
/// The block came from `acquire` with the same `M` and `P`, is not referenced
/// anywhere else, and its value owns no resources.
pub(crate) unsafe fn free<M, P>(held: NonNull<Held<M, P>>) {
    // SAFETY: read the permit out, free the storage, then release accounting.
    unsafe {
        let permit = ptr::addr_of!((*held.as_ptr()).permit).read();
        dealloc(held.as_ptr().cast(), Layout::new::<Held<M, P>>());
        drop(permit);
    }
}

/// The one authority over a stable block of metadata `M` and its permit `P`.
///
/// Only [`install`] creates one, from the block it has just acquired, and
/// only [`uninstall`] consumes one, releasing that block. The handle is not
/// `Copy` or `Clone` and has no public constructor, so no code outside this
/// module can mint one or duplicate it: holding the handle is holding the
/// block. The block's address is held as a pointer throughout, never as an
/// integer, so its provenance survives every suspension. The only other
/// pointers into the block derive from its value's place ([`Self::place`]),
/// whose every access borrows this handle, and from the views its owner
/// publishes from that place for shared reads, whose use the custody protocol
/// ends before the block is accessed mutably again or uninstalled.
pub struct Installed<M, P> {
    block: NonNull<Held<M, P>>,
    /// Owns a `Held<M, P>`, for variance and auto-trait purposes.
    marker: PhantomData<Held<M, P>>,
}

// SAFETY: an `Installed` is the unique owner of its block, as a `Box` is of
// its allocation: no other authority over the block exists, and views are
// held only beside the handle in the same record, so moving the handle
// moves the only mutable access. Sending it sends an `M` and a `P`, so it is
// `Send` exactly when both are.
unsafe impl<M: Send, P: Send> Send for Installed<M, P> {}
// SAFETY: shared access through `&Installed` yields only `&M` (`peek`) and
// `&P` (`permit`, read to name it), never a mutable borrow of either. As for
// a `Box`, sharing the handle shares an `M` and a `P`, so it is `Sync`
// exactly when both are.
unsafe impl<M: Sync, P: Sync> Sync for Installed<M, P> {}

impl<M, P> Installed<M, P> {
    /// The installed metadata, borrowed for as long as the handle is.
    pub(crate) fn get(&mut self) -> &mut M {
        let value = self.place().as_ptr(self);
        // SAFETY: the handle owns its live, initialized block exclusively;
        // the borrow of `self` bounds the returned reference.
        unsafe { &mut *value }
    }

    /// The installed value's place, the root of its provenance for the
    /// block's life ([`Place::root`]), reborrowing none of it: for a holder
    /// that reaches one part of the value exclusively while a reader may
    /// hold another part borrowed, as a stable option's state counts its
    /// payload's cleanup beside the payload a reader borrows. Every use ends
    /// before the block is uninstalled. Its custody, the token every access
    /// through it borrows ([`Place`]), is this handle.
    pub(crate) fn place(&mut self) -> Place<M> {
        // SAFETY: the block is live and owned by this handle; the projection
        // forms no reference, and every access to the value is through this
        // place or `get`, whose borrow `&mut self` bounds.
        unsafe {
            Place::root(NonNull::new_unchecked(
                ptr::addr_of_mut!((*self.block.as_ptr()).value).cast::<MaybeUninit<M>>(),
            ))
        }
    }

    /// The block's own permit, read through a shared borrow of the handle:
    /// how an observation names it
    /// ([`Releasing::permit_identity`](crate::bounded::Releasing::permit_identity)); never
    /// moved or released here. Defined for every `M`, so a vacated block
    /// (`Installed<MaybeUninit<M>, P>`) names its permit as a live one does.
    pub(crate) fn permit(&self) -> &P {
        // SAFETY: the handle owns its live block; the permit is written
        // before the handle exists ([`acquire`]) and stays initialized for
        // the block's whole life, vacated or not, and is only read here.
        unsafe { &(*self.block.as_ptr()).permit }
    }

    /// The installed metadata, read through a shared borrow of the handle:
    /// how an observation reads progress kept in the block.
    pub(crate) fn peek(&self) -> &M {
        // SAFETY: the handle owns its live, initialized block; `get` needs
        // `&mut self`, so no mutable borrow coexists with this one.
        unsafe { &(*self.block.as_ptr()).value }
    }

    /// Move the value out, leaving the block holding nothing: the handle
    /// returned is typed as vacated, so the moved-out bytes can never be
    /// read or dropped again, and the block can only be freed.
    pub(crate) fn vacate(self) -> (M, Installed<MaybeUninit<M>, P>) {
        const {
            assert!(
                size_of::<Held<M, P>>() == size_of::<Held<MaybeUninit<M>, P>>()
                    && core::mem::align_of::<Held<M, P>>()
                        == core::mem::align_of::<Held<MaybeUninit<M>, P>>(),
                "a vacated block has its value's layout"
            )
        };
        // SAFETY: the handle owns its live, initialized block exclusively and
        // is consumed here, so the value is read out exactly once; the
        // vacated handle reaches the same block, whose value it types as
        // uninitialized and whose permit is untouched. `Held` is `repr(C)`
        // and `MaybeUninit<M>` has `M`'s layout, so the permit keeps its
        // offset.
        unsafe {
            let value = ptr::addr_of!((*self.block.as_ptr()).value).read();
            (
                value,
                Installed {
                    block: self.block.cast(),
                    marker: PhantomData,
                },
            )
        }
    }

    /// Drop the value in place, then free the block and release its permit,
    /// a release its acquisition paid for: the terminal release of an
    /// owner dropped without stepped cleanup.
    ///
    /// # Safety
    /// The value's destructor frees only allocations admitted with their
    /// releases, and neither unwinds nor allocates.
    pub(crate) unsafe fn dispose(self) {
        // SAFETY: the handle owns its live, initialized block exclusively and
        // is consumed here; forwarded from the caller.
        unsafe {
            ptr::drop_in_place(ptr::addr_of_mut!((*self.block.as_ptr()).value));
            free(self.block);
        }
    }
}

impl<M, P> Installed<MaybeUninit<M>, P> {
    /// Free a vacated block and release its permit, a release its
    /// acquisition paid for. Its bytes hold no value, so nothing is dropped.
    pub(crate) fn free(self) {
        // SAFETY: the handle is the block's only authority and is consumed;
        // a vacated block's value owns nothing.
        unsafe { free(self.block) };
    }
}

/// Acquire a block of `M` whose acquisition writes the header `head` makes
/// at the place `project` names, admitting `contract`, for the acquisition
/// `holder` names on `pending` ([`acquire`]); the handle that owns it.
///
/// # Safety
/// As [`acquire`].
pub(crate) unsafe fn installed<M, W, A: Allocator>(
    contract: Contract<W, M, A::Permit>,
    pending: &mut Pending<A::Origin>,
    holder: &mut Option<Ticket>,
    head: impl FnOnce() -> W,
    project: impl FnOnce(*mut M) -> *mut W,
    a: &mut A,
) -> BoundedResult<Installed<M, A::Permit>, A> {
    // SAFETY: forwarded from the caller.
    let block =
        unsafe { acquire::<M, W, A>(contract, pending, holder, || true, head, project, a)? };
    Ok(Installed {
        block,
        marker: PhantomData,
    })
}

/// Acquire a block of `M` into the empty `slot`, admitting `contract`, its
/// acquisition writing the header `head` makes at the place `project`
/// names, for the acquisition `holder` names on `pending` ([`acquire`]).
///
/// # Safety
/// As [`acquire`]. A `slot` already holding a block is a plan mismatch and
/// acquires nothing.
pub(crate) unsafe fn install<M, W, A: Allocator>(
    contract: Contract<W, M, A::Permit>,
    slot: &mut Option<Installed<M, A::Permit>>,
    pending: &mut Pending<A::Origin>,
    holder: &mut Option<Ticket>,
    head: impl FnOnce() -> W,
    project: impl FnOnce(*mut M) -> *mut W,
    a: &mut A,
) -> BoundedResult<(), A> {
    if slot.is_some() {
        return Err(BoundedError::PlanMismatch);
    }
    // SAFETY: forwarded from the caller.
    *slot = Some(unsafe { installed::<M, W, A>(contract, pending, holder, head, project, a)? });
    Ok(())
}

/// Free the block `slot` holds, if any, and empty it: a release its
/// acquisition paid for, so nothing is admitted and nothing can refuse.
///
/// # Safety
/// The block's metadata owns no resources.
pub(crate) unsafe fn uninstall<M, P>(slot: &mut Option<Installed<M, P>>) {
    if let Some(installed) = slot.take() {
        // SAFETY: the handle was the block's only authority and is consumed
        // here; forwarded from the caller, its metadata owns nothing.
        unsafe { free(installed.block) };
    }
}

/// One child custody record: the child's own construction state, typed by
/// the engine that pushed it, and the record before it.
pub(crate) struct Child<S, P> {
    pub(crate) state: S,
    previous: Option<NonNull<Held<Child<S, P>, P>>>,
}

/// Last-in-first-out custody records for the children of one construction.
/// A record is pushed before its child acquires anything, so cleanup always
/// finds every partial child, newest first.
pub(crate) struct Stack<S, P> {
    head: Option<NonNull<Held<Child<S, P>, P>>>,
    /// The acquisition of the next record while it is pending: its credit
    /// is the operation's ([`Pending`]).
    ticket: Option<Ticket>,
    /// The records in the chain: a count the stack keeps beside its head,
    /// so observing it walks nothing.
    len: usize,
}

// SAFETY: the stack exclusively owns every record in its chain, as a
// `Box`-linked list does; sending it sends each record's `S` and `P`.
unsafe impl<S: Send, P: Send> Send for Stack<S, P> {}
// SAFETY: the only `&self` methods read the stack's own `len` and
// `ticket`, plain values; no record, state or permit is reached through
// shared access.
unsafe impl<S, P> Sync for Stack<S, P> {}

impl<S, P> Stack<S, P> {
    /// What pushing one record admits and holds ([`Contract`]): the record
    /// written whole with its permit, and its block. Every cost term of a
    /// child record reads it.
    pub(crate) const RECORD: Contract<Child<S, P>, Child<S, P>, P> = Contract::of();

    pub(crate) const fn new() -> Self {
        Self {
            head: None,
            ticket: None,
            len: 0,
        }
    }

    /// The records held, newest included.
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// Each record, newest first, its block's permit and its child's state,
    /// under the stack's exclusive custody: how a holder reports its
    /// records' permits and, through each state, its children's. Visits
    /// exactly [`Self::len`] records, changing none.
    pub(crate) fn for_each_record(&mut self, mut visit: impl FnMut(&P, &mut S)) {
        let mut next = self.head;
        for _ in 0..self.len {
            let Some(held) = next else {
                return;
            };
            // SAFETY: every block in the chain is owned by this stack until
            // popped, and the exclusive borrow excludes popping meanwhile;
            // the permit and the state are disjoint fields of the block.
            unsafe {
                let block = held.as_ptr();
                visit(&(*block).permit, &mut (*block).value.state);
                next = (*block).value.previous;
            }
        }
    }

    /// Cleanup began: the next record's acquisition, if pending, is
    /// abandoned. Its credit was settled at the operation's cleanup entry
    /// ([`Pending::settle_all`]); the stack forgets its ticket.
    pub(crate) fn abandon(&mut self) {
        self.ticket = None;
    }

    /// Push a record holding `state`, the child's initial state, its
    /// acquisition's credit held in `pending` across a refused or failed
    /// allocation.
    pub(crate) fn push<A: Allocator<Permit = P>>(
        &mut self,
        state: S,
        pending: &mut Pending<A::Origin>,
        a: &mut A,
    ) -> BoundedResult<(), A> {
        let previous = self.head;
        // SAFETY: the header is the whole record, every field written.
        let held = unsafe {
            acquire::<Child<S, P>, Child<S, P>, A>(
                Self::RECORD,
                pending,
                &mut self.ticket,
                || true,
                || Child { state, previous },
                |child| child,
                a,
            )?
        };
        self.head = Some(held);
        self.len += 1;
        Ok(())
    }

    /// Each record's state, newest first, under the stack's exclusive
    /// custody: how a holder sums what its children's cleanup still owes.
    /// Visits exactly [`Self::len`] records, changing none.
    pub(crate) fn for_each(&mut self, mut visit: impl FnMut(&mut S)) {
        let mut next = self.head;
        for _ in 0..self.len {
            let Some(held) = next else {
                return;
            };
            // SAFETY: every block in the chain is owned by this stack until
            // popped, and the exclusive borrow excludes popping meanwhile.
            unsafe {
                visit(&mut (*held.as_ptr()).value.state);
                next = (*held.as_ptr()).value.previous;
            }
        }
    }

    pub(crate) fn top(&mut self) -> Option<&mut Child<S, P>> {
        // SAFETY: the head block is owned by this stack until popped.
        self.head.map(|held| unsafe { &mut (*held.as_ptr()).value })
    }

    /// Release the newest record, whose child has been reclaimed, if any: a
    /// release its push paid for. True when a record was released.
    pub(crate) fn pop(&mut self) -> bool {
        let Some(held) = self.head else {
            return false;
        };
        // SAFETY: the head is owned by this stack and its child owns nothing.
        unsafe {
            self.head = (*held.as_ptr()).value.previous;
            free(held);
        }
        self.len -= 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounded::Unreadable;
    use crate::bounded::decode::construction::findings::{Expected, ExpectedHistory, Findings};

    /// A policy whose history its session holds and reports.
    const READ: ExpectedHistory = ExpectedHistory::Readable;

    /// A policy of a session a refused validation invalidated: its history
    /// is unreadable, the session being no evidence.
    const INVALIDATED_HISTORY: ExpectedHistory =
        ExpectedHistory::Unreadable(Unreadable::Session(Incomplete::Exhausted));
    use crate::bounded::{
        Capacity, Credit, Effect, Event, Incomplete, LimitRefusal, Limits, Observed, Releasing,
        Reservation, Session,
    };

    /// The observations of `observed` that bind or end `acquisition`, in
    /// stream order: `(index, family, performer, event)`.
    fn lifecycle(
        observed: &[Observed],
        acquisition: Identity,
    ) -> std::vec::Vec<(usize, u64, Performer, Event)> {
        observed
            .iter()
            .enumerate()
            .filter(|(_, observation)| match observation.event {
                Event::Bound {
                    acquisition: id, ..
                }
                | Event::End {
                    acquisition: id, ..
                } => id == acquisition,
                _ => false,
            })
            .map(|(index, observation)| {
                (index, observation.family, observation.by, observation.event)
            })
            .collect()
    }

    /// The acquisitions `pending`'s custody reports bound, by its one
    /// traversal ([`crate::bounded::bound_of`]).
    fn reported(pending: &Pending<<Limits as Budget>::Origin>) -> std::vec::Vec<Identity> {
        let mut bound = std::vec::Vec::new();
        let observed = crate::bounded::bound_of(
            |sink: &mut dyn CustodySink<()>| pending.observe_custody(sink),
            &mut |acquisition| bound.push(acquisition),
        );
        assert_eq!(observed, PermitsObserved::Complete);
        bound
    }

    /// A credit-free acquisition is bound custody until it ends, and ends
    /// once: reported before its end, not after; one `Bound` and one `End`
    /// of it, the end published by the family that minted it, and the
    /// stream refined.
    #[test]
    fn credit_free_acquisition_ends_once() {
        let mut findings = Findings::new();
        let s = session();
        let mut a = Limits::recorded_unlimited(&s);
        let mut pending = Pending::new(a.owner().expect("an owner"));
        let mut holder = None;
        let ticket = bound(&mut pending, &mut holder, &mut a).expect("bound");
        let acquisition = pending.acquisition::<()>(ticket).expect("its identity");
        findings.equal(
            "bound before its end",
            reported(&pending),
            vec![acquisition],
        );
        pending.settle_all(a.performer());
        findings.equal("unbound after its end", reported(&pending), vec![]);
        drop(pending);
        let family = Origin::family(&Budget::origin(&a));
        let by = a.performer();
        findings.policies([("a", a, READ)]);
        let finished = s.finish();
        if let Ok(observed) = &finished {
            let events = lifecycle(observed, acquisition);
            findings.equal("one bind, then one end", events.len(), 2);
            if let [
                (_, _, _, Event::Bound { .. }),
                (_, end_family, end_by, Event::End { .. }),
            ] = events.as_slice()
            {
                findings.equal(
                    "the end's publisher, the minting family",
                    *end_family,
                    family,
                );
                findings.equal("the end's performer", *end_by, by);
            } else {
                findings.check(false, || format!("not a bind then an end: {events:?}"));
            }
        }
        findings.conclude(&[("the session", &finished, Expected::Complete)]);
    }

    /// An acquisition retained across refusals keeps its capability: its
    /// release refused four times under `a`, admitted on the next retry,
    /// then cancelled: one identity
    /// throughout, one bind, one admission of its release, one end.
    #[test]
    fn refused_acquisition_reuses_capability() {
        let mut findings = Findings::new();
        let s = session();
        let mut a = Limits::recorded_unlimited(&s);
        let mut pending = Pending::new(a.owner().expect("an owner"));
        let mut holder = None;
        a.refuse_next();
        findings.check(
            admit_release(&mut pending, &mut holder, &mut a).is_err(),
            || "the first release admission was not refused",
        );
        let ticket = holder.expect("the binding is kept across the refusal");
        let acquisition = pending.acquisition::<()>(ticket).expect("its identity");
        let before = snapshot(&pending);
        for _ in 0..3 {
            a.clear_refusal();
            let at = a.attempts();
            a.refuse_next();
            findings.equal(
                "every repeated release admission refuses",
                admit_release(&mut pending, &mut holder, &mut a),
                Err(BoundedError::Refused(LimitRefusal::Scheduled(at))),
            );
            findings.equal(
                "refusal preserves the whole pending",
                snapshot(&pending),
                before,
            );
            findings.equal("refusal preserves the holder", holder, Some(ticket));
            findings.equal(
                "credit-free binding remains observable",
                reported(&pending),
                vec![acquisition],
            );
        }
        a.clear_refusal();
        findings.equal(
            "the release is admitted on the next retry",
            admit_release(&mut pending, &mut holder, &mut a),
            Ok(()),
        );
        findings.equal(
            "the same acquisition across every retry",
            pending.acquisition::<()>(ticket),
            Ok(acquisition),
        );
        pending.settle_all(a.performer());
        drop(pending);
        findings.policies([("a", a, READ)]);
        let finished = s.finish();
        if let Ok(observed) = &finished {
            findings.equal(
                "one bind and one end of the acquisition",
                lifecycle(observed, acquisition).len(),
                2,
            );
            let holds = observed
                .iter()
                .filter(|observation| {
                    matches!(
                        observation.event,
                        Event::Credit(Credit::Admit { held: Some(hold), .. })
                            if hold.acquisition == acquisition
                    )
                })
                .count();
            findings.equal("one admission of its release, never replayed", holds, 1);
        }
        findings.conclude(&[("the session", &finished, Expected::Complete)]);
    }

    /// An acquisition bound under A, continued under B in the same session
    /// and cancelled under B: its end is published by A, the minting
    /// family, performed by B; its release, admitted by B, settles into B.
    #[test]
    fn cross_family_retry_ends_in_minting_family() {
        let mut findings = Findings::new();
        let s = session();
        let mut a = Limits::recorded_unlimited(&s).refusing_each();
        let mut b = Limits::recorded_unlimited(&s);
        let mut pending = Pending::new(a.owner().expect("an owner"));
        let mut holder = None;
        findings.check(
            admit_release(&mut pending, &mut holder, &mut a).is_err(),
            || "the release under A was not refused",
        );
        let ticket = holder.expect("bound under A");
        let acquisition = pending.acquisition::<()>(ticket).expect("its identity");
        findings.check(
            admit_release(&mut pending, &mut holder, &mut b).is_ok(),
            || "the release under B was refused",
        );
        let (family_a, family_b) = (
            Origin::family(&Budget::origin(&a)),
            Origin::family(&Budget::origin(&b)),
        );
        let by_b = b.performer();
        let held = pending
            .release
            .as_ref()
            .expect("B's held release")
            .observation();
        pending.settle_all(by_b);
        drop(pending);
        findings.policies([("a", a, READ), ("b", b, READ)]);
        let finished = s.finish();
        if let Ok(observed) = &finished {
            findings.equal("the acquisition is A's", acquisition.family(), family_a);
            match lifecycle(observed, acquisition).as_slice() {
                [
                    (_, bound_family, _, Event::Bound { .. }),
                    (_, end_family, end_by, Event::End { .. }),
                ] => {
                    findings.equal("bound by A", *bound_family, family_a);
                    findings.equal("ended through A", *end_family, family_a);
                    findings.equal("ended by B", *end_by, by_b);
                }
                other => findings.check(false, || format!("not a bind then an end: {other:?}")),
            }
            let settlements: Vec<_> = observed
                .iter()
                .filter(|o| {
                    matches!(
                        o.event,
                        Event::Credit(Credit::Forfeit(settled, _))
                            if settled.acquisition == acquisition
                    )
                })
                .collect();
            findings.equal("exactly one release settlement", settlements.len(), 1);
            for observation in settlements {
                findings.equal("the release settles into B", observation.family, family_b);
                findings.equal("the settlement performer is B", observation.by, by_b);
                if let Event::Credit(Credit::Forfeit(settled, rule)) = observation.event {
                    findings.equal("the exact admitted release settles", settled.id, held.id);
                    findings.equal("cancellation has no permit", settled.permit, None);
                    findings.equal(
                        "the release was admitted by B",
                        settled.id.family(),
                        family_b,
                    );
                    findings.equal("the settlement is cancellation", rule, Forfeit::Cancelled);
                    findings.equal(
                        "the settlement is the whole release",
                        settled.work,
                        release_credit::<Reservation>(),
                    );
                    findings.equal(
                        "the settled obligation",
                        settled.obligation,
                        Obligation::Release,
                    );
                }
            }
        }
        findings.conclude(&[("the session", &finished, Expected::Complete)]);
    }

    /// Cancellation, then the holder's drop: the drop settles and ends
    /// nothing a second time.
    #[test]
    fn cancel_then_drop_does_not_end_twice() {
        let mut findings = Findings::new();
        let s = session();
        let mut a = Limits::recorded_unlimited(&s);
        let (mut pending, ticket) = suspended(&mut a);
        let acquisition = pending.acquisition::<()>(ticket).expect("its identity");
        pending.settle_all(a.performer());
        drop(pending);
        findings.policies([("a", a, READ)]);
        let finished = s.finish();
        if let Ok(observed) = &finished {
            let ends = lifecycle(observed, acquisition)
                .into_iter()
                .filter(|(_, _, _, event)| matches!(event, Event::End { .. }))
                .count();
            findings.equal("one end", ends, 1);
        }
        findings.conclude(&[("the session", &finished, Expected::Complete)]);
    }

    /// A completed acquisition, then a fresh one on the same holder: two
    /// distinct identities, each bound once and ended once.
    #[test]
    fn complete_then_reuse_mints_fresh_identity() {
        let mut findings = Findings::new();
        let s = session();
        let mut a = Limits::recorded_unlimited(&s);
        let mut pending = Pending::new(a.owner().expect("an owner"));
        let mut holder = None;
        let first = bound(&mut pending, &mut holder, &mut a).expect("bound");
        let first_id = pending.acquisition::<()>(first).expect("its identity");
        admit_grant(&mut pending, &mut holder, GRANT, &mut a).expect("the grant's write");
        admit_release(&mut pending, &mut holder, &mut a).expect("the grant's release");
        let grant_hold = pending.grant.as_ref().expect("grant held").observation();
        let release_hold = pending
            .release
            .as_ref()
            .expect("release held")
            .observation();
        let by = a.performer();
        let (permit, ()) = grant(&mut pending, &mut holder, BLOCK, || Ok(()), &mut a)
            .expect("the physical reservation completes");
        let permit_id = <Limits as Releasing>::permit_identity(&permit);
        findings.equal("completion clears the holder", holder, None);
        findings.check(
            pending.is_idle(),
            || "completion retained acquisition custody",
        );
        findings.equal("completion reports no binding", reported(&pending), vec![]);
        drop(permit);
        let second = bound(&mut pending, &mut holder, &mut a).expect("bound again");
        let second_id = pending.acquisition::<()>(second).expect("its identity");
        findings.check(
            first_id != second_id,
            || "the reused holder kept the old identity",
        );
        pending.settle_all(a.performer());
        drop(pending);
        findings.policies([("a", a, READ)]);
        let finished = s.finish();
        if let Ok(observed) = &finished {
            let spends: Vec<_> = observed
                .iter()
                .filter_map(|o| match o.event {
                    Event::Credit(Credit::Spend(settled)) if settled.acquisition == first_id => {
                        Some((o.family, o.by, settled))
                    }
                    _ => None,
                })
                .collect();
            findings.equal(
                "completion spends the release then the exact grant",
                spends,
                [release_hold, grant_hold]
                    .into_iter()
                    .map(|held| {
                        (
                            held.id.family(),
                            by,
                            crate::bounded::Settled {
                                obligation: held.obligation,
                                work: held.work,
                                id: held.id,
                                acquisition: first_id,
                                permit: Some(permit_id),
                            },
                        )
                    })
                    .collect(),
            );
            for (name, id) in [("first", first_id), ("second", second_id)] {
                findings.equal(name, lifecycle(observed, id).len(), 2);
            }
        }
        findings.conclude(&[("the session", &finished, Expected::Complete)]);
    }

    /// A holder dropped with its release held: the release forfeited, then
    /// the acquisition ended, both performed by no policy, and the stream
    /// refined with nothing outstanding and nothing active.
    #[test]
    fn drop_settles_before_ending() {
        let mut findings = Findings::new();
        let s = session();
        let mut a = Limits::recorded_unlimited(&s);
        let (pending, ticket) = suspended(&mut a);
        let acquisition = pending.acquisition::<()>(ticket).expect("its identity");
        let held = pending
            .release
            .as_ref()
            .expect("the held release")
            .observation();
        findings.equal(
            "no consumption before destruction",
            a.credits().consumed,
            NONE,
        );
        findings.equal("no forfeit before destruction", a.credits().forfeited, NONE);
        findings.equal(
            "destruction starts with the release held",
            pending.held_credit(),
            Some(held.work),
        );
        drop(pending);
        findings.policies([("a", a, READ)]);
        let finished = s.finish();
        if let Ok(observed) = &finished {
            let settlements: Vec<_> = observed
                .iter()
                .filter_map(|o| match o.event {
                    Event::Credit(Credit::Forfeit(settled, rule))
                        if settled.acquisition == acquisition =>
                    {
                        Some((o.family, o.by, settled, rule))
                    }
                    _ => None,
                })
                .collect();
            findings.equal(
                "destruction forfeits exactly the held release once",
                settlements,
                vec![(
                    held.id.family(),
                    Performer::None,
                    crate::bounded::Settled {
                        obligation: held.obligation,
                        work: held.work,
                        id: held.id,
                        acquisition,
                        permit: None,
                    },
                    Forfeit::Cancelled,
                )],
            );
            findings.equal(
                "destruction binds and ends exactly once",
                lifecycle(observed, acquisition).len(),
                2,
            );
            let forfeit = observed.iter().position(|observation| {
                matches!(
                    observation.event,
                    Event::Credit(Credit::Forfeit(settled, Forfeit::Cancelled))
                        if settled.acquisition == acquisition
                )
            });
            let end = lifecycle(observed, acquisition)
                .into_iter()
                .find(|(_, _, _, event)| matches!(event, Event::End { .. }));
            match (forfeit, end) {
                (Some(forfeit), Some((end, _, by, _))) => {
                    findings.check(forfeit < end, || "the end preceded the settlement");
                    findings.equal("the drop's performer", by, Performer::None);
                }
                other => findings.check(false, || format!("no settlement or no end: {other:?}")),
            }
        }
        findings.conclude(&[("the session", &finished, Expected::Complete)]);
    }

    /// The end cannot be recorded when the session has no event slot left
    /// for it: the session is no evidence, never a stream missing an end.
    /// The capacity is measured: the same run with room for every event,
    /// then with one slot fewer, which the end needs.
    #[test]
    fn end_exhaustion_invalidates_recording() {
        let run = |events: usize| {
            let s = Session::new(Capacity {
                permits: 16,
                events,
            });
            let mut a = Limits::recorded_unlimited(&s);
            let mut pending = Pending::new(a.owner().expect("an owner"));
            let mut holder = None;
            let _ = bound(&mut pending, &mut holder, &mut a);
            pending.settle_all(a.performer());
            drop((pending, a));
            s.finish()
        };
        let whole = run(256).expect("room for every event");
        assert!(matches!(
            whole.last().map(|o| o.event),
            Some(Event::End { .. })
        ));
        assert_eq!(run(whole.len() - 1), Err(Incomplete::Exhausted));
    }

    /// An acquisition of a family that records nothing: no identity, and
    /// its end publishes nothing and changes nothing.
    #[test]
    fn unrecorded_acquisition_has_no_recording_effect() {
        let mut a = Limits::unlimited();
        let mut pending = Pending::new(a.owner().expect("an ordinary owner"));
        let mut holder = None;
        let ticket = bound(&mut pending, &mut holder, &mut a).expect("bound");
        assert_eq!(pending.acquisition::<()>(ticket), Ok(Identity::UNOBSERVED));
        assert_eq!(reported(&pending), vec![Identity::UNOBSERVED]);
        pending.settle_all(a.performer());
        assert_eq!(reported(&pending), vec![]);
        assert!(pending.is_idle());
    }

    /// A recording session with room for every test below.
    fn session() -> Session {
        Session::new(Capacity {
            permits: 16,
            events: 256,
        })
    }

    /// A pending owned by a custody `a` minted, holding the release credit
    /// of one acquisition bound under `a` and suspended before its grant:
    /// the pending and the holder's ticket.
    fn suspended(a: &mut Limits) -> (Pending<<Limits as Budget>::Origin>, Ticket) {
        let mut pending = Pending::new(a.owner().expect("the custody's owner is minted"));
        let mut holder = None;
        admit_release(&mut pending, &mut holder, a).expect("the release is admitted held");
        (pending, holder.expect("the acquisition is bound"))
    }

    /// What a refused entry must leave of a pending: its binding, its
    /// recorded acquisition, what it admitted and the credit it holds.
    fn snapshot(
        pending: &Pending<<Limits as Budget>::Origin>,
    ) -> (Option<Ticket>, Identity, Admitted, Option<WriteWork>) {
        let (ticket, acquisition) = pending.binding();
        (
            ticket,
            acquisition,
            pending.held_phase(),
            pending.held_credit(),
        )
    }

    /// The resume-validation witness. An acquisition bound and suspended
    /// under session S, resumed by its own ticket under a family of session
    /// T, whose numeric family, owner and acquisition sequences collide with
    /// S's: the bind itself refuses ([`LimitRefusal::Unrecorded`]); the
    /// pending and resource accounting remain unchanged (no admission,
    /// allocation or observer effect under T); recording validity becomes
    /// sticky-invalid, the owner's S included, so a resume under S's own
    /// family is refused too. The direct bind is checked, so no later validation
    /// on the admission route can mask a resume that skipped its own. Every
    /// check is kept as a finding ([`Findings`]): the pending is settled,
    /// everything holding either session dropped, both sessions finished,
    /// and only then does the test conclude, naming every finding beside
    /// what each session finished as.
    #[test]
    fn a_resume_under_another_session_is_refused_by_the_bind_itself() {
        let mut findings = Findings::new();
        let (s, t) = (session(), session());
        let mut under_s = Limits::recorded_unlimited(&s);
        // T's numbering collides with S's: its first family, made first as
        // S's is, mints its owner and acquisition the same way and takes the
        // same numbers; the policy the resume is tried under is T's second.
        let mut twin_family = Limits::recorded_unlimited(&t);
        let mut under_t = Limits::recorded_unlimited(&t);
        let (mut pending, ticket) = suspended(&mut under_s);
        let (twin, _) = suspended(&mut twin_family);
        findings.equal(
            "the twin's owner",
            twin.owner::<()>().map(Owner::id),
            pending.owner::<()>().map(Owner::id),
        );
        findings.equal(
            "the twin's acquisition",
            twin.binding().1,
            pending.binding().1,
        );
        // Dropped with its acquisition bound and its release held: its
        // destruction settles the release, then ends the acquisition.
        drop(twin);
        let before = snapshot(&pending);
        let (attempts, live) = (under_t.attempts(), under_t.live_bytes());
        findings.equal(
            "a resume under another session's policy is refused by the bind itself",
            pending.bind(Some(ticket), &mut under_t),
            Err(BoundedError::Refused(LimitRefusal::Unrecorded)),
        );
        findings.equal(
            "Pending and resource accounting remain unchanged",
            snapshot(&pending),
            before,
        );
        findings.equal("nothing admitted under T", under_t.attempts(), attempts);
        findings.equal("nothing allocated under T", under_t.live_bytes(), live);
        findings.equal(
            "no credit admitted under T",
            under_t.credits().admitted,
            WriteWork::default(),
        );
        // The refused validation invalidated S too, the owner's session
        // (`Limits::validate_owner`, `owner.invalidate()`), and a compatible
        // pairing needs a still usable session (`Budget::validate_owner`): a
        // resume under S's own family is refused as well, nothing changed.
        findings.equal(
            "the resume under S, its session invalidated",
            pending.bind(Some(ticket), &mut under_s),
            Err(BoundedError::Refused(LimitRefusal::Unrecorded)),
        );
        findings.equal("the pending after S's resume", snapshot(&pending), before);
        pending.settle_all(Performer::None);
        drop(pending);
        findings.policies([
            ("under S", under_s, INVALIDATED_HISTORY),
            ("under T", under_t, INVALIDATED_HISTORY),
            ("the twin's family", twin_family, INVALIDATED_HISTORY),
        ]);
        // Both sessions the refused validation involved, the owner's and
        // the performing budget's, are sticky-invalid.
        findings.conclude(&[
            (OWNERS_SESSION, &s.finish(), INVALIDATED),
            (PERFORMING_SESSION, &t.finish(), INVALIDATED),
        ]);
    }

    /// The owner's session of a refused cross-session validation, named in
    /// its conclusion.
    const OWNERS_SESSION: &str =
        "S, the owner's session, whose recording validity becomes sticky-invalid";

    /// The performing budget's session of a refused cross-session
    /// validation, named in its conclusion.
    const PERFORMING_SESSION: &str =
        "T, the performing session, whose recording validity becomes sticky-invalid";

    /// What a session a refused validation involved finishes as: no
    /// evidence, sticky-invalid.
    const INVALIDATED: Expected = Expected::Incomplete(Incomplete::Exhausted);

    /// The grant's work of the scenario block: one value and eight bytes.
    const GRANT: Unit<Caller> = Unit::new(Caller, 1, 8);

    /// The bytes the scenario block requests.
    const BLOCK: u64 = 16;

    /// What `pending` holds for `family`, observed through its custody
    /// traversal ([`Pending::observe_custody`]), never from the ledgers: the
    /// remaining work of each held obligation whose identity is `family`'s,
    /// each held for the pending's bound acquisition, every discrepancy kept
    /// in `findings`. Nothing for no pending (dropped, its slots settled);
    /// `None` when the sum does not fit.
    fn held_by(
        findings: &mut Findings,
        pending: Option<&Pending<<Limits as Budget>::Origin>>,
        family: &Limits,
    ) -> Option<WriteWork> {
        let Some(pending) = pending else {
            return Some(WriteWork::default());
        };
        let number = Origin::family(&Budget::origin(family));
        let mut total = Some(WriteWork::default());
        let observed = crate::bounded::held_of(
            |sink: &mut dyn CustodySink<()>| pending.observe_custody(sink),
            &mut |held| {
                findings.equal(
                    "a held obligation names the pending's acquisition",
                    held.acquisition,
                    pending.binding().1,
                );
                if held.id.family() == number {
                    total = total.and_then(|total| total.checked_then(held.work));
                }
            },
        );
        findings.equal(
            "a pending owns no queue",
            observed,
            PermitsObserved::Complete,
        );
        total
    }

    /// `family`'s four quantities, each checked on its own and kept in
    /// `findings`: its ledgers' admitted, consumed and forfeited work; and
    /// what it holds, `held`, observed in the pending's slots by identity
    /// ([`held_by`]), with which the ledgers must conserve, and no
    /// violation. Aggregate conservation alone could hide a misattribution
    /// between families; a held amount derived from the ledgers could hide a
    /// slot settled into the wrong one.
    fn ledgers(
        findings: &mut Findings,
        name: &str,
        family: &Limits,
        pending: Option<&Pending<<Limits as Budget>::Origin>>,
        [admitted, consumed, forfeited, held]: [WriteWork; 4],
    ) {
        let credits = family.credits();
        findings.equal(&format!("{name}: admitted"), credits.admitted, admitted);
        findings.equal(&format!("{name}: consumed"), credits.consumed, consumed);
        findings.equal(&format!("{name}: forfeited"), credits.forfeited, forfeited);
        findings.check(!credits.violated, || {
            format!("{name}: a ledger update was refused")
        });
        let observed = held_by(findings, pending, family);
        findings.equal(
            &format!("{name}: held, observed in the slots"),
            observed,
            Some(held),
        );
        findings.equal(
            &format!("{name}: the ledgers conserve with what the slots hold"),
            observed.and_then(|observed| credits.conserved_with(observed)),
            Some(true),
        );
    }

    /// No work.
    const NONE: WriteWork = WriteWork::new(0, 0);

    /// A pending owned under `a`, its acquisition's grant's work admitted
    /// under `a` and its release under `b`, both held: the A/B half of every
    /// scenario below.
    fn granting(
        a: &mut Limits,
        b: &mut Limits,
    ) -> (Pending<<Limits as Budget>::Origin>, Option<Ticket>) {
        let mut pending = Pending::new(a.owner().expect("the custody's owner is minted"));
        let mut holder = None;
        admit_grant(&mut pending, &mut holder, GRANT, a).expect("the grant's work under A");
        admit_release(&mut pending, &mut holder, b).expect("the release under B");
        (pending, holder)
    }

    /// How many of `observed` satisfy `matches`.
    fn count(observed: &[Observed], matches: impl Fn(&Observed) -> bool) -> usize {
        observed.iter().filter(|observed| matches(observed)).count()
    }

    /// The acquisitions bound in `observed`: each mints its identity once,
    /// at its bind, never on a resume or a retry.
    fn binds(observed: &[Observed]) -> usize {
        count(observed, |observed| {
            matches!(observed.event, Event::Bound { .. })
        })
    }

    /// S1: the grant's work `g` admitted under A, the release refused there,
    /// the acquisition resumed under B, which admits exactly the release
    /// `r`: A is unchanged by the resume and holds `g`; B holds `r`; the
    /// pending holds both, once each. A and B are families of one recorded
    /// session, so the resume is accepted, and the session records one
    /// acquisition bound, not one per family.
    #[test]
    fn s1_a_release_refused_under_a_is_admitted_once_under_b() {
        let mut findings = Findings::new();
        let (g, r) = (GRANT.work(), release_credit::<Reservation>());
        let s = session();
        let mut a = Limits::recorded_unlimited(&s);
        let mut b = Limits::recorded_unlimited(&s);
        let mut pending = Pending::new(a.owner().expect("the owner is minted"));
        let mut holder = None;
        admit_grant(&mut pending, &mut holder, GRANT, &mut a).expect("the grant's work under A");
        a.refuse_next();
        let refused = admit_release(&mut pending, &mut holder, &mut a);
        findings.check(matches!(refused, Err(BoundedError::Refused(_))), || {
            format!("the release under A was not refused: {refused:?}")
        });
        ledgers(
            &mut findings,
            "A after the refusal",
            &a,
            Some(&pending),
            [g, NONE, NONE, g],
        );
        ledgers(
            &mut findings,
            "B before the resume",
            &b,
            Some(&pending),
            [NONE; 4],
        );
        findings.equal(
            "the refusal holds nothing more",
            pending.held_credit(),
            Some(g),
        );
        let resumed = admit_release(&mut pending, &mut holder, &mut b);
        findings.equal("the release under B", resumed, Ok(()));
        ledgers(
            &mut findings,
            "A after the resume",
            &a,
            Some(&pending),
            [g, NONE, NONE, g],
        );
        ledgers(&mut findings, "B", &b, Some(&pending), [r, NONE, NONE, r]);
        findings.equal("both held", pending.held_credit(), g.checked_then(r));
        pending.settle_all(Performer::None);
        ledgers(
            &mut findings,
            "A settled",
            &a,
            Some(&pending),
            [g, NONE, g, NONE],
        );
        ledgers(
            &mut findings,
            "B settled",
            &b,
            Some(&pending),
            [r, NONE, r, NONE],
        );
        drop(pending);
        findings.policies([("A", a, READ), ("B", b, READ)]);
        let s = s.finish();
        if let Ok(observed) = &s {
            findings.equal("one acquisition, bound once", binds(observed), 1);
        }
        findings.conclude(&[("S", &s, Expected::Complete)]);
    }

    /// S2: `n` allocation requests refused under C, then granted: exactly
    /// one grant's work admitted (A's) and one release (B's), never again on
    /// a retry, and `n + 1` requests; both obligations held across every
    /// refusal, then spent at the grant. Recorded: one acquisition bound,
    /// and the granted permit released once, by its drop.
    #[test]
    fn s2_refused_requests_admit_nothing_again() {
        const N: usize = 3;
        let mut findings = Findings::new();
        let (g, r) = (GRANT.work(), release_credit::<Reservation>());
        let s = session();
        let (mut a, mut b) = (
            Limits::recorded_unlimited(&s),
            Limits::recorded_unlimited(&s),
        );
        let mut c = Limits::recorded_unlimited(&s).refusing_requests(N);
        let (mut pending, mut holder) = granting(&mut a, &mut b);
        for refusal in 0..N {
            let result = grant(&mut pending, &mut holder, BLOCK, || Ok(()), &mut c);
            findings.check(matches!(result, Err(BoundedError::Refused(_))), || {
                format!("request {refusal} was not refused")
            });
            drop(result);
            c.clear_refusal();
            findings.equal("both kept held", pending.held_credit(), g.checked_then(r));
            ledgers(
                &mut findings,
                "A across refusals",
                &a,
                Some(&pending),
                [g, NONE, NONE, g],
            );
            ledgers(
                &mut findings,
                "B across refusals",
                &b,
                Some(&pending),
                [r, NONE, NONE, r],
            );
            ledgers(
                &mut findings,
                "C across refusals",
                &c,
                Some(&pending),
                [NONE; 4],
            );
        }
        let mut released = None;
        match grant(&mut pending, &mut holder, BLOCK, || Ok(()), &mut c) {
            Ok((permit, ())) => {
                findings.equal("one request per attempt", c.requests(), N + 1);
                ledgers(&mut findings, "A", &a, Some(&pending), [g, g, NONE, NONE]);
                ledgers(&mut findings, "B", &b, Some(&pending), [r, r, NONE, NONE]);
                ledgers(
                    &mut findings,
                    "C, the permit's grantor only",
                    &c,
                    Some(&pending),
                    [NONE; 4],
                );
                findings.check(
                    pending.is_idle() && holder.is_none(),
                    || "the granted acquisition did not end",
                );
                released = Some(<Limits as Releasing>::permit_identity(&permit));
                drop(permit);
                findings.equal("C's storage after the permit's drop", c.live_bytes(), 0);
            }
            Err(error) => findings.check(false, || format!("the retry was not granted: {error:?}")),
        }
        pending.settle_all(Performer::None);
        drop(pending);
        findings.policies([("A", a, READ), ("B", b, READ), ("C", c, READ)]);
        let s = s.finish();
        if let Ok(observed) = &s {
            findings.equal("the retries bound nothing new", binds(observed), 1);
            if let Some(id) = released {
                findings.equal(
                    "the granted permit released once",
                    count(observed, |o| o.event == Event::Released(id)),
                    1,
                );
            }
        }
        findings.conclude(&[("S", &s, Expected::Complete)]);
    }

    /// S2 through the composite route every block takes ([`acquire`]): a
    /// block's acquisition whose request is refused `n` times admits its
    /// write and its release once, at its first entry, and every retry
    /// resumes them held, admitting nothing again, until the grant spends
    /// both. Each family's ledgers are read after every refusal, before the
    /// call's result, so a retry that admitted again is named by the ledger
    /// it inflated.
    #[test]
    fn s2_a_refused_block_acquisition_admits_its_write_and_release_once() {
        const N: usize = 3;
        let mut findings = Findings::new();
        let contract = Contract::<u64, u64, Reservation>::of();
        let paid = contract
            .grant()
            .checked_then(release_credit::<Reservation>())
            .expect("a block's admissions fit");
        let s = session();
        let mut a = Limits::recorded_unlimited(&s).refusing_requests(N);
        let mut pending = Pending::new(a.owner().expect("the owner is minted"));
        let mut holder = None;
        let entry = |pending: &mut Pending<<Limits as Budget>::Origin>,
                     holder: &mut Option<Ticket>,
                     a: &mut Limits| {
            // SAFETY: the header is the whole `u64` value, written whole at
            // the value's own place; neither closure unwinds or allocates.
            unsafe {
                acquire::<u64, u64, Limits>(contract, pending, holder, || true, || 0, |m| m, a)
            }
        };
        for refusal in 0..N {
            let result = entry(&mut pending, &mut holder, &mut a);
            ledgers(
                &mut findings,
                &format!("A across refused request {refusal}"),
                &a,
                Some(&pending),
                [paid, NONE, NONE, paid],
            );
            match result {
                Err(BoundedError::Refused(_)) => {}
                Ok(raw) => {
                    findings.check(false, || format!("request {refusal} was not refused"));
                    // SAFETY: the block came from `acquire` with these types,
                    // is referenced nowhere else, and its `u64` owns nothing.
                    unsafe { free::<u64, Reservation>(raw) };
                }
                Err(error) => findings.check(false, || {
                    format!("request {refusal} was not refused: {error:?}")
                }),
            }
            a.clear_refusal();
        }
        match entry(&mut pending, &mut holder, &mut a) {
            Ok(raw) => {
                findings.equal("one request per attempt", a.requests(), N + 1);
                ledgers(
                    &mut findings,
                    "A granted",
                    &a,
                    Some(&pending),
                    [paid, paid, NONE, NONE],
                );
                findings.check(
                    pending.is_idle() && holder.is_none(),
                    || "the granted acquisition did not end",
                );
                // SAFETY: the block came from `acquire` with these types, is
                // referenced nowhere else, and its `u64` value owns nothing.
                unsafe { free::<u64, Reservation>(raw) };
            }
            Err(error) => findings.check(false, || format!("the retry was not granted: {error:?}")),
        }
        findings.equal("A's storage after the block's free", a.live_bytes(), 0);
        pending.settle_all(Performer::None);
        drop(pending);
        findings.policies([("A", a, READ)]);
        let s = s.finish();
        if let Ok(observed) = &s {
            findings.equal("the retries bound nothing new", binds(observed), 1);
        }
        findings.conclude(&[("S", &s, Expected::Complete)]);
    }

    /// S3: the permit granted under C, then the physical step succeeds or
    /// fails. Success: A consumes the grant's work, B the release, C holds
    /// the permit until it drops. Failure: A forfeits the grant's work, B
    /// still consumes the release (spent at the grant, prepaying the
    /// permit's drop), and the permit is released at once. The permit's
    /// release is observed apart from the ledgers: in C's live bytes, and as
    /// the session's one `Released` event of that permit, performed by no
    /// policy (the permit's drop). Each path records in a session of its
    /// own.
    #[test]
    fn s3_a_physical_outcome_settles_each_obligation_in_its_own_family() {
        let mut findings = Findings::new();
        let (g, r) = (GRANT.work(), release_credit::<Reservation>());
        let released = |observed: &[Observed], id: Identity| {
            count(observed, |o| {
                o.event == Event::Released(id) && o.by == Performer::None
            })
        };

        let success = session();
        let (mut a, mut b, mut c) = (
            Limits::recorded_unlimited(&success),
            Limits::recorded_unlimited(&success),
            Limits::recorded_unlimited(&success),
        );
        let (mut pending, mut holder) = granting(&mut a, &mut b);
        let mut granted = None;
        match grant(&mut pending, &mut holder, BLOCK, || Ok(()), &mut c) {
            Ok((permit, ())) => {
                ledgers(
                    &mut findings,
                    "A, success",
                    &a,
                    Some(&pending),
                    [g, g, NONE, NONE],
                );
                ledgers(
                    &mut findings,
                    "B, success",
                    &b,
                    Some(&pending),
                    [r, r, NONE, NONE],
                );
                ledgers(&mut findings, "C, success", &c, Some(&pending), [NONE; 4]);
                findings.equal("C holds the permit", c.live_bytes(), BLOCK);
                granted = Some(<Limits as Releasing>::permit_identity(&permit));
                drop(permit);
                findings.equal("the permit's drop releases it", c.live_bytes(), 0);
            }
            Err(error) => findings.check(false, || format!("success: not granted: {error:?}")),
        }
        pending.settle_all(Performer::None);
        drop(pending);
        findings.policies([
            ("A, success", a, READ),
            ("B, success", b, READ),
            ("C, success", c, READ),
        ]);
        let success = success.finish();
        if let (Some(id), Ok(observed)) = (granted, &success) {
            findings.equal(
                "success: the permit's effect reserved",
                count(observed, |o| {
                    matches!(
                        o.event,
                        Event::Effect(Effect::Reserved { permit, .. }) if permit == id
                    )
                }),
                1,
            );
            findings.equal(
                "success: released once, by its drop",
                released(observed, id),
                1,
            );
        }

        let failure = session();
        let (mut a, mut b, mut c) = (
            Limits::recorded_unlimited(&failure),
            Limits::recorded_unlimited(&failure),
            Limits::recorded_unlimited(&failure),
        );
        let (mut pending, mut holder) = granting(&mut a, &mut b);
        findings.equal(
            "failure: the physical failure reported",
            grant(
                &mut pending,
                &mut holder,
                BLOCK,
                || Err::<(), _>(Forfeit::AcquisitionFailed),
                &mut c,
            )
            .map(|_| ()),
            Err(BoundedError::Allocation { bytes: BLOCK }),
        );
        ledgers(
            &mut findings,
            "A, failure",
            &a,
            Some(&pending),
            [g, NONE, g, NONE],
        );
        ledgers(
            &mut findings,
            "B, failure",
            &b,
            Some(&pending),
            [r, r, NONE, NONE],
        );
        ledgers(&mut findings, "C, failure", &c, Some(&pending), [NONE; 4]);
        findings.equal(
            "the failed acquisition's permit was released",
            c.live_bytes(),
            0,
        );
        findings.check(pending.is_idle() && holder.is_none(), || {
            "failure: the acquisition ended with its release spent, nothing more admissible to it"
        });
        pending.settle_all(Performer::None);
        drop(pending);
        findings.policies([
            ("A, failure", a, READ),
            ("B, failure", b, READ),
            ("C, failure", c, READ),
        ]);
        let failure = failure.finish();
        if let Ok(observed) = &failure {
            let failed: Vec<Identity> = observed
                .iter()
                .filter_map(|o| match o.event {
                    Event::Effect(Effect::Failed { permit, .. }) => Some(permit),
                    _ => None,
                })
                .collect();
            findings.equal("failure: one permit's effect failed", failed.len(), 1);
            if let [id] = failed[..] {
                findings.equal(
                    "failure: released once, by its drop",
                    released(observed, id),
                    1,
                );
            }
        }
        findings.conclude(&[
            ("the success's session", &success, Expected::Complete),
            ("the failure's session", &failure, Expected::Complete),
        ]);
    }

    /// S4: cancelled before the grant, under D with no allowance at all, and
    /// dropped: A forfeits the grant's work and B the release, into their
    /// own families, and D makes no admission. The drop path is a custody's
    /// explicit settlement with no performer, then the pending dropped; a
    /// bare drop of a holding pending (the unwinding backstop) settles the
    /// same. Recorded: two settlements and the acquisition end are the observations the
    /// path's performer makes, D's under cancel and no policy's otherwise.
    #[test]
    fn s4_cancel_and_drop_forfeit_into_the_admitting_families() {
        let mut findings = Findings::new();
        let mut sessions = Vec::new();
        let (g, r) = (GRANT.work(), release_credit::<Reservation>());
        for path in ["cancel under D", "drop", "unwinding backstop"] {
            let s = session();
            let (mut a, mut b) = (
                Limits::recorded_unlimited(&s),
                Limits::recorded_unlimited(&s),
            );
            let d = Limits::recorded(0, 0, 0, &s);
            // The pending, kept by the cancel path (idle, settled) and gone
            // on the drop paths: its slots are what the held quantities read.
            let mut pending = Some(granting(&mut a, &mut b).0);
            let held = pending
                .as_ref()
                .expect("the pending exists before retirement");
            let acquisition = held.binding().1;
            let obligations = [
                held.grant.as_ref().expect("grant held").observation(),
                held.release.as_ref().expect("release held").observation(),
            ];
            findings.equal(
                "A has not settled before retirement",
                a.credits().consumed,
                NONE,
            );
            findings.equal(
                "A has not forfeited before retirement",
                a.credits().forfeited,
                NONE,
            );
            findings.equal(
                "B has not settled before retirement",
                b.credits().consumed,
                NONE,
            );
            findings.equal(
                "B has not forfeited before retirement",
                b.credits().forfeited,
                NONE,
            );
            let by = match (path, pending.as_mut()) {
                ("cancel under D", Some(held)) => {
                    held.settle_all(d.performer());
                    d.performer()
                }
                ("drop", Some(held)) => {
                    held.settle_all(Performer::None);
                    pending = None;
                    Performer::None
                }
                _ => {
                    pending = None;
                    Performer::None
                }
            };
            ledgers(
                &mut findings,
                &format!("A, {path}"),
                &a,
                pending.as_ref(),
                [g, NONE, g, NONE],
            );
            ledgers(
                &mut findings,
                &format!("B, {path}"),
                &b,
                pending.as_ref(),
                [r, NONE, r, NONE],
            );
            ledgers(
                &mut findings,
                &format!("D, {path}"),
                &d,
                pending.as_ref(),
                [NONE; 4],
            );
            findings.equal(&format!("{path}: D admitted"), d.attempts(), 0);
            // Everything holding the session dropped, the pending's owner
            // included, before its evidence is read.
            drop(pending);
            findings.policies([("A", a, READ), ("B", b, READ), ("D", d, READ)]);
            let finished = s.finish();
            if let Ok(observed) = &finished {
                let settlements: Vec<_> = observed
                    .iter()
                    .filter_map(|o| match o.event {
                        Event::Credit(Credit::Forfeit(settled, rule))
                            if settled.acquisition == acquisition =>
                        {
                            Some((o.family, o.by, settled, rule))
                        }
                        _ => None,
                    })
                    .collect();
                findings.equal(
                    &format!("{path}: exact settlements in admission order"),
                    settlements,
                    obligations
                        .into_iter()
                        .map(|held| {
                            (
                                held.id.family(),
                                by,
                                crate::bounded::Settled {
                                    obligation: held.obligation,
                                    work: held.work,
                                    id: held.id,
                                    acquisition,
                                    permit: None,
                                },
                                Forfeit::Cancelled,
                            )
                        })
                        .collect(),
                );
                match lifecycle(observed, acquisition).as_slice() {
                    [
                        (_, _, _, Event::Bound { owner, .. }),
                        (
                            end,
                            family,
                            performer,
                            Event::End {
                                owner: ended_owner, ..
                            },
                        ),
                    ] => {
                        findings.equal("the end retains its mint-time owner", ended_owner, owner);
                        findings.equal(
                            "the end retains its minting family",
                            *family,
                            acquisition.family(),
                        );
                        findings.equal("the end names the retirement performer", *performer, by);
                        findings.equal(
                            "both settlements precede the end",
                            count(&observed[..*end], |o| {
                                matches!(
                                    o.event, Event::Credit(Credit::Forfeit(settled, _))
                                        if settled.acquisition == acquisition
                                )
                            }),
                            2,
                        );
                    }
                    other => findings.check(false, || {
                        format!("{path}: not one bind and one end: {other:?}")
                    }),
                }
                // Each obligation forfeited once, `Cancelled`, by the path's
                // own performer: D's explicit cancellation names D, and only
                // a drop path names no policy. A slot cleared without its
                // explicit settlement leaves the forfeit to the obligation's
                // drop backstop, which names no policy.
                for obligation in [Obligation::Grant, Obligation::Release] {
                    findings.equal(
                        &format!("{path}: the {obligation:?} forfeited by the path's performer"),
                        count(observed, |o| {
                            o.by == by
                                && matches!(
                                    o.event,
                                    Event::Credit(Credit::Forfeit(settled, Forfeit::Cancelled))
                                        if settled.obligation == obligation
                                )
                        }),
                        1,
                    );
                }
                let settlements = count(observed, |o| {
                    o.by == by && matches!(o.event, Event::Credit(_))
                });
                findings.equal(
                    &format!("{path}: the performer made settlements and one end"),
                    count(observed, |o| o.by == by),
                    settlements + 1,
                );
                findings.equal(
                    &format!("{path}: two settlements, the grant's work and the release"),
                    settlements,
                    2,
                );
            }
            sessions.push((path, finished));
        }
        let sessions: Vec<_> = sessions
            .iter()
            .map(|(path, finished)| (*path, finished, Expected::Complete))
            .collect();
        findings.conclude(&sessions);
    }

    /// The payload allocation's resume witness. A payload's release
    /// admitted held under session S, its allocation then requested under a
    /// family of session T: [`allocate_payload`] itself refuses
    /// ([`LimitRefusal::Unrecorded`]) before any allocation is requested.
    /// T's attempts and live bytes are unchanged, no permit is in the payload
    /// slot, and the pending and resource accounting remain unchanged; the
    /// allocation admits no held work, so no validation on the admission
    /// route covers it. The refused validation makes both sessions it
    /// involved sticky-invalid, as a refused resume does. Every check is
    /// kept as a finding ([`Findings`]), concluded once the slot, the pending
    /// and both policies are dropped and both sessions finished.
    #[test]
    fn a_payload_allocation_under_another_session_is_refused_before_its_request() {
        let mut findings = Findings::new();
        let (s, t) = (session(), session());
        let mut under_s = Limits::recorded_unlimited(&s);
        let mut under_t = Limits::recorded_unlimited(&t);
        let (mut pending, ticket) = suspended(&mut under_s);
        let mut holder = Some(ticket);
        let mut slot: Option<Reservation> = None;
        let before = snapshot(&pending);
        let (attempts, live) = (under_t.attempts(), under_t.live_bytes());
        findings.equal(
            "a payload allocation under another session's policy is refused before its request",
            allocate_payload(
                &mut slot,
                |slot| Ok(slot),
                8,
                |_| true,
                &mut pending,
                &mut holder,
                &mut under_t,
            ),
            Err(BoundedError::Refused(LimitRefusal::Unrecorded)),
        );
        findings.check(
            slot.is_none(),
            || "a permit was granted into the payload slot",
        );
        findings.equal("the holder keeps its ticket", holder, Some(ticket));
        findings.equal("the pending is unchanged", snapshot(&pending), before);
        findings.equal("nothing requested under T", under_t.attempts(), attempts);
        findings.equal("nothing allocated under T", under_t.live_bytes(), live);
        pending.settle_all(Performer::None);
        drop((slot, pending));
        findings.policies([
            ("under S", under_s, INVALIDATED_HISTORY),
            ("under T", under_t, INVALIDATED_HISTORY),
        ]);
        findings.conclude(&[
            (OWNERS_SESSION, &s.finish(), INVALIDATED),
            (PERFORMING_SESSION, &t.finish(), INVALIDATED),
        ]);
    }

    /// Both crossings between recorded and unrecorded execution are refused
    /// by the resume itself, as a foreign session is: a recorded owner
    /// resumed under an ordinary family, and an ordinary owner under a
    /// recorded family. Each refused crossing invalidates the recorded
    /// session it involves, which is then no evidence, as its conclusion
    /// requires.
    #[test]
    fn a_resume_crossing_recorded_and_unrecorded_execution_is_refused() {
        let mut findings = Findings::new();
        let s = session();
        let mut recorded = Limits::recorded_unlimited(&s);
        let mut ordinary = Limits::unlimited();
        let (mut owned_recorded, ticket) = suspended(&mut recorded);
        let before = snapshot(&owned_recorded);
        findings.equal(
            "a recorded owner resumed under an ordinary family",
            owned_recorded.bind(Some(ticket), &mut ordinary),
            Err(BoundedError::Refused(LimitRefusal::Unrecorded)),
        );
        findings.equal(
            "the recorded owner's pending",
            snapshot(&owned_recorded),
            before,
        );
        findings.equal("nothing admitted, ordinary", ordinary.attempts(), 0);
        let (mut owned_ordinary, ticket) = suspended(&mut Limits::unlimited());
        let before = snapshot(&owned_ordinary);
        findings.equal(
            "an ordinary owner resumed under a recorded family",
            owned_ordinary.bind(Some(ticket), &mut recorded),
            Err(BoundedError::Refused(LimitRefusal::Unrecorded)),
        );
        findings.equal(
            "the ordinary owner's pending",
            snapshot(&owned_ordinary),
            before,
        );
        owned_recorded.settle_all(Performer::None);
        owned_ordinary.settle_all(Performer::None);
        drop((owned_recorded, owned_ordinary));
        findings.policies([
            ("recorded", recorded, INVALIDATED_HISTORY),
            (
                "ordinary",
                ordinary,
                ExpectedHistory::Unreadable(Unreadable::Unrecorded),
            ),
        ]);
        findings.conclude(&[(
            "S, the recorded owner's session, whose recording validity becomes sticky-invalid",
            &s.finish(),
            INVALIDATED,
        )]);
    }

    /// Same-session resumption across families (A then B) succeeds and
    /// keeps the one acquisition identity minted at the bind: no resume
    /// mints another, so an obligation admitted under B names the
    /// acquisition A bound, and each is held in its own family's ledgers.
    #[test]
    fn a_resume_under_another_family_of_the_session_keeps_its_acquisition() {
        let mut findings = Findings::new();
        let s = session();
        let mut family_a = Limits::recorded_unlimited(&s);
        let mut family_b = Limits::recorded_unlimited(&s);
        let mut pending = Pending::new(family_a.owner().expect("the owner is minted"));
        let mut holder = None;
        let ticket = bound(&mut pending, &mut holder, &mut family_a).expect("bound under A");
        let (owner, acquisition) = pending.acquiring::<()>(ticket).expect("bound");
        let grant = WRITE
            .admit_held(&mut family_a, 8, Obligation::Grant, owner, acquisition)
            .expect("the grant is admitted under A");
        pending.hold::<()>(ticket, grant).expect("held");
        findings.equal(
            "the resume under B",
            pending.bind(Some(ticket), &mut family_b),
            Ok(ticket),
        );
        findings.equal(
            "a resume under another family mints no acquisition",
            pending.acquisition::<()>(ticket),
            Ok(acquisition),
        );
        let (owner, _) = pending.acquiring::<()>(ticket).expect("bound");
        let release = const { released::<Reservation>() }
            .admit_held(&mut family_b, Obligation::Release, owner, acquisition)
            .expect("the release is admitted under B");
        pending.hold::<()>(ticket, release).expect("held");
        findings.equal(
            "the release names the acquisition A bound",
            pending
                .release
                .as_ref()
                .map(|release| release.acquisition()),
            Some(acquisition),
        );
        findings.equal("A admitted", family_a.credits().admitted, WRITE.work(8));
        findings.equal(
            "B admitted",
            family_b.credits().admitted,
            release_credit::<Reservation>(),
        );
        pending.settle_all(Performer::None);
        for (name, family) in [("A", &family_a), ("B", &family_b)] {
            findings.equal(
                &format!("{name} settled"),
                family.credits().conserved_with(WriteWork::default()),
                Some(true),
            );
        }
        drop(pending);
        findings.policies([("A", family_a, READ), ("B", family_b, READ)]);
        findings.conclude(&[("S", &s.finish(), Expected::Complete)]);
    }

    /// Two pendings' first tickets are both 1; their recorded acquisitions
    /// differ. An obligation admitted for one acquisition cannot be held by
    /// the other under a colliding ticket: `hold` refuses it, and dropped,
    /// it forfeits into its own family.
    #[test]
    fn colliding_tickets_cannot_substitute_one_acquisitions_credit_for_another() {
        let mut findings = Findings::new();
        let s = session();
        let mut a = Limits::recorded_unlimited(&s);
        let (mut first, first_ticket) = suspended(&mut a);
        let mut second = Pending::new(a.owner().expect("a second owner"));
        let mut holder = None;
        let second_ticket = bound(&mut second, &mut holder, &mut a).expect("bound");
        findings.equal("local tickets collide", first_ticket, second_ticket);
        findings.check(
            first.binding().1 != second.binding().1,
            || "the recorded acquisitions collide",
        );
        let foreign = first.release.take().expect("the first's release");
        findings.equal(
            "another acquisition's obligation is refused under a colliding ticket",
            second.hold::<()>(second_ticket, foreign),
            Err(BoundedError::PlanMismatch),
        );
        findings.equal(
            "the second holds nothing",
            second.held_credit(),
            Some(WriteWork::default()),
        );
        first.settle_all(Performer::None);
        second.settle_all(Performer::None);
        findings.equal(
            "A settled",
            a.credits().conserved_with(WriteWork::default()),
            Some(true),
        );
        drop((first, second));
        findings.policies([("A", a, READ)]);
        findings.conclude(&[("S", &s.finish(), Expected::Complete)]);
    }

    /// The cleanup witness after an invalidating resume: the obligations
    /// retained under S are settled explicitly into their original family,
    /// whose ledgers alone account for them, and session extraction rejects
    /// the invalidated evidence; cleanup is never established by a
    /// successful finish.
    #[test]
    fn cleanup_after_an_invalidating_resume_settles_into_the_original_family() {
        let mut findings = Findings::new();
        let (s, t) = (session(), session());
        let mut under_s = Limits::recorded_unlimited(&s);
        let mut under_t = Limits::recorded_unlimited(&t);
        let (mut pending, ticket) = suspended(&mut under_s);
        let held = pending.held_credit().expect("fits");
        findings.check(
            pending.bind(Some(ticket), &mut under_t).is_err(),
            || "the resume under T was not refused",
        );
        pending.settle_all(Performer::None);
        findings.check(pending.is_idle(), || "the settled pending is not idle");
        let s_credits = under_s.credits();
        findings.equal("forfeited into S, its origin", s_credits.forfeited, held);
        findings.equal(
            "S settled",
            s_credits.conserved_with(WriteWork::default()),
            Some(true),
        );
        findings.equal(
            "nothing admitted under T",
            under_t.credits().admitted,
            WriteWork::default(),
        );
        findings.equal(
            "nothing forfeited under T",
            under_t.credits().forfeited,
            WriteWork::default(),
        );
        drop(pending);
        findings.policies([
            ("under S", under_s, INVALIDATED_HISTORY),
            ("under T", under_t, INVALIDATED_HISTORY),
        ]);
        // The refused validation invalidates both sessions it involved: the
        // owner's and the performing budget's.
        findings.conclude(&[
            (OWNERS_SESSION, &s.finish(), INVALIDATED),
            (PERFORMING_SESSION, &t.finish(), INVALIDATED),
        ]);
    }

    /// An owner made at a deferred pending's first acquisition entry under
    /// an ordinary budget is initialized, not replaceable: the acquisition
    /// completed and the pending idle again, a later acquisition under a
    /// recorded budget is refused ([`LimitRefusal::Unrecorded`]) before any
    /// identity, admission or allocation, the pending keeping its ordinary
    /// owner, and its cleanup still available. The refused crossing
    /// invalidates the recorded budget's session.
    #[test]
    fn a_deferred_owner_made_ordinary_is_never_replaced_by_a_recorded_budget() {
        let mut findings = Findings::new();
        let s = session();
        let mut ordinary = Limits::unlimited();
        let mut recorded = Limits::recorded_unlimited(&s);
        let mut pending: Pending<<Limits as Budget>::Origin> = Pending::deferred();
        let mut holder = None;
        admit_release(&mut pending, &mut holder, &mut ordinary).expect("admitted, ordinary");
        let mut slot: Option<Reservation> = None;
        allocate_payload(
            &mut slot,
            |slot| Ok(slot),
            8,
            |_| true,
            &mut pending,
            &mut holder,
            &mut ordinary,
        )
        .expect("granted, ordinary");
        findings.check(
            pending.is_idle() && holder.is_none(),
            || "the ordinary acquisition did not end",
        );
        let made = pending
            .owner::<()>()
            .map(Owner::id)
            .expect("made at the first entry");
        let before = snapshot(&pending);
        let (attempts, live) = (recorded.attempts(), recorded.live_bytes());
        findings.equal(
            "an ordinary owner is refused under a recorded budget, never replaced",
            admit_release(&mut pending, &mut holder, &mut recorded),
            Err(BoundedError::Refused(LimitRefusal::Unrecorded)),
        );
        findings.equal("nothing bound", holder, None);
        findings.equal("the pending is unchanged", snapshot(&pending), before);
        findings.equal(
            "the owner kept",
            pending.owner::<()>().map(Owner::id),
            Ok(made),
        );
        findings.equal("nothing admitted under S", recorded.attempts(), attempts);
        findings.equal("nothing allocated under S", recorded.live_bytes(), live);
        findings.equal(
            "no credit admitted under S",
            recorded.credits().admitted,
            WriteWork::default(),
        );
        pending.settle_all(Performer::None);
        drop((slot, pending));
        findings.equal("cleanup released the payload", ordinary.live_bytes(), 0);
        findings.policies([
            ("recorded", recorded, INVALIDATED_HISTORY),
            (
                "ordinary",
                ordinary,
                ExpectedHistory::Unreadable(Unreadable::Unrecorded),
            ),
        ]);
        findings.conclude(&[(
            "S, the recorded budget's session, whose recording validity becomes sticky-invalid",
            &s.finish(),
            INVALIDATED,
        )]);
    }

    /// A deferred pending whose first acquisition entry is recorded makes a
    /// recorded owner there, and the acquisition proceeds under it: the run
    /// is complete evidence and refines the protocol.
    #[test]
    fn a_deferred_owner_made_by_a_recorded_first_entry_acquires() {
        let mut findings = Findings::new();
        let s = session();
        let mut recorded = Limits::recorded_unlimited(&s);
        let mut pending: Pending<<Limits as Budget>::Origin> = Pending::deferred();
        findings.check(
            pending.owner::<()>().is_err(),
            || "an owner was made before an entry",
        );
        let mut holder = None;
        admit_release(&mut pending, &mut holder, &mut recorded).expect("admitted, recorded");
        let mut slot: Option<Reservation> = None;
        allocate_payload(
            &mut slot,
            |slot| Ok(slot),
            8,
            |_| true,
            &mut pending,
            &mut holder,
            &mut recorded,
        )
        .expect("granted, recorded");
        findings.check(pending.is_idle(), || "the recorded acquisition did not end");
        findings.check(
            pending.owner::<()>().map(Owner::id) != Ok(Identity::UNOBSERVED),
            || "the owner made is not a recorded one",
        );
        drop((slot, pending));
        findings.policies([("recorded", recorded, READ)]);
        findings.conclude(&[("S", &s.finish(), Expected::Complete)]);
    }

    /// A payload's failed reservation, at the boundary right after the
    /// failing step and before any cleanup: the step is the reservation's
    /// physical failure ([`BoundedError::Allocation`]); the permit's effect
    /// was reported failed for the acquisition the pending bound; the permit
    /// was dropped inside the step, so the payload slot is empty and nothing
    /// is live; the release, spent at the grant, is consumed once and
    /// nothing is forfeited or still held; and the acquisition ended, the
    /// pending idle and the holder's ticket cleared. The session then holds
    /// one failed effect and one release of that permit, and refines.
    #[test]
    fn a_failed_payload_reservation_leaves_no_permit_past_its_step() {
        let mut findings = Findings::new();
        let s = session();
        let mut recorded = Limits::recorded_unlimited(&s);
        let mut pending: Pending<<Limits as Budget>::Origin> = Pending::deferred();
        let mut holder = None;
        admit_release(&mut pending, &mut holder, &mut recorded).expect("admitted, recorded");
        let acquisition = pending.binding().1;
        let mut slot: Option<Reservation> = None;
        findings.equal(
            "the step is the reservation's physical failure",
            allocate_payload(
                &mut slot,
                |slot| Ok(slot),
                8,
                |_| false,
                &mut pending,
                &mut holder,
                &mut recorded,
            ),
            Err(BoundedError::Allocation { bytes: 8 }),
        );
        findings.check(
            slot.is_none(),
            || "the failed reservation's permit outlived its step in the payload slot",
        );
        findings.equal(
            "nothing live once the failing step returns",
            recorded.live_bytes(),
            0,
        );
        findings.check(
            pending.is_idle() && holder.is_none(),
            || "the failed acquisition did not end",
        );
        let r = release_credit::<Reservation>();
        ledgers(
            &mut findings,
            "after the failing step",
            &recorded,
            Some(&pending),
            [r, r, NONE, NONE],
        );
        drop((slot, pending));
        findings.policies([("recorded", recorded, READ)]);
        let finished = s.finish();
        if let Ok(observed) = &finished {
            let failed: Vec<(Identity, Identity)> = observed
                .iter()
                .filter_map(|o| match o.event {
                    Event::Effect(Effect::Failed {
                        permit,
                        acquisition,
                    }) => Some((permit, acquisition)),
                    _ => None,
                })
                .collect();
            findings.equal("one permit's effect failed", failed.len(), 1);
            if let [(id, failed_for)] = failed[..] {
                findings.equal(
                    "the effect names the bound acquisition",
                    failed_for,
                    acquisition,
                );
                findings.equal(
                    "the failed permit released once",
                    count(observed, |o| o.event == Event::Released(id)),
                    1,
                );
            }
        }
        findings.conclude(&[("S", &finished, Expected::Complete)]);
    }

    // Stored types of the fixtures below, none holding an atomics family.
    impl Representation for u32 {
        type In<S: Atomics> = Self;
    }
    impl Representation for u64 {
        type In<S: Atomics> = Self;
    }
    impl Representation for [u64; 4] {
        type In<S: Atomics> = Self;
    }

    /// A block's contract, evaluated at run time as every caller evaluates
    /// it in a constant: its write is the header's bytes and the permit's,
    /// whatever the rest of the value, one admitted value; a whole value is
    /// its own header; its block is the whole held value with its permit,
    /// padding included, the bytes the allocator is asked for.
    #[test]
    fn a_blocks_contract_is_its_header_and_permit_written_and_its_whole_block() {
        let permit = size_of::<Reservation>();
        let written = |bytes: usize| ResourceBound {
            values: 1,
            bytes: bytes as u64,
            ..ResourceBound::default()
        };
        let header = Contract::<u32, [u64; 4], Reservation>::of();
        assert_eq!(header.write(), written(4 + permit));
        assert_eq!(header.block(), 32 + permit);
        let whole = Contract::<u64, u64, Reservation>::of();
        assert_eq!(whole.write(), written(8 + permit));
        assert_eq!(whole.block(), 8 + permit);
        // A value whose size is not a multiple of the permit's alignment:
        // the block holds the padding before the permit, which is written
        // by no unit.
        let padded = Contract::<u32, u32, Reservation>::of();
        assert_eq!(padded.write(), written(4 + permit));
        assert_eq!(padded.block(), 8 + permit);
        assert_eq!(
            release_cost::<Reservation>(),
            ResourceBound {
                values: 1,
                bytes: permit as u64,
                ..ResourceBound::default()
            }
        );
    }
}
