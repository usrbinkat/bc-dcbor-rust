//! The machine's transitions ([`Machine::observe`]), one per observation,
//! each the production transition it records (the crate's documentation),
//! and the driver's marks checked against the state they reach.

use std::collections::{BTreeMap, BTreeSet};

use crate::model::{
    AcquisitionState, At, Divergence, Held, Ledger, Life, Outcome, Permit, RecordState, Rule,
    Source,
};
use crate::{
    Answer, Call, Cause, Checkpoint, Class, Credit, Custody, Effect, End, Event, Evidence, Forfeit,
    Identity, LimitRefusal, Obligation, Observed, Performer, Publication, RecordStage, Run,
    Settled, WriteWork,
};

/// The record transitions production makes (`reclamation.rs`): a granted
/// block classified (`None` to `Granted`), its owner stage made (`Handle`),
/// its handle retired into its queue (`Queued`), taken by the queue's one
/// cleanup (`Active`), and its cleanup completed, by its handle or by the
/// queue (`Reclaimed`). Every other pair is no transition.
const fn record_step(from: Option<RecordStage>, to: RecordStage) -> bool {
    matches!(
        (from, to),
        (None, RecordStage::Granted)
            | (Some(RecordStage::Granted), RecordStage::Handle)
            | (Some(RecordStage::Handle), RecordStage::Queued)
            | (Some(RecordStage::Queued), RecordStage::Active)
            | (Some(RecordStage::Handle), RecordStage::Reclaimed)
            | (Some(RecordStage::Active), RecordStage::Reclaimed)
    )
}

/// Whether `rule` names `obligation` (`bounded.rs` `Forfeit`): a synchronous
/// acquisition's refusal forfeits its release and its grant's work, a failed
/// physical reservation the grant's work alone (its release was spent at the
/// grant), a cancellation any obligation, and an enumeration's completion
/// its window's controls.
const fn names(rule: Forfeit, obligation: Obligation) -> bool {
    match rule {
        Forfeit::AcquisitionRefused => {
            matches!(obligation, Obligation::Release | Obligation::Grant)
        }
        Forfeit::AcquisitionFailed => matches!(obligation, Obligation::Grant),
        Forfeit::Cancelled => true,
        Forfeit::EnumerationComplete => matches!(obligation, Obligation::BucketWindow),
    }
}

/// `left - right` in both quantities, or none when either falls below zero.
fn less(left: WriteWork, right: WriteWork) -> Option<WriteWork> {
    Some(WriteWork::new(
        left.values.checked_sub(right.values)?,
        left.bytes.checked_sub(right.bytes)?,
    ))
}

fn sum(left: WriteWork, right: WriteWork) -> Result<WriteWork, Rule> {
    left.checked_then(right).ok_or(Rule::Overflow)
}

/// What the machine holds under one owner at a checkpoint
/// ([`Machine::custody`]): its active acquisitions, its obligations still
/// holding work, by identity, and its live permits, each with its record
/// stage (none for a permit that is no record block).
#[derive(Default)]
struct Expected {
    bound: BTreeSet<Identity>,
    held: BTreeMap<Identity, Held>,
    permits: BTreeMap<Identity, Option<RecordStage>>,
}

/// The machine's state between observations ([`crate::model`]): one
/// transition system for every stream, a recorded run's and a whole
/// session's alike.
struct Machine {
    /// Every identity minted: owners, acquisitions, obligations, permits.
    minted: BTreeSet<Identity>,
    owners: BTreeSet<Identity>,
    /// Each acquisition and the owner that bound it: an ended one is kept,
    /// for its permits' attribution and so its identity is never bound or
    /// ended again.
    acquisitions: BTreeMap<Identity, AcquisitionState>,
    obligations: BTreeMap<Identity, Held>,
    permits: BTreeMap<Identity, Permit>,
    /// The acquisitions of [`Self::acquisitions`] bound and not yet ended,
    /// by identity: the one record of an acquisition's activity, which a
    /// checkpoint and quiescence read without walking every acquisition the
    /// session ever bound.
    unended: BTreeSet<Identity>,
    /// The obligations of [`Self::obligations`] still holding work, by
    /// identity, and the same obligations by the acquisition each was
    /// admitted for: what a checkpoint, an acquisition's end and quiescence
    /// read, so none walks every obligation the session ever admitted.
    outstanding: BTreeSet<Identity>,
    outstanding_by: BTreeMap<Identity, BTreeSet<Identity>>,
    /// The permits of [`Self::permits`] still live, by identity: what a
    /// checkpoint reads, so it costs the custody live there, not every
    /// permit the session ever granted.
    live: BTreeSet<Identity>,
    ledgers: BTreeMap<u64, Ledger>,
    /// Each performer's admitted work call awaiting its admission.
    admitting: BTreeMap<u64, WriteWork>,
    /// The refusal of the last call, while no call has been admitted since.
    refusal: Option<LimitRefusal>,
    /// A permit's reservation was observed failed.
    failed: bool,
    cleaning: Option<Cause>,
    published: Option<BTreeSet<Identity>>,
}

impl Machine {
    fn new() -> Self {
        Self {
            minted: BTreeSet::new(),
            owners: BTreeSet::new(),
            acquisitions: BTreeMap::new(),
            obligations: BTreeMap::new(),
            permits: BTreeMap::new(),
            unended: BTreeSet::new(),
            outstanding: BTreeSet::new(),
            outstanding_by: BTreeMap::new(),
            live: BTreeSet::new(),
            ledgers: BTreeMap::new(),
            admitting: BTreeMap::new(),
            refusal: None,
            failed: false,
            cleaning: None,
            published: None,
        }
    }

    /// Mint `identity`, published by `publisher`: of that family, fresh.
    fn mint(&mut self, identity: Identity, publisher: u64) -> Result<(), Rule> {
        if identity == Identity::UNOBSERVED || identity.family() == 0 {
            return Err(Rule::Unobserved);
        }
        if identity.family() != publisher {
            return Err(Rule::WrongFamily {
                identity,
                publisher,
            });
        }
        if !self.minted.insert(identity) {
            return Err(Rule::Reissued(identity));
        }
        Ok(())
    }

    fn ledger(&mut self, family: u64) -> &mut Ledger {
        self.ledgers.entry(family).or_default()
    }

    fn permit(&self, permit: Identity) -> Result<Permit, Rule> {
        self.permits
            .get(&permit)
            .copied()
            .ok_or(Rule::UnknownPermit(permit))
    }

    /// The permit named `permit`, refused unless live.
    fn live(&self, permit: Identity) -> Result<Permit, Rule> {
        let record = self.permit(permit)?;
        match record.life {
            Life::Live => Ok(record),
            life => Err(Rule::PermitLife { permit, life }),
        }
    }

    fn update(&mut self, permit: Identity, change: impl FnOnce(&mut Permit)) {
        if let Some(record) = self.permits.get_mut(&permit) {
            change(record);
            if record.life == Life::Live {
                self.live.insert(permit);
            } else {
                self.live.remove(&permit);
            }
        }
    }

    /// A fresh permit `record` under `permit`, indexed live when it is.
    fn grant(&mut self, permit: Identity, record: Permit) {
        if record.life == Life::Live {
            self.live.insert(permit);
        }
        self.permits.insert(permit, record);
    }

    /// Obligation `id` stored as `held`: indexed outstanding, under its
    /// acquisition, while it holds work, and no longer once it holds none.
    fn hold(&mut self, id: Identity, held: Held) {
        if held.remaining == WriteWork::default() {
            self.outstanding.remove(&id);
            if let Some(obligations) = self.outstanding_by.get_mut(&held.acquisition) {
                obligations.remove(&id);
                if obligations.is_empty() {
                    self.outstanding_by.remove(&held.acquisition);
                }
            }
        } else {
            self.outstanding.insert(id);
            self.outstanding_by
                .entry(held.acquisition)
                .or_default()
                .insert(id);
        }
        self.obligations.insert(id, held);
    }

    /// Advance the state by one observation, every rule its transition
    /// keeps checked.
    fn observe(&mut self, observed: &Observed) -> Result<(), Rule> {
        let publisher = observed.family;
        if let Event::Credit(Credit::Admit { work, .. }) = observed.event {
            self.admission(observed.by, work)?;
        } else if let Performer::Policy(policy) = observed.by
            && let Event::Call(..) = observed.event
            && let Some(work) = self.admitting.get(&policy)
        {
            return Err(Rule::MissingAdmission(*work));
        }
        match observed.event {
            Event::Call(call, answer) => self.call(observed.by, publisher, call, answer),
            Event::Credit(Credit::Admit { work, held }) => {
                let Some(hold) = held else {
                    let ledger = self.ledger(publisher);
                    ledger.admitted = sum(ledger.admitted, work)?;
                    ledger.consumed = sum(ledger.consumed, work)?;
                    return Ok(());
                };
                if self.cleaning.is_some() {
                    return Err(Rule::HoldInCleanup);
                }
                let unheld = less(work, hold.work).ok_or(Rule::Overheld)?;
                self.active(hold.acquisition)?;
                self.mint(hold.id, publisher)?;
                self.hold(
                    hold.id,
                    Held {
                        obligation: hold.obligation,
                        acquisition: hold.acquisition,
                        remaining: hold.work,
                    },
                );
                let ledger = self.ledger(publisher);
                ledger.admitted = sum(ledger.admitted, work)?;
                ledger.consumed = sum(ledger.consumed, unheld)?;
                Ok(())
            }
            Event::Credit(Credit::Spend(settled)) => self.settle(publisher, settled, None),
            Event::Credit(Credit::Forfeit(settled, rule)) => {
                self.settle(publisher, settled, Some(rule))
            }
            Event::Effect(effect) => self.effect(publisher, effect),
            Event::Split {
                parent,
                child,
                bytes,
            } => {
                let record = self.live(parent)?;
                if parent.family() != publisher {
                    return Err(Rule::WrongFamily {
                        identity: parent,
                        publisher,
                    });
                }
                if child.family() != parent.family() {
                    return Err(Rule::ForeignTransfer {
                        left: parent,
                        right: child,
                    });
                }
                let remaining = record
                    .bytes
                    .checked_sub(bytes)
                    .ok_or(Rule::SplitOverdrawn {
                        permit: parent,
                        held: record.bytes,
                        taken: bytes,
                    })?;
                self.mint(child, publisher)?;
                if record.record.is_some() {
                    return Err(Rule::RecordTransition {
                        permit: parent,
                        from: record.record.map(|state| state.stage),
                        to: RecordStage::Granted,
                    });
                }
                self.grant(
                    child,
                    Permit {
                        bytes,
                        source: Source::Split,
                        acquisition: record.acquisition,
                        outcome: None,
                        life: Life::Live,
                        record: None,
                    },
                );
                self.update(parent, |record| record.bytes = remaining);
                Ok(())
            }
            Event::Merge {
                survivor,
                retired,
                bytes,
            } => {
                if survivor == retired {
                    return Err(Rule::SelfMerge(survivor));
                }
                if survivor.family() != retired.family() {
                    return Err(Rule::ForeignTransfer {
                        left: survivor,
                        right: retired,
                    });
                }
                if survivor.family() != publisher {
                    return Err(Rule::WrongFamily {
                        identity: survivor,
                        publisher,
                    });
                }
                let input = self.live(retired)?;
                if input.bytes != bytes {
                    return Err(Rule::MergeMismatch {
                        permit: retired,
                        held: input.bytes,
                        passed: bytes,
                    });
                }
                let total = self
                    .live(survivor)?
                    .bytes
                    .checked_add(bytes)
                    .ok_or(Rule::Overflow)?;
                self.update(survivor, |record| record.bytes = total);
                self.update(retired, |record| {
                    record.bytes = 0;
                    record.life = Life::Retired;
                });
                Ok(())
            }
            Event::Released(permit) => {
                let record = self.permit(permit)?;
                if permit.family() != publisher {
                    return Err(Rule::WrongFamily {
                        identity: permit,
                        publisher,
                    });
                }
                if record.life != Life::Live {
                    return Err(Rule::PermitLife {
                        permit,
                        life: record.life,
                    });
                }
                if record.source == Source::Granted && record.acquisition.is_none() {
                    return Err(Rule::Unpaid(permit));
                }
                // An ordinary permit releases by the rules above; a record
                // block only unowned (a cancellation before its owner stage)
                // or once its cleanup completed.
                if let Some(state) = record.record
                    && !matches!(state.stage, RecordStage::Granted | RecordStage::Reclaimed)
                {
                    return Err(Rule::PrematureRecordRelease {
                        permit,
                        stage: state.stage,
                    });
                }
                self.update(permit, |record| record.life = Life::Released);
                Ok(())
            }
            Event::Owner(owner) => {
                self.mint(owner, publisher)?;
                self.owners.insert(owner);
                Ok(())
            }
            Event::Bound { acquisition, owner } => {
                if !self.owners.contains(&owner) {
                    return Err(Rule::UnknownOwner(owner));
                }
                self.mint(acquisition, publisher)?;
                self.acquisitions
                    .insert(acquisition, AcquisitionState { owner });
                self.unended.insert(acquisition);
                Ok(())
            }
            Event::End { acquisition, owner } => self.end(publisher, acquisition, owner),
            Event::Custody {
                permit,
                owner,
                stage,
            } => self.record(publisher, permit, owner, stage),
        }
    }

    /// The active acquisition `acquisition`: refused unless bound and not
    /// yet ended.
    fn active(&self, acquisition: Identity) -> Result<AcquisitionState, Rule> {
        let state = *self
            .acquisitions
            .get(&acquisition)
            .ok_or(Rule::UnknownAcquisition(acquisition))?;
        if !self.unended.contains(&acquisition) {
            return Err(Rule::AcquisitionEnded(acquisition));
        }
        Ok(state)
    }

    /// An acquisition's end (`Acquisition::end`, `Origin::end`): an active
    /// acquisition, published by the family that minted it, for the owner
    /// that bound it, with no obligation admitted for it still holding
    /// work. It stays known, inactive: never bound, admitted for or ended
    /// again.
    fn end(&mut self, publisher: u64, acquisition: Identity, owner: Identity) -> Result<(), Rule> {
        let state = self.active(acquisition)?;
        if acquisition.family() != publisher {
            return Err(Rule::WrongFamily {
                identity: acquisition,
                publisher,
            });
        }
        if state.owner != owner {
            return Err(Rule::EndOwner {
                acquisition,
                bound: state.owner,
                named: owner,
            });
        }
        // The least identity among the obligations admitted for this
        // acquisition still holding work.
        if let Some(&obligation) = self
            .outstanding_by
            .get(&acquisition)
            .and_then(BTreeSet::first)
        {
            return Err(Rule::EndOutstanding {
                acquisition,
                obligation,
            });
        }
        self.unended.remove(&acquisition);
        Ok(())
    }

    /// A record transition (`Releasing::custody`): a live, paid permit whose
    /// reservation was observed made, published by its own family, for the
    /// owner that bound the acquisition granting it, moving its record
    /// stage by one transition production makes ([`record_step`]), its
    /// owner never changing.
    fn record(
        &mut self,
        publisher: u64,
        permit: Identity,
        owner: Identity,
        stage: RecordStage,
    ) -> Result<(), Rule> {
        let record = self.live(permit)?;
        if permit.family() != publisher {
            return Err(Rule::WrongFamily {
                identity: permit,
                publisher,
            });
        }
        let acquisition = record.acquisition.ok_or(Rule::Unpaid(permit))?;
        if record.outcome != Some(Outcome::Reserved) {
            return Err(Rule::MissingEffect {
                permit,
                required: Outcome::Reserved,
            });
        }
        let bound = self
            .acquisitions
            .get(&acquisition)
            .ok_or(Rule::UnknownAcquisition(acquisition))?
            .owner;
        let held = record.record.map_or(bound, |state| state.owner);
        if owner != bound || owner != held {
            return Err(Rule::RecordOwner {
                permit,
                owner: held,
                named: owner,
            });
        }
        let from = record.record.map(|state| state.stage);
        if !record_step(from, stage) {
            return Err(Rule::RecordTransition {
                permit,
                from,
                to: stage,
            });
        }
        self.update(permit, |record| {
            record.record = Some(RecordState { owner, stage });
        });
        Ok(())
    }

    /// Admission correspondence (`admit_at`): a performer's admitted work
    /// call is followed by its admission of exactly that work before its
    /// next call, and an admission follows nothing else.
    fn admission(&mut self, by: Performer, admitted: WriteWork) -> Result<(), Rule> {
        let Performer::Policy(policy) = by else {
            return Err(Rule::AdmissionWithoutPolicy);
        };
        match self.admitting.remove(&policy) {
            Some(call) if call == admitted => Ok(()),
            Some(call) => Err(Rule::AdmissionMismatch { call, admitted }),
            None => Err(Rule::UnauthorizedAdmission(admitted)),
        }
    }

    fn call(
        &mut self,
        by: Performer,
        publisher: u64,
        call: Call,
        answer: Answer,
    ) -> Result<(), Rule> {
        if self.cleaning.is_some() && matches!(call, Call::Allocate(_)) {
            return Err(Rule::AllocateInCleanup);
        }
        match (call, answer) {
            // A foreground and a cleanup unit alike: the admission that
            // follows is the unit's own, whichever account it is charged to.
            (Call::Work { values, bytes } | Call::Reclaim { values, bytes }, Answer::Admitted) => {
                self.refusal = None;
                if let Performer::Policy(policy) = by {
                    self.admitting.insert(policy, WriteWork::new(values, bytes));
                }
                Ok(())
            }
            (Call::Allocate(bytes), Answer::Granted(permit)) => {
                self.refusal = None;
                self.mint(permit, publisher)?;
                self.grant(
                    permit,
                    Permit {
                        bytes,
                        source: Source::Granted,
                        acquisition: None,
                        outcome: None,
                        life: Life::Live,
                        record: None,
                    },
                );
                Ok(())
            }
            (_, Answer::Refused { refusal, .. }) => {
                self.refusal = Some(refusal);
                Ok(())
            }
            (call, answer) => Err(Rule::UnexpectedAnswer(call, answer)),
        }
    }

    /// A settlement into its obligation's origin (`Retained::record`): the
    /// named obligation of that kind and acquisition, published by its
    /// origin family, by at most what it holds, with its permit link.
    fn settle(
        &mut self,
        publisher: u64,
        settled: Settled,
        rule: Option<Forfeit>,
    ) -> Result<(), Rule> {
        let id = settled.id;
        let held = *self
            .obligations
            .get(&id)
            .ok_or(Rule::UnknownObligation(id))?;
        if id.family() != publisher {
            return Err(Rule::WrongFamily {
                identity: id,
                publisher,
            });
        }
        if held.obligation != settled.obligation {
            return Err(Rule::KindMismatch {
                obligation: id,
                held: held.obligation,
                named: settled.obligation,
            });
        }
        if held.acquisition != settled.acquisition {
            return Err(Rule::AcquisitionMismatch {
                obligation: id,
                held: held.acquisition,
                named: settled.acquisition,
            });
        }
        let remaining = less(held.remaining, settled.work).ok_or(Rule::Overdrawn {
            obligation: id,
            remaining: held.remaining,
            settled: settled.work,
        })?;
        let whole = remaining == WriteWork::default();
        if let Some(rule) = rule {
            if !names(rule, held.obligation) {
                return Err(Rule::UnnamedForfeit(held.obligation, rule));
            }
            if !whole {
                return Err(Rule::Partial(id));
            }
        } else if !whole && held.obligation != Obligation::BucketWindow {
            return Err(Rule::Partial(id));
        }
        match (held.obligation, rule, settled.permit) {
            (Obligation::BucketWindow, _, None) => {}
            (Obligation::BucketWindow, _, Some(_)) => return Err(Rule::PermitLink(id)),
            (Obligation::Release, None, Some(permit)) => {
                let record = self.live(permit)?;
                if record.source != Source::Granted {
                    return Err(Rule::PermitLink(id));
                }
                if record.acquisition.is_some() {
                    return Err(Rule::PermitBound(permit));
                }
                self.update(permit, |record| record.acquisition = Some(held.acquisition));
            }
            (Obligation::Release, None, None) => return Err(Rule::PermitLink(id)),
            (Obligation::Release, Some(_), Some(_)) => {
                return Err(Rule::ReleaseForfeitedAfterGrant(id));
            }
            (Obligation::Release, Some(_), None) => {}
            (Obligation::Grant, rule, Some(permit)) => {
                let record = self.permit(permit)?;
                if record.acquisition != Some(held.acquisition) {
                    return Err(Rule::PermitAcquisition {
                        permit,
                        bound: record.acquisition,
                        named: held.acquisition,
                    });
                }
                let required = match rule {
                    None => Some(Outcome::Reserved),
                    Some(Forfeit::AcquisitionFailed) => Some(Outcome::Failed),
                    Some(_) => None,
                };
                if let Some(required) = required
                    && record.outcome != Some(required)
                {
                    return Err(Rule::MissingEffect { permit, required });
                }
            }
            (Obligation::Grant, None | Some(Forfeit::AcquisitionFailed), None) => {
                return Err(Rule::PermitLink(id));
            }
            (Obligation::Grant, Some(_), None) => {}
        }
        self.hold(id, Held { remaining, ..held });
        let ledger = self.ledger(publisher);
        match rule {
            None => ledger.consumed = sum(ledger.consumed, settled.work)?,
            Some(_) => ledger.forfeited = sum(ledger.forfeited, settled.work)?,
        }
        Ok(())
    }

    /// A physical outcome (`Budget::effect`): published by the permit's own
    /// family, for the acquisition its release was spent for, once, never a
    /// split's child's.
    fn effect(&mut self, publisher: u64, effect: Effect) -> Result<(), Rule> {
        let (permit, acquisition, outcome) = match effect {
            Effect::Reserved {
                permit,
                acquisition,
            } => (permit, acquisition, Outcome::Reserved),
            Effect::Failed {
                permit,
                acquisition,
            } => (permit, acquisition, Outcome::Failed),
        };
        let record = self.live(permit)?;
        if permit.family() != publisher {
            return Err(Rule::WrongFamily {
                identity: permit,
                publisher,
            });
        }
        if record.acquisition != Some(acquisition) {
            return Err(Rule::PermitAcquisition {
                permit,
                bound: record.acquisition,
                named: acquisition,
            });
        }
        if record.source != Source::Granted || record.outcome.is_some() {
            return Err(Rule::EffectInvalid(permit));
        }
        self.update(permit, |record| record.outcome = Some(outcome));
        if outcome == Outcome::Failed {
            self.failed = true;
        }
        Ok(())
    }

    /// Whether a step is between its parts: an admission awaited, a granted
    /// permit whose release is unspent or whose outcome is unobserved, a
    /// failed permit not yet dropped, or a record whose cleanup completed
    /// and whose block is not yet freed (the one unit that does both).
    fn mid_step(&self) -> bool {
        !self.admitting.is_empty()
            || self.live.iter().any(|id| {
                let permit = &self.permits[id];
                permit.outcome == Some(Outcome::Failed)
                    || permit
                        .record
                        .is_some_and(|state| state.stage == RecordStage::Reclaimed)
                    || (permit.source == Source::Granted
                        && (permit.acquisition.is_none() || permit.outcome.is_none()))
            })
    }

    /// The machine's custody, by owner: each active acquisition under the
    /// owner that bound it, each obligation still holding work and each
    /// live permit, with its record stage, under the owner that bound its
    /// acquisition (`Event::Bound`). Published permits stay their owner's
    /// custody until released: publication moves who holds a value, not
    /// whose acquisition paid for it. A live permit bound to no acquisition
    /// at a quiescent point is unpaid.
    fn custody(&self) -> Result<BTreeMap<Identity, Expected>, Rule> {
        let mut expected: BTreeMap<Identity, Expected> = BTreeMap::new();
        for &acquisition in &self.unended {
            expected
                .entry(self.acquisitions[&acquisition].owner)
                .or_default()
                .bound
                .insert(acquisition);
        }
        let owner_of = |acquisition: Identity| {
            self.acquisitions
                .get(&acquisition)
                .map(|state| state.owner)
                .ok_or(Rule::UnknownAcquisition(acquisition))
        };
        for &id in &self.outstanding {
            let obligation = self.obligations[&id];
            let owner = owner_of(obligation.acquisition)?;
            expected
                .entry(owner)
                .or_default()
                .held
                .insert(id, obligation);
        }
        for &id in &self.live {
            let permit = &self.permits[&id];
            let acquisition = permit.acquisition.ok_or(Rule::Unpaid(id))?;
            let owner = owner_of(acquisition)?;
            expected
                .entry(owner)
                .or_default()
                .permits
                .insert(id, permit.record.map(|state| state.stage));
        }
        Ok(expected)
    }

    /// The observed custody equals the machine's, owner by owner: every
    /// reported owner known and reported once (the collector combines a
    /// component's repeated groups), each binding an acquisition that owner
    /// bound, each obligation and permit reported
    /// once across the whole observation, under the owner the machine bound
    /// it to, with its kind, acquisition and remaining work; and no owner
    /// holding custody left unreported. The observation is the production
    /// traversal's; the machine's `Bound` relationships only check it.
    fn checkpoint(&self, custody: &[Custody]) -> Result<(), Rule> {
        if self.mid_step() {
            return Err(Rule::MidStep);
        }
        let mut expected = self.custody()?;
        let mut owners = BTreeSet::new();
        let mut seen = BTreeSet::new();
        for reported in custody {
            let owner = reported.owner;
            if !self.owners.contains(&owner) {
                return Err(Rule::UnknownOwner(owner));
            }
            if !owners.insert(owner) {
                return Err(Rule::Duplicate(owner));
            }
            let Expected {
                mut bound,
                mut held,
                mut permits,
            } = expected.remove(&owner).unwrap_or_default();
            // The reported bindings are exactly this owner's active
            // acquisitions, each once: a binding is custody from its bind to
            // its end (`Event::End`), credit or none.
            for &acquisition in &reported.bound {
                if !seen.insert(acquisition) {
                    return Err(Rule::Duplicate(acquisition));
                }
                let state = *self
                    .acquisitions
                    .get(&acquisition)
                    .ok_or(Rule::UnknownAcquisition(acquisition))?;
                if state.owner != owner {
                    return Err(Rule::BindingElsewhere {
                        owner,
                        acquisition,
                        bound: state.owner,
                    });
                }
                if !self.unended.contains(&acquisition) {
                    return Err(Rule::StaleBinding { owner, acquisition });
                }
                bound.remove(&acquisition);
            }
            if let Some(&acquisition) = bound.iter().next() {
                return Err(Rule::MissingBinding { owner, acquisition });
            }
            for hold in &reported.held {
                if !seen.insert(hold.id) {
                    return Err(Rule::Duplicate(hold.id));
                }
                let obligation = held.remove(&hold.id).ok_or(Rule::ExtraHeld {
                    owner,
                    obligation: hold.id,
                })?;
                if hold.obligation != obligation.obligation {
                    return Err(Rule::KindMismatch {
                        obligation: hold.id,
                        held: obligation.obligation,
                        named: hold.obligation,
                    });
                }
                if hold.acquisition != obligation.acquisition {
                    return Err(Rule::AcquisitionMismatch {
                        obligation: hold.id,
                        held: obligation.acquisition,
                        named: hold.acquisition,
                    });
                }
                if hold.work != obligation.remaining {
                    return Err(Rule::HeldMismatch {
                        obligation: hold.id,
                        remaining: obligation.remaining,
                        reported: hold.work,
                    });
                }
            }
            if let Some(&obligation) = held.keys().next() {
                return Err(Rule::MissingHeld { owner, obligation });
            }
            for reported in &reported.permits {
                let permit = reported.permit;
                if !seen.insert(permit) {
                    return Err(Rule::Duplicate(permit));
                }
                let expected = permits
                    .remove(&permit)
                    .ok_or(Rule::ExtraPermit { owner, permit })?;
                if expected != reported.record {
                    return Err(Rule::HolderMismatch {
                        permit,
                        expected,
                        reported: reported.record,
                    });
                }
            }
            if let Some(&permit) = permits.keys().next() {
                return Err(Rule::MissingPermit { owner, permit });
            }
        }
        // An owner holding custody the observation never reported.
        for (&owner, unreported) in &expected {
            if let Some(&obligation) = unreported.held.keys().next() {
                return Err(Rule::MissingHeld { owner, obligation });
            }
            if let Some(&permit) = unreported.permits.keys().next() {
                return Err(Rule::MissingPermit { owner, permit });
            }
            if let Some(&acquisition) = unreported.bound.iter().next() {
                return Err(Rule::MissingBinding { owner, acquisition });
            }
        }
        Ok(())
    }

    /// The driver begins cleanup: a refusal's names the outstanding one, a
    /// physical failure's an observed failed reservation.
    fn clean(&mut self, cause: Cause) -> Result<(), Rule> {
        match cause {
            Cause::Error(Class::Refused(reason)) if self.refusal != Some(reason) => {
                return Err(Rule::RefusalUnmatched {
                    cause,
                    outstanding: self.refusal,
                });
            }
            Cause::Error(Class::Allocation) if !self.failed => return Err(Rule::NoFailedPermit),
            _ => {}
        }
        self.cleaning = Some(cause);
        Ok(())
    }

    /// The operation published: no refusal outstanding, no cleanup begun,
    /// every published permit live.
    fn publish(&mut self, publication: &Publication) -> Result<(), Rule> {
        if self.cleaning.is_some() {
            return Err(Rule::PublishedAfterCleaning);
        }
        if let Some(refusal) = self.refusal {
            return Err(Rule::PublishedRefused(refusal));
        }
        let mut published = BTreeSet::new();
        for &permit in &publication.permits {
            if !published.insert(permit) {
                return Err(Rule::Duplicate(permit));
            }
            if self.live(permit).is_err() {
                return Err(Rule::PublishedPermit(permit));
            }
        }
        self.published = Some(published);
        Ok(())
    }

    /// Quiescence: no admission awaited, every permit released or merged
    /// away, every granted permit's release paid and its outcome observed,
    /// every obligation settled.
    fn quiescent(&self) -> Result<(), Rule> {
        if let Some(work) = self.admitting.values().next() {
            return Err(Rule::MissingAdmission(*work));
        }
        for (&id, permit) in &self.permits {
            if permit.life == Life::Live {
                return Err(Rule::Leaked(id));
            }
            if permit.source == Source::Granted {
                if permit.acquisition.is_none() {
                    return Err(Rule::Unpaid(id));
                }
                if permit.outcome.is_none() {
                    return Err(Rule::NoEffect(id));
                }
            }
        }
        if let Some(&id) = self.outstanding.first() {
            return Err(Rule::Outstanding(id));
        }
        if let Some(&acquisition) = self.unended.first() {
            return Err(Rule::Unended(acquisition));
        }
        Ok(())
    }

    /// The end the run reached.
    fn reached(&self) -> Option<End> {
        match (self.cleaning, &self.published) {
            (Some(cause), None) => Some(cause.end()),
            (None, Some(_)) => Some(End::Published),
            _ => None,
        }
    }
}

/// The checkpoints one replay checks, in their order ([`replay`]): every
/// checkpoint's boundary, read once to place the marks, then each
/// checkpoint lent as the replay reaches its boundary, valid until the next
/// one is taken. A source reconstructing its checkpoints
/// ([`crate::History`]) keeps one working snapshot and lends it, never a
/// copy per checkpoint.
pub(crate) trait Checkpoints {
    /// Every checkpoint's boundary, in order.
    fn boundaries(&self) -> Vec<usize>;
    /// The next checkpoint, or none past the last.
    fn advance(&mut self) -> Option<&Checkpoint>;
}

/// Checkpoints held whole, in order ([`check`], [`settled`]).
struct Whole<'c> {
    all: &'c [Checkpoint],
    next: usize,
}

impl<'c> Whole<'c> {
    fn new(all: &'c [Checkpoint]) -> Self {
        Self { all, next: 0 }
    }
}

impl Checkpoints for Whole<'_> {
    fn boundaries(&self) -> Vec<usize> {
        self.all
            .iter()
            .map(|checkpoint| checkpoint.boundary)
            .collect()
    }

    fn advance(&mut self) -> Option<&Checkpoint> {
        let checkpoint = self.all.get(self.next)?;
        self.next += 1;
        Some(checkpoint)
    }
}

/// A mark of the run's driver, in the order the run places them.
enum Mark<'r> {
    Checkpoint,
    Cleaning(Cause),
    Published(&'r Publication),
}

/// The one replay every check makes: `observed` through the one transition
/// system, each mark at its boundary against the state the observations
/// before it reach (`[0, b)`), then the rest of the stream and quiescence.
/// Checkpoints are given in order and refused out of it; cleaning and
/// publication are merged in by boundary. Marks add checks; their absence
/// relaxes none. The machine reached, or the first divergence.
fn replay(
    observed: &[Observed],
    checkpoints: &mut impl Checkpoints,
    cleaning: Option<(usize, Cause)>,
    published: Option<&Publication>,
) -> Result<Machine, Divergence> {
    let mut marks: Vec<(usize, At, Mark<'_>)> = checkpoints
        .boundaries()
        .into_iter()
        .enumerate()
        .map(|(index, boundary)| (boundary, At::Checkpoint(index), Mark::Checkpoint))
        .collect();
    let mut previous = 0;
    for &(boundary, at, _) in &marks {
        if boundary < previous {
            return Err(Divergence {
                at,
                rule: Rule::BoundaryDecreasing { boundary, previous },
            });
        }
        previous = boundary;
    }
    if let Some((boundary, cause)) = cleaning {
        marks.push((boundary, At::Cleaning, Mark::Cleaning(cause)));
    }
    if let Some(publication) = published {
        marks.push((
            publication.boundary,
            At::Published,
            Mark::Published(publication),
        ));
    }
    // Stable: marks at one boundary keep the order above, which none of
    // their checks depends on.
    marks.sort_by_key(|&(boundary, _, _)| boundary);
    let mut machine = Machine::new();
    let mut next = 0;
    let mut advance = |machine: &mut Machine, to: usize| -> Result<(), Divergence> {
        while next < to {
            machine
                .observe(&observed[next])
                .map_err(|rule| Divergence {
                    at: At::Observation(next),
                    rule,
                })?;
            next += 1;
        }
        Ok(())
    };
    for (boundary, at, mark) in marks {
        if boundary > observed.len() {
            return Err(Divergence {
                at,
                rule: Rule::BoundaryPastEnd {
                    boundary,
                    len: observed.len(),
                },
            });
        }
        advance(&mut machine, boundary)?;
        let result = match mark {
            Mark::Checkpoint => machine.checkpoint(
                &checkpoints
                    .advance()
                    .expect("each checkpoint has one mark")
                    .custody,
            ),
            Mark::Cleaning(cause) => machine.clean(cause),
            Mark::Published(publication) => machine.publish(publication),
        };
        result.map_err(|rule| Divergence { at, rule })?;
    }
    advance(&mut machine, observed.len())?;
    machine
        .quiescent()
        .map_err(|rule| Divergence { at: At::End, rule })?;
    Ok(machine)
}

/// Check `run` against the machine ([`replay`] with its checkpoints,
/// cleanup and publication), then its end against what the run reached.
/// Accepted, or the first divergence.
pub fn check(run: &Run) -> Result<(), Divergence> {
    let machine = replay(
        &run.observed,
        &mut Whole::new(&run.checkpoints),
        run.cleaning,
        run.published.as_ref(),
    )?;
    let reached = machine.reached();
    if reached != Some(run.end) {
        return Err(Divergence {
            at: At::End,
            rule: Rule::EndMismatch {
                end: run.end,
                reached,
            },
        });
    }
    Ok(())
}

/// The evidence class a recorded run establishes, its one definition:
/// [`Evidence::Observed`] for a run the machine accepts ([`check`]); a run
/// it refuses establishes no class and is never recorded.
pub fn evidence(run: &Run) -> Result<Evidence, Divergence> {
    check(run).map(|()| Evidence::Observed)
}

/// A finished session's whole stream and the custody `checkpoints` its
/// runner took, through the same transitions and the same rules as
/// [`check`] ([`replay`]): admission correspondence; every permit given
/// paid for, given its observed outcome, and released exactly once or
/// merged away; every obligation settled; every identity, family and link
/// consistent; and each checkpoint's custody the state its boundary
/// reaches. What every recorded test's evidence is checked by
/// (`tests/support/lifecycle.rs`, `recorded_run`).
pub fn settled(observed: &[Observed], checkpoints: &[Checkpoint]) -> Result<(), Divergence> {
    settled_with(observed, &mut Whole::new(checkpoints))
}

/// [`settled`] over any checkpoint source ([`Checkpoints`]): the one
/// session check, a stored history's included ([`crate::History::settled`]).
pub(crate) fn settled_with(
    observed: &[Observed],
    checkpoints: &mut impl Checkpoints,
) -> Result<(), Divergence> {
    replay(observed, checkpoints, None, None).map(|_| ())
}

/// The calls a stream attempted, in order: what a call-by-call diagnostic
/// compares.
pub fn calls(observed: &[Observed]) -> Vec<Call> {
    observed
        .iter()
        .filter_map(|observation| match observation.event {
            Event::Call(call, _) => Some(call),
            _ => None,
        })
        .collect()
}
