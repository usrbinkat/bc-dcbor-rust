//! Kani harnesses of the credit ledgers (register item 4), two obligations
//! kept apart.
//!
//! # Ledger arithmetic, over arbitrary events
//!
//! [`Ledgers`] accumulates quantities and detects arithmetic failure; it
//! does not authorize settlement (a lone spend of one value leaves A = 0,
//! C = 1, unviolated). Its reference ([`Model`]) is stated from its
//! documentation (`Ledgers`, `policy.rs:190-195`), never computed by calling
//! it, in `u128`, where no sum of at most [`EVENTS`] `u64` quantities
//! overflows:
//!
//! - an admission adds its work to A and its unheld part to C; a spend adds
//!   to C; a forfeit adds to F;
//! - an admission holding more than it admitted, in either quantity,
//!   changes nothing and sets the violation;
//! - each component of each ledger is added by its own checked add: one
//!   that would exceed `u64::MAX` is left unchanged and sets the violation,
//!   while the event's other components still advance (not all-or-nothing);
//! - the violation is sticky.
//!
//! Domain: every sequence of at most [`EVENTS`] events, each of any kind and
//! any `WriteWork`, applied through [`Ledgers::record`], the one update
//! rule. An event's obligation and forfeit rule do not enter the ledgers, so
//! each names one fixed obligation and rule.
//!
//! # Credit conservation, over legal transitions only
//!
//! `A = C + F + H` is a property of the protocol, not of the ledgers: H is
//! the outstanding obligations' remaining work. The theorem's domain is the
//! legal transitions: an admission, held or not, into a family; and a
//! settlement of an outstanding obligation, spent, forfeited or dropped
//! unsettled, whole, into its own origin, through production's custody,
//! [`Retained`] (its `spend`, `forfeit` and `Drop`, `bounded.rs`), which
//! records into the origin's ledgers. H is the model's, never read from the
//! ledgers.
//!
//! It is proved by induction, for sequences of any length: a fresh family
//! is conserved (the base case), and from any state in which every family
//! is violated or balanced, any ledger components and any outstanding
//! credit, one legal transition leaves every family so, the violation
//! sticky and the family it does not name unchanged (the step). Each
//! harness checks one transition, so its formula does not grow with a
//! sequence's length.
//!
//! Out of the domain by construction, and named: a settlement of more than
//! an obligation holds, or of an obligation that is not outstanding. Production
//! refuses each. `Retained::spend` and `Retained::forfeit` take the custody
//! by value and settle exactly what it still holds, so no settlement exceeds
//! it and none repeats (`bounded.rs`, `Retained`); the one partial spend,
//! `Retained::consume`, refuses more than it holds (`PlanMismatch`). The
//! refinement machine refuses a settlement of an unknown or settled
//! obligation (`tests/refinement/src/machine.rs:360-363`,
//! `Rule::UnknownObligation`) and one exceeding its remaining work (`:384-388`,
//! `Rule::Overdrawn`).
//!
//! Each component's update is a compare-exchange loop (`Ledgers::add_one`,
//! policy.rs:254-268); on one thread its first exchange succeeds, so it runs
//! once; the ledger harnesses' event loops and their arrays' construction
//! run at most [`EVENTS`] = 4 times: the longest, 4, and its exit,
//! `kani::unwind(5)`; the conservation step has no loop of its own. One
//! thread: nothing here is about interleavings, which are the concurrency
//! gate's. Status: written and unverified until
//! the gate runs them. Compiled only under `cfg(kani)`.

use super::{Credits, Ledgers};
use crate::bounded::{
    Credit, Forfeit, Hold, Identity, Obligation, Origin, Performer, Retained, Settled, WriteWork,
};

/// The longest sequence the harnesses range over.
const EVENTS: usize = 4;

const MAX: u128 = u64::MAX as u128;

fn settled(work: WriteWork) -> Settled {
    Settled {
        obligation: Obligation::Release,
        work,
        id: Identity::UNOBSERVED,
        acquisition: Identity::UNOBSERVED,
        permit: None,
    }
}

fn hold(work: WriteWork) -> Hold {
    Hold {
        obligation: Obligation::Release,
        work,
        id: Identity::UNOBSERVED,
        acquisition: Identity::UNOBSERVED,
    }
}

fn any_work() -> WriteWork {
    WriteWork::new(kani::any(), kani::any())
}

/// Any credit event, of any kind and work.
fn any_event() -> Credit {
    match kani::any::<u8>() % 4 {
        0 => Credit::Admit {
            work: any_work(),
            held: None,
        },
        1 => Credit::Admit {
            work: any_work(),
            held: Some(hold(any_work())),
        },
        2 => Credit::Spend(settled(any_work())),
        _ => Credit::Forfeit(settled(any_work()), Forfeit::Cancelled),
    }
}

/// The arithmetic reference: A, C and F in `u128`, values and bytes, and
/// the violation (the module's "Ledger arithmetic").
#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct Model {
    admitted: [u128; 2],
    consumed: [u128; 2],
    forfeited: [u128; 2],
    violated: bool,
}

impl Model {
    /// `work` added to `ledger`, each component by its own checked add.
    fn add(ledger: &mut [u128; 2], violated: &mut bool, work: WriteWork) {
        for (component, amount) in ledger.iter_mut().zip([work.values, work.bytes]) {
            let next = *component + u128::from(amount);
            if next > MAX {
                *violated = true;
            } else {
                *component = next;
            }
        }
    }

    fn apply(&mut self, event: Credit) {
        match event {
            Credit::Admit { work, held } => {
                let part = held.map_or(WriteWork::new(0, 0), |hold| hold.work);
                if part.values > work.values || part.bytes > work.bytes {
                    self.violated = true;
                    return;
                }
                Self::add(&mut self.admitted, &mut self.violated, work);
                Self::add(
                    &mut self.consumed,
                    &mut self.violated,
                    WriteWork::new(work.values - part.values, work.bytes - part.bytes),
                );
            }
            Credit::Spend(spent) => Self::add(&mut self.consumed, &mut self.violated, spent.work),
            Credit::Forfeit(forfeited, _) => {
                Self::add(&mut self.forfeited, &mut self.violated, forfeited.work)
            }
        }
    }

    /// The model as a snapshot, when every component fits (always, by
    /// construction).
    fn credits(&self) -> Credits {
        let narrow = |ledger: [u128; 2]| WriteWork::new(ledger[0] as u64, ledger[1] as u64);
        Credits {
            admitted: narrow(self.admitted),
            consumed: narrow(self.consumed),
            forfeited: narrow(self.forfeited),
            violated: self.violated,
        }
    }
}

/// Any sequence of at most [`EVENTS`] events.
fn any_events() -> ([Credit; EVENTS], usize) {
    let events: [Credit; EVENTS] = core::array::from_fn(|_| any_event());
    let length: usize = kani::any();
    kani::assume(length <= EVENTS);
    (events, length)
}

/// Ledger arithmetic: after every prefix of every sequence of at most
/// [`EVENTS`] events, the production snapshot is the model's, component by
/// component, partial updates on overflow included, and the violation, once
/// set, stays set.
#[kani::proof]
#[kani::unwind(5)]
fn every_event_updates_its_components_by_checked_adds() {
    let (events, length) = any_events();
    let ledgers = Ledgers::default();
    let mut model = Model::default();
    let mut was_violated = false;
    for &event in &events[..length] {
        ledgers.record(event);
        model.apply(event);
        let snapshot = ledgers.snapshot();
        assert!(
            snapshot.admitted == model.credits().admitted,
            "the admitted ledger is the events' admissions, component by component"
        );
        assert!(
            snapshot.consumed == model.credits().consumed,
            "the consumed ledger is the events' consumption, component by component"
        );
        assert!(
            snapshot.forfeited == model.credits().forfeited,
            "the forfeited ledger is the events' forfeits, component by component"
        );
        assert!(
            !was_violated || snapshot.violated,
            "the violation is sticky"
        );
        assert!(
            snapshot.violated == model.violated,
            "the violation is set exactly when a component overflows or a hold exceeds its admission"
        );
        was_violated = snapshot.violated;
    }
}

/// A violated ledger is never reported conserved, whatever held credit is
/// offered beside it: `conserved_with` is `Some(false)` or `None`, never
/// `Some(true)`.
#[kani::proof]
#[kani::unwind(5)]
fn a_violated_ledger_is_never_conserved() {
    let (events, length) = any_events();
    let ledgers = Ledgers::default();
    for &event in &events[..length] {
        ledgers.record(event);
    }
    let credits = ledgers.snapshot();
    if credits.violated {
        assert!(
            credits.conserved_with(any_work()) != Some(true),
            "a violated ledger is never reported conserved"
        );
    }
}

/// Snapshot deltas. For two snapshots of one ledger, every sequence of at
/// most [`EVENTS`] events split at any point: over an interval with no
/// violation, the later snapshot less the earlier equals the components the
/// interval's events contributed (a fresh ledger of them alone); and a
/// violation stays visible in every delta taken at or after it, never
/// attributed away.
#[kani::proof]
#[kani::unwind(5)]
fn a_delta_is_the_interval_unless_violated_and_never_hides_a_violation() {
    let (events, length) = any_events();
    let split: usize = kani::any();
    kani::assume(split <= length);
    let ledgers = Ledgers::default();
    for &event in &events[..split] {
        ledgers.record(event);
    }
    let earlier = ledgers.snapshot();
    for &event in &events[split..length] {
        ledgers.record(event);
    }
    let later = ledgers.snapshot();
    let interval = Ledgers::default();
    for &event in &events[split..length] {
        interval.record(event);
    }
    let delta = later.checked_sub(earlier);
    if !later.violated {
        assert!(
            delta == Some(interval.snapshot()),
            "over an unviolated interval a delta is the interval's contributions"
        );
    } else {
        assert!(
            delta.is_none_or(|delta| delta.violated),
            "a delta taken at or after a violation shows it"
        );
    }
}

/// An origin family of the conservation model: settlements made through
/// production's custody ([`Retained`]) are recorded into its ledgers, the
/// one update rule, as a [`super::Family`] records them. It borrows ledgers
/// the harness owns, which outlive every custody holding the origin.
struct Ledger<'l>(&'l Ledgers);

impl Origin for Ledger<'_> {
    fn family(&self) -> u64 {
        0
    }

    fn settle(&self, settled: Settled, rule: Option<Forfeit>, _by: Performer) {
        self.0.record(match rule {
            None => Credit::Spend(settled),
            Some(rule) => Credit::Forfeit(settled, rule),
        });
    }

    /// An acquisition's end moves no ledger: the model records none.
    fn end(&self, _acquisition: Identity, _owner: Identity, _by: Performer) {}
}

/// The families of the conservation step: the family a transition records
/// into and one it must leave unchanged.
const FAMILIES: usize = 2;

/// One family's outstanding credit H in the reference arithmetic: values
/// and bytes in `u128`, where the sum of any two `u64` quantities fits.
type Held = [u128; 2];

/// `left + right` in each component.
fn plus(left: Held, right: WriteWork) -> Held {
    [
        left[0] + u128::from(right.values),
        left[1] + u128::from(right.bytes),
    ]
}

/// `left - right` in each component; the caller holds `right` within
/// `left`, as an outstanding custody's remaining work is within its
/// family's H.
fn minus(left: Held, right: WriteWork) -> Held {
    [
        left[0] - u128::from(right.values),
        left[1] - u128::from(right.bytes),
    ]
}

/// Whether `credits` and `held` balance, `A = C + F + H` in values and in
/// bytes, computed in `u128`, where no sum of four `u64`-bounded quantities
/// overflows: the reference the step is held to, never production's
/// [`Credits::conserved_with`], which it checks.
fn balanced(credits: &Credits, held: Held) -> bool {
    let component = |admitted: u64, consumed: u64, forfeited: u64, held: u128| {
        u128::from(admitted) == u128::from(consumed) + u128::from(forfeited) + held
    };
    component(
        credits.admitted.values,
        credits.consumed.values,
        credits.forfeited.values,
        held[0],
    ) && component(
        credits.admitted.bytes,
        credits.consumed.bytes,
        credits.forfeited.bytes,
        held[1],
    )
}

/// The conservation invariant of one family: violated (no longer claimed
/// conserved), or balanced against its outstanding credit.
fn conserved(credits: &Credits, held: Held) -> bool {
    credits.violated || balanced(credits, held)
}

/// A family's ledgers in any state: every component any `u64`, the
/// violation flag any word (set when nonzero, `Ledgers::snapshot`). Built
/// from the ledgers' own fields, so no production constructor is widened
/// for the proof.
fn any_ledgers() -> Ledgers {
    let atomic = || crate::sync::AtomicU64::new(kani::any());
    Ledgers {
        admitted: [atomic(), atomic()],
        consumed: [atomic(), atomic()],
        forfeited: [atomic(), atomic()],
        violated: atomic(),
    }
}

/// The custody of an outstanding obligation of `remaining` work admitted
/// through `ledgers`: production's [`Retained`], which records every
/// settlement into its origin.
fn custody(ledgers: &Ledgers, remaining: WriteWork) -> Retained<Ledger<'_>> {
    Retained {
        origin: Ledger(ledgers),
        sequence: 0,
        acquisition: Identity::UNOBSERVED,
        remaining,
        obligation: Obligation::Release,
    }
}

/// The checks of one family after a step from `before`, its credit then
/// `held`: the violation sticky; and an unviolated family's outstanding
/// credit fitting in `u64` and conserved by production's own reading,
/// `conserved_with`, and by the reference.
fn holds_after(before: &Credits, after: &Credits, held: Held) {
    assert!(
        !before.violated || after.violated,
        "a violated family stays violated"
    );
    if !after.violated {
        assert!(
            held[0] <= MAX && held[1] <= MAX,
            "an unviolated family's outstanding credit fits"
        );
        assert!(
            after.conserved_with(WriteWork::new(held[0] as u64, held[1] as u64)) == Some(true)
                && balanced(after, held),
            "legal transitions conserve: A = C + F + H"
        );
    }
}

/// Conservation, base case: a family's fresh ledgers, with nothing
/// outstanding, are unviolated and conserved, `A = C + F + H = 0`.
#[kani::proof]
fn a_fresh_family_is_conserved_with_nothing_held() {
    let credits = Ledgers::default().snapshot();
    assert!(!credits.violated, "a fresh family is unviolated");
    assert!(
        credits.conserved_with(WriteWork::new(0, 0)) == Some(true) && balanced(&credits, [0, 0]),
        "legal transitions conserve: A = C + F + H"
    );
}

/// Conservation, induction step: from any state of [`FAMILIES`] families
/// in which every family is conserved ([`conserved`]), each of its ledgers'
/// components any `u64` and its outstanding credit H any sum of `u64`
/// custodies, one legal transition into one family leaves every family
/// conserved, the violation sticky, and the other family's ledgers
/// unchanged. The transitions: an admission, unheld; an admission holding
/// at most what it admits, which opens a custody of the held part; and a
/// settlement of an outstanding custody of that family through production's
/// [`Retained`]: spent, forfeited or dropped unsettled, each of the whole
/// remainder, into its own origin. Any amount is any `u64` per component,
/// overflow included: a quantity that does not fit violates its family.
///
/// With the base case ([`a_fresh_family_is_conserved_with_nothing_held`]),
/// every finite sequence of legal transitions from fresh families conserves
/// every unviolated family, at any length: no bound on the events is part
/// of the theorem.
///
/// Its loops are only each component's compare-exchange (`Ledgers::add_one`),
/// whose first exchange succeeds on one thread, so its backedge is never
/// taken; `kani::unwind(5)` is its siblings' bound, its unwinding assertions
/// checking that no loop the run reaches takes more.
#[kani::proof]
#[kani::unwind(5)]
fn every_legal_transition_preserves_conservation() {
    // The ledgers outlive every custody admitted through them, as a family's
    // counters outlive its obligations.
    let ledgers: [Ledgers; FAMILIES] = [any_ledgers(), any_ledgers()];
    let family = usize::from(kani::any::<bool>());
    let other = 1 - family;
    let kind = kani::any::<u8>() % 5;
    // A settlement's custody is one of its family's outstanding
    // obligations, its remaining work within that family's H.
    let settled = any_work();
    let rest = [any_work(), any_work()];
    let mut held: [Held; FAMILIES] = [plus([0, 0], rest[0]), plus([0, 0], rest[1])];
    if kind >= 2 {
        held[family] = plus(held[family], settled);
    }
    let before = [ledgers[0].snapshot(), ledgers[1].snapshot()];
    kani::assume(conserved(&before[0], held[0]) && conserved(&before[1], held[1]));
    match kind {
        0 => ledgers[family].record(Credit::Admit {
            work: any_work(),
            held: None,
        }),
        1 => {
            // A legal held admission holds at most what it admits.
            let work = any_work();
            let part = any_work();
            kani::assume(part.values <= work.values && part.bytes <= work.bytes);
            ledgers[family].record(Credit::Admit {
                work,
                held: Some(hold(part)),
            });
            let opened = custody(&ledgers[family], part);
            assert!(
                opened.remaining() == part,
                "an outstanding custody holds the model's remaining work"
            );
            held[family] = plus(held[family], part);
            // Still outstanding: its credit is the family's H, never settled
            // by this step.
            core::mem::forget(opened);
        }
        _ => {
            let outstanding = custody(&ledgers[family], settled);
            assert!(
                outstanding.remaining() == settled,
                "an outstanding custody holds the model's remaining work"
            );
            match kind {
                2 => outstanding.spend(None, Performer::None),
                3 => outstanding.forfeit(Forfeit::Cancelled, None, Performer::None),
                _ => drop(outstanding),
            }
            held[family] = minus(held[family], settled);
        }
    }
    let after = [ledgers[0].snapshot(), ledgers[1].snapshot()];
    assert!(
        after[other] == before[other],
        "a transition records into its own family alone"
    );
    holds_after(&before[0], &after[0], held[0]);
    holds_after(&before[1], &after[1], held[1]);
}
