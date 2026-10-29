//! Shared-owner independence and cross-thread plan retirement through the
//! production owned pipeline. No test-owned lifecycle substitute is used.
#![cfg(feature = "std")]
#![forbid(unsafe_code)]
use dcbor::ByteString;
use dcbor::bounded::decode::Options;
use dcbor::bounded::decode::construction::reclamation::Reclaimed;
use dcbor::bounded::decode::construction::{DecodeOwner, TypedValue};
use dcbor::bounded::encoding::{OwnedPreparation, OwnedPrepared};
use dcbor::bounded::{Limits, Step};
use dcbor_test_support as support;

fn meter() -> Limits {
    Limits::unlimited().logged().strict()
}

/// `text` decoded into a value held by `owner`'s scope.
fn decoded(
    owner: &DecodeOwner<'static, Limits>,
    m: &mut Limits,
    text: &str,
) -> TypedValue<'static, ByteString, String, Limits> {
    let wire = dcbor::CBOR::from(text).to_cbor_data();
    let input = support::copy(owner, m, &wire);
    support::decode(m, input, Options::normalizing(8)).expect("typed construction failed")
}

/// One checked turn of an optional preparation; its plan once published, the
/// preparation then retired.
fn advance(
    m: &mut Limits,
    operation: &mut Option<OwnedPreparation<'static, ByteString, String, Limits>>,
) -> Option<OwnedPrepared<'static, ByteString, String, Limits>> {
    let preparation = operation.as_mut()?;
    match support::checked(m, |m| support::contracted(m, preparation)) {
        Ok(Step::Progress) => None,
        Ok(Step::Complete(plan)) => {
            support::exhausted(m, preparation);
            *operation = None;
            Some(plan)
        }
        Err(error) if support::ordinary_exhaustion(m, &error) => None,
        other => panic!("preparation failed: {}", support::label(&other)),
    }
}

/// The turns preparing `value` may take: its owned preparation's bound
/// (`encoding::owned_prepare_bound`) of the value's own shape.
fn preparation_turns(value: &TypedValue<'static, ByteString, String, Limits>) -> usize {
    support::turns(
        dcbor::bounded::encoding::owned_prepare_bound::<ByteString, String, Limits, ()>(
            support::shape(value.value()),
        )
        .expect("the preparation bound of a decoded value fits in u64"),
    )
}

/// The order in which two preparations sharing a scope take their turns,
/// which places the first's retirement relative to the second's life: before
/// it begins, while it is in flight with either leading, or after it
/// publishes. Each preparation's own turns are fixed by its value, so these
/// four orders are every relation the retirement can have to the other
/// operation.
#[derive(Clone, Copy, Debug)]
enum Interleaving {
    /// The first takes every turn it has, then the second: the first is
    /// retired before the second begins.
    FirstThenSecond,
    /// The second publishes, then the first takes its turns: the first is
    /// retired once the second's plan is live.
    SecondThenFirst,
    /// Turn about, the first leading: the first is retired while the second
    /// is in flight.
    AlternatingFirst,
    /// Turn about, the second leading.
    AlternatingSecond,
}

const INTERLEAVINGS: [Interleaving; 4] = [
    Interleaving::FirstThenSecond,
    Interleaving::SecondThenFirst,
    Interleaving::AlternatingFirst,
    Interleaving::AlternatingSecond,
];

impl Interleaving {
    /// Whether the first preparation takes turn `turn`, counted from zero,
    /// given which of the two are still live: always a live one.
    fn first(self, turn: usize, first: bool, second: bool) -> bool {
        match self {
            Self::FirstThenSecond => first,
            Self::SecondThenFirst => !second,
            Self::AlternatingFirst if first && second => turn.is_multiple_of(2),
            Self::AlternatingSecond if first && second => !turn.is_multiple_of(2),
            Self::AlternatingFirst | Self::AlternatingSecond => first,
        }
    }
}

/// Prepare two values in one scope in `interleaving`, retiring the first
/// preparation after its `cut`th turn while the second continues and the
/// scope drains the first's records between turns. Returns the first
/// preparation's turns.
fn interleave(cut: Option<usize>, interleaving: Interleaving) -> usize {
    let mut m = meter();
    let mut owner = support::scope(&mut m);
    let first = decoded(&owner, &mut m, "\u{301}\u{301}\u{301}");
    let second = decoded(&owner, &mut m, "independent value");
    // Every turn advances one live preparation, so their bounds together
    // bound the turns.
    let turns = preparation_turns(&first) + preparation_turns(&second);
    let mut a = Some(OwnedPreparation::prepare(first));
    let mut b = Some(OwnedPreparation::prepare(second));
    let mut plan_a = None;
    let mut plan_b = None;
    let mut a_turns = 0;
    for turn in 0..turns {
        if cut == Some(a_turns) {
            a = None;
        }
        if interleaving.first(turn, a.is_some(), b.is_some()) {
            a_turns += 1;
            if let Some(plan) = advance(&mut m, &mut a) {
                plan_a = Some(plan);
            }
        } else if let Some(plan) = advance(&mut m, &mut b) {
            plan_b = Some(plan);
        }
        // Drain the first's retired records while the second stays live.
        match support::scope_checked(&mut m, &mut owner, |owner, m| owner.step(m)) {
            Ok(Reclaimed::Progress | Reclaimed::Waiting | Reclaimed::Done) => {}
            Err(error) if support::ordinary_exhaustion(&m, &error) => {}
            Err(error) => panic!("interleaved cleanup failed: {error:?}"),
        }
        if a.is_none() && b.is_none() {
            break;
        }
    }
    assert!(
        a.is_none() && b.is_none(),
        "finite shared-owner preparation"
    );
    let plan_b = plan_b.expect("the second must publish despite the first's retirement");
    let len = plan_b.len();
    let bytes = support::emit(&mut m, &mut plan_b.into_writer(), len);
    assert_eq!(bytes, dcbor::CBOR::from("independent value").to_cbor_data());
    drop(plan_a);
    support::drain(&mut owner, &mut m);
    assert_eq!(m.live_bytes(), 0);
    a_turns
}

/// The first preparation retired at each of its boundaries, in every
/// interleaving with the second: the second publishes its exact bytes and the
/// scope recovers everything. A preparation's boundaries declare no cleanup
/// class, so every boundary runs in both layers.
#[test]
fn retiring_each_preparation_boundary_preserves_other_operations() {
    let turns = interleave(None, Interleaving::FirstThenSecond);
    assert!(turns > 0);
    for interleaving in INTERLEAVINGS {
        assert_eq!(
            interleave(None, interleaving),
            turns,
            "{interleaving:?}: the first preparation's turns depend on the other's"
        );
    }
    let mut progress = support::rigor::Progress::new("a preparation retired beside another");
    progress.stage(
        "every boundary in every interleaving",
        turns * INTERLEAVINGS.len(),
        turns * INTERLEAVINGS.len(),
    );
    for cut in 0..turns {
        for interleaving in INTERLEAVINGS {
            progress.case(format!("retired after {cut} turns, {interleaving:?}"));
            interleave(Some(cut), interleaving);
        }
    }
}

#[test]
fn cross_thread_plan_retirement_races_with_shutdown_without_double_release() {
    use std::sync::{Arc, Barrier};
    for reverse in [false, true] {
        let mut m = meter();
        let mut owner = support::scope(&mut m);
        let values = [
            decoded(&owner, &mut m, "first"),
            decoded(&owner, &mut m, "second"),
        ];
        let mut plans = Vec::new();
        for value in values {
            let bound = preparation_turns(&value);
            plans.push(
                support::drive_within(&mut m, &mut OwnedPreparation::prepare(value), bound)
                    .expect("preparation failed"),
            );
        }
        if reverse {
            plans.reverse();
        }
        let barrier = Arc::new(Barrier::new(3));
        std::thread::scope(|scope| {
            for plan in plans {
                let barrier = barrier.clone();
                scope.spawn(move || {
                    barrier.wait();
                    drop(plan);
                });
            }
            assert_ne!(
                support::scope_checked(&mut m, &mut owner, |owner, m| owner.shutdown_step(m)).ok(),
                Some(Reclaimed::Done),
                "shutdown completed with live plans"
            );
            barrier.wait();
            // Draining overlaps the retiring workers; the joins precede the
            // final drain, so scheduler starvation is not mistaken for a leak.
            for _ in 0..64 {
                match support::scope_checked(&mut m, &mut owner, |owner, m| owner.step(m)) {
                    Ok(_) => {}
                    Err(error) if support::ordinary_exhaustion(&m, &error) => {}
                    Err(error) => panic!("overlapping cleanup failed: {error:?}"),
                }
            }
        });
        support::drain(&mut owner, &mut m);
        assert_eq!(m.live_bytes(), 0);
    }
}

/// Every turn of a map's preparation taken on a worker thread of its own,
/// the suspended preparation moved between them. The test requires a
/// retained entry cursor and a retained normalization each to cross a worker
/// boundary. At minimal witness sizes the map holds 12 entries, the fewest
/// whose tree has an internal node (a full leaf holds 11), each value of 16
/// mark pairs as at full sizes: the reach map requires every region the full
/// sizes execute (`tests/reach-map.sh`), and two entries of four pairs left
/// the tree's internal-node paths, the one-byte text head and the
/// character arena's later growth unexecuted.
#[test]
#[cfg(feature = "custom-std-collections")]
fn suspended_entry_cursors_and_texts_transfer_between_workers() {
    use dcbor_test_support::rigor::sized;
    use std::collections::BTreeMap;
    let (entries, pairs) = sized((16, 16), (12, 16));
    let source: BTreeMap<String, String> = (0..entries)
        .map(|index| {
            (
                format!("key-{index:02}"),
                format!("q{}", "\u{301}\u{316}".repeat(pairs)),
            )
        })
        .collect();
    let mut symbolic = dcbor::Map::new();
    for (key, value) in &source {
        symbolic.insert(key.clone(), value.clone());
    }
    let wire = dcbor::CBOR::from(symbolic).to_cbor_data();
    let mut m = meter();
    let mut owner = support::scope(&mut m);
    let input = support::copy(&owner, &mut m, &wire);
    let value: TypedValue<'static, ByteString, BTreeMap<String, String>, Limits> =
        support::decode(&mut m, input, Options::normalizing(16)).expect("map decode");
    let turns = support::turns(
        dcbor::bounded::encoding::owned_prepare_bound::<
            ByteString,
            BTreeMap<String, String>,
            Limits,
            (),
        >(support::shape(value.value()))
        .expect("the preparation bound of a decoded map fits in u64"),
    );
    let mut operation = OwnedPreparation::prepare(value);
    let mut published = None;
    let mut observed_cursor = false;
    let mut observed_normalization = false;
    for _ in 0..turns {
        if let Some(position) = operation.position().detail.preparation {
            observed_cursor |= position.cursors != 0;
            observed_normalization |= position.normalizing && position.normalization.is_some();
        }
        let (next, next_meter, output) = std::thread::spawn(move || {
            let output = match support::checked(&mut m, |m| support::contracted(m, &mut operation))
            {
                Ok(Step::Complete(plan)) => Some(plan),
                Ok(Step::Progress) => None,
                Err(error) if support::ordinary_exhaustion(&m, &error) => None,
                other => panic!("worker preparation: {}", support::label(&other)),
            };
            (operation, m, output)
        })
        .join()
        .expect("worker panicked");
        operation = next;
        m = next_meter;
        if output.is_some() {
            published = output;
            break;
        }
    }
    drop(operation);
    let plan = published.expect("finite transferable preparation");
    let len = plan.len();
    let bytes = support::emit(&mut m, &mut plan.into_writer(), len);
    support::drain(&mut owner, &mut m);
    assert_eq!(bytes, wire);
    assert_eq!(m.live_bytes(), 0);
    assert!(
        observed_cursor,
        "no retained cursor crossed a worker boundary"
    );
    assert!(
        observed_normalization,
        "no retained normalization crossed a worker boundary"
    );
}
