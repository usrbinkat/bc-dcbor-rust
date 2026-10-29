//! User-defined construction-state destructors must never become cleanup.
use super::*;
use dcbor::bounded::decode::Kind;
use dcbor::bounded::decode::construction::in_place::{TreeKey, TreeKeyView};
use dcbor::bounded::decode::construction::reclamation::Written;
use std::collections::BTreeMap;

#[repr(transparent)]
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Value(u64);

// SAFETY: the transparent value uses exactly u64's construction and ordering.
unsafe impl TreeKey for Value {
    fn view(kind: Kind<'_>) -> Option<TreeKeyView<'_>> {
        u64::view(kind)
    }
}

struct State(Written);

/// The wrapped scalar state's custody, observed through it.
impl Custody for State {
    type Observation = Written;

    fn observe(&mut self) -> Written {
        self.0.observe()
    }
}

impl Drop for State {
    fn drop(&mut self) {
        panic!("B-tree cleanup invoked a construction-state destructor");
    }
}

// SAFETY: Value has exactly u64's representation and no additional resources.
// All reclamation is delegated to u64; the enclosing state needs no Drop.
unsafe impl<A: Allocator> Reclaim<A> for Value {
    type State = State;
    const INITIAL: State = State(Written::Empty);

    fn reclaim_step(slot: Slot<'_, Self, State>, a: &mut A) -> BoundedResult<Reclaimed, A> {
        // SAFETY: transparent representation and the matching u64 state.
        let scalar = unsafe { slot.child(|value| value.cast::<u64>(), |state| &mut state.0) };
        u64::reclaim_step(scalar, a)
    }

    /// The wrapped scalar's own count.
    fn remaining(slot: PeekSlot<'_, Self, State>) -> u64 {
        // SAFETY: transparent representation and the matching u64 state; the
        // cast is the projection construction and cleanup use.
        let scalar = unsafe { slot.child(|value| value.cast::<u64>(), |state| &mut state.0) };
        <u64 as Reclaim<A>>::remaining(scalar)
    }
}

// SAFETY: transparent representation preserves u64's stable destination and
// initialization contract, including its cost and all partial states.
unsafe impl<A: Allocator> InPlace<A> for Value {
    const COST: ConstructionCost = <u64 as InPlace<A>>::COST;

    fn build_step(
        document: &Document<'_, A::Permit>,
        index: usize,
        slot: Slot<'_, Self, State>,
        a: &mut A,
    ) -> ConstructResult<Built, A> {
        // SAFETY: transparent representation and the matching u64 state.
        let scalar = unsafe { slot.child(|value| value.cast::<u64>(), |state| &mut state.0) };
        u64::build_step(document, index, scalar, a)
    }
}

fn run(stop: Option<usize>, terminal: bool) -> usize {
    let mut m = meter();
    let mut owner = scope(&mut m);
    // Twelve entries require internal nodes and relocation of custody records.
    let mut wire = vec![0xac];
    for key in 0..12u8 {
        wire.extend_from_slice(&[key, key]);
    }
    let input = support::copy(&owner, &mut m, &wire);
    let mut decoder =
        TypedDecoder::<_, BTreeMap<Value, Value>, Limits>::new(input, Options::normalizing(8));
    let bound = support::typed_turns::<BTreeMap<Value, Value>>(wire.len());
    for turn in 0..bound {
        if stop == Some(turn) {
            if terminal {
                drop(decoder);
                // Exercise the owner's non-refusing terminal cleanup too.
                drop(owner);
                assert_eq!(m.live_bytes(), 0);
                return turn;
            }
            decoder.cancel();
            support::finish_within(&mut m, &mut decoder, bound);
            drop(decoder);
            drain(&mut owner, &mut m);
            assert_eq!(m.live_bytes(), 0);
            return turn;
        }
        match support::checked(&mut m, |m| support::contracted(m, &mut decoder)) {
            Ok(Step::Progress) => {}
            Err(error) if support::ordinary_exhaustion(&m, &error) => {}
            Ok(Step::Complete(value)) => {
                assert!(stop.is_none(), "requested cancellation was not observed");
                for key in 0..12u64 {
                    assert_eq!(value.value().get(&Value(key)).unwrap().0, key);
                }
                drop(value);
                drop(decoder);
                if terminal {
                    drop(owner);
                } else {
                    drain(&mut owner, &mut m);
                }
                assert_eq!(m.live_bytes(), 0);
                return turn;
            }
            other => panic!(
                "unexpected decode outcome: {}",
                match other {
                    Ok(_) => "finished without publication",
                    Err(_) => "decode failed",
                }
            ),
        }
    }
    panic!("tree construction exceeded the typed decode's bound");
}

/// The tree's decode stopped after every number of turns through its
/// publication ([`support::stop_matrix`]), each stop both a cancellation
/// with its cleanup and a terminal drop of the decoder and the scope: no
/// construction state's destructor runs, and everything is recovered.
#[test]
fn tree_custody_never_drops_child_states() {
    let last = run(None, false);
    assert_eq!(run(None, true), last);
    support::stop_matrix("a tree decode stopped", last, |turn| {
        assert_eq!(run(Some(turn), false), turn);
        assert_eq!(run(Some(turn), true), turn);
    });
}
