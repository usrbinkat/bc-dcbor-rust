//! User-defined construction-state destructors must never become cleanup.
use super::*;
use dcbor::bounded::Allocator;
use dcbor::bounded::decode::Kind;
use dcbor::bounded::decode::construction::in_place::{
    BindingContext, Building, TreeKey, TreeKeyView, build_part, observe_part, reclaim_part,
    remaining_part, reported,
};
use dcbor::bounded::decode::construction::reclamation::{Cleanup, Written};
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
    // Its own level and the wrapped scalar's, dispatched as a part.
    const DISPATCH_DEPTH: usize = <u64 as Reclaim<A>>::DISPATCH_DEPTH + 1;
    type State = State;
    const INITIAL: State = State(Written::Empty);

    fn reclaim_step(
        slot: Slot<'_, Self, State>,
        cleanup: &mut Cleanup<'_, A>,
    ) -> BoundedResult<Reclaimed, A> {
        // SAFETY: transparent representation and the matching u64 state.
        let scalar = unsafe { slot.child(|value| value.cast::<u64>(), |state| &mut state.0) };
        reclaim_part::<u64, A>(scalar, cleanup)
    }

    /// The wrapped scalar's own count.
    fn remaining(slot: PeekSlot<'_, Self, State>) -> Option<u64> {
        // SAFETY: transparent representation and the matching u64 state; the
        // cast is the projection construction and cleanup use.
        let scalar = unsafe { slot.child(|value| value.cast::<u64>(), |state| &mut state.0) };
        remaining_part::<u64, A>(scalar)
    }

    /// The wrapped scalar's own permits: none.
    fn observe_permits(
        slot: PeekSlot<'_, Self, State>,
        sink: &mut dyn CustodySink<A::Permit>,
    ) -> PermitsObserved {
        // SAFETY: transparent representation and the matching u64 state; the
        // cast is the projection construction and cleanup use.
        let scalar = unsafe { slot.child(|value| value.cast::<u64>(), |state| &mut state.0) };
        observe_part::<u64, A>(scalar, sink)
    }
}

// SAFETY: transparent representation preserves u64's stable destination and
// initialization contract, including its cost and all partial states.
unsafe impl<A: Allocator> InPlace<A> for Value {
    const COST: ConstructionCost = <u64 as InPlace<A>>::COST;

    fn build_step<'b>(
        ctx: BindingContext<'b, '_, '_, '_, Self, A>,
        a: &mut A,
    ) -> ConstructResult<Building<'b, Self>, A> {
        let mut ctx = ctx;
        let assembly = ctx.assembly();
        let index = ctx.index();
        // SAFETY: transparent representation and the matching u64 state,
        // projected from this value's own slot: the scalar is a part of the
        // value, from the same node.
        let scalar = match unsafe {
            ctx.part(index, |slot| {
                Ok::<_, core::convert::Infallible>(
                    slot.child(|value| value.cast::<u64>(), |state| &mut state.0),
                )
            })
        } {
            Ok(scalar) => scalar,
            Err(never) => match never {},
        };
        let built = build_part::<u64, A>(scalar, a)?;
        // SAFETY: `Done` is reported only once `build_part` verified the
        // scalar's record against its place, this value's own by the
        // transparent representation, so the value is initialized whole.
        Ok(unsafe { reported(built, assembly) })
    }
}

/// The tree's decode stopped at turn `stop`, cancelled with its cleanup or,
/// when `terminal`, dropped with its scope, as one recorded run whose
/// finalizer refines the stream at quiescence: the turn it ended at, and the
/// boundary valuations the run reached.
fn run(stop: Option<usize>, terminal: bool) -> (usize, dcbor::bounded::boundary::Reached) {
    // Twelve entries require internal nodes and relocation of custody
    // records.
    let mut wire = vec![0xac];
    for key in 0..12u8 {
        wire.extend_from_slice(&[key, key]);
    }
    let bound = support::typed_turns::<BTreeMap<Value, Value>>(wire.len());
    support::recorded_run(|run| {
        let policy = run.policy(u64::MAX);
        let turn = run.holding(
            dcbor::bounded::decode::construction::DecodeOwner::<'static, Limits>::new(),
            Retirement::Scope,
            &Unwitnessed,
            |owner| {
                owner.initialize(policy)?;
                let turn = owner.decoder::<_, BTreeMap<Value, Value>, _, _>(
                    policy,
                    support::Copying(&wire),
                    Options::normalizing(8),
                    &Unwitnessed,
                    |decoder| {
                        let mut turn = 0;
                        let published = decoder.controlled(
                            policy,
                            bound,
                            Retirement::Published,
                            true,
                            |_, _, at| {
                                turn = at;
                                stop == Some(at)
                            },
                            |value| {
                                for key in 0..12u64 {
                                    assert_eq!(
                                        value.value().value().get(&Value(key)).unwrap().0,
                                        key
                                    );
                                }
                            },
                        )?;
                        if published.is_some() {
                            assert!(stop.is_none(), "requested cancellation was not observed");
                        } else {
                            assert_eq!(stop, Some(turn), "decode stopped at another boundary");
                            if !terminal {
                                decoder.value().cancel();
                                decoder.finish(policy, bound, Retirement::Published)?;
                            }
                        }
                        Ok::<_, Finding>(turn)
                    },
                )??;
                if !terminal {
                    owner.drain(policy)?;
                }
                Ok::<_, Finding>(turn)
            },
        )?;
        run.with_policy(policy, |m| {
            assert_eq!(m.live_bytes(), 0);
            Ok((turn, m.reached()))
        })
    })
}

/// The tree's decode stopped after every number of turns through its
/// publication ([`support::stop_matrix`]), each stop both a cancellation
/// with its cleanup and a terminal drop of the decoder and the scope: no
/// construction state's destructor runs, and everything is recovered.
#[test]
fn tree_custody_never_drops_child_states() {
    let (last, _) = run(None, false);
    assert_eq!(run(None, true).0, last);
    support::stop_matrix("a tree decode stopped", last, |turn| {
        let (cancelled, by_cancellation) = run(Some(turn), false);
        assert_eq!(cancelled, turn);
        let (dropped, by_drop) = run(Some(turn), true);
        assert_eq!(dropped, turn);
        by_cancellation.union(by_drop)
    });
}
