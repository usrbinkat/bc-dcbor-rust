//! Public lifecycle gates for stable construction and retained reclamation.
//! These use the current public boundary; no substitute cleanup engine is used.
#![cfg(feature = "std")]
// The maximum-dispatch-depth fixture composes each child's full observation.
#![recursion_limit = "256"]

// The pipeline matrix fails each physical request through the observer.
#[global_allocator]
static HEAP: support::heap::Heap = support::heap::Heap;

use dcbor::bounded::decode::construction::in_place::{
    BindingContext, Building, ConstructionCost, InPlace, Transferable, admit, unit,
};
use dcbor::bounded::decode::construction::reclamation::{
    Cleanup, Custody, PeekSlot, Reclaim, Reclaimed, Slot,
};
use dcbor::bounded::decode::construction::{Borrowed, TypedValue};
use dcbor::bounded::decode::{ConstructResult, DecodeError, Options, wrong_type};
use dcbor::bounded::{Allocator, CustodySink, Limits, PermitsObserved};
use dcbor_test_support::{
    self as support, Borrowing, Finding, Lent, Retirement, Stopped, pipeline::Unwitnessed,
};
use std::cell::Cell;
use std::ptr::addr_of_mut;

thread_local! {
    static STARTS: Cell<usize> = const { Cell::new(0) };
    static DROPS: Cell<usize> = const { Cell::new(0) };
    static INITIALIZED: Cell<usize> = const { Cell::new(0) };
}

struct Probe {
    construction_address: usize,
    inline: [u8; 256],
}

impl Drop for Probe {
    fn drop(&mut self) {
        DROPS.set(DROPS.get() + 1);
    }
}

/// A [`Probe`]'s construction state: whether its address was written, and
/// the bytes of its inline payload initialized.
struct ProbeState {
    started: bool,
    written: usize,
}

/// Whether the address was written and how many payload bytes are: the
/// probe's whole custody.
impl Custody for ProbeState {
    type Observation = (bool, usize);

    fn observe(&mut self) -> (bool, usize) {
        (self.started, self.written)
    }
}

// SAFETY: each admitted unit initializes at most 64 bytes in the final slot.
// The retained state describes the byte prefix even when construction fails.
unsafe impl<A: Allocator> InPlace<A> for Probe {
    // Build: the address write, four 64-byte units and the final unit;
    // cleanup: four 64-byte units, or one unit before any byte.
    // Eight 64-byte units in all, four each way, beside the address write
    // and the empty cleanup unit.
    const COST: ConstructionCost = ConstructionCost::fixed(dcbor::const_cost!(
        dcbor::const_cost!(unit(64).checked_mul(8)).checked_add(dcbor::const_cost!(
            unit(std::mem::size_of::<usize>()).checked_add(unit(0))
        ))
    ));

    /// A third-party binding admits its own construction through the one
    /// route ([`admit`]), as `InPlace` documents.
    fn build_step<'b>(
        ctx: BindingContext<'b, '_, '_, '_, Self, A>,
        allocator: &mut A,
    ) -> ConstructResult<Building<'b, Self>, A> {
        let assembly = ctx.assembly();
        let node = ctx.node();
        let mut slot = ctx.into_slot();
        let (place, state) = slot.parts();
        // Each field is written by raw projection alone, never through a
        // reference to the partly initialized probe.
        let raw = place.as_ptr(state);
        if !state.started {
            admit(allocator, std::mem::size_of::<usize>())?;
            // SAFETY: a plain field of the slot's own destination, written by
            // raw projection.
            unsafe {
                addr_of_mut!((*raw).construction_address).write(raw as usize);
            }
            STARTS.set(STARTS.get() + 1);
            state.started = true;
            return Ok(Building::Progress);
        }
        if state.written < 256 {
            admit(allocator, 64)?;
            // SAFETY: the next 64 bytes of the inline payload, within its 256,
            // written by raw projection.
            unsafe {
                addr_of_mut!((*raw).inline)
                    .cast::<u8>()
                    .add(state.written)
                    .write_bytes(0x5a, 64);
            }
            state.written += 64;
            if state.written == 64 {
                INITIALIZED.set(INITIALIZED.get() + 1);
            }
            return Ok(Building::Progress);
        }
        admit(allocator, 0)?;
        if node.is_some_and(|node| node.encoded() == [0xf4]) {
            return Err(wrong_type());
        }
        // SAFETY: the address and all 256 payload bytes are written, each by
        // an admitted unit recorded in this state, and the probe holds no
        // other field; the slot is not reclaimed while it builds.
        Ok(Building::Done(unsafe { assembly.assemble() }))
    }
}

// SAFETY: the payload owns only plain bytes. Invalidate the initialized prefix
// in admitted units, without invoking its deliberately instrumented Drop.
unsafe impl<A: Allocator> Reclaim<A> for Probe {
    type State = ProbeState;
    const INITIAL: ProbeState = ProbeState {
        started: false,
        written: 0,
    };

    /// A third-party binding admits its own cleanup through the one route
    /// ([`admit`]), as `Reclaim` documents.
    fn reclaim_step(
        mut slot: Slot<'_, Self, ProbeState>,
        cleanup: &mut Cleanup<'_, A>,
    ) -> dcbor::bounded::BoundedResult<Reclaimed, A> {
        let state = slot.custody();
        let bytes = state.written.min(64);
        admit(cleanup, bytes)?;
        state.written -= bytes;
        if state.written == 0 {
            state.started = false;
            Ok(Reclaimed::Done)
        } else {
            Ok(Reclaimed::Progress)
        }
    }

    /// One call per 64-byte chunk written, and one for an empty prefix,
    /// whose call reports `Done` at once.
    fn remaining(mut slot: PeekSlot<'_, Self, ProbeState>) -> Option<u64> {
        Some((slot.custody().written.div_ceil(64) as u64).max(1))
    }

    /// The probe's bytes are inline: it owns no permit.
    fn observe_permits(
        _: PeekSlot<'_, Self, ProbeState>,
        _: &mut dyn CustodySink<A::Permit>,
    ) -> PermitsObserved {
        PermitsObserved::Complete
    }
}

/// `wire`, borrowed into a scope of a recorded run, decoded as `T` under
/// `options` ([`support::Holding::decoded`]), the published value held for
/// `body` and retired as a published handle, which releases nothing; the
/// scope then drains to nothing. The decode's own error is the run's
/// finding.
fn decoded<T: Transferable<Limits> + 'static, R>(
    wire: &[u8],
    options: Options,
    body: impl FnOnce(&TypedValue<'_, Borrowed<'_>, T, Limits>) -> R,
) -> R {
    support::recorded_run(|run| {
        let policy = run.policy(u64::MAX);
        let made = run.scoped(policy, &Unwitnessed, |owner| {
            owner
                .decoded::<T, _>(policy, wire, options, |output| body(output.value()))?
                .map_err(support::failed("the typed decode"))
        })?;
        run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0));
        Ok(made)
    })
}

#[test]
fn construction_initialization_requires_an_admitted_turn() {
    STARTS.set(0);
    let starts = support::recorded_run(|run| {
        let policy = run.policy(u64::MAX);
        run.scoped(policy, &Unwitnessed, |owner| {
            owner.decoder::<_, Probe, _, _>(
                policy,
                Borrowing(&[0xf6]),
                Options::normalizing(8),
                &Unwitnessed,
                |_| STARTS.get(),
            )
        })
    });
    assert_eq!(starts, 0, "new ran custom initialization without admission");
}

#[test]
fn publication_preserves_the_initialized_value_address() {
    let (constructed, published) =
        decoded::<Probe, _>(&[0xf6], Options::normalizing(8), |output| {
            assert_eq!(output.value().inline, [0x5a; 256]);
            assert_eq!(output.bytes(), [0xf6]);
            (
                output.value().construction_address,
                std::ptr::from_ref(output.value()) as usize,
            )
        });
    assert_eq!(
        constructed, published,
        "completion moved the initialized value"
    );
}

#[test]
fn dropping_output_does_not_execute_a_value_destructor() {
    DROPS.set(0);
    decoded::<Probe, _>(&[0xf6], Options::normalizing(8), |_| {
        assert_eq!(DROPS.get(), 0)
    });
    assert_eq!(
        DROPS.get(),
        0,
        "output Drop performed unadmitted reclamation"
    );
}

#[test]
fn published_handle_size_is_independent_of_inline_payload() {
    let small = std::mem::size_of::<TypedValue<'_, Borrowed<'_>, u8, Limits>>();
    let large = std::mem::size_of::<TypedValue<'_, Borrowed<'_>, Probe, Limits>>();
    assert_eq!(
        small, large,
        "publication carries the schema instead of an owning handle"
    );
}

/// The fault matrix of decoding a probe from a literal null through a custom
/// input ([`support::pipeline::matrix`]): every admission refused once in
/// one run and resumed without replaying committed work, each also in a run
/// of its own in the exhaustive layer; every physical request failed; and a
/// retire, an unwind and a cancellation at the decode's boundaries, every
/// construction boundary among them since the probe declares no reduction.
/// In every run no probe is destroyed by `Drop`; a published probe was
/// started once, is whole, and sits at the address it was built at; and some
/// stop reaches a partially written probe.
#[test]
fn every_probe_lifecycle_fault_keeps_custody_without_destructors() {
    use support::classes::parsed;
    use support::pipeline::{Expected, decode, matrix};
    use support::rigor::rigor;
    let partial = Cell::new(false);
    matrix("probe decode", rigor(), Expected::Complete, |schedule| {
        STARTS.set(0);
        DROPS.set(0);
        INITIALIZED.set(0);
        let report = decode::<Probe>(
            &[0xf6],
            Options::normalizing(8),
            schedule,
            &parsed::<Probe>(),
            |probe| {
                assert_eq!(probe.inline, [0x5a; 256]);
                assert_eq!(
                    probe.construction_address,
                    std::ptr::from_ref(probe) as usize,
                    "publication moved the probe"
                );
            },
        );
        if report.complete {
            assert_eq!(STARTS.get(), 1, "the probe was started more than once");
        }
        assert_eq!(DROPS.get(), 0, "a probe was destroyed by Drop");
        if report.stopped && INITIALIZED.get() > 0 {
            partial.set(true);
        }
        report
    });
    assert!(partial.get(), "no stop reached partial-value custody");
}

#[cfg(feature = "derive")]
mod large_schema {
    use super::*;
    use dcbor::bounded::decode::construction::TypedDecoder;

    macro_rules! record {
        ($($name:ident = $key:literal),* $(,)?) => {
            #[derive(dcbor::CBORBoundedDecodable)]
            struct Large {
                $(#[cbor(n = $key)] $name: u64,)*
            }
            impl Large {
                fn assert_literal_fields(&self) {
                    $(assert_eq!(self.$name, $key);)*
                }
            }
        };
    }

    record! {
        f00 = 0, f01 = 1, f02 = 2, f03 = 3,
        f04 = 4, f05 = 5, f06 = 6, f07 = 7,
        f08 = 8, f09 = 9, f10 = 10, f11 = 11,
        f12 = 12, f13 = 13, f14 = 14, f15 = 15,
        f16 = 16, f17 = 17, f18 = 18, f19 = 19,
        f20 = 20, f21 = 21, f22 = 22, f23 = 23,
        f24 = 24, f25 = 25, f26 = 26, f27 = 27,
        f28 = 28, f29 = 29, f30 = 30, f31 = 31,
    }

    #[test]
    fn large_schema_fixture_has_independent_literal_field_values() {
        let mut wire = vec![0xb8, 32];
        for key in 0u8..32 {
            for _ in 0..2 {
                if key >= 24 {
                    wire.push(0x18);
                }
                wire.push(key);
            }
        }
        decoded::<Large, _>(&wire, Options::normalizing(8), |output| {
            output.value().assert_literal_fields()
        });
    }

    #[test]
    fn controller_size_is_independent_of_schema_size() {
        assert!(std::mem::size_of::<Large>() >= 256);
        assert_eq!(
            std::mem::size_of::<TypedDecoder<'_, Borrowed<'_>, Large, Limits>>(),
            std::mem::size_of::<TypedDecoder<'_, Borrowed<'_>, u8, Limits>>(),
            "derive stores per-field construction state inline"
        );
    }
}

/// A decode that fails terminally holds charged custody until its own
/// cleanup runs: the failure leaves storage beyond the scope's, and only
/// cleanup to `Finished` leaves the scope holding no record.
#[test]
fn terminal_error_cannot_report_finished_with_live_custody() {
    let bound = support::typed_turns::<Probe>(1);
    support::recorded_run(|run| {
        let policy = run.policy(u64::MAX);
        run.scoped(policy, &Unwitnessed, |owner| {
            let scope_bytes = owner.with_policy(policy, |_, m| m.live_bytes());
            owner.lending(Retirement::Exhausted, Lent::new, |view| {
                let scope = view.value().get();
                view.decoder::<_, Probe, _, _>(
                    policy,
                    Borrowing(&[0xf4]),
                    Options::normalizing(8),
                    &Unwitnessed,
                    |decoder| {
                        match decoder.drive(policy, bound, Retirement::Published, |_| ()) {
                            Err(Stopped::Operation(DecodeError::Invalid(_))) => {}
                            other => {
                                return Err(Finding::Driver(format!(
                                    "fixture never reached its terminal construction error: \
                                     {other:?}"
                                )));
                            }
                        }
                        let held = decoder.with_policy(policy, |_, m| m.live_bytes());
                        assert!(held > scope_bytes, "the failure held nothing");
                        decoder.finish(policy, bound, Retirement::Published)?;
                        assert_eq!(
                            scope.outstanding(),
                            0,
                            "Finished abandoned charged construction records"
                        );
                        Ok(())
                    },
                )
            })?
        })?;
        run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0));
        Ok(())
    });
}

#[path = "reclamation/typed_lifecycle_matrix.rs"]
mod matrix;
