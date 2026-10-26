//! Public lifecycle gates for stable construction and retained reclamation.
//! These use the current public boundary; no substitute cleanup engine is used.
#![cfg(feature = "std")]
// The maximum-dispatch-depth fixture composes each child's full observation.
#![recursion_limit = "256"]

// The pipeline matrix fails each physical request through the observer.
#[global_allocator]
static HEAP: support::heap::Heap = support::heap::Heap;

use dcbor::bounded::decode::construction::in_place::{
    Built, ConstructionCost, InPlace, plus, times, unit,
};
use dcbor::bounded::decode::construction::reclamation::{Custody, Reclaim, Reclaimed};
use dcbor::bounded::decode::construction::{Borrowed, TypedDecoder, TypedValue};
use dcbor::bounded::decode::{ConstructResult, DecodeError, Document, Options, wrong_type};
use dcbor::bounded::{Allocator, BoundedError, Limits};
use dcbor_test_support::{self as support, Input, drain, open};
use std::cell::Cell;
use std::{
    mem::MaybeUninit,
    ptr::{NonNull, addr_of_mut},
};

thread_local! {
    static STARTS: Cell<usize> = const { Cell::new(0) };
    static DROPS: Cell<usize> = const { Cell::new(0) };
    static INITIALIZED: Cell<usize> = const { Cell::new(0) };
}

/// The policy of these gates: logged, strict, refusing call `deny_at`.
fn turns(deny_at: Option<usize>) -> Limits {
    Limits::unlimited().logged().strict().refusing(deny_at)
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
    const COST: ConstructionCost = ConstructionCost::fixed(plus(
        plus(unit(std::mem::size_of::<usize>()), times(unit(64), 4)),
        plus(unit(0), times(unit(64), 4)),
    ));

    #[expect(
        clippy::disallowed_methods,
        reason = "a third-party binding admits its own construction, as `InPlace` documents"
    )]
    unsafe fn build_step(
        document: &Document<'_, A::Permit>,
        _: usize,
        place: NonNull<MaybeUninit<Self>>,
        state: &mut ProbeState,
        allocator: &mut A,
    ) -> ConstructResult<Built, A> {
        let raw = place.as_ptr().cast::<Self>();
        if !state.started {
            allocator
                .traverse(1, std::mem::size_of::<usize>() as u64)
                .map_err(BoundedError::Refused)?;
            unsafe {
                addr_of_mut!((*raw).construction_address).write(raw as usize);
            }
            STARTS.set(STARTS.get() + 1);
            state.started = true;
            return Ok(Built::Progress);
        }
        if state.written < 256 {
            allocator.traverse(1, 64).map_err(BoundedError::Refused)?;
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
            return Ok(Built::Progress);
        }
        allocator.traverse(1, 0).map_err(BoundedError::Refused)?;
        if document.root().encoded() == [0xf4] {
            return Err(wrong_type());
        }
        Ok(Built::Done)
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

    #[expect(
        clippy::disallowed_methods,
        reason = "a third-party binding admits its own cleanup, as `Reclaim` documents"
    )]
    unsafe fn reclaim_step(
        _: NonNull<MaybeUninit<Self>>,
        state: &mut ProbeState,
        a: &mut A,
    ) -> dcbor::bounded::BoundedResult<Reclaimed, A> {
        let bytes = state.written.min(64);
        a.traverse(1, bytes as u64).map_err(BoundedError::Refused)?;
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
    unsafe fn remaining(_: NonNull<MaybeUninit<Self>>, state: &mut ProbeState) -> u64 {
        (state.written.div_ceil(64) as u64).max(1)
    }
}

fn finish<'s>(input: Input<'s>, m: &mut Limits) -> TypedValue<'s, Borrowed<'s>, Probe, Limits> {
    support::decode(m, input, Options::normalizing(8)).expect("literal null did not complete")
}

#[test]
fn construction_initialization_requires_an_admitted_turn() {
    STARTS.set(0);
    let mut m = turns(None);
    let (mut owner, input) = open(&mut m, &[0xf6]);
    let decoder = TypedDecoder::<_, Probe, Limits>::new(input, Options::normalizing(8));
    let starts = STARTS.get();
    drop(decoder);
    drain(&mut owner, &mut m);
    assert_eq!(starts, 0, "new ran custom initialization without admission");
}

#[test]
fn publication_preserves_the_initialized_value_address() {
    let mut m = turns(None);
    let (mut owner, input) = open(&mut m, &[0xf6]);
    let output = finish(input, &mut m);
    assert_eq!(output.value().inline, [0x5a; 256]);
    assert_eq!(output.bytes(), [0xf6]);
    let constructed = output.value().construction_address;
    let published = std::ptr::from_ref(output.value()) as usize;
    drop(output);
    drain(&mut owner, &mut m);
    assert_eq!(m.live_bytes(), 0);
    assert_eq!(
        constructed, published,
        "completion moved the initialized value"
    );
}

#[test]
fn dropping_output_does_not_execute_a_value_destructor() {
    DROPS.set(0);
    let mut m = turns(None);
    let (mut owner, input) = open(&mut m, &[0xf6]);
    let output = finish(input, &mut m);
    assert_eq!(DROPS.get(), 0);
    drop(output);
    drain(&mut owner, &mut m);
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
        let mut m = turns(None);
        let (mut owner, input) = open(&mut m, &wire);
        let output = support::decode::<_, Large>(&mut m, input, Options::normalizing(8))
            .expect("large schema did not publish its literal fields");
        output.value().assert_literal_fields();
        drop(output);
        drain(&mut owner, &mut m);
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

#[test]
fn terminal_error_cannot_report_finished_with_live_custody() {
    let mut m = turns(None);
    let (mut owner, input) = open(&mut m, &[0xf4]);
    let scope = m.live_bytes();
    let mut decoder = TypedDecoder::<_, Probe, Limits>::new(input, Options::normalizing(8));
    let bound = support::typed_turns::<Probe>(1);
    let failed = support::fail_within(&mut m, &mut decoder, bound);
    assert!(
        matches!(failed, DecodeError::Invalid(_)),
        "fixture never reached its terminal construction error"
    );
    assert!(m.live_bytes() > scope);
    support::finish_within(&mut m, &mut decoder, bound);
    assert_eq!(
        owner.outstanding(),
        0,
        "Finished abandoned charged construction records"
    );
    drop(decoder);
    drain(&mut owner, &mut m);
    assert_eq!(m.live_bytes(), 0);
}

#[path = "reclamation/typed_lifecycle_matrix.rs"]
mod matrix;
