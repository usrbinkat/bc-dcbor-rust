use core::{mem::MaybeUninit, ptr::NonNull};
use dcbor::bounded::decode::construction::{
    Acquisition, DecodeOwner, TypedDecoder, TypedValue,
    in_place::{Built, ConstructionCost, InPlace, plus, times, unit},
    reclamation::{Custody, Reclaim, Reclaimed},
};
use dcbor::bounded::decode::{ConstructResult, Document, Options};
use dcbor::bounded::{Allocator, BoundedError, BoundedResult, Budget, Limits, Step};
use dcbor_test_support::{self as support, Instrumented, acquire, drain, instrumented, scope};
use std::sync::{Arc, atomic::AtomicUsize};

#[cfg(feature = "custom-std-collections")]
#[path = "owned_pipeline/tree_state.rs"]
mod tree_state;

fn meter() -> Limits {
    Limits::unlimited().logged().strict()
}

#[test]
fn refused_acquisition_cannot_move_admission_to_another_scope() {
    let mut m = meter();
    let mut first = scope(&mut m);
    let mut second = scope(&mut m);
    let mut acquisition = Acquisition::<Instrumented, Limits>::new();
    m.clear_refusal();
    m.exhaust();
    let refused = matches!(
        first.allocate_step(&mut m, &mut acquisition),
        Err(BoundedError::Refused(_))
    );
    m.clear_refusal();
    m.fresh();
    let mismatch = matches!(
        second.allocate_step(&mut m, &mut acquisition),
        Err(BoundedError::PlanMismatch)
    );
    let record = acquire(&first, &mut m, &mut acquisition);
    drop(record);
    // Successful consumption resets the token, including its scope binding.
    m.fresh();
    let other = acquire(&second, &mut m, &mut acquisition);
    drop(other);
    drop(acquisition);
    drain(&mut first, &mut m);
    drain(&mut second, &mut m);
    assert!(refused && mismatch);
    assert_eq!(m.live_bytes(), 0);
}

#[test]
fn live_record_waiting_spends_no_work_and_shutdown_closes_admission() {
    let mut m = meter();
    let mut owner = scope(&mut m);
    m.fresh();
    let record = acquire::<Instrumented>(&owner, &mut m, &mut Acquisition::new());
    m.fresh();
    let allowance = m.remaining();
    let waiting = owner.step(&mut m);
    let closing = owner.shutdown_step(&mut m);
    let spent = m.remaining();
    let rejected = matches!(
        owner.allocate_step::<Instrumented>(&mut m, &mut Acquisition::new()),
        Err(BoundedError::PlanMismatch)
    );
    drop(record);
    drain(&mut owner, &mut m);
    assert_eq!(waiting.unwrap(), Reclaimed::Waiting);
    assert_eq!(closing.unwrap(), Reclaimed::Waiting);
    assert_eq!(spent, allowance);
    assert!(rejected);
    assert_eq!(m.live_bytes(), 0);
}

/// Decode an instrumented input, moving the whole consumer state between
/// turns and cancelling at turn `cancel_at`. Returns the turns taken and
/// whether the value was published.
fn run(cancel_at: Option<usize>) -> (usize, bool) {
    let wire = [0x62, b'o', b'k'];
    // The decode within its own bound; a cancelled one also reclaims the
    // instrumented input, whose cleanup its acquisition accounts: three
    // units, its bytes, its reservation and its handle.
    let bound =
        support::turns(
            dcbor::bounded::decode::construction::typed_decode_bound::<
                Instrumented,
                String,
                Limits,
                (),
            >(wire.len() as u64, Options::normalizing(8))
            .expect("the typed decode bound of an input held in memory fits in u64"),
        ) + 3;
    let mut m = meter();
    let mut owner = scope(&mut m);
    let released = Arc::new(AtomicUsize::new(0));
    let input = instrumented(&owner, &mut m, &wire, &released);
    let mut decoder = TypedDecoder::<_, String, Limits>::new(input, Options::normalizing(8));
    let mut finished = false;
    let mut published = false;
    let mut turns = 0;
    for turn in 0..bound {
        turns += 1;
        // Transfer the entire ordinary consumer state between turns.
        let moved = (owner, decoder);
        (owner, decoder) = moved;
        if cancel_at == Some(turn) {
            decoder.cancel();
        }
        let step = match support::checked(&mut m, |m| support::contracted(m, &mut decoder)) {
            Ok(step) => step,
            Err(error) if support::ordinary_exhaustion(&m, &error) => continue,
            Err(error) => panic!("{error:?}"),
        };
        match step {
            Step::Progress => {}
            Step::Complete(value) => {
                support::exhausted(&mut m, &mut decoder);
                let address = value.value() as *const String;
                drop(decoder);
                let moved = value;
                assert_eq!(moved.value(), "ok");
                assert_eq!(moved.value() as *const String, address);
                assert_eq!(moved.bytes(), [0x62, b'o', b'k']);
                drop(moved);
                finished = true;
                published = true;
                break;
            }
            Step::Finished => {
                support::exhausted(&mut m, &mut decoder);
                drop(decoder);
                finished = true;
                break;
            }
        }
    }
    assert!(finished, "decode/cancellation did not finish");
    drain(&mut owner, &mut m);
    assert_eq!(m.live_bytes(), 0);
    assert_eq!(released.load(std::sync::atomic::Ordering::SeqCst), 1);
    (turns, published)
}

#[test]
fn movable_decode_publication_and_retirement() {
    assert!(run(None).1, "uncancelled decode did not publish");
}

/// The decode cancelled before each of its turns through publication
/// ([`support::stop_matrix`]): cancellation takes effect before that turn's
/// step, so cancelling at any turn up to and including the publishing one
/// prevents publication, and only the stop past it publishes. Every cancelled
/// decode finishes its cleanup and the scope recovers everything ([`run`]).
#[test]
fn cancellation_through_initialization_parse_build_and_publication() {
    let (turns, published) = run(None);
    assert!(published, "uncancelled decode did not publish");
    support::stop_matrix("instrumented decode cancelled at a turn", turns, |stop| {
        let (_, published) = run(Some(stop));
        assert_eq!(
            published,
            stop == turns,
            "cancellation before turn {stop} of {turns}"
        );
    });
}

#[test]
fn cancelled_operation_finishes_while_unrelated_output_remains_live() {
    let mut m = meter();
    let mut owner = scope(&mut m);
    let released = Arc::new(AtomicUsize::new(0));
    let first = instrumented(&owner, &mut m, &[0x62, b'o', b'k'], &released);
    let second = instrumented(&owner, &mut m, &[0x62, b'o', b'k'], &released);
    let output = support::decode::<_, String>(&mut m, first, Options::normalizing(8))
        .expect("unexpected producer result");
    let mut cancelled = TypedDecoder::<_, String, Limits>::new(second, Options::normalizing(8));
    cancelled.cancel();
    let bound =
        support::turns(
            dcbor::bounded::decode::construction::typed_decode_bound::<
                Instrumented,
                String,
                Limits,
                (),
            >(3, Options::normalizing(8))
            .expect("the literal's typed decode bound fits in u64"),
        ) + 3; // The instrumented input's three cleanup units.
    support::finish_within(&mut m, &mut cancelled, bound);
    assert_eq!(
        output.value(),
        "ok",
        "cancellation disturbed an unrelated output"
    );
    drop(cancelled);
    drop(output);
    drain(&mut owner, &mut m);
    assert_eq!(m.live_bytes(), 0);
    assert_eq!(released.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[test]
fn shutdown_is_terminal_and_cannot_reopen_admission() {
    let mut m = meter();
    let mut owner = scope(&mut m);
    m.fresh();
    assert_eq!(owner.shutdown_step(&mut m).unwrap(), Reclaimed::Done);
    m.fresh();
    let reopened = owner.initialize_step(&mut m).is_ok();
    m.fresh();
    owner.shutdown_step(&mut m).unwrap();
    assert_eq!(m.live_bytes(), 0);
    assert!(!reopened, "closed owner accepted initialization again");
}

static PROBE_DROPS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
struct StableProbe {
    bytes: [u8; 256],
    address: usize,
}
impl Drop for StableProbe {
    fn drop(&mut self) {
        PROBE_DROPS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}
/// A [`StableProbe`]'s state: the 64-byte chunks written, then whether its
/// address is.
struct ProbeState {
    chunks: usize,
    addressed: bool,
}
/// The chunks written and whether the address is: the probe's whole custody.
impl Custody for ProbeState {
    type Observation = (usize, bool);

    fn observe(&mut self) -> (usize, bool) {
        (self.chunks, self.addressed)
    }
}
// SAFETY: each admitted step writes only a 64-byte chunk or the address field.
// No initialized field owns resources, so every partial prefix is reclaimable.
unsafe impl InPlace<Limits> for StableProbe {
    // Four 64-byte writes and the address write; one cleanup unit.
    const COST: ConstructionCost = ConstructionCost::fixed(plus(
        plus(times(unit(64), 4), unit(core::mem::size_of::<usize>())),
        unit(0),
    ));

    #[expect(
        clippy::disallowed_methods,
        reason = "a third-party binding admits its own construction, as `InPlace` documents"
    )]
    unsafe fn build_step(
        _: &Document<'_, <Limits as Allocator>::Permit>,
        _: usize,
        place: NonNull<MaybeUninit<Self>>,
        state: &mut ProbeState,
        a: &mut Limits,
    ) -> ConstructResult<Built, Limits> {
        let raw = place.as_ptr().cast::<Self>();
        if state.chunks < 4 {
            a.traverse(1, 64).map_err(BoundedError::Refused)?;
            unsafe {
                core::ptr::addr_of_mut!((*raw).bytes)
                    .cast::<u8>()
                    .add(state.chunks * 64)
                    .write_bytes(0x5a, 64);
            }
            state.chunks += 1;
            Ok(Built::Progress)
        } else {
            a.traverse(1, core::mem::size_of::<usize>() as u64)
                .map_err(BoundedError::Refused)?;
            unsafe {
                core::ptr::addr_of_mut!((*raw).address).write(raw as usize);
            }
            state.addressed = true;
            Ok(Built::Done)
        }
    }
}
// SAFETY: the probe's fields are plain bytes and an address; one admitted
// unit invalidates whatever prefix the state records, without Drop.
unsafe impl Reclaim<Limits> for StableProbe {
    type State = ProbeState;
    const INITIAL: ProbeState = ProbeState {
        chunks: 0,
        addressed: false,
    };

    #[expect(
        clippy::disallowed_methods,
        reason = "a third-party binding admits its own cleanup, as `Reclaim` documents"
    )]
    unsafe fn reclaim_step(
        _: NonNull<MaybeUninit<Self>>,
        state: &mut ProbeState,
        a: &mut Limits,
    ) -> BoundedResult<Reclaimed, Limits> {
        a.traverse(1, 0).map_err(BoundedError::Refused)?;
        *state = Self::INITIAL;
        Ok(Reclaimed::Done)
    }

    /// One call, which is `Done`.
    unsafe fn remaining(_: NonNull<MaybeUninit<Self>>, _: &mut ProbeState) -> u64 {
        1
    }
}

#[test]
fn owned_publication_preserves_construction_address_and_never_runs_payload_drop() {
    assert_eq!(
        core::mem::size_of::<TypedValue<'static, Instrumented, StableProbe, Limits>>(),
        core::mem::size_of::<TypedValue<'static, Instrumented, String, Limits>>()
    );
    let mut m = meter();
    let mut owner: DecodeOwner<'static, Limits> = scope(&mut m);
    let released = Arc::new(AtomicUsize::new(0));
    let input = instrumented(&owner, &mut m, &[0x62, b'o', b'k'], &released);
    let output = support::decode::<_, StableProbe>(&mut m, input, Options::normalizing(8))
        .expect("finite probe publication");
    assert_eq!(
        output.value().address,
        output.value() as *const StableProbe as usize
    );
    assert_eq!(output.value().bytes, [0x5a; 256]);
    drop(output);
    assert_eq!(PROBE_DROPS.load(std::sync::atomic::Ordering::SeqCst), 0);
    drain(&mut owner, &mut m);
    assert_eq!(m.live_bytes(), 0);
    assert_eq!(PROBE_DROPS.load(std::sync::atomic::Ordering::SeqCst), 0);
}
