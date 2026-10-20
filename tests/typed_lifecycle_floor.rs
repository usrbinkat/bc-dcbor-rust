//! Public lifecycle gates for stable construction and retained reclamation.
//! These use the current public boundary; no substitute cleanup engine is used.
#![cfg(feature = "std")]

use dcbor::bounded::decode::construction::in_place::{Built, InPlace};
use dcbor::bounded::decode::construction::reclamation::{Cursor, Reclaim, Reclaimed};
use dcbor::bounded::decode::construction::{DecodeOwner, TypedDecoder, TypedStep, TypedValue};
use dcbor::bounded::decode::{ConstructResult, Document, Options, wrong_type};
use dcbor::bounded::{Allocator, BoundedError, Budget};
use std::cell::Cell;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::{
    mem::MaybeUninit,
    ptr::{NonNull, addr_of_mut},
};

thread_local! {
    static STARTS: Cell<usize> = const { Cell::new(0) };
    static DROPS: Cell<usize> = const { Cell::new(0) };
    static INITIALIZED: Cell<usize> = const { Cell::new(0) };
}

struct Permit {
    live: Arc<AtomicU64>,
    bytes: u64,
}

impl Drop for Permit {
    fn drop(&mut self) {
        let old = self.live.fetch_sub(self.bytes, Ordering::SeqCst);
        assert!(old >= self.bytes, "reservation released twice");
    }
}

#[derive(Default)]
struct Turn {
    values: u64,
    bytes: u64,
    live: Arc<AtomicU64>,
    attempts: usize,
    deny_at: Option<usize>,
    refusals: usize,
    admitted: Vec<(u64, u64)>,
}

impl Turn {
    fn fresh(&mut self) {
        self.values = 0;
        self.bytes = 0;
    }
}

impl Budget for Turn {
    type Refusal = ();

    fn traverse(&mut self, values: u64, bytes: u64) -> Result<(), ()> {
        let attempt = self.attempts;
        self.attempts += 1;
        if self.deny_at == Some(attempt) || values > 3 - self.values || bytes > 64 - self.bytes {
            self.refusals += 1;
            return Err(());
        }
        self.values += values;
        self.bytes += bytes;
        self.admitted.push((values, bytes));
        Ok(())
    }
}

impl Allocator for Turn {
    type Permit = Permit;

    fn allocate(&mut self, bytes: u64) -> Result<Permit, ()> {
        self.live.fetch_add(bytes, Ordering::SeqCst);
        Ok(Permit {
            live: self.live.clone(),
            bytes,
        })
    }
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

// SAFETY: each admitted unit initializes at most 64 bytes in the final slot.
// The retained cursor describes the byte prefix even when construction fails.
unsafe impl<A: Allocator> InPlace<A> for Probe {
    unsafe fn build_step(
        document: &Document<'_, A::Permit>,
        _: usize,
        place: NonNull<MaybeUninit<Self>>,
        cursor: &mut Cursor,
        allocator: &mut A,
    ) -> ConstructResult<Built, A> {
        let raw = place.as_ptr().cast::<Self>();
        if cursor.state == 0 {
            allocator
                .traverse(1, std::mem::size_of::<usize>() as u64)
                .map_err(BoundedError::Refused)?;
            unsafe {
                addr_of_mut!((*raw).construction_address).write(raw as usize);
            }
            STARTS.set(STARTS.get() + 1);
            cursor.state = 1;
            return Ok(Built::Progress);
        }
        if cursor.position < 256 {
            allocator.traverse(1, 64).map_err(BoundedError::Refused)?;
            unsafe {
                addr_of_mut!((*raw).inline)
                    .cast::<u8>()
                    .add(cursor.position)
                    .write_bytes(0x5a, 64);
            }
            cursor.position += 64;
            if cursor.position == 64 {
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
    unsafe fn reclaim_step(
        _: NonNull<MaybeUninit<Self>>,
        cursor: &mut Cursor,
        a: &mut A,
    ) -> dcbor::bounded::BoundedResult<Reclaimed, A> {
        let bytes = cursor.position.min(64);
        a.traverse(1, bytes as u64).map_err(BoundedError::Refused)?;
        cursor.position -= bytes;
        if cursor.position == 0 {
            cursor.state = 0;
            Ok(Reclaimed::Done)
        } else {
            Ok(Reclaimed::Progress)
        }
    }
}

fn drain(owner: &DecodeOwner<'_, Turn>, turn: &mut Turn) {
    for _ in 0..512 {
        turn.fresh();
        if owner.shutdown_step(turn).unwrap() == Reclaimed::Done {
            assert_eq!(turn.live.load(Ordering::SeqCst), 0);
            return;
        }
    }
    panic!("owner did not drain");
}

fn finish<'o>(
    owner: &'o DecodeOwner<'static, Turn>,
    turn: &mut Turn,
) -> TypedValue<'static, 'o, Probe, Turn> {
    let mut decoder = TypedDecoder::<Probe, Turn>::new(owner, &[0xf6], Options::normalizing(8));
    for _ in 0..256 {
        turn.fresh();
        match decoder.step(turn) {
            Ok(TypedStep::Progress) => {}
            Ok(TypedStep::Complete(value)) => return value,
            _ => panic!("literal null did not complete under fresh turns"),
        }
    }
    panic!("one-node construction exceeded its finite completion bound");
}

#[test]
fn construction_initialization_requires_an_admitted_turn() {
    STARTS.set(0);
    let owner = DecodeOwner::new();
    let decoder = TypedDecoder::<Probe, Turn>::new(&owner, &[0xf6], Options::normalizing(8));
    let starts = STARTS.get();
    drop(decoder);
    assert_eq!(starts, 0, "new ran custom initialization without admission");
}

#[test]
fn publication_preserves_the_initialized_value_address() {
    let mut turn = Turn::default();
    let owner = DecodeOwner::new();
    let output = finish(&owner, &mut turn);
    assert_eq!(output.value().inline, [0x5a; 256]);
    let constructed = output.value().construction_address;
    let published = std::ptr::from_ref(output.value()) as usize;
    drop(output);
    drain(&owner, &mut turn);
    assert_eq!(
        constructed, published,
        "completion moved the initialized value"
    );
}

#[test]
fn dropping_output_does_not_execute_a_value_destructor() {
    DROPS.set(0);
    let mut turn = Turn::default();
    let owner = DecodeOwner::new();
    let output = finish(&owner, &mut turn);
    assert_eq!(DROPS.get(), 0);
    drop(output);
    drain(&owner, &mut turn);
    assert_eq!(
        DROPS.get(),
        0,
        "output Drop performed unadmitted reclamation"
    );
}

#[test]
fn published_handle_size_is_independent_of_inline_payload() {
    let small = std::mem::size_of::<TypedValue<'_, '_, u8, Turn>>();
    let large = std::mem::size_of::<TypedValue<'_, '_, Probe, Turn>>();
    assert_eq!(
        small, large,
        "publication carries the schema instead of an owning handle"
    );
}

#[test]
fn cancellation_at_each_construction_boundary_does_not_run_destructors() {
    // The fixture has one retained initialization step and one completion step.
    // Discover all pre-publication boundaries through the public driver first.
    let mut baseline = Turn::default();
    let owner = DecodeOwner::new();
    let mut decoder = TypedDecoder::<Probe, Turn>::new(&owner, &[0xf6], Options::normalizing(8));
    let mut boundaries = None;
    for step in 0..256 {
        baseline.fresh();
        match decoder.step(&mut baseline) {
            Ok(TypedStep::Progress) => {}
            Ok(TypedStep::Complete(value)) => {
                drop(value);
                boundaries = Some(step + 1);
                break;
            }
            _ => panic!("baseline construction failed"),
        }
    }
    drop(decoder);
    drain(&owner, &mut baseline);
    let boundaries = boundaries.expect("baseline exceeded finite bound");
    let mut violations = Vec::new();
    let mut observed_partial = false;
    for stop in 0..boundaries {
        DROPS.set(0);
        INITIALIZED.set(0);
        let mut turn = Turn::default();
        let owner = DecodeOwner::new();
        let mut decoder =
            TypedDecoder::<Probe, Turn>::new(&owner, &[0xf6], Options::normalizing(8));
        for _ in 0..stop {
            turn.fresh();
            assert!(matches!(decoder.step(&mut turn), Ok(TypedStep::Progress)));
        }
        assert_eq!(
            DROPS.get(),
            0,
            "partial value destroyed before cancellation"
        );
        observed_partial |= INITIALIZED.get() > 0;
        drop(decoder);
        drain(&owner, &mut turn);
        if DROPS.get() != 0 {
            violations.push(stop);
        }
    }
    assert!(
        observed_partial,
        "fixture did not reach partial-value custody"
    );
    assert!(
        violations.is_empty(),
        "unadmitted destruction at cancellation turns {violations:?}"
    );
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
        let owner = DecodeOwner::new();
        let mut turn = Turn::default();
        let mut decoder = TypedDecoder::<Large, Turn>::new(&owner, &wire, Options::normalizing(8));
        let mut completed = false;
        for _ in 0..16384 {
            turn.fresh();
            match decoder.step(&mut turn) {
                Ok(TypedStep::Progress)
                | Err(dcbor::bounded::decode::DecodeError::Resource(BoundedError::Refused(()))) => {
                }
                Ok(TypedStep::Complete(output)) => {
                    output.value().assert_literal_fields();
                    drop(output);
                    completed = true;
                    break;
                }
                _ => panic!("large schema did not publish its literal fields"),
            }
        }
        assert!(completed, "large schema exceeded its finite bound");
        drop(decoder);
        drain(&owner, &mut turn);
    }

    #[test]
    fn derived_initial_state_fits_a_single_metadata_quantum() {
        assert!(std::mem::size_of::<Large>() >= 256);
        assert!(
            std::mem::size_of::<TypedDecoder<'_, '_, Large, Turn>>() <= 64,
            "derive stores per-field construction state inline"
        );
    }
}

#[test]
fn terminal_error_cannot_report_finished_with_live_custody() {
    let mut turn = Turn::default();
    let owner = DecodeOwner::new();
    let mut decoder = TypedDecoder::<Probe, Turn>::new(&owner, &[0xf4], Options::normalizing(8));
    let mut failed = false;
    for _ in 0..256 {
        turn.fresh();
        if decoder.step(&mut turn).is_err() {
            failed = true;
            break;
        }
    }
    assert!(
        failed,
        "fixture never reached its terminal construction error"
    );
    assert!(turn.live.load(Ordering::SeqCst) > 0);
    for _ in 0..256 {
        turn.fresh();
        match decoder.step(&mut turn) {
            Ok(TypedStep::Progress) => {}
            Ok(TypedStep::Finished) => {
                assert_eq!(
                    turn.live.load(Ordering::SeqCst),
                    0,
                    "Finished abandoned charged construction resources"
                );
                return;
            }
            _ => panic!("terminal construction resumed or published a value"),
        }
    }
    panic!("terminal cleanup failed to finish within its input-derived bound");
}

#[path = "reclamation/typed_lifecycle_matrix.rs"]
mod matrix;
