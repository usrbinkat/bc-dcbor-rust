use core::{mem::MaybeUninit, ptr::NonNull};
use dcbor::bounded::decode::{
    Options,
    construction::{
        DecodeInput, OwnedDecodeOwner, OwnedDecodeStep, OwnedTypedDecoder,
        reclamation::{Cursor, Reclaim, Reclaimed},
    },
};
use dcbor::bounded::{Allocator, BoundedError, BoundedResult, Budget, Limits};

struct Input([u8; 3]);
struct Turn {
    pool: Limits,
    values: u64,
    bytes: u64,
}
impl Turn {
    fn fresh(&mut self) {
        self.values = 3;
        self.bytes = 64;
    }
}
impl Budget for Turn {
    type Refusal = ();
    fn traverse(&mut self, values: u64, bytes: u64) -> Result<(), ()> {
        if values > self.values || bytes > self.bytes {
            return Err(());
        }
        self.values -= values;
        self.bytes -= bytes;
        Ok(())
    }
}
impl Allocator for Turn {
    type Permit = <Limits as Allocator>::Permit;
    fn allocate(&mut self, bytes: u64) -> Result<Self::Permit, ()> {
        self.pool.allocate(bytes).map_err(|_| ())
    }
}
// SAFETY: this fixed byte array has no resources or interior mutation.
unsafe impl Reclaim<Turn> for Input {
    unsafe fn reclaim_step(
        _: NonNull<MaybeUninit<Self>>,
        _: &mut Cursor,
        a: &mut Turn,
    ) -> BoundedResult<Reclaimed, Turn> {
        a.traverse(1, 3).map_err(BoundedError::Refused)?;
        Ok(Reclaimed::Done)
    }
}
unsafe impl DecodeInput<Turn> for Input {
    fn bytes(&self) -> &[u8] {
        &self.0
    }
}

fn run(cancel_at: Option<usize>) {
    let mut a = Turn {
        pool: Limits::new(100_000, 10_000_000, 1_000_000),
        values: 3,
        bytes: 64,
    };
    let mut owner = OwnedDecodeOwner::new();
    owner.initialize_step(&mut a).unwrap();
    a.fresh();
    let mut input = owner.allocate_step::<Input>(&mut a, &mut false).unwrap();
    a.fresh();
    a.traverse(1, 3).unwrap();
    // SAFETY: admitted fixed-size initialization at the final address. The
    // resource has no children; reclaim accepts either cursor state.
    unsafe {
        let (place, cursor) = input.destination();
        place
            .as_ptr()
            .write(MaybeUninit::new(Input([0x62, b'o', b'k'])));
        cursor.position = 1;
    }
    let input = unsafe { input.publish() };
    let mut decoder = OwnedTypedDecoder::<_, String, Turn>::new(input, Options::normalizing(8));
    let mut complete = false;
    for turn in 0..10_000 {
        // Transfer the entire ordinary consumer state between turns.
        let moved = (owner, decoder);
        (owner, decoder) = moved;
        if cancel_at == Some(turn) {
            decoder.cancel();
        }
        a.fresh();
        let step = match decoder.step(&mut a) {
            Ok(step) => step,
            Err(dcbor::bounded::decode::DecodeError::Resource(BoundedError::Refused(()))) => {
                continue;
            }
            Err(error) => panic!("{error:?}"),
        };
        match step {
            OwnedDecodeStep::Progress => {}
            OwnedDecodeStep::Complete(value) => {
                let address = value.value() as *const String;
                drop(decoder);
                let moved = value;
                assert_eq!(moved.value(), "ok");
                assert_eq!(moved.value() as *const String, address);
                drop(moved);
                complete = true;
                break;
            }
            OwnedDecodeStep::Finished => {
                drop(decoder);
                complete = true;
                break;
            }
        }
    }
    assert!(complete, "decode/cancellation did not finish");
    for _ in 0..10_000 {
        a.fresh();
        if matches!(owner.shutdown_step(&mut a), Ok(Reclaimed::Done)) {
            assert_eq!(a.pool.live_bytes(), 0);
            return;
        }
    }
    panic!("owned shutdown did not finish");
}

#[test]
fn movable_decode_publication_and_retirement() {
    run(None);
}

#[test]
fn cancellation_through_initialization_parse_build_and_publication() {
    for turn in 0..160 {
        run(Some(turn));
    }
}
