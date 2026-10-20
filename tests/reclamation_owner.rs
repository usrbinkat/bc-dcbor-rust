#![cfg(feature = "std")]

#[cfg(feature = "derive")]
#[path = "reclamation/schema.rs"]
mod schema;

#[path = "reclamation/parser.rs"]
mod parser;

#[path = "reclamation/destination.rs"]
mod destination;

#[path = "reclamation/scoped.rs"]
mod scoped;

use dcbor::bounded::decode::construction::reclamation::{Cursor, Reclaim, Reclaimed, Reclaimer};
use dcbor::bounded::{Allocator, BoundedError, BoundedResult, Budget};
use std::cell::Cell;
use std::mem::MaybeUninit;
use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

thread_local! {
    static CLEANED: Cell<usize> = const { Cell::new(0) };
    static DROPPED: Cell<usize> = const { Cell::new(0) };
}

struct Permit(Arc<AtomicU64>, u64);
impl Drop for Permit {
    fn drop(&mut self) {
        assert!(self.0.fetch_sub(self.1, Ordering::SeqCst) >= self.1);
    }
}

struct Turn {
    live: Arc<AtomicU64>,
    values: u64,
    bytes: u64,
    refused: usize,
}
impl Turn {
    fn new() -> Self {
        Self {
            live: Arc::new(AtomicU64::new(0)),
            values: 3,
            bytes: 64,
            refused: 0,
        }
    }
    fn fresh(&mut self) {
        self.values = 3;
        self.bytes = 64;
    }
}
impl Budget for Turn {
    type Refusal = ();
    fn traverse(&mut self, values: u64, bytes: u64) -> Result<(), ()> {
        if values > self.values || bytes > self.bytes {
            self.refused += 1;
            return Err(());
        }
        self.values -= values;
        self.bytes -= bytes;
        Ok(())
    }
}
impl Allocator for Turn {
    type Permit = Permit;
    fn allocate(&mut self, bytes: u64) -> Result<Permit, ()> {
        self.live.fetch_add(bytes, Ordering::SeqCst);
        Ok(Permit(self.live.clone(), bytes))
    }
}

struct Payload([u8; 192]);
impl Drop for Payload {
    fn drop(&mut self) {
        DROPPED.set(DROPPED.get() + 1);
    }
}

// SAFETY: Payload owns no child allocations. The initialized byte prefix is
// tracked exactly; cleanup invalidates at most 64 bytes after admission, without
// reading uninitialized storage or invoking Payload's synchronous destructor.
unsafe impl Reclaim<Turn> for Payload {
    unsafe fn reclaim_step(
        _: NonNull<MaybeUninit<Self>>,
        cursor: &mut Cursor,
        a: &mut Turn,
    ) -> BoundedResult<Reclaimed, Turn> {
        let bytes = cursor.position.min(64);
        a.traverse(1, bytes as u64).map_err(BoundedError::Refused)?;
        cursor.position -= bytes;
        CLEANED.set(CLEANED.get() + bytes);
        Ok(if cursor.position == 0 {
            Reclaimed::Done
        } else {
            Reclaimed::Progress
        })
    }
}

#[test]
fn stable_publication_and_every_cleanup_admission_refusal() {
    // Select, three 64-byte cleanup units, release: five separate admissions.
    for refuse_at in 0..5 {
        CLEANED.set(0);
        DROPPED.set(0);
        let mut a = Turn::new();
        let owner = Reclaimer::new();
        let mut record = owner.allocate::<Payload>(&mut a).unwrap();
        let mut construction_address = 0;
        for _ in 0..3 {
            a.fresh();
            a.traverse(1, 64).unwrap();
            // SAFETY: byte-only payload; each admitted chunk initializes the
            // next prefix and records it before cancellation can occur.
            unsafe {
                let (place, cursor) = record.destination();
                construction_address = place.as_ptr() as usize;
                place
                    .as_ptr()
                    .cast::<u8>()
                    .add(cursor.position)
                    .write_bytes(0x5a, 64);
                cursor.position += 64;
            }
        }
        // SAFETY: all 192 bytes are initialized and tracked; no pointer escapes.
        let value = unsafe { record.publish() };
        let published_address = std::ptr::from_ref(value.value()) as usize;
        assert_eq!(value.value().0, [0x5a; 192]);
        drop(value);
        let held = a.live.load(Ordering::SeqCst);
        assert!(held >= 192);
        assert_eq!(DROPPED.get(), 0);
        for unit in 0..5 {
            if unit == refuse_at {
                let progress = CLEANED.get();
                for _ in 0..3 {
                    a.values = 0;
                    a.bytes = 0;
                    assert!(matches!(owner.step(&mut a), Err(BoundedError::Refused(()))));
                    assert_eq!(CLEANED.get(), progress);
                    assert_eq!(owner.outstanding(), 1);
                    assert_eq!(a.live.load(Ordering::SeqCst), held);
                }
            }
            a.fresh();
            let result = owner.shutdown_step(&mut a).unwrap();
            assert_eq!(
                result,
                if unit == 4 {
                    Reclaimed::Done
                } else {
                    Reclaimed::Progress
                }
            );
        }
        assert_eq!(construction_address, published_address);
        assert_eq!(a.refused, 3);
        assert_eq!(CLEANED.get(), 192);
        assert_eq!(DROPPED.get(), 0);
        assert_eq!(a.live.load(Ordering::SeqCst), 0);
        assert_eq!(owner.outstanding(), 0);
        a.fresh();
        assert!(matches!(
            owner.allocate::<Payload>(&mut a),
            Err(BoundedError::PlanMismatch)
        ));
    }
}

#[test]
fn cancellation_reclaims_only_the_initialized_prefix() {
    for chunks in 0..=3 {
        CLEANED.set(0);
        let mut a = Turn::new();
        let owner = Reclaimer::new();
        let mut record = owner.allocate::<Payload>(&mut a).unwrap();
        for _ in 0..chunks {
            a.fresh();
            a.traverse(1, 64).unwrap();
            // SAFETY: same prefix initialization protocol as above.
            unsafe {
                let (place, cursor) = record.destination();
                place
                    .as_ptr()
                    .cast::<u8>()
                    .add(cursor.position)
                    .write_bytes(7, 64);
                cursor.position += 64;
            }
        }
        let held = a.live.load(Ordering::SeqCst);
        drop(record);
        assert_eq!(a.live.load(Ordering::SeqCst), held);
        let mut done = false;
        for _ in 0..chunks.max(1) + 2 {
            a.fresh();
            if owner.shutdown_step(&mut a).unwrap() == Reclaimed::Done {
                done = true;
                break;
            }
        }
        assert!(done);
        assert_eq!(CLEANED.get(), chunks * 64);
        assert_eq!(a.live.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn text_build_publication_and_cancellation_keep_per_allocation_custody() {
    use dcbor::bounded::decode::construction::in_place::{Construction, Step};
    use dcbor::bounded::decode::decode;

    // Literal canonical text containing 65 ASCII bytes crosses a copy quantum.
    let mut wire = vec![0x78, 65];
    wire.extend_from_slice(&[b'x'; 65]);
    for stop in 0..=8 {
        let mut a = Turn::new();
        // Parsing is setup for this construction-only matrix, accounted in a
        // separate allowance. Every construction/reclamation turn below is 3/64.
        a.values = u64::MAX;
        a.bytes = u64::MAX;
        let document = decode(&wire, 8, &mut a).unwrap();
        let document_bytes = a.live.load(Ordering::SeqCst);
        let owner = Reclaimer::new();
        let mut operation = Construction::<String, Turn>::new(&owner, &document, 0);
        let mut output = None;
        for _ in 0..stop {
            a.fresh();
            match operation.step(&mut a).unwrap() {
                Step::Progress => {}
                Step::Complete(value) => {
                    assert_eq!(value.value().as_bytes(), &[b'x'; 65]);
                    output = Some(value);
                    break;
                }
                Step::Finished => panic!("construction finished without publishing"),
            }
        }
        let held = a.live.load(Ordering::SeqCst);
        drop(operation);
        drop(output);
        // Handle drops transfer custody; they cannot return any reservations.
        assert_eq!(a.live.load(Ordering::SeqCst), held);
        let mut done = false;
        let mut previous = held;
        for _ in 0..16 {
            a.fresh();
            let result = owner.shutdown_step(&mut a).unwrap();
            let live = a.live.load(Ordering::SeqCst);
            assert!(live <= previous, "reclamation acquired new storage");
            previous = live;
            if result == Reclaimed::Done {
                done = true;
                break;
            }
        }
        assert!(done, "text cleanup exceeded its allocation-derived bound");
        assert_eq!(a.live.load(Ordering::SeqCst), document_bytes);
        drop(document);
        assert_eq!(a.live.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn nested_vectors_construct_children_in_place_and_reclaim_all_allocations() {
    use dcbor::bounded::decode::construction::in_place::{Construction, Step};
    use dcbor::bounded::decode::decode;

    // [[1, 24], [], [256]], independently specified canonical bytes.
    let wire = [0x83, 0x82, 0x01, 0x18, 0x18, 0x80, 0x81, 0x19, 0x01, 0x00];
    let mut a = Turn::new();
    a.values = u64::MAX;
    a.bytes = u64::MAX;
    let document = decode(&wire, 8, &mut a).unwrap();
    let document_bytes = a.live.load(Ordering::SeqCst);
    let owner = Reclaimer::new();
    let mut operation = Construction::<Vec<Vec<u64>>, Turn>::new(&owner, &document, 0);
    let mut output = None;
    for _ in 0..wire.len() * 32 {
        a.fresh();
        match operation.step(&mut a).unwrap() {
            Step::Progress => {}
            Step::Complete(value) => {
                output = Some(value);
                break;
            }
            Step::Finished => panic!("nested vector finished without publication"),
        }
    }
    let output = output.expect("nested construction exceeded finite bound");
    assert_eq!(output.value(), &[vec![1, 24], vec![], vec![256]]);
    let held = a.live.load(Ordering::SeqCst);
    drop(operation);
    drop(output);
    assert_eq!(a.live.load(Ordering::SeqCst), held);
    let mut done = false;
    for _ in 0..wire.len() * 32 {
        a.fresh();
        if owner.shutdown_step(&mut a).unwrap() == Reclaimed::Done {
            done = true;
            break;
        }
    }
    assert!(done, "nested cleanup exceeded finite bound");
    assert_eq!(a.live.load(Ordering::SeqCst), document_bytes);
    drop(document);
    assert_eq!(a.live.load(Ordering::SeqCst), 0);
}

#[cfg(feature = "derive")]
#[test]
fn derived_newtype_uses_stable_child_construction_and_cleanup() {
    use dcbor::bounded::decode::construction::in_place::{Construction, Step};
    use dcbor::bounded::decode::decode;

    #[derive(dcbor::CBORBoundedDecodable)]
    struct Wrapped(Vec<String>);

    let wire = [0x82, 0x61, b'a', 0x62, b'b', b'c'];
    let mut a = Turn::new();
    a.values = u64::MAX;
    a.bytes = u64::MAX;
    let document = decode(&wire, 8, &mut a).unwrap();
    let document_bytes = a.live.load(Ordering::SeqCst);
    let owner = Reclaimer::new();
    let mut operation = Construction::<Wrapped, Turn>::new(&owner, &document, 0);
    let mut output = None;
    for _ in 0..wire.len() * 64 {
        a.fresh();
        match operation.step(&mut a).unwrap() {
            Step::Progress => {}
            Step::Complete(value) => {
                output = Some(value);
                break;
            }
            Step::Finished => panic!("newtype finished without publication"),
        }
    }
    let output = output.expect("newtype failed its finite completion bound");
    assert_eq!(output.value().0, ["a", "bc"]);
    drop(operation);
    drop(output);
    let mut done = false;
    for _ in 0..wire.len() * 64 {
        a.fresh();
        if owner.shutdown_step(&mut a).unwrap() == Reclaimed::Done {
            done = true;
            break;
        }
    }
    assert!(done);
    assert_eq!(a.live.load(Ordering::SeqCst), document_bytes);
    drop(document);
    assert_eq!(a.live.load(Ordering::SeqCst), 0);
}

#[cfg(feature = "derive")]
#[test]
fn named_fields_build_in_wire_order_and_abort_missing_required_fields() {
    use dcbor::bounded::decode::construction::in_place::{Construction, Step};
    use dcbor::bounded::decode::{DecodeError, decode};

    #[derive(dcbor::CBORBoundedDecodable)]
    struct Named {
        #[cbor(n = 9)]
        numbers: Vec<u64>,
        #[cbor(n = 1)]
        text: String,
    }
    // Unknown key 3 is ignored. Declaration order differs from wire order.
    let complete = &[0xa3, 1, 0x61, b'x', 3, 0xf6, 9, 0x81, 7][..];
    let missing = &[0xa1, 1, 0x61, b'x'][..];
    for wire in [complete, missing] {
        let mut a = Turn::new();
        a.values = u64::MAX;
        a.bytes = u64::MAX;
        let document = decode(wire, 8, &mut a).unwrap();
        let document_bytes = a.live.load(Ordering::SeqCst);
        let owner = Reclaimer::new();
        let mut operation = Construction::<Named, Turn>::new(&owner, &document, 0);
        let mut failed = false;
        let mut finished = false;
        for _ in 0..wire.len() * 64 {
            a.fresh();
            match operation.step(&mut a) {
                Ok(Step::Progress) => {}
                Ok(Step::Complete(value)) => {
                    assert_eq!(wire, complete);
                    assert_eq!(value.value().text, "x");
                    assert_eq!(value.value().numbers, [7]);
                    drop(value);
                    finished = true;
                    break;
                }
                Err(DecodeError::Invalid(dcbor::Error::MissingMapKey)) => {
                    assert_eq!(wire, missing);
                    assert!(!failed, "terminal error replayed");
                    failed = true;
                }
                Ok(Step::Finished) => {
                    assert!(failed);
                    assert_eq!(a.live.load(Ordering::SeqCst), document_bytes);
                    finished = true;
                    break;
                }
                _ => panic!("unexpected named-field construction result"),
            }
        }
        drop(operation);
        let mut drained = false;
        for _ in 0..wire.len() * 64 {
            a.fresh();
            if owner.shutdown_step(&mut a).unwrap() == Reclaimed::Done {
                drained = true;
                break;
            }
        }
        assert!(finished && drained);
        assert_eq!(failed, wire == missing);
        assert_eq!(a.live.load(Ordering::SeqCst), document_bytes);
        drop(document);
        assert_eq!(a.live.load(Ordering::SeqCst), 0);
    }
}

#[cfg(feature = "derive")]
#[test]
fn tagged_named_construction_validates_tag_before_initializing_fields() {
    use dcbor::bounded::decode::construction::in_place::{Construction, Step};
    use dcbor::bounded::decode::{DecodeError, decode};

    #[derive(dcbor::CBORBoundedDecodable)]
    #[cbor(tag = 42)]
    struct Tagged {
        #[cbor(n = 0)]
        number: u64,
    }
    for tag in [42, 43] {
        let wire = [0xd8, tag, 0xa1, 0, 7];
        let mut a = Turn::new();
        a.values = u64::MAX;
        a.bytes = u64::MAX;
        let document = decode(&wire, 8, &mut a).unwrap();
        let document_bytes = a.live.load(Ordering::SeqCst);
        let owner = Reclaimer::new();
        let mut operation = Construction::<Tagged, Turn>::new(&owner, &document, 0);
        let mut terminal = false;
        let mut wrong_tag = false;
        for _ in 0..128 {
            a.fresh();
            match operation.step(&mut a) {
                Ok(Step::Progress) => {}
                Ok(Step::Complete(value)) => {
                    assert_eq!(tag, 42);
                    assert_eq!(value.value().number, 7);
                    drop(value);
                    terminal = true;
                    break;
                }
                Err(DecodeError::Invalid(dcbor::Error::WrongTag(expected, found))) => {
                    assert!(!wrong_tag);
                    assert_eq!(expected.value(), 42);
                    assert_eq!(found.value(), 43);
                    wrong_tag = true;
                }
                Ok(Step::Finished) => {
                    assert!(wrong_tag);
                    assert_eq!(a.live.load(Ordering::SeqCst), document_bytes);
                    terminal = true;
                    break;
                }
                _ => panic!("unexpected tagged construction result"),
            }
        }
        drop(operation);
        for _ in 0..128 {
            a.fresh();
            if owner.shutdown_step(&mut a).unwrap() == Reclaimed::Done {
                break;
            }
        }
        assert!(terminal);
        assert_eq!(owner.outstanding(), 0);
        assert_eq!(a.live.load(Ordering::SeqCst), document_bytes);
        drop(document);
        assert_eq!(a.live.load(Ordering::SeqCst), 0);
    }
}
