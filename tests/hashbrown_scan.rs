#![cfg(feature = "hashbrown")]

use dcbor::bounded::*;
use std::hash::{BuildHasherDefault, Hasher};

#[derive(Default)]
struct Collisions;
impl Hasher for Collisions {
    fn finish(&self) -> u64 {
        0
    }
    fn write(&mut self, _: &[u8]) {}
}

type Colliding = hashbrown::HashMap<u64, u64, BuildHasherDefault<Collisions>>;

/// `map`'s shape, walked as the operation walks it first.
fn shape(map: &Colliding) -> encoding::Shape {
    let source: &dyn Schema = map;
    encoding::Shape::of(source, &mut Limits::unlimited()).unwrap()
}

/// The complete operation's bound for `map`: its shape's walk, its
/// preparation and its publication ([`encode_bound`]).
fn complete_bound(map: &Colliding) -> ResourceBound {
    encode_bound::<Reservation, LimitRefusal>(shape(map)).unwrap()
}

/// The index of `map`'s last occupied bucket.
fn last_occupied(map: &Colliding) -> usize {
    (0..map.num_buckets())
        .rev()
        .find(|&bucket| map.get_bucket(bucket).is_some())
        .expect("the map holds an entry")
}

/// A map whose table keeps the controls of 1023 erased entries beside its
/// one live entry, the last inserted. The scan inspects bucket controls in
/// windows of [`encoding::BUCKET_WINDOW`], each admitted before it is
/// inspected, from the first bucket until the map's declared entries are
/// yielded: every control before the live entry is charged, erased ones
/// included, and none after it. A map of no entries scans nothing. A budget
/// short of the controls before the live entry is refused; work is consumed
/// as admitted, never refunded: the refused run keeps what it was admitted,
/// at most the complete operation's bound, its walk included; the refusal
/// is made before the unit it refuses, and nothing is admitted or published
/// after it.
#[test]
fn erased_controls_before_the_last_entry_remain_in_the_scan_bound() {
    let mut map = Colliding::default();
    for key in 0..1024 {
        map.insert(key, 0);
    }
    let allocation = map.allocation_size();
    let capacity = map.capacity();
    let buckets = map.num_buckets();
    for key in 0..1023 {
        map.remove(&key);
    }
    assert_eq!(map.allocation_size(), allocation);
    assert_eq!(
        map.num_buckets(),
        buckets,
        "removal keeps every bucket index"
    );
    assert!(
        map.capacity() < capacity,
        "fixture must leave deleted controls"
    );
    let last = last_occupied(&map);
    // The controls the scan must inspect: every one up to the live entry.
    let scanned = last as u64 + 1;
    let window = encoding::BUCKET_WINDOW;
    assert!(
        last >= window,
        "the live entry lies past the first window, behind erased controls"
    );

    // The scan stops at the declared entry: one instruction per window
    // before the live entry's, that window's, and the map's end; no window
    // of the tail after it.
    let walked = shape(&map);
    assert_eq!(walked.dynamic, (last / window) as u64 + 2);
    assert!(
        (walked.dynamic as usize - 1) * window < buckets,
        "the walk scanned the tail"
    );

    // Erased controls before the live entry are charged: the complete
    // encoding admits a byte for every one, within its complete bound.
    let complete = complete_bound(&map);
    let mut limits = Limits::new(1_000_000, 1_000_000, 100_000);
    let encoded = encode(&map, &mut limits).unwrap();
    assert_eq!(encoded.as_ref(), &[0xa1, 0x19, 0x03, 0xff, 0]);
    drop(encoded);
    assert_eq!(limits.live_bytes(), 0);
    let erased = limits.used();
    assert!(
        erased.bytes >= scanned,
        "{erased:?} admits fewer bytes than the {scanned} controls scanned"
    );
    assert!(
        complete.work().covers(&erased),
        "{erased:?} beyond the complete bound {complete:?}"
    );

    // A map of no entries, however large its table, scans nothing: its end
    // follows its head.
    let empty = Colliding::with_capacity_and_hasher(1024, Default::default());
    assert!(empty.num_buckets() >= 1024);
    assert_eq!(shape(&empty).dynamic, 1);
    let mut limits = Limits::new(1_000_000, 1_000_000, 100_000);
    let encoded = encode(&empty, &mut limits).unwrap();
    assert_eq!(encoded.as_ref(), &[0xa0]);
    drop(encoded);
    assert!(complete_bound(&empty).work().covers(&limits.used()));

    // A budget a byte short of the controls before the live entry is
    // refused for work.
    let allowance = scanned - 1;
    let mut limits = Limits::new(1_000_000, allowance, 100_000);
    assert_eq!(
        encode(&map, &mut limits).map(|encoded| encoded.as_ref().to_vec()),
        Err(BoundedError::Refused(LimitRefusal::Work))
    );
    // Nothing is published, and nothing is held.
    assert_eq!(limits.live_bytes(), 0);
    // The refusal came before the unit it refused: that unit would have
    // passed the allowance from the work admitted before it, and no work was
    // admitted after it.
    let refusal = limits.trace().first_refusal().expect("the run was refused");
    assert_eq!(refusal.result, Err(LimitRefusal::Work));
    let Call::Work { bytes, .. } = refusal.call else {
        panic!("a work refusal refused {:?}", refusal.call);
    };
    assert!(
        refusal.work.bytes + bytes > allowance,
        "{refusal:?} refused within the allowance {allowance}"
    );
    let consumed = limits.used();
    assert_eq!(consumed, refusal.work, "work admitted after the refusal");
    // What was consumed is kept, and is within the allowance and the
    // complete operation's bound, the walk that precedes the scan included.
    assert!(
        consumed.bytes <= allowance,
        "{consumed:?} beyond {allowance}"
    );
    assert!(
        complete.work().covers(&consumed),
        "{consumed:?} beyond the complete bound {complete:?}"
    );
    assert_eq!(limits.remaining().bytes, allowance - consumed.bytes);
}
