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

#[test]
fn erased_controls_remain_in_the_synchronous_scan_bound() {
    let mut map = hashbrown::HashMap::<u64, u64, BuildHasherDefault<Collisions>>::default();
    for key in 0..1024 {
        map.insert(key, 0);
    }
    let allocation = map.allocation_size();
    let capacity = map.capacity();
    for key in 1..1024 {
        map.remove(&key);
    }
    assert_eq!(map.allocation_size(), allocation);
    assert!(
        map.capacity() < capacity,
        "fixture must leave deleted controls"
    );
    let old_bound = 2 * map.capacity() as u64 + 1;
    assert!(old_bound < allocation as u64);
    let mut limits = Limits::new(old_bound, old_bound, 100_000);
    assert!(matches!(
        encode(&map, &mut limits),
        Err(BoundedError::Refused(LimitRefusal::Work))
    ));
    assert_eq!(limits.live_bytes(), 0);
    assert_eq!(limits.remaining().values, old_bound);
    assert_eq!(limits.remaining().bytes, old_bound);

    let mut limits = Limits::new(1_000_000, 1_000_000, 100_000);
    let encoded = encode(&map, &mut limits).unwrap();
    assert_eq!(encoded.as_ref(), &[0xa1, 0, 0]);
    drop(encoded);
    assert_eq!(limits.live_bytes(), 0);
}
