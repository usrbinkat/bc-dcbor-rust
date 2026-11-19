use super::harness::*;
use super::support::{refusal_matrix, rigor::rigor, shape};
use dcbor::bounded::{
    encoding::{Instruction, Schema},
    BoundedError,
};
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
fn hash_map_deleted_buckets_encode_literal_output_after_every_refusal() {
    let mut map =
        HashMap::with_capacity_and_hasher(64, BuildHasherDefault::<Collisions>::default());
    for key in 0u64..64 {
        map.insert(key, key + 1);
    }
    let buckets = map.num_buckets();
    for key in 0..64 {
        if ![0, 23, 63].contains(&key) {
            map.remove(&key);
        }
    }
    assert_eq!(map.num_buckets(), buckets);
    let expected = [0xa3, 0, 1, 23, 0x18, 24, 0x18, 63, 0x18, 64];
    prepare_matrix(&map, Ok(&expected));
}

/// The hash map of `first => 1` and `second => 2`. Every key hashes alike
/// ([`Collisions`]), so each entry takes the next bucket and the table yields
/// them in insertion order (checked), `first` the predecessor: deterministic
/// for both the pinned hashbrown and the forked standard library, whichever
/// `HashMap` this module is compiled against.
fn keyed(first: Number, second: Number) -> HashMap<Number, u64, BuildHasherDefault<Collisions>> {
    let mut map = HashMap::with_capacity_and_hasher(2, BuildHasherDefault::<Collisions>::default());
    assert_eq!(map.insert(first, 1), None);
    assert_eq!(map.insert(second, 2), None);
    assert_eq!(
        map.keys().copied().collect::<Vec<_>>(),
        [first, second],
        "the table yields its keys in insertion order"
    );
    map
}

/// `10` then `10.0`, and `0` then `-0.0`: distinct hash map keys of one
/// canonical encoding. A hash table's entries are enumerated by the engine's
/// bucket traversal and merge-ordered by their prepared key bytes, so the
/// equal pair is refused by the merge (`encoding/maps/order.rs`, `Compare`)
/// as an invalid input (`DuplicateKey`, `Class::Invalid`), its comparison of
/// merge candidates recorded as a merge-order collision; across every refusal and
/// cancellation schedule too. The predecessor check (`encoding/dynamic.rs`,
/// `key-order`) is reached by the ordered path's claimed tree
/// (`native_schema_encoding.rs`).
#[test]
fn keys_colliding_after_reduction_are_refused_on_the_hash_path() {
    for (first, second) in [
        (Number::Integer(10), Number::Float(10.0)),
        (Number::Integer(0), Number::Float(-0.0)),
    ] {
        let map = keyed(first, second);
        let reached = key_order(&map, Err(BoundedError::DuplicateKey));
        assert!(
            reached.contains(MERGE_COLLISION),
            "{first:?} then {second:?}: no merge-order collision recorded"
        );
        prepare_matrix(&map, Err(BoundedError::DuplicateKey));
    }
}

/// The control: `10` then `10.5`, distinct canonical keys, encode in
/// canonical order, the later run's merge candidate recorded strictly after
/// the earlier's and never as a collision.
#[test]
fn distinct_keys_encode_and_record_their_order_on_the_hash_path() {
    let map = keyed(Number::Integer(10), Number::Float(10.5));
    let expected = [0xa2, 0x0a, 0x01, 0xf9, 0x49, 0x40, 0x02];
    let reached = key_order(&map, Ok(&expected));
    assert!(reached.contains(MERGE_AFTER), "no merge-order past recorded");
    assert!(
        !reached.contains(MERGE_COLLISION),
        "distinct keys recorded a collision"
    );
    prepare_matrix(&map, Ok(&expected));
}

/// A source can no longer skip bucket controls: `Instruction::Entry` carries
/// one entry and no index, and only the engine inspects a hash table's
/// buckets. What a source can still get wrong is offering an entry where no
/// unordered map takes one: refused, after every refusal schedule, for a
/// counted field map and an uncounted one.
#[test]
fn an_entry_offered_to_a_field_map_is_refused() {
    struct Misplaced(bool);
    impl Schema for Misplaced {
        fn instruction(&self, index: usize) -> Instruction<'_> {
            match index {
                0 if self.0 => Instruction::CountedMap(1),
                0 => Instruction::Map,
                _ => Instruction::Entry(&0u64, &0u64),
            }
        }
    }
    // The malformed source reaches only the map opener and its entry. A
    // valid one-entry map includes that prefix plus key and value
    // preparation, ordering and publication, so its production bound covers
    // the rejection without asking the shape walker to accept the protocol.
    let mut valid = HashMap::new();
    valid.insert(0u64, 0u64);
    let bound = shape(&valid);
    for counted in [true, false] {
        let source = Misplaced(counted);
        refusal_matrix(&format!("entry in a field map, counted {counted}"), rigor(), |fault| {
            prepare_run(&source, &Err(BoundedError::PlanMismatch), fault, bound)
        });
    }
}
