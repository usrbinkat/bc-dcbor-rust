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
