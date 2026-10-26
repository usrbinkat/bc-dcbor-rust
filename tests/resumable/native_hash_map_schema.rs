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

#[test]
fn entry_instruction_cannot_skip_more_than_admitted_controls() {
    struct InvalidAdvance(usize);
    impl Schema for InvalidAdvance {
        fn instruction(&self, index: usize) -> Instruction<'_> {
            if index == 0 {
                Instruction::UnorderedMap
            } else {
                Instruction::Entry {
                    next: self.0,
                    entry: None,
                }
            }
        }
    }
    // The malformed source reaches only the map opener and its first entry
    // instruction. A valid one-entry map includes that prefix plus key/value
    // preparation, ordering and publication, so its production bound covers
    // rejection without asking the shape walker to accept an invalid advance.
    let mut valid = HashMap::new();
    valid.insert(0u64, 0u64);
    let bound = shape(&valid);
    for next in [1, 66, usize::MAX] {
        let source = InvalidAdvance(next);
        refusal_matrix(&format!("invalid entry advance {next}"), rigor(), |fault| {
            prepare_run(&source, &Err(BoundedError::PlanMismatch), fault, bound)
        });
    }
}
