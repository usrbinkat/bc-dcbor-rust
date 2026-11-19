//! Kani harness of the preparation's whole-operation bound (register item
//! 4), written and unverified until the gate runs it: [`encode_bound`] of a
//! source's shape ([`Shape::of`]) covers what [`encode`] (the shape walk,
//! the preparation and publication in place) admits, requests, holds at once
//! and retains, unrefused and under a policy refusal at any one admission
//! attempt or allocation request, for every source of the domain. Policy
//! refusal at every attempt and request is covered; physical reservation
//! failure is not: `Vec::try_reserve_exact` under Kani's allocator never
//! fails, so the `Effect::Failed` paths are outside the domain.
//!
//! Domain, stated: every source a [`Source`] describes. Its root is one of
//! a leaf, an array of up to [`WIDTH`] children, a field map of up to
//! [`WIDTH`] fields (any keys, in any order), or an unordered map of up to
//! [`WIDTH`] entries (any keys, colliding ones included); each child, field
//! value, key and entry value is a leaf: an unsigned or negative integer of
//! any value, a byte string of up to [`BYTES`] bytes of any value, or a text
//! of up to [`BYTES`] bytes of any UTF-8 (normalized or not). Each leaf
//! answers as the crate's own schemas do (`values.rs`): a number its head,
//! then `End` (`numeric`, :171-177); a text `Text`, then `End` (`str`,
//! :268-276); a byte string its head, its `Bytes`, then `End` (:282-292);
//! the root an array's head and children (`[T]`, :294-301), a field map's
//! `Map`, `Field`s and `End`, or an unordered map's `UnorderedMap`,
//! `Entry`s and `End`. And one refusal at any one attempt and one at any
//! one request (each index any `u64` or none, an index past the run's last
//! refusing nothing). The encoding is synchronous and ends at its first
//! refusal, which every step returns through `?` (`bounded.rs` `prepare`,
//! :2494; `Prepared::publish`, writer.rs:145), so at most one of the two
//! refuses in a run and no loop gains an iteration for a refusal. Granted
//! bytes are checked against the bound's `allocated`, the sum of the
//! requests an operation is granted (`ResourceBound::allocated`,
//! `bounded.rs`:2151-2152); every attempted request's bytes, the refused
//! one included, against `allocated` and one request more, at most the
//! bound's `peak`: a request's bytes are held at once once granted, so no
//! single request exceeds the peak (`ResourceBound::peak`, :2153-2155).
//!
//! The general argument beyond the domain is the bound's own composition:
//! the walk's work (`walk_work`), every place of the preparation
//! (`PreparationTerms`), each a constant per instruction or a charge rule's
//! bytes, the arenas grown by the growth recurrence (`growth_proofs.rs`), a
//! text's normalization by `text_cursor`'s bound, key comparison by
//! `comparison_bound` (`decode/comparison/proofs.rs`), and publication by
//! `emit_bound` (`writer/proofs.rs`). This harness checks their composition
//! over the domain. The normalization's premise is checked over its own
//! domain, not by a harness: `text_cursor.rs`
//! `every_alphabet_text_is_encoded_within_its_bound_at_every_refusal_and_cancellation`,
//! every text of its alphabet up to five bytes, unrefused, refused at every
//! attempt and request, and cancelled before every step.
//!
//! # Unwind
//!
//! The longest loop the domain reaches is the preparation's engine loop
//! (`bounded.rs` `prepare`, `for _ in 0..steps`, :2493): it steps until the
//! plan completes, one admitted unit or more per step, each unit of at least
//! one value or a request whose release was admitted as a value
//! (`ResourceBound::steps`, :2166-2172), so at most the preparation bound's
//! values. The source of most values is an unordered map of [`WIDTH`]
//! entries whose four leaves are texts of one two-byte scalar of three
//! parts, two of them combining (U+01D5): each text's extent 6 (head and
//! part bytes, `Shape::text`, encoding.rs:1880-1891), so 12 instructions,
//! depth 2, one map, 2 entries, 2 merge levels, 4 merges, 24 key-merge and
//! payload bytes, 48 payload probes, extent 25, appended 34
//! (`Shape::walk`, :1929-2108; `Shape::merged`, :1895-1905). A byte
//! string's extent is 3, an integer's at most 9; a text adds its
//! normalization, so four such texts give the most. `PreparationTerms::of`
//! (encoding.rs:2644-3005) values, every unit of one value but ordering's
//! `MARK` (3, `text_cursor/ordering.rs`:31-35) and `COMPOSE` (2,
//! `text_cursor.rs`:397-401):
//!
//! - Instructions 12 (`INDEXED`, :2739); Pushes 15 (`PUSH`, :2768);
//! - the arenas, each relocated elements plus six per growth (four writes,
//!   `storage.rs` `GROWTH_WRITES` :209, and two releases): frames,
//!   gaps, open maps, cursors, windows, descriptors, scratch one growth each
//!   (6 each, 42), the plan of 35 bytes five growths and 60 relocated (90);
//! - Appends 20 (`APPEND.covering(34, 12 + 7)`, :2799);
//! - Texts 544: 4 check windows, the continuation's 38 initialization
//!   steps per text (`text_cursor/initialization.rs`:9-10; `Storage`
//!   `INIT_STEPS` 6, `storage.rs`:266; `PENDING_UNITS` 4, `stable.rs`:418)
//!   152, the normalizations 380 (95 per text, `TextTerms::of`,
//!   `text_cursor.rs`:572-656: reading 2, appending 9, copying 9, ordering
//!   46, two releases 6 each, composing 8, measuring 4, header 1, emitting
//!   4), publication 4 and output releases 4;
//! - Compaction 23, Merging 32, Comparisons 7, Check 3, Permutation 111,
//!   Visited 26, Completion 4, Cleanup 77 (:2843-3005).
//!
//! Together 1006. The other loops reached are shorter: the shape walk's
//! (per source, at most four instructions, :1952); `Owned::reserve`'s
//! growth loop and `owned_growth`'s (at most six growths at 35 elements,
//! `bounded.rs`:1799, :1977); the merge and permutation at two entries; the
//! normalization's ordering tables of sixteen counters
//! (`text_cursor/ordering.rs`:51); publication's segment loop, at most
//! `emit_bound(34)`'s 70 values (`writer.rs`:143); the places' folds over
//! at most 21 places (`bounded.rs` `additive`, :669). No bucket loop is
//! compiled: the harness builds without `hashbrown` and
//! `custom-std-collections` (`tests/gate/src/proofs.rs` `arguments`).
//! `kani::unwind(1007)`: the engine loop's 1006 iterations and its exit.
//! Compiled only under `cfg(kani)`.

use super::super::proof_budget::{Counting, Permit};
use super::{Argument, Instruction, MajorType, Schema, Shape, encode_bound};
use crate::bounded::{BoundedError, encode};

/// The most children, fields or entries of the root.
const WIDTH: usize = 2;

/// The most bytes of a byte string or a text leaf.
const BYTES: usize = 2;

/// A leaf of the domain.
#[derive(Clone, Copy)]
enum Leaf {
    Unsigned(u64),
    Negative(u64),
    Bytes([u8; BYTES], usize),
    /// UTF-8 by construction ([`any_leaf`]).
    Text([u8; BYTES], usize),
}

impl Schema for Leaf {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        match (self, index) {
            (Leaf::Unsigned(value), 0) => {
                Instruction::Head(MajorType::Unsigned, Argument::Shortest(*value))
            }
            (Leaf::Negative(value), 0) => {
                Instruction::Head(MajorType::Negative, Argument::Shortest(*value))
            }
            (Leaf::Bytes(_, length), 0) => {
                Instruction::Head(MajorType::ByteString, Argument::Shortest(*length as u64))
            }
            (Leaf::Bytes(bytes, length), 1) => Instruction::Bytes(&bytes[..*length]),
            // UTF-8 by construction; a text that were not would be outside
            // the profile, never a panic.
            (Leaf::Text(bytes, length), 0) => match core::str::from_utf8(&bytes[..*length]) {
                Ok(text) => Instruction::Text(text),
                Err(_) => Instruction::OutOfRange,
            },
            _ => Instruction::End,
        }
    }
}

/// Any leaf of the domain.
fn any_leaf() -> Leaf {
    let bytes: [u8; BYTES] = kani::any();
    let length: usize = kani::any();
    kani::assume(length <= BYTES);
    match kani::any::<u8>() % 4 {
        0 => Leaf::Unsigned(kani::any()),
        1 => Leaf::Negative(kani::any()),
        2 => Leaf::Bytes(bytes, length),
        _ => {
            kani::assume(core::str::from_utf8(&bytes[..length]).is_ok());
            Leaf::Text(bytes, length)
        }
    }
}

/// A source of the domain: a root of one kind over its leaves.
struct Source {
    kind: u8,
    count: usize,
    keys: [Leaf; WIDTH],
    fields: [u64; WIDTH],
    values: [Leaf; WIDTH],
}

impl Schema for Source {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        let at = index.checked_sub(1).filter(|&at| at < self.count);
        match self.kind {
            // An array of `count` children.
            0 => match (index, at) {
                (0, _) => {
                    Instruction::Head(MajorType::Array, Argument::Shortest(self.count as u64))
                }
                (_, Some(at)) => Instruction::Child(&self.values[at]),
                _ => Instruction::End,
            },
            // A field map of `count` fields.
            1 => match (index, at) {
                (0, _) => Instruction::Map,
                (_, Some(at)) => Instruction::Field(self.fields[at], Some(&self.values[at])),
                _ => Instruction::End,
            },
            // An unordered map of `count` entries.
            2 => match (index, at) {
                (0, _) => Instruction::UnorderedMap,
                (_, Some(at)) => Instruction::Entry(&self.keys[at], &self.values[at]),
                _ => Instruction::End,
            },
            // A leaf.
            _ => self.values[0].instruction(index),
        }
    }
}

/// None, or any index.
fn any_index() -> Option<u64> {
    if kani::any() { Some(kani::any()) } else { None }
}

/// Every source of the domain, under one refusal at any one attempt and one
/// at any one request, is encoded or
/// refused within the bound of its shape: the work admitted, the bytes
/// requested and the most held at once, each at most the bound's, and what
/// the encoding retains at most the bound's; a refused encoding returns its
/// refusal and retains nothing; nothing is held once the result drops. A
/// source whose walk fails has no shape and no bound: its encoding fails
/// too.
#[kani::proof]
#[kani::unwind(1007)]
fn the_encoding_bound_covers_every_source() {
    let count: usize = kani::any();
    kani::assume(count <= WIDTH);
    let source = Source {
        kind: kani::any::<u8>() % 4,
        count,
        keys: [any_leaf(), any_leaf()],
        fields: [kani::any(), kani::any()],
        values: [any_leaf(), any_leaf()],
    };
    let shape = Shape::of(&source, &mut Counting::new(false));
    let mut policy = Counting::scheduled(any_index(), any_index());
    let encoded = encode(&source, &mut policy);
    let retained = policy.live();
    let returned_refusal = matches!(encoded, Err(BoundedError::Refused(())));
    let encoded_ok = encoded.is_ok();
    drop(encoded);
    assert!(
        policy.live() == 0,
        "nothing is held once the encoding drops"
    );
    if policy.refused {
        assert!(returned_refusal, "a refused encoding returns its refusal");
        assert!(retained == 0, "a refused encoding retains nothing");
    }
    match shape {
        Err(_) => assert!(!encoded_ok, "a source whose walk fails is not encoded"),
        Ok(shape) => {
            let bound = encode_bound::<Permit, (), ()>(shape).expect("the domain's bound fits");
            assert!(
                bound.work().covers(&policy.admitted),
                "the encoding admits no more work than its bound"
            );
            assert!(
                policy.granted <= bound.allocated,
                "the encoding requests no more than its bound"
            );
            assert!(
                u128::from(policy.requested)
                    <= u128::from(bound.allocated) + u128::from(bound.peak),
                "the encoding's attempted requests, a refused one included, are within its bound and one request more"
            );
            assert!(
                policy.peak <= bound.peak,
                "the encoding holds no more at once than its bound"
            );
            assert!(
                retained <= bound.retained,
                "the encoding retains no more than its bound"
            );
        }
    }
}
