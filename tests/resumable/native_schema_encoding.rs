use super::harness::*;
use super::support::{
    Fault, Finding, Retirement, pipeline::Unwitnessed, prepare_turns, refusal_matrix, rigor::rigor,
    shape,
};
use dcbor::bounded::{
    BoundedError,
    encoding::{Instruction, Preparation, Schema},
};
use dcbor_derive::CBORBoundedEncodable;

#[derive(CBORBoundedEncodable)]
pub(super) struct Record {
    #[cbor(n = 24)]
    pub(super) omitted: Option<String>,
    #[cbor(n = 1)]
    pub(super) nested: Vec<Vec<String>>,
    #[cbor(n = 0)]
    pub(super) enabled: bool,
}

#[test]
fn derived_schema_every_admission_resumes_without_replay_and_cancels() {
    let source = Record {
        omitted: None,
        enabled: true,
        nested: vec![vec!["e\u{301}".into()]],
    };
    prepare_matrix(
        &source,
        Ok(&[0xa2, 0, 0xf5, 1, 0x81, 0x81, 0x62, 0xc3, 0xa9]),
    );
}

#[derive(CBORBoundedEncodable)]
enum Shape<T> {
    #[cbor(n = 7)]
    Unit,
    #[cbor(n = 24)]
    Tuple(T, Option<u64>),
    #[cbor(n = 2)]
    Named {
        #[cbor(n = 256)]
        absent: Option<T>,
        #[cbor(n = 24)]
        present: Option<T>,
        #[cbor(n = 0)]
        count: u64,
    },
}

/// The fault matrix of emitting `source`'s plan into a guarded destination
/// ([`refusal_matrix`]): every refusal resumed without replay, a refused
/// step moving nothing, and a cancellation at every call ending the trace
/// there. The plan is prepared and held by the run, then emitted by the
/// held emission schedule ([`emit_held`]), which never allocates, never
/// writes outside its destination, and never changes the plan's storage.
/// Each run prepares its plan under a family of its own and emits it under
/// another, the fault applied to the emission alone, so the matrix reads
/// the emission's calls. Named by its call site.
#[track_caller]
fn emission_matrix(source: &dyn Schema, expected: &[u8]) {
    let name = format!("emit at {}", std::panic::Location::caller());
    refusal_matrix(&name, rigor(), |fault: Fault| {
        super::support::recorded_run(|run| {
            let preparing = run.policy(POOL);
            let emitting = run.policy(POOL);
            run.holding(
                Preparation::new(source),
                Retirement::Released,
                &Unwitnessed,
                |operation| {
                    operation
                        .drive(
                            preparing,
                            prepare_turns(shape(source)),
                            Retirement::Released,
                            |plan| emit_held(plan, preparing, emitting, expected, fault),
                        )
                        .map_err(Finding::from)?
                },
            )?;
            run.with_policy(preparing, |m| assert_eq!(m.live_bytes(), 0));
            Ok(run.with_policy(emitting, |m| {
                assert_eq!(m.requests(), 0, "emission requested allocation");
                super::support::RefusalRun::of(m)
            }))
        })
    });
}

#[test]
fn enum_generic_optional_tagged_and_numeric_literals_survive_emission_refusals() {
    emission_matrix(&Shape::<String>::Unit, &[7]);
    emission_matrix(
        &Shape::Tuple("a".to_string(), None),
        &[0x83, 0x18, 24, 0x61, b'a', 0xf6],
    );
    let named = Shape::Named {
        absent: None,
        present: Some("a".to_string()),
        count: 1,
    };
    emission_matrix(&named, &[0x82, 2, 0xa2, 0, 1, 0x18, 24, 0x61, b'a']);
    emission_matrix(
        &dcbor::bounded::Tagged {
            tag: 42,
            value: named,
        },
        &[0xd8, 42, 0x82, 2, 0xa2, 0, 1, 0x18, 24, 0x61, b'a'],
    );
    emission_matrix(
        &vec![1.0f64, 1.5, f64::NAN],
        &[0x83, 1, 0xf9, 0x3e, 0, 0xf9, 0x7e, 0],
    );
    emission_matrix(&vec![-1i64, -25], &[0x82, 0x20, 0x38, 24]);
    emission_matrix(&[Some(1u64), None, Some(24)], &[0x83, 1, 0xf6, 0x18, 24]);
}

/// Ordered collections walked without searching: by the tree's own iterator
/// on stable, its node moves admitted with each step, and by the forked
/// std's stepped cursor, one admitted transition per step. A `BTreeMap`'s
/// entries are placed by their prepared key bytes, whatever the tree's own
/// order; a `dcbor::Map`'s come in canonical order and are checked in one
/// pass. The symbolic encoder is the independent oracle for every literal.
mod ordered {
    use super::*;
    use dcbor::{CBOR, CBORCase, CBOREncodable, Map};
    use std::collections::BTreeMap;

    /// The symbolic encoder's bytes for `value` ([`CBOREncodable`]), by
    /// reference; the fixtures here all encode.
    fn symbolic<T: CBOREncodable>(value: &T) -> Vec<u8> {
        value.encode_cbor_data().expect("the fixture encodes")
    }

    /// The canonical encoding of a map of `count` entries `n => n`.
    fn identity_map(count: u64) -> Vec<u8> {
        let mut expected = match count {
            0..24 => vec![0xa0 | count as u8],
            24..256 => vec![0xb8, count as u8],
            _ => panic!("identity map literal covers fewer than 256 entries"),
        };
        for n in 0..count {
            for _ in 0..2 {
                if n < 24 {
                    expected.push(n as u8);
                } else {
                    expected.extend([0x18, n as u8]);
                }
            }
        }
        expected
    }

    #[test]
    fn btree_map_entries_take_canonical_key_order_not_tree_order() {
        let source = BTreeMap::from([
            ("aa".to_string(), 1u64),
            ("b".to_string(), 2),
            ("e\u{301}".to_string(), 4),
            ("z".to_string(), 3),
        ]);
        // Tree order is aa, b, e+U+0301, z; canonical order sorts the
        // shorter encoded keys first and compares the normalized bytes.
        let expected = [
            0xa4, 0x61, b'b', 2, 0x61, b'z', 3, 0x62, b'a', b'a', 1, 0x62, 0xc3, 0xa9, 4,
        ];
        assert_eq!(symbolic(&source), expected);
        prepare_matrix(&source, Ok(&expected));
        emission_matrix(&source, &expected);
    }

    #[test]
    fn btree_map_keys_distinct_in_the_tree_but_canonically_equal_are_rejected() {
        let source = BTreeMap::from([("e\u{301}".to_string(), 1u64), ("\u{e9}".to_string(), 2)]);
        prepare_matrix(&source, Err(BoundedError::DuplicateKey));
    }

    #[test]
    fn empty_and_nested_trees_stack_their_cursors_as_keys_and_values() {
        prepare_matrix(&BTreeMap::<u64, u64>::new(), Ok(&[0xa0]));
        let values = BTreeMap::from([
            (1u64, BTreeMap::from([(2u64, vec![3u64])])),
            (0, BTreeMap::new()),
        ]);
        let expected = [0xa2, 0, 0xa0, 1, 0xa1, 2, 0x81, 3];
        assert_eq!(symbolic(&values), expected);
        prepare_matrix(&values, Ok(&expected));
        // A key's cursor is started and finished while the outer cursor is
        // suspended between two of its entries.
        let keys = BTreeMap::from([(BTreeMap::from([(1u64, 0u64)]), 7u64), (BTreeMap::new(), 8)]);
        let expected = [0xa2, 0xa0, 8, 0xa1, 1, 0, 7];
        assert_eq!(symbolic(&keys), expected);
        prepare_matrix(&keys, Ok(&expected));
    }

    /// The fewest entries whose tree has an internal node, read from the
    /// engine's height ([`dcbor::bounded::encoding::tree_height`]): its cursor
    /// descends, ascends and yields from an internal node.
    fn internal_node_entries() -> usize {
        (1..)
            .find(|&len| dcbor::bounded::encoding::tree_height(len) > 1)
            .expect("some tree has an internal node")
    }

    /// More entries than one leaf holds: the cursor descends, ascends and
    /// yields from internal nodes, one admitted transition per instruction.
    /// The fast layer's tree holds the fewest entries whose tree has an
    /// internal node ([`internal_node_entries`]); the two-byte map head and
    /// two-byte keys are emission's concern, refused at every admission by
    /// `wide_schema_finalizes_multibyte_map_head_without_payload_relocation`.
    /// The exhaustive layer's tree holds 40.
    #[test]
    fn multi_level_tree_is_walked_through_every_internal_node_transition() {
        use super::super::support::rigor::Rigor;
        let entries = match rigor() {
            Rigor::Fast => internal_node_entries(),
            Rigor::Exhaustive => 40,
        };
        let source: BTreeMap<u64, u64> = (0..entries as u64).map(|n| (n, n)).collect();
        let expected = identity_map(entries as u64);
        assert_eq!(symbolic(&source), expected);
        prepare_matrix(&source, Ok(&expected));
        emission_matrix(&source, &expected);
    }

    /// Every physical request of a tree's preparation failed in a run of its
    /// own. Each key needs normalization and the values' marks run from none
    /// to seven, so every text path, quick-check proven or normalized, is
    /// taken. The fast layer's tree holds the fewest entries whose tree has
    /// an internal node ([`internal_node_entries`]); the exhaustive layer's
    /// holds 64.
    #[test]
    fn every_tree_preparation_allocation_failure_preserves_physical_ownership() {
        use super::super::support::rigor::Rigor;
        let entries = match rigor() {
            Rigor::Fast => internal_node_entries(),
            Rigor::Exhaustive => 64,
        };
        assert!(entries >= 8, "the values' marks run from none to seven");
        let source: BTreeMap<String, String> = (0..entries)
            .map(|n| (format!("{n:02}e\u{301}"), "e\u{301}".repeat(n % 8)))
            .collect();
        prepare_physical_matrix(&source);
    }

    #[test]
    fn dcbor_map_matches_the_symbolic_encoder_across_every_refusal() {
        let mut map = Map::new();
        map.insert("k", 1.5f64).unwrap();
        map.insert(-1i64, true).unwrap();
        map.insert(10u64, "a").unwrap();
        let expected = [
            0xa3, 0x0a, 0x61, b'a', 0x20, 0xf5, 0x61, b'k', 0xf9, 0x3e, 0x00,
        ];
        assert_eq!(map.cbor_data(), expected);
        prepare_matrix(&map, Ok(&expected));
        emission_matrix(&map, &expected);
        prepare_physical_matrix(&map);
        prepare_matrix(&Map::new(), Ok(&[0xa0]));
    }

    #[test]
    fn symbolic_values_of_every_major_type_match_the_symbolic_encoder() {
        let mut inner = Map::new();
        inner.insert("b", 2u64).unwrap();
        inner.insert("a", 1u64).unwrap();
        let value = CBOR::from(vec![
            CBOR::from(0u64),
            CBOR::from(-25i64),
            CBOR::to_byte_string([1u8, 2]),
            CBOR::from(CBORCase::Text("e\u{301}".to_string())),
            CBOR::to_tagged_value(42u64, 7u64),
            CBOR::null(),
            CBOR::from(1.5f64),
            CBOR::from(inner),
        ]);
        let expected = [
            0x88, 0, 0x38, 24, 0x42, 1, 2, 0x62, 0xc3, 0xa9, 0xd8, 42, 7, 0xf6, 0xf9, 0x3e, 0,
            0xa2, 0x61, b'a', 1, 0x61, b'b', 2,
        ];
        assert_eq!(value.to_cbor_data(), expected);
        prepare_matrix(&value, Ok(&expected));
        emission_matrix(&value, &expected);
        prepare_physical_matrix(&value);
    }

    #[test]
    fn out_of_profile_negative_integers_are_rejected_wherever_they_occur() {
        let boundary = CBOR::from(CBORCase::Negative(i64::MAX as u64));
        let expected = [0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(boundary.to_cbor_data(), expected);
        prepare_matrix(&boundary, Ok(&expected));
        let wide = CBOR::from(CBORCase::Negative(i64::MAX as u64 + 1));
        // Replacing the rejected scalar by the largest valid negative
        // preserves structure and bounds all work before rejection.
        prepare_matrix_bounded(
            &wide,
            Err(BoundedError::OutOfRange),
            super::super::support::shape(&boundary),
        );
        let element = CBOR::from(vec![CBOR::from(1u64), wide.clone()]);
        let valid_element = CBOR::from(vec![CBOR::from(1u64), boundary.clone()]);
        prepare_matrix_bounded(
            &element,
            Err(BoundedError::OutOfRange),
            super::super::support::shape(&valid_element),
        );
        let mut entry = Map::new();
        entry.insert(0u64, wide.clone()).unwrap();
        let mut valid_entry = Map::new();
        valid_entry.insert(0u64, boundary.clone()).unwrap();
        prepare_matrix_bounded(
            &CBOR::from(entry),
            Err(BoundedError::OutOfRange),
            super::super::support::shape(&CBOR::from(valid_entry)),
        );
        prepare_matrix_bounded(
            &CBOR::to_tagged_value(1u64, wide),
            Err(BoundedError::OutOfRange),
            super::super::support::shape(&CBOR::to_tagged_value(1u64, boundary)),
        );
    }

    /// `depth` arrays nested around zero.
    fn nested(depth: usize) -> CBOR {
        let mut value = CBOR::from(0u64);
        for _ in 0..depth {
            value = CBOR::from(vec![value]);
        }
        value
    }

    #[test]
    fn symbolic_nesting_is_bounded_by_the_engine_frame_limit() {
        // The root and every nested value hold one frame each; 128 frames
        // are the limit.
        let deepest = nested(127);
        let mut expected = vec![0x81; 127];
        expected.push(0);
        assert_eq!(deepest.to_cbor_data(), expected);
        prepare_matrix(&deepest, Ok(&expected));
        // One additional array contributes its head and child/end
        // instructions. No 129th frame is acquired before rejection.
        let mut bound = super::super::support::shape(&deepest);
        bound.instructions += 3;
        bound.extent += 1;
        prepare_matrix_bounded(&nested(128), Err(BoundedError::DepthLimit), bound);
    }
}

/// Map keys that collide after numeric reduction, on the ordered path: tree
/// sources whose entry cursor yields the two keys as predecessor and
/// successor. Two sources, one per refusal site:
///
/// - a `BTreeMap<Number, u64>`, whose `Entries::ordered` is `false`
///   (`encoding/values.rs`: Rust key order is not canonical key order), so
///   its entries are merge-ordered by their prepared key bytes and an equal
///   pair is refused by the merge (`encoding/maps/order.rs`, `Compare`);
/// - [`Claimed`], the same tree claiming canonical order, whose keys the
///   engine checks each against the one before it instead of sorting
///   (`encoding/dynamic.rs`, `Verify`), the path a `dcbor::Map` takes, which
///   itself can no longer hold two keys of one canonical encoding.
///
/// Either refuses an equal pair as `DuplicateKey`. The merge records its run
/// heads' comparison as `merge-order`, the predecessor check its adjacent
/// keys' as `key-order`: two events, two predicates.
mod key_order {
    use super::*;
    use dcbor::bounded::encoding::{Entries, EntryStep, Slot};
    use std::collections::BTreeMap;

    /// A tree whose entries are claimed to come in canonical order. Its
    /// cursor is the tree's own; the claim is what the engine checks pair by
    /// pair, refusing an out-of-order pair, so a false claim is a refusal,
    /// never unsound.
    struct Claimed(BTreeMap<Number, u64>);

    impl Schema for Claimed {
        fn instruction(&self, index: usize) -> Instruction<'_> {
            match index {
                0 => Instruction::CountedUnorderedMap(self.0.len() as u64),
                1 => Instruction::Entries(self),
                _ => Instruction::End,
            }
        }
    }

    // SAFETY: `start`, `moves` and `next` delegate to the tree's own
    // `Entries` implementation, whose cursor `start` stores in the slot and
    // `next` reads back as the same type; only `ordered` differs, a claim the
    // engine verifies key by key.
    unsafe impl Entries for Claimed {
        fn start(&self, slot: &mut Slot) {
            self.0.start(slot);
        }

        fn moves(&self) -> u64 {
            self.0.moves()
        }

        fn ordered(&self) -> bool {
            true
        }

        unsafe fn next<'a>(&'a self, slot: &mut Slot) -> EntryStep<'a> {
            // SAFETY: `start` stored the tree's cursor in `slot`.
            unsafe { self.0.next(slot) }
        }
    }

    /// The tree of `first => 1` and `second => 2`, required to yield them in
    /// that order, so `first` is `second`'s predecessor: an integer orders
    /// before every float ([`Number`]).
    fn tree(first: Number, second: Number) -> BTreeMap<Number, u64> {
        let tree = BTreeMap::from([(first, 1), (second, 2)]);
        assert_eq!(
            tree.keys().copied().collect::<Vec<_>>(),
            [first, second],
            "the tree yields its keys in the order the fixture names"
        );
        tree
    }

    /// The pairs that are one canonical key after numeric reduction.
    const COLLIDING: [(Number, Number); 2] = [
        (Number::Integer(10), Number::Float(10.0)),
        (Number::Integer(0), Number::Float(-0.0)),
    ];

    /// `10` then `10.0`, and `0` then `-0.0`: each pair refused as an
    /// invalid input (`DuplicateKey`, `Class::Invalid`) at its comparison,
    /// which records a collision of its own predicate: `merge-order` by the
    /// merge (`order.rs`) for the tree, `key-order` by the predecessor check
    /// (`dynamic.rs`) for the claimed tree; across every refusal and
    /// cancellation schedule too.
    #[test]
    fn keys_colliding_after_reduction_are_refused_on_the_ordered_path() {
        for (first, second) in COLLIDING {
            let merged = tree(first, second);
            let checked = Claimed(tree(first, second));
            for (site, source, collision) in [
                ("merge", &merged as &dyn Schema, MERGE_COLLISION),
                ("predecessor check", &checked as &dyn Schema, KEY_COLLISION),
            ] {
                let reached = key_order(source, Err(BoundedError::DuplicateKey));
                assert!(
                    reached.contains(collision),
                    "{first:?} then {second:?}, {site}: no {collision:?} recorded"
                );
                prepare_matrix_named(
                    &format!("colliding {first:?} then {second:?}, {site}"),
                    source,
                    Err(BoundedError::DuplicateKey),
                    shape(source),
                );
            }
        }
    }

    /// The control: `10` then `10.5`, distinct canonical keys, encode in
    /// canonical order at both sites, each comparison recorded as strictly
    /// after, by its own predicate, and never as a collision of either.
    #[test]
    fn distinct_keys_encode_and_record_their_order_on_the_ordered_path() {
        let merged = tree(Number::Integer(10), Number::Float(10.5));
        let checked = Claimed(tree(Number::Integer(10), Number::Float(10.5)));
        let expected = [0xa2, 0x0a, 0x01, 0xf9, 0x49, 0x40, 0x02];
        for (site, source, after) in [
            ("merge", &merged as &dyn Schema, MERGE_AFTER),
            ("predecessor check", &checked as &dyn Schema, KEY_AFTER),
        ] {
            let reached = key_order(source, Ok(&expected));
            assert!(reached.contains(after), "{site}: no {after:?} recorded");
            for collision in [KEY_COLLISION, MERGE_COLLISION] {
                assert!(
                    !reached.contains(collision),
                    "{site}: distinct keys recorded {collision:?}"
                );
            }
            prepare_matrix_named(
                &format!("distinct numeric keys, {site}"),
                source,
                Ok(&expected),
                shape(source),
            );
        }
    }
}

/// A field map of the first `n` integer keys, each holding zero, whose head
/// waits in a gap for the count its fields reach.
struct GapFields(u64);

impl Schema for GapFields {
    fn instruction(&self, index: usize) -> Instruction<'_> {
        match index {
            0 => Instruction::Map,
            index if (index as u64) <= self.0 => Instruction::Field(index as u64 - 1, Some(&0u64)),
            _ => Instruction::End,
        }
    }
}

#[test]
fn many_map_headers_and_multibyte_payloads_preserve_gap_order_and_prefixes() {
    // Every head waits in its own gap: thirty-two gaps passed in order.
    let source: Vec<_> = (0..32).map(|_| GapFields(0)).collect();
    let mut expected = vec![0x98, 32];
    expected.extend([0xa0; 32]);
    emission_matrix(&source, &expected);
    // A derived map's count is known at its start: its head has no gap.
    #[derive(CBORBoundedEncodable)]
    struct Empty {}
    let source: Vec<_> = (0..32).map(|_| Empty {}).collect();
    emission_matrix(&source, &expected);
    let source = dcbor::ByteString::from(vec![0xaa; 256]);
    let mut expected = vec![0x59, 1, 0];
    expected.extend([0xaa; 256]);
    emission_matrix(&source, &expected);
}

/// Every physical request of a derived record's preparation failed in a run
/// of its own: an omitted optional, a scalar, and nested vectors of a
/// 96-byte text that normalizes and crosses the 64-byte quantum. Every outer
/// element repeats the same text's requests, so the fast layer holds two,
/// the first and a sibling after it; the exhaustive layer holds eight.
#[test]
fn every_schema_preparation_allocation_failure_preserves_physical_ownership() {
    use super::support::rigor::Rigor;
    let elements = match rigor() {
        Rigor::Fast => 2,
        Rigor::Exhaustive => 8,
    };
    prepare_physical_matrix(&Record {
        omitted: None,
        enabled: true,
        nested: vec![vec!["e\u{301}".repeat(32)]; elements],
    });
}

/// Thirty-two fields need a two-byte map head: a gap-headed map finalizes it
/// in its gap without relocating the payload, and a derived map, its count
/// known at its start, writes it at once.
#[test]
fn wide_schema_finalizes_multibyte_map_head_without_payload_relocation() {
    macro_rules! wide {
        ($($name:ident = $key:literal),* $(,)?) => {{
            #[derive(CBORBoundedEncodable)]
            struct Wide { $(#[cbor(n = $key)] $name: u64,)* }
            Wide { $($name: 0,)* }
        }};
    }
    let source = wide!(
        a0 = 0,
        a1 = 1,
        a2 = 2,
        a3 = 3,
        a4 = 4,
        a5 = 5,
        a6 = 6,
        a7 = 7,
        a8 = 8,
        a9 = 9,
        a10 = 10,
        a11 = 11,
        a12 = 12,
        a13 = 13,
        a14 = 14,
        a15 = 15,
        a16 = 16,
        a17 = 17,
        a18 = 18,
        a19 = 19,
        a20 = 20,
        a21 = 21,
        a22 = 22,
        a23 = 23,
        a24 = 24,
        a25 = 25,
        a26 = 26,
        a27 = 27,
        a28 = 28,
        a29 = 29,
        a30 = 30,
        a31 = 31,
    );
    let expected = [
        0xb8, 32, 0, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8, 0, 9, 0, 10, 0, 11, 0, 12, 0,
        13, 0, 14, 0, 15, 0, 16, 0, 17, 0, 18, 0, 19, 0, 20, 0, 21, 0, 22, 0, 23, 0, 0x18, 24, 0,
        0x18, 25, 0, 0x18, 26, 0, 0x18, 27, 0, 0x18, 28, 0, 0x18, 29, 0, 0x18, 30, 0, 0x18, 31, 0,
    ];
    emission_matrix(&source, &expected);
    emission_matrix(&GapFields(32), &expected);
}
