use super::harness::*;
use super::support::{
    Fault, allowed, drive_faulted_observed, refusal_matrix, refuse, rigor::rigor,
};
use dcbor::bounded::{
    BoundedError, Failure,
    encoding::{Instruction, Schema},
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
/// step leaving the emitted prefix unchanged, and a cancellation at every
/// call ending the trace there. Emission never allocates, never writes
/// outside its destination, and never releases the plan's storage. Named by
/// its call site.
#[track_caller]
fn emission_matrix(source: &dyn Schema, expected: &[u8]) {
    let name = format!("emit at {}", std::panic::Location::caller());
    let (plan, pool) = prepared(source);
    assert_eq!(plan.len(), expected.len());
    let live = pool.live_bytes();
    refusal_matrix(&name, rigor(), |fault: Fault| {
        let mut bytes = vec![0xee; expected.len() + 2];
        let mut writer = plan.writer(&mut bytes[1..expected.len() + 1]);
        let mut m = meter();
        refuse(&mut m, fault.refusal);
        let turns = allowed(&m, emit_turns(expected.len()));
        let mut prefix = Vec::new();
        let output = drive_faulted_observed(
            &mut m,
            &mut writer,
            turns,
            fault.cancel,
            |_, writer, result| {
                if matches!(result, Err(error) if error.refused()) {
                    assert_eq!(
                        writer.emitted_prefix(),
                        prefix,
                        "a refused step changed the emitted prefix"
                    );
                }
                assert_eq!(
                    writer.emitted_prefix(),
                    &expected[..writer.emitted_prefix().len()]
                );
                prefix.clear();
                prefix.extend_from_slice(writer.emitted_prefix());
                assert_eq!(
                    pool.live_bytes(),
                    live,
                    "emission changed the plan's storage"
                );
            },
        )
        .expect("emission failed");
        if output.is_some() {
            assert_eq!(writer.emitted_prefix(), expected);
        }
        assert_eq!(m.requests(), 0, "emission requested allocation");
        // The writer's borrow of `bytes` ends here; it has no destructor.
        assert_eq!(
            (bytes[0], bytes[expected.len() + 1]),
            (0xee, 0xee),
            "emission wrote outside its destination"
        );
        super::support::RefusalRun::of(&m)
    });
    drop(plan);
    assert_eq!(pool.live_bytes(), 0);
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
    use dcbor::{CBOR, CBORCase, Map};
    use std::collections::BTreeMap;

    /// The symbolic encoder's bytes for `value`.
    fn symbolic(value: impl Into<CBOR>) -> Vec<u8> {
        value.into().to_cbor_data()
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
        assert_eq!(symbolic(source.clone()), expected);
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
        assert_eq!(symbolic(values.clone()), expected);
        prepare_matrix(&values, Ok(&expected));
        // A key's cursor is started and finished while the outer cursor is
        // suspended between two of its entries.
        let keys = BTreeMap::from([(BTreeMap::from([(1u64, 0u64)]), 7u64), (BTreeMap::new(), 8)]);
        let expected = [0xa2, 0xa0, 8, 0xa1, 1, 0, 7];
        assert_eq!(symbolic(keys.clone()), expected);
        prepare_matrix(&keys, Ok(&expected));
    }

    #[test]
    fn multi_level_tree_is_walked_through_every_internal_node_transition() {
        // More entries than one leaf holds: the cursor descends, ascends and
        // yields from internal nodes, one admitted transition per instruction.
        let source: BTreeMap<u64, u64> = (0..40).map(|n| (n, n)).collect();
        let expected = identity_map(40);
        assert_eq!(symbolic(source.clone()), expected);
        prepare_matrix(&source, Ok(&expected));
        emission_matrix(&source, &expected);
    }

    #[test]
    fn every_tree_preparation_allocation_failure_preserves_physical_ownership() {
        let source: BTreeMap<String, String> = (0..64)
            .map(|n| (format!("{n:02}e\u{301}"), "e\u{301}".repeat(n % 8)))
            .collect();
        prepare_physical_matrix(&source);
    }

    #[test]
    fn dcbor_map_matches_the_symbolic_encoder_across_every_refusal() {
        let mut map = Map::new();
        map.insert("k", 1.5f64);
        map.insert(-1i64, true);
        map.insert(10u64, "a");
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
        inner.insert("b", 2u64);
        inner.insert("a", 1u64);
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
        entry.insert(0u64, wide.clone());
        let mut valid_entry = Map::new();
        valid_entry.insert(0u64, boundary.clone());
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

#[test]
fn every_schema_preparation_allocation_failure_preserves_physical_ownership() {
    prepare_physical_matrix(&Record {
        omitted: None,
        enabled: true,
        nested: vec![vec!["e\u{301}".repeat(32)]; 8],
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
