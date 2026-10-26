use super::harness::*;
use super::support::{
    drive_faulted_observed, exhausted, ordinary_exhaustion, prepare_turns, shape,
};
use dcbor::bounded::{
    BoundedError, Failure,
    encoding::{Preparation, Schema},
};
use dcbor_derive::CBORBoundedEncodable;
use hashbrown::HashTable;

fn table<K, V>(entries: impl IntoIterator<Item = (K, V)>) -> HashTable<(K, V)> {
    let mut result = HashTable::new();
    for (index, entry) in entries.into_iter().enumerate() {
        result.insert_unique(index as u64, entry, |_| 0);
    }
    result
}

#[test]
fn nested_tables_as_keys_and_values_resume_without_replay() {
    let source = table([
        (table([(2u64, 0u64), (1, 0)]), table([(1u64, 2u64)])),
        (table([(0, 1)]), table([(3, 4), (0, 5)])),
    ]);
    prepare_matrix(
        &source,
        Ok(&[
            0xa2, 0xa1, 0, 1, 0xa2, 0, 5, 3, 4, 0xa2, 1, 0, 2, 0, 0xa1, 1, 2,
        ]),
    );
}

#[derive(CBORBoundedEncodable)]
struct Record<T> {
    #[cbor(n = 0)]
    value: T,
    #[cbor(n = 1)]
    absent: Option<u64>,
}

#[test]
fn derived_fields_and_map_keys_compact_nested_header_gaps() {
    let source = Record {
        value: vec![table([
            (
                Record {
                    value: 2u64,
                    absent: Some(7),
                },
                vec![table([(1u64, 2u64)])],
            ),
            (
                Record {
                    value: 1u64,
                    absent: None,
                },
                vec![table([])],
            ),
        ])],
        absent: None,
    };
    prepare_matrix(
        &source,
        Ok(&[
            0xa1, 0, 0x81, 0xa2, 0xa1, 0, 1, 0x81, 0xa0, 0xa2, 0, 2, 1, 7, 0x81, 0xa1, 1, 2,
        ]),
    );
}

#[test]
fn canonical_collisions_inside_nested_map_keys_are_rejected() {
    let source = vec![table([
        (table([("e\u{301}".to_string(), 0u64)]), 1u64),
        (table([("\u{e9}".to_string(), 0u64)]), 2u64),
    ])];
    prepare_matrix(&source, Err(BoundedError::DuplicateKey));
}

#[test]
fn every_nested_table_physical_allocation_failure_retains_custody() {
    let source = table((0..8u64).map(|n| {
        (
            table([(n, "e\u{301}".repeat(8))]),
            Record {
                value: table([(n, vec![n; 8])]),
                absent: None,
            },
        )
    }));
    prepare_physical_matrix(&source);
}

enum Chain {
    Leaf(u64),
    Map(HashTable<(u64, Box<Chain>)>),
}

impl Schema for Chain {
    fn instruction(&self, index: usize) -> dcbor::bounded::encoding::Instruction<'_> {
        match self {
            Self::Leaf(value) => value.instruction(index),
            Self::Map(value) => value.instruction(index),
        }
    }
}

fn chain(depth: usize) -> Chain {
    let mut source = Chain::Leaf(7);
    for _ in 0..depth {
        source = Chain::Map(table([(0u64, Box::new(source))]));
    }
    source
}

#[test]
fn deep_tables_have_bounded_all_ready_steps_and_a_finite_completion_bound() {
    for depth in [1usize, 8, 32, 127] {
        let source = chain(depth);
        let mut operation = Preparation::new(&source);
        let mut m = meter();
        // Every depth through 127 is within the frame limit, so the source's
        // own shape gives the preparation's production bound: its values and
        // requested bytes bound its turns, a prepaid release step included
        // through the allocation it releases.
        let bound = prepare_turns(shape(&source));
        let plan = drive_faulted_observed(&mut m, &mut operation, bound, false, |m, _, result| {
            if let Err(error) = result {
                assert!(
                    ordinary_exhaustion(m, error),
                    "unexpected preparation error: {error:?}"
                );
            }
        })
        .expect("nested preparation failed")
        .expect("no cancellation selected");
        let mut expected = Vec::new();
        for _ in 0..depth {
            expected.extend([0xa1, 0]);
        }
        expected.push(7);
        emit(&plan, &expected, &mut m);
        drop(operation);
        drop(plan);
        assert_eq!(m.live_bytes(), 0);
    }
}

#[test]
fn excessive_nested_table_depth_is_terminal_without_publication() {
    let source = chain(128);
    let mut operation = Preparation::new(&source);
    let mut m = meter();
    // The source is past the depth limit, so its shape walk is refused and
    // no derived bound exists: the general bound applies.
    let result = drive_faulted_observed(
        &mut m,
        &mut operation,
        super::support::TURNS,
        false,
        |m, _, result| {
            if let Err(error) = result
                && error.refused()
            {
                assert!(
                    ordinary_exhaustion(m, error),
                    "unexpected refusal: {error:?}"
                );
            }
        },
    );
    assert_eq!(result.err(), Some(BoundedError::DepthLimit));
    exhausted(&mut m, &mut operation);
    drop(operation);
    assert_eq!(m.live_bytes(), 0);
}
