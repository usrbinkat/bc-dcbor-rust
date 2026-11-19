use super::*;

#[test]
fn unequal_intervals_permute_bytes_with_refusal_at_every_step() {
    // Every ordering of four unequal intervals, including lengths on either
    // side of a bitmap byte and a 64-byte initialization boundary.
    for lengths in [[1usize, 2, 3, 5], [1, 7, 65, 513]] {
        for a in 0..4 {
            for b in 0..4 {
                for c in 0..4 {
                    for d in 0..4 {
                        let order = [a, b, c, d];
                        if (0..4).any(|i| order[..i].contains(&order[i])) {
                            continue;
                        }
                        check(lengths, order);
                    }
                }
            }
        }
    }
}

fn check(lengths: [usize; 4], order: [usize; 4]) {
    let prefix = [0xde, 0xad, 0xbe, 0xef];
    let mut original = prefix.to_vec();
    let mut descriptors = Vec::new();
    for (index, length) in lengths.into_iter().enumerate() {
        let start = original.len();
        original.extend((0..length).map(|offset| (offset * 17 + index * 31) as u8));
        descriptors.push(Entry {
            start,
            key_end: start + 1,
            end: original.len(),
            output: 0,
        });
    }
    let mut expected = prefix.to_vec();
    let mut entries = Vec::new();
    for index in order {
        let entry = descriptors[index];
        expected.extend_from_slice(&original[entry.start..entry.end]);
        entries.push(entry);
    }
    let initial_entries = entries;
    // The unrefused run's admitted work, requested bytes and admitted calls:
    // what the refusing run must admit again, exactly, nothing replayed. The
    // recorded, refined witness of the same lifecycle, call for call, is
    // public preparation coverage (`tests/resumable/native_dynamic_maps.rs`
    // `the_permutation_moves_unequal_entries_in_every_order_without_replay`);
    // this test keeps the byte-movement oracle over the permutation alone,
    // under an ordinary policy that records no history.
    let mut baseline: Option<(crate::bounded::WriteWork, u64, usize)> = None;
    for refusing in [false, true] {
        let mut entries = initial_entries.clone();
        let mut bytes = original.clone();
        let mut operation = Permutation::new();
        // Every step runs in a fresh turn of one quantum (`TURN`), so a
        // unit larger than a quantum is refused for work at every attempt
        // and the run exceeds its step bound, naming it.
        let mut limits = Limits::new(u64::MAX, u64::MAX, 4096).strict();
        if refusing {
            limits.fail_each();
        }
        let mut moves = 0;
        // The permutation's own terms of the preparation's bound, at the
        // shape of this one map: four entries over the permuted payload,
        // every byte looked up among them and moved, its visited bitmap
        // grown and released ([`PreparationTerms`]); with this policy's
        // refusal allowance ([`Limits::allowed`]).
        let payload = (bytes.len() - prefix.len()) as u64;
        let terms =
            PreparationTerms::of::<crate::bounded::Reservation, crate::bounded::Family, ()>(
                Shape {
                    maps: 1,
                    unordered: 1,
                    entries: 4,
                    widest: 4,
                    extent: payload,
                    payloads: payload,
                    payload_probes: payload * levels::<()>(4).unwrap(),
                    largest_payload: payload,
                    unordered_depth: 1,
                    ..Shape::default()
                },
            )
            .unwrap();
        let bound = terms
            .term(PreparationPlace::Permutation)
            .checked_then(terms.term(PreparationPlace::Visited))
            .expect("one small map's permutation bound fits in u64");
        let steps = limits.allowed::<()>(bound.steps::<()>().unwrap()).unwrap();
        crate::bounded::within_steps("permutation", steps, || {
            let position = operation.position();
            let storage = operation.visited.position();
            let before = bytes.clone();
            let held = limits.live_bytes();
            let attempts = limits.attempts();
            let admitted = limits.attempts() - limits.refusals();
            limits.turn();
            let result = operation.step(&mut entries, &mut bytes, prefix.len(), &mut limits);
            match result {
                Err(BoundedError::Refused(_)) => {
                    assert_eq!(bytes, before);
                    assert_eq!(limits.live_bytes(), held);
                    if limits.attempts() == attempts + 1 {
                        assert_eq!(operation.position(), position);
                        assert_eq!(operation.visited.position(), storage);
                        assert_eq!(limits.attempts() - limits.refusals(), admitted);
                    }
                    core::ops::ControlFlow::Continue(())
                }
                Ok(done) => {
                    if position.phase == PermutationPhase::Move {
                        moves += 1;
                    }
                    if done {
                        core::ops::ControlFlow::Break(())
                    } else {
                        core::ops::ControlFlow::Continue(())
                    }
                }
                Err(error) => panic!("permutation {position:?}: {error:?}"),
            }
        });
        assert_eq!(moves, lengths.iter().sum::<usize>());
        assert_eq!(bytes, expected);
        assert_eq!(limits.live_bytes(), 0);
        let admitted = (
            limits.used(),
            limits.requested_bytes(),
            limits.attempts() - limits.refusals(),
        );
        if refusing {
            let baseline = baseline.expect("the unrefused run ran first");
            // Every admission refused once: one scheduled refusal per call
            // the baseline admitted, and then the same admissions.
            assert_eq!(limits.scheduled_refusals(), baseline.2);
            assert_eq!(
                admitted, baseline,
                "the refusing run replayed or skipped work"
            );
        } else {
            baseline = Some(admitted);
        }
        drop((operation, limits));
    }
}
