use super::*;

struct Turn {
    storage: Limits,
    values: u64,
    bytes: u64,
    refuse: bool,
    refused: bool,
}

impl Budget for Turn {
    type Refusal = LimitRefusal;

    fn traverse(&mut self, values: u64, bytes: u64) -> Result<(), Self::Refusal> {
        if self.refuse {
            self.refused = true;
            return Err(LimitRefusal::Work);
        }
        self.values += values;
        self.bytes += bytes;
        assert!(self.values <= 3);
        assert!(self.bytes <= 64);
        Ok(())
    }
}

impl Allocator for Turn {
    type Permit = <Limits as Allocator>::Permit;

    fn allocate(&mut self, bytes: u64) -> Result<Self::Permit, Self::Refusal> {
        if self.refuse {
            self.refused = true;
            return Err(LimitRefusal::Storage);
        }
        self.storage.allocate(bytes)
    }
}

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
    let mut bytes = original;
    let mut operation = Permutation::new();
    let mut turn = Turn {
        storage: Limits::new(0, 0, 4096),
        values: 0,
        bytes: 0,
        refuse: false,
        refused: false,
    };
    let mut moves = 0;
    let mut complete = false;
    for _ in 0..16 * bytes.len() + 256 {
        let position = operation.position();
        let before = bytes.clone();
        let held = turn.storage.live_bytes();
        turn.refuse = true;
        turn.refused = false;
        assert!(matches!(
            operation.step(&mut entries, &mut bytes, prefix.len(), &mut turn),
            Err(BoundedError::Refused(_))
        ));
        assert!(turn.refused);
        assert_eq!(operation.position(), position);
        assert_eq!(bytes, before);
        assert_eq!(turn.storage.live_bytes(), held);
        turn.refuse = false;
        turn.values = 0;
        turn.bytes = 0;
        if position.phase == PermutationPhase::Move {
            moves += 1;
        }
        if operation
            .step(&mut entries, &mut bytes, prefix.len(), &mut turn)
            .unwrap()
        {
            complete = true;
            break;
        }
    }
    assert!(complete, "input-derived step bound exceeded");
    assert_eq!(moves, lengths.iter().sum::<usize>());
    assert_eq!(bytes, expected);
    assert_eq!(turn.storage.live_bytes(), 0);
}
