//! Lossless checkpoint history. Unchanged custody is retained once; each
//! subsequent checkpoint stores only positional edits. Replay reconstructs
//! one checkpoint at a time, preserving traversal order and duplicate items.

use crate::{Checkpoint, Custody, Hold, Identity, Reported};

/// A contiguous replacement between an unchanged prefix and suffix.
/// Equality, rather than identity-keyed maps, preserves malformed reports too.
#[derive(Clone, Debug)]
struct Edit<T> {
    start: usize,
    removed: usize,
    inserted: Vec<T>,
}

impl<T: Clone + PartialEq> Edit<T> {
    fn between(before: &[T], after: &[T]) -> Self {
        let start = before.iter().zip(after).take_while(|(a, b)| a == b).count();
        let suffix = before[start..]
            .iter()
            .rev()
            .zip(after[start..].iter().rev())
            .take_while(|(a, b)| a == b)
            .count();
        Self {
            start,
            removed: before.len() - start - suffix,
            inserted: after[start..after.len() - suffix].to_vec(),
        }
    }

    fn apply(&self, values: &mut Vec<T>) {
        values.splice(
            self.start..self.start + self.removed,
            self.inserted.iter().cloned(),
        );
    }
}

#[derive(Clone, Debug)]
struct Changed {
    index: usize,
    owner: Identity,
    bound: Edit<Identity>,
    held: Edit<Hold>,
    permits: Edit<Reported>,
}

#[derive(Clone, Debug)]
struct Delta {
    boundary: usize,
    len: usize,
    changed: Vec<Changed>,
    appended: Vec<Custody>,
}

impl Delta {
    fn between(before: &[Custody], after: &Checkpoint) -> Self {
        let changed = before
            .iter()
            .zip(&after.custody)
            .enumerate()
            .filter(|(_, (a, b))| a != b)
            .map(|(index, (a, b))| Changed {
                index,
                owner: b.owner,
                bound: Edit::between(&a.bound, &b.bound),
                held: Edit::between(&a.held, &b.held),
                permits: Edit::between(&a.permits, &b.permits),
            })
            .collect();
        Self {
            boundary: after.boundary,
            len: after.custody.len(),
            changed,
            appended: after.custody[before.len().min(after.custody.len())..].to_vec(),
        }
    }

    fn apply(&self, checkpoint: &mut Checkpoint) {
        checkpoint.boundary = self.boundary;
        checkpoint.custody.truncate(self.len);
        for change in &self.changed {
            let group = &mut checkpoint.custody[change.index];
            group.owner = change.owner;
            change.bound.apply(&mut group.bound);
            change.held.apply(&mut group.held);
            change.permits.apply(&mut group.permits);
        }
        checkpoint.custody.extend(self.appended.iter().cloned());
    }
}

/// Every checkpoint, including repeated boundaries and unchanged reports.
/// Storage is the latest custody plus the edits, not the sum of snapshots.
#[derive(Clone, Debug, Default)]
pub struct History {
    deltas: Vec<Delta>,
    latest: Vec<Custody>,
}

impl History {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.deltas.len()
    }

    pub fn is_empty(&self) -> bool {
        self.deltas.is_empty()
    }

    pub fn push(&mut self, checkpoint: Checkpoint) {
        self.deltas.push(Delta::between(&self.latest, &checkpoint));
        self.latest = checkpoint.custody;
    }

    /// Reconstruct history in its original order with one working snapshot.
    pub fn iter(&self) -> impl Iterator<Item = Checkpoint> + Clone + '_ {
        self.deltas.iter().scan(
            Checkpoint {
                boundary: 0,
                custody: Vec::new(),
            },
            |checkpoint, delta| {
                delta.apply(checkpoint);
                Some(checkpoint.clone())
            },
        )
    }

    /// A checkpoint by its stable ordinal, reconstructed without retaining
    /// the preceding snapshots.
    pub fn get(&self, index: usize) -> Option<Checkpoint> {
        self.iter().nth(index)
    }

    /// Materialize the history for a serialized trace's owned [`crate::Run`].
    /// Ordinary lifecycle validation uses streaming replay instead.
    pub fn to_vec(&self) -> Vec<Checkpoint> {
        self.iter().collect()
    }

    /// The same replay and exact divergence rules as [`crate::settled`],
    /// with snapshots reconstructed only while they are checked.
    pub fn settled(&self, observed: &[crate::Observed]) -> Result<(), crate::Divergence> {
        crate::machine::settled_iter(observed, self.iter())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Event, Obligation, Observed, Performer, RecordStage, WriteWork};

    fn group(n: u64) -> Custody {
        Custody {
            owner: Identity::new(1, n),
            bound: vec![Identity::new(1, n + 100)],
            held: Vec::new(),
            permits: vec![Reported {
                permit: Identity::new(1, n + 200),
                record: Some(RecordStage::Handle),
            }],
        }
    }

    #[test]
    fn positional_edits_preserve_every_report_including_malformed_ones() {
        let mut history = History::new();
        let mut expected = Vec::new();
        let mut custody = vec![group(1), group(2), group(3)];
        for turn in 0..32 {
            match turn % 8 {
                0 => custody.push(group(turn + 4)),
                1 => custody[0].bound.push(Identity::new(2, turn)),
                2 => {
                    let duplicate = custody[0].permits[0];
                    custody[0].permits.push(duplicate);
                }
                3 => custody.reverse(),
                4 => {
                    custody.remove(1);
                }
                5 => custody[0].permits[0].record = Some(RecordStage::Queued),
                6 => custody[0].bound.clear(),
                _ => custody = vec![group(1), group(2), group(3)],
            }
            let checkpoint = Checkpoint {
                boundary: (turn / 2) as usize,
                custody: custody.clone(),
            };
            history.push(checkpoint.clone());
            expected.push(checkpoint);
        }
        assert_eq!(history.to_vec(), expected);
        for (index, checkpoint) in expected.iter().enumerate() {
            assert_eq!(history.get(index).as_ref(), Some(checkpoint));
        }
        assert_eq!(history.get(expected.len()), None);
    }

    /// Held obligations whose work changes, that are settled away and newly
    /// admitted, under owners whose hundreds of permits are rotated and
    /// reversed and whose groups are swapped: every checkpoint reconstructs
    /// exactly as it was pushed.
    #[test]
    fn obligation_edits_and_large_reordered_custody_reconstruct_exactly() {
        let hold = |n: u64, values: u64| Hold {
            obligation: [
                Obligation::Release,
                Obligation::Grant,
                Obligation::BucketWindow,
            ][(n % 3) as usize],
            work: WriteWork::new(values, values * 3),
            id: Identity::new(1, 1_000 + n),
            acquisition: Identity::new(1, 100 + n % 7),
        };
        let mut custody: Vec<Custody> = (0..8)
            .map(|g| Custody {
                owner: Identity::new(1, g + 1),
                bound: vec![Identity::new(1, 100 + g)],
                held: (0..64).map(|n| hold(g * 64 + n, 4)).collect(),
                permits: (0..512)
                    .map(|n| Reported {
                        permit: Identity::new(1, 100_000 + g * 512 + n),
                        record: None,
                    })
                    .collect(),
            })
            .collect();
        // xorshift64: a fixed sequence of edits, the same on every run.
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move |bound: usize| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            usize::try_from(state % bound as u64).expect("below a usize bound")
        };
        let mut history = History::new();
        let mut expected = Vec::new();
        for turn in 0..512_u64 {
            let g = next(custody.len());
            let group = &mut custody[g];
            match next(6) {
                0 if !group.held.is_empty() => {
                    let at = next(group.held.len());
                    group.held[at].work = WriteWork::new(next(8) as u64, next(64) as u64);
                }
                1 if !group.held.is_empty() => {
                    let at = next(group.held.len());
                    group.held.remove(at);
                }
                2 => {
                    let by = next(group.permits.len());
                    group.permits.rotate_left(by);
                }
                3 => group.permits.reverse(),
                4 => {
                    let other = next(custody.len());
                    custody.swap(g, other);
                }
                _ => group.held.push(hold(10_000 + turn, 1)),
            }
            let checkpoint = Checkpoint {
                boundary: usize::try_from(turn).expect("a turn fits in usize"),
                custody: custody.clone(),
            };
            history.push(checkpoint.clone());
            expected.push(checkpoint);
        }
        assert!(
            expected
                .iter()
                .zip(expected.iter().skip(1))
                .any(|(before, after)| before
                    .custody
                    .iter()
                    .zip(&after.custody)
                    .any(|(a, b)| a.owner == b.owner && a.held != b.held)),
            "no checkpoint changed a held obligation"
        );
        assert_eq!(
            history.to_vec(),
            expected,
            "reconstructed checkpoints differ from the checkpoints pushed"
        );
    }

    #[test]
    fn compressed_replay_preserves_the_first_rule_and_exact_location() {
        let owner = Identity::new(1, 1);
        let observed = [Observed {
            family: 1,
            by: Performer::Policy(1),
            event: Event::Owner(owner),
        }];
        let valid = Checkpoint {
            boundary: 1,
            custody: vec![Custody {
                owner,
                bound: Vec::new(),
                held: Vec::new(),
                permits: Vec::new(),
            }],
        };
        for defect in 0..5 {
            let mut checkpoints = vec![valid.clone(); 4];
            match defect {
                0 => {}
                1 => checkpoints[1].custody[0].owner = Identity::new(1, 9),
                2 => checkpoints[1].boundary = 0,
                3 => checkpoints[1].boundary = 2,
                _ => checkpoints[1].custody.push(valid.custody[0].clone()),
            }
            let mut history = History::new();
            for checkpoint in &checkpoints {
                history.push(checkpoint.clone());
            }
            let expected = crate::settled(&observed, &checkpoints);
            assert_eq!(expected.is_ok(), defect == 0);
            assert_eq!(history.settled(&observed), expected);
        }
    }
}
