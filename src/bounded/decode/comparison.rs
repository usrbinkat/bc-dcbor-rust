//! Retained lexicographic comparison of immutable encoded map keys.
use core::cmp::Ordering;

use super::super::{BoundedError, Budget, WriteWork};

/// One comparison turn; completion is returned exactly once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComparisonStep {
    Progress,
    Complete(Ordering),
    Finished,
}

/// A comparison owns no storage and borrows both keys for its entire lifetime.
/// Each turn examines at most 64 byte pairs. A refused admission changes
/// neither the comparison position nor its terminal state.
///
/// Both input lifetimes are retained, including across a refused step:
///
/// ```compile_fail,E0597
/// use dcbor::bounded::{Limits, decode::comparison::KeyComparison};
/// let mut comparison;
/// {
///     let key = vec![0x41, 0x01];
///     comparison = KeyComparison::new(&key, &[0x41, 0x02]);
/// }
/// let mut budget = Limits::new(3, 64, 0);
/// let _ = comparison.step(&mut budget);
/// ```
pub struct KeyComparison<'a> {
    left: &'a [u8],
    right: &'a [u8],
    position: usize,
    finished: bool,
}

impl<'a> KeyComparison<'a> {
    pub const fn new(left: &'a [u8], right: &'a [u8]) -> Self {
        Self {
            left,
            right,
            position: 0,
            finished: false,
        }
    }

    /// Number of byte pairs actually examined, including a differing pair.
    pub const fn position(&self) -> usize {
        self.position
    }

    /// Admission bound of the next turn, absent after completion.
    pub fn next_work(&self) -> Option<WriteWork> {
        if self.finished {
            None
        } else {
            let remaining = self.left.len().min(self.right.len()) - self.position;
            Some(WriteWork::new(1, remaining.min(64) as u64))
        }
    }

    pub fn step<B: Budget>(
        &mut self,
        budget: &mut B,
    ) -> Result<ComparisonStep, BoundedError<B::Refusal>> {
        let Some(work) = self.next_work() else {
            return Ok(ComparisonStep::Finished);
        };
        budget
            .traverse(work.values, work.bytes)
            .map_err(BoundedError::Refused)?;
        let end = self.position + work.bytes as usize;
        while self.position < end {
            let ordering = self.left[self.position].cmp(&self.right[self.position]);
            self.position += 1;
            if ordering != Ordering::Equal {
                self.finished = true;
                return Ok(ComparisonStep::Complete(ordering));
            }
        }
        if self.position == self.left.len().min(self.right.len()) {
            self.finished = true;
            Ok(ComparisonStep::Complete(
                self.left.len().cmp(&self.right.len()),
            ))
        } else {
            Ok(ComparisonStep::Progress)
        }
    }
}
