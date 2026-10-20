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
        if self.finished {
            return Ok(ComparisonStep::Finished);
        }
        if let Some(ordering) = compare_step(self.left, self.right, &mut self.position, budget)? {
            self.finished = true;
            Ok(ComparisonStep::Complete(ordering))
        } else {
            Ok(ComparisonStep::Progress)
        }
    }
}

/// Shared comparison unit for borrowed keys and arena-indexed keys. The caller
/// retains the offset and keeps both byte ranges unchanged until completion.
pub(crate) fn compare_step<B: Budget>(
    left: &[u8],
    right: &[u8],
    position: &mut usize,
    budget: &mut B,
) -> Result<Option<Ordering>, BoundedError<B::Refusal>> {
    let remaining = left
        .len()
        .min(right.len())
        .checked_sub(*position)
        .ok_or(BoundedError::PlanMismatch)?;
    let count = remaining.min(64);
    budget
        .traverse(1, count as u64)
        .map_err(BoundedError::Refused)?;
    let end = *position + count;
    while *position < end {
        let ordering = left[*position].cmp(&right[*position]);
        *position += 1;
        if ordering != Ordering::Equal {
            return Ok(Some(ordering));
        }
    }
    Ok((*position == left.len().min(right.len())).then(|| left.len().cmp(&right.len())))
}
