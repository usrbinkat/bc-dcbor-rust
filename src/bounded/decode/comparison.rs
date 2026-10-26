//! Retained lexicographic comparison of immutable encoded map keys.
use core::cmp::Ordering;

use super::super::{BoundedError, Budget, Caller, Capped, Failure, Resumable, Step, WriteWork};

/// One comparison turn: one value and at most a quantum of byte pairs. The
/// caller supplies the place.
pub(crate) const COMPARE: Capped<Caller> =
    Capped::new(Caller, 1, super::construction::stable::QUANTUM as u64);

/// Ranges belong to the enclosing parser's immutable input. Keeping this type
/// private prevents callers from substituting another buffer between turns.
pub(super) struct RangeComparison {
    left: core::ops::Range<usize>,
    right: core::ops::Range<usize>,
    position: usize,
    finished: bool,
}

impl RangeComparison {
    pub(super) fn new(left: core::ops::Range<usize>, right: core::ops::Range<usize>) -> Self {
        Self {
            left,
            right,
            position: 0,
            finished: false,
        }
    }

    pub(super) fn position(&self) -> usize {
        self.position
    }

    pub(super) fn step<B: Budget>(
        &mut self,
        input: &[u8],
        budget: &mut B,
    ) -> Result<Step<Ordering>, BoundedError<B::Refusal>> {
        if self.finished {
            return Ok(Step::Finished);
        }
        let (Some(left), Some(right)) =
            (input.get(self.left.clone()), input.get(self.right.clone()))
        else {
            self.finished = true;
            return Err(BoundedError::PlanMismatch);
        };
        finish(
            &mut self.finished,
            compare_step(left, right, &mut self.position, budget),
        )
    }
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
            let remaining = (self.left.len().min(self.right.len()) - self.position) as u64;
            Some(WriteWork::new(
                COMPARE.values(),
                remaining.min(COMPARE.cap()),
            ))
        }
    }

    pub fn step<B: Budget>(
        &mut self,
        budget: &mut B,
    ) -> Result<Step<Ordering>, BoundedError<B::Refusal>> {
        if self.finished {
            return Ok(Step::Finished);
        }
        finish(
            &mut self.finished,
            compare_step(self.left, self.right, &mut self.position, budget),
        )
    }
}

/// The [`ResourceBound`] of comparing two keys the shorter of which has
/// `shorter` bytes ([`KeyComparison`]): one turn per quantum of byte pairs,
/// and one for keys of no common bytes; every pair examined once; nothing
/// allocated.
pub fn comparison_bound(shorter: u64) -> super::super::ResourceBound {
    const { assert!(COMPARE.values() == 1) };
    super::super::ResourceBound {
        values: shorter.div_ceil(COMPARE.cap()).max(1),
        bytes: shorter,
        ..super::super::ResourceBound::default()
    }
}

impl<B: Budget> Resumable<B> for KeyComparison<'_> {
    type Output = Ordering;
    type Error = BoundedError<B::Refusal>;
    type Position = usize;

    fn step(&mut self, budget: &mut B) -> Result<Step<Ordering>, Self::Error> {
        KeyComparison::step(self, budget)
    }

    fn position(&mut self) -> usize {
        KeyComparison::position(self)
    }
}

/// One comparison turn's outcome. Completion and terminal errors finish the
/// comparison; a refusal leaves it resumable.
fn finish<R>(
    finished: &mut bool,
    turn: Result<Option<Ordering>, BoundedError<R>>,
) -> Result<Step<Ordering>, BoundedError<R>> {
    match turn {
        Ok(Some(ordering)) => {
            *finished = true;
            Ok(Step::Complete(ordering))
        }
        Ok(None) => Ok(Step::Progress),
        Err(error) => {
            if !error.refused() {
                *finished = true;
            }
            Err(error)
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
    let count = remaining.min(super::construction::stable::QUANTUM);
    COMPARE.admit(budget, count as u64)?;
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
