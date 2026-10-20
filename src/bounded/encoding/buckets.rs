//! Individually admitted hash-table bucket enumeration.
use super::super::{BoundedError, BoundedResult, Budget};
use hashbrown::HashTable;

#[derive(Debug, PartialEq, Eq)]
pub enum BucketStep<'a, T> {
    Vacant { index: usize },
    Entry { index: usize, value: &'a T },
    Complete,
    Finished,
}

/// Borrows a table without cloning, allocating, or scanning during creation.
/// Each step admits one control-byte inspection before calling `get_bucket`.
/// Vacant buckets are observable progress, including a sparse table's tail.
///
/// ```compile_fail,E0502
/// use dcbor::bounded::encoding::buckets::BucketCursor;
/// let mut table = hashbrown::HashTable::<u64>::new();
/// let cursor = BucketCursor::new(&table);
/// table.insert_unique(1, 1, |value| *value);
/// drop(cursor);
/// ```
pub struct BucketCursor<'a, T> {
    table: &'a HashTable<T>,
    next: usize,
    buckets: usize,
    finished: bool,
}

impl<'a, T> BucketCursor<'a, T> {
    pub fn new(table: &'a HashTable<T>) -> Self {
        Self {
            table,
            next: 0,
            buckets: table.num_buckets(),
            finished: false,
        }
    }

    /// Index of the next control byte to inspect, unchanged by refusal.
    pub fn position(&self) -> usize {
        self.next
    }

    pub fn bucket_count(&self) -> usize {
        self.buckets
    }

    pub fn step<B: Budget>(&mut self, budget: &mut B) -> BoundedResult<BucketStep<'a, T>, B> {
        self.advance(1, budget)
    }

    /// Inspect at most 64 buckets, stopping at the first entry. Vacant reports
    /// the first inspected index; position() reports the retained end position.
    pub fn step_batch<B: Budget>(&mut self, budget: &mut B) -> BoundedResult<BucketStep<'a, T>, B> {
        self.advance(64, budget)
    }

    fn advance<B: Budget>(
        &mut self,
        maximum: usize,
        budget: &mut B,
    ) -> BoundedResult<BucketStep<'a, T>, B> {
        if self.finished {
            return Ok(BucketStep::Finished);
        }
        if self.next == self.buckets {
            budget.traverse(1, 0).map_err(BoundedError::Refused)?;
            self.finished = true;
            return Ok(BucketStep::Complete);
        }
        let count = (self.buckets - self.next).min(maximum);
        budget
            .traverse(1, count as u64)
            .map_err(BoundedError::Refused)?;
        let index = self.next;
        let (next, value) = scan(self.table, index, count);
        self.next = next;
        Ok(match value {
            Some(value) => BucketStep::Entry {
                index: next - 1,
                value,
            },
            None => BucketStep::Vacant { index },
        })
    }
}

pub(super) fn scan<T>(table: &HashTable<T>, start: usize, maximum: usize) -> (usize, Option<&T>) {
    let end = start + (table.num_buckets() - start).min(maximum);
    for index in start..end {
        if let Some(value) = table.get_bucket(index) {
            return (index + 1, Some(value));
        }
    }
    (end, None)
}
