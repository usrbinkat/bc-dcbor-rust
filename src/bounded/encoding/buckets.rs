//! Individually admitted hash-table bucket enumeration.
use super::super::{
    BoundedError, BoundedResult, Budget, Places, Rate, ResourceBound, Unit, WriteWork,
};
use super::BUCKET_WINDOW;
use hashbrown::HashTable;

places! {
    /// The places bucket enumeration ([`BucketCursor`]) charges, one term of
    /// [`bucket_bound`] each.
    pub(crate) enum BucketPlace {
        Inspection,
        Completion,
    }
}

/// Inspecting buckets: one value and a byte per control byte inspected.
const INSPECT: Rate<BucketPlace> = Rate::based(
    BucketPlace::Inspection,
    WriteWork::new(1, 0),
    WriteWork::new(0, 1),
);

/// The most buckets one batched step inspects: one instruction's window.
const BATCH: usize = BUCKET_WINDOW;

/// Completing the enumeration.
const COMPLETE: Unit<BucketPlace> = Unit::new(BucketPlace::Completion, 1, 0);

#[derive(Debug, PartialEq, Eq)]
pub enum BucketStep<'a, T> {
    Vacant { index: usize },
    Entry { index: usize, value: &'a T },
    Complete,
    Finished,
}

/// Borrows a table without cloning, allocating, or scanning during creation.
/// Each step admits its control-byte inspections before scanning them.
/// Vacant buckets before the last entry are observable progress; once every
/// entry of the table is yielded, the cursor completes without scanning the
/// buckets after the last, as the table's own iterator stops at its item
/// count.
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
    /// Entries yielded so far.
    yielded: usize,
    finished: bool,
}

impl<'a, T> BucketCursor<'a, T> {
    pub fn new(table: &'a HashTable<T>) -> Self {
        Self {
            table,
            next: 0,
            buckets: table.num_buckets(),
            yielded: 0,
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
        self.advance(BATCH, budget)
    }

    fn advance<B: Budget>(
        &mut self,
        maximum: usize,
        budget: &mut B,
    ) -> BoundedResult<BucketStep<'a, T>, B> {
        if self.finished {
            return Ok(BucketStep::Finished);
        }
        // Every entry yielded: complete. Every bucket scanned short of that
        // is a table whose buckets do not hold its count.
        if self.yielded == self.table.len() {
            COMPLETE.admit(budget)?;
            self.finished = true;
            return Ok(BucketStep::Complete);
        }
        if self.next == self.buckets {
            self.finished = true;
            return Err(BoundedError::PlanMismatch);
        }
        let count = (self.buckets - self.next).min(maximum);
        INSPECT.admit(budget, count as u64)?;
        let index = self.next;
        let (next, value) = scan(self.table, index, count);
        self.next = next;
        Ok(match value {
            Some(value) => {
                self.yielded += 1;
                BucketStep::Entry {
                    index: next - 1,
                    value,
                }
            }
            None => BucketStep::Vacant { index },
        })
    }
}

/// The [`ResourceBound`](super::super::ResourceBound) of enumerating a table
/// of `buckets` buckets, `entries` of them occupied: one bucket per step
/// ([`BucketCursor::step`]), one unit of one control byte each; or batched
/// ([`BucketCursor::step_batch`]), one unit per 64 buckets, and one more per
/// entry, each of which ends its batch early; then one unit to complete.
/// A batch admits its whole window before it scans: one ending at its
/// window's end advances by what it admitted, one ending at an entry by at
/// least one bucket, so each entry adds at most a window less one bucket of
/// admitted control bytes. The cursor completes once every entry is
/// yielded; a bound taken before the table is scanned covers its last entry
/// in its last bucket, so it counts every bucket. Nothing is allocated or
/// retained. Refused, never saturated, when a quantity does not fit in
/// `u64`.
pub fn bucket_bound<R>(
    buckets: u64,
    entries: u64,
    batched: bool,
) -> Result<ResourceBound, BoundedError<R>> {
    BucketTerms::of::<R>(buckets, entries, batched)?.bound()
}

/// The terms [`bucket_bound`] sums, one per [`BucketPlace`].
struct BucketTerms {
    inspection: WriteWork,
    completion: WriteWork,
}

impl BucketTerms {
    fn of<R>(buckets: u64, entries: u64, batched: bool) -> Result<Self, BoundedError<R>> {
        use super::super::{add, mul};
        let window = BATCH as u64;
        let (steps, inspected) = if batched {
            (
                add(buckets.div_ceil(window), entries)?,
                add(buckets, mul(window - 1, entries)?)?,
            )
        } else {
            (buckets, buckets)
        };
        Ok(Self {
            inspection: INSPECT.over(steps, inspected)?,
            completion: COMPLETE.times(1)?,
        })
    }
}

impl Places for BucketTerms {
    type Place = BucketPlace;

    fn term(&self, place: BucketPlace) -> ResourceBound {
        match place {
            BucketPlace::Inspection => ResourceBound::of_work(self.inspection),
            BucketPlace::Completion => ResourceBound::of_work(self.completion),
        }
    }
}

/// The first occupied bucket of the `maximum` buckets from `start`, found a
/// control group at a time (`HashTable::next_full_bucket`): the index after
/// it and its value, or the window's end and none.
fn scan<T>(table: &HashTable<T>, start: usize, maximum: usize) -> (usize, Option<&T>) {
    let end = start + (table.num_buckets() - start).min(maximum);
    match table
        .next_full_bucket(start, end)
        .and_then(|index| Some((index, table.get_bucket(index)?)))
    {
        Some((index, value)) => (index + 1, Some(value)),
        None => (end, None),
    }
}

/// Place attribution of bucket enumeration, which this crate's tests record
/// under `std`.
#[cfg(test)]
#[cfg(feature = "std")]
mod attribution {
    use super::*;
    use crate::bounded::places::{self, Factor, Ledgered, Run, WORK};

    /// A table of `entries` values with room for at least `capacity`, its
    /// hashes spread by a fixed multiplier so its layout is reproducible.
    fn table(entries: u64, capacity: usize) -> HashTable<u64> {
        let hash = |value: &u64| value.wrapping_mul(0x9e37_79b9_7f4a_7c15);
        let mut table = HashTable::with_capacity(capacity);
        for value in 0..entries {
            table.insert_unique(hash(&value), value, hash);
        }
        table
    }

    /// A table of `values`, each hashed to itself, so each lies in its own
    /// home bucket when that bucket is free as it is inserted: values `0`
    /// through `199` fill the buckets of the same indices, and `255` the last
    /// bucket of the 256 the table grows to.
    fn dense() -> HashTable<u64> {
        let hash = |value: &u64| *value;
        let mut table = HashTable::new();
        for value in (0..200).chain([255]) {
            table.insert_unique(hash(&value), value, hash);
        }
        assert_eq!(table.num_buckets(), 256);
        assert_eq!(
            table.get_bucket(255),
            Some(&255),
            "the last bucket holds 255"
        );
        table
    }

    /// Every place of an enumeration, one bucket at a time and batched, is
    /// within its term ([`bucket_bound`]) on an empty table, a sparse one
    /// whose batches run their whole window, and a dense one whose batches
    /// end early at each entry and whose last entry lies in its last bucket,
    /// so the enumeration scans every bucket the term counts; every admission
    /// is made at some place; each place's witness charges it, and fails
    /// without its term; each term is tight on its witness.
    #[test]
    fn every_place_of_a_bucket_enumeration_is_within_its_term() {
        let tables = [
            ("empty", table(0, 0)),
            ("sparse", table(3, 1000)),
            ("dense", dense()),
        ];
        let mut runs = Vec::new();
        let mut witnesses = Vec::new();
        for (name, table) in &tables {
            for batched in [false, true] {
                let mut policy = Ledgered::new();
                let mut cursor = BucketCursor::new(table);
                let bound =
                    bucket_bound::<()>(cursor.bucket_count() as u64, table.len() as u64, batched)
                        .unwrap();
                let mut entries = 0u64;
                crate::bounded::within(name, bound, || {
                    let step = if batched {
                        cursor.step_batch(&mut policy)
                    } else {
                        cursor.step(&mut policy)
                    };
                    match step.expect("an unlimited policy never refuses") {
                        BucketStep::Entry { .. } => {
                            entries += 1;
                            core::ops::ControlFlow::Continue(())
                        }
                        BucketStep::Vacant { .. } => core::ops::ControlFlow::Continue(()),
                        BucketStep::Complete => core::ops::ControlFlow::Break(()),
                        BucketStep::Finished => unreachable!("completion ends the loop"),
                    }
                });
                assert_eq!(
                    entries,
                    table.len() as u64,
                    "{name}: every entry is visited"
                );
                match *name {
                    "empty" => witnesses.push((runs.len(), BucketPlace::Completion)),
                    "dense" => witnesses.push((runs.len(), BucketPlace::Inspection)),
                    _ => {}
                }
                let mode = if batched { "batched" } else { "one by one" };
                runs.push(Run {
                    outcome: places::Outcome::Published,
                    name: format!("{name} ({mode})"),
                    policy,
                    terms: BucketTerms::of::<()>(
                        cursor.bucket_count() as u64,
                        table.len() as u64,
                        batched,
                    )
                    .unwrap(),
                });
            }
        }
        places::check(&runs);
        places::witnessed(&runs, &witnesses);
        // Completion is one unit, exact. Inspection, on the dense table where
        // an entry ends nearly every batch, is within twice what was
        // inspected: each batch admits its whole window, and the term counts
        // a window less one bucket per entry.
        places::Tightness::new("buckets")
            .places(&runs, &witnesses, |place| match place {
                BucketPlace::Inspection => Factor::Within(2),
                BucketPlace::Completion => Factor::Within(1),
            })
            .joint(
                &runs,
                "dense (batched)",
                WORK,
                "a dense table in batches: an entry ends nearly every batch early, each batch \
                 admitting its whole window, its last entry in its last bucket",
            )
            .finish();
    }

    /// Enumeration completes once the table's entries are yielded, before
    /// the buckets after the last: a table whose one entry lies in its first
    /// bucket completes after one batch, whatever its size; an empty table
    /// completes at once. A cursor that reaches the last bucket short of the
    /// table's count is refused as a plan mismatch, never completed.
    #[test]
    fn enumeration_completes_at_the_last_entry() {
        let mut policy = crate::bounded::Limits::unlimited();
        let hash = |value: &u64| *value;
        let mut first = HashTable::with_capacity(10_000);
        first.insert_unique(0, 0u64, hash);
        assert_eq!(first.get_bucket(0), Some(&0));
        let mut cursor = BucketCursor::new(&first);
        assert_eq!(
            cursor.step_batch(&mut policy).unwrap(),
            BucketStep::Entry {
                index: 0,
                value: &0
            }
        );
        assert_eq!(
            cursor.step_batch(&mut policy).unwrap(),
            BucketStep::Complete
        );
        assert_eq!(
            cursor.position(),
            1,
            "no bucket after the entry was scanned"
        );
        assert_eq!(policy.used(), WriteWork::new(2, BATCH as u64));

        let empty = HashTable::<u64>::with_capacity(10_000);
        let mut cursor = BucketCursor::new(&empty);
        assert_eq!(
            cursor.step_batch(&mut policy).unwrap(),
            BucketStep::Complete
        );
        assert_eq!(cursor.position(), 0);

        let mut short = BucketCursor::new(&first);
        short.next = short.buckets;
        assert_eq!(
            short.step_batch(&mut policy),
            Err(BoundedError::PlanMismatch)
        );
        assert_eq!(short.step_batch(&mut policy).unwrap(), BucketStep::Finished);
    }
}
