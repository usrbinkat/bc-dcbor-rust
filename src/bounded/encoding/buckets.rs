//! The one traversal of a hash table's buckets: the engine's, admitted a
//! window of controls at a time, over the sealed set of tables whose bucket
//! accessors this crate's forks provide.
use super::super::boundary::{Bound, Predicate, Valuation, boundary};
use super::super::{
    BoundedError, BoundedResult, Budget, Places, Rate, ResourceBound, Unit, WriteWork, add,
};
use super::{BUCKET_WINDOW, Schema};

places! {
    /// The places bucket enumeration ([`BucketCursor`]) charges, one term of
    /// [`bucket_bound`] each.
    pub(crate) enum BucketPlace {
        Inspection,
        Completion,
    }
}

/// One call of the cursor: one value, and, when the call admits a window,
/// one byte per control of it. A window's controls are admitted once and
/// spent index by index as they are inspected; what is unspent when the
/// enumeration completes is forfeited, never refunded.
const INSPECT: Rate<BucketPlace> = Rate::based(
    BucketPlace::Inspection,
    WriteWork::new(1, 0),
    WriteWork::new(0, 1),
);

/// Completing the enumeration.
const COMPLETE: Unit<BucketPlace> = Unit::new(BucketPlace::Completion, 1, 0);

/// The state of one bucket, read from its one control byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BucketState {
    /// Never occupied since the table was allocated or last cleared.
    Vacant,
    /// Its entry was removed while probe sequences still run past it.
    Deleted,
    /// Holding an entry.
    Full,
}

mod sealed {
    /// Implemented only in this module's parent, for the tables of
    /// [`super::Buckets`]: no other crate can name it.
    pub trait Sealed {}
}

/// The bucket accessors of a hash table the engine enumerates
/// ([`super::Instruction::Buckets`]). Sealed: implemented only for std's
/// `HashMap` on the bounded-collection standard library, and hashbrown's
/// `HashMap` and `HashTable` of pairs, whose accessors are this crate's own
/// forks' (one control byte or one group of them per read, no hashing, no
/// key comparison), so no implementation scans more than the engine
/// admits or reports a state the table does not hold. A collection outside
/// the set yields its entries through [`super::Entries`].
///
/// ```compile_fail,E0277
/// use dcbor::bounded::encoding::buckets::Buckets;
/// struct Table;
/// impl Buckets for Table {
///     fn entry_count(&self) -> usize { 0 }
///     fn num_buckets(&self) -> usize { 0 }
///     fn next_full_bucket(&self, _: usize, _: usize) -> Option<usize> { None }
///     fn bucket_state(&self, _: usize) -> Option<dcbor::bounded::encoding::buckets::BucketState> { None }
///     fn entry(&self, _: usize) -> Option<(&dyn dcbor::bounded::encoding::Schema, &dyn dcbor::bounded::encoding::Schema)> { None }
/// }
/// ```
pub trait Buckets: sealed::Sealed {
    /// The entries the table holds.
    fn entry_count(&self) -> usize;

    /// The bucket indices, vacant and deleted ones included.
    fn num_buckets(&self) -> usize;

    /// The least occupied index in `start..end`, `end` at most
    /// [`Self::num_buckets`], found a group of controls at a time.
    fn next_full_bucket(&self, start: usize, end: usize) -> Option<usize>;

    /// The state of the bucket at `index`, or `None` past the last.
    fn bucket_state(&self, index: usize) -> Option<BucketState>;

    /// The entry of the occupied bucket at `index`, as schemas.
    fn entry(&self, index: usize) -> Option<(&dyn Schema, &dyn Schema)>;
}

#[cfg(feature = "hashbrown")]
fn hashbrown_state(state: hashbrown::BucketState) -> BucketState {
    match state {
        hashbrown::BucketState::Vacant => BucketState::Vacant,
        hashbrown::BucketState::Deleted => BucketState::Deleted,
        hashbrown::BucketState::Full => BucketState::Full,
    }
}

#[cfg(feature = "hashbrown")]
impl<K: Schema, V: Schema, S> sealed::Sealed for hashbrown::HashMap<K, V, S> {}

#[cfg(feature = "hashbrown")]
impl<K: Schema, V: Schema, S> Buckets for hashbrown::HashMap<K, V, S> {
    fn entry_count(&self) -> usize {
        hashbrown::HashMap::len(self)
    }

    fn num_buckets(&self) -> usize {
        hashbrown::HashMap::num_buckets(self)
    }

    fn next_full_bucket(&self, start: usize, end: usize) -> Option<usize> {
        hashbrown::HashMap::next_full_bucket(self, start, end)
    }

    fn bucket_state(&self, index: usize) -> Option<BucketState> {
        hashbrown::HashMap::bucket_state(self, index).map(hashbrown_state)
    }

    fn entry(&self, index: usize) -> Option<(&dyn Schema, &dyn Schema)> {
        self.get_bucket(index)
            .map(|(key, value)| (key as &dyn Schema, value as &dyn Schema))
    }
}

#[cfg(feature = "hashbrown")]
impl<K: Schema, V: Schema> sealed::Sealed for hashbrown::HashTable<(K, V)> {}

#[cfg(feature = "hashbrown")]
impl<K: Schema, V: Schema> Buckets for hashbrown::HashTable<(K, V)> {
    fn entry_count(&self) -> usize {
        hashbrown::HashTable::len(self)
    }

    fn num_buckets(&self) -> usize {
        hashbrown::HashTable::num_buckets(self)
    }

    fn next_full_bucket(&self, start: usize, end: usize) -> Option<usize> {
        hashbrown::HashTable::next_full_bucket(self, start, end)
    }

    fn bucket_state(&self, index: usize) -> Option<BucketState> {
        hashbrown::HashTable::bucket_state(self, index).map(hashbrown_state)
    }

    fn entry(&self, index: usize) -> Option<(&dyn Schema, &dyn Schema)> {
        self.get_bucket(index)
            .map(|pair| (&pair.0 as &dyn Schema, &pair.1 as &dyn Schema))
    }
}

#[cfg(feature = "custom-std-collections")]
fn std_state(state: std::collections::hash_map::BucketState) -> BucketState {
    use std::collections::hash_map::BucketState as Std;
    match state {
        Std::Vacant => BucketState::Vacant,
        Std::Deleted => BucketState::Deleted,
        Std::Full => BucketState::Full,
    }
}

#[cfg(feature = "custom-std-collections")]
impl<K: Schema, V: Schema, S> sealed::Sealed for std::collections::HashMap<K, V, S> {}

#[cfg(feature = "custom-std-collections")]
impl<K: Schema, V: Schema, S> Buckets for std::collections::HashMap<K, V, S> {
    fn entry_count(&self) -> usize {
        std::collections::HashMap::len(self)
    }

    fn num_buckets(&self) -> usize {
        std::collections::HashMap::num_buckets(self)
    }

    fn next_full_bucket(&self, start: usize, end: usize) -> Option<usize> {
        std::collections::HashMap::next_full_bucket(self, start, end)
    }

    fn bucket_state(&self, index: usize) -> Option<BucketState> {
        std::collections::HashMap::bucket_state(self, index).map(std_state)
    }

    fn entry(&self, index: usize) -> Option<(&dyn Schema, &dyn Schema)> {
        self.get_bucket(index)
            .map(|(key, value)| (key as &dyn Schema, value as &dyn Schema))
    }
}

/// What one call of a [`BucketCursor`] reached.
pub enum BucketStep<'a> {
    /// Every bucket of the window's credit was vacant or deleted; `index`
    /// is the first of them.
    Vacant { index: usize },
    /// The occupied bucket at `index` and its entry.
    Entry {
        index: usize,
        key: &'a dyn Schema,
        value: &'a dyn Schema,
    },
    /// Every entry was yielded.
    Complete,
    /// The enumeration completed, or failed, earlier.
    Finished,
}

/// The position of the one enumeration of a table's buckets: the next index
/// to inspect, the entries yielded, and the controls of the current window
/// admitted and not yet inspected. Plain data, borrowing nothing: the table
/// is given to each call, so a preparation retains the cursor beside its
/// table's reference across suspensions and relocations, and its position
/// and credit are what it resumes from, never recomputed. Creation scans
/// and admits nothing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BucketCursor {
    next: usize,
    yielded: usize,
    held: usize,
    finished: bool,
}

impl BucketCursor {
    pub const fn new() -> Self {
        Self {
            next: 0,
            yielded: 0,
            held: 0,
            finished: false,
        }
    }

    /// The next index to inspect, unchanged by a refusal.
    pub const fn position(&self) -> usize {
        self.next
    }

    /// The controls admitted and not yet inspected.
    pub const fn held(&self) -> usize {
        self.held
    }

    /// One call: once every entry is yielded, the completion; otherwise, a
    /// window's controls admitted when the last window's credit is spent,
    /// then the controls of the credit inspected up to and including the
    /// first occupied one. A window is index-aligned: windows start at zero
    /// and run [`BUCKET_WINDOW`] controls, the last to the table's end. A
    /// table whose buckets run out short of its count is refused as a plan
    /// mismatch. Records, through the one seam, the window against the
    /// table's end and the states of the controls inspected.
    pub fn step<'a, B: Budget>(
        &mut self,
        table: &'a dyn Buckets,
        budget: &mut B,
    ) -> BoundedResult<BucketStep<'a>, B> {
        if self.finished {
            return Ok(BucketStep::Finished);
        }
        if self.yielded == table.entry_count() {
            COMPLETE.admit(budget)?;
            // The rest of the window's credit is forfeited: the
            // enumeration is complete.
            self.held = 0;
            self.finished = true;
            return Ok(BucketStep::Complete);
        }
        let buckets = table.num_buckets();
        if self.next == buckets {
            self.finished = true;
            return Err(BoundedError::PlanMismatch);
        }
        // The credit is spent only at a window's end, so `next` is then
        // the start of the next window: a full window, or the table's
        // last, short one (`Below`).
        let window = if self.held == 0 {
            Bound::new(Predicate::Buckets, BUCKET_WINDOW).clamp(budget, buckets - self.next)
        } else {
            0
        };
        INSPECT.admit(budget, window as u64)?;
        self.held += window;
        let index = self.next;
        let end = index + self.held;
        let found = table.next_full_bucket(index, end);
        let stop = found.map_or(end, |bucket| bucket + 1);
        let mut vacant = false;
        let mut deleted = false;
        for at in index..stop {
            match table.bucket_state(at) {
                Some(BucketState::Vacant) => vacant = true,
                Some(BucketState::Deleted) => deleted = true,
                Some(BucketState::Full) | None => {}
            }
        }
        if vacant {
            boundary!(budget, Predicate::Buckets => Valuation::Vacant);
        }
        if deleted {
            boundary!(budget, Predicate::Buckets => Valuation::Tombstone);
        }
        self.held -= stop - index;
        self.next = stop;
        match found {
            Some(bucket) => {
                let (key, value) = table.entry(bucket).ok_or(BoundedError::PlanMismatch)?;
                boundary!(budget, Predicate::Buckets => Valuation::Occupied);
                self.yielded += 1;
                Ok(BucketStep::Entry {
                    index: bucket,
                    key,
                    value,
                })
            }
            None => Ok(BucketStep::Vacant { index }),
        }
    }
}

/// The [`ResourceBound`] of enumerating a table of `buckets` buckets,
/// `entries` of them occupied ([`BucketCursor::step`]): every call admits one
/// value, every control is admitted once with its window, and the calls are
/// at most one per window, each ending at the window's end, and one per
/// entry, each ending early at it; then one unit to complete. Nothing is
/// allocated or retained. Refused, never saturated, when a quantity does not
/// fit in `u64`.
pub fn bucket_bound<R>(buckets: u64, entries: u64) -> Result<ResourceBound, BoundedError<R>> {
    BucketTerms::of::<R>(1, buckets, entries)?.bound()
}

/// The work of enumerating `tables` tables of `buckets` buckets and
/// `entries` entries in all ([`bucket_bound`] summed): what a shape walk and
/// a preparation each charge for the tables they enumerate.
pub(crate) fn bucket_work<R>(
    tables: u64,
    buckets: u64,
    entries: u64,
) -> Result<WriteWork, BoundedError<R>> {
    let terms = BucketTerms::of::<R>(tables, buckets, entries)?;
    terms.inspection.then(terms.completion)
}

/// The windows of a table of `buckets` buckets: [`BUCKET_WINDOW`] controls
/// each, the last short.
pub(crate) fn windows(buckets: u64) -> u64 {
    buckets.div_ceil(BUCKET_WINDOW as u64)
}

/// The terms [`bucket_bound`] sums, one per [`BucketPlace`].
struct BucketTerms {
    inspection: WriteWork,
    completion: WriteWork,
}

impl BucketTerms {
    /// `tables` tables of `buckets` buckets and `entries` entries in all: a
    /// table's windows are summed over its own buckets, so the windows of
    /// many tables are at most the windows of their buckets together and one
    /// more per table.
    fn of<R>(tables: u64, buckets: u64, entries: u64) -> Result<Self, BoundedError<R>> {
        let calls = add(add(windows(buckets), tables)?, entries)?;
        Ok(Self {
            inspection: INSPECT.over(calls, buckets)?,
            completion: COMPLETE.times(tables)?,
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

#[cfg(test)]
#[cfg(all(feature = "std", feature = "hashbrown"))]
mod attribution {
    use super::*;
    use crate::bounded::boundary::{Boundary, Reached};
    use crate::bounded::places::{self, Factor, Ledgered, Run, WORK};
    use hashbrown::HashTable;

    /// A table of `entries` pairs with room for at least `capacity`, its
    /// hashes spread by a fixed multiplier so its layout is reproducible.
    fn table(entries: u64, capacity: usize) -> HashTable<(u64, u64)> {
        let hash = |pair: &(u64, u64)| pair.0.wrapping_mul(0x9e37_79b9_7f4a_7c15);
        let mut table = HashTable::with_capacity(capacity);
        for key in 0..entries {
            table.insert_unique(hash(&(key, 0)), (key, key), hash);
        }
        table
    }

    /// A table of pairs whose keys hash to themselves, so each lies in its
    /// own home bucket when free as it is inserted: keys `0` through `199`
    /// fill the buckets of the same indices, `255` the last of the 256.
    fn dense() -> HashTable<(u64, u64)> {
        let hash = |pair: &(u64, u64)| pair.0;
        let mut table = HashTable::new();
        for key in (0..200).chain([255]) {
            table.insert_unique(key, (key, key), hash);
        }
        assert_eq!(table.num_buckets(), 256);
        assert_eq!(table.get_bucket(255), Some(&(255, 255)));
        table
    }

    /// A collision cluster of 100 pairs, all but the last removed: its
    /// removals leave deleted controls.
    fn tombstoned() -> HashTable<(u64, u64)> {
        let collide = |_: &(u64, u64)| 0;
        let mut table = HashTable::new();
        for key in 0..100u64 {
            table.insert_unique(0, (key, key), collide);
        }
        for key in 0..99u64 {
            let (removed, _) = table
                .find_entry(0, |pair| pair.0 == key)
                .expect("each key is present once")
                .remove();
            assert_eq!(removed, (key, key));
        }
        table
    }

    /// `table` enumerated to completion under `policy`: the entries yielded.
    fn enumerate<B: Budget>(table: &HashTable<(u64, u64)>, policy: &mut B) -> u64
    where
        B::Refusal: core::fmt::Debug,
    {
        let bound = bucket_bound::<()>(table.num_buckets() as u64, table.len() as u64).unwrap();
        let mut cursor = BucketCursor::new();
        let mut entries = 0u64;
        crate::bounded::within("bucket enumeration", bound, || {
            match cursor
                .step(table, policy)
                .expect("an unlimited policy never refuses")
            {
                BucketStep::Entry { .. } => {
                    entries += 1;
                    core::ops::ControlFlow::Continue(())
                }
                BucketStep::Vacant { .. } => core::ops::ControlFlow::Continue(()),
                BucketStep::Complete => core::ops::ControlFlow::Break(()),
                BucketStep::Finished => unreachable!("completion ends the loop"),
            }
        });
        entries
    }

    /// Every place of an enumeration is within its term on an empty table,
    /// a sparse one, a dense one whose last entry is in its last bucket, and
    /// a tombstoned one; every admission is made at some place; each
    /// place's witness charges it; each control is admitted at most once,
    /// so the bytes admitted are at most the buckets.
    #[test]
    fn every_place_of_a_bucket_enumeration_is_within_its_term() {
        let tables = [
            ("empty", table(0, 0)),
            ("sparse", table(3, 1000)),
            ("dense", dense()),
            ("tombstoned", tombstoned()),
        ];
        let mut runs = Vec::new();
        let mut witnesses = Vec::new();
        for (name, table) in &tables {
            let mut policy = Ledgered::new();
            let entries = enumerate(table, &mut policy);
            assert_eq!(
                entries,
                table.len() as u64,
                "{name}: every entry is visited"
            );
            let admitted = policy.ledger().total().bytes;
            assert!(
                admitted <= table.num_buckets() as u64,
                "{name}: a control admitted twice: {admitted} bytes over {} buckets",
                table.num_buckets()
            );
            match *name {
                "empty" => witnesses.push((runs.len(), BucketPlace::Completion)),
                "dense" => witnesses.push((runs.len(), BucketPlace::Inspection)),
                _ => {}
            }
            runs.push(Run {
                outcome: places::Outcome::Published,
                name: (*name).to_string(),
                policy,
                terms: BucketTerms::of::<()>(1, table.num_buckets() as u64, table.len() as u64)
                    .unwrap(),
            });
        }
        places::check(&runs);
        places::witnessed(&runs, &witnesses);
        // Completion is one unit, exact. Inspection, on the dense table,
        // admits every control of its 256 once and one value per window
        // and per entry: within twice its term's values.
        places::Tightness::new("buckets")
            .places(&runs, &witnesses, |place| match place {
                BucketPlace::Inspection => Factor::Within(2),
                BucketPlace::Completion => Factor::Within(1),
            })
            .joint(
                &runs,
                "dense",
                WORK,
                "a dense table: an entry ends nearly every call, every control admitted once \
                 with its window, its last entry in its last bucket",
            )
            .finish();
    }

    /// A refused call leaves the cursor where it was, its credit included,
    /// and the retried call inspects what the refused one would have: a
    /// window's controls are admitted once, the next call within the window
    /// spending the credit held.
    #[test]
    fn a_window_is_admitted_once_and_its_credit_survives_refusal() {
        let table = dense();
        let mut policy = crate::bounded::Limits::unlimited().refusing_each();
        let mut cursor = BucketCursor::new();
        let before = cursor;
        assert!(
            cursor.step(&table, &mut policy).is_err(),
            "the first admission is refused"
        );
        assert_eq!(cursor, before, "a refused call moved the cursor");
        match cursor.step(&table, &mut policy).unwrap() {
            BucketStep::Entry { index: 0, .. } => {}
            _ => panic!("the first bucket holds an entry"),
        }
        assert_eq!(
            cursor.held(),
            BUCKET_WINDOW - 1,
            "the window's credit less the one control inspected"
        );
        assert_eq!(policy.used(), WriteWork::new(1, BUCKET_WINDOW as u64));
        assert!(cursor.step(&table, &mut policy).is_err());
        match cursor.step(&table, &mut policy).unwrap() {
            BucketStep::Entry { index: 1, .. } => {}
            _ => panic!("the second bucket holds an entry"),
        }
        assert_eq!(
            policy.used(),
            WriteWork::new(2, BUCKET_WINDOW as u64),
            "a call within the window admitted its controls again"
        );
    }

    /// Enumeration completes once the table's entries are yielded, before
    /// the buckets after the last: a table whose one entry lies in its first
    /// bucket completes after one call, whatever its size; an empty table
    /// completes at once. A cursor that reaches the last bucket short of the
    /// table's count is refused as a plan mismatch, never completed.
    #[test]
    fn enumeration_completes_at_the_last_entry() {
        let mut policy = crate::bounded::Limits::unlimited();
        let hash = |pair: &(u64, u64)| pair.0;
        let mut first = HashTable::with_capacity(10_000);
        first.insert_unique(0, (0u64, 0u64), hash);
        assert_eq!(first.get_bucket(0), Some(&(0, 0)));
        let mut cursor = BucketCursor::new();
        match cursor.step(&first, &mut policy).unwrap() {
            BucketStep::Entry { index: 0, .. } => {}
            _ => panic!("the first bucket holds the entry"),
        }
        match cursor.step(&first, &mut policy).unwrap() {
            BucketStep::Complete => {}
            _ => panic!("one entry yielded completes"),
        }
        assert_eq!(
            cursor.position(),
            1,
            "no bucket after the entry was scanned"
        );
        assert_eq!(cursor.held(), 0, "the credit is forfeited at completion");
        assert_eq!(policy.used(), WriteWork::new(2, BUCKET_WINDOW as u64));

        let empty = HashTable::<(u64, u64)>::with_capacity(10_000);
        let mut cursor = BucketCursor::new();
        match cursor.step(&empty, &mut policy).unwrap() {
            BucketStep::Complete => {}
            _ => panic!("an empty table completes at once"),
        }
        assert_eq!(cursor.position(), 0);

        let mut short = BucketCursor::new();
        short.next = first.num_buckets();
        assert!(matches!(
            short.step(&first, &mut policy),
            Err(BoundedError::PlanMismatch)
        ));
        assert!(matches!(
            short.step(&first, &mut policy),
            Ok(BucketStep::Finished)
        ));
    }

    /// The `Buckets` valuations a whole enumeration of `table` reached.
    fn reached(table: &HashTable<(u64, u64)>) -> Reached {
        let mut policy = crate::bounded::Limits::unlimited();
        enumerate(table, &mut policy);
        policy.reached()
    }

    fn reaches(reached: &Reached, valuation: Valuation) -> bool {
        reached.contains(Boundary {
            predicate: Predicate::Buckets,
            valuation,
        })
    }

    /// Each `Buckets` valuation is reached exactly where its table holds it:
    /// a dense table's windows cross occupied and never-occupied buckets,
    /// run inside the table (`Past`) and to its end (`At`), and cross no
    /// deleted bucket; a table whose last window is short reaches `Below`;
    /// a tombstoned cluster, which `bucket_state` confirms holds deleted
    /// buckets, reaches `Tombstone`; an empty table completes without
    /// scanning and reaches none.
    #[test]
    fn bucket_predicates_name_what_each_window_crossed() {
        let dense = reached(&dense());
        for valuation in [
            Valuation::Occupied,
            Valuation::Vacant,
            Valuation::Past,
            Valuation::At,
        ] {
            assert!(reaches(&dense, valuation), "dense: {valuation}");
        }
        assert!(
            !reaches(&dense, Valuation::Tombstone),
            "a table with nothing removed crosses no deleted bucket"
        );

        let mut small = HashTable::new();
        let hash = |pair: &(u64, u64)| pair.0;
        small.insert_unique(0, (0u64, 0u64), hash);
        assert!(
            small.num_buckets() < BUCKET_WINDOW,
            "a table of {} buckets is shorter than a window",
            small.num_buckets()
        );
        assert!(reaches(&reached(&small), Valuation::Below), "small: below");

        let cluster = tombstoned();
        assert!(
            (0..cluster.num_buckets())
                .any(|index| Buckets::bucket_state(&cluster, index) == Some(BucketState::Deleted)),
            "the emptied cluster holds deleted buckets"
        );
        let cluster = reached(&cluster);
        assert!(
            reaches(&cluster, Valuation::Tombstone),
            "cluster: tombstone"
        );
        assert!(
            reaches(&cluster, Valuation::Occupied),
            "cluster: its last key"
        );

        let empty = reached(&table(0, 0));
        assert!(
            Valuation::ALL
                .iter()
                .all(|&valuation| !reaches(&empty, valuation)),
            "an empty table completes without scanning a bucket"
        );
    }
}
