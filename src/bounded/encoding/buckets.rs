//! The one traversal of a hash table's buckets: the engine's, admitted a
//! window of controls at a time, over the sealed set of tables whose bucket
//! accessors this crate's forks provide.
use super::super::boundary::{Bound, Predicate, Valuation, boundary};
use super::super::{
    Acquisition, BoundedError, BoundedResult, Budget, CustodySink, Forfeit, Identity, Obligation,
    Origin, Owner, Performer, Places, Rate, ResourceBound, Retained, Unit, WriteWork, add,
};
use super::{BUCKET_WINDOW, Schema, close_window, window_obligation};

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
/// to inspect, the entries yielded, and whether it has ended. Plain data,
/// borrowing nothing and owning no credit: the table is given to each call,
/// so a preparation retains the position beside its table's reference, in
/// its cursor arena's slot, across suspensions and relocations. The
/// window's credit is not here: it is the window obligation the cursor's
/// custody holds beside it ([`BucketCursor`]). Creation scans and admits
/// nothing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BucketPosition {
    next: usize,
    yielded: usize,
    finished: bool,
}

impl BucketPosition {
    pub const fn new() -> Self {
        Self {
            next: 0,
            yielded: 0,
            finished: false,
        }
    }

    /// The next index to inspect, unchanged by a refusal.
    pub const fn index(&self) -> usize {
        self.next
    }
}

/// The custody of one enumeration of a table's buckets: its position; the
/// obligation of its current window's controls admitted and not yet
/// inspected ([`Obligation::BucketWindow`]), held with the origin that
/// admitted it, which every later spend and forfeit reaches whichever
/// budget performs it; and that window's acquisition's capability
/// ([`Acquisition`]), the one authority that publishes its end. A view over
/// the three, which their holder keeps apart (a preparation: the position
/// in its cursor arena's slot, the window's credit and its acquisition in
/// two parts of one window arena, each element one relocation unit; a
/// shape walk: all three on its frame); this is the one implementation of
/// the traversal, its settlement and its acquisitions' ends. Not `Copy`:
/// the window is custody.
pub struct BucketCursor<'c, O: Origin> {
    position: &'c mut BucketPosition,
    window: &'c mut Option<Retained<O>>,
    acquisition: &'c mut Option<Acquisition<O>>,
}

impl<'c, O: Origin> BucketCursor<'c, O> {
    /// The enumeration at `position`, its window's credit in `window` and
    /// its window's acquisition in `acquisition`.
    pub fn new(
        position: &'c mut BucketPosition,
        window: &'c mut Option<Retained<O>>,
        acquisition: &'c mut Option<Acquisition<O>>,
    ) -> Self {
        Self {
            position,
            window,
            acquisition,
        }
    }

    /// The window's acquisition, bound from its window's opening to its
    /// closing, as its holder reports it ([`CustodySink::bound`]).
    pub fn bound(&self) -> Option<Identity> {
        self.acquisition.as_ref().map(Acquisition::id)
    }

    /// The next index to inspect, unchanged by a refusal.
    pub fn position(&self) -> usize {
        self.position.next
    }

    /// The controls admitted and not yet inspected: the window's remaining
    /// bytes, one per control, the one record of them.
    pub fn held(&self) -> usize {
        held(self.window)
    }

    /// The obligation this cursor's custody holds, if any: its window's, a
    /// nonzero remainder reported once (`window_obligation`). A fragment,
    /// never a complete observation: emitted only inside the group its
    /// holder has open as `begin(Some(owner.id()))` of the very [`Owner`]
    /// the holder stores and passes to [`Self::step`], the owner every
    /// window acquisition binds under, since the cursor keeps no owner of
    /// its own ([`CustodySink`]). Its only caller is such a holder, the
    /// admission-trace bucket case; a preparation, which stores its window
    /// owner too, reports its windows through its window arena with the same
    /// leaf reading. Read-only and allocation-free; it admits, mints,
    /// publishes and settles nothing.
    pub fn observe_window<P>(&self, sink: &mut dyn CustodySink<P>) {
        if let Some(acquisition) = self.bound() {
            sink.bound(acquisition);
        }
        window_obligation(self.window, &mut |hold| sink.held(hold));
    }

    /// The credit this cursor's custody holds ([`Obligation::BucketWindow`]):
    /// its one window's remaining work, read from the retained obligation
    /// itself, its controls admitted and not yet inspected or forfeited, a
    /// byte each; nothing when no window is open. The public conservation
    /// observation of the enumeration: read beside its policies'
    /// [`crate::bounded::Limits::credits`], it is the `held` that
    /// [`crate::bounded::Credits::conserved_with`] checks. Always `Some`:
    /// the signature is the one every custody's `held_credit` shares.
    pub fn held_credit(&self) -> Option<WriteWork> {
        Some(
            self.window
                .as_ref()
                .map_or(WriteWork::default(), Retained::remaining),
        )
    }

    /// End the enumeration before its completion, its window's unspent
    /// credit forfeited under `rule` into the family that admitted it, `by`
    /// the performing budget ([`Budget::performer`]):
    /// [`Forfeit::EnumerationComplete`] when its map's declared count was
    /// reached, [`Forfeit::Cancelled`] when an error or cleanup ends it; the
    /// window's acquisition then ended (`super::close_window`). Admits nothing;
    /// later calls return [`BucketStep::Finished`].
    pub fn end(&mut self, by: Performer, rule: Forfeit) {
        close_window(self.window, self.acquisition, Some(rule), by);
        self.position.finished = true;
    }

    /// One call: once every entry is yielded, the completion; otherwise, a
    /// window's controls admitted when the last window's credit is spent,
    /// then the controls of the credit inspected up to and including the
    /// first occupied one. A window is index-aligned: windows start at zero
    /// and run [`BUCKET_WINDOW`] controls, the last to the table's end. A
    /// table whose buckets run out short of its count is refused as a plan
    /// mismatch. Records, through the one seam, the window against the
    /// table's end and the states of the controls inspected.
    ///
    /// A window's controls are one acquisition of `owner`, the custody that
    /// holds the cursor: its identity minted ([`Budget::acquisition`]),
    /// then the call's value and the controls admitted, the controls held
    /// (`Rate::admit_held`); a refused admission keeps the acquisition
    /// for the retry without holding credit. A call within a window admits its
    /// value alone and mints nothing.
    pub fn step<'a, B: Budget<Origin = O>>(
        &mut self,
        table: &'a dyn Buckets,
        owner: &Owner,
        budget: &mut B,
    ) -> BoundedResult<BucketStep<'a>, B> {
        let p = &mut *self.position;
        if p.finished {
            return Ok(BucketStep::Finished);
        }
        budget
            .validate_owner(owner)
            .map_err(BoundedError::Refused)?;
        if let Some(window) = self.window.as_ref()
            && self.acquisition.as_ref().map(Acquisition::id) != Some(window.acquisition())
        {
            return Err(BoundedError::PlanMismatch);
        }
        if p.yielded == table.entry_count() {
            COMPLETE.admit(budget)?;
            // The rest of the window's credit is forfeited: the
            // enumeration is complete.
            self.end(budget.performer(), Forfeit::EnumerationComplete);
            return Ok(BucketStep::Complete);
        }
        let buckets = table.num_buckets();
        if p.next == buckets {
            self.end(budget.performer(), Forfeit::Cancelled);
            return Err(BoundedError::PlanMismatch);
        }
        // The credit is spent only at a window's end, so `next` is then
        // the start of the next window: a full window, or the table's
        // last, short one (`Below`). A window opens in two stages: its
        // acquisition minted and kept in its slot, then its controls
        // admitted held. A refused admission keeps the acquisition for the
        // retry, which admits the controls alone and mints nothing; a
        // window holding credit with no acquisition is a defect.
        if self.window.is_none() {
            if self.acquisition.is_none() {
                *self.acquisition = Some(budget.acquisition(owner).map_err(BoundedError::Refused)?);
            }
            let acquisition = self
                .acquisition
                .as_ref()
                .ok_or(BoundedError::PlanMismatch)?
                .id();
            let window =
                Bound::new(Predicate::Buckets, BUCKET_WINDOW).clamp(budget, buckets - p.next);
            *self.window = Some(INSPECT.admit_held(
                budget,
                window as u64,
                Obligation::BucketWindow,
                owner,
                acquisition,
            )?);
        } else if self.acquisition.is_none() {
            return Err(BoundedError::PlanMismatch);
        } else {
            INSPECT.admit(budget, 0)?;
        }
        let p = &mut *self.position;
        let index = p.next;
        let end = index + held(self.window);
        let found = table.next_full_bucket(index, end);
        let stop = found.map_or(end, |bucket| bucket + 1);
        // The controls inspected now spend their credit; a window whose
        // every control is inspected holds nothing and goes.
        let inspected = INSPECT.held((stop - index) as u64)?;
        let by = budget.performer();
        if let Some(window) = self.window.as_mut() {
            window.consume(inspected, None, by)?;
            // A window whose every control is inspected closes: nothing
            // left to spend, its acquisition ended.
            if window.remaining() == WriteWork::default() {
                close_window(self.window, self.acquisition, None, by);
            }
        }
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
        self.position.next = stop;
        match found {
            Some(bucket) => {
                let Some((key, value)) = table.entry(bucket) else {
                    self.end(budget.performer(), Forfeit::Cancelled);
                    return Err(BoundedError::PlanMismatch);
                };
                boundary!(budget, Predicate::Buckets => Valuation::Occupied);
                self.position.yielded += 1;
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

/// The controls a window obligation still holds: its remaining bytes, one
/// per control ([`INSPECT`]'s per-element part); none without a window.
fn held<O: Origin>(window: &Option<Retained<O>>) -> usize {
    window
        .as_ref()
        .map_or(0, |window| window.remaining().bytes as usize)
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
    WriteWork::checked_sequence(&[terms.inspection, terms.completion]).ok_or(BoundedError::Overflow)
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
        let owner = policy.owner().expect("an unlimited policy makes an owner");
        let (mut position, mut window, mut acquisition) = (BucketPosition::new(), None, None);
        let mut cursor = BucketCursor::new(&mut position, &mut window, &mut acquisition);
        let mut entries = 0u64;
        crate::bounded::within("bucket enumeration", bound, || {
            match cursor
                .step(table, &owner, policy)
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
        // An ordinary owner, made apart from the refusing policy, whose
        // every admission is refused once.
        let owner = crate::bounded::Limits::unlimited()
            .owner()
            .expect("an ordinary owner");
        let mut policy = crate::bounded::Limits::unlimited().refusing_each();
        let (mut position, mut window, mut acquisition) = (BucketPosition::new(), None, None);
        let before = position;
        assert!(
            BucketCursor::new(&mut position, &mut window, &mut acquisition)
                .step(&table, &owner, &mut policy)
                .is_err(),
            "the first admission is refused"
        );
        assert_eq!(position, before, "a refused call moved the cursor");
        assert!(window.is_none(), "a refused call kept a window");
        let mut cursor = BucketCursor::new(&mut position, &mut window, &mut acquisition);
        match cursor.step(&table, &owner, &mut policy).unwrap() {
            BucketStep::Entry { index: 0, .. } => {}
            _ => panic!("the first bucket holds an entry"),
        }
        assert_eq!(
            cursor.held(),
            BUCKET_WINDOW - 1,
            "the window's credit less the one control inspected"
        );
        assert_eq!(policy.used(), WriteWork::new(1, BUCKET_WINDOW as u64));
        assert!(cursor.step(&table, &owner, &mut policy).is_err());
        match cursor.step(&table, &owner, &mut policy).unwrap() {
            BucketStep::Entry { index: 1, .. } => {}
            _ => panic!("the second bucket holds an entry"),
        }
        assert_eq!(
            policy.used(),
            WriteWork::new(2, BUCKET_WINDOW as u64),
            "a call within the window admitted its controls again"
        );
    }

    /// A call within a running window admits its base value alone, never a
    /// new window: refused under B, the position, the window's obligation
    /// (its identity, its acquisition, its origin's family) and its
    /// remaining credit are unchanged, A's ledgers unchanged and B's empty;
    /// resumed under B, B admits and consumes the base value alone, one
    /// value and no control, while the control it inspects is consumed from
    /// the window's own family, A, whose admissions are unchanged. Families
    /// of one recording session, so identities are observed. Planted
    /// control `tests/data/controls/bucket-window-readmitted.patch` admits a
    /// fresh window at every call and must fail it.
    #[test]
    fn a_call_within_a_window_admits_its_base_alone_across_refusal_and_policies() {
        use crate::bounded::{Capacity, Session};
        let session = Session::new(Capacity::DEFAULT);
        let table = dense();
        let mut a = crate::bounded::Limits::recorded_unlimited(&session);
        let owner = a.owner().expect("a recorded owner");
        let (mut position, mut window, mut acquisition) = (BucketPosition::new(), None, None);
        match BucketCursor::new(&mut position, &mut window, &mut acquisition)
            .step(&table, &owner, &mut a)
            .unwrap()
        {
            BucketStep::Entry { index: 0, .. } => {}
            _ => panic!("the first bucket holds an entry"),
        }
        let obligation = |window: &Option<Retained<crate::bounded::Family>>| {
            window
                .as_ref()
                .map(|window| (window.id(), window.acquisition(), window.remaining()))
        };
        let opened = obligation(&window).expect("the window is held after its first call");
        assert_eq!(opened.2, WriteWork::new(0, BUCKET_WINDOW as u64 - 1));
        let after_first = a.credits();

        let mut b = crate::bounded::Limits::recorded_unlimited(&session).refusing(Some(0));
        let before = position;
        assert!(matches!(
            BucketCursor::new(&mut position, &mut window, &mut acquisition)
                .step(&table, &owner, &mut b),
            Err(BoundedError::Refused(_))
        ));
        assert_eq!(position, before, "a refused call within the window moved");
        assert_eq!(
            obligation(&window),
            Some(opened),
            "a refused call within the window changed its obligation"
        );
        assert_eq!(a.credits(), after_first, "a refusal under B changed A");
        assert_eq!(
            b.credits(),
            crate::bounded::Credits::default(),
            "a refused call recorded credit"
        );

        match BucketCursor::new(&mut position, &mut window, &mut acquisition)
            .step(&table, &owner, &mut b)
            .unwrap()
        {
            BucketStep::Entry { index: 1, .. } => {}
            _ => panic!("the second bucket holds an entry"),
        }
        let resumed = b.credits();
        assert_eq!(
            (resumed.admitted, resumed.consumed, resumed.forfeited),
            (
                WriteWork::new(1, 0),
                WriteWork::new(1, 0),
                WriteWork::new(0, 0)
            ),
            "a call within the window under B admitted other than its base value"
        );
        let spent = a.credits();
        assert_eq!(spent.admitted, after_first.admitted, "A admitted again");
        assert_eq!(
            Some(spent.consumed),
            after_first.consumed.checked_then(WriteWork::new(0, 1)),
            "the inspected control was not consumed from the window's family"
        );
        let (id, acquisition_id, _) = opened;
        assert_eq!(
            obligation(&window),
            Some((
                id,
                acquisition_id,
                WriteWork::new(0, BUCKET_WINDOW as u64 - 2)
            )),
            "the window's obligation was replaced"
        );
        let (family_a, family_b) = (a.origin().family(), b.origin().family());
        let (by_a, by_b) = (a.performer(), b.performer());
        assert_eq!(id.family(), family_a, "the window's origin is not A's");
        // The cancellation, performed by B: the window's remainder forfeited
        // into A's family, nothing admitted in its place.
        BucketCursor::new(&mut position, &mut window, &mut acquisition)
            .end(by_b, Forfeit::Cancelled);
        assert!(window.is_none(), "the cancelled window is still held");
        let remainder = WriteWork::new(0, BUCKET_WINDOW as u64 - 2);
        drop((a, b, owner));
        let observed = session.finish().unwrap_or_else(|incomplete| {
            panic!("the window's recording is incomplete: {incomplete:?}")
        });
        use crate::bounded::{Credit, Event};
        let credits: Vec<_> = observed
            .iter()
            .filter_map(|observed| match &observed.event {
                Event::Credit(credit) => Some((observed.family, observed.by, credit)),
                _ => None,
            })
            .collect();
        // One held admission, the window's: A's, by A, its identities those
        // the obligation carries.
        let holds: Vec<_> = credits
            .iter()
            .filter_map(|(family, by, credit)| match credit {
                Credit::Admit {
                    work,
                    held: Some(hold),
                } => Some((*family, *by, *work, *hold)),
                _ => None,
            })
            .collect();
        assert_eq!(
            holds.len(),
            1,
            "a window admitted more than once: {credits:?}"
        );
        let (family, by, work, hold) = holds[0];
        assert_eq!((family, by), (family_a, by_a), "the window's admission");
        assert_eq!(work, WriteWork::new(1, BUCKET_WINDOW as u64));
        assert_eq!(
            (hold.obligation, hold.id, hold.acquisition, hold.work),
            (
                Obligation::BucketWindow,
                id,
                acquisition_id,
                WriteWork::new(0, BUCKET_WINDOW as u64)
            ),
            "the window's hold"
        );
        // B's base value: an unheld admission into B's family, by B.
        assert!(
            credits.iter().any(|(family, by, credit)| {
                *family == family_b
                    && *by == by_b
                    && matches!(credit, Credit::Admit { work, held: None }
                        if *work == WriteWork::new(1, 0))
            }),
            "B's base value was not admitted to B: {credits:?}"
        );
        // Each inspected control spent from the window's obligation into
        // A's family: the first by A, the second by B.
        let spends: Vec<_> = credits
            .iter()
            .filter_map(|(family, by, credit)| match credit {
                Credit::Spend(settled) if settled.id == id => {
                    Some((*family, *by, settled.acquisition, settled.work))
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            spends,
            [
                (family_a, by_a, acquisition_id, WriteWork::new(0, 1)),
                (family_a, by_b, acquisition_id, WriteWork::new(0, 1)),
            ],
            "the inspected controls' spends"
        );
        // The cancellation: the remainder forfeited Cancelled into A's
        // family, by B, once.
        let forfeits: Vec<_> = credits
            .iter()
            .filter_map(|(family, by, credit)| match credit {
                Credit::Forfeit(settled, rule) => Some((
                    *family,
                    *by,
                    settled.id,
                    settled.acquisition,
                    settled.work,
                    *rule,
                )),
                _ => None,
            })
            .collect();
        assert_eq!(
            forfeits,
            [(
                family_a,
                by_b,
                id,
                acquisition_id,
                remainder,
                Forfeit::Cancelled
            )],
            "the cancellation's forfeit"
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
        let owner = policy.owner().expect("an ordinary owner");
        let hash = |pair: &(u64, u64)| pair.0;
        let mut first = HashTable::with_capacity(10_000);
        first.insert_unique(0, (0u64, 0u64), hash);
        assert_eq!(first.get_bucket(0), Some(&(0, 0)));
        let (mut position, mut window, mut acquisition) = (BucketPosition::new(), None, None);
        let mut cursor = BucketCursor::new(&mut position, &mut window, &mut acquisition);
        match cursor.step(&first, &owner, &mut policy).unwrap() {
            BucketStep::Entry { index: 0, .. } => {}
            _ => panic!("the first bucket holds the entry"),
        }
        match cursor.step(&first, &owner, &mut policy).unwrap() {
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
        let (mut position, mut window, mut acquisition) = (BucketPosition::new(), None, None);
        let mut cursor = BucketCursor::new(&mut position, &mut window, &mut acquisition);
        match cursor.step(&empty, &owner, &mut policy).unwrap() {
            BucketStep::Complete => {}
            _ => panic!("an empty table completes at once"),
        }
        assert_eq!(cursor.position(), 0);

        let mut short = BucketPosition::new();
        short.next = first.num_buckets();
        let (mut window, mut acquisition) = (None, None);
        let mut cursor = BucketCursor::new(&mut short, &mut window, &mut acquisition);
        assert!(matches!(
            cursor.step(&first, &owner, &mut policy),
            Err(BoundedError::PlanMismatch)
        ));
        assert!(matches!(
            cursor.step(&first, &owner, &mut policy),
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
