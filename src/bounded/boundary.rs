//! Boundary predicates: the data conditions at which pointer arithmetic, an
//! offset, a length or a capacity changes form in a module that contains
//! `unsafe`, and the one seam that records which valuation of each a run
//! reached.
//!
//! Every such comparison goes through this module: a limit comparison
//! through a [`Bound`], whose methods are its only comparisons, and any other
//! predicate through [`boundary!`]. Each records its valuation to the policy
//! it was given ([`Budget::boundary`]) and returns exactly the result of the
//! comparison it replaces: recording is observation, in every build, and
//! never changes control flow or a result. A policy that does not record
//! ([`Budget::boundary`]'s default) makes the seam a plain comparison.
//!
//! What is reached is compared three ways, each a premise of running Miri on
//! minimal witnesses (spec P2-P4): the fast layer against the exhaustive one,
//! minimal witnesses against full ones, and the native run against each Miri
//! model in each domain. The rows they compare are [`Reached::rows`], one
//! predicate and one valuation per row, read back by [`Reached::parse_row`].
//!
//! A new kind of pointer derivation adds its predicate here in the same
//! change; the census (`tests/unsafe_census.rs`) refuses a comparison in a
//! scoped module that bypasses the seam.

extern crate alloc;
use super::Budget;
use core::cmp::Ordering;
use core::fmt;

/// An enumeration of names, each variant once, with its position as its
/// index: the enum, [`Self::ALL`], [`Self::COUNT`], its name and its parse.
macro_rules! named {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident { $($(#[$variant_meta:meta])* $variant:ident = $text:literal),+ $(,)? }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        $vis enum $name {
            $($(#[$variant_meta])* $variant),+
        }

        impl $name {
            /// Every value, each once, in declaration order.
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];
            /// How many values there are.
            pub const COUNT: usize = Self::ALL.len();

            /// The row text of this value.
            pub const fn name(self) -> &'static str {
                match self {
                    $(Self::$variant => $text),+
                }
            }

            /// The value whose row text is `text`.
            pub fn parse(text: &str) -> Option<Self> {
                Self::ALL.iter().copied().find(|value| value.name() == text)
            }

            /// This value's position in [`Self::ALL`].
            pub const fn index(self) -> usize {
                self as usize
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.name())
            }
        }
    };
}

named! {
    /// A boundary predicate: one data condition where pointer arithmetic,
    /// an offset, a length or a capacity changes form.
    pub enum Predicate {
        /// An arena's length against its capacity: an element written into
        /// spare capacity, or a growth.
        ArenaLength = "arena-length",
        /// An admitted unit's bytes against its cap, a quantum or less.
        Quantum = "quantum",
        /// Each step of an arena's growth.
        Growth = "growth",
        /// The element a relocation or a drain moves: the first, a middle
        /// one or the last.
        Relocation = "relocation",
        /// The copy units a compared key spans.
        KeySpan = "key-span",
        /// A traversal's nesting depth against its limit.
        DispatchDepth = "dispatch-depth",
        /// The parts of a text run sorted into canonical order.
        TextRun = "text-run",
        /// A hash table bucket and its control group.
        Buckets = "buckets",
        /// A B-tree's occupancy: empty, or the height of its plan.
        TreeOccupancy = "tree-occupancy",
        /// An initialization prefix's written units against its steps: the
        /// field a place's next write is derived for.
        Prefix = "prefix",
        /// An offset into a payload, or a span read from it, against the
        /// payload's length: where a slice of the input ends.
        Payload = "payload",
        /// A record's dense field index against the index searched for or
        /// reached: which field's place the next unit projects, present or
        /// omitted.
        Field = "field",
    }
}

named! {
    /// One valuation of a [`Predicate`].
    pub enum Valuation {
        /// The measured value is zero.
        Zero = "zero",
        /// The measured value is one.
        One = "one",
        /// Below the limit.
        Below = "below",
        /// At the limit.
        At = "at",
        /// Past the limit.
        Past = "past",
        /// The first element.
        First = "first",
        /// An element neither first nor last.
        Middle = "middle",
        /// The last element.
        Last = "last",
        /// One unit.
        Single = "single",
        /// Two units.
        Pair = "pair",
        /// More than two units.
        Many = "many",
        /// A staging block acquired.
        Stage = "stage",
        /// The grown allocation requested.
        Allocate = "allocate",
        /// A relocation published.
        Publish = "publish",
        /// An element relocated.
        Relocate = "relocate",
        /// A relocated arena settled.
        Settle = "settle",
        /// A vacated block released.
        Retire = "retire",
        /// A bucket never occupied.
        Vacant = "vacant",
        /// A bucket whose entry was deleted.
        Tombstone = "tombstone",
        /// A bucket holding an entry.
        Occupied = "occupied",
        /// No entry.
        Empty = "empty",
        /// A plan of height zero: one leaf.
        Height0 = "height-0",
        /// A plan of height one.
        Height1 = "height-1",
        /// A plan of height two.
        Height2 = "height-2",
        /// A plan of height three or more.
        Taller = "taller",
    }
}

const _: () = assert!(
    Valuation::COUNT <= u64::BITS as usize,
    "a predicate's valuations are one bit each of a u64"
);

/// One valuation of one predicate, reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Boundary {
    pub predicate: Predicate,
    pub valuation: Valuation,
}

/// A count a predicate measures: a length, an offset, a capacity, a depth
/// or a quantum.
pub trait Measure: Copy + Ord {
    /// [`Valuation::Zero`] or [`Valuation::One`] when the count is that.
    fn small(self) -> Option<Valuation>;

    /// How many units the count is: [`Valuation::Zero`],
    /// [`Valuation::Single`], [`Valuation::Pair`] or [`Valuation::Many`].
    fn units(self) -> Valuation;
}

macro_rules! measures {
    ($($ty:ty),+) => {
        $(impl Measure for $ty {
            fn small(self) -> Option<Valuation> {
                match self {
                    0 => Some(Valuation::Zero),
                    1 => Some(Valuation::One),
                    _ => None,
                }
            }

            fn units(self) -> Valuation {
                match self {
                    0 => Valuation::Zero,
                    1 => Valuation::Single,
                    2 => Valuation::Pair,
                    _ => Valuation::Many,
                }
            }
        })+
    };
}

measures!(u8, u16, u32, u64, usize);

/// Compare `value` with `limit` for `predicate`, recording to `budget` the
/// valuation reached: [`Valuation::Zero`] or [`Valuation::One`] of the value,
/// and [`Valuation::Below`], [`Valuation::At`] or [`Valuation::Past`] of the
/// limit. Returns the comparison, unchanged by the recording.
pub fn compare<B: Budget + ?Sized, T: Measure>(
    budget: &mut B,
    predicate: Predicate,
    value: T,
    limit: T,
) -> Ordering {
    let ordering = value.cmp(&limit);
    if let Some(valuation) = value.small() {
        budget.boundary(Boundary {
            predicate,
            valuation,
        });
    }
    budget.boundary(Boundary {
        predicate,
        valuation: match ordering {
            Ordering::Less => Valuation::Below,
            Ordering::Equal => Valuation::At,
            Ordering::Greater => Valuation::Past,
        },
    });
    ordering
}

/// Record that `predicate` reached `valuation`: a predicate that is not a
/// comparison with a limit, such as the element a relocation moves.
pub fn reach<B: Budget + ?Sized>(budget: &mut B, predicate: Predicate, valuation: Valuation) {
    budget.boundary(Boundary {
        predicate,
        valuation,
    });
}

/// The position of element `index` among `count`: [`Valuation::First`],
/// [`Valuation::Middle`] or [`Valuation::Last`], a sole element first.
pub const fn position(index: usize, count: usize) -> Valuation {
    if index == 0 {
        Valuation::First
    } else if index + 1 >= count {
        Valuation::Last
    } else {
        Valuation::Middle
    }
}

/// How many units `count` is ([`Measure::units`]).
pub fn units<T: Measure>(count: T) -> Valuation {
    count.units()
}

/// The recording entry of the seam. `boundary!(a, P, value, limit)` compares
/// `value` with `limit` for predicate `P`, records the valuation and returns
/// the [`Ordering`] ([`compare`]); `boundary!(a, P => valuation)` records a
/// valuation reached ([`reach`]). Either way only `a`'s
/// [`Budget::boundary`] observes it.
macro_rules! boundary {
    ($budget:expr, $predicate:expr => $valuation:expr) => {
        $crate::bounded::boundary::reach(&mut *$budget, $predicate, $valuation)
    };
    ($budget:expr, $predicate:expr, $value:expr, $limit:expr $(,)?) => {
        $crate::bounded::boundary::compare(&mut *$budget, $predicate, $value, $limit)
    };
}
pub(crate) use boundary;

/// A limit of a predicate: every comparison with it records the valuation
/// reached. Its comparisons are its only form; [`Self::raw_limit`] gives the
/// limit for arithmetic, and the census refuses any comparison of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bound<T> {
    predicate: Predicate,
    limit: T,
}

impl<T: Measure> Bound<T> {
    pub const fn new(predicate: Predicate, limit: T) -> Self {
        Self { predicate, limit }
    }

    /// The predicate this limit belongs to.
    pub const fn predicate(self) -> Predicate {
        self.predicate
    }

    /// The limit, for arithmetic. Never compared outside this type.
    pub const fn raw_limit(self) -> T {
        self.limit
    }

    /// `value <= limit`.
    pub fn admits<B: Budget + ?Sized>(self, budget: &mut B, value: T) -> bool {
        compare(budget, self.predicate, value, self.limit).is_le()
    }

    /// `value > limit`.
    pub fn exceeded<B: Budget + ?Sized>(self, budget: &mut B, value: T) -> bool {
        compare(budget, self.predicate, value, self.limit).is_gt()
    }

    /// `value >= limit`.
    pub fn reached<B: Budget + ?Sized>(self, budget: &mut B, value: T) -> bool {
        compare(budget, self.predicate, value, self.limit).is_ge()
    }

    /// `value < limit`.
    pub fn below<B: Budget + ?Sized>(self, budget: &mut B, value: T) -> bool {
        compare(budget, self.predicate, value, self.limit).is_lt()
    }

    /// `value.min(limit)`.
    pub fn clamp<B: Budget + ?Sized>(self, budget: &mut B, value: T) -> T {
        if compare(budget, self.predicate, value, self.limit).is_gt() {
            self.limit
        } else {
            value
        }
    }
}

/// The valuations a run reached, one bit per [`Valuation`] for each
/// [`Predicate`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Reached {
    bits: [u64; Predicate::COUNT],
}

impl Reached {
    pub const fn new() -> Self {
        Self {
            bits: [0; Predicate::COUNT],
        }
    }

    /// The reached set whose bit masks, by predicate, are `bits`.
    pub const fn from_bits(bits: [u64; Predicate::COUNT]) -> Self {
        Self { bits }
    }

    pub fn insert(&mut self, boundary: Boundary) {
        self.bits[boundary.predicate.index()] |= 1u64 << boundary.valuation.index();
    }

    pub fn contains(&self, boundary: Boundary) -> bool {
        self.bits[boundary.predicate.index()] & (1u64 << boundary.valuation.index()) != 0
    }

    /// Every valuation either set reached.
    pub fn union(mut self, other: Self) -> Self {
        for (bits, more) in self.bits.iter_mut().zip(other.bits) {
            *bits |= more;
        }
        self
    }

    /// The valuations this set reached and `other` did not.
    pub fn missing_from(self, other: Self) -> impl Iterator<Item = Boundary> {
        self.boundaries()
            .filter(move |boundary| !other.contains(*boundary))
    }

    pub fn is_empty(&self) -> bool {
        self.bits.iter().all(|bits| *bits == 0)
    }

    /// Every reached boundary, by predicate then valuation.
    pub fn boundaries(self) -> impl Iterator<Item = Boundary> {
        Predicate::ALL.iter().flat_map(move |&predicate| {
            Valuation::ALL
                .iter()
                .map(move |&valuation| Boundary {
                    predicate,
                    valuation,
                })
                .filter(move |boundary| self.contains(*boundary))
        })
    }

    /// Every reached boundary as a record row: the predicate, a tab, the
    /// valuation.
    pub fn rows(self) -> impl Iterator<Item = alloc::string::String> {
        self.boundaries().map(row)
    }

    /// The boundary a row of [`Self::rows`] names.
    pub fn parse_row(row: &str) -> Option<Boundary> {
        let (predicate, valuation) = row.split_once('\t')?;
        Some(Boundary {
            predicate: Predicate::parse(predicate)?,
            valuation: Valuation::parse(valuation)?,
        })
    }
}

/// The record row of `boundary`.
pub fn row(boundary: Boundary) -> alloc::string::String {
    alloc::format!("{}\t{}", boundary.predicate, boundary.valuation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounded::Limits;

    /// A comparison through the seam returns exactly the comparison it
    /// replaces, for every value and limit around each edge, and records
    /// the zero and one of the value and its side of the limit.
    #[test]
    fn the_seam_returns_the_comparison_it_replaces_and_records_its_side() {
        for limit in 0u64..6 {
            for value in 0u64..8 {
                let mut a = Limits::unlimited();
                let bound = Bound::new(Predicate::ArenaLength, limit);
                assert_eq!(bound.admits(&mut a, value), value <= limit);
                assert_eq!(bound.exceeded(&mut a, value), value > limit);
                assert_eq!(bound.reached(&mut a, value), value >= limit);
                assert_eq!(bound.below(&mut a, value), value < limit);
                assert_eq!(bound.clamp(&mut a, value), value.min(limit));
                let reached = a.reached();
                let side = match value.cmp(&limit) {
                    Ordering::Less => Valuation::Below,
                    Ordering::Equal => Valuation::At,
                    Ordering::Greater => Valuation::Past,
                };
                let mut expected = Reached::new();
                expected.insert(Boundary {
                    predicate: Predicate::ArenaLength,
                    valuation: side,
                });
                if let Some(small) = value.small() {
                    expected.insert(Boundary {
                        predicate: Predicate::ArenaLength,
                        valuation: small,
                    });
                }
                assert_eq!(reached, expected, "value {value}, limit {limit}");
            }
        }
    }

    /// A policy that does not record makes the seam a plain comparison.
    #[test]
    fn a_policy_that_records_nothing_still_gets_the_comparison() {
        struct Silent;
        impl Budget for Silent {
            type Refusal = ();
            fn traverse(&mut self, _: u64, _: u64) -> Result<(), ()> {
                Ok(())
            }
        }
        let bound = Bound::new(Predicate::Quantum, 64u64);
        assert!(bound.admits(&mut Silent, 64));
        assert!(bound.exceeded(&mut Silent, 65));
        assert_eq!(
            boundary!(&mut Silent, Predicate::Quantum, 3u64, 2),
            Ordering::Greater
        );
    }

    /// Positions and unit counts name their valuations, a sole element
    /// first; rows round-trip through their parse, and every name parses
    /// to itself.
    #[test]
    fn positions_units_and_rows_name_their_valuations() {
        assert_eq!(position(0, 1), Valuation::First);
        assert_eq!(position(0, 3), Valuation::First);
        assert_eq!(position(1, 3), Valuation::Middle);
        assert_eq!(position(2, 3), Valuation::Last);
        assert_eq!(
            [
                units(0u64),
                units(1usize),
                units(2u8),
                units(3u32),
                units(257u16)
            ],
            [
                Valuation::Zero,
                Valuation::Single,
                Valuation::Pair,
                Valuation::Many,
                Valuation::Many
            ]
        );
        for &predicate in Predicate::ALL {
            assert_eq!(Predicate::parse(predicate.name()), Some(predicate));
        }
        for &valuation in Valuation::ALL {
            assert_eq!(Valuation::parse(valuation.name()), Some(valuation));
        }
        let mut reached = Reached::new();
        let first = Boundary {
            predicate: Predicate::Relocation,
            valuation: Valuation::First,
        };
        let pair = Boundary {
            predicate: Predicate::KeySpan,
            valuation: Valuation::Pair,
        };
        reached.insert(pair);
        reached.insert(first);
        let rows: alloc::vec::Vec<_> = reached.rows().collect();
        assert_eq!(rows, ["relocation\tfirst", "key-span\tpair"]);
        assert_eq!(
            rows.iter()
                .map(|row| Reached::parse_row(row))
                .collect::<alloc::vec::Vec<_>>(),
            [Some(first), Some(pair)]
        );
        assert_eq!(Reached::parse_row("relocation\tsideways"), None);
        assert_eq!(Reached::parse_row("relocation"), None);
    }

    /// A reached set missing a valuation the other reached names it, and a
    /// union holds both: the comparators' one operation.
    #[test]
    fn a_missing_valuation_is_named() {
        let at = Boundary {
            predicate: Predicate::DispatchDepth,
            valuation: Valuation::At,
        };
        let past = Boundary {
            predicate: Predicate::DispatchDepth,
            valuation: Valuation::Past,
        };
        let mut full = Reached::new();
        full.insert(at);
        full.insert(past);
        let mut minimal = Reached::new();
        minimal.insert(at);
        assert_eq!(
            full.missing_from(minimal).collect::<alloc::vec::Vec<_>>(),
            [past]
        );
        assert_eq!(minimal.missing_from(full).count(), 0);
        assert_eq!(minimal.union(full), full);
        assert!(Reached::new().is_empty() && !full.is_empty());
    }

    /// Shared and terminal policies record into the storage they share, so
    /// cleanup on another policy of the same storage is reached.
    #[test]
    fn shared_and_terminal_policies_record_into_one_set() {
        let mut a = Limits::unlimited();
        let permit = crate::bounded::Allocator::allocate(&mut a, 8).expect("unlimited");
        let mut shared = a.share();
        boundary!(&mut shared, Predicate::Relocation => Valuation::Middle);
        let mut terminal = <Limits as crate::bounded::TerminalAllocator>::terminal(&permit);
        boundary!(&mut terminal, Predicate::Relocation => Valuation::Last);
        let reached = a.reached();
        for valuation in [Valuation::Middle, Valuation::Last] {
            assert!(reached.contains(Boundary {
                predicate: Predicate::Relocation,
                valuation,
            }));
        }
        drop(permit);
    }
}
