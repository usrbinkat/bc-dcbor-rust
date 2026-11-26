use half::f16;

use super::*;
use crate::CBOR;

/// Refuses past `values` visited values; nothing else is limited.
pub(crate) fn limited(values: u64) -> Limits {
    Limits::new(values, u64::MAX, u64::MAX)
}

/// A deterministic generator of inputs for the attribution checks: symbolic
/// values of every major type, nested; texts from scalars that exercise
/// every normalization path (ordinary, combining marks in and out of order,
/// precomposed, Hangul, four-byte, singletons); and mutations of encodings,
/// a byte changed or the input cut short. One seed, one sequence, so a
/// failing input is reproduced by its position. Its users, the attribution
/// checks, are compiled under `std`.
#[cfg(feature = "std")]
pub(crate) struct Generator(u64);

#[cfg(feature = "std")]
impl Generator {
    pub(crate) const fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }

    /// A number below `bound`, which is not zero.
    pub(crate) fn below(&mut self, bound: u64) -> u64 {
        (self.next() >> 33) % bound
    }

    /// One of `items`, which is not empty.
    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len() as u64) as usize]
    }

    /// A text of at most `max` scalars.
    pub(crate) fn text(&mut self, max: u64) -> String {
        const POOLS: [&[char]; 6] = [
            &['a', 'e', 'q', 'x', 'A', '1', ' '],
            &[
                '\u{301}', '\u{316}', '\u{308}', '\u{327}', '\u{344}', '\u{30a}',
            ],
            &['\u{e9}', '\u{c5}', '\u{1e69}', '\u{3d3}'],
            &['\u{1100}', '\u{1161}', '\u{11a8}', '\u{ac00}'],
            &['\u{1f600}', '\u{10000}'],
            &['\u{37e}', '\u{212b}', '\u{2126}'],
        ];
        let len = self.below(max + 1);
        let mut text = String::new();
        for _ in 0..len {
            let pool = self.pick(&POOLS);
            text.push(self.pick(pool));
        }
        text
    }

    /// A value nested at most `depth` deep.
    pub(crate) fn value(&mut self, depth: usize) -> CBOR {
        const LEAVES: u64 = 7;
        let kinds = if depth == 0 { LEAVES } else { LEAVES + 3 };
        match self.below(kinds) {
            0 => {
                let shift = self.below(64);
                CBOR::from(self.next() >> shift)
            }
            1 => {
                let shift = 1 + self.below(63);
                CBOR::from(-1 - (self.next() >> shift) as i64)
            }
            2 => CBOR::from(f64::from_bits(self.next())),
            3 => CBOR::from(self.text(24)),
            4 => {
                let len = self.below(80);
                let bytes: Vec<u8> = (0..len).map(|_| self.next() as u8).collect();
                CBOR::to_byte_string(bytes)
            }
            5 => CBOR::from(self.below(2) == 0),
            6 => CBOR::null(),
            7 => {
                let len = self.below(6);
                let items: Vec<CBOR> = (0..len).map(|_| self.value(depth - 1)).collect();
                CBOR::from(items)
            }
            8 => {
                let mut map = crate::Map::new();
                for _ in 0..self.below(6) {
                    let key = self.value(0);
                    let value = self.value(depth - 1);
                    // Generated keys can repeat: a repeated key keeps the
                    // latest value, replaced explicitly. Symbolic keys and
                    // values encode infallibly, so the replacement cannot
                    // refuse.
                    map.insert_or_replace(key, value)
                        .expect("a symbolic key and value always encode");
                }
                CBOR::from(map)
            }
            _ => {
                let tag = crate::Tag::with_value(self.below(1000));
                CBOR::to_tagged_value(tag, self.value(depth - 1))
            }
        }
    }

    /// `bytes` with one byte changed, or cut short; empty bytes unchanged.
    pub(crate) fn mutated(&mut self, bytes: &[u8]) -> Vec<u8> {
        let mut mutated = bytes.to_vec();
        if mutated.is_empty() {
            return mutated;
        }
        let at = self.below(mutated.len() as u64) as usize;
        if self.below(2) == 0 {
            mutated[at] ^= 1 << self.below(8);
        } else {
            mutated.truncate(at);
        }
        mutated
    }
}

/// `value`'s encoding against the symbolic encoding `symbolic`, both ways a
/// plan is consumed: written into an output of exactly its length within
/// its predicted work and allocating nothing, and published in place. The
/// bytes are equal, both strictly decode to one value, and every
/// allocation is released once the encodings drop.
pub(crate) fn check<T: Schema + ?Sized>(value: &T, symbolic: &[u8]) -> Vec<u8> {
    let mut allocator = Limits::unlimited();
    let bytes = {
        let prepared = prepare(value, &mut allocator).expect("an unlimited preparation completes");
        let mut bytes = vec![0u8; prepared.len()];
        let mut written = Limits::unlimited();
        prepared
            .encode_into(&mut bytes, &mut written)
            .expect("an unlimited write completes");
        let predicted = prepared
            .write_work::<()>()
            .expect("the prediction fits in u64");
        let reported = written.used();
        assert!(
            predicted.covers(&reported),
            "the write reported {reported:?} beyond {predicted:?}"
        );
        assert_eq!(written.requested_bytes(), 0, "a write allocates nothing");
        let published = prepared
            .publish(&mut allocator)
            .expect("an unlimited publication completes");
        assert_eq!(
            published.as_ref(),
            bytes,
            "publication in place writes the same bytes"
        );
        bytes
    };
    assert_eq!(allocator.live_bytes(), 0, "every allocation is released");
    assert_eq!(bytes, symbolic, "the bounded bytes are the symbolic bytes");
    assert_eq!(
        CBOR::try_from_data(&bytes).unwrap(),
        CBOR::try_from_data(symbolic).unwrap(),
        "both decode strictly to one value"
    );
    bytes
}

/// Integer heads at every width, by fixed bytes.
#[test]
fn integer_heads_have_their_fixed_bytes() {
    let fixtures: [(i64, &[u8]); 12] = [
        (0, &[0x00]),
        (23, &[0x17]),
        (24, &[0x18, 0x18]),
        (255, &[0x18, 0xff]),
        (256, &[0x19, 0x01, 0x00]),
        (65_536, &[0x1a, 0x00, 0x01, 0x00, 0x00]),
        (4_294_967_296, &[0x1b, 0, 0, 0, 1, 0, 0, 0, 0]),
        (-1, &[0x20]),
        (-24, &[0x37]),
        (-25, &[0x38, 0x18]),
        (-257, &[0x39, 0x01, 0x00]),
        (
            i64::MIN,
            &[0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        ),
    ];
    for (value, expected) in fixtures {
        assert_eq!(check(&value, expected), expected, "{value}");
    }
}

#[test]
fn integers_match_the_symbolic_encoding_at_every_width() {
    let signed = [
        i64::MIN,
        i64::MIN + 1,
        -4_294_967_297,
        -4_294_967_296,
        -65_537,
        -65_536,
        -257,
        -256,
        -25,
        -24,
        -1,
        0,
        23,
        24,
        255,
        256,
        65_535,
        65_536,
        4_294_967_295,
        4_294_967_296,
        i64::MAX,
    ];
    for value in signed {
        check(&value, &CBOR::from(value).to_cbor_data());
    }
    for value in [0u64, 23, 24, u32::MAX as u64, u64::MAX] {
        check(&value, &CBOR::from(value).to_cbor_data());
    }
    check(&u8::MAX, &CBOR::from(u8::MAX).to_cbor_data());
    check(&i8::MIN, &CBOR::from(i8::MIN).to_cbor_data());
}

/// Every half-precision pattern, and a spread of single and double
/// patterns, encode on the bounded path as on the symbolic one. This is
/// supplementary consistency evidence; numeric_profile.rs holds independent
/// specification vectors and value-preservation checks.
#[test]
fn floats_match_the_symbolic_encoding() {
    for bits in 0..=u16::MAX {
        let value = f16::from_bits(bits);
        check(&value, &CBOR::from(value).to_cbor_data());
    }
    let mut state = 0x2545_f491_4f6c_dd1du64;
    for _ in 0..50_000 {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let single = f32::from_bits((state >> 32) as u32);
        check(&single, &CBOR::from(single).to_cbor_data());
        let double = f64::from_bits(state);
        check(&double, &CBOR::from(double).to_cbor_data());
    }
    for value in [
        0.0f64,
        -0.0,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NAN,
        1.1,
    ] {
        check(&value, &CBOR::from(value).to_cbor_data());
    }
    assert_eq!(
        check(&f16::from_bits(0x0001), &[0xf9, 0x00, 0x01]),
        [0xf9, 0x00, 0x01]
    );
}

/// Byte strings and arrays of integers stay distinct representations.
#[test]
fn byte_strings_booleans_and_arrays_match_the_symbolic_encoding() {
    for length in [0usize, 1, 23, 24, 255, 256, 70_000] {
        let bytes = ByteString::new(vec![0xa5; length]);
        check(&bytes, &CBOR::from(bytes.clone()).to_cbor_data());
    }
    check(&true, &CBOR::from(true).to_cbor_data());
    check(&false, &CBOR::from(false).to_cbor_data());
    let numbers: Vec<u64> = (0..30).map(|n| n * 1000).collect();
    check(&numbers, &CBOR::from(numbers.clone()).to_cbor_data());
    let array = [7u8, 200, 255];
    assert_eq!(
        check(&array, &CBOR::from(array).to_cbor_data()),
        [0x83, 0x07, 0x18, 0xc8, 0x18, 0xff],
        "an array of bytes is an array of integers"
    );
    check(&array[..], &CBOR::from(&array[..]).to_cbor_data());
    let boxed: Box<Vec<u64>> = Box::new(numbers.clone());
    check(&boxed, &CBOR::from(numbers.clone()).to_cbor_data());
    let empty: Vec<u8> = Vec::new();
    check(&empty, &CBOR::from(empty.clone()).to_cbor_data());
}

/// A wrong-sized output is refused before anything is written, a larger
/// one and a smaller one alike.
#[test]
fn the_output_refuses_wrong_sizes() {
    let prepared = prepare(&1u64, &mut Limits::unlimited()).unwrap();
    for size in [0usize, 3] {
        let mut bytes = vec![0xeeu8; size];
        assert_eq!(
            prepared.encode_into(&mut bytes, &mut Limits::unlimited()),
            Err(BoundedError::OutputSize {
                measured: 1,
                provided: size as u64
            })
        );
        assert!(
            bytes.iter().all(|&byte| byte == 0xee),
            "nothing was written"
        );
    }
}

/// A source whose counted head disagrees with the fields it visits is
/// refused when its map ends, never published with a wrong count, in
/// either direction.
#[test]
fn a_miscounted_map_is_refused_at_its_end() {
    struct Miscounted(u64);
    impl Schema for Miscounted {
        fn instruction(&self, index: usize) -> encoding::Instruction<'_> {
            match index {
                0 => encoding::Instruction::CountedMap(self.0),
                1 => encoding::Instruction::Field(0, Some(&true)),
                _ => encoding::Instruction::End,
            }
        }
    }
    for count in [0, 2] {
        let mut limits = Limits::unlimited();
        assert_eq!(
            encode(&Miscounted(count), &mut limits).map(|encoded| encoded.as_ref().to_vec()),
            Err(BoundedError::PlanMismatch),
            "a head of {count} over one field"
        );
        assert_eq!(
            limits.live_bytes(),
            0,
            "the refused plan's storage is released"
        );
    }
    check(&Miscounted(1), &[0xa1, 0x00, 0xf5]);
}

/// A refusing budget stops the preparation before the value is visited,
/// and its refusal comes back as itself.
#[test]
fn a_refusal_is_returned_as_the_budget_gave_it() {
    assert_eq!(
        prepare(&42u64, &mut limited(0)).map(|prepared| prepared.len()),
        Err(BoundedError::Refused(LimitRefusal::Work))
    );
}

/// A value prepared under one policy is written under another, which admits
/// the output's release, grants its storage, exactly the encoding's length,
/// once, and admits its initialization and its write. The permit lives with
/// the bytes and is released with them. A refused write publishes nothing
/// and holds nothing; a refused storage request has admitted only the
/// release, forfeited, and holds nothing.
#[test]
fn an_owned_encoding_is_written_under_its_own_policy() {
    // The release of the published record, an `Encoded` of a reservation:
    // one value and its bytes.
    let release = WriteWork::new(1, core::mem::size_of::<Encoded<Reservation>>() as u64);
    let mut preparing = Limits::unlimited();
    let prepared = prepare(&24u64, &mut preparing).unwrap();
    let mut writing = Limits::unlimited();
    let encoded = prepared.encode_owned(&mut writing).unwrap();
    assert_eq!(encoded.as_ref(), [0x18, 0x18]);
    assert_eq!(
        writing.used(),
        WriteWork::new(release.values + 2, release.bytes + 4),
        "the release, the initialization of both bytes, then their one segment and the \
         completion"
    );
    assert_eq!(
        (writing.requests(), writing.requested_bytes()),
        (1, 2),
        "the output's storage, requested once at exactly its length"
    );
    assert_eq!(writing.live_bytes(), 2, "the permit lives with the bytes");
    drop(encoded);
    assert_eq!(writing.live_bytes(), 0, "and is released with them");

    // One value admits the release, none the initialization; the write's
    // first segment is refused.
    let mut refusing = limited(1);
    assert_eq!(
        prepared
            .encode_owned(&mut refusing)
            .map(|encoded| encoded.as_ref().to_vec()),
        Err(BoundedError::Refused(LimitRefusal::Work))
    );
    assert_eq!(refusing.requests(), 1, "the storage was granted first");
    assert_eq!(refusing.live_bytes(), 0, "a refused write releases it");

    // The output's two bytes exceed the whole one-byte live ceiling.
    let mut no_storage = Limits::new(u64::MAX, u64::MAX, 1);
    assert_eq!(
        prepared
            .encode_owned(&mut no_storage)
            .map(|encoded| encoded.as_ref().to_vec()),
        Err(BoundedError::Refused(LimitRefusal::TooLarge))
    );
    assert_eq!(
        (no_storage.used(), no_storage.live_bytes()),
        (release, 0),
        "a refused request has admitted only its release, and holds nothing"
    );
}

/// The growth bound is exactly what an `Owned` reports and holds: element
/// by element and in one reservation, for elements of several sizes and
/// every count across several doublings.
#[test]
fn owned_growth_is_exact() {
    fn measured<T: Default>(elements: usize, one_at_a_time: bool) -> Growth {
        let mut limits = Limits::unlimited();
        // The vector's custody, made once: every growth its acquisition.
        let owner = limits.owner().expect("an ordinary policy's owner");
        let mut owned = Owned::<T, Reservation>::new();
        if one_at_a_time {
            for _ in 0..elements {
                owned.push(T::default(), &mut limits, &owner).unwrap();
            }
        } else {
            owned.reserve(elements, &mut limits, &owner).unwrap();
        }
        let growth = Growth {
            allocations: limits.requests() as u64,
            // Growth.copied measures relocation alone. Acquisition also
            // prepays one release per request, charged separately.
            copied: limits.used().bytes
                - limits.requests() as u64 * Owned::<T, Reservation>::RELEASE_BYTES,
            allocated: limits.requested_bytes(),
            held: limits.live_bytes(),
            peak: limits.peak_bytes(),
        };
        drop(owned);
        assert_eq!(limits.live_bytes(), 0);
        growth
    }
    for elements in 0..=300usize {
        let count = elements as u64;
        let one = owned_growth::<()>(count, 1).unwrap();
        let wide = owned_growth::<()>(count, 24).unwrap();
        assert_eq!(measured::<u8>(elements, true), one, "{elements} bytes");
        assert_eq!(
            measured::<[u8; 24]>(elements, true),
            wide,
            "{elements} wide"
        );
        let reserved = measured::<[u8; 24]>(elements, false);
        assert_eq!(
            (reserved.allocated, reserved.held, reserved.peak),
            (wide.allocated, wide.held, wide.peak),
            "{elements} reserved at once"
        );
        assert_eq!(reserved.copied, 0, "an empty buffer relocates nothing");
        assert!(reserved.copied <= wide.copied);
    }
    assert_eq!(owned_growth::<()>(u64::MAX, 2), Err(BoundedError::Overflow));
}

/// The growth rule: four from empty, otherwise double, none past `u64`; its
/// `usize` form refused [`BoundedError::Overflow`] where the rule gives none.
#[test]
fn the_growth_rule_is_four_from_empty_then_double() {
    assert_eq!(grown_capacity(0), Some(4));
    assert_eq!(grown_capacity(4), Some(8));
    assert_eq!(grown_capacity(1 << 62), Some(1 << 63));
    assert_eq!(grown_capacity((1 << 63) + 1), None);
    assert_eq!(grown::<()>(0), Ok(4));
    assert_eq!(grown::<()>(4), Ok(8));
    assert_eq!(grown::<()>(usize::MAX), Err(BoundedError::Overflow));
}

/// An `Owned` pushed one element at a time grows through exactly the
/// capacities the growth rule steps through, the sequence [`owned_growth`]
/// counts: each distinct capacity it takes, in order, is the rule's next,
/// and there are as many as `owned_growth` counts allocations, the last the
/// one it holds.
#[test]
fn an_owned_grows_through_the_rules_capacities() {
    const ELEMENTS: u64 = 1000;
    let mut limits = Limits::unlimited();
    let owner = limits.owner().expect("an ordinary policy's owner");
    let mut owned = Owned::<u8, Reservation>::new();
    let mut observed = Vec::new();
    for element in 0..=ELEMENTS {
        owned.push(element as u8, &mut limits, &owner).unwrap();
        if observed.last() != Some(&owned.capacity) {
            observed.push(owned.capacity);
        }
    }
    let mut expected = Vec::new();
    let mut capacity = 0u64;
    while capacity < ELEMENTS + 1 {
        capacity = grown_capacity(capacity).unwrap();
        expected.push(usize::try_from(capacity).unwrap());
    }
    assert_eq!(observed, expected);
    let growth = owned_growth::<()>(ELEMENTS + 1, 1).unwrap();
    assert_eq!(growth.allocations, expected.len() as u64);
    assert_eq!(growth.held, capacity);
    drop(owned);
    assert_eq!(limits.live_bytes(), 0);
}

/// An `Owned` released through [`Owned::release`] drops its elements before
/// it releases its permit: each element records its drop, and the permit
/// refuses to drop before one has. This observes element order only, not the
/// buffer's deallocation; a plain drop's physical order, the buffer freed
/// before the permit, is witnessed by the heap observer
/// (`tests/resumable/native_heap.rs`,
/// `a_dropped_owned_frees_its_buffer_before_releasing_its_permit`), which
/// cannot reach this crate-private path. Reordering the fields so the permit drops first fails this test.
#[test]
fn a_released_owned_drops_its_elements_before_its_permit() {
    use core::cell::Cell;
    struct Marker<'f>(&'f Cell<bool>);
    impl Drop for Marker<'_> {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }
    struct Permit<'f>(&'f Cell<bool>);
    impl Drop for Permit<'_> {
        fn drop(&mut self) {
            assert!(
                self.0.get(),
                "the permit was released before any element was dropped"
            );
        }
    }
    fn owned(freed: &Cell<bool>) -> Owned<Marker<'_>, Permit<'_>> {
        Owned {
            items: Vec::from([Marker(freed), Marker(freed)]),
            capacity: 2,
            permit: Some(Permit(freed)),
        }
    }
    let dropped = Cell::new(false);
    let mut released = owned(&dropped);
    assert!(released.release(), "it held an allocation");
    assert!(dropped.get(), "release dropped the elements");
    assert!(!released.holds(), "and holds nothing after");
}

#[test]
fn work_composition_is_checked() {
    for most in [WriteWork::new(u64::MAX, 0), WriteWork::new(0, u64::MAX)] {
        assert_eq!(most.checked_then(WriteWork::new(1, 1)), None);
        assert_eq!(most.checked_times(2), None);
        assert_eq!(most.checked_times(1), Some(most));
        assert_eq!(most.checked_times(0), Some(WriteWork::default()));
    }
    assert_eq!(
        WriteWork::new(1, 2).checked_then(WriteWork::new(3, 4)),
        Some(WriteWork::new(4, 6))
    );
    assert_eq!(
        prepare(&[0u8; 0], &mut Limits::unlimited()).map(|p| p.len()),
        Ok(1)
    );
}

/// A [`Places`] bound composes its additive quantities and its peak apart:
/// a bound whose places hold storage at different times reports the peak
/// its own composition gives, and neither a sum of peaks it never reports
/// nor work it does not compose into the peak refuses it.
mod places_composition {
    use super::*;

    places! {
        enum Two { First, Second }
    }

    /// Every quantity of every place summed, the peaks with them: the fold
    /// the planted controls use, refusing wherever any sum does not fit.
    fn summed<T: Places>(terms: &T) -> Result<ResourceBound, BoundedError<()>> {
        T::Place::ALL
            .iter()
            .try_fold(ResourceBound::default(), |total, &place| {
                total.checked_add(terms.term(place))
            })
            .ok_or(BoundedError::Overflow)
    }

    /// Two places of one term each, held one after the other: the peak is
    /// the larger of theirs, an override of the default.
    struct Sequential(ResourceBound);

    impl Places for Sequential {
        type Place = Two;

        fn term(&self, _: Two) -> ResourceBound {
            self.0
        }

        fn peak<R>(&self) -> Result<u64, BoundedError<R>> {
            Ok(Two::ALL
                .iter()
                .map(|&place| self.term(place).peak)
                .max()
                .unwrap_or(0))
        }
    }

    /// Two places of one term each, held at once: every default of
    /// [`Places`] inherited, only the terms given.
    struct Concurrent(ResourceBound);

    impl Places for Concurrent {
        type Place = Two;

        fn term(&self, _: Two) -> ResourceBound {
            self.0
        }
    }

    /// A term of `values` values, one byte, and a peak of `peak`.
    fn term(values: u64, peak: u64) -> ResourceBound {
        ResourceBound {
            values,
            bytes: 1,
            allocated: 0,
            peak,
            retained: 0,
        }
    }

    /// The witness: two sequential places, each peaking at `u64::MAX`, are
    /// one bound of that peak and their work summed; work that does not fit
    /// still refuses it.
    #[test]
    fn a_sequential_peak_at_u64_max_is_a_bound() {
        assert_eq!(
            Sequential(term(1, u64::MAX)).bound::<()>(),
            Ok(ResourceBound {
                values: 2,
                bytes: 2,
                allocated: 0,
                peak: u64::MAX,
                retained: 0,
            })
        );
        assert_eq!(
            Sequential(term(u64::MAX, u64::MAX)).bound::<()>(),
            Err(BoundedError::Overflow)
        );
    }

    /// The default peak, inherited: peaks that do not fit refuse it, and
    /// work that does not fit does not, its peaks fitting; the bound then
    /// refuses over the work.
    #[test]
    fn the_default_peak_refuses_only_peaks_that_do_not_fit() {
        assert_eq!(
            Concurrent(term(1, u64::MAX)).peak::<()>(),
            Err(BoundedError::Overflow)
        );
        let work = Concurrent(term(u64::MAX, 3));
        assert_eq!(work.peak::<()>(), Ok(6));
        assert_eq!(work.bound::<()>(), Err(BoundedError::Overflow));
    }

    /// The planted controls, each the old form as a local fold: the bound
    /// that summed every quantity, peaks included, before taking its own
    /// peak refuses the sequential witness; and the default peak taken from
    /// that sum refuses work that overflows beside peaks that fit.
    #[test]
    fn folds_summing_what_they_do_not_report_refuse_valid_bounds() {
        let witness = Sequential(term(1, u64::MAX));
        let old_bound = summed(&witness).and_then(|all| {
            Ok(ResourceBound {
                peak: witness.peak()?,
                ..all
            })
        });
        assert_eq!(old_bound, Err(BoundedError::Overflow));
        assert!(witness.bound::<()>().is_ok());
        let work = Concurrent(term(u64::MAX, 3));
        assert_eq!(
            summed(&work).map(|all| all.peak),
            Err(BoundedError::Overflow)
        );
        assert_eq!(work.peak::<()>(), Ok(6));
    }
}

/// The composition algebra of [`ResourceBound`], witnessed by an executable
/// model until 29.58 item 4's proofs exist. A bound is realized as an event
/// trace: acquire its peak, release all but what it retains, admit its work,
/// request its allocated bytes, ending holding what it retains. Each
/// combinator composes traces by its meaning, and a simulator reads the
/// peak, retained, work and allocated quantities off a trace: every
/// combinator's result must equal the most its traces reach, for every pair
/// of bounds whose quantities each range over `0..=3`, and every count in
/// `0..=3` for the repetitions.
mod composition {
    use super::*;

    /// One event of a run.
    #[derive(Clone, Copy, Debug)]
    enum Event {
        /// Bytes taken and held.
        Acquire(u64),
        /// Held bytes given back.
        Release(u64),
        /// Work admitted.
        Work(u64, u64),
        /// An allocation requested.
        Request(u64),
    }

    /// One run of an operation, as the events it makes.
    type Trace = Vec<Event>;

    /// What a trace reaches: its work, its requests, the most it holds at
    /// once, and what it holds at its end.
    fn simulate(trace: &[Event]) -> ResourceBound {
        let (mut held, mut most) = (0u64, 0u64);
        let mut reached = ResourceBound::default();
        for event in trace {
            match *event {
                Event::Acquire(bytes) => {
                    held += bytes;
                    most = most.max(held);
                }
                Event::Release(bytes) => held -= bytes,
                Event::Work(values, bytes) => {
                    reached.values += values;
                    reached.bytes += bytes;
                }
                Event::Request(bytes) => reached.allocated += bytes,
            }
        }
        reached.peak = most;
        reached.retained = held;
        reached
    }

    /// The most of each quantity over `traces`: the oracle's own maximum,
    /// never a combinator under test.
    fn most_of(traces: &[Trace]) -> ResourceBound {
        let mut most = ResourceBound::default();
        for trace in traces {
            let reached = simulate(trace);
            most.values = most.values.max(reached.values);
            most.bytes = most.bytes.max(reached.bytes);
            most.allocated = most.allocated.max(reached.allocated);
            most.peak = most.peak.max(reached.peak);
            most.retained = most.retained.max(reached.retained);
        }
        most
    }

    /// The holding part of `bound`'s run: its peak acquired, then all but
    /// what it retains released.
    fn holding(bound: ResourceBound) -> Trace {
        vec![
            Event::Acquire(bound.peak),
            Event::Release(bound.peak - bound.retained),
        ]
    }

    /// The counted part of `bound`'s run: its work and its requests.
    fn counted(bound: ResourceBound) -> Trace {
        vec![
            Event::Work(bound.values, bound.bytes),
            Event::Request(bound.allocated),
        ]
    }

    /// `bound` realized as one run.
    fn run(bound: ResourceBound) -> Trace {
        let mut trace = holding(bound);
        trace.extend(counted(bound));
        trace
    }

    /// `first`'s run, then `next`'s, `first`'s output held.
    fn then(first: &Trace, next: &Trace) -> Trace {
        first.iter().chain(next).copied().collect()
    }

    /// `first`'s run, its output released, then `next`'s.
    fn followed_by(first: &Trace, retained: u64, next: &Trace) -> Trace {
        let mut trace = first.clone();
        trace.push(Event::Release(retained));
        trace.extend(next);
        trace
    }

    /// Every interleaving of the two runs' holding events, each followed by
    /// both runs' counted events, which no order changes.
    fn concurrent(a: ResourceBound, b: ResourceBound) -> Vec<Trace> {
        fn interleavings(left: &[Event], right: &[Event]) -> Vec<Trace> {
            match (left.split_first(), right.split_first()) {
                (None, _) => vec![right.to_vec()],
                (_, None) => vec![left.to_vec()],
                (Some((l, left_rest)), Some((r, right_rest))) => {
                    let mut all = Vec::new();
                    for mut rest in interleavings(left_rest, right) {
                        rest.insert(0, *l);
                        all.push(rest);
                    }
                    for mut rest in interleavings(left, right_rest) {
                        rest.insert(0, *r);
                        all.push(rest);
                    }
                    all
                }
            }
        }
        interleavings(&holding(a), &holding(b))
            .into_iter()
            .map(|mut trace| {
                trace.extend(counted(a));
                trace.extend(counted(b));
                trace
            })
            .collect()
    }

    /// `count` runs of `bound`, each one's output released before the next
    /// (`retained`) or kept.
    fn repeated(bound: ResourceBound, count: u64, released: bool) -> Trace {
        let mut trace = Trace::new();
        for at in 0..count {
            if released && at > 0 {
                trace.push(Event::Release(bound.retained));
            }
            trace.extend(run(bound));
        }
        trace
    }

    /// Every bound whose quantities each range over `0..=3`, what it retains
    /// within its peak (a peak counts what its operation retains).
    fn bounds() -> Vec<ResourceBound> {
        let mut all = Vec::new();
        for values in 0..=3 {
            for bytes in 0..=3 {
                for allocated in 0..=3 {
                    for peak in 0..=3 {
                        for retained in 0..=peak {
                            all.push(ResourceBound {
                                values,
                                bytes,
                                allocated,
                                peak,
                                retained,
                            });
                        }
                    }
                }
            }
        }
        all
    }

    /// Every combinator of two bounds equals the most its traces reach, for
    /// every pair of bounds.
    #[test]
    fn every_pairwise_combinator_is_the_most_its_traces_reach() {
        let all = bounds();
        for &a in &all {
            let ra = run(a);
            for &b in &all {
                let rb = run(b);
                let pair = format!("{a:?} with {b:?}");
                assert_eq!(
                    a.checked_then(b),
                    Some(most_of(&[then(&ra, &rb)])),
                    "then, {pair}"
                );
                assert_eq!(
                    a.checked_followed_by(b),
                    Some(most_of(&[followed_by(&ra, a.retained, &rb)])),
                    "followed_by, {pair}"
                );
                assert_eq!(
                    a.checked_add(b),
                    Some(most_of(&concurrent(a, b))),
                    "concurrent, {pair}"
                );
                assert_eq!(
                    a.larger(b),
                    most_of(&[ra.clone(), rb]),
                    "alternative, {pair}"
                );
            }
        }
    }

    /// Both repetitions equal the most their traces reach, for every bound
    /// and every count in `0..=3`; the concurrent repetition is `count`
    /// concurrent copies.
    #[test]
    fn every_repetition_is_the_most_its_traces_reach() {
        for bound in bounds() {
            for count in 0..=3u64 {
                let at = format!("{bound:?} {count} times");
                assert_eq!(
                    bound.checked_repeated(count),
                    Some(most_of(&[repeated(bound, count, true)])),
                    "repeated, {at}"
                );
                assert_eq!(
                    bound.checked_repeated_retained(count),
                    Some(most_of(&[repeated(bound, count, false)])),
                    "repeated_retained, {at}"
                );
                let mut copies = ResourceBound::default();
                for _ in 0..count {
                    copies = copies.checked_add(bound).expect("small bounds fit");
                }
                assert_eq!(bound.checked_mul(count), Some(copies), "copies, {at}");
            }
        }
    }

    /// The planted control: `then` with the peak `max(P_a, P_b)`, forgetting
    /// that the first's output is held beside the second's peak, disagrees
    /// with the simulator for some pair, so the oracle tells it apart.
    #[test]
    fn a_then_forgetting_the_held_output_is_refused_by_the_simulator() {
        fn wrong_then(a: ResourceBound, b: ResourceBound) -> ResourceBound {
            ResourceBound {
                values: a.values + b.values,
                bytes: a.bytes + b.bytes,
                allocated: a.allocated + b.allocated,
                peak: a.peak.max(b.peak),
                retained: a.retained + b.retained,
            }
        }
        let all = bounds();
        let refused = all.iter().any(|&a| {
            all.iter()
                .any(|&b| wrong_then(a, b) != most_of(&[then(&run(a), &run(b))]))
        });
        assert!(
            refused,
            "the simulator accepted a then without the held output"
        );
    }

    /// Each combinator refuses, never wraps, wherever its algebra adds or
    /// multiplies a quantity at `u64::MAX`; where it only takes a maximum or
    /// keeps a quantity, `u64::MAX` composes.
    #[test]
    fn every_combinator_refuses_a_quantity_beyond_u64() {
        const MAX: u64 = u64::MAX;
        let one = ResourceBound {
            values: 1,
            bytes: 1,
            allocated: 1,
            peak: 1,
            retained: 1,
        };
        let only = |set: fn(&mut ResourceBound)| {
            let mut bound = ResourceBound::default();
            set(&mut bound);
            bound
        };
        let work: [fn(&mut ResourceBound); 3] =
            [|b| b.values = MAX, |b| b.bytes = MAX, |b| b.allocated = MAX];
        for set in work {
            let most = only(set);
            assert_eq!(most.checked_then(one), None, "then {most:?}");
            assert_eq!(most.checked_followed_by(one), None, "followed_by {most:?}");
            assert_eq!(most.checked_add(one), None, "concurrent {most:?}");
            assert_eq!(most.checked_repeated(2), None, "repeated {most:?}");
            assert_eq!(most.checked_repeated_retained(2), None, "retained {most:?}");
            assert_eq!(most.checked_mul(2), None, "copies {most:?}");
            let mut either = one;
            set(&mut either);
            assert_eq!(most.larger(one), either, "alternative {most:?}");
        }
        // A whole retained output: held beside the next one's peak and kept
        // with its output by `then`, kept by every repetition that holds it.
        let held = ResourceBound {
            peak: MAX,
            retained: MAX,
            ..ResourceBound::default()
        };
        assert_eq!(held.checked_then(one), None, "then, the held output");
        assert_eq!(held.checked_add(one), None, "concurrent, the held output");
        assert_eq!(held.checked_repeated_retained(2), None, "retained twice");
        assert_eq!(held.checked_mul(2), None, "two concurrent copies");
        // Only the larger peak, or the last output, is taken: never summed.
        assert_eq!(
            held.checked_followed_by(one),
            Some(ResourceBound {
                peak: MAX,
                retained: 1,
                ..one
            })
        );
        assert_eq!(held.checked_repeated(2), Some(held));
        // `(n - 1) R + P` past `u64::MAX` through the peak alone.
        let peaked = ResourceBound {
            peak: MAX,
            retained: 1,
            ..ResourceBound::default()
        };
        assert_eq!(peaked.checked_repeated_retained(1), Some(peaked));
        assert_eq!(peaked.checked_repeated_retained(2), None, "R + P past u64");
        assert_eq!(
            peaked.checked_repeated_retained(0),
            Some(ResourceBound::default())
        );
        assert_eq!(
            held.larger(one),
            ResourceBound {
                peak: MAX,
                retained: MAX,
                ..one
            }
        );
    }
}

/// A bignum's encoding is the symbolic conversion's (`num_bigint.rs`), for
/// both signs, at zero and minus one, at every digit boundary where the
/// borrow of a negative magnitude crosses digits, and over generated
/// magnitudes of many digits: read from its digits a quantum at a time.
#[cfg(feature = "num-bigint")]
#[test]
fn bignums_match_the_symbolic_encoding() {
    use num_bigint::{BigInt, BigUint, Sign};
    let mut magnitudes = vec![
        BigUint::ZERO,
        BigUint::from(1u8),
        BigUint::from(255u8),
        BigUint::from(256u16),
        BigUint::from(u64::MAX),
        BigUint::from(1u128 << 64),
        (BigUint::from(1u128 << 64) << 64usize) - 1u8,
        BigUint::from(1u8) << 512usize,
    ];
    let mut state = 0x2545_f491_4f6c_dd1du64;
    for digits in [1usize, 7, 8, 9, 16, 17, 40] {
        let mut limbs = Vec::with_capacity(digits * 2);
        for _ in 0..digits * 2 {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            limbs.push((state >> 32) as u32);
        }
        magnitudes.push(BigUint::new(limbs));
    }
    for magnitude in magnitudes {
        check(&magnitude, &CBOR::from(magnitude.clone()).to_cbor_data());
        let positive = BigInt::from_biguint(Sign::Plus, magnitude.clone());
        check(&positive, &CBOR::from(positive.clone()).to_cbor_data());
        if magnitude != BigUint::ZERO {
            let negative = BigInt::from_biguint(Sign::Minus, magnitude);
            check(&negative, &CBOR::from(negative.clone()).to_cbor_data());
        }
    }
}

/// A tree keyed by its entries' encoded keys yields them in canonical
/// order: the order the engine checks in place of sorting is the sorted
/// order of the encoded keys, for keys of every major type and length.
#[test]
fn a_maps_iteration_order_is_its_encoded_key_order() {
    let mut map = crate::Map::new();
    for key in [
        CBOR::from(10u64),
        CBOR::from(-1i64),
        CBOR::from("z"),
        CBOR::from("aa"),
        CBOR::from(vec![1u64, 2]),
        CBOR::from(100_000u64),
        CBOR::from(false),
    ] {
        map.insert(key, 0u64).unwrap();
    }
    let iterated: Vec<Vec<u8>> = map.iter().map(|(key, _)| key.to_cbor_data()).collect();
    let mut sorted = iterated.clone();
    sorted.sort();
    assert_eq!(iterated, sorted);
    check(&map, &CBOR::from(map.clone()).to_cbor_data());
}

/// A standard tree's entries take canonical key order, not the tree's own:
/// Rust orders the text keys `"aa"` before `"z"`, their encodings the other
/// way round (`0x617a` before `0x626161`). The tree is walked by its stepped
/// cursor on the bounded-collection standard library and by its standard
/// iterator elsewhere, and the encoding is the symbolic conversion's.
#[test]
fn a_trees_entries_take_canonical_key_order_not_tree_order() {
    let mut tree = BTreeMap::new();
    tree.insert(String::from("aa"), 1u64);
    tree.insert(String::from("z"), 2u64);
    // Distinct `String`s can collide: text encodes in NFC, so "\u{e9}" and
    // "e\u{301}" are one key. These two keys are ASCII, which NFC leaves
    // unchanged, and differ, so their encodings differ and the encoding
    // cannot refuse.
    let symbolic = crate::CBOREncodable::encode_cbor(&tree)
        .expect("distinct ASCII keys are distinct CBOR keys");
    assert_eq!(
        check(&tree, &symbolic.to_cbor_data()),
        [0xa2, 0x61, b'z', 0x02, 0x62, b'a', b'a', 0x01]
    );
}

/// The stable walk of a tree, its whole range created and stepped, compares
/// no keys at any height from a single leaf to several levels, and yields
/// every entry once: its cost is its node moves alone, which
/// [`encoding::tree_moves`] bounds from the standard library's node
/// capacity and minimum fill (`B = 6`, `MIN_LEN = 5`). The height bound
/// steps exactly at the fewest entries each height holds.
#[cfg(feature = "std")]
#[test]
fn a_tree_iterators_steps_compare_no_keys() {
    use core::cell::Cell;
    use core::cmp::Ordering;
    std::thread_local! {
        static COMPARISONS: Cell<u64> = const { Cell::new(0) };
    }
    #[derive(PartialEq, Eq)]
    struct Counted(u64);
    impl PartialOrd for Counted {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.cmp(other))
        }
    }
    impl Ord for Counted {
        fn cmp(&self, other: &Self) -> Ordering {
            COMPARISONS.with(|count| count.set(count.get() + 1));
            self.0.cmp(&other.0)
        }
    }
    for len in [0u64, 1, 11, 12, 71, 72, 1_000, 20_000] {
        let tree: BTreeMap<Counted, ()> = (0..len).map(|key| (Counted(key), ())).collect();
        COMPARISONS.with(|count| count.set(0));
        let mut range = tree.range::<Counted, _>(..);
        let mut yielded = 0;
        while range.next().is_some() {
            yielded += 1;
        }
        assert_eq!(yielded, len);
        assert_eq!(COMPARISONS.with(Cell::get), 0, "{len} entries");
        assert!(encoding::tree_height(len as usize) >= 1);
    }
    // The least entries of `h` levels, `2 * 6^(h - 1) - 1`, is where the
    // height bound steps.
    assert_eq!(encoding::tree_height(10), 1);
    assert_eq!(encoding::tree_height(11), 2);
    assert_eq!(encoding::tree_height(70), 2);
    assert_eq!(encoding::tree_height(71), 3);
    assert_eq!(encoding::tree_moves(71), 6);
}

/// The charge rules every admission goes through, their errors' text, and
/// the storage primitives beside them, with exact values: what each rule
/// reports as a bound and what it admits through a real policy. Light enough
/// to run under Miri (`tests/miri-suites.txt`), where the float and integer
/// sweeps above are not.
///
/// Every rule is built with `let`, at run time: in a constant its
/// constructor would run only in the compiler, where neither the reach map's
/// coverage nor Miri's interpretation of the test sees it.
mod charge_rules {
    use super::*;

    #[test]
    fn a_unit_admits_exactly_its_values_and_bytes() {
        let unit = Unit::new(Caller, 2, 9);
        assert_eq!((unit.values(), unit.bytes()), (2, 9));
        assert_eq!(
            unit.bound(),
            ResourceBound {
                values: 2,
                bytes: 9,
                allocated: 0,
                peak: 0,
                retained: 0
            }
        );
        let mut limits = Limits::unlimited();
        unit.admit(&mut limits).unwrap();
        assert_eq!(limits.used(), WriteWork::new(2, 9));
    }

    /// A capped unit admits its values and the bytes it covers, at most its
    /// cap: one beyond is a defect of the engine, refused before admission.
    #[test]
    fn a_capped_unit_admits_at_most_its_cap() {
        let capped = Capped::new(Caller, 1, 64);
        assert_eq!((capped.values(), capped.cap()), (1, 64));
        let mut limits = Limits::unlimited();
        assert_eq!(
            capped.admit(&mut limits, 65),
            Err(BoundedError::PlanMismatch)
        );
        assert_eq!(limits.attempts(), 0, "a defect admits nothing");
        capped.admit(&mut limits, 64).unwrap();
        assert_eq!(limits.used(), WriteWork::new(1, 64));
        // 130 bytes in units of at most 64: three, and one more for the last
        // partial unit of one item.
        assert_eq!(capped.covering::<()>(130, 1), Ok(WriteWork::new(4, 130)));
        assert_eq!(capped.times::<()>(2), Ok(WriteWork::new(2, 128)));
    }

    #[test]
    fn a_scan_admits_its_values_and_every_byte_it_spans() {
        let scan = Scan::new(Caller, 2);
        assert_eq!(scan.values(), 2);
        assert_eq!(scan.units::<()>(3, 50), Ok(WriteWork::new(6, 50)));
        let mut limits = Limits::unlimited();
        scan.admit(&mut limits, 7).unwrap();
        assert_eq!(limits.used(), WriteWork::new(2, 7));
    }

    /// A rate admits its base once and its work per element; over several
    /// admissions the base is paid per admission.
    #[test]
    fn a_rate_admits_its_base_and_its_work_per_element() {
        let per = Rate::new(Caller, 1, 8);
        let based = Rate::based(Caller, WriteWork::new(2, 4), WriteWork::new(1, 8));
        assert_eq!(per.of::<()>(3), Ok(WriteWork::new(3, 24)));
        assert_eq!(based.of::<()>(3), Ok(WriteWork::new(5, 28)));
        assert_eq!(based.over::<()>(2, 3), Ok(WriteWork::new(7, 32)));
        let mut limits = Limits::unlimited();
        based.admit(&mut limits, 3).unwrap();
        assert_eq!(limits.used(), WriteWork::new(5, 28));
    }

    /// Every integer width encodes as the symbolic conversion encodes it,
    /// at its own extremes, through each width's own schema.
    #[test]
    fn every_integer_width_matches_the_symbolic_encoding() {
        check(&u16::MAX, &CBOR::from(u16::MAX).to_cbor_data());
        check(&u32::MAX, &CBOR::from(u32::MAX).to_cbor_data());
        check(&usize::MAX, &CBOR::from(usize::MAX).to_cbor_data());
        check(&i16::MIN, &CBOR::from(i16::MIN).to_cbor_data());
        check(&i32::MIN, &CBOR::from(i32::MIN).to_cbor_data());
        check(&i16::MAX, &CBOR::from(i16::MAX).to_cbor_data());
        check(&i32::MAX, &CBOR::from(i32::MAX).to_cbor_data());
    }

    /// A policy borrowed mutably is a policy: admissions and allocations
    /// through the borrow reach the policy it borrows.
    #[test]
    fn a_borrowed_policy_admits_and_allocates_for_its_owner() {
        let mut limits = Limits::unlimited();
        let mut borrowed = &mut limits;
        Unit::new(Caller, 1, 3).admit(&mut borrowed).unwrap();
        let permit = <&mut Limits as Allocator>::allocate(&mut borrowed, 5).unwrap();
        assert_eq!(limits.used(), WriteWork::new(1, 3));
        assert_eq!(limits.live_bytes(), 5);
        drop(permit);
        assert_eq!(limits.live_bytes(), 0);
    }

    #[test]
    fn errors_name_their_cause() {
        let shown = |error: BoundedError<LimitRefusal>| format!("{error}");
        assert_eq!(
            shown(BoundedError::Refused(LimitRefusal::Work)),
            "bounded encoding refused: work limit"
        );
        assert_eq!(
            shown(BoundedError::Overflow),
            "encoded length or work exceeds u64"
        );
        assert_eq!(
            shown(BoundedError::OutOfRange),
            "value is outside the dCBOR profile"
        );
        assert_eq!(
            shown(BoundedError::DuplicateKey),
            "duplicate canonical map key"
        );
        assert_eq!(
            shown(BoundedError::DepthLimit),
            "symbolic encoding nesting limit exceeded"
        );
        assert_eq!(
            shown(BoundedError::Allocation { bytes: 12 }),
            "an allocation of 12 bytes failed"
        );
        assert_eq!(
            shown(BoundedError::OutputSize {
                measured: 3,
                provided: 5
            }),
            "bounded encoding measured 3 bytes, given an output of 5"
        );
        assert_eq!(
            shown(BoundedError::PlanMismatch),
            "bounded encoding diverged from its plan"
        );
    }

    /// An insertion shifts the elements after it, admitting each one's
    /// move; a position past the end is refused before anything is admitted.
    #[test]
    fn an_insertion_admits_the_move_of_every_element_after_it() {
        let mut limits = Limits::unlimited();
        let owner = limits.owner().expect("an ordinary policy's owner");
        let mut owned = Owned::<u64, Reservation>::new();
        owned.push(1, &mut limits, &owner).unwrap();
        owned.push(3, &mut limits, &owner).unwrap();
        let before = limits.used();
        owned.insert(1, 2, &mut limits, &owner).unwrap();
        assert_eq!(owned.as_slice(), [1, 2, 3]);
        assert_eq!(
            limits.used(),
            WriteWork::new(before.values, before.bytes + 8),
            "one shifted element of eight bytes, no growth"
        );
        let attempts = limits.attempts();
        assert_eq!(
            owned.insert(5, 9, &mut limits, &owner),
            Err(BoundedError::Overflow)
        );
        assert_eq!(limits.attempts(), attempts);
        assert_eq!(owned.as_slice(), [1, 2, 3]);
    }

    #[test]
    fn growths_sum_every_quantity_refused_on_overflow() {
        let growth = Growth {
            copied: 1,
            allocations: 2,
            allocated: 3,
            held: 4,
            peak: 5,
        };
        assert_eq!(
            growth.plus::<()>(growth),
            Ok(Growth {
                copied: 2,
                allocations: 4,
                allocated: 6,
                held: 8,
                peak: 10,
            })
        );
        let most = Growth {
            peak: u64::MAX,
            ..Growth::default()
        };
        assert_eq!(growth.plus::<()>(most), Err(BoundedError::Overflow));
    }
}
