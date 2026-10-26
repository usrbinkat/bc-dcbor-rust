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
                    map.insert(key, value);
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

/// A value prepared under one policy is written under another into storage
/// owned with the caller's permit: the writing budget is told of the
/// initialization and the write, never of an allocation; a refused write
/// publishes nothing and drops the permit.
#[test]
fn an_owned_encoding_is_written_under_its_own_budget() {
    let mut preparing = Limits::unlimited();
    let prepared = prepare(&24u64, &mut preparing).unwrap();
    let mut storage = Limits::unlimited();
    let permit = storage.allocate(prepared.len() as u64).unwrap();
    let mut writing = Limits::unlimited();
    let encoded = prepared.encode_owned(permit, &mut writing).unwrap();
    assert_eq!(encoded.as_ref(), [0x18, 0x18]);
    assert_eq!(
        writing.used().bytes,
        4,
        "the initialization of both bytes, then their one segment"
    );
    assert_eq!(writing.used().values, 2, "the segment and the completion");
    assert_eq!(
        writing.requested_bytes(),
        0,
        "the writing budget allocates nothing"
    );
    assert_eq!(storage.live_bytes(), 2, "the permit lives with the bytes");
    drop(encoded);
    assert_eq!(storage.live_bytes(), 0, "and is released with them");

    let permit = storage.allocate(prepared.len() as u64).unwrap();
    assert_eq!(
        prepared
            .encode_owned(permit, &mut limited(0))
            .map(|encoded| encoded.as_ref().to_vec()),
        Err(BoundedError::Refused(LimitRefusal::Work))
    );
    assert_eq!(storage.live_bytes(), 0, "a refused write drops its permit");
}

/// The growth bound is exactly what an `Owned` reports and holds: element
/// by element and in one reservation, for elements of several sizes and
/// every count across several doublings.
#[test]
fn owned_growth_is_exact() {
    fn measured<T: Default>(elements: usize, one_at_a_time: bool) -> Growth {
        let mut limits = Limits::unlimited();
        let mut owned = Owned::<T, Reservation>::new();
        if one_at_a_time {
            for _ in 0..elements {
                owned.push(T::default(), &mut limits).unwrap();
            }
        } else {
            owned.reserve(elements, &mut limits).unwrap();
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

#[test]
fn work_composition_is_checked() {
    let most = WriteWork::new(u64::MAX, 0);
    assert_eq!(
        most.then::<()>(WriteWork::new(1, 0)),
        Err(BoundedError::Overflow)
    );
    assert_eq!(most.times::<()>(2), Err(BoundedError::Overflow));
    assert_eq!(
        prepare(&[0u8; 0], &mut Limits::unlimited()).map(|p| p.len()),
        Ok(1)
    );
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
        map.insert(key, 0u64);
    }
    let iterated: Vec<Vec<u8>> = map.iter().map(|(key, _)| key.to_cbor_data()).collect();
    let mut sorted = iterated.clone();
    sorted.sort();
    assert_eq!(iterated, sorted);
    check(&map, &CBOR::from(map.clone()).to_cbor_data());
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
