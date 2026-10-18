extern crate alloc;

use alloc::rc::Rc;
use core::cell::Cell;

use half::f16;

use super::*;
use crate::CBOR;

/// A budget and allocator that records what it is told, refuses
/// traversal past `value_limit` visited values and allocation past
/// `scratch_limit` requested bytes, and tracks live and peak allocation
/// through its permits.
pub(crate) struct Tally {
    pub(crate) values: u64,
    pub(crate) bytes: u64,
    pub(crate) requested: u64,
    value_limit: u64,
    scratch_limit: u64,
    live: Rc<Cell<u64>>,
    peak: Rc<Cell<u64>>,
}

/// One admitted allocation; dropping it releases its bytes.
pub(crate) struct TallyPermit {
    bytes: u64,
    live: Rc<Cell<u64>>,
}

impl Drop for TallyPermit {
    fn drop(&mut self) {
        self.live.set(self.live.get() - self.bytes);
    }
}

impl Tally {
    fn with(value_limit: u64, scratch_limit: u64) -> Self {
        Self {
            values: 0,
            bytes: 0,
            requested: 0,
            value_limit,
            scratch_limit,
            live: Rc::new(Cell::new(0)),
            peak: Rc::new(Cell::new(0)),
        }
    }

    pub(crate) fn unlimited() -> Self {
        Self::with(u64::MAX, u64::MAX)
    }

    /// Refuses past `values` visited values.
    pub(crate) fn limited(values: u64) -> Self {
        Self::with(values, u64::MAX)
    }

    /// Refuses past `bytes` requested allocation bytes.
    pub(crate) fn scratch_limited(bytes: u64) -> Self {
        Self::with(u64::MAX, bytes)
    }

    pub(crate) fn live(&self) -> u64 {
        self.live.get()
    }

    pub(crate) fn peak(&self) -> u64 {
        self.peak.get()
    }
}

impl Budget for Tally {
    type Refusal = &'static str;

    fn traverse(&mut self, values: u64, bytes: u64) -> Result<(), &'static str> {
        let values = self.values.checked_add(values).ok_or("overflow")?;
        let bytes = self.bytes.checked_add(bytes).ok_or("overflow")?;
        if values > self.value_limit {
            return Err("traversal refused");
        }
        self.values = values;
        self.bytes = bytes;
        Ok(())
    }
}

impl Allocator for Tally {
    type Permit = TallyPermit;

    fn allocate(&mut self, bytes: u64) -> Result<TallyPermit, &'static str> {
        let requested = self.requested.checked_add(bytes).ok_or("overflow")?;
        if requested > self.scratch_limit {
            return Err("allocation refused");
        }
        self.requested = requested;
        let live = self.live.get().checked_add(bytes).ok_or("overflow")?;
        self.live.set(live);
        self.peak.set(self.peak.get().max(live));
        Ok(TallyPermit {
            bytes,
            live: Rc::clone(&self.live),
        })
    }
}

/// Both passes of `value` against the symbolic encoding `symbolic`: the
/// bytes are equal, both strictly decode to one value, the length is
/// exact, the write reports no more than predicted, and every allocation
/// is released once the preparation drops.
pub(crate) fn check<T: BoundedEncodable + ?Sized>(value: &T, symbolic: &[u8]) -> Vec<u8> {
    let mut allocator = Tally::unlimited();
    let bytes = {
        let prepared = prepare(value, &mut allocator).unwrap();
        let mut bytes = vec![0u8; usize::try_from(prepared.len()).unwrap()];
        let mut written = Tally::unlimited();
        prepared.encode_into(&mut bytes, &mut written).unwrap();
        let reported = WriteWork::new(written.values, written.bytes);
        assert!(
            prepared.write_work().covers(&reported),
            "the write reported {reported:?} beyond {:?}",
            prepared.write_work()
        );
        assert_eq!(written.requested, 0, "a write allocates nothing");
        bytes
    };
    assert_eq!(allocator.live(), 0, "every allocation is released");
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

/// Elements of a fixed measure are measured from their count, and the
/// prediction still covers every element the write visits; an array of
/// them has a fixed measure itself.
#[test]
fn fixed_measures_compose() {
    let flags = vec![true, false, true];
    let mut measuring = Tally::unlimited();
    let prepared = prepare(&flags, &mut measuring).unwrap();
    assert_eq!(measuring.values, 1, "measurement visits the array only");
    assert_eq!(
        prepared.write_work().values,
        4,
        "the write visits the array and each flag"
    );
    check(&flags, &CBOR::from(flags.clone()).to_cbor_data());
    let fixed = <[bool; 3]>::FIXED.unwrap();
    assert_eq!(fixed.len, 4);
    assert_eq!(fixed.write, WriteWork::new(4, 0));
    assert_eq!(<[u8; 3]>::FIXED, None, "integers are not of fixed length");
}

/// A wrong-sized output is refused before anything is written; a write
/// past the output writes nothing of it; a short write is refused at its
/// end.
#[test]
fn the_output_refuses_wrong_sizes_overflow_and_a_short_finish() {
    let prepared = prepare(&1u64, &mut Tally::unlimited()).unwrap();
    let mut bytes = [0xeeu8; 3];
    assert_eq!(
        prepared.encode_into(&mut bytes, &mut Tally::unlimited()),
        Err(BoundedError::OutputSize {
            measured: 1,
            provided: 3
        })
    );
    assert_eq!(bytes, [0xee; 3], "nothing was written");
    let mut short = [0u8; 2];
    let mut output = Output::new(&mut short);
    assert_eq!(
        output.slice::<()>(&[1, 2, 3]),
        Err(BoundedError::Capacity {
            needed: 3,
            remaining: 2
        })
    );
    assert_eq!(output.written(), 0);
    output.byte::<()>(7).unwrap();
    assert_eq!(
        output.finish::<()>(1),
        Err(BoundedError::Length {
            measured: 1,
            written: 1
        }),
        "one of two bytes written is not a complete output"
    );
    assert_eq!(short, [7, 0]);
}

/// A measure that is wrong for what is written is caught at the sink, not
/// trusted.
#[test]
fn a_wrong_measure_is_refused_at_the_sink() {
    struct Understated;
    impl BoundedEncodable for Understated {
        fn measure<A: Allocator>(
            &self,
            _: &mut Plan<A::Permit>,
            _: &mut A,
        ) -> BoundedResult<Measure, A> {
            Ok(Measure::leaf(1, 0))
        }

        fn write<P, B: Budget>(
            &self,
            _: &mut Cursor<'_, P>,
            output: &mut Output<'_>,
            _: &mut B,
        ) -> BoundedResult<(), B> {
            output.head(MajorType::Unsigned, 256)
        }
    }
    let prepared = prepare(&Understated, &mut Tally::unlimited()).unwrap();
    let mut bytes = [0u8; 1];
    assert_eq!(
        prepared.encode_into(&mut bytes, &mut Tally::unlimited()),
        Err(BoundedError::Capacity {
            needed: 3,
            remaining: 1
        })
    );
}

/// A refusing budget stops the preparation before the value is visited,
/// and its refusal comes back as itself.
#[test]
fn a_refusal_is_returned_as_the_budget_gave_it() {
    assert_eq!(
        prepare(&42u64, &mut Tally::limited(0)).map(|prepared| prepared.len()),
        Err(BoundedError::Refused("traversal refused"))
    );
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
        prepare(&[0u8; 0], &mut Tally::unlimited()).map(|p| p.len()),
        Ok(1)
    );
}
