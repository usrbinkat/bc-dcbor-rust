use super::driver::{Driver, Event, Operation, finish, resume};
use super::harness::*;
use dcbor::bounded::BoundedError;
use dcbor::bounded::decode::{BoundedDecodable, decode_typed};
use dcbor::bounded::decode::{
    DecodeError, Options,
    construction::{ResumableDecodable, TypedDecoder, TypedStep, TypedValue},
};
use dcbor::bounded::{BoundedEncodable, encode};
use dcbor::{ByteString, CBORBoundedDecodable, CBORBoundedEncodable};

impl<T: ResumableDecodable> Operation<TypedValue<T, Permit>> for TypedDecoder<'_, T, Permit> {
    fn advance(&mut self, meter: &mut Meter) -> Result<Event<TypedValue<T, Permit>>, &'static str> {
        Ok(match self.step(meter) {
            Ok(TypedStep::Progress) => Event::Progress,
            Ok(TypedStep::Complete(value)) => Event::Complete(value),
            Ok(TypedStep::Finished) => Event::Finished,
            Err(DecodeError::Resource(BoundedError::Refused(reason))) => Event::Refused(reason),
            Err(DecodeError::Invalid(_)) => Event::Invalid,
            Err(_) => return Err("retained derived constructor resource or policy failure"),
        })
    }
}

fn typed_driver<T: ResumableDecodable>(
    wire: &[u8],
    meter: Meter,
) -> Driver<TypedDecoder<'_, T, Permit>, TypedValue<T, Permit>> {
    Driver::from_operation(TypedDecoder::new(wire, Options::normalizing(8)), meter)
}

#[derive(Debug, PartialEq, CBORBoundedDecodable, CBORBoundedEncodable)]
struct Record {
    #[cbor(n = 0)]
    text: String,
    #[cbor(n = 1)]
    bytes: ByteString,
    #[cbor(n = 2)]
    optional: Option<bool>,
}

#[derive(Debug, PartialEq, CBORBoundedDecodable, CBORBoundedEncodable)]
struct Wrapper(String);

#[derive(Debug, PartialEq, CBORBoundedDecodable, CBORBoundedEncodable)]
enum Choice {
    #[cbor(n = 0)]
    Empty,
    #[cbor(n = 1)]
    Text(String),
    #[cbor(n = 2)]
    Fields {
        #[cbor(n = 0)]
        value: String,
    },
}

#[derive(Debug, PartialEq, CBORBoundedDecodable, CBORBoundedEncodable)]
#[cbor(tag = 42)]
struct Tagged {
    #[cbor(n = 0)]
    text: String,
}

#[derive(Debug, PartialEq, CBORBoundedDecodable, CBORBoundedEncodable)]
struct Unit;

#[derive(Debug, PartialEq, CBORBoundedDecodable, CBORBoundedEncodable)]
struct Collection<T> {
    #[cbor(n = 0)]
    values: Vec<T>,
}

fn literal<T: BoundedDecodable + BoundedEncodable + std::fmt::Debug + PartialEq>(
    wire: &[u8],
    expected: &T,
) {
    let mut m = meter();
    let result = decode_typed::<T, _>(wire, 8, &mut m).unwrap();
    assert_eq!(result.value(), expected);
    let mut writing = meter();
    let bytes = encode(expected, &mut writing).unwrap();
    assert_eq!(bytes.as_ref(), wire);
    drop(bytes);
    assert_eq!(writing.pool.live(), 0);
    drop(result);
    assert_eq!(m.pool.live(), 0);
}

#[test]
fn derived_record_distinguishes_absence_empty_bytes_and_present_false() {
    literal(
        &[0xa2, 0x00, 0x60, 0x01, 0x40],
        &Record {
            text: String::new(),
            bytes: ByteString::new(Vec::new()),
            optional: None,
        },
    );
    literal(
        &[0xa3, 0x00, 0x60, 0x01, 0x40, 0x02, 0xf4],
        &Record {
            text: String::new(),
            bytes: ByteString::new(Vec::new()),
            optional: Some(false),
        },
    );
}

#[test]
fn derived_newtypes_tags_and_enum_shapes_have_literal_wire_oracles() {
    literal(&[0xf6], &Unit);
    literal(
        &[0xa1, 0x00, 0x82, 0x61, b'a', 0x61, b'b'],
        &Collection {
            values: vec![Wrapper("a".into()), Wrapper("b".into())],
        },
    );
    literal(&[0x61, b'x'], &Wrapper("x".into()));
    literal(&[0x00], &Choice::Empty);
    literal(&[0x82, 0x01, 0x61, b'x'], &Choice::Text("x".into()));
    literal(
        &[0x82, 0x02, 0xa1, 0x00, 0x61, b'x'],
        &Choice::Fields { value: "x".into() },
    );
    let wire = [0xd8, 0x2a, 0xa1, 0x00, 0x61, b'x'];
    let expected = Tagged { text: "x".into() };
    let mut m = meter();
    let value = decode_typed::<Tagged, _>(&wire, 8, &mut m).unwrap();
    assert_eq!(value.value(), &expected);
    // As in the symbolic API, the explicit wrapper emits the outer tag.
    let mut writing = meter();
    let output = encode(
        &dcbor::bounded::Tagged {
            tag: 42,
            value: &expected,
        },
        &mut writing,
    )
    .unwrap();
    assert_eq!(output.as_ref(), wire);
    drop(output);
    drop(value);
    assert_eq!(m.pool.live(), 0);
    assert_eq!(writing.pool.live(), 0);
}

fn resumed_shape<T: ResumableDecodable + std::fmt::Debug + PartialEq>(wire: &[u8], expected: &T) {
    let mut reference = typed_driver::<T>(wire, meter());
    finish(&mut reference, 4096);
    let output = reference.output.take().unwrap();
    assert_eq!(output.value(), expected);
    drop(output);
    let baseline = reference.meter;
    every_case(baseline.calls.len(), |stop| {
        let mut m = meter();
        let reason = match baseline.calls[stop] {
            Call::Allocate(_) => Refusal::Capacity,
            Call::Work { .. } => Refusal::Work,
        };
        m.fail_at = Some((stop, reason));
        let pool = m.pool.clone();
        let mut driver = typed_driver::<T>(wire, m);
        resume(&mut driver, reason);
        assert_eq!(driver.output.as_ref().unwrap().value(), expected);
        let mut trace = baseline.calls.clone();
        trace.insert(stop, baseline.calls[stop]);
        assert_eq!(driver.meter.calls, trace);
        assert_eq!(
            (driver.meter.values, driver.meter.bytes),
            (baseline.values, baseline.bytes)
        );
        driver.meter.assert_units(3, 64);
        let output = driver.output.take().unwrap();
        drop(driver);
        assert_eq!(output.value(), expected);
        drop(output);
        assert_eq!(pool.live(), 0);
    });
}

#[test]
fn derived_unit_and_newtype_resume_without_schema_replay() {
    every_case(2, |case| match case {
        0 => resumed_shape(&[0xf6], &Unit),
        _ => resumed_shape(&[0x61, b'x'], &Wrapper("x".into())),
    });
}

#[test]
fn every_enum_shape_resumes_without_discriminant_replay() {
    every_case(3, |case| match case {
        0 => resumed_shape(&[0x00], &Choice::Empty),
        1 => resumed_shape(&[0x82, 0x01, 0x61, b'x'], &Choice::Text("x".into())),
        _ => resumed_shape(
            &[0x82, 0x02, 0xa1, 0x00, 0x61, b'x'],
            &Choice::Fields { value: "x".into() },
        ),
    });
}

#[test]
fn tagged_and_generic_nested_values_resume_without_reconstruction() {
    every_case(2, |case| match case {
        0 => resumed_shape(
            &[0xd8, 0x2a, 0xa1, 0x00, 0x61, b'x'],
            &Tagged { text: "x".into() },
        ),
        _ => resumed_shape(
            &[0xa1, 0x00, 0x82, 0x61, b'a', 0x61, b'b'],
            &Collection {
                values: vec![Wrapper("a".into()), Wrapper("b".into())],
            },
        ),
    });
}

#[test]
fn derived_discriminants_tags_and_lengths_are_strictly_rejected() {
    for wire in [
        &[0x03][..],
        &[0x81, 0x01],
        &[0x83, 0x01, 0x61, b'x', 0x00],
        &[0x82, 0x20, 0x61, b'x'],
        &[0x82, 0x02, 0xa0],
    ] {
        let mut m = meter();
        assert!(decode_typed::<Choice, _>(wire, 8, &mut m).is_err());
        assert_eq!(m.pool.live(), 0);
    }
    for wire in [&[0xa1, 0x00, 0x60][..], &[0xd8, 0x2b, 0xa1, 0x00, 0x60]] {
        let mut m = meter();
        assert!(decode_typed::<Tagged, _>(wire, 8, &mut m).is_err());
        assert_eq!(m.pool.live(), 0);
    }
}

#[test]
fn derived_record_preserves_unknown_fields_policy_and_rejects_invalid_known_fields() {
    for wire in [
        &[0xa0][..],
        &[0xa2, 0x00, 0x00, 0x01, 0x40],
        &[0xa3, 0x00, 0x60, 0x00, 0x60, 0x01, 0x40],
        &[0xa3, 0x00, 0x60, 0x01, 0x40, 0x02, 0x00],
    ] {
        let mut m = meter();
        assert!(
            decode_typed::<Record, _>(wire, 8, &mut m).is_err(),
            "{wire:x?}"
        );
        assert_eq!(m.pool.live(), 0);
    }
    // Existing derive semantics ignore unknown fields. Continuation must not
    // turn this compatibility rule into a new rejection policy.
    let mut m = meter();
    let value =
        decode_typed::<Record, _>(&[0xa3, 0x00, 0x60, 0x01, 0x40, 0x03, 0xf5], 8, &mut m).unwrap();
    assert_eq!(
        value.value(),
        &Record {
            text: String::new(),
            bytes: ByteString::new(Vec::new()),
            optional: None,
        }
    );
    drop(value);
    assert_eq!(m.pool.live(), 0);
}

#[test]
fn derived_nested_fields_resume_at_every_admission_without_reconstruction() {
    let wire = [
        0xa3, 0x00, 0x62, 0xc3, 0xa9, 0x01, 0x42, 0x00, 0xff, 0x02, 0xf4,
    ];
    let expected = Record {
        text: "é".into(),
        bytes: ByteString::new(vec![0, 255]),
        optional: Some(false),
    };
    let mut reference = typed_driver::<Record>(&wire, meter());
    finish(&mut reference, 4096);
    let result = reference.output.take().unwrap();
    assert_eq!(result.value(), &expected);
    drop(result);
    let baseline = reference.meter;
    every_case(baseline.calls.len(), |stop| {
        let mut m = meter();
        m.fail_at = Some((stop, Refusal::Work));
        let pool = m.pool.clone();
        let mut driver = typed_driver::<Record>(&wire, m);
        resume(&mut driver, Refusal::Work);
        assert_eq!(driver.output.as_ref().unwrap().value(), &expected);
        driver.meter.assert_units(3, 64);
        let value = driver.output.take().unwrap();
        drop(driver);
        assert!(pool.live() >= 4);
        assert_eq!(value.value(), &expected);
        drop(value);
        assert_eq!(pool.live(), 0);
    });
}
