use super::harness::*;
use super::support::{
    self, Fault, Traced, allowed, drive_faulted, drive_within, refusal_matrix, refuse, rigor::rigor,
};
use dcbor::bounded::decode::Options;
use dcbor::bounded::decode::construction::{
    Borrowed, DecodeOwner, TypedDecoder, in_place::Transferable,
};
use dcbor::bounded::decode::{BoundedDecodable, decode_typed};
use dcbor::bounded::{Schema, encode};
use dcbor::{ByteString, CBORBoundedDecodable, CBORBoundedEncodable};

type Typed<'s, T> = Traced<TypedDecoder<'s, Borrowed<'s>, T, Limits>>;

/// A scope over `wire` and a traced typed decode of it. Setup is not
/// measured: the policy's counts, log and trace cover only the decode, with
/// an unlimited allowance; a schedule's refusals are applied after.
fn typed<'s, T: Transferable<Limits> + 's>(
    wire: &'s [u8],
    m: &mut Limits,
) -> (DecodeOwner<'s, Limits>, Typed<'s, T>) {
    let (owner, input) = support::open(m, wire);
    m.measure();
    m.open();
    (
        owner,
        Traced(TypedDecoder::new(input, Options::normalizing(8))),
    )
}

#[derive(Debug, PartialEq, CBORBoundedDecodable, CBORBoundedEncodable)]
pub(super) struct Record {
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
#[repr(C, u8)]
pub(super) enum Choice {
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

fn literal<T: BoundedDecodable + Schema + std::fmt::Debug + PartialEq>(wire: &[u8], expected: &T) {
    let mut m = meter();
    let result = decode_typed::<T, _>(wire, 8, &mut m).unwrap();
    assert_eq!(result.value(), expected);
    let mut writing = meter();
    let bytes = encode(expected, &mut writing).unwrap();
    assert_eq!(bytes.as_ref(), wire);
    drop(bytes);
    assert_eq!(writing.live_bytes(), 0);
    drop(result);
    assert_eq!(m.live_bytes(), 0);
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
    assert_eq!(m.live_bytes(), 0);
    assert_eq!(writing.live_bytes(), 0);
}

/// The fault matrix of a traced typed decode of `T` from `wire`
/// ([`refusal_matrix`]): every refusal resumed to `expected`, and a
/// cancellation at every call, the decoder then dropped and its records
/// drained. Every run drains its scope before returning its calls, so a
/// mismatch the matrix reports never meets live records.
fn resumed_shape<T: Transferable<Limits> + std::fmt::Debug + PartialEq + 'static>(
    wire: &[u8],
    expected: &T,
) {
    let name = format!(
        "typed decode of {} from {wire:02x?}",
        core::any::type_name::<T>()
    );
    refusal_matrix(&name, rigor(), |fault: Fault| {
        let mut m = meter();
        let (mut owner, mut operation) = typed::<T>(wire, &mut m);
        refuse(&mut m, fault.refusal);
        let pool = m.share();
        let turns = allowed(&m, typed_turns::<T>(wire.len()));
        let output = drive_faulted(&mut m, &mut operation, turns, fault.cancel)
            .expect("a derived literal decodes");
        if let Some(output) = &output {
            assert_eq!(output.value(), expected);
            m.assert_units(TURN);
        }
        drop(output);
        drop(operation);
        support::drain(&mut owner, &mut pool.share());
        assert_eq!(pool.live_bytes(), 0);
        support::RefusalRun::of(&m)
    });
}

#[test]
fn derived_unit_and_newtype_resume_without_schema_replay() {
    every_fixture(2, |case| match case {
        0 => resumed_shape(&[0xf6], &Unit),
        _ => resumed_shape(&[0x61, b'x'], &Wrapper("x".into())),
    });
}

#[test]
fn every_enum_shape_resumes_without_discriminant_replay() {
    every_fixture(3, |case| match case {
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
    every_fixture(2, |case| match case {
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
        assert_eq!(m.live_bytes(), 0);
    }
    for wire in [&[0xa1, 0x00, 0x60][..], &[0xd8, 0x2b, 0xa1, 0x00, 0x60]] {
        let mut m = meter();
        assert!(decode_typed::<Tagged, _>(wire, 8, &mut m).is_err());
        assert_eq!(m.live_bytes(), 0);
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
        assert_eq!(m.live_bytes(), 0);
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
    assert_eq!(m.live_bytes(), 0);
}

#[test]
fn derived_nested_fields_resume_at_every_admission_without_reconstruction() {
    let wire = [
        0xa3, 0x00, 0x62, 0xc3, 0xa9, 0x01, 0x42, 0x00, 0xff, 0x02, 0xf4,
    ];
    let expected = Record {
        text: "\u{e9}".into(),
        bytes: ByteString::new(vec![0, 255]),
        optional: Some(false),
    };
    resumed_shape(&wire, &expected);
    // The published value outlives its decoder and holds its fields'
    // storage; a property of publication, not of the refusal schedule.
    let mut m = meter();
    let (mut owner, mut reference) = typed::<Record>(&wire, &mut m);
    let pool = m.share();
    let value = drive_within(&mut m, &mut reference, typed_turns::<Record>(wire.len()))
        .expect("baseline decode");
    drop(reference);
    assert!(pool.live_bytes() >= 4);
    assert_eq!(value.value(), &expected);
    drop(value);
    support::drain(&mut owner, &mut pool.share());
    assert_eq!(pool.live_bytes(), 0);
}
