use super::harness::*;
use super::support::{
    self, Fault, Finding, Retirement, Traced, pipeline::Unwitnessed, refusal_matrix, rigor::rigor,
};
use dcbor::bounded::decode::Options;
use dcbor::bounded::decode::construction::{
    Borrowed, DecodeOwner, TypedDecoder, in_place::Transferable,
};
use dcbor::bounded::decode::decode_typed;
use dcbor::bounded::{Schema, encode};
use dcbor::{ByteString, CBORBoundedDecodable, CBORBoundedEncodable};

/// Scope setup precedes the measured traced decode. Publication outlives its
/// decoder; the run holds every operation and handle through observed retirement.
fn typed_case<'s, T: Transferable<Limits> + 's>(
    wire: &'s [u8],
    fault: Fault,
    check: impl FnOnce(&T, &Limits),
) -> support::RefusalRun {
    suite(|run, policy| {
        let cleanup = run.shared_policy(policy);
        run.holding(
            DecodeOwner::new(),
            Retirement::Scope,
            &Unwitnessed,
            |scope| {
                scope.initialize(policy)?;
                let borrow = scope.value().borrow_input(wire);
                scope.holding(borrow, Retirement::Stopped, |borrow| {
                    borrow.drive_then(
                        policy,
                        support::turns(
                            dcbor::bounded::decode::construction::borrow_bound::<Limits, ()>()
                                .expect("borrow bound fits in u64"),
                        ),
                        Retirement::Published,
                        |input| {
                            Traced(TypedDecoder::<Borrowed<'s>, T, Limits>::new(
                                input,
                                Options::normalizing(8),
                            ))
                        },
                        Retirement::Stopped,
                        |operation| {
                            operation.with_policy(policy, |_, m| {
                                m.measure();
                                m.open();
                            });
                            operation.drive_faulted(
                                policy,
                                typed_turns::<T>(wire.len()),
                                Retirement::Published,
                                fault,
                                |_, _| {},
                                |value| {
                                    value.with_policy(policy, |value, m| {
                                        check(value.value(), m);
                                        m.assert_units(TURN);
                                    })
                                },
                            )?;
                            Ok::<_, Finding>(())
                        },
                    )?
                })?;
                scope.drain(cleanup)
            },
        )?;
        Ok(run.with_policy(policy, |m| {
            assert_eq!(m.live_bytes(), 0);
            support::RefusalRun::of(m)
        }))
    })
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

fn literal<T: Transferable<Limits> + Schema + std::fmt::Debug + PartialEq + 'static>(
    wire: &[u8],
    expected: &T,
) {
    support::recorded_run(|run| {
        // The decode and the encoding, each under a family of its own.
        let decoding = run.policy(POOL);
        let result = run.with_policy(decoding, |m| {
            decode_typed::<T, _>(wire, 8, m).map_err(failed("the literal's decode"))
        })?;
        let writing = run.policy(POOL);
        run.holding(result, Retirement::LastReference, &Unwitnessed, |result| {
            assert_eq!(result.value().value(), expected);
            let bytes = result
                .with_policy(writing, |_, w| encode(expected, w))
                .map_err(failed("the literal's encoding"))?;
            result.holding(bytes, Retirement::Released, |bytes| {
                assert_eq!(bytes.value().as_ref(), wire);
            });
            result.with_policy(writing, |_, w| assert_eq!(w.live_bytes(), 0));
            Ok::<_, Finding>(())
        })?;
        run.with_policy(decoding, |m| assert_eq!(m.live_bytes(), 0));
        Ok(())
    });
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
    support::recorded_run(|run| {
        let decoding = run.policy(POOL);
        let value = run.with_policy(decoding, |m| {
            decode_typed::<Tagged, _>(&wire, 8, m).map_err(failed("the tagged decode"))
        })?;
        // As in the symbolic API, the explicit wrapper emits the outer tag.
        let writing = run.policy(POOL);
        run.holding(value, Retirement::LastReference, &Unwitnessed, |value| {
            assert_eq!(value.value().value(), &expected);
            let output = value
                .with_policy(writing, |_, w| {
                    encode(
                        &dcbor::bounded::Tagged {
                            tag: 42,
                            value: &expected,
                        },
                        w,
                    )
                })
                .map_err(failed("the tagged encoding"))?;
            value.holding(output, Retirement::Released, |output| {
                assert_eq!(output.value().as_ref(), wire);
            });
            value.with_policy(writing, |_, w| assert_eq!(w.live_bytes(), 0));
            Ok::<_, Finding>(())
        })?;
        run.with_policy(decoding, |m| assert_eq!(m.live_bytes(), 0));
        Ok(())
    });
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
        typed_case::<T>(wire, fault, |value, m| {
            assert_eq!(value, expected);
            m.assert_units(TURN);
        })
    });
}

#[test]
fn derived_unit_and_newtype_resume_without_schema_replay() -> Result<(), Vec<Finding>> {
    every_fixture(2, |case| {
        match case {
            0 => resumed_shape(&[0xf6], &Unit),
            _ => resumed_shape(&[0x61, b'x'], &Wrapper("x".into())),
        }
        Ok(())
    })
}

#[test]
fn every_enum_shape_resumes_without_discriminant_replay() -> Result<(), Vec<Finding>> {
    every_fixture(3, |case| {
        match case {
            0 => resumed_shape(&[0x00], &Choice::Empty),
            1 => resumed_shape(&[0x82, 0x01, 0x61, b'x'], &Choice::Text("x".into())),
            _ => resumed_shape(
                &[0x82, 0x02, 0xa1, 0x00, 0x61, b'x'],
                &Choice::Fields { value: "x".into() },
            ),
        }
        Ok(())
    })
}

#[test]
fn tagged_and_generic_nested_values_resume_without_reconstruction() -> Result<(), Vec<Finding>> {
    every_fixture(2, |case| {
        match case {
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
        }
        Ok(())
    })
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
        synchronous_case(
            |m| decode_typed::<Choice, _>(wire, 8, m),
            |result, _| {
                assert!(result.is_err());
            },
        );
    }
    for wire in [&[0xa1, 0x00, 0x60][..], &[0xd8, 0x2b, 0xa1, 0x00, 0x60]] {
        synchronous_case(
            |m| decode_typed::<Tagged, _>(wire, 8, m),
            |result, _| {
                assert!(result.is_err());
            },
        );
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
        synchronous_case(
            |m| decode_typed::<Record, _>(wire, 8, m),
            |result, _| {
                assert!(result.is_err(), "{wire:x?}");
            },
        );
    }
    // Existing derive semantics ignore unknown fields. Continuation must not
    // turn this compatibility rule into a new rejection policy.
    synchronous_case(
        |m| decode_typed::<Record, _>(&[0xa3, 0x00, 0x60, 0x01, 0x40, 0x03, 0xf5], 8, m),
        |result, _| {
            let value = result.expect("a record with an unknown field");
            assert_eq!(
                value.value(),
                &Record {
                    text: String::new(),
                    bytes: ByteString::new(Vec::new()),
                    optional: None,
                }
            );
        },
    );
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
    typed_case::<Record>(&wire, Fault::NONE, |value, m| {
        assert!(m.live_bytes() >= 4);
        assert_eq!(value, &expected);
    });
}
