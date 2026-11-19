//! Public interface no other test reached, each held to its own contract: a
//! map's queries, default, hash, diagnostics and conversion to a hash map; a
//! key comparison's bound against the work it admits; the emptiness of every
//! prepared encoding; the typed decoder's numeric ranges and its error text;
//! and the operation-local cleanup of an owned plan and of its writer.
#![cfg(feature = "std")]
#![forbid(unsafe_code)]
use core::cmp::Ordering;
use core::hash::{Hash, Hasher};
use dcbor::bounded::decode::comparison::{KeyComparison, comparison_bound};
use dcbor::bounded::decode::construction::DecodeOwner;
use dcbor::bounded::decode::construction::in_place::Transferable;
use dcbor::bounded::decode::construction::reclamation::Reclaimed;
use dcbor::bounded::decode::{DecodeError, Options, decode_typed};
use dcbor::bounded::encoding::{OwnedPrepared, OwnedWriter, Preparation, owned_prepare_bound};
use dcbor::bounded::text_cursor::pipeline::TextPreparation;
use dcbor::bounded::{BoundedError, LimitRefusal, Limits, ResourceBound, Step};
use dcbor::{ByteString, CBOR, Error, Map};
use dcbor_test_support::{
    self as support, Finding, Holding, Lent, PolicyId, Retirement, pipeline::Unwitnessed,
    reclamation::Reclaiming,
};

/// The bytes a value hashes into a hasher, in order.
#[derive(Default)]
struct Recorded(Vec<u8>);

impl Hasher for Recorded {
    fn finish(&self) -> u64 {
        0
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
    }
}

fn recorded(value: &impl Hash) -> Vec<u8> {
    let mut hasher = Recorded::default();
    value.hash(&mut hasher);
    hasher.0
}

/// A map answers by encoded key: an integer key and a float that reduces to
/// it are one key, a text of its digits another. The default map is the
/// empty one.
#[test]
fn a_maps_queries_and_default_answer_by_encoded_key() {
    let empty = Map::default();
    assert!(empty.is_empty());
    assert_eq!(empty, Map::new());
    let mut map = Map::new();
    map.insert(1, "one").unwrap();
    assert!(!map.is_empty());
    assert!(map.contains_key(1).unwrap());
    assert!(map.contains_key(1.0).unwrap());
    assert!(!map.contains_key(2).unwrap());
    assert!(!map.contains_key("1").unwrap());
    // The float is the same key: inserting it is refused, the map unchanged.
    assert!(matches!(
        map.insert(1.0, "float one"),
        Err(Error::DuplicateMapKey)
    ));
    assert_eq!(map.len(), 1);
    assert_eq!(map.get::<_, String>(1).unwrap(), Some("one".to_string()));
}

/// A map hashes its entry count, then each entry's encoded key, its key and
/// its value, in key order; its diagnostics show each encoded key in hex
/// beside the key and value.
#[test]
fn a_map_hashes_and_shows_each_entry_by_its_encoded_key() {
    let mut map = Map::new();
    map.insert("b", 2).unwrap();
    map.insert(1, "one").unwrap();
    let entries = [
        (CBOR::from(1), CBOR::from("one")),
        (CBOR::from("b"), CBOR::from(2)),
    ];
    let mut expected = Recorded::default();
    expected.write_usize(entries.len());
    for (key, value) in &entries {
        key.to_cbor_data().hash(&mut expected);
        key.hash(&mut expected);
        value.hash(&mut expected);
    }
    assert_eq!(recorded(&map), expected.0);
    let shown: Vec<String> = entries
        .iter()
        .map(|(key, value)| {
            format!(
                "0x{}: ({key:?}, {value:?})",
                hex::encode(key.to_cbor_data())
            )
        })
        .collect();
    assert_eq!(format!("{map:?}"), format!("{{{}}}", shown.join(", ")));
}

/// A map converts to a hash map of its keys and values as they are; any
/// other value is the wrong type.
#[test]
fn a_map_converts_to_a_hash_map_of_its_entries() {
    let mut map = Map::new();
    map.insert(1, "one").unwrap();
    map.insert("b", 2).unwrap();
    let table: dcbor::HashMap<CBOR, CBOR> = CBOR::from(map)
        .try_into()
        .expect("a map converts to a hash map");
    assert_eq!(table.len(), 2);
    assert_eq!(table.get(&CBOR::from(1)), Some(&CBOR::from("one")));
    assert_eq!(table.get(&CBOR::from("b")), Some(&CBOR::from(2)));
    assert!(matches!(
        dcbor::HashMap::<CBOR, CBOR>::try_from(CBOR::from(7)),
        Err(Error::WrongType)
    ));
}

/// A comparison of two keys, the shorter of `shorter` bytes and a prefix of
/// the other, admits exactly its bound's work: a turn per quantum of byte
/// pairs, one for keys of no common bytes, every pair once, nothing held.
#[test]
fn a_key_comparisons_bound_is_the_work_it_admits() {
    assert_eq!(
        comparison_bound(0),
        ResourceBound {
            values: 1,
            ..ResourceBound::default()
        }
    );
    for shorter in [0usize, 1, 64, 65, 128, 129] {
        let left = vec![7u8; shorter];
        let right = vec![7u8; shorter + 1];
        let bound = comparison_bound(shorter as u64);
        assert_eq!(
            (bound.allocated, bound.peak, bound.retained),
            (0, 0, 0),
            "{shorter}"
        );
        let mut budget = Limits::unlimited();
        let mut comparison = KeyComparison::new(&left, &right);
        let mut ordering = None;
        for _ in 0..bound.values {
            match comparison.step(&mut budget).expect("an unlimited budget") {
                Step::Progress => {}
                Step::Complete(complete) => {
                    ordering = Some(complete);
                    break;
                }
                Step::Finished => panic!("{shorter}: finished without an ordering"),
            }
        }
        assert_eq!(ordering, Some(Ordering::Less), "{shorter}");
        assert_eq!(budget.used(), bound.work(), "{shorter}");
        assert_eq!(comparison.position(), shorter, "{shorter}");
    }
}

/// Every prepared encoding holds at least its head, an empty text's
/// included: a plan and a prepared text are never empty.
#[test]
fn every_prepared_encoding_holds_at_least_its_head() {
    for (text, len) in [("", 1usize), ("abc", 4)] {
        let source = text.to_string();
        support::recorded_run(|run| {
            let policy = run.policy(u64::MAX);
            run.holding(
                Preparation::new(&source),
                Retirement::Released,
                &Unwitnessed,
                |preparation| {
                    preparation.drive(
                        policy,
                        support::prepare_turns(support::shape(&source)),
                        Retirement::Released,
                        |plan| {
                            assert_eq!(plan.value().len(), len, "{text:?}");
                            assert!(!plan.value().is_empty(), "{text:?}");
                            plan.holding(
                                TextPreparation::new(text),
                                Retirement::Released,
                                |preparation| {
                                    preparation.drive(
                                        policy,
                                        support::normalize_turns(text),
                                        Retirement::Released,
                                        |prepared| {
                                            assert_eq!(
                                                prepared.value().len(),
                                                len as u64,
                                                "{text:?}"
                                            );
                                            assert!(!prepared.value().is_empty(), "{text:?}");
                                        },
                                    )
                                },
                            )
                        },
                    )?
                },
            )?;
            run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0, "{text:?}"));
            Ok(())
        });
    }
}

/// Each decode error names its cause: a resource refusal and an invalid
/// input as their own errors do.
#[test]
fn decode_errors_name_their_cause() {
    let cases: [(DecodeError<LimitRefusal>, String); 5] = [
        (
            DecodeError::Resource(BoundedError::Allocation { bytes: 5 }),
            "an allocation of 5 bytes failed".into(),
        ),
        (
            DecodeError::Resource(BoundedError::Refused(LimitRefusal::Work)),
            "bounded encoding refused: work limit".into(),
        ),
        (
            DecodeError::Invalid(Error::WrongType),
            Error::WrongType.to_string(),
        ),
        (
            DecodeError::DepthLimit { limit: 3 },
            "decoding exceeds nesting limit 3".into(),
        ),
        (
            DecodeError::UnprovenText,
            "text not proven NFC by the quick check is refused by this decoding".into(),
        ),
    ];
    for (error, text) in cases {
        assert_eq!(error.to_string(), text, "{error:?}");
    }
}

/// `value` decoded as `T` by the typed decoder, everything it held released.
fn typed<T: Transferable<Limits> + Copy + 'static>(
    value: CBOR,
) -> Result<T, DecodeError<LimitRefusal>> {
    let wire = value.to_cbor_data();
    let mut limits = Limits::unlimited();
    let decoded = decode_typed::<T, _>(&wire, 0, &mut limits).map(|typed| *typed.value());
    assert_eq!(limits.live_bytes(), 0);
    decoded
}

/// Integers decode within their type's range and are refused outside it;
/// floats decode from a float or an integer the target represents exactly,
/// and are refused otherwise, as their symbolic conversions do.
#[test]
fn typed_numbers_decode_within_their_types_range() {
    assert!(matches!(typed::<u8>(CBOR::from(255)), Ok(255)));
    assert!(matches!(
        typed::<u8>(CBOR::from(256)),
        Err(DecodeError::Invalid(Error::OutOfRange))
    ));
    assert!(matches!(
        typed::<i8>(CBOR::from(-129)),
        Err(DecodeError::Invalid(Error::OutOfRange))
    ));
    assert!(matches!(typed::<f64>(CBOR::from(1.5)), Ok(1.5)));
    assert!(matches!(typed::<f64>(CBOR::from(3)), Ok(3.0)));
    assert!(matches!(typed::<f64>(CBOR::from(-2)), Ok(-2.0)));
    assert!(matches!(typed::<f32>(CBOR::from(1.5)), Ok(1.5)));
    // 2^24 + 1 and 0.1 have no exact single-precision value.
    assert!(matches!(
        typed::<f32>(CBOR::from(16_777_217)),
        Err(DecodeError::Invalid(Error::OutOfRange))
    ));
    assert!(matches!(
        typed::<f32>(CBOR::from(0.1)),
        Err(DecodeError::Invalid(Error::OutOfRange))
    ));
    assert!(matches!(
        typed::<f64>(CBOR::from("x")),
        Err(DecodeError::Invalid(Error::WrongType))
    ));
}

/// `wire`, a text, copied into `owner`'s scope, decoded and its encoding
/// prepared owned; and the turns its record's in-place cleanup can take:
/// the preparation's, which its owned bound covers, then the source value's,
/// which the value's decode bound covers (`owned_prepare_bound`: the source
/// is accounted by its decode), with the copied input it holds, which the
/// copy's own bound covers. A writer reclaims through the same record. Or a
/// driver's stop as the run's finding.
struct PlanCase<'v> {
    owner: &'v DecodeOwner<'static, Limits>,
    policy: PolicyId,
    scope_bytes: u64,
    cleanup: usize,
}

fn planned<R>(
    wire: &[u8],
    body: impl FnOnce(
        &mut Holding<'_, '_, OwnedPrepared<'static, ByteString, String, Limits>, Unwitnessed>,
        PlanCase<'_>,
    ) -> Result<R, Finding>,
) -> R {
    support::recorded_run(|run| {
        let policy = run.policy(u64::MAX);
        let result = run.scoped(policy, &Unwitnessed, |owner| {
            let scope_bytes = owner.with_policy(policy, |_, m| m.live_bytes());
            owner.lending(Retirement::Exhausted, Lent::new, |view| {
                let owner = view.value().get();
                view.copied(policy, wire, |input| {
                    input.decode::<String, _>(policy, Options::quick_only(8), |value| {
                        let prepared = support::turns(
                            owned_prepare_bound::<ByteString, String, Limits, ()>(support::shape(
                                value.value().value(),
                            ))
                            .expect("the owned preparation bound fits in u64"),
                        );
                        let copied = support::turns(
                            dcbor::bounded::decode::construction::copy_bound::<Limits, ()>(
                                wire.len() as u64,
                            )
                            .expect("the copy bound fits in u64"),
                        );
                        value.prepare(policy, |plan| {
                            plan.holding(Lent::new(owner), Retirement::Exhausted, |queue| {
                                queue.quiesce(policy)
                            })?;
                            assert!(owner.outstanding() > 0, "the plan holds no record");
                            body(
                                plan,
                                PlanCase {
                                    owner,
                                    policy,
                                    scope_bytes,
                                    cleanup: prepared
                                        + support::typed_turns::<String>(wire.len())
                                        + copied,
                                },
                            )
                        })?
                    })?
                })?
            })
        })?;
        run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0));
        Ok(result)
    })
}

/// An emptied slot's step reports `Done`, admitting the completion it
/// reports.
fn emptied<W>(m: &mut Limits, slot: &mut Reclaiming<W>) {
    assert!(slot.value().is_none());
    let attempts = m.attempts();
    assert!(matches!(slot.probe_empty(m), Ok(Reclaimed::Done)));
    assert_eq!(m.attempts(), attempts + 1);
}

/// An owned plan reclaimed in place releases its record and the value it
/// encodes, every record its handle held, before the scope is shut down;
/// the scope then holds only itself.
#[test]
fn an_owned_plan_reclaimed_in_place_releases_its_record_and_source() {
    let wire = CBOR::from("an owned plan").to_cbor_data();
    planned(&wire, |plan, case| {
        assert_eq!(plan.value().len(), wire.len());
        assert!(!plan.value().is_empty());
        plan.transfer(
            |plan| Reclaiming::new(plan, OwnedPrepared::reclaim_step),
            Retirement::Stopped,
            |cleanup| {
                cleanup.reclaim(case.policy, case.cleanup, |_| {})?;
                assert_eq!(case.owner.outstanding(), 0, "a record outlived cleanup");
                cleanup.with_policy(case.policy, |slot, m| {
                    assert_eq!(
                        m.live_bytes(),
                        case.scope_bytes,
                        "the plan or its source outlived cleanup"
                    );
                    emptied(m, slot);
                });
                Ok(())
            },
        )
    });
}

/// A writer reclaimed in place partway through its emission keeps its
/// emission position on every step of the cleanup, then releases its plan
/// and the value it encodes, every record its handle held, before the scope
/// is shut down.
#[test]
fn a_writer_reclaimed_in_place_keeps_its_emission_position() {
    let wire = CBOR::from("w".repeat(100).as_str()).to_cbor_data();
    planned(&wire, |plan, case| {
        plan.transfer(
            OwnedPrepared::into_writer,
            Retirement::Published,
            |writer| {
                let mut bytes = Vec::with_capacity(wire.len());
                assert!(!writer.emit(case.policy, &mut bytes, wire.len(), |_, _, at| at == 1)?);
                assert_eq!(bytes, wire[..64]);
                let at = writer.value().position().emission;
                assert_eq!((at.written, at.finished), (64, false));
                writer.transfer(
                    |writer| Reclaiming::new(writer, OwnedWriter::reclaim_step),
                    Retirement::Stopped,
                    |cleanup| {
                        cleanup.reclaim(case.policy, case.cleanup, |writer| {
                            assert_eq!(
                                writer.position().emission,
                                at,
                                "cleanup moved the emission"
                            );
                        })?;
                        assert_eq!(case.owner.outstanding(), 0, "a record outlived cleanup");
                        cleanup.with_policy(case.policy, |slot, m| {
                            assert_eq!(
                                m.live_bytes(),
                                case.scope_bytes,
                                "the plan or its source outlived cleanup"
                            );
                            emptied(m, slot);
                        });
                        Ok(())
                    },
                )
            },
        )
    });
}
