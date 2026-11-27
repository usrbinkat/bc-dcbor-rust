#![cfg(feature = "std")]

// The observed construction driver witnesses physical storage.
#[global_allocator]
static HEAP: support::heap::Heap = support::heap::Heap;

use dcbor_test_support as support;

#[cfg(feature = "derive")]
#[path = "reclamation/schema.rs"]
mod schema;

#[path = "reclamation/parser.rs"]
mod parser;

#[path = "reclamation/destination.rs"]
mod destination;

#[path = "reclamation/scoped.rs"]
mod scoped;

use dcbor::ByteString;
use dcbor::bounded::decode::construction::in_place::{Transferable, admit};
use dcbor::bounded::decode::construction::reclamation::{
    Cleanup, Custody, PeekSlot, Reclaim, Reclaimed, Slot,
};
use dcbor::bounded::decode::construction::{
    Acquisition, Construction, DecodeOwner, OwnedRecord, TypedValue,
};
use dcbor::bounded::decode::{DecodeError, Options};
use dcbor::bounded::{
    BoundedError, BoundedResult, Budget, CustodySink, Limits, PermitsObserved, Releasing, Step,
};
use std::cell::Cell;
use support::{CustodyBatch, Finding, Lent, Retirement, Stopped, pipeline::Unwitnessed};

thread_local! {
    static CLEANED: Cell<usize> = const { Cell::new(0) };
    static DROPPED: Cell<usize> = const { Cell::new(0) };
}

/// An operation reports the scope's outstanding records exactly as the
/// scope's authority counts them (`ScopeRef::outstanding` against
/// `DecodeOwner::position`, two paths to one count), while it retains the
/// scope; publication transfers that reference to the output and the
/// exhausted operation reports zero. The authority reports the scope
/// closed from the moment shutdown closes its queue, before shutdown can
/// complete, a published value still live. The value is held beside the
/// scope, outside it, so the scope is shut down exclusively while it lives.
#[test]
fn an_operation_reports_the_scope_count_and_a_closing_scope_reports_closed() {
    let wire = [0x82, 0x01, 0x02];
    support::recorded_run(|run| {
        let policy = run.policy(u64::MAX);
        let (reported, open, closing, closed) = run.holding(
            CustodyBatch::<TypedValue<'static, ByteString, Vec<u64>, Limits>>::slots(1),
            Retirement::Exhausted,
            &Unwitnessed,
            |values| {
                values.lending(Retirement::Exhausted, Lent::new, |lent| {
                    let values = lent.value().get();
                    lent.holding(DecodeOwner::new(), Retirement::Scope, |owner| {
                        owner.initialize(policy)?;
                        let reported =
                            owner.lending(Retirement::Exhausted, Lent::new, |view| {
                                let scope = view.value().get();
                                view.copied(policy, &wire, |input| {
                                    input.parse(policy, Options::normalizing(8), |document| {
                                        document.transfer(
                                            Construction::<_, Vec<u64>, Limits>::construct,
                                            Retirement::Stopped,
                                            |operation| {
                                                let mut reported = Vec::new();
                                                operation.drive_observed(
                                                    policy,
                                                    support::typed_turns::<Vec<u64>>(wire.len()),
                                                    Retirement::Published,
                                                    |_, operation| {
                                                        let position = operation.position();
                                                        let outstanding = position.outstanding;
                                                        assert_eq!(
                                                            outstanding,
                                                            if position.finished {
                                                                0
                                                            } else {
                                                                scope.outstanding()
                                                            },
                                                            "the operation's count against the \
                                                         authority's"
                                                        );
                                                        reported.push(outstanding);
                                                    },
                                                    |value| {
                                                        assert_eq!(value.value().value(), &[1, 2]);
                                                        value.deposit(values, 0);
                                                    },
                                                )?;
                                                Ok::<_, Finding>(reported)
                                            },
                                        )
                                    })
                                })
                            })???;
                        // The value holds its record and a scope reference,
                        // so shutdown can only close the queue and wait.
                        let (open, closing, closed) = owner.with_policy(policy, |owner, m| {
                            let open = !owner.position().closed;
                            m.fresh();
                            let closing = owner.shutdown_step(m);
                            (open, closing, owner.position().closed)
                        });
                        owner.drawn(values, 0, Retirement::Published, |_| ());
                        owner.drain(policy)?;
                        Ok::<_, Finding>((reported, open, closing, closed))
                    })
                })
            },
        )?;
        assert!(
            reported.iter().any(|count| *count >= 2),
            "no step had more than one record live: {reported:?}"
        );
        assert!(open, "a scope closed before shutdown");
        assert_ne!(
            closing.map_err(support::failed("the closing shutdown step"))?,
            Reclaimed::Done
        );
        assert!(
            closed,
            "a scope whose shutdown closed its queue reports open"
        );
        run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0));
        Ok(())
    });
}

/// The operation's part of a class (`OperationClass`) on scopes holding a
/// record besides the operation's own, which no single pipeline reaches: a
/// parse whose record is allocated, its prefix still empty, has the detail
/// of one not yet allocated (`Parsed::detail` reads only the held input
/// until its prefix completes), so whether its record is allocated is the
/// one fact separating them, while the allocated one's cleanup also
/// releases its record. Each member's scope holds the same number of
/// records, its queue drained: an unallocated parse beside another live
/// input, and an allocated one whose other input was dropped and drained.
/// A third member, the allocated parse beside the live input, holds one
/// record more and cleans up as the second does: the scope's other records
/// are no part of the operation's cleanup, nor of its class.
#[test]
fn an_operation_class_separates_its_record_from_the_scopes_other_records() {
    use dcbor::bounded::decode::construction::{DocumentDecoder, OwnedInitialized};
    type Copied = <ByteString as Reclaim<Limits>>::State;
    static WIRE: [u8; 3] = [0x82, 0x01, 0x02];
    static OTHER: [u8; 1] = [0x00];
    /// Calls any loop of a member takes at most.
    const CALLS: usize = 256;
    fn copied(
        owner: &DecodeOwner<'static, Limits>,
        a: &mut Limits,
        wire: &'static [u8],
    ) -> OwnedInitialized<'static, ByteString, Limits> {
        let mut copy = owner.copy_input(wire);
        for _ in 0..CALLS {
            if let Step::Complete(input) = copy.step(a).expect("an unlimited copy") {
                return input;
            }
        }
        panic!("the copy did not publish");
    }
    let member = |allocated: bool, other_live: bool| {
        let what = format!("a parse, allocated {allocated}, another input live {other_live}");
        let mut a = Limits::unlimited();
        let mut owner = DecodeOwner::<'static, Limits>::new();
        owner.initialize_step(&mut a).expect("the scope");
        let input = copied(&owner, &mut a, &WIRE);
        let mut other = Some(copied(&owner, &mut a, &OTHER));
        let mut decoder = DocumentDecoder::parse(input, Options::normalizing(8));
        if allocated {
            assert!(
                matches!(decoder.step(&mut a), Ok(Step::Progress)),
                "{what}: the record's allocation"
            );
        }
        if !other_live {
            let held = owner.outstanding();
            drop(other.take());
            for _ in 0..CALLS {
                if owner.outstanding() < held {
                    break;
                }
                owner.step(&mut a).expect("an unlimited drain");
            }
            assert_eq!(owner.outstanding(), held - 1, "{what}: the drain");
        }
        let position = decoder.position();
        assert_eq!(position.allocated, allocated, "{what}");
        assert_eq!(position.initialized, 0, "{what}: a prefix written");
        let class = position.class::<Copied>();
        decoder.cancel();
        let (attempts, live) = (a.attempts(), a.live_bytes());
        let mut finished = false;
        for _ in 0..CALLS {
            if matches!(
                decoder.step(&mut a).expect("an unlimited cleanup"),
                Step::Finished
            ) {
                finished = true;
                break;
            }
        }
        assert!(finished, "{what}: the cleanup did not finish");
        let cleanup = (a.attempts() - attempts, live - a.live_bytes());
        drop((decoder, other));
        let mut done = false;
        for _ in 0..CALLS {
            if owner.shutdown_step(&mut a).expect("an unlimited shutdown") == Reclaimed::Done {
                done = true;
                break;
            }
        }
        assert!(done, "{what}: the scope did not shut down");
        assert_eq!(a.live_bytes(), 0, "{what}: storage kept");
        (what, position, class, cleanup)
    };
    let unallocated = member(false, true);
    let allocated = member(true, false);
    let beside = member(true, true);
    assert_eq!(
        (unallocated.1.outstanding, unallocated.1.queue),
        (allocated.1.outstanding, allocated.1.queue),
        "the scopes of the first two members differ"
    );
    assert_ne!(
        unallocated.3, allocated.3,
        "the allocated record's cleanup is the unallocated one's"
    );
    support::agree(
        "an operation beside the scope's other records",
        [unallocated, allocated, beside].map(|(what, _, class, cleanup)| (what, class, cleanup)),
    );
}

/// A built tree's cleanup never takes more calls than its state declares,
/// and the declaration falls by at least one with every call: it is the
/// most calls cleanup can still take, so no phase may declare more than the
/// phase before it left. Trees of no entry, one, a full leaf, and one and
/// two past it (a root over two leaves) take every cleanup phase: entering
/// cleanup, each entry's value, key and removal, the nodes, the arenas and
/// the metadata.
#[cfg(feature = "custom-std-collections")]
#[test]
fn a_tree_declares_no_less_cleanup_than_it_takes() {
    use std::collections::BTreeMap;
    for count in [0u64, 1, 11, 12, 13] {
        let mut symbolic = dcbor::Map::new();
        for n in 0..count {
            symbolic.insert(n, n).unwrap();
        }
        let wire = dcbor::CBOR::from(symbolic).to_cbor_data();
        support::recorded_run(|run| {
            let policy = run.policy(u64::MAX);
            let steps = support::turns(support::root_bound::<BTreeMap<u64, u64>>(&wire));
            run.standalone::<BTreeMap<u64, u64>, _, _>(policy, &wire, &Unwitnessed, |held| {
                assert!(
                    held.build_standalone(policy, steps, None, |_, _, _| {})?
                        .is_some(),
                    "a tree of {count} entries was not built"
                );
                let driver = held.value();
                assert_eq!(
                    driver.value().expect("a built tree is readable").len() as u64,
                    count
                );
                let first = driver
                    .remaining()
                    .expect("a tree's cleanup count fits in u64");
                let mut declared = first;
                let mut taken = 0u64;
                held.reclaim_standalone(policy, steps, |driver, _, reclaimed| {
            if matches!(reclaimed, Err(BoundedError::Refused(_))) {
                return;
            }
            taken += 1;
            assert!(
                taken <= first,
                "a tree of {count} entries took more than the {first} calls it declared"
            );
            match reclaimed {
                Ok(Reclaimed::Done) => return,
                Ok(Reclaimed::Progress) => {}
                other => panic!("unexpected tree cleanup: {other:?}"),
            }
            let next = driver
                .remaining()
                .expect("a tree's cleanup count fits in u64");
            assert!(
                next < declared,
                "a tree of {count} entries declared {next} calls after a call, from {declared}"
            );
            declared = next;
        })?;
                Ok(())
            })?;
            run.with_policy(policy, |m| {
                assert_eq!(m.live_bytes(), 0, "a tree of {count} entries left storage")
            });
            Ok(())
        });
    }
}

/// The fault matrix of constructing `T` from `wire`, parsing being setup
/// ([`support::refusal_matrix`]): every admission, each allocation request
/// among them, refused once in one run, which must attempt exactly the
/// admitted calls each twice in a row (ordinary turn exhaustion is witnessed
/// separately), so work admitted before a refused
/// allocation is retained and never admitted again; in the exhaustive layer
/// each refused in a run of its own; and a cancellation at every call. A
/// published value satisfies `inspect`; every reservation is recovered.
fn refused_allocations_conserve_work<T: Transferable<Limits> + 'static>(
    wire: &[u8],
    inspect: &dyn Fn(&T),
) {
    let name = format!(
        "construction of {} from {wire:02x?}",
        core::any::type_name::<T>()
    );
    let baseline = support::refusal_matrix(&name, support::rigor::rigor(), |fault| {
        support::recorded_run(|run| {
            let policy = run.policy(u64::MAX);
            let (calls, recorded, read) = run.scoped(policy, &Unwitnessed, |owner| {
                owner.copied(policy, wire, |input| {
                    input.parse(policy, Options::normalizing(8), |document| {
                        // Measure construction alone: parsing is setup.
                        document.with_policy(policy, |_, m| m.measure());
                        document.transfer(
                            Construction::<_, T, Limits>::construct,
                            Retirement::Stopped,
                            |operation| {
                                operation.drive_faulted(
                                    policy,
                                    support::typed_turns::<T>(wire.len()),
                                    Retirement::Published,
                                    fault,
                                    |_, _| {},
                                    |value| inspect(value.value().value()),
                                )?;
                                Ok::<_, Finding>(())
                            },
                        )
                    })
                })???;
                // Publication retires the publisher. Read its policy through
                // the surviving scope, before the scope's drain adds calls.
                // Both snapshots read the same unchanged history.
                Ok::<_, Finding>(owner.with_policy(policy, |_, m| {
                    (
                        support::RefusalRun::of(m),
                        support::RefusalRun::of(m),
                        m.calls().len(),
                    )
                }))
            })?;
            let (by, followed) = run.with_policy(policy, |m| {
                assert_eq!(m.live_bytes(), 0);
                (m.performer(), m.calls().len() - read)
            });
            // The run read in flight is the session's record of it, followed
            // by exactly the drain's calls.
            run.inspect_evidence(move |observed, _| recorded.recorded_in(observed, by, followed));
            Ok(calls)
        })
    });
    assert!(
        baseline
            .calls()
            .iter()
            .any(|call| matches!(call, dcbor::bounded::Call::Allocate(_))),
        "{name}: the fixture performs no allocation"
    );
}

#[test]
fn refused_allocations_conserve_construction_work() {
    use dcbor::bounded::decode::construction::in_place::StableOption;

    refused_allocations_conserve_work::<Option<u64>>(&[0x07], &|v| assert_eq!(*v, Some(7)));
    refused_allocations_conserve_work::<Option<u64>>(&[0xf6], &|v| assert_eq!(*v, None));
    refused_allocations_conserve_work::<Option<String>>(&[0x61, b'x'], &|v| {
        assert_eq!(v.as_deref(), Some("x"))
    });
    refused_allocations_conserve_work::<StableOption<u64, Limits>>(&[0x07], &|v| {
        assert_eq!(v.as_ref(), Some(&7))
    });
    refused_allocations_conserve_work::<StableOption<u64, Limits>>(&[0xf6], &|v| {
        assert!(!v.is_some())
    });
    refused_allocations_conserve_work::<String>(&[0x61, b'x'], &|v| assert_eq!(v, "x"));
    // [[1, 24], [], [256]]
    refused_allocations_conserve_work::<Vec<Vec<u64>>>(
        &[0x83, 0x82, 0x01, 0x18, 0x18, 0x80, 0x81, 0x19, 0x01, 0x00],
        &|v| assert_eq!(v, &[vec![1, 24], vec![], vec![256]]),
    );
    // Fixed arrays build each element in the destination's own slot.
    refused_allocations_conserve_work::<[u64; 3]>(
        &[0x83, 0x01, 0x18, 0x18, 0x19, 0x01, 0x00],
        &|v| assert_eq!(v, &[1, 24, 256]),
    );
    // [["a"], []]
    refused_allocations_conserve_work::<[Vec<String>; 2]>(&[0x82, 0x81, 0x61, b'a', 0x80], &|v| {
        assert_eq!(v, &[vec!["a".to_string()], vec![]])
    });
}

/// Every built-in construction is within its type's cost, built or failed:
/// scalars, byte buffers short and spanning several copy units, multibyte
/// text, vectors and nested vectors, fixed arrays of the right and wrong
/// lengths, native and stable optionals present and null, and nodes of the
/// wrong kind.
#[test]
fn every_built_in_construction_is_within_its_cost() {
    use dcbor::ByteString;
    use dcbor::bounded::decode::construction::in_place::StableOption;
    use support::{builds_within_cost as builds, rejects_within_cost as rejects};
    let text = |text: &str| dcbor::CBOR::from(text).to_cbor_data();
    let long = "x".repeat(1000);
    let multibyte = "\u{e9}\u{1f600}".repeat(100);
    builds::<u64>(&[0x19, 0x01, 0x00], |v| assert_eq!(*v, 256));
    rejects::<u8>(&[0x19, 0x01, 0x00]);
    builds::<i64>(&[0x38, 0x18], |v| assert_eq!(*v, -25));
    builds::<bool>(&[0xf5], |v| assert!(*v));
    builds::<f64>(&[0xf9, 0x3e, 0x00], |v| assert_eq!(*v, 1.5));
    rejects::<u64>(&[0x61, b'x']);
    for source in ["", "x", &long, &multibyte] {
        builds::<String>(&text(source), |v| assert_eq!(v, source));
    }
    rejects::<String>(&[0x41, 0x00]);
    let bytes = dcbor::CBOR::to_byte_string(vec![0x5a; 1000]).to_cbor_data();
    builds::<ByteString>(&bytes, |v| assert_eq!(v.data(), &[0x5a; 1000][..]));
    rejects::<ByteString>(&text("x"));
    let values: Vec<u64> = (0..300).collect();
    let numbers = dcbor::CBOR::from(values.clone()).to_cbor_data();
    builds::<Vec<u64>>(&numbers, |v| assert_eq!(v, &values));
    rejects::<Vec<String>>(&numbers);
    let sources = [long.clone(), multibyte.clone(), String::new()];
    let strings = dcbor::CBOR::from(sources.to_vec()).to_cbor_data();
    builds::<Vec<String>>(&strings, |v| assert_eq!(v, &sources));
    let nested = [0x83, 0x82, 0x01, 0x18, 0x18, 0x80, 0x81, 0x19, 0x01, 0x00];
    builds::<Vec<Vec<u64>>>(&nested, |v| {
        assert_eq!(v, &[vec![1, 24], vec![], vec![256]])
    });
    builds::<[String; 3]>(&strings, |v| assert_eq!(v, &sources));
    rejects::<[String; 2]>(&strings);
    builds::<Option<String>>(&text(&long), |v| {
        assert_eq!(v.as_deref(), Some(long.as_str()))
    });
    builds::<Option<String>>(&[0xf6], |v| assert_eq!(*v, None));
    builds::<StableOption<Vec<u64>, Limits>>(&numbers, |v| assert_eq!(v.as_ref(), Some(&values)));
    builds::<StableOption<Vec<u64>, Limits>>(&[0xf6], |v| assert!(!v.is_some()));
    rejects::<StableOption<Vec<u64>, Limits>>(&text("x"));
}

/// Every reducing built-in binding's declared cleanup reduction is a
/// simulation of cleanup on every state its construction reaches, cancelled
/// at each build step ([`support::certified`]), and every transition those
/// constructions and cleanups take is in the binding's successor relations,
/// with exactly the cleanup they bound ([`support::legal`]): byte buffers
/// empty, within one copy unit, across copy units and of multibyte text;
/// native options of a scalar and of text, present and null; stable options
/// of a scalar and of text, present and null; and a rejection at each
/// binding's own inspection. The evidence is these fixtures' reached states,
/// each binding's argument for its reduction stated at its definition.
#[test]
fn every_reducing_binding_is_certified_and_its_transitions_legal() {
    use dcbor::ByteString;
    use dcbor::bounded::decode::construction::in_place::StableOption;
    use support::legality::{buffer, optional, stable_option, written};
    use support::{certified, legal};
    let text = |text: &str| dcbor::CBOR::from(text).to_cbor_data();
    let long = "x".repeat(65);
    let multibyte = "\u{e9}\u{1f600}".repeat(20);
    let bytes = dcbor::CBOR::to_byte_string(vec![0x5a; 70]).to_cbor_data();
    let texts = [text(""), text("x"), text(&long), text(&multibyte)];
    for wire in &texts {
        let name = format!("String from {wire:02x?}");
        legal(&name, &certified::<String>(&name, wire), &buffer());
    }
    let mistyped = text("x");
    for wire in [&[0x40][..], bytes.as_slice(), mistyped.as_slice()] {
        let name = format!("ByteString from {wire:02x?}");
        legal(&name, &certified::<ByteString>(&name, wire), &buffer());
    }
    // A text, an integer and a byte string where a text is expected: each
    // rejected by the payload's own inspection.
    for wire in [
        &[0xf6][..],
        texts[1].as_slice(),
        texts[2].as_slice(),
        &[0x41, 0x00],
    ] {
        let name = format!("Option<String> from {wire:02x?}");
        legal(
            &name,
            &certified::<Option<String>>(&name, wire),
            &optional(buffer()),
        );
    }
    for wire in [&[0x07][..], &[0xf6], texts[1].as_slice()] {
        let name = format!("Option<u64> from {wire:02x?}");
        legal(
            &name,
            &certified::<Option<u64>>(&name, wire),
            &optional(written()),
        );
    }
    for wire in [&[0xf6][..], texts[2].as_slice(), &[0x07]] {
        let name = format!("StableOption<String> from {wire:02x?}");
        legal(
            &name,
            &certified::<StableOption<String, Limits>>(&name, wire),
            &stable_option(buffer()),
        );
    }
    for wire in [&[0x07][..], &[0xf6], texts[1].as_slice()] {
        let name = format!("StableOption<u64> from {wire:02x?}");
        legal(
            &name,
            &certified::<StableOption<u64, Limits>>(&name, wire),
            &stable_option(written()),
        );
    }
}

/// A checked text's construction (one engine, its rules
/// [`dcbor::StabilizedText`]'s and [`dcbor::AsciiText`]'s): its declared
/// reduction, the text's, and its complete class are certified on every
/// state it reaches ([`support::uniform`]), and every transition is in its
/// successor relations, the check's then the text's
/// ([`support::legality::checked`]); each `accepted` text is built, and each
/// `refused` one and an integer where a text is expected are refused, within
/// the cost. A refused text is dCBOR text: only the type's rule refuses it,
/// by `refusal`'s variant naming the expected code point.
fn checked_text_is_certified<T>(
    type_name: &str,
    text_of: fn(&T) -> &str,
    accepted: &[&str],
    refused: &[(&str, u32)],
    refusal: fn(&dcbor::Error) -> Option<u32>,
) where
    T: dcbor::bounded::decode::construction::in_place::Transferable<Limits> + 'static,
    T::State: dcbor::bounded::decode::construction::Uniform
        + dcbor::bounded::decode::construction::reclamation::Custody<
            Observation = dcbor::bounded::decode::construction::in_place::CheckedObservation,
        >,
{
    use support::legality::checked;
    use support::{builds_within_cost, certified, legal, rejects_within_cost, uniform};
    let text = |text: &str| dcbor::CBOR::from(text).to_cbor_data();
    for source in accepted {
        let wire = text(source);
        let name = format!("{type_name} from {wire:02x?}");
        legal(&name, &uniform::<T>(&name, &wire), &checked());
        builds_within_cost::<T>(&wire, |v| assert_eq!(text_of(v), *source));
    }
    // Nothing completes from these, so the complete class has no member to
    // check: the reduction alone is certified.
    let mut rejected: Vec<Vec<u8>> = refused.iter().map(|(source, _)| text(source)).collect();
    rejected.push(vec![0x07]);
    for wire in &rejected {
        let name = format!("{type_name} from {wire:02x?}");
        legal(&name, &certified::<T>(&name, wire), &checked());
        rejects_within_cost::<T>(wire);
    }
    for &(source, point) in refused {
        let wire = text(source);
        assert_eq!(
            String::try_from(dcbor::CBOR::try_from_data(&wire).unwrap()).unwrap(),
            source,
            "{source:?} is not dCBOR text"
        );
        let built = constructed::<T>(
            &wire,
            Discipline::Admitted,
            |error| matches!(error, DecodeError::Invalid(error) if refusal(error) == Some(point)),
            |_| {},
        );
        assert!(!built, "{source:?} was built as a {type_name}");
    }
}

/// [`checked_text_is_certified`] under the stabilized-text rule. Texts:
/// empty, one byte, across a copy unit, of multibyte scalars, an assigned
/// code point of the pinned version (U+1FA8A TROMBONE, `DerivedAge.txt`
/// line 2106); refused: an unassigned one (U+0378).
#[test]
fn a_stabilized_text_is_certified_its_transitions_legal_and_within_its_cost() {
    use dcbor::{Error, StabilizedText};
    let long = "x".repeat(65);
    let multibyte = "\u{e9}\u{1f600}".repeat(20);
    checked_text_is_certified::<StabilizedText>(
        "StabilizedText",
        StabilizedText::as_str,
        &["", "x", &long, &multibyte, "\u{1fa8a}"],
        &[("\u{378}", 0x378)],
        |error| match error {
            Error::UnassignedCodePoint(point) => Some(*point),
            _ => None,
        },
    );
}

/// [`checked_text_is_certified`] under the ASCII rule. Texts: empty, one
/// byte, across a copy unit, both edges of the range (U+0000, U+007F)
/// across copy units; refused: the first code point past the range
/// (U+0080) after ASCII bytes, and a two-byte scalar the NFC quick check
/// proves (U+00E9), which the quick-only wire profile admits and only the
/// rule refuses.
#[test]
fn an_ascii_text_is_certified_its_transitions_legal_and_within_its_cost() {
    use dcbor::{AsciiText, Error};
    let long = "x".repeat(65);
    let edges = "\u{0}\u{7f}".repeat(40);
    checked_text_is_certified::<AsciiText>(
        "AsciiText",
        AsciiText::as_str,
        &["", "x", &long, &edges],
        &[("ab\u{80}", 0x80), ("\u{e9}", 0xE9)],
        |error| match error {
            Error::NonAsciiText(point) => Some(*point),
            _ => None,
        },
    );
}

/// A fixed-length byte string's construction ([`dcbor::FixedBytes`]): its
/// declared reduction and complete class are certified on every state it
/// reaches ([`support::uniform`]), every transition is in its successor
/// relations ([`support::legality::fixed`]), and it is built within its
/// cost. Lengths: empty, one byte, within one copy unit, exactly one
/// quantum, one past it, across several units. Refused, certified and
/// within its cost, its refusal's custody released: a byte string one byte
/// short and one byte long, each naming both lengths, and a text of the
/// type's length, the wrong type.
#[test]
fn a_fixed_byte_string_is_certified_its_transitions_legal_and_within_its_cost() {
    use dcbor::{Error, FixedBytes};
    use support::legality::fixed;
    use support::{builds_within_cost, certified, legal, rejects_within_cost, uniform};
    fn lengths<const N: usize>() {
        let source: [u8; N] = core::array::from_fn(|at| at as u8);
        let wire = dcbor::CBOR::to_byte_string(source).to_cbor_data();
        let name = format!("FixedBytes<{N}> from {N} bytes");
        legal(&name, &uniform::<FixedBytes<N>>(&name, &wire), &fixed());
        builds_within_cost::<FixedBytes<N>>(&wire, |v| assert_eq!(v.as_array(), &source));
        for wrong in [N.checked_sub(1), Some(N + 1)].into_iter().flatten() {
            let wire = dcbor::CBOR::to_byte_string(vec![1u8; wrong]).to_cbor_data();
            let name = format!("FixedBytes<{N}> from {wrong} bytes");
            legal(&name, &certified::<FixedBytes<N>>(&name, &wire), &fixed());
            rejects_within_cost::<FixedBytes<N>>(&wire);
            let built = constructed::<FixedBytes<N>>(
                &wire,
                Discipline::Admitted,
                |error| {
                    matches!(
                        error,
                        DecodeError::Invalid(Error::WrongLength { expected, actual })
                            if *expected == N && *actual == wrong
                    )
                },
                |_| {},
            );
            assert!(!built, "{name}: built");
        }
        let text = dcbor::CBOR::from("x".repeat(N).as_str()).to_cbor_data();
        let name = format!("FixedBytes<{N}> from a text of {N} bytes");
        legal(&name, &certified::<FixedBytes<N>>(&name, &text), &fixed());
        rejects_within_cost::<FixedBytes<N>>(&text);
    }
    lengths::<0>();
    lengths::<1>();
    lengths::<32>();
    lengths::<64>();
    lengths::<65>();
    lengths::<200>();
}

/// A fixed-length byte string copies each byte exactly once, in units of at
/// most a quantum, each admitted before it is copied, and allocates
/// nothing; a refusal of its length is one admitted unit. The units are
/// derived here by hand from the rule, not from the binding: at the root
/// its session's bind unit (1, 0), then the copies, then the session's
/// begin-cleanup unit (1, 0) and the one cleanup unit (1, 0). The copies:
/// one of no bytes for the empty type; one of 32; one of 64; 64 and 1 for
/// 65; 64, 64 and 2 for 130. The refusal of 129 bytes where 130 are fixed:
/// one unit of one value and no bytes. The copy's charge witness: a copy
/// that wrote bytes without admitting them fails here.
#[test]
fn a_fixed_byte_string_copies_every_byte_once_and_allocates_nothing() {
    use dcbor::FixedBytes;
    use dcbor::bounded::WriteWork;
    fn charged<const N: usize>(copies: u64) {
        let source = [0x5au8; N];
        let wire = dcbor::CBOR::to_byte_string(source).to_cbor_data();
        let built = support::construction::<FixedBytes<N>>(&wire, None, |v| {
            assert_eq!(v.as_array(), &source)
        });
        assert!(built.built, "FixedBytes<{N}> was not built");
        assert!(
            built.allocations.is_empty(),
            "FixedBytes<{N}> allocated {:?}",
            built.allocations
        );
        assert_eq!(
            built.used,
            WriteWork::new(3 + copies, N as u64),
            "FixedBytes<{N}>: the bind, {copies} copies of {N} bytes, the begin-cleanup \
             unit, then one cleanup unit"
        );
    }
    charged::<0>(1);
    charged::<32>(1);
    charged::<64>(1);
    charged::<65>(2);
    charged::<130>(3);
    let wire = dcbor::CBOR::to_byte_string([0x5au8; 129]).to_cbor_data();
    let refused = support::construction::<FixedBytes<130>>(&wire, None, |_| {});
    assert!(refused.rejected && !refused.built);
    assert!(refused.allocations.is_empty());
    assert_eq!(
        refused.used,
        WriteWork::new(4, 0),
        "the bind, the one refusing unit, the begin-cleanup unit, then one cleanup unit"
    );
}

/// How [`constructed`] schedules a construction's turns and its cleanup's.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Discipline {
    /// Every turn admitted as it comes.
    Admitted,
    /// Every turn's next admission first refused once, checked to move,
    /// charge and release nothing ([`support::Holding::repeated`]); the
    /// cleanup after a refusal under every admission refused once
    /// ([`support::pipeline::Refusal::Each`]). The run must have refused.
    RefusedFirst,
}

/// `T` constructed from the document of `wire` in a scope of a recorded run,
/// within its construction's bound, scheduled by `discipline`: published,
/// the held value given to `inspect` and retired as a published handle,
/// which releases nothing (`true`); or refused with an error `refused`
/// accepts, its own cleanup then run to `Finished` within the same bound,
/// the scope holding no record afterwards (`false`). Either way the scope
/// drains to nothing. Any other stop is the run's finding.
fn constructed<T>(
    wire: &[u8],
    discipline: Discipline,
    refused: impl Fn(&support::DecodeFailure) -> bool,
    inspect: impl FnOnce(&TypedValue<'static, ByteString, T, Limits>),
) -> bool
where
    T: dcbor::bounded::decode::construction::in_place::Transferable<Limits> + 'static,
{
    let turns = support::typed_turns::<T>(wire.len());
    support::recorded_run(|run| {
        let policy = run.policy(u64::MAX);
        let refusals = run.with_policy(policy, |m| m.refusals());
        let built = run.scoped(policy, &Unwitnessed, |owner| {
            owner.lending(Retirement::Exhausted, Lent::new, |view| {
                let scope = view.value().get();
                view.copied(policy, wire, |input| {
                    input.parse(policy, Options::normalizing(8), |document| {
                        document.transfer(
                            Construction::<_, T, Limits>::construct,
                            Retirement::Stopped,
                            |operation| {
                                let consume = |value: &mut support::Holding<'_, '_, _, _>| {
                                    inspect(value.value())
                                };
                                let driven = match discipline {
                                    Discipline::Admitted => operation.drive(
                                        policy,
                                        turns,
                                        Retirement::Published,
                                        consume,
                                    ),
                                    Discipline::RefusedFirst => operation.repeated(
                                        policy,
                                        turns,
                                        Retirement::Published,
                                        1,
                                        |_, _| {},
                                        consume,
                                    ),
                                };
                                match driven {
                                    Ok(()) => Ok(true),
                                    Err(Stopped::Operation(error)) if refused(&error) => {
                                        if discipline == Discipline::RefusedFirst {
                                            operation.with_policy(policy, |_, m| {
                                                support::refuse(
                                                    m,
                                                    support::pipeline::Refusal::Each,
                                                );
                                            });
                                        }
                                        operation.finish(policy, turns, Retirement::Published)?;
                                        operation.with_policy(policy, |_, m| {
                                            m.fail_call(None);
                                            m.clear_refusal();
                                        });
                                        if scope.outstanding() != 0 {
                                            return Err(Finding::Defect(format!(
                                                "a refused {} kept {} records",
                                                core::any::type_name::<T>(),
                                                scope.outstanding()
                                            )));
                                        }
                                        Ok(false)
                                    }
                                    Err(stop) => Err(Finding::Driver(format!(
                                        "{} from {wire:02x?} stopped as {stop:?}",
                                        core::any::type_name::<T>()
                                    ))),
                                }
                            },
                        )
                    })
                })
            })??
        })?;
        run.with_policy(policy, |m| {
            assert_eq!(m.live_bytes(), 0);
            if discipline == Discipline::RefusedFirst {
                assert!(m.refusals() > refusals, "no admission was refused");
            }
        });
        Ok(built)
    })
}

/// A checked text checks every byte of its text exactly once, in windows of
/// at most a quantum ending on a scalar, before anything is allocated: its
/// construction admits exactly a `String`'s, and one unit of one value and
/// the window's bytes per window more. Each case's windows, `(values,
/// bytes)`, are derived by hand from the rule, not from the binding.
/// `refused`, a two-byte text the rule refuses, admits its one window and
/// allocates nothing; its cleanup is the one unit of a buffer with nothing
/// installed, one value. Built at the root, its session adds its bind and
/// begin-cleanup units, one value each (`SESSION_COST`), which the
/// comparisons with a `String` cancel. The check's charge witness: a check
/// that inspected a window without admitting it fails here.
fn checked_text_checks_every_byte_once<T>(
    text_of: fn(&T) -> &str,
    cases: &[(String, (u64, u64))],
    refused: &str,
) where
    T: dcbor::bounded::decode::construction::in_place::InPlace<Limits>,
{
    use dcbor::bounded::WriteWork;
    for (source, (values, bytes)) in cases {
        let wire = dcbor::CBOR::from(source.as_str()).to_cbor_data();
        let checked = support::construction::<T>(&wire, None, |v| assert_eq!(text_of(v), source));
        let text = support::construction::<String>(&wire, None, |v| assert_eq!(v, source));
        assert_eq!(
            WriteWork::new(
                checked.used.values - text.used.values,
                checked.used.bytes - text.used.bytes
            ),
            WriteWork::new(*values, *bytes),
            "the check of {} bytes",
            source.len()
        );
        assert_eq!(checked.allocations, text.allocations);
    }
    assert_eq!(refused.len(), 2, "the refused text is two bytes");
    let wire = dcbor::CBOR::from(refused).to_cbor_data();
    let refused = support::construction::<T>(&wire, None, |_| {});
    assert!(refused.rejected && !refused.built);
    assert!(
        refused.allocations.is_empty(),
        "a refused text allocated {:?}",
        refused.allocations
    );
    // The session's bind unit (1, 0), the one window of the text's two bytes
    // (1, 2), the session's begin-cleanup unit (1, 0), then the buffer's one
    // cleanup unit with nothing installed (1, 0).
    assert_eq!(
        refused.used,
        WriteWork::new(4, 2),
        "the bind, the one window of two bytes, the begin-cleanup unit, then one cleanup unit"
    );
}

/// [`checked_text_checks_every_byte_once`] under the stabilized-text rule:
/// none for the empty text; one of 4 bytes for U+1FA8A; 64, 64 and 2 for
/// 130 one-byte scalars; 64 and 16 for 40 two-byte ones; and, for one byte
/// then sixteen four-byte scalars, 61, the quantum backed off to the scalar
/// boundary below byte 64, then 4. Refused: U+0378, unassigned.
#[test]
fn a_stabilized_text_checks_every_byte_once_before_building() {
    use dcbor::StabilizedText;
    let backed_off = format!("x{}", "\u{1fa8a}".repeat(16));
    checked_text_checks_every_byte_once::<StabilizedText>(
        StabilizedText::as_str,
        &[
            (String::new(), (0, 0)),
            ("\u{1fa8a}".to_string(), (1, 4)),
            ("x".repeat(130), (3, 130)),
            ("\u{e9}".repeat(40), (2, 80)),
            (backed_off, (2, 65)),
        ],
        "\u{378}",
    );
}

/// [`checked_text_checks_every_byte_once`] under the ASCII rule: none for
/// the empty text; one of 1 byte for U+007F; 64, 64 and 2 for 130 one-byte
/// scalars; 64 exactly for 64, no window backed off, every ASCII scalar one
/// byte. Refused: U+00E9, not ASCII.
#[test]
fn an_ascii_text_checks_every_byte_once_before_building() {
    use dcbor::AsciiText;
    checked_text_checks_every_byte_once::<AsciiText>(
        AsciiText::as_str,
        &[
            (String::new(), (0, 0)),
            ("\u{7f}".to_string(), (1, 1)),
            ("x".repeat(130), (3, 130)),
            ("\u{0}".repeat(64), (1, 64)),
        ],
        "\u{e9}",
    );
}

/// A minimal big integer's construction ([`dcbor::MinimalBigInt`]): its
/// declared reduction, its magnitude's, and its complete class are certified
/// on every state it reaches ([`support::uniform`]), every transition is in
/// its successor relations, the sign's then the magnitude's
/// ([`support::legality::minimal_bigint`]), and it is built within its cost,
/// its value encoding back to the same bytes. Accepted: plain integers at
/// both edges of dCBOR's range, the least bignum of each sign, and a bignum
/// of 70 bytes, across copy units. Refused, each by the unit that writes the
/// sign, before the binding allocates anything of its own (the document is
/// parsed by the fixture, outside the measured construction): `c2 41 01` and
/// `c2 40` (plain values as
/// bignums), `c2 42 00 01` (a leading zero), the planted control's target
/// `c2 4a 00 01 00..` (a leading zero outside the range, refused by that rule
/// alone), another tag, and a text.
#[test]
fn a_minimal_big_integer_is_certified_its_transitions_legal_and_within_its_cost() {
    use dcbor::{Error, MinimalBigInt};
    use support::legality::minimal_bigint;
    use support::{builds_within_cost, certified, legal, rejects_within_cost, uniform};
    let wide = format!("c25846{}{}", "01", "00".repeat(69));
    let accepted = [
        "00",
        "01",
        "20",
        "1818",
        "1bffffffffffffffff",
        "3b7fffffffffffffff",
        "c3488000000000000000",
        "c249010000000000000000",
        "c349010000000000000000",
        wide.as_str(),
    ];
    for hex in accepted {
        let wire = hex::decode(hex).unwrap();
        let name = format!("MinimalBigInt from {hex}");
        legal(
            &name,
            &uniform::<MinimalBigInt>(&name, &wire),
            &minimal_bigint(),
        );
        builds_within_cost::<MinimalBigInt>(&wire, |v| {
            assert_eq!(dcbor::CBOR::from(v).to_cbor_data(), wire)
        });
    }
    let refused = [
        "c24101",
        "c240",
        "c2420001",
        "c24a00010000000000000000",
        "c34a00010000000000000000",
        "d82a4101",
        "6131",
    ];
    for hex in refused {
        let wire = hex::decode(hex).unwrap();
        let name = format!("MinimalBigInt from {hex}");
        let states = certified::<MinimalBigInt>(&name, &wire);
        assert!(
            states.iter().all(|state| state.allocations.is_empty()),
            "{name}: a refused encoding allocated"
        );
        legal(&name, &states, &minimal_bigint());
        rejects_within_cost::<MinimalBigInt>(&wire);
    }
    let built = constructed::<MinimalBigInt>(
        &hex::decode("c24101").unwrap(),
        Discipline::Admitted,
        |error| matches!(error, DecodeError::Invalid(Error::NonCanonicalNumeric)),
        |_| {},
    );
    assert!(!built, "c2 41 01 was built as a minimal big integer");
}

/// A container's observation counts its older children rather than holding
/// each whole (the sequence declares a reduction only over elements of a
/// uniform complete class, certified in `owned_pipeline_matrix.rs`; the
/// derived field map and enum and the B-tree declare none). Its observation
/// is still complete for custody:
/// on every state its construction reaches, two equal observations hold
/// equal live bytes and clean up identically, unit by unit
/// ([`support::observation`]); and every transition is in the sequence's
/// successor relations over its element's, with the remaining cleanup and
/// the witnessed allocations wherever the observation determines them
/// ([`support::legal`]). Vectors of text, of optional text present and null
/// (the case a container reduction would merge), of integers, nested
/// vectors, an empty vector, and fixed arrays, built and rejected.
#[test]
fn every_container_observation_is_complete_and_its_transitions_legal() {
    use support::legality::{buffer, optional, sequence, written};
    use support::{legal, observation};
    // ["a", "bc"]
    let strings = [0x82, 0x61, b'a', 0x62, b'b', b'c'];
    // ["a", null, "b"]
    let optionals = [0x83, 0x61, b'a', 0xf6, 0x61, b'b'];
    // [[1, 24], [], [256]]
    let nested = [0x83, 0x82, 0x01, 0x18, 0x18, 0x80, 0x81, 0x19, 0x01, 0x00];
    // [1, 24, 256]
    let integers = [0x83, 0x01, 0x18, 0x18, 0x19, 0x01, 0x00];
    let name = "Vec<String>";
    legal(
        name,
        &observation::<Vec<String>, _>(name, &strings, |o| *o),
        &sequence(buffer(), false),
    );
    let name = "Vec<Option<String>>";
    legal(
        name,
        &observation::<Vec<Option<String>>, _>(name, &optionals, |o| *o),
        &sequence(optional(buffer()), false),
    );
    let name = "Vec<Vec<u64>>";
    legal(
        name,
        &observation::<Vec<Vec<u64>>, _>(name, &nested, |o| *o),
        &sequence(sequence(written(), false), false),
    );
    let name = "Vec<u64>";
    legal(
        name,
        &observation::<Vec<u64>, _>(name, &integers, |o| *o),
        &sequence(written(), false),
    );
    let name = "empty Vec<String>";
    legal(
        name,
        &observation::<Vec<String>, _>(name, &[0x80], |o| *o),
        &sequence(buffer(), false),
    );
    let name = "[String; 2]";
    legal(
        name,
        &observation::<[String; 2], _>(name, &strings, |o| *o),
        &sequence(buffer(), true),
    );
    let name = "[u64; 3]";
    legal(
        name,
        &observation::<[u64; 3], _>(name, &integers, |o| *o),
        &sequence(written(), true),
    );
    // Three elements where two are declared: rejected at the inspection.
    let name = "[String; 2] of three";
    legal(
        name,
        &observation::<[String; 2], _>(name, &optionals, |o| *o),
        &sequence(buffer(), true),
    );
    // An element of the wrong kind: rejected after the first commit.
    let name = "Vec<String> with an integer";
    legal(
        name,
        &observation::<Vec<String>, _>(name, &[0x82, 0x61, b'a', 0x01], |o| *o),
        &sequence(buffer(), false),
    );
}

/// Properties over counts and lengths, each domain enumerated whole, each
/// member certified or checked complete and legal with its exact cleanup
/// and witnessed allocations: every text length from empty through three
/// copy units and one byte more, in one-byte scalars and in two-byte ones,
/// whose copies back off to a scalar boundary wherever a unit ends inside
/// one; every vector length through nine, of text whose lengths cycle
/// across a copy unit and of optional text alternating present and null;
/// and nested vectors of every shape up to three by three. The exhaustive
/// layer extends the text lengths to eight copy units and the vector
/// lengths to twenty-four.
#[test]
fn properties_hold_across_counts_and_lengths() {
    use dcbor::CBOR;
    use support::legality::{buffer, optional, sequence, written};
    use support::rigor::{Rigor, rigor};
    use support::{certified, legal, observation};
    let exhaustive = rigor() == Rigor::Exhaustive;
    let units = if exhaustive { 8 } else { 3 };
    for length in 0..=units * 64 + 1 {
        for source in ["x".repeat(length), "\u{e9}".repeat(length / 2)] {
            let name = format!("String of {} bytes", source.len());
            let wire = CBOR::from(source).to_cbor_data();
            legal(&name, &certified::<String>(&name, &wire), &buffer());
        }
    }
    let counts = if exhaustive { 24 } else { 9 };
    for count in 0..=counts {
        let texts: Vec<String> = (0..count).map(|n| "y".repeat((n * 37) % 130)).collect();
        let name = format!("Vec<String> of {count}");
        let wire = CBOR::from(texts).to_cbor_data();
        legal(
            &name,
            &observation::<Vec<String>, _>(&name, &wire, |o| *o),
            &sequence(buffer(), false),
        );
        let optionals: Vec<CBOR> = (0..count)
            .map(|n| {
                if n % 2 == 0 {
                    CBOR::from("z")
                } else {
                    CBOR::null()
                }
            })
            .collect();
        let name = format!("Vec<Option<String>> of {count}");
        let wire = CBOR::from(optionals).to_cbor_data();
        legal(
            &name,
            &observation::<Vec<Option<String>>, _>(&name, &wire, |o| *o),
            &sequence(optional(buffer()), false),
        );
    }
    for outer in 0..=3usize {
        for inner in 0..=3u64 {
            let nested: Vec<CBOR> = (0..outer)
                .map(|row| {
                    CBOR::from(
                        (0..inner)
                            .map(|n| n * 24 + row as u64)
                            .collect::<Vec<u64>>(),
                    )
                })
                .collect();
            let name = format!("Vec<Vec<u64>> of {outer} by {inner}");
            let wire = CBOR::from(nested).to_cbor_data();
            legal(
                &name,
                &observation::<Vec<Vec<u64>>, _>(&name, &wire, |o| *o),
                &sequence(sequence(written(), false), false),
            );
        }
    }
}

/// The text fixture every planted defect is put through: long enough to
/// cross a copy unit, so the payload is held over several states.
fn planted_text() -> Vec<u8> {
    dcbor::CBOR::from("x".repeat(65)).to_cbor_data()
}

/// A planted buffer reduction that drops whether the payload permit is
/// held merges states whose cleanup releases different bytes.
#[test]
#[should_panic(expected = "the class merges states of different custody")]
fn a_buffer_reduction_merging_payload_custody_is_rejected() {
    use dcbor::bounded::decode::construction::in_place::{BufferClass, stage_class};
    use dcbor::bounded::decode::construction::reclamation::Reduction;
    type State = <String as Reclaim<Limits>>::State;
    // The root session's class kept; the buffer's planted.
    support::simulation::<String, _>("planted buffer reduction", &planted_text(), |observation| {
        let buffer = match <State as Reduction>::class(&observation.inner) {
            BufferClass::Written { .. } => BufferClass::Written { payload: false },
            BufferClass::Freed { .. } => BufferClass::Freed { payload: false },
            class => class,
        };
        (stage_class(observation.stage), buffer)
    });
}

/// A planted optional reduction that merges a live payload with an idle
/// option merges states whose cleanup takes different units.
#[test]
#[should_panic(expected = "the class merges states of different custody")]
fn an_optional_reduction_merging_idle_and_live_payloads_is_rejected() {
    use dcbor::bounded::decode::construction::in_place::{OptionalClass, stage_class};
    use dcbor::bounded::decode::construction::reclamation::Reduction;
    type State = <Option<String> as Reclaim<Limits>>::State;
    // The root session's class kept; the option's planted.
    support::simulation::<Option<String>, _>(
        "planted optional reduction",
        &planted_text(),
        |observation| {
            let option = match <State as Reduction>::class(&observation.inner) {
                OptionalClass::Live(_) => OptionalClass::Idle,
                class => class,
            };
            (stage_class(observation.stage), option)
        },
    );
}

/// A planted observer reporting a stale phase, every held buffer as empty,
/// merges states whose next cleanup unit admits different work.
#[test]
#[should_panic(expected = "the class merges states of different custody")]
fn an_observation_reporting_a_stale_phase_is_rejected() {
    use dcbor::bounded::decode::construction::in_place::{
        BufferCustody, BufferObservation, BufferPhase,
    };
    // The root session's stage kept; the buffer's phase planted stale.
    support::observation::<String, _>("planted stale phase", &planted_text(), |observation| {
        let buffer = match observation.inner {
            BufferObservation::Held(custody) => BufferObservation::Held(BufferCustody {
                phase: BufferPhase::Empty,
                ..custody
            }),
            unallocated => unallocated,
        };
        (observation.stage, buffer)
    });
}

/// A planted claim that a freed buffer's allocation is still live, its
/// permit being kept: every transition and every permit is as the real
/// binding's, so only the heap observer's witness can catch it.
#[test]
#[should_panic(expected = "the live physical allocations witnessed differ")]
fn a_claim_of_a_freed_buffer_is_rejected_by_the_heap_witness() {
    use support::legality::{Legality, buffer};
    let real = buffer();
    let planted = Legality {
        physical: std::rc::Rc::clone(&real.permits),
        ..real
    };
    let name = "planted physical claim";
    support::legal(
        name,
        &support::certified::<String>(name, &planted_text()),
        &planted,
    );
}

/// A planted observer that never reports the payload permit leaves every
/// reached state distinct, so no completeness check can merge them; the
/// successor relation catches it, since a granted payload must appear.
#[test]
#[should_panic(expected = "is not in the binding's successor relation")]
fn an_observation_omitting_the_payload_permit_is_rejected() {
    use dcbor::bounded::decode::construction::in_place::{
        BufferCustody, BufferObservation, SessionObservation,
    };
    let name = "planted payload omission";
    let states: Vec<_> = support::certified::<String>(name, &planted_text())
        .into_iter()
        .map(|state| {
            // The root session's stage kept; the buffer's permit omitted.
            state.project(|observation| SessionObservation {
                stage: observation.stage,
                inner: match observation.inner {
                    BufferObservation::Held(custody) => BufferObservation::Held(BufferCustody {
                        payload: false,
                        ..custody
                    }),
                    unallocated => unallocated,
                },
            })
        })
        .collect();
    support::legal(name, &states, &support::legality::buffer());
}

#[test]
fn fixed_arrays_construct_in_place_and_reclaim_every_element() {
    // [[1, 2], [3, 24]], independently specified canonical bytes.
    let wire = [0x82, 0x82, 0x01, 0x02, 0x82, 0x03, 0x18, 0x18];
    let built = constructed::<[[u64; 2]; 2]>(
        &wire,
        Discipline::Admitted,
        |_| false,
        |output| {
            assert_eq!(output.value(), &[[1, 2], [3, 24]]);
            assert_eq!(output.bytes(), wire);
        },
    );
    assert!(built, "the fixed arrays were not built");
}

struct Payload([u8; 192]);
impl Drop for Payload {
    fn drop(&mut self) {
        DROPPED.set(DROPPED.get() + 1);
    }
}

/// A [`Payload`]'s state: the bytes of its prefix initialized.
struct PayloadState {
    initialized: usize,
}

/// The initialized prefix's bytes are the payload's whole custody.
impl Custody for PayloadState {
    type Observation = usize;

    fn observe(&mut self) -> usize {
        self.initialized
    }
}

// SAFETY: Payload owns no child allocations. The initialized byte prefix is
// tracked exactly; cleanup invalidates at most 64 bytes after admission, without
// reading uninitialized storage or invoking Payload's synchronous destructor.
unsafe impl Reclaim<Limits> for Payload {
    type State = PayloadState;
    const INITIAL: PayloadState = PayloadState { initialized: 0 };

    fn reclaim_step(
        mut slot: Slot<'_, Self, PayloadState>,
        cleanup: &mut Cleanup<'_, Limits>,
    ) -> BoundedResult<Reclaimed, Limits> {
        let state = slot.custody();
        let bytes = state.initialized.min(64);
        // The one admission route for a binding outside the crate.
        admit(cleanup, bytes)?;
        state.initialized -= bytes;
        CLEANED.set(CLEANED.get() + bytes);
        Ok(if state.initialized == 0 {
            Reclaimed::Done
        } else {
            Reclaimed::Progress
        })
    }

    /// One call per 64-byte chunk still initialized, and one for an empty
    /// prefix, whose call reports `Done` at once.
    fn remaining(mut slot: PeekSlot<'_, Self, PayloadState>) -> Option<u64> {
        Some((slot.custody().initialized.div_ceil(64) as u64).max(1))
    }

    /// Plain bytes: no permit of its own; the record's block is the
    /// record's to report.
    fn observe_permits(
        _: PeekSlot<'_, Self, PayloadState>,
        _: &mut dyn CustodySink<<Limits as Releasing>::Permit>,
    ) -> PermitsObserved {
        PermitsObserved::Complete
    }
}

/// `chunks` admitted 64-byte chunks of a held payload `record` initialized
/// under `m`: the address of its construction, zero when no chunk was
/// written.
fn fill(record: &mut OwnedRecord<'_, Payload, Limits>, m: &mut Limits, chunks: usize) -> usize {
    let mut construction_address = 0;
    for _ in 0..chunks {
        m.fresh();
        admit(m, 64).unwrap();
        let mut slot = record.destination();
        let (place, state) = slot.parts();
        let raw = place.as_ptr(state);
        construction_address = raw as usize;
        // SAFETY: byte-only payload; each admitted chunk initializes the
        // next prefix, within the payload's 192 bytes, and records it before
        // cancellation can occur.
        unsafe {
            raw.cast::<u8>()
                .add(state.initialized)
                .write_bytes(0x5a, 64);
        }
        state.initialized += 64;
    }
    construction_address
}

/// A payload record acquired in the scope `owner` holds, under `policy`,
/// `chunks` of it initialized ([`fill`]), for `body`, which holds it as a
/// published handle: retired to the scope's queue once `body` returns
/// unless `body` moves it on. The acquisition's stop is the run's finding.
fn payload<R>(
    owner: &mut support::Holding<'_, '_, DecodeOwner<'static, Limits>, Unwitnessed>,
    policy: support::PolicyId,
    chunks: usize,
    body: impl FnOnce(
        &mut support::Holding<'_, '_, OwnedRecord<'static, Payload, Limits>, Unwitnessed>,
        usize,
    ) -> R,
) -> Result<R, Finding> {
    owner.lending(Retirement::Exhausted, Lent::new, |view| {
        let scope = view.value().get();
        view.holding(
            Acquisition::<Payload, Limits>::new(),
            Retirement::Stopped,
            |acquisition| {
                acquisition.with_policy(policy, |_, m| m.fresh());
                acquisition.acquire(policy, scope, |record| {
                    let address = record.with_policy(policy, |record, m| fill(record, m, chunks));
                    body(record, address)
                })
            },
        )
    })
}

#[test]
fn stable_publication_and_every_cleanup_admission_refusal() {
    // Select and three 64-byte cleanup units may refuse. The last cleanup
    // unit also frees the record and scope using their prepaid admissions.
    support::stop_matrix(
        "published payload cleanup refusal boundaries",
        3,
        |refuse_at| {
            CLEANED.set(0);
            DROPPED.set(0);
            support::recorded_run(|run| {
                let policy = run.policy(u64::MAX);
                published_cleanup_under(run, policy, refuse_at)
            })
        },
    );
}

/// [`stable_publication_and_every_cleanup_admission_refusal`]'s run under
/// `policy` of `run`, cleanup unit `refuse_at` refused repeatedly first: the
/// payload published and retired to the queue, then the scope shut down by
/// the fixture's own schedule, its authority held by the run throughout.
/// The boundary valuations it reached, or a driver's stop as the run's
/// finding.
fn published_cleanup_under(
    run: &mut support::RecordedRun,
    policy: support::PolicyId,
    refuse_at: usize,
) -> Result<dcbor::bounded::boundary::Reached, Finding> {
    run.holding(
        DecodeOwner::new(),
        Retirement::Scope,
        &Unwitnessed,
        |owner| {
            owner.initialize(policy)?;
            let (construction_address, published_address) =
                payload(owner, policy, 3, |record, construction_address| {
                    record.transfer(
                        // SAFETY: all 192 bytes are initialized and tracked; no
                        // pointer escapes.
                        |record| unsafe { record.publish() },
                        Retirement::Published,
                        |value| {
                            let payload = value.value().value();
                            assert_eq!(payload.0, [0x5a; 192]);
                            (construction_address, std::ptr::from_ref(payload) as usize)
                        },
                    )
                })?;
            owner.with_policy(policy, |owner, m| {
                shut_down_refused(owner, m, refuse_at)?;
                assert_eq!(construction_address, published_address);
                Ok(m.reached())
            })
        },
    )
}

/// The shutdown of `owner`, holding the published payload's queued record,
/// under `m`, its cleanup unit `refuse_at` refused three times in place
/// first ([`support::repeated_refusal`]): every unit `Progress` until the
/// fourth, `Done`, which frees the record and the scope; the payload's
/// destructor never run, every byte of it cleaned, nothing live, and the
/// closed scope refusing a new acquisition.
fn shut_down_refused(
    owner: &mut DecodeOwner<'static, Limits>,
    m: &mut Limits,
    refuse_at: usize,
) -> Result<(), Finding> {
    let held = m.live_bytes();
    assert!(held >= 192);
    assert_eq!(DROPPED.get(), 0);
    let refusals = m.refusals();
    for unit in 0..4 {
        let progress = if unit == refuse_at {
            support::repeated_refusal(m, owner, 3, unit, |m, owner| {
                let before = (CLEANED.get(), owner.outstanding(), m.live_bytes());
                let result = support::scope_checked(m, owner, |owner, m| owner.shutdown_step(m))
                    .map(|reclaimed| match reclaimed {
                        Reclaimed::Progress => Step::Progress,
                        Reclaimed::Waiting | Reclaimed::Done => Step::Complete(reclaimed),
                    });
                (
                    before,
                    (CLEANED.get(), owner.outstanding(), m.live_bytes()),
                    (result, None),
                )
            })?
        } else {
            None
        };
        m.clear_refusal();
        m.fresh();
        let result = match progress {
            Some(Step::Progress) => Reclaimed::Progress,
            Some(Step::Complete(reclaimed)) => reclaimed,
            Some(Step::Finished) => {
                return Err(Finding::Driver(
                    "published payload cleanup finished without completion".to_owned(),
                ));
            }
            None => owner
                .shutdown_step(m)
                .map_err(support::failed("payload cleanup"))?,
        };
        assert_eq!(
            result,
            if unit == 3 {
                Reclaimed::Done
            } else {
                Reclaimed::Progress
            }
        );
    }
    assert_eq!(m.refusals() - refusals, 3);
    assert_eq!(CLEANED.get(), 192);
    assert_eq!(DROPPED.get(), 0);
    assert_eq!(m.live_bytes(), 0);
    assert_eq!(owner.outstanding(), 0);
    m.fresh();
    assert!(matches!(
        owner.allocate_step::<Payload>(m, &mut Acquisition::new()),
        Err(BoundedError::PlanMismatch)
    ));
    Ok(())
}

/// The scope holds a queued record to the cleanup count it declared when its
/// cleanup began: a record understating it
/// ([`support::Understated`]) is refused as a defect at the first
/// call beyond it, so no drain runs on unbounded. The first step removes the
/// record, the second spends its one declared call, the third is refused.
#[test]
fn a_record_cleaning_up_beyond_its_declared_count_is_a_defect() {
    // An ordinary policy: the defective scope is kept for the process's life
    // (below), so no run of it reaches the quiescence a recording would be
    // read at, and the test reads no history.
    let mut m = Limits::unlimited().strict();
    let mut owner = DecodeOwner::<'static, Limits>::new();
    owner
        .initialize_step(&mut m)
        .expect("an unlimited scope initializes");
    let mut record = owner
        .allocate_step::<support::Understated>(&mut m, &mut Acquisition::new())
        .expect("an unlimited record acquires");
    support::understate(&mut record, 2);
    drop(record);
    for step in ["removal", "declared call"] {
        m.fresh();
        assert_eq!(
            owner.step(&mut m),
            Ok(Reclaimed::Progress),
            "the {step} was not taken"
        );
    }
    m.fresh();
    assert_eq!(owner.step(&mut m), Err(BoundedError::PlanMismatch));
    assert_eq!(owner.outstanding(), 1);
    // The defect leaves custody its contract no longer describes: stepping
    // on, or the terminal drain dropping the owner would start, aborts by
    // design. The scope is kept for the process's life in a static, never
    // dropped: the leak is declared, and Miri does not report memory
    // reachable from a static, so the test keeps its Miri coverage.
    static DEFECTIVE: std::sync::Mutex<
        Vec<dcbor::bounded::decode::construction::DecodeOwner<'static, Limits>>,
    > = std::sync::Mutex::new(Vec::new());
    DEFECTIVE
        .lock()
        .expect("no holder of the defective scopes panicked")
        .push(owner);
}

#[test]
fn cancellation_reclaims_only_the_initialized_prefix() {
    for chunks in 0..=3 {
        CLEANED.set(0);
        // The record retires to the queue as a published handle, releasing
        // nothing; the drain cleans exactly its initialized prefix.
        support::recorded_run(|run| {
            let policy = run.policy(u64::MAX);
            run.scoped(policy, &Unwitnessed, |owner| {
                payload(owner, policy, chunks, |_, _| ())
            })?;
            assert_eq!(CLEANED.get(), chunks * 64);
            run.with_policy(policy, |m| assert_eq!(m.live_bytes(), 0));
            Ok(())
        });
    }
}

#[test]
fn text_build_publication_and_cancellation_keep_per_allocation_custody() {
    // Literal canonical text containing 65 ASCII bytes crosses a copy quantum.
    let mut wire = vec![0x78, 65];
    wire.extend_from_slice(&[b'x'; 65]);
    let boundaries = retired_text(&wire, usize::MAX)
        .0
        .expect("text construction never reached publication");
    support::stop_matrix("retired text construction", boundaries, |stop| {
        let (published, reached) = retired_text(&wire, stop);
        assert_eq!(
            published.is_some(),
            stop == boundaries,
            "a stop after {stop} turns"
        );
        reached
    });
}

/// Construct the text `wire` holds, retiring the construction after `stop`
/// turns: retirement releases nothing, since handle drops only transfer
/// custody, and the scope's queued cleanup never acquires storage and
/// recovers everything, all within the decode's bound. The turns
/// construction took to publish, when it published within `stop`, and the
/// boundary valuations the run reached. One recorded run, its finalizer
/// refining the stream.
fn retired_text(wire: &[u8], stop: usize) -> (Option<usize>, dcbor::bounded::boundary::Reached) {
    retired::<String>(wire, stop, Discipline::Admitted, |value| {
        assert_eq!(value.as_bytes(), &[b'x'; 65]);
    })
}

/// Construct `T` from `wire`, retiring the construction after `stop` turns
/// ([`support::Holding::controlled`]), a published value given to `inspect`:
/// the retirements of the stopped construction and of the published value
/// release nothing, each retirement's rule holding it; then the scope's
/// queued cleanup recovers everything without acquiring storage, within the
/// decode's bound, each unit, under [`Discipline::RefusedFirst`], first
/// refused without release. The turns construction took to publish, when it
/// published within `stop`, and the boundary valuations the run reached.
/// One recorded run, its finalizer refining the stream.
fn retired<T: Transferable<Limits> + 'static>(
    wire: &[u8],
    stop: usize,
    discipline: Discipline,
    inspect: impl Fn(&T),
) -> (Option<usize>, dcbor::bounded::boundary::Reached) {
    let bound = support::typed_turns::<T>(wire.len());
    support::recorded_run(|run| {
        let policy = run.policy(u64::MAX);
        run.holding(
            DecodeOwner::new(),
            Retirement::Scope,
            &Unwitnessed,
            |owner| {
                owner.initialize(policy)?;
                // Retirement of the stopped construction and of a published
                // value releases nothing: each retirement's rule holds it.
                let published = owner.copied(policy, wire, |input| {
                    input.parse(policy, Options::normalizing(8), |document| {
                        document.transfer(
                            Construction::<_, T, Limits>::construct,
                            Retirement::Stopped,
                            |operation| {
                                let mut turns = 0;
                                let published = operation.controlled(
                                    policy,
                                    bound,
                                    Retirement::Published,
                                    true,
                                    |_, _, at| {
                                        turns = at + 1;
                                        at == stop
                                    },
                                    |value| inspect(value.value().value()),
                                )?;
                                Ok::<_, Finding>(published.map(|()| turns))
                            },
                        )
                    })
                })???;
                let mut previous = owner.with_policy(policy, |_, m| m.live_bytes());
                for at in 0..bound {
                    if discipline == Discipline::RefusedFirst && owner.value().outstanding() != 0 {
                        // The unit first refused, without release; a prepaid
                        // release, which has no admission to refuse, is
                        // progress that releases.
                        let done = owner.with_policy(policy, |owner, m| {
                            m.clear_refusal();
                            m.exhaust();
                            let held = m.live_bytes();
                            match owner.shutdown_step(m) {
                                Err(BoundedError::Refused(_)) => assert_eq!(m.live_bytes(), held),
                                Ok(Reclaimed::Progress) => assert!(m.live_bytes() < held),
                                Ok(Reclaimed::Done) => {
                                    assert_eq!(m.live_bytes(), 0);
                                    return true;
                                }
                                other => panic!("unexpected cleanup: {other:?}"),
                            }
                            m.clear_refusal();
                            false
                        });
                        if done {
                            return owner.with_policy(policy, |_, m| Ok((published, m.reached())));
                        }
                    }
                    let result = owner
                        .scope_step(policy, at, |owner, m| owner.shutdown_step(m))?
                        .map_err(support::failed("the scope's shutdown"))?;
                    let live = owner.with_policy(policy, |_, m| m.live_bytes());
                    assert!(live <= previous, "reclamation acquired new storage");
                    previous = live;
                    if result == Reclaimed::Done {
                        assert_eq!(live, 0);
                        return owner.with_policy(policy, |_, m| Ok((published, m.reached())));
                    }
                }
                Err(Finding::Driver(format!(
                    "the cleanup of {} exceeded its bound of {bound} turns",
                    core::any::type_name::<T>()
                )))
            },
        )
    })
}

#[test]
fn nested_vectors_construct_children_in_place_and_reclaim_all_allocations() {
    // [[1, 24], [], [256]], independently specified canonical bytes.
    let wire = [0x83, 0x82, 0x01, 0x18, 0x18, 0x80, 0x81, 0x19, 0x01, 0x00];
    let built = constructed::<Vec<Vec<u64>>>(
        &wire,
        Discipline::Admitted,
        |_| false,
        |output| {
            assert_eq!(output.value(), &[vec![1, 24], vec![], vec![256]]);
            assert_eq!(output.bytes(), wire);
        },
    );
    assert!(built, "the nested vectors were not built");
}

#[cfg(feature = "derive")]
#[test]
fn derived_newtype_uses_stable_child_construction_and_cleanup() {
    #[derive(dcbor::CBORBoundedDecodable)]
    struct Wrapped(Vec<String>);

    let wire = [0x82, 0x61, b'a', 0x62, b'b', b'c'];
    let built = constructed::<Wrapped>(
        &wire,
        Discipline::Admitted,
        |_| false,
        |output| assert_eq!(output.value().0, ["a", "bc"]),
    );
    assert!(built, "the newtype was not built");
}

#[cfg(feature = "derive")]
#[test]
fn named_fields_build_in_wire_order_and_abort_missing_required_fields() {
    #[derive(dcbor::CBORBoundedDecodable)]
    struct Named {
        #[cbor(n = 9)]
        numbers: Vec<u64>,
        #[cbor(n = 1)]
        text: String,
    }
    // Unknown key 3 is ignored. Declaration order differs from wire order.
    let complete = &[0xa3, 1, 0x61, b'x', 3, 0xf6, 9, 0x81, 7][..];
    let missing = &[0xa1, 1, 0x61, b'x'][..];
    // The construction's own bound covers it, and its cleanup after the
    // missing field's rejection.
    for wire in [complete, missing] {
        let built = constructed::<Named>(
            wire,
            Discipline::Admitted,
            |error| matches!(error, DecodeError::Invalid(dcbor::Error::MissingMapKey)),
            |value| {
                assert_eq!(value.value().text, "x");
                assert_eq!(value.value().numbers, [7]);
            },
        );
        assert_eq!(built, wire == complete, "{wire:02x?}");
    }
}

#[cfg(feature = "derive")]
#[test]
fn tagged_named_construction_validates_tag_before_initializing_fields() {
    #[derive(dcbor::CBORBoundedDecodable)]
    #[cbor(tag = 42)]
    struct Tagged {
        #[cbor(n = 0)]
        number: u64,
    }
    // The construction's own bound covers it, and its cleanup after the
    // wrong tag's rejection.
    for tag in [42, 43] {
        let wire = [0xd8, tag, 0xa1, 0, 7];
        let built = constructed::<Tagged>(
            &wire,
            Discipline::Admitted,
            |error| {
                matches!(
                    error,
                    DecodeError::Invalid(dcbor::Error::WrongTag(expected, found))
                        if expected.value() == 42 && found.value() == 43
                )
            },
            |value| assert_eq!(value.value().number, 7),
        );
        assert_eq!(built, tag == 42, "tag {tag}");
    }
}
