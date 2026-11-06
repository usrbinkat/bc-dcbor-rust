//! The tag store is the caller's: the crate keeps none (no shipped static,
//! `tests/unsafe_census.rs`), and no conversion or codec path reads one.
//! Here, what a store holds: registering this crate's tags again changes
//! neither what the store registers nor the bytes it holds, and every
//! registration the store cannot take is a typed refusal that registers
//! nothing. The heap observer witnesses the bytes, every allocation of the
//! store made and freed while it observes.
#![cfg(feature = "std")]

use dcbor::Error;
use dcbor::prelude::*;
use dcbor_test_support::heap;

#[global_allocator]
static HEAP: heap::Heap = heap::Heap;

/// This crate's tag values, every one `register_tags_in` registers.
fn crate_tag_values() -> Vec<TagValue> {
    [
        &[dcbor::TAG_DATE][..],
        #[cfg(feature = "num-bigint")]
        &[dcbor::TAG_POSITIVE_BIGNUM, dcbor::TAG_NEGATIVE_BIGNUM][..],
    ]
    .concat()
}

/// What `tags` registers for `values`: each value's name, the value its
/// name looks up, and whether the value has a summarizer.
fn registered(
    tags: &TagsStore,
    values: &[TagValue],
) -> Vec<(TagValue, String, Option<TagValue>, bool)> {
    values
        .iter()
        .map(|&value| {
            let name = tags.name_for_value(value);
            let named = tags.tag_for_name(&name).map(|tag| tag.value());
            (value, name, named, tags.summarizer(value).is_some())
        })
        .collect()
}

/// The idempotence oracle: a store built empty and registered by `register`
/// once, then again, registers the same tags and holds exactly the same
/// live bytes after the second registration as after the first, every
/// allocation of the store observed from its creation. `values` are the
/// tags compared.
fn registration_is_idempotent(values: &[TagValue], mut register: impl FnMut(&mut TagsStore)) {
    assert!(
        heap::installed(),
        "the oracle witnesses physical storage: install heap::Heap as the binary's global \
         allocator"
    );
    let observation = heap::Observation::begin(None);
    let mut tags = TagsStore::default();
    register(&mut tags);
    // What the first registration registers is read before its bytes are
    // taken, so both snapshots hold this record of it alike.
    let first = registered(&tags, values);
    let once = observation.snapshot();
    register(&mut tags);
    let twice = observation.snapshot();
    let second = registered(&tags, values);
    observation.stop();
    assert!(!twice.overflow, "heap observation incomplete");
    assert_eq!(
        second, first,
        "registering again changed what the store registers"
    );
    assert_eq!(
        twice.live, once.live,
        "registering again changed the bytes the store holds: {} then {}",
        once.live, twice.live
    );
    drop(tags);
}

/// Registering this crate's tags again is a no-op in content and in the
/// bytes the store holds: each tag is registered under the name it has, and
/// each summarizer replaces its own.
#[test]
fn registering_again_changes_neither_the_store_nor_what_it_holds() {
    let values = crate_tag_values();
    registration_is_idempotent(&values, |tags| {
        register_tags_in(tags).expect("this crate's tags register");
    });
    let mut tags = TagsStore::default();
    register_tags_in(&mut tags).expect("this crate's tags register");
    assert_eq!(tags.name_for_value(dcbor::TAG_DATE), "date");
    assert!(tags.summarizer(dcbor::TAG_DATE).is_some());
}

/// The oracle's planted control: a registration that adds a tag each time
/// it runs grows the store, and the oracle refuses it.
#[test]
#[should_panic(expected = "registering again changed the bytes the store holds")]
fn a_registration_that_grows_the_store_is_refused() {
    let mut next = 1000u64;
    registration_is_idempotent(&crate_tag_values(), |tags| {
        register_tags_in(tags).expect("this crate's tags register");
        tags.insert(Tag::new(next, format!("planted-{next}")))
            .expect("a fresh tag registers");
        next += 1;
    });
}

/// Every registration the store cannot take is refused, typed, and
/// registers nothing, its whole batch included: an unnamed tag, an empty
/// name, a value under another name, a name for another value, and a batch
/// whose members disagree with each other.
#[test]
fn every_refused_registration_registers_nothing() {
    let mut tags = TagsStore::default();
    register_tags_in(&mut tags).expect("this crate's tags register");
    let values = crate_tag_values();
    let before = registered(&tags, &values);
    let unchanged = |tags: &TagsStore, refused: &str| {
        assert_eq!(
            registered(tags, &values),
            before,
            "{refused} changed the store"
        );
        assert_eq!(
            tags.tag_for_value(9),
            None,
            "{refused} registered its batch"
        );
        assert_eq!(
            tags.tag_for_name("nine"),
            None,
            "{refused} registered its batch"
        );
    };
    let refusals: [(&str, Vec<Tag>, Error); 5] = [
        (
            "an unnamed tag",
            vec![Tag::new(9, "nine"), Tag::with_value(7)],
            Error::UnnamedTag(7),
        ),
        (
            "an empty name",
            vec![Tag::new(9, "nine"), Tag::new(8, "")],
            Error::EmptyTagName(8),
        ),
        (
            "a value under another name",
            vec![Tag::new(9, "nine"), Tag::new(dcbor::TAG_DATE, "epoch")],
            Error::ConflictingTagName {
                value: dcbor::TAG_DATE,
                registered: "date".to_string(),
                given: "epoch".to_string(),
            },
        ),
        (
            "a name for another value",
            vec![Tag::new(9, "nine"), Tag::new(4, "date")],
            Error::ConflictingTagValue {
                name: "date".to_string(),
                registered: dcbor::TAG_DATE,
                given: 4,
            },
        ),
        (
            "a batch disagreeing with itself",
            vec![Tag::new(9, "nine"), Tag::new(9, "neun")],
            Error::ConflictingTagName {
                value: 9,
                registered: "nine".to_string(),
                given: "neun".to_string(),
            },
        ),
    ];
    for (refused, batch, expected) in refusals {
        let error = tags
            .insert_all(batch)
            .expect_err("the registration is refused");
        assert_eq!(error.to_string(), expected.to_string(), "{refused}");
        assert_eq!(
            core::mem::discriminant(&error),
            core::mem::discriminant(&expected),
            "{refused}"
        );
        unchanged(&tags, refused);
    }
    assert!(
        matches!(
            TagsStore::new([Tag::with_value(5)]),
            Err(Error::UnnamedTag(5))
        ),
        "a store built from an unnamed tag is refused"
    );
}

/// A date's tag and its name are the same whatever any store registers:
/// converting a date reads no store, so a store that names tag 1 otherwise
/// changes neither the date's encoding nor its description.
#[test]
fn a_dates_tag_reads_no_store() {
    let date = Date::from_timestamp(-100.0);
    let encoded = CBOR::from(date);
    assert_eq!(encoded.hex(), "c13863");
    assert_eq!(encoded.to_string(), "date(-100)");
    let tags = TagsStore::new([Tag::new(dcbor::TAG_DATE, "epoch-seconds")])
        .expect("an unregistered value registers");
    assert_eq!(CBOR::from(date).to_string(), "date(-100)");
    assert_eq!(
        CBOR::from(date).diagnostic_annotated(&tags),
        "1(-100)   / epoch-seconds /"
    );
    assert_eq!(Date::cbor_tags()[0].name(), Some("date".to_string()));
    let decoded =
        Date::try_from(CBOR::try_from_hex("c13863").expect("canonical")).expect("a date decodes");
    assert_eq!(decoded, date);
}
