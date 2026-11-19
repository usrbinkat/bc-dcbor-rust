//! The correspondence of a derived type's CDDL with its decoders: over a
//! generated domain of dCBOR data items, an item is accepted by each of the
//! type's decoders (symbolic, bounded) exactly when an independent CDDL
//! validator (`cddl`, RFC 8610) admits it against the type's document
//! (`dcbor::cddl::document`).
//!
//! The domain is every valid sample the fixture gives and every mutation of
//! each ([`mutations`]): the whole item replaced by a value of every other
//! kind; a map's keys removed one by one, each value replaced by every
//! other kind, an unknown key added; an array's elements removed, one
//! appended, each replaced, its first (a variant's discriminant) changed; a
//! tag stripped and changed; each mutation applied at the top and one level
//! down. Every item is a dCBOR encoding, made by this crate's own encoder,
//! since the CDDL denotes data items and dCBOR conformance is the decoder's
//! to enforce beyond it (`dcbor::cddl`, "What a rule denotes").
//!
//! The claim is the domain's alone: evidence class `checked`, over the
//! generated items, not a proof over every data item.
//!
//! # The value classes the domain reaches
//!
//! Every replacement [`kinds`] makes, so every class below at every map
//! value and array element of every sample, and one level down:
//!
//! - both simple values dCBOR admits besides `null` (`false` via the
//!   samples, `true`), and `null`;
//! - every integer range edge of every integer type with a rule (`u8`,
//!   `u16`, `u32`, `u64`, `i8`, `i16`, `i32`, `i64`; `usize` is `u64`'s):
//!   the edge and the value one past it on each side a range has, so a
//!   range rendered one too narrow or one too wide admits an item its
//!   decoder refuses, or the reverse; and `0`, `-1`;
//! - a non-integral float, an infinity and the canonical NaN: classes no
//!   integer, text or container rule admits, and no fixture field decodes;
//! - a text, a byte string, an empty and a nonempty array, an empty map;
//! - a tagged item under a tag no fixture names (`2`, a bignum's, around a
//!   byte string) and under one (`1`, around an integer).
//!
//! # The value classes it excludes, and why
//!
//! - Items that are not dCBOR: non-canonical encodings, non-shortest
//!   heads, indefinite lengths, duplicate or misordered map keys, floats a
//!   reduction would shorten, non-NFC text, simple values other than
//!   `false`, `true` and `null`, negative integers below `-2^63`. Each is
//!   refused by every dCBOR decoder before any type is consulted, and the
//!   CDDL denotes data items, not their encodings: the correspondence is
//!   over dCBOR-valid items only (`dcbor::cddl`, "What a rule denotes"),
//!   and this crate's encoder, which makes every item, cannot write them.
//! - Types with no rule (`dcbor::cddl`, "What has a rule"), so no fixture
//!   field of them: a derived type with such a field does not compile
//!   (`dcbor-derive/tests/ui/fail/cddl_float_field.rs`). Each, with the set
//!   its decoder accepts and the RFC 8610 construct that set would need:
//!   - floats (`float.rs`:171-191, and the `f32`, `f16` decoders after it):
//!     an unsigned or negative integer is accepted exactly when the float
//!     represents it (`exact.rs` `exact_from_u64`, `exact_from_i128`), every
//!     float otherwise. Above 2^53 the integers binary64 represents are not
//!     an interval but every multiple of a power of two of at most 53
//!     significant bits. RFC 8610 names integer sets by ranges (section
//!     2.2.2.1, contiguous), comparisons (`.lt`, `.le`, `.gt`, `.ge`,
//!     section 3.8.6, contiguous), value choices (section 2.2.2) and `.bits`
//!     (section 3.8.2, which bit positions may be set, fixed positions, not
//!     a count of significant bits). Only a choice of every such integer
//!     names the set, on the order of 2^55 alternatives: no rule is
//!     generated for it;
//!   - `Date` (`date.rs`:423-429): tag 1 around a timestamp decoded by the
//!     float decoder above, the same set under a tag;
//!   - `MinimalBigInt` (`minimal_bigint.rs`:116-125, its decoder :244):
//!     tag 2 or 3 around a byte string accepted exactly when it is nonempty,
//!     its first byte nonzero, and its value outside the plain range. A
//!     byte string's controls are `.size` (section 3.8.1, its length),
//!     `.bits` (section 3.8.2, which bits *may* be set, never that one
//!     must), `.cbor` and `.cborseq` (section 3.8.4, its embedded item);
//!     `.regexp` (section 3.8.3) applies to text strings only, and `.and`
//!     and `.within` (section 3.8.5) intersect, with no complement. None
//!     requires a nonzero first byte, so the leading-zero rule has no CDDL
//!     form;
//!   - hash sets (`set.rs` `distinct`, :131-148): an array accepted exactly
//!     when no two elements convert to one `T`. An array's group constrains
//!     each element by its own entry and occurrence (sections 2.1, 3.2);
//!     no construct relates two elements, so distinctness has no CDDL form;
//!   - `StabilizedText` (`stabilized_text.rs`:160-169): a text accepted
//!     exactly when every code point is assigned in the pinned Unicode
//!     version. Not inexpressible: `tstr .regexp` (section 3.8.3, XSD
//!     regular expressions) with a character class of the pinned assigned
//!     ranges would name it. Excluded instead because that class would be
//!     generated from the one `DerivedAge.txt` the decoder's table is built
//!     from (`build.rs`), so the check would compare the table with itself,
//!     not with an independent oracle; and the oracle's support for a class
//!     of that size at release 0.10.7 is not read. Its own tests are the
//!     type's (`tests/stabilized_text.rs`).
//! - Mutations more than one level below a sample: the domain stops at one
//!   nested level ([`mutations`]). A rule is generated per type, independent
//!   of where the type occurs: `Cddl::cddl` takes only the rules being
//!   built (`src/cddl.rs`:70-74); `Rules::rule` (:116-142) defines a type's
//!   rule once, keyed by its `TypeId`, and every occurrence names it; each
//!   container's expression is its element's, composed without position
//!   (`Vec`, `VecDeque` :274-284, `BTreeMap`, `HashMap` :290-303); and a
//!   derived member's value is its field type's expression
//!   (`dcbor-derive/src/cddl.rs` `member`, :14-23). A rule's matching is
//!   positional-independent (RFC 8610 section 2, a rule name denotes one
//!   set), and each decoder decodes a field through that field type's own
//!   decoder, so an item at any depth matches a type's rule exactly as it
//!   does one level down, where the domain checks it.
//! - Lengths beyond a sample's: the length-free forms admit every length,
//!   `tstr`, `bstr` (`src/cddl.rs`:249-259), `any` (:261-265), `[* T]`
//!   (:274-284), `{ * K => V }` (:268-272, :290-303), so a longer text,
//!   byte string, array or table is one class with a shorter one on both
//!   sides. The forms that do fix a length are a map's required members
//!   (`map`, :177-187) and a variant's arity (`variant`, :206-210), each
//!   reached by the removal and append mutations above.

use dcbor::prelude::*;

/// One item of a domain: how it was made, and the item.
pub struct Item {
    pub label: String,
    pub cbor: CBOR,
}

/// A value of every kind, each a replacement a mutation makes (the module's
/// "The value classes the domain reaches").
fn kinds() -> Vec<(&'static str, CBOR)> {
    vec![
        ("null", CBOR::null()),
        ("true", CBOR::from(true)),
        ("0", CBOR::from(0u64)),
        ("-1", CBOR::from(-1i64)),
        ("u8::MAX", CBOR::from(u64::from(u8::MAX))),
        ("u8::MAX + 1", CBOR::from(u64::from(u8::MAX) + 1)),
        ("u16::MAX", CBOR::from(u64::from(u16::MAX))),
        ("u16::MAX + 1", CBOR::from(u64::from(u16::MAX) + 1)),
        ("u32::MAX", CBOR::from(u64::from(u32::MAX))),
        ("u32::MAX + 1", CBOR::from(u64::from(u32::MAX) + 1)),
        ("u64::MAX", CBOR::from(u64::MAX)),
        ("i8::MIN", CBOR::from(i64::from(i8::MIN))),
        ("i8::MIN - 1", CBOR::from(i64::from(i8::MIN) - 1)),
        ("i8::MAX", CBOR::from(i64::from(i8::MAX))),
        ("i8::MAX + 1", CBOR::from(i64::from(i8::MAX) + 1)),
        ("i16::MIN", CBOR::from(i64::from(i16::MIN))),
        ("i16::MIN - 1", CBOR::from(i64::from(i16::MIN) - 1)),
        ("i16::MAX", CBOR::from(i64::from(i16::MAX))),
        ("i16::MAX + 1", CBOR::from(i64::from(i16::MAX) + 1)),
        ("i32::MIN", CBOR::from(i64::from(i32::MIN))),
        ("i32::MIN - 1", CBOR::from(i64::from(i32::MIN) - 1)),
        ("i32::MAX", CBOR::from(i64::from(i32::MAX))),
        ("i32::MAX + 1", CBOR::from(i64::from(i32::MAX) + 1)),
        ("i64::MIN", CBOR::from(i64::MIN)),
        ("i64::MAX", CBOR::from(i64::MAX)),
        ("i64::MAX + 1", CBOR::from(i64::MAX as u64 + 1)),
        ("1.5", CBOR::from(1.5f64)),
        ("infinity", CBOR::from(f64::INFINITY)),
        ("NaN", CBOR::from(f64::NAN)),
        ("a text", CBOR::from("t")),
        ("a byte string", CBOR::to_byte_string([1u8])),
        ("an empty array", CBOR::from(Vec::<CBOR>::new())),
        ("an array", CBOR::from(vec![CBOR::from(0u64)])),
        ("an empty map", CBOR::from(Map::new())),
        (
            "tag 2 around a byte string",
            CBOR::to_tagged_value(2, CBOR::to_byte_string([1u8])),
        ),
        ("tag 1 around 0", CBOR::to_tagged_value(1, CBOR::from(0u64))),
    ]
}

/// The map of `entries`, or none when two of its keys are one dCBOR key.
fn map_of(entries: &[(CBOR, CBOR)]) -> Option<CBOR> {
    let mut map = Map::new();
    for (key, value) in entries {
        map.insert(key.clone(), value.clone()).ok()?;
    }
    Some(CBOR::from(map))
}

/// Every mutation of `item` described in the module docs, `depth` levels
/// down from it (one level below the top when `depth` is 1), each labelled
/// by what was done, a nested one by the path to it.
fn mutate(item: &CBOR, depth: usize) -> Vec<Item> {
    let mut out: Vec<Item> = kinds()
        .into_iter()
        .map(|(kind, cbor)| Item {
            label: format!("replaced by {kind}"),
            cbor,
        })
        .collect();
    match item.as_case() {
        CBORCase::Map(map) => {
            let entries: Vec<(CBOR, CBOR)> = map
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            for (at, (key, value)) in entries.iter().enumerate() {
                let mut removed = entries.clone();
                removed.remove(at);
                if let Some(cbor) = map_of(&removed) {
                    out.push(Item {
                        label: format!("key {} removed", key.diagnostic()),
                        cbor,
                    });
                }
                let nested = if depth > 0 {
                    mutate(value, depth - 1)
                } else {
                    Vec::new()
                };
                let replacements = kinds()
                    .into_iter()
                    .map(|(kind, cbor)| (format!("replaced by {kind}"), cbor))
                    .chain(nested.into_iter().map(|item| (item.label, item.cbor)));
                for (what, replacement) in replacements {
                    let mut replaced = entries.clone();
                    replaced[at].1 = replacement;
                    if let Some(cbor) = map_of(&replaced) {
                        out.push(Item {
                            label: format!("key {} > {what}", key.diagnostic()),
                            cbor,
                        });
                    }
                }
            }
            for unknown in [CBOR::from(99u64), CBOR::from("x")] {
                let mut added = entries.clone();
                added.push((unknown.clone(), CBOR::from(0u64)));
                if let Some(cbor) = map_of(&added) {
                    out.push(Item {
                        label: format!("unknown key {} added", unknown.diagnostic()),
                        cbor,
                    });
                }
            }
        }
        CBORCase::Array(items) => {
            for at in 0..items.len() {
                let mut removed = items.clone();
                removed.remove(at);
                out.push(Item {
                    label: format!("element {at} removed"),
                    cbor: CBOR::from(removed),
                });
                let nested = if depth > 0 {
                    mutate(&items[at], depth - 1)
                } else {
                    Vec::new()
                };
                let replacements = kinds()
                    .into_iter()
                    .map(|(kind, cbor)| (format!("replaced by {kind}"), cbor))
                    .chain(nested.into_iter().map(|item| (item.label, item.cbor)));
                for (what, replacement) in replacements {
                    let mut replaced = items.clone();
                    replaced[at] = replacement;
                    out.push(Item {
                        label: format!("element {at} > {what}"),
                        cbor: CBOR::from(replaced),
                    });
                }
            }
            let mut appended = items.clone();
            appended.push(CBOR::from(0u64));
            out.push(Item {
                label: "element appended".to_string(),
                cbor: CBOR::from(appended),
            });
            if let Some(CBORCase::Unsigned(discriminant)) = items.first().map(CBOR::as_case) {
                let mut changed = items.clone();
                changed[0] = CBOR::from(discriminant + 1);
                out.push(Item {
                    label: format!(
                        "discriminant {discriminant} changed to {}",
                        discriminant + 1
                    ),
                    cbor: CBOR::from(changed),
                });
            }
        }
        CBORCase::Tagged(tag, inner) => {
            out.push(Item {
                label: format!("tag {} stripped", tag.value()),
                cbor: inner.clone(),
            });
            out.push(Item {
                label: format!("tag {} changed to {}", tag.value(), tag.value() + 1),
                cbor: CBOR::to_tagged_value(tag.value() + 1, inner.clone()),
            });
            if depth > 0 {
                for item in mutate(inner, depth - 1) {
                    out.push(Item {
                        label: format!("tag {} > {}", tag.value(), item.label),
                        cbor: CBOR::to_tagged_value(tag.value(), item.cbor),
                    });
                }
            }
        }
        _ => {}
    }
    out
}

/// The domain of `samples`: each sample itself (`valid`) and every mutation
/// of it, one level down, each distinct encoding once, the first label it
/// was made by kept.
pub fn mutations(samples: &[CBOR]) -> Vec<Item> {
    let mut domain: Vec<Item> = Vec::new();
    let mut seen: Vec<Vec<u8>> = Vec::new();
    for sample in samples {
        let made = std::iter::once(Item {
            label: "valid".to_string(),
            cbor: sample.clone(),
        })
        .chain(mutate(sample, 1));
        for item in made {
            let bytes = item.cbor.to_cbor_data();
            if !seen.contains(&bytes) {
                seen.push(bytes);
                domain.push(item);
            }
        }
    }
    domain
}

/// The kind of difference a mismatch on an item made by `label` shows: a
/// field's optionality (a key removed), the keys no field names (a key
/// added), a tag, or the domain otherwise.
fn divergence(label: &str) -> &'static str {
    let last = label.rsplit(" > ").next().unwrap_or(label);
    if last.starts_with("key ") && last.ends_with(" removed") {
        "optionality divergence"
    } else if last.starts_with("unknown key ") {
        "unknown-key divergence"
    } else if last.starts_with("tag ") {
        "tag divergence"
    } else {
        "domain divergence"
    }
}

/// One decoder of the type under check: its name, and whether it accepts
/// an encoding.
pub type Decoder<'d> = (&'static str, &'d dyn Fn(&[u8]) -> bool);

/// Every finding of `fixture`, its CDDL `document` against its `decoders`
/// over `domain`: the document must parse with every rule it names defined
/// (`cddl::ast::CDDL::from_slice`); every item must be accepted by each
/// decoder exactly when the validator admits it; some item must be admitted
/// and some refused, or the domain distinguishes nothing.
pub fn findings(
    fixture: &str,
    document: &str,
    domain: &[Item],
    decoders: &[Decoder<'_>],
) -> Vec<String> {
    let mut findings = Vec::new();
    if let Err(error) = cddl::ast::CDDL::from_slice(document.as_bytes()) {
        findings.push(format!(
            "{fixture}: its CDDL does not parse whole: {error}\n{document}"
        ));
        return findings;
    }
    let (mut admitted, mut refused) = (0usize, 0usize);
    for item in domain {
        let bytes = item.cbor.to_cbor_data();
        let validated = cddl::validate_cbor_from_slice(document, &bytes, None);
        let admits = validated.is_ok();
        if admits {
            admitted += 1;
        } else {
            refused += 1;
        }
        for (decoder, accepts) in decoders {
            let accepted = accepts(&bytes);
            if accepted != admits {
                findings.push(format!(
                    "{fixture}: {}: `{}` ({}): the {decoder} decoder {} it, the CDDL {} it{}",
                    divergence(&item.label),
                    item.label,
                    item.cbor.diagnostic(),
                    if accepted { "accepts" } else { "refuses" },
                    if admits { "admits" } else { "refuses" },
                    match &validated {
                        Ok(()) => String::new(),
                        Err(error) => format!(" ({error})"),
                    },
                ));
            }
        }
    }
    if admitted == 0 || refused == 0 {
        findings.push(format!(
            "{fixture}: the domain distinguishes nothing: {admitted} items admitted, \
             {refused} refused"
        ));
    }
    findings
}
