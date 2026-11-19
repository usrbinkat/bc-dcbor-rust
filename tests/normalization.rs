//! Unicode NFC conformance for the bounded and symbolic paths, independent
//! of their algorithms: the Unicode Character Database's own
//! `NormalizationTest.txt` of the pinned version (`tests/data`, beside its
//! license, `LICENSE-UNICODE`) is the oracle, read as the file defines it.
//! It is compiled in, so a run reads no file and Miri's isolation runs it
//! unchanged, and it must be of the Unicode version the crate normalizes by
//! (`dcbor::UNICODE_VERSION`): data of another version is refused before any
//! row is read.
//!
//! dCBOR requires NFC alone (Section 2.5 of the dCBOR specification): of the
//! file's invariants, the NFC ones are dCBOR's, checked in both directions,
//! normalizing (bounded and symbolic encoding) and validating (decoding,
//! which accepts a text exactly when it is its own NFC). The NFD, NFKC and
//! NFKD invariants name operations dCBOR does not perform.

use std::collections::BTreeSet;

use dcbor::{CBOR, Error, UNICODE_VERSION, bounded::*, is_assigned};

/// The pinned version's conformance file, as the UCD publishes it.
const NORMALIZATION_TEST: &str = include_str!("data/NormalizationTest.txt");

/// The columns of a row: source, NFC, NFD, NFKC, NFKD (c1 to c5).
const COLUMNS: usize = 5;

/// One data line of the file: its line number, its part, its five columns.
struct Row {
    line: usize,
    part: String,
    columns: [String; COLUMNS],
}

impl Row {
    /// Each column paired with the NFC the file states for it: c2 for c1,
    /// c2 and c3 (`c2 == toNFC(c1) == toNFC(c2) == toNFC(c3)`), c4 for c4
    /// and c5 (`c4 == toNFC(c4) == toNFC(c5)`).
    fn nfc_pairs(&self) -> [(usize, &str, &str); COLUMNS] {
        let [c1, c2, c3, c4, c5] = &self.columns;
        [
            (1, c1, c2),
            (2, c2, c2),
            (3, c3, c2),
            (4, c4, c4),
            (5, c5, c4),
        ]
    }
}

/// `version` as the file names it, `X.Y.Z`.
fn dotted((major, minor, update): (u8, u8, u8)) -> String {
    format!("{major}.{minor}.{update}")
}

/// The file's rows, refused unless its header names `pinned`, the version
/// this crate normalizes by, and every line is a part header, a comment, or
/// a row of five columns of code points, each ending in `;`, after a part
/// header.
fn parse(text: &str, pinned: (u8, u8, u8)) -> Result<Vec<Row>, String> {
    let header = text.lines().next().unwrap_or_default();
    let named = header
        .strip_prefix("# NormalizationTest-")
        .and_then(|rest| rest.strip_suffix(".txt"))
        .ok_or_else(|| format!("line 1, {header:?}, is not a NormalizationTest header"))?;
    if named != dotted(pinned) {
        return Err(format!(
            "the data is of Unicode {named}, the crate normalizes by Unicode {}",
            dotted(pinned)
        ));
    }
    let mut part: Option<String> = None;
    let mut rows = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = index + 1;
        let data = raw.split('#').next().unwrap_or_default().trim();
        if data.is_empty() {
            continue;
        }
        if let Some(name) = data.strip_prefix('@') {
            part = Some(name.trim().to_string());
            continue;
        }
        let Some(part) = &part else {
            return Err(format!("line {line}: a row before any part header"));
        };
        let fields: Vec<&str> = data.split(';').collect();
        let (last, columns) = fields
            .split_last()
            .ok_or_else(|| format!("line {line}: no columns"))?;
        if !last.trim().is_empty() || columns.len() != COLUMNS {
            return Err(format!(
                "line {line}: {data:?} is not five columns each ending in ';'"
            ));
        }
        let mut parsed: [String; COLUMNS] = Default::default();
        for (slot, field) in parsed.iter_mut().zip(columns) {
            *slot = code_points(field).map_err(|error| format!("line {line}: {error}"))?;
        }
        rows.push(Row {
            line,
            part: part.clone(),
            columns: parsed,
        });
    }
    if rows.is_empty() {
        return Err("the data holds no row".to_string());
    }
    Ok(rows)
}

/// A column's text: its code points, hexadecimal, separated by spaces; at
/// least one, each a scalar value.
fn code_points(field: &str) -> Result<String, String> {
    let mut text = String::new();
    for point in field.split_whitespace() {
        let value = u32::from_str_radix(point, 16)
            .map_err(|error| format!("{point:?} is not a code point: {error}"))?;
        text.push(char::from_u32(value).ok_or_else(|| format!("{point} is not a scalar value"))?);
    }
    if text.is_empty() {
        return Err(format!("the column {field:?} holds no code point"));
    }
    Ok(text)
}

/// The file's rows at the pinned version.
fn rows() -> Vec<Row> {
    parse(NORMALIZATION_TEST, UNICODE_VERSION)
        .unwrap_or_else(|error| panic!("NormalizationTest.txt: {error}"))
}

/// The data is of the version the crate normalizes by, read through the
/// library (`dcbor::UNICODE_VERSION`), never named here; every part the
/// file declares holds rows, in the order it declares them.
#[test]
fn the_data_is_of_the_pinned_unicode_version() {
    let rows = rows();
    let mut parts: Vec<&str> = rows.iter().map(|row| row.part.as_str()).collect();
    parts.dedup();
    let declared: Vec<&str> = NORMALIZATION_TEST
        .lines()
        .filter_map(|line| line.strip_prefix('@'))
        .map(|rest| rest.split('#').next().unwrap_or_default().trim())
        .collect();
    assert!(!declared.is_empty(), "the file declares no part");
    assert_eq!(parts, declared, "a part the file declares holds no row");
}

/// The version check refuses data of any other version, naming both, and
/// data without a header: the planted controls of the check above, each
/// header derived from the pinned version, never written here.
#[test]
fn a_header_of_another_version_is_refused() {
    let (major, minor, update) = UNICODE_VERSION;
    let body = NORMALIZATION_TEST
        .split_once('\n')
        .expect("a header line")
        .1;
    for other in [
        (major + 1, minor, update),
        (major, minor + 1, update),
        (major, minor, update + 1),
    ] {
        let planted = format!("# NormalizationTest-{}.txt\n{body}", dotted(other));
        let error = parse(&planted, UNICODE_VERSION)
            .err()
            .unwrap_or_else(|| panic!("data of Unicode {} was accepted", dotted(other)));
        assert!(
            error.contains(&dotted(other)) && error.contains(&dotted(UNICODE_VERSION)),
            "{error}"
        );
    }
    assert!(
        parse(body, UNICODE_VERSION).is_err(),
        "headerless data was accepted"
    );
}

/// Every row's NFC invariants, in both directions. Normalizing: each column
/// normalizes to the NFC the file states for it on the bounded path, and the
/// symbolic path encodes the same bytes. Validating: each column's own,
/// unnormalized wire is accepted by the decoder, and decodes to itself,
/// exactly when the file states it is its own NFC; otherwise it is refused
/// as `NonCanonicalString`. Both outcomes occur.
#[test]
fn every_row_holds_the_nfc_invariants_in_both_directions() {
    let (mut accepted, mut refused) = (0usize, 0usize);
    for row in rows() {
        for (column, input, expected) in row.nfc_pairs() {
            let at = format!("line {} ({}), c{column} {input:?}", row.line, row.part);
            assert_eq!(normalized(input), expected, "{at}: normalized");
            let decoded = CBOR::try_from_data(text_wire(input));
            if input == expected {
                let text: String = decoded
                    .unwrap_or_else(|error| panic!("{at}: its own NFC refused: {error}"))
                    .try_into()
                    .unwrap();
                assert_eq!(text, input, "{at}: decoded");
                accepted += 1;
            } else {
                assert!(
                    matches!(decoded, Err(Error::NonCanonicalString)),
                    "{at}: not its NFC, decoded as {decoded:?}"
                );
                refused += 1;
            }
        }
    }
    assert!(
        accepted > 0 && refused > 0,
        "{accepted} accepted, {refused} refused"
    );
}

/// The file's second invariant: every code point assigned in this version
/// (`dcbor::is_assigned`, the stabilized-text table, generated from the
/// same version's `DerivedAge.txt`) that Part 1 does not list in c1 is its
/// own NFC: normalized to itself, and accepted by the decoder as itself.
#[test]
fn every_assigned_code_point_part_one_omits_is_its_own_nfc() {
    let rows = rows();
    let listed: BTreeSet<char> = rows
        .iter()
        .filter(|row| row.part.starts_with("Part1"))
        .map(|row| {
            let mut chars = row.columns[0].chars();
            match (chars.next(), chars.next()) {
                (Some(c), None) => c,
                _ => panic!("line {}: Part 1's c1 is one code point", row.line),
            }
        })
        .collect();
    assert!(!listed.is_empty(), "the file has no Part 1");
    let mut checked = 0usize;
    for c in (0..=0x10_FFFF).filter_map(char::from_u32) {
        if !is_assigned(c) || listed.contains(&c) {
            continue;
        }
        let text = c.to_string();
        assert_eq!(normalized(&text), text, "U+{:04X} normalized", u32::from(c));
        let decoded: String = CBOR::try_from_data(text_wire(&text))
            .unwrap_or_else(|error| panic!("U+{:04X} refused: {error}", u32::from(c)))
            .try_into()
            .unwrap();
        assert_eq!(decoded, text, "U+{:04X} decoded", u32::from(c));
        checked += 1;
    }
    assert!(checked > 0, "no assigned code point outside Part 1");
}

/// `input` normalized and encoded on the bounded path, the symbolic path
/// required to encode the same bytes, decoded back to text.
fn normalized(input: &str) -> String {
    let prepared = prepare(input, &mut Limits::unlimited()).unwrap();
    let mut bytes = vec![0; prepared.len()];
    prepared
        .encode_into(&mut bytes, &mut Limits::unlimited())
        .unwrap();
    assert_eq!(
        CBOR::from(input).to_cbor_data(),
        bytes,
        "symbolic and bounded normalization of {input:?} differ"
    );
    CBOR::try_from_data(bytes).unwrap().try_into().unwrap()
}

/// `text`'s bytes as a CBOR text string, unnormalized: the shortest head of
/// its length, then its bytes.
fn text_wire(text: &str) -> Vec<u8> {
    let n = text.len();
    let mut wire = match n {
        0..24 => vec![0x60 | n as u8],
        24..256 => vec![0x78, n as u8],
        256..65536 => vec![0x79, (n >> 8) as u8, n as u8],
        _ => {
            let mut head = vec![0x7a];
            head.extend(
                u32::try_from(n)
                    .expect("a conformance row fits in u32")
                    .to_be_bytes(),
            );
            head
        }
    };
    wire.extend_from_slice(text.as_bytes());
    wire
}

#[test]
fn long_runs_preserve_order_and_do_not_insert_characters() {
    // q has no composition with these marks. Classes are 1, 220 and 230.
    let low = "\u{334}".repeat(256);
    let middle = "\u{316}".repeat(256);
    let high = "\u{301}".repeat(256);
    let ordered = format!("q{low}{middle}{high}");
    assert_eq!(normalized(&ordered), ordered);
    assert_eq!(normalized(&format!("q{high}{middle}{low}")), ordered);
    let equal = format!("q{}", "\u{301}\u{302}".repeat(256));
    assert_eq!(normalized(&equal), equal);
    assert_eq!(
        normalized(&format!("{high}{middle}{low}")),
        format!("{low}{middle}{high}")
    );
    assert_eq!(normalized("\u{344}"), "\u{308}\u{301}");
    assert_eq!(normalized("\u{1100}\u{1161}\u{11a8}"), "\u{ac01}");
}

#[test]
fn reversed_combining_runs_have_linear_reported_work() {
    fn measured(n: usize) -> WriteWork {
        let input = format!(
            "q{}{}{}",
            "\u{301}".repeat(n),
            "\u{316}".repeat(n),
            "\u{334}".repeat(n)
        );
        let mut limits = Limits::new(10_000_000, 100_000_000, 10_000_000);
        let before = limits.remaining();
        let result = encode(&input, &mut limits).unwrap();
        let after = limits.remaining();
        drop(result);
        assert_eq!(limits.live_bytes(), 0);
        WriteWork::new(before.values - after.values, before.bytes - after.bytes)
    }
    let small = measured(512);
    let large = measured(4096);
    assert!(large.values <= small.values * 9);
    assert!(large.bytes <= small.bytes * 9);
}
