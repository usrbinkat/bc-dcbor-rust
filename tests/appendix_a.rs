//! dCBOR conformance: Appendix A, "dCBOR Numeric Test Vectors", of the
//! Internet-Draft revision this crate implements
//! (`dcbor::DCBOR_DRAFT_REVISION`), copied unchanged into
//! `tests/data/dcbor-appendix-a.md` (provenance and license in
//! `tests/data/README.md`). The vectors are the oracle, read as the draft
//! publishes them: the file is compiled in, so a run reads no file and runs
//! unchanged under Miri's isolation, in every domain, with no feature gate.
//! Data of another revision is refused before any row is read.
//!
//! Every row of the table of valid encodings is encoded by the symbolic and
//! the bounded encoder from each host value the row names, and decoded by
//! both decoders to the value it names; every row of the table of invalid
//! encodings is refused by both decoders with the error its reason names.
//! No row count is written here.

use core::mem::discriminant;

use dcbor::bounded::decode::{DecodeError, Kind, decode};
use dcbor::bounded::{Limits, Schema, encode};
use dcbor::{CBOR, DCBOR_DRAFT_REVISION, Error};
use half::f16;

/// The pinned revision's Appendix A, its provenance on the first line.
const APPENDIX_A: &str = include_str!("data/dcbor-appendix-a.md");

/// The opening of the provenance line; the revision follows it, then a
/// comma.
const PROVENANCE: &str = "<!-- ";

/// The bounded decoder's nesting limit for every vector: each is one scalar
/// node, and `bounded::decode::decode` counts array, map and tag ancestors,
/// a scalar having depth zero. The least limit that decodes one node; no
/// relation to the symbolic profile's `SYMBOLIC_DEPTH` is implied.
const SCALAR_DEPTH: usize = 0;

/// A value as the first token of a row's value column names it.
#[derive(Clone, Copy, Debug)]
enum Value {
    /// An integer in `0..=u64::MAX`.
    Unsigned(u64),
    /// An integer in `i64::MIN..0`.
    Negative(i64),
    /// An integer below `i64::MIN`, outside dCBOR's integer range: named by
    /// rows of the invalid table only.
    Beyond(i128),
    Float(f64),
    Infinity,
    NegativeInfinity,
    NaN,
}

/// Why a row of the invalid table is refused, as its reason column names it.
#[derive(Clone, Copy, Debug)]
enum Reason {
    /// "Can be reduced to ...": a float whose value has a shorter form.
    Reducible,
    /// "Not preferred encoding.": a float wider than its value needs.
    NotPreferred,
    /// "Not canonical NaN.": a NaN other than `f97e00`.
    NonCanonicalNaN,
    /// "65-bit negative integer value.": below dCBOR's integer range.
    NegativeBeyondRange,
}

impl Reason {
    /// The reason column's text this reason is named by.
    const NAMES: [(&'static str, Reason); 4] = [
        ("Can be reduced", Reason::Reducible),
        ("Not preferred encoding", Reason::NotPreferred),
        ("Not canonical NaN", Reason::NonCanonicalNaN),
        ("65-bit negative integer value", Reason::NegativeBeyondRange),
    ];

    /// The error both decoders must refuse a row of this reason with: a
    /// float or head not in its narrowest canonical form is
    /// `NonCanonicalNumeric` (`float::validate_canonical_*`,
    /// `decode::parse_header_varint`); a negative integer below the range is
    /// `OutOfRange`.
    fn error(self) -> Error {
        match self {
            Reason::Reducible | Reason::NotPreferred | Reason::NonCanonicalNaN => {
                Error::NonCanonicalNumeric
            }
            Reason::NegativeBeyondRange => Error::OutOfRange,
        }
    }
}

/// A row of the table of valid encodings.
struct Valid {
    line: usize,
    value: Value,
    /// "(any size)": every float width holding the value encodes the row.
    any_size: bool,
    /// "(any payload)": every NaN payload encodes the row.
    any_payload: bool,
    encoding: Vec<u8>,
}

/// A row of the table of invalid encodings.
struct Invalid {
    line: usize,
    value: Value,
    encoding: Vec<u8>,
    reason: Reason,
}

/// Both tables, in file order.
struct Vectors {
    valid: Vec<Valid>,
    invalid: Vec<Invalid>,
}

/// Which table a separator line opens, from its heading's third column.
#[derive(Clone, Copy, PartialEq)]
enum Table {
    Valid,
    Invalid,
}

/// The file's vectors, refused unless its first line names `pinned`, the
/// revision this crate implements, and every table is one of the two the
/// appendix defines, each present once, holding rows of three cells: a
/// value, an encoding in backticks, and a note or a known reason.
fn parse(text: &str, pinned: &str) -> Result<Vectors, String> {
    let header = text.lines().next().unwrap_or_default();
    let named = header
        .strip_prefix(PROVENANCE)
        .and_then(|rest| rest.split_once(','))
        .map(|(revision, _)| revision)
        .ok_or_else(|| format!("line 1, {header:?}, is not a provenance line"))?;
    if named != pinned {
        return Err(format!(
            "the data is of {named}, the crate implements {pinned}"
        ));
    }
    let lines: Vec<&str> = text.lines().collect();
    let mut vectors = Vectors {
        valid: Vec::new(),
        invalid: Vec::new(),
    };
    let mut seen: Vec<Table> = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        if !lines[index].starts_with("| :") {
            index += 1;
            continue;
        }
        let at = index + 1;
        let heading = index
            .checked_sub(1)
            .map(|previous| cells(lines[previous], previous + 1))
            .ok_or_else(|| format!("line {at}: a separator with no heading"))??;
        let table = match heading[2] {
            "Note" => Table::Valid,
            "Reason for Rejection" => Table::Invalid,
            other => {
                return Err(format!(
                    "line {at}: a table whose third column is {other:?}"
                ));
            }
        };
        if seen.contains(&table) {
            return Err(format!("line {at}: a second table of the same kind"));
        }
        seen.push(table);
        index += 1;
        while index < lines.len() && !lines[index].trim().is_empty() {
            let line = index + 1;
            let [value_cell, encoding_cell, third] = cells(lines[index], line)?;
            let (value, any_size, any_payload) =
                value_of(value_cell).map_err(|error| format!("line {line}: {error}"))?;
            let encoding =
                encoding_of(encoding_cell).map_err(|error| format!("line {line}: {error}"))?;
            match table {
                Table::Valid => {
                    if let Value::Beyond(n) = value {
                        return Err(format!(
                            "line {line}: {n} is outside dCBOR's integer range in the table of valid encodings"
                        ));
                    }
                    vectors.valid.push(Valid {
                        line,
                        value,
                        any_size,
                        any_payload,
                        encoding,
                    });
                }
                Table::Invalid => {
                    if any_size || any_payload {
                        return Err(format!(
                            "line {line}: a qualifier in the table of invalid encodings"
                        ));
                    }
                    let reason = Reason::NAMES
                        .iter()
                        .find(|(name, _)| third.starts_with(name))
                        .map(|&(_, reason)| reason)
                        .ok_or_else(|| format!("line {line}: no known reason {third:?}"))?;
                    if !names_its_encoding(value, &encoding) {
                        return Err(format!(
                            "line {line}: {value_cell:?} is not the value its encoding holds"
                        ));
                    }
                    vectors.invalid.push(Invalid {
                        line,
                        value,
                        encoding,
                        reason,
                    });
                }
            }
            index += 1;
        }
    }
    if vectors.valid.is_empty() {
        return Err("the data holds no row of valid encodings".to_string());
    }
    if vectors.invalid.is_empty() {
        return Err("the data holds no row of invalid encodings".to_string());
    }
    Ok(vectors)
}

/// A table row's three cells, trimmed: `| a | b | c |`.
fn cells(line: &str, number: usize) -> Result<[&str; 3], String> {
    let inner = line
        .strip_prefix('|')
        .and_then(|rest| rest.strip_suffix('|'))
        .ok_or_else(|| format!("line {number}: {line:?} is not a table row"))?;
    let parts: Vec<&str> = inner.split('|').map(str::trim).collect();
    <[&str; 3]>::try_from(parts.as_slice())
        .map_err(|_| format!("line {number}: {line:?} is not three cells"))
}

/// A value cell: its first token, `Infinity`, `-Infinity` or `NaN`, else an
/// integer (a decimal or exponent marks a float), then an optional
/// parenthesized annotation whose items `any size` and `any payload` are
/// qualifiers, each allowed only where the value names a class of floats.
/// Other items are the draft's arithmetic notes and are ignored, except an
/// item beginning `any `, which can only be a misspelled qualifier: ignoring
/// it would test the row with fewer host values, so it is refused.
fn value_of(cell: &str) -> Result<(Value, bool, bool), String> {
    let (token, rest) = cell
        .split_once(char::is_whitespace)
        .map_or((cell, ""), |(token, rest)| (token, rest.trim()));
    let value = match token {
        "Infinity" => Value::Infinity,
        "-Infinity" => Value::NegativeInfinity,
        "NaN" => Value::NaN,
        _ if token.contains(['.', 'e', 'E']) => Value::Float(
            token
                .parse::<f64>()
                .map_err(|error| format!("{token:?} is not a float: {error}"))?,
        ),
        _ => {
            let n = token
                .parse::<i128>()
                .map_err(|error| format!("{token:?} is not an integer: {error}"))?;
            if let Ok(unsigned) = u64::try_from(n) {
                Value::Unsigned(unsigned)
            } else if let Ok(negative) = i64::try_from(n) {
                Value::Negative(negative)
            } else if n < 0 {
                Value::Beyond(n)
            } else {
                return Err(format!("{n} exceeds every CBOR integer"));
            }
        }
    };
    let (mut any_size, mut any_payload) = (false, false);
    if !rest.is_empty() {
        let annotation = rest
            .strip_prefix('(')
            .and_then(|inner| inner.strip_suffix(')'))
            .ok_or_else(|| format!("{rest:?} after the value is not an annotation"))?;
        for item in annotation.split(',').map(str::trim) {
            match item {
                "any size" => any_size = true,
                "any payload" => any_payload = true,
                _ if item.starts_with("any ") => {
                    return Err(format!("{item:?} is no qualifier"));
                }
                _ => {}
            }
        }
    }
    let floats = matches!(
        value,
        Value::Infinity | Value::NegativeInfinity | Value::NaN
    );
    if any_size && !floats {
        return Err(format!("\"any size\" qualifies {token:?}"));
    }
    if any_payload && !matches!(value, Value::NaN) {
        return Err(format!("\"any payload\" qualifies {token:?}"));
    }
    Ok((value, any_size, any_payload))
}

/// An encoding cell: hexadecimal in backticks.
fn encoding_of(cell: &str) -> Result<Vec<u8>, String> {
    let digits = cell
        .strip_prefix('`')
        .and_then(|rest| rest.strip_suffix('`'))
        .ok_or_else(|| format!("{cell:?} is not an encoding in backticks"))?;
    hex::decode(digits).map_err(|error| format!("{digits:?} is not hexadecimal: {error}"))
}

/// The float a float head's bytes hold, at the width the head names.
fn wire_float(encoding: &[u8]) -> Option<f64> {
    match *encoding {
        [0xf9, a, b] => Some(f16::from_bits(u16::from_be_bytes([a, b])).to_f64()),
        [0xfa, a, b, c, d] => Some(f64::from(f32::from_bits(u32::from_be_bytes([a, b, c, d])))),
        [0xfb, ..] if encoding.len() == 9 => {
            let bits: [u8; 8] = encoding[1..].try_into().ok()?;
            Some(f64::from_bits(u64::from_be_bytes(bits)))
        }
        _ => None,
    }
}

/// Whether an invalid row's value is the value its encoding holds: a float
/// head's float, or an eight-byte negative head's `-1 - argument`. The
/// invalid table's rows are wire shapes a decoder must refuse; this ties
/// each to the value the draft says it is.
fn names_its_encoding(value: Value, encoding: &[u8]) -> bool {
    if let Some(float) = wire_float(encoding) {
        return match value {
            Value::Float(v) => float == v,
            Value::Infinity => float == f64::INFINITY,
            Value::NegativeInfinity => float == f64::NEG_INFINITY,
            Value::NaN => float.is_nan(),
            _ => false,
        };
    }
    match *encoding {
        [0x3b, ..] if encoding.len() == 9 => {
            let Ok(bits) = <[u8; 8]>::try_from(&encoding[1..]) else {
                return false;
            };
            let n = -1 - i128::from(u64::from_be_bytes(bits));
            match value {
                Value::Beyond(b) => b == n,
                Value::Negative(i) => i128::from(i) == n,
                _ => false,
            }
        }
        _ => false,
    }
}

/// The file's vectors at the pinned revision.
fn vectors() -> Vectors {
    parse(APPENDIX_A, DCBOR_DRAFT_REVISION)
        .unwrap_or_else(|error| panic!("dcbor-appendix-a.md: {error}"))
}

/// A host value one of the encoders is given.
#[derive(Clone, Copy, Debug)]
enum Host {
    U64(u64),
    I64(i64),
    F64(f64),
    F32(f32),
    F16(f16),
}

impl Host {
    fn symbolic(self) -> Vec<u8> {
        match self {
            Host::U64(v) => CBOR::from(v),
            Host::I64(v) => CBOR::from(v),
            Host::F64(v) => CBOR::from(v),
            Host::F32(v) => CBOR::from(v),
            Host::F16(v) => CBOR::from(v),
        }
        .to_cbor_data()
    }

    fn bounded(self) -> Vec<u8> {
        match self {
            Host::U64(v) => encoded(&v),
            Host::I64(v) => encoded(&v),
            Host::F64(v) => encoded(&v),
            Host::F32(v) => encoded(&v),
            Host::F16(v) => encoded(&v),
        }
    }

    /// The host value whose float the bytes of a float head hold, at that
    /// width.
    fn of_wire_float(encoding: &[u8]) -> Option<Host> {
        match *encoding {
            [0xf9, a, b] => Some(Host::F16(f16::from_bits(u16::from_be_bytes([a, b])))),
            [0xfa, a, b, c, d] => Some(Host::F32(f32::from_bits(u32::from_be_bytes([a, b, c, d])))),
            [0xfb, ..] => wire_float(encoding).map(Host::F64),
            _ => None,
        }
    }
}

/// The bounded encoding of `value` under an unlimited policy.
fn encoded(value: &(impl Schema + ?Sized)) -> Vec<u8> {
    encode(value, &mut Limits::unlimited())
        .expect("an unlimited encoding completes")
        .as_ref()
        .to_vec()
}

/// `n` as each float width that holds it exactly: dCBOR reduces a whole
/// float to its integer, so each must encode as the integer does.
fn exact_floats(n: i128) -> Vec<Host> {
    let mut hosts = Vec::new();
    let double = n as f64;
    if double as i128 == n {
        hosts.push(Host::F64(double));
    }
    let single = n as f32;
    if single as i128 == n {
        hosts.push(Host::F32(single));
    }
    let half = f16::from_f64(double);
    if half.to_f64() as i128 == n && half.is_finite() {
        hosts.push(Host::F16(half));
    }
    hosts
}

/// Every host value a valid row names: its integer and each float width
/// holding it exactly; its float at each width holding it exactly; for an
/// "any size" row the value at every width; for an "any payload" row also
/// every NaN of the invalid table, at the width its encoding names.
fn hosts(row: &Valid, invalid: &[Invalid]) -> Vec<Host> {
    let mut hosts = Vec::new();
    match row.value {
        Value::Unsigned(n) => {
            hosts.push(Host::U64(n));
            hosts.extend(exact_floats(i128::from(n)));
        }
        Value::Negative(n) => {
            hosts.push(Host::I64(n));
            hosts.extend(exact_floats(i128::from(n)));
        }
        Value::Float(v) => {
            hosts.push(Host::F64(v));
            let single = v as f32;
            if f64::from(single) == v {
                hosts.push(Host::F32(single));
            }
            let half = f16::from_f64(v);
            if half.to_f64() == v {
                hosts.push(Host::F16(half));
            }
        }
        Value::Infinity | Value::NegativeInfinity | Value::NaN => {
            let (double, single, half) = match row.value {
                Value::Infinity => (f64::INFINITY, f32::INFINITY, f16::INFINITY),
                Value::NegativeInfinity => {
                    (f64::NEG_INFINITY, f32::NEG_INFINITY, f16::NEG_INFINITY)
                }
                _ => (f64::NAN, f32::NAN, f16::NAN),
            };
            hosts.push(Host::F64(double));
            if row.any_size {
                hosts.push(Host::F32(single));
                hosts.push(Host::F16(half));
            }
            if row.any_payload {
                let payloads: Vec<Host> = invalid
                    .iter()
                    .filter(|other| matches!(other.value, Value::NaN))
                    .map(|other| {
                        Host::of_wire_float(&other.encoding).unwrap_or_else(|| {
                            panic!("line {}: a NaN with no float head", other.line)
                        })
                    })
                    .collect();
                assert!(
                    !payloads.is_empty(),
                    "line {}: any payload, and the invalid table holds no NaN",
                    row.line
                );
                hosts.extend(payloads);
            }
        }
        Value::Beyond(_) => unreachable!("refused by parse in the valid table"),
    }
    hosts
}

/// The bounded decoder's root value is the row's value: an integer as
/// itself, a whole float reduced to its integer, a float as itself.
fn bounded_means(at: &str, value: Value, kind: Kind<'_>) {
    let holds = match (value, kind) {
        (Value::Unsigned(n), Kind::Unsigned(m)) => n == m,
        (Value::Negative(n), Kind::Negative(m)) => n == m,
        (Value::Float(v), Kind::Unsigned(m)) => v.fract() == 0.0 && v as i128 == i128::from(m),
        (Value::Float(v), Kind::Negative(m)) => v.fract() == 0.0 && v as i128 == i128::from(m),
        (Value::Float(v), Kind::Float(f)) => v == f,
        (Value::Infinity, Kind::Float(f)) => f == f64::INFINITY,
        (Value::NegativeInfinity, Kind::Float(f)) => f == f64::NEG_INFINITY,
        (Value::NaN, Kind::Float(f)) => f.is_nan(),
        _ => false,
    };
    assert!(holds, "{at}: the bounded decoder read {kind:?}");
}

/// The symbolic decoder's value is the row's value, extracted as the row's
/// type.
fn symbolic_means(at: &str, value: Value, cbor: CBOR) {
    match value {
        Value::Unsigned(n) => assert_eq!(u64::try_from(cbor).ok(), Some(n), "{at}: decoded"),
        Value::Negative(n) => assert_eq!(i64::try_from(cbor).ok(), Some(n), "{at}: decoded"),
        Value::Float(v) => assert_eq!(f64::try_from(cbor).ok(), Some(v), "{at}: decoded"),
        Value::Infinity => {
            assert_eq!(
                f64::try_from(cbor).ok(),
                Some(f64::INFINITY),
                "{at}: decoded"
            );
        }
        Value::NegativeInfinity => {
            assert_eq!(
                f64::try_from(cbor).ok(),
                Some(f64::NEG_INFINITY),
                "{at}: decoded"
            );
        }
        Value::NaN => assert!(
            f64::try_from(cbor).is_ok_and(f64::is_nan),
            "{at}: decoded as no NaN"
        ),
        Value::Beyond(_) => unreachable!("refused by parse in the valid table"),
    }
}

/// The data is of the revision the crate implements, read through the
/// library (`dcbor::DCBOR_DRAFT_REVISION`), never named here.
#[test]
fn the_data_is_of_the_pinned_draft_revision() {
    let header = APPENDIX_A.lines().next().expect("a provenance line");
    assert!(
        header.starts_with(&format!("{PROVENANCE}{DCBOR_DRAFT_REVISION},")),
        "{header}"
    );
    vectors();
}

/// The revision check refuses data of either neighbouring revision, naming
/// both, and data without its provenance line: the planted controls of the
/// check above, each revision derived from the pinned one, never written
/// here.
#[test]
fn data_of_another_revision_is_refused() {
    let (name, number) = DCBOR_DRAFT_REVISION
        .rsplit_once('-')
        .expect("a revision ends in its number");
    let width = number.len();
    let revision: u32 = number.parse().expect("a revision number");
    let (header, body) = APPENDIX_A.split_once('\n').expect("a provenance line");
    let rest = header
        .strip_prefix(PROVENANCE)
        .and_then(|rest| rest.strip_prefix(DCBOR_DRAFT_REVISION))
        .expect("the provenance line names the pinned revision");
    for other in [revision - 1, revision + 1] {
        let other = format!("{name}-{other:0width$}");
        let planted = format!("{PROVENANCE}{other}{rest}\n{body}");
        let error = parse(&planted, DCBOR_DRAFT_REVISION)
            .err()
            .unwrap_or_else(|| panic!("data of {other} was accepted"));
        assert!(
            error.contains(&other) && error.contains(DCBOR_DRAFT_REVISION),
            "{error}"
        );
    }
    let error = parse(body, DCBOR_DRAFT_REVISION)
        .err()
        .expect("data without its provenance line was accepted");
    assert!(error.starts_with("line 1"), "{error}");
}

/// A malformed row is refused naming its line: the planted controls of the
/// row parser, each a one-cell change to a row of the data. An encoding out
/// of backticks, a value token that is no number, a reason the appendix
/// does not define, an invalid row whose encoding holds another value, and a
/// misspelled qualifier.
#[test]
fn a_malformed_row_is_refused_naming_its_line() {
    for (from, to) in [
        ("`f93e00`", "f93e00"),
        ("| 1.5 ", "| x1.5 "),
        ("Not canonical NaN.", "Not a reason."),
        ("`f94a00`", "`f94b00`"),
        ("any payload", "any payloads"),
    ] {
        let line = APPENDIX_A
            .lines()
            .position(|line| line.contains(from))
            .unwrap_or_else(|| panic!("no row holds {from:?}"))
            + 1;
        let planted = APPENDIX_A.replacen(from, to, 1);
        let error = parse(&planted, DCBOR_DRAFT_REVISION)
            .err()
            .unwrap_or_else(|| panic!("{from:?} replaced by {to:?} was accepted"));
        assert!(
            error.starts_with(&format!("line {line}:")),
            "{from:?} replaced by {to:?}: {error}"
        );
    }
}

/// Every valid row in both directions. Encoding: each host value the row
/// names is encoded to the row's bytes by the symbolic and the bounded
/// encoder. Decoding: the row's bytes are accepted by the symbolic decoder,
/// re-encode to themselves and decode to the row's value, and are accepted
/// by the bounded decoder, whose root is the row's value.
#[test]
fn every_valid_encoding_is_produced_and_accepted_by_both_paths() {
    let vectors = vectors();
    for row in &vectors.valid {
        let at = format!("line {}", row.line);
        for host in hosts(row, &vectors.invalid) {
            assert_eq!(host.symbolic(), row.encoding, "{at}: symbolic {host:?}");
            assert_eq!(host.bounded(), row.encoding, "{at}: bounded {host:?}");
        }
        let cbor = CBOR::try_from_data(&row.encoding)
            .unwrap_or_else(|error| panic!("{at}: the symbolic decoder refused: {error}"));
        assert_eq!(cbor.to_cbor_data(), row.encoding, "{at}: re-encoded");
        symbolic_means(&at, row.value, cbor);
        let mut limits = Limits::unlimited();
        let document = decode(&row.encoding, SCALAR_DEPTH, &mut limits)
            .unwrap_or_else(|error| panic!("{at}: the bounded decoder refused: {error:?}"));
        bounded_means(&at, row.value, document.root().kind());
        assert_eq!(document.root().encoded(), row.encoding.as_slice(), "{at}");
    }
}

/// Every invalid row is refused by both decoders with the error its reason
/// names: the symbolic decoder's own error, and the bounded decoder's
/// `DecodeError::Invalid` carrying it.
#[test]
fn every_invalid_encoding_is_refused_by_both_decoders_for_its_reason() {
    for row in vectors().invalid {
        let at = format!("line {} ({:?}, {:?})", row.line, row.value, row.reason);
        let expected = row.reason.error();
        match CBOR::try_from_data(&row.encoding) {
            Err(error) if discriminant(&error) == discriminant(&expected) => {}
            other => panic!("{at}: the symbolic decoder returned {other:?}, expected {expected:?}"),
        }
        let mut limits = Limits::unlimited();
        match decode(&row.encoding, SCALAR_DEPTH, &mut limits).map(|_| ()) {
            Err(DecodeError::Invalid(error)) if discriminant(&error) == discriminant(&expected) => {
            }
            other => panic!("{at}: the bounded decoder returned {other:?}, expected {expected:?}"),
        }
    }
}
