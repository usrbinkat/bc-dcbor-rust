//! Kani harnesses of header minimality: the canonicality level of the proof
//! hierarchy (register item 4) for heads, and for heads only. Status: the
//! harnesses are written and unverified; none is evidence until the gate
//! runs it and records its row.
//!
//! The theorem is head representation consistency: an integer argument is
//! written and accepted only at its shortest width, the float heads (`f9`,
//! `fa`, `fb`) at their fixed widths being the one exception. It is not
//! numeric-profile acceptance. The parser accepts heads whose items the
//! decoder refuses afterwards, each by its own check, discharged by its own
//! harness:
//!
//! - a negative argument beyond dCBOR's range: `crate::decode::negative`,
//!   the one range rule every decoder calls, its harness over every `u64`
//!   in `src/decode/proofs.rs` (`the_negative_range_rule_is_exact`);
//! - a float that is not canonical at its width: the validators
//!   (`validate_canonical_f16`, `_f32`, `_f64`), called by the
//!   `MajorType::Simple` arm of `decode_cbor_internal`;
//! - a simple value other than `false`, `true` and `null`: the same arm's
//!   `InvalidSimpleValue`.
//!
//! The three have one harness together over every one-item scalar input to
//! the symbolic decoder (`src/decode/proofs.rs`,
//! `a_scalar_item_is_accepted_exactly_in_the_profile`); the validators'
//! agreement with the reduction's reference has its harness over every binary64
//! value in `src/float/proofs.rs` and enumerated over every binary16 value,
//! and every binary32 value in the exhaustive layer (`DCBOR_RIGOR`), in
//! `float.rs`'s tests.
//!
//! Two harnesses, each universal over its stated domain:
//!
//! - the one head writer ([`super::write_argument`]) writes every integer
//!   argument, of every major type, at the shortest width that holds it,
//!   and the decoders' one head parser reads it back;
//! - the one head parser (`crate::decode::parse_header_varint`) accepts a
//!   head only when it is the one the writer writes for what it parsed:
//!   the shortest head of an integer argument, or a float's fixed width.
//!
//! The parser is every decoder's: the symbolic decoder
//! (`decode_cbor_internal`), the bounded flat decoder (`bounded::decode`'s
//! `decode_with`) and the retained header cursor (`HeaderState::step`) each
//! call it (found by search, each call site read), so the second harness
//! is the refusal of every non-shortest head by all three; that the call
//! sites stay the only ones is a search, not part of the proof.
//!
//! Reference semantics (RFC 8949 section 4.2.1, dCBOR's integer rule): an
//! argument below 24 is carried in the initial byte; otherwise in the
//! fewest of one, two, four or eight following bytes that hold it, in
//! network order.
//!
//! The writer's loop runs at most eight times and the comparisons at most
//! nine: `kani::unwind(10)` bounds both, every iteration included.
//! Compiled only under `cfg(kani)`.

use super::{Argument, MAX_HEAD_LEN, MajorType, write_argument};
use crate::decode::parse_header_varint;

/// Every major type, by its three bits.
fn major(bits: u8) -> MajorType {
    match bits & 7 {
        0 => MajorType::Unsigned,
        1 => MajorType::Negative,
        2 => MajorType::ByteString,
        3 => MajorType::Text,
        4 => MajorType::Array,
        5 => MajorType::Map,
        6 => MajorType::Tagged,
        _ => MajorType::Simple,
    }
}

/// The reference width of an integer argument's head: its following bytes.
fn following(value: u64) -> usize {
    if value < 24 {
        0
    } else if value >> 8 == 0 {
        1
    } else if value >> 16 == 0 {
        2
    } else if value >> 32 == 0 {
        4
    } else {
        8
    }
}

/// The additional information of a head of `following` bytes carrying
/// `value`.
fn additional(value: u64, following: usize) -> u8 {
    match following {
        0 => value as u8,
        1 => 24,
        2 => 25,
        4 => 26,
        _ => 27,
    }
}

/// Every integer argument of every major type is written at its reference
/// width, its additional information and its bytes in network order, and
/// the decoders' parser reads it back whole.
#[kani::proof]
#[kani::unwind(10)]
fn every_integer_head_is_the_shortest_and_reads_back() {
    let value: u64 = kani::any();
    let major_type = major(kani::any());
    let mut out = [0u8; MAX_HEAD_LEN];
    let length = write_argument(major_type, Argument::Shortest(value), &mut out);
    let width = following(value);
    assert!(
        length == 1 + width,
        "a head takes the fewest following bytes"
    );
    assert!(
        out[0] & 31 == additional(value, width),
        "a head's additional information names its width"
    );
    let mut carried = 0u64;
    for byte in &out[1..length] {
        carried = (carried << 8) | u64::from(*byte);
    }
    assert!(
        width == 0 || carried == value,
        "a head's following bytes carry its argument in network order"
    );
    assert!(
        matches!(
            parse_header_varint(&out[..length]),
            Ok((parsed, read, len)) if parsed == major_type && read == value && len == length
        ),
        "the decoders read every written head back whole"
    );
}

/// Every head the decoders' parser accepts, of any bytes and any length up
/// to the widest, is exactly the head the writer writes for what it
/// parsed: the shortest head of an integer argument, or, for the three
/// float heads (`f9`, `fa`, `fb`), the float's fixed width. So every
/// non-shortest head of an integer argument is refused.
#[kani::proof]
#[kani::unwind(10)]
fn the_decoders_accept_only_the_heads_the_writer_writes() {
    let bytes: [u8; MAX_HEAD_LEN] = kani::any();
    let available: usize = kani::any();
    kani::assume(available <= MAX_HEAD_LEN);
    let input = &bytes[..available];
    if let Ok((major_type, value, length)) = parse_header_varint(input) {
        let argument = match bytes[0] {
            0xf9 => Argument::Fixed16(value as u16),
            0xfa => Argument::Fixed32(value as u32),
            0xfb => Argument::Fixed64(value),
            _ => Argument::Shortest(value),
        };
        let mut written = [0u8; MAX_HEAD_LEN];
        let written_length = write_argument(major_type, argument, &mut written);
        assert!(
            written_length == length && written[..length] == input[..length],
            "an accepted head is the one the writer writes"
        );
    }
}
