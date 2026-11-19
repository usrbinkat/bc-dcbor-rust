//! Text stabilized under the pinned Unicode version (UAX #15, section 12,
//! normalization process for stabilized strings): dCBOR text, so in NFC,
//! that holds no code point the pinned version leaves unassigned. dCBOR
//! itself requires only NFC; a code point unassigned today may be assigned
//! by a later version with a decomposition or a combining class, under
//! which this NFC text would no longer be normal. A stabilized text holds
//! none, so its normal form is the same under every later version.
//!
//! The assigned set is generated at build time from the package's one copy
//! of the pinned version's `DerivedAge.txt` (`data/unicode`, `build.rs`),
//! never written by hand; that its version is the one the pinned
//! `unicode-normalization` normalizes by is checked at compile time.

import_stdlib!();

use unicode_normalization::is_nfc;

use crate::{CBOR, CBORCase, Error, Result};

/// The build script's table: [`assigned::DERIVED_AGE_VERSION`] and
/// [`assigned::ASSIGNED`].
mod assigned {
    include!(concat!(env!("OUT_DIR"), "/unicode_assigned.rs"));
}

/// The Unicode version this crate normalizes by and checks text against:
/// the pinned `unicode-normalization`'s, re-exported, the one constant the
/// gates read into their input-closure identity.
pub use unicode_normalization::UNICODE_VERSION;

// The data the assigned set is generated from is of the version the pinned
// normalization is: a pin moved without its data, or data moved without the
// pin, fails to compile here (E0080).
const _: () = assert!(
    assigned::DERIVED_AGE_VERSION.0 == UNICODE_VERSION.0
        && assigned::DERIVED_AGE_VERSION.1 == UNICODE_VERSION.1
        && assigned::DERIVED_AGE_VERSION.2 == UNICODE_VERSION.2,
    "data/unicode's DerivedAge.txt is not of the Unicode version unicode-normalization pins"
);

/// Whether `c` is assigned in the pinned Unicode version.
pub fn is_assigned(c: char) -> bool {
    assigned_in(assigned::ASSIGNED, c)
}

/// Whether `c` lies in one of `table`'s sorted, disjoint inclusive ranges:
/// the one lookup, over the generated table or, in the tests' planted
/// controls, over another.
pub(crate) fn assigned_in(table: &[(u32, u32)], c: char) -> bool {
    let point = u32::from(c);
    table
        .binary_search_by(|&(start, end)| {
            if end < point {
                cmp::Ordering::Less
            } else if start > point {
                cmp::Ordering::Greater
            } else {
                cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// The first code point of `text` the pinned version leaves unassigned, if
/// any: what the bounded decoding of a [`StabilizedText`] checks, window by
/// admitted window.
pub(crate) fn first_unassigned(text: &str) -> Option<char> {
    first_unassigned_in(assigned::ASSIGNED, text)
}

/// The first code point of `text` not in `table`, if any.
pub(crate) fn first_unassigned_in(table: &[(u32, u32)], text: &str) -> Option<char> {
    text.chars().find(|&c| !assigned_in(table, c))
}

/// `text` as a stabilized text under `table`: refused with
/// [`Error::NonCanonicalString`] unless in NFC, then with
/// [`Error::UnassignedCodePoint`] at its first code point `table` does not
/// assign.
pub(crate) fn check_in(table: &[(u32, u32)], text: &str) -> Result<()> {
    if !is_nfc(text) {
        return Err(Error::NonCanonicalString);
    }
    match first_unassigned_in(table, text) {
        Some(c) => Err(Error::UnassignedCodePoint(u32::from(c))),
        None => Ok(()),
    }
}

/// Text in NFC holding only code points assigned in the pinned Unicode
/// version ([`UNICODE_VERSION`]): what dCBOR accepts as text, and nothing a
/// later Unicode version could renormalize.
///
/// ```
/// use dcbor::prelude::*;
/// use dcbor::StabilizedText;
///
/// # fn main() -> dcbor::Result<()> {
/// // U+1FA8A TROMBONE, assigned in Unicode 17.0.
/// let text = StabilizedText::new("\u{1FA8A}")?;
/// let cbor = CBOR::from(text.clone());
/// assert_eq!(StabilizedText::try_from(cbor)?, text);
/// // U+0378 is unassigned: plain dCBOR text, but not stabilized.
/// assert!(matches!(
///     StabilizedText::new("\u{378}"),
///     Err(dcbor::Error::UnassignedCodePoint(0x378))
/// ));
/// assert!(String::try_from(CBOR::from("\u{378}")).is_ok());
/// # Ok(())
/// # }
/// ```
///
/// Its bounded decoding (`InPlace`) builds the text as a `String` is built,
/// in place, after checking every code point of the decoded text, which
/// dCBOR's decoder has already proved NFC, in windows of at most a quantum,
/// each admitted before it is inspected.
///
/// Transparent over its `String`: the bounded decoding builds the text at
/// the value's own place.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct StabilizedText(String);

impl StabilizedText {
    /// `text`, refused unless in NFC ([`Error::NonCanonicalString`]) and
    /// holding only assigned code points ([`Error::UnassignedCodePoint`],
    /// naming the first that is not).
    pub fn new(text: impl Into<String>) -> Result<Self> {
        let text = text.into();
        check_in(assigned::ASSIGNED, &text)?;
        Ok(Self(text))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl TryFrom<String> for StabilizedText {
    type Error = Error;

    fn try_from(text: String) -> Result<Self> {
        Self::new(text)
    }
}

impl From<StabilizedText> for CBOR {
    fn from(text: StabilizedText) -> Self {
        CBOR::from(text.0)
    }
}

/// A CBOR text, accepted as dCBOR accepts it (NFC), then refused at its
/// first code point the pinned version does not assign; any other value
/// is [`Error::WrongType`].
impl TryFrom<CBOR> for StabilizedText {
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        match cbor.into_case() {
            CBORCase::Text(text) => Self::new(text),
            _ => Err(Error::WrongType),
        }
    }
}

/// Bounded encoding: a stabilized text encodes as its text, which its
/// construction already proved stabilized.
impl crate::bounded::encoding::Schema for StabilizedText {
    fn instruction(&self, index: usize) -> crate::bounded::encoding::Instruction<'_> {
        crate::bounded::encoding::Schema::instruction(self.0.as_str(), index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The generated table is sorted, disjoint and non-adjacent, within the
    /// code space, and of the pinned version.
    #[test]
    fn the_generated_table_is_sorted_disjoint_and_of_the_pinned_version() {
        assert_eq!(assigned::DERIVED_AGE_VERSION, UNICODE_VERSION);
        assert!(!assigned::ASSIGNED.is_empty());
        for window in assigned::ASSIGNED.windows(2) {
            let ((_, end), (start, _)) = (window[0], window[1]);
            assert!(end + 1 < start, "{window:?} overlap or touch");
        }
        for &(start, end) in assigned::ASSIGNED {
            assert!(start <= end && end <= 0x10_FFFF, "{start:X}..{end:X}");
        }
    }

    /// U+0378, unassigned in the pinned version: no line of its
    /// `DerivedAge.txt` lists it (lines 895 `0376..0377` and 71 `037A` are
    /// the nearest).
    const UNASSIGNED: char = '\u{378}';

    /// U+1FA8A TROMBONE, assigned in 17.0 (`DerivedAge.txt` line 2106).
    const TROMBONE: char = '\u{1FA8A}';

    /// The refusal of an unassigned code point rests on the table alone: a
    /// planted table marking it assigned accepts it, so the refusal the
    /// generated table makes is the table's, not the check's.
    #[test]
    fn a_table_marking_an_unassigned_code_point_assigned_accepts_it() {
        let text = String::from(UNASSIGNED);
        assert!(matches!(
            check_in(assigned::ASSIGNED, &text),
            Err(Error::UnassignedCodePoint(0x378))
        ));
        let mut planted: Vec<(u32, u32)> = assigned::ASSIGNED.to_vec();
        planted.push((0x378, 0x378));
        planted.sort_unstable();
        assert!(
            check_in(&planted, &text).is_ok(),
            "the planted table still refused U+0378"
        );
    }

    /// A table missing the range that assigns a code point refuses it: the
    /// planted table drops the range holding U+1FA8A, and the check then
    /// refuses it, naming it.
    #[test]
    fn a_table_missing_a_range_refuses_what_that_range_assigns() {
        let text = String::from(TROMBONE);
        assert!(check_in(assigned::ASSIGNED, &text).is_ok());
        let planted: Vec<(u32, u32)> = assigned::ASSIGNED
            .iter()
            .copied()
            .filter(|&(start, end)| !(start <= 0x1FA8A && 0x1FA8A <= end))
            .collect();
        assert_eq!(planted.len() + 1, assigned::ASSIGNED.len());
        assert!(matches!(
            check_in(&planted, &text),
            Err(Error::UnassignedCodePoint(0x1FA8A))
        ));
    }

    /// The lookup at each edge of every range: its first and last code
    /// points are assigned, the code points just outside are not, unless an
    /// adjacent range covers them, which a merged table never has.
    #[test]
    fn every_range_edge_is_looked_up_exactly() {
        let table = assigned::ASSIGNED;
        for &(start, end) in table {
            for point in [start, end] {
                if let Some(c) = char::from_u32(point) {
                    assert!(assigned_in(table, c), "U+{point:04X}");
                }
            }
            for point in [start.checked_sub(1), end.checked_add(1)]
                .into_iter()
                .flatten()
            {
                if let Some(c) = char::from_u32(point) {
                    assert!(!assigned_in(table, c), "U+{point:04X} outside its range");
                }
            }
        }
    }
}
