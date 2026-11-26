//! Text of ASCII characters alone: dCBOR text whose every code point is below
//! U+0080.
//!
//! An ASCII text is always in NFC and the NFC quick check proves it so (UAX
//! #15, section 9: every ASCII code point is `NFC_Quick_Check=Yes` with
//! canonical combining class 0), under every Unicode version. So a type made
//! of ASCII texts decodes under [`crate::bounded::decode::TextPolicy::QuickOnly`]:
//! no text it accepts needs normalizing to be proved canonical, and its
//! decoding's work does not scale with normalization. The type declares it
//! (its bounded binding's wire profile), so a record of such fields
//! inherits it.

import_stdlib!();

use crate::{Error, Result};

/// The first code point of `text` that is not ASCII, if any: what the
/// bounded decoding of an [`AsciiText`] checks, window by admitted window.
pub(crate) fn first_non_ascii(text: &str) -> Option<char> {
    text.chars().find(|c| !c.is_ascii())
}

/// Text holding only ASCII characters (U+0000 to U+007F): identifiers,
/// tokens and other machine-read strings, whose canonical form no Unicode
/// version can change and whose decoding needs no normalization.
///
/// ```
/// use dcbor::prelude::*;
/// use dcbor::AsciiText;
///
/// # fn main() -> dcbor::Result<()> {
/// let text = AsciiText::new("kappa-registry")?;
/// let cbor = CBOR::from(text.clone());
/// assert_eq!(AsciiText::try_from(cbor)?, text);
/// // U+00E9 is NFC dCBOR text, but not ASCII.
/// assert!(matches!(
///     AsciiText::new("caf\u{e9}"),
///     Err(dcbor::Error::NonAsciiText(0xE9))
/// ));
/// assert!(String::try_from(CBOR::from("caf\u{e9}")).is_ok());
/// # Ok(())
/// # }
/// ```
///
/// Its bounded decoding (`InPlace`) builds the text as a `String` is built,
/// in place, after checking every byte of the decoded text in windows of at
/// most a quantum, each admitted before it is inspected; its wire profile
/// admits only quick-check-proven text.
///
/// Transparent over its `String`: the bounded decoding builds the text at
/// the value's own place.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct AsciiText(String);

impl AsciiText {
    /// `text`, refused with [`Error::NonAsciiText`] at its first code point
    /// that is not ASCII. Every ASCII text is in NFC, so no other check is
    /// needed.
    pub fn new(text: impl Into<String>) -> Result<Self> {
        let text = text.into();
        match first_non_ascii(&text) {
            Some(c) => Err(Error::NonAsciiText(u32::from(c))),
            None => Ok(Self(text)),
        }
    }

    /// The empty text, ASCII as it holds no code point; allocates nothing.
    pub const fn empty() -> Self {
        Self(String::new())
    }
}

crate::checked_text::checked_text!(AsciiText);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CBOR;

    /// The ASCII range's edges: U+0000 and U+007F are accepted, U+0080 is
    /// refused and named, as the first non-ASCII code point of a longer
    /// text is.
    #[test]
    fn the_ascii_range_is_exactly_below_u_0080() {
        assert!(AsciiText::new("\u{0}").is_ok());
        assert!(AsciiText::new("\u{7F}").is_ok());
        assert!(AsciiText::new("").is_ok());
        assert!(
            matches!(AsciiText::new("\u{80}"), Err(Error::NonAsciiText(0x80))),
            "U+0080 was accepted as ASCII"
        );
        assert!(matches!(
            AsciiText::new("ab\u{E9}\u{1F600}"),
            Err(Error::NonAsciiText(0xE9))
        ));
    }

    /// The symbolic decoder refuses a non-ASCII text and any value that is
    /// no text.
    #[test]
    fn the_symbolic_decoder_refuses_what_is_not_ascii_text() {
        assert!(matches!(
            AsciiText::try_from(CBOR::from("\u{E9}")),
            Err(Error::NonAsciiText(0xE9))
        ));
        assert!(matches!(
            AsciiText::try_from(CBOR::from(1u8)),
            Err(Error::WrongType)
        ));
        assert_eq!(
            AsciiText::try_from(CBOR::from("id")).unwrap().as_str(),
            "id"
        );
    }
}
