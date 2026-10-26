use super::*;
use crate::bounded::text::QuickCheck;

/// Validating one scalar, or a text's end: one value and a scalar's most
/// bytes. The parser supplies the place.
pub(super) const SCALAR: Unit<Caller> = Unit::new(Caller, 1, char::MAX.len_utf8() as u64);

pub(super) struct Utf8 {
    pub(super) position: usize,
    /// The NFC quick check over the scalars validated so far.
    pub(super) quick: QuickCheck,
}

impl Utf8 {
    pub(super) fn new() -> Self {
        Self {
            position: 0,
            quick: QuickCheck::new(),
        }
    }

    pub(super) fn step<'a, B: Budget>(
        &mut self,
        bytes: &'a [u8],
        budget: &mut B,
    ) -> Result<Option<&'a str>, DecodeError<B::Refusal>> {
        SCALAR.admit(budget)?;
        if self.position == bytes.len() {
            // SAFETY: position advances only across complete scalar slices
            // accepted by str::from_utf8 below. It began at zero and now equals
            // the entire slice length. The enclosing parser always supplies
            // the same immutable payload throughout validation.
            return Ok(Some(unsafe { core::str::from_utf8_unchecked(bytes) }));
        }
        let width = match bytes[self.position] {
            0..=0x7f => 1,
            0xc2..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf4 => 4,
            _ => 1,
        };
        let remaining = bytes.len() - self.position;
        let end = self.position + width.min(remaining);
        let scalar =
            core::str::from_utf8(&bytes[self.position..end]).map_err(Error::InvalidUtf8)?;
        let ch = scalar.chars().next().ok_or(Error::Underrun)?;
        self.quick.scalar(ch);
        self.position = end;
        Ok(None)
    }
}
