use super::*;
use unicode_normalization::{IsNormalized, char::canonical_combining_class, is_nfc_quick};

pub(super) struct Utf8<'a> {
    bytes: &'a [u8],
    pub(super) position: usize,
    last_class: u8,
    pub(super) quick: IsNormalized,
}

impl<'a> Utf8<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            position: 0,
            last_class: 0,
            quick: IsNormalized::Yes,
        }
    }

    pub(super) fn step<B: Budget>(
        &mut self,
        budget: &mut B,
    ) -> Result<Option<&'a str>, DecodeError<B::Refusal>> {
        budget.traverse(1, 4).map_err(BoundedError::Refused)?;
        if self.position == self.bytes.len() {
            // SAFETY: position advances only across complete scalar slices
            // accepted by str::from_utf8 below. It began at zero and now equals
            // the entire slice length. The immutable borrow prevents mutation
            // throughout validation and throughout the returned str lifetime.
            return Ok(Some(unsafe { core::str::from_utf8_unchecked(self.bytes) }));
        }
        let width = match self.bytes[self.position] {
            0..=0x7f => 1,
            0xc2..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf4 => 4,
            _ => 1,
        };
        let remaining = self.bytes.len() - self.position;
        let end = self.position + width.min(remaining);
        let scalar =
            core::str::from_utf8(&self.bytes[self.position..end]).map_err(Error::InvalidUtf8)?;
        let ch = scalar.chars().next().ok_or(Error::Underrun)?;
        let class = canonical_combining_class(ch);
        if class != 0 && self.last_class > class {
            self.quick = IsNormalized::No;
        } else if self.quick != IsNormalized::No {
            match is_nfc_quick(core::iter::once(ch)) {
                IsNormalized::No => self.quick = IsNormalized::No,
                IsNormalized::Maybe => self.quick = IsNormalized::Maybe,
                IsNormalized::Yes => {}
            }
        }
        self.last_class = class;
        self.position = end;
        Ok(None)
    }
}
