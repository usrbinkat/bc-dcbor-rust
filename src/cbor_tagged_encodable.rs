import_stdlib!();

use crate::{CBOR, CBORCase, CBORTagged, Error, Result};

/// # Tagged CBOR Encoding Support
///
/// This module provides the `CBORTaggedEncodable` trait, which enables types to
/// be encoded as tagged CBOR values.
///
/// CBOR tags provide semantic information about the encoded data. For example,
/// tag 1 is used for dates, indicating that the value should be interpreted
/// as a timestamp. The dCBOR library ensures these tags are encoded
/// deterministically.
///
/// A trait for types that can be encoded to CBOR with a specific tag.
///
/// This trait extends `CBORTagged` to provide methods for encoding a value
/// with its associated tag. Types that implement this trait define how they
/// should be represented in CBOR format, both with and without their tag.
/// Each method is fallible, as [`crate::CBOREncodable`]'s are: an untagged
/// value whose fields do not encode (a host map of colliding keys) is
/// refused with its own error, and a type that lists no tag cannot be
/// encoded tagged ([`Error::NoTag`]).
///
/// ## Example
///
/// ```
/// use dcbor::prelude::*;
///
/// # fn main() -> dcbor::Result<()> {
/// // Define a Date type
/// #[derive(Debug, Clone, PartialEq)]
/// struct Date(f64); // Timestamp as seconds since epoch
///
/// // Implement CBORTagged
/// impl CBORTagged for Date {
///     fn cbor_tags() -> Vec<Tag> {
///         vec![Tag::with_value(1)] // Standard date tag
///     }
/// }
///
/// // Implement encoding to tagged CBOR
/// impl CBORTaggedEncodable for Date {
///     fn untagged_cbor(&self) -> dcbor::Result<CBOR> {
///         // Date content is represented as a number
///         Ok(self.0.into())
///     }
/// }
///
/// // Create a date and encode it
/// let date = Date(1609459200.0); // 2021-01-01 00:00:00 UTC
///
/// // Get the untagged CBOR (just the timestamp)
/// let untagged = date.untagged_cbor()?;
/// // Timestamp is converted to an integer when it has no fractional part
/// assert_eq!(untagged.diagnostic(), "1609459200");
///
/// // Get the tagged CBOR (with tag 1)
/// let tagged = date.tagged_cbor()?;
/// assert_eq!(tagged.diagnostic(), "1(1609459200)");
///
/// // Get binary representation
/// let data = date.tagged_cbor_data()?;
/// # let _ = data;
/// # Ok(())
/// # }
/// ```
pub trait CBORTaggedEncodable: CBORTagged {
    /// Returns the untagged CBOR encoding of this instance, refused with
    /// its own error when a part of it does not encode.
    fn untagged_cbor(&self) -> Result<CBOR>;

    /// Returns the tagged CBOR encoding of this instance.
    ///
    /// This method wraps the result of `untagged_cbor()` with the first tag
    /// from `cbor_tags()`, which is considered the "preferred" tag for the
    /// type, refused with [`Error::NoTag`] when the type lists none.
    ///
    /// Even if a type supports multiple tags for backward-compatible decoding
    /// via `cbor_tags()`, only the first (preferred) tag is used for encoding.
    /// This ensures consistency in newly created data while maintaining the
    /// ability to read older formats.
    ///
    /// In most cases, you don't need to override this method.
    fn tagged_cbor(&self) -> Result<CBOR> {
        let tag = Self::cbor_tags().into_iter().next().ok_or(Error::NoTag)?;
        Ok(CBORCase::Tagged(tag, self.untagged_cbor()?).into())
    }

    /// Returns the tagged value in CBOR binary representation.
    ///
    /// This is a convenience method that converts the result of `tagged_cbor()`
    /// to binary format.
    fn tagged_cbor_data(&self) -> Result<Vec<u8>> {
        Ok(self.tagged_cbor()?.to_cbor_data())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Tag;

    /// A type that lists no tag.
    struct Untagged;

    impl CBORTagged for Untagged {
        fn cbor_tags() -> Vec<Tag> {
            Vec::new()
        }
    }

    impl CBORTaggedEncodable for Untagged {
        fn untagged_cbor(&self) -> Result<CBOR> {
            Ok(CBOR::null())
        }
    }

    /// A type listing no tag has no tagged encoding: refused as `NoTag`,
    /// never a panic indexing an empty list; its untagged encoding stands.
    #[test]
    fn a_type_listing_no_tag_is_refused_a_tagged_encoding() {
        assert!(matches!(Untagged.tagged_cbor(), Err(Error::NoTag)));
        assert!(matches!(Untagged.tagged_cbor_data(), Err(Error::NoTag)));
        assert_eq!(Untagged.untagged_cbor().unwrap(), CBOR::null());
    }
}
