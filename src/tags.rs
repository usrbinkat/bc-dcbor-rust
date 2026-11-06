import_stdlib!();

#[doc(hidden)]
pub use paste::paste;

use crate::{CBORTaggedDecodable, Date, Result, Tag, TagValue, TagsStore, TagsStoreTrait};

#[macro_export]
macro_rules! const_cbor_tag {
    ($value:expr, $const_name:ident, $name:expr) => {
        $crate::paste! {
            pub const [<TAG_ $const_name>]: u64 = $value;
            pub const [<TAG_NAME_ $const_name>]: &str = $name;
        }
    };
}

#[macro_export]
macro_rules! cbor_tag {
    ($const_name:ident) => {
        $crate::paste! {
            $crate::Tag::new([<TAG_ $const_name>], [<TAG_NAME_ $const_name>])
        }
    };
}

const_cbor_tag!(1, DATE, "date");
// Tag value for positive bignums (RFC 8949 §3.4.3).
#[cfg(feature = "num-bigint")]
const_cbor_tag!(2, POSITIVE_BIGNUM, "positive-bignum");
// Tag value for negative bignums (RFC 8949 §3.4.3).
#[cfg(feature = "num-bigint")]
const_cbor_tag!(3, NEGATIVE_BIGNUM, "negative-bignum");

/// Registers this crate's tags in `tags_store`, with their summarizers: the
/// date tag, and the bignum tags where bignums are supported.
///
/// A tag store is always the caller's: diagnostic notation and annotated hex
/// dumps name and summarize tags from the store they are given
/// ([`crate::DiagFormatOpts::tags`], [`crate::HexFormatOpts::tags`]), and no
/// conversion or codec path consults one. Registering again is a no-op in
/// content: every tag is registered under the name it already has, and each
/// summarizer replaces its own.
///
/// # Errors
///
/// [`crate::Error::ConflictingTagName`] or [`crate::Error::ConflictingTagValue`]
/// when the store already registers one of these tag values under another
/// name, or one of these names for another tag value; nothing is registered
/// then ([`TagsStore::insert_all`]).
///
/// # Examples
///
/// ```
/// use dcbor::prelude::*;
///
/// # fn main() -> dcbor::Result<()> {
/// let mut tags = TagsStore::default();
/// dcbor::register_tags_in(&mut tags)?;
/// assert_eq!(tags.name_for_value(1), "date");
///
/// let date: CBOR = Date::from_ymd(2023, 2, 8).into();
/// let opts = DiagFormatOpts::default().summarize(true).tags(&tags);
/// assert_eq!(date.diagnostic_opt(&opts), "2023-02-08");
/// # Ok(())
/// # }
/// ```
pub fn register_tags_in(tags_store: &mut TagsStore) -> Result<()> {
    tags_store.insert_all([cbor_tag!(DATE)])?;
    tags_store.set_summarizer(
        TAG_DATE,
        Arc::new(|untagged_cbor, _| Ok(format!("{}", Date::from_untagged_cbor(untagged_cbor)?))),
    );
    #[cfg(feature = "num-bigint")]
    {
        use crate::{bigint_from_negative_untagged_cbor, biguint_from_untagged_cbor};

        tags_store.insert_all([cbor_tag!(POSITIVE_BIGNUM), cbor_tag!(NEGATIVE_BIGNUM)])?;

        tags_store.set_summarizer(
            TAG_POSITIVE_BIGNUM,
            Arc::new(|untagged_cbor, _| {
                let biguint = biguint_from_untagged_cbor(untagged_cbor)?;
                Ok(format!("bignum({})", biguint))
            }),
        );

        tags_store.set_summarizer(
            TAG_NEGATIVE_BIGNUM,
            Arc::new(|untagged_cbor, _| {
                let bigint = bigint_from_negative_untagged_cbor(untagged_cbor)?;
                Ok(format!("bignum({})", bigint))
            }),
        );
    }
    Ok(())
}

/// Converts a slice of tag values to their corresponding [`Tag`] objects in
/// `tags`.
///
/// Each value is looked up in the store given and returned as the tag
/// registered for it, with its name; a value the store does not register is
/// returned as a tag with just the value (no name).
///
/// # Examples
///
/// ```
/// use dcbor::prelude::*;
///
/// # fn main() -> dcbor::Result<()> {
/// let tags = TagsStore::new([Tag::new(1, "test-tag")])?;
///
/// // A list of tag values - some may be registered, others may not
/// let found = tags_for_values(&tags, &[1, 42, 999]);
///
/// // The first tag (value 1) is registered with its name
/// assert_eq!(found[0].value(), 1);
/// assert_eq!(found[0].name(), Some("test-tag".to_string()));
///
/// // Unregistered tags have a value but no name
/// assert_eq!(found[1].value(), 42);
/// assert_eq!(found[1].name(), None);
/// assert_eq!(found[2].value(), 999);
/// # Ok(())
/// # }
/// ```
pub fn tags_for_values(tags: &dyn TagsStoreTrait, values: &[TagValue]) -> Vec<Tag> {
    values
        .iter()
        .map(|value| {
            tags.tag_for_value(*value)
                .unwrap_or_else(|| Tag::with_value(*value))
        })
        .collect()
}
