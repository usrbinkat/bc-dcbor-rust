import_stdlib!();

use crate::{CBOR, Error, Result, Tag, TagValue};

/// A function type for summarizing CBOR values as human-readable strings.
///
/// `CBORSummarizer` is used to create custom formatters for tagged CBOR values.
/// It's a type alias for a thread-safe function pointer that takes a CBOR value
/// and returns a string representation or an error.
///
/// ## Purpose
///
/// In CBOR, tags provide semantic meaning to data structures. A
/// `CBORSummarizer` helps interpret and display these tagged values in a
/// human-readable format. This is particularly useful for debugging, logging,
/// or displaying CBOR data to users.
///
/// ## Thread Safety
///
/// The `CBORSummarizer` type is wrapped in an `Arc` (Atomic Reference Count)
/// and requires `Send + Sync` traits, making it safe to share between threads.
///
/// ## Examples
///
/// ```
/// use std::sync::Arc;
///
/// use dcbor::prelude::*;
///
/// # fn main() -> dcbor::Result<()> {
/// // Create a custom summarizer for a date tag
/// let date_summarizer: CBORSummarizer = Arc::new(|cbor, _flat| {
///     // Extract timestamp from tagged CBOR
///     let timestamp: f64 = cbor.clone().try_into()?;
///
///     // Format timestamp as ISO date (simplified example)
///     Ok(format!("Date: {:.1} seconds since epoch", timestamp))
/// });
///
/// // Create a tags store
/// let mut tags = TagsStore::default();
///
/// // Register a tag for date (tag 1 is the standard CBOR tag for dates)
/// tags.insert(Tag::new(1, "date"))?;
///
/// // Register our summarizer for tag 1
/// tags.set_summarizer(1, date_summarizer);
/// # Ok(())
/// # }
/// ```
///
/// When this summarizer is used (for example in diagnostic output), it would
/// convert a tagged CBOR timestamp into a more readable date format.
pub type CBORSummarizer = Arc<dyn (Fn(CBOR, bool) -> Result<String>) + Send + Sync>;

/// A trait for types that can map between CBOR tags and their human-readable
/// names.
///
/// The `TagsStoreTrait` provides a standardized interface for resolving CBOR
/// tags to human-readable names and vice versa. This is useful for debugging
/// and displaying CBOR data in a more understandable format.
///
/// ## Functionality
///
/// This trait defines methods for:
/// - Converting between tag numbers and human-readable names
/// - Looking up tags by name or value
/// - Retrieving summarizers for specific tags
///
/// ## Implementation
///
/// Implementers of this trait should maintain a bidirectional mapping between
/// tag values (numbers) and their corresponding names. The primary
/// implementation is [`TagsStore`], but other implementations can be created
/// for specific needs. A store is always passed explicitly to what reads it
/// ([`crate::DiagFormatOpts::tags`], [`crate::HexFormatOpts::tags`]); the
/// crate keeps none of its own.
///
/// ## Examples
///
/// ```
/// use dcbor::prelude::*;
///
/// # fn main() -> dcbor::Result<()> {
/// // Create a store that implements TagsStoreTrait
/// let mut tags = TagsStore::default();
///
/// // Register a tag with a human-readable name
/// tags.insert(Tag::new(1, "date"))?;
///
/// // Look up tag by number
/// let tag_name = tags.name_for_value(1);
/// assert_eq!(tag_name, "date");
///
/// // Look up tag by name
/// let tag = tags.tag_for_name("date").unwrap();
/// assert_eq!(tag.value(), 1);
/// # Ok(())
/// # }
/// ```
///
/// The trait also includes a helper method to handle the common case of
/// optional tag stores.
pub trait TagsStoreTrait {
    fn assigned_name_for_tag(&self, tag: &Tag) -> Option<String>;
    fn name_for_tag(&self, tag: &Tag) -> String;
    fn tag_for_value(&self, value: TagValue) -> Option<Tag>;
    fn tag_for_name(&self, name: &str) -> Option<Tag>;
    fn name_for_value(&self, value: TagValue) -> String;
    fn summarizer(&self, tag: TagValue) -> Option<&CBORSummarizer>;

    fn name_for_tag_opt<T>(tag: &Tag, tags: Option<&T>) -> String
    where
        T: TagsStoreTrait,
        Self: Sized,
    {
        match tags {
            None => tag.value().to_string(),
            Some(tags) => tags.name_for_tag(tag),
        }
    }
}

/// A registry that maintains mappings between CBOR tags, their human-readable
/// names, and optional summarizers.
///
/// The `TagsStore` is the primary implementation of the [`TagsStoreTrait`],
/// providing a bidirectional mapping between CBOR tag values (numbers) and
/// their human-readable names. It also supports registering custom summarizers
/// for specific tags.
///
/// ## Use Cases
///
/// The `TagsStore` serves several important purposes:
///
/// 1. **Readability**: Converting numeric tags to meaningful names in
///    diagnostic output
/// 2. **Consistency**: Ensuring consistent tag usage throughout an application
/// 3. **Documentation**: Providing a central registry of all tags used in a
///    system
/// 4. **Customization**: Supporting custom summarization of tagged values
///
/// ## Features
///
/// - Bidirectional lookup between tag values and names
/// - Registrations that would make either lookup ambiguous refused, typed
/// - Optional registration of custom summarizers for specific tags
/// - Default implementation for an empty registry
///
/// ## Examples
///
/// ### Basic usage
///
/// ```
/// use dcbor::prelude::*;
///
/// # fn main() -> dcbor::Result<()> {
/// // Create a new TagsStore with a set of predefined tags
/// let tags = TagsStore::new([
///     Tag::new(1, "date"),
///     Tag::new(2, "positive_bignum"),
///     Tag::new(3, "negative_bignum"),
/// ])?;
///
/// // Look up a tag by its value
/// let date_tag = tags.tag_for_value(1).unwrap();
/// assert_eq!(date_tag.name().unwrap(), "date");
///
/// // Look up a tag name by value
/// let name = tags.name_for_value(2);
/// assert_eq!(name, "positive_bignum");
///
/// // Look up a tag by its name
/// let neg_tag = tags.tag_for_name("negative_bignum").unwrap();
/// assert_eq!(neg_tag.value(), 3);
/// # Ok(())
/// # }
/// ```
///
/// ### Adding summarizers
///
/// ```
/// use std::sync::Arc;
///
/// use dcbor::prelude::*;
///
/// # fn main() -> dcbor::Result<()> {
/// // Create an empty tags store
/// let mut tags = TagsStore::default();
///
/// // Register a tag
/// tags.insert(Tag::new(1, "date"))?;
///
/// // Add a summarizer for the date tag
/// tags.set_summarizer(
///     1,
///     Arc::new(|cbor, _flat| {
///         let timestamp: f64 = cbor.clone().try_into()?;
///         Ok(format!("Timestamp: {}", timestamp))
///     }),
/// );
///
/// // Later, this summarizer can be retrieved and used
/// let date_summarizer = tags.summarizer(1);
/// assert!(date_summarizer.is_some());
/// # Ok(())
/// # }
/// ```
///
/// ## Registration
///
/// Every registered tag is named, and each name and each value is registered
/// once: registering a tag without a name, with an empty name, with a value
/// already registered under another name, or with a name already registered
/// for another value is refused, typed ([`Error::UnnamedTag`],
/// [`Error::EmptyTagName`], [`Error::ConflictingTagName`],
/// [`Error::ConflictingTagValue`]), and registers nothing. Registering a tag
/// under the name it already has changes nothing.
///
/// ```
/// use dcbor::prelude::*;
///
/// # fn main() -> dcbor::Result<()> {
/// let mut tags = TagsStore::new([Tag::new(1, "date")])?;
/// tags.insert(Tag::new(1, "date"))?;
/// assert!(matches!(
///     tags.insert(Tag::new(1, "epoch")),
///     Err(dcbor::Error::ConflictingTagName { value: 1, .. })
/// ));
/// assert!(matches!(
///     tags.insert(Tag::with_value(7)),
///     Err(dcbor::Error::UnnamedTag(7))
/// ));
/// assert_eq!(tags.name_for_value(1), "date");
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct TagsStore {
    tags_by_value: HashMap<TagValue, Tag>,
    tags_by_name: HashMap<String, Tag>,
    summarizers: HashMap<TagValue, CBORSummarizer>,
}

impl TagsStore {
    /// A store registering `tags` ([`Self::insert_all`]).
    pub fn new<T>(tags: T) -> Result<Self>
    where
        T: IntoIterator<Item = Tag>,
    {
        let mut store = Self::default();
        store.insert_all(tags)?;
        Ok(store)
    }

    /// Register `tag` ([`Self::insert_all`]).
    pub fn insert(&mut self, tag: Tag) -> Result<()> {
        self.insert_all([tag])
    }

    /// Register every tag of `tags`, all of them or, refused, none: each
    /// must be named, with a nonempty name, and agree with the store and
    /// with the others on which name each value has and which value each
    /// name has ([`TagsStore`], "Registration"). The first refusal is
    /// returned.
    pub fn insert_all<T>(&mut self, tags: T) -> Result<()>
    where
        T: IntoIterator<Item = Tag>,
    {
        let mut names: BTreeMap<TagValue, String> = BTreeMap::new();
        let mut values: BTreeMap<String, TagValue> = BTreeMap::new();
        let mut admitted: Vec<(String, Tag)> = Vec::new();
        for tag in tags {
            let value = tag.value();
            let name = match tag.name() {
                None => return Err(Error::UnnamedTag(value)),
                Some(name) if name.is_empty() => return Err(Error::EmptyTagName(value)),
                Some(name) => name,
            };
            let registered_name = self
                .tags_by_value
                .get(&value)
                .and_then(|registered| registered.name())
                .or_else(|| names.get(&value).cloned());
            if let Some(registered) = registered_name
                && registered != name
            {
                return Err(Error::ConflictingTagName {
                    value,
                    registered,
                    given: name,
                });
            }
            let registered_value = self
                .tags_by_name
                .get(&name)
                .map(Tag::value)
                .or_else(|| values.get(&name).copied());
            if let Some(registered) = registered_value
                && registered != value
            {
                return Err(Error::ConflictingTagValue {
                    name,
                    registered,
                    given: value,
                });
            }
            names.insert(value, name.clone());
            values.insert(name.clone(), value);
            admitted.push((name, tag));
        }
        for (name, tag) in admitted {
            // A tag the store holds already is held under this name (checked
            // above): it is left as it is. Inserting it again would replace
            // equal entries, and a map's insertion reserves room for one more
            // entry before it looks its key up, growing a full table, so
            // registering again would change the bytes the store holds.
            if self.tags_by_value.contains_key(&tag.value()) {
                continue;
            }
            self.tags_by_value.insert(tag.value(), tag.clone());
            self.tags_by_name.insert(name, tag);
        }
        Ok(())
    }

    /// Summarize values of tag `tag` with `summarizer`, replacing any
    /// summarizer it had: in place, so replacing one changes neither the
    /// tags summarized nor the room the store holds for them.
    pub fn set_summarizer(&mut self, tag: TagValue, summarizer: CBORSummarizer) {
        match self.summarizers.get_mut(&tag) {
            Some(held) => *held = summarizer,
            None => {
                self.summarizers.insert(tag, summarizer);
            }
        }
    }
}

impl TagsStoreTrait for TagsStore {
    fn assigned_name_for_tag(&self, tag: &Tag) -> Option<String> {
        self.tag_for_value(tag.value())
            .and_then(|registered| registered.name())
    }

    fn name_for_tag(&self, tag: &Tag) -> String {
        self.assigned_name_for_tag(tag)
            .unwrap_or_else(|| tag.value().to_string())
    }

    fn tag_for_name(&self, name: &str) -> Option<Tag> {
        self.tags_by_name.get(name).cloned()
    }

    fn tag_for_value(&self, value: TagValue) -> Option<Tag> {
        self.tags_by_value.get(&value).cloned()
    }

    fn name_for_value(&self, value: TagValue) -> String {
        self.tag_for_value(value)
            .and_then(|tag| tag.name())
            .unwrap_or_else(|| value.to_string())
    }

    fn summarizer(&self, tag: TagValue) -> Option<&CBORSummarizer> {
        self.summarizers.get(&tag)
    }
}

/// An empty store.
impl Default for TagsStore {
    fn default() -> Self {
        Self {
            tags_by_value: HashMap::new(),
            tags_by_name: HashMap::new(),
            summarizers: HashMap::new(),
        }
    }
}
