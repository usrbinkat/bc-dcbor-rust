import_stdlib!();

use crate::{CBOR, CBORCase, CBOREncodable, Error, Result};

/// # Array Support in dCBOR
///
/// dCBOR provides conversions to and from CBOR arrays for various collection
/// types.
///
/// Encoding goes through [`CBOREncodable`]: a vector, slice, fixed array or
/// deque of any encodable elements encodes as a CBOR array of their
/// encodings, any element's failure returned, at any depth of nesting (a
/// vector of host maps one of which holds two keys of one canonical encoding
/// is refused). Where every element converts infallibly (`Into<CBOR>`), the
/// infallible `From<_> for CBOR` conversions remain, and agree with the
/// encoding.
///
/// Supported collection types:
/// - Rust arrays (`[T; N]`)
/// - Vectors (`Vec<T>`) and slices (`[T]`)
/// - VecDeque (`VecDeque<T>`)
///
/// A hash set encodes as a set ([`crate::Set`]), in canonical order, never
/// in its iteration order.
///
/// ## Examples
///
/// ```
/// use dcbor::prelude::*;
///
/// # fn main() -> dcbor::Result<()> {
/// // Create CBOR from Rust array (fixed size)
/// let array_cbor: CBOR = [1, 2, 3].into();
///
/// // Create CBOR from Vec
/// let vec = vec![1, 2, 3];
/// let vec_cbor: CBOR = vec.into();
///
/// // Mixed types in Vec
/// let mixed_vec: Vec<CBOR> = vec![
///     1.into(),         // Integer
///     "hello".into(),   // String
///     [1, 2, 3].into(), // Nested array
///     true.into(),      // Boolean
/// ];
/// let mixed_cbor: CBOR = mixed_vec.into();
///
/// // Elements that encode fallibly: a vector of host maps.
/// let maps = vec![std::collections::BTreeMap::from([(1, 2)])];
/// assert_eq!(maps.encode_cbor()?.diagnostic_flat(), "[{1: 2}]");
///
/// // Convert back to Vec
/// let numbers: Vec<i32> = array_cbor.try_into()?;
/// assert_eq!(numbers, vec![1, 2, 3]);
/// # let _ = (vec_cbor, mixed_cbor);
/// # Ok(())
/// # }
/// ```
impl<T> From<Vec<T>> for CBOR
where
    T: Into<CBOR>,
{
    fn from(vec: Vec<T>) -> Self {
        CBORCase::Array(vec.into_iter().map(|x| x.into()).collect()).into()
    }
}

impl<T> From<&[T]> for CBOR
where
    T: Into<CBOR> + Clone,
{
    fn from(array: &[T]) -> Self {
        CBORCase::Array(array.iter().map(|x| x.clone().into()).collect()).into()
    }
}

/// The elements of a CBOR array, each moved out and converted lazily, in
/// order, the conversion's error carried per element: the one definition
/// every array decoder reads. No element is cloned, so none needs `Clone`.
fn converted<T>(cbor: CBOR) -> Result<impl Iterator<Item = Result<T>>>
where
    T: TryFrom<CBOR>,
    Error: From<T::Error>,
{
    match cbor.into_case() {
        CBORCase::Array(cbor_array) => Ok(cbor_array
            .into_iter()
            .map(|element| T::try_from(element).map_err(Error::from))),
        _ => Err(Error::WrongType),
    }
}

/// A sequence of an array's converted elements, every one kept (a sequence
/// may repeat a value), the first failure returned.
fn elements<T, C>(cbor: CBOR) -> Result<C>
where
    T: TryFrom<CBOR>,
    Error: From<T::Error>,
    C: FromIterator<T>,
{
    converted(cbor)?.collect()
}

impl<T> TryFrom<CBOR> for Vec<T>
where
    T: TryFrom<CBOR>,
    Error: From<T::Error>,
{
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        elements(cbor)
    }
}

impl<T, const N: usize> From<[T; N]> for CBOR
where
    T: Into<CBOR>,
{
    fn from(array: [T; N]) -> Self {
        CBORCase::Array(array.into_iter().map(|x| x.into()).collect()).into()
    }
}

impl<T> From<VecDeque<T>> for CBOR
where
    T: Into<CBOR>,
{
    fn from(deque: VecDeque<T>) -> Self {
        CBORCase::Array(deque.into_iter().map(|x| x.into()).collect()).into()
    }
}

impl<T> TryFrom<CBOR> for VecDeque<T>
where
    T: TryFrom<CBOR>,
    Error: From<T::Error>,
{
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        elements(cbor)
    }
}

/// A hash set of an array's elements, refused with
/// [`Error::DuplicateMapKey`] when two of them convert to one `T` (an array
/// may repeat a value, or hold distinct values a coarser `T` equates): no
/// element is ever silently dropped (`set::distinct`).
impl<T, S> TryFrom<CBOR> for HashSet<T, S>
where
    T: TryFrom<CBOR> + Eq + hash::Hash,
    S: hash::BuildHasher + Default,
    Error: From<T::Error>,
{
    type Error = Error;

    fn try_from(cbor: CBOR) -> Result<Self> {
        crate::set::distinct(converted(cbor)?)
    }
}

/// The CBOR array of `items`' encodings, in their order, the first failure
/// returned: the one definition every sequence's encoding uses.
fn array<I>(items: I) -> Result<CBOR>
where
    I: IntoIterator,
    I::Item: CBOREncodable,
{
    Ok(CBORCase::Array(
        items
            .into_iter()
            .map(CBOREncodable::into_encoded_cbor)
            .collect::<Result<Vec<CBOR>>>()?,
    )
    .into())
}

impl<T: CBOREncodable> CBOREncodable for [T] {
    fn encode_cbor(&self) -> Result<CBOR> {
        array(self)
    }
}

impl<T: CBOREncodable> CBOREncodable for Vec<T> {
    fn encode_cbor(&self) -> Result<CBOR> {
        array(self)
    }

    /// The elements moved into the array, each encoded by value.
    fn into_encoded_cbor(self) -> Result<CBOR> {
        array(self)
    }
}

impl<T: CBOREncodable, const N: usize> CBOREncodable for [T; N] {
    fn encode_cbor(&self) -> Result<CBOR> {
        array(self)
    }

    fn into_encoded_cbor(self) -> Result<CBOR> {
        array(self)
    }
}

impl<T: CBOREncodable> CBOREncodable for VecDeque<T> {
    fn encode_cbor(&self) -> Result<CBOR> {
        array(self)
    }

    fn into_encoded_cbor(self) -> Result<CBOR> {
        array(self)
    }
}

/// `array`'s elements sorted by their encodings, refused with the first
/// element's error when one does not encode. Repeated elements are kept: an
/// array may repeat a value, and elements of one encoding contribute the same
/// bytes in either order, so the sorted encoding is deterministic. Uniqueness
/// is a set's rule, enforced where a set is built ([`crate::Set`]), never
/// here.
pub fn sort_array_by_cbor_encoding<T>(array: impl AsRef<[T]>) -> Result<Vec<T>>
where
    T: CBOREncodable + Clone,
{
    sorted(array.as_ref())
}

/// The borrowed `items` sorted by their encodings, each cloned once, into
/// the returned vector, after the sort: the one sort every sortable
/// collection uses.
fn sorted<'a, T>(items: impl IntoIterator<Item = &'a T>) -> Result<Vec<T>>
where
    T: CBOREncodable + Clone + 'a,
{
    let mut encoded: Vec<(Vec<u8>, &T)> = items
        .into_iter()
        .map(|item| Ok((item.encode_cbor_data()?, item)))
        .collect::<Result<_>>()?;
    encoded.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(encoded.into_iter().map(|(_, item)| item.clone()).collect())
}

/// Collections whose elements sort by their encodings
/// (`sort_array_by_cbor_encoding`).
pub trait CBORSortable<T> {
    fn sort_by_cbor_encoding(&self) -> Result<Vec<T>>;
}

impl<T: CBOREncodable + Clone> CBORSortable<T> for Vec<T> {
    fn sort_by_cbor_encoding(&self) -> Result<Vec<T>> {
        sort_array_by_cbor_encoding(self)
    }
}

impl<T: CBOREncodable + Clone> CBORSortable<T> for &[T] {
    fn sort_by_cbor_encoding(&self) -> Result<Vec<T>> {
        sort_array_by_cbor_encoding(self)
    }
}

impl<T: CBOREncodable + Clone, S> CBORSortable<T> for HashSet<T, S> {
    fn sort_by_cbor_encoding(&self) -> Result<Vec<T>> {
        sorted(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Where both apply, a sequence's infallible conversion and its encoding
    /// agree, for every sequence form.
    #[test]
    fn sequence_conversions_and_encodings_agree() {
        let vec = vec![1u64, 24, 300];
        assert_eq!(vec.encode_cbor().unwrap(), CBOR::from(vec.clone()));
        assert_eq!(
            vec.clone().into_encoded_cbor().unwrap(),
            CBOR::from(vec.clone())
        );
        assert_eq!(
            vec.as_slice().encode_cbor().unwrap(),
            CBOR::from(vec.as_slice())
        );
        let fixed = ["a", "b"];
        assert_eq!(fixed.encode_cbor().unwrap(), CBOR::from(fixed));
        let deque: VecDeque<u8> = [3, 2, 1].into();
        assert_eq!(deque.encode_cbor().unwrap(), CBOR::from(deque.clone()));
    }

    /// Sorting by encoding keeps repeated elements, and elements of one
    /// canonical encoding (numeric reduction, NFC) both, adjacent.
    #[test]
    fn sorting_keeps_repeated_elements() {
        assert_eq!(
            vec![300u64, 1, 24].sort_by_cbor_encoding().unwrap(),
            [1, 24, 300]
        );
        assert_eq!(vec![2u64, 1, 1].sort_by_cbor_encoding().unwrap(), [1, 1, 2]);
        assert_eq!(
            [2u64, 1, 1].as_slice().sort_by_cbor_encoding().unwrap(),
            [1, 1, 2]
        );
        let reduced = vec![CBOR::from(11), CBOR::from(10), CBOR::from(10.0)]
            .sort_by_cbor_encoding()
            .unwrap();
        assert_eq!(
            reduced.iter().map(CBOR::to_cbor_data).collect::<Vec<_>>(),
            [[0x0a], [0x0a], [0x0b]]
        );
        let normalized = vec![String::from("\u{e9}"), String::from("e\u{301}")]
            .sort_by_cbor_encoding()
            .unwrap();
        assert_eq!(normalized.len(), 2);
    }

    /// Sorting refuses an element that does not encode, with its own error.
    #[test]
    fn sorting_refuses_an_element_that_does_not_encode() {
        let colliding =
            BTreeMap::from([(String::from("\u{e9}"), 1), (String::from("e\u{301}"), 2)]);
        assert!(matches!(
            vec![BTreeMap::new(), colliding].sort_by_cbor_encoding(),
            Err(Error::DuplicateMapKey)
        ));
    }
}
