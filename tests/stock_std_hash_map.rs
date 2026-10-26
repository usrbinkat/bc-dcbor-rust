//! Stock std must not acquire a bounded implementation based on insertion
//! capacity: deletion can leave a larger physical table to scan.
#![cfg(all(feature = "std", not(feature = "custom-std-collections")))]

use dcbor::bounded::Schema;
use std::collections::HashMap;

// Inference has exactly one candidate only while the bounded implementation is
// absent. If it is added, the second impl makes `_` ambiguous at compile time.
#[test]
fn stock_hash_map_has_no_schema_implementation() {
    trait Absent<A> {
        fn assert_absent() {}
    }
    impl<T: ?Sized> Absent<()> for T {}
    struct Implemented;
    impl<T: ?Sized + Schema> Absent<Implemented> for T {}

    <HashMap<u64, u64> as Absent<_>>::assert_absent();
}
