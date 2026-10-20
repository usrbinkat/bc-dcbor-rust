//! Executable public-boundary gates against the existing dCBOR implementation.
//! Test-owned instrumentation never parses, normalizes, or restarts a decode.
#![cfg(feature = "std")]
#![cfg_attr(feature = "custom-std-collections", feature(hashmap_bucket_access))]

#[path = "resumable/native_bindings.rs"]
mod bindings;

#[path = "resumable/native_bound_defects.rs"]
mod bound_defects;
#[path = "resumable/native_comparison_cursor.rs"]
mod comparison_cursor;
#[path = "resumable/native_continuation.rs"]
mod continuation;
#[path = "resumable/native_deadlines.rs"]
mod deadlines;
#[cfg(feature = "derive")]
#[path = "resumable/native_derive.rs"]
mod derive;
#[path = "resumable/native_differential.rs"]
mod differential;
#[path = "resumable/native_driver.rs"]
mod driver;
#[cfg(feature = "hashbrown")]
#[path = "resumable/native_dynamic_maps.rs"]
mod dynamic_maps;
#[cfg(feature = "hashbrown")]
mod hash_map_schema {
    use hashbrown::HashMap;
    include!("resumable/native_hash_map_schema.rs");
}
#[cfg(feature = "custom-std-collections")]
mod std_hash_map_schema {
    use std::collections::HashMap;
    include!("resumable/native_hash_map_schema.rs");
}
#[path = "resumable/native_harness.rs"]
mod harness;
#[path = "resumable/native_header_cursor.rs"]
mod header_cursor;
#[path = "resumable/native_heap.rs"]
mod heap;
#[path = "resumable/native_latency.rs"]
mod latency;
#[path = "resumable/native_malformed.rs"]
mod malformed;
#[cfg(feature = "hashbrown")]
#[path = "resumable/native_map_review.rs"]
mod map_review;
#[path = "resumable/native_matrix.rs"]
mod matrix;
#[cfg(all(feature = "hashbrown", feature = "derive"))]
#[path = "resumable/native_nested_maps.rs"]
mod nested_maps;
#[path = "resumable/native_output_bounds.rs"]
mod output_bounds;
#[path = "resumable/native_ownership.rs"]
mod ownership;
#[path = "resumable/native_pipeline.rs"]
mod pipeline;
#[path = "resumable/native_preparation_heap.rs"]
mod preparation_heap;
#[path = "resumable/native_quick_suspension.rs"]
mod quick_suspension;
#[path = "resumable/native_repeated.rs"]
mod repeated;
#[path = "resumable/native_schedules.rs"]
mod schedules;
#[cfg(feature = "derive")]
#[path = "resumable/native_schema_encoding.rs"]
mod schema_encoding;
#[path = "resumable/native_storage_cursor.rs"]
mod storage_cursor;
#[path = "resumable/native_tests.rs"]
mod tests;
#[path = "resumable/native_text_matrix.rs"]
mod text_matrix;
#[path = "resumable/native_text_progress.rs"]
mod text_progress;
