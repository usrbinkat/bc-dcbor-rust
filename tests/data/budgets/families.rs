// Family, test target, exact test name, forked collections required.
families! {
    ("btree-occupancy", "owned_btree", "node_occupancy_boundaries_preserve_rust_order_and_canonical_encoding", true),
    ("btree-construction", "owned_btree", "tree_construction_is_complete_and_its_transitions_legal", true),
    ("payload-decode", "resumable_contract", "tests::decoder_payload_operations_fit_three_value_sixty_four_byte_quantum", false),
    ("normalization", "resumable_contract", "tests::long_normalization_has_bounded_preparation_and_emission_units", false),
    ("shared-pool", "resumable_contract", "tests::shared_pool_thousand_real_decodes_restore_exact_capacity", false),
    ("payload-latency", "resumable_contract", "latency::large_payload_decode_meets_measured_step_ceiling_and_ownership_contract", false),
    ("combining-progress", "resumable_contract", "text_matrix::long_combining_run_requires_retained_progress_not_whole_run_admission", false),
    ("combining-validation", "resumable_contract", "text_matrix::long_valid_combining_sequence_is_accepted_and_one_late_disordered_mark_rejects_it", false),
    ("vacant-buckets", "resumable_contract", "map_review::vacant_bucket_batches_retain_exact_positions_and_bound_total_steps", false),
    ("nested-payload", "resumable_contract", "map_review::nested_payload_work_is_bounded_by_bytes_times_dynamic_depth", false),
    ("emission", "resumable_contract", "schedules::emission_is_bounded_independently_of_preparation", false),
    ("concurrent-constructors", "resumable_contract", "schedules::capacity_pool_survives_concurrent_success_and_every_refused_constructor", false),
    ("arena-growth", "resumable_contract", "matrix::arena_growth_quantum_is_checked_without_text_or_payload_processing", false),
}
