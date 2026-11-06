// The one inventory of the tightness families, `include!`d by the library,
// which compiles each family's record of its build in (`src/bounded.rs`,
// `places`), and by the gate, which checks every variant's record of each
// (`tests/gate`, `records`). Each defines `families!` to read it. Explicit:
// discovering the files present would miss a family whose every record was
// removed.
families! {
    // Recorded in every variant.
    every: [
        "buckets",
        "decode",
        "emission",
        "header",
        "lifecycle_borrow",
        "lifecycle_construct",
        "lifecycle_copy",
        "lifecycle_operations",
        "lifecycle_parse",
        "lifecycle_scope",
        "preparation",
        "retained_parse",
        "string_decode",
        "text_encode",
        "text_joint",
        "text_write",
        "validation",
    ],
    // Code compiled only over the forked collections: recorded in the
    // custom-std variants alone.
    custom_std: ["btree"],
}
