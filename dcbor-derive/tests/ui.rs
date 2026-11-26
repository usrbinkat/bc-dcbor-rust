//! The derive's compile-pass and compile-fail contract, checked under both
//! compilers of the development shells: the custom-std nightly the crate is
//! delivered on (`nix develop`, `.#custom-std`) and stable (`.#stable`).
//!
//! A fixture whose diagnostic is the same under both is blessed once
//! (`tests/ui/fail`). A fixture whose diagnostic is the compiler's own
//! wording, which changes between compiler versions (`E0521`'s labels and
//! notes), has one source (`tests/ui/versioned`), compiled under each
//! compiler from a wrapper beside that compiler's own expectation
//! (`tests/ui/versioned/<channel>`, `include!` keeping the source's spans).
//! Both are blessed from their own shell (`TRYBUILD=overwrite`).
#[test]
fn bounded_derive_contract() {
    let tests = trybuild::TestCases::new();
    tests.pass("tests/ui/pass/*.rs");
    tests.compile_fail("tests/ui/fail/*.rs");
    tests.compile_fail(versioned());
}

/// The wrappers of the versioned fixtures blessed under this compiler.
#[rustversion::stable]
fn versioned() -> &'static str {
    "tests/ui/versioned/stable/*.rs"
}

/// The wrappers of the versioned fixtures blessed under this compiler.
#[rustversion::nightly]
fn versioned() -> &'static str {
    "tests/ui/versioned/nightly/*.rs"
}

/// No shell provides another channel, and no expectation is blessed for
/// one: refused where it would be compiled, never skipped.
#[rustversion::not(any(stable, nightly))]
fn versioned() -> &'static str {
    compile_error!(
        "the UI expectations are blessed for the stable and custom-std nightly shells alone"
    )
}
