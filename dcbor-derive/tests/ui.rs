// Compiler diagnostics differ between channels (nightly adds feature
// suggestions such as `#![feature(trivial_bounds)]`); the expected `.stderr`
// files are blessed on stable.
#[rustversion::attr(not(stable), ignore = "UI diagnostics are blessed on stable")]
#[test]
fn bounded_derive_contract() {
    let tests = trybuild::TestCases::new();
    tests.pass("tests/ui/pass/*.rs");
    tests.compile_fail("tests/ui/fail/*.rs");
}
