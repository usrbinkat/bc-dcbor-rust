#[test]
fn bounded_derive_contract() {
    let tests = trybuild::TestCases::new();
    tests.pass("tests/ui/pass/*.rs");
    tests.compile_fail("tests/ui/fail/*.rs");
}
