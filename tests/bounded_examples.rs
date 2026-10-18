#![cfg(all(feature = "std", feature = "derive"))]
#[path = "../examples/bounded_record.rs"]
mod record;

#[test]
fn record_publisher_wire_and_error_contract() {
    record::main();
}
