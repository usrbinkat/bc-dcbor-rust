//! Compiles every recording budget of the inventory in
//! (`dcbor_record::budgets::inventory`), so a check reads its record with no
//! filesystem access, Miri's host isolation included: each record's file
//! name with its contents, or `None` where no record is present yet, which
//! only that record's own recording run accepts (`budgets.rs`).
use std::{env, fs, path::PathBuf};

fn main() {
    let directory = "../data/budgets";
    println!("cargo:rerun-if-changed={directory}");
    let mut source = String::from("const EMBEDDED: &[(&str, Option<&str>)] = &[\n");
    for selection in dcbor_record::budgets::inventory() {
        let path = format!("{directory}/{}", selection.name);
        let value = match fs::read_to_string(&path) {
            Ok(data) => format!("Some({data:?})"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => "None".into(),
            Err(error) => panic!("{path}: {error}"),
        };
        source.push_str(&format!("    ({:?}, {value}),\n", selection.name));
    }
    source.push_str("];\n");
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR"));
    let target = output.join("budgets.rs");
    fs::write(&target, source)
        .unwrap_or_else(|error| panic!("{} cannot be written: {error}", target.display()));
}
