//! The one form of every recorded oracle of this repository: the admission
//! traces (`tests/resumable/native_traces.rs`), the tightness ratios
//! (`src/bounded.rs`, `places`), the matrix costs (`tests/support/rigor.rs`),
//! the model checkers' derived bounds and the gates' results
//! (`tests/gate`). A record names the configuration it was recorded under on
//! its first line, [`CONFIGURATION_LINE`] and the development shell's
//! `DCBOR_CONFIGURATION` (the toolchain and the standard library it builds
//! against); its rows follow, one per line. A record is published whole:
//! written to a temporary file beside it, then renamed over it, so a failed
//! recording leaves the previous record intact.
//!
//! Each consumer owns its rows' columns and their parse; this crate owns
//! the header, the configuration it names and the publication, defined
//! once. It is a leaf: it depends on no crate of the workspace, so neither
//! test instrumentation nor gate tooling reaches a build through it.

use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The variable the development shells export naming the configuration a
/// run is under.
pub const CONFIGURATION: &str = "DCBOR_CONFIGURATION";

/// The first line of every record: this marker, then its configuration.
pub const CONFIGURATION_LINE: &str = "#\tconfiguration\t";

/// The configuration this run is under, when its shell exports one.
pub fn configuration() -> Option<String> {
    std::env::var(CONFIGURATION)
        .ok()
        .filter(|identity| !identity.is_empty())
}

/// The configuration this run is under, required: recording under no named
/// configuration would publish evidence no reader could place.
pub fn recording_configuration() -> String {
    configuration().unwrap_or_else(|| {
        panic!("recording requires {CONFIGURATION}, which the flake's shells export")
    })
}

/// A record of `rows` under `configuration`: the header, then each row and
/// its newline.
pub fn render<'r>(configuration: &str, rows: impl IntoIterator<Item = &'r str>) -> String {
    let mut data = format!("{CONFIGURATION_LINE}{configuration}\n");
    for row in rows {
        data.push_str(row);
        data.push('\n');
    }
    data
}

/// A record read: the configuration it names, and each row with its line
/// number in the record.
#[derive(Debug, PartialEq, Eq)]
pub struct Record<'d> {
    pub configuration: &'d str,
    pub rows: Vec<(usize, &'d str)>,
}

/// `data`, the record at `path`, read: its configuration line required,
/// the rows after it in order. `record_with` names how the record is
/// written, for a reader whose record lacks its configuration line.
pub fn read<'d>(path: &str, data: &'d str, record_with: &str) -> Record<'d> {
    try_read(data).unwrap_or_else(|| {
        panic!(
            "{path}:1: not the configuration it was recorded under; record it with {record_with}"
        )
    })
}

/// `data` read as a record, or `None` when its first line is not a
/// configuration line: how a gate tells a record from any other file.
pub fn try_read(data: &str) -> Option<Record<'_>> {
    let mut lines = data.lines();
    let configuration = lines.next()?.strip_prefix(CONFIGURATION_LINE)?;
    Some(Record {
        configuration,
        rows: lines
            .enumerate()
            .map(|(index, row)| (index + 2, row))
            .collect(),
    })
}

/// Publish `data` as `path` whole: written to a temporary file beside it,
/// then renamed over it, so a failed write leaves the previous record.
pub fn publish(path: &str, data: &str) {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let temporary = format!(
        "{path}.{}.{}.tmp",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .unwrap_or_else(|error| panic!("{temporary}: {error}"));
    let result = file
        .write_all(data.as_bytes())
        .and_then(|_| file.sync_all());
    drop(file);
    if let Err(error) = result.and_then(|_| std::fs::rename(&temporary, path)) {
        // The rename's or the write's error is the one reported; a temporary
        // file that cannot be removed adds nothing to it.
        let _ = std::fs::remove_file(&temporary);
        panic!("{path}: {error}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A record renders its configuration first and its rows in order, is
    /// read back to the same configuration and rows with their line numbers,
    /// and is published whole, leaving no temporary file beside it.
    #[test]
    fn a_record_names_its_configuration_and_is_published_whole() {
        let data = render("toolchain=t std=s", ["one\t1", "two\t2"]);
        assert_eq!(
            data,
            format!("{CONFIGURATION_LINE}toolchain=t std=s\none\t1\ntwo\t2\n")
        );
        let record = read("planted", &data, "planted=1");
        assert_eq!(record.configuration, "toolchain=t std=s");
        assert_eq!(record.rows, vec![(2, "one\t1"), (3, "two\t2")]);
        let directory = std::env::temp_dir().join(format!("dcbor-record-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("a temporary directory");
        let path = directory.join("record.txt");
        let path = path.to_str().expect("a UTF-8 temporary path");
        std::fs::write(path, "previous").expect("the previous record");
        publish(path, &data);
        assert_eq!(std::fs::read_to_string(path).expect("the record"), data);
        assert_eq!(
            std::fs::read_dir(&directory).unwrap().count(),
            1,
            "temporary evidence was not removed"
        );
        std::fs::remove_dir_all(&directory).expect("the temporary directory removed");
    }

    /// A file whose first line is not a configuration line is no record.
    #[test]
    fn a_file_without_a_configuration_line_is_no_record() {
        assert_eq!(try_read("unrecognized evidence\n"), None);
        assert_eq!(try_read(""), None);
        assert_eq!(
            try_read(&render("c", ["row"])),
            Some(Record {
                configuration: "c",
                rows: vec![(2, "row")],
            })
        );
    }

    /// A record without its configuration line is refused, naming how to
    /// record it.
    #[test]
    #[should_panic(
        expected = "planted:1: not the configuration it was recorded under; record it with planted=1"
    )]
    fn a_record_without_its_configuration_line_is_refused() {
        read("planted", "one\t1\n", "planted=1");
    }
}
