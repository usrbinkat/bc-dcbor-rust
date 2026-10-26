//! The verification layer a run carries, and its progress, reported as it
//! runs.
//!
//! Both layers apply the same oracles to the same operations; they differ
//! only in which schedules they select, and each states its claim:
//!
//! - `fast`, the default: every admission refused once and resumed, in one
//!   pass that suspends at each from the state the unrefused run reaches
//!   there; every physical request failed in a run of its own; and one stop
//!   of each kind per certified cleanup class, every stop at a boundary
//!   whose class is not certified. It claims every refusal and physical
//!   failure, and every stop up to the cleanup simulations the classes
//!   declare.
//! - `exhaustive`: in addition, every admission refused in a run of its own,
//!   and every stop of each kind at every boundary, each class's members
//!   required to clean up alike: the evidence that checks the fast layer's
//!   reductions on the schedules it reaches.
//!
//! The layer is chosen by `DCBOR_RIGOR`; any other value is an error naming
//! the two. Under Miri the variable reaches the interpreted test only when
//! forwarded (`-Zmiri-env-forward=DCBOR_RIGOR`).
use std::fmt::Display;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// The variable naming the layer.
pub const VARIABLE: &str = "DCBOR_RIGOR";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rigor {
    Fast,
    Exhaustive,
}

/// The layer this run carries: `DCBOR_RIGOR` read once, `fast` when unset.
pub fn rigor() -> Rigor {
    static RIGOR: OnceLock<Rigor> = OnceLock::new();
    *RIGOR.get_or_init(|| match std::env::var(VARIABLE) {
        Err(std::env::VarError::NotPresent) => Rigor::Fast,
        Ok(value) => match value.as_str() {
            "fast" => Rigor::Fast,
            "exhaustive" => Rigor::Exhaustive,
            other => panic!("{VARIABLE}={other:?}: the layers are fast and exhaustive"),
        },
        Err(error) => panic!("{VARIABLE}: {error}"),
    })
}

/// Emit an exact, address-free class inventory for the native/Miri gate.
/// Sorting and rendering happen outside physical-observer windows. The gate
/// compares whole inventories, so a missing matrix or class is a failure.
pub fn classes(name: &str, classes: impl IntoIterator<Item = String>) {
    match std::env::var("DCBOR_CLASS_COVERAGE") {
        Err(std::env::VarError::NotPresent) => return,
        Ok(value) if value == "1" => {}
        other => panic!("DCBOR_CLASS_COVERAGE must be 1 or unset: {other:?}"),
    }
    let classes: std::collections::BTreeSet<_> = classes.into_iter().collect();
    eprintln!("DCBOR_CLASSES\t{name:?}\t{}", classes.len());
    for class in classes {
        eprintln!("DCBOR_CLASS\t{name:?}\t{class:?}");
    }
}

/// A matrix's progress: each stage and each case it runs, written to
/// standard error as it starts, with the time since the matrix began, so a
/// slow case and a stalled one can be told apart while they run.
pub struct Progress {
    name: String,
    started: Instant,
    stage: &'static str,
    total: usize,
    done: usize,
    costs: Vec<String>,
}

impl Progress {
    pub fn new(name: impl Display) -> Self {
        let name = name.to_string();
        eprintln!("[{name}] rigor {:?}", rigor());
        Self {
            name,
            started: Instant::now(),
            stage: "",
            total: 0,
            done: 0,
            costs: Vec::new(),
        }
    }

    /// Begin a stage of `total` cases, `of` the schedules it selects them
    /// from.
    pub fn stage(&mut self, stage: &'static str, total: usize, of: usize) {
        self.costs.push(format!("stage\t{stage}\t{total}\t{of}"));
        self.stage = stage;
        self.total = total;
        self.done = 0;
        eprintln!(
            "[{}] {stage}: {total} of {of} schedules at {:?}",
            self.name,
            self.elapsed()
        );
    }

    /// Begin the next case of the stage, named by what it schedules.
    pub fn case(&mut self, case: impl Display) {
        self.done += 1;
        eprintln!(
            "[{}] {} {}/{}: {case} at {:?}",
            self.name,
            self.stage,
            self.done,
            self.total,
            self.elapsed()
        );
    }

    fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    /// Measured dimensions of the baseline, independent of schedule selection.
    pub fn dimension(&mut self, name: &'static str, count: usize) {
        self.costs.push(format!("dimension\t{name}\t{count}"));
        eprintln!("[{}] {name}: {count}", self.name);
    }
}

impl Drop for Progress {
    fn drop(&mut self) {
        eprintln!("[{}] finished at {:?}", self.name, self.elapsed());
        if !std::thread::panicking() {
            ratchet(&self.name, &self.costs);
        }
    }
}

/// Gate-controlled cost evidence. A record is published only after the matrix
/// returns normally, never while unwinding from a failed oracle. Configuration,
/// feature projection, layer and the full semantic name are checked exactly.
fn ratchet(name: &str, costs: &[String]) {
    use std::{fs, path::PathBuf};
    let mode = match std::env::var("DCBOR_COST_MODE") {
        Err(std::env::VarError::NotPresent) => return,
        Ok(mode) if mode == "check" || mode == "record" => mode,
        other => panic!("DCBOR_COST_MODE must be check, record or unset: {other:?}"),
    };
    let configuration =
        std::env::var("DCBOR_CONFIGURATION").expect("cost evidence requires DCBOR_CONFIGURATION");
    let variant = std::env::var("DCBOR_COST_VARIANT")
        .expect("cost evidence requires the gate's exact feature projection");
    assert!(!configuration.is_empty());
    assert!(!variant.is_empty());
    let binary = std::env::current_exe().expect("test executable has a path");
    let binary = binary
        .file_stem()
        .expect("test executable has a name")
        .to_str()
        .expect("test executable name is UTF-8");
    // Cargo appends an artifact hash. It is not semantic evidence identity.
    let binary = match binary.rsplit_once('-') {
        Some((stem, hash)) if hash.len() == 16 && hash.bytes().all(|b| b.is_ascii_hexdigit()) => {
            stem
        }
        _ => binary,
    };
    let thread = std::thread::current();
    let test = thread
        .name()
        .expect("matrix cost evidence requires a named test thread");
    let identity = format!("{variant}\t{:?}\t{binary}\t{test:?}\t{name:?}", rigor());
    // The digest is only a bounded filename. Full identity in the record
    // detects collisions; no coverage or oracle comparison uses the digest.
    let hash = identity.bytes().fold(0xcbf29ce484222325u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x100000001b3)
    });
    let root = std::env::var_os("DCBOR_COST_DIRECTORY")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../data/costs"));
    let path = root.join(format!("{hash:016x}.txt"));
    let data = format!(
        "#\tconfiguration\t{configuration}\n#\tidentity\t{identity}\n{}\n",
        costs.join("\n")
    );
    if mode == "check" {
        let recorded = fs::read_to_string(&path).unwrap_or_else(|error| {
            panic!(
                "{}: {error}; record checked matrix costs with a mechanism reason",
                path.display()
            )
        });
        check_cost(&recorded, &data, &identity);
        eprintln!("DCBOR_COST\t{hash:016x}");
        return;
    }
    let reason =
        std::env::var("DCBOR_COST_REASON").expect("recording costs requires DCBOR_COST_REASON");
    assert!(
        !reason.trim().is_empty(),
        "cost recording requires a mechanism reason"
    );
    assert!(
        !reason.contains(['\n', '\r', '\t']),
        "cost reason must be one line"
    );
    fs::create_dir_all(&root).expect("cost directory is writable");
    // Serialize writes from parallel test threads and reject two matrices
    // using the same identity with different measured costs in one process.
    static WRITTEN: OnceLock<std::sync::Mutex<std::collections::BTreeMap<String, String>>> =
        OnceLock::new();
    let mut written = WRITTEN
        .get_or_init(Default::default)
        .lock()
        .expect("cost recorder lock");
    if let Some(previous) = written.get(&identity) {
        let previous = previous.clone();
        drop(written);
        assert_eq!(
            previous, data,
            "{identity}: inconsistent costs for one matrix identity"
        );
        eprintln!("DCBOR_COST\t{hash:016x}");
        return;
    }
    match fs::read_to_string(&path) {
        Ok(previous) => assert_eq!(
            previous.lines().nth(1),
            data.lines().nth(1),
            "cost filename collision"
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("{}: {error}", path.display()),
    }
    let temporary = root.join(format!(".{hash:016x}.{}.tmp", std::process::id()));
    {
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .expect("create unique cost evidence file");
        file.write_all(format!("{data}#\treason\t{reason}\n").as_bytes())
            .expect("write cost evidence");
        file.sync_all().expect("persist cost evidence");
    }
    fs::rename(&temporary, &path).expect("publish cost evidence atomically");
    written.insert(identity, data);
    eprintln!("DCBOR_COST\t{hash:016x}");
}

fn check_cost(recorded: &str, measured: &str, identity: &str) {
    let (data, reason) = recorded
        .rsplit_once("#\treason\t")
        .expect("cost record requires its mechanism reason");
    let reason = reason
        .strip_suffix('\n')
        .expect("cost record must end with a newline");
    assert!(
        !reason.trim().is_empty() && !reason.contains(['\n', '\r', '\t']),
        "cost record requires a nonempty single-line mechanism reason"
    );
    assert_eq!(
        data, measured,
        "{identity}: matrix cost or selection changed"
    );
}

#[cfg(test)]
mod tests {
    use super::check_cost;

    const MEASURED: &str = "#\tconfiguration\tfork-a\n#\tidentity\tcopy\ndimension\tattempts\t12\nstage\tstops\t3\t9\n";

    #[test]
    fn identical_cost_and_configuration_pass() {
        check_cost(
            &format!("{MEASURED}#\treason\tprepaid release accounting\n"),
            MEASURED,
            "copy",
        );
    }

    #[test]
    #[should_panic(expected = "matrix cost or selection changed")]
    fn increased_work_is_rejected() {
        let record = format!("{MEASURED}#\treason\tinitial qualification\n");
        check_cost(
            &record,
            &MEASURED.replace("attempts\t12", "attempts\t13"),
            "copy",
        );
    }

    #[test]
    #[should_panic(expected = "matrix cost or selection changed")]
    fn omitted_schedules_are_rejected() {
        let record = format!("{MEASURED}#\treason\tinitial qualification\n");
        check_cost(
            &record,
            &MEASURED.replace("stops\t3\t9", "stops\t2\t9"),
            "copy",
        );
    }

    #[test]
    #[should_panic(expected = "matrix cost or selection changed")]
    fn stale_configuration_is_rejected() {
        let record = format!("{MEASURED}#\treason\tinitial qualification\n");
        check_cost(&record, &MEASURED.replace("fork-a", "fork-b"), "copy");
    }

    #[test]
    #[should_panic(expected = "nonempty single-line mechanism reason")]
    fn unexplained_record_is_rejected() {
        check_cost(&format!("{MEASURED}#\treason\t\n"), MEASURED, "copy");
    }
}
