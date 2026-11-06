//! The launchers' own contracts, where a launcher decides what it passes to
//! the gate: each run on a copy of the script in a scratch repository, with
//! the programs it launches replaced by recorders.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The repository's tests directory.
fn tests() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// A scratch repository named for `test`, removed unless the test fails.
struct Scratch(PathBuf);

impl Scratch {
    fn new(test: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "dcbor-gate-launchers-{test}-{}",
            std::process::id()
        ));
        if root.exists() {
            std::fs::remove_dir_all(&root).unwrap();
        }
        std::fs::create_dir_all(root.join("tests")).unwrap();
        std::fs::create_dir_all(root.join("bin")).unwrap();
        Self(root)
    }

    fn executable(&self, relative: &str, text: &str) {
        let path = self.0.join(relative);
        std::fs::write(&path, text).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
}

/// The contribution gate checks the records, then the cost evidence, passing
/// a completed run to reuse when one is named, and fails when the cost
/// check fails.
#[test]
fn the_contribution_gate_forwards_a_reused_run_and_its_failure() {
    let scratch = Scratch::new("contribution");
    std::fs::copy(
        tests().join("run-contribution-contracts.sh"),
        scratch.0.join("tests/run-contribution-contracts.sh"),
    )
    .unwrap();
    scratch.executable("bin/cargo", "#!/bin/sh\nexit 0\n");
    scratch.executable(
        "tests/record-evidence.sh",
        "#!/bin/bash\nprintf '%s\\n' \"$*\" >> evidence-arguments\n\
         if [[ \"$1\" == check-costs ]]; then exit \"${REUSE_EXIT:-0}\"; fi\n",
    );
    let path = format!(
        "{}:{}",
        scratch.0.join("bin").display(),
        std::env::var("PATH").unwrap()
    );
    for status in [0, 1] {
        let arguments = scratch.0.join("evidence-arguments");
        if arguments.exists() {
            std::fs::remove_file(&arguments).unwrap();
        }
        let output = Command::new("bash")
            .arg("tests/run-contribution-contracts.sh")
            .current_dir(&scratch.0)
            .env("PATH", &path)
            .env("TMPDIR", &scratch.0)
            .env("DCBOR_COST_REUSE", "/completed run")
            .env("REUSE_EXIT", status.to_string())
            .env_remove("CONTRACT_LOG_DIR")
            .env_remove("DCBOR_RIGOR")
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(status),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            std::fs::read_to_string(&arguments).unwrap(),
            "check\ncheck-costs /completed run\n"
        );
    }
}
