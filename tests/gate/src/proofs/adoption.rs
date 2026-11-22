//! Adoption: a finished calibration run that is a sample, copied whole into
//! the tree where predictions may cite it, published so that no adopted run
//! is ever replaced, every directory and file of it made durable, and
//! accepted by a receipt written only once that durability was established
//! ([`super::AdoptionReceipt`]), which every reader of an adopted run
//! requires ([`RunRecords::adopted`]).

use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};

use super::{
    ADOPTION_RECORD, AdoptionReceipt, CALIBRATION, PURPOSE_CALIBRATION, RUNTIME_VERSION,
    RunIdentityRecord, RunRecords, contained, eligible_sample, harnesses, read_manifest,
    record_files, strict_json, typed,
};

/// The lock every adoption into one tree holds for its whole adoption, in
/// its calibration directory: adoptions of a tree are serialized, so a
/// publication is accepted or recovered by exactly one of them.
pub const ADOPTION_LOCK: &str = ".adoption.lock";

/// Exclude an in-progress publication while its acceptance receipt is read.
/// Portable committed evidence has no lock file; reading it creates none.
pub(super) fn publication_read_lock(directory: &Path) -> Result<Option<std::fs::File>, String> {
    use std::os::unix::fs::OpenOptionsExt;
    let parent = directory.parent().ok_or_else(|| {
        format!(
            "{}: an adopted run has no parent directory",
            directory.display()
        )
    })?;
    let path = parent.join(ADOPTION_LOCK);
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("{}: {error}", path.display())),
    };
    if !file
        .metadata()
        .map_err(|error| format!("{}: {error}", path.display()))?
        .is_file()
    {
        return Err(format!("{}: not a regular lock file", path.display()));
    }
    file.try_lock_shared().map_err(|error| {
        format!(
            "{}: adoption acceptance is in progress: {error}",
            path.display()
        )
    })?;
    Ok(Some(file))
}

/// Why an adoption did not establish an adopted run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Adoption {
    /// Refused: nothing was published, and nothing of this adoption's own
    /// staging is left (its removal's own failure, if any, named beside
    /// why).
    Refused(String),
    /// Published at `destination`, a sample by the one authority, but its
    /// durability was not established: the directory or its parent could
    /// not be synchronized, or its acceptance receipt could not be made
    /// durable, so after a crash the published name may be lost. No receipt
    /// is left, so no reader accepts the run ([`RunRecords::adopted`]); the
    /// destination is kept as it is, and adopting the same evidence again
    /// recovers it ([`adopt`]). `error` is why.
    Unsynchronized { destination: PathBuf, error: String },
    /// Releasing the serialization lock failed. Preserve the exact outcome
    /// of publication separately; a release failure does not undo acceptance.
    ReleaseFailed {
        outcome: Box<Result<PathBuf, Adoption>>,
        error: String,
    },
}

impl std::fmt::Display for Adoption {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(why) => write!(formatter, "{why}"),
            Self::Unsynchronized { destination, error } => write!(
                formatter,
                "{}: published, but its durability is not established and no reader accepts \
                 it; adopt the same evidence again to recover it: {error}",
                destination.display()
            ),
            Self::ReleaseFailed { outcome, error } => write!(
                formatter,
                "adoption outcome {outcome:?}; its serialization lock was not released: {error}"
            ),
        }
    }
}

/// Unlock explicitly before closing: a concurrently forked subprocess may
/// still hold an inherited descriptor for this open file description.
fn finish_adoption(
    lock: std::fs::File,
    outcome: Result<PathBuf, Adoption>,
) -> Result<PathBuf, Adoption> {
    match lock.unlock() {
        Ok(()) => outcome,
        Err(error) => Err(Adoption::ReleaseFailed {
            outcome: Box::new(outcome),
            error: error.to_string(),
        }),
    }
}

/// The file or directory at `path` made durable (`fsync(2)`): a file's
/// bytes, or a directory's entries. A new entry's own name is durable only
/// once its parent directory is synchronized too, which every caller does.
fn synchronized(path: &Path) -> Result<(), String> {
    std::fs::File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|error| format!("{}: synchronizing: {error}", path.display()))
}

/// Every directory of `relative` under `base` that does not exist created,
/// one component at a time, each recorded in `created` as it is made; a
/// component that exists must be a directory of its own, not a link.
fn create_directories(
    base: &Path,
    relative: &Path,
    created: &mut Vec<PathBuf>,
) -> Result<(), String> {
    let mut at = base.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(part) = component else {
            return Err(format!(
                "{}: not a plain path beneath {}",
                relative.display(),
                base.display()
            ));
        };
        at.push(part);
        match std::fs::create_dir(&at) {
            Ok(()) => created.push(at.clone()),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let kind = std::fs::symlink_metadata(&at)
                    .map_err(|error| format!("{}: {error}", at.display()))?
                    .file_type();
                if !kind.is_dir() {
                    return Err(format!("{}: exists and is not a directory", at.display()));
                }
            }
            Err(error) => return Err(format!("{}: {error}", at.display())),
        }
    }
    Ok(())
}

/// Each directory of `created` and the parent holding its entry made
/// durable, deepest first, so every entry is durable before the entry
/// naming its directory.
fn synchronize_created(
    created: &[PathBuf],
    sync: &dyn Fn(&Path) -> Result<(), String>,
) -> Result<(), String> {
    let mut directories: Vec<PathBuf> = created
        .iter()
        .flat_map(|directory| {
            [
                Some(directory.clone()),
                directory.parent().map(Path::to_path_buf),
            ]
        })
        .flatten()
        .collect();
    directories.sort_by(|one, other| {
        other
            .components()
            .count()
            .cmp(&one.components().count())
            .then_with(|| one.cmp(other))
    });
    directories.dedup();
    directories.iter().try_for_each(|directory| sync(directory))
}

/// The directory `staged` renamed to `destination` by `renameat2(2)` with
/// `RENAME_NOREPLACE`, which replaces nothing: refused when `destination`
/// exists in any form, an empty or non-empty directory, a file or a link,
/// and refused as unsupported where the kernel or the filesystem does not
/// provide it, with no fallback that could replace. Then the published
/// directory and its parent synchronized by `sync`. A failed rename
/// published nothing ([`Adoption::Refused`], `staged` left to its caller);
/// a failed synchronization after it leaves `destination` published and
/// says so ([`Adoption::Unsynchronized`]).
fn publish_with(
    staged: &Path,
    destination: &Path,
    sync: &dyn Fn(&Path) -> Result<(), String>,
) -> Result<(), Adoption> {
    use std::os::unix::ffi::OsStrExt;
    let path = |path: &Path| {
        std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| {
            Adoption::Refused(format!("{}: a path holding a NUL byte", path.display()))
        })
    };
    let (from, to) = (path(staged)?, path(destination)?);
    // SAFETY: `from` and `to` are NUL-terminated strings owned by this frame
    // and alive across the call; AT_FDCWD makes the kernel resolve them as
    // given; the call reads both and writes through no pointer.
    let renamed = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if renamed != 0 {
        let error = std::io::Error::last_os_error();
        return Err(Adoption::Refused(match error.raw_os_error() {
            Some(libc::EEXIST) => format!("{}: already adopted", destination.display()),
            Some(libc::EINVAL | libc::ENOSYS) => format!(
                "{}: {error}: renaming without replacing is unsupported here, and no adoption \
                 publishes by a rename that could replace",
                destination.display()
            ),
            _ => format!("{}: {error}", destination.display()),
        }));
    }
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    sync(destination)
        .and_then(|()| sync(parent))
        .map_err(|error| Adoption::Unsynchronized {
            destination: destination.to_path_buf(),
            error,
        })
}

/// The publication at `destination`, whose durability was established,
/// accepted: its receipt `receipt` created exclusively ([`ADOPTION_RECORD`]),
/// its bytes and its entry synchronized by `sync`. A receipt that could not
/// be made durable is removed, so no reader takes the publication for an
/// accepted one; its removal's own failure is named beside why.
fn accept(
    destination: &Path,
    receipt: &AdoptionReceipt,
    sync: &dyn Fn(&Path) -> Result<(), String>,
) -> Result<(), String> {
    let path = destination.join(ADOPTION_RECORD);
    let encoded = serde_json::to_vec_pretty(receipt)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    let written = file
        .write_all(&encoded)
        .map_err(|error| format!("{}: {error}", path.display()))
        .and_then(|()| sync(&path))
        .and_then(|()| sync(destination));
    match written {
        Ok(()) => Ok(()),
        Err(error) => Err(match std::fs::remove_file(&path) {
            Ok(()) => match sync(destination) {
                Ok(()) => error,
                Err(removal) => format!(
                    "{error}; {}: the receipt removal was not synchronized: {removal}",
                    destination.display()
                ),
            },
            Err(removal) => format!(
                "{error}; {}: the receipt whose durability was not established could not be \
                 removed: {removal}",
                path.display()
            ),
        }),
    }
}

/// Copy the records of the finished calibration run whose evidence is
/// `evidence` (a run's `LOG.evidence`, its log beside it as `LOG`) into the
/// tree at `root`, under [`CALIBRATION`]`/RUN`, its log as `kani.log` and its
/// evidence as `evidence/`, every instrumented binary left out, and accept it
/// ([`adopt_with`] with `fsync(2)`).
pub fn adopt(evidence: &Path, root: &Path) -> Result<PathBuf, Adoption> {
    adopt_with(evidence, root, &synchronized)
}

/// An adoption: the run's identity a calibration's; [`CALIBRATION`]
/// created under `root` as needed, every directory it created and the
/// parent holding its entry synchronized by `sync`; the tree's adoption lock
/// held ([`ADOPTION_LOCK`]); then, when the run was published but never
/// accepted, its recovery ([`recover`]); otherwise the copy staged in a
/// directory of this adoption's own beside its destination, every file,
/// every directory and every parent entry of it synchronized; held to the
/// one authority ([`eligible_sample`]); published atomically under a name
/// that must not exist ([`publish_with`]); and accepted ([`accept`]).
/// Refused when the run is not a calibration's or not a sample, when any
/// record is not a regular file, or when the run was already adopted, its
/// staging removed; a publication whose durability could not be established
/// says so, keeps the published run and leaves it unaccepted.
fn adopt_with(
    evidence: &Path,
    root: &Path,
    sync: &dyn Fn(&Path) -> Result<(), String>,
) -> Result<PathBuf, Adoption> {
    let refused = Adoption::Refused;
    match std::fs::symlink_metadata(evidence) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => {
            return Err(refused(format!(
                "{}: a run's evidence is a directory of its own, not a link",
                evidence.display()
            )));
        }
        Err(error) => return Err(refused(format!("{}: {error}", evidence.display()))),
    }
    let identity = std::fs::read(evidence.join("run.json"))
        .map_err(|error| format!("{}/run.json: {error}", evidence.display()))
        .and_then(|bytes| strict_json(&bytes))
        .and_then(|value| typed::<RunIdentityRecord>(value, "run.json"))
        .and_then(RunIdentityRecord::validate)
        .map_err(refused)?;
    if identity.purpose() != PURPOSE_CALIBRATION {
        return Err(refused(format!(
            "run {}: its purpose is {}, not calibration: only a calibration is adopted",
            identity.id(),
            identity.purpose()
        )));
    }
    let declared = harnesses(&root.join("src")).map_err(refused)?;
    let log = evidence.with_extension("log");
    let mut created = Vec::new();
    create_directories(root, Path::new(CALIBRATION), &mut created).map_err(refused)?;
    synchronize_created(&created, sync).map_err(refused)?;
    let base = contained(root, Path::new(CALIBRATION)).map_err(refused)?;
    let lock_path = base.join(ADOPTION_LOCK);
    let serialized = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .and_then(|file| file.lock().map(|()| file))
        .map_err(|error| refused(format!("{}: {error}", lock_path.display())))?;
    let outcome = (|| {
        let destination = base.join(identity.id());
        match std::fs::symlink_metadata(&destination) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(refused(format!("{}: {error}", destination.display()))),
            Ok(_) => {
                let receipt = destination.join(ADOPTION_RECORD);
                return match std::fs::symlink_metadata(&receipt) {
                    Ok(_) => Err(refused(format!(
                        "{}: already adopted",
                        destination.display()
                    ))),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        recover(evidence, &destination, identity.id(), &declared, sync)
                    }
                    Err(error) => Err(refused(format!("{}: {error}", receipt.display()))),
                };
            }
        }
        // Staged beside its destination, under a name no other adoption holds,
        // so the last step is a rename within one directory of one filesystem
        // and a competing adoption never touches this one's copy.
        let nonce = std::fs::read_to_string("/proc/sys/kernel/random/uuid")
            .map_err(|error| refused(format!("/proc/sys/kernel/random/uuid: {error}")))?;
        let staged = base.join(format!(".adopting-{}-{}", identity.id(), nonce.trim()));
        std::fs::create_dir(&staged)
            .map_err(|error| refused(format!("{}: {error}", staged.display())))?;
        let staging = (|| -> Result<AdoptionReceipt, String> {
            let mut created = vec![staged.clone()];
            let copied = staged.join("kani.log");
            std::fs::copy(&log, &copied).map_err(|error| format!("{}: {error}", log.display()))?;
            sync(&copied)?;
            for relative in record_files(evidence)? {
                let relative = Path::new(&relative);
                let directory =
                    Path::new("evidence").join(relative.parent().unwrap_or(Path::new("")));
                create_directories(&staged, &directory, &mut created)?;
                let target = staged.join("evidence").join(relative);
                std::fs::copy(evidence.join(relative), &target)
                    .map_err(|error| format!("{}: {error}", target.display()))?;
                sync(&target)?;
            }
            synchronize_created(&created, sync)?;
            // The staged copy is laid out as an adopted run is before its
            // acceptance: adopted only when it is a sample by the one authority.
            let sample = eligible_sample(&RunRecords::staged(&staged)?, identity.id(), &declared)?;
            Ok(AdoptionReceipt {
                version: RUNTIME_VERSION,
                run: identity.id().to_string(),
                manifest_sha256: sample.manifest_sha256().to_string(),
            })
        })();
        let published = match staging {
            Ok(receipt) => publish_with(&staged, &destination, sync).map(|()| receipt),
            Err(why) => Err(refused(why)),
        };
        match published {
            Ok(receipt) => accept(&destination, &receipt, sync)
                .map(|()| destination.clone())
                .map_err(|error| Adoption::Unsynchronized {
                    destination: destination.clone(),
                    error,
                }),
            Err(Adoption::Refused(why)) => {
                Err(Adoption::Refused(match std::fs::remove_dir_all(&staged) {
                    Ok(()) => why,
                    Err(error) => format!(
                        "{why}; its staging {} could not be removed: {error}",
                        staged.display()
                    ),
                }))
            }
            Err(unsynchronized) => Err(unsynchronized),
        }
    })();
    finish_adoption(serialized, outcome)
}

/// The recovery of a publication at `destination` that was never accepted
/// (no receipt: its durability was never established): the published copy
/// held to the one authority as staged ([`RunRecords::staged`]), its
/// manifest the very manifest of the run's evidence at `evidence`; then
/// every file, every directory and the entry naming it synchronized by
/// `sync`, deepest first; then accepted ([`accept`]). Refused when the
/// publication is no sample or not this run's records.
fn recover(
    evidence: &Path,
    destination: &Path,
    run: &str,
    declared: &BTreeSet<String>,
    sync: &dyn Fn(&Path) -> Result<(), String>,
) -> Result<PathBuf, Adoption> {
    let refused = Adoption::Refused;
    let sample = RunRecords::staged(destination)
        .and_then(|records| eligible_sample(&records, run, declared))
        .map_err(|why| {
            refused(format!(
                "{}: a publication never accepted, and no sample: {why}",
                destination.display()
            ))
        })?;
    let source = read_manifest(evidence, Some(run)).map_err(refused)?;
    if source.sha256() != sample.manifest_sha256() {
        return Err(refused(format!(
            "{}: publishes the manifest {}, the run's evidence holds {}: not this run's records",
            destination.display(),
            sample.manifest_sha256(),
            source.sha256()
        )));
    }
    let published = destination.join("evidence");
    let mut directories = BTreeSet::from([destination.to_path_buf(), published.clone()]);
    let mut files = vec![destination.join("kani.log")];
    for relative in record_files(&published).map_err(refused)? {
        let file = published.join(&relative);
        let mut at = file.parent();
        while let Some(directory) = at.filter(|directory| directory.starts_with(destination)) {
            directories.insert(directory.to_path_buf());
            at = directory.parent();
        }
        files.push(file);
    }
    let directories: Vec<PathBuf> = directories.into_iter().collect();
    let synchronized = files
        .iter()
        .try_for_each(|file| sync(file))
        .and_then(|()| synchronize_created(&directories, sync));
    let unsynchronized = |error: String| Adoption::Unsynchronized {
        destination: destination.to_path_buf(),
        error,
    };
    synchronized.map_err(unsynchronized)?;
    let receipt = AdoptionReceipt {
        version: RUNTIME_VERSION,
        run: run.to_string(),
        manifest_sha256: sample.manifest_sha256().to_string(),
    };
    accept(destination, &receipt, sync).map_err(unsynchronized)?;
    Ok(destination.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory of its own under the system's temporary directory.
    fn scratch(test: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("dcbor-adoption-{test}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    /// A staged directory holding one file.
    fn staged(root: &Path, name: &str) -> PathBuf {
        let staged = root.join(name);
        std::fs::create_dir(&staged).unwrap();
        std::fs::write(staged.join("record"), name).unwrap();
        staged
    }

    /// Publication replaces nothing: an empty directory, a non-empty one, a
    /// file and a link at the destination each refuse it, and each is left
    /// exactly as it was, the staged copy untouched.
    #[test]
    fn publication_replaces_nothing() {
        let root = scratch("no-replace");
        type Plant = fn(&Path);
        let destinations: [(&str, Plant); 4] = [
            ("empty-directory", |path| std::fs::create_dir(path).unwrap()),
            ("directory", |path| {
                std::fs::create_dir(path).unwrap();
                std::fs::write(path.join("kept"), "kept").unwrap();
            }),
            ("file", |path| std::fs::write(path, "kept").unwrap()),
            ("link", |path| {
                std::os::unix::fs::symlink("elsewhere", path).unwrap()
            }),
        ];
        for (name, plant) in destinations {
            let destination = root.join(name);
            plant(&destination);
            let before = crate::proofs::SourceState::read(&root)
                .unwrap()
                .digests()
                .unwrap();
            let staged = staged(&root, &format!(".staged-{name}"));
            let found = publish_with(&staged, &destination, &synchronized);
            assert_eq!(
                found,
                Err(Adoption::Refused(format!(
                    "{}: already adopted",
                    destination.display()
                ))),
                "{name}"
            );
            assert_eq!(
                std::fs::read(staged.join("record")).unwrap(),
                format!(".staged-{name}").as_bytes()
            );
            std::fs::remove_dir_all(&staged).unwrap();
            assert_eq!(
                crate::proofs::SourceState::read(&root)
                    .unwrap()
                    .digests()
                    .unwrap(),
                before,
                "{name}: the destination changed"
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A synchronization that fails after the rename leaves the run
    /// published and says so, naming the destination and the failure; one
    /// that fails before it publishes nothing.
    #[test]
    fn an_unsynchronized_publication_is_not_an_established_one() {
        let root = scratch("unsynchronized");
        let destination = root.join("run");
        let staged = staged(&root, ".staged");
        let failing = |path: &Path| Err(format!("{}: injected", path.display()));
        let found = publish_with(&staged, &destination, &failing);
        assert_eq!(
            found,
            Err(Adoption::Unsynchronized {
                destination: destination.clone(),
                error: format!("{}: injected", destination.display()),
            })
        );
        assert_eq!(
            std::fs::read(destination.join("record")).unwrap(),
            b".staged"
        );
        assert!(!staged.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A publication whose durability was not established is accepted by no
    /// reader until it is recovered: the predictions citing it are refused
    /// while it holds no receipt, whether the synchronization after its
    /// rename failed or its receipt could not be made durable (the receipt
    /// then removed); adopting the same evidence again recovers it, and the
    /// predictions read.
    #[test]
    fn an_unaccepted_publication_is_refused_until_recovered() {
        let tree = crate::proofs::tests::CalibrationTree::new("unaccepted-publication");
        let mut references = tree.three();
        for (id, failing) in [
            ("00000000-0000-0000-0000-0000000000d1", "publication"),
            ("00000000-0000-0000-0000-0000000000d2", "receipt"),
        ] {
            let evidence =
                crate::proofs::tests::finished_run(&tree, id, "calibration", "a::x", "SUCCESSFUL");
            let destination = tree.root.join(CALIBRATION).join(id);
            let injected = match failing {
                "publication" => destination.clone(),
                _ => destination.join(ADOPTION_RECORD),
            };
            let sync = |path: &Path| {
                if path == injected {
                    Err(format!("{}: injected", path.display()))
                } else {
                    synchronized(path)
                }
            };
            let found = adopt_with(&evidence, &tree.root, &sync);
            assert!(
                matches!(&found, Err(Adoption::Unsynchronized { destination: at, .. }) if *at == destination),
                "{failing}: {found:?}"
            );
            assert!(
                !destination.join(ADOPTION_RECORD).exists(),
                "{failing}: an unestablished publication holds a receipt"
            );
            let manifest =
                crate::process::sha256(&destination.join("evidence/manifest.json")).unwrap();
            references.0[0] = serde_json::json!({"run": id, "manifest_sha256": manifest});
            let document = serde_json::to_vec(&tree.document(&references, 1400, 2300)).unwrap();
            let refused = tree.read(&document);
            assert!(
                matches!(&refused, Err(why) if why.contains("its publication was never accepted")),
                "{failing}: an unaccepted publication was read: {refused:?}"
            );
            assert_eq!(adopt(&evidence, &tree.root), Ok(destination.clone()));
            tree.read(&document)
                .unwrap_or_else(|why| panic!("{failing}: the recovered run is refused: {why}"));
            assert_eq!(
                adopt(&evidence, &tree.root),
                Err(Adoption::Refused(format!(
                    "{}: already adopted",
                    destination.display()
                )))
            );
        }
    }

    #[test]
    fn a_receipt_is_not_read_while_acceptance_is_in_progress() {
        let tree = crate::proofs::tests::CalibrationTree::new("receipt-in-progress");
        let id = "00000000-0000-0000-0000-0000000000d3";
        let evidence =
            crate::proofs::tests::finished_run(&tree, id, "calibration", "a::x", "SUCCESSFUL");
        let destination = tree.root.join(CALIBRATION).join(id);
        let receipt = destination.join(ADOPTION_RECORD);
        let observed = std::cell::Cell::new(false);
        let sync = |path: &Path| {
            if path == receipt {
                observed.set(true);
                let read = RunRecords::adopted(&destination);
                assert!(
                    read.is_err(),
                    "acceptance-in-progress: a reader accepted an unsynchronized receipt: {read:?}"
                );
            }
            synchronized(path)
        };
        assert_eq!(
            adopt_with(&evidence, &tree.root, &sync),
            Ok(destination.clone())
        );
        assert!(
            observed.get(),
            "the receipt synchronization was not exercised"
        );
        RunRecords::adopted(&destination).unwrap();
    }

    #[test]
    fn a_failed_receipt_synchronizes_its_removal() {
        let root = scratch("receipt-removal");
        let receipt = AdoptionReceipt {
            version: RUNTIME_VERSION,
            run: "00000000-0000-0000-0000-0000000000d4".to_string(),
            manifest_sha256: "0".repeat(64),
        };
        let synchronized_removal = std::cell::Cell::new(false);
        let sync = |path: &Path| {
            if path == root.join(ADOPTION_RECORD) {
                Err("receipt synchronization failed".to_string())
            } else {
                assert!(!root.join(ADOPTION_RECORD).exists());
                synchronized_removal.set(true);
                Err("removal synchronization failed".to_string())
            }
        };
        let error = accept(&root, &receipt, &sync).unwrap_err();
        assert!(
            synchronized_removal.get(),
            "the receipt removal was not synchronized"
        );
        assert!(error.contains("receipt synchronization failed"), "{error}");
        assert!(error.contains("removal synchronization failed"), "{error}");
        std::fs::remove_dir(&root).unwrap();
    }

    #[test]
    fn recovery_never_follows_a_publication_symlink() {
        let tree = crate::proofs::tests::CalibrationTree::new("recovery-symlink");
        let id = "00000000-0000-0000-0000-0000000000d5";
        let evidence =
            crate::proofs::tests::finished_run(&tree, id, "calibration", "a::x", "SUCCESSFUL");
        let destination = adopt(&evidence, &tree.root).unwrap();
        std::fs::remove_file(destination.join(ADOPTION_RECORD)).unwrap();
        let elsewhere = tree.root.join("elsewhere");
        std::fs::rename(&destination, &elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &destination).unwrap();
        let recovered = adopt(&evidence, &tree.root);
        assert!(
            matches!(recovered, Err(Adoption::Refused(_))),
            "recovery-followed-link: {recovered:?}"
        );
        assert!(
            !elsewhere.join(ADOPTION_RECORD).exists(),
            "recovery wrote acceptance outside its publication"
        );
    }

    #[test]
    fn completion_unlocks_even_when_an_inherited_descriptor_remains() {
        let root = scratch("inherited-lock");
        let path = root.join(ADOPTION_LOCK);
        let lock = std::fs::File::create(&path).unwrap();
        lock.lock().unwrap();
        let inherited = lock.try_clone().unwrap();
        let destination = root.join("run");
        assert_eq!(
            finish_adoption(lock, Ok(destination.clone())),
            Ok(destination)
        );
        let reader = std::fs::File::open(&path).unwrap();
        reader
            .try_lock_shared()
            .expect("completion left its lock held by an inherited descriptor");
        drop(reader);
        drop(inherited);
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&root).unwrap();
    }

    /// Every directory an adoption creates, and the parent holding each
    /// one's entry, is synchronized, deepest first.
    #[test]
    fn every_created_directory_is_synchronized_deepest_first() {
        let root = scratch("created");
        let mut created = Vec::new();
        create_directories(&root, Path::new("a/b/c"), &mut created).unwrap();
        assert_eq!(
            created,
            [root.join("a"), root.join("a/b"), root.join("a/b/c")]
        );
        let synced = std::cell::RefCell::new(Vec::new());
        synchronize_created(&created, &|path: &Path| {
            synced.borrow_mut().push(path.to_path_buf());
            Ok(())
        })
        .unwrap();
        assert_eq!(
            synced.into_inner(),
            [
                root.join("a/b/c"),
                root.join("a/b"),
                root.join("a"),
                root.clone()
            ]
        );
        let mut again = Vec::new();
        create_directories(&root, Path::new("a/b"), &mut again).unwrap();
        assert!(
            again.is_empty(),
            "an existing directory was recorded as created"
        );
        std::fs::write(root.join("file"), "").unwrap();
        let found = create_directories(&root, Path::new("file/x"), &mut again).unwrap_err();
        assert!(found.contains("exists and is not a directory"), "{found}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Adoptions of one run competing at once: exactly one publishes and
    /// accepts, the published run is exactly the run's records, every other
    /// is refused as already adopted, and no staging is left.
    #[test]
    fn competing_adoptions_publish_one_run() {
        let tree = crate::proofs::tests::CalibrationTree::new("competing-adoption");
        let id = "00000000-0000-0000-0000-0000000000c1";
        let evidence =
            crate::proofs::tests::finished_run(&tree, id, "calibration", "a::x", "SUCCESSFUL");
        let barrier = std::sync::Barrier::new(4);
        let results: Vec<Result<PathBuf, Adoption>> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..4)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        adopt(&evidence, &tree.root)
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect()
        });
        let destination = tree.root.join(CALIBRATION).join(id);
        let won: Vec<&PathBuf> = results
            .iter()
            .filter_map(|result| result.as_ref().ok())
            .collect();
        assert_eq!(won.len(), 1, "{results:#?}");
        for result in &results {
            if let Err(fault) = result {
                assert_eq!(
                    fault,
                    &Adoption::Refused(format!("{}: already adopted", destination.display())),
                    "{results:#?}"
                );
            }
        }
        for relative in record_files(&evidence).unwrap() {
            assert_eq!(
                std::fs::read(destination.join("evidence").join(&relative)).unwrap(),
                std::fs::read(evidence.join(&relative)).unwrap(),
                "{relative}"
            );
        }
        eligible_sample(
            &RunRecords::adopted(&destination).unwrap(),
            id,
            &crate::proofs::tests::CalibrationTree::census(),
        )
        .unwrap();
        let left: Vec<String> = std::fs::read_dir(tree.root.join(CALIBRATION))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(".adopting-"))
            .collect();
        assert!(left.is_empty(), "staging left: {left:?}");
    }
}
