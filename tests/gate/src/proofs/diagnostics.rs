//! Formula diagnostics of one harness's preserved instrumented binary, from a
//! discovery run's evidence (`LOGS/kani.evidence/loop-bounds/H`): evidence
//! only, never a sample, a qualification or a control side. Every step runs
//! the solver the discovery recorded (`solver.identity`) with the solver
//! command it recorded (`solver.arguments`), unchanged but for the step's
//! own flags, as a bounded workload ([`crate::process::bounded`]): isolated
//! as every recorded workload is, its whole scope stopped at its deadline.
//! A diagnosis writes into a directory of its own, numbered and created
//! exclusively under the root it is given, never into the discovery's logs:
//! its identity (`identity.json`), each step's `command`, `status`, `stdout`
//! and `stderr` in a directory of the step's, and `summary.json`.
//!
//! Output formats read at CBMC `cbmc-6.11.0` + `fc0bc35`:
//! - a `--json-ui` run prints one JSON array, every message and result an
//!   element (`util/ui_message.cpp`); `--show-byte-ops` writes its object
//!   into that array, after a `,` (`goto-symex/show_program.cpp`,
//!   `show_byte_ops_json`), so the whole output is still one array, read
//!   strictly;
//! - `--show-properties` prints an element holding `properties`, each with
//!   `name`, `class`, `sourceLocation`, `description`
//!   (`goto-programs/show_properties.cpp`, `convert_properties_json`);
//! - a verification prints an element `result`, each entry `property` and
//!   `status`, one of `SUCCESS`, `FAILURE`, `UNKNOWN`, `NOT CHECKED`,
//!   `UNREACHABLE`, `ERROR` (`goto-checker/properties.cpp`);
//! - `--program-only` prints its steps as plain text whatever the
//!   interface: `// N LOCATION`, then `(k) STEP` for a kept step or
//!   `(sliced) STEP` for a sliced one (`show_program.cpp`, `show_program`),
//!   LOCATION as `source_locationt::as_string` renders it, `file F line L
//!   column C function FN`, each part present only when known
//!   (`util/source_location.cpp`);
//! - `--show-byte-ops` writes `byteOpsStats`, holding `byteExtractStats` and
//!   `byteUpdateStats`, each a list of steps with their `sourceLocation` and
//!   a count, a JSON number (`show_byte_ops_json`, `get_byte_op_json`);
//! - the solver exits 0 when every step succeeds or every property holds, 10
//!   when one fails and 5 when one is inconclusive; every other code is an
//!   error (`util/exit_codes.h`).
//!
//! Kani marks its reachability checks with the property class
//! `reachability_check` (kani-driver `cbmc_property_renderer.rs`); CBMC its
//! unwinding assertions with `unwind`.

use std::collections::BTreeMap;
use std::io::BufRead;
use std::path::{Path, PathBuf};

/// Every step's deadline: the cap a calibration plan gives one harness's
/// whole verification (`tests/data/proofs/calibration`'s plans), so no step
/// of a diagnosis is cut shorter than the harness itself would be.
pub const STEP_SECONDS: u64 = 1_800;

/// How many entries of each aggregation are reported.
pub const TOP: usize = 20;

/// How one step ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Ended {
    Exited {
        code: i32,
    },
    /// Stopped by a signal before its deadline.
    Signaled {
        signal: i32,
    },
    /// Stopped by its scope's deadline ([`crate::process::bounded`]).
    Deadline {
        seconds: u64,
    },
}

impl Ended {
    fn render(self) -> String {
        match self {
            Self::Exited { code } => format!("exit status: {code}\n"),
            Self::Signaled { signal } => format!("signal: {signal}\n"),
            Self::Deadline { seconds } => format!("deadline: {seconds} s\n"),
        }
    }
}

/// The class of one property ([`classify`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// An assertion written in the harness's own file.
    Harness,
    Reachability,
    Unwinding,
    /// Every other property: production assertions, overflow and pointer
    /// checks, by their CBMC class.
    Other,
}

/// One property of the inventory.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Property {
    pub name: String,
    pub class: String,
    pub kind: Kind,
    pub file: Option<String>,
    pub line: Option<String>,
    pub function: Option<String>,
    pub description: String,
}

/// A property's status in a verification's `result` (`properties.cpp`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub enum Status {
    #[serde(rename = "SUCCESS")]
    Success,
    #[serde(rename = "FAILURE")]
    Failure,
    #[serde(rename = "UNKNOWN")]
    Unknown,
    #[serde(rename = "NOT CHECKED")]
    NotChecked,
    #[serde(rename = "UNREACHABLE")]
    Unreachable,
    #[serde(rename = "ERROR")]
    Error,
}

impl Status {
    /// `text` as CBMC writes it; refused for any other text.
    pub fn parse(text: &str) -> Result<Self, String> {
        Ok(match text {
            "SUCCESS" => Self::Success,
            "FAILURE" => Self::Failure,
            "UNKNOWN" => Self::Unknown,
            "NOT CHECKED" => Self::NotChecked,
            "UNREACHABLE" => Self::Unreachable,
            "ERROR" => Self::Error,
            other => return Err(format!("a property status CBMC does not write: {other:?}")),
        })
    }
}

/// What a verification step established about its properties.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Verdict {
    /// The solver exited with a verification's code (0, 5 or 10) and
    /// reported the property's status.
    Reported { status: Status },
    /// The step reached its deadline.
    Deadline,
    /// The solver ended otherwise, or reported no status: nothing of the
    /// property is established.
    Unreported { ended: Ended },
}

/// The harness's evidence a diagnosis reads: its solver, its recorded
/// command's arguments without the program and without `--json-ui`, and its
/// preserved artifact and digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recorded {
    pub solver: PathBuf,
    pub arguments: Vec<String>,
    pub artifact: PathBuf,
    pub sha256: String,
}

/// The records of `harness` under `evidence` (`LOGS/kani.evidence`): its
/// `solver.identity`, `solver.arguments` and `artifact.json`, the preserved
/// artifact's bytes held to the recorded digest and named by the command.
pub fn recorded(evidence: &Path, harness: &str) -> Result<Recorded, String> {
    let at = evidence
        .join("loop-bounds")
        .join(harness.replace("::", "."));
    let read = |file: &str| {
        std::fs::read(at.join(file))
            .map_err(|error| format!("{}: {error}", at.join(file).display()))
    };
    let identity = super::strict_json(&read("solver.identity")?)
        .map_err(|fault| format!("solver.identity: {fault}"))?;
    let solver = identity["solver"]["path"]
        .as_str()
        .filter(|path| path.starts_with('/'))
        .ok_or("solver.identity names no absolute solver path")?;
    let bytes = read("solver.arguments")?;
    let command = super::command_record(&bytes)?;
    let parts: Vec<String> = command
        .iter()
        .map(|part| {
            std::str::from_utf8(part)
                .map(str::to_string)
                .map_err(|_| "solver.arguments holds an argument that is not UTF-8".to_string())
        })
        .collect::<Result<_, _>>()?;
    let [program, arguments @ ..] = parts.as_slice() else {
        return Err("solver.arguments is empty".to_string());
    };
    if program != solver {
        return Err(format!(
            "solver.arguments runs {program}, solver.identity records {solver}"
        ));
    }
    let artifact_record = super::strict_json(&read("artifact.json")?)
        .map_err(|fault| format!("artifact.json: {fault}"))?;
    let artifact = artifact_record["path"]
        .as_str()
        .ok_or("artifact.json names no path")?;
    let sha256 = artifact_record["sha256"]
        .as_str()
        .filter(|digest| super::sha256_text(digest))
        .ok_or("artifact.json records no digest")?;
    let actual = crate::process::sha256(Path::new(artifact))?;
    if actual != sha256 {
        return Err(format!(
            "{artifact}: its bytes have digest {actual}, artifact.json records {sha256}"
        ));
    }
    if !arguments.iter().any(|argument| argument == artifact) {
        return Err(format!(
            "solver.arguments does not name the preserved artifact {artifact}"
        ));
    }
    Ok(Recorded {
        solver: PathBuf::from(solver),
        arguments: arguments
            .iter()
            .filter(|argument| *argument != "--json-ui")
            .cloned()
            .collect(),
        artifact: PathBuf::from(artifact),
        sha256: sha256.to_string(),
    })
}

/// One step's records: its directory, created exclusively, and how it
/// ended. Its standard output is the directory's `stdout`.
pub struct Ran {
    pub directory: PathBuf,
    pub ended: Ended,
}

impl Ran {
    pub fn stdout(&self) -> PathBuf {
        self.directory.join("stdout")
    }
}

/// Run `recorded`'s solver with its arguments and `extra` as a bounded
/// workload of `workload`'s, stopped at `seconds`, its records in
/// `out/name`. A signal at or past the deadline is the deadline's; one
/// before it is the signal's.
pub fn step(
    workload: &crate::process::Workload,
    recorded: &Recorded,
    out: &Path,
    name: &str,
    extra: &[String],
    seconds: u64,
) -> Result<Ran, String> {
    let directory = out.join(name);
    std::fs::create_dir(&directory).map_err(|error| format!("{}: {error}", directory.display()))?;
    let mut arguments = recorded.arguments.clone();
    arguments.extend_from_slice(extra);
    let record: Vec<u8> = std::iter::once(recorded.solver.to_string_lossy().into_owned())
        .chain(arguments.iter().cloned())
        .flat_map(|part| part.into_bytes().into_iter().chain([0]))
        .collect();
    crate::process::record(&directory.join("command"), &record)?;
    let file = |file: &str| {
        std::fs::File::create_new(directory.join(file))
            .map_err(|error| format!("{}: {error}", directory.join(file).display()))
    };
    let started = std::time::Instant::now();
    let status = crate::process::bounded(workload, &recorded.solver, seconds)
        .args(&arguments)
        .stdout(file("stdout")?)
        .stderr(file("stderr")?)
        .status()
        .map_err(|error| format!("{}: {error}", recorded.solver.display()))?;
    let ended = {
        use std::os::unix::process::ExitStatusExt;
        match (status.code(), status.signal()) {
            (Some(code), _) => Ended::Exited { code },
            (None, Some(_)) if started.elapsed().as_secs() >= seconds => {
                Ended::Deadline { seconds }
            }
            (None, Some(signal)) => Ended::Signaled { signal },
            (None, None) => return Err(format!("{name}: an exit status of no code or signal")),
        }
    };
    crate::process::record(&directory.join("status"), ended.render().as_bytes())?;
    Ok(Ran { directory, ended })
}

/// The elements of a `--json-ui` output at `path`: one JSON array, read
/// strictly ([`super::strict_json`]).
fn json_stream(path: &Path) -> Result<Vec<serde_json::Value>, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    match super::strict_json(&bytes).map_err(|fault| format!("{}: {fault}", path.display()))? {
        serde_json::Value::Array(elements) => Ok(elements),
        other => Err(format!(
            "{}: a --json-ui output that is not one array: {other}",
            path.display()
        )),
    }
}

/// The class of a property: Kani's reachability checks, CBMC's unwinding
/// assertions, an assertion of the harness's file `harness_file` (the file
/// its location names ends with that path, component by component), or
/// other.
pub fn classify(class: &str, file: Option<&str>, harness_file: &str) -> Kind {
    match class {
        "reachability_check" => Kind::Reachability,
        "unwind" => Kind::Unwinding,
        "assertion" if file.is_some_and(|file| Path::new(file).ends_with(harness_file)) => {
            Kind::Harness
        }
        _ => Kind::Other,
    }
}

/// The properties of a `--show-properties` output's elements, classified
/// against `harness_file`. Refused when they hold no inventory or a
/// property without its name or class.
pub fn properties(
    elements: &[serde_json::Value],
    harness_file: &str,
) -> Result<Vec<Property>, String> {
    let inventory = elements
        .iter()
        .find_map(|element| element["properties"].as_array())
        .ok_or("the output holds no `properties` inventory")?;
    inventory
        .iter()
        .map(|property| {
            let text = |key: &str| property[key].as_str().map(str::to_string);
            let location = |key: &str| property["sourceLocation"][key].as_str().map(str::to_string);
            let name =
                text("name").ok_or_else(|| format!("a property names no name: {property}"))?;
            let class = text("class").ok_or_else(|| format!("property {name} names no class"))?;
            let file = location("file");
            Ok(Property {
                kind: classify(&class, file.as_deref(), harness_file),
                description: text("description").unwrap_or_default(),
                line: location("line"),
                function: location("function"),
                file,
                class,
                name,
            })
        })
        .collect()
}

/// The status a verification's elements give `property`; `None` when they
/// report none. Refused for a status CBMC does not write.
pub fn status(elements: &[serde_json::Value], property: &str) -> Result<Option<Status>, String> {
    elements
        .iter()
        .filter_map(|element| element["result"].as_array())
        .flatten()
        .find(|result| result["property"] == property)
        .map(|result| {
            let text = result["status"]
                .as_str()
                .ok_or_else(|| format!("the result of {property} has no status: {result}"))?;
            Status::parse(text)
        })
        .transpose()
}

/// The verdict a verification step reached on `property`: its reported
/// status when the solver exited as a verification exits (0, 5, 10:
/// `util/exit_codes.h`).
pub fn verdict(ran: &Ran, property: &str) -> Result<Verdict, String> {
    Ok(match ran.ended {
        Ended::Deadline { .. } => Verdict::Deadline,
        Ended::Exited { code: 0 | 5 | 10 } => match status(&json_stream(&ran.stdout())?, property)?
        {
            Some(status) => Verdict::Reported { status },
            None => Verdict::Unreported { ended: ran.ended },
        },
        ended => Verdict::Unreported { ended },
    })
}

/// `ran` refused unless it exited 0: a step that only shows the program
/// succeeds exactly so (`util/exit_codes.h`, `CPROVER_EXIT_SUCCESS`).
fn succeeded(ran: &Ran, name: &str) -> Result<(), String> {
    match ran.ended {
        Ended::Exited { code: 0 } => Ok(()),
        ended => Err(format!(
            "{name} ended {ended:?} ({}): nothing of it is evidence",
            ran.directory.display()
        )),
    }
}

/// A source location as `source_locationt::as_string` renders it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Location {
    pub file: Option<String>,
    pub line: Option<String>,
    pub function: Option<String>,
}

impl Location {
    /// `text`, `file F line L column C function FN` with any part absent
    /// (`source_location.cpp`); the function, which may hold spaces, runs to
    /// the end or to a `bytecode-index`, which only a Java program has.
    pub fn parse(text: &str) -> Self {
        let mut location = Self::default();
        let mut rest = text.trim();
        if let Some(after) = rest.strip_prefix("file ") {
            let end = [" line ", " column ", " function "]
                .iter()
                .filter_map(|next| after.find(next))
                .min()
                .unwrap_or(after.len());
            location.file = Some(after[..end].to_string());
            rest = after[end..].trim_start();
        }
        if let Some(after) = rest.strip_prefix("line ") {
            let end = after.find(' ').unwrap_or(after.len());
            location.line = Some(after[..end].to_string());
            rest = after[end..].trim_start();
        }
        if let Some(after) = rest.strip_prefix("column ") {
            let end = after.find(' ').unwrap_or(after.len());
            rest = after[end..].trim_start();
        }
        if let Some(after) = rest.strip_prefix("function ") {
            let end = after.find(" bytecode-index ").unwrap_or(after.len());
            location.function = Some(after[..end].to_string());
        }
        location
    }

    /// `file:line`, `?` for a part absent.
    pub fn file_line(&self) -> String {
        format!(
            "{}:{}",
            self.file.as_deref().unwrap_or("?"),
            self.line.as_deref().unwrap_or("?")
        )
    }

    pub fn function_name(&self) -> String {
        self.function.clone().unwrap_or_else(|| "?".to_string())
    }
}

/// What one investigation asks of a formula, given at the diagnosis, never
/// fixed in the gate: source sites by `file:line`, functions by a fragment
/// of their name, whose shares of the kept steps are reported, and a callee
/// whose callers are.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct Focus {
    pub sites: Vec<(String, String)>,
    pub functions: Vec<String>,
    pub callee: Option<String>,
}

impl Focus {
    /// `arguments` as `--site FILE:LINE`, `--function FRAGMENT` and
    /// `--callers FRAGMENT`, the last at most once; refused for anything
    /// else.
    pub fn parse(arguments: &[&str]) -> Result<Self, String> {
        let mut focus = Self::default();
        let mut rest = arguments.iter();
        while let Some(&flag) = rest.next() {
            let value = rest.next().ok_or_else(|| format!("{flag} needs a value"))?;
            match flag {
                "--site" => {
                    let (file, line) = value
                        .rsplit_once(':')
                        .filter(|(file, line)| {
                            !file.is_empty() && line.bytes().all(|b| b.is_ascii_digit())
                        })
                        .ok_or_else(|| format!("--site {value}: not FILE:LINE"))?;
                    focus.sites.push((file.to_string(), line.to_string()));
                }
                "--function" => focus.functions.push(value.to_string()),
                "--callers" if focus.callee.is_none() => focus.callee = Some(value.to_string()),
                "--callers" => return Err("--callers is given once".to_string()),
                other => return Err(format!("an unknown focus {other}")),
            }
        }
        Ok(focus)
    }
}

/// One aggregation entry: a key, its count and its share of the total.
#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct Entry {
    pub key: String,
    pub count: u64,
    pub share: f64,
}

fn share(count: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        count as f64 / total as f64
    }
}

/// The `top` keys of `counts` by count, ties by key, each with its share of
/// `total`.
pub fn top(counts: &BTreeMap<String, u64>, total: u64, top: usize) -> Vec<Entry> {
    let mut entries: Vec<(&String, &u64)> = counts.iter().collect();
    entries.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
    entries
        .into_iter()
        .take(top)
        .map(|(key, &count)| Entry {
            key: key.clone(),
            count,
            share: share(count, total),
        })
        .collect()
}

/// A focus entry's steps and their share of all kept steps.
#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct Site {
    pub site: String,
    pub steps: u64,
    pub share: f64,
}

/// The kept steps of a `--program-only` output, aggregated in one pass over
/// its lines, none held: by function and by `file:line`, each focus site's
/// and function's, and the callee's callers (the function of the kept step
/// before each run of steps inside it).
#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct Formula {
    pub steps: u64,
    pub by_function: Vec<Entry>,
    pub by_file_line: Vec<Entry>,
    pub sites: Vec<Site>,
    pub callers: Vec<Entry>,
}

/// The formula of the `--program-only` output at `path` under `focus`:
/// each line read strictly as UTF-8, sliced steps left out, as slicing
/// removes them from the formula.
pub fn formula(path: &Path, focus: &Focus) -> Result<Formula, String> {
    let file = std::fs::File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let mut reader = std::io::BufReader::new(file);
    let mut line = Vec::new();
    let mut at: Option<Location> = None;
    let mut previous: Option<String> = None;
    let (mut steps, mut functions, mut lines, mut callers) =
        (0u64, BTreeMap::new(), BTreeMap::new(), BTreeMap::new());
    let mut site_steps = vec![0u64; focus.sites.len() + focus.functions.len()];
    let mut number = 0usize;
    loop {
        line.clear();
        if reader
            .read_until(b'\n', &mut line)
            .map_err(|error| format!("{}: {error}", path.display()))?
            == 0
        {
            break;
        }
        number += 1;
        let text = std::str::from_utf8(&line)
            .map_err(|error| format!("{}:{number}: not UTF-8: {error}", path.display()))?
            .trim_end_matches(['\n', '\r']);
        if let Some(comment) = text.strip_prefix("// ") {
            // `// N LOCATION`: the instruction's location number, then its
            // location.
            at = Some(Location::parse(
                comment.split_once(' ').map_or("", |(_, rest)| rest),
            ));
            continue;
        }
        // A kept step's count is digits; a sliced one's is `sliced`.
        let kept = text
            .strip_prefix('(')
            .and_then(|rest| rest.split_once(')'))
            .is_some_and(|(count, _)| {
                !count.is_empty() && count.bytes().all(|b| b.is_ascii_digit())
            });
        let Some(location) = at.as_ref().filter(|_| kept) else {
            continue;
        };
        steps += 1;
        let function = location.function_name();
        *functions.entry(function.clone()).or_insert(0) += 1;
        *lines.entry(location.file_line()).or_insert(0) += 1;
        for (count, (file, site_line)) in site_steps.iter_mut().zip(&focus.sites) {
            if location.line.as_deref() == Some(site_line.as_str())
                && location
                    .file
                    .as_deref()
                    .is_some_and(|located| Path::new(located).ends_with(file))
            {
                *count += 1;
            }
        }
        for (count, fragment) in site_steps[focus.sites.len()..]
            .iter_mut()
            .zip(&focus.functions)
        {
            if function.contains(fragment.as_str()) {
                *count += 1;
            }
        }
        if let Some(callee) = &focus.callee {
            let inside = |name: &str| name.contains(callee.as_str());
            if inside(&function)
                && !previous.as_deref().is_some_and(inside)
                && let Some(caller) = &previous
            {
                *callers.entry(caller.clone()).or_insert(0) += 1;
            }
        }
        previous = Some(function);
    }
    let named = focus
        .sites
        .iter()
        .map(|(file, line)| format!("{file}:{line}"))
        .chain(
            focus
                .functions
                .iter()
                .map(|f| format!("function containing {f:?}")),
        );
    let entered: u64 = callers.values().sum();
    Ok(Formula {
        steps,
        by_function: top(&functions, steps, TOP),
        by_file_line: top(&lines, steps, TOP),
        sites: named
            .zip(site_steps)
            .map(|(site, count)| Site {
                site,
                steps: count,
                share: share(count, steps),
            })
            .collect(),
        callers: top(&callers, entered, usize::MAX),
    })
}

/// The byte operations of a `--show-byte-ops` output's elements.
#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct ByteOps {
    pub extracts: u64,
    pub updates: u64,
    pub by_function: Vec<Entry>,
    pub by_file_line: Vec<Entry>,
}

/// The byte operations its elements' `byteOpsStats` state, aggregated.
pub fn byte_ops(elements: &[serde_json::Value]) -> Result<ByteOps, String> {
    let stats = elements
        .iter()
        .find_map(|element| element.get("byteOpsStats"))
        .ok_or("the output holds no `byteOpsStats`")?;
    let (mut functions, mut lines) = (BTreeMap::new(), BTreeMap::new());
    let mut steps = 0u64;
    let mut totals = [0u64; 2];
    for (total, (stats_key, list, count)) in totals.iter_mut().zip([
        ("byteExtractStats", "byteExtractList", "numOfExtracts"),
        ("byteUpdateStats", "byteUpdateList", "numOfUpdates"),
    ]) {
        let part = &stats[stats_key];
        for entry in part[list]
            .as_array()
            .ok_or_else(|| format!("no `{list}`"))?
        {
            let location = &entry["sourceLocation"];
            let located = Location {
                file: location["file"].as_str().map(str::to_string),
                line: location["line"].as_str().map(str::to_string),
                function: location["function"].as_str().map(str::to_string),
            };
            steps += 1;
            *functions.entry(located.function_name()).or_insert(0) += 1;
            *lines.entry(located.file_line()).or_insert(0) += 1;
        }
        *total = part[count]
            .as_u64()
            .ok_or_else(|| format!("`{count}` is not a count: {}", part[count]))?;
    }
    Ok(ByteOps {
        extracts: totals[0],
        updates: totals[1],
        by_function: top(&functions, steps, TOP),
        by_file_line: top(&lines, steps, TOP),
    })
}

/// One property's verdict and the records it rests on.
#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct Verified {
    pub property: Property,
    pub verdict: Verdict,
    pub records: PathBuf,
    /// A failed property's trace, run again with `--trace`.
    pub trace: Option<PathBuf>,
}

/// The reachability checks, verified together.
#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct Reachability {
    pub records: PathBuf,
    pub verdicts: BTreeMap<String, Verdict>,
}

/// A diagnosis's summary, written whatever it reaches: every part it
/// completed.
#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct Summary {
    pub harness: String,
    pub artifact: PathBuf,
    pub artifact_sha256: String,
    pub solver: PathBuf,
    pub focus: Focus,
    pub inventory: Vec<Property>,
    pub verified: Vec<Verified>,
    pub reachability: Option<Reachability>,
    pub formula: Option<Formula>,
    pub byte_ops: Option<ByteOps>,
    /// Why the diagnosis ended before its last part.
    pub refused: Option<String>,
}

/// The directory of a new diagnosis of `harness` under `root`, numbered
/// from 1 and created exclusively: concurrent diagnoses never share one.
fn diagnosis_directory(root: &Path, harness: &str) -> Result<PathBuf, String> {
    std::fs::create_dir_all(root).map_err(|error| format!("{}: {error}", root.display()))?;
    let stem = harness.replace("::", ".");
    for number in 1u32.. {
        let directory = root.join(format!("{stem}.{number}"));
        match std::fs::create_dir(&directory) {
            Ok(()) => return Ok(directory),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(format!("{}: {error}", directory.display())),
        }
    }
    Err(format!("{}: no free diagnosis number", root.display()))
}

/// The run identity of the discovery whose evidence is `evidence`
/// (`run.json`, validated), refused unless its purpose is discovery. It is
/// the diagnosis's source identity: the source state that discovery
/// compiled (`tree_sha256`, the digest of its clean commit's copy), never a
/// digest of the directory a diagnosis runs in, which is the checkout and
/// holds its build output.
fn discovery_identity(evidence: &Path) -> Result<super::RunIdentity, String> {
    let path = evidence.join("run.json");
    let bytes = std::fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let identity =
        super::typed::<super::RunIdentityRecord>(super::strict_json(&bytes)?, "run.json")?
            .validate()?;
    if identity.purpose() != super::PURPOSE_DISCOVERY {
        return Err(format!(
            "{}: run {} has the purpose {}, not a discovery: only a discovery's evidence is diagnosed",
            path.display(),
            identity.id(),
            identity.purpose()
        ));
    }
    Ok(identity)
}

/// Diagnose `harness` (its source file `harness_file`, relative to the
/// package, as CBMC records it) from the discovery evidence `evidence`,
/// under `focus`, in a new directory under `root` ([`diagnosis_directory`]),
/// its steps run by `workload`: its identity, then the property inventory;
/// one verdict per harness and unwinding assertion, a failed one traced;
/// the reachability checks together; the formula's steps and byte
/// operations. `summary.json` is written once, when the diagnosis ends,
/// with every part it completed. Refused, after writing it with the reason
/// (`refused`), when a harness assertion failed or a step the summary rests
/// on did not succeed. The summary and the diagnosis's directory.
pub fn diagnose(
    workload: &crate::process::Workload,
    evidence: &Path,
    harness: &str,
    harness_file: &str,
    focus: Focus,
    root: &Path,
) -> Result<(Summary, PathBuf), String> {
    let discovery = discovery_identity(evidence)?;
    let recorded = recorded(evidence, harness)?;
    let out = diagnosis_directory(root, harness)?;
    let identity = serde_json::json!({
        "harness": harness,
        "evidence": evidence,
        "discovery": {
            "id": discovery.id(),
            "revision": discovery.revision(),
            "tree_sha256": discovery.record().tree_sha256,
            "loop_policy_sha256": discovery.record().loop_policy_sha256,
        },
        "artifact": {"path": recorded.artifact, "sha256": recorded.sha256},
        "solver": recorded.solver,
    });
    crate::process::record(
        &out.join("identity.json"),
        &serde_json::to_vec_pretty(&identity).map_err(|error| error.to_string())?,
    )?;
    let mut summary = Summary {
        harness: harness.to_string(),
        artifact: recorded.artifact.clone(),
        artifact_sha256: recorded.sha256.clone(),
        solver: recorded.solver.clone(),
        focus,
        inventory: Vec::new(),
        verified: Vec::new(),
        reachability: None,
        formula: None,
        byte_ops: None,
        refused: None,
    };
    let ended = parts(workload, &recorded, harness_file, &out, &mut summary);
    if let Err(fault) = &ended {
        summary.refused = Some(fault.clone());
    }
    crate::process::record(
        &out.join("summary.json"),
        &serde_json::to_vec_pretty(&summary).map_err(|error| error.to_string())?,
    )?;
    ended.map(|()| (summary, out))
}

/// The parts of a diagnosis ([`diagnose`]), each step of `recorded`'s run by
/// `workload` into `out`, every completed one in `summary`; refused at the
/// first that fails.
fn parts(
    workload: &crate::process::Workload,
    recorded: &Recorded,
    harness_file: &str,
    out: &Path,
    summary: &mut Summary,
) -> Result<(), String> {
    let run =
        |name: &str, extra: &[String]| step(workload, recorded, out, name, extra, STEP_SECONDS);
    let json_ui = "--json-ui".to_string();
    let shown = run(
        "properties",
        &["--show-properties".to_string(), json_ui.clone()],
    )?;
    succeeded(&shown, "properties")?;
    summary.inventory = properties(&json_stream(&shown.stdout())?, harness_file)?;
    let checked: Vec<Property> = summary
        .inventory
        .iter()
        .filter(|p| matches!(p.kind, Kind::Harness | Kind::Unwinding))
        .cloned()
        .collect();
    for (index, property) in checked.into_iter().enumerate() {
        let name = format!("verify-{index:04}");
        let property_flag = ["--property".to_string(), property.name.clone()];
        let ran = run(
            &name,
            &[property_flag.as_slice(), std::slice::from_ref(&json_ui)].concat(),
        )?;
        crate::process::record(&ran.directory.join("property"), property.name.as_bytes())?;
        let verdict = verdict(&ran, &property.name)?;
        let failed = verdict
            == (Verdict::Reported {
                status: Status::Failure,
            });
        let trace = if failed {
            let traced = run(
                &format!("{name}-trace"),
                &[
                    property_flag.as_slice(),
                    &["--trace".to_string(), json_ui.clone()],
                ]
                .concat(),
            )?;
            Some(traced.directory)
        } else {
            None
        };
        let harness_failed = failed && property.kind == Kind::Harness;
        let described = format!("{} ({})", property.name, property.description);
        summary.verified.push(Verified {
            property,
            verdict,
            records: ran.directory,
            trace,
        });
        if harness_failed {
            return Err(format!(
                "harness assertion {described} FAILED; its trace is in {}",
                out.display()
            ));
        }
    }
    let reachability: Vec<&Property> = summary
        .inventory
        .iter()
        .filter(|p| p.kind == Kind::Reachability)
        .collect();
    if !reachability.is_empty() {
        let mut extra: Vec<String> = reachability
            .iter()
            .flat_map(|p| ["--property".to_string(), p.name.clone()])
            .collect();
        extra.push(json_ui.clone());
        let ran = run("reachability", &extra)?;
        let verdicts = reachability
            .iter()
            .map(|p| Ok((p.name.clone(), verdict(&ran, &p.name)?)))
            .collect::<Result<_, String>>()?;
        summary.reachability = Some(Reachability {
            records: ran.directory,
            verdicts,
        });
    }
    let program = run("program", &["--program-only".to_string()])?;
    succeeded(&program, "program")?;
    let formula = formula(&program.stdout(), &summary.focus)?;
    if formula.steps == 0 {
        return Err(format!(
            "program: no kept step in {}",
            program.directory.display()
        ));
    }
    summary.formula = Some(formula);
    let bytes = run("byte-ops", &["--show-byte-ops".to_string(), json_ui])?;
    succeeded(&bytes, "byte-ops")?;
    summary.byte_ops = Some(byte_ops(&json_stream(&bytes.stdout())?)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HARNESS_FILE: &str = "src/bounded/policy/proofs.rs";

    fn elements(text: &str) -> Vec<serde_json::Value> {
        match super::super::strict_json(text.as_bytes()).unwrap() {
            serde_json::Value::Array(elements) => elements,
            other => panic!("not an array: {other}"),
        }
    }

    #[test]
    fn properties_are_classified_by_class_and_file_components() {
        let output = elements(
            r#"[{"program": "CBMC 6.11.0"},
            {"properties": [
              {"name": "h.assertion.1", "class": "assertion", "description": "A = C + F + H",
               "sourceLocation": {"file": "src/bounded/policy/proofs.rs", "line": "377",
                                  "function": "h"}},
              {"name": "x.assertion.1", "class": "assertion", "description": "a suffix only",
               "sourceLocation": {"file": "src/bounded/policy/notproofs.rs", "line": "1"}},
              {"name": "h.reach.1", "class": "reachability_check", "description": "r",
               "sourceLocation": {"file": "src/bounded/policy/proofs.rs", "line": "377"}},
              {"name": "f.unwind.0", "class": "unwind", "description": "unwinding assertion loop 0",
               "sourceLocation": {"file": "src/bounded/policy.rs", "line": "290"}},
              {"name": "f.overflow.1", "class": "arithmetic_overflow", "description": "o",
               "sourceLocation": {"file": "src/bounded/policy.rs"}}
            ]}]"#,
        );
        let kinds: Vec<(String, Kind)> = properties(&output, HARNESS_FILE)
            .unwrap()
            .into_iter()
            .map(|p| (p.name, p.kind))
            .collect();
        assert_eq!(
            kinds,
            [
                ("h.assertion.1".to_string(), Kind::Harness),
                ("x.assertion.1".to_string(), Kind::Other),
                ("h.reach.1".to_string(), Kind::Reachability),
                ("f.unwind.0".to_string(), Kind::Unwinding),
                ("f.overflow.1".to_string(), Kind::Other),
            ]
        );
        let refused = properties(&elements(r#"[{"program": "CBMC"}]"#), HARNESS_FILE).unwrap_err();
        assert!(refused.contains("no `properties`"), "{refused}");
    }

    #[test]
    fn a_status_is_read_from_the_result_stream_and_refused_when_unknown() {
        let output = elements(
            r#"[{"program": "CBMC"}, {"messageText": "m", "messageType": "STATUS-MESSAGE"},
            {"result": [{"property": "p.1", "status": "SUCCESS"},
                        {"property": "p.2", "status": "NOT CHECKED"},
                        {"property": "p.3", "status": "MAYBE"}]},
            {"cProverStatus": "failure"}]"#,
        );
        assert_eq!(status(&output, "p.1"), Ok(Some(Status::Success)));
        assert_eq!(status(&output, "p.2"), Ok(Some(Status::NotChecked)));
        assert!(status(&output, "p.3").unwrap_err().contains("MAYBE"));
        assert_eq!(status(&output, "p.4"), Ok(None));
    }

    #[test]
    fn a_byte_ops_object_inside_the_stream_is_read_strictly() {
        let output = elements(
            "[{\"program\": \"CBMC\"}\n,\n{\"byteOpsStats\": {\"byteExtractStats\": \
             {\"byteExtractList\": [{\"sourceLocation\": {\"file\": \"a.rs\", \"line\": \"1\", \
             \"function\": \"f\"}}], \"numOfExtracts\": 1}, \"byteUpdateStats\": \
             {\"byteUpdateList\": [], \"numOfUpdates\": 0}}}\n]",
        );
        let found = byte_ops(&output).unwrap();
        assert_eq!((found.extracts, found.updates), (1, 0));
        assert_eq!(found.by_function[0].key, "f");
        let text = elements(
            r#"[{"byteOpsStats": {"byteExtractStats": {"byteExtractList": [], "numOfExtracts": "2"},
                "byteUpdateStats": {"byteUpdateList": [], "numOfUpdates": 0}}}]"#,
        );
        assert!(byte_ops(&text).unwrap_err().contains("not a count"));
        assert!(super::super::strict_json(b"[{\"a\": 1} {\"b\": 2}]").is_err());
    }

    #[test]
    fn a_location_is_parsed_as_cbmc_renders_it() {
        let located = Location::parse("file src/a b.rs line 3 column 9 function <a as b>::c d");
        assert_eq!(located.file.as_deref(), Some("src/a b.rs"));
        assert_eq!(located.file_line(), "src/a b.rs:3");
        assert_eq!(located.function_name(), "<a as b>::c d");
        let java = Location::parse("function f bytecode-index 7");
        assert_eq!(java.function_name(), "f");
        assert_eq!(Location::parse("").file_line(), "?:?");
    }

    #[test]
    fn a_formula_streams_kept_steps_into_its_focus() {
        let directory = tempdir("formula");
        let path = directory.join("stdout");
        std::fs::write(
            &path,
            "\nProgram constraints:\n\
// 1 file src/bounded/policy/proofs.rs line 321 column 9 function h\n\
(1) x#1 == 2\n\
// 2 file core/memchr.rs line 1 function core::slice::memchr::memchr_naive\n\
(2) a\n\
(3) b\n\
// 3 file src/bounded/policy.rs line 290 function f\n\
(sliced) y#1 == 3\n\
// 4 file src/bounded/policy/proofs.rs line 349 function h\n\
(4) z\n\
       guard: g\n\
// 5 file core/memchr.rs line 1 function core::slice::memchr::memchr_naive\n\
(5) c\n",
        )
        .unwrap();
        let focus = Focus::parse(&[
            "--site",
            "src/bounded/policy/proofs.rs:321",
            "--function",
            "memchr",
            "--callers",
            "memchr_naive",
        ])
        .unwrap();
        let found = formula(&path, &focus).unwrap();
        assert_eq!(found.steps, 5);
        assert_eq!(
            found.by_function[0].key,
            "core::slice::memchr::memchr_naive"
        );
        assert_eq!(found.by_function[0].count, 3);
        assert_eq!(found.sites[0].steps, 1);
        assert_eq!(found.sites[1].steps, 3);
        assert_eq!(
            found.callers,
            [Entry {
                key: "h".into(),
                count: 2,
                share: 1.0
            }]
        );
        std::fs::write(&path, b"// 1 file \xff line 1\n(1) x\n").unwrap();
        assert!(
            formula(&path, &Focus::default())
                .unwrap_err()
                .contains("not UTF-8")
        );
        std::fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn a_focus_is_parsed_or_refused() {
        assert!(
            Focus::parse(&["--site", "a.rs"])
                .unwrap_err()
                .contains("FILE:LINE")
        );
        assert!(
            Focus::parse(&["--site"])
                .unwrap_err()
                .contains("needs a value")
        );
        assert!(
            Focus::parse(&["--callers", "a", "--callers", "b"])
                .unwrap_err()
                .contains("once")
        );
        assert!(
            Focus::parse(&["--other", "x"])
                .unwrap_err()
                .contains("unknown")
        );
    }

    /// A directory of its own under the system's temporary directory,
    /// removed first if a failed run left it.
    fn tempdir(name: &str) -> PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "dcbor-gate-diagnostics-{name}-{}",
            std::process::id()
        ));
        if directory.exists() {
            std::fs::remove_dir_all(&directory).unwrap();
        }
        std::fs::create_dir_all(&directory).unwrap();
        directory
    }

    /// Discovery evidence of harness `h` whose solver is `solver`, and its
    /// artifact.
    fn discovery_evidence(directory: &Path, solver: &Path) -> PathBuf {
        let evidence = directory.join("kani.evidence");
        let at = evidence.join("loop-bounds").join("a.h");
        std::fs::create_dir_all(&at).unwrap();
        let artifact = directory.join("artifact.out");
        std::fs::write(&artifact, b"goto binary").unwrap();
        let solver = solver.to_str().unwrap();
        std::fs::write(
            at.join("solver.identity"),
            serde_json::to_vec(&serde_json::json!({"solver": {"path": solver}})).unwrap(),
        )
        .unwrap();
        let mut command = Vec::new();
        for part in [solver, artifact.to_str().unwrap(), "--json-ui"] {
            command.extend_from_slice(part.as_bytes());
            command.push(0);
        }
        std::fs::write(at.join("solver.arguments"), command).unwrap();
        std::fs::write(
            at.join("artifact.json"),
            serde_json::to_vec(&serde_json::json!({
                "path": artifact,
                "sha256": crate::process::sha256(&artifact).unwrap(),
            }))
            .unwrap(),
        )
        .unwrap();
        write_identity(&evidence, super::super::PURPOSE_DISCOVERY);
        evidence
    }

    /// The source state the fixture's discovery records.
    const TREE: &str = "94c31505a3d7504ce18ed571b0a586c32a8d6ec372e8e5851e88e659fdf24a60";
    /// The fixture's discovery run identifier.
    const RUN: &str = "409e62f1-83d8-4144-b9d7-ae6c629ccc91";

    /// `evidence`'s run identity (`run.json`), of `purpose`.
    fn write_identity(evidence: &Path, purpose: &str) {
        let identity = super::super::RunIdentityRecord {
            version: super::super::RUNTIME_VERSION,
            id: RUN.to_string(),
            purpose: purpose.to_string(),
            revision: "c303ce7502584427108246cd599a2f656e9ffe8b406e325f2c7359264e03bb08"
                .to_string(),
            tree_sha256: TREE.to_string(),
            build: "kani --package dcbor --lib".to_string(),
            loop_policy_sha256: "61408177d0a9de25f6bff09f7dc50e206240678227213a593bd4a5d966cd35d8"
                .to_string(),
            started: super::super::Instant {
                seconds: 1,
                nanoseconds: 0,
            },
        };
        std::fs::write(
            evidence.join("run.json"),
            serde_json::to_vec(&identity).unwrap(),
        )
        .unwrap();
    }

    /// A diagnosis's identity is the discovery's: its run and the source
    /// state it compiled, read from its validated `run.json`, never a digest
    /// of the directory the diagnosis runs in (the checkout, its build output
    /// included); evidence of any other purpose is refused before anything
    /// runs.
    #[test]
    fn a_diagnosis_is_bound_to_its_discovery_run() {
        let directory = tempdir("bound");
        let evidence = discovery_evidence(&directory, &solver(&directory, 0));
        let root = directory.join("kani.diagnostics");
        let (_, out) = diagnose(
            &unconfined(),
            &evidence,
            "a::h",
            "src/h.rs",
            Focus::default(),
            &root,
        )
        .unwrap();
        let identity: serde_json::Value =
            serde_json::from_slice(&std::fs::read(out.join("identity.json")).unwrap()).unwrap();
        assert_eq!(identity["discovery"]["id"], RUN);
        assert_eq!(identity["discovery"]["tree_sha256"], TREE);
        write_identity(&evidence, super::super::PURPOSE_CALIBRATION);
        let refused = diagnose(
            &unconfined(),
            &evidence,
            "a::h",
            "src/h.rs",
            Focus::default(),
            &root,
        )
        .err()
        .unwrap();
        assert!(refused.contains("not a discovery"), "{refused}");
        assert!(!root.join("a.h.2").exists());
        std::fs::remove_dir_all(&directory).unwrap();
    }

    /// A stand-in solver answering each step's flags as CBMC 6.11.0 would,
    /// exiting `verify` for a verification.
    fn solver(directory: &Path, verify: i32) -> PathBuf {
        let path = directory.join("cbmc");
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\n\
case \"$*\" in\n\
*--show-properties*) echo '[{{\"properties\": [{{\"name\": \"h.assertion.1\", \"class\": \"assertion\", \"description\": \"d\", \"sourceLocation\": {{\"file\": \"src/h.rs\"}}}}]}}]' ;;\n\
*--program-only*) printf '// 1 file src/h.rs line 1 function h\\n(1) x\\n' ;;\n\
*--show-byte-ops*) echo '[{{\"byteOpsStats\": {{\"byteExtractStats\": {{\"byteExtractList\": [], \"numOfExtracts\": 0}}, \"byteUpdateStats\": {{\"byteUpdateList\": [], \"numOfUpdates\": 0}}}}}}]' ;;\n\
*--property*) echo '[{{\"result\": [{{\"property\": \"h.assertion.1\", \"status\": \"SUCCESS\"}}]}}]'; exit {verify} ;;\n\
esac\n"
            ),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    /// The launcher that runs its command as it is: this module's tests
    /// exercise the diagnosis, not the confinement (tests/workload.sh).
    fn unconfined() -> crate::process::Workload {
        crate::process::Workload::at("env")
    }

    /// Evidence whose artifact's bytes changed after it was recorded is
    /// refused before anything runs.
    #[test]
    fn evidence_of_another_artifact_is_refused() {
        let directory = tempdir("recorded");
        let evidence = discovery_evidence(&directory, &solver(&directory, 0));
        assert!(recorded(&evidence, "a::h").is_ok());
        std::fs::write(directory.join("artifact.out"), b"changed").unwrap();
        assert!(
            recorded(&evidence, "a::h")
                .unwrap_err()
                .contains("its bytes have digest")
        );
        std::fs::remove_dir_all(&directory).unwrap();
    }

    /// A step records its command, its status and its output in a
    /// directory of its own, refused when the directory exists.
    #[test]
    fn a_step_records_its_command_status_and_output() {
        let directory = tempdir("step");
        let evidence = discovery_evidence(&directory, &solver(&directory, 0));
        let recorded = recorded(&evidence, "a::h").unwrap();
        let ran = step(
            &unconfined(),
            &recorded,
            &directory,
            "s",
            &["--program-only".into()],
            60,
        )
        .unwrap();
        assert_eq!(ran.ended, Ended::Exited { code: 0 });
        assert_eq!(
            std::fs::read_to_string(ran.directory.join("status")).unwrap(),
            "exit status: 0\n"
        );
        assert!(
            std::fs::read(ran.directory.join("command"))
                .unwrap()
                .ends_with(b"--program-only\0")
        );
        assert!(
            std::fs::read_to_string(ran.stdout())
                .unwrap()
                .contains("(1) x")
        );
        assert!(step(&unconfined(), &recorded, &directory, "s", &[], 60).is_err());
        std::fs::remove_dir_all(&directory).unwrap();
    }

    /// A whole diagnosis in a numbered directory of its own, a second one
    /// beside it; and a verification that exits as no verification does is
    /// no verdict. Planted control (`gate-diagnosis-exit-unchecked`): take
    /// a verification's status whatever its exit code.
    #[test]
    fn a_diagnosis_is_its_own_and_takes_only_a_verifications_status() {
        let directory = tempdir("diagnose");
        let evidence = discovery_evidence(&directory, &solver(&directory, 0));
        let root = directory.join("kani.diagnostics");
        let (summary, first) = diagnose(
            &unconfined(),
            &evidence,
            "a::h",
            "src/h.rs",
            Focus::default(),
            &root,
        )
        .unwrap();
        assert_eq!(first, root.join("a.h.1"));
        assert_eq!(
            summary.verified[0].verdict,
            Verdict::Reported {
                status: Status::Success
            }
        );
        assert_eq!(summary.formula.as_ref().unwrap().steps, 1);
        assert!(first.join("summary.json").exists() && first.join("identity.json").exists());
        let (_, second) = diagnose(
            &unconfined(),
            &evidence,
            "a::h",
            "src/h.rs",
            Focus::default(),
            &root,
        )
        .unwrap();
        assert_eq!(second, root.join("a.h.2"));
        let failing = directory.join("failing");
        std::fs::create_dir(&failing).unwrap();
        let broken = discovery_evidence(&failing, &solver(&failing, 6));
        let (summary, _) = diagnose(
            &unconfined(),
            &broken,
            "a::h",
            "src/h.rs",
            Focus::default(),
            &root,
        )
        .unwrap();
        assert_eq!(
            summary.verified[0].verdict,
            Verdict::Unreported {
                ended: Ended::Exited { code: 6 }
            },
            "exit-code-unchecked: a verification that exited 6 was taken for its status"
        );
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
