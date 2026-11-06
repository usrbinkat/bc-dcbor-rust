//! The reach map's records (`tests/reach-map.sh`): which test of the Miri
//! gate's selection executes which code of this crate's `src/`, read from
//! LLVM's coverage export, and the map's verdict.
//!
//! `llvm-cov export -format=text` writes `llvm.coverage.json.export`: each
//! instrumented function with its file names and its regions, `[line_start,
//! col_start, line_end, col_end, count, file_id, expanded_file_id, kind]`,
//! where kind 0 is a code region (1 an expansion, 2 skipped, 3 a gap, 4 a
//! branch). Only this crate's `src/` is kept: a mutant lies there.
//!
//! The map fails when a function of a tainted module (`dcbor_census`)
//! outside test code is reached by no test Miri runs, when a test at
//! minimal witness sizes leaves unexecuted a region its full-size run
//! executes, or when it reaches other boundary predicate valuations than its
//! full-size run does (`inventory::witness_loss`, read from each run's log,
//! spec P3). Test code, a module the census finds compiled only under
//! `cfg(test)` or such an item of a shipped module, is never mutated, so it
//! is no trust boundary and need not be reached.

use std::collections::BTreeMap;
use std::path::{Component, Path};

use dcbor_census::{CensusCfg, CensusModule};
use serde::{Deserialize, Serialize};

/// A code region: its start and end, each a line and a column.
pub type Region = [usize; 4];

/// The code regions executed, by file under `src/`, sorted and distinct.
pub type Regions = BTreeMap<String, Vec<Region>>;

/// An instrumented function and the span of its code regions in its file.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Function {
    pub name: String,
    pub file: String,
    pub start: [usize; 2],
    pub end: [usize; 2],
}

/// One selection line of the map: its domain and kind, its tests, and the
/// regions each executed at minimal witness sizes, in the tests' order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Suite {
    pub domain: String,
    pub kind: String,
    pub tests: Vec<String>,
    pub reach: Vec<Regions>,
}

/// A function of a tainted module no test reaches, with its module.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unreached {
    pub function: Function,
    pub module: String,
}

/// The regions a test's full-size run executed and its minimal run did not.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Loss {
    pub suite: String,
    pub test: String,
    pub regions: Regions,
}

/// The boundary valuations a test's minimal run lacks of its full-size
/// run's, each `-`, or reaches beyond them, each `+`
/// (`inventory::witness_loss`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValuationLoss {
    pub suite: String,
    pub test: String,
    pub valuations: Vec<String>,
}

/// The map: `reach.json`, written by [`index`] and read by the mutation
/// campaign's Miri plan (`mutation::miri_plan`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReachMap {
    pub identity: String,
    pub suites: BTreeMap<String, Suite>,
    pub unreached_functions: Vec<Unreached>,
    pub witness_loss: Vec<Loss>,
    pub valuation_loss: Vec<ValuationLoss>,
}

const CODE: u64 = 0;

/// The package whose features the gates select.
const PACKAGE: &str = "dcbor";

#[derive(Deserialize)]
struct Export {
    #[serde(rename = "type")]
    kind: String,
    data: Vec<Unit>,
}

#[derive(Deserialize)]
struct Unit {
    functions: Vec<Exported>,
}

#[derive(Deserialize)]
struct Exported {
    name: String,
    filenames: Vec<String>,
    regions: Vec<[u64; 8]>,
}

fn read(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))
}

fn json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    serde_json::from_str(&read(path)?).map_err(|error| format!("{}: {error}", path.display()))
}

fn index_of(value: u64, what: &str) -> Result<usize, String> {
    usize::try_from(value).map_err(|_| format!("{what} {value} does not fit"))
}

/// The one test executable a `cargo test --no-run --message-format=json`
/// build reported in `messages`.
pub fn executable(messages: &str) -> Result<String, String> {
    let mut found = Vec::new();
    for line in messages
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with('{'))
    {
        let message: serde_json::Value =
            serde_json::from_str(line).map_err(|error| format!("a build message: {error}"))?;
        let artifact =
            message.get("reason").and_then(|reason| reason.as_str()) == Some("compiler-artifact");
        let test = message
            .get("profile")
            .and_then(|profile| profile.get("test"))
            .and_then(serde_json::Value::as_bool)
            == Some(true);
        if let (true, true, Some(executable)) = (
            artifact,
            test,
            message
                .get("executable")
                .and_then(|executable| executable.as_str()),
        ) {
            found.push(executable.to_string());
        }
    }
    match found.as_slice() {
        [one] => Ok(one.clone()),
        other => Err(format!("expected one test executable, found {other:?}")),
    }
}

/// `filename` relative to `root` when it lies under `root/src`.
fn relative(root: &Path, filename: &str) -> Option<String> {
    let shown = Path::new(filename).strip_prefix(root).ok()?;
    match shown.components().next() {
        Some(Component::Normal(first)) if first == "src" => Some(shown.to_str()?.to_string()),
        _ => None,
    }
}

fn exported(export: &str) -> Result<Vec<Exported>, String> {
    let export: Export =
        serde_json::from_str(export).map_err(|error| format!("not an llvm-cov export: {error}"))?;
    if export.kind != "llvm.coverage.json.export" {
        return Err(format!("not an llvm-cov export: {:?}", export.kind));
    }
    Ok(export
        .data
        .into_iter()
        .flat_map(|unit| unit.functions)
        .collect())
}

fn region(raw: &[u64; 8]) -> Result<Region, String> {
    Ok([
        index_of(raw[0], "a line")?,
        index_of(raw[1], "a column")?,
        index_of(raw[2], "a line")?,
        index_of(raw[3], "a column")?,
    ])
}

/// The code regions `export` records executed, by file under `root/src`.
pub fn regions(root: &Path, export: &str) -> Result<Regions, String> {
    let mut executed: BTreeMap<String, std::collections::BTreeSet<Region>> = BTreeMap::new();
    for function in exported(export)? {
        for raw in &function.regions {
            if raw[7] != CODE || raw[4] == 0 {
                continue;
            }
            let file = function
                .filenames
                .get(index_of(raw[5], "a file index")?)
                .ok_or_else(|| format!("{}: a region of no file", function.name))?;
            if let Some(shown) = relative(root, file) {
                executed.entry(shown).or_default().insert(region(raw)?);
            }
        }
    }
    Ok(executed
        .into_iter()
        .map(|(file, spans)| (file, spans.into_iter().collect()))
        .collect())
}

/// Every instrumented function `export` records under `root/src`: its name,
/// its file, and the span of its code regions there.
pub fn functions(root: &Path, export: &str) -> Result<Vec<Function>, String> {
    let mut found = std::collections::BTreeSet::new();
    for function in exported(export)? {
        let code: Vec<&[u64; 8]> = function
            .regions
            .iter()
            .filter(|raw| raw[7] == CODE)
            .collect();
        let Some(first) = code.first() else {
            continue;
        };
        let file = function
            .filenames
            .get(index_of(first[5], "a file index")?)
            .ok_or_else(|| format!("{}: a region of no file", function.name))?;
        let Some(shown) = relative(root, file) else {
            continue;
        };
        let own: Vec<Region> = code
            .iter()
            .filter(|raw| raw[5] == first[5])
            .map(|raw| region(raw))
            .collect::<Result<_, _>>()?;
        let start = own.iter().map(|region| [region[0], region[1]]).min();
        let end = own.iter().map(|region| [region[2], region[3]]).max();
        if let (Some(start), Some(end)) = (start, end) {
            found.insert(Function {
                name: function.name.clone(),
                file: shown,
                start,
                end,
            });
        }
    }
    Ok(found.into_iter().collect())
}

/// Whether `region` overlaps the span `start..=end`.
pub fn overlaps(region: &Region, start: [usize; 2], end: [usize; 2]) -> bool {
    [region[0], region[1]] <= end && start <= [region[2], region[3]]
}

/// The regions `full` holds and `minimal` does not, by file.
pub fn lost(minimal: &Regions, full: &Regions) -> Regions {
    full.iter()
        .filter_map(|(file, spans)| {
            let kept = minimal.get(file);
            let dropped: Vec<Region> = spans
                .iter()
                .filter(|span| !kept.is_some_and(|kept| kept.contains(span)))
                .copied()
                .collect();
            (!dropped.is_empty()).then(|| (file.clone(), dropped))
        })
        .collect()
}

/// The census the map's run wrote (`out/census.txt`), recorded under
/// `configuration`: its modules and its cfg predicates.
pub fn census(
    out: &Path,
    configuration: &str,
) -> Result<(Vec<CensusModule>, Vec<CensusCfg>), String> {
    let path = out.join("census.txt");
    let (recorded, modules, cfgs) = dcbor_census::parse(&read(&path)?)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    if recorded != configuration {
        return Err(format!(
            "{}: recorded under another configuration: {recorded}",
            path.display()
        ));
    }
    Ok((modules, cfgs))
}

/// The inventory of test `at` of suite `base`'s run at witness `sizes`, read
/// from its log (`out/raw/<base>/<sizes>/<at>.log`, tests/reach-map.sh).
fn logged(
    out: &Path,
    base: &str,
    sizes: &str,
    at: usize,
) -> Result<crate::inventory::Inventory, String> {
    let path = out
        .join("raw")
        .join(base)
        .join(sizes)
        .join(format!("{at}.log"));
    crate::inventory::of(&read(&path)?).map_err(|fault| format!("{}: {fault}", path.display()))
}

/// The map of the run whose records are under `out`, for the selection
/// lines `bases`, written to `out/reach.json`, and its faults: each function
/// of a tainted module, outside test code, that no test reaches, each
/// region a test's minimal witness drops, each boundary valuation its
/// minimal witness reaches differently from its full one, and each `cfg`
/// predicate of the census no gated build compiles, under the crate's
/// `cfg_exemptions` (`cfgs::faults`; the repository's are
/// `cfgs::EXEMPTIONS`).
pub fn index(
    out: &Path,
    bases: &[&str],
    configuration: &str,
    cfg_exemptions: &[(&str, &str, &str)],
) -> Result<(ReachMap, Vec<String>), String> {
    let (census, cfgs) = census(out, configuration)?;
    // Every predicate the census found holds in some build the gates make
    // (G11), the builds' features as `cargo metadata` resolved them
    // (`out/metadata.json`, tests/reach-map.sh).
    let table = crate::cfgs::feature_table(&read(&out.join("metadata.json"))?, PACKAGE)?;
    let cfg_faults = crate::cfgs::faults(&cfgs, &crate::cfgs::builds(&table)?, cfg_exemptions);
    let mut suites = BTreeMap::new();
    let mut reached_by: BTreeMap<String, Vec<Region>> = BTreeMap::new();
    let mut instrumented = std::collections::BTreeSet::new();
    let mut witness_loss = Vec::new();
    let mut valuation_loss = Vec::new();
    for &base in bases {
        let tests: Vec<String> = read(&out.join(format!("{base}.tests")))?
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(str::to_string)
            .collect();
        let mut reach = Vec::new();
        for (at, test) in tests.iter().enumerate() {
            let minimal: Regions = json(&out.join("reach").join(base).join(format!("{at}.json")))?;
            let full: Regions =
                json(&out.join("reach-full").join(base).join(format!("{at}.json")))?;
            let missing = lost(&minimal, &full);
            if !missing.is_empty() {
                witness_loss.push(Loss {
                    suite: base.to_string(),
                    test: test.clone(),
                    regions: missing,
                });
            }
            let valuations = crate::inventory::witness_loss(
                &logged(out, base, "minimal", at)?,
                &logged(out, base, "full", at)?,
            )?;
            if !valuations.is_empty() {
                valuation_loss.push(ValuationLoss {
                    suite: base.to_string(),
                    test: test.clone(),
                    valuations,
                });
            }
            for (file, spans) in &minimal {
                reached_by.entry(file.clone()).or_default().extend(spans);
            }
            reach.push(minimal);
        }
        let functions: Vec<Function> = json(&out.join("functions").join(format!("{base}.json")))?;
        instrumented.extend(functions);
        suites.insert(
            base.to_string(),
            Suite {
                domain: read(&out.join(format!("{base}.domain")))?
                    .trim()
                    .to_string(),
                kind: read(&out.join(format!("{base}.kind")))?.trim().to_string(),
                tests,
                reach,
            },
        );
    }
    let mut unreached = Vec::new();
    for function in instrumented {
        let module = dcbor_census::module_of(&census, &function.file, function.start[0])
            .ok_or_else(|| {
                format!(
                    "{}:{} lies in no module of the census",
                    function.file, function.start[0]
                )
            })?;
        if !module.tainted || module.test || module.holds_test_item(function.start[0]) {
            continue;
        }
        let reached = reached_by.get(&function.file).is_some_and(|regions| {
            regions
                .iter()
                .any(|region| overlaps(region, function.start, function.end))
        });
        if !reached {
            unreached.push(Unreached {
                module: module.module.clone(),
                function,
            });
        }
    }
    unreached.sort_by(|left, right| {
        (&left.function.file, left.function.start)
            .cmp(&(&right.function.file, right.function.start))
    });
    let map = ReachMap {
        identity: read(&out.join("identity.txt"))?.trim().to_string(),
        suites,
        unreached_functions: unreached,
        witness_loss,
        valuation_loss,
    };
    let path = out.join("reach.json");
    let data = serde_json::to_string(&map).map_err(|error| format!("the reach map: {error}"))?;
    dcbor_record::publish(
        path.to_str().ok_or("the reach map's path is not UTF-8")?,
        &format!("{data}\n"),
    );
    let mut faults: Vec<String> = map
        .unreached_functions
        .iter()
        .map(|unreached| {
            format!(
                "unreached under Miri: {}:{} {} ({})",
                unreached.function.file,
                unreached.function.start[0],
                unreached.function.name,
                unreached.module
            )
        })
        .collect();
    for loss in &map.witness_loss {
        for (file, spans) in &loss.regions {
            for [line_start, col_start, line_end, col_end] in spans {
                faults.push(format!(
                    "minimal witness drops a path: {} {}: {file}:{line_start}:{col_start}-{line_end}:{col_end}",
                    loss.suite, loss.test
                ));
            }
        }
    }
    for loss in &map.valuation_loss {
        for valuation in &loss.valuations {
            faults.push(format!(
                "minimal witness reaches another boundary valuation: {} {}: {valuation}",
                loss.suite, loss.test
            ));
        }
    }
    faults.extend(cfg_faults);
    Ok((map, faults))
}

/// The map at `out/reach.json`.
pub fn load(out: &Path) -> Result<ReachMap, String> {
    json(&out.join("reach.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = "src/storage.rs";
    const BASE: &str = "all-features-owned_input";
    const TEST: &str = "acquisition";
    /// `cargo metadata` of the package, its feature table only.
    const METADATA: &str = r#"{"packages": [{"name": "dcbor", "features": {
        "default": ["std"], "std": ["thiserror/std"], "no_std": ["hashbrown", "thiserror"],
        "num-bigint": ["dep:num-bigint"], "custom-std-collections": ["std"],
        "derive": ["dep:dcbor-derive"], "multithreaded": [], "hashbrown": ["dep:hashbrown"],
        "thiserror": ["dep:thiserror"]}}]}"#;
    /// A test's log reporting two boundary valuations.
    const REACHED: &str = "running 1 test\n\
        DCBOR_REACHED\t\"m\"\tquantum\tat\n\
        DCBOR_REACHED\t\"m\"\tquantum\tpast\n\
        test acquisition ... ok\n";

    fn module(name: &str, start: usize, end: usize, tainted: bool) -> CensusModule {
        CensusModule {
            file: FILE.to_string(),
            module: name.to_string(),
            start,
            end,
            holds_unsafe: tainted,
            tainted,
            test: false,
            test_items: Vec::new(),
        }
    }

    /// The crate root, holding no `unsafe`, around every fixture's module.
    fn root() -> CensusModule {
        module("crate", 1, 200, false)
    }

    /// A test's executed regions: one on each of `lines` of FILE.
    fn regions_on(lines: &[usize]) -> Regions {
        BTreeMap::from([(
            FILE.to_string(),
            lines.iter().map(|&line| [line, 1, line, 40]).collect(),
        )])
    }

    struct Out(std::path::PathBuf);

    impl Out {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("dcbor-gate-reach-{name}-{}", std::process::id()));
            if path.exists() {
                std::fs::remove_dir_all(&path).unwrap();
            }
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn write(&self, relative: &str, text: &str) {
            let path = self.0.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }

        /// The index over one suite of one test whose minimal and full runs
        /// executed `minimal` and `full`, both reaching the same boundary
        /// valuations, its function `grow` at lines 12-14, its census
        /// `census`.
        fn index(
            &self,
            census: &[CensusModule],
            minimal: &Regions,
            full: &Regions,
        ) -> Result<(ReachMap, Vec<String>), String> {
            self.logged(census, minimal, full, REACHED, REACHED)
        }

        /// [`Self::index`], the minimal run's log `minimal_log` and the full
        /// run's `full_log`.
        fn logged(
            &self,
            census: &[CensusModule],
            minimal: &Regions,
            full: &Regions,
            minimal_log: &str,
            full_log: &str,
        ) -> Result<(ReachMap, Vec<String>), String> {
            self.indexed(census, &[], minimal, full, (minimal_log, full_log))
        }

        /// [`Self::logged`] over a census holding `cfgs`, a crate of no
        /// `cfg` exemption.
        fn indexed(
            &self,
            census: &[CensusModule],
            cfgs: &[CensusCfg],
            minimal: &Regions,
            full: &Regions,
            (minimal_log, full_log): (&str, &str),
        ) -> Result<(ReachMap, Vec<String>), String> {
            self.write(&format!("raw/{BASE}/minimal/0.log"), minimal_log);
            self.write(&format!("raw/{BASE}/full/0.log"), full_log);
            self.write("census.txt", &dcbor_census::render("this", census, cfgs));
            self.write("metadata.json", METADATA);
            self.write("identity.txt", "reach-identity\n");
            self.write(&format!("{BASE}.tests"), &format!("{TEST}\n"));
            self.write(&format!("{BASE}.domain"), "all-features\n");
            self.write(&format!("{BASE}.kind"), "test\n");
            self.write(
                &format!("reach/{BASE}/0.json"),
                &serde_json::to_string(minimal).unwrap(),
            );
            self.write(
                &format!("reach-full/{BASE}/0.json"),
                &serde_json::to_string(full).unwrap(),
            );
            let grow = [Function {
                name: "grow".to_string(),
                file: FILE.to_string(),
                start: [12, 5],
                end: [14, 6],
            }];
            self.write(
                &format!("functions/{BASE}.json"),
                &serde_json::to_string(&grow).unwrap(),
            );
            index(&self.0, &[BASE], "this", &[])
        }
    }

    impl Drop for Out {
        fn drop(&mut self) {
            if !std::thread::panicking() {
                std::fs::remove_dir_all(&self.0).unwrap();
            }
        }
    }

    #[test]
    fn a_reached_function_passes_and_the_map_reads_back() {
        let out = Out::new("reached");
        let (map, faults) = out
            .index(
                &[root(), module("crate::storage", 10, 20, true)],
                &regions_on(&[13]),
                &regions_on(&[13]),
            )
            .unwrap();
        assert_eq!(faults, Vec::<String>::new());
        assert_eq!(map.unreached_functions, Vec::new());
        assert_eq!(map.witness_loss, Vec::new());
        assert_eq!(map.valuation_loss, Vec::new());
        assert_eq!(load(&out.0).unwrap(), map);
        assert_eq!(map.suites[BASE].tests, vec![TEST.to_string()]);
    }

    #[test]
    fn a_tainted_function_no_test_reaches_fails() {
        let out = Out::new("unreached");
        let (map, faults) = out
            .index(
                &[root(), module("crate::storage", 10, 20, true)],
                &regions_on(&[30]),
                &regions_on(&[30]),
            )
            .unwrap();
        assert_eq!(
            map.unreached_functions
                .iter()
                .map(|unreached| (unreached.function.name.as_str(), unreached.module.as_str()))
                .collect::<Vec<_>>(),
            vec![("grow", "crate::storage")]
        );
        assert_eq!(
            faults,
            vec!["unreached under Miri: src/storage.rs:12 grow (crate::storage)".to_string()]
        );
    }

    #[test]
    fn test_code_and_untainted_code_need_not_be_reached() {
        let out = Out::new("test-code");
        let mut test = module("crate::storage", 10, 20, true);
        test.test = true;
        assert_eq!(
            out.index(&[root(), test], &regions_on(&[30]), &regions_on(&[30]))
                .unwrap()
                .1,
            Vec::<String>::new()
        );
        let untainted = module("crate::storage", 10, 20, false);
        assert_eq!(
            out.index(&[root(), untainted], &regions_on(&[30]), &regions_on(&[30]))
                .unwrap()
                .1,
            Vec::<String>::new()
        );
    }

    /// The function, at lines 12-14, inside a test-only item of a tainted,
    /// shipped module need not be reached; outside one, it must be.
    #[test]
    fn a_test_item_of_a_shipped_module_need_not_be_reached() {
        let out = Out::new("test-item");
        let mut within = module("crate::storage", 10, 20, true);
        within.test_items = vec![(11, 15)];
        assert_eq!(
            out.index(&[root(), within], &regions_on(&[30]), &regions_on(&[30]))
                .unwrap()
                .1,
            Vec::<String>::new()
        );
        let mut beside = module("crate::storage", 10, 20, true);
        beside.test_items = vec![(16, 18)];
        assert_eq!(
            out.index(&[root(), beside], &regions_on(&[30]), &regions_on(&[30]))
                .unwrap()
                .1
                .len(),
            1
        );
    }

    #[test]
    fn a_minimal_witness_dropping_a_full_region_fails() {
        let out = Out::new("loss");
        let (map, faults) = out
            .index(
                &[root(), module("crate::storage", 10, 20, true)],
                &regions_on(&[13]),
                &regions_on(&[13, 16]),
            )
            .unwrap();
        assert_eq!(
            map.witness_loss,
            vec![Loss {
                suite: BASE.to_string(),
                test: TEST.to_string(),
                regions: regions_on(&[16]),
            }]
        );
        assert_eq!(
            faults,
            vec![format!(
                "minimal witness drops a path: {BASE} {TEST}: src/storage.rs:16:1-16:40"
            )]
        );
    }

    /// The planted controls of the witness-size comparison of boundary
    /// valuations: a minimal run under another matrix name reaching the
    /// full run's valuations passes; one missing a valuation the full run
    /// reaches, and one reaching a valuation the full run does not, each
    /// fail, named; a malformed valuation breaks the index.
    #[test]
    fn a_minimal_witness_reaching_other_valuations_fails() {
        let out = Out::new("valuations");
        let census = [root(), module("crate::storage", 10, 20, true)];
        let renamed = REACHED.replace("\"m\"", "\"m 3\"");
        let (map, faults) = out
            .logged(
                &census,
                &regions_on(&[13]),
                &regions_on(&[13]),
                &renamed,
                REACHED,
            )
            .unwrap();
        assert_eq!(
            (map.valuation_loss, faults),
            (Vec::new(), Vec::<String>::new())
        );
        let short = "DCBOR_REACHED\t\"m\"\tquantum\tat\n";
        let (map, faults) = out
            .logged(
                &census,
                &regions_on(&[13]),
                &regions_on(&[13]),
                short,
                REACHED,
            )
            .unwrap();
        assert_eq!(
            map.valuation_loss,
            vec![ValuationLoss {
                suite: BASE.to_string(),
                test: TEST.to_string(),
                valuations: vec!["-quantum\tpast".to_string()],
            }]
        );
        assert_eq!(
            faults,
            vec![format!(
                "minimal witness reaches another boundary valuation: {BASE} {TEST}: -quantum\tpast"
            )]
        );
        let more = format!("{REACHED}DCBOR_REACHED\t\"m\"\tbuckets\ttombstone\n");
        let (_, faults) = out
            .logged(
                &census,
                &regions_on(&[13]),
                &regions_on(&[13]),
                &more,
                REACHED,
            )
            .unwrap();
        assert_eq!(
            faults,
            vec![format!(
                "minimal witness reaches another boundary valuation: {BASE} {TEST}: +buckets\ttombstone"
            )]
        );
        let broken = "DCBOR_REACHED\t\"m\"\tquantum\tsideways\n";
        assert!(
            out.logged(
                &census,
                &regions_on(&[13]),
                &regions_on(&[13]),
                broken,
                REACHED
            )
            .unwrap_err()
            .contains("no predicate or valuation")
        );
    }

    /// The map's verdict holds the census's `cfg` completeness (G11): a
    /// predicate some gated build compiles passes; the planted control, a
    /// predicate no gated build compiles, is a fault of the map, named.
    #[test]
    fn a_predicate_no_build_compiles_fails_the_map() {
        use dcbor_census::CfgForm;
        let out = Out::new("cfgs");
        let census = [root(), module("crate::storage", 10, 20, true)];
        let cfg = |predicate: &str| CensusCfg {
            file: FILE.to_string(),
            line: 3,
            form: CfgForm::Attribute,
            predicate: predicate.to_string(),
        };
        let compiled = [cfg("feature = \"std\"")];
        let (_, faults) = out
            .indexed(
                &census,
                &compiled,
                &regions_on(&[13]),
                &regions_on(&[13]),
                (REACHED, REACHED),
            )
            .unwrap();
        assert_eq!(faults, Vec::<String>::new());
        let never = [cfg("all (feature = \"std\" , not (feature = \"std\"))")];
        let (_, faults) = out
            .indexed(
                &census,
                &never,
                &regions_on(&[13]),
                &regions_on(&[13]),
                (REACHED, REACHED),
            )
            .unwrap();
        assert_eq!(
            faults,
            vec![format!(
                "{FILE}:3: cfg(all (feature = \"std\" , not (feature = \"std\"))): holds in no build the gates make"
            )]
        );
    }

    /// A census of another configuration, and a function in no module of
    /// it, are refused.
    #[test]
    fn a_census_of_another_run_or_shape_is_refused() {
        let out = Out::new("census");
        out.write("census.txt", &dcbor_census::render("that", &[root()], &[]));
        assert!(
            census(&out.0, "this")
                .unwrap_err()
                .contains("another configuration")
        );
        let elsewhere = CensusModule {
            file: "src/other.rs".to_string(),
            ..root()
        };
        assert!(
            out.index(&[elsewhere], &regions_on(&[13]), &regions_on(&[13]))
                .unwrap_err()
                .contains("lies in no module of the census")
        );
    }

    /// An export's executed code regions under `src/` are kept, by file,
    /// sorted and distinct; a region of another kind, one never executed and
    /// one outside `src/` are not; each function's span is its own file's
    /// code regions.
    #[test]
    fn an_export_yields_executed_regions_and_function_spans() {
        let root = Path::new("/repo");
        let export = serde_json::json!({
            "type": "llvm.coverage.json.export",
            "version": "2.0.1",
            "data": [{
                "functions": [
                    {
                        "name": "grow",
                        "count": 1,
                        "filenames": ["/repo/src/storage.rs", "/repo/src/macros.rs"],
                        "regions": [
                            [14, 1, 14, 9, 1, 0, 0, 0],
                            [12, 5, 13, 2, 3, 0, 0, 0],
                            [12, 5, 13, 2, 3, 0, 0, 0],
                            [20, 1, 20, 2, 0, 0, 0, 0],
                            [30, 1, 30, 2, 5, 0, 0, 4],
                            [1, 1, 2, 2, 5, 1, 0, 0]
                        ]
                    },
                    {
                        "name": "outside",
                        "filenames": ["/elsewhere/src/lib.rs"],
                        "regions": [[1, 1, 1, 2, 1, 0, 0, 0]]
                    },
                    {
                        "name": "tests",
                        "filenames": ["/repo/tests/a.rs"],
                        "regions": [[1, 1, 1, 2, 1, 0, 0, 0]]
                    }
                ]
            }]
        })
        .to_string();
        assert_eq!(
            regions(root, &export).unwrap(),
            BTreeMap::from([
                ("src/macros.rs".to_string(), vec![[1, 1, 2, 2]]),
                (
                    "src/storage.rs".to_string(),
                    vec![[12, 5, 13, 2], [14, 1, 14, 9]]
                ),
            ])
        );
        assert_eq!(
            functions(root, &export).unwrap(),
            vec![Function {
                name: "grow".to_string(),
                file: "src/storage.rs".to_string(),
                start: [12, 5],
                end: [20, 2],
            }]
        );
        let other = serde_json::json!({"type": "other", "data": []}).to_string();
        assert!(
            regions(root, &other)
                .unwrap_err()
                .contains("not an llvm-cov export")
        );
    }

    /// The one test executable of a build is found; none, or two, is
    /// refused.
    #[test]
    fn a_build_reports_exactly_one_test_executable() {
        let artifact = |executable: &str, test: bool| {
            serde_json::json!({
                "reason": "compiler-artifact",
                "profile": {"test": test},
                "executable": executable
            })
            .to_string()
        };
        let messages = format!(
            "{}\n{}\nCompiling dcbor\n{}\n",
            artifact("/t/owned_input-1", true),
            artifact("/t/build-script", false),
            serde_json::json!({"reason": "build-finished", "success": true})
        );
        assert_eq!(executable(&messages), Ok("/t/owned_input-1".to_string()));
        let two = format!("{}\n{}\n", artifact("/t/a", true), artifact("/t/b", true));
        assert!(
            executable(&two)
                .unwrap_err()
                .contains("expected one test executable")
        );
        assert!(
            executable("")
                .unwrap_err()
                .contains("expected one test executable")
        );
    }

    #[test]
    fn a_region_overlaps_a_span_it_touches() {
        assert!(overlaps(&[12, 1, 12, 40], [12, 5], [14, 6]));
        assert!(overlaps(&[14, 6, 15, 1], [12, 5], [14, 6]));
        assert!(!overlaps(&[14, 7, 15, 1], [12, 5], [14, 6]));
        assert!(!overlaps(&[10, 1, 12, 4], [12, 5], [14, 6]));
    }
}
