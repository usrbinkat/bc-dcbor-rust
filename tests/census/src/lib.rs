//! A leaf over the record format (`dcbor_record`): the rows of the unsafe
//! census, the one record two crates share that may not depend on each
//! other. The census test (`tests/unsafe_census.rs`) writes it, and the gate
//! (`tests/gate`, `reach` and `mutation`) reads it; the gate's own code
//! never enters the library's test builds, Miri's included.
//!
//! One row per module of the crate: its file, its path, its line span,
//! whether its own code holds `unsafe`, whether it or an ancestor does
//! (tainted), whether it or an ancestor is compiled only under `cfg(test)`
//! (test code), and the line spans of its own items so compiled
//! (`test_items`), test code within a shipped module. The record's first row
//! names the columns; a row of any other shape is refused.
//!
//! After the modules, one row per `cfg` predicate of the crate's sources and
//! tests ([`CensusCfg`], each beginning [`CFG`]): its file, its line, its
//! form (`cfg`, `cfg!` or `cfg_attr`) and its whole expression, which the
//! gate evaluates against every build it makes (`cfgs`).

/// The census's columns, its first row.
pub const COLUMNS: &str = "file\tmodule\tstart\tend\tunsafe\ttainted\ttest\ttest_items";

/// One module of the census.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CensusModule {
    /// The file it lies in, relative to the crate root.
    pub file: String,
    /// Its path from the crate root, `crate` for the root.
    pub module: String,
    /// Its line span within `file`.
    pub start: usize,
    pub end: usize,
    /// Its own code holds `unsafe`.
    pub holds_unsafe: bool,
    /// It or an ancestor holds `unsafe`.
    pub tainted: bool,
    /// It or an ancestor is compiled only under `cfg(test)`.
    pub test: bool,
    /// The line spans of its own items compiled only under `cfg(test)`.
    pub test_items: Vec<(usize, usize)>,
}

/// Whether `start..=end` is a nonempty range of lines from 1.
fn lines(start: usize, end: usize) -> bool {
    1 <= start && start <= end
}

fn boolean(text: &str, field: &str) -> Result<bool, String> {
    match text {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(format!("{field} is {other:?}, not a boolean")),
    }
}

fn line(text: &str, field: &str) -> Result<usize, String> {
    text.parse()
        .map_err(|_| format!("{field} is {text:?}, not a line"))
}

impl CensusModule {
    /// Whether `line` lies in one of this module's test-only items.
    pub fn holds_test_item(&self, line: usize) -> bool {
        self.test_items
            .iter()
            .any(|&(start, end)| start <= line && line <= end)
    }

    /// The module's row.
    pub fn row(&self) -> String {
        let items = if self.test_items.is_empty() {
            "-".to_string()
        } else {
            self.test_items
                .iter()
                .map(|(start, end)| format!("{start}-{end}"))
                .collect::<Vec<_>>()
                .join(",")
        };
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{items}",
            self.file,
            self.module,
            self.start,
            self.end,
            self.holds_unsafe,
            self.tainted,
            self.test,
        )
    }

    /// The module a row records: exactly eight columns, each of its type,
    /// its span and every test item's a nonempty range of lines from 1.
    pub fn parse(row: &str) -> Result<Self, String> {
        let columns: Vec<&str> = row.split('\t').collect();
        let [file, module, start, end, holds_unsafe, tainted, test, items] = columns[..] else {
            return Err(format!("census row {row:?}: not eight columns"));
        };
        let fault = |error: String| format!("census row {row:?}: {error}");
        let start = line(start, "start").map_err(fault)?;
        let end = line(end, "end").map_err(fault)?;
        if !lines(start, end) {
            return Err(fault("its span is not a range of lines".to_string()));
        }
        let test_items = if items == "-" {
            Vec::new()
        } else {
            items
                .split(',')
                .map(|item| {
                    let (first, last) = item
                        .split_once('-')
                        .ok_or_else(|| format!("test item {item:?} is not a range of lines"))?;
                    let (first, last) = (line(first, "a test item")?, line(last, "a test item")?);
                    if lines(first, last) {
                        Ok((first, last))
                    } else {
                        Err(format!("test item {item:?} is not a range of lines"))
                    }
                })
                .collect::<Result<_, String>>()
                .map_err(fault)?
        };
        if file.is_empty() || module.is_empty() {
            return Err(fault("its file and module are named".to_string()));
        }
        Ok(Self {
            file: file.to_string(),
            module: module.to_string(),
            start,
            end,
            holds_unsafe: boolean(holds_unsafe, "unsafe").map_err(fault)?,
            tainted: boolean(tainted, "tainted").map_err(fault)?,
            test: boolean(test, "test").map_err(fault)?,
            test_items,
        })
    }
}

/// The first column of a cfg row.
pub const CFG: &str = "cfg";

/// The form a `cfg` predicate is written in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CfgForm {
    /// `#[cfg(..)]`: the item exists only where the predicate holds.
    Attribute,
    /// `cfg!(..)`: a boolean in every build, each value a path.
    Macro,
    /// `#[cfg_attr(predicate, ..)]`: the attributes apply only where it holds.
    Attr,
}

impl CfgForm {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Attribute => "cfg",
            Self::Macro => "cfg!",
            Self::Attr => "cfg_attr",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        [Self::Attribute, Self::Macro, Self::Attr]
            .into_iter()
            .find(|form| form.name() == text)
    }
}

/// One `cfg` predicate of the crate: where it is written, its form, and its
/// whole expression as its tokens render (`all (test , feature = "std")`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CensusCfg {
    pub file: String,
    pub line: usize,
    pub form: CfgForm,
    pub predicate: String,
}

impl CensusCfg {
    /// The predicate's row: [`CFG`], its file, line, form and expression.
    pub fn row(&self) -> String {
        format!(
            "{CFG}\t{}\t{}\t{}\t{}",
            self.file,
            self.line,
            self.form.name(),
            self.predicate
        )
    }

    /// The predicate a row records: exactly five columns, the first
    /// [`CFG`], a line from 1, a known form and a nonempty expression.
    pub fn parse(row: &str) -> Result<Self, String> {
        let columns: Vec<&str> = row.split('\t').collect();
        let [CFG, file, line_at, form, predicate] = columns[..] else {
            return Err(format!("cfg row {row:?}: not a cfg row of five columns"));
        };
        let fault = |error: String| format!("cfg row {row:?}: {error}");
        let line_at = line(line_at, "line").map_err(fault)?;
        if line_at == 0 || file.is_empty() || predicate.is_empty() {
            return Err(fault("its file, line and predicate are named".to_string()));
        }
        Ok(Self {
            file: file.to_string(),
            line: line_at,
            form: CfgForm::parse(form).ok_or_else(|| fault(format!("no form {form:?}")))?,
            predicate: predicate.to_string(),
        })
    }
}

/// The census of `modules` and `cfgs` under `configuration`: a record of the
/// columns, every module's row, then every predicate's.
pub fn render(configuration: &str, modules: &[CensusModule], cfgs: &[CensusCfg]) -> String {
    let rows: Vec<String> = modules
        .iter()
        .map(CensusModule::row)
        .chain(cfgs.iter().map(CensusCfg::row))
        .collect();
    dcbor_record::render(
        configuration,
        core::iter::once(COLUMNS).chain(rows.iter().map(String::as_str)),
    )
}

/// The census `data` records: its configuration, its modules and its cfg
/// predicates. A file of no record, one without its columns, a census of no
/// module, a module row after a cfg row and a row of another shape are
/// refused, named by line.
pub fn parse(data: &str) -> Result<(String, Vec<CensusModule>, Vec<CensusCfg>), String> {
    let record = dcbor_record::try_read(data).ok_or("the census is not a record")?;
    let mut rows = record.rows.into_iter();
    match rows.next() {
        Some((_, columns)) if columns == COLUMNS => {}
        other => return Err(format!("the census does not name its columns: {other:?}")),
    }
    let mut modules = Vec::new();
    let mut cfgs = Vec::new();
    for (at, row) in rows {
        if row.split('\t').next() == Some(CFG) {
            cfgs.push(CensusCfg::parse(row).map_err(|error| format!("census:{at}: {error}"))?);
        } else if cfgs.is_empty() {
            modules
                .push(CensusModule::parse(row).map_err(|error| format!("census:{at}: {error}"))?);
        } else {
            return Err(format!("census:{at}: a module row after the cfg rows"));
        }
    }
    if modules.is_empty() {
        return Err("the census holds no module".to_string());
    }
    Ok((record.configuration.to_string(), modules, cfgs))
}

/// The innermost module of `census` containing `file:line`.
pub fn module_of<'c>(
    census: &'c [CensusModule],
    file: &str,
    line: usize,
) -> Option<&'c CensusModule> {
    census
        .iter()
        .filter(|module| module.file == file && module.start <= line && line <= module.end)
        .min_by_key(|module| module.end - module.start)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = "src/storage.rs";

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

    /// A module's row reads back to the module, test items included, and the
    /// census record to its configuration and modules.
    #[test]
    fn a_census_reads_back_what_it_renders() {
        let mut items = module("crate::storage", 10, 20, true);
        items.test = true;
        items.test_items = vec![(12, 14), (17, 17)];
        assert!(items.row().ends_with("\ttrue\t12-14,17-17"));
        assert_eq!(CensusModule::parse(&items.row()), Ok(items.clone()));
        assert!(items.holds_test_item(13));
        assert!(!items.holds_test_item(15));
        let census = vec![module("crate", 1, 200, false), items];
        let cfgs = vec![
            CensusCfg {
                file: FILE.to_string(),
                line: 3,
                form: CfgForm::Attribute,
                predicate: "all (test , feature = \"std\")".to_string(),
            },
            CensusCfg {
                file: FILE.to_string(),
                line: 9,
                form: CfgForm::Macro,
                predicate: "loom".to_string(),
            },
        ];
        assert_eq!(
            parse(&render("this", &census, &cfgs)),
            Ok(("this".to_string(), census, cfgs))
        );
    }

    /// A cfg row of another shape, and a module row after a cfg row, are
    /// refused.
    #[test]
    fn a_cfg_row_of_another_shape_is_refused() {
        for (row, message) in [
            ("cfg\tsrc/a.rs\t3\tcfg", "five columns"),
            ("cfg\tsrc/a.rs\tx\tcfg\ttest", "not a line"),
            ("cfg\tsrc/a.rs\t0\tcfg\ttest", "are named"),
            ("cfg\tsrc/a.rs\t3\tcfg\t", "are named"),
            ("cfg\tsrc/a.rs\t3\tcfg?\ttest", "no form"),
        ] {
            let error = CensusCfg::parse(row).expect_err(row);
            assert!(error.contains(message), "{row:?}: {error}");
        }
        let module = module("crate", 1, 2, false).row();
        let late = dcbor_record::render(
            "c",
            [
                COLUMNS,
                module.as_str(),
                "cfg\tsrc/a.rs\t1\tcfg\ttest",
                module.as_str(),
            ],
        );
        assert!(parse(&late).unwrap_err().contains("after the cfg rows"));
    }

    /// Every row of another shape is refused, naming its fault.
    #[test]
    fn a_row_of_another_shape_is_refused() {
        let row = module("crate::storage", 10, 20, true).row();
        let replaced = |at: usize, value: &str| {
            let mut columns: Vec<&str> = row.split('\t').collect();
            columns[at] = value;
            columns.join("\t")
        };
        let cases = [
            (
                row.rsplit_once('\t').unwrap().0.to_string(),
                "not eight columns",
            ),
            (format!("{row}\textra"), "not eight columns"),
            (replaced(5, "1"), "tainted is \"1\", not a boolean"),
            (replaced(2, "true"), "start is \"true\", not a line"),
            (replaced(3, "twenty"), "end is \"twenty\", not a line"),
            (replaced(2, "0"), "not a range of lines"),
            (replaced(2, "21"), "not a range of lines"),
            (
                replaced(7, "12-13-14"),
                "a test item is \"13-14\", not a line",
            ),
            (
                replaced(7, "14-12"),
                "test item \"14-12\" is not a range of lines",
            ),
            (
                replaced(7, "12"),
                "test item \"12\" is not a range of lines",
            ),
            (replaced(7, ""), "test item \"\" is not a range of lines"),
            (replaced(0, ""), "its file and module are named"),
        ];
        for (row, message) in cases {
            let error = CensusModule::parse(&row).expect_err(&row);
            assert!(error.contains(message), "{row:?}: {error}");
        }
    }

    /// A file of no record, a census without its columns and an empty one
    /// are refused.
    #[test]
    fn an_empty_or_unnamed_census_is_refused() {
        assert!(parse("no record\n").unwrap_err().contains("not a record"));
        let row = module("crate", 1, 2, false).row();
        assert!(
            parse(&dcbor_record::render("c", [row.as_str()]))
                .unwrap_err()
                .contains("columns")
        );
        assert!(
            parse(&render("c", &[], &[]))
                .unwrap_err()
                .contains("no module")
        );
        let bad = dcbor_record::render("c", [COLUMNS, "x"]);
        assert!(parse(&bad).unwrap_err().starts_with("census:3:"));
    }

    /// The innermost module holds a line; a line of no module's file has
    /// none.
    #[test]
    fn the_innermost_module_holds_a_line() {
        let root = module("crate", 1, 200, false);
        let inner = module("crate::storage", 10, 20, true);
        let census = [root.clone(), inner.clone()];
        assert_eq!(module_of(&census, FILE, 15), Some(&inner));
        assert_eq!(module_of(&census, FILE, 30), Some(&root));
        assert_eq!(module_of(&census, "src/other.rs", 15), None);
    }
}
