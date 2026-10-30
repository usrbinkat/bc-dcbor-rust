//! The census of this crate's unsafe trust boundaries: every module whose
//! own code holds `unsafe`, and every module a private item of one is
//! visible in. The soundness of unsafe code rests on state the safe code
//! within its privacy boundary maintains (a length, a capacity, a phase, an
//! offset), so the unit of trust is the module and its descendants, not the
//! `unsafe fn` body: a mutant of safe code there can set up what the unsafe
//! code relies on. The mutation campaign's Miri layer (`mutation-evidence.sh`)
//! judges every native survivor inside such a module under Miri.
//!
//! A module's own code is its items outside its nested inline modules. It
//! holds `unsafe` when its tokens contain the keyword (a block, a function,
//! an impl, a trait, or a macro's tokens), or when it invokes a macro of this
//! crate whose definition contains it: the expansion is the invoking module's
//! code and reaches its private items. Doc text is a literal, never a
//! keyword. A module is tainted when it or an ancestor holds `unsafe`.
//!
//! A module is test code when it or an ancestor is compiled only under
//! `cfg(test)` (`source_tree::test_only`): it is never mutated (cargo-mutants
//! skips every node so attributed, `visit.rs` `attrs_excluded`), so it is no
//! trust boundary of the shipped crate, and the reach map does not require it
//! reached under Miri. So is an item of a shipped module so compiled, or an
//! item of one of its impls or traits: its line span is recorded with its
//! module.
//!
//! The walk is the crate's one module walk (`source_tree`). With
//! `DCBOR_UNSAFE_CENSUS` naming a file, the census is written there as JSON
//! lines, one module each: its file, path, line span, whether its own code
//! holds `unsafe`, whether it is tainted, whether it is test code, and the
//! line spans of its own test-only items.

mod source_tree;

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use proc_macro2::{Spacing, TokenStream, TokenTree};
use quote::ToTokens;
use source_tree::Tree;
use syn::spanned::Spanned;
use syn::{Attribute, ImplItem, Item, ItemMod, TraitItem};

/// The variable naming the file the census is written to.
const OUTPUT: &str = "DCBOR_UNSAFE_CENSUS";

/// One module of the crate.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Module {
    /// The file it lies in, relative to the crate root.
    file: String,
    /// Its path from the crate root, `crate` for the root.
    path: String,
    /// Its line span within `file`: the whole file for a file module, its
    /// braces for an inline one.
    start: usize,
    end: usize,
    /// The index of its parent in the census, `None` for the root.
    parent: Option<usize>,
    /// Its own declaration compiles it only under `cfg(test)`.
    test_only: bool,
    /// The line spans of its own items compiled only under `cfg(test)`,
    /// and of such items of its impls and traits.
    test_items: Vec<(usize, usize)>,
    /// The `unsafe` keyword in its own code.
    unsafe_tokens: bool,
    /// The macros its own code invokes, by name.
    invoked: BTreeSet<String>,
    /// The statics its own code defines outside its test-only items, a
    /// function's included, by name and line; a `thread_local!` as
    /// `thread_local!`.
    statics: Vec<(String, usize)>,
}

/// What one walk found: every module, the macros of the crate whose
/// definitions contain `unsafe`, and the shared tree's faults.
struct Census {
    tree: Tree,
    modules: Vec<Module>,
    unsafe_macros: BTreeSet<String>,
}

/// The `unsafe` keyword, invoked macro names and `unsafe`-bearing macro
/// definitions in `tokens`.
#[derive(Default)]
struct Scanned {
    unsafe_tokens: bool,
    invoked: BTreeSet<String>,
    unsafe_macros: BTreeSet<String>,
    /// Each `static` item defined (the `'static` lifetime is no item), by
    /// name and line, and each `thread_local!`.
    statics: Vec<(String, usize)>,
}

impl Scanned {
    fn scan(&mut self, tokens: TokenStream) {
        let trees: Vec<TokenTree> = tokens.into_iter().collect();
        for (at, tree) in trees.iter().enumerate() {
            match tree {
                TokenTree::Group(group) => self.scan(group.stream()),
                TokenTree::Ident(ident) => {
                    let name = ident.to_string();
                    if name == "unsafe" {
                        self.unsafe_tokens = true;
                    }
                    if name == "static" {
                        let lifetime = at
                            .checked_sub(1)
                            .and_then(|before| trees.get(before))
                            .is_some_and(|before| {
                                matches!(before, TokenTree::Punct(punct) if punct.as_char() == '\'')
                            });
                        let mut next = at + 1;
                        if matches!(trees.get(next), Some(TokenTree::Ident(word)) if word == "mut")
                        {
                            next += 1;
                        }
                        if let (false, Some(TokenTree::Ident(defined))) =
                            (lifetime, trees.get(next))
                        {
                            self.statics
                                .push((defined.to_string(), ident.span().start().line));
                        }
                    }
                    let bang = matches!(trees.get(at + 1), Some(TokenTree::Punct(punct))
                        if punct.as_char() == '!' && punct.spacing() == Spacing::Alone);
                    if !bang {
                        continue;
                    }
                    if name == "thread_local" {
                        self.statics
                            .push(("thread_local!".to_string(), ident.span().start().line));
                    }
                    if name == "macro_rules" {
                        // A definition: `macro_rules! name { body }`.
                        if let (Some(TokenTree::Ident(defined)), Some(TokenTree::Group(body))) =
                            (trees.get(at + 2), trees.get(at + 3))
                        {
                            let mut inner = Scanned::default();
                            inner.scan(body.stream());
                            if inner.unsafe_tokens {
                                self.unsafe_macros.insert(defined.to_string());
                            }
                        }
                    } else if matches!(trees.get(at + 2), Some(TokenTree::Group(_))) {
                        self.invoked.insert(name);
                    }
                }
                TokenTree::Punct(_) | TokenTree::Literal(_) => {}
            }
        }
    }
}

impl Census {
    /// The module file at `path`, at `module_path`, under `parent`, compiled
    /// only under `cfg(test)` when `test_only`.
    fn module_file(
        &mut self,
        path: &Path,
        module_path: String,
        parent: Option<usize>,
        test_only: bool,
    ) {
        let Some(file) = self.tree.load(path) else {
            return;
        };
        self.module(
            &file.shown,
            &file.module_dir,
            module_path,
            (parent, test_only),
            (1, file.lines),
            &file.syntax.items,
        );
    }

    /// One module: its own items scanned, its nested modules recorded as
    /// its children, each with whether its declaration compiles it only
    /// under `cfg(test)`.
    fn module(
        &mut self,
        file: &str,
        module_dir: &Path,
        module_path: String,
        (parent, test_only): (Option<usize>, bool),
        (start, end): (usize, usize),
        items: &[Item],
    ) {
        let index = self.modules.len();
        self.modules.push(Module {
            file: file.to_string(),
            path: module_path.clone(),
            start,
            end,
            parent,
            test_only,
            test_items: Vec::new(),
            unsafe_tokens: false,
            invoked: BTreeSet::new(),
            statics: Vec::new(),
        });
        let mut own = Scanned::default();
        let mut nested: Vec<&ItemMod> = Vec::new();
        let mut test_items = Vec::new();
        for item in items {
            match item {
                Item::Mod(module) => {
                    // A module's attributes are its declaration, in its
                    // parent's code; its contents are its own.
                    for attr in &module.attrs {
                        own.scan(attr.to_token_stream());
                    }
                    if module.unsafety.is_some() {
                        own.unsafe_tokens = true;
                    }
                    nested.push(module);
                }
                other => {
                    own.scan(other.to_token_stream());
                    self.test_items(file, &module_path, other, &mut test_items);
                }
            }
        }
        self.unsafe_macros.extend(own.unsafe_macros);
        let statics = own
            .statics
            .into_iter()
            .filter(|(_, line)| {
                !test_items
                    .iter()
                    .any(|&(start, end)| start <= *line && *line <= end)
            })
            .collect();
        let record = &mut self.modules[index];
        record.unsafe_tokens = own.unsafe_tokens;
        record.invoked = own.invoked;
        record.test_items = test_items;
        record.statics = statics;
        for module in nested {
            let name = module.ident.to_string();
            let child_path = format!("{module_path}::{name}");
            let test_only = match source_tree::test_only(&module.attrs) {
                Ok(test_only) => test_only,
                Err(error) => {
                    self.tree.faults.push(format!(
                        "{file}: {child_path}: its `cfg` does not parse: {error}"
                    ));
                    continue;
                }
            };
            match &module.content {
                Some((_, items)) => {
                    let span = module.span();
                    self.module(
                        file,
                        &module_dir.join(&name),
                        child_path,
                        (Some(index), test_only),
                        (span.start().line, span.end().line),
                        items,
                    );
                }
                None => {
                    let shown = file.to_string();
                    let declared_path = child_path.clone();
                    if let Some(path) = self.tree.declared(module_dir, module, |what| {
                        format!("{shown}: {declared_path}: {what}")
                    }) {
                        self.module_file(&path, child_path, Some(index), test_only);
                    }
                }
            }
        }
    }

    /// The line span of `item`, a module's own item, into `spans` when it is
    /// compiled only under `cfg(test)`; otherwise those of its impl's or
    /// trait's items that are. An attribute that does not parse is a fault.
    fn test_items(
        &mut self,
        file: &str,
        module: &str,
        item: &Item,
        spans: &mut Vec<(usize, usize)>,
    ) {
        let faults = &mut self.tree.faults;
        // An attribute that does not parse is a fault of the walk, and the
        // item is taken as shipped code, which the reach map still requires.
        let mut test_only = |attrs: &[Attribute]| {
            source_tree::test_only(attrs).unwrap_or_else(|error| {
                faults.push(format!(
                    "{file}: {module}: an item's `cfg` does not parse: {error}"
                ));
                false
            })
        };
        let lines = |span: proc_macro2::Span| (span.start().line, span.end().line);
        if test_only(item_attrs(item)) {
            spans.push(lines(item.span()));
            return;
        }
        match item {
            Item::Impl(implementation) => {
                for member in &implementation.items {
                    if test_only(impl_item_attrs(member)) {
                        spans.push(lines(member.span()));
                    }
                }
            }
            Item::Trait(definition) => {
                for member in &definition.items {
                    if test_only(trait_item_attrs(member)) {
                        spans.push(lines(member.span()));
                    }
                }
            }
            _ => {}
        }
    }

    /// Whether module `index`'s own code holds `unsafe`, directly or through
    /// a macro of this crate whose definition contains it.
    fn holds_unsafe(&self, index: usize) -> bool {
        let module = &self.modules[index];
        module.unsafe_tokens
            || module
                .invoked
                .iter()
                .any(|name| self.unsafe_macros.contains(name))
    }

    /// Whether module `index` or an ancestor holds `unsafe`.
    fn tainted(&self, index: usize) -> bool {
        let mut at = Some(index);
        while let Some(index) = at {
            if self.holds_unsafe(index) {
                return true;
            }
            at = self.modules[index].parent;
        }
        false
    }

    /// Whether module `index` or an ancestor is compiled only under
    /// `cfg(test)`.
    fn test(&self, index: usize) -> bool {
        let mut at = Some(index);
        while let Some(index) = at {
            if self.modules[index].test_only {
                return true;
            }
            at = self.modules[index].parent;
        }
        false
    }

    /// The census as JSON lines.
    fn json(&self) -> String {
        let mut out = String::new();
        for (index, module) in self.modules.iter().enumerate() {
            let test_items = module
                .test_items
                .iter()
                .map(|(start, end)| format!("[{start},{end}]"))
                .collect::<Vec<_>>()
                .join(",");
            writeln!(
                out,
                "{{\"file\":{},\"module\":{},\"start\":{},\"end\":{},\"unsafe\":{},\"tainted\":{},\"test\":{},\"test_items\":[{test_items}]}}",
                quoted(&module.file),
                quoted(&module.path),
                module.start,
                module.end,
                self.holds_unsafe(index),
                self.tainted(index),
                self.test(index)
            )
            .expect("writing to a String does not fail");
        }
        out
    }
}

/// An item's own attributes. Unparsed tokens (`Verbatim`), and any form a
/// later `syn` adds, carry none the walk can read.
fn item_attrs(item: &Item) -> &[Attribute] {
    match item {
        Item::Const(item) => &item.attrs,
        Item::Enum(item) => &item.attrs,
        Item::ExternCrate(item) => &item.attrs,
        Item::Fn(item) => &item.attrs,
        Item::ForeignMod(item) => &item.attrs,
        Item::Impl(item) => &item.attrs,
        Item::Macro(item) => &item.attrs,
        Item::Mod(item) => &item.attrs,
        Item::Static(item) => &item.attrs,
        Item::Struct(item) => &item.attrs,
        Item::Trait(item) => &item.attrs,
        Item::TraitAlias(item) => &item.attrs,
        Item::Type(item) => &item.attrs,
        Item::Union(item) => &item.attrs,
        Item::Use(item) => &item.attrs,
        _ => &[],
    }
}

/// An impl item's own attributes, as [`item_attrs`].
fn impl_item_attrs(item: &ImplItem) -> &[Attribute] {
    match item {
        ImplItem::Const(item) => &item.attrs,
        ImplItem::Fn(item) => &item.attrs,
        ImplItem::Type(item) => &item.attrs,
        ImplItem::Macro(item) => &item.attrs,
        _ => &[],
    }
}

/// A trait item's own attributes, as [`item_attrs`].
fn trait_item_attrs(item: &TraitItem) -> &[Attribute] {
    match item {
        TraitItem::Const(item) => &item.attrs,
        TraitItem::Fn(item) => &item.attrs,
        TraitItem::Type(item) => &item.attrs,
        TraitItem::Macro(item) => &item.attrs,
        _ => &[],
    }
}

/// `text` as a JSON string.
fn quoted(text: &str) -> String {
    let mut out = String::from("\"");
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            ch if (ch as u32) < 0x20 => {
                write!(out, "\\u{:04x}", ch as u32).expect("writing to a String does not fail")
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}

/// The census of the crate at `root`, walked from `src/lib.rs`, every
/// unreached source file a fault.
fn census(root: &Path) -> Census {
    let mut census = Census {
        tree: Tree::new(root.to_path_buf()),
        modules: Vec::new(),
        unsafe_macros: BTreeSet::new(),
    };
    census.module_file(
        &root.join("src").join("lib.rs"),
        "crate".to_string(),
        None,
        false,
    );
    census.tree.unreached();
    census
}

/// The census of this crate: the walk is complete, the modules known to
/// hold `unsafe` are found holding it, and a module whose only unsafe is a
/// crate macro's expansion is found tainted. Written out when
/// `DCBOR_UNSAFE_CENSUS` names a file.
#[test]
fn every_unsafe_trust_boundary_of_this_crate_is_found() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let census = census(root);
    assert!(census.tree.faults.is_empty(), "{:#?}", census.tree.faults);
    let find = |path: &str| {
        census
            .modules
            .iter()
            .position(|module| module.path == path)
            .unwrap_or_else(|| panic!("the census has no module {path}"))
    };
    for path in [
        "crate::bounded::decode::construction::reclamation",
        "crate::bounded::decode::construction::stable",
        "crate::bounded::decode::initialization",
    ] {
        assert!(census.holds_unsafe(find(path)), "{path} holds unsafe");
    }
    assert!(
        census.unsafe_macros.contains("init_field") && census.unsafe_macros.contains("init_part"),
        "the initialization macros' unsafe is found: {:?}",
        census.unsafe_macros
    );
    assert!(
        census.tainted(find("crate::bounded::text_cursor::ordering")),
        "a module initializing through `init_part!` is tainted"
    );
    assert!(
        census.test(find("crate::bounded::places")),
        "the test builds' place attribution is test code"
    );
    assert!(
        !census.test(find("crate::bounded::decode::construction::reclamation")),
        "the reclamation engine is shipped code"
    );
    // The retained parser's test-only cleanup charge is a test item of its
    // shipped module.
    let cursor = &census.modules[find("crate::bounded::decode::cursor")];
    let source = fs::read_to_string(root.join(&cursor.file)).expect("the cursor is readable");
    let line = source
        .lines()
        .position(|line| line.contains("fn finished_cleanup"))
        .expect("the cursor defines finished_cleanup")
        + 1;
    assert!(
        cursor
            .test_items
            .iter()
            .any(|&(start, end)| start <= line && line <= end),
        "finished_cleanup, line {line}, is not among {:?}",
        cursor.test_items
    );
    if let Some(output) = std::env::var_os(OUTPUT) {
        fs::write(PathBuf::from(output), census.json()).expect("the census output is writable");
    }
}

/// The statics of shipped code, every module and item compiled outside
/// `cfg(test)`, by module path and name.
fn shipped_statics(census: &Census) -> Vec<(String, String)> {
    census
        .modules
        .iter()
        .enumerate()
        .filter(|&(index, _)| !census.test(index))
        .flat_map(|(_, module)| {
            module
                .statics
                .iter()
                .map(|(name, _)| (module.path.clone(), name.clone()))
        })
        .collect()
}

/// No shipped code keeps state in a static but the tag registry. Miri
/// reports memory still allocated when a run ends only when no static
/// reaches it, so an allocation a static holds is a leak no Miri run can
/// see. The one static is `crate::tags::GLOBAL_TAGS`, the process-wide
/// registry of tag names the symbolic API's diagnostics read
/// (`with_tags!`, `diag.rs`, `dump.rs`): it holds what callers register, for
/// the process's life, by design, and no code of `crate::bounded` reaches
/// it. A static added anywhere else, a function's included, or a
/// `thread_local!`, fails here until it is declared with its reason.
#[test]
fn no_shipped_static_holds_state_but_the_tag_registry() {
    let census = census(Path::new(env!("CARGO_MANIFEST_DIR")));
    assert!(census.tree.faults.is_empty(), "{:#?}", census.tree.faults);
    assert_eq!(
        shipped_statics(&census),
        vec![("crate::tags".to_string(), "GLOBAL_TAGS".to_string())],
        "a shipped static that is not declared: Miri cannot report a leak it holds"
    );
}

/// The static scan's pass and fail scenarios: a static at module level, one
/// inside a function, a `static mut` and a `thread_local!` are found; the
/// `'static` lifetime, a static of a test-only module and a test-only item
/// of a shipped module are not.
#[test]
fn the_static_scan_finds_every_shipped_static_and_nothing_else() {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("static_census_tree");
    if root.exists() {
        fs::remove_dir_all(&root).expect("the previous fixture tree is removable");
    }
    let src = root.join("src");
    fs::create_dir_all(&src).expect("the fixture tree is writable");
    fs::write(
        src.join("lib.rs"),
        "pub static TABLE: [u8; 2] = [1, 2];\n\
         pub fn named(text: &'static str) -> &'static str {\n\
             static NEXT: u8 = 0;\n\
             let _ = NEXT;\n\
             text\n\
         }\n\
         static mut COUNT: u8 = 0;\n\
         std::thread_local! { static DEPTH: u8 = const { 0 }; }\n\
         #[cfg(test)]\nmod checks { static PROBE: u8 = 0; }\n\
         #[cfg(test)]\nstatic FIXTURE: u8 = 0;\n",
    )
    .expect("the fixture tree is writable");
    let scanned = census(&root);
    assert!(scanned.tree.faults.is_empty(), "{:#?}", scanned.tree.faults);
    let found = |name: &str| ("crate".to_string(), name.to_string());
    assert_eq!(
        shipped_statics(&scanned),
        vec![
            found("TABLE"),
            found("NEXT"),
            found("COUNT"),
            found("thread_local!"),
            found("DEPTH"),
        ]
    );
}

/// Where `source`, one file's text, names `miri` in a `cfg`: in `cfg(..)`,
/// `cfg!(..)` or `cfg_attr(..)`, except `cfg_attr(miri, ignore)` exactly.
/// The reach map (`tests/reach-map.sh`) records the paths each test executes
/// natively and the campaign judges a mutant under Miri on the tests those
/// paths name, so a test must execute under Miri what it executes natively:
/// ignoring one under Miri drops it from Miri's own listing, and any other
/// `miri` predicate would make the map describe paths Miri does not run.
/// Witness sizes for Miri are chosen at run time (`DCBOR_WITNESS`), on the
/// same path in both.
fn miri_divergences(source: &str) -> Result<Vec<String>, String> {
    let tokens: TokenStream = source
        .parse()
        .map_err(|error| format!("does not lex: {error}"))?;
    let mut found = Vec::new();
    divergences(tokens, &mut found);
    Ok(found)
}

fn divergences(tokens: TokenStream, found: &mut Vec<String>) {
    let trees: Vec<TokenTree> = tokens.into_iter().collect();
    for (at, tree) in trees.iter().enumerate() {
        match tree {
            TokenTree::Group(group) => divergences(group.stream(), found),
            TokenTree::Ident(ident) if ident.to_string().starts_with("cfg") => {
                let name = ident.to_string();
                let predicate = match (trees.get(at + 1), trees.get(at + 2)) {
                    (Some(TokenTree::Group(group)), _) if name == "cfg" || name == "cfg_attr" => {
                        Some(group.stream())
                    }
                    (Some(TokenTree::Punct(bang)), Some(TokenTree::Group(group)))
                        if name == "cfg" && bang.as_char() == '!' =>
                    {
                        Some(group.stream())
                    }
                    _ => None,
                };
                let Some(predicate) = predicate else {
                    continue;
                };
                let shown = predicate.to_string();
                if names(predicate, "miri")
                    && !(name == "cfg_attr" && shown.replace(' ', "") == "miri,ignore")
                {
                    found.push(format!("{name}({shown})"));
                }
            }
            TokenTree::Ident(_) | TokenTree::Punct(_) | TokenTree::Literal(_) => {}
        }
    }
}

/// Whether `tokens` contain the identifier `name`.
fn names(tokens: TokenStream, name: &str) -> bool {
    tokens.into_iter().any(|tree| match tree {
        TokenTree::Group(group) => names(group.stream(), name),
        TokenTree::Ident(ident) => ident == name,
        TokenTree::Punct(_) | TokenTree::Literal(_) => false,
    })
}

/// No code of this crate, nor of its tests, executes differently under Miri
/// except by being ignored there.
#[test]
fn no_code_diverges_under_miri() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = BTreeSet::new();
    source_tree::sources(&root.join("src"), &mut files);
    source_tree::sources(&root.join("tests"), &mut files);
    source_tree::sources(&root.join("dcbor-derive").join("src"), &mut files);
    let mut violations = Vec::new();
    for file in &files {
        let source = fs::read_to_string(file)
            .unwrap_or_else(|error| panic!("{}: cannot be read: {error}", file.display()));
        match miri_divergences(&source) {
            Ok(found) => violations.extend(
                found
                    .into_iter()
                    .map(|cfg| format!("{}: {cfg}", file.display())),
            ),
            Err(error) => violations.push(format!("{}: {error}", file.display())),
        }
    }
    assert!(violations.is_empty(), "{violations:#?}");
}

/// The divergence check's pass and fail scenarios: ignoring under Miri
/// passes; every other `miri` predicate, in an attribute, a `cfg_attr` or
/// `cfg!`, fails; `miri` outside a `cfg` and a `!=` pass.
#[test]
fn only_ignoring_under_miri_is_not_a_divergence() {
    assert_eq!(
        miri_divergences(
            "#[test]\n#[cfg_attr(miri, ignore)]\nfn slow() {}\n\
             fn named() { let miri = 1; let _ = miri != 2; }\n"
        ),
        Ok(Vec::new())
    );
    assert_eq!(
        miri_divergences(
            "#[cfg(miri)] fn a() {}\n\
             #[cfg(not(miri))] fn b() {}\n\
             #[cfg_attr(miri, allow(unused))] fn c() {}\n\
             fn d() -> usize { if cfg!(miri) { 3 } else { 3000 } }\n"
        ),
        Ok(vec![
            "cfg(miri)".to_string(),
            "cfg(not (miri))".to_string(),
            "cfg_attr(miri , allow (unused))".to_string(),
            "cfg(miri)".to_string(),
        ])
    );
}

/// The census's pass and fail scenarios over a module tree: a module with an
/// `unsafe` block, an inline module beneath it (tainted), a module holding
/// only `unsafe` in doc text (clean), a module invoking a macro whose
/// definition holds `unsafe` (holding it), a module with only `!=` (clean),
/// and a declared module with no file (a fault).
#[test]
fn the_census_finds_unsafe_by_tokens_and_macros_and_nothing_else() {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("unsafe_census_tree");
    if root.exists() {
        fs::remove_dir_all(&root).expect("the previous fixture tree is removable");
    }
    let src = root.join("src");
    fs::create_dir_all(&src).expect("the fixture tree is writable");
    for (name, source) in [
        (
            "lib.rs",
            "mod raw;\nmod docs;\nmod invoking;\nmod comparing;\nmod missing;\n\
             macro_rules! poke { ($p:expr) => { unsafe { *$p = 0 } }; }\n",
        ),
        (
            "raw.rs",
            "pub fn zero(p: *mut u8) { unsafe { *p = 0 } }\n\
             mod inner {\n    pub fn safe() -> usize { 1 }\n}\n",
        ),
        (
            "docs.rs",
            "/// Calls nothing unsafe.\npub fn safe() -> usize { 1 }\n",
        ),
        ("invoking.rs", "pub fn zero(p: *mut u8) { poke!(p) }\n"),
        (
            "comparing.rs",
            "pub fn differ(a: u8, b: u8) -> bool { a != b }\n",
        ),
    ] {
        fs::write(src.join(name), source).expect("the fixture tree is writable");
    }
    let rooted = census(&root);
    let candidates = [src.join("missing.rs"), src.join("missing").join("mod.rs")];
    assert_eq!(
        rooted.tree.faults,
        vec![format!(
            "src/lib.rs: crate::missing: `mod missing` resolves to none of {candidates:?}"
        )]
    );
    let summary: Vec<(String, usize, usize, bool, bool)> = rooted
        .modules
        .iter()
        .enumerate()
        .map(|(index, module)| {
            (
                module.path.clone(),
                module.start,
                module.end,
                rooted.holds_unsafe(index),
                rooted.tainted(index),
            )
        })
        .collect();
    assert_eq!(
        summary,
        vec![
            ("crate".to_string(), 1, 6, true, true),
            ("crate::raw".to_string(), 1, 4, true, true),
            ("crate::raw::inner".to_string(), 2, 4, false, true),
            ("crate::docs".to_string(), 1, 2, false, true),
            ("crate::invoking".to_string(), 1, 1, true, true),
            ("crate::comparing".to_string(), 1, 1, false, true),
        ],
        "the crate root holds the macro definition, so every module is tainted beneath it"
    );
    // The same tree without the macro at the root: only the modules whose own
    // code holds unsafe, and their descendants, are tainted.
    fs::write(
        src.join("lib.rs"),
        "mod raw;\nmod docs;\nmod invoking;\nmod comparing;\n\
         mod macros { macro_rules! poke { ($p:expr) => { unsafe { *$p = 0 } }; } }\n",
    )
    .expect("the fixture tree is writable");
    let nested = census(&root);
    assert!(nested.tree.faults.is_empty(), "{:#?}", nested.tree.faults);
    let tainted: Vec<(String, bool, bool)> = nested
        .modules
        .iter()
        .enumerate()
        .map(|(index, module)| {
            (
                module.path.clone(),
                nested.holds_unsafe(index),
                nested.tainted(index),
            )
        })
        .collect();
    assert_eq!(
        tainted,
        vec![
            ("crate".to_string(), false, false),
            ("crate::raw".to_string(), true, true),
            ("crate::raw::inner".to_string(), false, true),
            ("crate::docs".to_string(), false, false),
            ("crate::invoking".to_string(), true, true),
            ("crate::comparing".to_string(), false, false),
            ("crate::macros".to_string(), true, true),
        ]
    );
    // Test code: a module compiled only under `cfg(test)`, alone or in an
    // `all(..)`, is test code with every descendant; `any(test, ..)` and
    // `not(test)` compile outside tests too and are not.
    fs::write(
        src.join("lib.rs"),
        "mod raw;\nmod docs;\nmod invoking;\nmod comparing;\n\
         mod macros { macro_rules! poke { ($p:expr) => { unsafe { *$p = 0 } }; } }\n\
         #[cfg(test)]\nmod checks { mod deeper { pub fn probe() {} } }\n\
         #[cfg(all(test, feature = \"std\"))]\nmod gated { pub fn probe() {} }\n\
         #[cfg(any(test, feature = \"std\"))]\nmod either { pub fn probe() {} }\n\
         #[cfg(not(test))]\nmod shipped { pub fn probe() {} }\n\
         mod items {\n\
             pub fn shipped() {}\n\
             #[cfg(test)]\n\
             pub fn probe() {}\n\
             pub struct Kept;\n\
             impl Kept {\n\
                 pub fn kept(&self) {}\n\
                 #[cfg(test)]\n\
                 fn checked(&self) {}\n\
             }\n\
         }\n",
    )
    .expect("the fixture tree is writable");
    let testing = census(&root);
    assert!(testing.tree.faults.is_empty(), "{:#?}", testing.tree.faults);
    let test: Vec<(String, bool)> = testing
        .modules
        .iter()
        .enumerate()
        .map(|(index, module)| (module.path.clone(), testing.test(index)))
        .collect();
    assert_eq!(
        test,
        vec![
            ("crate".to_string(), false),
            ("crate::raw".to_string(), false),
            ("crate::raw::inner".to_string(), false),
            ("crate::docs".to_string(), false),
            ("crate::invoking".to_string(), false),
            ("crate::comparing".to_string(), false),
            ("crate::macros".to_string(), false),
            ("crate::checks".to_string(), true),
            ("crate::checks::deeper".to_string(), true),
            ("crate::gated".to_string(), true),
            ("crate::either".to_string(), false),
            ("crate::shipped".to_string(), false),
            ("crate::items".to_string(), false),
        ]
    );
    // A shipped module's test-only items, its own and its impl's, each by
    // its whole span, attribute included: lines 16-17 and 21-22.
    let items = testing
        .modules
        .iter()
        .find(|module| module.path == "crate::items")
        .expect("the census has crate::items");
    assert_eq!(items.test_items, vec![(16, 17), (21, 22)]);
    assert!(
        testing
            .modules
            .iter()
            .filter(|module| module.path != "crate::items")
            .all(|module| module.test_items.is_empty()),
        "no other module holds a test-only item"
    );
}
