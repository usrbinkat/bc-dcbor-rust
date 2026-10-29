//! The module tree of a crate, walked from `src/lib.rs` as the compiler
//! resolves it: the one walk every source check of this crate shares
//! (`charge_identity.rs`, `unsafe_census.rs`). A check visits each parsed file
//! with a visitor of its own and resolves the out-of-line modules it meets
//! through [`Tree::declared`], so every check reaches the same files by the
//! same rules, and every source file under `src` that no module declares is a
//! fault of the walk, never silently unchecked.

#![allow(
    dead_code,
    reason = "each test crate including this module uses part of it"
)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use syn::punctuated::Punctuated;
use syn::{Attribute, ItemMod, Meta};

/// The files a walk reached and its faults: what it could not resolve,
/// read or parse, and what it did not reach.
pub struct Tree {
    pub root: PathBuf,
    pub reached: BTreeSet<PathBuf>,
    pub faults: Vec<String>,
}

/// One module file, parsed: its path as diagnostics name it, where its
/// out-of-line children are, its line count, and its syntax.
pub struct ModuleFile {
    pub path: PathBuf,
    pub shown: String,
    pub module_dir: PathBuf,
    pub lines: usize,
    pub syntax: syn::File,
}

impl Tree {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            reached: BTreeSet::new(),
            faults: Vec::new(),
        }
    }

    /// `path` relative to the walk's root, as diagnostics name it.
    pub fn shown(&self, path: &Path) -> String {
        match path.strip_prefix(&self.root) {
            Ok(relative) => relative.display().to_string(),
            Err(_) => path.display().to_string(),
        }
    }

    /// The module file at `path`, read and parsed, recorded as reached; a
    /// file declared twice, unreadable or unparsable is a fault and `None`.
    pub fn load(&mut self, path: &Path) -> Option<ModuleFile> {
        let shown = self.shown(path);
        if !self.reached.insert(path.to_path_buf()) {
            self.faults
                .push(format!("{shown}: declared as a module twice"));
            return None;
        }
        let source = match fs::read_to_string(path) {
            Ok(source) => source,
            Err(error) => {
                self.faults
                    .push(format!("{shown}: cannot be read: {error}"));
                return None;
            }
        };
        let syntax = match syn::parse_file(&source) {
            Ok(syntax) => syntax,
            Err(error) => {
                self.faults
                    .push(format!("{shown}: does not parse: {error}"));
                return None;
            }
        };
        let (Some(parent), Some(stem)) = (path.parent(), path.file_stem()) else {
            self.faults
                .push(format!("{shown}: has no directory or no name"));
            return None;
        };
        // A `lib.rs`, `main.rs` or `mod.rs` holds its children beside it;
        // any other module file in the directory of its own name.
        let module_dir = match path.file_name().and_then(|name| name.to_str()) {
            Some("lib.rs" | "main.rs" | "mod.rs") => parent.to_path_buf(),
            _ => parent.join(stem),
        };
        Some(ModuleFile {
            path: path.to_path_buf(),
            shown,
            module_dir,
            lines: source.lines().count().max(1),
            syntax,
        })
    }

    /// The file of the out-of-line module `module`, declared in a module
    /// whose children are in `module_dir`: exactly one of its two paths. A
    /// `#[path]`, no file or both files is a fault, located by `located`.
    pub fn declared(
        &mut self,
        module_dir: &Path,
        module: &ItemMod,
        located: impl Fn(&str) -> String,
    ) -> Option<PathBuf> {
        let name = module.ident.to_string();
        if module.attrs.iter().any(|attr| attr.path().is_ident("path")) {
            self.faults.push(located(&format!(
                "`#[path]` on `mod {name}` is not modeled; extend the walk to resolve it"
            )));
            return None;
        }
        let candidates = [
            module_dir.join(format!("{name}.rs")),
            module_dir.join(&name).join("mod.rs"),
        ];
        let found: Vec<&PathBuf> = candidates.iter().filter(|path| path.is_file()).collect();
        match found.as_slice() {
            [path] => Some((*path).clone()),
            [] => {
                self.faults.push(located(&format!(
                    "`mod {name}` resolves to none of {candidates:?}"
                )));
                None
            }
            _ => {
                self.faults.push(located(&format!(
                    "`mod {name}` resolves to both of {candidates:?}"
                )));
                None
            }
        }
    }

    /// Every source file under `src` the walk did not reach, as a fault:
    /// called once the walk from `src/lib.rs` has finished.
    pub fn unreached(&mut self) {
        let mut files = BTreeSet::new();
        sources(&self.root.join("src"), &mut files);
        let unreached: Vec<String> = files
            .difference(&self.reached)
            .map(|file| {
                format!(
                    "{}: is not reached from src/lib.rs, so this check cannot see what it \
                     compiles",
                    self.shown(file)
                )
            })
            .collect();
        self.faults.extend(unreached);
    }
}

/// Every `.rs` file under `dir`.
pub fn sources(dir: &Path, files: &mut BTreeSet<PathBuf>) {
    let entries = fs::read_dir(dir).unwrap_or_else(|error| panic!("{}: {error}", dir.display()));
    for entry in entries {
        let path = entry
            .unwrap_or_else(|error| panic!("{}: {error}", dir.display()))
            .path();
        if path.is_dir() {
            sources(&path, files);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.insert(path);
        }
    }
}

/// Whether `attrs` compile their item only under `cfg(test)`: `test`, or
/// `all(..)` with a predicate that requires it. `not(test)` and
/// `any(test, ..)` also compile outside tests.
pub fn test_only(attrs: &[Attribute]) -> syn::Result<bool> {
    for attr in attrs {
        if attr.path().is_ident("cfg") && requires_test(&attr.parse_args::<Meta>()?)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn requires_test(meta: &Meta) -> syn::Result<bool> {
    match meta {
        Meta::Path(path) => Ok(path.is_ident("test")),
        Meta::List(list) if list.path.is_ident("all") => {
            let nested =
                list.parse_args_with(Punctuated::<Meta, syn::Token![,]>::parse_terminated)?;
            for meta in &nested {
                if requires_test(meta)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        Meta::List(_) | Meta::NameValue(_) => Ok(false),
    }
}
