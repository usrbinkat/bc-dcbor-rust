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
//! `DCBOR_UNSAFE_CENSUS` naming a file, the census is published there, a
//! record of one row per module (`dcbor_census`, the one definition of its
//! rows, which the gate reads): its file, path, line span, whether its own
//! code holds `unsafe`, whether it is tainted, whether it is test code, and
//! the line spans of its own test-only items; then one row per `cfg`
//! predicate of the crate's sources and tests, which the gate requires to
//! hold in some build it makes (`tests/gate`, `cfgs`).

mod source_tree;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use dcbor_census::CensusModule;
use proc_macro2::{Spacing, TokenStream, TokenTree};
use quote::ToTokens;
use source_tree::Tree;
use syn::parse::Parser;
use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{Attribute, ImplItem, Item, ItemMod, TraitItem, UseTree};

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
    /// The paths into the standard library's `sync` its own code names
    /// outside its test-only items (`core::sync::atomic::AtomicBool`,
    /// `alloc::sync::Arc`), `use` trees flattened, by path and line.
    sync_paths: Vec<(String, usize)>,
    /// The paths into the standard library's `thread` its own code names
    /// outside its test-only items (`std::thread`, `std::thread::current`),
    /// as [`Module::sync_paths`].
    thread_paths: Vec<(String, usize)>,
    /// The routes into a tag store ([`TAG_STORE_ROUTES`]) its own code names
    /// outside its test-only items, by name and line.
    tag_routes: Vec<(String, usize)>,
    /// The bucket accessors ([`BUCKET_ACCESSORS`]) its own code names outside
    /// its test-only items, by name and line.
    bucket_reads: Vec<(String, usize)>,
    /// What its own code names outside its test-only items that would
    /// allocate other than through the global allocator: a name of
    /// [`ALLOCATOR_NAMES`], or a path into the standard library's `alloc`
    /// module ending in `Allocator`, by name and line.
    allocators: Vec<(String, usize)>,
    /// The comparisons and bound calls its own code makes outside its
    /// test-only items and outside the seam ([`BoundarySites`]).
    boundary_sites: Vec<BoundarySite>,
}

/// One comparison or bound call the boundary rule governs: the function or
/// constant it lies in (the outermost named one), its line, what it is
/// (`<`, `min`, `checked_add`, ...), and whether an operand extracts a
/// bound's raw limit (`raw_limit`), a bypass of the seam.
#[derive(Clone, Debug, PartialEq, Eq)]
struct BoundarySite {
    function: String,
    line: usize,
    what: String,
    raw: bool,
}

/// Whether a method or function of this name is one the boundary rule
/// governs: a limit taken (`min`, `max`, `clamp`) or a checked or saturating
/// operation.
fn governed(name: &str) -> bool {
    matches!(name, "min" | "max" | "clamp")
        || name.starts_with("checked_")
        || name.starts_with("saturating_")
}

/// The comparisons and bound calls of the visited items that do not go
/// through the seam: every `<`, `<=`, `>`, `>=`, and every call of a
/// [`governed`] name, except `clamp` on a bound (`Bound::new(..)` or a local
/// bound from one), which is the seam's own. A macro's arguments are code
/// too: they are visited as expressions (`cost!(..)`, `assert!(..)`; for
/// `matches!`, its scrutinee and guard), except a `boundary!` invocation's,
/// the seam's own comparison; a macro whose arguments are not expressions is
/// a site of its own, so no form of code hides a comparison from the rule.
#[derive(Default)]
struct BoundarySites {
    function: Option<String>,
    bounds: BTreeSet<String>,
    found: Vec<BoundarySite>,
}

impl BoundarySites {
    /// Visit `visit` as the item `name`, unless already within one: a nested
    /// item counts toward its outermost named item.
    fn within(&mut self, name: String, visit: impl FnOnce(&mut Self)) {
        if self.function.is_some() {
            visit(self);
            return;
        }
        self.function = Some(name);
        visit(self);
        self.function = None;
        self.bounds.clear();
    }

    fn record(&mut self, line: usize, what: String, raw: bool) {
        let function = self
            .function
            .clone()
            .unwrap_or_else(|| "<item>".to_string());
        self.found.push(BoundarySite {
            function,
            line,
            what,
            raw,
        });
    }

    /// The sites of a `macro_rules!` definition, `tokens` (its name and body,
    /// or its arms): each arm's transcriber, its fragments substituted by
    /// their kinds ([`macro_arguments::substitute`]), parsed as items,
    /// statements or one expression and visited as code is. A transcriber
    /// that parses as none of them, or an arm that is not `(matcher) =>
    /// {transcriber}`, is a site of its own.
    fn definition(&mut self, tokens: TokenStream) {
        let mut trees: Vec<TokenTree> = tokens.into_iter().collect();
        if let [TokenTree::Ident(_), TokenTree::Group(body)] = trees.as_slice() {
            trees = body.stream().into_iter().collect();
        }
        let mut at = 0;
        while at < trees.len() {
            let arm = (
                trees.get(at),
                trees.get(at + 1),
                trees.get(at + 2),
                trees.get(at + 3),
            );
            let (
                Some(TokenTree::Group(matcher)),
                Some(TokenTree::Punct(equals)),
                Some(TokenTree::Punct(greater)),
                Some(TokenTree::Group(transcriber)),
            ) = arm
            else {
                self.record(
                    trees[at].span().start().line,
                    "macro_rules!: an arm not parsed".to_string(),
                    false,
                );
                return;
            };
            if equals.as_char() != '=' || greater.as_char() != '>' {
                self.record(
                    equals.span().start().line,
                    "macro_rules!: an arm not parsed".to_string(),
                    false,
                );
                return;
            }
            let mut kinds = std::collections::BTreeMap::new();
            macro_arguments::fragment_kinds(matcher.stream(), &mut kinds);
            let body = macro_arguments::substitute(transcriber.stream(), &kinds);
            self.transcribed(body, transcriber.span().start().line);
            at += 4;
            if matches!(trees.get(at), Some(TokenTree::Punct(punct)) if punct.as_char() == ';') {
                at += 1;
            }
        }
    }

    /// A substituted transcriber, `body`, visited as items, statements or
    /// one expression, whichever it parses as; none of them a site at `line`.
    fn transcribed(&mut self, body: TokenStream, line: usize) {
        if let Ok(file) = syn::parse2::<syn::File>(body.clone()) {
            for item in &file.items {
                <Self as Visit<'_>>::visit_item(self, item);
            }
        } else if let Ok(statements) = syn::Block::parse_within.parse2(body.clone()) {
            for statement in &statements {
                <Self as Visit<'_>>::visit_stmt(self, statement);
            }
        } else if let Ok(expr) = syn::parse2::<syn::Expr>(body) {
            <Self as Visit<'_>>::visit_expr(self, &expr);
        } else {
            self.record(line, "macro_rules!: a body not parsed".to_string(), false);
        }
    }

    /// Whether `expr` is a bound: `Bound::new(..)`, or a local bound from one.
    fn is_bound(&self, expr: &syn::Expr) -> bool {
        match expr {
            syn::Expr::Call(call) => matches!(&*call.func, syn::Expr::Path(path)
                if path.path.segments.len() >= 2
                    && path.path.segments[path.path.segments.len() - 2].ident == "Bound"
                    && path.path.segments[path.path.segments.len() - 1].ident == "new"),
            syn::Expr::Path(path) => path
                .path
                .get_ident()
                .is_some_and(|ident| self.bounds.contains(&ident.to_string())),
            syn::Expr::Paren(paren) => self.is_bound(&paren.expr),
            _ => false,
        }
    }
}

/// Whether `expr` names `raw_limit`: an operand extracting a bound's limit.
fn extracts(expr: &syn::Expr) -> bool {
    names(expr.to_token_stream(), "raw_limit")
}

impl<'ast> Visit<'ast> for BoundarySites {
    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        self.within(item.sig.ident.to_string(), |this| {
            syn::visit::visit_item_fn(this, item)
        });
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        self.within(item.sig.ident.to_string(), |this| {
            syn::visit::visit_impl_item_fn(this, item)
        });
    }

    fn visit_trait_item_fn(&mut self, item: &'ast syn::TraitItemFn) {
        self.within(item.sig.ident.to_string(), |this| {
            syn::visit::visit_trait_item_fn(this, item)
        });
    }

    // A constant, and a `const` block, is evaluated at compile time from
    // types and constants alone: no comparison in it depends on data, and a
    // failed assertion in it is a compile error (E0080). Its sites are not
    // visited. A `const fn` is not one: it runs at run time too.
    fn visit_item_const(&mut self, _: &'ast syn::ItemConst) {}

    fn visit_impl_item_const(&mut self, _: &'ast syn::ImplItemConst) {}

    fn visit_trait_item_const(&mut self, _: &'ast syn::TraitItemConst) {}

    fn visit_expr_const(&mut self, _: &'ast syn::ExprConst) {}

    fn visit_local(&mut self, local: &'ast syn::Local) {
        if let (syn::Pat::Ident(pattern), Some(init)) = (&local.pat, &local.init)
            && self.is_bound(&init.expr)
        {
            self.bounds.insert(pattern.ident.to_string());
        }
        syn::visit::visit_local(self, local);
    }

    fn visit_expr_binary(&mut self, expr: &'ast syn::ExprBinary) {
        let what = match expr.op {
            syn::BinOp::Lt(_) => Some("<"),
            syn::BinOp::Le(_) => Some("<="),
            syn::BinOp::Gt(_) => Some(">"),
            syn::BinOp::Ge(_) => Some(">="),
            _ => None,
        };
        if let Some(what) = what {
            let raw = extracts(&expr.left) || extracts(&expr.right);
            self.record(expr.op.span().start().line, what.to_string(), raw);
        }
        syn::visit::visit_expr_binary(self, expr);
    }

    fn visit_expr_method_call(&mut self, expr: &'ast syn::ExprMethodCall) {
        let name = expr.method.to_string();
        if governed(&name) && !(name == "clamp" && self.is_bound(&expr.receiver)) {
            let raw = extracts(&expr.receiver) || expr.args.iter().any(extracts);
            self.record(expr.method.span().start().line, name, raw);
        }
        syn::visit::visit_expr_method_call(self, expr);
    }

    fn visit_expr_call(&mut self, expr: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*expr.func
            && let Some(last) = path.path.segments.last()
            && governed(&last.ident.to_string())
        {
            let raw = expr.args.iter().any(extracts);
            self.record(last.ident.span().start().line, last.ident.to_string(), raw);
        }
        syn::visit::visit_expr_call(self, expr);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        let Some(name) = mac.path.segments.last().map(|last| last.ident.to_string()) else {
            return;
        };
        if name == "boundary" {
            return;
        }
        if name == "macro_rules" {
            // A definition: its body is code once it expands, but holds `$`
            // fragments no parser reads as expressions. Its tokens are
            // scanned instead: each governed call and each comparison is a
            // site of the item defining it.
            self.definition(mac.tokens.clone());
            return;
        }
        let line = mac.path.span().start().line;
        // The arguments are parsed from the invocation's own tokens, so each
        // site keeps its line; they are visited under this item.
        match macro_arguments::invocation(&name, mac.tokens.clone()) {
            Some(macro_arguments::Arguments::Expressions(arguments)) => {
                for argument in &arguments {
                    <Self as Visit<'_>>::visit_expr(self, argument);
                }
            }
            Some(macro_arguments::Arguments::Items(items)) => {
                for item in &items {
                    <Self as Visit<'_>>::visit_item(self, item);
                }
            }
            None => self.record(line, format!("{name}!: arguments not expressions"), false),
        }
    }
}

/// The parsers of macro code the boundary rule visits: an invocation's
/// arguments, and a definition's transcribers.
mod macro_arguments {
    use std::collections::BTreeMap;

    use proc_macro2::{Delimiter, Group, Ident, Literal, Punct, Spacing, TokenStream, TokenTree};
    use syn::parse::{ParseStream, Parser};
    use syn::punctuated::Punctuated;
    use syn::{Expr, Item, Pat, Token, Type};

    /// What an invocation's arguments parsed as.
    pub(super) enum Arguments {
        Expressions(Vec<Expr>),
        Items(Vec<Item>),
    }

    /// The arguments of an invocation of `name`, `tokens`: for `matches!`,
    /// its scrutinee and guard; otherwise comma-separated expressions, then
    /// items, then pieces separated by commas and `=>`, each an expression
    /// or a type (`floats!(f16 => f16::ZERO)`). None when they are none of
    /// these.
    pub(super) fn invocation(name: &str, tokens: TokenStream) -> Option<Arguments> {
        if name == "matches" {
            return matched.parse2(tokens).ok().map(Arguments::Expressions);
        }
        if let Ok(expressions) = expressions.parse2(tokens.clone()) {
            return Some(Arguments::Expressions(expressions));
        }
        if let Ok(file) = syn::parse2::<syn::File>(tokens.clone()) {
            return Some(Arguments::Items(file.items));
        }
        mapped(tokens).map(Arguments::Expressions)
    }

    /// Pieces separated by top-level commas and `=>`: each an expression,
    /// collected, or a type, which holds none; any other piece refuses all.
    fn mapped(tokens: TokenStream) -> Option<Vec<Expr>> {
        let trees: Vec<TokenTree> = tokens.into_iter().collect();
        let mut pieces: Vec<Vec<TokenTree>> = vec![Vec::new()];
        let mut at = 0;
        while at < trees.len() {
            match &trees[at] {
                TokenTree::Punct(comma) if comma.as_char() == ',' => pieces.push(Vec::new()),
                TokenTree::Punct(equals)
                    if equals.as_char() == '='
                        && equals.spacing() == Spacing::Joint
                        && matches!(trees.get(at + 1),
                            Some(TokenTree::Punct(greater)) if greater.as_char() == '>') =>
                {
                    pieces.push(Vec::new());
                    at += 1;
                }
                other => pieces
                    .last_mut()
                    .expect("pieces start with one")
                    .push(other.clone()),
            }
            at += 1;
        }
        let mut found = Vec::new();
        for piece in pieces.into_iter().filter(|piece| !piece.is_empty()) {
            let tokens: TokenStream = piece.into_iter().collect();
            if let Ok(expr) = syn::parse2::<Expr>(tokens.clone()) {
                found.push(expr);
            } else if syn::parse2::<Type>(tokens).is_err() {
                return None;
            }
        }
        Some(found)
    }

    /// Each fragment a matcher declares, `$name:kind`, by name.
    pub(super) fn fragment_kinds(tokens: TokenStream, kinds: &mut BTreeMap<String, String>) {
        let trees: Vec<TokenTree> = tokens.into_iter().collect();
        for (at, tree) in trees.iter().enumerate() {
            match tree {
                TokenTree::Group(group) => fragment_kinds(group.stream(), kinds),
                TokenTree::Punct(dollar) if dollar.as_char() == '$' => {
                    if let (
                        Some(TokenTree::Ident(name)),
                        Some(TokenTree::Punct(colon)),
                        Some(TokenTree::Ident(kind)),
                    ) = (trees.get(at + 1), trees.get(at + 2), trees.get(at + 3))
                        && colon.as_char() == ':'
                    {
                        kinds.insert(name.to_string(), kind.to_string());
                    }
                }
                _ => {}
            }
        }
    }

    /// A transcriber with each fragment `$name` replaced by code of its kind
    /// at the fragment's span, `$crate` by `crate`, and each repetition
    /// `$( .. ) sep op` by one copy of its contents: a visibility, an item or
    /// a statement by nothing, a block by `{}`, a literal by `0`, a lifetime
    /// by one, any other kind by an identifier, which parses as an
    /// expression, a type, a pattern, a path or a name.
    pub(super) fn substitute(tokens: TokenStream, kinds: &BTreeMap<String, String>) -> TokenStream {
        let trees: Vec<TokenTree> = tokens.into_iter().collect();
        let mut out: Vec<TokenTree> = Vec::new();
        let mut at = 0;
        while at < trees.len() {
            match &trees[at] {
                TokenTree::Punct(dollar) if dollar.as_char() == '$' => match trees.get(at + 1) {
                    Some(TokenTree::Ident(name)) => {
                        let span = name.span();
                        let placeholder = || TokenTree::Ident(Ident::new("__fragment", span));
                        if name == "crate" {
                            out.push(TokenTree::Ident(name.clone()));
                        } else {
                            match kinds.get(&name.to_string()).map(String::as_str) {
                                Some("vis" | "item" | "stmt") => {}
                                Some("block") => {
                                    let mut block =
                                        Group::new(Delimiter::Brace, TokenStream::new());
                                    block.set_span(span);
                                    out.push(TokenTree::Group(block));
                                }
                                Some("literal") => {
                                    let mut zero = Literal::usize_unsuffixed(0);
                                    zero.set_span(span);
                                    out.push(TokenTree::Literal(zero));
                                }
                                Some("lifetime") => {
                                    let mut quote = Punct::new('\'', Spacing::Joint);
                                    quote.set_span(span);
                                    out.push(TokenTree::Punct(quote));
                                    out.push(placeholder());
                                }
                                _ => out.push(placeholder()),
                            }
                        }
                        at += 2;
                    }
                    Some(TokenTree::Group(repeated)) => {
                        out.extend(substitute(repeated.stream(), kinds));
                        at += 2;
                        let operator = |tree: Option<&TokenTree>| {
                            matches!(tree, Some(TokenTree::Punct(op))
                                if matches!(op.as_char(), '*' | '+' | '?'))
                        };
                        if operator(trees.get(at)) {
                            at += 1;
                        } else if trees.get(at).is_some() && operator(trees.get(at + 1)) {
                            at += 2;
                        }
                    }
                    _ => {
                        out.push(trees[at].clone());
                        at += 1;
                    }
                },
                TokenTree::Group(group) => {
                    let mut copied =
                        Group::new(group.delimiter(), substitute(group.stream(), kinds));
                    copied.set_span(group.span());
                    out.push(TokenTree::Group(copied));
                    at += 1;
                }
                other => {
                    out.push(other.clone());
                    at += 1;
                }
            }
        }
        out.into_iter().collect()
    }

    /// Comma-separated expressions, a trailing comma allowed.
    pub(super) fn expressions(input: ParseStream) -> syn::Result<Vec<Expr>> {
        Ok(Punctuated::<Expr, Token![,]>::parse_terminated(input)?
            .into_iter()
            .collect())
    }

    /// `matches!(scrutinee, pattern if guard)`: the scrutinee and the guard,
    /// the expressions of the invocation; the pattern holds none.
    pub(super) fn matched(input: ParseStream) -> syn::Result<Vec<Expr>> {
        let scrutinee: Expr = input.parse()?;
        input.parse::<Token![,]>()?;
        Pat::parse_multi_with_leading_vert(input)?;
        let mut found = vec![scrutinee];
        if input.peek(Token![if]) {
            input.parse::<Token![if]>()?;
            found.push(input.parse()?);
        }
        if input.peek(Token![,]) {
            input.parse::<Token![,]>()?;
        }
        if !input.is_empty() {
            return Err(input.error("tokens after a matches! guard"));
        }
        Ok(found)
    }
}

/// The accessors that read a hash table's buckets: a group scan, one
/// bucket's entry, one control byte. The engine's one bucket traversal
/// (`encoding::buckets::BucketCursor`) is the only shipped code that reads
/// them, each window admitted before it is inspected; any other reader would
/// inspect controls no admission covers.
const BUCKET_ACCESSORS: &[&str] = &["next_full_bucket", "get_bucket", "bucket_state"];

/// The one module whose shipped code reads buckets ([`BUCKET_ACCESSORS`]).
const BUCKET_TRAVERSAL: &str = "crate::bounded::encoding::buckets";

/// The names through which code allocates other than through the global
/// allocator, or replaces it: a global allocator's trait and attribute, and
/// the unstable allocator API's feature.
const ALLOCATOR_NAMES: &[&str] = &["GlobalAlloc", "global_allocator", "allocator_api"];

/// Every name through which code reaches a tag store: the store and its
/// trait, the registration of this crate's tags, the lookup over a store,
/// a store's summarizers, and every formatting entry point that takes a
/// store (the options' `tags`, the annotated forms and the summary). The
/// crate keeps no store of its own (no shipped static,
/// [`no_shipped_code_keeps_state_in_a_static`]), so a store reaches code
/// only through one of these names.
const TAG_STORE_ROUTES: &[&str] = &[
    "TagsStore",
    "TagsStoreTrait",
    "register_tags_in",
    "tags_for_values",
    "CBORSummarizer",
    "DiagFormatOpts",
    "HexFormatOpts",
    "diagnostic_annotated",
    "summary",
    "hex_annotated",
    "diagnostic_opt",
    "hex_opt",
];

/// The paths into the standard library's modules `modules` (`core::sync`,
/// `std::thread`, under `core`, `std` or `alloc`) that the visited items
/// name: every path written in code, and every leaf of a `use` tree as its
/// full path, the module itself included (`use std::thread;`).
struct StdPaths {
    modules: &'static [&'static str],
    found: Vec<(String, usize)>,
}

impl StdPaths {
    fn new(modules: &'static [&'static str]) -> Self {
        Self {
            modules,
            found: Vec::new(),
        }
    }

    fn record(&mut self, segments: &[String], line: usize) {
        if let [root, module, ..] = segments
            && matches!(root.as_str(), "core" | "std" | "alloc")
            && self.modules.contains(&module.as_str())
        {
            self.found.push((segments.join("::"), line));
        }
    }

    fn use_tree(&mut self, prefix: &mut Vec<String>, tree: &UseTree) {
        let leaf = |this: &mut Self, prefix: &mut Vec<String>, name: String, line: usize| {
            prefix.push(name);
            this.record(prefix, line);
            prefix.pop();
        };
        match tree {
            UseTree::Path(path) => {
                prefix.push(path.ident.to_string());
                self.use_tree(prefix, &path.tree);
                prefix.pop();
            }
            UseTree::Name(name) => leaf(
                self,
                prefix,
                name.ident.to_string(),
                name.ident.span().start().line,
            ),
            UseTree::Rename(rename) => leaf(
                self,
                prefix,
                rename.ident.to_string(),
                rename.ident.span().start().line,
            ),
            UseTree::Glob(glob) => leaf(
                self,
                prefix,
                "*".to_string(),
                glob.star_token.span.start().line,
            ),
            UseTree::Group(group) => {
                for tree in &group.items {
                    self.use_tree(prefix, tree);
                }
            }
        }
    }
}

impl<'ast> Visit<'ast> for StdPaths {
    fn visit_path(&mut self, path: &'ast syn::Path) {
        let segments: Vec<String> = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect();
        self.record(&segments, path.span().start().line);
        syn::visit::visit_path(self, path);
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        self.use_tree(&mut Vec::new(), &item.tree);
    }
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
    /// Each route into a tag store ([`TAG_STORE_ROUTES`]) named, by name and
    /// line. Doc text is a literal, never a name.
    tag_routes: Vec<(String, usize)>,
    /// Each bucket accessor ([`BUCKET_ACCESSORS`]) named, by name and line.
    bucket_reads: Vec<(String, usize)>,
    /// Each name of [`ALLOCATOR_NAMES`], by name and line.
    allocators: Vec<(String, usize)>,
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
                    if TAG_STORE_ROUTES.contains(&name.as_str()) {
                        self.tag_routes
                            .push((name.clone(), ident.span().start().line));
                    }
                    if BUCKET_ACCESSORS.contains(&name.as_str()) {
                        self.bucket_reads
                            .push((name.clone(), ident.span().start().line));
                    }
                    if ALLOCATOR_NAMES.contains(&name.as_str()) {
                        self.allocators
                            .push((name.clone(), ident.span().start().line));
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
        let index = self.modules.len();
        self.module(
            &file.shown,
            &file.module_dir,
            module_path,
            (parent, test_only),
            (1, file.lines),
            &file.syntax.items,
        );
        // A file's inner attributes (`#![feature(..)]`) are its module's own
        // code, though no item carries them.
        let mut inner = Scanned::default();
        for attr in &file.syntax.attrs {
            inner.scan(attr.to_token_stream());
        }
        self.modules[index].allocators.extend(inner.allocators);
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
            sync_paths: Vec::new(),
            thread_paths: Vec::new(),
            tag_routes: Vec::new(),
            bucket_reads: Vec::new(),
            allocators: Vec::new(),
            boundary_sites: Vec::new(),
        });
        let mut own = Scanned::default();
        let mut sync = StdPaths::new(&["sync"]);
        let mut threads = StdPaths::new(&["thread"]);
        let mut alloc_paths = StdPaths::new(&["alloc"]);
        let mut boundaries = BoundarySites::default();
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
                    sync.visit_item(other);
                    threads.visit_item(other);
                    alloc_paths.visit_item(other);
                    boundaries.visit_item(other);
                    self.test_items(file, &module_path, other, &mut test_items);
                }
            }
        }
        self.unsafe_macros.extend(own.unsafe_macros);
        let shipped = |found: Vec<(String, usize)>| -> Vec<(String, usize)> {
            found
                .into_iter()
                .filter(|(_, line)| {
                    !test_items
                        .iter()
                        .any(|&(start, end)| start <= *line && *line <= end)
                })
                .collect()
        };
        let statics = shipped(own.statics);
        let sync_paths = shipped(sync.found);
        let thread_paths = shipped(threads.found);
        let tag_routes = shipped(own.tag_routes);
        let bucket_reads = shipped(own.bucket_reads);
        let allocators = shipped(
            own.allocators
                .into_iter()
                .chain(
                    alloc_paths
                        .found
                        .into_iter()
                        .filter(|(path, _)| path.ends_with("::Allocator")),
                )
                .collect(),
        );
        let boundary_sites: Vec<BoundarySite> = boundaries
            .found
            .into_iter()
            .filter(|site| {
                !test_items
                    .iter()
                    .any(|&(start, end)| start <= site.line && site.line <= end)
            })
            .collect();
        let record = &mut self.modules[index];
        record.unsafe_tokens = own.unsafe_tokens;
        record.invoked = own.invoked;
        record.test_items = test_items;
        record.statics = statics;
        record.sync_paths = sync_paths;
        record.thread_paths = thread_paths;
        record.tag_routes = tag_routes;
        record.bucket_reads = bucket_reads;
        record.allocators = allocators;
        record.boundary_sites = boundary_sites;
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

    /// The census's rows (`dcbor_census`), one per module.
    fn rows(&self) -> Vec<CensusModule> {
        self.modules
            .iter()
            .enumerate()
            .map(|(index, module)| CensusModule {
                file: module.file.clone(),
                module: module.path.clone(),
                start: module.start,
                end: module.end,
                holds_unsafe: self.holds_unsafe(index),
                tainted: self.tainted(index),
                test: self.test(index),
                test_items: module.test_items.clone(),
            })
            .collect()
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
    let rows = census.rows();
    let cfgs = cfg_rows(root).unwrap_or_else(|faults| panic!("{faults:#?}"));
    assert!(
        cfgs.iter()
            .any(|cfg| cfg.file == "src/sync.rs" && cfg.predicate == "all (loom , shuttle)"),
        "the census records the checker guard's predicate"
    );
    let configuration = "census";
    assert_eq!(
        dcbor_census::parse(&dcbor_census::render(configuration, &rows, &cfgs)),
        Ok((configuration.to_string(), rows.clone(), cfgs.clone())),
        "the census reads back as written"
    );
    if let Some(output) = std::env::var(OUTPUT)
        .ok()
        .filter(|output| !output.is_empty())
    {
        dcbor_record::publish(
            &output,
            &dcbor_census::render(&dcbor_record::recording_configuration(), &rows, &cfgs),
        );
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

/// No shipped code keeps state in a static. Miri reports memory still
/// allocated when a run ends only when no static reaches it, so an
/// allocation a static holds is a leak no Miri run can see; and state a
/// static keeps is shared by every operation of the process, so an outcome
/// would depend on what ran before it. The tag store is the caller's,
/// passed to what reads it (`diag.rs`, `dump.rs`), never the crate's. A
/// static added anywhere, a function's included, or a `thread_local!`,
/// fails here.
#[test]
fn no_shipped_code_keeps_state_in_a_static() {
    let census = census(Path::new(env!("CARGO_MANIFEST_DIR")));
    assert!(census.tree.faults.is_empty(), "{:#?}", census.tree.faults);
    assert_eq!(
        shipped_statics(&census),
        Vec::<(String, String)>::new(),
        "shipped code keeps state in a static: Miri cannot report a leak it holds"
    );
}

/// Where a shipped module of `crate::bounded` names a route into a tag
/// store ([`TAG_STORE_ROUTES`]), by module path and name.
fn bounded_tag_routes(census: &Census) -> Vec<(String, String)> {
    census
        .modules
        .iter()
        .enumerate()
        .filter(|&(index, module)| {
            !census.test(index)
                && (module.path == "crate::bounded" || module.path.starts_with("crate::bounded::"))
        })
        .flat_map(|(_, module)| {
            module
                .tag_routes
                .iter()
                .map(|(name, _)| (module.path.clone(), name.clone()))
        })
        .collect()
}

/// The bounded engine reaches no tag store: a store is the caller's, reached
/// only through a name of [`TAG_STORE_ROUTES`], and no shipped module of
/// `crate::bounded` names one. A bounded outcome is a function of its input
/// and its policy alone, never of what any store registers.
#[test]
fn no_bounded_module_reaches_a_tag_store() {
    let census = census(Path::new(env!("CARGO_MANIFEST_DIR")));
    assert!(census.tree.faults.is_empty(), "{:#?}", census.tree.faults);
    assert_eq!(
        bounded_tag_routes(&census),
        Vec::<(String, String)>::new(),
        "a bounded module reaches a tag store"
    );
}

/// The route check's pass and fail scenarios: a store's type, a store
/// registered and a summary taken in a bounded module, and in one nested
/// beneath it, are found; the same names in a module outside
/// `crate::bounded`, in a bounded module's test-only item, in a test-only
/// bounded module and in doc text are not.
#[test]
fn the_tag_store_check_finds_every_route_from_the_bounded_engine_and_nothing_else() {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("tag_store_census_tree");
    if root.exists() {
        fs::remove_dir_all(&root).expect("the previous fixture tree is removable");
    }
    let src = root.join("src");
    fs::create_dir_all(src.join("bounded")).expect("the fixture tree is writable");
    for (name, source) in [
        ("lib.rs", "mod bounded;\nmod diag;\n"),
        (
            "bounded.rs",
            "mod encoding;\n\
             #[cfg(test)]\nmod checks { fn probe(t: &TagsStore) {} }\n\
             /// Names no TagsStore: doc text.\n\
             pub fn named(cbor: &CBOR) -> String {\n\
             \x20   let mut tags = TagsStore::default();\n\
             \x20   register_tags_in(&mut tags).ok();\n\
             \x20   cbor.summary(&tags)\n\
             }\n\
             #[cfg(test)]\n\
             fn fixture() -> DiagFormatOpts<'static> { DiagFormatOpts::default() }\n",
        ),
        (
            "bounded/encoding.rs",
            "pub fn noted(o: HexFormatOpts<'_>) -> HexFormatOpts<'_> { o }\n",
        ),
        (
            "diag.rs",
            "pub fn annotated(c: &CBOR, t: &dyn TagsStoreTrait) -> String { c.diagnostic_annotated(t) }\n",
        ),
    ] {
        fs::write(src.join(name), source).expect("the fixture tree is writable");
    }
    let scanned = census(&root);
    assert!(scanned.tree.faults.is_empty(), "{:#?}", scanned.tree.faults);
    let found = |module: &str, name: &str| (module.to_string(), name.to_string());
    assert_eq!(
        bounded_tag_routes(&scanned),
        vec![
            found("crate::bounded", "TagsStore"),
            found("crate::bounded", "register_tags_in"),
            found("crate::bounded", "summary"),
            found("crate::bounded::encoding", "HexFormatOpts"),
            found("crate::bounded::encoding", "HexFormatOpts"),
        ]
    );
}

/// Where shipped code outside [`BUCKET_TRAVERSAL`] names a bucket accessor
/// ([`BUCKET_ACCESSORS`]), by module path and name.
fn bucket_reads_outside_the_traversal(census: &Census) -> Vec<(String, String)> {
    census
        .modules
        .iter()
        .enumerate()
        .filter(|&(index, module)| !census.test(index) && module.path != BUCKET_TRAVERSAL)
        .flat_map(|(_, module)| {
            module
                .bucket_reads
                .iter()
                .map(|(name, _)| (module.path.clone(), name.clone()))
        })
        .collect()
}

/// Only the engine's one bucket traversal reads a hash table's buckets: no
/// other shipped module names a bucket accessor, so no source, schema
/// implementation or engine path inspects a control its window did not
/// admit. The traversal itself reads them.
#[test]
fn only_the_bucket_traversal_reads_buckets() {
    let census = census(Path::new(env!("CARGO_MANIFEST_DIR")));
    assert!(census.tree.faults.is_empty(), "{:#?}", census.tree.faults);
    assert_eq!(
        bucket_reads_outside_the_traversal(&census),
        Vec::<(String, String)>::new(),
        "read buckets only through encoding::buckets::BucketCursor"
    );
    let traversal = census
        .modules
        .iter()
        .find(|module| module.path == BUCKET_TRAVERSAL)
        .expect("the census has the bucket traversal");
    for accessor in BUCKET_ACCESSORS {
        assert!(
            traversal
                .bucket_reads
                .iter()
                .any(|(name, _)| name == accessor),
            "the traversal names {accessor}: {:?}",
            traversal.bucket_reads
        );
    }
}

/// The bucket check's pass and fail scenarios: a group scan in an engine
/// module and a bucket read in a module outside `crate::bounded` are found;
/// every accessor in the traversal's own module, one in a test-only item and
/// one named only in doc text are not.
#[test]
fn the_bucket_check_finds_every_read_outside_the_traversal_and_nothing_else() {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("bucket_census_tree");
    if root.exists() {
        fs::remove_dir_all(&root).expect("the previous fixture tree is removable");
    }
    let src = root.join("src");
    fs::create_dir_all(src.join("bounded").join("encoding")).expect("the fixture tree is writable");
    for (name, source) in [
        ("lib.rs", "mod bounded;\nmod symbolic;\n"),
        ("bounded.rs", "pub mod encoding;\n"),
        (
            "bounded/encoding.rs",
            "pub mod buckets;\n\
             /// Reads no bucket_state: doc text.\n\
             pub fn scanned(t: &T) -> Option<usize> { t.next_full_bucket(0, 64) }\n\
             #[cfg(test)]\n\
             fn probe(t: &T) { t.get_bucket(0); }\n",
        ),
        (
            "bounded/encoding/buckets.rs",
            "pub fn all(t: &T) { t.next_full_bucket(0, 1); t.get_bucket(0); t.bucket_state(0); }\n",
        ),
        ("symbolic.rs", "pub fn peek(m: &M) { m.get_bucket(1); }\n"),
    ] {
        fs::write(src.join(name), source).expect("the fixture tree is writable");
    }
    let scanned = census(&root);
    assert!(scanned.tree.faults.is_empty(), "{:#?}", scanned.tree.faults);
    let found = |module: &str, name: &str| (module.to_string(), name.to_string());
    assert_eq!(
        bucket_reads_outside_the_traversal(&scanned),
        vec![
            found("crate::bounded::encoding", "next_full_bucket"),
            found("crate::symbolic", "get_bucket"),
        ]
    );
}

/// Where shipped code names a way to allocate other than through the global
/// allocator ([`Module::allocators`]), by module path and name.
fn foreign_allocators(census: &Census) -> Vec<(String, String)> {
    census
        .modules
        .iter()
        .enumerate()
        .filter(|&(index, _)| !census.test(index))
        .flat_map(|(_, module)| {
            module
                .allocators
                .iter()
                .map(|(name, _)| (module.path.clone(), name.clone()))
        })
        .collect()
}

/// The library allocates memory only through the global allocator: no
/// shipped code defines or installs one, enables the allocator API or names
/// the standard library's `Allocator`. The crate's own `Allocator` grants
/// permits, never memory, so no allocator handed to a scope can allocate.
/// This is what the physical witness rests on: a global heap observer sees
/// every physical allocation the library makes, natively and under Miri,
/// and inside a model checker, whose runtime allocates on the same threads,
/// nothing could attribute them (`src/sync/models.rs`; the support crate's
/// `pipeline::Unwitnessed`).
#[test]
fn the_library_allocates_only_through_the_global_allocator() {
    let census = census(Path::new(env!("CARGO_MANIFEST_DIR")));
    assert!(census.tree.faults.is_empty(), "{:#?}", census.tree.faults);
    assert_eq!(
        foreign_allocators(&census),
        Vec::<(String, String)>::new(),
        "shipped code allocates past the global allocator: the heap observer would not see it"
    );
}

/// The allocator check's pass and fail scenarios: a global allocator
/// installed, the allocator API enabled and the standard library's
/// `Allocator` named are found; the global allocator's own functions, the
/// crate's own `Allocator`, a test-only global allocator and a name in doc
/// text are not.
#[test]
fn the_allocator_check_finds_every_allocator_past_the_global_one_and_nothing_else() {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("allocator_census_tree");
    if root.exists() {
        fs::remove_dir_all(&root).expect("the previous fixture tree is removable");
    }
    let src = root.join("src");
    fs::create_dir_all(&src).expect("the fixture tree is writable");
    for (name, source) in [
        (
            "lib.rs",
            "#![feature(allocator_api)]\nmod engine;\nmod policy;\n",
        ),
        (
            "engine.rs",
            "struct Counting;\n\
             unsafe impl core::alloc::GlobalAlloc for Counting {}\n\
             #[global_allocator]\nstatic HEAP: Counting = Counting;\n\
             pub fn boxed<A: std::alloc::Allocator>(a: A) {}\n\
             /// Never a GlobalAlloc: doc text.\n\
             pub fn raw(l: core::alloc::Layout) { unsafe { alloc::alloc::dealloc(alloc::alloc::alloc(l), l) } }\n",
        ),
        (
            "policy.rs",
            "pub trait Allocator { fn allocate(&mut self); }\n\
             #[cfg(test)]\nmod checks { #[global_allocator] static T: super::Heap = super::Heap; }\n",
        ),
    ] {
        fs::write(src.join(name), source).expect("the fixture tree is writable");
    }
    let scanned = census(&root);
    assert!(scanned.tree.faults.is_empty(), "{:#?}", scanned.tree.faults);
    let found = |module: &str, name: &str| (module.to_string(), name.to_string());
    assert_eq!(
        foreign_allocators(&scanned),
        vec![
            found("crate", "allocator_api"),
            found("crate::engine", "GlobalAlloc"),
            found("crate::engine", "global_allocator"),
            found("crate::engine", "std::alloc::Allocator"),
        ]
    );
}

/// Every function, of a module whose own code holds `unsafe`, whose
/// comparisons and bound calls stay outside the seam, by module, function
/// (`*` for the whole module) and why: none of them derives a pointer, an
/// offset, a length or a capacity that unsafe code relies on, or each is
/// checked at compile time. Everything else in such a module goes through
/// the seam (`bounded::boundary`). An exemption whose function has no such
/// site is stale.
const BOUNDARY_EXEMPTIONS: &[(&str, &str, &str)] = &[
    (
        "crate::bounded",
        "write_extent",
        "const evaluation: a write extent checked at compile time (E0080)",
    ),
    (
        "crate::bounded",
        "permit_bytes",
        "const evaluation: a permit's size checked at compile time (E0080)",
    ),
    (
        "crate::bounded",
        "covering",
        "bound arithmetic: units covering a count, no pointer",
    ),
    (
        "crate::bounded",
        "owned_growth",
        "bound arithmetic: the doubling policy over counts, no pointer",
    ),
    (
        "crate::bounded",
        "next_rise",
        "bound arithmetic: a binary search over a monotone bound's sizes",
    ),
    (
        "crate::bounded",
        "then",
        "bound composition: a peak as the larger of two",
    ),
    (
        "crate::bounded",
        "followed_by",
        "bound composition: a peak as the larger of two",
    ),
    (
        "crate::bounded",
        "checked_add",
        "bound composition: overflow is None",
    ),
    (
        "crate::bounded",
        "checked_mul",
        "bound composition: overflow is None",
    ),
    (
        "crate::bounded",
        "larger",
        "bound composition: each quantity's larger",
    ),
    (
        "crate::bounded",
        "covers",
        "a run within its bound: a check of evidence, no pointer",
    ),
    (
        "crate::bounded",
        "add",
        "checked addition refused as Overflow",
    ),
    (
        "crate::bounded",
        "mul",
        "checked multiplication refused as Overflow",
    ),
    ("crate::bounded", "integer", "an integer's sign"),
    (
        "crate::bounded",
        "reserve",
        "Owned::reserve: checked growth refused as Overflow",
    ),
    (
        "crate::bounded::policy",
        "*",
        "the policy's accounting totals and limits, no pointer derived",
    ),
    (
        "crate::bounded::decode::storage",
        "reclaim_remaining",
        "a count of cleanup calls",
    ),
    (
        "crate::bounded::decode::storage",
        "settle_remaining",
        "a count of settlement calls",
    ),
    (
        "crate::bounded::decode::storage",
        "allocate_grown",
        "checked growth refused as Overflow",
    ),
    (
        "crate::bounded::decode::cursor::publication",
        "release_remaining",
        "a count of cleanup calls",
    ),
    (
        "crate::bounded::decode::cursor",
        "of",
        "bound arithmetic of the retained parse",
    ),
    (
        "crate::bounded::decode::cursor",
        "peak_of",
        "bound arithmetic of the retained parse",
    ),
    (
        "crate::bounded::decode::cursor",
        "reclaim_remaining",
        "a count of cleanup calls",
    ),
    (
        "crate::bounded::decode::cursor",
        "advance",
        "the numeric profile (an argument above i64::MAX), checked lengths refused as Overflow, and the phase chosen by children remaining",
    ),
    (
        "crate::bounded::decode",
        "next",
        "checked indexing of a published document's children, no policy",
    ),
    (
        "crate::bounded::decode",
        "decode_with",
        "the numeric profile, checked lengths refused as Overflow, the phase chosen by children remaining, and remaining input taken before its clamp records it",
    ),
    (
        "crate::bounded::decode",
        "of",
        "bound arithmetic of the synchronous decode",
    ),
    (
        "crate::bounded::decode",
        "peak_of",
        "bound arithmetic of the synchronous decode",
    ),
    (
        "crate::bounded::decode::construction::reclamation::owned",
        "add_reference",
        "a reference count's overflow guard, no policy",
    ),
    (
        "crate::bounded::decode::construction::parse",
        "custody",
        "a re-check of a prefix the calling step records",
    ),
    (
        "crate::bounded::decode::construction::parse",
        "remaining",
        "a count of cleanup calls, observed without a policy",
    ),
    (
        "crate::bounded::decode::construction::parse",
        "detail",
        "observation without a policy",
    ),
    (
        "crate::bounded::decode::construction::construct",
        "custody",
        "a re-check of a prefix the calling step records",
    ),
    (
        "crate::bounded::decode::construction::construct",
        "remaining",
        "a count of cleanup calls, observed without a policy",
    ),
    (
        "crate::bounded::decode::construction::construct",
        "detail",
        "observation without a policy",
    ),
    (
        "crate::bounded::decode::construction::in_place",
        "checked_per_byte",
        "the construction cost algebra, overflow None",
    ),
    (
        "crate::bounded::decode::construction::in_place",
        "checked_add",
        "the construction cost algebra, overflow None",
    ),
    (
        "crate::bounded::decode::construction::in_place",
        "checked_children",
        "the construction cost algebra, overflow None",
    ),
    (
        "crate::bounded::decode::construction::in_place",
        "scalar_cost",
        "the construction cost algebra",
    ),
    (
        "crate::bounded::decode::construction::in_place::text",
        "buffer_cost",
        "the construction cost algebra",
    ),
    (
        "crate::bounded::decode::construction::in_place::vector",
        "sequence_cost",
        "the construction cost algebra",
    ),
    (
        "crate::bounded::decode::construction::in_place::vector",
        "build",
        "checked lengths refused as Overflow",
    ),
    (
        "crate::bounded::decode::construction::in_place::fields",
        "cost",
        "the construction cost algebra",
    ),
    (
        "crate::bounded::decode::construction::in_place::fields",
        "entry",
        "the construction cost algebra",
    ),
    (
        "crate::bounded::decode::construction::in_place::fields",
        "entries",
        "the construction cost algebra",
    ),
    (
        "crate::bounded::decode::construction::in_place::fields",
        "build",
        "checked lengths refused as Overflow",
    ),
    (
        "crate::bounded::decode::construction::in_place::enumeration",
        "cost",
        "the construction cost algebra",
    ),
    (
        "crate::bounded::decode::construction::in_place::enumeration",
        "selection",
        "the construction cost algebra",
    ),
    (
        "crate::bounded::decode::construction::in_place::enumeration",
        "build",
        "checked lengths refused as Overflow, and the array form's nonempty check",
    ),
    (
        "crate::bounded::decode::construction::in_place::tagged",
        "cost",
        "the construction cost algebra",
    ),
    (
        "crate::bounded::decode::construction::in_place::tagged",
        "build",
        "checked lengths refused as Overflow",
    ),
    (
        "crate::bounded::decode::construction::in_place::btree",
        "raised",
        "plan arithmetic certified for every count through 20,000 (plan_tests); its class recorded at PlanRoot",
    ),
    (
        "crate::bounded::decode::construction::in_place::btree",
        "shape",
        "plan arithmetic certified with raised",
    ),
    (
        "crate::bounded::decode::construction::in_place::btree",
        "child",
        "plan arithmetic certified with raised",
    ),
    (
        "crate::bounded::decode::construction::in_place::btree",
        "rank",
        "plan arithmetic certified with raised",
    ),
    (
        "crate::bounded::decode::construction::in_place::btree",
        "planned",
        "plan arithmetic certified with raised",
    ),
    (
        "crate::bounded::decode::construction::in_place::btree",
        "meta",
        "a re-check of a prefix the calling step records",
    ),
    (
        "crate::bounded::decode::construction::in_place::btree",
        "observe",
        "observation without a policy",
    ),
    (
        "crate::bounded::decode::construction::in_place::btree",
        "build",
        "checked lengths refused as Overflow, and run widths before their clamp records them",
    ),
    (
        "crate::bounded::decode::construction::in_place::btree",
        "compare",
        "a window's end before its clamp records it",
    ),
    (
        "crate::bounded::decode::construction::in_place::btree::cleanup",
        "remaining",
        "a count of cleanup calls",
    ),
    ("crate::map", "insert_next", "symbolic key order, no offset"),
    (
        "crate::bounded::encoding",
        "of",
        "PreparationTerms::of: bound arithmetic",
    ),
    (
        "crate::bounded::encoding",
        "walk",
        "the shape walk's counts, admitted and refused as Overflow",
    ),
    (
        "crate::bounded::encoding",
        "merged",
        "the shape walk's counts",
    ),
    (
        "crate::bounded::encoding",
        "levels",
        "bound arithmetic: merge levels of a count",
    ),
    (
        "crate::bounded::encoding",
        "tree_height",
        "bound arithmetic: a tree's height for a count",
    ),
    (
        "crate::bounded::encoding",
        "advance",
        "an entry cursor's admitted node moves against those it states (a count, admitted in units), and the instruction index, a map payload's start and the omitted gap bytes, each checked and refused as Overflow",
    ),
    (
        "crate::bounded::encoding::values",
        "instruction",
        "the numeric profile: a negative argument above i64::MAX is out of range, no offset",
    ),
    (
        "crate::bounded::decode::construction::in_place::enumeration",
        "remaining",
        "a count of cleanup calls, observed without a policy",
    ),
    (
        "crate::bounded::decode::construction::in_place::fields",
        "remaining",
        "a count of cleanup calls, observed without a policy",
    ),
    (
        "crate::bounded::decode::construction::in_place::optional",
        "remaining",
        "a count of cleanup calls, observed without a policy",
    ),
    (
        "crate::bounded::decode::construction::in_place::optional",
        "cost",
        "the construction cost algebra, overflow None",
    ),
    (
        "crate::bounded::decode::construction::in_place::stable_option",
        "remaining",
        "a count of cleanup calls, observed without a policy",
    ),
    (
        "crate::bounded::decode::construction::in_place::stable_option",
        "cost",
        "the construction cost algebra, overflow None",
    ),
    (
        "crate::bounded::decode::construction::in_place::tagged",
        "remaining",
        "a count of cleanup calls, observed without a policy",
    ),
    (
        "crate::bounded::decode::construction::in_place::vector",
        "remaining",
        "a count of cleanup calls, observed without a policy",
    ),
    (
        "crate::bounded::encoding",
        "counted_complete",
        "a counted map's declared count against its entries",
    ),
    (
        "crate::bounded::encoding",
        "plan_len",
        "a plan's length, checked",
    ),
    (
        "crate::bounded::encoding",
        "admit_stepped",
        "an admission over a count",
    ),
    (
        "crate::bounded::encoding",
        "custody",
        "a re-check of a prefix the calling step records",
    ),
    (
        "crate::bounded::encoding",
        "remaining",
        "a count of cleanup calls, observed without a policy",
    ),
    (
        "crate::bounded::encoding",
        "detail",
        "observation without a policy",
    ),
    (
        "crate::bounded::encoding::dynamic",
        "reclaim_remaining",
        "a count of cleanup calls",
    ),
    (
        "crate::bounded::encoding::dynamic",
        "compact_child",
        "the omitted gap bytes' checked subtraction, refused as PlanMismatch",
    ),
    (
        "crate::bounded::encoding::permutation",
        "step",
        "the payload's length past its base and the output offsets, checked and refused",
    ),
    (
        "crate::bounded::encoding::maps::order",
        "step",
        "the run width's checked doubling refused as Overflow",
    ),
];

/// Every violation of the boundary rule in the crate at `census` under
/// `exemptions`: a governed site of a shipped module whose own code holds
/// `unsafe` that is outside the seam and not exempted, as `module:
/// function:line: what`; any such site comparing a bound's raw limit, even
/// exempted; an exemption with no reason; and an exemption whose module or
/// function holds no such site (stale).
fn boundary_violations(census: &Census, exemptions: &[(&str, &str, &str)]) -> Vec<String> {
    let mut violations = Vec::new();
    let mut used = vec![false; exemptions.len()];
    for (index, module) in census.modules.iter().enumerate() {
        if census.test(index) || !census.holds_unsafe(index) {
            continue;
        }
        for site in &module.boundary_sites {
            let exempt = exemptions.iter().position(|&(path, function, _)| {
                path == module.path && (function == "*" || function == site.function)
            });
            if site.raw {
                // An exemption covering the function has a site; it cannot
                // excuse a bypass of the seam.
                if let Some(at) = exempt {
                    used[at] = true;
                }
                violations.push(format!(
                    "{}: {}:{}: a raw limit compared ({})",
                    module.path, site.function, site.line, site.what
                ));
            } else if let Some(at) = exempt {
                used[at] = true;
            } else {
                violations.push(format!(
                    "{}: {}:{}: {}",
                    module.path, site.function, site.line, site.what
                ));
            }
        }
    }
    for (at, &(path, function, reason)) in exemptions.iter().enumerate() {
        if reason.is_empty() {
            violations.push(format!("{path}: {function}: an exemption without a reason"));
        }
        if !used[at] {
            violations.push(format!("{path}: {function}: a stale exemption, no site"));
        }
    }
    violations
}

/// In every shipped module whose own code holds `unsafe`, each comparison
/// and bound call goes through the seam or lies in a function exempted by
/// name with its reason; no raw limit is compared; no exemption is stale
/// ([`boundary_violations`]). P2: pointer arithmetic depends on data only
/// through the boundary predicates the seam records.
#[test]
fn every_boundary_in_an_unsafe_module_goes_through_the_seam() {
    let census = census(Path::new(env!("CARGO_MANIFEST_DIR")));
    assert!(census.tree.faults.is_empty(), "{:#?}", census.tree.faults);
    let violations = boundary_violations(&census, BOUNDARY_EXEMPTIONS);
    assert!(violations.is_empty(), "{violations:#?}");
}

/// The boundary rule's pass and fail scenarios: in a module holding
/// `unsafe`, an unwrapped comparison fails; a comparison over a raw limit
/// fails even exempted; a governed call inside a macro's arguments, a
/// comparison in a `matches!` guard, a macro whose arguments are not
/// expressions, and a governed call and a comparison in a `macro_rules!`
/// body fail, and so does one in a `const fn`, which runs at run time; an
/// exemption without a reason, one naming a function with no site and one
/// naming no module fail; a `boundary!` comparison, in code or in a
/// definition's body, a comparison in a constant or a `const` block, a clamp
/// on a bound and on a local bound, an exempted call and a test-only
/// comparison pass; a module holding no `unsafe` is out of scope.
#[test]
fn the_boundary_check_finds_every_unwrapped_site_and_nothing_else() {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("boundary_census_tree");
    if root.exists() {
        fs::remove_dir_all(&root).expect("the previous fixture tree is removable");
    }
    let src = root.join("src");
    fs::create_dir_all(&src).expect("the fixture tree is writable");
    for (name, source) in [
        ("lib.rs", "mod engine;\nmod safe;\n"),
        (
            "engine.rs",
            "pub unsafe fn raw() {}\n\
             pub fn compared(a: usize, b: usize) -> bool { a < b }\n\
             pub fn exempted(a: usize) -> usize { a.min(4) }\n\
             pub fn wrapped(a: &mut A, b: usize) -> bool { boundary!(a, P, b, 4).is_lt() }\n\
             pub fn bypass(l: Bound<usize>, b: usize) -> bool { b < l.raw_limit() }\n\
             pub fn reasonless(a: usize) -> usize { a.max(1) }\n\
             pub fn clamped(a: &mut A, b: usize) -> usize {\n\
             \x20   let limit = Bound::new(P, 4);\n\
             \x20   Bound::new(P, 8).clamp(a, b) + limit.clamp(a, b)\n\
             }\n\
             #[cfg(test)]\n\
             fn probe(a: usize) -> bool { a > 1 }\n\
             pub fn macroed(a: usize) -> Option<usize> { cost!(a.checked_add(1)) }\n\
             pub fn guarded(a: Option<usize>) -> bool { matches!(a, Some(x) if x < 2) }\n\
             pub fn opaque() { places! { A: B } }\n\
             macro_rules! step { ($a:expr) => { if $a.saturating_sub(1) > 0 { boundary!(a, P, $a, 4) } } }\n\
             pub const LIMIT: usize = if 3 > 2 { 4usize.saturating_add(1) } else { 2 };\n\
             pub fn sized<T>() { const { assert!(core::mem::size_of::<T>() <= 8) } }\n\
             pub const fn runs(a: usize) -> usize { a.saturating_sub(1) }\n",
        ),
        ("safe.rs", "pub fn ignored(a: usize) -> bool { a < 2 }\n"),
    ] {
        fs::write(src.join(name), source).expect("the fixture tree is writable");
    }
    let scanned = census(&root);
    assert!(scanned.tree.faults.is_empty(), "{:#?}", scanned.tree.faults);
    assert_eq!(
        boundary_violations(
            &scanned,
            &[
                ("crate::engine", "exempted", "a limit with no pointer"),
                (
                    "crate::engine",
                    "bypass",
                    "claimed, but a raw limit is compared"
                ),
                ("crate::engine", "reasonless", ""),
                ("crate::engine", "gone", "a function with no site"),
                ("crate::other", "anything", "a module that does not exist"),
            ],
        ),
        vec![
            "crate::engine: compared:2: <".to_string(),
            "crate::engine: bypass:5: a raw limit compared (<)".to_string(),
            "crate::engine: macroed:13: checked_add".to_string(),
            "crate::engine: guarded:14: <".to_string(),
            "crate::engine: opaque:15: places!: arguments not expressions".to_string(),
            "crate::engine: <item>:16: >".to_string(),
            "crate::engine: <item>:16: saturating_sub".to_string(),
            "crate::engine: runs:19: saturating_sub".to_string(),
            "crate::engine: reasonless: an exemption without a reason".to_string(),
            "crate::engine: gone: a stale exemption, no site".to_string(),
            "crate::other: anything: a stale exemption, no site".to_string(),
        ]
    );
}

/// The files that register tags in a store and read it.
const TAG_STORE_FILES: &[&str] = &["src/tags.rs", "src/tags_store.rs"];

/// Every function of the tag store's files under `root` ([`TAG_STORE_FILES`],
/// test items excluded) whose body names a panicking macro or method
/// ([`PANICKING`]), each `file: function`. A registration the store cannot
/// take is a typed refusal through the crate's one error taxonomy
/// (`Error::UnnamedTag`, `EmptyTagName`, `ConflictingTagName`,
/// `ConflictingTagValue`), never a panic through public API.
fn panicking_registration(root: &Path) -> Vec<String> {
    let mut violations = Vec::new();
    for shown in TAG_STORE_FILES {
        let source = fs::read_to_string(root.join(shown))
            .unwrap_or_else(|error| panic!("{shown}: cannot be read: {error}"));
        let syntax = match syn::parse_file(&source) {
            Ok(syntax) => syntax,
            Err(error) => {
                violations.push(format!("{shown}: does not parse: {error}"));
                continue;
            }
        };
        let mut fns: Vec<(&syn::Signature, &syn::Block)> = Vec::new();
        collect_fns(&syntax.items, &mut fns);
        for (signature, block) in fns {
            if PANICKING
                .iter()
                .any(|token| names(block.to_token_stream(), token))
            {
                violations.push(format!("{shown}: {}", signature.ident));
            }
        }
    }
    violations
}

/// No registration or lookup of a tag store panics ([`panicking_registration`]).
#[test]
fn no_tag_registration_panics() {
    assert_eq!(
        panicking_registration(Path::new(env!("CARGO_MANIFEST_DIR"))),
        Vec::<String>::new()
    );
}

/// The registration check's pass and fail scenarios: a refusal returned
/// passes; a name unwrapped, a conflict asserted and a conflict panicked on
/// fail, in a free function and in an impl; a test-only function that
/// unwraps does not count, nor does a panic named only in doc text.
#[test]
fn the_registration_check_finds_every_panicking_registration_and_nothing_else() {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("registration_census_tree");
    if root.exists() {
        fs::remove_dir_all(&root).expect("the previous fixture tree is removable");
    }
    fs::create_dir_all(root.join("src")).expect("the fixture tree is writable");
    fs::write(
        root.join("src/tags.rs"),
        "/// Never calls panic!.\n\
         pub fn register(store: &mut TagsStore) -> Result<()> { store.insert(tag())?; Ok(()) }\n\
         pub fn named(tag: &Tag) -> String { tag.name().unwrap() }\n\
         #[cfg(test)]\n\
         fn probe(tag: &Tag) -> String { tag.name().unwrap() }\n",
    )
    .expect("the fixture tree is writable");
    fs::write(
        root.join("src/tags_store.rs"),
        "impl TagsStore {\n\
         \x20   pub fn insert(&mut self, tag: Tag) { assert!(tag.name().is_some()); }\n\
         \x20   pub fn conflict(&self) { panic!(\"conflicting name\") }\n\
         \x20   pub fn refused(&self) -> Result<()> { Err(Error::UnnamedTag(0)) }\n\
         }\n",
    )
    .expect("the fixture tree is writable");
    assert_eq!(
        panicking_registration(&root),
        vec![
            "src/tags.rs: named".to_string(),
            "src/tags_store.rs: insert".to_string(),
            "src/tags_store.rs: conflict".to_string(),
        ]
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

/// The model checker's facade: the one shipped module that names the
/// standard library's atomics (`src/sync.rs`).
const FACADE: &str = "crate::sync";

/// Where shipped code names an atomic of the standard library outside
/// [`FACADE`], by module path and path named. `Arc` is not the facade's: a
/// permit holding loom's `Arc` (two of the standard library's) would exceed
/// `PERMIT_BYTES`, so no model substitutes it, and `CBOR` derives `Eq` over
/// its own, which loom's `Arc` does not implement.
fn sync_bypasses(census: &Census) -> Vec<(String, String)> {
    census
        .modules
        .iter()
        .enumerate()
        .filter(|&(index, module)| !census.test(index) && module.path != FACADE)
        .flat_map(|(_, module)| {
            module
                .sync_paths
                .iter()
                .filter(|(path, _)| path.split("::").nth(2) == Some("atomic"))
                .map(|(path, _)| (module.path.clone(), path.clone()))
        })
        .collect()
}

/// Every atomic the library holds is named through the facade, so a model
/// checker that substitutes the facade's atomics substitutes all of them: an
/// atomic named past it would stay a real one under loom, its orderings
/// unexplored.
#[test]
fn no_library_module_names_an_atomic_past_the_facade() {
    let census = census(Path::new(env!("CARGO_MANIFEST_DIR")));
    assert!(census.tree.faults.is_empty(), "{:#?}", census.tree.faults);
    assert_eq!(
        sync_bypasses(&census),
        Vec::<(String, String)>::new(),
        "name these through crate::sync, or the models do not check them"
    );
    let facade = census
        .modules
        .iter()
        .find(|module| module.path == FACADE)
        .expect("the census has the facade");
    assert!(
        facade
            .sync_paths
            .iter()
            .any(|(path, _)| path == "core::sync::atomic::AtomicPtr"),
        "the facade names core's atomics: {:?}",
        facade.sync_paths
    );
}

/// The facade check's pass and fail scenarios: an atomic in an expression
/// and in a nested `use` group are found; the facade's own atomics, an
/// `Arc` and a `Mutex` of the standard library, a path through the facade
/// and a test-only item are not.
#[test]
fn the_facade_check_finds_every_atomic_past_it_and_nothing_else() {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("sync_census_tree");
    if root.exists() {
        fs::remove_dir_all(&root).expect("the previous fixture tree is removable");
    }
    let src = root.join("src");
    fs::create_dir_all(&src).expect("the fixture tree is writable");
    for (name, source) in [
        (
            "lib.rs",
            "mod sync;\nmod bounded;\nmod symbolic;\n\
             pub fn fenced() { core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst) }\n",
        ),
        (
            "sync.rs",
            "pub(crate) use core::sync::atomic::{AtomicBool, Ordering};\n",
        ),
        (
            "bounded.rs",
            "use alloc::{sync::Arc, vec::Vec};\n\
             use std::sync::{atomic::AtomicU64, Mutex};\n\
             use crate::sync::AtomicBool;\n\
             #[cfg(test)]\n\
             fn probe() -> std::sync::atomic::AtomicUsize { todo!() }\n",
        ),
        ("symbolic.rs", "use std::sync::Arc;\n"),
    ] {
        fs::write(src.join(name), source).expect("the fixture tree is writable");
    }
    let scanned = census(&root);
    assert!(scanned.tree.faults.is_empty(), "{:#?}", scanned.tree.faults);
    let found = |module: &str, path: &str| (module.to_string(), path.to_string());
    assert_eq!(
        sync_bypasses(&scanned),
        vec![
            found("crate", "core::sync::atomic::fence"),
            found("crate", "core::sync::atomic::Ordering::SeqCst"),
            found("crate::bounded", "std::sync::atomic::AtomicU64"),
        ]
    );
}

/// Where shipped code names the standard library's `thread`, by module path
/// and path named: a thread's identity, its spawning, its locals.
fn thread_names(census: &Census) -> Vec<(String, String)> {
    census
        .modules
        .iter()
        .enumerate()
        .filter(|&(index, _)| !census.test(index))
        .flat_map(|(_, module)| {
            module
                .thread_paths
                .iter()
                .map(|(path, _)| (module.path.clone(), path.clone()))
        })
        .collect()
}

/// The state threads share, by file and type: the decode scope's queue,
/// links, flags and counter (`Reclaimer`), its reference count beside it
/// (`ScopeHead`), each queued record's link and published cells (`Header`),
/// and the storage counters every reservation and shared policy holds
/// (`Counters`, `policy.rs`; a `Limits` itself is one operation's, never
/// shared: `share` builds a fresh one over the same counters). FF-13's
/// premise that no per-worker identity enters the protocol is checked over
/// exactly these.
const PROTOCOL: &[(&str, &str)] = &[
    (
        "src/bounded/decode/construction/reclamation.rs",
        "Reclaimer",
    ),
    ("src/bounded/decode/construction/reclamation.rs", "Header"),
    (
        "src/bounded/decode/construction/reclamation/owned.rs",
        "ScopeHead",
    ),
    ("src/bounded/policy.rs", "Counters"),
];

/// A record's dispatch, written once by its acquisition before the record is
/// published and only read after: fixed per record type, no shared state.
const DISPATCH: &[&str] = &["Advance", "Finish"];

/// The build's family types by their aliases (`src/sync.rs`): what a type
/// not generic over the family holds of it.
const FAMILY_ALIASES: &[&str] = &[
    "AtomicBool",
    "AtomicUsize",
    "AtomicPtr",
    "AtomicU64",
    "Plain",
];

/// Fields written only before their holder is shared, then only read, each
/// by type and field: the release observer, which `observe_releases` sets
/// through `Arc::get_mut`, refused once the counters are shared.
const CONFIGURED: &[(&str, &str)] = &[("Counters", "release_observer")];

/// Arrays of the family's primitives indexed by a fixed enumeration, never by
/// a worker, each by type and field: the boundary valuations reached, one
/// bitmask per `Predicate` (`Predicate::COUNT` of them), which any thread
/// only ORs into. An array is otherwise refused: indexed by a worker, it
/// would carry the worker's identity into the protocol.
const ENUMERATED: &[(&str, &str)] = &[("Counters", "reached")];

/// Every field of the `protocol` types under `root` that is not protocol
/// state the atomics family carries, each `file: Type.field: type`, and
/// every protocol type that is gone. A field is the family's (its type's
/// first segment is the family parameter `S`, or one of the build's
/// [`FAMILY_ALIASES`]: a flag, a counter, a link, a total or a published
/// cell), another protocol type, a marker (`PhantomData`, `PhantomPinned`),
/// a record's [`DISPATCH`], or a field [`CONFIGURED`] before sharing. So the
/// state threads share is the family's primitives alone, which the models
/// substitute and the orderings the models explore govern; a plain field
/// shared between threads, or a worker's index or identity, would be none of
/// these.
fn protocol_state(root: &Path, protocol: &[(&str, &str)]) -> Vec<String> {
    let names: Vec<&str> = protocol.iter().map(|(_, name)| *name).collect();
    let mut violations = Vec::new();
    for (file, name) in protocol {
        let source = fs::read_to_string(root.join(file))
            .unwrap_or_else(|error| panic!("{file}: cannot be read: {error}"));
        let syntax = match syn::parse_file(&source) {
            Ok(syntax) => syntax,
            Err(error) => {
                violations.push(format!("{file}: does not parse: {error}"));
                continue;
            }
        };
        let found = syntax.items.iter().find_map(|item| match item {
            Item::Struct(definition) if definition.ident == name => Some(definition),
            _ => None,
        });
        let Some(definition) = found else {
            violations.push(format!("{file}: no protocol type {name}"));
            continue;
        };
        for (at, field) in definition.fields.iter().enumerate() {
            let field_name = field
                .ident
                .as_ref()
                .map_or_else(|| at.to_string(), ToString::to_string);
            let first = match &field.ty {
                syn::Type::Path(path) => path
                    .path
                    .segments
                    .first()
                    .map(|segment| segment.ident.to_string()),
                _ => None,
            };
            let configured = CONFIGURED.contains(&(*name, field_name.as_str()));
            // An enumerated array holds the family's primitives alone.
            let enumerated = ENUMERATED.contains(&(*name, field_name.as_str()))
                && matches!(&field.ty, syn::Type::Array(array)
                if matches!(&*array.elem, syn::Type::Path(element)
                    if element.path.segments.first().is_some_and(|segment| {
                        FAMILY_ALIASES.contains(&segment.ident.to_string().as_str())
                            || segment.ident == "S"
                    })));
            let allowed = configured
                || enumerated
                || first.as_deref().is_some_and(|first| {
                    first == "S"
                        || first == "PhantomData"
                        || first == "PhantomPinned"
                        || FAMILY_ALIASES.contains(&first)
                        || names.contains(&first)
                        || DISPATCH.contains(&first)
                });
            if !allowed {
                violations.push(format!(
                    "{file}: {name}.{field_name}: {}",
                    field.ty.to_token_stream()
                ));
            }
        }
    }
    violations
}

/// FF-13's premises that workers are interchangeable and no per-worker
/// identity enters the protocol, structurally: the protocol's state is its
/// atomics family's primitives alone ([`protocol_state`]), and no shipped
/// code names a thread, so nothing the protocol does can depend on which
/// thread does it. The dynamic half runs every assignment of a scope's
/// operations to threads (`reclamation/owned.rs`,
/// `which_thread_performs_an_operation_changes_nothing`).
#[test]
fn the_protocol_holds_no_worker_identity() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    assert_eq!(protocol_state(root, PROTOCOL), Vec::<String>::new());
    let census = census(root);
    assert!(census.tree.faults.is_empty(), "{:#?}", census.tree.faults);
    assert_eq!(
        thread_names(&census),
        Vec::<(String, String)>::new(),
        "shipped code names a thread"
    );
}

/// The premise checks' pass and fail scenarios: a family primitive, a
/// marker, a nested protocol type and a record's dispatch pass; a plain
/// counter, a worker's index and a reference fail, and a protocol type that
/// is gone is reported. A thread named in shipped code, through a path, a
/// `use` of the module and a group, is found; one in a test-only item and
/// another module's `thread` are not.
#[test]
fn the_premise_checks_find_identity_and_plain_state_and_nothing_else() {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("protocol_census_tree");
    if root.exists() {
        fs::remove_dir_all(&root).expect("the previous fixture tree is removable");
    }
    let src = root.join("src");
    fs::create_dir_all(&src).expect("the fixture tree is writable");
    fs::write(
        src.join("queue.rs"),
        "struct Reclaimer<A, S: Atomics> {\n\
             head: S::Link<Header<A, S>>,\n\
             stepping: S::Flag,\n\
             confined: PhantomData<*mut ()>,\n\
             steps: usize,\n\
             worker: [S::Counter; 4],\n\
         }\n\
         struct Header<A, S: Atomics> {\n\
             next: S::Link<Header<A, S>>,\n\
             advance: Advance<A>,\n\
             custody: S::Cell<Holder>,\n\
             owner: &'static Reclaimer<A, S>,\n\
             _pin: PhantomPinned,\n\
         }\n\
         struct ScopeHead<A, S: Atomics> {\n\
             owner: Reclaimer<A, S>,\n\
             references: S::Counter,\n\
         }\n\
         struct Counters {\n\
             live: AtomicU64,\n\
             release_observer: Option<fn(u64)>,\n\
             reached: [AtomicU64; 12],\n\
             thread: Option<std::thread::ThreadId>,\n\
         }\n",
    )
    .expect("the fixture tree is writable");
    let fixture = [
        ("src/queue.rs", "Reclaimer"),
        ("src/queue.rs", "Header"),
        ("src/queue.rs", "ScopeHead"),
        ("src/queue.rs", "Counters"),
        ("src/queue.rs", "Scope"),
    ];
    assert_eq!(
        protocol_state(&root, &fixture),
        vec![
            "src/queue.rs: Reclaimer.steps: usize".to_string(),
            "src/queue.rs: Reclaimer.worker: [S :: Counter ; 4]".to_string(),
            "src/queue.rs: Header.owner: & 'static Reclaimer < A , S >".to_string(),
            "src/queue.rs: Counters.thread: Option < std :: thread :: ThreadId >".to_string(),
            "src/queue.rs: no protocol type Scope".to_string(),
        ]
    );
    fs::write(
        src.join("lib.rs"),
        "mod queue;\n\
         mod other;\n\
         use std::thread;\n\
         pub fn who() -> std::thread::ThreadId { thread::current().id() }\n\
         pub use std::thread::{self as threads, yield_now};\n\
         #[cfg(test)]\n\
         fn probe() { std::thread::sleep(core::time::Duration::ZERO) }\n",
    )
    .expect("the fixture tree is writable");
    fs::write(
        src.join("other.rs"),
        "pub mod thread { pub fn current() {} }\npub fn f() { thread::current() }\n",
    )
    .expect("the fixture tree is writable");
    let scanned = census(&root);
    assert!(scanned.tree.faults.is_empty(), "{:#?}", scanned.tree.faults);
    let found = |path: &str| ("crate".to_string(), path.to_string());
    assert_eq!(
        thread_names(&scanned),
        vec![
            found("std::thread"),
            found("std::thread::ThreadId"),
            found("std::thread::self"),
            found("std::thread::yield_now"),
            (
                "crate::queue".to_string(),
                "std::thread::ThreadId".to_string()
            ),
        ]
    );
}

/// The cost algebra's items deleted with its panicking copy: costs compose
/// through `ResourceBound::checked_add` and `checked_mul` and the
/// `ConstructionCost::checked_*` methods alone.
const DELETED_COST_ITEMS: &[&str] = &["plus", "times", "sum", "product"];

/// The tokens through which a cost composition could panic instead of
/// refusing.
const PANICKING: &[&str] = &[
    "panic",
    "assert",
    "assert_eq",
    "unwrap",
    "expect",
    "unreachable",
];

/// Every function of the construction cost algebra under `root`
/// (`src/bounded/decode/construction/in_place.rs` and its modules, test
/// items excluded) that could panic on a cost instead of refusing it: a
/// `const fn` returning a cost (`ConstructionCost` or `ResourceBound`, bare
/// or in an `Option`) whose body names a panicking macro or method, and any
/// of the [`DELETED_COST_ITEMS`] defined again. A cost that does not fit in
/// `u64` is `None`: a compile error in a `COST` item (`const_cost!`), a
/// refusal at run time, never a panic.
fn panicking_costs(root: &Path) -> Vec<String> {
    let base = root.join("src/bounded/decode/construction");
    let mut files = BTreeSet::new();
    files.insert(base.join("in_place.rs"));
    source_tree::sources(&base.join("in_place"), &mut files);
    let mut violations = Vec::new();
    for file in files {
        let shown = file
            .strip_prefix(root)
            .unwrap_or(&file)
            .display()
            .to_string();
        let source = fs::read_to_string(&file)
            .unwrap_or_else(|error| panic!("{}: cannot be read: {error}", file.display()));
        let syntax = match syn::parse_file(&source) {
            Ok(syntax) => syntax,
            Err(error) => {
                violations.push(format!("{shown}: does not parse: {error}"));
                continue;
            }
        };
        let mut fns: Vec<(&syn::Signature, &syn::Block)> = Vec::new();
        collect_fns(&syntax.items, &mut fns);
        for (signature, block) in fns {
            let name = signature.ident.to_string();
            if DELETED_COST_ITEMS.contains(&name.as_str()) {
                violations.push(format!(
                    "{shown}: {name}: a deleted cost item, defined again"
                ));
            }
            let returns_cost = match &signature.output {
                syn::ReturnType::Type(_, ty) => {
                    let shown = ty.to_token_stream().to_string();
                    shown.contains("ConstructionCost") || shown.contains("ResourceBound")
                }
                syn::ReturnType::Default => false,
            };
            if signature.constness.is_some()
                && returns_cost
                && PANICKING
                    .iter()
                    .any(|token| names(block.to_token_stream(), token))
            {
                violations.push(format!("{shown}: {name}: a cost that can panic"));
            }
        }
    }
    violations
}

/// Every function of `items`, free or in an impl, inline modules descended
/// into, test-only items excluded.
fn collect_fns<'a>(items: &'a [Item], fns: &mut Vec<(&'a syn::Signature, &'a syn::Block)>) {
    for item in items {
        if source_tree::test_only(item_attrs(item)).unwrap_or(false) {
            continue;
        }
        match item {
            Item::Fn(function) => fns.push((&function.sig, &function.block)),
            Item::Impl(implementation) => {
                for member in &implementation.items {
                    if let ImplItem::Fn(function) = member
                        && !source_tree::test_only(&function.attrs).unwrap_or(false)
                    {
                        fns.push((&function.sig, &function.block));
                    }
                }
            }
            Item::Mod(module) => {
                if let Some((_, items)) = &module.content {
                    collect_fns(items, fns);
                }
            }
            _ => {}
        }
    }
}

/// No construction cost can panic: every composition is checked, its
/// overflow `None` ([`panicking_costs`]).
#[test]
fn no_construction_cost_panics_on_overflow() {
    assert_eq!(
        panicking_costs(Path::new(env!("CARGO_MANIFEST_DIR"))),
        Vec::<String>::new()
    );
}

/// The cost check's pass and fail scenarios: a checked composition passes;
/// a const cost that panics, one that unwraps, and the deleted `plus`
/// defined again fail; a test-only panicking cost and a non-const function
/// returning a cost do not count.
#[test]
fn the_cost_check_finds_every_panicking_cost_and_nothing_else() {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("cost_census_tree");
    if root.exists() {
        fs::remove_dir_all(&root).expect("the previous fixture tree is removable");
    }
    let base = root.join("src/bounded/decode/construction");
    fs::create_dir_all(base.join("in_place")).expect("the fixture tree is writable");
    fs::write(
        base.join("in_place.rs"),
        "pub const fn plus(a: ResourceBound, b: ResourceBound) -> ResourceBound { a }\n\
         pub const fn checked(a: ResourceBound) -> Option<ResourceBound> { a.checked_mul(2) }\n\
         pub const fn summed(a: u64) -> ResourceBound {\n\
         \x20   match a.checked_add(1) { Some(_) => todo(), None => panic!(\"overflow\") }\n\
         }\n\
         pub fn at_run_time(a: ResourceBound) -> ResourceBound { a.checked_mul(2).unwrap() }\n\
         #[cfg(test)]\n\
         const fn probe(a: ResourceBound) -> ResourceBound { a.checked_mul(2).unwrap() }\n",
    )
    .expect("the fixture tree is writable");
    fs::write(
        base.join("in_place/text.rs"),
        "impl Cost {\n\
         \x20   pub const fn wrapped(self) -> ConstructionCost { self.checked().expect(\"fits\") }\n\
         }\n",
    )
    .expect("the fixture tree is writable");
    // Files in path order, by component: the directory `in_place` before
    // the file `in_place.rs`.
    assert_eq!(
        panicking_costs(&root),
        vec![
            "src/bounded/decode/construction/in_place/text.rs: wrapped: a cost that can panic"
                .to_string(),
            "src/bounded/decode/construction/in_place.rs: plus: a deleted cost item, defined again"
                .to_string(),
            "src/bounded/decode/construction/in_place.rs: summed: a cost that can panic"
                .to_string(),
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
    Ok(cfg_predicates(source)?
        .into_iter()
        .filter_map(|(name, predicate, _)| {
            let shown = predicate.to_string();
            (names(predicate, "miri")
                && !(name == "cfg_attr" && shown.replace(' ', "") == "miri,ignore"))
                .then(|| format!("{name}({shown})"))
        })
        .collect())
}

/// Where `source`, one file's text, names a model checker (`loom`,
/// `shuttle`) in a `cfg`: in `cfg(..)`, `cfg!(..)` or `cfg_attr(..)`, each
/// rendered with its line. A feature merely named `loom` is a string, not
/// the cfg, and is not found.
fn checker_cfgs(source: &str) -> Result<Vec<(String, usize)>, String> {
    Ok(cfg_predicates(source)?
        .into_iter()
        .filter_map(|(name, predicate, line)| {
            let shown = predicate.to_string();
            (names(predicate.clone(), "loom") || names(predicate, "shuttle"))
                .then(|| (format!("{name}({shown})"), line))
        })
        .collect())
}

/// Every `cfg` predicate in `source`: the form's name (`cfg`, `cfg!`,
/// `cfg_attr`), the predicate's tokens (a `cfg_attr`'s whole group, its
/// attributes after its predicate) and the line of the form, as `cfg(..)`,
/// `cfg!(..)` and `cfg_attr(..)` write them, in order.
fn cfg_predicates(source: &str) -> Result<Vec<(String, TokenStream, usize)>, String> {
    let tokens: TokenStream = source
        .parse()
        .map_err(|error| format!("does not lex: {error}"))?;
    let mut found = Vec::new();
    collect_cfg_predicates(tokens, &mut found);
    Ok(found)
}

fn collect_cfg_predicates(tokens: TokenStream, found: &mut Vec<(String, TokenStream, usize)>) {
    let trees: Vec<TokenTree> = tokens.into_iter().collect();
    for (at, tree) in trees.iter().enumerate() {
        match tree {
            TokenTree::Group(group) => collect_cfg_predicates(group.stream(), found),
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
                if let Some(predicate) = predicate {
                    // The macro form named apart: its predicate is an
                    // expression, each value of which is a path.
                    let form = if matches!(trees.get(at + 1), Some(TokenTree::Punct(_))) {
                        "cfg!".to_string()
                    } else {
                        name
                    };
                    found.push((form, predicate, ident.span().start().line));
                }
            }
            TokenTree::Ident(_) | TokenTree::Punct(_) | TokenTree::Literal(_) => {}
        }
    }
}

/// The predicate of a `cfg_attr`'s group: its tokens before the first
/// top-level comma, the attributes after it dropped.
fn cfg_attr_predicate(group: TokenStream) -> TokenStream {
    group
        .into_iter()
        .take_while(|tree| !matches!(tree, TokenTree::Punct(punct) if punct.as_char() == ','))
        .collect()
}

/// Every `cfg` predicate of the crate's sources and its tests (the files
/// built in the crate's own feature domains; the derive crate has features
/// of its own), as census rows: its file relative to `root`, line, form and
/// whole expression. A file that does not lex is a fault.
fn cfg_rows(root: &Path) -> Result<Vec<dcbor_census::CensusCfg>, Vec<String>> {
    let mut files = BTreeSet::new();
    source_tree::sources(&root.join("src"), &mut files);
    source_tree::sources(&root.join("tests"), &mut files);
    let mut rows = Vec::new();
    let mut faults = Vec::new();
    for file in files {
        let shown = file
            .strip_prefix(root)
            .unwrap_or(&file)
            .display()
            .to_string();
        let source = fs::read_to_string(&file)
            .unwrap_or_else(|error| panic!("{}: cannot be read: {error}", file.display()));
        match cfg_predicates(&source) {
            Ok(found) => {
                for (name, predicate, line) in found {
                    let (form, predicate) = match name.as_str() {
                        "cfg" => (dcbor_census::CfgForm::Attribute, predicate),
                        "cfg!" => (dcbor_census::CfgForm::Macro, predicate),
                        _ => (dcbor_census::CfgForm::Attr, cfg_attr_predicate(predicate)),
                    };
                    rows.push(dcbor_census::CensusCfg {
                        file: shown.clone(),
                        line,
                        form,
                        predicate: predicate.to_string(),
                    });
                }
            }
            Err(error) => faults.push(format!("{shown}: {error}")),
        }
    }
    if faults.is_empty() {
        Ok(rows)
    } else {
        Err(faults)
    }
}

/// The cfg rows' pass and fail scenarios: an attribute, a macro and a
/// `cfg_attr` in the sources and the tests are each recorded with its whole
/// expression, the `cfg_attr` cut at its predicate; a predicate inside a
/// string literal is not one, and the derive crate is not read.
#[test]
fn the_cfg_rows_record_every_predicate_whole_and_nothing_else() {
    use dcbor_census::{CensusCfg, CfgForm};
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("cfg_census_tree");
    if root.exists() {
        fs::remove_dir_all(&root).expect("the previous fixture tree is removable");
    }
    for directory in ["src", "tests", "dcbor-derive/src"] {
        fs::create_dir_all(root.join(directory)).expect("the fixture tree is writable");
    }
    for (name, source) in [
        (
            "src/lib.rs",
            "#[cfg(all(test, feature = \"std\"))]\nmod checks {}\n\
             pub fn wide() -> bool { cfg!(feature = \"num-bigint\") }\n\
             pub const TEXT: &str = \"#[cfg(windows)]\";\n",
        ),
        (
            "tests/a.rs",
            "#[cfg_attr(miri, ignore)]\n#[test]\nfn slow() {}\n",
        ),
        (
            "dcbor-derive/src/lib.rs",
            "#[cfg(feature = \"derived\")]\nfn f() {}\n",
        ),
    ] {
        fs::write(root.join(name), source).expect("the fixture tree is writable");
    }
    let row = |file: &str, line, form, predicate: &str| CensusCfg {
        file: file.to_string(),
        line,
        form,
        predicate: predicate.to_string(),
    };
    assert_eq!(
        cfg_rows(&root),
        Ok(vec![
            row(
                "src/lib.rs",
                1,
                CfgForm::Attribute,
                "all (test , feature = \"std\")"
            ),
            row("src/lib.rs", 3, CfgForm::Macro, "feature = \"num-bigint\""),
            row("tests/a.rs", 1, CfgForm::Attr, "miri"),
        ])
    );
}

/// Every source file of the crate, its tests and the derive crate.
fn crate_sources(root: &Path) -> BTreeSet<PathBuf> {
    let mut files = BTreeSet::new();
    source_tree::sources(&root.join("src"), &mut files);
    source_tree::sources(&root.join("tests"), &mut files);
    source_tree::sources(&root.join("dcbor-derive").join("src"), &mut files);
    files
}

/// Whether `file` is the checker seam: `src/sync.rs` or a file of its
/// module tree, `src/sync/`.
fn in_checker_seam(root: &Path, file: &Path) -> bool {
    file == root.join("src").join("sync.rs") || file.starts_with(root.join("src").join("sync"))
}

/// The functions that enter a model checker's execution outside the seam,
/// each by its file, relative to the crate root, and its function, from the
/// one table of them (`dcbor_model_bounds::ENTRY_POINTS`), which the gate
/// runs from too: under a checker's cfg the library holds that checker's
/// atomics in every build (`src/sync.rs`), and they exist only inside a
/// model, so a test that runs under the cfg enters one. Which test enters a
/// model is a choice of the tests, never behaviour of the library.
fn model_entry_points() -> Vec<(&'static str, &'static str)> {
    dcbor_model_bounds::ENTRY_POINTS
        .iter()
        .map(|entry| (entry.file, entry.function))
        .collect()
}

/// Each function of `source`, a test file, by name and line span, its
/// attributes included, inline modules descended into.
fn function_spans(source: &str) -> Result<Vec<(String, usize, usize)>, String> {
    let file = syn::parse_file(source).map_err(|error| format!("does not parse: {error}"))?;
    let mut spans = Vec::new();
    collect_function_spans(&file.items, &mut spans);
    Ok(spans)
}

fn collect_function_spans(items: &[Item], spans: &mut Vec<(String, usize, usize)>) {
    for item in items {
        match item {
            Item::Fn(function) => {
                let span = function.span();
                spans.push((
                    function.sig.ident.to_string(),
                    span.start().line,
                    span.end().line,
                ));
            }
            Item::Mod(module) => {
                if let Some((_, items)) = &module.content {
                    collect_function_spans(items, spans);
                }
            }
            _ => {}
        }
    }
}

/// Every place the crate at `root` names a model checker in a `cfg` that is
/// not allowed there, and every declared entry point of `entry_points` that
/// names none: no violation when the checker cfg appears in the library
/// only at its seam (`src/sync.rs` and `src/sync/`), which substitutes the
/// atomics by type, so no accounting or protocol code branches on the
/// build; in the tests only inside a declared entry point; and in the
/// derive crate nowhere. A declared entry point that is gone or enters no
/// model is stale and reported too.
fn checker_sites(root: &Path, entry_points: &[(&str, &str)]) -> Vec<String> {
    let mut violations = Vec::new();
    let mut entered: BTreeSet<(String, String)> = BTreeSet::new();
    for file in crate_sources(root) {
        if in_checker_seam(root, &file) {
            continue;
        }
        let relative = file.strip_prefix(root).unwrap_or(&file).to_path_buf();
        let shown = relative.display().to_string();
        let source = fs::read_to_string(&file)
            .unwrap_or_else(|error| panic!("{}: cannot be read: {error}", file.display()));
        let found = match checker_cfgs(&source) {
            Ok(found) => found,
            Err(error) => {
                violations.push(format!("{shown}: {error}"));
                continue;
            }
        };
        if found.is_empty() {
            continue;
        }
        let declared: Vec<&str> = entry_points
            .iter()
            .filter(|(path, _)| relative.starts_with("tests") && Path::new(path) == relative)
            .map(|(_, name)| *name)
            .collect();
        let spans = if declared.is_empty() {
            Vec::new()
        } else {
            match function_spans(&source) {
                Ok(spans) => spans,
                Err(error) => {
                    violations.push(format!("{shown}: {error}"));
                    continue;
                }
            }
        };
        for (cfg, line) in found {
            let entry = spans.iter().find(|(name, start, end)| {
                declared.contains(&name.as_str()) && *start <= line && line <= *end
            });
            match entry {
                Some((name, ..)) => {
                    entered.insert((shown.clone(), name.clone()));
                }
                None => violations.push(format!("{shown}:{line}: {cfg}")),
            }
        }
    }
    for (path, name) in entry_points {
        if !entered.contains(&((*path).to_string(), (*name).to_string())) {
            violations.push(format!(
                "{path}: {name}: a declared model entry point that enters no model"
            ));
        }
    }
    violations
}

/// A model checker is named in a `cfg` only at the seam and at the declared
/// entry points, and every declared entry point enters a model
/// ([`checker_sites`]).
#[test]
fn checkers_are_named_only_at_the_seam_and_the_declared_entry_points() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let violations = checker_sites(root, &model_entry_points());
    assert!(violations.is_empty(), "{violations:#?}");
}

/// The checker scan's pass and fail scenarios: a checker named in an
/// attribute, nested in `all(..)`, in `cfg!` and in `cfg_attr` is found with
/// its line; a feature named `loom` (a string) and the identifier outside a
/// `cfg` are not. Over a tree: the seam's file and a declared entry point's
/// function pass; a library module, the derive crate and an undeclared test
/// function fail; a declared entry point that enters no model, and one that
/// does not exist, are stale.
#[test]
fn the_checker_check_finds_every_checker_cfg_and_nothing_else() {
    assert_eq!(
        checker_cfgs(
            "#[cfg(loom)] fn a() {}\n\
             #[cfg(all(test, shuttle))] mod b {}\n\
             fn c() -> bool { cfg!(loom) }\n\
             #[cfg_attr(shuttle, allow(unused))] fn d() {}\n\
             #[cfg(feature = \"loom\")] fn e() {}\n\
             fn f() { let loom = 1; let _ = loom; }\n"
        ),
        Ok(vec![
            ("cfg(loom)".to_string(), 1),
            ("cfg(all (test , shuttle))".to_string(), 2),
            ("cfg!(loom)".to_string(), 3),
            ("cfg_attr(shuttle , allow (unused))".to_string(), 4),
        ])
    );
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("checker_census_tree");
    if root.exists() {
        fs::remove_dir_all(&root).expect("the previous fixture tree is removable");
    }
    for directory in ["src", "tests", "dcbor-derive/src"] {
        fs::create_dir_all(root.join(directory)).expect("the fixture tree is writable");
    }
    for (name, source) in [
        ("src/lib.rs", "mod sync;\n#[cfg(loom)]\nfn branched() {}\n"),
        ("src/sync.rs", "#[cfg(loom)]\npub(crate) enum Loom {}\n"),
        (
            "tests/models.rs",
            "#[test]\n\
             fn entered() {\n\
             \x20   #[cfg(loom)]\n\
             \x20   loom_model();\n\
             }\n\
             fn undeclared() { if cfg!(shuttle) {} }\n\
             fn idle() {}\n",
        ),
        (
            "dcbor-derive/src/lib.rs",
            "#[cfg(shuttle)]\nfn derived() {}\n",
        ),
    ] {
        fs::write(root.join(name), source).expect("the fixture tree is writable");
    }
    assert_eq!(
        checker_sites(
            &root,
            &[
                ("tests/models.rs", "entered"),
                ("tests/models.rs", "idle"),
                ("tests/models.rs", "missing"),
            ],
        ),
        vec![
            "dcbor-derive/src/lib.rs:1: cfg(shuttle)".to_string(),
            "src/lib.rs:2: cfg(loom)".to_string(),
            "tests/models.rs:6: cfg!(shuttle)".to_string(),
            "tests/models.rs: idle: a declared model entry point that enters no model".to_string(),
            "tests/models.rs: missing: a declared model entry point that enters no model"
                .to_string(),
        ]
    );
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    assert!(in_checker_seam(
        crate_root,
        &crate_root.join("src").join("sync.rs")
    ));
    assert!(in_checker_seam(
        crate_root,
        &crate_root.join("src").join("sync").join("models.rs")
    ));
    assert!(!in_checker_seam(
        crate_root,
        &crate_root.join("src").join("bounded").join("policy.rs")
    ));
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
    let files = crate_sources(root);
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
            "cfg!(miri)".to_string(),
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
