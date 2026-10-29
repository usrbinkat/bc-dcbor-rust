//! Charge identity over this crate's source: every charge rule (`Unit`,
//! `Capped`, `Scan`, `Rate`, defined in `src/bounded.rs`) is constructed
//! only where the compiler evaluates it once: a `const` or `static` item, an
//! associated `const`, a `const { .. }` block, or the body of a `const fn`.
//! An admission site then reads a named definition and the bound reads the
//! same one. A rule built inline at a site is a second definition of its
//! rate, invisible to the attribution checks when its amounts equal the
//! first's; this check refuses it and names the site.
//!
//! The walk follows the module tree from `src/lib.rs` as the compiler does
//! (`source_tree`, shared with every source check of this crate), every
//! feature-gated module included, and fails on any source file it does not
//! reach. Code compiled only under `cfg(test)` is exempt: its probes build
//! rules of their own. The rule types are `pub(crate)`, so neither derived
//! code nor another crate can construct one: this crate's source is the
//! whole domain.

mod source_tree;

use std::fs;
use std::mem;
use std::path::{Path, PathBuf};

use proc_macro2::{Spacing, TokenStream, TokenTree};
use source_tree::{Tree, test_only};
use syn::visit::{self, Visit};
use syn::{
    Attribute, Expr, ExprConst, ExprPath, ExprStruct, ImplItem, ImplItemConst, ImplItemFn, Item,
    ItemConst, ItemFn, ItemImpl, ItemMod, ItemStatic, ItemTrait, ItemType, Local, Macro, TraitItem,
    TraitItemConst, TraitItemFn, Type, UseRename,
};

/// The charge rule types.
const RULES: [&str; 4] = ["Unit", "Capped", "Scan", "Rate"];

/// Their constructors.
const CONSTRUCTORS: [&str; 3] = ["new", "of", "based"];

/// The fix a construction outside a constant is reported with.
const FIX: &str = "define the rule once as a `const` item (or return it from a `const fn`) \
                   and admit through that definition";

/// What an alias or a renamed import of a rule type is reported with.
const HIDDEN: &str = "hiding its constructions from this check; name the rule type itself";

/// One walk over a module tree: the shared tree, whose faults hold what the
/// walk could not resolve and every violation found, in the order found, and
/// how many constructions it found in constant contexts.
struct Walk {
    tree: Tree,
    defined: usize,
}

impl Walk {
    fn new(root: PathBuf) -> Self {
        Self {
            tree: Tree::new(root),
            defined: 0,
        }
    }

    /// Check the module file at `path`, declared at `scope`.
    fn module_file(&mut self, path: &Path, scope: Vec<String>, exempt: bool) {
        let Some(file) = self.tree.load(path) else {
            return;
        };
        Checker::new(self, file.shown, file.module_dir, scope, exempt).visit_file(&file.syntax);
    }
}

/// The walk of one module file.
struct Checker<'w> {
    walk: &'w mut Walk,
    file: String,
    /// Where the current module's out-of-line children are.
    module_dir: PathBuf,
    /// The items enclosing the current node, outermost first.
    scope: Vec<String>,
    /// Whether the current node is evaluated by the compiler: a `const` or
    /// `static` item, a `const` block, a `const fn` body.
    constant: bool,
    /// Whether `Self` names a rule type here.
    rule_self: bool,
    /// Whether the current node is compiled only under `cfg(test)`.
    exempt: bool,
}

impl<'w> Checker<'w> {
    fn new(
        walk: &'w mut Walk,
        file: String,
        module_dir: PathBuf,
        scope: Vec<String>,
        exempt: bool,
    ) -> Self {
        Self {
            walk,
            file,
            module_dir,
            scope,
            constant: false,
            rule_self: false,
            exempt,
        }
    }

    /// Where the current node is: its file and the items enclosing it.
    fn location(&self) -> String {
        let scope = if self.scope.is_empty() {
            "crate root".to_string()
        } else {
            self.scope.join(" > ")
        };
        format!("{}: {scope}", self.file)
    }

    fn located(&self, what: &str) -> String {
        format!("{}: {what}", self.location())
    }

    /// A violation in the code itself, which test-only code may commit.
    fn report(&mut self, what: &str) {
        if !self.exempt {
            let located = self.located(what);
            self.walk.tree.faults.push(located);
        }
    }

    /// A failure of the walk, reported in test-only code too: whatever it
    /// fails to see, it cannot check.
    fn fault(&mut self, what: &str) {
        let located = self.located(what);
        self.walk.tree.faults.push(located);
    }

    /// A rule constructed as `shown`, written directly or `within` the
    /// tokens of a macro.
    fn construction(&mut self, shown: &str, within: Option<&str>) {
        if self.exempt {
            return;
        }
        if self.constant {
            self.walk.defined += 1;
            return;
        }
        let site = match within {
            Some(within) => format!("`{shown}` in the tokens of {within}"),
            None => format!("`{shown}`"),
        };
        self.report(&format!(
            "{site} constructs a charge rule outside a constant; {FIX}"
        ));
    }

    fn scoped(&mut self, name: String, f: impl FnOnce(&mut Self)) {
        self.scope.push(name);
        f(self);
        self.scope.pop();
    }

    fn context(&mut self, constant: bool, f: impl FnOnce(&mut Self)) {
        let outer = mem::replace(&mut self.constant, constant);
        f(self);
        self.constant = outer;
    }

    /// `f` under the exemption `attrs` give it. A `cfg` that does not parse
    /// is reported and exempts nothing.
    fn attributed(&mut self, attrs: &[Attribute], f: impl FnOnce(&mut Self)) {
        let test = match test_only(attrs) {
            Ok(test) => test,
            Err(error) => {
                self.report(&format!(
                    "a `cfg` attribute does not parse ({error}); the check cannot tell \
                     whether this code is test-only"
                ));
                false
            }
        };
        let outer = self.exempt;
        self.exempt |= test;
        f(self);
        self.exempt = outer;
    }

    fn tokens(&mut self, tokens: &TokenStream, within: &str) {
        let mut found = Vec::new();
        constructions(tokens.clone(), &mut found);
        for shown in found {
            self.construction(&shown, Some(within));
        }
    }

    fn path(&mut self, path: &syn::Path) {
        let segments: Vec<String> = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect();
        if let [.., owner, constructor] = segments.as_slice()
            && CONSTRUCTORS.contains(&constructor.as_str())
            && (RULES.contains(&owner.as_str()) || (owner == "Self" && self.rule_self))
        {
            self.construction(&format!("{owner}::{constructor}"), None);
        }
    }

    /// The out-of-line module `module`, at exactly one of its two paths
    /// ([`Tree::declared`]).
    fn declared(&mut self, module: &ItemMod) {
        let location = self.location();
        let module_dir = self.module_dir.clone();
        let found = self
            .walk
            .tree
            .declared(&module_dir, module, |what| format!("{location}: {what}"));
        if let Some(path) = found {
            let scope = self.scope.clone();
            let exempt = self.exempt;
            self.walk.module_file(&path, scope, exempt);
        }
    }
}

/// The name of `ty` when it is a path.
fn type_name(ty: &Type) -> Option<String> {
    match ty {
        Type::Path(path) => path
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string()),
        _ => None,
    }
}

/// Every rule construction in `tokens`, a macro's: a rule type, `::`, an
/// optional turbofish and `::`, then a constructor.
fn constructions(tokens: TokenStream, found: &mut Vec<String>) {
    let trees: Vec<TokenTree> = tokens.into_iter().collect();
    for (at, tree) in trees.iter().enumerate() {
        match tree {
            TokenTree::Group(group) => constructions(group.stream(), found),
            TokenTree::Ident(ident) => {
                let name = ident.to_string();
                if RULES.contains(&name.as_str())
                    && let Some(constructor) = constructor_after(&trees[at + 1..])
                {
                    found.push(format!("{name}::{constructor}"));
                }
            }
            TokenTree::Punct(_) | TokenTree::Literal(_) => {}
        }
    }
}

/// `rest` after a leading `::`.
fn separated(rest: &[TokenTree]) -> Option<&[TokenTree]> {
    match rest {
        [TokenTree::Punct(first), TokenTree::Punct(second), tail @ ..]
            if first.as_char() == ':'
                && first.spacing() == Spacing::Joint
                && second.as_char() == ':' =>
        {
            Some(tail)
        }
        _ => None,
    }
}

/// The constructor named after a rule type, its turbofish skipped.
fn constructor_after(rest: &[TokenTree]) -> Option<String> {
    let mut rest = separated(rest)?;
    if let Some(TokenTree::Punct(open)) = rest.first()
        && open.as_char() == '<'
    {
        let mut depth = 0usize;
        let mut close = None;
        for (at, tree) in rest.iter().enumerate() {
            let TokenTree::Punct(punct) = tree else {
                continue;
            };
            // The `>` of an `->` closes nothing.
            let arrow = at > 0
                && matches!(&rest[at - 1], TokenTree::Punct(previous)
                    if previous.as_char() == '-' && previous.spacing() == Spacing::Joint);
            match punct.as_char() {
                '<' => depth += 1,
                '>' if !arrow => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(at);
                        break;
                    }
                }
                _ => {}
            }
        }
        rest = separated(&rest[close? + 1..])?;
    }
    match rest.first() {
        Some(TokenTree::Ident(ident)) if CONSTRUCTORS.contains(&ident.to_string().as_str()) => {
            Some(ident.to_string())
        }
        _ => None,
    }
}

impl<'ast> Visit<'ast> for Checker<'_> {
    fn visit_item(&mut self, item: &'ast Item) {
        let attrs = match item {
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
            Item::Verbatim(tokens) => {
                self.tokens(tokens, "an item syn does not interpret");
                return;
            }
            _ => {
                self.fault("an item kind this check does not model; extend `visit_item`");
                return;
            }
        };
        self.attributed(attrs, |this| visit::visit_item(this, item));
    }

    fn visit_impl_item(&mut self, item: &'ast ImplItem) {
        let attrs = match item {
            ImplItem::Const(item) => &item.attrs,
            ImplItem::Fn(item) => &item.attrs,
            ImplItem::Type(item) => &item.attrs,
            ImplItem::Macro(item) => &item.attrs,
            ImplItem::Verbatim(tokens) => {
                self.tokens(tokens, "an impl item syn does not interpret");
                return;
            }
            _ => {
                self.fault("an impl item kind this check does not model; extend `visit_impl_item`");
                return;
            }
        };
        self.attributed(attrs, |this| visit::visit_impl_item(this, item));
    }

    fn visit_trait_item(&mut self, item: &'ast TraitItem) {
        let attrs = match item {
            TraitItem::Const(item) => &item.attrs,
            TraitItem::Fn(item) => &item.attrs,
            TraitItem::Type(item) => &item.attrs,
            TraitItem::Macro(item) => &item.attrs,
            TraitItem::Verbatim(tokens) => {
                self.tokens(tokens, "a trait item syn does not interpret");
                return;
            }
            _ => {
                self.fault(
                    "a trait item kind this check does not model; extend `visit_trait_item`",
                );
                return;
            }
        };
        self.attributed(attrs, |this| visit::visit_trait_item(this, item));
    }

    fn visit_local(&mut self, local: &'ast Local) {
        self.attributed(&local.attrs, |this| visit::visit_local(this, local));
    }

    fn visit_item_mod(&mut self, module: &'ast ItemMod) {
        let name = module.ident.to_string();
        self.scoped(format!("mod {name}"), |this| match &module.content {
            Some(_) => {
                let inner = this.module_dir.join(&name);
                let outer = mem::replace(&mut this.module_dir, inner);
                visit::visit_item_mod(this, module);
                this.module_dir = outer;
            }
            None => this.declared(module),
        });
    }

    fn visit_item_const(&mut self, item: &'ast ItemConst) {
        self.scoped(format!("const {}", item.ident), |this| {
            this.context(true, |this| visit::visit_item_const(this, item));
        });
    }

    fn visit_impl_item_const(&mut self, item: &'ast ImplItemConst) {
        self.scoped(format!("const {}", item.ident), |this| {
            this.context(true, |this| visit::visit_impl_item_const(this, item));
        });
    }

    fn visit_trait_item_const(&mut self, item: &'ast TraitItemConst) {
        self.scoped(format!("const {}", item.ident), |this| {
            this.context(true, |this| visit::visit_trait_item_const(this, item));
        });
    }

    fn visit_item_static(&mut self, item: &'ast ItemStatic) {
        self.scoped(format!("static {}", item.ident), |this| {
            this.context(true, |this| visit::visit_item_static(this, item));
        });
    }

    fn visit_expr_const(&mut self, block: &'ast ExprConst) {
        self.context(true, |this| visit::visit_expr_const(this, block));
    }

    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        let constant = item.sig.constness.is_some();
        self.scoped(format!("fn {}", item.sig.ident), |this| {
            this.context(constant, |this| visit::visit_item_fn(this, item));
        });
    }

    fn visit_impl_item_fn(&mut self, item: &'ast ImplItemFn) {
        let constant = item.sig.constness.is_some();
        self.scoped(format!("fn {}", item.sig.ident), |this| {
            this.context(constant, |this| visit::visit_impl_item_fn(this, item));
        });
    }

    fn visit_trait_item_fn(&mut self, item: &'ast TraitItemFn) {
        let constant = item.sig.constness.is_some();
        self.scoped(format!("fn {}", item.sig.ident), |this| {
            this.context(constant, |this| visit::visit_trait_item_fn(this, item));
        });
    }

    fn visit_item_impl(&mut self, item: &'ast ItemImpl) {
        let name = type_name(&item.self_ty);
        let rule = name.as_deref().is_some_and(|name| RULES.contains(&name));
        let shown = name.unwrap_or_else(|| "a non-path type".to_string());
        self.scoped(format!("impl {shown}"), |this| {
            let outer = mem::replace(&mut this.rule_self, rule);
            visit::visit_item_impl(this, item);
            this.rule_self = outer;
        });
    }

    fn visit_item_trait(&mut self, item: &'ast ItemTrait) {
        self.scoped(format!("trait {}", item.ident), |this| {
            visit::visit_item_trait(this, item);
        });
    }

    fn visit_item_type(&mut self, item: &'ast ItemType) {
        if type_name(&item.ty).is_some_and(|name| RULES.contains(&name.as_str())) {
            self.report(&format!(
                "`type {}` aliases a charge rule type, {HIDDEN}",
                item.ident
            ));
        }
        visit::visit_item_type(self, item);
    }

    fn visit_use_rename(&mut self, rename: &'ast UseRename) {
        let name = rename.ident.to_string();
        if RULES.contains(&name.as_str()) {
            self.report(&format!(
                "`use .. {name} as {}` renames a charge rule type, {HIDDEN}",
                rename.rename
            ));
        }
        visit::visit_use_rename(self, rename);
    }

    fn visit_expr_path(&mut self, expr: &'ast ExprPath) {
        self.path(&expr.path);
        visit::visit_expr_path(self, expr);
    }

    fn visit_expr_struct(&mut self, expr: &'ast ExprStruct) {
        if let Some(last) = expr.path.segments.last() {
            let name = last.ident.to_string();
            if RULES.contains(&name.as_str()) || (name == "Self" && self.rule_self) {
                self.construction(&format!("{name} {{ .. }}"), None);
            }
        }
        visit::visit_expr_struct(self, expr);
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        let name: Vec<String> = mac
            .path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect();
        self.tokens(&mac.tokens, &format!("`{}!`", name.join("::")));
        visit::visit_macro(self, mac);
    }

    fn visit_expr(&mut self, expr: &'ast Expr) {
        if let Expr::Verbatim(tokens) = expr {
            self.tokens(tokens, "an expression syn does not interpret");
        }
        visit::visit_expr(self, expr);
    }
}

/// The walk of the crate at `root` from `src/lib.rs`, every source file under
/// `src` it did not reach reported.
fn crate_walk(root: &Path) -> Walk {
    let mut walk = Walk::new(root.to_path_buf());
    walk.module_file(&root.join("src").join("lib.rs"), Vec::new(), false);
    walk.tree.unreached();
    walk
}

#[test]
fn every_charge_rule_of_this_crate_is_defined_in_a_constant() {
    let walk = crate_walk(Path::new(env!("CARGO_MANIFEST_DIR")));
    assert!(walk.tree.faults.is_empty(), "{:#?}", walk.tree.faults);
    assert!(
        walk.defined > 0,
        "no charge rule was found in a constant: the walk saw none of src/bounded.rs's \
         definitions"
    );
}

/// What one fixture file violates, and how many constructions it defines in
/// constants.
fn checked(source: &str) -> (Vec<String>, usize) {
    let file =
        syn::parse_file(source).unwrap_or_else(|error| panic!("the fixture parses: {error}"));
    let mut walk = Walk::new(PathBuf::from("fixtures"));
    Checker::new(
        &mut walk,
        "fixture.rs".to_string(),
        PathBuf::from("fixtures"),
        Vec::new(),
        false,
    )
    .visit_file(&file);
    (walk.tree.faults, walk.defined)
}

fn outside(scope: &str, site: &str) -> String {
    format!("fixture.rs: {scope}: {site} constructs a charge rule outside a constant; {FIX}")
}

/// The pass scenario: every constant context, the constructors' own
/// `const fn` bodies, macros within constants, and test-only probes.
#[test]
fn rules_defined_in_constants_pass() {
    let (violations, defined) = checked(
        r#"
        const VALUE: Unit<P> = Unit::new(P::Values, 1, 0);
        struct Engine;
        impl Engine {
            const SCAN: Scan<P> = Scan::new(P::Payload, 1);
        }
        const fn counting() -> Rate<P> {
            Rate::based(P::Ordering, WriteWork::new(512, 0), WriteWork::new(3, 32))
        }
        static COPY: Capped<P> = Capped::new(P::Copies, 1, 64);
        fn admit(budget: &mut B) {
            const { Unit::<P>::of::<u64>(P::Values) }.admit(budget);
            VALUE.admit(budget);
        }
        impl<P> Unit<P> {
            const fn one(place: P) -> Self {
                Self::new(place, 1, 0)
            }
        }
        const LISTED: [Unit<P>; 1] = listed!(Unit::new(P::Values, 2, 0));
        #[cfg(test)]
        mod tests {
            fn probe() { Unit::new(Probe::Only, 2, 3); }
        }
        #[cfg(all(test, feature = "std"))]
        fn probe() { let _ = vec![Rate::new(P::Values, 1, 0)]; }
        "#,
    );
    assert_eq!(violations, Vec::<String>::new());
    assert_eq!(defined, 7, "every definition in a constant is seen");
}

/// The fail scenarios: each construction outside a constant, each way of
/// hiding one, and a `cfg` the check cannot read, with its diagnostic.
#[test]
fn rules_outside_constants_fail_naming_their_site() {
    let cases: [(&str, Vec<String>); 11] = [
        (
            "fn admit(budget: &mut B) { Unit::new(P::Values, 1, 0).admit(budget); }",
            vec![outside("fn admit", "`Unit::new`")],
        ),
        (
            "impl Engine { fn admit(&self) { let rule = || Scan::new(P::Payload, 1); } }",
            vec![outside("impl Engine > fn admit", "`Scan::new`")],
        ),
        (
            "const fn outer() { fn inner() -> Rate<P> { Rate::new(P::Ordering, 1, 0) } }",
            vec![outside("fn outer > fn inner", "`Rate::new`")],
        ),
        (
            "fn admit() { let rules = vec![Capped::new(P::Copies, 1, 64)]; }",
            vec![outside("fn admit", "`Capped::new` in the tokens of `vec!`")],
        ),
        (
            "fn admit() { Rate::<P>::based(P::Ordering, BASE, EACH); }",
            vec![outside("fn admit", "`Rate::based`")],
        ),
        (
            "#[cfg(not(test))] fn admit() { Unit::of::<u64>(P::Values); }",
            vec![outside("fn admit", "`Unit::of`")],
        ),
        (
            "#[cfg(any(test, feature = \"std\"))] fn admit() { Unit::new(P::Values, 1, 0); }",
            vec![outside("fn admit", "`Unit::new`")],
        ),
        (
            "impl<P> Capped<P> { fn widened(self) -> Self { Self::new(self.place, 1, 128) } }",
            vec![outside("impl Capped > fn widened", "`Self::new`")],
        ),
        (
            "fn admit() { let rule = Unit { place: P::Values, values: 1, bytes: 0 }; }",
            vec![outside("fn admit", "`Unit { .. }`")],
        ),
        (
            "use crate::bounded::Unit as Charge;",
            vec![format!(
                "fixture.rs: crate root: `use .. Unit as Charge` renames a charge rule \
                 type, {HIDDEN}"
            )],
        ),
        (
            "type Charge = Unit<P>;",
            vec![format!(
                "fixture.rs: crate root: `type Charge` aliases a charge rule type, {HIDDEN}"
            )],
        ),
    ];
    for (source, expected) in cases {
        let (violations, _) = checked(source);
        assert_eq!(violations, expected, "{source}");
    }
    // A `cfg` the check cannot read exempts nothing: its code is checked.
    let (violations, _) = checked("#[cfg(all(test,,))] fn admit() { Unit::new(P::Values, 1, 0); }");
    assert_eq!(violations.len(), 2, "{violations:#?}");
    assert!(
        violations[0].starts_with("fixture.rs: crate root: a `cfg` attribute does not parse (")
            && violations[0].ends_with("); the check cannot tell whether this code is test-only"),
        "{violations:#?}"
    );
    assert_eq!(violations[1], outside("fn admit", "`Unit::new`"));
}

/// The walk's own pass and fail scenarios over a module tree: a module
/// reached and checked, a test-only module reached and exempt, a declared
/// module with no file, and a source file no module declares.
#[test]
fn the_walk_reaches_every_source_file_or_fails() {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("charge_identity_walk");
    if root.exists() {
        fs::remove_dir_all(&root).expect("the previous fixture tree is removable");
    }
    let src = root.join("src");
    fs::create_dir_all(&src).expect("the fixture tree is writable");
    for (name, source) in [
        (
            "lib.rs",
            "mod present;\nmod missing;\n#[cfg(test)]\nmod tests;\n",
        ),
        ("present.rs", "fn admit() { Unit::new(P::Values, 1, 0); }\n"),
        ("tests.rs", "fn probe() { Unit::new(Probe::Only, 2, 3); }\n"),
        (
            "stray.rs",
            "const VALUE: Unit<P> = Unit::new(P::Values, 1, 0);\n",
        ),
    ] {
        fs::write(src.join(name), source).expect("the fixture tree is writable");
    }
    let walk = crate_walk(&root);
    let candidates = [src.join("missing.rs"), src.join("missing").join("mod.rs")];
    assert_eq!(
        walk.tree.faults,
        vec![
            format!(
                "src/present.rs: mod present > fn admit: `Unit::new` constructs a charge \
                 rule outside a constant; {FIX}"
            ),
            format!("src/lib.rs: mod missing: `mod missing` resolves to none of {candidates:?}"),
            "src/stray.rs: is not reached from src/lib.rs, so this check cannot see what it \
             compiles"
                .to_string(),
        ]
    );
    assert_eq!(
        walk.defined, 0,
        "test-only and unreached files define nothing"
    );
}
