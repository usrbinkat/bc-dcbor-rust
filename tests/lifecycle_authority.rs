//! Structural witnesses for the shared lifecycle's authority boundaries.
mod source_tree;

use proc_macro2::{Delimiter, TokenStream, TokenTree};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use syn::visit::{self, Visit};

#[derive(Default)]
struct Authority {
    functions: BTreeMap<String, usize>,
    budgets: usize,
    forbidden: Vec<String>,
    classifications: bool,
}

impl<'ast> Visit<'ast> for Authority {
    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        let name = item.sig.ident.to_string();
        *self.functions.entry(name.clone()).or_default() += 1;
        if matches!(item.vis, syn::Visibility::Public(_)) && name != "recorded_run_short" {
            self.recording_capacity(&item.sig);
        }
        if matches!(item.vis, syn::Visibility::Public(_))
            // classes::emit classifies a borrowed position; it is not the
            // root lifecycle API that executes a writer.
            && !(self.classifications && name == "emit")
            && matches!(
                name.as_str(),
                "scheduled"
                    | "scheduled_scope"
                    | "scheduled_step"
                    | "drive"
                    | "drive_within"
                    | "drive_faulted"
                    | "drive_faulted_observed"
                    | "resume"
                    | "resume_within"
                    | "finish"
                    | "finish_within"
                    | "fail"
                    | "fail_within"
                    | "suspend"
                    | "suspend_within"
                    | "emit"
                    | "emit_turn"
                    | "measured"
                    | "recorded_run_capacity"
            )
        {
            self.forbidden.push(name);
        }
        visit::visit_item_fn(self, item);
    }

    fn visit_item_struct(&mut self, item: &'ast syn::ItemStruct) {
        for field in &item.fields {
            if matches!(field.vis, syn::Visibility::Public(_)) {
                let mut capacity = RecordingCapacity::default();
                capacity.visit_type(&field.ty);
                if capacity.0 {
                    self.forbidden
                        .push(format!("public recording capacity field: {}", item.ident));
                }
            }
        }
        if item.ident == "Budgets" {
            self.budgets += 1;
        }
        if item.ident == "Pacing" {
            self.forbidden.push("competing Pacing schedule".to_owned());
        }
        visit::visit_item_struct(self, item);
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        if let syn::Type::Path(path) = item.self_ty.as_ref()
            && path.path.is_ident("Budgets")
        {
            for member in &item.items {
                if let syn::ImplItem::Fn(method) = member
                    && !matches!(method.vis, syn::Visibility::Inherited)
                    && matches!(
                        method.sig.ident.to_string().as_str(),
                        "measure" | "capacity" | "observe" | "begin" | "end" | "insert"
                    )
                {
                    self.forbidden
                        .push(format!("raw budget evidence: {}", method.sig.ident));
                }
            }
        }
        visit::visit_item_impl(self, item);
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if matches!(item.vis, syn::Visibility::Public(_)) {
            self.recording_capacity(&item.sig);
        }
        visit::visit_impl_item_fn(self, item);
    }

    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if !source_tree::test_only(&item.attrs).expect("valid cfg") {
            visit::visit_item_mod(self, item);
        }
    }
}

impl Authority {
    fn recording_capacity(&mut self, signature: &syn::Signature) {
        let mut capacity = RecordingCapacity::default();
        capacity.visit_signature(signature);
        if capacity.0 {
            self.forbidden.push(format!(
                "public raw recording capacity: {}",
                signature.ident
            ));
        }
    }
}

// Inspect nested types too: references, callback arguments and return types
// cannot expose the raw capacity under a different function name.
#[derive(Default)]
struct RecordingCapacity(bool);

impl<'ast> Visit<'ast> for RecordingCapacity {
    fn visit_type_path(&mut self, item: &'ast syn::TypePath) {
        if item
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "Capacity")
        {
            self.0 = true;
        }
        visit::visit_type_path(self, item);
    }
}

#[test]
fn execution_cleanup_and_worker_startup_have_one_authority() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut sources = BTreeSet::new();
    source_tree::sources(&root.join("tests/support"), &mut sources);
    let mut authority = Authority::default();
    for source in sources {
        authority.classifications = source == root.join("tests/support/classes.rs");
        let text = std::fs::read_to_string(&source).expect("support source readable");
        let syntax = syn::parse_file(&text).expect("support source parses");
        authority.visit_file(&syntax);
    }
    assert!(
        authority.forbidden.is_empty(),
        "free custody execution: {:?}",
        authority.forbidden
    );
    assert_eq!(
        authority.budgets, 1,
        "recording budgets must have one authority"
    );
    for name in [
        "drive_executed",
        "wound_by",
        "reclaim_by",
        "joined_batch",
        "measured",
    ] {
        assert_eq!(
            authority.functions.get(name),
            Some(&1),
            "{name} must have one authority"
        );
    }
}

#[derive(Default)]
struct Unrecorded(Vec<String>);

#[derive(Default)]
struct BudgetFamilies(BTreeMap<String, usize>);

impl<'ast> Visit<'ast> for BudgetFamilies {
    fn visit_expr_call(&mut self, item: &'ast syn::ExprCall) {
        if let syn::Expr::Path(function) = item.func.as_ref() {
            let names: Vec<_> = function
                .path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect();
            let family_entry = names.last().is_some_and(|name| name == "budgets")
                || names.ends_with(&["Budgets".into(), "new".into()]);
            if family_entry
                && let Some(syn::Expr::Lit(literal)) = item.args.first()
                && let syn::Lit::Str(family) = &literal.lit
            {
                *self.0.entry(family.value()).or_default() += 1;
            }
        }
        visit::visit_expr_call(self, item);
    }
}

#[test]
fn every_budget_family_has_one_fixture_entry_and_one_launch_identity() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut sources = BTreeSet::new();
    source_tree::sources(&root.join("tests"), &mut sources);
    let mut found = BudgetFamilies::default();
    for source in sources {
        let text = std::fs::read_to_string(&source).expect("test source readable");
        let syntax = syn::parse_file(&text).expect("test source parses");
        found.visit_file(&syntax);
    }
    let mut expected = BTreeMap::new();
    for &(family, ..) in dcbor_record::budgets::FAMILIES {
        assert!(
            expected.insert(family.to_owned(), 1).is_none(),
            "duplicate budget family in launch inventory: {family}"
        );
    }
    assert_eq!(
        found.0, expected,
        "budget fixture entries differ from the launch inventory"
    );
    let mut records = BTreeSet::new();
    let mut launches = BTreeSet::new();
    for selection in dcbor_record::budgets::inventory() {
        assert!(
            records.insert(selection.name.clone()),
            "duplicate budget record: {}",
            selection.name
        );
        assert!(
            launches.insert((
                selection.features,
                selection.target,
                selection.test,
                selection.rigor.name(),
                selection.witness.name(),
            )),
            "two budget families share a launch identity: {}",
            selection.name
        );
    }
}

/// Every item, in the library, its tests and fuzz targets, that states a
/// recording capacity, and how many times: the one default
/// ([`dcbor::bounded::Capacity::DEFAULT`]); the budget authority's sizing of
/// a measured budget (`measured`) and its bootstrap capacity (`MEASURING`);
/// and the recordings whose size is what their test checks: a boundary
/// bounded by its slot count, an exhaustion at a stated size, a short
/// recording's refusal, and the concurrency models' derived capacity. Any
/// other recording records into the default or its measured budget.
const SIZED: &[(&str, &str, usize)] = &[
    ("src/bounded/policy/record.rs", "DEFAULT", 1),
    ("tests/support/lifecycle.rs", "measured", 1),
    ("tests/support/budgets.rs", "MEASURING", 1),
    (
        "tests/support/lifecycle.rs",
        "a_short_recording_never_enlarges_the_default",
        3,
    ),
    (
        "tests/support/lifecycle.rs",
        "a_driver_stops_at_the_turn_its_recording_runs_out_of_event_slots",
        1,
    ),
    (
        "tests/support/lifecycle.rs",
        "a_driver_stops_at_the_turn_its_recording_runs_out_of_permit_records",
        1,
    ),
    (
        "tests/support/lifecycle.rs",
        "concurrent_workers_each_name_the_first_invalidation",
        1,
    ),
    ("tests/resumable/native_harness.rs", "aggregated", 1),
    (
        "src/bounded/policy/record.rs",
        "boundaries_retain_the_verified_prefix_without_crossing_publication_gaps",
        1,
    ),
    (
        "src/bounded/policy/record.rs",
        "a_boundary_counts_every_completed_publication_and_nothing_else",
        1,
    ),
    (
        "src/bounded/decode/construction/findings.rs",
        "an_exhausted_session_is_held_to_its_expected_reason",
        1,
    ),
    (
        "src/bounded/decode/construction/stable.rs",
        "end_exhaustion_invalidates_recording",
        1,
    ),
    ("src/sync/models.rs", "DRAINED", 1),
];

/// Explicit `Capacity` and capacity-impl `Self` expressions, including macro
/// bodies, by file and enclosing function, constant, static or macro.
#[derive(Default)]
struct RecordingSizes {
    items: Vec<String>,
    found: BTreeMap<String, usize>,
    file: String,
    capacity_impl: bool,
}

impl RecordingSizes {
    fn within(&mut self, name: String, visit: impl FnOnce(&mut Self)) {
        self.items.push(name);
        visit(self);
        self.items.pop();
    }

    fn record(&mut self) {
        let holder = self.items.last().cloned().unwrap_or_default();
        *self
            .found
            .entry(format!("{} {holder}", self.file))
            .or_default() += 1;
    }

    /// Macro token bodies are not visited as expressions by syn. Count
    /// explicit capacity bodies recursively, including repetitions and
    /// qualified paths, without interpreting strings as source.
    fn tokens(&mut self, tokens: TokenStream) {
        let trees: Vec<_> = tokens.into_iter().collect();
        for (at, tree) in trees.iter().enumerate() {
            if let TokenTree::Group(group) = tree {
                let implementation = at >= 2
                    && matches!(&trees[at - 2], TokenTree::Ident(keyword) if keyword == "impl");
                let declaration = implementation
                    || (at >= 2
                        && matches!(&trees[at - 2], TokenTree::Ident(keyword)
                            if keyword == "struct" || keyword == "enum"));
                if group.delimiter() == Delimiter::Brace
                    && !declaration
                    && at > 0
                    && let TokenTree::Ident(name) = &trees[at - 1]
                    && (name == "Capacity" || (name == "Self" && self.capacity_impl))
                {
                    self.record();
                }
                let previous = self.capacity_impl;
                if implementation {
                    self.capacity_impl =
                        matches!(&trees[at - 1], TokenTree::Ident(name) if name == "Capacity");
                }
                self.tokens(group.stream());
                self.capacity_impl = previous;
            }
        }
    }
}

impl<'ast> Visit<'ast> for RecordingSizes {
    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        let previous = self.capacity_impl;
        self.capacity_impl = matches!(item.self_ty.as_ref(), syn::Type::Path(path)
            if path.path.segments.last().is_some_and(|segment| segment.ident == "Capacity"));
        visit::visit_item_impl(self, item);
        self.capacity_impl = previous;
    }

    fn visit_macro(&mut self, item: &'ast syn::Macro) {
        self.tokens(item.tokens.clone());
    }

    fn visit_item_macro(&mut self, item: &'ast syn::ItemMacro) {
        if let Some(name) = &item.ident {
            self.within(name.to_string(), |sizes| {
                visit::visit_item_macro(sizes, item)
            });
        } else {
            visit::visit_item_macro(self, item);
        }
    }

    fn visit_item_static(&mut self, item: &'ast syn::ItemStatic) {
        self.within(item.ident.to_string(), |sizes| {
            visit::visit_item_static(sizes, item)
        });
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        self.within(item.sig.ident.to_string(), |sizes| {
            visit::visit_item_fn(sizes, item)
        });
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        self.within(item.sig.ident.to_string(), |sizes| {
            visit::visit_impl_item_fn(sizes, item)
        });
    }

    fn visit_item_const(&mut self, item: &'ast syn::ItemConst) {
        self.within(item.ident.to_string(), |sizes| {
            visit::visit_item_const(sizes, item)
        });
    }

    fn visit_impl_item_const(&mut self, item: &'ast syn::ImplItemConst) {
        self.within(item.ident.to_string(), |sizes| {
            visit::visit_impl_item_const(sizes, item)
        });
    }

    fn visit_expr_struct(&mut self, item: &'ast syn::ExprStruct) {
        if item.path.segments.last().is_some_and(|segment| {
            segment.ident == "Capacity" || (segment.ident == "Self" && self.capacity_impl)
        }) {
            self.record();
        }
        visit::visit_expr_struct(self, item);
    }
}

#[test]
fn recording_size_census_includes_self_and_macro_bodies() {
    let syntax = syn::parse_file(
        r#"
        impl Capacity {
            const DEFAULT: Self = Self { permits: 1, events: 2 };
            fn nested() {
                inspect!(Self { permits: 0, events: 1 });
            }
        }
        impl Other {
            const DEFAULT: Self = Self { value: 1 };
        }
        macro_rules! sized {
            ($($n:expr),*) => {
                $(record(crate::bounded::Capacity {
                    permits: $n, events: 2
                });)*
            };
        }
        macro_rules! generated {
            () => {
                impl Capacity {
                    const EXTRA: Self = Self { permits: 1, events: 1 };
                }
                impl Other {
                    const EXTRA: Self = Self { value: 1 };
                }
            };
        }
        static SHORT: Capacity = Capacity { permits: 0, events: 0 };
        fn ordinary() {
            inspect!(Capacity::DEFAULT);
            inspect!("Capacity { permits: 1, events: 2 }");
        }
        "#,
    )
    .expect("the census witness parses");
    let mut sizes = RecordingSizes {
        file: "witness".into(),
        ..RecordingSizes::default()
    };
    sizes.visit_file(&syntax);
    assert_eq!(
        sizes.found,
        BTreeMap::from([
            ("witness DEFAULT".into(), 1),
            ("witness nested".into(), 1),
            ("witness sized".into(), 1),
            ("witness generated".into(), 1),
            ("witness SHORT".into(), 1),
        ]),
        "recording sizes must include Self and macro bodies without counting unrelated tokens"
    );
}

#[test]
fn every_recording_records_into_the_default_unless_its_size_is_tested() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut sources = BTreeSet::new();
    for tree in ["src", "tests", "fuzz/src"] {
        source_tree::sources(&root.join(tree), &mut sources);
    }
    let mut sizes = RecordingSizes::default();
    for source in sources {
        sizes.file = source
            .strip_prefix(root)
            .expect("a source under the package")
            .display()
            .to_string();
        let text = std::fs::read_to_string(&source).expect("source readable");
        let syntax = syn::parse_file(&text).expect("source parses");
        sizes.visit_file(&syntax);
    }
    let mut expected = BTreeMap::new();
    for &(file, item, count) in SIZED {
        assert!(
            expected.insert(format!("{file} {item}"), count).is_none(),
            "duplicate recording-size authority: {file} {item}"
        );
    }
    assert_eq!(
        sizes.found, expected,
        "hand-sized recording capacities differ from the exact-size table"
    );
}

impl<'ast> Visit<'ast> for Unrecorded {
    fn visit_expr_path(&mut self, item: &'ast syn::ExprPath) {
        let names: Vec<_> = item
            .path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect();
        if names
            .windows(2)
            .any(|pair| pair[0] == "Limits" && matches!(pair[1].as_str(), "new" | "unlimited"))
        {
            self.0.push(names.join("::"));
        }
        visit::visit_expr_path(self, item);
    }
}

#[test]
fn fuzz_policies_cannot_bypass_the_recorded_run() {
    let mut sources = BTreeSet::new();
    source_tree::sources(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/src"),
        &mut sources,
    );
    for source in sources {
        let text = std::fs::read_to_string(&source).expect("fuzz source readable");
        let syntax = syn::parse_file(&text).expect("fuzz source parses");
        let mut unrecorded = Unrecorded::default();
        unrecorded.visit_file(&syntax);
        assert!(
            unrecorded.0.is_empty(),
            "{}: unrecorded policies {:?}",
            source.display(),
            unrecorded.0
        );
    }
}
