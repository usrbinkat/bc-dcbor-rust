//! Structural witnesses for the shared lifecycle's authority boundaries.
mod source_tree;

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
