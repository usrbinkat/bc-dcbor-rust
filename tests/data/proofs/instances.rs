//! The one declaration of the Kani harness instances: families whose
//! property is one generic body, checked one constant size at a time so the
//! production bound is computed for constants. Read by two consumers through
//! `#[path]`, never copied: `build.rs`, which writes each family's
//! `#[kani::proof]` functions into `$OUT_DIR/proof_instances/` for the
//! family's file to include, and the gate's census
//! (`tests/gate/src/proofs.rs`, `harnesses`), which expects exactly those
//! harnesses. Both take them from [`instances`], the one expansion.
//!
//! A family declares its axes: the input lengths, each with its own unwind,
//! the nesting limits and the text policies. [`instances`] expands their
//! complete product and refuses a declaration whose axes do not each cover
//! their domain exactly (every length from 0 through the family's longest,
//! every nesting limit from 0 through its deepest, no value twice) or whose
//! names do not distinguish every instance. The domain constants the
//! family's file states (`longest`, `deepest`) are checked against the axes'
//! largest values in the generated code itself, at compile time, so a file
//! that widens its domain without its instances does not build.

/// One family of instances.
pub struct Family {
    /// The source file, relative to the package root, that includes the
    /// family's generated instances.
    pub file: &'static str,
    /// The module path of that file from the crate root.
    pub module: &'static str,
    /// The generated file's name under `$OUT_DIR/proof_instances/`.
    pub generated: &'static str,
    /// Each instance's name: `{len}`, `{depth}` and `{policy}` replaced by
    /// its values.
    pub name: &'static str,
    /// Each instance's call of the family's body, with the same
    /// placeholders, `{policy}` by the policy's expression.
    pub call: &'static str,
    /// The `#[kani::stub]` pairs every instance takes.
    pub stubs: &'static [(&'static str, &'static str)],
    /// Every input length, each with its instance's `#[kani::unwind]`.
    pub lengths: &'static [(usize, u32)],
    /// Every nesting limit; `[0]` for a family without the axis.
    pub depths: &'static [usize],
    /// Every text policy, its name in instance names and its expression in
    /// calls; `[("", "")]` for a family without the axis.
    pub policies: &'static [(&'static str, &'static str)],
    /// The constant of the family's file stating its longest input, asserted
    /// in the generated code to be the lengths' largest.
    pub longest: &'static str,
    /// The constant stating its deepest nesting limit, asserted to be the
    /// nesting limits' largest; `None` for a family without the axis.
    pub deepest: Option<&'static str>,
}

/// One instance: its harness name, its unwind and its call of the body.
pub struct Instance {
    pub name: String,
    pub unwind: u32,
    pub call: String,
}

/// The decode stubs: the binary16 adapters' `half` dispatch, which Kani
/// does not model, replaced by their exactness contracts
/// (`src/float/proofs.rs`).
const FLOAT_STUBS: &[(&str, &str)] = &[
    (
        "crate::float::narrowed",
        "crate::float::proofs::from_f64_contract",
    ),
    (
        "crate::float::widened",
        "crate::float::proofs::to_f64_contract",
    ),
];

/// The text policies of the decode families.
const POLICIES: &[(&str, &str)] = &[("normalized", "Normalize"), ("quick_only", "QuickOnly")];

/// Every family.
pub const FAMILIES: &[Family] = &[
    Family {
        file: "src/bounded/decode/decode_proofs.rs",
        module: "bounded::decode::decode_proofs",
        generated: "decode.rs",
        name: "the_decode_bound_covers_inputs_of_{len}_bytes_at_depth_{depth}_{policy}",
        call: "check::<{len}>({depth}, {policy})",
        stubs: FLOAT_STUBS,
        lengths: &[(0, 2), (1, 3), (2, 4), (3, 5), (4, 6)],
        depths: &[0, 1, 2],
        policies: POLICIES,
        longest: "INPUT",
        deepest: Some("DEPTH"),
    },
    Family {
        file: "src/bounded/decode/string_cursor/proofs.rs",
        module: "bounded::decode::string_cursor::proofs",
        generated: "string.rs",
        name: "the_string_bound_covers_inputs_of_{len}_bytes_at_depth_{depth}_{policy}",
        call: "check::<{len}>({depth}, {policy})",
        stubs: FLOAT_STUBS,
        lengths: &[(0, 378), (1, 378), (2, 378), (3, 378), (4, 378)],
        depths: &[0, 1, 2],
        policies: POLICIES,
        longest: "INPUT",
        deepest: Some("DEPTH"),
    },
    Family {
        file: "src/bounded/decode/header/proofs.rs",
        module: "bounded::decode::header::proofs",
        generated: "header.rs",
        name: "the_header_bound_covers_heads_of_{len}_bytes",
        call: "check::<{len}>()",
        stubs: &[],
        lengths: &[
            (0, 12),
            (1, 12),
            (2, 12),
            (3, 12),
            (4, 12),
            (5, 12),
            (6, 12),
            (7, 12),
            (8, 12),
            (9, 12),
        ],
        depths: &[0],
        policies: &[("", "")],
        longest: "MAX_HEAD_LEN",
        deepest: None,
    },
];

/// `values`, which must be every value from 0 through its largest once, in
/// order: the axis covers its domain exactly.
fn covering(family: &Family, axis: &str, values: &[usize]) -> Result<(), String> {
    if values.is_empty() || values.iter().copied().ne(0..values.len()) {
        return Err(format!(
            "{}: its {axis} {values:?} are not every value from 0 through the largest, once each",
            family.file
        ));
    }
    Ok(())
}

/// Every instance of `family`: the product of its lengths, nesting limits
/// and policies, in that order. Refused when an axis does not cover its
/// domain exactly, when a family without a nesting axis declares more than
/// one limit, or when two instances share a name.
pub fn instances(family: &Family) -> Result<Vec<Instance>, String> {
    let lengths: Vec<usize> = family.lengths.iter().map(|(len, _)| *len).collect();
    covering(family, "lengths", &lengths)?;
    covering(family, "nesting limits", family.depths)?;
    if family.deepest.is_none() && family.depths != [0] {
        return Err(format!(
            "{}: it has no nesting axis but declares the limits {:?}",
            family.file, family.depths
        ));
    }
    if family.policies.is_empty() {
        return Err(format!("{}: no text policy", family.file));
    }
    let mut found = Vec::new();
    let mut names = std::collections::BTreeSet::new();
    for &(len, unwind) in family.lengths {
        for &depth in family.depths {
            for &(policy, expression) in family.policies {
                let fill = |template: &str, policy: &str| {
                    template
                        .replace("{len}", &len.to_string())
                        .replace("{depth}", &depth.to_string())
                        .replace("{policy}", policy)
                };
                let name = fill(family.name, policy);
                if !names.insert(name.clone()) {
                    return Err(format!(
                        "{}: the instance name {name} is not distinct",
                        family.file
                    ));
                }
                found.push(Instance {
                    name,
                    unwind,
                    call: fill(family.call, expression),
                });
            }
        }
    }
    Ok(found)
}

/// The source of `family`'s generated instances: the file's domain
/// constants checked against the axes' largest values, then each
/// instance's `#[kani::proof]` with its unwind and the family's stubs,
/// calling its body.
pub fn generated(family: &Family) -> Result<String, String> {
    let instances = instances(family)?;
    let mut out = format!(
        "// Generated by build.rs from tests/data/proofs/instances.rs for {}. Do not edit.\n",
        family.file
    );
    let longest = family.lengths.len() - 1;
    let deepest = family.depths.len() - 1;
    for (constant, value) in [(Some(family.longest), longest), (family.deepest, deepest)] {
        if let Some(constant) = constant {
            out.push_str(&format!(
                "const _: () = assert!({constant} == {value}, \"tests/data/proofs/instances.rs \
                 covers {constant} = {value}\");\n"
            ));
        }
    }
    for instance in instances {
        out.push_str(&format!(
            "\n#[kani::proof]\n#[kani::unwind({})]\n",
            instance.unwind
        ));
        for (original, replacement) in family.stubs {
            out.push_str(&format!("#[kani::stub({original}, {replacement})]\n"));
        }
        out.push_str(&format!(
            "fn {}() {{\n    {};\n}}\n",
            instance.name, instance.call
        ));
    }
    Ok(out)
}

/// The line by which `family`'s file includes its generated instances.
pub fn inclusion(family: &Family) -> String {
    format!(
        "include!(concat!(env!(\"OUT_DIR\"), \"/proof_instances/{}\"));",
        family.generated
    )
}
