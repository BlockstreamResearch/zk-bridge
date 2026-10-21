//! smplx compiles the claim leaf to the CMR the crate does.
//!
//! The crate substitutes each parameter into the text (`claim::source`) and compiles it with the vendored
//! SimplicityHL. smplx 0.0.12 compiles the leaf another way: its `Program` takes the text as written and the
//! parameters as arguments, enables every unstable feature, adds debug symbols only at `simplex test -v` or above,
//! and uses the SimplicityHL release its lock names, 0.7.2. `smplx_cmr` makes that same call to that release, so
//! a leaf built with smplx's SDK or generated bindings commits to the CMR a manifest records.

mod common;

use common::{manifest_params, published_manifests};
use liquid_bridge_poc::claim::{compile, parameters, test_params, Params, TEMPLATE};

use simplicity::Cmr;
use smplx_simplicityhl::{
    ast::ElementsJetHinter, Arguments, TemplateProgram, UnstableFeatures, Value,
};
use std::collections::{BTreeSet, HashMap};

/// The CMR of `program` compiled the way smplx's `Program` compiles it, with the arguments of `p`.
fn smplx_cmr(program: &str, p: &Params, debug_symbols: bool) -> Cmr {
    let template = TemplateProgram::new_with_unstable(
        program,
        &UnstableFeatures::all(),
        Box::new(ElementsJetHinter),
    )
    .unwrap_or_else(|e| panic!("smplx's SimplicityHL rejects the leaf:\n{e}"));
    let declared: BTreeSet<&str> = template
        .parameters()
        .iter()
        .map(|(name, _)| name.as_ref())
        .collect();
    let given = parameters(p);
    let names: BTreeSet<&str> = given.iter().map(|(name, _)| *name).collect();
    assert_eq!(
        declared, names,
        "the leaf's parameters are those claim::parameters gives"
    );
    let arguments: HashMap<_, _> = template
        .parameters()
        .iter()
        .map(|(name, ty)| {
            let (_, literal) = given.iter().find(|(n, _)| *n == name.as_ref()).unwrap();
            let value = Value::parse_from_str(literal, ty)
                .unwrap_or_else(|e| panic!("param::{}: {e}", name.as_ref()));
            (name.clone(), value)
        })
        .collect();
    template
        .instantiate(Arguments::from(arguments), debug_symbols)
        .unwrap()
        .commit()
        .cmr()
}

fn crate_cmr(p: &Params) -> Cmr {
    compile(p).unwrap().commit().cmr()
}

#[test]
fn smplx_compiles_the_leaf_the_crate_does() {
    let p = test_params();
    assert_eq!(smplx_cmr(TEMPLATE, &p, false), crate_cmr(&p));
}

/// A published instance's claim leaf, compiled by smplx's route, is the manifest's `claim_leaf.cmr`.
#[test]
fn smplx_compiles_the_published_leaves() {
    for (record, m) in published_manifests() {
        let p = manifest_params(&m);
        let cmr = smplx_cmr(TEMPLATE, &p, false);
        assert_eq!(cmr, crate_cmr(&p), "{record}");
        assert_eq!(
            hex::encode(cmr.as_ref()),
            m["claim_leaf"]["cmr"].as_str().unwrap(),
            "{record}"
        );
    }
}

/// Debug symbols are part of the program: with them, as smplx's `simplex test -v` and `-vv` compile, the leaf is
/// another one, which no published state tree commits.
#[test]
fn smplx_debug_symbols_give_another_leaf() {
    let p = test_params();
    assert_ne!(smplx_cmr(TEMPLATE, &p, true), crate_cmr(&p));
}

/// `simplex build` (smplx 0.0.9 and 0.0.12) rewrites the leaf into a module, target/simplex/simf/claim.simf, and
/// its generated bindings compile that text. Run `simplex build` in contracts/simplicity first.
///
/// Once target/simplex exists, both versions exit 0 on a leaf that does not parse, writing nothing for it and
/// keeping an earlier build's output, so output older than simf/claim.simf is refused as stale.
#[test]
#[ignore = "needs `simplex build` output in target/simplex"]
fn simplex_build_output_compiles_to_the_leaf() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = dir.join("target/simplex/simf/claim.simf");
    let built = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e}; run `simplex build` first", path.display()));
    let modified = |p: &std::path::Path| std::fs::metadata(p).unwrap().modified().unwrap();
    assert!(
        modified(&path) >= modified(&dir.join("simf/claim.simf")),
        "{} is older than simf/claim.simf: `simplex build` did not rebuild it",
        path.display()
    );
    let p = test_params();
    assert_eq!(smplx_cmr(&built, &p, false), crate_cmr(&p));
    for (record, m) in published_manifests() {
        let p = manifest_params(&m);
        assert_eq!(smplx_cmr(&built, &p, false), crate_cmr(&p), "{record}");
    }
}
