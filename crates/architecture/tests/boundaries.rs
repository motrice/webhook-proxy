//! Dependency-direction enforcement for the hexagon.
//!
//! This is the file that lets a human trust an agent's PR without reading every
//! line of it. Widening a boundary means editing `ALLOWED` below, which shows up
//! in review as a deliberate architectural decision rather than an accident
//! buried in a `Cargo.toml`.

use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;

/// Layer a crate belongs to, lowest (most pure) first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Layer {
    Domain,
    Application,
    Adapter,
    App,
    /// This test crate. Nothing may depend on it.
    Architecture,
}

/// External crates each layer may use. Inner layers stay deliberately poor.
///
/// `domain` is empty and must stay empty: a dependency there is a dependency
/// for every test in the system.
fn allowed_external(layer: Layer) -> &'static [&'static str] {
    match layer {
        Layer::Domain => &[],
        // Error plumbing and trait-object async only. No runtime, no serde:
        // serialisation is an adapter concern, not a use-case concern.
        Layer::Application => &["thiserror", "async-trait"],
        // Adapters talk to the real world, so they get a free hand.
        Layer::Adapter | Layer::App | Layer::Architecture => ANY,
    }
}

/// Sentinel meaning "no restriction on external dependencies".
const ANY: &[&str] = &["*"];

/// Which layers a layer may depend on *within* the workspace.
fn allowed_internal(layer: Layer) -> &'static [Layer] {
    match layer {
        // The pure core and this test crate both sit on nothing.
        Layer::Domain | Layer::Architecture => &[],
        Layer::Application => &[Layer::Domain],
        // Adapters may not depend on each other: two adapters that need to
        // share code are telling you the shared part belongs in application.
        Layer::Adapter => &[Layer::Domain, Layer::Application],
        Layer::App => &[Layer::Domain, Layer::Application, Layer::Adapter],
    }
}

struct Crate {
    name: String,
    layer: Layer,
    /// Normal (non-dev, non-build) dependencies.
    deps: BTreeSet<String>,
}

/// Classify by manifest path, so a new adapter is picked up by living in
/// `crates/adapters/`, with no registration step to forget.
fn classify(name: &str, manifest_path: &str) -> Layer {
    if manifest_path.contains("/crates/adapters/") {
        return Layer::Adapter;
    }
    match name {
        "domain" => Layer::Domain,
        "application" => Layer::Application,
        "architecture" => Layer::Architecture,
        // Two composition roots, because there are two deployments: the
        // platform service and the tenant agent (bead gc-72e). Both wire
        // adapters, which is the thing that makes a crate this layer, and
        // neither may depend on the other — the test below holds them to a
        // named list so a third does not appear by accident.
        "app" | "agent" => Layer::App,
        other => panic!(
            "crate `{other}` at {manifest_path} is in no layer.\n\
             Put adapters under crates/adapters/, or add the crate to \
             `classify` in crates/architecture/tests/boundaries.rs."
        ),
    }
}

fn workspace() -> Vec<Crate> {
    let out = Command::new(env!("CARGO"))
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .output()
        .expect("run cargo metadata");
    assert!(
        out.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let meta: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("parse cargo metadata");

    meta["packages"]
        .as_array()
        .expect("packages array")
        .iter()
        .map(|pkg| {
            let name = pkg["name"].as_str().expect("package name").to_owned();
            let manifest = pkg["manifest_path"].as_str().expect("manifest_path");
            let deps = pkg["dependencies"]
                .as_array()
                .expect("dependencies array")
                .iter()
                // `kind` is null for normal deps, "dev"/"build" otherwise.
                // Dev-dependencies are intentionally unrestricted: a test may
                // use whatever it needs to prove the production path.
                .filter(|d| d["kind"].is_null())
                .map(|d| d["name"].as_str().expect("dep name").to_owned())
                .collect();
            Crate {
                name: name.clone(),
                layer: classify(&name, manifest),
                deps,
            }
        })
        .collect()
}

#[test]
fn dependencies_only_point_inward() {
    let crates = workspace();
    let layer_of: BTreeMap<&str, Layer> =
        crates.iter().map(|c| (c.name.as_str(), c.layer)).collect();

    let mut violations = Vec::new();

    for c in &crates {
        for dep in &c.deps {
            if let Some(&dep_layer) = layer_of.get(dep.as_str()) {
                // Internal dependency: check it against the layer graph.
                if !allowed_internal(c.layer).contains(&dep_layer) {
                    violations.push(format!(
                        "{} ({:?}) must not depend on {dep} ({dep_layer:?})",
                        c.name, c.layer
                    ));
                }
            } else {
                // External crate: check the per-layer allowlist.
                let allowed = allowed_external(c.layer);
                if allowed != ANY && !allowed.contains(&dep.as_str()) {
                    violations.push(format!(
                        "{} ({:?}) must not depend on external crate `{dep}`. \
                         Allowed: {allowed:?}. Either move the code to an \
                         adapter, or widen `allowed_external` on purpose.",
                        c.name, c.layer
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "hexagonal boundary violated:\n  {}",
        violations.join("\n  ")
    );
}

/// The domain's poverty is the whole point, so it gets its own named test:
/// a failure here reads as "you made the core impure", not "graph error".
#[test]
fn domain_has_no_dependencies() {
    let domain = workspace()
        .into_iter()
        .find(|c| c.layer == Layer::Domain)
        .expect("a domain crate must exist");
    assert!(
        domain.deps.is_empty(),
        "domain must have zero dependencies, found: {:?}.\n\
         Anything the domain seems to need from a library is either a value \
         type you should own, or an effect that belongs behind a port.",
        domain.deps
    );
}

/// Catches the classic drift where someone adds a crate outside `crates/`, or
/// an adapter that is secretly a composition root.
///
/// The App layer holds a NAMED LIST rather than a count, and that is the
/// difference bead gc-72e made: there are two deployments now — the platform
/// service and the tenant agent — so two composition roots is correct, and
/// "exactly one" was the wrong invariant rather than a violated one. A count of
/// two would have let a third arrive without anybody deciding to, which is the
/// drift this test is actually for.
#[test]
fn every_layer_is_populated_by_exactly_what_it_should_be() {
    let crates = workspace();

    for required in [Layer::Domain, Layer::Application] {
        let n = crates.iter().filter(|c| c.layer == required).count();
        assert_eq!(n, 1, "expected exactly one {required:?} crate, found {n}");
    }

    let roots: BTreeSet<&str> = crates
        .iter()
        .filter(|c| c.layer == Layer::App)
        .map(|c| c.name.as_str())
        .collect();
    assert_eq!(
        roots,
        BTreeSet::from(["agent", "app"]),
        "the composition roots are not the two deployments this workspace ships.          A new one is an architectural decision: add it here and to `classify`,          and say in the commit which deployment it is."
    );
}

/// Neither deployment may reach into the other.
///
/// They share the domain, the use cases and the adapters, and nothing else. A
/// dependency between them would make one of them a library with a `main` in
/// it, and the two are deployed into different namespaces under different
/// teams' control — so sharing code through the layers below is the only way
/// they are allowed to agree about anything.
#[test]
fn the_two_composition_roots_do_not_depend_on_each_other() {
    let crates = workspace();
    let roots: Vec<&Crate> = crates.iter().filter(|c| c.layer == Layer::App).collect();

    for root in &roots {
        for other in &roots {
            if root.name == other.name {
                continue;
            }
            assert!(
                !root.deps.contains(&other.name),
                "{} depends on {}, which makes one composition root a library                  for the other",
                root.name,
                other.name
            );
        }
    }
}
