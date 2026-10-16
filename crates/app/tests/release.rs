//! The release configuration, checked against what it claims to build.
//!
//! Bead gc-lw3. A release workflow is the one thing in this repository that
//! cannot be tried locally: it runs on a tag, once, and a mistake in it is
//! found at the worst possible moment. So the parts that CAN be checked from
//! here are — that it names a Containerfile that exists, a stage that file
//! declares, and a registry path the deployment manifests reference.
//!
//! `manifests.rs` already asserts the Containerfile declares a `runtime` stage
//! "the release workflow will name". Nothing asserted the workflow named it.
//! This closes that loop from the other end.

use serde_yaml_ng::Value;

const ARTIFACTS: &str = include_str!("../../../.github/artifacts.yml");
const RELEASE: &str = include_str!("../../../.github/workflows/release.yml");
const DEV_IMAGE: &str = include_str!("../../../.github/workflows/dev-image.yml");
const PR: &str = include_str!("../../../.github/workflows/pr.yml");
const CONTAINERFILE: &str = include_str!("../../../deploy/Containerfile");
const DEPLOYMENT: &str = include_str!("../../../deploy/webhook-proxy/deployment.yaml");
const AGENT_DEPLOYMENT: &str = include_str!("../../../deploy/alert-agent/deployment.yaml");

/// The repository's short name, which is also the image's.
const REPOSITORY: &str = "webhook-proxy";

fn artifacts() -> Value {
    serde_yaml_ng::from_str(ARTIFACTS).expect("the artefact config parses")
}

fn the_container() -> Value {
    let containers = artifacts()["containers"]
        .as_sequence()
        .expect("the artefact config declares containers")
        .clone();
    assert_eq!(
        containers.len(),
        1,
        "one container, by bead gc-kow. A second would need deciding, not adding."
    );
    containers[0].clone()
}

#[test]
fn the_release_builds_the_containerfile_this_repository_has() {
    // A path that does not exist fails on a tag, which is the one moment
    // nobody wants to debug a build.
    let container = the_container();
    let path = container["container-file"]
        .as_str()
        .expect("the container names a Containerfile");

    assert_eq!(path, "deploy/Containerfile");
    assert!(
        std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../deploy/Containerfile"
        ))
        .is_file(),
        "{path} is named by the release and is not in the repository"
    );

    // And the stage. The Containerfile's deployable stage is not its last one by
    // design, so naming it is what stops a stage added later from silently
    // becoming the released image.
    let target = container["target"]
        .as_str()
        .expect("the container names a stage");
    assert!(
        CONTAINERFILE.contains(&format!("AS {target}")),
        "the release builds stage {target:?}, which the Containerfile does not declare"
    );
}

#[test]
fn the_released_image_is_the_one_the_manifests_name() {
    // reusable-ci collapses the redundant `<repo>/<repo>` subpath ONLY when a
    // container's name equals the repository's short name. Call it anything
    // else and the image becomes ghcr.io/motrice/webhook-proxy/<name>, the
    // deployment pulls a path nothing publishes, and the symptom is
    // ImagePullBackOff on a manifest that reads correctly.
    let container = the_container();
    assert_eq!(
        container["name"].as_str(),
        Some(REPOSITORY),
        "the container's name differs from the repository's, so the published \
         path gains a subpath the manifests do not name"
    );

    // Both deployments pull the collapsed path, and the agent deliberately
    // shares the platform's image: one commit, one gate, one tag, so the two
    // cannot be released out of step.
    let expected = format!("ghcr.io/motrice/{REPOSITORY}");
    for (what, manifest) in [
        ("the platform", DEPLOYMENT),
        ("the agent", AGENT_DEPLOYMENT),
    ] {
        assert!(
            manifest.contains(&expected),
            "{what}'s manifest does not pull {expected}"
        );
    }
}

#[test]
fn the_release_publishes_no_binary() {
    // Bead gc-kow: the only deployment target is a cluster, nobody runs this
    // from a tarball, and an artefact with no audience still has to be signed,
    // SBOM'd and patched. `extract.binary` is cheap to add, which is exactly
    // why its absence is worth asserting rather than trusting.
    assert!(
        the_container()["extract"].is_null(),
        "the release extracts a binary, which gc-kow decided against"
    );
}

#[test]
fn both_architectures_are_built() {
    // This development cluster is arm64 under Lima; CI and anything production
    // is amd64. An image built for one would work everywhere it was tested and
    // nowhere it was deployed, or the reverse.
    let container = the_container();
    let platforms = container["platforms"]
        .as_str()
        .expect("the container names its platforms");

    for architecture in ["linux/amd64", "linux/arm64"] {
        assert!(
            platforms.contains(architecture),
            "{architecture} is not built: {platforms}"
        );
    }
}

/// Every `reusable-ci` ref a workflow pins, with the file it came from.
fn pinned_refs() -> Vec<(&'static str, String)> {
    [
        ("pr.yml", PR),
        ("release.yml", RELEASE),
        ("dev-image.yml", DEV_IMAGE),
    ]
    .iter()
    .flat_map(|(name, source)| {
        source
            .match_indices("diggsweden/reusable-ci/")
            .filter_map(move |(at, _)| {
                let rest = &source[at..];
                let marker = rest.find('@')?;
                let after = &rest[marker + 1..];
                let end = after.find(|c: char| !c.is_ascii_alphanumeric())?;
                Some((*name, after[..end].to_owned()))
            })
            .collect::<Vec<_>>()
    })
    .collect()
}

#[test]
fn every_workflow_pins_the_same_reusable_ci_commit() {
    // A release checked by one version of the policy layer and published by
    // another is two definitions of green, and the difference would show up as
    // a release that passed every gate and shipped something the gates would
    // now reject. Updating the pin is deliberate and belongs in one commit,
    // which this makes true rather than hoped for.
    let pinned = pinned_refs();
    assert!(
        pinned.len() >= 3,
        "expected a pinned ref in each workflow, found {pinned:?}"
    );

    let first = &pinned[0].1;
    for (file, reference) in &pinned {
        assert_eq!(
            reference, first,
            "{file} pins {reference}, and {} pins {first}",
            pinned[0].0
        );
        // A full commit SHA, not a tag: a tag can be moved, and OpenSSF
        // scorecard asks for this for the same reason.
        assert_eq!(
            reference.len(),
            40,
            "{file} pins {reference}, which is not a full commit SHA"
        );
    }
}

#[test]
fn the_release_maps_every_secret_it_needs_and_inherits_nothing() {
    // v3.0.0 does not support `secrets: inherit`, and that is the better
    // default: a workflow that inherited everything would hand every secret
    // this repository holds to a third-party workflow whether the release used
    // it or not. Asserted because the failure mode of getting it wrong is a
    // release that dies partway through, having already pushed something.
    // Comments stripped before matching, because this file EXPLAINS why it
    // does not inherit — and a check that read its own explanation as the
    // thing it forbids would be the kind of test that is only ever satisfied
    // by saying less.
    let settings: String = RELEASE
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !settings.contains("secrets: inherit"),
        "release.yml inherits its secrets, which v3.0.0 does not support and \
         which would pass this repository's every secret to a third party"
    );

    for secret in [
        "RELEASE_TOKEN",
        "RELEASE_GPG_PRIVATE_KEY",
        "RELEASE_GPG_PASSPHRASE",
    ] {
        assert!(
            settings.contains(secret),
            "{secret} is not mapped, so the step needing it fails mid-release"
        );
        // And documented, because only the maintainer can set one and a secret
        // nobody wrote down is a release nobody else can cut.
        let readme = include_str!("../../../README.md");
        assert!(
            readme.contains(secret),
            "{secret} is mapped by the workflow and named nowhere in README.md"
        );
    }
}

#[test]
fn the_dev_image_publishes_the_same_stage_as_a_release() {
    // Two workflows building two different stages would mean the thing deployed
    // from main is not the thing released from a tag — which is exactly the
    // divergence gc-kow's "no second build path" was about, arrived at from
    // inside CI instead of from a manifest.
    let container = the_container();
    let target = container["target"]
        .as_str()
        .expect("the container names a stage");

    assert!(
        DEV_IMAGE.contains(&format!("target: {target}")),
        "dev-image.yml does not build stage {target:?}"
    );
    assert!(
        DEV_IMAGE.contains("container-file: deploy/Containerfile"),
        "dev-image.yml does not build the Containerfile the release builds"
    );
}
