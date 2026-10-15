//! The agent's manifests, and what they must not contain.
//!
//! The platform's own `manifests.rs` checks that values agree with the binary.
//! This one mostly checks ABSENCES, because the absences are what make this
//! deployment thin (bead gc-72e): nothing reaches it, nothing stores for it,
//! and nothing routes to it. An absence is exactly what a reviewer stops
//! noticing, and exactly what somebody adds in good faith later.

use std::fs;

use serde_yaml_ng::Value;

const DEPLOYMENT: &str = include_str!("../../../deploy/alert-agent/deployment.yaml");
const POLICY: &str = include_str!("../../../deploy/alert-agent/networkpolicy.yaml");
const KUSTOMIZATION: &str = include_str!("../../../deploy/alert-agent/kustomization.yaml");

fn deployment() -> Value {
    serde_yaml_ng::from_str(DEPLOYMENT).expect("the Deployment parses")
}

fn container() -> Value {
    deployment()["spec"]["template"]["spec"]["containers"]
        .as_sequence()
        .expect("the Deployment runs a container")
        .iter()
        .find(|entry| entry["name"].as_str() == Some("alert-agent"))
        .expect("a container named for the binary")
        .clone()
}

#[test]
fn nothing_reaches_this_deployment() {
    // The whole of what "thin" means. A Service, an HTTPRoute or an ingress
    // rule would each be somebody deciding this agent should be reachable, and
    // none of them is this repository's to add: it PULLS, which is why a tenant
    // running it takes on no public surface.
    let directory = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/alert-agent");
    let mut kinds = Vec::new();
    for entry in fs::read_dir(directory).expect("the directory is readable") {
        let path = entry.expect("a readable entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("yaml") {
            continue;
        }
        let text = fs::read_to_string(&path).expect("readable");
        if let Ok(parsed) = serde_yaml_ng::from_str::<Value>(&text)
            && let Some(kind) = parsed["kind"].as_str()
        {
            kinds.push(kind.to_owned());
        }
    }

    for forbidden in ["Service", "HTTPRoute", "Ingress", "Gateway"] {
        assert!(
            !kinds.iter().any(|kind| kind == forbidden),
            "a {forbidden} appeared in the agent's manifests. Nothing should reach \
             this pod: it claims its work from the platform. If something now has \
             to reach it, that is a decision for a bead, not a manifest."
        );
    }
}

#[test]
fn the_policy_allows_egress_and_declares_no_ingress_at_all() {
    // Not a restrictive ingress rule — NONE. Under a namespace's
    // default-deny-ingress the absence is already the whole policy, and an
    // empty ingress rule would read as an oversight somebody should fill in.
    let policy: Value = serde_yaml_ng::from_str(POLICY).expect("the policy parses");
    let types: Vec<&str> = policy["spec"]["policyTypes"]
        .as_sequence()
        .expect("the policy declares its types")
        .iter()
        .map(|kind| kind.as_str().expect("a string"))
        .collect();

    assert_eq!(types, vec!["Egress"]);
    assert!(
        policy["spec"]["ingress"].is_null(),
        "the agent's policy has an ingress rule, which says something may reach it"
    );

    // And DNS, which is the rule everybody forgets. Without it the agent logs
    // "cannot reach the platform" forever while the platform is healthy.
    assert!(POLICY.contains("port: 53"), "egress to DNS is not allowed");
}

#[test]
fn the_agent_runs_the_agent_binary_from_the_platforms_image() {
    // One image, one tag, two commands. They ship together — one commit, one
    // gate, one tag — so a platform and an agent that disagree about the
    // hand-off format cannot come from the same release. Only the command
    // differs, and a Deployment that forgot it would run the platform in a
    // tenant's namespace, which would start, listen, and serve nobody.
    let container = container();
    let command: Vec<&str> = container["command"]
        .as_sequence()
        .expect("the container names its command")
        .iter()
        .map(|part| part.as_str().expect("a string"))
        .collect();

    assert_eq!(command, vec!["/usr/local/bin/alert-agent"]);
    assert_eq!(
        container["image"].as_str(),
        Some("ghcr.io/motrice/webhook-proxy:main"),
        "the agent runs an image other than the platform's, so the two could be \
         released out of step"
    );
}

#[test]
fn the_manifest_names_the_variables_the_binary_reads() {
    // The same failure the platform's manifests test exists for: the binary
    // falls back to a default for the two it can default, so a misspelled name
    // is silent — the agent would read a routing file nothing is mounted at and
    // refuse to start, which looks like a broken image rather than a typo.
    let declared: Vec<String> = container()["env"]
        .as_sequence()
        .expect("the container declares its environment")
        .iter()
        .map(|entry| entry["name"].as_str().expect("a name").to_owned())
        .collect();

    for name in [
        "ALERT_AGENT_PLATFORM",
        "ALERT_AGENT_CONFIG",
        "ALERT_AGENT_SECRETS_DIR",
    ] {
        assert!(
            declared.iter().any(|set| set == name),
            "{name} is not set: {declared:?}"
        );
    }

    // And nothing it does not read. A `WEBHOOK_PROXY_*` here would be somebody
    // copying the platform's manifest, and the agent would ignore it silently.
    for set in &declared {
        assert!(
            set.starts_with("ALERT_AGENT_"),
            "{set} is set and this binary reads no such variable"
        );
    }
}

#[test]
fn the_rendered_room_urls_never_reach_a_disk() {
    // Every room URL is itself a credential (bead gc-o61): anyone holding it can
    // post to that room. An ordinary emptyDir is a directory on the node, so
    // this being memory-backed is the difference between a credential in RAM
    // and a credential on somebody's disk.
    let volumes = deployment()["spec"]["template"]["spec"]["volumes"]
        .as_sequence()
        .expect("the pod declares its volumes")
        .clone();
    let secrets = volumes
        .iter()
        .find(|volume| volume["name"].as_str() == Some("secrets"))
        .expect("a volume for the rendered secrets");

    assert_eq!(
        secrets["emptyDir"]["medium"].as_str(),
        Some("Memory"),
        "the room URLs are rendered onto a disk"
    );

    // And every mount is read-only: nothing here is ever written.
    for mount in container()["volumeMounts"]
        .as_sequence()
        .expect("the container mounts something")
    {
        assert_eq!(
            mount["readOnly"].as_bool(),
            Some(true),
            "{:?} is writable",
            mount["name"]
        );
    }
}

#[test]
fn every_manifest_in_the_directory_is_one_the_kustomization_applies() {
    // The same invariant the platform's manifests keep, for the same reason: a
    // manifest written, reviewed, committed and never applied fails silently,
    // and the NetworkPolicy here is exactly the one whose absence nobody would
    // notice until something was unreachable.
    let directory = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/alert-agent");
    let applied: Vec<&str> = KUSTOMIZATION
        .lines()
        .filter_map(|line| line.trim().strip_prefix("- "))
        .map(str::trim)
        .collect();

    let mut unapplied = Vec::new();
    for entry in fs::read_dir(directory).expect("the directory is readable") {
        let path = entry.expect("a readable entry").path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("a named file")
            .to_owned();
        let yaml = path
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("yaml"));
        if !yaml || name == "kustomization.yaml" {
            continue;
        }
        if !applied.iter().any(|line| line.contains(&name)) {
            unapplied.push(name);
        }
    }

    assert!(
        unapplied.is_empty(),
        "{unapplied:?} will never be applied: nothing in kustomization.yaml names them"
    );
}
