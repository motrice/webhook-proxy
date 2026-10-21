//! The deployment manifests and the composition root have to agree, and nothing
//! in either file can tell you whether they do.
//!
//! Every mismatch here fails the same way: a pod that starts, answers no probe
//! or reads no configuration, and says nothing about why. The binary falls back
//! to a default for every variable it reads, so a misspelled name in the
//! manifest is silent — the pod simply listens on loopback where no probe can
//! reach it, or reads `/etc/webhook-proxy/config.yaml` where nothing is mounted.
//!
//! So these tests do not compare the manifest against a list written here; a
//! list would be a mirror of the same mistake. They take a value *out of the
//! manifest*, hand it to the built binary, and assert the binary visibly obeys
//! it. A name the binary does not read cannot pass.

use std::collections::HashMap;
use std::fs;
use std::process::Stdio;
use std::time::Duration;

use serde_yaml_ng::Value;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::process::Command;

const DEPLOYMENT: &str = include_str!("../../../deploy/webhook-proxy/deployment.yaml");
const SERVICE: &str = include_str!("../../../deploy/webhook-proxy/service.yaml");
const ROUTE: &str = include_str!("../../../deploy/webhook-proxy/httproute.yaml");
const POLICY: &str = include_str!("../../../deploy/webhook-proxy/networkpolicy.yaml");
const KUSTOMIZATION: &str = include_str!("../../../deploy/webhook-proxy/kustomization.yaml");
const CONTAINERFILE: &str = include_str!("../../../deploy/Containerfile");
const AGENT: &str = include_str!("../../../deploy/webhook-proxy/vault-agent.hcl");
const ROUTING: &str = include_str!("../../../deploy/webhook-proxy/config.example.yaml");
const IGNORED: &str = include_str!("../../../.dockerignore");

/// The Deployment's containers, by name.
///
/// By name rather than by position, and not because there happen to be two. The
/// agent beside the proxy needs no agreement with the binary at all — it needs
/// one with the directory, which the assertions below check. Pinning this to
/// "there is exactly one container" would mean loosening a test every time the
/// pod gains one, which is the wrong way round.
fn containers() -> std::collections::BTreeMap<String, Value> {
    let manifest: Value = serde_yaml_ng::from_str(DEPLOYMENT).expect("the Deployment parses");
    manifest["spec"]["template"]["spec"]["containers"]
        .as_sequence()
        .expect("the Deployment runs containers")
        .iter()
        .map(|entry| {
            (
                entry["name"]
                    .as_str()
                    .expect("a named container")
                    .to_owned(),
                entry.clone(),
            )
        })
        .collect()
}

/// The container running the binary this crate builds.
fn container() -> Value {
    containers()
        .remove("webhook-proxy")
        .expect("the Deployment runs the proxy")
}

/// The volumes the pod declares, by name.
fn volumes() -> std::collections::BTreeMap<String, Value> {
    let manifest: Value = serde_yaml_ng::from_str(DEPLOYMENT).expect("the Deployment parses");
    manifest["spec"]["template"]["spec"]["volumes"]
        .as_sequence()
        .expect("the pod declares volumes")
        .iter()
        .map(|entry| {
            (
                entry["name"].as_str().expect("a named volume").to_owned(),
                entry.clone(),
            )
        })
        .collect()
}

/// Every secret name the routing file refers to, wherever it appears.
///
/// Collected by walking for the key rather than by knowing the shape, so a new
/// place to name a secret is covered the day it is added.
fn secrets_named_by_the_routing_file() -> std::collections::BTreeSet<String> {
    fn walk(node: &Value, found: &mut std::collections::BTreeSet<String>) {
        match node {
            Value::Mapping(entries) => {
                for (key, value) in entries {
                    if key.as_str() == Some("secret")
                        && let Some(name) = value.as_str()
                    {
                        found.insert(name.to_owned());
                    }
                    walk(value, found);
                }
            }
            Value::Sequence(items) => items.iter().for_each(|item| walk(item, found)),
            _ => {}
        }
    }

    let routing: Value = serde_yaml_ng::from_str(ROUTING).expect("the routing file parses");
    let mut found = std::collections::BTreeSet::new();
    walk(&routing, &mut found);
    found
}

/// Every file the agent is configured to render.
fn files_the_agent_renders() -> std::collections::BTreeSet<String> {
    AGENT
        .lines()
        .filter_map(|line| line.trim().strip_prefix("destination = \""))
        .filter_map(|rest| rest.strip_suffix('"'))
        .filter_map(|path| path.rsplit('/').next())
        .map(str::to_owned)
        .collect()
}

/// What the manifest puts in the container's environment, by name.
fn environment() -> HashMap<String, String> {
    container()["env"]
        .as_sequence()
        .expect("the container has an environment")
        .iter()
        .map(|entry| {
            (
                entry["name"].as_str().expect("a named variable").to_owned(),
                // Only literals: a valueFrom here would mean the manifest no
                // longer says what the binary will be given, and this file
                // could no longer check it.
                entry["value"]
                    .as_str()
                    .unwrap_or_else(|| {
                        panic!(
                            "{} has no literal value",
                            entry["name"].as_str().unwrap_or("?")
                        )
                    })
                    .to_owned(),
            )
        })
        .collect()
}

/// Where the container mounts things, by volume name.
fn mounts() -> HashMap<String, Value> {
    container()["volumeMounts"]
        .as_sequence()
        .expect("the container mounts its configuration")
        .iter()
        .map(|mount| {
            (
                mount["name"].as_str().expect("a named mount").to_owned(),
                mount.clone(),
            )
        })
        .collect()
}

/// The HTTP probe the manifest declares under `kind`.
fn probe(kind: &str) -> Value {
    container()[kind]["httpGet"].clone()
}

/// A running binary, killed when the test lets go of it.
#[derive(Debug)]
struct Started {
    child: tokio::process::Child,
    /// The address it announced on stdout.
    address: String,
    /// The second address it announced: the operator's surface, where /health,
    /// /api-info and /metrics answer and no tenant may knock (bead gc-wdt).
    operator: String,
}

impl Drop for Started {
    fn drop(&mut self) {
        // start_kill rather than kill().await: Drop cannot await, and a bound
        // port left behind would make the next run flaky.
        let _ = self.child.start_kill();
    }
}

/// Runs the binary with exactly this environment and returns what it said.
///
/// Either it is running and announced an address, or it exited with a
/// complaint. Nothing else: these tests are about whether a variable was
/// obeyed, and both outcomes are evidence of that.
async fn started_with(env: HashMap<String, String>) -> Result<Started, String> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_webhook-proxy"));
    command
        .env_clear()
        // No waiting. The binary waits for configuration to appear before
        // refusing (gc-6b7), which is right in a pod and wrong here: these tests
        // point a variable somewhere decisive and read the complaint, and
        // nothing is going to render a file underneath them.
        .env("WEBHOOK_PROXY_STARTUP_WAIT_MS", "0")
        // An ephemeral operator port too (bead gc-wdt), or these tests race for
        // the one default.
        .env("WEBHOOK_PROXY_OPERATOR_LISTEN", "127.0.0.1:0")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in env {
        command.env(name, value);
    }

    let mut child = command.spawn().expect("the binary runs");
    let stdout = child.stdout.take().expect("stdout is piped");
    let mut lines = BufReader::new(stdout).lines();

    let announced = tokio::time::timeout(Duration::from_secs(10), lines.next_line())
        .await
        .map_err(|_| "the binary printed nothing within ten seconds".to_owned())?
        .map_err(|why| why.to_string())?;

    if let Some(line) = announced {
        let address = line
            .strip_prefix("listening on ")
            .ok_or_else(|| format!("unexpected first line: {line}"))?
            .to_owned();
        let second = tokio::time::timeout(Duration::from_secs(10), lines.next_line())
            .await
            .map_err(|_| "the binary announced one address and not the other".to_owned())?
            .map_err(|why| why.to_string())?
            .ok_or_else(|| "the binary exited after announcing one address".to_owned())?;
        let operator = second
            .strip_prefix("operator listening on ")
            .ok_or_else(|| format!("unexpected second line: {second}"))?
            .to_owned();
        Ok(Started {
            child,
            address,
            operator,
        })
    } else {
        // It exited. EVERYTHING it said is the evidence, not just the first
        // line: the binary may legitimately say something before it refuses --
        // that it is waiting for configuration, or that it is holding
        // deliveries in memory (bead gc-f7t) -- and a harness that read one
        // line would turn any such line into a test failure somewhere else
        // entirely. Reading to the end is safe because the process has already
        // exited.
        let mut why = String::new();
        if let Some(mut stderr) = child.stderr.take() {
            let _ = stderr.read_to_string(&mut why).await;
        }
        Err(why)
    }
}

/// A routing file and secrets directory the binary will accept, on disk.
fn a_usable_configuration() -> (tempfile::TempDir, String, String) {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let secrets = dir.path().join("secrets");
    fs::create_dir(&secrets).expect("writable");
    fs::write(secrets.join("a-secret"), "not-a-real-secret").expect("writable");
    fs::write(secrets.join("a-room-url"), "http://127.0.0.1:1/hook").expect("writable");

    let file = dir.path().join("config.yaml");
    fs::write(
        &file,
        "version: 1
tenants:
  - a-tenant
origins:
  - id: a-forge
    tenant: a-tenant
    speaks: github
    verify:
      hmac_sha256:
        secret: a-secret
",
    )
    .expect("writable");

    let as_text = |path: &std::path::Path| path.to_str().expect("a utf-8 path").to_owned();
    let (file, secrets) = (as_text(&file), as_text(&secrets));
    // The directory is handed back so it outlives the call: dropping it here
    // would delete the files before the binary read them.
    (dir, file, secrets)
}

#[tokio::test]
async fn the_probe_path_in_the_manifest_is_a_path_the_binary_answers() {
    // Taken from the manifest, not written here. A probe pointed at a path the
    // binary does not serve makes every pod unready, and the manifest looks
    // perfectly reasonable while it happens.
    let path = probe("readinessProbe")["path"]
        .as_str()
        .expect("the readiness probe is an HTTP GET")
        .to_owned();
    let alive = probe("livenessProbe")["path"]
        .as_str()
        .expect("the liveness probe is an HTTP GET")
        .to_owned();

    // THE TWO PROBES MUST DIFFER, and this assertion used to say the opposite
    // — that they must agree, which was right while there was only one answer
    // to give. Bead gc-28a split the questions: liveness answers from the
    // process alone, because restarting will not reach a database that is down;
    // readiness asks the store, because a pod that cannot store a delivery
    // should not be in the Service. A manifest that pointed both at the same
    // path would have thrown one of those away, silently.
    assert_ne!(
        path, alive,
        "both probes ask the same question, so one of them is not being asked"
    );

    let (dir, file, secrets) = a_usable_configuration();
    let running = started_with(HashMap::from([
        ("WEBHOOK_PROXY_LISTEN".to_owned(), "127.0.0.1:0".to_owned()),
        ("WEBHOOK_PROXY_CONFIG".to_owned(), file),
        ("WEBHOOK_PROXY_SECRETS_DIR".to_owned(), secrets),
    ]))
    .await
    .expect("the binary starts");

    // ON THE OPERATOR SOCKET, because that is the port both probes name since
    // bead gc-wdt. The number itself is checked against the manifest in
    // `the_port_is_the_same_number_everywhere_it_appears`; what this proves is
    // that the path answers on the socket that port belongs to.
    let answer = reqwest::get(format!("http://{}{path}", running.operator))
        .await
        .expect("the binary answers the probe path");

    // The liveness path too, on the same socket: two probes naming two paths is
    // two chances for a manifest to name one the binary does not serve.
    let living = reqwest::get(format!("http://{}{alive}", running.operator))
        .await
        .expect("the binary answers the liveness path");
    assert!(
        living.status().is_success(),
        "{alive} answered {:?}",
        living.status()
    );

    // And not on the tenant-facing one, which is the whole reason the probe had
    // to move: a probe aimed there would get this 404 and hold every pod
    // unready.
    let elsewhere = reqwest::get(format!("http://{}{path}", running.address))
        .await
        .expect("the tenant-facing listener answers");
    assert_eq!(
        elsewhere.status(),
        reqwest::StatusCode::NOT_FOUND,
        "{path} is served to every tenant as well"
    );

    assert!(
        answer.status().is_success(),
        "{path} answered {:?}",
        answer.status()
    );
    drop((running, dir));
}

#[tokio::test]
async fn the_manifest_names_the_variable_the_binary_reads_for_its_routing_file() {
    // The oracle: point the manifest's own variable at a file that is not there.
    // If the name is the one the binary reads, it refuses to start and names that
    // file. If the name is misspelled, the binary silently falls back to
    // /etc/webhook-proxy/config.yaml — and would start, or complain about the
    // wrong path.
    let (name, _) = environment()
        .into_iter()
        .find(|(name, value)| {
            name.contains("CONFIG")
                && std::path::Path::new(value)
                    .extension()
                    .is_some_and(|kind| kind.eq_ignore_ascii_case("yaml"))
        })
        .expect("the manifest tells the binary where its routing file is");

    let dir = tempfile::tempdir().expect("a temporary directory");
    let absent = dir.path().join("not-mounted.yaml");

    let why = started_with(HashMap::from([(
        name.clone(),
        absent.to_str().expect("a utf-8 path").to_owned(),
    )]))
    .await
    .expect_err("a missing routing file must stop the process");

    assert!(
        why.contains("not-mounted.yaml"),
        "{name} is not the variable the binary reads: {why}"
    );
}

#[tokio::test]
async fn the_manifest_names_the_variable_the_binary_reads_for_its_secrets() {
    // The oracle has to run the other way round here. Pointing the variable at
    // an empty directory proves nothing: the binary's own fallback,
    // /etc/webhook-proxy/secrets, is also empty on any machine this test runs
    // on, so a misspelled name produces exactly the same complaint. A mutation
    // run caught that — the first version of this test passed with the name
    // changed to WEBHOOK_PROXY_SECRETS_PATH.
    //
    // So: point it at a directory that *does* hold every secret the routing file
    // names, and assert the process starts. Starting is only possible if the
    // binary looked where the manifest pointed.
    let fallback = std::path::Path::new("/etc/webhook-proxy/secrets");
    assert!(
        !fallback.exists(),
        "{fallback:?} exists on this machine, so this test cannot tell a correct \
         variable name from a misspelled one"
    );

    let (name, _) = environment()
        .into_iter()
        .find(|(name, _)| name.contains("SECRETS"))
        .expect("the manifest tells the binary where its secrets are mounted");

    let (dir, file, secrets) = a_usable_configuration();

    let running = started_with(HashMap::from([
        ("WEBHOOK_PROXY_LISTEN".to_owned(), "127.0.0.1:0".to_owned()),
        ("WEBHOOK_PROXY_CONFIG".to_owned(), file),
        (name.clone(), secrets),
    ]))
    .await
    .unwrap_or_else(|why| panic!("{name} is not the directory the binary reads: {why}"));

    drop((running, dir));
}

#[tokio::test]
async fn the_manifest_names_the_variable_the_binary_reads_for_its_listen_address() {
    // BY NAME, NOT BY SUBSTRING. Two variables contain "LISTEN" since bead
    // gc-wdt, so `find(|name| name.contains("LISTEN"))` would have picked one
    // of them by HashMap order — a test that passes or fails depending on
    // nothing.
    let declared = environment()
        .get("WEBHOOK_PROXY_LISTEN")
        .expect("the manifest tells the binary where to listen")
        .clone();
    let name = "WEBHOOK_PROXY_LISTEN".to_owned();

    let (dir, file, secrets) = a_usable_configuration();
    // An address no host can bind. Obeyed, the process refuses to start and says
    // which variable; ignored, it starts happily on the default.
    let why = started_with(HashMap::from([
        (name.clone(), "203.0.113.1:9".to_owned()),
        ("WEBHOOK_PROXY_CONFIG".to_owned(), file),
        ("WEBHOOK_PROXY_SECRETS_DIR".to_owned(), secrets),
    ]))
    .await
    .expect_err("an unbindable address must stop the process");

    assert!(
        why.contains(&name),
        "{name} is not the variable the binary reads: {why}"
    );

    // And the value itself, which no amount of starting the binary can judge: in
    // a pod, loopback is reachable by nothing — not the probe, not the Service.
    assert!(
        declared.starts_with("0.0.0.0:"),
        "a pod that listens on {declared} answers no probe and no Service"
    );
    drop(dir);
}

#[tokio::test]
async fn the_manifest_names_the_variable_the_binary_reads_for_its_operator_address() {
    // The second socket is only a boundary if the binary actually reads this
    // name (bead gc-wdt). Pointed at an address no host can bind, the process
    // must refuse and say which variable — ignored, it would quietly serve
    // /metrics on its loopback default and the manifest would be describing a
    // socket nobody is listening on.
    let declared = environment()
        .get("WEBHOOK_PROXY_OPERATOR_LISTEN")
        .expect("the manifest tells the binary where to serve the operator's surface")
        .clone();

    let (dir, file, secrets) = a_usable_configuration();
    let why = started_with(HashMap::from([
        (
            "WEBHOOK_PROXY_OPERATOR_LISTEN".to_owned(),
            "203.0.113.1:9".to_owned(),
        ),
        ("WEBHOOK_PROXY_LISTEN".to_owned(), "127.0.0.1:0".to_owned()),
        ("WEBHOOK_PROXY_CONFIG".to_owned(), file),
        ("WEBHOOK_PROXY_SECRETS_DIR".to_owned(), secrets),
    ]))
    .await
    .expect_err("an unbindable operator address must stop the process");

    assert!(
        why.contains("WEBHOOK_PROXY_OPERATOR_LISTEN"),
        "WEBHOOK_PROXY_OPERATOR_LISTEN is not the variable the binary reads: {why}"
    );
    assert!(
        declared.starts_with("0.0.0.0:"),
        "a pod that serves the operator's surface on {declared} answers no probe and no scrape"
    );
    drop(dir);
}

#[test]
fn the_port_is_the_same_number_everywhere_it_appears() {
    let declared = environment();
    let port_of = |name: &str| {
        declared
            .get(name)
            .unwrap_or_else(|| panic!("the manifest sets {name}"))
            .strip_prefix("0.0.0.0:")
            .unwrap_or_else(|| panic!("{name} is not a 0.0.0.0 address"))
            .parse::<u64>()
            .expect("a port number")
    };
    // TWO PORTS SINCE BEAD gc-wdt, and which is which is the whole point: 8080
    // is reachable by every tenant because the hand-off lives there, 9090 by
    // the cluster's own machinery. A test that only checked "the same number
    // everywhere" would now pass with the two swapped.
    let tenants = port_of("WEBHOOK_PROXY_LISTEN");
    let operator = port_of("WEBHOOK_PROXY_OPERATOR_LISTEN");
    assert_ne!(
        tenants, operator,
        "both surfaces are on one socket, so every tenant can read every other \
         tenant's room names (bead gc-wdt)"
    );

    let declared_ports: std::collections::BTreeMap<String, u64> = container()["ports"]
        .as_sequence()
        .expect("the container declares its ports")
        .iter()
        .map(|entry| {
            (
                entry["name"].as_str().expect("a named port").to_owned(),
                entry["containerPort"].as_u64().expect("a port number"),
            )
        })
        .collect();
    assert_eq!(
        declared_ports.values().copied().collect::<Vec<u64>>(),
        {
            let mut both = vec![tenants, operator];
            both.sort_unstable();
            both
        },
        "the declared containerPorts are not the ports the binary is told to bind: \
         {declared_ports:?}"
    );

    // BOTH PROBES NAME THE OPERATOR PORT, because that is where /health answers
    // now. Aimed at the tenant-facing port they would get a 404 and every pod
    // would be permanently unready — which is the one way this split can break a
    // deployment, so it is the assertion to keep.
    for kind in ["readinessProbe", "livenessProbe"] {
        assert_eq!(
            probe(kind)["port"].as_u64(),
            Some(operator),
            "the {kind} is aimed at a port where /health does not answer"
        );
    }

    let service: Value = serde_yaml_ng::from_str(SERVICE).expect("the Service parses");
    let forwarded: Vec<u64> = service["spec"]["ports"]
        .as_sequence()
        .expect("the Service forwards something")
        .iter()
        .map(|entry| entry["targetPort"].as_u64().expect("a port number"))
        .collect();
    assert!(
        forwarded.contains(&tenants),
        "the Service does not forward to the port the senders and the agents use: {forwarded:?}"
    );
    assert!(
        forwarded.contains(&operator),
        "the Service does not publish the operator port, so a ServiceMonitor has \
         nothing to name: {forwarded:?}"
    );

    // The NetworkPolicy filters the pod's port, not the Service's, because it
    // is evaluated after the Service has rewritten the destination. Here the
    // Service's numbers equal the pod's deliberately, so naming the wrong one
    // would pass — and would go on passing until somebody made them differ, by
    // which time the policy would be denying the traffic it was written to
    // allow.
    let policy: Value = serde_yaml_ng::from_str(POLICY).expect("the NetworkPolicy parses");
    let allowed = policy["spec"]["ingress"]
        .as_sequence()
        .expect("the policy allows something");
    assert!(!allowed.is_empty(), "the policy allows nothing in");

    let mut granted_the_operator_port = 0;
    for rule in allowed {
        let ports = rule["ports"]
            .as_sequence()
            .expect("a rule names the ports it allows");
        assert!(
            !ports.is_empty(),
            "a rule names no port, so it allows every port this pod ever opens"
        );

        // Which rule this is, read from what it selects rather than from its
        // position: a rule that admits a tenant's agent must never name the
        // operator port, because that is the leak this bead closed.
        let selects = serde_yaml_ng::to_string(&rule["from"]).expect("the rule's selectors");
        let for_a_tenant = selects.contains("agent");

        for port in ports {
            let port = port["port"].as_u64();
            assert!(
                port == Some(tenants) || port == Some(operator),
                "the policy allows a port nothing listens on: {port:?}"
            );
            if port == Some(operator) {
                assert!(
                    !for_a_tenant,
                    "a rule admitting a tenant's agent grants the operator port, which \
                     is how every tenant could read every other tenant's room names \
                     (bead gc-wdt)"
                );
                granted_the_operator_port += 1;
            }
        }
    }
    assert_eq!(
        granted_the_operator_port, 1,
        "the operator port is granted by {granted_the_operator_port} rules; it should \
         be exactly one, the scraper's"
    );
}

#[test]
fn the_configured_paths_are_the_paths_the_volumes_are_mounted_at() {
    let declared = environment();
    let mounted = mounts();

    let file = declared
        .iter()
        .find(|(name, _)| name.contains("CONFIG"))
        .map(|(_, value)| std::path::PathBuf::from(value))
        .expect("a routing file");
    let directory = file.parent().expect("a parent directory");

    let paths: Vec<&str> = mounted
        .values()
        .map(|mount| mount["mountPath"].as_str().expect("a mount path"))
        .collect();

    assert!(
        paths.contains(&directory.to_str().expect("a utf-8 path")),
        "the routing file is read from {directory:?}, which nothing is mounted at: {paths:?}"
    );
    assert!(
        paths.contains(
            &declared
                .iter()
                .find(|(name, _)| name.contains("SECRETS"))
                .map(|(_, value)| value.as_str())
                .expect("a secrets directory")
        ),
        "the secrets directory is read from a path nothing is mounted at: {paths:?}"
    );

    for (name, mount) in &mounted {
        assert_eq!(
            mount["readOnly"].as_bool(),
            Some(true),
            "{name} is writable; nothing here is ever written, and the root filesystem is read-only"
        );
    }
}

#[test]
fn the_image_is_one_that_was_published_rather_than_built_here() {
    // The gc-kow decision: the release workflow publishes, this consumes. A
    // manifest that referred to a locally built tag would be a second path, and
    // the two would diverge the first time only one of them was rebuilt.
    let container = container();
    let image = container["image"].as_str().expect("an image reference");

    // Named by registry rather than by the one registry, because a cluster
    // whose pods have no route to the internet has to pull this through its own
    // mirror — the OpenShift estate pulls everything through Nexus (gc-hzn).
    // "Published" is the property that matters, and what proves it is a
    // registry host and a tag: a bare `webhook-proxy:dev` resolves to whatever
    // happens to be in the node's image store, which is the second build path
    // gc-kow exists to forbid.
    // Split the digest off before the tag: a digest contains a colon of its
    // own, so looking for the last colon in `repo@sha256:abc` finds the wrong
    // one. Pinning by digest is better than pinning by tag and should not be
    // the thing this test rejects.
    let (repository, reference) = match image.split_once('@') {
        Some((repository, digest)) => (repository, digest),
        None => image
            .rsplit_once(':')
            .expect("an image with a tag or a digest"),
    };
    assert!(
        repository
            .split('/')
            .next()
            .is_some_and(|host| host.contains('.') || host.contains(':')),
        "{image} names no registry, so it resolves to whatever the node already has"
    );
    assert!(
        repository.ends_with("/webhook-proxy"),
        "{image} is not this product, whatever else it is"
    );
    assert!(
        !reference.is_empty() && reference != "latest",
        "{image} names no particular build, so a rollback has nothing to roll back to"
    );
}

#[test]
fn the_route_publishes_the_webhook_path_and_nothing_else() {
    // /health and /metrics both exist for machines that reach the pod directly
    // — kubelet and Prometheus — and neither is routed. Publishing /health
    // would hand the internet a free liveness oracle for an internal service;
    // publishing /metrics would hand it which rooms exist and how busy each one
    // is. Publishing / would hand it everything added later by accident, which
    // is the failure this assertion is really for: it is written as "exactly
    // /webhook" rather than "not /health", so an endpoint nobody thought about
    // is excluded by default.
    let route: Value = serde_yaml_ng::from_str(ROUTE).expect("the HTTPRoute parses");
    let rules = route["spec"]["rules"]
        .as_sequence()
        .expect("the route has rules");

    let published: Vec<&str> = rules
        .iter()
        .flat_map(|rule| {
            rule["matches"]
                .as_sequence()
                .expect("a rule matches something")
                .iter()
                .map(|matched| matched["path"]["value"].as_str().expect("a path"))
        })
        .collect();

    assert_eq!(
        published,
        vec!["/webhook"],
        "the route publishes more than the webhook endpoint"
    );
}

#[test]
fn the_containerfile_declares_the_stage_the_release_workflow_will_name() {
    // gc-lw3 will put `target: runtime` in .github/artifacts.yml. Renaming the
    // stage here would break a release and nothing else, which is the worst time
    // to find out.
    assert!(
        CONTAINERFILE.contains("AS runtime"),
        "the runtime stage is not named `runtime`"
    );
    // No target triple on the build itself. Cross-compiling to a fixed triple
    // would make one architecture the real one and the other a thing that only
    // breaks in the pipeline nobody watches. BuildKit's own
    // `--mount=type=cache,target=` is a different flag and is why this looks at
    // the cargo invocation rather than the whole file.
    let building: Vec<&str> = CONTAINERFILE
        .lines()
        .filter(|line| line.contains("cargo build"))
        .collect();
    assert_eq!(building.len(), 1, "exactly one build, please: {building:?}");
    assert!(
        !building[0].contains("--target"),
        "a pinned target triple would make one architecture a special case"
    );

    // BOTH BINARIES, from one build. They are two deployments that ship
    // together — one commit, one gate, one tag — so a platform and an agent
    // that disagree about the hand-off format cannot come from the same tag.
    // Two images would make that possible, and nothing but
    // crates/app/tests/cutover.rs checks that agreement.
    for binary in ["webhook-proxy", "alert-agent"] {
        assert!(
            building[0].contains(&format!("--bin {binary}")),
            "{binary} is not built: {}",
            building[0]
        );
        assert!(
            CONTAINERFILE.contains(&format!("/usr/local/bin/{binary} /usr/local/bin/{binary}")),
            "{binary} is built and not copied into the runtime stage"
        );
    }

    // The context is the whole workspace, so the host's build output has to be
    // excluded from it — not for size, though it is gigabytes, but because a
    // COPY of target/ lands under the cache mount the build uses for the same
    // path and leaves cargo reading artefacts built for another platform.
    assert!(
        IGNORED.lines().any(|line| line.trim() == "target/"),
        "the host's target/ would be copied into the build context"
    );
}

/// Every secret this deployment asks for, from both places that can name one.
///
/// The routing file names a secret per Origin and per Destination. The database
/// is named in the environment instead, because which store a Dispatch waits in
/// is a choice at the composition root and not part of routing (bead gc-vfz).
/// Both are secrets the agent has to render, so both belong in one set.
fn secrets_this_deployment_asks_for() -> std::collections::BTreeSet<String> {
    let mut asked = secrets_named_by_the_routing_file();
    if let Some(name) = environment().get("WEBHOOK_PROXY_DATABASE_SECRET") {
        asked.insert(name.clone());
    }
    asked
}

#[test]
fn the_agent_renders_exactly_the_secrets_this_deployment_asks_for() {
    // The failure this prevents is quiet and total: add a room to the routing
    // file, forget its template stanza, and the pod waits for a secret nothing
    // will ever write — then refuses, naming a file whose absence is explained
    // nowhere. The two lists are written in different files in different
    // languages, so nothing but this keeps them in step.
    //
    // The database secret is the same failure with a worse blast radius, which
    // is why it is in this set rather than checked beside it: name it in the
    // environment and forget the stanza, and the proxy refuses to start at all
    // rather than refusing one Origin.
    assert_eq!(
        files_the_agent_renders(),
        secrets_this_deployment_asks_for(),
        "the agent and this deployment disagree about which secrets exist"
    );
}

#[test]
fn the_deployment_names_a_database_so_a_dispatch_outlives_the_process() {
    // Bead gc-vfz. The outbox, the sweep and replay all landed and were reachable
    // from nowhere: WEBHOOK_PROXY_DATABASE_SECRET was set in no deployment, so
    // stored() fell back to memory everywhere and main.rs's claim that anything
    // mid-way through "is still in the outbox" was false wherever it ran.
    //
    // This asserts the switch is on, not that the database works. What makes it
    // meaningful is the paired test above: naming the secret here obliges the
    // agent to render it, and the proxy refuses to start without it — so a
    // deployment built from these manifests is durable or it is not running.
    // There is no third state for a sender to be unable to see.
    let declared = environment();
    let name = declared
        .get("WEBHOOK_PROXY_DATABASE_SECRET")
        .expect("the deployment names the secret holding the database URL");

    assert!(
        !name.trim().is_empty(),
        "WEBHOOK_PROXY_DATABASE_SECRET is present but empty, which the binary \
         reads as 'no database' — the filter in Config::from_environment treats \
         a blank name as absent, so this would silently keep the memory outbox"
    );
}

#[test]
fn more_than_one_replica_requires_a_shared_store() {
    // BEAD gc-f7t. These two lines are a pair and nothing said so: replicas: 2
    // is only correct because WEBHOOK_PROXY_DATABASE_SECRET is set, so every
    // replica answers out of the same store. Drop one and keep the other and
    // the deployment is silently broken -- which is what happened when these
    // manifests were adapted for a dev cluster: replicas: 2 came across, the
    // database did not, and two replicas each held their own memory store.
    //
    // What that looked like is the reason this is a test and not a comment: a
    // webhook landed in replica A's memory, the agent's claim was load-balanced
    // to B and got an empty list, its report was load-balanced to B and got a
    // 404, and the symptoms were a duplicate in a room and a delivered counter
    // that disagreed with what the room received. Nothing in that points at a
    // replica count, and setting replicas: 1 fixed it instantly.
    //
    // THIS CANNOT CATCH ANOTHER REPOSITORY'S RENDERING -- the trimming happened
    // in wallet-iac-k3s, which this test cannot see. What it does is keep THIS
    // repository from ever shipping the broken pair, and state the rule in the
    // one place that fails loudly. deploy/webhook-proxy/README.md carries it in
    // prose for whoever adapts these files.
    let manifest: Value = serde_yaml_ng::from_str(DEPLOYMENT).expect("the Deployment parses");
    let replicas = manifest["spec"]["replicas"].as_u64().expect(
        "the Deployment says how many replicas it wants, rather than leaving it to a default",
    );

    if replicas > 1 {
        let declared = environment();
        let named = declared
            .get("WEBHOOK_PROXY_DATABASE_SECRET")
            .map(String::as_str)
            .unwrap_or_default();

        assert!(
            !named.trim().is_empty(),
            "this Deployment asks for {replicas} replicas and names no database, so each              replica would hold its own memory store: a claim or a report can reach a              replica that has never heard of the delivery. Either name              WEBHOOK_PROXY_DATABASE_SECRET or set replicas: 1 (bead gc-f7t)"
        );
    }
}

#[test]
fn every_rendered_secret_is_readable_by_the_group_the_proxy_runs_as() {
    // The agent writes these files and the proxy reads them. Owner-only means
    // nobody, and the symptom is a pod reporting a secret as absent for a file
    // that is present and unreadable — which this deployment has already paid
    // for once, on the Secret that preceded this (gc-d01).
    //
    // This now carries weight `fsGroup: 65532` used to. With no pod-level ids
    // (see deployment.yaml), what the two containers are guaranteed to share is
    // the group, not the uid: a cluster that assigns a uid per namespace still
    // runs both with the same primary group. Group-read is therefore the
    // mechanism and not a belt-and-braces second one.
    let granting: Vec<&str> = AGENT
        .lines()
        .filter_map(|line| line.trim().strip_prefix("perms"))
        .map(str::trim)
        .collect();

    assert_eq!(
        granting.len(),
        files_the_agent_renders().len(),
        "a template renders a file without saying who may read it: {granting:?}"
    );
    for perms in granting {
        let mode = perms
            .trim_start_matches(['=', ' '])
            .trim_matches('"')
            .to_owned();
        let group = mode
            .chars()
            .nth(2)
            .and_then(|digit| digit.to_digit(8))
            .expect("an octal mode");
        assert!(group & 0b100 != 0, "{mode} is not readable by the group");
    }
}

#[test]
fn the_rendered_secrets_never_reach_a_disk() {
    // The volume the proxy reads its secrets from is also the one the agent
    // writes them to, and it has to be memory-backed. An ordinary emptyDir is a
    // directory on the node, so every secret this proxy holds would be written
    // to a disk nobody thinks of as holding secrets.
    let declared = environment();
    let directory = declared
        .iter()
        .find(|(name, _)| name.contains("SECRETS"))
        .map(|(_, value)| value.clone())
        .expect("a secrets directory");

    let mounted = mounts();
    let (holding, mount) = mounted
        .iter()
        .find(|(_, mount)| mount["mountPath"].as_str() == Some(directory.as_str()))
        .expect("something is mounted where the secrets are read from");

    assert_eq!(
        mount["readOnly"].as_bool(),
        Some(true),
        "the proxy never writes a secret; it should not be able to"
    );
    assert_eq!(
        volumes()[holding]["emptyDir"]["medium"].as_str(),
        Some("Memory"),
        "{holding} is backed by the node's disk, so every secret is written to it"
    );
}

#[test]
fn something_in_the_pod_actually_fills_the_directory_the_proxy_waits_on() {
    // The proxy waits for its secrets and then refuses (gc-6b7). If nothing in
    // the pod writes to that volume, the wait is the whole of the start-up and
    // the refusal is guaranteed — a manifest that looks complete and produces a
    // pod that can never start.
    let directory = environment()
        .into_iter()
        .find(|(name, _)| name.contains("SECRETS"))
        .map(|(_, value)| value)
        .expect("a secrets directory");

    let filling: Vec<String> = containers()
        .into_iter()
        .filter(|(name, _)| name != "webhook-proxy")
        .filter(|(_, container)| {
            container["volumeMounts"]
                .as_sequence()
                .is_some_and(|mounts| {
                    mounts.iter().any(|mount| {
                        mount["mountPath"].as_str() == Some(directory.as_str())
                            && mount["readOnly"].as_bool() != Some(true)
                    })
                })
        })
        .map(|(name, _)| name)
        .collect();

    assert_eq!(
        filling.len(),
        1,
        "exactly one container should write the secrets the proxy reads, found {filling:?}"
    );
}

#[test]
fn no_user_or_group_id_is_hardcoded_so_a_cluster_that_assigns_one_can() {
    // This manifest named 65532 three times and was right to, on a cluster that
    // lets a workload choose. OpenShift's `restricted-v2` does not: it assigns
    // a uid from the namespace's `openshift.io/sa.scc.uid-range` and refuses a
    // pod that names its own, and it range-checks `fsGroup` the same way. The
    // platform has the receipt for a chart that hardcoded 10001.
    //
    // Written as "none of these keys appear" rather than "the uid is not
    // 65532", because a different number would fail in exactly the same way and
    // for the same reason. Bead gc-hzn.
    let manifest: Value = serde_yaml_ng::from_str(DEPLOYMENT).expect("the Deployment parses");
    let pod = &manifest["spec"]["template"]["spec"]["securityContext"];

    for assigned in ["runAsUser", "runAsGroup", "fsGroup", "supplementalGroups"] {
        assert!(
            pod[assigned].is_null(),
            "the pod names its own {assigned}, which a cluster that assigns ids will refuse"
        );
    }
    for (name, container) in containers() {
        for assigned in ["runAsUser", "runAsGroup"] {
            assert!(
                container["securityContext"][assigned].is_null(),
                "{name} names its own {assigned}, which a cluster that assigns ids will refuse"
            );
        }
    }

    // And the part that must survive the removal: not naming a uid is not the
    // same as accepting root. `runAsNonRoot` says the only thing this workload
    // actually needs to say about who it runs as.
    assert_eq!(
        pod["runAsNonRoot"].as_bool(),
        Some(true),
        "nothing requires a non-root uid any more, so an image defaulting to root would run as root"
    );
}

#[test]
fn every_manifest_in_the_directory_is_one_the_kustomization_applies() {
    // A manifest that is written, reviewed, committed and never applied. The
    // NetworkPolicy this bead added would have been exactly that if the
    // kustomization had not been edited too, and nothing would have said so:
    // `kubectl apply -k` would succeed, the pod would come up, and on a cluster
    // with default-deny it would be unreachable for the original reason.
    let directory = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/webhook-proxy");
    let applied: Vec<&str> = KUSTOMIZATION
        .lines()
        .filter_map(|line| line.trim().strip_prefix("- "))
        .map(str::trim)
        .collect();

    let mut unapplied: Vec<String> = Vec::new();
    for entry in fs::read_dir(directory).expect("the deployment directory is readable") {
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
        // A file named anywhere in the kustomization counts: a generator names
        // its input as `config.yaml=config.example.yaml`, which is applied just
        // as much as a resource is, only not as one.
        if !applied.iter().any(|line| line.contains(&name)) {
            unapplied.push(name);
        }
    }

    assert!(
        unapplied.is_empty(),
        "{unapplied:?} will never be applied: nothing in kustomization.yaml names them"
    );
}
