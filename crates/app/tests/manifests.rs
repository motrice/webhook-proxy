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
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

const DEPLOYMENT: &str = include_str!("../../../deploy/webhook-proxy/deployment.yaml");
const SERVICE: &str = include_str!("../../../deploy/webhook-proxy/service.yaml");
const ROUTE: &str = include_str!("../../../deploy/webhook-proxy/httproute.yaml");
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
        Ok(Started { child, address })
    } else {
        // It exited. Its complaint is the evidence.
        let mut why = String::new();
        if let Some(stderr) = child.stderr.take() {
            let _ = BufReader::new(stderr).read_line(&mut why).await;
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
origins:
  - id: a-forge
    speaks: github
    verify:
      hmac_sha256:
        secret: a-secret
destinations:
  - id: a-room
    kind: chat_room
    webhook:
      secret: a-room-url
subscriptions:
  - destination: a-room
    match:
      origin: a-forge
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
    assert_eq!(
        probe("livenessProbe")["path"].as_str(),
        Some(path.as_str()),
        "the two probes must agree, or one of them is testing nothing"
    );

    let (dir, file, secrets) = a_usable_configuration();
    let running = started_with(HashMap::from([
        ("WEBHOOK_PROXY_LISTEN".to_owned(), "127.0.0.1:0".to_owned()),
        ("WEBHOOK_PROXY_CONFIG".to_owned(), file),
        ("WEBHOOK_PROXY_SECRETS_DIR".to_owned(), secrets),
    ]))
    .await
    .expect("the binary starts");

    let answer = reqwest::get(format!("http://{}{path}", running.address))
        .await
        .expect("the binary answers the probe path");

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
    let (name, declared) = environment()
        .into_iter()
        .find(|(name, _)| name.contains("LISTEN"))
        .expect("the manifest tells the binary where to listen");

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

#[test]
fn the_port_is_the_same_number_everywhere_it_appears() {
    let declared = environment();
    let listen = declared
        .values()
        .find_map(|value| value.strip_prefix("0.0.0.0:"))
        .expect("a listen address")
        .parse::<u64>()
        .expect("a port number");

    assert_eq!(
        container()["ports"][0]["containerPort"].as_u64(),
        Some(listen),
        "the declared containerPort is not the port the binary is told to bind"
    );
    assert_eq!(
        probe("readinessProbe")["port"].as_u64(),
        Some(listen),
        "the readiness probe is aimed at a port nothing listens on"
    );
    assert_eq!(
        probe("livenessProbe")["port"].as_u64(),
        Some(listen),
        "the liveness probe is aimed at a port nothing listens on"
    );

    let service: Value = serde_yaml_ng::from_str(SERVICE).expect("the Service parses");
    assert_eq!(
        service["spec"]["ports"][0]["targetPort"].as_u64(),
        Some(listen),
        "the Service forwards to a port nothing listens on"
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

    assert!(
        image.starts_with("ghcr.io/motrice/webhook-proxy:"),
        "{image} is not the published image"
    );
    assert!(
        !image.ends_with(":latest"),
        "{image} names no particular build, so a rollback has nothing to roll back to"
    );
}

#[test]
fn the_route_publishes_the_webhook_path_and_nothing_else() {
    // /health exists for kubelet, which reaches the pod directly. Publishing it
    // would hand the internet a free liveness oracle for an internal service,
    // and publishing / would hand it everything added later by accident.
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

    // The context is the whole workspace, so the host's build output has to be
    // excluded from it — not for size, though it is gigabytes, but because a
    // COPY of target/ lands under the cache mount the build uses for the same
    // path and leaves cargo reading artefacts built for another platform.
    assert!(
        IGNORED.lines().any(|line| line.trim() == "target/"),
        "the host's target/ would be copied into the build context"
    );
}

#[test]
fn the_agent_renders_exactly_the_secrets_the_routing_file_names() {
    // The failure this prevents is quiet and total: add a room to the routing
    // file, forget its template stanza, and the pod waits for a secret nothing
    // will ever write — then refuses, naming a file whose absence is explained
    // nowhere. The two lists are written in different files in different
    // languages, so nothing but this keeps them in step.
    assert_eq!(
        files_the_agent_renders(),
        secrets_named_by_the_routing_file(),
        "the agent and the routing file disagree about which secrets exist"
    );
}

#[test]
fn every_rendered_secret_is_readable_by_the_group_the_proxy_runs_as() {
    // The agent writes these files and the proxy reads them. Owner-only means
    // nobody, and the symptom is a pod reporting a secret as absent for a file
    // that is present and unreadable — which this deployment has already paid
    // for once, on the Secret that preceded this (gc-d01).
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
