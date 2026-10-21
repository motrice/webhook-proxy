//! One delivery, one room, exactly one message — across both binaries.
//!
//! THE TEST BEAD gc-72e.3.2 EXISTS FOR. Until that cutover two things
//! delivered: this service's own loop, and a tenant's agent. Nothing in a diff
//! shows that, because the fault is two working paths rather than one broken
//! one — so the property is pinned here instead, where re-enabling either path
//! fails a named test.
//!
//! IT ALSO CLOSES A GAP gc-72e.2 LEFT. The claim and report JSON is written in
//! `crates/app/src/collecting.rs` and read in `crates/agent/src/platform.rs`,
//! each with its own tests and nothing comparing the two: a renamed field would
//! pass every unit test in the workspace. Proving one message end to end
//! necessarily proves the two ends agree about the format.
//!
//! WHY THE AGENT BINARY IS FOUND BY PATH. `env!("CARGO_BIN_EXE_...")` resolves
//! only inside the crate that declares a binary, and these two are declared in
//! two crates, so neither can start both by that route. The agent is located
//! beside this test's own executable instead — which is where cargo puts it.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

const PAYLOAD: &[u8] = include_bytes!("../../adapters/github-signatures/fixtures/push.json");
const SIGNATURE: &str = include_str!("../../adapters/github-signatures/fixtures/push.signature");
const SECRET: &str = include_str!("../../adapters/github-signatures/fixtures/push.secret");

const ROOM: &str = "team-room";
const TENANT: &str = "a-tenant";

/// What a room was sent, as (hook id, body).
type Notices = Arc<Mutex<Vec<(String, String)>>>;

/// Kills the child when the test ends, however it ends.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.start_kill();
    }
}

/// The agent's binary, beside this test's own.
///
/// `current_exe` is `target/<profile>/deps/cutover-<hash>`, so the binaries sit
/// two directories up. Asserted rather than assumed: a path that silently did
/// not exist would make this test fail as a timeout, which is the least
/// informative way for it to fail.
fn agent_binary() -> PathBuf {
    let mut at = std::env::current_exe().expect("this test has a path");
    at.pop();
    at.pop();
    at.push("alert-agent");
    assert!(
        at.is_file(),
        "the agent binary is not at {}. Both binaries have to be built for this \
         test; `cargo test --workspace` does that.",
        at.display()
    );
    at
}

/// A stub room that records what it was told.
async fn a_room() -> (String, Notices) {
    let seen: Notices = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route(
            "/hook/{id}",
            post(
                move |State(seen): State<Notices>,
                      axum::extract::Path(id): axum::extract::Path<String>,
                      body: String| async move {
                    seen.lock().expect("not poisoned").push((id, body));
                    (StatusCode::OK, r#"{"ok":true}"#)
                },
            ),
        )
        .with_state(Arc::clone(&seen));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let address = listener.local_addr().expect("an address");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("the stub serves");
    });

    (format!("http://{address}/hook"), seen)
}

/// Stands in for the service mesh.
///
/// In a cluster the sidecar verifies the agent's certificate and SETS
/// `x-forwarded-client-cert` from it, replacing whatever the request carried.
/// There is no sidecar here, so this does the one thing the platform depends on
/// it for: it adds the header and forwards.
///
/// That this is needed at all IS the design. The agent never sends its own
/// identity — bead gc-nkb refused a parameter — so a test that wanted to claim
/// had to provide what the mesh provides, which is exactly the assumption
/// `crates/app/src/collecting.rs` documents.
async fn as_the_mesh_would(platform: String, namespace: &'static str) -> String {
    let client = reqwest::Client::new();
    let app = Router::new().fallback(move |request: axum::extract::Request| {
        let client = client.clone();
        let platform = platform.clone();
        async move {
            let (parts, body) = request.into_parts();
            let bytes = axum::body::to_bytes(body, 1 << 20)
                .await
                .expect("a readable body");
            let answered = client
                .request(parts.method.clone(), format!("{platform}{}", parts.uri))
                .headers(parts.headers.clone())
                .header(
                    "x-forwarded-client-cert",
                    format!(
                        "By=spiffe://cluster.local/ns/webhook-proxy/sa/webhook-proxy;\
                             Hash=0;Subject=\"\";\
                             URI=spiffe://cluster.local/ns/{namespace}/sa/alert-agent"
                    ),
                )
                .body(bytes)
                .send()
                .await
                .expect("the platform answers");

            let status = answered.status();
            let body = answered.bytes().await.expect("a body");
            (
                StatusCode::from_u16(status.as_u16()).expect("a status"),
                body,
            )
        }
    });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let address = listener.local_addr().expect("an address");
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("the mesh stub serves");
    });

    format!("http://{address}")
}

/// The platform's configuration, and the secrets it names.
fn platform_files(dir: &std::path::Path) -> HashMap<&'static str, String> {
    let secrets = dir.join("platform-secrets");
    fs::create_dir(&secrets).expect("writable");
    fs::write(secrets.join("github-webhook-secret"), SECRET).expect("writable");

    let file = dir.join("platform.yaml");
    fs::write(
        &file,
        format!(
            "version: 1
tenants:
  - {TENANT}
origins:
  - id: github
    tenant: {TENANT}
    speaks: github
    verify:
      hmac_sha256:
        secret: github-webhook-secret
"
        ),
    )
    .expect("writable");

    HashMap::from([
        (
            "WEBHOOK_PROXY_CONFIG",
            file.to_str().expect("a utf-8 path").to_owned(),
        ),
        (
            "WEBHOOK_PROXY_SECRETS_DIR",
            secrets.to_str().expect("a utf-8 path").to_owned(),
        ),
    ])
}

/// The tenant's configuration, naming the stub room.
fn agent_files(dir: &std::path::Path, room: &str) -> HashMap<&'static str, String> {
    let secrets = dir.join("agent-secrets");
    fs::create_dir(&secrets).expect("writable");
    fs::write(secrets.join("team-room-url"), format!("{room}/{ROOM}")).expect("writable");

    let file = dir.join("agent.yaml");
    fs::write(
        &file,
        format!(
            "version: 1
destinations:
  - id: {ROOM}
    kind: chat_room
    webhook:
      secret: team-room-url
subscriptions:
  - destination: {ROOM}
    match:
      origin: github
"
        ),
    )
    .expect("writable");

    HashMap::from([
        (
            "ALERT_AGENT_CONFIG",
            file.to_str().expect("a utf-8 path").to_owned(),
        ),
        (
            "ALERT_AGENT_SECRETS_DIR",
            secrets.to_str().expect("a utf-8 path").to_owned(),
        ),
    ])
}

/// Starts the platform and waits for it to say where it is listening.
async fn platform(env: &HashMap<&'static str, String>) -> (Running, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_webhook-proxy"));
    command
        .env_clear()
        .env("WEBHOOK_PROXY_LISTEN", "127.0.0.1:0")
        .env("WEBHOOK_PROXY_STARTUP_WAIT_MS", "0")
        // An ephemeral operator port too (bead gc-wdt), or these tests race for
        // the one default.
        .env("WEBHOOK_PROXY_OPERATOR_LISTEN", "127.0.0.1:0")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    for (name, value) in env {
        command.env(name, value);
    }

    let mut child = command.spawn().expect("the platform runs");
    let stdout = child.stdout.take().expect("stdout is piped");
    let mut lines = BufReader::new(stdout).lines();

    let announced = tokio::time::timeout(Duration::from_secs(10), lines.next_line())
        .await
        .expect("the platform printed something within ten seconds")
        .expect("a line");
    // It exited if there is no line. Its complaint is the interesting part, and
    // a bare "announced nothing" would send somebody looking at the wrong thing.
    let Some(announced) = announced else {
        let mut why = String::new();
        if let Some(stderr) = child.stderr.take() {
            let _ = BufReader::new(stderr).read_line(&mut why).await;
        }
        panic!("the platform did not start: {why}");
    };
    let address = announced
        .rsplit_once(' ')
        .expect("`listening on <address>`")
        .1
        .to_owned();

    (Running(child), format!("http://{address}"))
}

/// Polls until the room has been told, or gives up.
///
/// Polled rather than slept through, so a working path is fast and a broken one
/// still fails rather than hanging the suite.
async fn told(seen: &Notices, how_long: Duration) -> Vec<(String, String)> {
    let deadline = tokio::time::Instant::now() + how_long;
    loop {
        let so_far = seen.lock().expect("not poisoned").clone();
        if !so_far.is_empty() || tokio::time::Instant::now() > deadline {
            return so_far;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn one_delivery_reaches_one_room_exactly_once() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let (room, seen) = a_room().await;

    let platform_env = platform_files(dir.path());
    let (_platform, platform_at) = platform(&platform_env).await;
    let mesh = as_the_mesh_would(platform_at.clone(), TENANT).await;

    // A real signed push, accepted by the platform.
    let answered = reqwest::Client::new()
        .post(format!("{platform_at}/webhook/github"))
        .header("content-type", "application/json")
        .header("X-Hub-Signature-256", SIGNATURE.trim())
        .body(PAYLOAD.to_vec())
        .send()
        .await
        .expect("the platform answers");
    assert_eq!(answered.status(), StatusCode::ACCEPTED);

    // THE PLATFORM MUST NOT HAVE SENT ANYTHING. It holds no room URL and runs
    // no delivery loop, so a message arriving before the agent starts would
    // mean the cutover did not happen.
    assert!(
        told(&seen, Duration::from_millis(400)).await.is_empty(),
        "the platform delivered to a room, which it must no longer do"
    );

    // Now the agent, pointed at the platform through the mesh stub.
    let mut command = Command::new(agent_binary());
    command
        .env_clear()
        .env("ALERT_AGENT_PLATFORM", &mesh)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    for (name, value) in agent_files(dir.path(), &room) {
        command.env(name, value);
    }
    let _agent = Running(command.spawn().expect("the agent runs"));

    let told = told(&seen, Duration::from_secs(10)).await;

    assert_eq!(
        told.len(),
        1,
        "one delivery reached one room {} times: {told:?}",
        told.len()
    );
    assert_eq!(told[0].0, ROOM);
    // The agent's own render, so the message really came the long way round.
    assert!(told[0].1.contains("webhook-proxy"), "{:?}", told[0].1);

    // And it stays one. A second message here would mean the Delivery was
    // offered again — the lease lapsing without a report, or the report not
    // being accepted — which is the duplicate the whole hand-off is arranged
    // to avoid in the ordinary case.
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        seen.lock().expect("not poisoned").len(),
        1,
        "the room was told again after being told once"
    );
}
