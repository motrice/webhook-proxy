//! Drives the built binary end to end.
//!
//! This is the test that makes the walking skeleton a skeleton rather than six
//! crates that have never met. It spawns the real executable, posts a real signed
//! GitHub payload at it over real HTTP, and asserts a stub hookshot received the
//! rendered Notice.
//!
//! The payload, its signature and its secret are the fixture triple from
//! `github-signatures`, whose signature was computed by openssl and
//! cross-checked against python. Reusing it keeps the oracle independent: if this
//! test computed the signature with our own HMAC code, a shared mistake would
//! pass unnoticed.

use std::collections::HashMap;
use std::fs;
use std::process::Stdio;
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

/// A real branch deletion, signed with the same test secret.
const DELETION: &[u8] =
    include_bytes!("../../adapters/github-signatures/fixtures/branch-delete.json");
const DELETION_SIGNATURE: &str =
    include_str!("../../adapters/github-signatures/fixtures/branch-delete.signature");

const ROOM: &str = "devsecops-room";
const PLATFORM: &str = "platform-room";

/// The value the monitoring sender shares. Long enough to be a real one, and
/// obviously not.
const TOKEN: &str = "not-a-real-token-but-long-enough-to-look-like-one";

/// A real Alertmanager notification: three alerts, deliberately matching two
/// rooms, one room, and no room respectively.
const NOTIFICATION: &[u8] =
    include_bytes!("../../adapters/alertmanager-payload/fixtures/firing.json");

/// What the stub hookshot recorded: which room, and the body it was sent.
type Notices = Arc<Mutex<Vec<(String, String)>>>;

/// Kills the child when the test ends, however it ends.
#[derive(Debug)]
struct Proxy {
    child: Child,
    address: String,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        // start_kill rather than kill().await: Drop cannot await, and leaving a
        // bound port behind would make the next run flaky.
        let _ = self.child.start_kill();
    }
}

/// A stub hookshot. Returns its URL and the bodies it was sent.
async fn hookshot() -> (String, Notices) {
    // Which room received what, not just what was received: a test that cannot
    // tell the rooms apart cannot say that a rule selected the right one.
    let seen: Notices = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route(
            "/hook/{id}",
            post(
                |State(seen): State<Notices>,
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

    // The base; each room's own address is this plus its identity, so the stub
    // can say which rule selected it.
    (format!("http://{address}/hook"), seen)
}

/// Starts the binary and waits until it says which port it took.
async fn start(extra: HashMap<&str, String>) -> Result<Proxy, String> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_webhook-proxy"));
    command
        .env_clear()
        .env("WEBHOOK_PROXY_LISTEN", "127.0.0.1:0")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in extra {
        command.env(name, value);
    }

    let mut child = command.spawn().expect("the binary runs");
    let stdout = child.stdout.take().expect("stdout is piped");
    let mut lines = BufReader::new(stdout).lines();

    // Bounded, so a binary that never starts fails the test rather than hanging
    // the suite.
    let announced = tokio::time::timeout(Duration::from_secs(10), lines.next_line())
        .await
        .map_err(|_| "the binary printed nothing within ten seconds".to_owned())?
        .map_err(|why| why.to_string())?;

    let Some(line) = announced else {
        // It exited. Its complaint is the interesting part.
        let mut why = String::new();
        if let Some(stderr) = child.stderr.take() {
            let _ = BufReader::new(stderr).read_line(&mut why).await;
        }
        return Err(why);
    };

    let address = line
        .strip_prefix("listening on ")
        .ok_or_else(|| format!("unexpected first line: {line}"))?
        .to_owned();

    Ok(Proxy { child, address })
}

/// The routing this deployment is given, written where the binary will find it.
///
/// Two senders on two mechanisms and three rules, because that is the shape a
/// reviewer has to believe. The `TempDir` is returned so the files outlive the
/// call: dropping it would delete them before the binary read them.
fn configured(base: &str) -> (tempfile::TempDir, HashMap<&'static str, String>) {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let secrets = dir.path().join("secrets");
    fs::create_dir(&secrets).expect("a writable temporary directory");

    for (name, value) in [
        ("github-webhook-secret", SECRET.to_owned()),
        ("alertmanager-token", TOKEN.to_owned()),
        ("devsecops-room-url", format!("{base}/{ROOM}")),
        ("platform-room-url", format!("{base}/{PLATFORM}")),
    ] {
        fs::write(secrets.join(name), value).expect("a writable temporary directory");
    }

    let file = dir.path().join("config.yaml");
    fs::write(
        &file,
        format!(
            "version: 1
origins:
  - id: github
    speaks: github
    verify:
      hmac_sha256:
        secret: github-webhook-secret
  - id: alertmanager
    speaks: alertmanager
    verify:
      bearer:
        secret: alertmanager-token
destinations:
  - id: {ROOM}
    kind: chat_room
    webhook:
      secret: devsecops-room-url
  - id: {PLATFORM}
    kind: chat_room
    webhook:
      secret: platform-room-url
subscriptions:
  - destination: {ROOM}
    match:
      origin: github
  - destination: {ROOM}
    match:
      origin: alertmanager
      severity: critical
  - destination: {PLATFORM}
    match:
      origin: alertmanager
      namespace: prod
"
        ),
    )
    .expect("a writable temporary directory");

    let env = HashMap::from([
        (
            "WEBHOOK_PROXY_CONFIG",
            file.to_str().expect("a utf-8 path").to_owned(),
        ),
        (
            "WEBHOOK_PROXY_SECRETS_DIR",
            secrets.to_str().expect("a utf-8 path").to_owned(),
        ),
    ]);
    (dir, env)
}

/// What a sender presents, and under which header.
enum Credential<'a> {
    /// A signature over the body.
    Signature(&'a str),
    /// A value shared in advance.
    Shared(&'a str),
    /// Nothing at all.
    None,
}

async fn post_as(
    address: &str,
    sender: &str,
    credential: Credential<'_>,
    body: &[u8],
) -> StatusCode {
    let client = reqwest::Client::new();
    let mut request = client
        .post(format!("http://{address}/webhook/{sender}"))
        .header("content-type", "application/json")
        .body(body.to_vec());
    request = match credential {
        Credential::Signature(value) => request.header("X-Hub-Signature-256", value),
        Credential::Shared(value) => request.header("Authorization", format!("Bearer {value}")),
        Credential::None => request,
    };

    request.send().await.expect("the proxy answers").status()
}

async fn post_webhook(address: &str, signature: Option<&str>, body: &[u8]) -> StatusCode {
    let credential = signature.map_or(Credential::None, Credential::Signature);
    post_as(address, "github", credential, body).await
}

/// The stub is answered asynchronously, so give it a moment — bounded, and
/// polled rather than slept through, so a working path is fast and a broken one
/// still fails.
/// Waits until at least `wanted` notices have arrived, or gives up.
///
/// Takes the count rather than waiting for the first, because a test asserting
/// that three alerts reached two rooms has to wait for all of them: returning on
/// the first would make the assertion race the dispatcher.
async fn delivered(
    seen: &Arc<Mutex<Vec<(String, String)>>>,
    wanted: usize,
) -> Vec<(String, String)> {
    for _ in 0..50 {
        let received = seen.lock().expect("not poisoned").clone();
        if received.len() >= wanted {
            return received;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    seen.lock().expect("not poisoned").clone()
}

/// What one room was told, as text.
fn told(received: &[(String, String)], room: &str) -> Vec<String> {
    received
        .iter()
        .filter(|(id, _)| id == room)
        .map(|(_, body)| {
            let sent: serde_json::Value = serde_json::from_str(body).expect("valid JSON");
            sent["text"].as_str().expect("a text field").to_owned()
        })
        .collect()
}

#[tokio::test]
async fn two_senders_prove_themselves_two_ways_through_one_front_door() {
    // The test a reviewer reads to believe this epic. One deployment, two
    // Origins, two mechanisms, and neither accepts the other's credential.
    let (base, _seen) = hookshot().await;
    let (_dir, env) = configured(&base);
    let proxy = start(env).await.expect("the proxy starts");

    // Each with its own credential: accepted.
    assert_eq!(
        post_as(
            &proxy.address,
            "github",
            Credential::Signature(SIGNATURE),
            PAYLOAD
        )
        .await,
        StatusCode::ACCEPTED
    );
    assert_eq!(
        post_as(
            &proxy.address,
            "alertmanager",
            Credential::Shared(TOKEN),
            NOTIFICATION
        )
        .await,
        StatusCode::ACCEPTED
    );

    // Each with the other's: refused. A mechanism is not a fallback, and the
    // header a sender happens to send does not decide which one applies.
    assert_eq!(
        post_as(&proxy.address, "github", Credential::Shared(TOKEN), PAYLOAD).await,
        StatusCode::UNAUTHORIZED,
        "the signing Origin accepted a shared value"
    );
    assert_eq!(
        post_as(
            &proxy.address,
            "alertmanager",
            Credential::Signature(SIGNATURE),
            NOTIFICATION
        )
        .await,
        StatusCode::UNAUTHORIZED,
        "the sharing Origin accepted a signature"
    );
}

#[tokio::test]
async fn a_push_and_an_alert_reach_only_their_own_subscribers() {
    let (base, seen) = hookshot().await;
    let (_dir, env) = configured(&base);
    let proxy = start(env).await.expect("the proxy starts");

    assert_eq!(
        post_webhook(&proxy.address, Some(SIGNATURE), PAYLOAD).await,
        StatusCode::ACCEPTED
    );

    let received = delivered(&seen, 1).await;
    let devsecops = told(&received, ROOM);
    assert_eq!(devsecops.len(), 1, "{received:?}");
    assert!(devsecops[0].contains("bjornmolin"), "{devsecops:?}");

    // The room that only subscribes to alerts hears nothing about a push.
    assert!(told(&received, PLATFORM).is_empty(), "{received:?}");
}

#[tokio::test]
async fn an_alert_reaches_every_room_whose_rule_matches_and_no_others() {
    let (base, seen) = hookshot().await;
    let (_dir, env) = configured(&base);
    let proxy = start(env).await.expect("the proxy starts");

    assert_eq!(
        post_as(
            &proxy.address,
            "alertmanager",
            Credential::Shared(TOKEN),
            NOTIFICATION
        )
        .await,
        StatusCode::ACCEPTED
    );

    // The notification carries three alerts, chosen so that one matches two
    // rules, one matches one, and one matches none:
    //
    //   critical / prod    -> devsecops (severity) and platform (namespace)
    //   unstated / prod    -> platform only
    //   unrecognised / platform -> nothing at all
    let received = delivered(&seen, 3).await;

    let devsecops = told(&received, ROOM);
    assert_eq!(devsecops.len(), 1, "devsecops: {received:?}");
    assert!(
        devsecops[0].starts_with("firing — critical:"),
        "{devsecops:?}"
    );

    let platform = told(&received, PLATFORM);
    assert_eq!(platform.len(), 2, "platform: {received:?}");

    // And the third reached nobody, which is not an error: the sender was told
    // its notification was accepted.
    assert_eq!(received.len(), 3, "{received:?}");
    assert!(
        !received
            .iter()
            .any(|(_, body)| body.contains("CertExpiring")),
        "an alert matching no rule was delivered anyway: {received:?}"
    );
}

#[tokio::test]
async fn a_wrongly_signed_push_reaches_nobody() {
    let (base, seen) = hookshot().await;
    let (_dir, env) = configured(&base);
    let proxy = start(env).await.expect("the proxy starts");

    // A well-formed signature of the right length for the wrong body.
    let wrong = format!("sha256={}", "0".repeat(64));
    assert_eq!(
        post_webhook(&proxy.address, Some(&wrong), PAYLOAD).await,
        StatusCode::UNAUTHORIZED
    );
    assert!(delivered(&seen, 1).await.is_empty());
}

#[tokio::test]
async fn no_configured_sender_can_be_reached_without_its_credential() {
    let (base, seen) = hookshot().await;
    let (_dir, env) = configured(&base);
    let proxy = start(env).await.expect("the proxy starts");

    for (sender, body) in [("github", PAYLOAD), ("alertmanager", NOTIFICATION)] {
        assert_eq!(
            post_as(&proxy.address, sender, Credential::None, body).await,
            StatusCode::UNAUTHORIZED,
            "{sender} was reachable with no credential"
        );
    }
    assert!(delivered(&seen, 1).await.is_empty());
}

#[tokio::test]
async fn a_path_naming_no_configured_sender_is_not_found() {
    let (base, _seen) = hookshot().await;
    let (_dir, env) = configured(&base);
    let proxy = start(env).await.expect("the proxy starts");

    // Not 401: there is nothing here to authenticate against. The set of senders
    // stays unenumerable either way, because a wrong credential for a real
    // sender and a real credential for no sender both end the conversation.
    assert_eq!(
        post_as(
            &proxy.address,
            "somebody-else",
            Credential::Signature(SIGNATURE),
            PAYLOAD
        )
        .await,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn a_signed_branch_deletion_reaches_the_room_as_a_deletion() {
    let (base, seen) = hookshot().await;
    let (_dir, env) = configured(&base);
    let proxy = start(env).await.expect("the proxy starts");

    assert_eq!(
        post_as(
            &proxy.address,
            "github",
            Credential::Signature(DELETION_SIGNATURE),
            DELETION
        )
        .await,
        StatusCode::ACCEPTED
    );

    let received = delivered(&seen, 1).await;
    let devsecops = told(&received, ROOM);
    assert_eq!(devsecops.len(), 1, "{received:?}");
    assert!(devsecops[0].contains("deleted"), "{devsecops:?}");
    assert!(!devsecops[0].contains("no commits"), "{devsecops:?}");
    assert!(!devsecops[0].contains("://"), "{devsecops:?}");
}

#[tokio::test]
async fn health_answers_without_asking_the_destination() {
    let (base, _seen) = hookshot().await;
    let (_dir, env) = configured(&base);
    let proxy = start(env).await.expect("the proxy starts");

    let body = reqwest::get(format!("http://{}/health", proxy.address))
        .await
        .expect("the proxy answers")
        .text()
        .await
        .expect("a body");

    assert_eq!(body, "ok");
}

#[tokio::test]
async fn a_routing_file_that_cannot_be_used_stops_the_process_and_says_where() {
    // The whole operator experience of a bad deploy. It must happen before the
    // socket is bound, so a broken deployment never looks healthy.
    let dir = tempfile::tempdir().expect("a temporary directory");
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
      secret: a-url
subscriptions:
  - destination: no-such-room
    match:
      origin: a-forge
",
    )
    .expect("writable");
    let secrets = dir.path().join("secrets");
    fs::create_dir(&secrets).expect("writable");
    fs::write(secrets.join("a-secret"), "shhh").expect("writable");
    fs::write(secrets.join("a-url"), "http://127.0.0.1:1/hook").expect("writable");

    let env = HashMap::from([
        (
            "WEBHOOK_PROXY_CONFIG",
            file.to_str().expect("a utf-8 path").to_owned(),
        ),
        (
            "WEBHOOK_PROXY_SECRETS_DIR",
            secrets.to_str().expect("a utf-8 path").to_owned(),
        ),
    ]);

    let why = start(env).await.expect_err("it must refuse to start");

    assert!(why.contains("config.yaml"), "{why}");
    assert!(why.contains("subscriptions[0].destination"), "{why}");
    assert!(why.contains("no-such-room"), "{why}");
    // No secret value, ever, in the line most likely to be pasted somewhere.
    assert!(!why.contains("shhh"), "{why}");
}

#[tokio::test]
async fn an_absent_routing_file_stops_the_process_rather_than_starting_empty() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let env = HashMap::from([(
        "WEBHOOK_PROXY_CONFIG",
        dir.path()
            .join("absent.yaml")
            .to_str()
            .expect("a utf-8 path")
            .to_owned(),
    )]);

    let why = start(env).await.expect_err("it must refuse to start");

    assert!(why.contains("absent.yaml"), "{why}");
}

/// Runs the built binary's `check`, with no listener and no network.
fn check(env: &HashMap<&'static str, String>) -> (bool, String, String) {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_webhook-proxy"));
    command.arg("check").env_clear();
    for (name, value) in env {
        command.env(name, value);
    }
    let done = command.output().expect("the binary runs");
    (
        done.status.success(),
        String::from_utf8_lossy(&done.stdout).into_owned(),
        String::from_utf8_lossy(&done.stderr).into_owned(),
    )
}

#[test]
fn check_prints_what_the_published_example_would_route() {
    // The published example, read by the binary an operator would run. Nothing
    // else parses that file in a deployment, so this is what stops it rotting.
    let dir = tempfile::tempdir().expect("a temporary directory");
    for name in [
        "github-webhook-secret",
        "alertmanager-token",
        "devsecops-room-url",
        "platform-room-url",
        "audit-room-url",
    ] {
        fs::write(dir.path().join(name), format!("not-real-{name}")).expect("writable");
    }

    let env = HashMap::from([
        (
            "WEBHOOK_PROXY_CONFIG",
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../deploy/config.example.yaml"
            )
            .to_owned(),
        ),
        (
            "WEBHOOK_PROXY_SECRETS_DIR",
            dir.path().to_str().expect("a utf-8 path").to_owned(),
        ),
    ]);

    let (ok, out, err) = check(&env);

    assert!(ok, "check refused the published example: {err}{out}");
    assert!(out.contains("/webhook/github"), "{out}");
    assert!(out.contains("/webhook/alertmanager"), "{out}");
    assert!(out.contains("namespace*=platform"), "{out}");
    assert!(out.contains("5 secret(s) present"), "{out}");
    // Never a value, in the output a reviewer pastes into a pull request.
    assert!(!out.contains("not-real-"), "{out}");
}

#[test]
fn check_refuses_a_file_the_process_would_refuse_and_says_where() {
    let dir = tempfile::tempdir().expect("a temporary directory");
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
      secret: a-url
subscriptions:
  - destination: typo-room
    match:
      origin: a-forge
",
    )
    .expect("writable");
    fs::write(dir.path().join("a-secret"), "shhh").expect("writable");
    fs::write(dir.path().join("a-url"), "http://127.0.0.1:1/hook").expect("writable");

    let env = HashMap::from([
        (
            "WEBHOOK_PROXY_CONFIG",
            file.to_str().expect("a utf-8 path").to_owned(),
        ),
        (
            "WEBHOOK_PROXY_SECRETS_DIR",
            dir.path().to_str().expect("a utf-8 path").to_owned(),
        ),
    ]);

    let (ok, _out, err) = check(&env);

    assert!(!ok, "check accepted a file naming an undeclared room");
    assert!(err.contains("config.yaml"), "{err}");
    assert!(err.contains("subscriptions[0].destination"), "{err}");
    assert!(err.contains("typo-room"), "{err}");
    assert!(!err.contains("shhh"), "{err}");
}

#[test]
fn check_shows_a_room_that_a_typo_left_unreachable() {
    // The case no validation rule could catch: the file is entirely valid, and a
    // room will simply never hear anything. Visible as a line in a pull request.
    let dir = tempfile::tempdir().expect("a temporary directory");
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
  - id: watched-room
    kind: chat_room
    webhook:
      secret: a-url
  - id: forgotten-room
    kind: chat_room
    webhook:
      secret: b-url
subscriptions:
  - destination: watched-room
    match:
      repositry: motrice/webhook-proxy
",
    )
    .expect("writable");
    for (name, value) in [
        ("a-secret", "shhh"),
        ("a-url", "http://127.0.0.1:1/a"),
        ("b-url", "http://127.0.0.1:1/b"),
    ] {
        fs::write(dir.path().join(name), value).expect("writable");
    }

    let env = HashMap::from([
        (
            "WEBHOOK_PROXY_CONFIG",
            file.to_str().expect("a utf-8 path").to_owned(),
        ),
        (
            "WEBHOOK_PROXY_SECRETS_DIR",
            dir.path().to_str().expect("a utf-8 path").to_owned(),
        ),
    ]);

    let (ok, out, err) = check(&env);

    // Valid, so it starts. And useless, which only the table can tell you.
    assert!(ok, "{err}{out}");
    assert!(out.contains("(nothing selects this room)"), "{out}");
    // And the typo itself: a name no Event ever offers, so it can only match if
    // a sender chooses to send it — which a forge never will.
    assert!(out.contains("repositry*="), "{out}");
}

/// A stub hookshot that records what it was sent and only then takes its time
/// answering.
///
/// Recording first is what makes the shutdown test deterministic rather than
/// timed: once a notice has been recorded the proxy is provably inside the
/// dispatcher, still holding the request open, which is the only moment at which
/// a termination signal proves anything.
async fn unhurried_hookshot(answering_after: Duration) -> (String, Notices) {
    let seen: Notices = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route(
            "/hook/{id}",
            post(
                move |State(seen): State<Notices>,
                      axum::extract::Path(id): axum::extract::Path<String>,
                      body: String| async move {
                    seen.lock().expect("not poisoned").push((id, body));
                    tokio::time::sleep(answering_after).await;
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

/// Asks the process to stop the way Kubernetes does.
fn ask_to_stop(pid: u32) {
    let signalled = std::process::Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status()
        .expect("kill(1) runs");
    assert!(signalled.success(), "could not signal {pid}");
}

#[tokio::test]
async fn a_termination_signal_lets_a_request_already_accepted_finish() {
    // The delivery promise is best-effort, and the deployment criterion is that
    // a restart loses at most what is in flight. Without a graceful stop even
    // that is not true: SIGTERM kills the process between the dispatch and the
    // response, so the sender sees a reset connection on a webhook that was in
    // fact delivered — the worst of both, because it will be retried.
    let (base, seen) = unhurried_hookshot(Duration::from_millis(750)).await;
    let (_dir, env) = configured(&base);
    let mut proxy = start(env).await.expect("the binary starts");
    let address = proxy.address.clone();
    let pid = proxy.child.id().expect("a running child");

    let signature = SIGNATURE.trim().to_owned();
    let posting =
        tokio::spawn(async move { post_webhook(&address, Some(&signature), PAYLOAD).await });

    // The notice has reached the stub, so the proxy is inside the dispatcher
    // with the request still open. Signal exactly there.
    assert_eq!(delivered(&seen, 1).await.len(), 1);
    ask_to_stop(pid);

    assert_eq!(
        posting.await.expect("the request task survives"),
        StatusCode::ACCEPTED,
        "the response was lost to the signal"
    );

    let stopped = tokio::time::timeout(Duration::from_secs(10), proxy.child.wait())
        .await
        .expect("it stops within ten seconds")
        .expect("a wait status");

    // Killed by a signal is not a clean stop: it is what happens when nothing
    // handles SIGTERM, and it is what this asserts is no longer the case.
    assert!(stopped.success(), "did not stop cleanly: {stopped:?}");
}
