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
async fn hookshot() -> (String, Arc<Mutex<Vec<String>>>) {
    let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route(
            "/hook/{id}",
            post(
                |State(seen): State<Arc<Mutex<Vec<String>>>>, body: String| async move {
                    seen.lock().expect("not poisoned").push(body);
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

    (format!("http://{address}/hook/SECRETHOOKID"), seen)
}

/// Starts the binary and waits until it says which port it took.
async fn start(extra: HashMap<&str, String>) -> Result<Proxy, String> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_app"));
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

fn configured(url: &str) -> HashMap<&'static str, String> {
    HashMap::from([
        ("GITHUB_WEBHOOK_SECRET", SECRET.to_owned()),
        ("ELEMENT_WEBHOOK_URL", url.to_owned()),
        ("ELEMENT_ROOM", ROOM.to_owned()),
    ])
}

async fn post_webhook(address: &str, signature: Option<&str>, body: &[u8]) -> StatusCode {
    let client = reqwest::Client::new();
    let mut request = client
        .post(format!("http://{address}/webhook/github"))
        .header("content-type", "application/json")
        .body(body.to_vec());
    if let Some(value) = signature {
        request = request.header("X-Hub-Signature-256", value);
    }

    request.send().await.expect("the proxy answers").status()
}

/// The stub is answered asynchronously, so give it a moment — bounded, and
/// polled rather than slept through, so a working path is fast and a broken one
/// still fails.
async fn delivered(seen: &Arc<Mutex<Vec<String>>>) -> Vec<String> {
    for _ in 0..50 {
        let received = seen.lock().expect("not poisoned").clone();
        if !received.is_empty() {
            return received;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    Vec::new()
}

#[tokio::test]
async fn a_signed_push_reaches_the_room() {
    let (url, seen) = hookshot().await;
    let proxy = start(configured(&url)).await.expect("the proxy starts");

    let status = post_webhook(&proxy.address, Some(SIGNATURE), PAYLOAD).await;

    assert_eq!(status, StatusCode::ACCEPTED);

    let received = delivered(&seen).await;
    assert_eq!(received.len(), 1, "the room should have been told once");

    let sent: serde_json::Value = serde_json::from_str(&received[0]).expect("valid JSON");
    let text = sent["text"].as_str().expect("a text field");
    assert!(text.contains("motrice/webhook-proxy"), "{text}");
    assert!(text.contains("main"), "{text}");
    assert!(text.contains("bjornmolin"), "{text}");
}

#[tokio::test]
async fn a_signed_branch_deletion_reaches_the_room_as_a_deletion() {
    // The whole path for the second Event: a signed payload whose `deleted` flag
    // the inbound adapter reads, a domain Event with no commits to be empty, and
    // a Notice that says what happened rather than describing it as a push of
    // nothing. Tested here because no single layer can prove the sentence that
    // comes out the far end.
    let (url, seen) = hookshot().await;
    let proxy = start(configured(&url)).await.expect("the proxy starts");

    let status = post_webhook(&proxy.address, Some(DELETION_SIGNATURE), DELETION).await;

    assert_eq!(status, StatusCode::ACCEPTED);

    let received = delivered(&seen).await;
    assert_eq!(received.len(), 1, "the room should have been told once");

    let sent: serde_json::Value = serde_json::from_str(&received[0]).expect("valid JSON");
    let text = sent["text"].as_str().expect("a text field");
    assert!(text.contains("deleted"), "{text}");
    assert!(text.contains("bead/gc-old"), "{text}");
    assert!(text.contains("bjornmolin"), "{text}");
    assert!(
        !text.contains("no commits"),
        "a deletion must not be reported as a push that carried nothing: {text}"
    );
}

#[tokio::test]
async fn a_wrongly_signed_push_reaches_nobody() {
    let (url, seen) = hookshot().await;
    let proxy = start(configured(&url)).await.expect("the proxy starts");

    // A well-formed signature of the right length for the wrong body.
    let wrong = format!("sha256={}", "0".repeat(64));
    let status = post_webhook(&proxy.address, Some(&wrong), PAYLOAD).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        delivered(&seen).await.is_empty(),
        "an unverified push must reach nobody"
    );
}

#[tokio::test]
async fn an_unsigned_push_reaches_nobody() {
    let (url, seen) = hookshot().await;
    let proxy = start(configured(&url)).await.expect("the proxy starts");

    let status = post_webhook(&proxy.address, None, PAYLOAD).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(delivered(&seen).await.is_empty());
}

#[tokio::test]
async fn health_answers_without_asking_the_destination() {
    let (url, _) = hookshot().await;
    let proxy = start(configured(&url)).await.expect("the proxy starts");

    let body = reqwest::get(format!("http://{}/health", proxy.address))
        .await
        .expect("the proxy answers")
        .text()
        .await
        .expect("a body");

    assert_eq!(body, "ok");
}

#[tokio::test]
async fn a_missing_secret_stops_the_process_and_says_which_one() {
    let (url, _) = hookshot().await;
    let mut without = configured(&url);
    without.remove("GITHUB_WEBHOOK_SECRET");

    let complaint = start(without)
        .await
        .expect_err("it must refuse to start without a secret");

    assert!(
        complaint.contains("GITHUB_WEBHOOK_SECRET"),
        "the complaint must name the variable: {complaint}"
    );
    assert!(
        !complaint.contains(SECRET.trim()),
        "the complaint must not contain a secret value: {complaint}"
    );
}
