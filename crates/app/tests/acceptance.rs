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
use std::time::Duration;

use axum::http::StatusCode;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
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

/// The value the monitoring sender shares. Long enough to be a real one, and
/// obviously not.
const TOKEN: &str = "not-a-real-token-but-long-enough-to-look-like-one";

/// The value the Grafana sender shares. Its own, not the monitoring one: two
/// alerting senders with one credential would mean neither could be withdrawn
/// without silencing the other, and a rule naming `origin: grafana` would be
/// worth no more than one naming `origin: alertmanager`.
const GRAFANA_TOKEN: &str = "also-not-a-real-token-and-not-the-other-one";

/// A real Grafana unified-alerting notification, schema v1.
const GRAFANA_NOTIFICATION: &[u8] =
    include_bytes!("../../adapters/grafana-payload/fixtures/firing.json");

/// A real Alertmanager notification: three alerts, deliberately matching two
/// rooms, one room, and no room respectively.
const NOTIFICATION: &[u8] =
    include_bytes!("../../adapters/alertmanager-payload/fixtures/firing.json");

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

/// Starts the binary and waits until it says which port it took.
async fn start(extra: HashMap<&str, String>) -> Result<Proxy, String> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_webhook-proxy"));
    command
        .env_clear()
        .env("WEBHOOK_PROXY_LISTEN", "127.0.0.1:0")
        // No waiting, unless a test asks for it. Nothing here is racing an agent
        // that renders secrets, and the real bound in every test that proves a
        // refusal would be half a minute of suite each.
        .env("WEBHOOK_PROXY_STARTUP_WAIT_MS", "0")
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
        // It exited, and everything it said is the interesting part rather than
        // only the first line -- the binary may say something before it refuses
        // (bead gc-f7t). Reading to the end is safe: the process is gone.
        let mut why = String::new();
        if let Some(mut stderr) = child.stderr.take() {
            let _ = stderr.read_to_string(&mut why).await;
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
fn configured() -> (tempfile::TempDir, HashMap<&'static str, String>) {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let secrets = dir.path().join("secrets");
    fs::create_dir(&secrets).expect("a writable temporary directory");

    for (name, value) in [
        ("github-webhook-secret", SECRET.to_owned()),
        ("alertmanager-token", TOKEN.to_owned()),
        ("grafana-token", GRAFANA_TOKEN.to_owned()),
    ] {
        fs::write(secrets.join(name), value).expect("a writable temporary directory");
    }

    let file = dir.path().join("config.yaml");
    fs::write(
        &file,
        "version: 1
tenants:
  - devsecops
  - platform
origins:
  - id: github
    tenant: devsecops
    speaks: github
    verify:
      hmac_sha256:
        secret: github-webhook-secret
  - id: alertmanager
    tenant: devsecops
    speaks: alertmanager
    verify:
      bearer:
        secret: alertmanager-token
  - id: grafana
    tenant: platform
    speaks: grafana
    verify:
      bearer:
        secret: grafana-token
",
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

#[tokio::test]
async fn two_senders_prove_themselves_two_ways_through_one_front_door() {
    // The test a reviewer reads to believe this epic. One deployment, two
    // Origins, two mechanisms, and neither accepts the other's credential.
    let (_dir, env) = configured();
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
async fn a_signed_branch_deletion_is_translated_and_accepted() {
    // A second real GitHub payload, with its own signature, through the binary.
    // The test that used to cover this asserted the room showed it as a
    // deletion; this service reaches no room now (bead gc-72e.3.2), so what is
    // left to prove here is the half that is still this service's — that the
    // translator reads a payload shaped unlike a push and the delivery is
    // accepted rather than refused as unreadable.
    //
    // How it RENDERS in a room is the agent's, and element-notices has its own
    // tests for that.
    let (_dir, env) = configured();
    let proxy = start(env).await.expect("the proxy starts");

    assert_eq!(
        post_webhook(&proxy.address, Some(DELETION_SIGNATURE.trim()), DELETION).await,
        StatusCode::ACCEPTED
    );
}

#[tokio::test]
async fn a_wrongly_signed_push_is_refused_and_stored_nowhere() {
    let (_dir, env) = configured();
    let proxy = start(env).await.expect("the proxy starts");

    // A well-formed signature of the right length for the wrong body.
    let wrong = format!("sha256={}", "0".repeat(64));
    assert_eq!(
        post_webhook(&proxy.address, Some(&wrong), PAYLOAD).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn no_configured_sender_can_be_reached_without_its_credential() {
    let (_dir, env) = configured();
    let proxy = start(env).await.expect("the proxy starts");

    for (sender, body) in [("github", PAYLOAD), ("alertmanager", NOTIFICATION)] {
        assert_eq!(
            post_as(&proxy.address, sender, Credential::None, body).await,
            StatusCode::UNAUTHORIZED,
            "{sender} was reachable with no credential"
        );
    }
}

#[tokio::test]
async fn a_path_naming_no_configured_sender_is_not_found() {
    let (_dir, env) = configured();
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
async fn health_answers_without_asking_the_destination() {
    let (_dir, env) = configured();
    let proxy = start(env).await.expect("the proxy starts");

    let body = reqwest::get(format!("http://{}/health", proxy.address))
        .await
        .expect("the proxy answers")
        .text()
        .await
        .expect("a body");

    assert_eq!(body, "ok");
}

/// What a tenant's agent presents, as the service mesh would set it.
///
/// `x-forwarded-client-cert` is Envoy's header, and inside a mesh the sidecar
/// SETS it from the verified peer certificate — replacing whatever the request
/// carried. These tests write it themselves, which is exactly what makes the
/// mesh load-bearing: without a sidecar in front, any caller could do this.
/// `crates/app/src/collecting.rs` says so in the place somebody deploying this
/// will read.
fn as_agent_of(namespace: &str) -> String {
    format!(
        "By=spiffe://cluster.local/ns/webhook-proxy/sa/webhook-proxy;\
         Hash=0000000000000000000000000000000000000000000000000000000000000000;\
         Subject=\"\";URI=spiffe://cluster.local/ns/{namespace}/sa/alert-agent"
    )
}

/// Claims whatever this agent is owed.
async fn claim_as(address: &str, namespace: &str) -> (StatusCode, serde_json::Value) {
    let answered = reqwest::Client::new()
        .post(format!("http://{address}/deliveries/claim"))
        .header("x-forwarded-client-cert", as_agent_of(namespace))
        .send()
        .await
        .expect("the proxy answers");
    let status = answered.status();
    let body = answered
        .json::<serde_json::Value>()
        .await
        .unwrap_or(serde_json::Value::Null);
    (status, body)
}

/// Reports what became of one Delivery, as that tenant's agent.
async fn report_as(
    address: &str,
    namespace: &str,
    delivery: &str,
    report: serde_json::Value,
) -> StatusCode {
    reqwest::Client::new()
        .post(format!("http://{address}/deliveries/{delivery}/report"))
        .header("x-forwarded-client-cert", as_agent_of(namespace))
        .json(&report)
        .send()
        .await
        .expect("the proxy answers")
        .status()
}

/// What `/metrics` says right now.
async fn scraped(address: &str) -> String {
    reqwest::get(format!("http://{address}/metrics"))
        .await
        .expect("the binary answers a scrape")
        .text()
        .await
        .expect("a body")
}

#[tokio::test]
async fn an_agent_is_offered_none_of_another_tenants_deliveries() {
    // THE ONE PROPERTY THE WHOLE SPLIT EXISTS TO PROVIDE, end to end against
    // the running binary. The store proves it twice already — in memory and
    // against the SQL — and this proves the part neither can: that the tenant
    // actually comes from the caller's identity, and that nothing between the
    // socket and the store substitutes a parameter for it.
    //
    // Two senders belonging to two tenants, per the fixture: `github` is
    // devsecops's and `grafana` is platform's.
    let (_dir, env) = configured();
    let proxy = start(env).await.expect("the proxy starts");

    assert_eq!(
        post_as(
            &proxy.address,
            "github",
            Credential::Signature(SIGNATURE.trim()),
            PAYLOAD,
        )
        .await,
        StatusCode::ACCEPTED
    );
    assert_eq!(
        post_as(
            &proxy.address,
            "grafana",
            Credential::Shared(GRAFANA_TOKEN),
            GRAFANA_NOTIFICATION,
        )
        .await,
        StatusCode::ACCEPTED
    );

    let (status, devsecops) = claim_as(&proxy.address, "devsecops").await;
    assert_eq!(status, StatusCode::OK);
    let (status, platform) = claim_as(&proxy.address, "platform").await;
    assert_eq!(status, StatusCode::OK);

    let origins = |claimed: &serde_json::Value| -> Vec<String> {
        claimed["deliveries"]
            .as_array()
            .expect("a list of deliveries")
            .iter()
            .map(|one| one["origin"].as_str().expect("an origin").to_owned())
            .collect()
    };

    // Each tenant sees its own sender's Delivery and only that one. Asserted
    // both ways round, so this cannot pass by one of them being offered
    // nothing: an empty answer for both would satisfy "sees none of the
    // other's" while meaning the hand-off is broken.
    assert_eq!(origins(&devsecops), vec!["github"]);
    assert_eq!(origins(&platform), vec!["grafana"]);

    // And the lease, which the platform owns and an agent must not assume.
    assert!(
        devsecops["lease_expires_ms"].as_i64().is_some(),
        "a claim returned no lease: {devsecops}"
    );
}

#[tokio::test]
async fn a_caller_the_mesh_did_not_identify_is_offered_nothing() {
    // No header at all, which in production means a pod with no sidecar rather
    // than an attacker — and is the case where answering anything at all would
    // be the worst possible failure. 401 and not 403: nothing established who
    // is calling, so there is nothing to authorise.
    let (_dir, env) = configured();
    let proxy = start(env).await.expect("the proxy starts");

    let answered = reqwest::Client::new()
        .post(format!("http://{}/deliveries/claim", proxy.address))
        .send()
        .await
        .expect("the proxy answers");

    assert_eq!(answered.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_caller_speaking_for_no_tenant_here_is_offered_nothing() {
    // The case that makes the public path safe by construction rather than by
    // routing: a request arriving through the ingress gateway carries the
    // GATEWAY's identity, and `istio-ingress` is not a tenant. So even a
    // deployment that published this path by mistake would hand out nothing.
    let (_dir, env) = configured();
    let proxy = start(env).await.expect("the proxy starts");

    for namespace in ["istio-ingress", "wallet-lab-prod", "default"] {
        let (status, body) = claim_as(&proxy.address, namespace).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "a caller speaking for {namespace:?} was answered {status}: {body}"
        );
        // And it learns nothing about which tenants do exist.
        let said = body.to_string();
        for tenant in ["devsecops", "platform"] {
            assert!(
                !said.contains(tenant),
                "the refusal named a tenant this deployment serves: {said}"
            );
        }
    }
}

#[tokio::test]
async fn an_agent_reports_its_rooms_and_is_not_offered_it_again() {
    // The other half of the hand-off: a report is terminal, and what it
    // discharges is not offered to anybody again. Without this the queue never
    // drains and every tenant looks like a tenant that has stopped collecting.
    let (_dir, env) = configured();
    let proxy = start(env).await.expect("the proxy starts");

    assert_eq!(
        post_as(
            &proxy.address,
            "github",
            Credential::Signature(SIGNATURE.trim()),
            PAYLOAD,
        )
        .await,
        StatusCode::ACCEPTED
    );

    let (_, claimed) = claim_as(&proxy.address, "devsecops").await;
    let delivery = claimed["deliveries"][0]["delivery"]
        .as_str()
        .expect("a delivery identity")
        .to_owned();

    let reported = reqwest::Client::new()
        .post(format!(
            "http://{}/deliveries/{delivery}/report",
            proxy.address
        ))
        .header("x-forwarded-client-cert", as_agent_of("devsecops"))
        .json(&serde_json::json!({
            "outcome": "reached",
            "rooms": [{ "room": ROOM, "outcome": "delivered" }],
        }))
        .send()
        .await
        .expect("the proxy answers");
    assert_eq!(reported.status(), StatusCode::NO_CONTENT);

    // A claim after the lease would otherwise offer it again, so the proof that
    // the report was terminal is that nothing comes back even to the tenant
    // that holds the claim.
    let (status, after) = claim_as(&proxy.address, "devsecops").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        after["deliveries"].as_array().expect("a list").is_empty(),
        "a reported Delivery was offered again: {after}"
    );
}

#[tokio::test]
async fn one_tenant_cannot_report_another_tenants_delivery() {
    // Reported by identity, and the identity alone is not the authority. A
    // DeliveryId is random, so guessing one is not a practical attack — but it
    // travels, in traces and logs and room messages, and authorisation that
    // rests on an identifier being hard to guess is not authorisation.
    let (_dir, env) = configured();
    let proxy = start(env).await.expect("the proxy starts");

    assert_eq!(
        post_as(
            &proxy.address,
            "github",
            Credential::Signature(SIGNATURE.trim()),
            PAYLOAD,
        )
        .await,
        StatusCode::ACCEPTED
    );
    let (_, claimed) = claim_as(&proxy.address, "devsecops").await;
    let delivery = claimed["deliveries"][0]["delivery"]
        .as_str()
        .expect("a delivery identity")
        .to_owned();

    let report = |namespace: &'static str, delivery: String, address: String| async move {
        reqwest::Client::new()
            .post(format!("http://{address}/deliveries/{delivery}/report"))
            .header("x-forwarded-client-cert", as_agent_of(namespace))
            .json(&serde_json::json!({ "outcome": "routed_to_nothing" }))
            .send()
            .await
            .expect("the proxy answers")
            .status()
    };

    // The other tenant discharges nothing, and is told the same thing it would
    // be told about an identity that never existed.
    assert_eq!(
        report("platform", delivery.clone(), proxy.address.clone()).await,
        StatusCode::NOT_FOUND
    );
    // The positive oracle: its own tenant still can, so the refusal above was
    // not the store having lost it.
    assert_eq!(
        report("devsecops", delivery, proxy.address.clone()).await,
        StatusCode::NO_CONTENT
    );
}

#[tokio::test]
async fn an_origin_naming_a_tenant_nobody_listed_stops_the_process() {
    // The failure bead gc-nkb exists to prevent, proved against the binary
    // rather than against the parser. If a tenant came into being by being
    // mentioned, this typo would create one: every alert from that sender would
    // verify, be accepted, be stored, be owed to a tenant nobody has an agent
    // for, and eventually be swept — with every step reporting success.
    //
    // It must happen BEFORE the socket is bound, which is why this is an
    // acceptance test and not a unit one: a deployment that is wrong this way
    // must never look healthy, and `webhook-proxy check` runs on every change
    // to this file in the operations repository, so nobody should reach here.
    let dir = tempfile::tempdir().expect("a temporary directory");
    let file = dir.path().join("config.yaml");
    fs::write(
        &file,
        "version: 1
tenants:
  - wallet-lab-prod
origins:
  - id: a-forge
    tenant: wallet-lab-prd
    speaks: github
    verify:
      hmac_sha256:
        secret: a-secret
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

    assert!(why.contains("origins[0].tenant"), "{why}");
    assert!(why.contains("wallet-lab-prd"), "{why}");
    // And what IS listed, so the reader does not have to go and look for the
    // difference between two names that differ by one letter.
    assert!(why.contains("wallet-lab-prod"), "{why}");
    assert!(!why.contains("shhh"), "{why}");
}

#[test]
fn check_says_which_tenant_each_sender_files_under() {
    // The tenant decides which agent is ever offered an alert, and it cannot be
    // inferred from anything else in the file — so the one thing a reviewer of
    // a routing change most needs to see is exactly the thing `check` has to
    // print. This is the pipeline's view of it.
    let (_dir, env) = configured();

    let (ok, out, err) = check(&env);

    assert!(ok, "{err}{out}");
    assert!(
        out.contains("/webhook/github  signs its body, speaks github, for tenant devsecops"),
        "{out}"
    );
    assert!(out.contains("speaks grafana, for tenant platform"), "{out}");
    // The tenants themselves, listed, and the count — because a tenant listed
    // and then misspelled under every Origin would otherwise show as nothing.
    assert!(out.contains("2 tenant(s),"), "{out}");
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
tenants:
  - a-tenant
origins:
  - id: a-forge
    tenant: a-tenant
    speaks: github
    verify:
      hmac_sha256:
        secret: no-such-secret
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
    assert!(why.contains("origins[0].verify.secret"), "{why}");
    assert!(why.contains("no-such-secret"), "{why}");
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
    // The names are taken from the file rather than written here. A list in
    // this test would be a second place to keep in step, and it would fail for
    // the wrong reason the day the example gains a sender — which is what it did
    // when it gained Grafana.
    let dir = tempfile::tempdir().expect("a temporary directory");
    let wanted = secrets_named_by(EXAMPLE);
    for name in &wanted {
        fs::write(dir.path().join(name), format!("not-real-{name}")).expect("writable");
    }

    let env = HashMap::from([
        ("WEBHOOK_PROXY_CONFIG", EXAMPLE_PATH.to_owned()),
        (
            "WEBHOOK_PROXY_SECRETS_DIR",
            dir.path().to_str().expect("a utf-8 path").to_owned(),
        ),
    ]);

    let (ok, out, err) = check(&env);

    assert!(ok, "check refused the published example: {err}{out}");
    // Every sender the file declares is reachable, and the file decides which
    // those are: a published example that documents a sender the proxy will not
    // serve is how a GitOps author gets a 404 from a correct-looking config.
    assert!(out.contains("/webhook/github"), "{out}");
    assert!(out.contains("/webhook/alertmanager"), "{out}");
    assert!(out.contains("/webhook/grafana"), "{out}");
    // Whose each sender's alerts are, which this half of the configuration
    // still decides and which a reviewer cannot infer from anything else.
    assert!(out.contains("for tenant devsecops"), "{out}");
    assert!(out.contains("for tenant platform"), "{out}");
    // AND NO ROOMS AND NO RULES, because this service has none (bead
    // gc-72e.3.2). `alert-agent check` is what prints those, against the
    // tenant's own file.
    assert!(!out.contains("rooms"), "{out}");
    assert!(!out.contains("room(s)"), "{out}");
    assert!(
        out.contains(&format!("{} secret(s) present", wanted.len())),
        "{out}"
    );
    // Never a value, in the output a reviewer pastes into a pull request.
    assert!(!out.contains("not-real-"), "{out}");
}

/// The published example, as the binary and the tests both read it.
const EXAMPLE_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../deploy/webhook-proxy/config.example.yaml"
);
const EXAMPLE: &str = include_str!("../../../deploy/webhook-proxy/config.example.yaml");

/// Every secret name a routing file refers to, wherever it appears.
fn secrets_named_by(routing: &str) -> std::collections::BTreeSet<String> {
    fn walk(node: &serde_yaml_ng::Value, found: &mut std::collections::BTreeSet<String>) {
        match node {
            serde_yaml_ng::Value::Mapping(entries) => {
                for (key, value) in entries {
                    if key.as_str() == Some("secret")
                        && let Some(name) = value.as_str()
                    {
                        found.insert(name.to_owned());
                    }
                    walk(value, found);
                }
            }
            serde_yaml_ng::Value::Sequence(items) => items.iter().for_each(|i| walk(i, found)),
            _ => {}
        }
    }
    let parsed: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(routing).expect("the routing file parses");
    let mut found = std::collections::BTreeSet::new();
    walk(&parsed, &mut found);
    found
}

#[test]
fn check_refuses_a_file_the_process_would_refuse_and_says_where() {
    let dir = tempfile::tempdir().expect("a temporary directory");
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
        secret: no-such-secret
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

    assert!(
        !ok,
        "check accepted a file naming a secret that is not there"
    );
    assert!(err.contains("config.yaml"), "{err}");
    assert!(err.contains("origins[0].verify.secret"), "{err}");
    assert!(err.contains("no-such-secret"), "{err}");
    assert!(!err.contains("shhh"), "{err}");
}

#[tokio::test]
async fn a_secret_that_arrives_a_moment_late_is_waited_for() {
    // The deployment this has to survive: an agent renders the secrets into a
    // tmpfs beside this process, and for the first seconds of a pod's life the
    // directory is empty. Refusing immediately is correct about the state and
    // wrong about the situation — and Kubernetes answers it with
    // CrashLoopBackOff, 0s then 10s then 20s then 40s, so a pod can take a
    // minute to come up over a race that resolved in three seconds. Bead gc-6b7.
    //
    // Written against the binary saying it is waiting, not against a delay. The
    // first version of this test wrote the file after 400ms and passed with no
    // waiting implemented at all, because a debug binary takes longer than that
    // to reach its first read — it was measuring which of two races won.
    let (dir, env) = configured();

    let late = dir.path().join("secrets").join("github-webhook-secret");
    let contents = fs::read_to_string(&late).expect("the fixture wrote it");
    fs::remove_file(&late).expect("a writable temporary directory");

    let mut command = Command::new(env!("CARGO_BIN_EXE_webhook-proxy"));
    command
        .env_clear()
        .env("WEBHOOK_PROXY_LISTEN", "127.0.0.1:0")
        .env("WEBHOOK_PROXY_STARTUP_WAIT_MS", "10000")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in &env {
        command.env(name, value);
    }
    let mut child = command.spawn().expect("the binary runs");

    let mut complaints = BufReader::new(child.stderr.take().expect("stderr is piped")).lines();
    let waiting = tokio::time::timeout(Duration::from_secs(10), complaints.next_line())
        .await
        .expect("it says something within ten seconds")
        .expect("stderr is readable")
        .expect("it says it is waiting rather than exiting");

    // It has looked, not found it, and said which one. Only now does it appear.
    assert!(waiting.contains("github-webhook-secret"), "{waiting}");
    fs::write(&late, contents).expect("a writable temporary directory");

    let mut announced = BufReader::new(child.stdout.take().expect("stdout is piped")).lines();
    let line = tokio::time::timeout(Duration::from_secs(10), announced.next_line())
        .await
        .expect("it starts within ten seconds")
        .expect("stdout is readable")
        .expect("it announces a port rather than exiting");

    assert!(line.starts_with("listening on 127.0.0.1:"), "{line}");

    let _ = child.start_kill();
    drop(dir);
}

#[tokio::test]
async fn a_proxy_holding_deliveries_in_memory_says_so_before_it_listens() {
    // BEAD gc-f7t, found by adapting these manifests for a dev cluster. The
    // rendering kept replicas: 2 and did not carry the database, so two
    // replicas each held their own memory store. Nothing said so, and the
    // symptoms pointed nowhere near a replica count: a webhook stored in A's
    // memory, an agent's claim load-balanced to B getting an empty list, a
    // report load-balanced to B answering 404, a duplicate in the room and a
    // delivered counter that disagreed with what the room actually got.
    //
    // A process cannot know its own replica count, so this cannot fail closed.
    // It CAN say what it is doing, in the first thing it prints, which turns
    // that whole investigation into one line of a log.
    let (dir, env) = configured();
    assert!(
        !env.contains_key("WEBHOOK_PROXY_DATABASE_SECRET"),
        "this fixture names a database, so it proves nothing about the fallback"
    );

    let mut command = Command::new(env!("CARGO_BIN_EXE_webhook-proxy"));
    command
        .env_clear()
        .env("WEBHOOK_PROXY_LISTEN", "127.0.0.1:0")
        .env("WEBHOOK_PROXY_STARTUP_WAIT_MS", "0")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in &env {
        command.env(name, value);
    }
    let mut child = command.spawn().expect("the binary runs");

    let mut complaints = BufReader::new(child.stderr.take().expect("stderr is piped")).lines();
    let said = tokio::time::timeout(Duration::from_secs(10), complaints.next_line())
        .await
        .expect("it says something within ten seconds")
        .expect("stderr is readable")
        .expect("it says what it is doing rather than exiting");

    // The words an operator needs: that it is memory, and the rule that makes
    // memory unsafe. Not a hint that something might be suboptimal.
    assert!(said.contains("memory"), "{said}");
    assert!(
        said.contains("one replica"),
        "the line does not name the rule it exists for: {said}"
    );

    // ON STDERR AND NOT STDOUT, because stdout is a protocol: the first line is
    // the address, which the acceptance harness and an operator both read. A
    // warning printed there would have broken every test in this file, which is
    // a thing worth asserting rather than discovering.
    let mut announced = BufReader::new(child.stdout.take().expect("stdout is piped")).lines();
    let line = tokio::time::timeout(Duration::from_secs(10), announced.next_line())
        .await
        .expect("it starts within ten seconds")
        .expect("stdout is readable")
        .expect("it announces a port rather than exiting");
    assert!(line.starts_with("listening on 127.0.0.1:"), "{line}");

    let _ = child.start_kill();
    drop(dir);
}

#[tokio::test]
async fn a_proxy_that_names_a_database_does_not_warn_about_memory() {
    // The other side of the same line, cheaply: a deployment that names a
    // database must not be told it is running on memory. Proved without a
    // database by naming a secret that is not there -- the binary then
    // complains about the missing secret, which is only reachable from the
    // branch that did NOT fall back. An unconditional warning would fail here.
    let (dir, env) = configured();

    let mut command = Command::new(env!("CARGO_BIN_EXE_webhook-proxy"));
    command
        .env_clear()
        .env("WEBHOOK_PROXY_LISTEN", "127.0.0.1:0")
        .env("WEBHOOK_PROXY_STARTUP_WAIT_MS", "0")
        .env("WEBHOOK_PROXY_DATABASE_SECRET", "database-url")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in &env {
        command.env(name, value);
    }
    let mut child = command.spawn().expect("the binary runs");

    let mut complaints = BufReader::new(child.stderr.take().expect("stderr is piped")).lines();
    let said = tokio::time::timeout(Duration::from_secs(10), complaints.next_line())
        .await
        .expect("it says something within ten seconds")
        .expect("stderr is readable")
        .expect("it complains rather than starting silently");

    assert!(said.contains("database-url"), "{said}");
    assert!(
        !said.contains("memory"),
        "a deployment that named a database was told it is running on memory: {said}"
    );

    let _ = child.start_kill();
    drop(dir);
}

#[tokio::test]
async fn a_secret_that_never_arrives_still_stops_the_process_and_names_it() {
    // The other half, and the one that matters more: waiting must not turn a
    // misconfiguration into a process that hangs. A deployment missing a secret
    // is broken, and it should say which secret, in seconds.
    let (dir, mut env) = configured();

    fs::remove_file(dir.path().join("secrets").join("github-webhook-secret"))
        .expect("a writable temporary directory");

    env.insert("WEBHOOK_PROXY_STARTUP_WAIT_MS", "600".to_owned());

    let why = start(env).await.expect_err("it must refuse to start");

    assert!(why.contains("github-webhook-secret"), "{why}");
    assert!(why.contains("secrets"), "{why}");
}

#[test]
fn check_does_not_wait_for_anything() {
    // `check` validates a file. Nothing is racing it, and a reviewer running it
    // on a laptop should not sit through a timeout for a path that is simply
    // wrong. So it reads once and says so, whatever the bound is set to.
    let dir = tempfile::tempdir().expect("a temporary directory");
    let env = HashMap::from([
        (
            "WEBHOOK_PROXY_CONFIG",
            dir.path()
                .join("absent.yaml")
                .to_str()
                .expect("a utf-8 path")
                .to_owned(),
        ),
        // Twenty seconds on offer, and the assertion allows five. Long enough
        // that honouring it is unmistakable, short enough that a regression
        // fails in twenty seconds rather than holding up the suite — the first
        // version offered ten minutes and took all of them to fail.
        ("WEBHOOK_PROXY_STARTUP_WAIT_MS", "20000".to_owned()),
    ]);

    let began = std::time::Instant::now();
    let (ok, out, err) = check(&env);

    assert!(!ok, "{err}{out}");
    assert!(err.contains("absent.yaml"), "{err}");
    assert!(
        began.elapsed() < Duration::from_secs(5),
        "{:?}",
        began.elapsed()
    );
}

#[tokio::test]
async fn the_alerting_senders_do_not_share_a_credential() {
    // Two senders, two tokens, and neither opens the other. Without this a rule
    // naming `origin: grafana` would be worth no more than one naming
    // `origin: alertmanager`, because whoever held either value could claim to be
    // either — and `origin` is the one label the proxy sets rather than reads,
    // which is the whole reason a rule may rely on it.
    let (_dir, env) = configured();
    let proxy = start(env).await.expect("the binary starts");

    let borrowed = post_as(
        &proxy.address,
        "grafana",
        Credential::Shared(TOKEN),
        GRAFANA_NOTIFICATION,
    )
    .await;
    let other_way = post_as(
        &proxy.address,
        "alertmanager",
        Credential::Shared(GRAFANA_TOKEN),
        NOTIFICATION,
    )
    .await;

    assert_eq!(borrowed, StatusCode::UNAUTHORIZED);
    assert_eq!(other_way, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_loss_a_tenant_reports_is_counted_by_room_and_by_reason() {
    // THE WHOLE POINT OF BEAD gc-556, end to end against the running binary.
    // Before this, an abandoned dispatch existed in exactly one place: the
    // agent's own log, in one pod, for as long as that pod lived — and the pod
    // is rolled by a routine apply. The sender was told `202` and every signal
    // upstream stayed green while a room went quiet.
    //
    // Counted by REASON as well as by room, because the four are not
    // interchangeable to whoever acts on one: `rejected` is a configuration
    // problem in the tenant's own repo, `unreachable` is the network, and
    // `intercepted` means something answered on the room's behalf.
    let (_dir, env) = configured();
    let proxy = start(env).await.expect("the proxy starts");

    assert_eq!(
        post_webhook(&proxy.address, Some(SIGNATURE.trim()), PAYLOAD).await,
        StatusCode::ACCEPTED
    );
    let (_, claimed) = claim_as(&proxy.address, "devsecops").await;
    let delivery = claimed["deliveries"][0]["delivery"]
        .as_str()
        .expect("a delivery identity")
        .to_owned();

    assert_eq!(
        report_as(
            &proxy.address,
            "devsecops",
            &delivery,
            serde_json::json!({
                "outcome": "reached",
                "rooms": [{ "room": ROOM, "outcome": "abandoned", "reason": "unreachable" }],
            }),
        )
        .await,
        StatusCode::NO_CONTENT
    );

    let scraped = scraped(&proxy.address).await;
    assert!(
        scraped.contains(&format!(
            "webhook_proxy_room_abandoned_total{{tenant=\"devsecops\",room=\"{ROOM}\",reason=\"unreachable\"}} 1"
        )),
        "{scraped}"
    );
    // And in the total an alert can name without knowing which rooms exist.
    assert!(
        scraped.contains("webhook_proxy_room_abandoned_total 1"),
        "{scraped}"
    );
    // Not as a delivery. A loss counted on both sides of the ratio would make
    // the ratio say everything is fine, which is worse than no ratio.
    assert!(
        !scraped.contains("webhook_proxy_room_delivered_total{"),
        "{scraped}"
    );
}

#[tokio::test]
async fn a_report_that_arrives_twice_is_one_loss() {
    // The API deliberately allows a second report — an agent whose reply was
    // lost on the way back must be able to send it again, and this document
    // says so. So the counter has to be driven by what the STORE says the
    // report discharged, not by the request arriving: counting per request
    // would turn one loss into as many as the agent had attempts to tell us
    // about it, and a number that inflates under exactly the conditions you
    // are investigating is worse than no number.
    let (_dir, env) = configured();
    let proxy = start(env).await.expect("the proxy starts");

    post_webhook(&proxy.address, Some(SIGNATURE.trim()), PAYLOAD).await;
    let (_, claimed) = claim_as(&proxy.address, "devsecops").await;
    let delivery = claimed["deliveries"][0]["delivery"]
        .as_str()
        .expect("a delivery identity")
        .to_owned();
    let twice = serde_json::json!({
        "outcome": "reached",
        "rooms": [{ "room": ROOM, "outcome": "abandoned", "reason": "rejected" }],
    });

    assert_eq!(
        report_as(&proxy.address, "devsecops", &delivery, twice.clone()).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        report_as(&proxy.address, "devsecops", &delivery, twice).await,
        StatusCode::NOT_FOUND,
        "the second report was not refused, so this test proves nothing"
    );

    let scraped = scraped(&proxy.address).await;
    assert!(
        scraped.contains("webhook_proxy_room_abandoned_total 1"),
        "two reports of one loss were counted twice: {scraped}"
    );
}

#[tokio::test]
async fn a_delivered_report_counts_against_the_room_that_accepted_it() {
    // The denominator, and the reason it is worth the series: an absolute
    // number of losses says nothing on its own — a tenant sending thousands an
    // hour and a tenant sending one a week want very different thresholds, so
    // what an operator alerts on is a ratio and a ratio needs both halves.
    let (_dir, env) = configured();
    let proxy = start(env).await.expect("the proxy starts");

    post_webhook(&proxy.address, Some(SIGNATURE.trim()), PAYLOAD).await;
    let (_, claimed) = claim_as(&proxy.address, "devsecops").await;
    let delivery = claimed["deliveries"][0]["delivery"]
        .as_str()
        .expect("a delivery identity")
        .to_owned();

    assert_eq!(
        report_as(
            &proxy.address,
            "devsecops",
            &delivery,
            serde_json::json!({
                "outcome": "reached",
                "rooms": [{ "room": ROOM, "outcome": "delivered" }],
            }),
        )
        .await,
        StatusCode::NO_CONTENT
    );

    let scraped = scraped(&proxy.address).await;
    assert!(
        scraped.contains(&format!(
            "webhook_proxy_room_delivered_total{{tenant=\"devsecops\",room=\"{ROOM}\"}} 1"
        )),
        "{scraped}"
    );
    assert!(
        scraped.contains("webhook_proxy_room_abandoned_total 0"),
        "a delivery was counted as a loss: {scraped}"
    );
}

#[tokio::test]
async fn a_scrape_reveals_no_secret_and_no_room_address() {
    // These numbers are the sort of thing that ends up on a dashboard anybody
    // can open. A room NAME can appear — bead gc-556 counts what each room was
    // told, from its tenant's own reports — and a room ADDRESS cannot: a
    // `Destination` is a name with no address by construction, and the URL
    // never leaves the tenant's namespace. So the assertion is about addresses
    // and credentials, which is what there was ever anything to leak about.
    let (_dir, env) = configured();
    let proxy = start(env).await.expect("the binary starts");

    post_webhook(&proxy.address, Some(SIGNATURE.trim()), PAYLOAD).await;

    let scraped = scraped(&proxy.address).await;

    assert!(!scraped.contains("http"), "{scraped}");
    assert!(!scraped.contains(TOKEN), "{scraped}");
    assert!(!scraped.contains(SECRET.trim()), "{scraped}");
}

#[tokio::test]
async fn a_scrape_of_a_proxy_nothing_has_been_sent_through_is_empty_but_shaped() {
    // Not an error and not a blank page: a scraper meeting a fresh pod should
    // get the metric names it expects, with nothing under them, rather than
    // having to tell "no data" apart from "no endpoint".
    let (_dir, env) = configured();
    let proxy = start(env).await.expect("the binary starts");

    let scraped = reqwest::get(format!("http://{}/metrics", proxy.address))
        .await
        .expect("the binary answers a scrape")
        .text()
        .await
        .expect("a body");

    // What a room was told is keyed by room again, but only on its tenant's
    // word: this service reaches no room (bead gc-72e.3.2), so the series the
    // old one-deployment product exported by observing its own sends cannot
    // come back under its old names.
    assert!(!scraped.contains("dispatches_delivered"), "{scraped}");

    // The loss total, present at zero before any room exists, because a rule
    // on a series that does not exist yet never fires (bead gc-556).
    assert!(
        scraped.contains("webhook_proxy_room_abandoned_total 0"),
        "{scraped}"
    );

    // The tenant side, which exists for the one loss nothing else can see: an
    // alert no agent ever collected reached no room, so it has none to be
    // counted against (bead gc-g9x). Present at zero rather than absent, for
    // the same reason as the lines above — a scraper must not have to tell "no
    // data" from "no endpoint", and an alerting rule on a counter that does not
    // exist yet never fires.
    assert!(
        scraped.contains("webhook_proxy_uncollected_dropped_total 0"),
        "{scraped}"
    );
    assert!(
        scraped.contains("# TYPE webhook_proxy_outstanding_deliveries gauge"),
        "{scraped}"
    );
    assert!(
        scraped.contains("# TYPE webhook_proxy_outstanding_oldest_ms gauge"),
        "{scraped}"
    );
    // And no tenant is behind on a fresh pod, so the gauges carry no series.
    assert!(!scraped.contains("tenant="), "{scraped}");
}

#[tokio::test]
async fn api_info_says_what_is_answering_without_being_asked_for_a_credential() {
    // VER.06 of the national REST API-profil, accepted rather than refused in
    // bead gc-4oo.2: an operator looking at a running pod should be able to tell
    // which version answered. Unauthenticated by its own definition, which is
    // why it may name the API and its documentation and NOTHING about Origins,
    // Destinations, rooms or secrets — see the assertions at the end.
    let (_dir, env) = configured();
    let proxy = start(env).await.expect("the proxy starts");

    let answered = reqwest::Client::new()
        .get(format!("http://{}/api-info", proxy.address))
        .send()
        .await
        .expect("api-info answers");

    assert_eq!(answered.status(), StatusCode::OK);
    assert_eq!(
        answered
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/json"),
        "AME.01: the representation is JSON"
    );

    let body: serde_json::Value = answered.json().await.expect("a JSON body");

    // The field names the profile's own api-info uses. RAP-LP's VER.06 only
    // checks that the resource exists, so nothing but this test holds the shape.
    assert_eq!(body["apiName"], "webhook-proxy");
    assert_eq!(
        body["apiVersion"], "0.0.0",
        "read from the crate version, so a release that forgets it is impossible"
    );
    assert_eq!(body["apiStatus"], "beta");
    assert!(
        body["apiDocumentation"]
            .as_str()
            .expect("apiDocumentation is a string")
            .starts_with("https://"),
        "a reader has to be able to follow it: {:?}",
        body["apiDocumentation"]
    );

    // DOT.02: RFC 3339. Checked by shape rather than by parsing, because a date
    // crate here would be a dependency added to assert ten characters.
    let released = body["apiReleased"]
        .as_str()
        .expect("apiReleased is a string");
    assert_eq!(released.len(), 10, "a date, not a timestamp: {released:?}");
    let parts: Vec<&str> = released.split('-').collect();
    assert_eq!(parts.len(), 3, "YYYY-MM-DD: {released:?}");
    assert!(
        parts[0].len() == 4 && parts[1].len() == 2 && parts[2].len() == 2,
        "YYYY-MM-DD: {released:?}"
    );
    assert!(
        released.chars().all(|c| c.is_ascii_digit() || c == '-'),
        "YYYY-MM-DD: {released:?}"
    );

    // What it must never carry. The routing file this test configures names
    // three rooms and three secrets; api-info is reachable by anyone who can
    // reach the port, so a leak here is a leak to everyone.
    let whole = body.to_string();
    for forbidden in [TOKEN, GRAFANA_TOKEN, SECRET.trim()] {
        assert!(
            !whole.contains(forbidden),
            "api-info carries {forbidden:?}, which a caller it does not authenticate must not see: {whole}"
        );
    }

    // Field names are camelCase and nothing else (AME.04, AME.05).
    for name in body.as_object().expect("an object").keys() {
        assert!(
            name.chars().all(|c| c.is_ascii_alphanumeric()) && name.starts_with(char::is_lowercase),
            "not camelCase: {name:?}"
        );
    }
}

#[test]
fn api_info_moves_its_release_date_when_a_version_is_actually_released() {
    // apiReleased is the one value in api-info that cannot be derived: nothing
    // stamps a release date yet (bead gc-lw3). A literal is therefore a thing
    // somebody has to remember, and the moment it matters is exactly the moment
    // nobody is thinking about it — the first real release.
    //
    // So this ties the two together. While the version is 0.0.0 the date is the
    // day the interface was first described, which is true. The instant the
    // version moves, this fails unless the date moved with it.
    let version = env!("CARGO_PKG_VERSION");
    let described = "2026-10-12";

    if version == "0.0.0" {
        return;
    }

    let served = include_str!("../src/main.rs");
    assert!(
        !served.contains(&format!("const RELEASED: &str = \"{described}\"")),
        "the crate version is {version}, so this is a released API, and \
         apiReleased still says {described} — the day the interface was first \
         written down. Set it to this version's release date."
    );
}
