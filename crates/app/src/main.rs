//! Composition root. The only crate permitted to name a concrete adapter.
//!
//! Everything here is wiring: read configuration, construct adapters, inject
//! them into the use case, start the inbound adapter. No business logic, and
//! therefore nothing here needs a unit test — it is covered by the acceptance
//! test, which drives the built binary.

use std::collections::HashMap;
use std::fmt;
use std::process::ExitCode;
use std::time::Duration;
use std::time::Instant;

use alertmanager_payload::AlertmanagerPayload;
use application::ports::{Dispatcher, Proofs, Translator};
use axum::routing::get;
use domain::Verification;
use element_notices::ElementNotices;
use github_payload::GithubPayload;
use github_signatures::GithubSignatures;
use grafana_payload::GrafanaPayload;
use inbound_http::{AUTHORIZATION_HEADER, Inbound, SIGNATURE_HEADER, Sender, router};
use shared_values::SharedValues;
use std::path::PathBuf;
use std::sync::Arc;
use system::{RandomIds, SystemClock};
use yaml_config::{Configuration, Speaks};

/// Why the process will not start.
///
/// Every variant names the environment variable at fault and never its value: a
/// startup error is the single most likely thing to be pasted into a chat window.
#[derive(Debug)]
enum Unstartable {
    /// A variable is present but unusable.
    Unusable { name: &'static str, why: String },
    /// The routing file cannot be used. Its own message names the file and the
    /// field, so this adds nothing to it.
    Configuration(String),
    /// The HTTP client for the destination could not be built.
    NoClient,
    /// The listening socket could not be served.
    Serving(String),
}

impl fmt::Display for Unstartable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unusable { name, why } => write!(f, "{name} is unusable: {why}"),
            Self::Configuration(why) => write!(f, "{why}"),
            Self::NoClient => write!(f, "the HTTP client for the destination could not be built"),
            Self::Serving(why) => write!(f, "could not serve: {why}"),
        }
    }
}

/// Everything the process needs to start that is not policy.
///
/// Who may send and who hears what live in the routing file, because a human
/// reviews those as a diff. What is left here is what the process needs in order
/// to run: where to listen, how long to wait, how much to accept, and where to
/// find the file and the secrets it names. Bead gc-ast.3 drew that line.
struct Config {
    listen: String,
    max_body: usize,
    timeout: Duration,
    file: PathBuf,
    secrets: PathBuf,
    startup_wait: Duration,
}

impl Config {
    /// Reads configuration from the environment.
    ///
    /// Nothing here is a secret any more: the file names them and the values are
    /// read from a mounted directory. What remains has defaults, because a
    /// missing listen address is an inconvenience where a missing secret would be
    /// a proxy that cannot authenticate what it receives. The file itself has no
    /// fallback — a deployment without one refuses to start.
    fn from_env() -> Self {
        Self {
            listen: optional("WEBHOOK_PROXY_LISTEN", "127.0.0.1:8080"),
            max_body: optional("WEBHOOK_PROXY_MAX_BODY", "1048576")
                .parse()
                .unwrap_or(1_048_576),
            timeout: Duration::from_millis(
                optional("WEBHOOK_PROXY_TIMEOUT_MS", "5000")
                    .parse()
                    .unwrap_or(5_000),
            ),
            file: PathBuf::from(optional(
                "WEBHOOK_PROXY_CONFIG",
                "/etc/webhook-proxy/config.yaml",
            )),
            secrets: PathBuf::from(optional(
                "WEBHOOK_PROXY_SECRETS_DIR",
                "/etc/webhook-proxy/secrets",
            )),
            // Settable, which the rest of this struct's defaults are not needed
            // to be, for two reasons worth stating. A cluster whose secret store
            // is slow to answer may need longer; and the tests that prove this
            // refuses have to prove it without waiting out the real bound, which
            // would otherwise put half a minute into the suite for every one of
            // them.
            startup_wait: Duration::from_millis(
                optional("WEBHOOK_PROXY_STARTUP_WAIT_MS", "30000")
                    .parse()
                    .unwrap_or(30_000),
            ),
        }
    }
}

fn optional(name: &str, fallback: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| fallback.to_owned())
}

/// How often to look again while waiting for configuration.
///
/// Short enough that a pod is not held up by the polling itself, long enough
/// that a directory which stays empty for the whole bound is not stat'd
/// thousands of times for nothing.
const LOOK_AGAIN: Duration = Duration::from_millis(250);

/// Reads the routing file and its secrets, waiting for them to appear.
///
/// Refusing to start without them is right, and `Configuration::read` does it
/// with a message naming what is missing. What it cannot tell apart is "missing"
/// from "not rendered yet" — and in the deployment this runs in, an agent
/// renders the secrets into a tmpfs beside this process, so for the first
/// seconds of a pod's life the directory is empty by design.
///
/// Exiting there is answered by Kubernetes with `CrashLoopBackOff`: 0s, 10s, 20s,
/// 40s. The agent is done in about three seconds and the pod can still take a
/// minute to come up, because the backoff is punishing a race rather than a
/// fault. Bead gc-6b7.
///
/// Any failure is retried, not only an absent file. The agent writes its
/// templates directly rather than swapping them in atomically the way a
/// Kubernetes volume does, so a half-written routing file is a transient state
/// too, and telling the two apart would mean reading the reason text.
///
/// The bound is what keeps this from turning a misconfiguration into a process
/// that hangs: when it expires, this refuses with exactly the message it would
/// have refused with immediately.
async fn configured(config: &Config) -> Result<Configuration, Unstartable> {
    let deadline = Instant::now() + config.startup_wait;
    let mut said = false;

    loop {
        let why = match Configuration::read(&config.file, &config.secrets) {
            Ok(routing) => return Ok(routing),
            Err(why) => why.to_string(),
        };

        if Instant::now() >= deadline {
            return Err(Unstartable::Configuration(why));
        }

        // Once, and on stderr for the same reason the refusal below is printed
        // rather than logged: it must be readable with the log filter turned
        // down, and stdout carries the one line saying which port was taken.
        if !said {
            eprintln!("webhook-proxy is waiting for its configuration: {why}");
            said = true;
        }

        tokio::time::sleep(LOOK_AGAIN).await;
    }
}

/// Liveness and readiness for k3s probes.
///
/// Deliberately answers from the process alone: a probe that depended on the
/// destination being reachable would restart a healthy proxy every time a chat
/// server hiccupped.
async fn health() -> &'static str {
    "ok"
}

/// Resolves when the orchestrator asks the process to stop.
///
/// Unix only, which is the whole target: the container is Linux and development
/// is macOS. SIGTERM is what Kubernetes sends before it waits out the grace
/// period; SIGINT is what Ctrl-C sends, and treating them alike means the
/// behaviour an operator sees locally is the behaviour the cluster gets.
///
/// Without this, SIGTERM kills the process at whatever instruction it had
/// reached, which is routinely between dispatching a webhook and answering the
/// sender — so the sender sees a reset connection for a Notice that did arrive,
/// and retries it. Bead gc-d01's criterion is that a restart loses at most what
/// is in flight, and that is only true if accepted work is allowed to finish.
async fn asked_to_stop() {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = match signal(SignalKind::terminate()) {
        Ok(stream) => stream,
        // Nothing to fall back to, and exiting here would make the process
        // unstartable over a signal handler. Staying up without a graceful stop
        // is the lesser failure, and it is loud.
        Err(why) => {
            tracing::error!(%why, "cannot listen for SIGTERM; stops will not be graceful");
            return std::future::pending().await;
        }
    };
    let mut interrupt = match signal(SignalKind::interrupt()) {
        Ok(stream) => stream,
        Err(why) => {
            tracing::error!(%why, "cannot listen for SIGINT; stops will not be graceful");
            return std::future::pending().await;
        }
    };

    let signalled = tokio::select! {
        _ = terminate.recv() => "SIGTERM",
        _ = interrupt.recv() => "SIGINT",
    };
    tracing::info!(
        signal = signalled,
        "stopping; finishing what has been accepted"
    );
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // One argument, and only one, so there is no argument parser to go wrong.
    // `check` validates the routing file and prints what it would route, which
    // is what a reviewer runs on a pull request and what the operations
    // repository's own pipeline runs. It opens no socket and reaches no network,
    // so it is safe anywhere — including a pipeline with no cluster access.
    if std::env::args().nth(1).as_deref() == Some("check") {
        return match check() {
            Ok(table) => {
                print!("{table}");
                ExitCode::SUCCESS
            }
            Err(why) => {
                eprintln!("webhook-proxy cannot start: {why}");
                ExitCode::FAILURE
            }
        };
    }

    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(why) => {
            // Printed rather than logged: a configuration failure must be
            // readable even if the log filter is set to something quiet.
            eprintln!("webhook-proxy cannot start: {why}");
            ExitCode::FAILURE
        }
    }
}

/// Reads the routing file and says what it would route.
///
/// Exactly the same read the process does at start-up, so a file this accepts is
/// a file the process will start with, and a file it refuses is one the process
/// would refuse too. Sharing the path is the point: a check that validated
/// something slightly different from what runs would be worse than no check.
fn check() -> Result<String, Unstartable> {
    let config = Config::from_env();
    let routing = Configuration::read(&config.file, &config.secrets)
        .map_err(|why| Unstartable::Configuration(why.to_string()))?;

    Ok(routing.routing_table())
}

async fn run() -> Result<(), Unstartable> {
    let config = Config::from_env();

    // Everything about who may send and who hears what comes from here. The file
    // refuses itself if anything is wrong, naming the file and the field, so this
    // adds nothing to its message — it only waits for it to be there at all.
    let routing = configured(&config).await?;

    // One verifier per mechanism, each holding every secret. Which Origin gets
    // which is decided below, from what that Origin declared — never here, and
    // never from anything in a request.
    let secrets: HashMap<String, Vec<u8>> = routing
        .secrets()
        .iter()
        .map(|(name, value)| (name.clone(), value.as_bytes().to_vec()))
        .collect();
    let signing: Arc<dyn Proofs> = Arc::new(GithubSignatures::new(secrets.clone()));
    let sharing: Arc<dyn Proofs> = Arc::new(SharedValues::new(secrets));

    let dispatcher: Arc<dyn Dispatcher> = Arc::new(
        ElementNotices::new(routing.webhooks().clone(), config.timeout)
            .map_err(|_| Unstartable::NoClient)?,
    );

    // The one place that maps a declaration onto what enforces it.
    //
    // Both matches are exhaustive, so every mechanism has exactly one verifier
    // and one header, and every vocabulary exactly one translator. A new
    // mechanism or a new sender cannot be added without the compiler stopping
    // here and asking which. Bead gc-dy4.
    let senders: HashMap<String, Sender> = routing
        .origins()
        .iter()
        .map(|(path, declared)| {
            let (proofs, presented) = match declared.origin.verify() {
                Verification::Signed { .. } => (Arc::clone(&signing), SIGNATURE_HEADER),
                Verification::Shared { .. } => (Arc::clone(&sharing), AUTHORIZATION_HEADER),
            };
            let translator: Arc<dyn Translator> = match declared.speaks {
                Speaks::Github => Arc::new(GithubPayload),
                Speaks::Alertmanager => Arc::new(AlertmanagerPayload),
                Speaks::Grafana => Arc::new(GrafanaPayload),
            };
            (
                path.clone(),
                Sender {
                    origin: declared.origin.clone(),
                    proofs,
                    translator,
                    presented,
                },
            )
        })
        .collect();

    let inbound = Inbound::new(
        senders,
        dispatcher,
        Arc::new(SystemClock),
        Arc::new(RandomIds),
        routing.subscriptions().to_vec(),
    );

    let app = router(inbound, config.max_body).route("/health", get(health));

    let listener = tokio::net::TcpListener::bind(&config.listen)
        .await
        .map_err(|why| Unstartable::Unusable {
            name: "WEBHOOK_PROXY_LISTEN",
            why: why.to_string(),
        })?;
    let address = listener
        .local_addr()
        .map_err(|why| Unstartable::Serving(why.to_string()))?;

    // Printed on stdout, not logged, because the acceptance test reads it to
    // learn which port was chosen when asked to bind port 0 — and because an
    // operator wants it even with logging turned down.
    println!("listening on {address}");
    tracing::info!(%address, "webhook-proxy started");

    axum::serve(listener, app)
        .with_graceful_shutdown(asked_to_stop())
        .await
        .map_err(|why| Unstartable::Serving(why.to_string()))?;

    Ok(())
}
