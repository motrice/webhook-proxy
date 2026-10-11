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
use application::ports::{Dispatcher, Outbox, Proofs, Translator};
use application::{Retries, Retry};
use axum::routing::get;
use domain::Verification;
use element_notices::ElementNotices;
use github_payload::GithubPayload;
use github_signatures::GithubSignatures;
use grafana_payload::GrafanaPayload;
use inbound_http::{AUTHORIZATION_HEADER, Inbound, SIGNATURE_HEADER, Sender, router};
use memory_outbox::MemoryOutbox;
use postgres_outbox::PostgresOutbox;
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
    retry: Retry,
    sweep: Duration,
    /// The name of the secret holding the database connection string, if there
    /// is one. The NAME, never the value: a connection string carries a
    /// password, and an environment variable is visible in a process listing
    /// and in every crash report.
    ///
    /// In the environment rather than in the routing file because gc-ast.3 drew
    /// that line: who may send and who hears what live in the file, because a
    /// human reviews those as a diff. Where this process keeps its state is
    /// what it needs in order to run.
    database: Option<String>,
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
            // Five attempts over about half a minute of waiting, doubling from
            // one second and capped at thirty. Long enough to ride out a chat
            // server restart; short enough that an alert nobody will ever get is
            // reported as lost while somebody still cares.
            retry: Retry::new(
                Duration::from_secs(1),
                Duration::from_secs(30),
                optional("WEBHOOK_PROXY_ATTEMPTS", "5").parse().unwrap_or(5),
            ),
            // How often to look for work. Nothing waits on this — the relay has
            // already sent what it could — so it is a sweep rather than a queue,
            // and a short one would be mostly empty polls.
            sweep: Duration::from_millis(
                optional("WEBHOOK_PROXY_SWEEP_MS", "5000")
                    .parse()
                    .unwrap_or(5_000),
            ),
            database: std::env::var("WEBHOOK_PROXY_DATABASE_SECRET")
                .ok()
                .filter(|name| !name.trim().is_empty()),
        }
    }
}

fn optional(name: &str, fallback: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| fallback.to_owned())
}

/// How many Dispatches one sweep of the outbox takes at a time.
///
/// Bounded so a pass cannot hold a replica for an unbounded time, and so two
/// replicas share the work rather than one taking all of it.
const RETRY_BATCH: usize = 32;

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

/// How many connections the proxy keeps open to the database.
///
/// Two replicas, a request path and a sweep each: small on purpose, because a
/// pool larger than the work is a pool that hides a leak.
const DATABASE_CONNECTIONS: u32 = 8;

/// Where Dispatches wait, which decides whether they survive a restart.
///
/// In memory unless a database is configured, and that is the honest default:
/// nothing is lost that was not going to be lost anyway, and a deployment that
/// wants durability says so. The port is the same either way, which is why this
/// is a choice at the composition root rather than a change anywhere else.
async fn stored(config: &Config) -> Result<Arc<dyn Outbox>, Unstartable> {
    let Some(name) = config.database.as_deref() else {
        return Ok(Arc::new(MemoryOutbox::new()));
    };

    // Read from the mounted directory like every other secret, and never from
    // the environment: a connection string carries a password.
    let path = config.secrets.join(name);
    let url = std::fs::read_to_string(&path).map_err(|_| {
        Unstartable::Configuration(format!(
            "WEBHOOK_PROXY_DATABASE_SECRET names {name:?}, and no secret of that name is in {}",
            config.secrets.display()
        ))
    })?;
    // Trailing newline is a renderer's doing, not the secret's — the same rule
    // yaml-config applies to every other secret.
    let url = url.trim_end_matches(['\n', '\r']);

    // Waited for, not crash-looped into, for the reason gc-6b7 gives: a database
    // that is still starting is not a misconfiguration, and CrashLoopBackOff
    // punishes the race rather than the fault. The schema is applied here too,
    // behind the advisory lock sqlx takes, so two replicas cannot race it.
    let deadline = Instant::now() + config.startup_wait;
    let mut said = false;
    loop {
        match PostgresOutbox::connect(url, DATABASE_CONNECTIONS).await {
            Ok(outbox) => return Ok(Arc::new(outbox)),
            Err(why) if Instant::now() < deadline => {
                if !said {
                    // No address and no password: StorageUnavailable carries
                    // neither, which is the whole reason it exists (gc-b0n).
                    eprintln!("webhook-proxy is waiting for the delivery store: {why}");
                    said = true;
                }
                tokio::time::sleep(LOOK_AGAIN).await;
            }
            Err(why) => return Err(Unstartable::Configuration(why.to_string())),
        }
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

    let outbox = stored(&config).await?;

    let inbound = Inbound::new(
        senders,
        Arc::clone(&dispatcher),
        Arc::clone(&outbox),
        Arc::new(SystemClock),
        Arc::new(RandomIds),
        routing.subscriptions().to_vec(),
        config.retry,
    );

    // The second half of the promise. The relay sends immediately; this is what
    // comes back to whatever that could not deliver, so a Destination that was
    // down for a minute is not a message nobody ever sees.
    let retrying = tokio::spawn({
        let dispatcher = Arc::clone(&dispatcher);
        let outbox = Arc::clone(&outbox);
        let retry = config.retry;
        let sweep = config.sweep;
        async move {
            let clock = SystemClock;
            let retries = Retries::new(dispatcher.as_ref(), outbox.as_ref(), &clock, retry);
            loop {
                match retries.once(RETRY_BATCH).await {
                    Ok(attempted) if !attempted.idle() => tracing::info!(
                        delivered = attempted.delivered,
                        retrying = attempted.retrying,
                        abandoned = attempted.abandoned,
                        "retried what was due"
                    ),
                    Ok(_) => {}
                    // No address, no credential: StorageUnavailable carries
                    // none, and this line is written from it.
                    Err(why) => tracing::error!(%why, "cannot read the outbox"),
                }
                tokio::time::sleep(sweep).await;
            }
        }
    });

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

    // Stopped with the listener. Anything it was mid-way through is still in
    // the outbox, which is the point of the outbox.
    retrying.abort();

    Ok(())
}
