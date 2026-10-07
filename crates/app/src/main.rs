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

use application::ports::Dispatcher;
use axum::routing::get;
use domain::{
    Destination, DestinationId, DestinationKind, Filter, Origin, OriginId, SecretId, Subscription,
    Verification,
};
use element_notices::ElementNotices;
use github_payload::GithubPayload;
use github_signatures::GithubSignatures;
use inbound_http::{Inbound, router};
use std::sync::Arc;
use system::{RandomIds, SystemClock};

/// The name this deployment knows its one Origin by. It appears in the webhook
/// path, so GitHub is configured to post to `/webhook/github`.
const ORIGIN: &str = "github";

/// The name the Origin's secret is held under. An internal label, not a value.
const SECRET: &str = "github-webhook-secret";

/// Why the process will not start.
///
/// Every variant names the environment variable at fault and never its value: a
/// startup error is the single most likely thing to be pasted into a chat window.
#[derive(Debug)]
enum Unstartable {
    /// A required variable is absent or blank.
    Missing(&'static str),
    /// A variable is present but unusable.
    Unusable { name: &'static str, why: String },
    /// The HTTP client for the destination could not be built.
    NoClient,
    /// The listening socket could not be served.
    Serving(String),
}

impl fmt::Display for Unstartable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(name) => write!(f, "{name} is not set"),
            Self::Unusable { name, why } => write!(f, "{name} is unusable: {why}"),
            Self::NoClient => write!(f, "the HTTP client for the destination could not be built"),
            Self::Serving(why) => write!(f, "could not serve: {why}"),
        }
    }
}

/// Shorthand for the `Missing` case, since configuration reading only has that
/// one failure.
type Missing = Unstartable;

/// Everything the process needs to start.
struct Config {
    listen: String,
    max_body: usize,
    timeout: Duration,
    github_secret: String,
    element_url: String,
    element_room: String,
}

impl Config {
    /// Reads configuration from the environment.
    ///
    /// Secrets have no defaults and no fallbacks. A deployment missing one fails
    /// to start rather than starting in a state where it cannot authenticate
    /// what it receives — this proxy is the authentication boundary, so running
    /// without a secret would be worse than not running.
    fn from_env() -> Result<Self, Missing> {
        Ok(Self {
            listen: optional("WEBHOOK_PROXY_LISTEN", "127.0.0.1:8080"),
            max_body: optional("WEBHOOK_PROXY_MAX_BODY", "1048576")
                .parse()
                .unwrap_or(1_048_576),
            timeout: Duration::from_millis(
                optional("WEBHOOK_PROXY_TIMEOUT_MS", "5000")
                    .parse()
                    .unwrap_or(5_000),
            ),
            github_secret: required("GITHUB_WEBHOOK_SECRET")?,
            element_url: required("ELEMENT_WEBHOOK_URL")?,
            element_room: required("ELEMENT_ROOM")?,
        })
    }
}

fn required(name: &'static str) -> Result<String, Missing> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or(Unstartable::Missing(name))
}

fn optional(name: &str, fallback: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| fallback.to_owned())
}

/// Liveness and readiness for k3s probes.
///
/// Deliberately answers from the process alone: a probe that depended on the
/// destination being reachable would restart a healthy proxy every time a chat
/// server hiccupped.
async fn health() -> &'static str {
    "ok"
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

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

async fn run() -> Result<(), Unstartable> {
    let config = Config::from_env()?;

    let signatures = Arc::new(GithubSignatures::new(HashMap::from([(
        SECRET.to_owned(),
        config.github_secret.into_bytes(),
    )])));

    let room = DestinationId::new(&config.element_room).map_err(|blank| Unstartable::Unusable {
        name: "ELEMENT_ROOM",
        why: blank.to_string(),
    })?;
    let dispatcher: Arc<dyn Dispatcher> = Arc::new(
        ElementNotices::new(
            HashMap::from([(config.element_room.clone(), config.element_url)]),
            config.timeout,
        )
        .map_err(|_| Unstartable::NoClient)?,
    );

    let subscriptions = vec![Subscription::new(
        Destination::new(room, DestinationKind::ChatRoom),
        Filter::Everything,
    )];

    // Both names are consts in this file rather than configuration, so neither
    // can be blank today. Reported rather than unwrapped all the same: the
    // composition root is where a bad name becomes a refusal to start, and the
    // moment either comes from a file (gc-ast.11) this is already the right
    // shape. Same idiom as ELEMENT_ROOM above.
    let origin_id = OriginId::new(ORIGIN).map_err(|blank| Unstartable::Unusable {
        name: "the Origin identity",
        why: blank.to_string(),
    })?;
    let secret_id = SecretId::new(SECRET).map_err(|blank| Unstartable::Unusable {
        name: "the secret name",
        why: blank.to_string(),
    })?;
    // Signed, because GitHub signs. A second mechanism is a configuration
    // change, never a fallback this code could choose (gc-ast.2).
    let origins = HashMap::from([(
        ORIGIN.to_owned(),
        Origin::new(origin_id, Verification::Signed { secret: secret_id }),
    )]);

    let inbound = Inbound::new(
        signatures,
        Arc::new(GithubPayload),
        dispatcher,
        Arc::new(SystemClock),
        Arc::new(RandomIds),
        subscriptions,
        origins,
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
        .await
        .map_err(|why| Unstartable::Serving(why.to_string()))?;

    Ok(())
}
