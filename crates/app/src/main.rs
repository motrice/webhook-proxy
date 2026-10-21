//! Composition root. The only crate permitted to name a concrete adapter.
//!
//! Everything here is wiring: read configuration, construct adapters, inject
//! them into the use case, start the inbound adapter. No business logic, and
//! therefore nothing here needs a unit test — it is covered by the acceptance
//! test, which drives the built binary.

use std::collections::HashMap;
use std::fmt;
use std::fmt::Write as _;
use std::process::ExitCode;
use std::time::Duration;
use std::time::Instant;

use alertmanager_payload::AlertmanagerPayload;
mod collecting;

use application::ports::{Handover, Proofs, Reoffered, Translator};
use application::{Backlog, Outcomes, Retention};
use axum::http::StatusCode;
use axum::routing::get;
use domain::{DeliveryId, Verification};
use github_payload::GithubPayload;
use github_signatures::GithubSignatures;
use grafana_payload::GrafanaPayload;
use inbound_http::{AUTHORIZATION_HEADER, Inbound, SIGNATURE_HEADER, Sender, router};
use memory_outbox::MemoryHandover;
use postgres_outbox::PostgresHandover;
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
    /// The listening socket could not be served.
    Serving(String),
}

impl fmt::Display for Unstartable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unusable { name, why } => write!(f, "{name} is unusable: {why}"),
            Self::Configuration(why) => write!(f, "{why}"),
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
    /// Where the operator's surface answers: `/metrics`, `/health`, `/api-info`.
    ///
    /// A SECOND SOCKET, AND IT IS A BOUNDARY RATHER THAN TIDINESS (bead gc-wdt).
    /// Every tenant's agent must be allowed to reach `listen`, because claim and
    /// report live there — so anything served beside them is served to every
    /// tenant. The series `/metrics` exports are labelled by tenant and room, so
    /// one tenant could enumerate another's room identities, how much each is
    /// being told, and which are failing and why. Measured from a tenant
    /// namespace, not reasoned about.
    ///
    /// A `NetworkPolicy` cannot draw this line: ingress rules select a pod and a
    /// port, never a path, and the port the agent needs is the port metrics was
    /// on. A second socket is the one separation the process itself can make.
    operator: String,
    max_body: usize,
    file: PathBuf,
    secrets: PathBuf,
    startup_wait: Duration,
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
            // Loopback by default for the same reason as above: a default that
            // reached the network would be a surface nobody asked for. The
            // manifest sets both, and the manifest tests prove it.
            operator: optional("WEBHOOK_PROXY_OPERATOR_LISTEN", "127.0.0.1:9090"),
            max_body: optional("WEBHOOK_PROXY_MAX_BODY", "1048576")
                .parse()
                .unwrap_or(1_048_576),
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
/// In memory unless a database is configured. Every deployment configures one —
/// bead gc-vfz decided that these rooms want durable delivery, and the manifests
/// name the secret, so the memory outbox is what a local run gets rather than
/// what anybody is served by. The port is the same either way, which is why this
/// is a choice at the composition root rather than a change anywhere else.
///
/// The cost of that decision is paid here: a database this cannot reach makes
/// the proxy refuse with 503 rather than accept what it cannot promise to keep,
/// so an outage of the store refuses traffic that the memory outbox would have
/// accepted and probably delivered. That is the trade gc-vfz accepted, with the
/// reasoning recorded there rather than argued again in a comment.
/// The two durable stores, which stand or fall together.
///
/// Where a Delivery waits for its tenant.
///
/// One store, where there were two until bead gc-72e.3.2: the other held work
/// this service delivered itself, and it no longer delivers anything.
async fn stored(config: &Config) -> Result<Arc<dyn Handover>, Unstartable> {
    let Some(name) = config.database.as_deref() else {
        // SAID OUT LOUD, BECAUSE NOTHING ELSE CAN SAY IT (bead gc-f7t). A
        // process cannot know its own replica count, so this cannot fail
        // closed; what it can do is state the one rule that makes a memory
        // store safe, in the first thing it prints.
        //
        // The failure it exists for was measured on a dev cluster: two replicas
        // with no database each held their own store, a webhook landed in A's
        // memory, the agent's claim was load-balanced to B and got an empty
        // list, its report was load-balanced to B and got a 404, and the
        // symptoms were a duplicate in a room and a delivered counter that
        // disagreed with what the room got. Nothing in that points at a replica
        // count.
        //
        // ON STDERR, not stdout: stdout's first line is the address, which the
        // acceptance tests and an operator both read as a protocol.
        eprintln!(
            "webhook-proxy is holding deliveries in memory: WEBHOOK_PROXY_DATABASE_SECRET \
             is not set, so this deployment must run exactly one replica — with more, a \
             claim or a report can reach a replica that has never heard of the delivery — \
             and nothing uncollected survives a restart"
        );
        return Ok(Arc::new(MemoryHandover::new()));
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
        match PostgresHandover::connect(url, DATABASE_CONNECTIONS).await {
            Ok(handover) => return Ok(Arc::new(handover)),
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

/// Sends a past Delivery again, and says where it went.
///
/// Offers a stored Delivery to its tenant again, marked as a replay.
///
/// WHAT THIS USED TO DO, and why it changed: it re-sent a stored Dispatch
/// itself. Routing left this service (bead gc-g9x), so there is no Dispatch to
/// re-send and no room for this process to reach — what it has instead is the
/// Delivery, which survives its report for a month, and a tenant whose agent
/// will deliver it by the rules in force now. The outcome a person wanted is
/// the same and the mechanism is not, which is worth knowing before reading
/// the output.
///
/// IT STILL ARRIVES MARKED. Bead gc-6a5.3 decided that deliberately and the
/// decision survives the change of mechanism: an alert arriving twice is how a
/// responder learns something got worse, so a replay that looked like a retry
/// would be a lie told by a tool. The flag travels with the claim, and the
/// agent — not this process — puts `(replayed)` in the room.
///
/// NO TENANT IS ASKED FOR. The person running this has a Delivery identity out
/// of a log line; making them find its tenant first would mean looking it up
/// from the thing they are already holding. See `Handover::reoffer`, which is
/// the only method on that port with no tenant and says why.
async fn replay(id: &str) -> Result<String, Unstartable> {
    let config = Config::from_env();

    let delivery = DeliveryId::new(id)
        .map_err(|why| Unstartable::Configuration(format!("that is not a delivery: {why}")))?;

    // Nothing here dispatches, reads a routing file or reaches a room: a replay
    // is now one row changing its mind about being settled.
    let handover = stored(&config).await?;

    let mut said = String::new();
    match handover
        .reoffer(&delivery)
        .await
        .map_err(|why| Unstartable::Configuration(why.to_string()))?
    {
        Reoffered::Owed => {
            writeln!(
                said,
                "offered again to its tenant, marked as a replay. Its agent \
                 will deliver it by the rules in force now, which is usually \
                 the point — and nothing here can say which rooms those are."
            )
            .expect("writing to a String cannot fail");
        }
        Reoffered::NotStored => {
            // Not a failure, and said plainly: "nothing happened" is the one
            // outcome an operator is most likely to misread as success.
            writeln!(
                said,
                "nothing goes by that identity. Either it was never accepted, \
                 or retention has already deleted it — one month from \
                 acceptance, and the two are indistinguishable from here."
            )
            .expect("writing to a String cannot fail");
        }
    }
    Ok(said)
}

/// How long a Delivery nobody collected is kept.
///
/// One month, by bead gc-mnn. Measured from acceptance, which is the age a
/// reader means when they ask how old something is.
///
/// Not configurable, deliberately. It is a retention decision about other
/// people's alert text — a summary, labels, a permalink into monitoring — and
/// an environment variable would let a deployment quietly choose "forever",
/// which gc-mnn rejected precisely because it is what happens when nobody
/// decides.
const KEEP_FOR: Duration = Duration::from_hours(30 * 24);

/// How long a Delivery may sit uncollected before it is worth saying so.
///
/// A day: long enough that a tenant's agent being restarted, or a weekend
/// deployment freeze, is not an incident; short enough that a stopped agent is
/// noticed twenty-nine days before its alerts start being dropped.
const REPORT_BEHIND_AFTER: Duration = Duration::from_hours(24);

/// How often retention runs.
///
/// Its own interval rather than the outbox sweep's, which is five seconds: the
/// questions here are about days and a month, and asking them every five
/// seconds would mean a `GROUP BY` over every outstanding row twelve times a
/// minute for an answer that cannot have changed.
///
/// A task in this process rather than a cron job, which is bead gc-mnn's
/// reasoning: a second thing the deployment already does cannot drift out of
/// the deployment, and a job nobody owns eventually belongs to nobody.
const REAP_EVERY: Duration = Duration::from_mins(15);

/// Retention, and the only report anybody gets that a tenant has stopped.
///
/// A task rather than part of serving, like the outbox sweep: nothing waits on
/// it. What it writes is the deliverable, not a side effect — bead gc-g9x
/// deferred the read API on the explicit promise that an operator could still
/// learn an agent had stopped, and this is where that promise is kept or not.
fn reaping(
    handover: Arc<dyn Handover>,
    backlog: Arc<Backlog>,
    every: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let clock = SystemClock;
        let retention = Retention::new(handover.as_ref(), &clock, KEEP_FOR, REPORT_BEHIND_AFTER);
        loop {
            match retention.once().await {
                Ok(reaped) if !reaped.quiet() => {
                    // ONE LINE PER DROPPED DELIVERY, not a count. This is the
                    // third kind of loss gc-g9x enumerated, and the one nothing
                    // else can see: a room that gave up is counted against that
                    // room, and an alert no tenant ever collected has no room
                    // to count against. A summary line would make it a number
                    // with nothing to trace back to the push that caused it.
                    //
                    // The trace is what makes it traceable (gc-4oo.5); the
                    // Events are deliberately not here, because an alert's
                    // summary and labels are other people's words.
                    for lost in &reaped.uncollected {
                        tracing::error!(
                            delivery = %lost.delivery,
                            tenant = %lost.tenant,
                            origin = %lost.origin,
                            trace = %lost.trace,
                            accepted_at_ms = lost.accepted_at.millis_since_epoch(),
                            "dropped an alert its tenant never collected: retention \
                             reached it first"
                        );
                    }
                    backlog.dropped(reaped.uncollected.len());

                    // One line per tenant that is behind, at warn rather than
                    // error: it is not yet a loss, which is the distinction the
                    // whole job rests on. Nothing is logged for a tenant that
                    // is keeping up, so this stays readable.
                    for tenant in &reaped.behind {
                        tracing::warn!(
                            tenant = %tenant.tenant,
                            outstanding = tenant.outstanding,
                            oldest_at_ms = tenant.oldest.millis_since_epoch(),
                            "a tenant has not collected its alerts"
                        );
                    }
                    backlog.found(&reaped.behind);

                    if reaped.settled > 0 {
                        tracing::info!(
                            settled = reaped.settled,
                            "retention removed settled deliveries"
                        );
                    }
                }
                // A quiet pass still has to clear the gauges: a tenant that
                // caught up must stop being reported, or its worst number
                // stands forever and somebody eventually acts on it.
                Ok(_) => backlog.found(&[]),
                Err(why) => tracing::error!(%why, "cannot apply retention"),
            }
            tokio::time::sleep(every).await;
        }
    })
}

/// The counters, in the format Prometheus scrapes.
///
/// Beside `/health` and for the same reason: both answer a machine that reaches
/// the pod directly, and neither is published through the Gateway. gc-d01's
/// `HTTPRoute` carries `/webhook` and nothing else on purpose — publishing an
/// internal endpoint hands the internet a free oracle about a service it should
/// not be able to see, and Prometheus scrapes pods rather than routes.
///
/// Reads a count and nothing else. A scrape must never touch the store: a
/// monitoring system polling every fifteen seconds would otherwise become load
/// on the thing it is monitoring, and would go quiet exactly when the database
/// is in trouble — which is when somebody is looking.
fn exported(backlog: &Backlog, told: &Outcomes) -> String {
    let mut out = String::new();

    // KEYED BY ROOM AGAIN, BUT ON SOMEBODY ELSE'S WORD. This service does not
    // reach a room — a tenant's agent does, in another namespace, with no
    // scrape endpoint of its own by design (bead gc-72e) — so what a room saw
    // is counted here from the reports that already cross the wire, and not
    // observed here (bead gc-556). Two honest consequences: a loss an agent
    // never manages to report is not counted, and the count is as current as
    // that tenant's last report.
    //
    // A ROOM NAME IS NOT A ROOM ADDRESS, which is why this is sayable at all: a
    // `Destination` is a name with no address by construction, the URL lives in
    // the tenant's own namespace, and this process never learns one. So nothing
    // here is an address or a secret — a tenant is a namespace, a room is a
    // name its tenant chose, and the numbers are counts and a moment.
    writeln!(
        out,
        "# HELP webhook_proxy_uncollected_dropped_total Alerts deleted by retention \
         that no tenant ever collected. These are losses."
    )
    .expect("writing to a String cannot fail");
    writeln!(
        out,
        "# TYPE webhook_proxy_uncollected_dropped_total counter"
    )
    .expect("writing to a String cannot fail");
    writeln!(
        out,
        "webhook_proxy_uncollected_dropped_total {}",
        backlog.losses()
    )
    .expect("writing to a String cannot fail");

    for (name, help, kind) in [
        (
            "webhook_proxy_outstanding_deliveries",
            "Deliveries a tenant has not collected, older than the reporting \
             threshold. A tenant keeping up does not appear.",
            "gauge",
        ),
        (
            "webhook_proxy_outstanding_oldest_ms",
            "When the oldest uncollected Delivery for this tenant was accepted. \
             A count alone cannot tell a busy tenant from a stopped one.",
            "gauge",
        ),
    ] {
        writeln!(out, "# HELP {name} {help}").expect("writing to a String cannot fail");
        writeln!(out, "# TYPE {name} {kind}").expect("writing to a String cannot fail");
        for (tenant, outstanding) in backlog.all() {
            let value = if name.ends_with("_ms") {
                outstanding.oldest.millis_since_epoch()
            } else {
                i64::try_from(outstanding.owed).unwrap_or(i64::MAX)
            };
            writeln!(out, "{name}{{tenant=\"{}\"}} {value}", escaped(&tenant))
                .expect("writing to a String cannot fail");
        }
    }

    // THE ONE LINE AN ALERT CAN BE WRITTEN AGAINST WITHOUT KNOWING WHICH ROOMS
    // EXIST, and the reason it is here at zero rather than only when something
    // has been lost: a rule on a series that does not exist yet never fires, so
    // the first loss in a fresh pod would be the one nobody is paged for.
    writeln!(
        out,
        "# HELP webhook_proxy_room_abandoned_total Dispatches a tenant's agent \
         spent its whole retry budget on and did not deliver. These are losses."
    )
    .expect("writing to a String cannot fail");
    writeln!(out, "# TYPE webhook_proxy_room_abandoned_total counter")
        .expect("writing to a String cannot fail");
    writeln!(out, "webhook_proxy_room_abandoned_total {}", told.losses())
        .expect("writing to a String cannot fail");
    for ((tenant, room, why), count) in told.abandoned() {
        writeln!(
            out,
            "webhook_proxy_room_abandoned_total{{tenant=\"{}\",room=\"{}\",reason=\"{why}\"}} {count}",
            escaped(&tenant),
            escaped(&room)
        )
        .expect("writing to a String cannot fail");
    }

    // The denominator. An absolute number of losses says nothing on its own: a
    // tenant sending thousands an hour and a tenant sending one a week want
    // very different thresholds, and a ratio needs both halves (bead gc-556).
    writeln!(
        out,
        "# HELP webhook_proxy_room_delivered_total Dispatches a tenant's agent \
         reported as accepted by the room."
    )
    .expect("writing to a String cannot fail");
    writeln!(out, "# TYPE webhook_proxy_room_delivered_total counter")
        .expect("writing to a String cannot fail");
    for ((tenant, room), count) in told.delivered() {
        writeln!(
            out,
            "webhook_proxy_room_delivered_total{{tenant=\"{}\",room=\"{}\"}} {count}",
            escaped(&tenant),
            escaped(&room)
        )
        .expect("writing to a String cannot fail");
    }

    out
}

/// A label value Prometheus can read back.
///
/// A Destination's identity cannot contain a quote, a backslash or a newline —
/// `yaml-config` refuses a secret name that is not a usable file name, and the
/// same names identify rooms. This escapes anyway, because that constraint
/// lives in another crate and an exporter that depended on it silently would
/// produce an unparseable scrape the day it changed.
fn escaped(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// Liveness. The process is running and its own machinery answers.
///
/// Deliberately answers from the process alone: a probe that depended on the
/// destination being reachable would restart a healthy proxy every time a chat
/// server hiccupped.
///
/// THAT ARGUMENT IS LIVENESS'S AND IT KEEPS IT (bead gc-28a). It did not cover
/// the database and it did not cover readiness, which is a different question —
/// `ready` below asks it. Restarting will not reach a database that is down, so
/// the store must never appear here: a dependency failure that turned into a
/// restart loop would replace a recoverable outage with a pod that is never up
/// long enough to recover.
async fn health() -> &'static str {
    "ok"
}

/// Readiness. Whether this pod can do the work, which means its store answering.
///
/// WHAT THIS FIXES (bead gc-28a): a replica whose pool cannot reach the database
/// used to answer "ok", stay Ready, keep its Endpoint and take its share of
/// traffic from the Service — and fail every request it got. A sender that was
/// going to be told `202` is told `503`, an agent's claim is handed nothing, and
/// a report cannot settle. With two replicas that is half of everything,
/// intermittently, behind a green probe.
///
/// Kubernetes already knows what to do about a pod that cannot serve: take it
/// out of the Service until it can. This process used to decline to say so.
///
/// THE VALUE APPEARS EXACTLY WHEN THERE IS A HEALTHY SIBLING. At one replica,
/// removing the only pod turns a `503` into a connection refused, which is no
/// better — and the memory store is reachable by construction, so the
/// no-database shape gc-f7t calls supported stays Ready throughout.
///
/// The destination stays out of this as much as out of liveness: an unreachable
/// room is the agent's problem, in another namespace, and it is counted
/// (gc-556).
async fn ready(handover: &dyn Handover) -> (StatusCode, &'static str) {
    if handover.reachable().await.is_ok() {
        (StatusCode::OK, "ready")
    } else {
        // No address, no credential, no driver text: `StorageUnavailable`
        // carries none (gc-b0n), and a probe's body is read by anybody who can
        // reach the port. What it is NOT is silence — this log line says the
        // same thing where an operator will find it after the fact.
        // THE LOG CARRIES THE REASON AND THE RESPONSE DOES NOT. A probe reads a
        // status code, so a body buys nothing here — and declaring one in
        // docs/openapi.yaml would make it this interface's first error with a
        // schema, which brings RAP-LP's FEL.02 (errors SKALL be
        // application/problem+json) to bear on a readiness endpoint while every
        // other error in the spec has no body at all. Whether this API adopts
        // RFC 9457 is bead gc-4oo.2's to decide, not this bead's to pre-empt.
        tracing::warn!("not ready: the delivery store is not answering");
        (StatusCode::SERVICE_UNAVAILABLE, "")
    }
}

/// The surface the cluster's own machinery reaches, and no tenant.
///
/// Assembled here rather than in `run` so that what belongs on this socket is
/// one list in one place: everything that is neither the public webhook nor the
/// tenant hand-off (bead gc-wdt). A path added to the wrong router is a path
/// served to every tenant, which is not the sort of mistake that should depend
/// on reading a long function.
///
/// One rule, so there is nothing to judge when a path is added. What is here is
/// reachable by whoever the `NetworkPolicy` admits to this port — Prometheus and
/// the kubelet — and what is on the other router is reachable by every tenant.
/// `/health` and `/ready` are here rather than beside the hand-off because they
/// answer a machine that reaches the pod directly; `deployment.yaml`'s probes
/// name this port, and `crates/app/tests/manifests.rs` refuses a probe that
/// names the other one.
fn operators(
    backlog: Arc<Backlog>,
    outcomes: Arc<Outcomes>,
    handover: Arc<dyn Handover>,
) -> axum::Router {
    axum::Router::new()
        .route("/health", get(health))
        .route(
            "/ready",
            get(move || {
                let handover = Arc::clone(&handover);
                async move { ready(handover.as_ref()).await }
            }),
        )
        .route("/api-info", get(api_info))
        .route(
            "/metrics",
            get(move || {
                let backlog = Arc::clone(&backlog);
                let outcomes = Arc::clone(&outcomes);
                async move { exported(&backlog, &outcomes) }
            }),
        )
}

/// When this version of the interface was published.
///
/// A literal, and the one value here that cannot be derived: there is no release
/// process yet (bead gc-lw3), so nothing stamps a date. It is the day
/// `docs/openapi.yaml` first described this interface, which is what "released"
/// means for an API — the interface became available to a reader, whatever the
/// deployment history.
///
/// `api_info_moves_its_release_date_when_a_version_is_actually_released` fails if
/// the crate version ever leaves `0.0.0` while this is unchanged, so the first
/// real release cannot quietly serve a two-year-old date.
const RELEASED: &str = "2026-10-12";

/// Where a reader goes next. Reachable without a credential, like this resource.
const DOCUMENTATION: &str =
    "https://github.com/motrice/webhook-proxy/blob/main/docs/sending-to-this-proxy.md";

/// What is answering, for an operator looking at a running pod.
///
/// VER.06 of the national REST API-profil, accepted rather than refused in bead
/// gc-4oo.2 because it is cheap and genuinely useful: nothing else here says
/// which version replied. It lives at the root rather than under a version
/// segment because VER.05 is departed — the path is the sender's configuration,
/// not ours to version.
///
/// Unauthenticated by its own definition, so what it must NOT say is the
/// interesting part: no Origin, no Destination, no room, no secret, nothing
/// about what this deployment is configured to relay. Naming the product and its
/// documentation is the whole of it. The acceptance test asserts the absence by
/// searching the body for the test deployment's own rooms and tokens.
///
/// `apiVersion` is read from the crate rather than written here, so a release
/// that forgets to update it is impossible rather than merely discouraged.
async fn api_info() -> impl axum::response::IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        serde_json::json!({
            // The BIN name, not the package name: the crate is `app` and the
            // product is `webhook-proxy`. Still derived rather than written, so
            // a rename cannot leave this answering the old one.
            "apiName": env!("CARGO_BIN_NAME"),
            "apiVersion": env!("CARGO_PKG_VERSION"),
            "apiReleased": RELEASED,
            "apiDocumentation": DOCUMENTATION,
            // Beta until the inbound contract stops moving: gc-4oo still has
            // open children that change what this interface answers.
            "apiStatus": "beta",
        })
        .to_string(),
    )
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

    // Explicit, and the only way a replay ever starts. Nothing on the request
    // path can reach it: a replay exists because a person decided one was
    // needed, after an outage or a bug in a renderer, and a room being sent
    // something twice should always be traceable to somebody asking.
    if std::env::args().nth(1).as_deref() == Some("replay") {
        let Some(id) = std::env::args().nth(2) else {
            eprintln!("usage: webhook-proxy replay <delivery-id>");
            return ExitCode::FAILURE;
        };
        return match replay(&id).await {
            Ok(table) => {
                print!("{table}");
                ExitCode::SUCCESS
            }
            Err(why) => {
                eprintln!("webhook-proxy cannot replay: {why}");
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
                    tenant: declared.tenant.clone(),
                    proofs,
                    translator,
                    presented,
                },
            )
        })
        .collect();

    let handover = stored(&config).await?;

    let inbound = Inbound::new(
        senders,
        Arc::clone(&handover),
        Arc::new(SystemClock),
        Arc::new(RandomIds),
    );

    // The hand-off to a tenant's agent. Merged rather than layered, so these two
    // paths carry no body limit and no part of the sender pipeline: nothing
    // about them is a webhook. What authenticates them is the service mesh, and
    // `collecting`'s own documentation says what that assumption costs if it
    // does not hold.
    // What each room was told, shared: the report path writes it and the scrape
    // reads it. In this process because the tenant agents that learn these
    // outcomes have no scrape endpoint and bead gc-72e forbade them one, so an
    // abandoned dispatch was visible in one pod's log and nowhere else — and
    // gone with that pod (bead gc-556).
    let outcomes = Arc::new(Outcomes::new());

    let collecting = collecting::Collecting::new(
        Arc::clone(&handover),
        Arc::new(SystemClock),
        routing.tenants().clone(),
        Arc::clone(&outcomes),
    );

    // One backlog, shared: the retention task writes it and the scrape reads it.
    // A scrape must never touch the store (see `exported`), so what /metrics
    // says about a tenant is as fresh as the last pass and no fresher — which is
    // the right trade for a number measured in days.
    let backlog = Arc::new(Backlog::new());
    let reaped = reaping(Arc::clone(&handover), Arc::clone(&backlog), REAP_EVERY);

    // WHAT EVERY TENANT MAY REACH, and nothing else (bead gc-wdt): the senders'
    // webhook, and the hand-off the agents authenticate themselves to.
    let app = router(inbound, config.max_body).merge(collecting::routes(collecting));

    // WHAT THE CLUSTER'S OWN MACHINERY REACHES, on its own socket (bead gc-wdt),
    // and never anything a tenant may knock on.
    let operator = operators(
        Arc::clone(&backlog),
        Arc::clone(&outcomes),
        Arc::clone(&handover),
    );

    let listener = tokio::net::TcpListener::bind(&config.listen)
        .await
        .map_err(|why| Unstartable::Unusable {
            name: "WEBHOOK_PROXY_LISTEN",
            why: why.to_string(),
        })?;
    // BOTH BOUND BEFORE EITHER IS ANNOUNCED. A process that printed its first
    // address and then failed on the second would have told the truth in a way
    // that reads as a successful start, and the acceptance harness takes that
    // line as proof it is up.
    let watching = tokio::net::TcpListener::bind(&config.operator)
        .await
        .map_err(|why| Unstartable::Unusable {
            name: "WEBHOOK_PROXY_OPERATOR_LISTEN",
            why: why.to_string(),
        })?;
    let address = listener
        .local_addr()
        .map_err(|why| Unstartable::Serving(why.to_string()))?;
    let watched = watching
        .local_addr()
        .map_err(|why| Unstartable::Serving(why.to_string()))?;

    // Printed on stdout, not logged, because the acceptance test reads it to
    // learn which port was chosen when asked to bind port 0 — and because an
    // operator wants it even with logging turned down. THE FIRST LINE IS A
    // PROTOCOL: it is the public address, and the operator address comes after
    // it, so a reader that only wants one keeps working.
    println!("listening on {address}");
    println!("operator listening on {watched}");
    tracing::info!(%address, %watched, "webhook-proxy started");

    // Both served from one task tree, and the public one owns the shutdown: when
    // it has finished draining what it accepted, this future is dropped and the
    // operator socket closes with it. So a probe during a graceful stop still
    // sees a process that is answering, which is what it is doing.
    //
    // The operator server is in the select rather than spawned so that its own
    // failure is this function's failure. Spawned, it could die unnoticed and
    // leave a pod that passes no probe while serving every webhook.
    let served = axum::serve(listener, app).with_graceful_shutdown(asked_to_stop());
    let watched_over = axum::serve(watching, operator);
    tokio::select! {
        ended = served => ended.map_err(|why| Unstartable::Serving(why.to_string()))?,
        ended = watched_over => ended.map_err(|why| Unstartable::Serving(why.to_string()))?,
    }

    // Stopped with the listener. Anything it was mid-way through is still in
    // the outbox, which is the point of the outbox — and is only true of a
    // durable one. Against the memory outbox this line drops whatever was
    // waiting, silently and uncounted; that is why gc-vfz made every deployment
    // name a database rather than leaving the sentence above to be wishful.
    // Stopped with the listener, and nothing is lost by it: retention is a month, so
    // a pass that does not happen because the process is shutting down happens
    // on the next start instead. Nothing waits on this and nothing is half
    // done — a sweep deletes and reports in one statement.
    reaped.abort();

    Ok(())
}
