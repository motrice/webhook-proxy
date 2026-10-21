//! The tenant agent: a thin deliverer with its own rooms.
//!
//! A second deployment, in a tenant's own namespace, holding the only two
//! things that are genuinely the tenant's: which alerts reach which room, and
//! those rooms' URLs. Bead gc-72e.
//!
//! WHAT IT DOES NOT HOLD is most of what makes it thin. No Origin and no
//! sender's secret — the platform authenticates senders. No tenant name — the
//! platform derives the tenant from the Origin at acceptance and from this
//! agent's own mTLS identity at claim time, so a name here would be checked
//! against nothing (bead gc-nkb). No database: it pulls, and it is stateless.
//!
//! IT IS THE ONLY THING THAT REACHES A ROOM. The platform verifies a delivery
//! and owes it to a tenant; bead gc-72e.3.2 removed its dispatcher, its outbox
//! and its retry loop, so if this agent does not deliver an alert then nobody
//! does. What a room saw, and what it was never told, is in this process's log
//! and the counters beside it.
//!
//! This paragraph used to say the opposite — that the platform delivered too
//! and running this would duplicate every message — and it stayed true for two
//! beads and then false for one. Bead gc-o2x: the cost of leaving it was that
//! an operator read it as the explanation for a loss that had a different cause
//! entirely.

mod platform;

use std::path::PathBuf;
use std::process::ExitCode;

use application::{Deliver, Retry, idle_for};
use element_notices::ElementNotices;
use system::{RandomIds, Resting, SystemClock};
use yaml_config::TenantConfiguration;

use crate::platform::Platform;

/// Where the agent reads its rules and its rooms from.
///
/// The same two variables the platform uses for the same two things, spelled
/// for this binary: an operator who has deployed one should not have to learn a
/// second vocabulary, and a shared spelling would mean one `ConfigMap` could be
/// mounted into the wrong deployment and read.
const CONFIG: &str = "ALERT_AGENT_CONFIG";
const SECRETS: &str = "ALERT_AGENT_SECRETS_DIR";

/// Where the platform answers. In the environment because it is where this
/// process runs, not what it is allowed to do — the same line bead gc-ast.3
/// drew for the proxy.
const PLATFORM: &str = "ALERT_AGENT_PLATFORM";

/// How long to wait for the platform, and for a room.
///
/// Well inside the five-minute lease either way. Not configurable: a timeout
/// long enough to matter would be a timeout long enough to outlive the claim,
/// and then the agent would deliver work it no longer holds.
const TIMEOUT: core::time::Duration = core::time::Duration::from_secs(10);

/// The budget for one room: five attempts, a second doubling to thirty.
///
/// About thirty-one seconds all told, which is what makes a five-minute lease
/// comfortable rather than tight (bead gc-81d). Spent in process, because the
/// agent has no store to come back to it from.
fn budget() -> Retry {
    Retry::new(
        core::time::Duration::from_secs(1),
        core::time::Duration::from_secs(30),
        5,
    )
}

/// What the agent was asked for, and could not do.
enum Unstartable {
    /// The configuration cannot be used. Carries the file and the field.
    Configuration(String),
    /// A variable the run mode cannot default.
    Missing(&'static str),
    /// Something this build does not do was asked for.
    Unknown(String),
}

impl std::fmt::Display for Unstartable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Configuration(why) => write!(f, "{why}"),
            Self::Missing(name) => write!(
                f,
                "{name} is not set, and there is nothing sensible to default it \
                 to: an agent that guessed where the platform is would either \
                 reach nothing or reach somebody else's"
            ),
            Self::Unknown(what) => write!(
                f,
                "{what:?} is not something this build does. With no argument it \
                 claims, delivers and reports; `check` validates {CONFIG} \
                 against {SECRETS} and prints what would be routed"
            ),
        }
    }
}

/// Reads the file the way a run would, and prints the consequence.
///
/// What a reviewer runs on a pull request and what the tenant's own pipeline
/// runs on every change to the file. It opens no socket and reaches no network,
/// so it is safe anywhere — including a pipeline with no cluster access.
fn check() -> Result<String, Unstartable> {
    configured().map(|config| config.routing_table())
}

/// Claim, deliver, report, repeat.
///
/// No socket and no listener: it pulls, which is most of what "thin" means.
/// There is nothing to shut down gracefully either — a pass is either finished
/// or has not been reported, and an unreported pass comes back when the lease
/// lapses, which is the duplicate bead gc-81d accepted knowingly.
async fn serve() -> Result<(), Unstartable> {
    let where_platform = std::env::var(PLATFORM).map_err(|_| Unstartable::Missing(PLATFORM))?;
    let routing = configured()?;

    let platform = Platform::at(&where_platform, TIMEOUT)
        .map_err(|why| Unstartable::Configuration(why.to_string()))?;
    let rooms = ElementNotices::new(routing.webhooks().clone(), TIMEOUT)
        .map_err(|_| Unstartable::Configuration("no HTTP client could be built".to_owned()))?;

    let subscriptions = routing.subscriptions().to_vec();
    let clock = SystemClock;
    let deliver = Deliver::new(
        &platform,
        &rooms,
        &clock,
        &RandomIds,
        &Resting,
        &subscriptions,
        budget(),
    );

    tracing::info!(
        rooms = routing.webhooks().len(),
        rules = subscriptions.len(),
        "alert-agent started"
    );

    loop {
        match deliver.once().await {
            Ok(done) if !done.quiet() => {
                // ONE LINE PER LOST ROOM, not a count. In this version it is
                // the only way anybody learns a room never got something
                // (bead gc-g9x), so a summary would make a loss a number with
                // nothing to trace back to the push that caused it.
                for (delivery, room, why, spent) in &done.lost {
                    tracing::error!(
                        delivery = %delivery.as_str(),
                        room = %room.as_str(),
                        reason = ?why,
                        attempts = spent,
                        "gave up telling a room"
                    );
                }
                for delivery in &done.unreported {
                    tracing::warn!(
                        delivery = %delivery.as_str(),
                        "delivered but could not be reported, so it will be \
                         offered again and a room will see it twice"
                    );
                }
                for delivery in &done.lapsed {
                    tracing::warn!(
                        delivery = %delivery.as_str(),
                        "the claim lapsed before this was finished; it was not \
                         reported, because it may now be somebody else's"
                    );
                }
                tracing::info!(
                    reached = done.reached.len(),
                    lost = done.lost.len(),
                    routed_to_nothing = done.routed_to_nothing.len(),
                    "delivered what was claimed"
                );
            }
            // Nothing claimed, so nothing to say and nothing to wait for but
            // the next alert.
            Ok(_) => tokio::time::sleep(idle_for()).await,
            Err(why) => {
                // No address and no identity: Unreachable carries neither.
                tracing::error!(%why, "cannot reach the platform");
                tokio::time::sleep(idle_for()).await;
            }
        }
    }
}

/// The tenant's own file, read the way both modes read it.
fn configured() -> Result<TenantConfiguration, Unstartable> {
    let file = PathBuf::from(
        std::env::var(CONFIG).unwrap_or_else(|_| "/etc/alert-agent/routing/config.yaml".to_owned()),
    );
    let secrets = PathBuf::from(
        std::env::var(SECRETS).unwrap_or_else(|_| "/etc/alert-agent/secrets".to_owned()),
    );

    TenantConfiguration::read(&file, &secrets)
        .map_err(|why| Unstartable::Configuration(why.to_string()))
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
    // The platform's binary reads its subcommand the same way.
    let asked = std::env::args().nth(1);

    let outcome = match asked.as_deref() {
        Some("check") => check(),
        // The run mode never returns Ok: it loops until the pod is stopped, so
        // anything it hands back is a reason it could not start at all.
        None => serve().await.map(|()| String::new()),
        Some(other) => Err(Unstartable::Unknown(other.to_owned())),
    };

    match outcome {
        Ok(table) => {
            print!("{table}");
            ExitCode::SUCCESS
        }
        Err(why) => {
            eprintln!("alert-agent cannot start: {why}");
            ExitCode::FAILURE
        }
    }
}
