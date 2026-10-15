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
//! NOTHING HERE DELIVERS YET. This binary reads its configuration and says what
//! it would route; claiming, delivering and reporting arrive in bead gc-72e.2,
//! and the cutover that stops the platform delivering is gc-72e.3. It refuses
//! to do anything else rather than offering a command that looks like it serves
//! — an agent that appeared to run while delivering nothing is the worst of the
//! available half-states, because the platform is still delivering and
//! everything would look fine.

use std::path::PathBuf;
use std::process::ExitCode;

use yaml_config::TenantConfiguration;

/// Where the agent reads its rules and its rooms from.
///
/// The same two variables the platform uses for the same two things, spelled
/// for this binary: an operator who has deployed one should not have to learn a
/// second vocabulary, and a shared spelling would mean one `ConfigMap` could be
/// mounted into the wrong deployment and read.
const CONFIG: &str = "ALERT_AGENT_CONFIG";
const SECRETS: &str = "ALERT_AGENT_SECRETS_DIR";

/// What the agent was asked for, and could not do.
enum Unstartable {
    /// The configuration cannot be used. Carries the file and the field.
    Configuration(String),
    /// Something other than `check` was asked for.
    Unknown(String),
}

impl std::fmt::Display for Unstartable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Configuration(why) => write!(f, "{why}"),
            Self::Unknown(what) => write!(
                f,
                "{what:?} is not something this build does. It reads `check`, \
                 which validates {CONFIG} against {SECRETS} and prints what \
                 would be routed. Delivering arrives in bead gc-72e.2"
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
    let file = PathBuf::from(
        std::env::var(CONFIG).unwrap_or_else(|_| "/etc/alert-agent/routing/config.yaml".to_owned()),
    );
    let secrets = PathBuf::from(
        std::env::var(SECRETS).unwrap_or_else(|_| "/etc/alert-agent/secrets".to_owned()),
    );

    TenantConfiguration::read(&file, &secrets)
        .map(|config| config.routing_table())
        .map_err(|why| Unstartable::Configuration(why.to_string()))
}

fn main() -> ExitCode {
    // One argument, and only one, so there is no argument parser to go wrong.
    // The platform's binary reads its subcommand the same way.
    let asked = std::env::args().nth(1);

    let outcome = match asked.as_deref() {
        Some("check") => check(),
        Some(other) => Err(Unstartable::Unknown(other.to_owned())),
        None => Err(Unstartable::Unknown(String::new())),
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
