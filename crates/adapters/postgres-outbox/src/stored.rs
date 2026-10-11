//! An Event, written down and read back.
//!
//! The domain has no dependencies at all — that is enforced by
//! `crates/architecture`, and it is why no type in it can derive `Serialize`.
//! So persisting an Event means mapping it by hand, here, which is the same
//! anti-corruption layer the payload adapters are: they map a sender's wire
//! format inward, and this maps the domain outward.
//!
//! The cost of the boundary is this module. The benefit is that a column layout
//! is a storage decision, changeable without touching a domain type, and that a
//! new Event variant is a compile error here rather than a silently dropped
//! field.

use domain::{
    AlertId, AlertStatus, BranchName, Commit, CommitId, Event, Labels, Permalink, Pusher,
    RepositoryName, Severity, Summary, Timestamp,
};
use serde_json::{Map, Value, json};

/// An Event could not be read back from what was stored.
///
/// Only reachable if a row was written by a different version of this code, or
/// edited by hand. It is an error rather than a silent default because a Notice
/// built from a half-read Event would be worse than one that never arrived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unreadable(pub &'static str);

impl core::fmt::Display for Unreadable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "a stored event is unreadable: {}", self.0)
    }
}

/// Writes an Event down.
pub fn written(event: &Event) -> Value {
    match event {
        Event::PushedCommits {
            repository,
            branch,
            pusher,
            commits,
            permalink,
        } => json!({
            "kind": "pushed_commits",
            "repository": repository.as_str(),
            "branch": branch.as_str(),
            "pusher": pusher.as_str(),
            "commits": commits
                .iter()
                .map(|commit| json!({
                    "id": commit.id().as_str(),
                    "summary": commit.summary().as_str(),
                }))
                .collect::<Vec<_>>(),
            "permalink": permalink.as_ref().map(Permalink::as_str),
        }),
        Event::DeletedBranch {
            repository,
            branch,
            pusher,
        } => json!({
            "kind": "deleted_branch",
            "repository": repository.as_str(),
            "branch": branch.as_str(),
            "pusher": pusher.as_str(),
        }),
        Event::Alert {
            id,
            severity,
            status,
            summary,
            labels,
            started,
            permalink,
        } => json!({
            "kind": "alert",
            "id": id.as_str(),
            // None is Unstated, and that is a real state rather than a missing
            // field: a sender that said nothing about urgency is not the same
            // as one that said "info".
            "severity": severity.as_label(),
            "status": status.as_label(),
            "summary": summary.as_str(),
            "labels": labels
                .iter()
                .map(|(name, value)| (name.as_str().to_owned(), Value::from(value.as_str())))
                .collect::<Map<String, Value>>(),
            "started": started.millis_since_epoch(),
            "permalink": permalink.as_ref().map(Permalink::as_str),
        }),
    }
}

/// Reads an Event back.
///
/// # Errors
///
/// [`Unreadable`] if the stored shape is not one this version writes.
pub fn read(stored: &Value) -> Result<Event, Unreadable> {
    match text(stored, "kind")? {
        "pushed_commits" => Ok(Event::PushedCommits {
            repository: RepositoryName::new(text(stored, "repository")?)
                .map_err(|_| Unreadable("a blank repository"))?,
            branch: BranchName::new(text(stored, "branch")?)
                .map_err(|_| Unreadable("a blank branch"))?,
            pusher: Pusher::new(text(stored, "pusher")?)
                .map_err(|_| Unreadable("a blank pusher"))?,
            commits: commits(stored)?,
            permalink: permalink(stored)?,
        }),
        "deleted_branch" => Ok(Event::DeletedBranch {
            repository: RepositoryName::new(text(stored, "repository")?)
                .map_err(|_| Unreadable("a blank repository"))?,
            branch: BranchName::new(text(stored, "branch")?)
                .map_err(|_| Unreadable("a blank branch"))?,
            pusher: Pusher::new(text(stored, "pusher")?)
                .map_err(|_| Unreadable("a blank pusher"))?,
        }),
        "alert" => Ok(Event::Alert {
            id: AlertId::new(text(stored, "id")?).map_err(|_| Unreadable("a blank alert id"))?,
            // Absent means Unstated, which is what as_label produced for it.
            severity: stored
                .get("severity")
                .and_then(Value::as_str)
                .map_or(Severity::Unstated, Severity::from_label),
            status: AlertStatus::from_label(text(stored, "status")?)
                .ok_or(Unreadable("an unrecognised status"))?,
            summary: Summary::new(text(stored, "summary")?)
                .map_err(|_| Unreadable("a blank summary"))?,
            labels: labels(stored)?,
            started: Timestamp::from_millis_since_epoch(
                stored
                    .get("started")
                    .and_then(Value::as_i64)
                    .ok_or(Unreadable("no started moment"))?,
            ),
            permalink: permalink(stored)?,
        }),
        _ => Err(Unreadable("an unrecognised kind")),
    }
}

fn text<'v>(stored: &'v Value, field: &'static str) -> Result<&'v str, Unreadable> {
    stored
        .get(field)
        .and_then(Value::as_str)
        .ok_or(Unreadable(field))
}

fn permalink(stored: &Value) -> Result<Option<Permalink>, Unreadable> {
    match stored.get("permalink").and_then(Value::as_str) {
        None => Ok(None),
        Some(published) => Permalink::new(published)
            .map(Some)
            .map_err(|_| Unreadable("a blank permalink")),
    }
}

fn commits(stored: &Value) -> Result<Vec<Commit>, Unreadable> {
    stored
        .get("commits")
        .and_then(Value::as_array)
        .ok_or(Unreadable("no commits"))?
        .iter()
        .map(|commit| {
            Ok(Commit::new(
                CommitId::new(text(commit, "id")?).map_err(|_| Unreadable("a blank commit id"))?,
                Summary::new(text(commit, "summary")?)
                    .map_err(|_| Unreadable("a blank commit summary"))?,
            ))
        })
        .collect()
}

fn labels(stored: &Value) -> Result<Labels, Unreadable> {
    let held = stored
        .get("labels")
        .and_then(Value::as_object)
        .ok_or(Unreadable("no labels"))?;

    let pairs: Vec<(&str, &str)> = held
        .iter()
        .map(|(name, value)| value.as_str().map(|value| (name.as_str(), value)))
        .collect::<Option<Vec<_>>>()
        .ok_or(Unreadable("a label that is not text"))?;

    Ok(Labels::from_pairs(pairs))
}

#[cfg(test)]
mod tests {
    use domain::{
        AlertId, AlertStatus, BranchName, Commit, CommitId, Event, Labels, Permalink, Pusher,
        RepositoryName, Severity, Summary, Timestamp,
    };

    use super::{Unreadable, read, written};

    /// Written down and read back must be the same Event. Everything else in
    /// this module is in service of that one property: a Notice built from a
    /// half-read Event is worse than one that never arrived.
    fn survives(event: &Event) {
        assert_eq!(read(&written(event)).as_ref(), Ok(event));
    }

    fn a_push(commits: Vec<Commit>, permalink: Option<&str>) -> Event {
        Event::PushedCommits {
            repository: RepositoryName::new("motrice/webhook-proxy").expect("a name"),
            branch: BranchName::new("main").expect("a name"),
            pusher: Pusher::new("bjornmolin").expect("a name"),
            commits,
            permalink: permalink.map(|p| Permalink::new(p).expect("a reference")),
        }
    }

    fn a_commit(id: &str, summary: &str) -> Commit {
        Commit::new(
            CommitId::new(id).expect("an id"),
            Summary::new(summary).expect("a summary"),
        )
    }

    fn an_alert(severity: Severity, status: AlertStatus, labels: Labels) -> Event {
        Event::Alert {
            id: AlertId::new("7b1a177c").expect("an identity"),
            severity,
            status,
            summary: Summary::new("api latency above target").expect("a summary"),
            labels,
            started: Timestamp::from_millis_since_epoch(1_759_000_000_000),
            permalink: None,
        }
    }

    #[test]
    fn a_push_survives_being_written_down() {
        survives(&a_push(
            vec![a_commit(
                "6113728f27ae",
                "feat: reject overdrawn withdrawals",
            )],
            Some("https://forge.example/compare/a...b"),
        ));
    }

    #[test]
    fn a_push_that_changed_nothing_survives_too() {
        // An empty list is a real state — a force-push to the commit that was
        // already there — and must not come back as a deletion.
        survives(&a_push(vec![], None));
    }

    #[test]
    fn the_order_of_commits_survives() {
        // Oldest first, which the domain promises and a reader relies on.
        let event = a_push(
            vec![
                a_commit("aaaa11112222", "first"),
                a_commit("bbbb33334444", "second"),
                a_commit("cccc55556666", "third"),
            ],
            None,
        );
        survives(&event);

        let Event::PushedCommits { commits, .. } = read(&written(&event)).expect("readable") else {
            panic!("a push came back as something else");
        };
        let summaries: Vec<&str> = commits.iter().map(|c| c.summary().as_str()).collect();
        assert_eq!(summaries, vec!["first", "second", "third"]);
    }

    #[test]
    fn a_deletion_survives_and_stays_a_deletion() {
        // The absence of commits is what distinguishes it. Coming back as a push
        // with none would tell a room the wrong thing in the same words.
        survives(&Event::DeletedBranch {
            repository: RepositoryName::new("motrice/webhook-proxy").expect("a name"),
            branch: BranchName::new("old-work").expect("a name"),
            pusher: Pusher::new("bjornmolin").expect("a name"),
        });
    }

    #[test]
    fn every_severity_survives_including_the_ones_with_no_number() {
        for severity in [
            Severity::Critical,
            Severity::Warning,
            Severity::Info,
            Severity::Unstated,
            Severity::Unrecognised("page-the-duty-officer".to_owned()),
        ] {
            survives(&an_alert(severity, AlertStatus::Firing, Labels::none()));
        }
    }

    #[test]
    fn a_severity_nobody_stated_does_not_come_back_as_one_somebody_did() {
        // Unstated writes null, and null must read back as Unstated rather than
        // as a default. A sender that said nothing about urgency is not the same
        // as one that said "info", and a responder reads that word to decide
        // whether to get up.
        let stored = written(&an_alert(
            Severity::Unstated,
            AlertStatus::Firing,
            Labels::none(),
        ));

        assert!(stored["severity"].is_null(), "{stored}");
        let Event::Alert { severity, .. } = read(&stored).expect("readable") else {
            panic!("an alert came back as something else");
        };
        assert_eq!(severity, Severity::Unstated);
    }

    #[test]
    fn both_statuses_survive() {
        for status in [AlertStatus::Firing, AlertStatus::Resolved] {
            survives(&an_alert(Severity::Critical, status, Labels::none()));
        }
    }

    #[test]
    fn labels_survive_with_their_values() {
        survives(&an_alert(
            Severity::Critical,
            AlertStatus::Firing,
            Labels::from_pairs([
                ("namespace", "prod"),
                ("service", "api"),
                ("alertname", "HighLatency"),
            ]),
        ));
    }

    #[test]
    fn a_label_value_that_looks_like_markup_or_json_survives_as_itself() {
        // Label values are written by whoever can deploy a workload. Storing
        // them as JSON must not give them a second chance to mean something.
        survives(&an_alert(
            Severity::Warning,
            AlertStatus::Firing,
            Labels::from_pairs([
                ("markup", "<b>x</b> [a](http://evil.example)"),
                ("quoted", r#"{"not":"a field"}"#),
                ("awkward", "a \"quote\" and a \\ backslash"),
            ]),
        ));
    }

    #[test]
    fn a_row_written_by_something_else_is_refused_rather_than_guessed() {
        // Only reachable from a row written by another version or edited by
        // hand. Refused, because an Event assembled from half a row would reach
        // a room looking exactly like one that was real.
        assert_eq!(
            read(&serde_json::json!({"kind": "something_new"})),
            Err(Unreadable("an unrecognised kind"))
        );
        assert_eq!(
            read(&serde_json::json!({"kind": "pushed_commits", "repository": "r"})),
            Err(Unreadable("branch"))
        );
        assert!(
            read(&serde_json::json!({
                "kind": "alert", "id": "a", "status": "sideways",
                "summary": "s", "labels": {}, "started": 1
            }))
            .is_err()
        );
    }
}
