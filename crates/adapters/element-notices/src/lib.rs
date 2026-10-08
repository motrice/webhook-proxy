//! Notices for an Element room, delivered through a hookshot generic webhook.
//!
//! Two things about this destination shape everything here.
//!
//! It has no authentication: possession of the webhook URL is the only
//! credential it has. So the URL is configuration, held in this crate and
//! nowhere else, and is kept out of `Debug` by hand — see README under "The
//! security boundary".
//!
//! Its audience is people. Every field of an Event is written by whoever can
//! push, not by the sender whose signature we checked, so a Notice is an
//! injection target.
//!
//! This used to defend by sending no markup at all, on the reasoning that a
//! plain-text Notice has nothing to escape. That defence was conditional and the
//! condition turned out to be false: hookshot renders markdown in the `text`
//! field — proved on the live instance, bead gc-fks — so a commit message
//! reading `[Payroll portal has moved](http://attacker.example)` became a
//! clickable link with wording of its attacker's choosing, in a room that trusts
//! the forge. We sent no markup and markup appeared anyway, because the
//! destination made it.
//!
//! Escaping markdown instead cannot work: no escape stops a bare URL
//! autolinking, and one of the URLs is our own permalink, which should be a
//! link. So a Notice is now sent twice — `text` as before, for a client that
//! falls back to it, and `html` which hookshot uses verbatim. In HTML we say
//! what is a link, under one rule:
//!
//! **a link may appear only when its visible text is exactly its destination.**
//!
//! A link that says one thing and goes to another is the whole attack; a link
//! whose text is where it goes cannot lie, so a reader can judge it before
//! clicking. Our permalink qualifies. Nothing a sender wrote ever does.

use std::collections::HashMap;
use std::fmt;
use std::fmt::Write as _;
use std::time::Duration;

use application::ports::{DispatchFailed, Dispatcher};
use domain::{AlertStatus, Commit, DeliveryId, Destination, Event, Labels, Permalink, Severity};

/// How much of a summary a reader sees before it is cut.
///
/// A summary comes from an annotation, and an annotation is as long as whoever
/// wrote it liked. One alert must not be able to fill a room.
const SUMMARY_LIMIT: usize = 200;

/// How much of a label name or value a reader sees before it is cut.
const LABEL_LIMIT: usize = 60;

/// How many labels a reader sees before the rest are counted instead.
const LABELS_SHOWN: usize = 8;

/// How much of a commit identity a reader sees.
///
/// Shortening is a presentation choice made here. The domain keeps an identity
/// whole, and has a test saying so.
const SHORT_ID: usize = 8;

/// Posts Notices to hookshot webhooks, one per Destination.
pub struct ElementNotices {
    client: reqwest::Client,
    /// Destination identity to webhook URL. The URL never leaves this map.
    endpoints: HashMap<String, String>,
}

/// The HTTP client could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientUnavailable;

impl ElementNotices {
    /// Holds the webhook URL for each Destination, and a bounded timeout.
    ///
    /// # Errors
    ///
    /// [`ClientUnavailable`] if the HTTP client cannot be constructed.
    pub fn new(
        endpoints: HashMap<String, String>,
        timeout: Duration,
    ) -> Result<Self, ClientUnavailable> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|_| ClientUnavailable)?;

        Ok(Self { client, endpoints })
    }
}

/// Prints nothing that could be a credential.
///
/// Written by hand rather than derived, because a derived `Debug` on this type
/// would print every room's webhook URL into whatever log line touched it.
impl fmt::Debug for ElementNotices {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ElementNotices({} destinations configured)",
            self.endpoints.len()
        )
    }
}

/// An Event as prose for people to read, in plain text.
///
/// The fallback body. A client that cannot render the HTML shows this, so it has
/// to say the same thing — which is why both renderings come from one
/// [`Composed`] rather than from two renderers written side by side.
#[must_use]
pub fn notice(event: &Event) -> String {
    composed(event).as_text()
}

/// The same Event as HTML, which is what a reader actually sees.
///
/// Every borrowed string is escaped and nothing a sender wrote can become
/// markup. The only element produced is an anchor for the permalink, and only
/// when its visible text is exactly its destination.
#[must_use]
pub fn notice_html(event: &Event) -> String {
    composed(event).as_html()
}

/// A Notice's structure, before it is either kind of text.
fn composed(event: &Event) -> Composed {
    match event {
        Event::DeletedBranch {
            repository,
            branch,
            pusher,
        } => Composed::said(format!(
            "{} deleted branch {} in {}",
            pusher.as_str(),
            branch.as_str(),
            repository.as_str()
        )),
        Event::Alert {
            severity,
            status,
            summary,
            labels,
            permalink,
            ..
        } => alerted(
            severity,
            *status,
            summary.as_str(),
            labels,
            permalink.as_ref(),
        ),
        Event::PushedCommits {
            repository,
            branch,
            pusher,
            commits,
            permalink,
        } => pushed(
            repository.as_str(),
            branch.as_str(),
            pusher.as_str(),
            commits,
            permalink.as_ref(),
        ),
    }
}

/// An alert, for somebody who has to decide whether to get out of bed.
///
/// Status first, because whether it is still happening is the thing read first
/// and the thing most costly to misread. Then the severity, then the one line the
/// sender wrote, then the labels a responder needs to know where to look, then
/// where to look.
///
/// Every part of it except the status and the severity word is written by whoever
/// can deploy a workload, which is a wider set of people than whoever can push to
/// a repository. So: line breaks in a value are neutralised so a value cannot
/// forge a line, every borrowed string is bounded so one alert cannot fill a
/// room, and nothing written here is markup — the HTML rendering escapes what it
/// is given, so a value cannot become one either.
fn alerted(
    severity: &Severity,
    status: AlertStatus,
    summary: &str,
    labels: &Labels,
    permalink: Option<&Permalink>,
) -> Composed {
    let header = match severity.as_label() {
        // A severity the sender did not state has nothing to print, so the line
        // does not claim one rather than inventing a default.
        None => format!(
            "{} — {}",
            status.as_label(),
            bounded(summary, SUMMARY_LIMIT)
        ),
        Some(stated) => format!(
            "{} — {}: {}",
            status.as_label(),
            bounded(stated, LABEL_LIMIT),
            bounded(summary, SUMMARY_LIMIT)
        ),
    };

    let mut composed = Composed::said(header);

    let shown = label_line(labels);
    if !shown.is_empty() {
        composed.hanging(shown);
    }
    composed.pointing_at(permalink);
    composed
}

/// The labels, on one line, in the order the domain keeps them.
///
/// Severity and status are left out because the header already states them, and
/// repeating them would push something a responder has not seen off the end.
fn label_line(labels: &Labels) -> String {
    let mut shown = Vec::new();
    let mut omitted = 0usize;

    for (name, value) in labels.iter() {
        if matches!(name.as_str(), "severity" | "status") {
            continue;
        }
        if shown.len() == LABELS_SHOWN {
            omitted += 1;
            continue;
        }
        shown.push(format!(
            "{}={}",
            flatten(name.as_str(), LABEL_LIMIT),
            flatten(value.as_str(), LABEL_LIMIT)
        ));
    }

    let mut line = shown.join(" ");
    // Said, never silently dropped: a responder who cannot see a label should at
    // least know one exists.
    if omitted > 0 {
        if !line.is_empty() {
            line.push(' ');
        }
        write!(line, "(+{omitted} more)").expect("writing to a String cannot fail");
    }
    line
}

/// Text a sender wrote, made safe to put on a line of its own.
///
/// A newline in a label value is the dangerous one: without this, a workload
/// could annotate itself so that a room shows what looks like a separate message,
/// including one that appears to come from the push path. The characters are kept
/// — nothing is dropped — but as their escapes, so they are visible as text and
/// cannot break the line.
fn flatten(value: &str, limit: usize) -> String {
    let escaped: String = value
        .chars()
        .map(|c| match c {
            '\n' => "\\n".to_owned(),
            '\r' => "\\r".to_owned(),
            '\t' => "\\t".to_owned(),
            other if other.is_control() => char::REPLACEMENT_CHARACTER.to_string(),
            other => other.to_string(),
        })
        .collect();

    bounded(&escaped, limit)
}

/// At most `limit` characters, with a mark when there was more.
///
/// Counted in characters rather than bytes, so the cut never lands inside one.
/// Bounded because a summary comes from an annotation and an annotation can be
/// as long as whoever wrote it liked; one alert must not be able to fill a room.
fn bounded(value: &str, limit: usize) -> String {
    let mut out: String = value.chars().take(limit).collect();
    if value.chars().nth(limit).is_some() {
        out.push('…');
    }
    out
}

/// A push, with however many commits it carried.
///
/// An empty list is a push that changed nothing — a force-push to the commit
/// that was already there, most often. It is stated plainly and without
/// mentioning deletion, because a deletion is now its own Event and saying
/// "possibly a deletion" here would be hedging about something already known.
fn pushed(
    repository: &str,
    branch: &str,
    pusher: &str,
    commits: &[Commit],
    permalink: Option<&Permalink>,
) -> Composed {
    let mut composed = if commits.is_empty() {
        Composed::said(format!(
            "{pusher} pushed no commits to {branch} in {repository}"
        ))
    } else {
        let count = commits.len();
        let plural = if count == 1 { "commit" } else { "commits" };
        let mut listed = Composed::said(format!(
            "{pusher} pushed {count} {plural} to {branch} in {repository}"
        ));
        for commit in commits {
            let id = commit.id().as_str();
            let short = id.get(..SHORT_ID).unwrap_or(id);
            listed.hanging(format!("{short} {}", commit.summary().as_str()));
        }
        listed
    };

    // Last, on its own line and unindented: a reader sees what happened first
    // and where to look second, and the line is not mistaken for another commit.
    composed.pointing_at(permalink);
    composed
}

/// A Notice's structure, before it is text of either kind.
///
/// It exists so there is one source of structure and two renderings of it. Two
/// renderers maintained side by side drift, and the one that drifts is the one
/// nobody reads — which here would be the plain-text fallback, seen by exactly
/// the clients least able to cope with a surprise.
struct Composed {
    lines: Vec<Line>,
    /// Where to look. Rendered last and apart, never inline.
    link: Option<String>,
}

/// One line of a Notice, and whether it hangs under the line above it.
enum Line {
    /// Flush left. What happened.
    Said(String),
    /// Indented. A detail of the line above — a commit, or an alert's labels.
    Hanging(String),
}

impl Composed {
    /// Begins a Notice with the line that says what happened.
    fn said(line: String) -> Self {
        Self {
            lines: vec![Line::Said(line)],
            link: None,
        }
    }

    /// Adds a detail under what has been said so far.
    fn hanging(&mut self, line: String) {
        self.lines.push(Line::Hanging(line));
    }

    /// Records where to look, if the Origin published somewhere.
    fn pointing_at(&mut self, permalink: Option<&Permalink>) {
        self.link = permalink.map(|link| link.as_str().to_owned());
    }

    /// The plain-text rendering: the fallback body.
    fn as_text(&self) -> String {
        let mut out = String::new();
        for line in &self.lines {
            if !out.is_empty() {
                out.push('\n');
            }
            match line {
                Line::Said(text) => out.push_str(text),
                Line::Hanging(text) => {
                    out.push_str("  ");
                    out.push_str(text);
                }
            }
        }
        if let Some(link) = &self.link {
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(link);
        }
        out
    }

    /// The HTML rendering: what a reader actually sees.
    ///
    /// A newline is only whitespace in HTML, so the structure is carried by
    /// `<br>`; the indent is non-breaking, because ordinary spaces collapse and
    /// the indent is what distinguishes a commit from the line above it.
    fn as_html(&self) -> String {
        let mut out = String::new();
        for line in &self.lines {
            if !out.is_empty() {
                out.push_str("<br>");
            }
            match line {
                Line::Said(text) => out.push_str(&escaped(text)),
                Line::Hanging(text) => {
                    out.push_str("&nbsp;&nbsp;");
                    out.push_str(&escaped(text));
                }
            }
        }
        if let Some(link) = &self.link {
            if !out.is_empty() {
                out.push_str("<br>");
            }
            out.push_str(&linked(link));
        }
        out
    }
}

/// Text that cannot become markup.
///
/// The apostrophe is escaped as well as the four that strictly must be. It is
/// never wrong, and it means this function does not depend on the caller knowing
/// whether what it produces will land in an attribute or between tags.
fn escaped(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

/// A permalink, as a link when that is safe and as characters when it is not.
///
/// The visible text is the destination, always. That is the whole rule: a link
/// that says one thing and goes to another is the attack this defends against,
/// and one whose text is where it goes cannot lie about it.
fn linked(permalink: &str) -> String {
    if !publishable(permalink) {
        return escaped(permalink);
    }
    let shown = escaped(permalink);
    format!("<a href=\"{shown}\">{shown}</a>")
}

/// Whether a permalink is one we are willing to make clickable.
///
/// `Permalink::new` checks only that it is not blank, and the value comes from
/// the payload — so it is written by whoever can push and need not be a URL at
/// all. `javascript:` and `data:` are the obvious ones; whitespace is refused
/// too, because a value that is not a single token is not a thing a reader can
/// check by looking at it.
fn publishable(permalink: &str) -> bool {
    let lowered = permalink.to_ascii_lowercase();
    (lowered.starts_with("http://") || lowered.starts_with("https://"))
        && !permalink
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
}

/// Which kind of failure a transport error is, in the Destination's terms.
///
/// Nothing from the HTTP client escapes this function: a `reqwest::Error`
/// reaching the use case would mean this adapter had leaked.
fn classify(error: &reqwest::Error) -> DispatchFailed {
    if error.is_timeout() {
        DispatchFailed::TimedOut
    } else {
        DispatchFailed::Unreachable
    }
}

#[async_trait::async_trait]
impl Dispatcher for ElementNotices {
    async fn dispatch(
        &self,
        _delivery: &DeliveryId,
        event: &Event,
        destination: &Destination,
    ) -> Result<(), DispatchFailed> {
        // A Destination we hold no URL for cannot be reached. This is a
        // configuration gap rather than a refusal, and it is reported as a loss
        // like any other: the caller counts and logs it.
        let Some(endpoint) = self.endpoints.get(destination.id().as_str()) else {
            return Err(DispatchFailed::Unreachable);
        };

        let response = self
            .client
            .post(endpoint)
            // Both. `html` is what a reader sees; `text` is the body a client
            // falling back shows, and is also what stops hookshot applying
            // markdown of its own — which is how an Event field became a live
            // link in the room (gc-qev).
            .json(&serde_json::json!({
                "text": notice(event),
                "html": notice_html(event),
            }))
            .send()
            .await
            .map_err(|error| classify(&error))?;

        let status = response.status();
        if status.is_client_error() {
            return Err(DispatchFailed::Rejected);
        }
        if !status.is_success() {
            return Err(DispatchFailed::Unreachable);
        }

        // hookshot answers a success with {"ok":true}. An `ok` of false is a
        // refusal even under a 2xx. Anything else — a body we cannot read, or
        // one without the field — is taken as success rather than invented into
        // a failure: the status is the contract, and this is a courtesy check.
        let body = response.text().await.map_err(|error| classify(&error))?;
        let refused = serde_json::from_str::<serde_json::Value>(&body)
            .is_ok_and(|json| json.get("ok").and_then(serde_json::Value::as_bool) == Some(false));

        if refused {
            return Err(DispatchFailed::Rejected);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use application::ports::{DispatchFailed, Dispatcher};
    use axum::Router;
    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::post;
    use domain::{
        AlertId, AlertStatus, BranchName, Commit, CommitId, DeliveryId, Destination, DestinationId,
        DestinationKind, Event, LabelName, LabelValue, Labels, Permalink, Pusher, RepositoryName,
        Severity, Summary, Timestamp,
    };

    use super::{ElementNotices, LABEL_LIMIT, LABELS_SHOWN, SUMMARY_LIMIT, notice, notice_html};

    /// Stands in for the room's bearer credential.
    const HOOK_ID: &str = "SUPERSECRETHOOKID";

    fn push(repository: &str, branch: &str, pusher: &str, commits: &[(&str, &str)]) -> Event {
        linked_push(repository, branch, pusher, commits, None)
    }

    fn linked_push(
        repository: &str,
        branch: &str,
        pusher: &str,
        commits: &[(&str, &str)],
        permalink: Option<&str>,
    ) -> Event {
        Event::PushedCommits {
            repository: RepositoryName::new(repository).expect("a name"),
            branch: BranchName::new(branch).expect("a name"),
            pusher: Pusher::new(pusher).expect("a name"),
            commits: commits
                .iter()
                .map(|(id, summary)| {
                    Commit::new(
                        CommitId::new(id).expect("an id"),
                        Summary::new(summary).expect("a summary"),
                    )
                })
                .collect(),
            permalink: permalink.map(|p| Permalink::new(p).expect("a reference")),
        }
    }

    fn deletion(repository: &str, branch: &str, pusher: &str) -> Event {
        Event::DeletedBranch {
            repository: RepositoryName::new(repository).expect("a name"),
            branch: BranchName::new(branch).expect("a name"),
            pusher: Pusher::new(pusher).expect("a name"),
        }
    }

    fn a_push() -> Event {
        push(
            "motrice/webhook-proxy",
            "main",
            "bjornmolin",
            &[
                (
                    "aa11bb22cc33dd44",
                    "feat(domain): reject overdrawn withdrawals",
                ),
                ("6113728f27ae82c7", "docs: tidy the glossary"),
            ],
        )
    }

    fn room(id: &str) -> Destination {
        Destination::new(
            DestinationId::new(id).expect("a non-blank id"),
            DestinationKind::ChatRoom,
        )
    }

    fn a_delivery() -> DeliveryId {
        DeliveryId::new("d-1").expect("a non-blank identity")
    }

    // ---- rendering: pure, no HTTP ----------------------------------------

    #[test]
    fn a_notice_says_who_pushed_what_and_where() {
        let text = notice(&a_push());

        assert!(text.contains("bjornmolin"), "{text}");
        assert!(text.contains("main"), "{text}");
        assert!(text.contains("motrice/webhook-proxy"), "{text}");
        assert!(text.contains("2 commits"), "{text}");
        assert!(text.contains("docs: tidy the glossary"), "{text}");
    }

    #[test]
    fn one_commit_reads_as_one_commit() {
        let text = notice(&push(
            "motrice/webhook-proxy",
            "main",
            "bjornmolin",
            &[("aa11bb22cc33dd44", "fix the thing")],
        ));

        assert!(text.contains("1 commit "), "{text}");
        assert!(!text.contains("1 commits"), "{text}");
    }

    #[test]
    fn a_commit_identity_is_shortened_for_a_reader() {
        let text = notice(&a_push());

        assert!(text.contains("aa11bb22"), "{text}");
        assert!(!text.contains("aa11bb22cc33dd44"), "{text}");
    }

    #[test]
    fn a_commit_message_containing_markup_appears_literally() {
        // Commit messages are written by whoever can push, which is a far wider
        // set than whoever holds the webhook URL. See gc-o61.
        let text = notice(&push(
            "motrice/webhook-proxy",
            "main",
            "bjornmolin",
            &[("aa11bb22cc33dd44", "<b>urgent</b> see [here](http://evil)")],
        ));

        assert!(
            text.contains("<b>urgent</b> see [here](http://evil)"),
            "{text}"
        );
    }

    #[test]
    fn a_branch_or_repository_containing_markup_appears_literally() {
        let text = notice(&push(
            "motrice/<img src=x>",
            "feature/<script>alert(1)</script>",
            "<i>nobody</i>",
            &[],
        ));

        assert!(text.contains("motrice/<img src=x>"), "{text}");
        assert!(text.contains("feature/<script>alert(1)</script>"), "{text}");
        assert!(text.contains("<i>nobody</i>"), "{text}");
    }

    // Three situations, three true sentences. These three tests are the reason
    // the Event gained a variant: before it did, one of the three had to be
    // rendered as a guess or as a hedge.

    #[test]
    fn a_notice_ends_with_the_link_when_one_was_published() {
        let text = notice(&linked_push(
            "motrice/webhook-proxy",
            "main",
            "bjornmolin",
            &[("aa11bb22cc33dd44", "fix the thing")],
            Some("https://forge.example/motrice/webhook-proxy/compare/a...b"),
        ));

        // On its own line and unindented, so it is not read as another commit.
        assert!(
            text.ends_with("\nhttps://forge.example/motrice/webhook-proxy/compare/a...b"),
            "{text}"
        );
    }

    #[test]
    fn a_notice_without_a_link_does_not_look_unfinished() {
        let text = notice(&a_push());

        assert!(!text.ends_with('\n'), "{text}");
        assert!(!text.contains("://"), "{text}");
        // The last line is still a commit, so nothing dangles where a link would
        // have been.
        assert!(
            text.lines().last().expect("a line").starts_with("  "),
            "{text}"
        );
    }

    #[test]
    fn a_push_that_changed_nothing_still_carries_its_link() {
        let text = notice(&linked_push(
            "motrice/webhook-proxy",
            "main",
            "bjornmolin",
            &[],
            Some("https://forge.example/c/1"),
        ));

        assert!(text.contains("no commits"), "{text}");
        assert!(text.ends_with("\nhttps://forge.example/c/1"), "{text}");
    }

    #[test]
    fn a_link_appears_literally_and_is_not_made_into_markup() {
        // About the plain-text rendering, and it was never enough on its own.
        // This and the other "appears literally" tests assert what this adapter
        // SENDS, which was always true and stayed true while a commit message
        // became a live link in the room — because the destination rendered
        // markdown in what we sent. A test here cannot see that; the live
        // instance was the only oracle, and gc-fks was the one that asked it.
        // What covers the gap now is the HTML rendering and its own tests.
        let text = notice(&linked_push(
            "motrice/webhook-proxy",
            "main",
            "bjornmolin",
            &[],
            Some("https://forge.example/x?a=1&b=<2>"),
        ));

        assert!(text.contains("https://forge.example/x?a=1&b=<2>"), "{text}");
        assert!(!text.contains("]("), "{text}");
    }

    /// How many lines the rendering is *meant* to have: the header, one per
    /// label line, and the link if any. Used to prove a label value did not
    /// create one.
    fn expected_line_count(text: &str) -> usize {
        text.lines().filter(|l| !l.is_empty()).count()
    }

    fn alert_with(
        severity: Severity,
        status: AlertStatus,
        summary: &str,
        labels: &[(&str, &str)],
        permalink: Option<&str>,
    ) -> Event {
        Event::Alert {
            id: AlertId::new("7b1a177c").expect("an identity"),
            severity,
            status,
            summary: Summary::new(summary).expect("a summary"),
            labels: labels.iter().fold(Labels::none(), |set, (name, value)| {
                set.with(
                    LabelName::new(name).expect("a non-blank name"),
                    LabelValue::new(value).expect("a non-blank value"),
                )
            }),
            started: Timestamp::from_millis_since_epoch(1_759_000_000_000),
            permalink: permalink.map(|p| Permalink::new(p).expect("a reference")),
        }
    }

    fn an_alert(severity: Severity, status: AlertStatus, summary: &str) -> Event {
        Event::Alert {
            id: AlertId::new("7b1a177c").expect("an identity"),
            severity,
            status,
            summary: Summary::new(summary).expect("a summary"),
            labels: Labels::none(),
            started: Timestamp::from_millis_since_epoch(1_759_000_000_000),
            permalink: None,
        }
    }

    #[test]
    fn a_firing_critical_alert_reads_exactly_like_this() {
        // The whole text, pinned. Status first because whether it is still
        // happening is read first and is the most costly thing to misread; then
        // the severity; then the sender's line; then where to look.
        let text = notice(&alert_with(
            Severity::Critical,
            AlertStatus::Firing,
            "api latency above target",
            &[
                ("alertname", "HighLatency"),
                ("namespace", "prod"),
                ("service", "api"),
                // Already in the header, so it must not be repeated below.
                ("severity", "critical"),
            ],
            Some("https://prometheus.example/graph?g0.expr=latency"),
        ));

        assert_eq!(
            text,
            "firing — critical: api latency above target\n  \
             alertname=HighLatency namespace=prod service=api\n\
             https://prometheus.example/graph?g0.expr=latency"
        );
    }

    #[test]
    fn a_resolved_alert_cannot_be_mistaken_for_a_new_firing_one() {
        let resolved = notice(&alert_with(
            Severity::Critical,
            AlertStatus::Resolved,
            "api latency above target",
            &[("namespace", "prod")],
            None,
        ));

        // The first word of the first line, so the eye reaches it before anything
        // a sender wrote.
        assert!(resolved.starts_with("resolved — "), "{resolved}");
        assert!(!resolved.contains("firing"), "{resolved}");

        let firing = notice(&alert_with(
            Severity::Critical,
            AlertStatus::Firing,
            "api latency above target",
            &[("namespace", "prod")],
            None,
        ));
        assert_ne!(resolved, firing);
    }

    #[test]
    fn the_link_is_the_last_line_when_there_is_one_and_absent_when_there_is_not() {
        let with = notice(&alert_with(
            Severity::Warning,
            AlertStatus::Firing,
            "disk filling",
            &[("namespace", "prod")],
            Some("https://forge.example/a"),
        ));
        assert!(with.ends_with("\nhttps://forge.example/a"), "{with}");

        let without = notice(&alert_with(
            Severity::Warning,
            AlertStatus::Firing,
            "disk filling",
            &[("namespace", "prod")],
            None,
        ));
        // Nothing stands in its place: no empty line, no placeholder.
        assert!(!without.contains("://"), "{without}");
        assert!(!without.ends_with('\n'), "{without}");
        assert_eq!(without.lines().count(), 2, "{without}");
    }

    #[test]
    fn a_summary_longer_than_two_hundred_characters_is_cut_and_marked() {
        // The bound is SUMMARY_LIMIT, 200 characters. Named here so a change to
        // it has to change this test too, which is the point of naming it.
        let long = "x".repeat(SUMMARY_LIMIT + 50);
        let text = notice(&alert_with(
            Severity::Info,
            AlertStatus::Firing,
            &long,
            &[],
            None,
        ));

        let first = text.lines().next().expect("a line");
        assert!(first.contains(&"x".repeat(SUMMARY_LIMIT)), "{first}");
        assert!(!first.contains(&"x".repeat(SUMMARY_LIMIT + 1)), "{first}");
        // Cut, and visibly so: a reader must not think they have the whole line.
        assert!(first.ends_with('…'), "{first}");
    }

    #[test]
    fn a_long_label_value_is_cut_without_splitting_a_character() {
        // Counted in characters, not bytes, so the cut never lands inside one.
        // A multi-byte value is the case that would panic if it did.
        let long = "ä".repeat(LABEL_LIMIT + 10);
        let text = notice(&alert_with(
            Severity::Info,
            AlertStatus::Firing,
            "fine",
            &[("note", &long)],
            None,
        ));

        assert!(
            text.contains(&format!("note={}…", "ä".repeat(LABEL_LIMIT))),
            "{text}"
        );
    }

    #[test]
    fn labels_beyond_the_shown_count_are_counted_rather_than_hidden() {
        let many: Vec<(String, String)> = (0..LABELS_SHOWN + 3)
            .map(|n| (format!("label{n:02}"), format!("value{n}")))
            .collect();
        let refs: Vec<(&str, &str)> = many.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect();

        let text = notice(&alert_with(
            Severity::Info,
            AlertStatus::Firing,
            "fine",
            &refs,
            None,
        ));

        // A responder who cannot see a label should at least know one exists.
        assert!(text.contains("(+3 more)"), "{text}");
    }

    #[tokio::test]
    async fn no_webhook_url_reaches_the_room_or_a_log_line() {
        // Structural rather than careful: `notice` is handed an Event and nothing
        // else, so it has no URL to leak. This pins the observable half, and the
        // Debug impl, which is the one place a URL could escape by accident.
        let (url, seen) = hookshot(StatusCode::OK, r#"{"ok":true}"#, Duration::ZERO).await;
        let notices = notices_to(&url, Duration::from_secs(5));

        let event = alert_with(
            Severity::Critical,
            AlertStatus::Firing,
            "something is wrong",
            &[("namespace", "prod")],
            None,
        );
        notices
            .dispatch(&a_delivery(), &event, &room("room"))
            .await
            .expect("the stub accepts");

        let sent = seen.lock().expect("the stub is not poisoned").clone();
        let body = &sent.first().expect("one request").1;
        assert!(
            !body.contains(HOOK_ID),
            "the hook id reached the room: {body}"
        );

        let printed = format!("{notices:?}");
        assert!(!printed.contains(HOOK_ID), "{printed}");
        assert!(!printed.contains("://"), "{printed}");
    }

    // ---- the injection test, written first --------------------------------
    //
    // Everything else about this rendering is taste. This is the security
    // boundary: an alert's text comes from a workload annotation, so from whoever
    // can deploy to the cluster — a wider set of people than whoever can push to
    // a repository.

    #[test]
    fn a_label_value_cannot_forge_a_line_or_smuggle_markup() {
        // A newline in a label value is the dangerous one. Without neutralising
        // it, a workload could annotate itself so that the room shows what looks
        // like a second, separate message — including one that appears to come
        // from the push path.
        let forged = "prod\nbjornmolin pushed 3 commits to main in motrice/webhook-proxy";
        let text = notice(&alert_with(
            Severity::Critical,
            AlertStatus::Firing,
            "something is wrong",
            &[
                ("namespace", forged),
                ("markup", "<b>x</b> [a](http://evil)"),
            ],
            None,
        ));

        // The forged text is present — nothing is dropped — but it cannot have
        // produced a line of its own.
        assert!(text.contains("bjornmolin pushed 3 commits"), "{text}");
        for line in text.lines() {
            assert!(
                !line.starts_with("bjornmolin pushed"),
                "a label value started a line of its own:\n{text}"
            );
        }

        // Markup is literal, as everywhere else here: this renderer emits none,
        // so there is nothing to escape and nothing to get wrong.
        assert!(text.contains("<b>x</b>"), "{text}");
        assert!(text.contains("[a](http://evil)"), "{text}");
    }

    #[test]
    fn a_carriage_return_cannot_forge_a_line_either() {
        // A lone carriage return is a line break to some clients and not to
        // others, which is worse than either: the room and the test would
        // disagree about what was sent.
        let text = notice(&alert_with(
            Severity::Critical,
            AlertStatus::Firing,
            "something is wrong",
            &[("note", "before\rafter")],
            None,
        ));

        assert_eq!(text.lines().count(), expected_line_count(&text), "{text}");
        assert!(
            !text.contains('\r'),
            "a raw carriage return reached the room"
        );
    }

    // These predate the full rendering and are kept rather than folded into it.
    // They say what must be true of *any* rendering — the severity, the summary
    // and whether it is over are all present, nothing is invented when the
    // severity is unstated — where the pinned-text test above says what is true
    // of this one. A change of layout should break that test and leave these
    // alone; if it breaks these, something a reader needs went missing.

    #[test]
    fn an_alert_notice_says_the_severity_the_summary_and_whether_it_is_over() {
        let text = notice(&an_alert(
            Severity::Critical,
            AlertStatus::Firing,
            "api latency above target",
        ));

        assert!(text.contains("critical"), "{text}");
        assert!(text.contains("api latency above target"), "{text}");
        assert!(text.contains("firing"), "{text}");
    }

    #[test]
    fn a_resolved_alert_says_resolved_and_not_firing() {
        let text = notice(&an_alert(
            Severity::Warning,
            AlertStatus::Resolved,
            "disk filling",
        ));

        assert!(text.contains("resolved"), "{text}");
        assert!(!text.contains("firing"), "{text}");
    }

    #[test]
    fn an_alert_with_no_stated_severity_does_not_invent_one() {
        let text = notice(&an_alert(
            Severity::Unstated,
            AlertStatus::Firing,
            "something",
        ));

        assert!(text.contains("something"), "{text}");
        assert!(text.contains("firing"), "{text}");
        for invented in ["critical", "warning", "info", "unknown", "unstated"] {
            assert!(!text.contains(invented), "invented {invented}: {text}");
        }
    }

    #[test]
    fn an_alert_summary_containing_markup_appears_literally() {
        // An alert summary comes from a workload annotation, so from whoever can
        // deploy. Same guarantee as the push path, tested rather than inherited.
        let text = notice(&an_alert(
            Severity::Unrecognised("<b>sev1</b>".to_owned()),
            AlertStatus::Firing,
            "<script>alert(1)</script> see [here](http://evil)",
        ));

        assert!(text.contains("<script>alert(1)</script>"), "{text}");
        assert!(text.contains("<b>sev1</b>"), "{text}");
    }

    #[test]
    fn a_deleted_branch_reads_as_a_deletion() {
        let text = notice(&deletion(
            "motrice/webhook-proxy",
            "bead/gc-old",
            "bjornmolin",
        ));

        assert!(text.contains("bjornmolin"), "{text}");
        assert!(text.contains("bead/gc-old"), "{text}");
        assert!(text.contains("motrice/webhook-proxy"), "{text}");
        assert!(text.to_lowercase().contains("deleted"), "{text}");
        // It must not describe a deletion as a push of nothing, which is the
        // sentence this bead existed to remove.
        assert!(!text.contains("no commits"), "{text}");
    }

    #[test]
    fn a_push_that_changed_nothing_says_so_and_does_not_mention_deletion() {
        let text = notice(&push("motrice/webhook-proxy", "main", "bjornmolin", &[]));

        assert!(text.contains("no commits"), "{text}");
        // The hedge is gone: this is no longer possibly-a-deletion.
        assert!(!text.to_lowercase().contains("delet"), "{text}");
    }

    #[test]
    fn a_push_of_commits_lists_them() {
        let text = notice(&a_push());

        assert!(text.contains("2 commits"), "{text}");
        assert!(text.contains("docs: tidy the glossary"), "{text}");
        assert!(!text.to_lowercase().contains("delet"), "{text}");
    }

    #[test]
    fn a_deletion_containing_markup_appears_literally_too() {
        // The deletion path interpolates the same attacker-controlled fields as
        // the push path — whoever can delete a branch chose its name — so it
        // needs the same guarantee, not an inherited assumption. See gc-o61.
        let text = notice(&deletion(
            "motrice/<img src=x>",
            "feature/<script>alert(1)</script>",
            "<i>nobody</i>",
        ));

        assert!(text.contains("motrice/<img src=x>"), "{text}");
        assert!(text.contains("feature/<script>alert(1)</script>"), "{text}");
        assert!(text.contains("<i>nobody</i>"), "{text}");
    }

    // ---- delivery: against a stub hookshot --------------------------------

    #[derive(Clone)]
    struct Stub {
        seen: Arc<Mutex<Vec<(String, String)>>>,
        status: StatusCode,
        reply: &'static str,
        delay: Duration,
    }

    async fn record(
        State(stub): State<Stub>,
        headers: HeaderMap,
        body: String,
    ) -> (StatusCode, &'static str) {
        if !stub.delay.is_zero() {
            tokio::time::sleep(stub.delay).await;
        }
        let content_type = headers
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        stub.seen
            .lock()
            .expect("not poisoned")
            .push((content_type, body));

        (stub.status, stub.reply)
    }

    /// A stub hookshot on a loopback port. Returns its URL and what it received.
    async fn hookshot(
        status: StatusCode,
        reply: &'static str,
        delay: Duration,
    ) -> (String, Arc<Mutex<Vec<(String, String)>>>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let stub = Stub {
            seen: Arc::clone(&seen),
            status,
            reply,
            delay,
        };
        let app = Router::new()
            .route("/hook/{id}", post(record))
            .with_state(stub);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let address = listener.local_addr().expect("an address");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("the stub serves");
        });

        (format!("http://{address}/hook/{HOOK_ID}"), seen)
    }

    fn notices_to(url: &str, timeout: Duration) -> ElementNotices {
        ElementNotices::new(
            HashMap::from([("room".to_owned(), url.to_owned())]),
            timeout,
        )
        .expect("a client")
    }

    #[tokio::test]
    async fn the_request_is_json_carrying_the_notice_as_text() {
        let (url, seen) = hookshot(StatusCode::OK, r#"{"ok":true}"#, Duration::ZERO).await;

        notices_to(&url, Duration::from_secs(5))
            .dispatch(&a_delivery(), &a_push(), &room("room"))
            .await
            .expect("the stub accepts");

        let received = seen.lock().expect("not poisoned").clone();
        assert_eq!(received.len(), 1);
        let (content_type, body) = &received[0];
        assert!(content_type.contains("application/json"), "{content_type}");

        let sent: serde_json::Value = serde_json::from_str(body).expect("valid JSON");
        assert!(sent.get("text").is_some(), "{sent}");
        assert!(
            sent["text"]
                .as_str()
                .expect("text is a string")
                .contains("bjornmolin"),
            "{sent}"
        );
        // `html` as well, since gc-fks established that hookshot renders the
        // `text` field as markdown and gc-qev decided what to do about it. The
        // two fields and no others: nothing here claims a username.
        assert!(sent.get("html").is_some(), "{sent}");
        assert_eq!(sent.as_object().expect("an object").len(), 2, "{sent}");
        // And `text` stays the plain rendering. It is the body a client falling
        // back shows, so markup in it would be the original defect wearing a
        // different field name.
        let text = sent["text"].as_str().expect("text is a string");
        assert!(!text.contains('<'), "{sent}");
        assert!(!text.contains("&nbsp;"), "{sent}");
    }

    #[tokio::test]
    async fn a_success_status_carrying_ok_false_is_still_a_refusal() {
        // Not asked for by the bead. hookshot signals success with {"ok":true},
        // so an explicit false under a 2xx is a refusal being dressed as a
        // success, and treating it as delivered would lose a Notice silently.
        let (url, _) = hookshot(StatusCode::OK, r#"{"ok":false}"#, Duration::ZERO).await;

        let outcome = notices_to(&url, Duration::from_secs(5))
            .dispatch(&a_delivery(), &a_push(), &room("room"))
            .await;

        assert_eq!(outcome, Err(DispatchFailed::Rejected));
    }

    #[tokio::test]
    async fn a_bad_hook_id_is_a_refusal_not_a_leaked_client_error() {
        let (url, _) = hookshot(StatusCode::NOT_FOUND, "no such hook", Duration::ZERO).await;

        let outcome = notices_to(&url, Duration::from_secs(5))
            .dispatch(&a_delivery(), &a_push(), &room("room"))
            .await;

        assert_eq!(outcome, Err(DispatchFailed::Rejected));
    }

    #[tokio::test]
    async fn a_failing_destination_is_unreachable() {
        let (url, _) = hookshot(StatusCode::INTERNAL_SERVER_ERROR, "broken", Duration::ZERO).await;

        let outcome = notices_to(&url, Duration::from_secs(5))
            .dispatch(&a_delivery(), &a_push(), &room("room"))
            .await;

        assert_eq!(outcome, Err(DispatchFailed::Unreachable));
    }

    #[tokio::test]
    async fn a_slow_destination_times_out_rather_than_hanging() {
        let (url, _) = hookshot(StatusCode::OK, r#"{"ok":true}"#, Duration::from_millis(500)).await;

        let outcome = notices_to(&url, Duration::from_millis(50))
            .dispatch(&a_delivery(), &a_push(), &room("room"))
            .await;

        assert_eq!(outcome, Err(DispatchFailed::TimedOut));
    }

    #[tokio::test]
    async fn a_destination_we_have_no_url_for_is_unreachable() {
        let (url, _) = hookshot(StatusCode::OK, r#"{"ok":true}"#, Duration::ZERO).await;

        let outcome = notices_to(&url, Duration::from_secs(5))
            .dispatch(&a_delivery(), &a_push(), &room("some-other-room"))
            .await;

        assert_eq!(outcome, Err(DispatchFailed::Unreachable));
    }

    #[test]
    fn debug_output_cannot_leak_a_webhook_url() {
        let notices = ElementNotices::new(
            HashMap::from([(
                "room".to_owned(),
                format!("https://hookshot.example.invalid/hook/{HOOK_ID}"),
            )]),
            Duration::from_secs(5),
        )
        .expect("a client");

        let printed = format!("{notices:?}");

        assert!(!printed.contains(HOOK_ID), "{printed}");
        assert!(!printed.contains("https://"), "{printed}");
        assert!(printed.contains('1'), "{printed}");
    }

    /// Turns a rendering back into the characters a reader would see.
    ///
    /// Used to prove the two renderings say the same thing. Deliberately the
    /// inverse of what the renderer does and nothing cleverer: if it needed to
    /// understand HTML, it would be a second renderer and could drift too.
    fn as_read(html: &str) -> String {
        let mut text = html.replace("<br>", "\n").replace("&nbsp;", " ");
        // The anchor, if any: its visible text is already between the tags.
        while let Some(open) = text.find("<a href=\"") {
            let close = text[open..].find('>').expect("an opened tag is closed") + open;
            text.replace_range(open..=close, "");
        }
        text = text.replace("</a>", "");
        // &amp; last, or an escaped &lt; would be decoded twice.
        text.replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&#39;", "'")
            .replace("&amp;", "&")
    }

    #[test]
    fn a_markdown_link_in_a_commit_message_is_shown_as_the_characters_someone_typed() {
        // The defect this bead exists for. hookshot renders markdown in `text`,
        // so a commit message can put a clickable link with wording of its own
        // choosing into a room that trusts the forge. In HTML we say what is a
        // link, and this is not one.
        let html = notice_html(&linked_push(
            "motrice/webhook-proxy",
            "main",
            "bjornmolin",
            &[(
                "6113728f27ae",
                "[Payroll portal has moved](http://attacker.example)",
            )],
            None,
        ));

        assert!(html.contains("[Payroll portal has moved]"), "{html}");
        assert!(
            !html.contains("<a href=\"http://attacker.example"),
            "{html}"
        );
    }

    #[test]
    fn the_characters_that_would_otherwise_be_markup_are_escaped_everywhere() {
        let html = notice_html(&linked_push(
            "motrice/<b>x</b>",
            "main&more",
            "o'brien",
            &[("6113728f27ae", "a \"quoted\" <script>alert(1)</script>")],
            None,
        ));

        assert!(!html.contains("<b>"), "{html}");
        assert!(!html.contains("<script>"), "{html}");
        assert!(html.contains("&lt;script&gt;"), "{html}");
        assert!(html.contains("&amp;more"), "{html}");
        assert!(html.contains("&quot;quoted&quot;"), "{html}");
        assert!(html.contains("&#39;brien"), "{html}");
    }

    #[test]
    fn a_permalink_becomes_a_link_whose_visible_text_is_its_destination() {
        // The whole rule in one assertion. A link that says one thing and goes
        // to another is the attack; a link whose text is its destination cannot
        // lie about where it goes, so a reader can judge it before clicking.
        let html = notice_html(&linked_push(
            "motrice/webhook-proxy",
            "main",
            "bjornmolin",
            &[],
            Some("https://forge.example/x?a=1&b=2"),
        ));

        assert!(
            html.contains(
                "<a href=\"https://forge.example/x?a=1&amp;b=2\">\
                 https://forge.example/x?a=1&amp;b=2</a>"
            ),
            "{html}"
        );
    }

    #[test]
    fn a_permalink_with_a_scheme_we_do_not_publish_is_shown_as_text() {
        // Permalink::new checks only that it is not blank, and the value comes
        // from the payload — so it is attacker-controlled and need not be a URL
        // at all. Anything but http and https is printed, never linked.
        for hostile in [
            "javascript:alert(1)",
            "data:text/html,<b>x</b>",
            "https:/\nevil",
            // Internal whitespace, which is constructible. Leading whitespace is
            // not: Permalink::new trims, so that case cannot arise and testing it
            // would be testing the domain's constructor from here.
            "https://forge.example/a b",
        ] {
            let html = notice_html(&linked_push(
                "motrice/webhook-proxy",
                "main",
                "bjornmolin",
                &[],
                Some(hostile),
            ));

            assert!(
                !html.contains("<a href"),
                "{hostile:?} became a link: {html}"
            );
        }
    }

    #[test]
    fn lines_are_broken_with_br_because_a_newline_is_only_whitespace_in_html() {
        // What the live instance showed: our newlines collapsed and the push
        // arrived as one run-on line, losing the structure this renderer builds.
        let html = notice_html(&linked_push(
            "motrice/webhook-proxy",
            "main",
            "bjornmolin",
            &[("6113728f27ae", "a change")],
            Some("https://forge.example/x"),
        ));

        assert!(
            !html.contains('\n'),
            "a raw newline renders as a space: {html}"
        );
        assert_eq!(html.matches("<br>").count(), 2, "{html}");
        // The indent survives too, which plain spaces would not.
        assert!(html.contains("&nbsp;&nbsp;6113728f"), "{html}");
    }

    #[test]
    fn both_renderings_say_the_same_thing() {
        // Two renderers drift. This is what stops them: whatever a reader sees
        // in the room must be what a client falling back to plain text sees.
        for event in [
            a_push(),
            linked_push(
                "motrice/<b>x</b>",
                "main&more",
                "o'brien",
                &[("6113728f27ae", "[a](http://evil.example) & \"more\"")],
                Some("https://forge.example/x?a=1&b=2"),
            ),
            deletion("motrice/webhook-proxy", "main", "bjornmolin"),
            alert_with(
                Severity::Critical,
                AlertStatus::Firing,
                "api <latency> above target",
                &[
                    ("namespace", "prod"),
                    ("markup", "<b>x</b> [a](http://evil)"),
                ],
                Some("https://prometheus.example/graph"),
            ),
        ] {
            assert_eq!(as_read(&notice_html(&event)), notice(&event));
        }
    }
}
