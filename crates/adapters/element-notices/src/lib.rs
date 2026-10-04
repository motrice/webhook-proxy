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
//! injection target. The defence is to send no markup at all: a plain-text
//! Notice has nothing to escape and nothing to get wrong. That is only a
//! complete defence if hookshot does not itself render markdown in the `text`
//! field, which is an open question on the live instance — so the claim here is
//! "we send no markup", not "markup cannot appear".

use std::collections::HashMap;
use std::fmt;
use std::fmt::Write as _;
use std::time::Duration;

use application::ports::{DispatchFailed, Dispatcher};
use domain::{Commit, DeliveryId, Destination, Event};

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

/// An Event as a line of prose for people to read.
///
/// Plain text, deliberately. Nothing here interpolates into markup, so no field
/// needs escaping and no escaping can be forgotten.
#[must_use]
pub fn notice(event: &Event) -> String {
    match event {
        Event::DeletedBranch {
            repository,
            branch,
            pusher,
        } => format!(
            "{} deleted branch {} in {}",
            pusher.as_str(),
            branch.as_str(),
            repository.as_str()
        ),
        Event::PushedCommits {
            repository,
            branch,
            pusher,
            commits,
        } => pushed(
            repository.as_str(),
            branch.as_str(),
            pusher.as_str(),
            commits,
        ),
    }
}

/// A push, with however many commits it carried.
///
/// An empty list is a push that changed nothing — a force-push to the commit
/// that was already there, most often. It is stated plainly and without
/// mentioning deletion, because a deletion is now its own Event and saying
/// "possibly a deletion" here would be hedging about something already known.
fn pushed(repository: &str, branch: &str, pusher: &str, commits: &[Commit]) -> String {
    if commits.is_empty() {
        return format!("{pusher} pushed no commits to {branch} in {repository}");
    }

    let count = commits.len();
    let plural = if count == 1 { "commit" } else { "commits" };
    let mut text = format!("{pusher} pushed {count} {plural} to {branch} in {repository}");
    for commit in commits {
        let id = commit.id().as_str();
        let short = id.get(..SHORT_ID).unwrap_or(id);
        write!(text, "\n  {short} {}", commit.summary().as_str())
            .expect("writing to a String cannot fail");
    }

    text
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
            .json(&serde_json::json!({ "text": notice(event) }))
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
        BranchName, Commit, CommitId, DeliveryId, Destination, DestinationId, DestinationKind,
        Event, Pusher, RepositoryName, Summary,
    };

    use super::{ElementNotices, notice};

    /// Stands in for the room's bearer credential.
    const HOOK_ID: &str = "SUPERSECRETHOOKID";

    fn push(repository: &str, branch: &str, pusher: &str, commits: &[(&str, &str)]) -> Event {
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
        // Only `text`: nothing claims a username or HTML, because whether this
        // instance honours those is unverified (gc-3pa.8 note).
        assert_eq!(sent.as_object().expect("an object").len(), 1, "{sent}");
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
}
