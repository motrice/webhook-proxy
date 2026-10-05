//! GitHub's push payload, translated into the Events it reports.
//!
//! This is the anti-corruption layer for one Origin: GitHub's field names and
//! JSON shape stop here, and an [`Event`] comes out the other side. Nothing in
//! this crate is reachable from the domain or the application — they see only
//! the `Translator` port.
//!
//! The event kind is inferred from the payload's shape rather than read from
//! GitHub's `X-GitHub-Event` header, because a `VerifiedDelivery` carries bytes,
//! an Origin, an identity and an arrival time, and nothing else. Putting a
//! header into the domain to carry a hint would be transport vocabulary in the
//! core. Inferring also degrades better: a payload that is not a push simply is
//! not a push, rather than depending on a header that may be missing.
//!
//! Within a push, what the push *did* is read from the body's `deleted` flag. A
//! deletion and a push that changed nothing both carry an empty commit list, so
//! the count cannot tell them apart; this is the only place that can, which is
//! why the two leave here as different Events.

use application::ports::{Translator, Untranslatable};
use domain::{
    BranchName, Commit, CommitId, Event, Permalink, Pusher, RepositoryName, Summary,
    VerifiedDelivery,
};
use serde::Deserialize;

/// Only `refs/heads/...` is a branch. A tag push is a different thing and is
/// not translated.
const BRANCH: &str = "refs/heads/";

/// Shown in place of a commit summary when the message is empty.
///
/// Git permits an empty commit message. Refusing the whole Delivery over one
/// would mean a room hears nothing about a push because one commit was odd,
/// which is a worse outcome than saying so plainly.
const NO_MESSAGE: &str = "(no commit message)";

/// Translates GitHub payloads. Stateless.
#[derive(Debug, Clone, Copy, Default)]
pub struct GithubPayload;

/// GitHub's push payload, reduced to the fields we use.
///
/// Deserialising into this is also the test of whether a payload *is* a push:
/// a `ping` has no `ref`, a `create` has no `commits`, and either way serde
/// refuses and we report nothing rather than guessing.
#[derive(Deserialize)]
struct Push {
    #[serde(rename = "ref")]
    reference: String,
    repository: Repository,
    pusher: Account,
    /// GitHub says so explicitly when the push deleted the ref. Absent means a
    /// push, so this defaults to false rather than refusing the payload: a
    /// sender that omits the field is describing an ordinary push.
    #[serde(default)]
    deleted: bool,
    /// GitHub's own link comparing what the branch was against what it now is.
    ///
    /// Taken as published. Nothing here knows how to build such an address, and
    /// that is the point: a link can travel inward as a domain value without any
    /// address scheme existing in the core or in a Destination's adapter.
    #[serde(default)]
    compare: Option<String>,
    #[serde(default)]
    commits: Vec<PushedCommit>,
}

#[derive(Deserialize)]
struct Repository {
    full_name: String,
}

#[derive(Deserialize)]
struct Account {
    name: String,
}

#[derive(Deserialize)]
struct PushedCommit {
    id: String,
    message: String,
}

impl Translator for GithubPayload {
    fn events(&self, delivery: &VerifiedDelivery) -> Result<Vec<Event>, Untranslatable> {
        // Must be JSON at all, or there is nothing to read.
        let json: serde_json::Value =
            serde_json::from_slice(delivery.body().as_bytes()).map_err(|_| Untranslatable)?;

        // Not being a push is not an error. An event we do not handle has
        // nothing to say, and saying so is the whole of our obligation.
        let Ok(push) = serde_json::from_value::<Push>(json) else {
            return Ok(Vec::new());
        };
        let Some(branch) = push.reference.strip_prefix(BRANCH) else {
            return Ok(Vec::new());
        };

        // Past here the payload claims to be a push to a branch, so a field we
        // cannot use means it is unusable rather than uninteresting.
        let repository =
            RepositoryName::new(&push.repository.full_name).map_err(|_| Untranslatable)?;
        let branch = BranchName::new(branch).map_err(|_| Untranslatable)?;
        let pusher = Pusher::new(&push.pusher.name).map_err(|_| Untranslatable)?;

        // A deletion carries no commits, so there is nothing to translate and
        // the list is ignored rather than trusted: were a sender ever to send
        // both, the flag is the claim about what happened and the commits would
        // be the stale half.
        if push.deleted {
            return Ok(vec![Event::DeletedBranch {
                repository,
                branch,
                pusher,
            }]);
        }

        let commits = push
            .commits
            .iter()
            .map(translate_commit)
            .collect::<Result<Vec<_>, _>>()?;

        // A link we cannot use is dropped rather than carried or complained
        // about: a blank reference would reach a reader as something to click
        // that goes nowhere, and refusing the push over it would lose the news.
        let permalink = push
            .compare
            .as_deref()
            .and_then(|published| Permalink::new(published).ok());

        Ok(vec![Event::PushedCommits {
            repository,
            branch,
            pusher,
            commits,
            permalink,
        }])
    }
}

/// One commit, reduced to what a Destination shows.
///
/// An empty message becomes [`NO_MESSAGE`] rather than refusing the Delivery.
/// A blank identity does refuse it: a commit we cannot name is a payload we
/// cannot report on.
fn translate_commit(raw: &PushedCommit) -> Result<Commit, Untranslatable> {
    let id = CommitId::new(&raw.id).map_err(|_| Untranslatable)?;
    let summary = Summary::new(&raw.message)
        .or_else(|_| Summary::new(NO_MESSAGE))
        .map_err(|_| Untranslatable)?;

    Ok(Commit::new(id, summary))
}

#[cfg(test)]
mod tests {
    use application::ports::{Translator, Untranslatable};
    use domain::{
        Body, Delivery, DeliveryId, Event, OriginId, Permalink, Signature, Timestamp,
        VerifiedDelivery,
    };

    use super::GithubPayload;

    const PUSH: &[u8] = include_bytes!("../fixtures/push.json");
    const BRANCH_DELETE: &[u8] = include_bytes!("../fixtures/branch-delete.json");

    /// A Delivery that has been through verification, which is the only thing
    /// the port accepts — by design, so nothing is parsed before its signature
    /// matched.
    fn verified(body: &[u8]) -> VerifiedDelivery {
        let signature = Signature::from_bytes([1, 2, 3]);
        Delivery::new(
            DeliveryId::new("d-1").expect("a non-blank identity"),
            OriginId::new("a-forge").expect("a non-blank origin identity"),
            Body::from_bytes(body.to_vec()),
            Timestamp::from_millis_since_epoch(1_759_000_000_000),
        )
        .verify(&signature, &signature)
        .expect("matching signatures")
    }

    fn translate(body: &[u8]) -> Result<Vec<Event>, Untranslatable> {
        GithubPayload.events(&verified(body))
    }

    fn only_event(body: &[u8]) -> Event {
        let mut events = translate(body).expect("translatable");
        assert_eq!(events.len(), 1, "{events:?}");
        events.remove(0)
    }

    #[test]
    fn a_captured_push_yields_the_event_it_reports() {
        let Event::PushedCommits {
            repository,
            branch,
            pusher,
            commits,
            ..
        } = only_event(PUSH)
        else {
            panic!("a push");
        };

        assert_eq!(repository.as_str(), "motrice/webhook-proxy");
        assert_eq!(branch.as_str(), "main");
        assert_eq!(pusher.as_str(), "bjornmolin");
        assert_eq!(commits.len(), 2);
        assert_eq!(
            commits[0].id().as_str(),
            "aa11bb22cc33dd44ee55ff6677889900aabbccdd"
        );
    }

    #[test]
    fn a_commit_body_does_not_reach_the_event() {
        // The fixture's first commit has a body that must not travel: a
        // Destination shows one line, and the domain's Summary enforces that.
        let Event::PushedCommits { commits, .. } = only_event(PUSH) else {
            panic!("a push");
        };

        assert_eq!(
            commits[0].summary().as_str(),
            "feat(domain): reject overdrawn withdrawals"
        );
    }

    #[test]
    fn the_branch_is_the_ref_without_its_prefix() {
        let Event::PushedCommits { branch, .. } = only_event(PUSH) else {
            panic!("a push");
        };

        assert_eq!(branch.as_str(), "main");
    }

    #[test]
    fn a_branch_delete_becomes_a_deletion_not_an_empty_push() {
        // Captured from a real payload: `deleted: true` with an empty commit
        // list and an all-zero `after`. The flag is the only thing that
        // distinguishes this from a push that changed nothing, and reading it
        // here is the whole reason the distinction can exist in the domain.
        let Event::DeletedBranch {
            repository,
            branch,
            pusher,
        } = only_event(BRANCH_DELETE)
        else {
            panic!("a deletion");
        };

        assert_eq!(repository.as_str(), "motrice/webhook-proxy");
        assert_eq!(branch.as_str(), "bead/gc-old");
        assert_eq!(pusher.as_str(), "bjornmolin");
    }

    #[test]
    fn a_push_that_changed_nothing_stays_a_push() {
        // The other half of the distinction, and the reason an empty commit list
        // is not enough to infer a deletion: `deleted` is false, so this is a
        // push that happened to carry nothing — a force-push to the same commit,
        // for instance.
        let quiet = br#"{"ref": "refs/heads/main",
                         "deleted": false,
                         "repository": {"full_name": "motrice/webhook-proxy"},
                         "pusher": {"name": "bjornmolin"},
                         "commits": []}"#;

        let Event::PushedCommits { commits, .. } = only_event(quiet) else {
            panic!("a push");
        };

        assert!(commits.is_empty());
    }

    #[test]
    fn a_payload_with_no_deleted_field_is_read_as_a_push() {
        // Absence is not deletion. A sender that omits the flag is describing a
        // push, so the default must be false rather than an error.
        let terse = br#"{"ref": "refs/heads/main",
                         "repository": {"full_name": "motrice/webhook-proxy"},
                         "pusher": {"name": "bjornmolin"},
                         "commits": [{"id": "abc123", "message": "fine"}]}"#;

        let Event::PushedCommits { commits, .. } = only_event(terse) else {
            panic!("a push");
        };

        assert_eq!(commits.len(), 1);
    }

    #[test]
    fn a_push_carries_the_link_the_sender_published() {
        // Read, never built. GitHub publishes the comparison link in the payload,
        // so no address scheme is known here or anywhere else — which is what
        // made carrying a link possible without leaking a vendor into the core.
        let Event::PushedCommits { permalink, .. } = only_event(PUSH) else {
            panic!("a push");
        };

        assert_eq!(
            permalink.as_ref().map(Permalink::as_str),
            Some("https://github.com/motrice/webhook-proxy/compare/9049f1265b7d...6113728f27ae")
        );
    }

    #[test]
    fn a_push_without_a_published_link_still_becomes_an_event() {
        // A missing link is not a reason to drop a real push, so the field is
        // absent rather than the Delivery being refused.
        let unlinked = br#"{"ref": "refs/heads/main",
                            "repository": {"full_name": "motrice/webhook-proxy"},
                            "pusher": {"name": "bjornmolin"},
                            "commits": [{"id": "abc123", "message": "fine"}]}"#;

        let Event::PushedCommits {
            commits, permalink, ..
        } = only_event(unlinked)
        else {
            panic!("a push");
        };

        assert_eq!(commits.len(), 1);
        assert!(permalink.is_none());
    }

    #[test]
    fn a_blank_published_link_is_treated_as_no_link() {
        // Whitespace is not a reference. Dropping it is better than carrying a
        // link a reader cannot follow, and better than refusing the push.
        let blank = br#"{"ref": "refs/heads/main",
                         "compare": "   ",
                         "repository": {"full_name": "motrice/webhook-proxy"},
                         "pusher": {"name": "bjornmolin"},
                         "commits": []}"#;

        let Event::PushedCommits { permalink, .. } = only_event(blank) else {
            panic!("a push");
        };

        assert!(permalink.is_none());
    }

    #[test]
    fn a_deletion_discards_the_link_the_sender_published() {
        // The fixture carries a compare link, because a real deletion payload
        // does. It is dropped: DeletedBranch has no field for one, and comparing
        // against a ref that no longer exists would tell a reader nothing.
        let Event::DeletedBranch { .. } = only_event(BRANCH_DELETE) else {
            panic!("a deletion");
        };
    }

    #[test]
    fn invalid_json_cannot_be_read_at_all() {
        assert_eq!(translate(b"{not json"), Err(Untranslatable));
    }

    #[test]
    fn a_payload_that_is_not_a_push_reports_nothing_and_is_not_an_error() {
        // GitHub's ping. We are not the sender's error reporter, so an event we
        // do not handle is success with nothing to say.
        let ping = br#"{"zen": "Non-blocking is better than blocking.", "hook_id": 1}"#;

        assert_eq!(translate(ping), Ok(vec![]));
    }

    #[test]
    fn a_tag_push_reports_nothing_rather_than_inventing_a_branch() {
        let tag = br#"{"ref": "refs/tags/v1.0.0",
                       "repository": {"full_name": "motrice/webhook-proxy"},
                       "pusher": {"name": "bjornmolin"},
                       "commits": []}"#;

        assert_eq!(translate(tag), Ok(vec![]));
    }

    #[test]
    fn a_commit_with_an_empty_message_is_marked_rather_than_refusing_the_push() {
        // Git allows an empty commit message. Refusing the whole Delivery would
        // mean the room hears nothing about the push.
        let odd = br#"{"ref": "refs/heads/main",
                       "repository": {"full_name": "motrice/webhook-proxy"},
                       "pusher": {"name": "bjornmolin"},
                       "commits": [{"id": "abc123", "message": "   \n  "}]}"#;

        let Event::PushedCommits { commits, .. } = only_event(odd) else {
            panic!("a push");
        };

        assert_eq!(commits.len(), 1);
        assert_eq!(commits[0].summary().as_str(), "(no commit message)");
    }

    #[test]
    fn a_blank_repository_name_cannot_be_read() {
        let blank = br#"{"ref": "refs/heads/main",
                         "repository": {"full_name": "  "},
                         "pusher": {"name": "bjornmolin"},
                         "commits": []}"#;

        assert_eq!(translate(blank), Err(Untranslatable));
    }

    #[test]
    fn a_commit_with_a_blank_identity_cannot_be_read() {
        let blank = br#"{"ref": "refs/heads/main",
                         "repository": {"full_name": "motrice/webhook-proxy"},
                         "pusher": {"name": "bjornmolin"},
                         "commits": [{"id": " ", "message": "fine"}]}"#;

        assert_eq!(translate(blank), Err(Untranslatable));
    }
}
