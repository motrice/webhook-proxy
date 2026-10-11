//! An outbox that remembers nothing past the process.
//!
//! The first implementation of [`application::ports::Outbox`], so the use cases
//! can be driven before a database exists — and the one the test suite keeps
//! using afterwards, because a suite that needs a database is a suite people
//! stop running.
//!
//! It is not a stub. It keeps the two guarantees the port states and a durable
//! implementation will have to keep as well: a Delivery's Dispatches are stored
//! all together or not at all, and they come back in the order they were
//! accepted. Getting those wrong here would mean the use-case tests prove
//! something the real store does not do.
//!
//! What it deliberately does not do is survive a restart, which is the whole
//! point of bead gc-b0n and the reason this one is cheap.

use std::collections::HashMap;
use std::sync::Mutex;

use application::ports::{Outbox, StorageUnavailable};
use async_trait::async_trait;
use domain::{DeliveryId, Dispatch};

/// Dispatches held in memory, keyed by the Delivery that produced them.
///
/// `Debug` prints counts and never contents. A Dispatch carries an Event, and
/// an Event carries a commit message or an alert annotation — other people's
/// words, which is exactly what the rest of this codebase keeps out of logs.
#[derive(Default)]
pub struct MemoryOutbox {
    // One lock over the whole map rather than finer-grained locking: `accept`
    // has to be all-or-nothing, and the cheapest way to be atomic is to be the
    // only writer while it runs. A database does this with a transaction.
    accepted: Mutex<HashMap<DeliveryId, Vec<Dispatch>>>,
}

impl MemoryOutbox {
    /// An empty outbox.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many Deliveries it is holding Dispatches for.
    #[must_use]
    pub fn deliveries(&self) -> usize {
        self.accepted.lock().map_or(0, |held| held.len())
    }
}

impl core::fmt::Debug for MemoryOutbox {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MemoryOutbox({} deliveries)", self.deliveries())
    }
}

#[async_trait]
impl Outbox for MemoryOutbox {
    async fn accept(&self, dispatches: &[Dispatch]) -> Result<(), StorageUnavailable> {
        // A poisoned lock means another thread panicked holding it, and what it
        // was holding is a half-written map. Reporting unavailable is the honest
        // answer and the one the caller can act on: the sender is refused rather
        // than told something was stored.
        let mut held = self.accepted.lock().map_err(|_| StorageUnavailable)?;

        // Grouped first, inserted second, so a `dispatches` carrying more than
        // one Delivery's work still lands all at once.
        let mut grouped: HashMap<DeliveryId, Vec<Dispatch>> = HashMap::new();
        for dispatch in dispatches {
            grouped
                .entry(dispatch.delivery().clone())
                .or_default()
                .push(dispatch.clone());
        }

        for (delivery, mut theirs) in grouped {
            held.entry(delivery).or_default().append(&mut theirs);
        }

        Ok(())
    }

    async fn accepted(&self, delivery: &DeliveryId) -> Result<Vec<Dispatch>, StorageUnavailable> {
        let held = self.accepted.lock().map_err(|_| StorageUnavailable)?;
        Ok(held.get(delivery).cloned().unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use domain::{
        BranchName, Commit, CommitId, Destination, DestinationId, DestinationKind, Event, Pusher,
        RepositoryName, Summary,
    };

    use super::{DeliveryId, Dispatch, MemoryOutbox, Outbox, StorageUnavailable};

    fn delivery(id: &str) -> DeliveryId {
        DeliveryId::new(id).expect("a non-blank identity")
    }

    fn room(id: &str) -> Destination {
        Destination::new(
            DestinationId::new(id).expect("a non-blank identity"),
            DestinationKind::ChatRoom,
        )
    }

    fn a_push(summary: &str) -> Event {
        Event::PushedCommits {
            repository: RepositoryName::new("motrice/webhook-proxy").expect("a name"),
            branch: BranchName::new("main").expect("a name"),
            pusher: Pusher::new("bjornmolin").expect("a name"),
            commits: vec![Commit::new(
                CommitId::new("6113728f27ae").expect("an id"),
                Summary::new(summary).expect("a summary"),
            )],
            permalink: None,
        }
    }

    fn dispatch(id: &str, summary: &str, to: &str) -> Dispatch {
        Dispatch::new(delivery(id), a_push(summary), room(to))
    }

    #[tokio::test]
    async fn what_was_accepted_comes_back_under_the_identity_it_was_accepted_with() {
        let outbox = MemoryOutbox::new();
        let stored = vec![dispatch("d-1", "a change", "devsecops-room")];

        outbox.accept(&stored).await.expect("an empty outbox");

        assert_eq!(
            outbox.accepted(&delivery("d-1")).await.expect("held"),
            stored
        );
    }

    #[tokio::test]
    async fn an_identity_that_was_never_accepted_is_empty_and_not_an_error() {
        // The distinction the port draws: nothing stored under this name is an
        // answer, and the store being unreachable is a failure. A caller that
        // could not tell them apart would refuse a sender over an empty result.
        let outbox = MemoryOutbox::new();

        assert_eq!(outbox.accepted(&delivery("never")).await, Ok(Vec::new()));
    }

    #[tokio::test]
    async fn a_delivery_that_fanned_out_keeps_the_order_its_rules_fired_in() {
        // A reader comparing two runs should not have to sort them, and the
        // order a Delivery fanned out in is the order the routing file is
        // written in. A map would lose that, silently.
        let outbox = MemoryOutbox::new();
        let fanned = vec![
            dispatch("d-2", "a change", "devsecops-room"),
            dispatch("d-2", "a change", "platform-room"),
            dispatch("d-2", "a change", "audit-room"),
        ];

        outbox.accept(&fanned).await.expect("an empty outbox");

        let held = outbox.accepted(&delivery("d-2")).await.expect("held");
        let rooms: Vec<&str> = held.iter().map(|d| d.destination().id().as_str()).collect();
        assert_eq!(rooms, vec!["devsecops-room", "platform-room", "audit-room"]);
    }

    #[tokio::test]
    async fn one_delivery_is_stored_all_together_or_not_at_all() {
        // The guarantee the promise rests on. A Delivery whose Dispatches were
        // half stored and then acknowledged is the failure this port exists to
        // prevent: the sender believes it is delivered, and the Destinations
        // that were not recorded are never attempted and never reported.
        //
        // In memory the whole map is locked while this runs, so the way to show
        // it is that nothing is ever observable in between — accept either adds
        // every Dispatch of a Delivery or none of them.
        let outbox = MemoryOutbox::new();

        outbox
            .accept(&[
                dispatch("d-3", "first", "devsecops-room"),
                dispatch("d-3", "second", "platform-room"),
            ])
            .await
            .expect("an empty outbox");

        assert_eq!(
            outbox.accepted(&delivery("d-3")).await.expect("held").len(),
            2
        );
    }

    #[tokio::test]
    async fn accepting_for_several_deliveries_at_once_keeps_them_apart() {
        let outbox = MemoryOutbox::new();

        outbox
            .accept(&[
                dispatch("d-4", "a change", "devsecops-room"),
                dispatch("d-5", "another", "platform-room"),
                dispatch("d-4", "a change", "audit-room"),
            ])
            .await
            .expect("an empty outbox");

        assert_eq!(
            outbox.accepted(&delivery("d-4")).await.expect("held").len(),
            2
        );
        assert_eq!(
            outbox.accepted(&delivery("d-5")).await.expect("held").len(),
            1
        );
        assert_eq!(outbox.deliveries(), 2);
    }

    #[tokio::test]
    async fn accepting_twice_under_one_identity_adds_rather_than_replaces() {
        // Not obviously right, and chosen deliberately: a sender that retries
        // produces a second accept under the same identity, and losing the first
        // would mean losing Dispatches that may already have been sent. Keeping
        // both means a duplicate message, which gc-6a5.4 calls cosmetic and
        // which gc-6a5.4 is where deduplication belongs.
        let outbox = MemoryOutbox::new();

        outbox
            .accept(&[dispatch("d-6", "first", "devsecops-room")])
            .await
            .expect("an empty outbox");
        outbox
            .accept(&[dispatch("d-6", "again", "devsecops-room")])
            .await
            .expect("still available");

        assert_eq!(
            outbox.accepted(&delivery("d-6")).await.expect("held").len(),
            2
        );
    }

    #[test]
    fn debug_counts_deliveries_and_prints_nothing_anybody_wrote() {
        // A Dispatch carries an Event, and an Event carries a commit message —
        // somebody else's words, which the rest of this codebase keeps out of
        // logs. Body prints its length for the same reason.
        let outbox = MemoryOutbox::new();
        let printed = format!("{outbox:?}");

        assert_eq!(printed, "MemoryOutbox(0 deliveries)");
    }

    #[tokio::test]
    async fn a_dispatch_in_the_outbox_does_not_print_what_somebody_wrote() {
        let outbox = MemoryOutbox::new();
        outbox
            .accept(&[dispatch(
                "d-7",
                "fix the thing nobody should read",
                "a-room",
            )])
            .await
            .expect("an empty outbox");

        let printed = format!("{outbox:?}");

        assert!(!printed.contains("nobody should read"), "{printed}");
    }

    #[test]
    fn the_unavailable_error_names_no_address_and_no_credential() {
        // What a log line is written from, when gc-mbr's error is logged. A
        // driver's own error would carry the connection string; this one carries
        // nothing at all.
        let printed = format!("{StorageUnavailable}");

        assert_eq!(printed, "the delivery store is unavailable");
    }
}
