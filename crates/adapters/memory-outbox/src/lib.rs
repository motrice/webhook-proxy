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

use std::sync::Mutex;

use application::ports::{Outbox, Outcome, Recorded, StorageUnavailable};
use async_trait::async_trait;
use domain::{DeliveryId, Dispatch, DispatchId, Timestamp};

/// Dispatches held in memory, in the order they were accepted.
///
/// `Debug` prints counts and never contents. A Dispatch carries an Event, and
/// an Event carries a commit message or an alert annotation — other people's
/// words, which is exactly what the rest of this codebase keeps out of logs.
#[derive(Default)]
pub struct MemoryOutbox {
    // One lock over everything rather than finer-grained locking. `accept` has
    // to be all-or-nothing and `due` has to claim, and the cheapest way to be
    // both is to be the only writer while they run. A database does this with a
    // transaction and SELECT ... FOR UPDATE SKIP LOCKED; see bead gc-b0n.
    held: Mutex<Held>,
}

/// Everything the outbox knows, behind one lock.
#[derive(Default)]
struct Held {
    /// In acceptance order, which is the order a Delivery fanned out in.
    records: Vec<Recorded>,
    /// Identities handed out so far. Unique within the process, which is all an
    /// in-memory store can promise and all its callers may assume.
    minted: u64,
    /// Dispatches handed to a caller by `due` and not yet settled. Holding them
    /// out is what stops two workers sending the same Notice twice.
    claimed: Vec<DispatchId>,
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
        // A set rather than sort-and-dedup, because DeliveryId is Hash and Eq
        // and is deliberately not Ord: nothing in the domain orders identities,
        // and adding an ordering to make a counting helper shorter would be the
        // tail wagging the dog.
        self.held.lock().map_or(0, |held| {
            held.records
                .iter()
                .map(|record| record.dispatch().delivery())
                .collect::<std::collections::HashSet<_>>()
                .len()
        })
    }
}

impl core::fmt::Debug for MemoryOutbox {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MemoryOutbox({} deliveries)", self.deliveries())
    }
}

impl Held {
    /// Replaces what is known about one Dispatch, and releases any claim on it.
    fn settle(&mut self, id: &DispatchId, attempts: u32, outcome: Outcome) {
        self.claimed.retain(|claimed| claimed != id);
        for record in &mut self.records {
            if record.id() == id {
                *record = Recorded::new(id.clone(), record.dispatch().clone(), attempts, outcome);
                return;
            }
        }
    }

    /// What is known about one Dispatch, if anything.
    fn attempts(&self, id: &DispatchId) -> u32 {
        self.records
            .iter()
            .find(|record| record.id() == id)
            .map_or(0, Recorded::attempts)
    }
}

#[async_trait]
impl Outbox for MemoryOutbox {
    async fn accept(
        &self,
        dispatches: &[Dispatch],
        at: Timestamp,
    ) -> Result<Vec<Recorded>, StorageUnavailable> {
        // A poisoned lock means another thread panicked holding it, and what it
        // was holding is half-written. Reporting unavailable is the honest
        // answer and the one the caller can act on: the sender is refused rather
        // than told something was stored.
        let mut held = self.held.lock().map_err(|_| StorageUnavailable)?;

        // Built first and appended at the end, so a failure part-way through
        // leaves nothing behind. In memory nothing can fail here; doing it in
        // the order a transaction would is what keeps this honest as a stand-in.
        let mut arriving = Vec::with_capacity(dispatches.len());
        for dispatch in dispatches {
            held.minted += 1;
            let id =
                DispatchId::new(&format!("mem-{}", held.minted)).map_err(|_| StorageUnavailable)?;
            arriving.push(Recorded::new(
                id,
                dispatch.clone(),
                0,
                Outcome::Waiting { again_at: at },
            ));
        }
        held.records.extend(arriving.iter().cloned());

        Ok(arriving)
    }

    async fn accepted(&self, delivery: &DeliveryId) -> Result<Vec<Recorded>, StorageUnavailable> {
        let held = self.held.lock().map_err(|_| StorageUnavailable)?;
        Ok(held
            .records
            .iter()
            .filter(|record| record.dispatch().delivery() == delivery)
            .cloned()
            .collect())
    }

    async fn due(&self, now: Timestamp, limit: usize) -> Result<Vec<Recorded>, StorageUnavailable> {
        let mut held = self.held.lock().map_err(|_| StorageUnavailable)?;

        let ready: Vec<Recorded> = held
            .records
            .iter()
            .filter(|record| match record.outcome() {
                // Due now, and not already in somebody else's hands.
                Outcome::Waiting { again_at } => {
                    again_at <= now && !held.claimed.contains(record.id())
                }
                Outcome::Delivered { .. } | Outcome::Abandoned { .. } => false,
            })
            .take(limit)
            .cloned()
            .collect();

        for record in &ready {
            held.claimed.push(record.id().clone());
        }

        Ok(ready)
    }

    async fn delivered(&self, id: &DispatchId, at: Timestamp) -> Result<(), StorageUnavailable> {
        let mut held = self.held.lock().map_err(|_| StorageUnavailable)?;
        let attempts = held.attempts(id) + 1;
        held.settle(id, attempts, Outcome::Delivered { at });
        Ok(())
    }

    async fn failed(
        &self,
        id: &DispatchId,
        _at: Timestamp,
        again_at: Timestamp,
    ) -> Result<(), StorageUnavailable> {
        let mut held = self.held.lock().map_err(|_| StorageUnavailable)?;
        let attempts = held.attempts(id) + 1;
        held.settle(id, attempts, Outcome::Waiting { again_at });
        Ok(())
    }

    async fn abandoned(&self, id: &DispatchId, at: Timestamp) -> Result<(), StorageUnavailable> {
        let mut held = self.held.lock().map_err(|_| StorageUnavailable)?;
        let attempts = held.attempts(id) + 1;
        held.settle(id, attempts, Outcome::Abandoned { at });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use domain::{
        BranchName, Commit, CommitId, Destination, DestinationId, DestinationKind, Event, OriginId,
        Pusher, RepositoryName, Summary,
    };

    use super::{
        DeliveryId, Dispatch, MemoryOutbox, Outbox, Outcome, StorageUnavailable, Timestamp,
    };

    /// An arbitrary moment. Nothing here reads a clock; the caller supplies time,
    /// which is what makes these tests fast and never flaky.
    fn at(millis: i64) -> Timestamp {
        Timestamp::from_millis_since_epoch(1_759_000_000_000 + millis)
    }

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
        Dispatch::new(
            delivery(id),
            OriginId::new("github").expect("a non-blank id"),
            a_push(summary),
            room(to),
        )
    }

    #[tokio::test]
    async fn what_was_accepted_comes_back_under_the_identity_it_was_accepted_with() {
        let outbox = MemoryOutbox::new();
        let stored = dispatch("d-1", "a change", "devsecops-room");

        outbox
            .accept(std::slice::from_ref(&stored), at(0))
            .await
            .expect("an empty outbox");

        let held = outbox.accepted(&delivery("d-1")).await.expect("held");
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].dispatch(), &stored);
        assert_eq!(held[0].attempts(), 0);
        assert_eq!(held[0].outcome(), Outcome::Waiting { again_at: at(0) });
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

        outbox
            .accept(
                &[
                    dispatch("d-2", "a change", "devsecops-room"),
                    dispatch("d-2", "a change", "platform-room"),
                    dispatch("d-2", "a change", "audit-room"),
                ],
                at(0),
            )
            .await
            .expect("an empty outbox");

        let held = outbox.accepted(&delivery("d-2")).await.expect("held");
        let rooms: Vec<&str> = held
            .iter()
            .map(|record| record.dispatch().destination().id().as_str())
            .collect();
        assert_eq!(rooms, vec!["devsecops-room", "platform-room", "audit-room"]);
    }

    #[tokio::test]
    async fn one_delivery_is_stored_all_together_or_not_at_all() {
        // The guarantee the promise rests on. A Delivery whose Dispatches were
        // half stored and then acknowledged is the failure this port exists to
        // prevent: the sender believes it is delivered, and the Destinations
        // that were not recorded are never attempted and never reported.
        let outbox = MemoryOutbox::new();

        outbox
            .accept(
                &[
                    dispatch("d-3", "first", "devsecops-room"),
                    dispatch("d-3", "second", "platform-room"),
                ],
                at(0),
            )
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
            .accept(
                &[
                    dispatch("d-4", "a change", "devsecops-room"),
                    dispatch("d-5", "another", "platform-room"),
                    dispatch("d-4", "a change", "audit-room"),
                ],
                at(0),
            )
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
        // both means a duplicate message, which gc-6a5.4 calls cosmetic and is
        // where deduplication belongs.
        let outbox = MemoryOutbox::new();

        outbox
            .accept(&[dispatch("d-6", "first", "devsecops-room")], at(0))
            .await
            .expect("an empty outbox");
        outbox
            .accept(&[dispatch("d-6", "again", "devsecops-room")], at(0))
            .await
            .expect("still available");

        assert_eq!(
            outbox.accepted(&delivery("d-6")).await.expect("held").len(),
            2
        );
    }

    // ---- what is due, and who gets it ------------------------------------

    #[tokio::test]
    async fn something_just_accepted_is_due_at_once() {
        // Not after a first delay. A Notice that waited for a backoff it had not
        // earned would make every room slower for nothing.
        let outbox = MemoryOutbox::new();
        outbox
            .accept(&[dispatch("d-7", "a change", "a-room")], at(0))
            .await
            .expect("an empty outbox");

        assert_eq!(outbox.due(at(0), 10).await.expect("asked").len(), 1);
    }

    #[tokio::test]
    async fn two_workers_are_not_handed_the_same_dispatch() {
        // The Deployment runs two replicas, so this is the normal case and not
        // an edge one. Both sending it would show a room the same Notice twice.
        let outbox = MemoryOutbox::new();
        outbox
            .accept(&[dispatch("d-8", "a change", "a-room")], at(0))
            .await
            .expect("an empty outbox");

        let first = outbox.due(at(0), 10).await.expect("asked");
        let second = outbox.due(at(0), 10).await.expect("asked");

        assert_eq!(first.len(), 1);
        assert!(second.is_empty(), "handed out twice: {second:?}");
    }

    #[tokio::test]
    async fn a_dispatch_that_arrived_is_never_due_again_and_says_when() {
        let outbox = MemoryOutbox::new();
        outbox
            .accept(&[dispatch("d-9", "a change", "a-room")], at(0))
            .await
            .expect("an empty outbox");
        let claimed = outbox.due(at(0), 10).await.expect("asked");

        outbox
            .delivered(claimed[0].id(), at(500))
            .await
            .expect("recorded");

        assert!(outbox.due(at(9_999), 10).await.expect("asked").is_empty());
        let held = outbox.accepted(&delivery("d-9")).await.expect("held");
        assert_eq!(held[0].outcome(), Outcome::Delivered { at: at(500) });
        assert_eq!(held[0].attempts(), 1);
    }

    #[tokio::test]
    async fn a_dispatch_that_failed_waits_until_it_is_due_again() {
        let outbox = MemoryOutbox::new();
        outbox
            .accept(&[dispatch("d-10", "a change", "a-room")], at(0))
            .await
            .expect("an empty outbox");
        let claimed = outbox.due(at(0), 10).await.expect("asked");

        outbox
            .failed(claimed[0].id(), at(100), at(1_000))
            .await
            .expect("recorded");

        // Released by failing, so it is claimable again — but not yet.
        assert!(outbox.due(at(999), 10).await.expect("asked").is_empty());
        let ready = outbox.due(at(1_000), 10).await.expect("asked");
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].attempts(), 1);
    }

    #[tokio::test]
    async fn a_dispatch_that_was_given_up_on_is_never_due_again() {
        // Terminal, and the difference from Waiting is the whole reason Outcome
        // has three states: an abandoned Dispatch that still looked due would be
        // retried forever by a worker that could not tell.
        let outbox = MemoryOutbox::new();
        outbox
            .accept(&[dispatch("d-11", "a change", "a-room")], at(0))
            .await
            .expect("an empty outbox");
        let claimed = outbox.due(at(0), 10).await.expect("asked");

        outbox
            .abandoned(claimed[0].id(), at(700))
            .await
            .expect("recorded");

        assert!(outbox.due(at(9_999), 10).await.expect("asked").is_empty());
        let held = outbox.accepted(&delivery("d-11")).await.expect("held");
        assert_eq!(held[0].outcome(), Outcome::Abandoned { at: at(700) });
    }

    #[tokio::test]
    async fn no_more_than_asked_for_is_handed_out() {
        let outbox = MemoryOutbox::new();
        outbox
            .accept(
                &[
                    dispatch("d-12", "one", "a-room"),
                    dispatch("d-12", "two", "b-room"),
                    dispatch("d-12", "three", "c-room"),
                ],
                at(0),
            )
            .await
            .expect("an empty outbox");

        assert_eq!(outbox.due(at(0), 2).await.expect("asked").len(), 2);
    }

    // ---- what must never be printed --------------------------------------

    #[test]
    fn debug_counts_deliveries_and_prints_nothing_anybody_wrote() {
        // A Dispatch carries an Event, and an Event carries a commit message —
        // somebody else's words, which the rest of this codebase keeps out of
        // logs. Body prints its length for the same reason.
        let outbox = MemoryOutbox::new();

        assert_eq!(format!("{outbox:?}"), "MemoryOutbox(0 deliveries)");
    }

    #[tokio::test]
    async fn a_dispatch_in_the_outbox_does_not_print_what_somebody_wrote() {
        let outbox = MemoryOutbox::new();
        outbox
            .accept(
                &[dispatch(
                    "d-13",
                    "fix the thing nobody should read",
                    "a-room",
                )],
                at(0),
            )
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
        assert_eq!(
            format!("{StorageUnavailable}"),
            "the delivery store is unavailable"
        );
    }
}
