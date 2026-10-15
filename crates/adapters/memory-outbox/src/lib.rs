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

use application::ports::{
    Archive, Handover, Offered, Outbox, Outcome, Page, Recorded, StorageUnavailable, TenantId,
    Window,
};
use async_trait::async_trait;
use domain::{DeliveryId, DestinationId, Dispatch, DispatchId, Timestamp};

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
                // The acceptance moment is carried over rather than refreshed:
                // settling says what became of a Dispatch, not when it arrived.
                *record = Recorded::new(
                    id.clone(),
                    record.dispatch().clone(),
                    attempts,
                    outcome,
                    record.accepted_at(),
                );
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
                at,
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

/// Reads what the store holds, scoped to the rooms a caller may see.
///
/// The filtering lives here rather than in a caller because the port says so
/// (bead gc-mnn): an adapter that returned everything would make every caller
/// responsible for an authorisation decision, and one that forgot would leak
/// with no test to catch it.
#[async_trait]
impl Archive for MemoryOutbox {
    async fn arrived(
        &self,
        rooms: &[DestinationId],
        window: Window,
        page: &Page,
    ) -> Result<Vec<Recorded>, StorageUnavailable> {
        let held = self.held.lock().map_err(|_| StorageUnavailable)?;

        Ok(paged(
            held.records
                .iter()
                .filter(|record| visible(record, rooms))
                .filter(|record| within(record, window))
                .rev(),
            page,
        ))
    }

    async fn went(
        &self,
        delivery: &DeliveryId,
        rooms: &[DestinationId],
    ) -> Result<Vec<Recorded>, StorageUnavailable> {
        let held = self.held.lock().map_err(|_| StorageUnavailable)?;

        Ok(held
            .records
            .iter()
            .filter(|record| record.dispatch().delivery() == delivery)
            .filter(|record| visible(record, rooms))
            .cloned()
            .collect())
    }

    async fn waiting(
        &self,
        rooms: &[DestinationId],
        page: &Page,
    ) -> Result<Vec<Recorded>, StorageUnavailable> {
        let held = self.held.lock().map_err(|_| StorageUnavailable)?;

        Ok(paged(
            held.records
                .iter()
                .filter(|record| matches!(record.outcome(), Outcome::Waiting { .. }))
                .filter(|record| visible(record, rooms))
                .rev(),
            page,
        ))
    }
}

/// Whether a caller holding these rooms may see this record.
///
/// Identity text rather than the value, because a `DestinationId` is neither
/// `Hash` nor `Ord` by design — the same reason `Tally` keys on text.
fn visible(record: &Recorded, rooms: &[DestinationId]) -> bool {
    rooms
        .iter()
        .any(|room| room.as_str() == record.dispatch().destination().id().as_str())
}

/// Whether a record was accepted inside the window.
///
/// Accepted, not settled: a reader asking what arrived yesterday means what a
/// sender sent yesterday, not what this proxy finished with yesterday.
fn within(record: &Recorded, window: Window) -> bool {
    let at = record.accepted_at();

    window.from.is_none_or(|from| at >= from) && window.to.is_none_or(|to| at <= to)
}

/// Takes one page, starting after whatever the caller already has.
fn paged<'a>(records: impl Iterator<Item = &'a Recorded>, page: &Page) -> Vec<Recorded> {
    let mut seen_the_cursor = page.after.is_none();

    records
        .filter(|record| {
            if seen_the_cursor {
                return true;
            }
            // The cursor itself is not returned again; the page starts after it.
            seen_the_cursor = page
                .after
                .as_ref()
                .is_some_and(|after| after.as_str() == record.id().as_str());
            false
        })
        .take(page.limit)
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use domain::{
        BranchName, Commit, CommitId, Correlation, Destination, DestinationId, DestinationKind,
        Event, OriginId, Pusher, RepositoryName, Summary,
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
            vec![a_push(summary)],
            room(to),
            Correlation::new("4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7", None)
                .expect("a well formed correlation"),
        )
        .expect("at least one event")
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

#[cfg(test)]
mod archive_tests {
    use application::ports::{Archive, Outbox, Outcome, Page, Window};
    use domain::{
        BranchName, Commit, CommitId, Correlation, DeliveryId, Destination, DestinationId,
        DestinationKind, Dispatch, Event, OriginId, Pusher, RepositoryName, Summary, Timestamp,
    };

    use super::MemoryOutbox;

    fn at(millis: i64) -> Timestamp {
        Timestamp::from_millis_since_epoch(1_759_000_000_000 + millis)
    }

    fn rooms(ids: &[&str]) -> Vec<DestinationId> {
        ids.iter()
            .map(|id| DestinationId::new(id).expect("a non-blank identity"))
            .collect()
    }

    fn page(limit: usize) -> Page {
        Page { limit, after: None }
    }

    fn dispatch(delivery: &str, summary: &str, to: &str) -> Dispatch {
        Dispatch::new(
            DeliveryId::new(delivery).expect("a non-blank id"),
            OriginId::new("github").expect("a non-blank id"),
            vec![Event::PushedCommits {
                repository: RepositoryName::new("motrice/webhook-proxy").expect("a name"),
                branch: BranchName::new("main").expect("a name"),
                pusher: Pusher::new("bjornmolin").expect("a name"),
                commits: vec![Commit::new(
                    CommitId::new("6113728f27ae").expect("an id"),
                    Summary::new(summary).expect("a summary"),
                )],
                permalink: None,
            }],
            Destination::new(
                DestinationId::new(to).expect("a non-blank id"),
                DestinationKind::ChatRoom,
            ),
            Correlation::new("4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7", None)
                .expect("a well formed correlation"),
        )
        .expect("at least one event")
    }

    #[tokio::test]
    async fn a_reader_sees_only_the_rooms_it_was_given() {
        // Bead gc-mnn: a reader may see what the rooms named for it received.
        // The filtering is the port's, so this is the test that would catch an
        // implementation returning everything.
        let outbox = MemoryOutbox::new();
        outbox
            .accept(
                &[
                    dispatch("d-1", "for devsecops", "devsecops-room"),
                    dispatch("d-2", "for platform", "platform-room"),
                ],
                at(0),
            )
            .await
            .expect("available");

        let seen = outbox
            .arrived(&rooms(&["devsecops-room"]), Window::default(), &page(10))
            .await
            .expect("available");

        assert_eq!(seen.len(), 1);
        assert_eq!(
            seen[0].dispatch().destination().id().as_str(),
            "devsecops-room"
        );
    }

    #[tokio::test]
    async fn a_reader_with_no_rooms_sees_nothing_rather_than_everything() {
        // The direction that matters. An empty list is a reader with no entry in
        // the deployment's reader file, and the dangerous reading of "no filter"
        // is "no restriction".
        let outbox = MemoryOutbox::new();
        outbox
            .accept(&[dispatch("d-1", "a change", "devsecops-room")], at(0))
            .await
            .expect("available");

        assert!(
            outbox
                .arrived(&[], Window::default(), &page(10))
                .await
                .expect("available")
                .is_empty()
        );
        assert!(
            outbox
                .went(&DeliveryId::new("d-1").expect("a non-blank id"), &[])
                .await
                .expect("available")
                .is_empty()
        );
        assert!(
            outbox
                .waiting(&[], &page(10))
                .await
                .expect("available")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn what_arrived_comes_back_most_recent_first_and_one_page_at_a_time() {
        let outbox = MemoryOutbox::new();
        for (offset, summary) in ["first", "second", "third"].iter().enumerate() {
            outbox
                .accept(
                    &[dispatch(&format!("d-{offset}"), summary, "a-room")],
                    at(i64::try_from(offset).expect("small") * 1000),
                )
                .await
                .expect("available");
        }

        let first = outbox
            .arrived(&rooms(&["a-room"]), Window::default(), &page(2))
            .await
            .expect("available");
        assert_eq!(first.len(), 2, "a page is a page");

        let next = outbox
            .arrived(
                &rooms(&["a-room"]),
                Window::default(),
                &Page {
                    limit: 2,
                    after: Some(first[1].id().clone()),
                },
            )
            .await
            .expect("available");

        assert_eq!(next.len(), 1, "the rest of it");
        assert_ne!(
            next[0].id().as_str(),
            first[1].id().as_str(),
            "a page starts after the cursor, it does not repeat it"
        );
    }

    #[tokio::test]
    async fn a_window_asks_about_when_the_sender_sent_not_when_we_finished() {
        let outbox = MemoryOutbox::new();
        outbox
            .accept(&[dispatch("d-early", "early", "a-room")], at(0))
            .await
            .expect("available");
        outbox
            .accept(&[dispatch("d-late", "late", "a-room")], at(10_000))
            .await
            .expect("available");

        let early = outbox
            .arrived(
                &rooms(&["a-room"]),
                Window {
                    from: None,
                    to: Some(at(5_000)),
                },
                &page(10),
            )
            .await
            .expect("available");

        assert_eq!(early.len(), 1);
        assert_eq!(early[0].dispatch().delivery().as_str(), "d-early");
    }

    #[tokio::test]
    async fn what_is_still_owed_excludes_what_was_delivered() {
        let outbox = MemoryOutbox::new();
        let accepted = outbox
            .accept(
                &[
                    dispatch("d-1", "delivered", "a-room"),
                    dispatch("d-2", "still owed", "a-room"),
                ],
                at(0),
            )
            .await
            .expect("available");
        outbox
            .delivered(accepted[0].id(), at(1))
            .await
            .expect("available");

        let owed = outbox
            .waiting(&rooms(&["a-room"]), &page(10))
            .await
            .expect("available");

        assert_eq!(owed.len(), 1);
        assert_eq!(owed[0].dispatch().delivery().as_str(), "d-2");
        assert!(matches!(owed[0].outcome(), Outcome::Waiting { .. }));
    }

    #[tokio::test]
    async fn an_unknown_delivery_answers_empty_rather_than_erring() {
        // Retention is one month (gc-mnn), so "it was here last quarter" and "it
        // was never here" are the same answer. A reader must not be able to tell
        // a room it may not see from a delivery that does not exist.
        let outbox = MemoryOutbox::new();

        assert!(
            outbox
                .went(
                    &DeliveryId::new("never-accepted").expect("a non-blank id"),
                    &rooms(&["a-room"])
                )
                .await
                .expect("available")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn nothing_a_query_returns_can_carry_an_address_or_a_credential() {
        // Asserted rather than left to a reviewer, which is this bead's own
        // criterion. The absence is structural -- a Destination is a name with no
        // address and the request body is never stored -- so this is the test
        // that fails if somebody makes it otherwise.
        let outbox = MemoryOutbox::new();
        outbox
            .accept(&[dispatch("d-1", "a change", "devsecops-room")], at(0))
            .await
            .expect("available");

        let seen = outbox
            .arrived(&rooms(&["devsecops-room"]), Window::default(), &page(10))
            .await
            .expect("available");
        let printed = format!("{seen:?}");

        // A positive oracle first, because the assertions below are absences and
        // an empty answer would satisfy every one of them. This is the mistake
        // gc-ast.13's secrets-dir test made: it passed with the variable
        // misspelled, because nothing and the wrong thing looked the same.
        assert_eq!(seen.len(), 1, "nothing to inspect, so nothing is proved");
        assert!(
            printed.contains("devsecops-room"),
            "the room's NAME is expected and present; it is its address that must not be"
        );

        // The shapes a leak would take: the room's webhook URL, the secret NAME
        // the routing file uses for it, a bearer token, a connection string.
        for forbidden in [
            "http://",
            "https://",
            "devsecops-room-url",
            "Bearer",
            "postgres://",
        ] {
            assert!(
                !printed.contains(forbidden),
                "a query answer carries {forbidden:?}: {printed}"
            );
        }
    }
}

/// Deliveries held for their tenants, in memory.
///
/// A second store beside [`MemoryOutbox`] rather than a column on it, because
/// [`Handover`] holds a different unit — a Delivery, not a Dispatch — and owes
/// it to somebody else. See the port for why the platform cannot store a
/// Dispatch for work a tenant routes.
///
/// IN THIS CRATE DESPITE ITS NAME, and the Postgres side is the reason. An
/// adapter may not depend on another adapter, so a separate handover crate
/// could not share `postgres-outbox`'s connection pool or its migrations — and
/// two pools against one database is a worse thing to own than one slightly
/// misnamed crate. The in-memory side follows the same shape so the two
/// implementations of the port stay comparable.
#[derive(Default)]
pub struct MemoryHandover {
    /// In the order offered, which is the order it should be collected in.
    offered: Mutex<Vec<Offered>>,
}

impl MemoryHandover {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many Deliveries are outstanding, across every tenant.
    ///
    /// For a test and for a count; not a way around the port's tenant scoping,
    /// which is why it answers a number and never a record.
    #[must_use]
    pub fn held(&self) -> usize {
        self.offered.lock().map_or(0, |offered| offered.len())
    }
}

/// Counts, never contents — an `Offered` carries Events, which are other
/// people's words.
impl core::fmt::Debug for MemoryHandover {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MemoryHandover({} outstanding)", self.held())
    }
}

#[async_trait]
impl Handover for MemoryHandover {
    async fn offer(&self, offered: &Offered) -> Result<(), StorageUnavailable> {
        let mut held = self.offered.lock().map_err(|_| StorageUnavailable)?;
        held.push(offered.clone());
        Ok(())
    }

    async fn outstanding(
        &self,
        tenant: &TenantId,
        limit: usize,
    ) -> Result<Vec<Offered>, StorageUnavailable> {
        let held = self.offered.lock().map_err(|_| StorageUnavailable)?;
        Ok(held
            .iter()
            .filter(|offered| offered.tenant() == tenant)
            .take(limit)
            .cloned()
            .collect())
    }
}

#[cfg(test)]
mod handover_tests {
    use application::ports::{Handover, Offered, TenantId};
    use domain::{
        BranchName, Correlation, DeliveryId, Event, OriginId, Pusher, RepositoryName, Timestamp,
    };

    use super::MemoryHandover;

    fn at(millis: i64) -> Timestamp {
        Timestamp::from_millis_since_epoch(1_759_000_000_000 + millis)
    }

    fn tenant(id: &str) -> TenantId {
        TenantId::new(id).expect("a namespace name")
    }

    fn offered(delivery: &str, whose: &str, when: i64) -> Offered {
        Offered::new(
            DeliveryId::new(delivery).expect("a non-blank id"),
            tenant(whose),
            OriginId::new("alertmanager").expect("a non-blank id"),
            vec![Event::PushedCommits {
                repository: RepositoryName::new("motrice/webhook-proxy").expect("a name"),
                branch: BranchName::new("main").expect("a name"),
                pusher: Pusher::new("bjornmolin").expect("a name"),
                commits: vec![],
                permalink: None,
            }],
            Correlation::new("4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7", None)
                .expect("a well formed correlation"),
            at(when),
        )
        .expect("at least one event")
    }

    #[tokio::test]
    async fn a_tenant_is_offered_only_its_own() {
        // THE PROPERTY THE WHOLE SPLIT EXISTS FOR, at the lowest level it can be
        // stated. gc-wcw.2 proves it again over HTTP against a caller's
        // identity; this proves the store itself does not hand one tenant
        // another's work, so a leak there cannot be blamed on the endpoint.
        let store = MemoryHandover::new();
        store
            .offer(&offered("d-1", "wallet-lab-prod", 1))
            .await
            .expect("stored");
        store
            .offer(&offered("d-2", "wallet-hsm-prod", 2))
            .await
            .expect("stored");

        let theirs = store
            .outstanding(&tenant("wallet-lab-prod"), 10)
            .await
            .expect("asked");

        assert_eq!(theirs.len(), 1, "one tenant's work came back as two");
        assert_eq!(theirs[0].delivery().as_str(), "d-1");
        assert_eq!(theirs[0].tenant().as_str(), "wallet-lab-prod");
        // And the positive oracle, so this cannot pass by returning nothing:
        // the store does hold the other one, for the other tenant.
        assert_eq!(store.held(), 2);
        assert_eq!(
            store
                .outstanding(&tenant("wallet-hsm-prod"), 10)
                .await
                .expect("asked")
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn a_tenant_with_nothing_outstanding_is_not_an_error() {
        // A tenant whose agent has kept up looks exactly like a tenant that
        // does not exist, and must: this port is asked by an authenticated
        // caller, and a distinguishable answer would say whether another
        // namespace is a tenant here.
        let store = MemoryHandover::new();
        store
            .offer(&offered("d-1", "wallet-lab-prod", 1))
            .await
            .expect("stored");

        assert!(
            store
                .outstanding(&tenant("wallet-hsm-prod"), 10)
                .await
                .expect("asked")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn the_oldest_is_offered_first_and_no_more_than_asked_for() {
        // Oldest first because that is the order it should be collected in; and
        // bounded, because this queue grows without limit precisely when nobody
        // is collecting, which is the case it has to survive being asked about.
        let store = MemoryHandover::new();
        for (id, when) in [("d-1", 1), ("d-2", 2), ("d-3", 3)] {
            store
                .offer(&offered(id, "wallet-lab-prod", when))
                .await
                .expect("stored");
        }

        let first_two = store
            .outstanding(&tenant("wallet-lab-prod"), 2)
            .await
            .expect("asked");

        assert_eq!(
            first_two
                .iter()
                .map(|o| o.delivery().as_str().to_owned())
                .collect::<Vec<_>>(),
            vec!["d-1", "d-2"]
        );
    }

    #[tokio::test]
    async fn nothing_is_lost_between_being_offered_and_being_read_back() {
        // The Events arrive together, which is what gc-smz's grouping needs, and
        // the correlation arrives with them, which is what keeps a room message
        // traceable back to the sender's push across the hand-off.
        let store = MemoryHandover::new();
        let one = offered("d-1", "wallet-lab-prod", 1);
        store.offer(&one).await.expect("stored");

        let read_back = store
            .outstanding(&tenant("wallet-lab-prod"), 10)
            .await
            .expect("asked");

        assert_eq!(read_back, vec![one]);
    }
}
