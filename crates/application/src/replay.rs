//! Sending a past Delivery again, because somebody asked.

use domain::{DeliveryId, Dispatch, Subscription, destinations_for};

use crate::ports::{Attempt, Clock, Dispatcher, Ids, Outbox};

/// What a replay did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Replayed {
    /// Destinations that were told again.
    pub reached: Vec<domain::DestinationId>,
    /// Destinations that could not be told, and will be tried again.
    pub failed: Vec<domain::DestinationId>,
}

/// Why a Delivery could not be replayed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unreplayable {
    /// Nothing was ever stored under that identity.
    ///
    /// Either it was never accepted, or it was accepted before this process
    /// kept anything — the in-memory outbox forgets at a restart, which is the
    /// usual reason an operator meets this.
    Unknown,
    /// The store could not be asked.
    StorageUnavailable,
}

impl core::fmt::Display for Unreplayable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unknown => write!(f, "nothing is stored under that delivery"),
            Self::StorageUnavailable => write!(f, "the delivery store is unavailable"),
        }
    }
}

/// Sends a past Delivery again.
///
/// Explicit, and never reached from the request path: a replay exists because a
/// person decided one was needed, after an outage or a bug in a renderer. The
/// only thing that may start one is somebody asking.
///
/// It re-routes rather than re-sending what was sent. The Events are what was
/// established when the Delivery was verified, and they do not change; who
/// should hear about them is a rule in a file that may well have changed since,
/// and the point of a replay is usually that it did. So the Destinations are
/// worked out again from the Subscriptions in force now.
pub struct Replay<'a> {
    dispatcher: &'a dyn Dispatcher,
    outbox: &'a dyn Outbox,
    clock: &'a dyn Clock,
    ids: &'a dyn Ids,
    subscriptions: &'a [Subscription],
}

impl<'a> Replay<'a> {
    /// Wires the use case to the outside world.
    #[must_use]
    pub fn new(
        dispatcher: &'a dyn Dispatcher,
        outbox: &'a dyn Outbox,
        clock: &'a dyn Clock,
        ids: &'a dyn Ids,
        subscriptions: &'a [Subscription],
    ) -> Self {
        Self {
            dispatcher,
            outbox,
            clock,
            ids,
            subscriptions,
        }
    }

    /// Sends everything this Delivery established, to whoever should hear it now.
    ///
    /// # Errors
    ///
    /// [`Unreplayable::Unknown`] if nothing is stored under that identity, and
    /// [`Unreplayable::StorageUnavailable`] if the store could not be asked. A
    /// Dispatch that fails to send is not an error: it is stored like any other
    /// and the worker comes back to it.
    pub async fn delivery(&self, delivery: &DeliveryId) -> Result<Replayed, Unreplayable> {
        let stored = self
            .outbox
            .accepted(delivery)
            .await
            .map_err(|_| Unreplayable::StorageUnavailable)?;

        if stored.is_empty() {
            return Err(Unreplayable::Unknown);
        }

        // What this Delivery established, each fact once. A Delivery fans out to
        // a Dispatch per Destination, so the same Event appears as many times as
        // it had rooms to go to.
        //
        // Recoverable only because every Event here reached at least one
        // Destination: one that matched no rule produced no Dispatch and was
        // never stored. So a replay can re-route a fact to rooms that did not
        // want it before, and cannot resurrect a fact that nobody wanted at all.
        // Stated rather than hidden, because it is the limit of what "uses the
        // current Subscriptions" can mean.
        let mut facts: Vec<&domain::Event> = Vec::new();
        for record in &stored {
            for event in record.dispatch().events() {
                if !facts.contains(&event) {
                    facts.push(event);
                }
            }
        }

        // Routed again, from the rules in force now rather than the ones in
        // force then. The Origin is the one that was verified when this arrived
        // and is stored beside the Dispatch — never one an operator typed,
        // because `origin` is the label every trustworthy rule is built on.
        let origin = stored[0].dispatch().origin().clone();

        // A new hop in the ORIGINAL chain, not a chain of its own. A replay
        // exists to send that delivery again, so an operator who follows the
        // trace from the room back ought to arrive at the push or the alert that
        // caused it -- months later, through a dispatch nobody kept a request
        // for. A fresh trace would make the replay look like something that
        // happened on its own.
        let correlation = self.ids.next_hop_in(stored[0].dispatch().correlation());

        // Grouped per Destination, exactly as the request path does, so a replay
        // arrives as one message per room rather than as the fan-out this
        // product stopped doing (gc-lhh).
        let mut grouped: Vec<(domain::Destination, Vec<domain::Event>)> = Vec::new();
        for event in &facts {
            for destination in destinations_for(&origin, event, self.subscriptions) {
                match grouped
                    .iter_mut()
                    .find(|(known, _)| known.id() == destination.id())
                {
                    Some((_, theirs)) => theirs.push((*event).clone()),
                    None => grouped.push((destination.clone(), vec![(*event).clone()])),
                }
            }
        }

        let planned: Vec<Dispatch> = grouped
            .into_iter()
            .filter_map(|(destination, theirs)| {
                Dispatch::new(
                    delivery.clone(),
                    origin.clone(),
                    theirs,
                    destination,
                    correlation.clone(),
                )
            })
            .collect();

        // Stored first, like any other Dispatch, so a replay that fails is
        // retried rather than lost — and so the new rows are distinguishable
        // from the originals, which keep their own identities and outcomes.
        let accepted = self
            .outbox
            .accept(&planned, self.clock.now())
            .await
            .map_err(|_| Unreplayable::StorageUnavailable)?;

        let mut replayed = Replayed::default();
        for record in &accepted {
            let dispatch = record.dispatch();
            let destination = dispatch.destination().id().clone();

            match self
                .dispatcher
                .dispatch(
                    dispatch.delivery(),
                    dispatch.events(),
                    dispatch.destination(),
                    Attempt::Replay,
                    dispatch.correlation(),
                )
                .await
            {
                Ok(()) => {
                    let _ = self.outbox.delivered(record.id(), self.clock.now()).await;
                    replayed.reached.push(destination);
                }
                Err(_) => replayed.failed.push(destination),
            }
        }

        Ok(replayed)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use domain::{
        BranchName, Commit, CommitId, Correlation, Destination, DestinationId, DestinationKind,
        DispatchId, Event, Filter, OriginId, Pusher, RepositoryName, Summary, Timestamp,
    };

    use super::{DeliveryId, Dispatch, Ids, Replay, Subscription, Unreplayable};
    use crate::ports::{
        Attempt, Clock, DispatchFailed, Dispatcher, Outbox, Outcome, Recorded, StorageUnavailable,
    };

    const NOW: i64 = 1_759_000_000_000;

    /// Mints the hop a replay makes, fixed so a test can name it.
    struct OneId;
    impl Ids for OneId {
        fn next_delivery_id(&self) -> DeliveryId {
            DeliveryId::new("d-replayed").expect("a non-blank identity")
        }

        fn next_correlation(&self) -> Correlation {
            Correlation::new("1111111111111111111111111111111b", "1111111111111111", None)
                .expect("a well formed correlation")
        }

        fn next_hop_in(&self, chain: &Correlation) -> Correlation {
            chain
                .continued_as("b7ad6b7169203331")
                .expect("a well formed span")
        }
    }

    struct FixedClock;
    impl Clock for FixedClock {
        fn now(&self) -> Timestamp {
            Timestamp::from_millis_since_epoch(NOW)
        }
    }

    /// Records where each call went, and how it was announced.
    #[derive(Default)]
    struct Recorder {
        sent: Mutex<Vec<(String, Attempt)>>,
    }

    #[async_trait]
    impl Dispatcher for Recorder {
        async fn dispatch(
            &self,
            _delivery: &DeliveryId,
            _events: &[Event],
            destination: &Destination,
            attempt: Attempt,
            _correlation: &Correlation,
        ) -> Result<(), DispatchFailed> {
            self.sent
                .lock()
                .expect("not poisoned")
                .push((destination.id().as_str().to_owned(), attempt));
            Ok(())
        }
    }

    /// An outbox holding what a test put in it, and keeping what it is given.
    struct Held {
        existing: Vec<Recorded>,
        accepted: Mutex<Vec<Dispatch>>,
    }

    impl Held {
        fn holding(existing: Vec<Recorded>) -> Self {
            Self {
                existing,
                accepted: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl Outbox for Held {
        async fn accept(
            &self,
            dispatches: &[Dispatch],
            at: Timestamp,
        ) -> Result<Vec<Recorded>, StorageUnavailable> {
            self.accepted
                .lock()
                .expect("not poisoned")
                .extend(dispatches.iter().cloned());
            Ok(dispatches
                .iter()
                .enumerate()
                .map(|(offset, dispatch)| {
                    Recorded::new(
                        DispatchId::new(&format!("r-{}", offset + 1)).expect("non-blank"),
                        dispatch.clone(),
                        0,
                        Outcome::Waiting { again_at: at },
                    )
                })
                .collect())
        }

        async fn accepted(
            &self,
            _delivery: &DeliveryId,
        ) -> Result<Vec<Recorded>, StorageUnavailable> {
            Ok(self.existing.clone())
        }

        async fn due(
            &self,
            _now: Timestamp,
            _limit: usize,
        ) -> Result<Vec<Recorded>, StorageUnavailable> {
            Ok(Vec::new())
        }

        async fn delivered(
            &self,
            _id: &DispatchId,
            _at: Timestamp,
        ) -> Result<(), StorageUnavailable> {
            Ok(())
        }

        async fn failed(
            &self,
            _id: &DispatchId,
            _at: Timestamp,
            _again_at: Timestamp,
        ) -> Result<(), StorageUnavailable> {
            Ok(())
        }

        async fn abandoned(
            &self,
            _id: &DispatchId,
            _at: Timestamp,
        ) -> Result<(), StorageUnavailable> {
            Ok(())
        }
    }

    fn a_push() -> Event {
        Event::PushedCommits {
            repository: RepositoryName::new("motrice/webhook-proxy").expect("a name"),
            branch: BranchName::new("main").expect("a name"),
            pusher: Pusher::new("bjornmolin").expect("a name"),
            commits: vec![Commit::new(
                CommitId::new("6113728f27ae").expect("an id"),
                Summary::new("a change").expect("a summary"),
            )],
            permalink: None,
        }
    }

    fn room(id: &str) -> Destination {
        Destination::new(
            DestinationId::new(id).expect("a non-blank id"),
            DestinationKind::ChatRoom,
        )
    }

    fn stored_to(rooms: &[&str]) -> Vec<Recorded> {
        rooms
            .iter()
            .enumerate()
            .map(|(offset, to)| {
                Recorded::new(
                    DispatchId::new(&format!("s-{}", offset + 1)).expect("non-blank"),
                    Dispatch::new(
                        DeliveryId::new("d-1").expect("a non-blank id"),
                        OriginId::new("github").expect("a non-blank id"),
                        vec![a_push()],
                        room(to),
                        Correlation::new(
                            "4bf92f3577b34da6a3ce929d0e0e4736",
                            "00f067aa0ba902b7",
                            None,
                        )
                        .expect("a well formed correlation"),
                    )
                    .expect("at least one event"),
                    1,
                    Outcome::Delivered {
                        at: Timestamp::from_millis_since_epoch(NOW),
                    },
                )
            })
            .collect()
    }

    /// A rule sending everything to these rooms.
    fn everything_to(rooms: &[&str]) -> Vec<Subscription> {
        rooms
            .iter()
            .map(|to| Subscription::new(room(to), Filter::Everything))
            .collect()
    }

    #[tokio::test]
    async fn a_stored_delivery_is_sent_again_and_says_that_it_was() {
        let dispatcher = Recorder::default();
        let outbox = Held::holding(stored_to(&["devsecops-room"]));
        let subscriptions = everything_to(&["devsecops-room"]);
        let replay = Replay::new(&dispatcher, &outbox, &FixedClock, &OneId, &subscriptions);

        let replayed = replay
            .delivery(&DeliveryId::new("d-1").expect("a non-blank id"))
            .await
            .expect("it is stored");

        assert_eq!(replayed.reached.len(), 1);
        assert_eq!(
            dispatcher.sent.lock().expect("not poisoned").as_slice(),
            &[("devsecops-room".to_owned(), Attempt::Replay)]
        );
    }

    #[tokio::test]
    async fn a_replay_uses_the_rules_in_force_now_and_not_the_ones_that_were() {
        // The criterion this bead turns on. A replay happens because something
        // was wrong — often the routing itself — so re-sending to exactly the
        // rooms that were chosen before would replay the mistake along with the
        // message.
        let dispatcher = Recorder::default();
        // It went to one room when it arrived.
        let outbox = Held::holding(stored_to(&["devsecops-room"]));
        // The rules say two rooms now, and no longer the first.
        let subscriptions = everything_to(&["platform-room", "audit-room"]);
        let replay = Replay::new(&dispatcher, &outbox, &FixedClock, &OneId, &subscriptions);

        replay
            .delivery(&DeliveryId::new("d-1").expect("a non-blank id"))
            .await
            .expect("it is stored");

        let sent: Vec<String> = dispatcher
            .sent
            .lock()
            .expect("not poisoned")
            .iter()
            .map(|(room, _)| room.clone())
            .collect();
        assert_eq!(sent, vec!["platform-room", "audit-room"]);
    }

    #[tokio::test]
    async fn a_fact_is_sent_once_per_room_however_many_rooms_it_reached_before() {
        // One Delivery fans out to a Dispatch per Destination, so the same Event
        // is stored as many times as it had rooms. Replaying each row would send
        // a room one copy per room it went to last time.
        let dispatcher = Recorder::default();
        let outbox = Held::holding(stored_to(&["a-room", "b-room", "c-room"]));
        let subscriptions = everything_to(&["only-room"]);
        let replay = Replay::new(&dispatcher, &outbox, &FixedClock, &OneId, &subscriptions);

        replay
            .delivery(&DeliveryId::new("d-1").expect("a non-blank id"))
            .await
            .expect("it is stored");

        assert_eq!(dispatcher.sent.lock().expect("not poisoned").len(), 1);
    }

    #[tokio::test]
    async fn a_replay_is_stored_like_anything_else_so_a_failure_survives() {
        let dispatcher = Recorder::default();
        let outbox = Held::holding(stored_to(&["devsecops-room"]));
        let subscriptions = everything_to(&["devsecops-room"]);
        let replay = Replay::new(&dispatcher, &outbox, &FixedClock, &OneId, &subscriptions);

        replay
            .delivery(&DeliveryId::new("d-1").expect("a non-blank id"))
            .await
            .expect("it is stored");

        // New rows, with their own identities: the originals keep theirs and
        // their outcomes, so the two are told apart in the store as well as in
        // the room.
        assert_eq!(outbox.accepted.lock().expect("not poisoned").len(), 1);
    }

    #[tokio::test]
    async fn an_identity_nothing_is_stored_under_is_refused_rather_than_ignored() {
        // An operator who mistypes an identity must not be told "done".
        let dispatcher = Recorder::default();
        let outbox = Held::holding(Vec::new());
        let subscriptions = everything_to(&["devsecops-room"]);
        let replay = Replay::new(&dispatcher, &outbox, &FixedClock, &OneId, &subscriptions);

        let outcome = replay
            .delivery(&DeliveryId::new("never").expect("a non-blank id"))
            .await;

        assert_eq!(outcome, Err(Unreplayable::Unknown));
        assert!(dispatcher.sent.lock().expect("not poisoned").is_empty());
    }

    #[tokio::test]
    async fn a_replay_that_now_matches_nothing_sends_nothing_and_says_so() {
        // Not an error: the rules changed and nobody wants this any more. The
        // operator sees that it reached nowhere, which is the truth.
        let dispatcher = Recorder::default();
        let outbox = Held::holding(stored_to(&["devsecops-room"]));
        let replay = Replay::new(&dispatcher, &outbox, &FixedClock, &OneId, &[]);

        let replayed = replay
            .delivery(&DeliveryId::new("d-1").expect("a non-blank id"))
            .await
            .expect("it is stored");

        assert!(replayed.reached.is_empty());
        assert!(dispatcher.sent.lock().expect("not poisoned").is_empty());
    }
}
