//! A tenant's agent delivering what it claimed, and saying what became of it.
//!
//! The agent's whole loop: claim, route by the tenant's own rules, deliver to
//! each room with a bounded budget, report terminally. Bead gc-72e.2.
//!
//! WHY `Retries` DOES NOT TRANSFER. That worker drives a loop over an
//! [`Outbox`](crate::ports::Outbox): it asks the store what is due, attempts
//! it, and hands the outcome back for the store to remember. An agent has no
//! store — it is stateless by design (bead gc-g9x) — so its budget is spent
//! inside one claim, between being handed the work and reporting on it. What
//! does transfer unchanged is [`Retry`], the policy: how long to wait and how
//! many times. The difference between a policy and the loop that runs it is
//! exactly the seam this file sits on.
//!
//! THE GROUPING MOVED HERE FROM `Relay`. Routing leaves the platform (bead
//! gc-g9x), so the arrangement of Events into one message per room arrives
//! with it. Until bead gc-72e.3 both copies exist, which is deliberate and
//! temporary: the platform is still delivering, and deleting its copy before
//! anything replaced it would have stopped every room hearing anything.

use core::time::Duration;

use domain::{
    Correlation, DeliveryId, Destination, DestinationId, Event, Subscription, destinations_for,
};

use crate::Retry;
use crate::ports::{
    Acknowledged, Attempt, Clock, DispatchFailed, Dispatcher, Ids, Offers, Owed, Pause, Report,
    RoomOutcome, Unreachable,
};

/// What one pass did.
///
/// Returned rather than logged, because what counts and what writes a line is
/// the composition root's business — the same division `Retries` and `Retention`
/// already follow.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Delivered {
    /// Rooms that were told, as (delivery, room).
    pub reached: Vec<(DeliveryId, DestinationId)>,
    /// Rooms that were never told, with the last reason and how many attempts
    /// it took to give up. EVERY ONE OF THESE IS A LOSS, and in this version
    /// the line the agent writes about it is the only way anybody finds out.
    pub lost: Vec<(DeliveryId, DestinationId, DispatchFailed, u32)>,
    /// Deliveries whose rules matched no room at all. Not losses: a tenant may
    /// genuinely not want something, and saying so is what keeps the platform's
    /// queue draining (bead gc-g9x).
    pub routed_to_nothing: Vec<DeliveryId>,
    /// Deliveries delivered but not acknowledged, because the platform could
    /// not be told or no longer held them. These will be offered again, and the
    /// rooms already reached will see a duplicate — the regression bead gc-81d
    /// accepted knowingly.
    pub unreported: Vec<DeliveryId>,
    /// Deliveries abandoned mid-way because the lease lapsed first.
    ///
    /// Deliberately not reported: once the lease is gone the Delivery may be
    /// somebody else's, and a report then could discharge work another agent is
    /// still doing.
    pub lapsed: Vec<DeliveryId>,
}

impl Delivered {
    /// Whether there is anything worth saying.
    #[must_use]
    pub fn quiet(&self) -> bool {
        self.reached.is_empty()
            && self.lost.is_empty()
            && self.routed_to_nothing.is_empty()
            && self.unreported.is_empty()
            && self.lapsed.is_empty()
    }
}

/// The agent's loop.
pub struct Deliver<'a> {
    platform: &'a dyn Offers,
    dispatcher: &'a dyn Dispatcher,
    clock: &'a dyn Clock,
    ids: &'a dyn Ids,
    pause: &'a dyn Pause,
    /// The tenant's own rules, from the tenant's own repository.
    subscriptions: &'a [Subscription],
    retry: Retry,
}

impl<'a> Deliver<'a> {
    /// Wires the agent to the outside world.
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "the composition root's job is to name every collaborator once; \
                  grouping them into a struct would move the list rather than shorten it"
    )]
    pub fn new(
        platform: &'a dyn Offers,
        dispatcher: &'a dyn Dispatcher,
        clock: &'a dyn Clock,
        ids: &'a dyn Ids,
        pause: &'a dyn Pause,
        subscriptions: &'a [Subscription],
        retry: Retry,
    ) -> Self {
        Self {
            platform,
            dispatcher,
            clock,
            ids,
            pause,
            subscriptions,
            retry,
        }
    }

    /// Claim what is owed, deliver it, and report.
    ///
    /// # Errors
    ///
    /// [`Unreachable`] only when the claim itself failed, so nothing was
    /// started. A platform that goes away mid-pass leaves the Deliveries it
    /// already handed over in `unreported`, which is a loss of the *record*
    /// rather than of the message.
    pub async fn once(&self) -> Result<Delivered, Unreachable> {
        let claimed = self.platform.claim().await?;
        let mut done = Delivered::default();

        for one in &claimed {
            self.one(one, &mut done).await;
        }

        Ok(done)
    }

    /// Deliver one claimed Delivery, and report on it.
    async fn one(&self, owed: &Owed, done: &mut Delivered) {
        let delivery = owed.delivery().clone();

        let grouped = self.grouped(owed.origin(), owed.events());

        // Terminal and not an error. Without this the platform's queue never
        // drains and a tenant whose rules match nothing looks exactly like a
        // tenant whose agent has died (bead gc-g9x).
        if grouped.is_empty() {
            done.routed_to_nothing.push(delivery.clone());
            self.discharge(&delivery, &Report::RoutedToNothing, done)
                .await;
            return;
        }

        let mut outcomes = Vec::with_capacity(grouped.len());
        for (destination, events) in grouped {
            // Checked before each room rather than once, because the budget is
            // spent between rooms as well as within one.
            if self.clock.now().millis_since_epoch() >= owed.lease_until().millis_since_epoch() {
                done.lapsed.push(delivery.clone());
                return;
            }

            match self
                .attempted(
                    &delivery,
                    &events,
                    &destination,
                    owed.correlation(),
                    owed.replayed(),
                )
                .await
            {
                Ok(()) => {
                    done.reached
                        .push((delivery.clone(), destination.id().clone()));
                    outcomes.push((destination.id().clone(), RoomOutcome::Delivered));
                }
                Err((why, spent)) => {
                    done.lost
                        .push((delivery.clone(), destination.id().clone(), why, spent));
                    outcomes.push((destination.id().clone(), RoomOutcome::Abandoned));
                }
            }
        }

        self.discharge(&delivery, &Report::Reached(outcomes), done)
            .await;
    }

    /// One room, up to the budget.
    ///
    /// Returns the last reason and the attempts spent, so a loss can be
    /// reported against something nameable rather than as a number.
    async fn attempted(
        &self,
        delivery: &DeliveryId,
        events: &[Event],
        destination: &Destination,
        chain: &Correlation,
        replayed: bool,
    ) -> Result<(), (DispatchFailed, u32)> {
        let mut failures = 0_u32;
        loop {
            // A NEW HOP PER ATTEMPT, from the chain the claim arrived on rather
            // than a fresh one. That is what makes a room message traceable
            // back through this agent and the platform to the sender's push —
            // and with no read API, that chain is the whole diagnostic story
            // (bead gc-g9x).
            let hop = self.ids.next_hop_in(chain);

            // `First` even on a retry: a retry is the same message arriving
            // late and nobody has seen it, so marking it would be noise in an
            // alert channel. Only a replay somebody ASKED FOR is marked, and
            // whether this is one is the platform's knowledge rather than a
            // guess made here (bead gc-6a5.3).
            let attempt = if replayed {
                Attempt::Replay
            } else {
                Attempt::First
            };
            match self
                .dispatcher
                .dispatch(delivery, events, destination, attempt, &hop)
                .await
            {
                Ok(()) => return Ok(()),
                Err(why) => {
                    failures += 1;
                    match self.retry.again_after(failures) {
                        Some(wait) => self.pause.rest(wait).await,
                        None => return Err((why, failures)),
                    }
                }
            }
        }
    }

    /// Tell the platform, and record what it said.
    async fn discharge(&self, delivery: &DeliveryId, report: &Report, done: &mut Delivered) {
        match self.platform.report(delivery, report).await {
            Ok(Acknowledged::Recorded) => {}
            // Both of these mean the same thing to the rooms: they were told.
            // What is lost is the record, so the Delivery comes back when the
            // lease lapses and a room sees it twice.
            Ok(Acknowledged::NotOutstanding) | Err(Unreachable) => {
                done.unreported.push(delivery.clone());
            }
        }
    }

    /// The Events of one Delivery, arranged as one message per room.
    ///
    /// PER DESTINATION, NOT PER EVENT. A sender that grouped twenty alerts into
    /// one notification meant a room to get one message, and fanning them out
    /// again would undo a decision it made deliberately (bead gc-lhh). Nothing
    /// in the platform's API would notice if this were wrong, which is why it
    /// has a test of its own.
    ///
    /// Destinations in the order they were first selected, and Events within
    /// one in the order the sender reported them: a reader comparing two
    /// incidents should not find the same facts in a different arrangement.
    fn grouped(
        &self,
        origin: &domain::OriginId,
        events: &[Event],
    ) -> Vec<(Destination, Vec<Event>)> {
        let mut grouped: Vec<(Destination, Vec<Event>)> = Vec::new();
        for event in events {
            for destination in destinations_for(origin, event, self.subscriptions) {
                match grouped
                    .iter_mut()
                    .find(|(known, _)| known.id() == destination.id())
                {
                    Some((_, theirs)) => theirs.push(event.clone()),
                    None => grouped.push((destination.clone(), vec![event.clone()])),
                }
            }
        }
        grouped
    }
}

/// How long a pass should wait before asking again when there was nothing.
///
/// Here rather than in the composition root because it is the other half of the
/// same policy: an agent that claimed nothing has nothing to wait for except
/// the next alert, and a tight loop against the platform would be a denial of
/// service written by the thing being served.
#[must_use]
pub const fn idle_for() -> Duration {
    Duration::from_secs(5)
}

#[cfg(test)]
mod tests {
    use core::time::Duration;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use domain::{
        BranchName, Commit, CommitId, Correlation, DeliveryId, Destination, DestinationId,
        DestinationKind, Event, Filter, LabelName, LabelValue, Labels, OriginId, Pusher,
        RepositoryName, Subscription, Summary, Timestamp,
    };

    use super::Deliver;
    use crate::Retry;
    use crate::ports::{
        Acknowledged, Attempt, Clock, DispatchFailed, Dispatcher, Ids, Offers, Owed, Pause, Report,
        RoomOutcome, Unreachable,
    };

    fn at(millis: i64) -> Timestamp {
        Timestamp::from_millis_since_epoch(millis)
    }

    /// A clock a test can step. The lease matters, so time has to be a value.
    struct Ticking(Mutex<i64>);
    impl Clock for Ticking {
        fn now(&self) -> Timestamp {
            at(*self.0.lock().expect("not poisoned"))
        }
    }

    /// Hops that say which chain they came from, so a test can tell a
    /// continuation from a fresh chain.
    struct Hops;
    impl Ids for Hops {
        fn next_delivery_id(&self) -> DeliveryId {
            unreachable!("an agent names no delivery")
        }
        fn next_correlation(&self) -> Correlation {
            unreachable!("an agent starts no chain: it continues the one it claimed")
        }
        fn next_hop_in(&self, chain: &Correlation) -> Correlation {
            // Same trace, a different span. That is what a hop is.
            Correlation::new(chain.trace(), "00f067aa0ba90299", chain.state())
                .expect("a well formed hop")
        }
    }

    /// Never waits, so a thirty-one second budget is a fast test.
    struct NoWait(Mutex<Vec<Duration>>);
    #[async_trait]
    impl Pause for NoWait {
        async fn rest(&self, how_long: Duration) {
            self.0.lock().expect("not poisoned").push(how_long);
        }
    }

    fn room(id: &str) -> Destination {
        Destination::new(
            DestinationId::new(id).expect("an identity"),
            DestinationKind::ChatRoom,
        )
    }

    fn everything_to(ids: &[&str]) -> Vec<Subscription> {
        ids.iter()
            .map(|id| Subscription::new(room(id), Filter::Everything))
            .collect()
    }

    fn a_push(summary: &str) -> Event {
        Event::PushedCommits {
            repository: RepositoryName::new("motrice/webhook-proxy").expect("a name"),
            branch: BranchName::new("main").expect("a name"),
            pusher: Pusher::new("bjorn").expect("a name"),
            commits: vec![Commit::new(
                CommitId::new("6113728f27ae").expect("an id"),
                Summary::new(summary).expect("a summary"),
            )],
            permalink: None,
        }
    }

    fn claimed(delivery: &str, events: Vec<Event>, until: i64) -> Owed {
        offered_as(delivery, events, until, false)
    }

    fn offered_as(delivery: &str, events: Vec<Event>, until: i64, replayed: bool) -> Owed {
        Owed::new(
            DeliveryId::new(delivery).expect("an identity"),
            OriginId::new("alertmanager-a-tenant").expect("an identity"),
            events,
            Correlation::new("4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7", None)
                .expect("a chain"),
            at(0),
            at(until),
            replayed,
        )
        .expect("at least one event")
    }

    /// A platform a test can watch, and can make unreachable.
    struct Platform {
        offering: Mutex<Vec<Owed>>,
        reported: Mutex<Vec<(String, Report)>>,
        answers: Acknowledged,
        reachable: bool,
    }

    impl Platform {
        fn offering(claimed: Vec<Owed>) -> Self {
            Self {
                offering: Mutex::new(claimed),
                reported: Mutex::new(Vec::new()),
                answers: Acknowledged::Recorded,
                reachable: true,
            }
        }

        fn reported(&self) -> Vec<(String, Report)> {
            self.reported.lock().expect("not poisoned").clone()
        }
    }

    #[async_trait]
    impl Offers for Platform {
        async fn claim(&self) -> Result<Vec<Owed>, Unreachable> {
            if !self.reachable {
                return Err(Unreachable);
            }
            Ok(core::mem::take(
                &mut *self.offering.lock().expect("not poisoned"),
            ))
        }

        async fn report(
            &self,
            delivery: &DeliveryId,
            report: &Report,
        ) -> Result<Acknowledged, Unreachable> {
            if !self.reachable {
                return Err(Unreachable);
            }
            self.reported
                .lock()
                .expect("not poisoned")
                .push((delivery.as_str().to_owned(), report.clone()));
            Ok(self.answers)
        }
    }

    /// A dispatcher that records what it was sent and can be made to fail.
    struct Rooms {
        sent: Mutex<Vec<(String, usize, String, Attempt)>>,
        failing: Vec<&'static str>,
    }

    impl Rooms {
        fn new(failing: Vec<&'static str>) -> Self {
            Self {
                sent: Mutex::new(Vec::new()),
                failing,
            }
        }

        /// Each call, as (room, how many events, the span it carried).
        fn sent(&self) -> Vec<(String, usize, String, Attempt)> {
            self.sent.lock().expect("not poisoned").clone()
        }
    }

    #[async_trait]
    impl Dispatcher for Rooms {
        async fn dispatch(
            &self,
            _delivery: &DeliveryId,
            events: &[Event],
            destination: &Destination,
            attempt: Attempt,
            correlation: &Correlation,
        ) -> Result<(), DispatchFailed> {
            let id = destination.id().as_str().to_owned();
            self.sent.lock().expect("not poisoned").push((
                id.clone(),
                events.len(),
                correlation.span().to_owned(),
                attempt,
            ));
            if self.failing.contains(&id.as_str()) {
                return Err(DispatchFailed::Rejected);
            }
            Ok(())
        }
    }

    /// Five attempts, a second doubling to a thirty-second cap: the budget the
    /// deployment actually configures.
    fn budget() -> Retry {
        Retry::new(Duration::from_secs(1), Duration::from_secs(30), 5)
    }

    #[tokio::test]
    async fn the_events_of_one_delivery_reach_a_room_as_one_message() {
        // gc-smz's grouping, which the API cannot protect. The platform hands
        // over three Events together; a room gets ONE message carrying three,
        // not three messages. Nothing on the wire would notice the difference,
        // which is why this test exists rather than a review.
        let platform = Platform::offering(vec![claimed(
            "d-1",
            vec![a_push("first"), a_push("second"), a_push("third")],
            60_000,
        )]);
        let rooms = Rooms::new(vec![]);
        let subscriptions = everything_to(&["team-room"]);
        let clock = Ticking(Mutex::new(0));
        let waited = NoWait(Mutex::new(Vec::new()));
        let deliver = Deliver::new(
            &platform,
            &rooms,
            &clock,
            &Hops,
            &waited,
            &subscriptions,
            budget(),
        );

        let done = deliver.once().await.expect("the platform answered");

        assert_eq!(rooms.sent().len(), 1, "{:?}", rooms.sent());
        assert_eq!(rooms.sent()[0].1, 3, "the grouping was undone");
        assert_eq!(done.reached.len(), 1);
        assert!(done.lost.is_empty());
    }

    #[tokio::test]
    async fn each_room_is_told_once_and_the_report_names_them_all() {
        let platform = Platform::offering(vec![claimed("d-1", vec![a_push("x")], 60_000)]);
        let rooms = Rooms::new(vec![]);
        let subscriptions = everything_to(&["team-room", "oncall-room"]);
        let clock = Ticking(Mutex::new(0));
        let waited = NoWait(Mutex::new(Vec::new()));
        let deliver = Deliver::new(
            &platform,
            &rooms,
            &clock,
            &Hops,
            &waited,
            &subscriptions,
            budget(),
        );

        deliver.once().await.expect("the platform answered");

        let sent: Vec<String> = rooms
            .sent()
            .into_iter()
            .map(|(room, _, _, _)| room)
            .collect();
        assert_eq!(sent, vec!["team-room", "oncall-room"]);

        let reported = platform.reported();
        assert_eq!(reported.len(), 1);
        assert_eq!(
            reported[0].1,
            Report::Reached(vec![
                (
                    DestinationId::new("team-room").expect("an identity"),
                    RoomOutcome::Delivered
                ),
                (
                    DestinationId::new("oncall-room").expect("an identity"),
                    RoomOutcome::Delivered
                ),
            ])
        );
    }

    #[tokio::test]
    async fn a_delivery_matching_no_room_is_reported_as_routed_to_nothing() {
        // The report that keeps the platform's queue draining. A tenant whose
        // rules match nothing has nothing to say about rooms, and staying
        // silent would make it indistinguishable from a tenant whose agent has
        // died (gc-g9x).
        let platform = Platform::offering(vec![claimed("d-1", vec![a_push("x")], 60_000)]);
        let rooms = Rooms::new(vec![]);
        let subscriptions = vec![Subscription::new(
            room("elsewhere"),
            // A label no push can carry.
            Filter::Labelled(Labels::none().with(
                LabelName::new("severity").expect("a name"),
                LabelValue::new("critical").expect("a value"),
            )),
        )];
        let clock = Ticking(Mutex::new(0));
        let waited = NoWait(Mutex::new(Vec::new()));
        let deliver = Deliver::new(
            &platform,
            &rooms,
            &clock,
            &Hops,
            &waited,
            &subscriptions,
            budget(),
        );

        let done = deliver.once().await.expect("the platform answered");

        assert!(rooms.sent().is_empty(), "something was sent to nobody");
        assert_eq!(done.routed_to_nothing.len(), 1);
        assert_eq!(platform.reported()[0].1, Report::RoutedToNothing);
    }

    #[tokio::test]
    async fn a_room_that_never_accepts_is_abandoned_within_the_budget_and_reported() {
        // The loss, and the only way anybody learns a room never got something
        // in a version with no read API. The budget is spent in process,
        // because the agent has no store to come back to it from.
        let platform = Platform::offering(vec![claimed("d-1", vec![a_push("x")], 600_000)]);
        let rooms = Rooms::new(vec!["team-room"]);
        let subscriptions = everything_to(&["team-room"]);
        let clock = Ticking(Mutex::new(0));
        let waited = NoWait(Mutex::new(Vec::new()));
        let deliver = Deliver::new(
            &platform,
            &rooms,
            &clock,
            &Hops,
            &waited,
            &subscriptions,
            budget(),
        );

        let done = deliver.once().await.expect("the platform answered");

        assert_eq!(rooms.sent().len(), 5, "the budget was not five attempts");
        assert_eq!(
            waited.0.lock().expect("not poisoned").as_slice(),
            [
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_secs(4),
                Duration::from_secs(8),
            ],
            "the backoff is not the policy's"
        );
        assert_eq!(done.lost.len(), 1);
        assert_eq!(done.lost[0].1.as_str(), "team-room");
        assert_eq!(done.lost[0].3, 5, "the loss does not say what it cost");
        // Reported as abandoned rather than withheld: the platform's obligation
        // is discharged, and the loss is this agent's to log.
        assert_eq!(
            platform.reported()[0].1,
            Report::Reached(vec![(
                DestinationId::new("team-room").expect("an identity"),
                RoomOutcome::Abandoned
            )])
        );
    }

    #[tokio::test]
    async fn every_attempt_continues_the_chain_it_claimed() {
        // What makes a room message traceable back through two services to the
        // sender's push. The trace is the claim's; the span is this agent's.
        let platform = Platform::offering(vec![claimed("d-1", vec![a_push("x")], 60_000)]);
        let rooms = Rooms::new(vec![]);
        let subscriptions = everything_to(&["team-room"]);
        let clock = Ticking(Mutex::new(0));
        let waited = NoWait(Mutex::new(Vec::new()));
        let deliver = Deliver::new(
            &platform,
            &rooms,
            &clock,
            &Hops,
            &waited,
            &subscriptions,
            budget(),
        );

        deliver.once().await.expect("the platform answered");

        // A different span from the one claimed, which is what a hop is: the
        // call this agent made is not the call the sender made.
        assert_eq!(rooms.sent()[0].2, "00f067aa0ba90299");
        // And an ordinary delivery is not marked as a replay.
        assert_eq!(rooms.sent()[0].3, Attempt::First);
    }

    #[tokio::test]
    async fn an_agent_whose_lease_lapsed_stops_and_does_not_report() {
        // The lease is the platform's and is not renewable (gc-81d). Once it is
        // gone the Delivery may be somebody else's, so reporting could
        // discharge work another agent is still doing. Stopping leaves the
        // already-reached room a duplicate, which is the regression gc-81d
        // accepted knowingly — and the lesser of the two.
        let platform = Platform::offering(vec![claimed("d-1", vec![a_push("x")], 10)]);
        let rooms = Rooms::new(vec![]);
        let subscriptions = everything_to(&["team-room"]);
        // Already past the expiry when the pass begins.
        let clock = Ticking(Mutex::new(11));
        let waited = NoWait(Mutex::new(Vec::new()));
        let deliver = Deliver::new(
            &platform,
            &rooms,
            &clock,
            &Hops,
            &waited,
            &subscriptions,
            budget(),
        );

        let done = deliver.once().await.expect("the platform answered");

        assert!(
            rooms.sent().is_empty(),
            "a lapsed claim was still delivered"
        );
        assert_eq!(done.lapsed, vec![DeliveryId::new("d-1").expect("an id")]);
        assert!(
            platform.reported().is_empty(),
            "a lapsed claim was reported, which could discharge another agent's work"
        );
    }

    #[tokio::test]
    async fn a_report_the_platform_no_longer_wants_is_not_an_error() {
        // The likeliest cause is that this agent's lease lapsed while it was
        // delivering and somebody else has since discharged the Delivery.
        // Retrying a report that will never be accepted would be the wrong
        // reaction; recording it so the duplicate is explainable is the right
        // one.
        let mut platform = Platform::offering(vec![claimed("d-1", vec![a_push("x")], 60_000)]);
        platform.answers = Acknowledged::NotOutstanding;
        let rooms = Rooms::new(vec![]);
        let subscriptions = everything_to(&["team-room"]);
        let clock = Ticking(Mutex::new(0));
        let waited = NoWait(Mutex::new(Vec::new()));
        let deliver = Deliver::new(
            &platform,
            &rooms,
            &clock,
            &Hops,
            &waited,
            &subscriptions,
            budget(),
        );

        let done = deliver.once().await.expect("the platform answered");

        assert_eq!(done.reached.len(), 1, "the room was still told");
        assert_eq!(
            done.unreported,
            vec![DeliveryId::new("d-1").expect("an id")]
        );
    }

    #[tokio::test]
    async fn a_platform_that_cannot_be_reached_delivers_nothing_and_says_so() {
        let mut platform = Platform::offering(vec![claimed("d-1", vec![a_push("x")], 60_000)]);
        platform.reachable = false;
        let rooms = Rooms::new(vec![]);
        let subscriptions = everything_to(&["team-room"]);
        let clock = Ticking(Mutex::new(0));
        let waited = NoWait(Mutex::new(Vec::new()));
        let deliver = Deliver::new(
            &platform,
            &rooms,
            &clock,
            &Hops,
            &waited,
            &subscriptions,
            budget(),
        );

        assert_eq!(deliver.once().await, Err(Unreachable));
        assert!(rooms.sent().is_empty());
    }

    #[tokio::test]
    async fn a_pass_with_nothing_offered_has_nothing_to_say() {
        let platform = Platform::offering(vec![]);
        let rooms = Rooms::new(vec![]);
        let subscriptions = everything_to(&["team-room"]);
        let clock = Ticking(Mutex::new(0));
        let waited = NoWait(Mutex::new(Vec::new()));
        let deliver = Deliver::new(
            &platform,
            &rooms,
            &clock,
            &Hops,
            &waited,
            &subscriptions,
            budget(),
        );

        assert!(deliver.once().await.expect("asked").quiet());
    }

    #[tokio::test]
    async fn a_delivery_the_platform_marked_a_replay_arrives_marked() {
        // Bead gc-6a5.3's decision, surviving the change of mechanism. An alert
        // arriving twice is how a responder learns something got worse, so a
        // replay that looked like a retry would be a lie told by a tool — and
        // this agent is now the only thing that can put the mark in the room.
        //
        // Read from the claim and never guessed: whether something is a replay
        // is the platform's knowledge. A retry inside the budget stays
        // unmarked, which the test above pins.
        let platform = Platform::offering(vec![offered_as("d-1", vec![a_push("x")], 60_000, true)]);
        let rooms = Rooms::new(vec![]);
        let subscriptions = everything_to(&["team-room"]);
        let clock = Ticking(Mutex::new(0));
        let waited = NoWait(Mutex::new(Vec::new()));
        let deliver = Deliver::new(
            &platform,
            &rooms,
            &clock,
            &Hops,
            &waited,
            &subscriptions,
            budget(),
        );

        deliver.once().await.expect("the platform answered");

        assert_eq!(rooms.sent().len(), 1);
        assert_eq!(rooms.sent()[0].3, Attempt::Replay);
    }

    #[tokio::test]
    async fn a_retry_of_a_replay_stays_marked_for_every_attempt() {
        // Each attempt is its own call and carries its own mark. An agent that
        // marked only the first would put `(replayed)` in a room or not
        // depending on whether the first attempt happened to fail, which is
        // the kind of inconsistency nobody would think to look for.
        let platform =
            Platform::offering(vec![offered_as("d-1", vec![a_push("x")], 600_000, true)]);
        let rooms = Rooms::new(vec!["team-room"]);
        let subscriptions = everything_to(&["team-room"]);
        let clock = Ticking(Mutex::new(0));
        let waited = NoWait(Mutex::new(Vec::new()));
        let deliver = Deliver::new(
            &platform,
            &rooms,
            &clock,
            &Hops,
            &waited,
            &subscriptions,
            budget(),
        );

        deliver.once().await.expect("the platform answered");

        let marks: Vec<Attempt> = rooms.sent().into_iter().map(|(_, _, _, a)| a).collect();
        assert_eq!(marks, vec![Attempt::Replay; 5]);
    }
}
