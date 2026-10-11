//! The use case: one inbound Delivery reaches everyone who should hear about it.

use core::time::Duration;

use domain::{
    Body, Delivery, DeliveryId, Destination, DestinationId, Dispatch, Event, Origin, Proof,
    Subscription, destinations_for,
};

use crate::ports::{Attempt, Clock, DispatchFailed, Dispatcher, Ids, Outbox, Proofs, Translator};

/// Why a Delivery was not accepted at all.
///
/// Distinct from a Dispatch failing: these mean nothing was sent anywhere,
/// because we could not establish what we had.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// The claimed signature did not match the computed one.
    ProofMismatch,
    /// The Origin's secret could not be obtained, so no judgement was possible.
    SecretUnavailable,
    /// The payload could not be read.
    Untranslatable,
    /// Nothing was stored, so nothing was promised.
    ///
    /// A 202 means the Delivery is stored and will be attempted until it
    /// succeeds or is abandoned (bead gc-mbr). When it cannot be stored the
    /// sender is refused rather than told something untrue — and deliberately
    /// not accepted into memory instead, which would make a 202 mean two
    /// different things depending on state the sender cannot see.
    StorageUnavailable,
}

/// How long to wait before trying a failed Dispatch again, and when to stop.
///
/// A policy rather than a constant, and it lives here rather than in the store
/// because every implementation of [`Outbox`] would otherwise have to agree
/// about it. The store is told a moment; what moment is the use case's business.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retry {
    first: Duration,
    ceiling: Duration,
    attempts: u32,
}

impl Retry {
    /// Wait `first` after the first failure, doubling up to `ceiling`, and give
    /// up after `attempts` of them.
    #[must_use]
    pub const fn new(first: Duration, ceiling: Duration, attempts: u32) -> Self {
        Self {
            first,
            ceiling,
            attempts,
        }
    }

    /// How long to wait after this many failures, or `None` to give up.
    ///
    /// Doubling, because a Destination that is down is usually down for longer
    /// than the last wait; and capped, because a budget spent entirely on one
    /// very long wait would mean a Destination that recovered in between is
    /// still not told.
    #[must_use]
    pub fn again_after(&self, failures: u32) -> Option<Duration> {
        if failures >= self.attempts {
            return None;
        }
        // failures is at least 1 here, so the first wait is `first` itself.
        let doubling = self
            .first
            .saturating_mul(1_u32 << failures.saturating_sub(1).min(31));
        Some(doubling.min(self.ceiling))
    }

    /// How many attempts a Dispatch gets before it is abandoned.
    #[must_use]
    pub const fn attempts(&self) -> u32 {
        self.attempts
    }
}

/// What the relay did with one Delivery.
///
/// Reports what did not arrive rather than hiding it, and distinguishes two
/// things that used to be one. A Dispatch that failed and will be tried again is
/// not a loss — it is stored, and something will come back to it. A Dispatch
/// that has run out of attempts is. Reporting both as "lost" would have made the
/// log unreadable the moment retrying existed: every transient failure would
/// look like a message nobody will ever see.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relayed {
    delivery: DeliveryId,
    reached: Vec<DestinationId>,
    retrying: Vec<(DestinationId, DispatchFailed, usize)>,
    abandoned: Vec<(DestinationId, DispatchFailed, usize)>,
}

impl Relayed {
    /// Which Delivery this describes.
    #[must_use]
    pub fn delivery(&self) -> &DeliveryId {
        &self.delivery
    }

    /// Destinations that were told.
    #[must_use]
    pub fn reached(&self) -> &[DestinationId] {
        &self.reached
    }

    /// Destinations that were not told yet, and why.
    ///
    /// Not losses. Each of these is stored and due to be tried again, so a
    /// caller reporting them should say so — an operator told a Notice was lost
    /// goes looking for it, and an operator told it will be retried waits.
    #[must_use]
    pub fn retrying(&self) -> &[(DestinationId, DispatchFailed, usize)] {
        &self.retrying
    }

    /// Destinations that will not be told, and why.
    ///
    /// These are the losses, in the sense the delivery promise means: attempted
    /// until the budget ran out and given up on. The caller logs and counts
    /// them, as it always did.
    ///
    /// The number is how many facts the message carried. One loss, however many
    /// — it is one message that did not arrive, and counting a grouped dispatch
    /// as several would make the number mean something different depending on
    /// how a sender configured its grouping. The count is reported so the detail
    /// is recoverable without changing what is counted.
    #[must_use]
    pub fn abandoned(&self) -> &[(DestinationId, DispatchFailed, usize)] {
        &self.abandoned
    }
}

/// Relays one inbound Delivery to every Destination that should hear about it.
///
/// Holds no rules of its own: the signature decision belongs to `Delivery`, the
/// routing decision to `destinations_for`. What lives here is the order those
/// happen in, and the refusal to let one Destination's failure affect another's.
pub struct Relay<'a> {
    signatures: &'a dyn Proofs,
    translator: &'a dyn Translator,
    dispatcher: &'a dyn Dispatcher,
    outbox: &'a dyn Outbox,
    clock: &'a dyn Clock,
    ids: &'a dyn Ids,
    subscriptions: &'a [Subscription],
    retry: Retry,
}

impl<'a> Relay<'a> {
    /// Wires the use case to the outside world.
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "the composition root's job is to name every collaborator once;                   grouping them into a struct would move the list rather than shorten it"
    )]
    pub fn new(
        signatures: &'a dyn Proofs,
        translator: &'a dyn Translator,
        dispatcher: &'a dyn Dispatcher,
        outbox: &'a dyn Outbox,
        clock: &'a dyn Clock,
        ids: &'a dyn Ids,
        subscriptions: &'a [Subscription],
        retry: Retry,
    ) -> Self {
        Self {
            signatures,
            translator,
            dispatcher,
            outbox,
            clock,
            ids,
            subscriptions,
            retry,
        }
    }

    /// Accept a Delivery, and tell everyone who should hear about it.
    ///
    /// Returns `Ok` even when every Dispatch failed. That is the delivery
    /// promise made executable: a Destination being down is not the sender's
    /// problem, and turning it into a failure here would make the inbound
    /// adapter answer with an error, which would make the sender retry, which
    /// would re-deliver to the Destinations that had already succeeded.
    ///
    /// # Errors
    ///
    /// [`Refused`] only when nothing could be sent at all.
    pub async fn relay(
        &self,
        origin: &Origin,
        body: Body,
        claimed: &Proof,
    ) -> Result<Relayed, Refused> {
        let delivery = Delivery::new(
            self.ids.next_delivery_id(),
            origin.id().clone(),
            body,
            self.clock.now(),
        );

        let expected = self
            .signatures
            .expected(origin, delivery.body())
            .map_err(|_| Refused::SecretUnavailable)?;

        // The domain decides, and consumes the Delivery doing it, so an
        // unverified one cannot be used further down by accident.
        let verified = delivery
            .verify(claimed, &expected)
            .map_err(|_| Refused::ProofMismatch)?;

        // Only now is the payload read. Translation after verification is the
        // reason this is a port rather than something the adapter does first.
        let events = self
            .translator
            .events(&verified)
            .map_err(|_| Refused::Untranslatable)?;

        // Decided before anything is stored or sent, so the whole fan-out is one
        // thing to accept. A Delivery is stored all at once or not at all: half
        // of it stored and then acknowledged would mean the sender believes it
        // delivered while the Destinations that were not recorded are never
        // attempted and never reported.
        // Per Destination, not per Event. A sender that grouped twenty alerts
        // into one notification meant a room to get one message, and fanning
        // them out again would undo a decision it made deliberately — bead
        // gc-lhh. Different alerts can select different rooms, so each room gets
        // the subset that chose it.
        //
        // Destinations in the order they were first selected, and Events within
        // one in the order the sender reported them: a reader comparing two
        // incidents should not find the same facts in a different arrangement.
        let mut grouped: Vec<(Destination, Vec<Event>)> = Vec::new();
        for event in &events {
            // The Origin from the *verified* Delivery, not the one the caller
            // named: routing must turn on who actually signed this. The two are
            // the same value today, and asking the VerifiedDelivery means they
            // cannot drift apart later. See bead gc-srw.
            for destination in destinations_for(verified.origin(), event, self.subscriptions) {
                match grouped
                    .iter_mut()
                    .find(|(known, _)| known.id() == destination.id())
                {
                    Some((_, theirs)) => theirs.push(event.clone()),
                    None => grouped.push((destination.clone(), vec![event.clone()])),
                }
            }
        }

        let planned: Vec<Dispatch> = grouped
            .into_iter()
            .filter_map(|(destination, theirs)| {
                Dispatch::new(
                    verified.id().clone(),
                    // From the *verified* Delivery, which is the same reason
                    // routing asks it rather than the caller: the Origin a
                    // replay routes by must be the one that was established,
                    // never one somebody typed.
                    verified.origin().clone(),
                    theirs,
                    destination,
                )
            })
            .collect();

        // Stored before the sender is told anything, which is what a 202 now
        // means. Refused rather than sent-without-storing: see gc-mbr.
        let stored = self
            .outbox
            .accept(&planned, self.clock.now())
            .await
            .map_err(|_| Refused::StorageUnavailable)?;

        let mut reached = Vec::new();
        let mut retrying = Vec::new();
        let mut abandoned = Vec::new();

        // Sent now rather than left for the worker. The outbox is the safety net
        // and not the critical path: a Notice that waited for a poll would make
        // every room slower in the common case, where nothing has failed at all.
        for record in &stored {
            let dispatch = record.dispatch();
            let destination = dispatch.destination().id().clone();

            match self
                .dispatcher
                .dispatch(
                    dispatch.delivery(),
                    dispatch.events(),
                    dispatch.destination(),
                    Attempt::First,
                )
                .await
            {
                Ok(()) => {
                    self.settle_delivered(record.id()).await;
                    reached.push(destination);
                }
                // Recorded, never propagated: one Destination being down must
                // not deny the others, nor refuse the delivery.
                Err(failure) => {
                    let carried = dispatch.events().len();
                    if self.settle_failed(record.id(), 1).await {
                        retrying.push((destination, failure, carried));
                    } else {
                        abandoned.push((destination, failure, carried));
                    }
                }
            }
        }

        Ok(Relayed {
            delivery: verified.id().clone(),
            reached,
            retrying,
            abandoned,
        })
    }

    /// Records that a Dispatch arrived.
    ///
    /// A store that cannot be told is not an error the caller can act on: the
    /// Notice did arrive, and refusing the sender now would make it send again.
    /// The cost of staying quiet is that the Dispatch stays due and the worker
    /// sends it a second time — a duplicate, which gc-6a5.4 calls cosmetic and
    /// is where deduplication belongs.
    async fn settle_delivered(&self, id: &domain::DispatchId) {
        let _ = self.outbox.delivered(id, self.clock.now()).await;
    }

    /// Records that a Dispatch failed. True if it will be tried again.
    async fn settle_failed(&self, id: &domain::DispatchId, failures: u32) -> bool {
        let now = self.clock.now();
        if let Some(wait) = self.retry.again_after(failures) {
            let _ = self.outbox.failed(id, now, now.after(wait)).await;
            true
        } else {
            let _ = self.outbox.abandoned(id, now).await;
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use core::time::Duration;

    use domain::{
        Blank, Body, BranchName, DeliveryId, Destination, DestinationId, DestinationKind, Dispatch,
        DispatchId, Event, Filter, LabelName, LabelValue, Labels, Origin, OriginId, Proof, Pusher,
        RepositoryName, SecretId, Subscription, Timestamp, Verification, VerifiedDelivery,
    };

    use super::{Refused, Relay, Retry};
    use crate::ports::{
        Attempt, Clock, DispatchFailed, Dispatcher, Ids, MalformedProof, Outbox, Outcome, Proofs,
        Recorded, SecretUnavailable, StorageUnavailable, Translator, Untranslatable,
    };

    const SIGNATURE: [u8; 3] = [1, 2, 3];

    struct Secret(Result<Proof, SecretUnavailable>);
    impl Proofs for Secret {
        fn expected(&self, _origin: &Origin, _body: &Body) -> Result<Proof, SecretUnavailable> {
            self.0.clone()
        }

        /// The use case never calls this — an inbound adapter does, before it has
        /// anything to relay — so the fake is honest about not being exercised.
        fn claimed(&self, _presented: &str) -> Result<Proof, MalformedProof> {
            unreachable!("the relay is given a claimed signature, it does not read one")
        }
    }

    struct Says(Result<Vec<Event>, Untranslatable>);
    impl Translator for Says {
        fn events(&self, _delivery: &VerifiedDelivery) -> Result<Vec<Event>, Untranslatable> {
            self.0.clone()
        }
    }

    struct FixedClock;
    impl Clock for FixedClock {
        fn now(&self) -> Timestamp {
            Timestamp::from_millis_since_epoch(1_759_000_000_000)
        }
    }

    struct OneId;
    impl Ids for OneId {
        fn next_delivery_id(&self) -> DeliveryId {
            DeliveryId::new("d-1").expect("a non-blank identity")
        }
    }

    /// Records what it was asked to send, and fails for the Destinations named.
    struct Recorder {
        sent: Mutex<Vec<String>>,
        failing: Vec<&'static str>,
    }

    impl Recorder {
        fn new(failing: Vec<&'static str>) -> Self {
            Self {
                sent: Mutex::new(Vec::new()),
                failing,
            }
        }

        fn sent(&self) -> Vec<String> {
            self.sent.lock().expect("not poisoned").clone()
        }
    }

    #[async_trait]
    impl Dispatcher for Recorder {
        async fn dispatch(
            &self,
            _delivery: &DeliveryId,
            _events: &[Event],
            destination: &Destination,
            _attempt: Attempt,
        ) -> Result<(), DispatchFailed> {
            let id = destination.id().as_str().to_owned();
            if self.failing.contains(&id.as_str()) {
                return Err(DispatchFailed::Unreachable);
            }
            self.sent.lock().expect("not poisoned").push(id);
            Ok(())
        }
    }

    fn an_origin() -> Origin {
        Origin::new(
            OriginId::new("a-forge").expect("a non-blank origin identity"),
            Verification::Signed {
                secret: SecretId::new("a-secret").expect("a non-blank secret name"),
            },
        )
    }

    fn name(text: &str) -> Result<RepositoryName, Blank> {
        RepositoryName::new(text)
    }

    fn a_push() -> Event {
        Event::PushedCommits {
            repository: name("webhook-proxy").expect("a name"),
            branch: BranchName::new("main").expect("a name"),
            pusher: Pusher::new("bjorn").expect("a name"),
            commits: vec![],
            permalink: None,
        }
    }

    fn room(id: &str) -> Destination {
        Destination::new(
            DestinationId::new(id).expect("a non-blank id"),
            DestinationKind::ChatRoom,
        )
    }

    fn everything_to(ids: &[&str]) -> Vec<Subscription> {
        ids.iter()
            .map(|id| Subscription::new(room(id), Filter::Everything))
            .collect()
    }

    fn signature() -> Proof {
        Proof::from_bytes(SIGNATURE)
    }

    /// An outbox a test can watch, and can make refuse.
    ///
    /// Thin on purpose: the real behaviours are proved against the in-memory
    /// adapter in its own crate. What this has to do is let a test see what was
    /// stored and settled, and be unavailable on demand — which is the one case
    /// the use case has to get right and no adapter can produce.
    struct Held {
        records: Mutex<Vec<Recorded>>,
        settled: Mutex<Vec<(String, &'static str)>>,
        available: bool,
    }

    impl Held {
        fn available() -> Self {
            Self {
                records: Mutex::new(Vec::new()),
                settled: Mutex::new(Vec::new()),
                available: true,
            }
        }

        fn unavailable() -> Self {
            Self {
                available: false,
                ..Self::available()
            }
        }

        /// What became of each Dispatch, in the order it was settled.
        fn settled(&self) -> Vec<(String, &'static str)> {
            self.settled.lock().expect("not poisoned").clone()
        }
    }

    #[async_trait]
    impl Outbox for Held {
        async fn accept(
            &self,
            dispatches: &[Dispatch],
            at: Timestamp,
        ) -> Result<Vec<Recorded>, StorageUnavailable> {
            if !self.available {
                return Err(StorageUnavailable);
            }
            let mut held = self.records.lock().expect("not poisoned");
            let mut stored = Vec::new();
            for (offset, dispatch) in dispatches.iter().enumerate() {
                stored.push(Recorded::new(
                    DispatchId::new(&format!("s-{}", held.len() + offset + 1)).expect("non-blank"),
                    dispatch.clone(),
                    0,
                    Outcome::Waiting { again_at: at },
                ));
            }
            held.extend(stored.iter().cloned());
            Ok(stored)
        }

        async fn accepted(
            &self,
            delivery: &DeliveryId,
        ) -> Result<Vec<Recorded>, StorageUnavailable> {
            let held = self.records.lock().expect("not poisoned");
            Ok(held
                .iter()
                .filter(|record| record.dispatch().delivery() == delivery)
                .cloned()
                .collect())
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
            id: &DispatchId,
            _at: Timestamp,
        ) -> Result<(), StorageUnavailable> {
            self.settled
                .lock()
                .expect("not poisoned")
                .push((id.as_str().to_owned(), "delivered"));
            Ok(())
        }

        async fn failed(
            &self,
            id: &DispatchId,
            _at: Timestamp,
            _again_at: Timestamp,
        ) -> Result<(), StorageUnavailable> {
            self.settled
                .lock()
                .expect("not poisoned")
                .push((id.as_str().to_owned(), "failed"));
            Ok(())
        }

        async fn abandoned(
            &self,
            id: &DispatchId,
            _at: Timestamp,
        ) -> Result<(), StorageUnavailable> {
            self.settled
                .lock()
                .expect("not poisoned")
                .push((id.as_str().to_owned(), "abandoned"));
            Ok(())
        }
    }

    /// A policy that will always try again, so a test asserting routing is not
    /// also asserting a retry budget.
    fn generous() -> Retry {
        Retry::new(Duration::from_secs(1), Duration::from_mins(1), 5)
    }

    #[tokio::test]
    async fn a_verified_delivery_reaches_every_matching_destination() {
        let secret = Secret(Ok(signature()));
        let says = Says(Ok(vec![a_push()]));
        let dispatcher = Recorder::new(vec![]);
        let subscriptions = everything_to(&["first", "second"]);
        let outbox = Held::available();
        let relay = Relay::new(
            &secret,
            &says,
            &dispatcher,
            &outbox,
            &FixedClock,
            &OneId,
            &subscriptions,
            generous(),
        );

        let relayed = relay
            .relay(
                &an_origin(),
                Body::from_bytes(b"payload".to_vec()),
                &signature(),
            )
            .await
            .expect("a matching signature is accepted");

        assert_eq!(dispatcher.sent(), vec!["first", "second"]);
        assert_eq!(relayed.reached().len(), 2);
        assert!(relayed.retrying().is_empty());
        assert!(relayed.abandoned().is_empty());
        assert_eq!(relayed.delivery().as_str(), "d-1");
    }

    #[tokio::test]
    async fn one_failing_destination_does_not_stop_the_others_and_is_reported() {
        let secret = Secret(Ok(signature()));
        let says = Says(Ok(vec![a_push()]));
        let dispatcher = Recorder::new(vec!["second"]);
        let subscriptions = everything_to(&["first", "second", "third"]);
        let outbox = Held::available();
        let relay = Relay::new(
            &secret,
            &says,
            &dispatcher,
            &outbox,
            &FixedClock,
            &OneId,
            &subscriptions,
            generous(),
        );

        let relayed = relay
            .relay(
                &an_origin(),
                Body::from_bytes(b"payload".to_vec()),
                &signature(),
            )
            .await
            .expect("a dispatch failure never refuses the delivery");

        assert_eq!(dispatcher.sent(), vec!["first", "third"]);
        // Retrying, not lost. It is stored and due to be tried again, and
        // calling that a loss would make every transient failure look like a
        // message nobody will ever see.
        assert_eq!(
            relayed.retrying(),
            &[(
                DestinationId::new("second").expect("a non-blank id"),
                DispatchFailed::Unreachable,
                // One fact in the message that did not arrive. Reported so a
                // log line can say how much was in it, without changing that it
                // counts as one.
                1
            )]
        );
        assert!(relayed.abandoned().is_empty());
    }

    #[tokio::test]
    async fn a_mismatched_signature_dispatches_nothing() {
        let secret = Secret(Ok(Proof::from_bytes([9, 9, 9])));
        let says = Says(Ok(vec![a_push()]));
        let dispatcher = Recorder::new(vec![]);
        let subscriptions = everything_to(&["first"]);
        let outbox = Held::available();
        let relay = Relay::new(
            &secret,
            &says,
            &dispatcher,
            &outbox,
            &FixedClock,
            &OneId,
            &subscriptions,
            generous(),
        );

        let refused = relay
            .relay(
                &an_origin(),
                Body::from_bytes(b"payload".to_vec()),
                &signature(),
            )
            .await
            .expect_err("a mismatch is refused");

        assert_eq!(refused, Refused::ProofMismatch);
        assert!(dispatcher.sent().is_empty());
    }

    #[tokio::test]
    async fn an_unavailable_secret_is_not_the_same_outcome_as_a_mismatch() {
        // One means we could not check, the other that we checked and it was
        // wrong. Collapsing them would hide a misconfigured deployment behind
        // what looks like an attack.
        let secret = Secret(Err(SecretUnavailable));
        let says = Says(Ok(vec![a_push()]));
        let dispatcher = Recorder::new(vec![]);
        let subscriptions = everything_to(&["first"]);
        let outbox = Held::available();
        let relay = Relay::new(
            &secret,
            &says,
            &dispatcher,
            &outbox,
            &FixedClock,
            &OneId,
            &subscriptions,
            generous(),
        );

        let refused = relay
            .relay(
                &an_origin(),
                Body::from_bytes(b"payload".to_vec()),
                &signature(),
            )
            .await
            .expect_err("no secret means no judgement");

        assert_eq!(refused, Refused::SecretUnavailable);
        assert!(dispatcher.sent().is_empty());
    }

    #[tokio::test]
    async fn an_unreadable_payload_dispatches_nothing() {
        let secret = Secret(Ok(signature()));
        let says = Says(Err(Untranslatable));
        let dispatcher = Recorder::new(vec![]);
        let subscriptions = everything_to(&["first"]);
        let outbox = Held::available();
        let relay = Relay::new(
            &secret,
            &says,
            &dispatcher,
            &outbox,
            &FixedClock,
            &OneId,
            &subscriptions,
            generous(),
        );

        let refused = relay
            .relay(
                &an_origin(),
                Body::from_bytes(b"payload".to_vec()),
                &signature(),
            )
            .await
            .expect_err("an unreadable payload is refused");

        assert_eq!(refused, Refused::Untranslatable);
        assert!(dispatcher.sent().is_empty());
    }

    #[tokio::test]
    async fn an_event_nobody_subscribed_to_reaches_nobody_and_is_not_an_error() {
        let secret = Secret(Ok(signature()));
        let says = Says(Ok(vec![a_push()]));
        let dispatcher = Recorder::new(vec![]);
        let subscriptions = vec![Subscription::new(
            room("elsewhere"),
            // A label requirement no push can satisfy. It used to be a
            // Filter::Repository; the Filter now asks for labels so that one
            // mechanism serves senders that have no repository at all (gc-ast.1).
            Filter::Labelled(Labels::none().with(
                LabelName::new("repository").expect("a non-blank name"),
                LabelValue::new("another-repository").expect("a non-blank value"),
            )),
        )];
        let outbox = Held::available();
        let relay = Relay::new(
            &secret,
            &says,
            &dispatcher,
            &outbox,
            &FixedClock,
            &OneId,
            &subscriptions,
            generous(),
        );

        let relayed = relay
            .relay(
                &an_origin(),
                Body::from_bytes(b"payload".to_vec()),
                &signature(),
            )
            .await
            .expect("nobody caring is not a failure");

        assert!(relayed.reached().is_empty());
        assert!(relayed.retrying().is_empty());
        assert!(relayed.abandoned().is_empty());
        assert!(dispatcher.sent().is_empty());
    }

    #[tokio::test]
    async fn a_delivery_reporting_nothing_we_care_about_is_accepted_silently() {
        let secret = Secret(Ok(signature()));
        let says = Says(Ok(vec![]));
        let dispatcher = Recorder::new(vec![]);
        let subscriptions = everything_to(&["first"]);
        let outbox = Held::available();
        let relay = Relay::new(
            &secret,
            &says,
            &dispatcher,
            &outbox,
            &FixedClock,
            &OneId,
            &subscriptions,
            generous(),
        );

        let relayed = relay
            .relay(
                &an_origin(),
                Body::from_bytes(b"payload".to_vec()),
                &signature(),
            )
            .await
            .expect("we are not the sender's error reporter");

        assert!(relayed.reached().is_empty());
        assert!(dispatcher.sent().is_empty());
    }

    // ---- what a 202 now means (gc-mbr) -----------------------------------

    #[tokio::test]
    async fn nothing_is_sent_when_nothing_could_be_stored() {
        // The promise in one test. A 202 means stored; when it cannot be
        // stored the sender is refused, and deliberately not accepted into
        // memory and sent anyway — which would make a 202 mean two different
        // things depending on state the sender cannot see.
        let secret = Secret(Ok(signature()));
        let says = Says(Ok(vec![a_push()]));
        let dispatcher = Recorder::new(vec![]);
        let subscriptions = everything_to(&["first", "second"]);
        let outbox = Held::unavailable();
        let relay = Relay::new(
            &secret,
            &says,
            &dispatcher,
            &outbox,
            &FixedClock,
            &OneId,
            &subscriptions,
            generous(),
        );

        let outcome = relay
            .relay(
                &an_origin(),
                Body::from_bytes(b"payload".to_vec()),
                &signature(),
            )
            .await;

        assert_eq!(outcome, Err(Refused::StorageUnavailable));
        assert!(
            dispatcher.sent().is_empty(),
            "a Notice was sent that nothing had promised to retry"
        );
    }

    #[tokio::test]
    async fn everything_is_stored_before_anything_is_sent() {
        let secret = Secret(Ok(signature()));
        let says = Says(Ok(vec![a_push()]));
        let dispatcher = Recorder::new(vec![]);
        let subscriptions = everything_to(&["first", "second"]);
        let outbox = Held::available();
        let relay = Relay::new(
            &secret,
            &says,
            &dispatcher,
            &outbox,
            &FixedClock,
            &OneId,
            &subscriptions,
            generous(),
        );

        relay
            .relay(
                &an_origin(),
                Body::from_bytes(b"payload".to_vec()),
                &signature(),
            )
            .await
            .expect("the store is available");

        // Both Dispatches of the fan-out, stored under the Delivery's identity,
        // and both settled as delivered once they were sent.
        let held = outbox
            .accepted(&DeliveryId::new("d-1").expect("a non-blank id"))
            .await
            .expect("available");
        assert_eq!(held.len(), 2);
        assert_eq!(
            outbox.settled(),
            vec![
                ("s-1".to_owned(), "delivered"),
                ("s-2".to_owned(), "delivered")
            ]
        );
    }

    #[tokio::test]
    async fn a_dispatch_with_attempts_left_is_recorded_for_another_try() {
        let secret = Secret(Ok(signature()));
        let says = Says(Ok(vec![a_push()]));
        let dispatcher = Recorder::new(vec!["first"]);
        let subscriptions = everything_to(&["first"]);
        let outbox = Held::available();
        let relay = Relay::new(
            &secret,
            &says,
            &dispatcher,
            &outbox,
            &FixedClock,
            &OneId,
            &subscriptions,
            generous(),
        );

        let relayed = relay
            .relay(
                &an_origin(),
                Body::from_bytes(b"payload".to_vec()),
                &signature(),
            )
            .await
            .expect("a dispatch failure never refuses the delivery");

        assert_eq!(outbox.settled(), vec![("s-1".to_owned(), "failed")]);
        assert_eq!(relayed.retrying().len(), 1);
        assert!(relayed.abandoned().is_empty());
    }

    #[tokio::test]
    async fn a_dispatch_with_no_attempts_left_is_given_up_on_at_once() {
        // A budget of one means the first failure is the last. Without this the
        // policy would be decided by whether anything ever called it, and a
        // Dispatch could sit waiting for an attempt that was never coming.
        let secret = Secret(Ok(signature()));
        let says = Says(Ok(vec![a_push()]));
        let dispatcher = Recorder::new(vec!["first"]);
        let subscriptions = everything_to(&["first"]);
        let outbox = Held::available();
        let relay = Relay::new(
            &secret,
            &says,
            &dispatcher,
            &outbox,
            &FixedClock,
            &OneId,
            &subscriptions,
            Retry::new(Duration::from_secs(1), Duration::from_mins(1), 1),
        );

        let relayed = relay
            .relay(
                &an_origin(),
                Body::from_bytes(b"payload".to_vec()),
                &signature(),
            )
            .await
            .expect("a dispatch failure never refuses the delivery");

        assert_eq!(outbox.settled(), vec![("s-1".to_owned(), "abandoned")]);
        assert!(relayed.retrying().is_empty());
        assert_eq!(relayed.abandoned().len(), 1);
    }

    // ---- the retry policy ------------------------------------------------

    #[test]
    fn waiting_doubles_and_then_stops_growing() {
        // Doubling because a Destination that is down is usually down for longer
        // than the last wait; capped because a budget spent on one very long
        // wait means a Destination that recovered in between is still not told.
        let retry = Retry::new(Duration::from_secs(2), Duration::from_secs(10), 9);

        assert_eq!(retry.again_after(1), Some(Duration::from_secs(2)));
        assert_eq!(retry.again_after(2), Some(Duration::from_secs(4)));
        assert_eq!(retry.again_after(3), Some(Duration::from_secs(8)));
        assert_eq!(retry.again_after(4), Some(Duration::from_secs(10)));
        assert_eq!(retry.again_after(5), Some(Duration::from_secs(10)));
    }

    #[test]
    fn the_budget_is_what_ends_it() {
        let retry = Retry::new(Duration::from_secs(1), Duration::from_mins(1), 3);

        assert!(retry.again_after(2).is_some());
        assert_eq!(retry.again_after(3), None, "attempt four was not refused");
        assert_eq!(retry.again_after(400), None);
    }
}
