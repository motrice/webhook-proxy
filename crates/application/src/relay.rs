//! The use case: one inbound Delivery reaches everyone who should hear about it.

use domain::{
    Body, Delivery, DeliveryId, DestinationId, Origin, Signature, Subscription, destinations_for,
};

use crate::ports::{Clock, DispatchFailed, Dispatcher, Ids, Signatures, Translator};

/// Why a Delivery was not accepted at all.
///
/// Distinct from a Dispatch failing: these mean nothing was sent anywhere,
/// because we could not establish what we had.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// The claimed signature did not match the computed one.
    SignatureMismatch,
    /// The Origin's secret could not be obtained, so no judgement was possible.
    SecretUnavailable,
    /// The payload could not be read.
    Untranslatable,
}

/// What the relay did with one Delivery.
///
/// Reports losses rather than hiding them: the delivery promise is best-effort,
/// and a best-effort system whose losses are invisible is indistinguishable from
/// a broken one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relayed {
    delivery: DeliveryId,
    reached: Vec<DestinationId>,
    lost: Vec<(DestinationId, DispatchFailed)>,
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

    /// Destinations that were not told, and why. Each of these is a loss the
    /// caller is expected to log and count.
    #[must_use]
    pub fn lost(&self) -> &[(DestinationId, DispatchFailed)] {
        &self.lost
    }
}

/// Relays one inbound Delivery to every Destination that should hear about it.
///
/// Holds no rules of its own: the signature decision belongs to `Delivery`, the
/// routing decision to `destinations_for`. What lives here is the order those
/// happen in, and the refusal to let one Destination's failure affect another's.
pub struct Relay<'a> {
    signatures: &'a dyn Signatures,
    translator: &'a dyn Translator,
    dispatcher: &'a dyn Dispatcher,
    clock: &'a dyn Clock,
    ids: &'a dyn Ids,
    subscriptions: &'a [Subscription],
}

impl<'a> Relay<'a> {
    /// Wires the use case to the outside world.
    #[must_use]
    pub fn new(
        signatures: &'a dyn Signatures,
        translator: &'a dyn Translator,
        dispatcher: &'a dyn Dispatcher,
        clock: &'a dyn Clock,
        ids: &'a dyn Ids,
        subscriptions: &'a [Subscription],
    ) -> Self {
        Self {
            signatures,
            translator,
            dispatcher,
            clock,
            ids,
            subscriptions,
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
        claimed: &Signature,
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
            .map_err(|_| Refused::SignatureMismatch)?;

        // Only now is the payload read. Translation after verification is the
        // reason this is a port rather than something the adapter does first.
        let events = self
            .translator
            .events(&verified)
            .map_err(|_| Refused::Untranslatable)?;

        let mut reached = Vec::new();
        let mut lost = Vec::new();
        for event in &events {
            for destination in destinations_for(event, self.subscriptions) {
                match self
                    .dispatcher
                    .dispatch(verified.id(), event, destination)
                    .await
                {
                    Ok(()) => reached.push(destination.id().clone()),
                    // Recorded, never propagated: one Destination being down
                    // must not deny the others, nor refuse the delivery.
                    Err(failure) => lost.push((destination.id().clone(), failure)),
                }
            }
        }

        Ok(Relayed {
            delivery: verified.id().clone(),
            reached,
            lost,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use domain::{
        Blank, Body, BranchName, DeliveryId, Destination, DestinationId, DestinationKind, Event,
        Filter, Origin, OriginId, Pusher, RepositoryName, SecretId, Signature, Subscription,
        Timestamp, VerifiedDelivery,
    };

    use super::{Refused, Relay};
    use crate::ports::{
        Clock, DispatchFailed, Dispatcher, Ids, MalformedSignature, SecretUnavailable, Signatures,
        Translator, Untranslatable,
    };

    const SIGNATURE: [u8; 3] = [1, 2, 3];

    struct Secret(Result<Signature, SecretUnavailable>);
    impl Signatures for Secret {
        fn expected(&self, _origin: &Origin, _body: &Body) -> Result<Signature, SecretUnavailable> {
            self.0.clone()
        }

        /// The use case never calls this — an inbound adapter does, before it has
        /// anything to relay — so the fake is honest about not being exercised.
        fn claimed(&self, _presented: &str) -> Result<Signature, MalformedSignature> {
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
            _event: &Event,
            destination: &Destination,
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
        Origin::new(OriginId::new("a-forge"), SecretId::new("a-secret"))
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

    fn signature() -> Signature {
        Signature::from_bytes(SIGNATURE)
    }

    #[tokio::test]
    async fn a_verified_delivery_reaches_every_matching_destination() {
        let secret = Secret(Ok(signature()));
        let says = Says(Ok(vec![a_push()]));
        let dispatcher = Recorder::new(vec![]);
        let subscriptions = everything_to(&["first", "second"]);
        let relay = Relay::new(
            &secret,
            &says,
            &dispatcher,
            &FixedClock,
            &OneId,
            &subscriptions,
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
        assert!(relayed.lost().is_empty());
        assert_eq!(relayed.delivery().as_str(), "d-1");
    }

    #[tokio::test]
    async fn one_failing_destination_does_not_stop_the_others_and_is_reported() {
        let secret = Secret(Ok(signature()));
        let says = Says(Ok(vec![a_push()]));
        let dispatcher = Recorder::new(vec!["second"]);
        let subscriptions = everything_to(&["first", "second", "third"]);
        let relay = Relay::new(
            &secret,
            &says,
            &dispatcher,
            &FixedClock,
            &OneId,
            &subscriptions,
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
        assert_eq!(
            relayed.lost(),
            &[(
                DestinationId::new("second").expect("a non-blank id"),
                DispatchFailed::Unreachable
            )]
        );
    }

    #[tokio::test]
    async fn a_mismatched_signature_dispatches_nothing() {
        let secret = Secret(Ok(Signature::from_bytes([9, 9, 9])));
        let says = Says(Ok(vec![a_push()]));
        let dispatcher = Recorder::new(vec![]);
        let subscriptions = everything_to(&["first"]);
        let relay = Relay::new(
            &secret,
            &says,
            &dispatcher,
            &FixedClock,
            &OneId,
            &subscriptions,
        );

        let refused = relay
            .relay(
                &an_origin(),
                Body::from_bytes(b"payload".to_vec()),
                &signature(),
            )
            .await
            .expect_err("a mismatch is refused");

        assert_eq!(refused, Refused::SignatureMismatch);
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
        let relay = Relay::new(
            &secret,
            &says,
            &dispatcher,
            &FixedClock,
            &OneId,
            &subscriptions,
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
        let relay = Relay::new(
            &secret,
            &says,
            &dispatcher,
            &FixedClock,
            &OneId,
            &subscriptions,
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
            Filter::Repository(name("another-repository").expect("a name")),
        )];
        let relay = Relay::new(
            &secret,
            &says,
            &dispatcher,
            &FixedClock,
            &OneId,
            &subscriptions,
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
        assert!(relayed.lost().is_empty());
        assert!(dispatcher.sent().is_empty());
    }

    #[tokio::test]
    async fn a_delivery_reporting_nothing_we_care_about_is_accepted_silently() {
        let secret = Secret(Ok(signature()));
        let says = Says(Ok(vec![]));
        let dispatcher = Recorder::new(vec![]);
        let subscriptions = everything_to(&["first"]);
        let relay = Relay::new(
            &secret,
            &says,
            &dispatcher,
            &FixedClock,
            &OneId,
            &subscriptions,
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
}
