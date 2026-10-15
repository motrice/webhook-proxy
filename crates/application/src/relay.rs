//! The use case: one inbound Delivery is verified, read, and owed to a tenant.

use domain::{Body, Correlation, Delivery, DeliveryId, Origin, Proof};

use crate::ports::{Clock, Handover, Ids, Offered, Proofs, TenantId, Translator};

/// Why a Delivery was not accepted at all.
///
/// Every one of these means nothing was stored and nothing was promised,
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
    /// A 202 means the Delivery is stored and will be OFFERED TO ITS TENANT
    /// (bead gc-g9x, restating gc-mbr). When it cannot be stored the sender is
    /// refused rather than told something untrue — and deliberately not
    /// accepted into memory instead, which would make a 202 mean two different
    /// things depending on state the sender cannot see.
    StorageUnavailable,
}

/// What the relay did with one Delivery.
///
/// Two values, and it used to carry three lists as well: which rooms were
/// told, which would be tried again, which had been given up on. All three
/// belonged to a service that delivered, and this one does not any more (bead
/// gc-72e.3.2) — it verifies, translates, and owes the Delivery to a tenant.
/// What became of a room is now reported by that tenant's agent, logged where
/// it happened, and the platform learns it only as a report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relayed {
    delivery: DeliveryId,
    correlation: Correlation,
}

impl Relayed {
    /// Which Delivery this describes.
    #[must_use]
    pub fn delivery(&self) -> &DeliveryId {
        &self.delivery
    }

    /// The chain it belongs to.
    ///
    /// Reported back because the caller may not know it: a sender that sent no
    /// correlation had one made for it here, and the only way it can put that
    /// in its own log is if the answer carries it. It is also what makes a loss
    /// line — written by an agent, in another namespace — correlatable with
    /// whatever the sender was doing at the time.
    #[must_use]
    pub fn correlation(&self) -> &Correlation {
        &self.correlation
    }
}

/// Accepts one inbound Delivery and owes it to the tenant it belongs to.
///
/// Holds no rules of its own: the signature decision belongs to `Delivery`, and
/// which tenant an Origin belongs to is configuration. What lives here is the
/// order things happen in — nothing is parsed before a signature matches, and
/// nothing is promised before it is stored.
///
/// WHAT IT STOPPED DOING, and the deletion is most of this bead. It used to
/// route with `destinations_for`, group the Events per room, store a Dispatch
/// per room in an `Outbox`, send each one immediately, and hand the failures to
/// a worker that came back to them. All of that is a tenant's now (bead
/// gc-g9x): its own rules, in its own repository, delivered by its own agent to
/// rooms this service does not know and never learns.
pub struct Relay<'a> {
    signatures: &'a dyn Proofs,
    translator: &'a dyn Translator,
    handover: &'a dyn Handover,
    clock: &'a dyn Clock,
    ids: &'a dyn Ids,
}

impl<'a> Relay<'a> {
    /// Wires the use case to the outside world.
    ///
    /// Five collaborators where there were eight. The three that went —
    /// a dispatcher, an outbox and a retry policy — were the whole of what it
    /// took to deliver, which is the shape of this change.
    #[must_use]
    pub fn new(
        signatures: &'a dyn Proofs,
        translator: &'a dyn Translator,
        handover: &'a dyn Handover,
        clock: &'a dyn Clock,
        ids: &'a dyn Ids,
    ) -> Self {
        Self {
            signatures,
            translator,
            handover,
            clock,
            ids,
        }
    }

    /// Accept a Delivery, and owe it to its tenant.
    ///
    /// # Errors
    ///
    /// [`Refused`] when nothing could be established or nothing stored. There
    /// is no longer a case where some of a Delivery succeeded and some did not:
    /// one Delivery is one record, so this either accepted it or did not.
    ///
    /// `carried` is whatever correlation the caller sent, if it was usable. A
    /// caller that sent none, or sent something malformed, gets a fresh one
    /// rather than a refusal: the policy lives here rather than in the adapter
    /// because it is a decision about what a delivery is worth, not about how a
    /// header is spelled.
    pub async fn relay(
        &self,
        origin: &Origin,
        tenant: &TenantId,
        body: Body,
        claimed: &Proof,
        carried: Option<Correlation>,
    ) -> Result<Relayed, Refused> {
        let correlation = carried.unwrap_or_else(|| self.ids.next_correlation());

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

        // Owed to its tenant before the sender is told anything, which is what
        // a 202 means: stored, and will be offered to its tenant.
        //
        // No Destination appears anywhere here, and that is the split: this
        // service does not know this tenant's rooms and cannot learn them. A
        // Delivery that translated to no Events is not owed to anybody — there
        // would be nothing to deliver and no room list to report, so its
        // tenant could never discharge it.
        if let Some(offered) = Offered::new(
            verified.id().clone(),
            tenant.clone(),
            verified.origin().clone(),
            events,
            correlation.clone(),
            self.clock.now(),
        ) {
            self.handover
                .offer(&offered)
                .await
                .map_err(|_| Refused::StorageUnavailable)?;
        }

        Ok(Relayed {
            delivery: verified.id().clone(),
            correlation,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use domain::{
        Body, BranchName, Correlation, DeliveryId, Event, Origin, OriginId, Proof, Pusher,
        RepositoryName, SecretId, Timestamp, Verification, VerifiedDelivery,
    };

    use super::{Refused, Relay};
    use crate::ports::{
        Behind, Claimed, Clock, Discharged, Handover, Ids, MalformedProof, Offered, Proofs,
        Reoffered, Report, SecretUnavailable, StorageUnavailable, Swept, TenantId, Translator,
        Untranslatable,
    };

    const SIGNATURE: [u8; 3] = [1, 2, 3];

    fn signature() -> Proof {
        Proof::from_bytes(SIGNATURE.to_vec())
    }

    fn an_origin() -> Origin {
        Origin::new(
            OriginId::new("a-forge").expect("an identity"),
            Verification::Signed {
                secret: SecretId::new("a-secret").expect("a name"),
            },
        )
    }

    fn a_tenant() -> TenantId {
        TenantId::new("a-tenant").expect("a namespace name")
    }

    fn a_push() -> Event {
        Event::PushedCommits {
            repository: RepositoryName::new("motrice/webhook-proxy").expect("a name"),
            branch: BranchName::new("main").expect("a name"),
            pusher: Pusher::new("bjorn").expect("a name"),
            commits: vec![],
            permalink: None,
        }
    }

    struct Secret(Result<Proof, SecretUnavailable>);
    impl Proofs for Secret {
        fn expected(&self, _origin: &Origin, _body: &Body) -> Result<Proof, SecretUnavailable> {
            self.0.clone()
        }
        fn claimed(&self, _presented: &str) -> Result<Proof, MalformedProof> {
            unreachable!("the adapter reads the credential, not this use case")
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

    /// Identities a test can predict, and a correlation it can recognise as
    /// having been invented here rather than sent by a caller.
    struct OneId;
    impl Ids for OneId {
        fn next_delivery_id(&self) -> DeliveryId {
            DeliveryId::new("d-1").expect("an identity")
        }
        fn next_correlation(&self) -> Correlation {
            Correlation::new("00000000000000000000000000000001", "0000000000000001", None)
                .expect("a chain")
        }
        fn next_hop_in(&self, _chain: &Correlation) -> Correlation {
            unreachable!("this service makes no onward call to hop in")
        }
    }

    /// Somewhere to owe a Delivery, which a test can watch and can make refuse.
    struct Owed {
        offered: Mutex<Vec<Offered>>,
        available: bool,
    }

    impl Owed {
        fn available() -> Self {
            Self {
                offered: Mutex::new(Vec::new()),
                available: true,
            }
        }

        fn unavailable() -> Self {
            Self {
                available: false,
                ..Self::available()
            }
        }

        fn offered(&self) -> Vec<Offered> {
            self.offered.lock().expect("not poisoned").clone()
        }
    }

    #[async_trait]
    impl Handover for Owed {
        async fn offer(&self, offered: &Offered) -> Result<(), StorageUnavailable> {
            if !self.available {
                return Err(StorageUnavailable);
            }
            self.offered
                .lock()
                .expect("not poisoned")
                .push(offered.clone());
            Ok(())
        }

        async fn outstanding(
            &self,
            _tenant: &TenantId,
            _limit: usize,
        ) -> Result<Vec<Offered>, StorageUnavailable> {
            unreachable!("the relay never reads back")
        }

        async fn claim(
            &self,
            _tenant: &TenantId,
            _limit: usize,
            _now: Timestamp,
            _lease: core::time::Duration,
        ) -> Result<Vec<Claimed>, StorageUnavailable> {
            unreachable!("the relay never claims")
        }

        async fn report(
            &self,
            _tenant: &TenantId,
            _delivery: &DeliveryId,
            _report: &Report,
            _at: Timestamp,
        ) -> Result<Discharged, StorageUnavailable> {
            unreachable!("the relay never reports")
        }

        async fn reoffer(&self, _delivery: &DeliveryId) -> Result<Reoffered, StorageUnavailable> {
            unreachable!("the relay never re-offers")
        }

        async fn sweep(&self, _accepted_before: Timestamp) -> Result<Swept, StorageUnavailable> {
            unreachable!("the relay never sweeps")
        }

        async fn behind(
            &self,
            _accepted_before: Timestamp,
        ) -> Result<Vec<Behind>, StorageUnavailable> {
            unreachable!("the relay never asks after a backlog")
        }
    }

    async fn relaying(
        secret: &Secret,
        says: &Says,
        owed: &Owed,
        carried: Option<Correlation>,
    ) -> Result<super::Relayed, Refused> {
        Relay::new(secret, says, owed, &FixedClock, &OneId)
            .relay(
                &an_origin(),
                &a_tenant(),
                Body::from_bytes(b"payload".to_vec()),
                &signature(),
                carried,
            )
            .await
    }

    #[tokio::test]
    async fn a_verified_delivery_is_owed_to_its_tenant_and_to_nobody_else() {
        // The whole of what this use case does now. One Delivery, one record,
        // no rooms: which rooms hear about it is its tenant's business, decided
        // in the tenant's own repository by the tenant's own agent.
        let owed = Owed::available();

        let relayed = relaying(
            &Secret(Ok(signature())),
            &Says(Ok(vec![a_push(), a_push()])),
            &owed,
            None,
        )
        .await
        .expect("a matching signature is accepted");

        let held = owed.offered();
        assert_eq!(held.len(), 1, "one Delivery became {} records", held.len());
        assert_eq!(held[0].tenant(), &a_tenant());
        assert_eq!(held[0].origin(), an_origin().id());
        assert_eq!(
            held[0].events().len(),
            2,
            "a sender grouped two facts and they were owed separately, which \
             undoes gc-smz's grouping before any agent can honour it"
        );
        assert_eq!(relayed.delivery().as_str(), "d-1");
    }

    #[tokio::test]
    async fn a_mismatched_signature_owes_nothing() {
        let owed = Owed::available();
        let other = Proof::from_bytes(vec![9, 9, 9]);

        let outcome = Relay::new(
            &Secret(Ok(other)),
            &Says(Ok(vec![a_push()])),
            &owed,
            &FixedClock,
            &OneId,
        )
        .relay(
            &an_origin(),
            &a_tenant(),
            Body::from_bytes(b"payload".to_vec()),
            &signature(),
            None,
        )
        .await;

        assert_eq!(outcome, Err(Refused::ProofMismatch));
        assert!(owed.offered().is_empty());
    }

    #[tokio::test]
    async fn an_unavailable_secret_is_not_the_same_outcome_as_a_mismatch() {
        // One means we could not check; the other means we checked and it was
        // wrong. A deployment holding no secret for a configured Origin is our
        // fault and must not hide behind what looks like an attack.
        let owed = Owed::available();

        let outcome = relaying(
            &Secret(Err(SecretUnavailable)),
            &Says(Ok(vec![a_push()])),
            &owed,
            None,
        )
        .await;

        assert_eq!(outcome, Err(Refused::SecretUnavailable));
        assert!(owed.offered().is_empty());
    }

    #[tokio::test]
    async fn an_unreadable_payload_owes_nothing() {
        // And it is read only after the signature matched, which is why the
        // translator is a port rather than something the adapter does first.
        let owed = Owed::available();

        let outcome = relaying(
            &Secret(Ok(signature())),
            &Says(Err(Untranslatable)),
            &owed,
            None,
        )
        .await;

        assert_eq!(outcome, Err(Refused::Untranslatable));
        assert!(owed.offered().is_empty());
    }

    #[tokio::test]
    async fn a_delivery_that_cannot_be_stored_is_refused_rather_than_accepted() {
        // The promise in one test. A 202 means stored and will be offered to
        // its tenant; when it cannot be stored the sender is refused rather
        // than told something untrue, and deliberately not accepted into
        // memory instead — which would make a 202 mean two different things
        // depending on state the sender cannot see.
        let owed = Owed::unavailable();

        let outcome = relaying(
            &Secret(Ok(signature())),
            &Says(Ok(vec![a_push()])),
            &owed,
            None,
        )
        .await;

        assert_eq!(outcome, Err(Refused::StorageUnavailable));
    }

    #[tokio::test]
    async fn a_delivery_reporting_nothing_is_accepted_and_owes_nobody() {
        // Success, and no record. A sender telling us about something we do not
        // care about must not leave a row its tenant can never discharge:
        // there are no facts to deliver, so there is no room list to report.
        let owed = Owed::available();

        relaying(&Secret(Ok(signature())), &Says(Ok(vec![])), &owed, None)
            .await
            .expect("a Delivery reporting nothing is not an error");

        assert!(owed.offered().is_empty());
    }

    #[tokio::test]
    async fn a_caller_that_sent_no_chain_is_told_the_one_it_was_filed_under() {
        // The only way a sender learns which chain to put in its own log. It is
        // also what lets the agent's loss line, written in another namespace,
        // be read beside whatever the sender was doing at the time.
        let owed = Owed::available();

        let relayed = relaying(
            &Secret(Ok(signature())),
            &Says(Ok(vec![a_push()])),
            &owed,
            None,
        )
        .await
        .expect("accepted");

        assert_eq!(
            relayed.correlation().trace(),
            "00000000000000000000000000000001"
        );
        // And the record carries the same chain, so the hand-off continues it
        // rather than starting a new one.
        assert_eq!(
            owed.offered()[0].correlation().trace(),
            relayed.correlation().trace()
        );
    }

    #[tokio::test]
    async fn a_chain_the_caller_sent_is_the_one_it_is_filed_under() {
        let owed = Owed::available();
        let theirs = Correlation::new("4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7", None)
            .expect("a chain");

        let relayed = relaying(
            &Secret(Ok(signature())),
            &Says(Ok(vec![a_push()])),
            &owed,
            Some(theirs.clone()),
        )
        .await
        .expect("accepted");

        assert_eq!(relayed.correlation().trace(), theirs.trace());
        assert_eq!(owed.offered()[0].correlation().trace(), theirs.trace());
    }
}
