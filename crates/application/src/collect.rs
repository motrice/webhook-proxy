//! A tenant's agent collecting what it is owed, and saying what became of it.
//!
//! Two operations and no third, as bead gc-81d decided: claim a Delivery whole,
//! report its rooms terminally. Neither side may abandon on the other's behalf,
//! so there is no "give up" verb in either direction (bead gc-g9x).
//!
//! THE AUTHORISATION DECISION LIVES HERE, and that placement is the point of
//! the file. The caller's identity establishes a namespace; whether that
//! namespace is a tenant *this deployment serves* is a question about
//! configuration, and answering it in an adapter would put the one rule the
//! whole split exists for somewhere no test of this crate could reach. An
//! adapter that forgot it would compile, pass, and serve every caller.

use std::collections::BTreeSet;

use core::time::Duration;
use domain::DeliveryId;

use crate::ports::{Claimed, Clock, Discharged, Handover, Report, StorageUnavailable, TenantId};

/// What a caller may not do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// The caller speaks for a namespace this deployment serves no tenant for.
    ///
    /// Not "unknown tenant" from the caller's point of view: an agent in a
    /// namespace nobody configured, and the ingress gateway's own identity,
    /// arrive here identically and are both told the same nothing. That is what
    /// makes the public path safe by construction rather than by routing —
    /// `istio-ingress` is not a tenant, so a request that reached this through
    /// the public gateway speaks for the gateway and is refused here.
    NotATenantHere,
    /// The store could not be asked or told.
    StorageUnavailable,
}

impl From<StorageUnavailable> for Refused {
    fn from(_: StorageUnavailable) -> Self {
        Self::StorageUnavailable
    }
}

/// The hand-off, from the platform's side.
pub struct Collect<'a> {
    handover: &'a dyn Handover,
    clock: &'a dyn Clock,
    /// Every tenant this deployment serves, from its routing file.
    ///
    /// The authorisation list, and it is the same list `tenants:` already
    /// carries — so there is no second place for the two to drift, and adding a
    /// tenant to the file is the whole act of letting its agent collect.
    tenants: &'a BTreeSet<TenantId>,
    /// How long a claim holds, decided here rather than by an adapter or a
    /// caller. Bead gc-81d: the platform owns the lease.
    lease: Duration,
    /// How many Deliveries one claim may take.
    ///
    /// The platform's number, not the caller's. A caller-supplied bound would
    /// be one more thing to validate and would let an agent decide this
    /// service's memory footprint; the agent gains nothing from choosing it,
    /// because it can simply claim again.
    batch: usize,
}

impl<'a> Collect<'a> {
    /// Wires the use case to the outside world.
    #[must_use]
    pub fn new(
        handover: &'a dyn Handover,
        clock: &'a dyn Clock,
        tenants: &'a BTreeSet<TenantId>,
        lease: Duration,
        batch: usize,
    ) -> Self {
        Self {
            handover,
            clock,
            tenants,
            lease,
            batch,
        }
    }

    /// What this caller's tenant has not yet discharged, leased to it.
    ///
    /// # Errors
    ///
    /// [`Refused::NotATenantHere`] if the caller speaks for a namespace no
    /// tenant is configured for, and [`Refused::StorageUnavailable`] if the
    /// store could not be asked.
    pub async fn claim(&self, caller: &TenantId) -> Result<Vec<Claimed>, Refused> {
        self.serving(caller)?;
        Ok(self
            .handover
            .claim(caller, self.batch, self.clock.now(), self.lease)
            .await?)
    }

    /// Records what became of one of this caller's own Deliveries.
    ///
    /// # Errors
    ///
    /// As [`Self::claim`]. A Delivery that is not outstanding for this caller
    /// is **not** an error: it answers [`Discharged::NotOutstanding`], which is
    /// the same answer for another tenant's Delivery, one already reported, and
    /// one that never existed.
    pub async fn report(
        &self,
        caller: &TenantId,
        delivery: &DeliveryId,
        report: &Report,
    ) -> Result<Discharged, Refused> {
        self.serving(caller)?;
        Ok(self
            .handover
            .report(caller, delivery, report, self.clock.now())
            .await?)
    }

    /// Whether this deployment serves a tenant by that name.
    fn serving(&self, caller: &TenantId) -> Result<(), Refused> {
        if self.tenants.contains(caller) {
            Ok(())
        } else {
            Err(Refused::NotATenantHere)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use domain::{
        BranchName, Correlation, DeliveryId, DestinationId, Event, OriginId, Pusher,
        RepositoryName, Timestamp,
    };

    use super::{Collect, Refused};
    use crate::ports::{
        Behind, Claimed, Clock, Discharged, Handover, Offered, Reoffered, Report, RoomOutcome,
        StorageUnavailable, Swept, TenantId,
    };

    fn at(millis: i64) -> Timestamp {
        Timestamp::from_millis_since_epoch(1_759_000_000_000 + millis)
    }

    struct FixedClock;
    impl Clock for FixedClock {
        fn now(&self) -> Timestamp {
            at(0)
        }
    }

    fn tenant(id: &str) -> TenantId {
        TenantId::new(id).expect("a namespace name")
    }

    fn serving(ids: &[&str]) -> BTreeSet<TenantId> {
        ids.iter().map(|id| tenant(id)).collect()
    }

    fn offered(delivery: &str, whose: &str) -> Offered {
        Offered::new(
            DeliveryId::new(delivery).expect("an identity"),
            tenant(whose),
            OriginId::new("alertmanager").expect("a name"),
            vec![Event::PushedCommits {
                repository: RepositoryName::new("motrice/webhook-proxy").expect("a name"),
                branch: BranchName::new("main").expect("a name"),
                pusher: Pusher::new("bjorn").expect("a name"),
                commits: vec![],
                permalink: None,
            }],
            Correlation::new("4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7", None)
                .expect("a chain"),
            at(1),
        )
        .expect("at least one event")
    }

    /// A store that records what it was asked, so a test can see which tenant
    /// reached it — and whether anything reached it at all.
    struct Owed {
        held: Mutex<Vec<Offered>>,
        asked: Mutex<Vec<String>>,
    }

    impl Owed {
        fn holding(offered: Vec<Offered>) -> Self {
            Self {
                held: Mutex::new(offered),
                asked: Mutex::new(Vec::new()),
            }
        }

        /// Which tenants the store was asked about, in order.
        fn asked(&self) -> Vec<String> {
            self.asked.lock().expect("not poisoned").clone()
        }
    }

    #[async_trait]
    impl Handover for Owed {
        async fn offer(&self, offered: &Offered) -> Result<(), StorageUnavailable> {
            self.held
                .lock()
                .expect("not poisoned")
                .push(offered.clone());
            Ok(())
        }

        async fn outstanding(
            &self,
            tenant: &TenantId,
            limit: usize,
        ) -> Result<Vec<Offered>, StorageUnavailable> {
            Ok(self
                .held
                .lock()
                .expect("not poisoned")
                .iter()
                .filter(|offered| offered.tenant() == tenant)
                .take(limit)
                .cloned()
                .collect())
        }

        async fn claim(
            &self,
            tenant: &TenantId,
            limit: usize,
            now: Timestamp,
            lease: core::time::Duration,
        ) -> Result<Vec<Claimed>, StorageUnavailable> {
            self.asked
                .lock()
                .expect("not poisoned")
                .push(tenant.as_str().to_owned());
            Ok(self
                .outstanding(tenant, limit)
                .await?
                .into_iter()
                .map(|offered| Claimed::new(offered, now.after(lease), false))
                .collect())
        }

        // Nothing in this file offers anything again: a replay is an operator's
        // command, not part of this use case.
        async fn reoffer(&self, _delivery: &DeliveryId) -> Result<Reoffered, StorageUnavailable> {
            unreachable!("collecting never re-offers")
        }

        // Nothing in this file sweeps: what is kept and who is told about a
        // backlog is `retention.rs`, and its own fake implements these.
        async fn sweep(&self, _accepted_before: Timestamp) -> Result<Swept, StorageUnavailable> {
            unreachable!("collecting never sweeps")
        }

        async fn behind(
            &self,
            _accepted_before: Timestamp,
        ) -> Result<Vec<Behind>, StorageUnavailable> {
            unreachable!("collecting never asks after a backlog")
        }

        async fn report(
            &self,
            tenant: &TenantId,
            delivery: &DeliveryId,
            _report: &Report,
            _at: Timestamp,
        ) -> Result<Discharged, StorageUnavailable> {
            self.asked
                .lock()
                .expect("not poisoned")
                .push(tenant.as_str().to_owned());
            let mut held = self.held.lock().expect("not poisoned");
            let before = held.len();
            held.retain(|offered| offered.delivery() != delivery || offered.tenant() != tenant);
            if held.len() == before {
                Ok(Discharged::NotOutstanding)
            } else {
                Ok(Discharged::Settled)
            }
        }
    }

    fn collecting<'a>(store: &'a Owed, tenants: &'a BTreeSet<TenantId>) -> Collect<'a> {
        Collect::new(
            store,
            &FixedClock,
            tenants,
            core::time::Duration::from_mins(5),
            10,
        )
    }

    #[tokio::test]
    async fn a_caller_speaking_for_no_configured_tenant_never_reaches_the_store() {
        // THE REFUSAL HAPPENS BEFORE THE STORE IS ASKED, which is why the fake
        // records what it was asked rather than only what it returned. A
        // version that asked and then filtered would pass a test checking only
        // the answer, and would be one forgotten `WHERE` away from a leak.
        //
        // The caller here is the ingress gateway's own namespace, which is the
        // case that makes the public path safe by construction: a request that
        // arrives through the public gateway speaks for `istio-ingress`, and
        // `istio-ingress` is not a tenant.
        let store = Owed::holding(vec![offered("d-1", "wallet-lab-prod")]);
        let tenants = serving(&["wallet-lab-prod"]);
        let collect = collecting(&store, &tenants);

        let outcome = collect.claim(&tenant("istio-ingress")).await;

        assert_eq!(outcome, Err(Refused::NotATenantHere));
        assert!(
            store.asked().is_empty(),
            "the store was asked about a caller this deployment serves no tenant for"
        );
    }

    #[tokio::test]
    async fn a_tenant_claims_its_own_and_is_told_when_the_claim_lapses() {
        let store = Owed::holding(vec![
            offered("d-1", "wallet-lab-prod"),
            offered("d-2", "wallet-hsm-prod"),
        ]);
        let tenants = serving(&["wallet-lab-prod", "wallet-hsm-prod"]);
        let collect = collecting(&store, &tenants);

        let claimed = collect
            .claim(&tenant("wallet-lab-prod"))
            .await
            .expect("a configured tenant may collect");

        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0].offered().delivery().as_str(), "d-1");
        // Returned rather than assumed: with two binaries that could disagree
        // about its length, the platform is the one that owns it (gc-81d).
        assert_eq!(
            claimed[0].until(),
            at(0).after(core::time::Duration::from_mins(5))
        );
    }

    #[tokio::test]
    async fn a_tenant_cannot_report_another_tenants_delivery() {
        // Reported by identity, and the identity alone is not the authority.
        // A DeliveryId is random, so guessing one is not a practical attack —
        // but it travels, in traces and logs and room messages, and
        // authorisation that rests on an identifier being hard to guess is not
        // authorisation.
        let store = Owed::holding(vec![offered("d-2", "wallet-hsm-prod")]);
        let tenants = serving(&["wallet-lab-prod", "wallet-hsm-prod"]);
        let collect = collecting(&store, &tenants);

        let outcome = collect
            .report(
                &tenant("wallet-lab-prod"),
                &DeliveryId::new("d-2").expect("an identity"),
                &Report::RoutedToNothing,
            )
            .await
            .expect("a configured tenant may report");

        assert_eq!(outcome, Discharged::NotOutstanding);
        // And the positive oracle: its own tenant can still discharge it, so
        // this did not pass because the store had lost it.
        assert_eq!(
            collect
                .report(
                    &tenant("wallet-hsm-prod"),
                    &DeliveryId::new("d-2").expect("an identity"),
                    &Report::RoutedToNothing,
                )
                .await
                .expect("its own tenant may report it"),
            Discharged::Settled
        );
    }

    #[tokio::test]
    async fn routed_to_nothing_discharges_it_like_any_other_report() {
        // The report that keeps the queue draining. A tenant whose rules match
        // no room has nothing to say about rooms, and without this it would
        // look exactly like a tenant whose agent has died (gc-g9x).
        let store = Owed::holding(vec![offered("d-1", "wallet-lab-prod")]);
        let tenants = serving(&["wallet-lab-prod"]);
        let collect = collecting(&store, &tenants);

        assert_eq!(
            collect
                .report(
                    &tenant("wallet-lab-prod"),
                    &DeliveryId::new("d-1").expect("an identity"),
                    &Report::RoutedToNothing,
                )
                .await
                .expect("reported"),
            Discharged::Settled
        );
        assert!(
            collect
                .claim(&tenant("wallet-lab-prod"))
                .await
                .expect("asked")
                .is_empty(),
            "a discharged Delivery was offered again"
        );
    }

    #[tokio::test]
    async fn reporting_twice_is_safe_and_is_not_an_error() {
        // An agent whose report was lost on the way back must be able to send
        // it again. An error would make a retry look like a fault, and the
        // agent's only other option would be to deliver again.
        let store = Owed::holding(vec![offered("d-1", "wallet-lab-prod")]);
        let tenants = serving(&["wallet-lab-prod"]);
        let collect = collecting(&store, &tenants);
        let delivery = DeliveryId::new("d-1").expect("an identity");
        let rooms = Report::Reached(vec![(
            DestinationId::new("a-room").expect("an identity"),
            RoomOutcome::Delivered,
        )]);

        let first = collect
            .report(&tenant("wallet-lab-prod"), &delivery, &rooms)
            .await
            .expect("reported");
        let again = collect
            .report(&tenant("wallet-lab-prod"), &delivery, &rooms)
            .await
            .expect("reporting again is not an error");

        assert_eq!(first, Discharged::Settled);
        assert_eq!(again, Discharged::NotOutstanding);
    }
}
