//! A store that remembers nothing past the process.
//!
//! An implementation of [`application::ports::Handover`], so the use cases can
//! be driven before a database exists — and the one the test suite keeps using
//! afterwards, because a suite that needs a database is a suite people stop
//! running.
//!
//! It is not a stub. It keeps the guarantees the port states and a durable
//! implementation has to keep as well: a tenant is offered only its own work,
//! two agents are never handed the same Delivery, and a claim lapses rather
//! than being released. Getting those wrong here would mean the use-case tests
//! prove something the real store does not do.
//!
//! THE CRATE NAME IS NOW WRONG and is left alone on purpose. It held an outbox
//! until bead gc-72e.3.2 removed the delivery loop that read one. Renaming it
//! would touch every manifest and import in the workspace inside a change that
//! is already large, so it is filed as its own small job instead.
//!
//! What it deliberately does not do is survive a restart, which is the whole
//! point of bead gc-b0n and the reason this one is cheap.

use std::sync::Mutex;

use application::ports::{
    Behind, Claimed, Counted, Discharged, Handover, Offered, PerReason, PerRoom, PerTenant,
    Reoffered, Report, RoomOutcome, StorageUnavailable, Swept, TenantId, Uncollected,
};
use async_trait::async_trait;
use domain::{DeliveryId, Timestamp};

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
    offered: Mutex<Vec<Owed>>,
    /// What has been reported and what has been dropped, since this process
    /// started.
    ///
    /// COUNTED BY THE STORE RATHER THAN BY ITS CALLER, which is bead gc-5px and
    /// is a property of the port rather than of this implementation: a count
    /// kept beside the metrics endpoint is one replica's share of the truth,
    /// and one a routine apply destroys. Here it still dies with the process —
    /// so does everything else in this store, and the deployment that endorses
    /// two replicas is the one that names a database (bead gc-f7t).
    ///
    /// Separate from `offered` and not derived from it, because `report`
    /// removes the row it discharges: by the time there is something to count,
    /// the thing it was counted from is gone.
    counted: Mutex<Tallies>,
}

/// The three counts this store keeps, each keyed by what it may be summed over.
#[derive(Default)]
struct Tallies {
    /// Rooms that were told, by (tenant, room).
    delivered: std::collections::BTreeMap<(String, String), u64>,
    /// Rooms that were not, by (tenant, room, reason). EVERY ONE IS A LOSS.
    abandoned: std::collections::BTreeMap<(String, String, String), u64>,
    /// Deliveries swept away before their tenant collected them, by tenant.
    dropped: std::collections::BTreeMap<String, u64>,
}

/// One Delivery owed, and whether somebody is holding it.
struct Owed {
    offered: Offered,
    /// Whether a person asked for this to be offered again.
    replayed: bool,
    /// When the current claim lapses, if there is one. `None` means nobody
    /// holds it; a moment in the past means a claim that lapsed and has not
    /// been noticed yet, which reads the same to every query here.
    claimed_until: Option<Timestamp>,
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
    async fn counted(&self) -> Result<Counted, StorageUnavailable> {
        let counted = self.counted.lock().map_err(|_| StorageUnavailable)?;
        Ok(Counted {
            delivered: counted
                .delivered
                .iter()
                .map(|((tenant, room), count)| PerRoom {
                    tenant: tenant.clone(),
                    room: room.clone(),
                    count: *count,
                })
                .collect(),
            abandoned: counted
                .abandoned
                .iter()
                .map(|((tenant, room, reason), count)| PerReason {
                    tenant: tenant.clone(),
                    room: room.clone(),
                    reason: reason.clone(),
                    count: *count,
                })
                .collect(),
            dropped: counted
                .dropped
                .iter()
                .map(|(tenant, count)| PerTenant {
                    tenant: tenant.clone(),
                    count: *count,
                })
                .collect(),
        })
    }

    async fn offer(&self, offered: &Offered) -> Result<(), StorageUnavailable> {
        let mut held = self.offered.lock().map_err(|_| StorageUnavailable)?;
        held.push(Owed {
            offered: offered.clone(),
            claimed_until: None,
            replayed: false,
        });
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
            .filter(|owed| owed.offered.tenant() == tenant)
            .take(limit)
            .map(|owed| owed.offered.clone())
            .collect())
    }

    async fn claim(
        &self,
        tenant: &TenantId,
        limit: usize,
        now: Timestamp,
        lease: core::time::Duration,
    ) -> Result<Vec<Claimed>, StorageUnavailable> {
        let until = now.after(lease);
        let mut held = self.offered.lock().map_err(|_| StorageUnavailable)?;

        // One lock over the read and the write, which is what makes this a
        // claim rather than a query: two callers must not be handed the same
        // Delivery, because both would deliver it. The database does the same
        // thing with SELECT ... FOR UPDATE SKIP LOCKED inside a transaction.
        Ok(held
            .iter_mut()
            .filter(|owed| {
                owed.offered.tenant() == tenant
                    // Lapsed claims come back by themselves, which is why
                    // nothing has to clean up after an agent that died
                    // mid-delivery.
                    && owed.claimed_until.is_none_or(|held| held <= now)
            })
            .take(limit)
            .map(|owed| {
                owed.claimed_until = Some(until);
                Claimed::new(owed.offered.clone(), until, owed.replayed)
            })
            .collect())
    }

    async fn report(
        &self,
        tenant: &TenantId,
        delivery: &DeliveryId,
        report: &Report,
        _at: Timestamp,
    ) -> Result<Discharged, StorageUnavailable> {
        let mut held = self.offered.lock().map_err(|_| StorageUnavailable)?;
        let before = held.len();

        // BOTH the identity and the tenant, so one tenant reporting another's
        // Delivery discharges nothing. The identity alone would be authorisation
        // resting on a random number being hard to guess.
        held.retain(|owed| owed.offered.delivery() != delivery || owed.offered.tenant() != tenant);

        // Removed rather than kept with the report beside it, which is the one
        // place this store deliberately differs from the durable one: what a
        // report SAYS is of no use to a process that forgets everything at
        // exit, and keeping it would be modelling a retention sweep that has
        // nothing to sweep.
        if held.len() == before {
            return Ok(Discharged::NotOutstanding);
        }

        // COUNTED ONLY HERE, past the return above, which is what makes a
        // report that arrives twice one count rather than two. An agent whose
        // reply was lost on the way back must be able to send it again and this
        // API says so, so the second one discharges nothing and must count
        // nothing — a number that inflates under exactly the conditions
        // somebody is investigating is worse than no number (bead gc-556).
        if let Report::Reached(rooms) = report {
            let mut counted = self.counted.lock().map_err(|_| StorageUnavailable)?;
            for (room, outcome) in rooms {
                let whose = tenant.as_str().to_owned();
                let room = room.as_str().to_owned();
                match outcome {
                    RoomOutcome::Delivered => {
                        *counted.delivered.entry((whose, room)).or_default() += 1;
                    }
                    RoomOutcome::Abandoned(why) => {
                        *counted
                            .abandoned
                            .entry((whose, room, why.spelled().to_owned()))
                            .or_default() += 1;
                    }
                }
            }
        }
        Ok(Discharged::Settled)
    }

    async fn reoffer(&self, delivery: &DeliveryId) -> Result<Reoffered, StorageUnavailable> {
        // This store forgets a reported Delivery (see `report`), so a replay
        // here can only reach one still outstanding — which is the case where
        // the OFFERING is already right and only the MARKING is wanted. The
        // durable store is where a reported Delivery survives to be offered
        // again, and it has its own test for that.
        let mut held = self.offered.lock().map_err(|_| StorageUnavailable)?;
        let Some(owed) = held
            .iter_mut()
            .find(|owed| owed.offered.delivery() == delivery)
        else {
            return Ok(Reoffered::NotStored);
        };

        owed.replayed = true;
        // Any claim on it lapses now, so the next agent to ask is handed it.
        owed.claimed_until = None;
        Ok(Reoffered::Owed)
    }

    async fn sweep(&self, accepted_before: Timestamp) -> Result<Swept, StorageUnavailable> {
        let mut held = self.offered.lock().map_err(|_| StorageUnavailable)?;

        // EVERY ROW HERE IS UNCOLLECTED, because `report` removes a discharged
        // one rather than keeping it with its report beside it — see the note
        // there. So this store's `settled` is always zero, and that is honest
        // rather than a gap: a process that forgets everything at exit has no
        // month of settled rows to retain. The durable store is where the
        // distinction means something, and it has its own tests for it.
        let (old, current): (Vec<Owed>, Vec<Owed>) = held
            .drain(..)
            .partition(|owed| owed.offered.accepted_at() < accepted_before);
        *held = current;

        let uncollected: Vec<Uncollected> = old.iter().map(|owed| lost(&owed.offered)).collect();

        // THE COUNT OF A LOSS, kept where the rows were, for the reason the
        // port's `counted` gives: it used to be an integer in the process that
        // exported it, so an apply that rolled the pod destroyed the evidence
        // that anything had been dropped.
        let mut counted = self.counted.lock().map_err(|_| StorageUnavailable)?;
        for one in &uncollected {
            *counted.dropped.entry(one.tenant.clone()).or_default() += 1;
        }
        drop(counted);

        Ok(Swept {
            settled: 0,
            uncollected,
        })
    }

    async fn behind(&self, accepted_before: Timestamp) -> Result<Vec<Behind>, StorageUnavailable> {
        let held = self.offered.lock().map_err(|_| StorageUnavailable)?;

        // A map keyed by the tenant's text, because what comes back is a report
        // and not a set of domain values — the port says why.
        let mut piling: std::collections::BTreeMap<String, (usize, Timestamp)> =
            std::collections::BTreeMap::new();
        for owed in held
            .iter()
            .filter(|owed| owed.offered.accepted_at() < accepted_before)
        {
            let entry = piling
                .entry(owed.offered.tenant().as_str().to_owned())
                .or_insert((0, owed.offered.accepted_at()));
            entry.0 += 1;
            if owed.offered.accepted_at() < entry.1 {
                entry.1 = owed.offered.accepted_at();
            }
        }

        Ok(piling
            .into_iter()
            .map(|(tenant, (outstanding, oldest))| Behind {
                tenant,
                outstanding,
                oldest,
            })
            .collect())
    }
}

/// What a loss report says about one Delivery nobody collected.
///
/// Built here rather than in the port so that both stores produce the same
/// shape from the same fields, and so the one thing it must never carry — an
/// Event, which is somebody's alert text — has nowhere to come from.
fn lost(offered: &Offered) -> Uncollected {
    Uncollected {
        delivery: offered.delivery().as_str().to_owned(),
        tenant: offered.tenant().as_str().to_owned(),
        origin: offered.origin().as_str().to_owned(),
        trace: offered.correlation().trace().to_owned(),
        accepted_at: offered.accepted_at(),
    }
}

#[cfg(test)]
mod handover_tests {
    use application::ports::{
        Discharged, DispatchFailed, Handover, Offered, Reoffered, Report, RoomOutcome, TenantId,
    };
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

    /// The lease these tests claim under. The length is the platform's choice
    /// and arrives as an argument, so a test can step past it.
    const FIVE_MINUTES: core::time::Duration = core::time::Duration::from_mins(5);

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

    #[tokio::test]
    async fn two_agents_are_never_handed_the_same_delivery() {
        // What makes this a claim rather than a query. Both agents would
        // deliver what they were handed, so a room would see it twice — and
        // under the split the claimant is not another replica of this binary
        // but a pod in somebody else's namespace.
        let store = MemoryHandover::new();
        for id in ["d-1", "d-2"] {
            store
                .offer(&offered(id, "wallet-lab-prod", 1))
                .await
                .expect("stored");
        }

        let first = store
            .claim(&tenant("wallet-lab-prod"), 1, at(10), FIVE_MINUTES)
            .await
            .expect("claimed");
        let second = store
            .claim(&tenant("wallet-lab-prod"), 1, at(10), FIVE_MINUTES)
            .await
            .expect("claimed");

        assert_eq!(first.len(), 1);
        assert_eq!(second.len(), 1);
        assert_ne!(
            first[0].offered().delivery(),
            second[0].offered().delivery(),
            "two agents were handed the same Delivery"
        );
    }

    #[tokio::test]
    async fn a_claim_nobody_ever_reports_comes_back_by_itself() {
        // The reason nothing has to clean up after an agent that died
        // mid-delivery, and the reason the lease is the platform's: a claim
        // lapses rather than being released, so a namespace that never comes
        // back costs this service nothing to notice.
        let store = MemoryHandover::new();
        store
            .offer(&offered("d-1", "wallet-lab-prod", 1))
            .await
            .expect("stored");

        let held = store
            .claim(&tenant("wallet-lab-prod"), 10, at(0), FIVE_MINUTES)
            .await
            .expect("claimed");
        assert_eq!(held.len(), 1);

        // A moment inside the lease: still held, so nothing is offered.
        assert!(
            store
                .claim(&tenant("wallet-lab-prod"), 10, at(60_000), FIVE_MINUTES)
                .await
                .expect("asked")
                .is_empty(),
            "a Delivery under an unexpired claim was offered again"
        );

        // And after it: back, with no intervention.
        assert_eq!(
            store
                .claim(
                    &tenant("wallet-lab-prod"),
                    10,
                    at(5 * 60_000 + 1),
                    FIVE_MINUTES
                )
                .await
                .expect("asked")
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn a_claim_by_one_tenant_does_not_hide_another_tenants_work() {
        // The lease and the tenant scoping are independent, and a store that
        // confused them would be hard to notice: one tenant collecting would
        // quietly starve another.
        let store = MemoryHandover::new();
        store
            .offer(&offered("d-1", "wallet-lab-prod", 1))
            .await
            .expect("stored");
        store
            .offer(&offered("d-2", "wallet-hsm-prod", 2))
            .await
            .expect("stored");

        store
            .claim(&tenant("wallet-lab-prod"), 10, at(0), FIVE_MINUTES)
            .await
            .expect("claimed");

        let theirs = store
            .claim(&tenant("wallet-hsm-prod"), 10, at(0), FIVE_MINUTES)
            .await
            .expect("claimed");

        assert_eq!(theirs.len(), 1);
        assert_eq!(theirs[0].offered().delivery().as_str(), "d-2");
    }

    #[tokio::test]
    async fn a_reported_delivery_is_not_offered_again_and_a_stranger_cannot_report_it() {
        let store = MemoryHandover::new();
        store
            .offer(&offered("d-1", "wallet-lab-prod", 1))
            .await
            .expect("stored");
        let delivery = DeliveryId::new("d-1").expect("an identity");

        // Another tenant discharges nothing, and the positive oracle follows:
        // its own tenant still can, so this did not pass by the store having
        // lost it.
        assert_eq!(
            store
                .report(
                    &tenant("wallet-hsm-prod"),
                    &delivery,
                    &Report::RoutedToNothing,
                    at(1)
                )
                .await
                .expect("asked"),
            Discharged::NotOutstanding
        );
        assert_eq!(
            store
                .report(
                    &tenant("wallet-lab-prod"),
                    &delivery,
                    &Report::RoutedToNothing,
                    at(2)
                )
                .await
                .expect("asked"),
            Discharged::Settled
        );
        assert!(
            store
                .claim(&tenant("wallet-lab-prod"), 10, at(3), FIVE_MINUTES)
                .await
                .expect("asked")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_delivery_offered_again_is_marked_as_a_replay() {
        // The marking is what a replay is for here (gc-6a5.3). This store
        // forgets a reported Delivery, so what it can reach is one still
        // outstanding — where the offering is already right and only the mark
        // is wanted. The durable store has its own test for re-offering
        // something already reported.
        let store = MemoryHandover::new();
        store
            .offer(&offered("d-1", "wallet-lab-prod", 1))
            .await
            .expect("stored");
        let delivery = DeliveryId::new("d-1").expect("an identity");

        assert!(
            !store
                .claim(&tenant("wallet-lab-prod"), 10, at(0), FIVE_MINUTES)
                .await
                .expect("claimed")[0]
                .replayed(),
            "a first delivery was marked a replay"
        );

        assert_eq!(
            store.reoffer(&delivery).await.expect("asked"),
            Reoffered::Owed
        );

        let again = store
            .claim(&tenant("wallet-lab-prod"), 10, at(1), FIVE_MINUTES)
            .await
            .expect("claimed");
        assert_eq!(again.len(), 1, "the claim it was under did not lapse");
        assert!(again[0].replayed());
    }

    #[tokio::test]
    async fn offering_something_this_store_never_had_again_says_so() {
        let store = MemoryHandover::new();

        assert_eq!(
            store
                .reoffer(&DeliveryId::new("never-existed").expect("an identity"))
                .await
                .expect("asked"),
            Reoffered::NotStored
        );
    }

    #[tokio::test]
    async fn a_loss_its_tenant_reported_is_counted_by_room_and_by_reason() {
        // BEAD gc-5px: counted BY THE STORE, which is the whole change. These
        // numbers used to be accumulated in the process that served the
        // metrics endpoint, so two replicas each held a share of them and a
        // routine apply zeroed the count of a real loss. A count belongs
        // wherever the store is — which for this store is still one process,
        // and that is honest rather than a gap: nothing here survives exit.
        //
        // By REASON as well as by room, because the four are not
        // interchangeable to whoever acts on one: `rejected` is a
        // configuration problem in the tenant's own repository, `unreachable`
        // is the network.
        let store = MemoryHandover::new();
        store
            .offer(&offered("d-1", "wallet-lab-prod", 1))
            .await
            .expect("stored");

        assert_eq!(
            store
                .report(
                    &tenant("wallet-lab-prod"),
                    &DeliveryId::new("d-1").expect("an identity"),
                    &Report::Reached(vec![(
                        domain::DestinationId::new("oncall-room").expect("an identity"),
                        RoomOutcome::Abandoned(DispatchFailed::Unreachable),
                    )]),
                    at(2),
                )
                .await
                .expect("asked"),
            Discharged::Settled
        );

        let counted = store.counted().await.expect("asked");
        assert_eq!(counted.abandoned.len(), 1, "{counted:?}");
        assert_eq!(counted.abandoned[0].tenant, "wallet-lab-prod");
        assert_eq!(counted.abandoned[0].room, "oncall-room");
        assert_eq!(counted.abandoned[0].reason, "unreachable");
        assert_eq!(counted.abandoned[0].count, 1);
        assert!(
            counted.delivered.is_empty(),
            "a loss was counted as a delivery, which would make a ratio of \
             the two say everything is fine: {counted:?}"
        );
    }
    #[tokio::test]
    async fn a_delivery_swept_away_before_anyone_collected_it_is_counted_against_its_tenant() {
        // The third kind of loss bead gc-g9x enumerated, and the only one that
        // happens without anybody having attempted anything: retention deletes
        // a Delivery its tenant never came for. Counted by tenant because it
        // never reached a room, so there is no room to name.
        //
        // This count was an `AtomicU64` beside the metrics endpoint
        // (`Backlog::dropped`) and is the one the bare
        // `webhook_proxy_uncollected_dropped_total` was read from, so it had
        // both defects at once: two replicas each ran the sweep and each held
        // a share of the answer, and an apply set it back to zero.
        let store = MemoryHandover::new();
        for (id, whose) in [
            ("d-1", "wallet-lab-prod"),
            ("d-2", "wallet-lab-prod"),
            ("d-3", "wallet-hsm-prod"),
        ] {
            store.offer(&offered(id, whose, 1)).await.expect("stored");
        }

        let swept = store.sweep(at(2)).await.expect("swept");
        assert_eq!(swept.uncollected.len(), 3, "the sweep deleted nothing");

        let counted = store.counted().await.expect("asked");
        assert_eq!(
            counted
                .dropped
                .iter()
                .map(|one| (one.tenant.as_str(), one.count))
                .collect::<Vec<_>>(),
            vec![("wallet-hsm-prod", 1), ("wallet-lab-prod", 2)],
            "{counted:?}"
        );
    }
}
