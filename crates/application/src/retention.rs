//! What is kept, for how long, and who is told when something is dropped.
//!
//! Two jobs on one interval, and they are the same job from two directions: how
//! much a tenant has failed to collect, and what was deleted because it failed
//! to collect for long enough. Bead gc-wcw.3.
//!
//! THIS IS WHAT REPLACES A READ API. Bead gc-g9x deferred one on the explicit
//! promise that an operator could still answer "did my alert arrive" — from the
//! tenant agent's own logs for a delivery that was attempted, and from here for
//! one that never was. If this is quiet when a tenant's agent has stopped, that
//! promise was not kept.

use core::time::Duration;

use domain::Timestamp;

use crate::ports::{Behind, Clock, Handover, StorageUnavailable, Swept, Uncollected};

/// What one pass found and removed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Reaped {
    /// Rows deleted whose tenant had reported them. Not losses.
    pub settled: usize,
    /// Rows deleted that no tenant ever collected. Every one is a loss.
    pub uncollected: Vec<Uncollected>,
    /// Tenants whose work is piling up, oldest-first backlog and all.
    pub behind: Vec<Behind>,
}

impl Reaped {
    /// Whether there is anything worth saying.
    ///
    /// So a pass that found a healthy system logs nothing. An interval job that
    /// writes a line every time floods the log somebody is reading to find the
    /// one line that matters — the same reason gc-mbr logs a store outage on
    /// the transition rather than per request.
    #[must_use]
    pub fn quiet(&self) -> bool {
        self.settled == 0 && self.uncollected.is_empty() && self.behind.is_empty()
    }
}

/// How long anything is kept, and when a backlog is worth reporting.
pub struct Retention<'a> {
    handover: &'a dyn Handover,
    clock: &'a dyn Clock,
    /// One month, by bead gc-mnn. Measured from acceptance, which is the age a
    /// reader means when they ask how old something is.
    keep_for: Duration,
    /// How long a Delivery may sit uncollected before it is worth a line.
    ///
    /// Shorter than `keep_for` and necessarily so: a threshold equal to the
    /// retention period would mean an operator first heard about a stopped
    /// agent in the same pass that deleted its work.
    report_after: Duration,
}

impl<'a> Retention<'a> {
    /// Wires the job to the store and the clock.
    ///
    /// # Panics
    ///
    /// If `report_after` is not shorter than `keep_for`. A deployment
    /// configured that way would delete a tenant's work in the same pass that
    /// first mentioned it, which is the one outcome this whole bead exists to
    /// prevent — so it is refused at startup rather than discovered a month in.
    #[must_use]
    pub fn new(
        handover: &'a dyn Handover,
        clock: &'a dyn Clock,
        keep_for: Duration,
        report_after: Duration,
    ) -> Self {
        assert!(
            report_after < keep_for,
            "a backlog must be reported before it is deleted: reporting after \
             {report_after:?} and keeping for {keep_for:?} would mean an \
             operator first heard about a stopped agent in the pass that \
             dropped its alerts"
        );
        Self {
            handover,
            clock,
            keep_for,
            report_after,
        }
    }

    /// One pass: report what is piling up, then delete what is too old.
    ///
    /// In that order, deliberately. Reporting first means a Delivery about to
    /// be deleted has already been counted as outstanding at least once, so an
    /// operator watching the backlog gauge saw it before the loss counter did.
    /// The other order would make a quietly-dropped alert the first anybody
    /// heard of a tenant.
    ///
    /// # Errors
    ///
    /// [`StorageUnavailable`] if the store could not be asked. Nothing is
    /// deleted then, and the next pass tries again: retention is a month, so
    /// being late by one interval costs nothing.
    pub async fn once(&self) -> Result<Reaped, StorageUnavailable> {
        let now = self.clock.now();

        let behind = self.handover.behind(before(now, self.report_after)).await?;
        let Swept {
            settled,
            uncollected,
        } = self.handover.sweep(before(now, self.keep_for)).await?;

        Ok(Reaped {
            settled,
            uncollected,
            behind,
        })
    }
}

/// The moment `elapsed` ago.
///
/// `Timestamp::after` is the only arithmetic the domain offers, so going
/// backwards is done here rather than by adding a second operation to a domain
/// type for one caller's benefit.
fn before(now: Timestamp, elapsed: Duration) -> Timestamp {
    let millis = i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX);
    Timestamp::from_millis_since_epoch(now.millis_since_epoch() - millis)
}

#[cfg(test)]
mod tests {
    use core::time::Duration;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use domain::{DeliveryId, Timestamp};

    use super::Retention;
    use crate::ports::{
        Behind, Claimed, Clock, Discharged, Handover, Offered, Reoffered, Report,
        StorageUnavailable, Swept, TenantId, Uncollected,
    };

    const MONTH: Duration = Duration::from_hours(30 * 24);
    const A_DAY: Duration = Duration::from_hours(24);

    fn at(millis: i64) -> Timestamp {
        Timestamp::from_millis_since_epoch(millis)
    }

    struct FixedClock(i64);
    impl Clock for FixedClock {
        fn now(&self) -> Timestamp {
            at(self.0)
        }
    }

    /// A store that records the cutoffs it was given, because the cutoffs are
    /// the whole of what this use case decides.
    struct Store {
        asked_behind: Mutex<Vec<i64>>,
        asked_sweep: Mutex<Vec<i64>>,
        swept: Swept,
        behind: Vec<Behind>,
        available: bool,
    }

    impl Store {
        fn holding(swept: Swept, behind: Vec<Behind>) -> Self {
            Self {
                asked_behind: Mutex::new(Vec::new()),
                asked_sweep: Mutex::new(Vec::new()),
                swept,
                behind,
                available: true,
            }
        }

        fn unavailable() -> Self {
            Self {
                available: false,
                ..Self::holding(Swept::default(), Vec::new())
            }
        }
    }

    #[async_trait]
    impl Handover for Store {
        async fn offer(&self, _offered: &Offered) -> Result<(), StorageUnavailable> {
            unreachable!("retention never offers")
        }

        async fn outstanding(
            &self,
            _tenant: &TenantId,
            _limit: usize,
        ) -> Result<Vec<Offered>, StorageUnavailable> {
            unreachable!("retention asks `behind`, which is the question it has")
        }

        async fn claim(
            &self,
            _tenant: &TenantId,
            _limit: usize,
            _now: Timestamp,
            _lease: Duration,
        ) -> Result<Vec<Claimed>, StorageUnavailable> {
            unreachable!("retention never claims")
        }

        async fn report(
            &self,
            _tenant: &TenantId,
            _delivery: &DeliveryId,
            _report: &Report,
            _at: Timestamp,
        ) -> Result<Discharged, StorageUnavailable> {
            unreachable!("retention never reports")
        }

        // Nothing in this file offers anything again: a replay is an operator's
        // command, not part of this use case.
        async fn reoffer(&self, _delivery: &DeliveryId) -> Result<Reoffered, StorageUnavailable> {
            unreachable!("retention never re-offers")
        }

        async fn sweep(&self, accepted_before: Timestamp) -> Result<Swept, StorageUnavailable> {
            if !self.available {
                return Err(StorageUnavailable);
            }
            self.asked_sweep
                .lock()
                .expect("not poisoned")
                .push(accepted_before.millis_since_epoch());
            Ok(self.swept.clone())
        }

        async fn behind(
            &self,
            accepted_before: Timestamp,
        ) -> Result<Vec<Behind>, StorageUnavailable> {
            if !self.available {
                return Err(StorageUnavailable);
            }
            self.asked_behind
                .lock()
                .expect("not poisoned")
                .push(accepted_before.millis_since_epoch());
            Ok(self.behind.clone())
        }
    }

    fn uncollected(delivery: &str, whose: &str) -> Uncollected {
        Uncollected {
            delivery: delivery.to_owned(),
            tenant: whose.to_owned(),
            origin: "alertmanager".to_owned(),
            trace: "4bf92f3577b34da6a3ce929d0e0e4736".to_owned(),
            accepted_at: at(0),
        }
    }

    #[tokio::test]
    async fn each_cutoff_is_its_own_period_before_now() {
        // The one thing this use case decides. A single cutoff for both
        // questions would mean a tenant's backlog was reported for the first
        // time in the pass that deleted it.
        let month: i64 = 30 * 24 * 60 * 60 * 1000;
        let day: i64 = 24 * 60 * 60 * 1000;
        let now = 10 * month;
        let store = Store::holding(Swept::default(), Vec::new());
        let clock = FixedClock(now);

        Retention::new(&store, &clock, MONTH, A_DAY)
            .once()
            .await
            .expect("a pass");

        assert_eq!(
            *store.asked_sweep.lock().expect("not poisoned"),
            vec![now - month]
        );
        assert_eq!(
            *store.asked_behind.lock().expect("not poisoned"),
            vec![now - day]
        );
    }

    #[tokio::test]
    async fn a_healthy_pass_has_nothing_to_say() {
        // So an interval job does not write a line every few minutes. The log
        // somebody reads to find a stopped agent must not be mostly this job
        // reporting that nothing happened.
        let store = Store::holding(Swept::default(), Vec::new());
        let clock = FixedClock(0);

        let reaped = Retention::new(&store, &clock, MONTH, A_DAY)
            .once()
            .await
            .expect("a pass");

        assert!(reaped.quiet());
    }

    #[tokio::test]
    async fn a_deleted_uncollected_delivery_comes_back_to_be_reported() {
        // The third kind of loss (gc-g9x). The use case does not log it itself
        // — the composition root does, because what counts and what writes a
        // line is that crate's business — but it must HAND IT BACK, or the
        // sweep is a shredder with a number attached.
        let store = Store::holding(
            Swept {
                settled: 3,
                uncollected: vec![
                    uncollected("d-1", "wallet-lab-prod"),
                    uncollected("d-2", "wallet-lab-prod"),
                ],
            },
            Vec::new(),
        );
        let clock = FixedClock(0);

        let reaped = Retention::new(&store, &clock, MONTH, A_DAY)
            .once()
            .await
            .expect("a pass");

        assert!(!reaped.quiet());
        assert_eq!(reaped.settled, 3);
        assert_eq!(reaped.uncollected.len(), 2);
        assert_eq!(reaped.uncollected[0].tenant, "wallet-lab-prod");
        // What was lost and whose, and never what it said: nothing here can
        // carry an Event, so no alert summary can reach a log line.
        assert_eq!(reaped.uncollected[0].delivery, "d-1");
        assert_eq!(
            reaped.uncollected[0].trace,
            "4bf92f3577b34da6a3ce929d0e0e4736"
        );
    }

    #[tokio::test]
    async fn a_tenant_falling_behind_is_reported_without_anything_being_deleted() {
        // The case that matters most and is easiest to get wrong: nothing is
        // old enough to delete, and an operator still has to hear about it. If
        // this were silent until the sweep caught up, the first news of a
        // stopped agent would be a month of dropped alerts.
        let store = Store::holding(
            Swept::default(),
            vec![Behind {
                tenant: "wallet-lab-prod".to_owned(),
                outstanding: 412,
                oldest: at(1_000),
            }],
        );
        let clock = FixedClock(0);

        let reaped = Retention::new(&store, &clock, MONTH, A_DAY)
            .once()
            .await
            .expect("a pass");

        assert!(
            !reaped.quiet(),
            "a tenant was 412 behind and nothing said so"
        );
        assert_eq!(reaped.settled, 0);
        assert!(reaped.uncollected.is_empty());
        assert_eq!(reaped.behind[0].outstanding, 412);
    }

    #[tokio::test]
    async fn a_store_that_cannot_be_asked_deletes_nothing_and_says_so() {
        let store = Store::unavailable();
        let clock = FixedClock(0);

        assert_eq!(
            Retention::new(&store, &clock, MONTH, A_DAY).once().await,
            Err(StorageUnavailable)
        );
    }

    #[test]
    #[should_panic(expected = "reported before it is deleted")]
    fn reporting_no_sooner_than_deleting_is_refused_at_startup() {
        // A deployment configured this way would delete a tenant's work in the
        // same pass that first mentioned it. Refused where it is cheap to
        // notice rather than a month into running.
        let store = Store::holding(Swept::default(), Vec::new());
        let clock = FixedClock(0);
        let _ = Retention::new(&store, &clock, MONTH, MONTH);
    }
}
