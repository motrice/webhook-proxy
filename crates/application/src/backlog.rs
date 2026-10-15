//! What a tenant has not collected, and what was dropped because of it.
//!
//! The counting half of bead gc-wcw.3. Separate from [`crate::Tally`] because
//! it answers a different question about a different thing: that one is "which
//! room is being told how much", keyed by room; this is "which tenant has
//! stopped keeping up", keyed by tenant. One type holding both would be keyed
//! by neither.
//!
//! WHY THIS EXISTS AT ALL: bead gc-g9x deferred the read API on the promise
//! that an operator could still tell when an agent had stopped. The platform
//! refuses to invent "abandoned on the tenant's behalf" — it keeps offering —
//! so a count and an age are the whole of what it owes instead. With no API,
//! this and the log line beside it are the only way anybody finds out.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use domain::Timestamp;

use crate::ports::Behind;

/// How far behind each tenant is, and how much has been dropped.
///
/// Read by the metrics endpoint and written by the retention job, which is why
/// it is shared rather than owned: a scrape must never touch the store, because
/// a monitoring system polling every fifteen seconds would become load on the
/// thing it is monitoring and would go quiet exactly when the database is in
/// trouble — which is when somebody is looking.
#[derive(Debug, Default)]
pub struct Backlog {
    /// The last pass's answer, keyed by the tenant's text.
    ///
    /// REPLACED WHOLESALE each pass rather than merged, because `behind` returns
    /// an exception list: a tenant that has caught up is absent from it, and
    /// merging would leave its last bad number standing forever. The series
    /// disappearing is how a scraper learns it recovered.
    behind: Mutex<BTreeMap<String, Outstanding>>,
    /// Deliveries deleted that no tenant ever collected. A running total, and
    /// the only one of these numbers that is a loss count.
    dropped: AtomicU64,
}

/// One tenant's backlog, as of the last pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outstanding {
    /// How many Deliveries are owed and older than the reporting threshold.
    pub owed: usize,
    /// When the oldest of them was accepted. The number an operator acts on: a
    /// count alone cannot distinguish a busy tenant from a stopped one.
    pub oldest: Timestamp,
}

impl Backlog {
    /// Nothing known yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// What the last pass found.
    pub fn found(&self, behind: &[Behind]) {
        if let Ok(mut held) = self.behind.lock() {
            *held = behind
                .iter()
                .map(|one| {
                    (
                        one.tenant.clone(),
                        Outstanding {
                            owed: one.outstanding,
                            oldest: one.oldest,
                        },
                    )
                })
                .collect();
        }
    }

    /// That many more Deliveries were deleted without ever being collected.
    pub fn dropped(&self, how_many: usize) {
        self.dropped.fetch_add(how_many as u64, Ordering::Relaxed);
    }

    /// Every tenant that was behind when anybody last looked.
    #[must_use]
    pub fn all(&self) -> Vec<(String, Outstanding)> {
        self.behind.lock().map_or_else(
            |_| Vec::new(),
            |held| held.iter().map(|(k, v)| (k.clone(), *v)).collect(),
        )
    }

    /// How many Deliveries have been dropped uncollected since start.
    ///
    /// The third kind of loss gc-g9x enumerated, and the one no other counter
    /// can see: a room that gave up is counted against that room, and a tenant
    /// that never collected has no room to count against.
    #[must_use]
    pub fn losses(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use domain::Timestamp;

    use super::Backlog;
    use crate::ports::Behind;

    fn at(millis: i64) -> Timestamp {
        Timestamp::from_millis_since_epoch(millis)
    }

    fn behind(tenant: &str, owed: usize, oldest: i64) -> Behind {
        Behind {
            tenant: tenant.to_owned(),
            outstanding: owed,
            oldest: at(oldest),
        }
    }

    #[test]
    fn a_tenant_that_caught_up_stops_being_reported() {
        // The reason the map is replaced rather than merged. A merged map would
        // leave a recovered tenant's worst number standing forever, and
        // somebody would eventually act on it.
        let backlog = Backlog::new();

        backlog.found(&[
            behind("wallet-lab-prod", 412, 1),
            behind("wallet-hsm-prod", 3, 2),
        ]);
        assert_eq!(backlog.all().len(), 2);

        backlog.found(&[behind("wallet-hsm-prod", 3, 2)]);
        let still = backlog.all();
        assert_eq!(still.len(), 1);
        assert_eq!(still[0].0, "wallet-hsm-prod");
    }

    #[test]
    fn a_backlog_carries_its_oldest_and_not_only_a_count() {
        let backlog = Backlog::new();
        backlog.found(&[behind("wallet-lab-prod", 412, 7)]);

        let (tenant, outstanding) = backlog.all().remove(0);
        assert_eq!(tenant, "wallet-lab-prod");
        assert_eq!(outstanding.owed, 412);
        assert_eq!(outstanding.oldest, at(7));
    }

    #[test]
    fn dropped_deliveries_accumulate_and_are_losses() {
        // A running total, unlike the backlog above: a loss that scrolled past
        // is still a loss, and a counter that reset each pass would make them
        // invisible to anything but a scrape timed perfectly.
        let backlog = Backlog::new();

        assert_eq!(backlog.losses(), 0);
        backlog.dropped(2);
        backlog.dropped(5);
        assert_eq!(backlog.losses(), 7);

        // And a pass that found a backlog does not touch the loss count: being
        // behind is not yet a loss, which is the distinction the whole bead
        // rests on.
        backlog.found(&[behind("wallet-lab-prod", 412, 1)]);
        assert_eq!(backlog.losses(), 7);
    }
}
