//! The clock and the source of identities.
//!
//! Small, but adapters nonetheless: reading the time and inventing an identity
//! are effects, and `purity` fails the build if the domain tries either. Putting
//! them here rather than in the composition root keeps that crate to wiring, and
//! means a test can swap both for something fixed without the binary knowing.

use std::time::{SystemTime, UNIX_EPOCH};

use application::ports::{Clock, Ids};
use domain::{DeliveryId, Timestamp};

/// The machine's clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    /// The current moment.
    ///
    /// A clock set before 1970 yields the epoch rather than panicking: a wrong
    /// timestamp on a log line is a smaller problem than a process that will not
    /// start, and this is the only sensible thing to do without a way to fail.
    fn now(&self) -> Timestamp {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| {
                i64::try_from(since.as_millis()).unwrap_or(i64::MAX)
            });

        Timestamp::from_millis_since_epoch(millis)
    }
}

/// Random identities.
#[derive(Debug, Clone, Copy, Default)]
pub struct RandomIds;

impl Ids for RandomIds {
    /// A fresh identity, unique across restarts.
    ///
    /// Random rather than sequential on purpose: a counter would repeat after a
    /// restart, and these identities are what a loss report names — two different
    /// deliveries sharing one would make the log lie.
    fn next_delivery_id(&self) -> DeliveryId {
        DeliveryId::new(&uuid::Uuid::new_v4().to_string()).expect("a uuid is never blank")
    }
}

#[cfg(test)]
mod tests {
    use application::ports::{Clock, Ids};

    use super::{RandomIds, SystemClock};

    #[test]
    fn the_clock_reports_a_moment_in_this_century() {
        // 2020-01-01. A clock reporting the epoch means `duration_since` failed,
        // which is worth noticing in a test rather than in production.
        let now = SystemClock.now().millis_since_epoch();

        assert!(now > 1_577_836_800_000, "clock reported {now}");
    }

    #[test]
    fn two_identities_are_never_the_same() {
        let first = RandomIds.next_delivery_id();
        let second = RandomIds.next_delivery_id();

        assert_ne!(first, second);
    }

    #[test]
    fn an_identity_is_long_enough_to_be_worth_logging() {
        assert_eq!(RandomIds.next_delivery_id().as_str().len(), 36);
    }
}
