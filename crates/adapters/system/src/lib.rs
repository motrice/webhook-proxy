//! The clock, the source of identities, and somewhere to wait.
//!
//! Small, but adapters nonetheless: reading the time and inventing an identity
//! are effects, and `purity` fails the build if the domain tries either. Putting
//! them here rather than in the composition root keeps that crate to wiring, and
//! means a test can swap both for something fixed without the binary knowing.

use std::time::{SystemTime, UNIX_EPOCH};

use application::ports::{Clock, Ids, Pause};
use domain::{Correlation, DeliveryId, Timestamp};

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

    fn next_correlation(&self) -> Correlation {
        Correlation::new(&fresh_trace(), &fresh_span(), None)
            .expect("a version 4 uuid is lowercase hexadecimal and never all zeroes")
    }

    fn next_hop_in(&self, chain: &Correlation) -> Correlation {
        chain
            .continued_as(&fresh_span())
            .expect("a version 4 uuid is lowercase hexadecimal and never all zeroes")
    }
}

/// Thirty-two lowercase hexadecimal characters, never all zeroes.
///
/// A version 4 uuid in its simple form is exactly that length, and its version
/// nibble is always `4`, so the all-zeroes value the standard reserves cannot
/// come out of here. That is why the callers above may `expect`.
fn fresh_trace() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

/// Sixteen of them, with the same guarantee.
///
/// The SECOND half of a fresh uuid, not the first. The variant bits live at the
/// start of that half, so it is never all zeroes either; the first half is
/// unconstrained random and could in principle be. One in sixteen to the
/// sixteenth is not a risk worth taking when the alternative is choosing a
/// different substring.
fn fresh_span() -> String {
    uuid::Uuid::new_v4().simple().to_string()[16..].to_owned()
}

#[cfg(test)]
mod tests {
    use application::ports::{Clock, Ids};

    #[test]
    fn a_generated_correlation_is_well_formed_and_starts_a_chain() {
        let started = RandomIds.next_correlation();

        assert_eq!(started.trace().len(), 32);
        assert_eq!(started.span().len(), 16);
        assert_eq!(started.state(), None, "we invent no state for anyone");
    }

    #[test]
    fn two_generated_correlations_share_nothing() {
        // The point of generating rather than refusing: two senders that both
        // sent no correlation must not end up looking like one call chain.
        let one = RandomIds.next_correlation();
        let other = RandomIds.next_correlation();

        assert_ne!(one.trace(), other.trace());
        assert_ne!(one.span(), other.span());
    }

    #[test]
    fn a_new_hop_keeps_the_chain_and_changes_only_the_hop() {
        let received = RandomIds.next_correlation();
        let onward = RandomIds.next_hop_in(&received);

        assert_eq!(onward.trace(), received.trace(), "same chain");
        assert_ne!(onward.span(), received.span(), "different call");
    }

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

/// Waiting, on the runtime.
///
/// An adapter for the same reason the clock is one: sleeping is an effect, and
/// the application layer is allowed `thiserror` and `async-trait` and nothing
/// else, so it could not reach a runtime even if a use case wanted to. That
/// restriction is what lets a test prove a thirty-one second retry budget in
/// no time at all.
#[derive(Debug, Clone, Copy, Default)]
pub struct Resting;

#[async_trait::async_trait]
impl Pause for Resting {
    async fn rest(&self, how_long: core::time::Duration) {
        tokio::time::sleep(how_long).await;
    }
}

#[cfg(test)]
mod waiting {
    use application::ports::Pause;

    use super::Resting;

    /// Waiting waits, which sounds too obvious to test until you notice that
    /// the retry budget is five of these and that a `Pause` which returned
    /// immediately would turn a thirty-one second budget into five attempts in
    /// a row against a room that is down.
    ///
    /// `start_paused` makes the clock a value rather than a wall: the sleep
    /// below is instant, and the assertion is still about the time that was
    /// meant to pass.
    #[tokio::test(start_paused = true)]
    async fn resting_waits_as_long_as_it_was_asked_to() {
        let began = tokio::time::Instant::now();

        Resting.rest(core::time::Duration::from_secs(30)).await;

        assert!(began.elapsed() >= core::time::Duration::from_secs(30));
    }
}
