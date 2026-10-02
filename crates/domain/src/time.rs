//! Moments.

/// A moment, as milliseconds since the Unix epoch.
///
/// The domain never asks what time it is — that is an effect, and `purity`
/// fails the build if anything here tries. A Timestamp only ever arrives as an
/// argument, from a Clock port implemented by an adapter, which is what lets
/// every test in this crate run in microseconds and never flake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp(i64);

impl Timestamp {
    /// A moment, counted from the Unix epoch. Negative values are moments
    /// before it, which is unusual but not wrong.
    #[must_use]
    pub const fn from_millis_since_epoch(millis: i64) -> Self {
        Self(millis)
    }

    /// Milliseconds since the Unix epoch.
    #[must_use]
    pub const fn millis_since_epoch(self) -> i64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::Timestamp;

    #[test]
    fn a_timestamp_keeps_the_moment_it_was_given() {
        assert_eq!(
            Timestamp::from_millis_since_epoch(1_759_000_000_000).millis_since_epoch(),
            1_759_000_000_000
        );
    }

    #[test]
    fn timestamps_order_by_when_they_happened() {
        let earlier = Timestamp::from_millis_since_epoch(1);
        let later = Timestamp::from_millis_since_epoch(2);

        assert!(earlier < later);
    }
}
