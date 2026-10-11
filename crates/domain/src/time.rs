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

    /// The moment this long after.
    ///
    /// A Duration is a value, not an effect — nothing here reads a clock — so
    /// this stays in the domain rather than becoming arithmetic every caller
    /// repeats. Saturating rather than wrapping: a moment far enough in the
    /// future to overflow is wrong, and a moment that silently became the distant
    /// past would make something due immediately and retry forever.
    #[must_use]
    pub fn after(self, elapsed: core::time::Duration) -> Self {
        let millis = i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX);
        Self(self.0.saturating_add(millis))
    }
}

#[cfg(test)]
mod tests {
    use super::Timestamp;

    #[test]
    fn a_moment_after_another_is_that_much_later() {
        let now = Timestamp::from_millis_since_epoch(1_759_000_000_000);

        assert_eq!(
            now.after(core::time::Duration::from_millis(1_500)),
            Timestamp::from_millis_since_epoch(1_759_000_001_500)
        );
    }

    #[test]
    fn a_duration_too_large_to_add_saturates_rather_than_wrapping() {
        // Wrapping would put the moment in the distant past, which would make a
        // Dispatch due immediately and retried forever — a quiet infinite loop
        // rather than a loud error.
        let now = Timestamp::from_millis_since_epoch(1_759_000_000_000);

        assert_eq!(
            now.after(core::time::Duration::MAX).millis_since_epoch(),
            i64::MAX
        );
    }

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
