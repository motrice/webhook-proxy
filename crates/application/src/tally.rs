//! How much each room is being told, and how much of it was lost.

use std::collections::HashMap;
use std::sync::Mutex;

use domain::DestinationId;

/// What each Destination has been sent, counted since this process started.
///
/// Per Destination rather than one number for the deployment, because the
/// question this exists to answer is *which room is noisy*. A global count says
/// a thousand messages went somewhere, which nobody can act on; the whole point
/// is to notice a room being flooded before somebody mutes it, and a muted
/// channel stays muted long after the incident that caused it.
///
/// Shared rather than owned by one adapter, because a Dispatch is attempted in
/// two places now: the request path sends immediately, and the worker comes
/// back to whatever failed. A count living in the inbound adapter would miss
/// every retry, and the numbers would quietly stop adding up.
///
/// It holds no address and no secret, and cannot: a `DestinationId` is a name,
/// and where a Destination lives is configuration belonging to the adapter that
/// reaches it.
#[derive(Debug, Default)]
pub struct Tally {
    // Keyed by the identity's text rather than by DestinationId, which is
    // deliberately neither Hash nor Ord: nothing in the domain orders or hashes
    // identities, and deriving either so a counter could use a map would be the
    // tail wagging the dog.
    counted: Mutex<HashMap<String, Counts>>,
}

/// What became of the Dispatches bound for one Destination.
///
/// Three numbers that compose: every Dispatch ends up in exactly one of them,
/// or in none yet because it is still waiting. `delivered` is what a reader in
/// that room actually saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Counts {
    /// Arrived. What the room saw.
    pub delivered: u64,
    /// Failed, and stored for another attempt. Not a loss.
    pub retrying: u64,
    /// Given up on. These are the losses.
    pub abandoned: u64,
}

impl Tally {
    /// Nothing counted yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// One more Dispatch arrived at this Destination.
    pub fn delivered(&self, destination: &DestinationId) {
        self.add(destination, |counts| counts.delivered += 1);
    }

    /// One more Dispatch failed and will be tried again.
    ///
    /// Counted per attempt rather than per Dispatch, so a Destination that is
    /// down shows a number that keeps climbing — which is the signal. It is
    /// therefore *not* the count of messages waiting, and README says so.
    pub fn retrying(&self, destination: &DestinationId) {
        self.add(destination, |counts| counts.retrying += 1);
    }

    /// One more Dispatch was given up on.
    pub fn abandoned(&self, destination: &DestinationId) {
        self.add(destination, |counts| counts.abandoned += 1);
    }

    /// What has become of everything bound for this Destination.
    #[must_use]
    pub fn counts(&self, destination: &DestinationId) -> Counts {
        self.counted
            .lock()
            .map(|counted| {
                counted
                    .get(destination.as_str())
                    .copied()
                    .unwrap_or_default()
            })
            .unwrap_or_default()
    }

    /// Every Destination anything has been sent to, with its counts.
    ///
    /// In a stable order, so two readings taken a minute apart can be compared
    /// line by line.
    #[must_use]
    pub fn all(&self) -> Vec<(String, Counts)> {
        let mut counted: Vec<(String, Counts)> = self
            .counted
            .lock()
            .map(|counted| {
                counted
                    .iter()
                    .map(|(id, counts)| (id.clone(), *counts))
                    .collect()
            })
            .unwrap_or_default();
        counted.sort_by(|(left, _), (right, _)| left.cmp(right));
        counted
    }

    /// Dispatches given up on, across every Destination.
    ///
    /// The number the delivery promise is about: a best-effort system whose
    /// losses are invisible is indistinguishable from a broken one.
    #[must_use]
    pub fn losses(&self) -> u64 {
        self.counted
            .lock()
            .map(|counted| counted.values().map(|counts| counts.abandoned).sum())
            .unwrap_or_default()
    }

    fn add(&self, destination: &DestinationId, change: impl FnOnce(&mut Counts)) {
        // A poisoned lock means a thread panicked holding it. Losing a count is
        // not worth propagating an error through a dispatch path, and it is not
        // worth panicking a second time either: the numbers are for a human
        // looking at trends, not for anything that decides.
        if let Ok(mut counted) = self.counted.lock() {
            change(counted.entry(destination.as_str().to_owned()).or_default());
        }
    }
}

#[cfg(test)]
mod tests {
    use domain::DestinationId;

    use super::{Counts, Tally};

    fn room(id: &str) -> DestinationId {
        DestinationId::new(id).expect("a non-blank id")
    }

    #[test]
    fn a_room_nothing_was_sent_to_counts_zero_rather_than_being_absent() {
        // An operator asking about a quiet room should be told it is quiet, not
        // be left to wonder whether the question was understood.
        assert_eq!(Tally::new().counts(&room("never")), Counts::default());
    }

    #[test]
    fn what_a_room_saw_is_counted_apart_from_what_it_did_not() {
        let tally = Tally::new();

        tally.delivered(&room("devsecops-room"));
        tally.delivered(&room("devsecops-room"));
        tally.retrying(&room("devsecops-room"));
        tally.abandoned(&room("devsecops-room"));

        assert_eq!(
            tally.counts(&room("devsecops-room")),
            Counts {
                delivered: 2,
                retrying: 1,
                abandoned: 1
            }
        );
    }

    #[test]
    fn rooms_are_counted_apart_from_each_other() {
        // The whole reason this is per Destination. A global number says a
        // thousand messages went somewhere, which nobody can act on; the
        // question is always *which room*.
        let tally = Tally::new();

        tally.delivered(&room("devsecops-room"));
        tally.abandoned(&room("platform-room"));

        assert_eq!(tally.counts(&room("devsecops-room")).delivered, 1);
        assert_eq!(tally.counts(&room("devsecops-room")).abandoned, 0);
        assert_eq!(tally.counts(&room("platform-room")).delivered, 0);
        assert_eq!(tally.counts(&room("platform-room")).abandoned, 1);
    }

    #[test]
    fn the_numbers_compose_so_arithmetic_on_them_is_right() {
        // Two numbers invite arithmetic, and the arithmetic should be right.
        // Every Dispatch bound for a room ends in exactly one of delivered or
        // abandoned, or in neither because it is still waiting — so delivered
        // plus abandoned is what has finished, and never more than was sent.
        let tally = Tally::new();

        // Five Dispatches: three arrived, one is still being retried, one was
        // given up on after being retried twice.
        for _ in 0..3 {
            tally.delivered(&room("a-room"));
        }
        tally.retrying(&room("a-room"));
        tally.retrying(&room("a-room"));
        tally.retrying(&room("a-room"));
        tally.abandoned(&room("a-room"));

        let counts = tally.counts(&room("a-room"));
        assert_eq!(counts.delivered + counts.abandoned, 4, "four have finished");
        // Retries are counted per attempt, not per Dispatch, so they do NOT
        // subtract into anything. That is the trap in these three numbers and
        // the reason README says what they mean.
        assert_eq!(counts.retrying, 3);
    }

    #[test]
    fn losses_are_the_abandoned_ones_across_every_room() {
        // The number the delivery promise is about. A retry is not a loss: it
        // is stored and something will come back to it.
        let tally = Tally::new();

        tally.abandoned(&room("a-room"));
        tally.abandoned(&room("b-room"));
        tally.retrying(&room("c-room"));
        tally.delivered(&room("d-room"));

        assert_eq!(tally.losses(), 2);
    }

    #[test]
    fn every_room_anything_was_sent_to_is_listed_in_a_stable_order() {
        // Two readings a minute apart should be comparable line by line.
        let tally = Tally::new();

        tally.delivered(&room("platform-room"));
        tally.delivered(&room("audit-room"));
        tally.delivered(&room("devsecops-room"));

        let listed: Vec<String> = tally.all().into_iter().map(|(id, _)| id).collect();
        assert_eq!(
            listed,
            vec!["audit-room", "devsecops-room", "platform-room"]
        );
    }

    #[test]
    fn nothing_here_can_hold_an_address_or_a_secret() {
        // A DestinationId is a name. Where a Destination lives is configuration
        // belonging to the adapter that reaches it, and these numbers are the
        // sort of thing that ends up on a dashboard.
        let tally = Tally::new();
        tally.delivered(&room("devsecops-room"));

        let printed = format!("{tally:?}");

        assert!(printed.contains("devsecops-room"), "{printed}");
        assert!(!printed.contains("http"), "{printed}");
    }
}
