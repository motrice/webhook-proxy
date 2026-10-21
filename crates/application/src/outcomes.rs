//! What each room was told, as its tenant reported it.
//!
//! Bead gc-556, and the thing it fixes is worth stating: an abandoned dispatch
//! used to be visible in exactly one place — the agent's own log, in one pod,
//! for as long as that pod lived. The sender is told `202` the moment a
//! delivery is stored, which is the right contract, so every signal upstream
//! stays green while a room goes quiet. The platform's own counters could not
//! see it either: the delivery WAS collected, so nothing was uncollected and
//! nothing was outstanding.
//!
//! COUNTED HERE RATHER THAN IN THE AGENT, which was a decision (gc-556). An
//! agent has no scrape endpoint and bead gc-72e forbade it one — no Service, no
//! `HTTPRoute`, no ingress `NetworkPolicy` — so a counter there would have needed
//! that property reopened or a push-based dependency added. The outcomes
//! already cross the wire in every report, so the platform counts what it is
//! told. Two consequences, and both are honest rather than incidental:
//!
//! - A loss the agent never manages to report is not counted. Its lease lapses
//!   and the Delivery is offered again, so the work is not lost; the record of
//!   that attempt is.
//! - The counter lives in the platform, so it survives an agent restart —
//!   which is the specific failure that made the log useless: a routine apply
//!   rolled the agent and took the only evidence of a real loss with it.

use std::collections::BTreeMap;
use std::sync::Mutex;

use crate::ports::RoomOutcome;

/// Deliveries each room was told about, and the ones it was not.
///
/// Read by the metrics endpoint and written when a report is accepted. Keyed by
/// the tenant AND the room, because a room identity is only unique within the
/// tenant that configured it: two tenants may each have an `oncall-room`, and
/// collapsing them would add two teams' numbers together.
#[derive(Debug, Default)]
pub struct Outcomes {
    /// Rooms that were told, by (tenant, room).
    delivered: Mutex<BTreeMap<(String, String), u64>>,
    /// Rooms that were not, by (tenant, room, reason). EVERY ONE IS A LOSS.
    ///
    /// The reason is part of the key rather than a separate total, because the
    /// four are not interchangeable to whoever acts on one: a room that refused
    /// needs a configuration change, a room that was never reached needs the
    /// network looked at, and `Intercepted` means something answered on the
    /// room's behalf and the room never saw it at all.
    abandoned: Mutex<BTreeMap<(String, String, &'static str), u64>>,
}

impl Outcomes {
    /// Nothing counted yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one terminal statement about one room.
    ///
    /// Called ONLY for a report that discharged something. A report that
    /// arrives twice — an agent whose first reply was lost — must not count
    /// twice, and the store is what knows the difference: it answers
    /// `NotOutstanding` the second time.
    pub fn reported(&self, tenant: &str, room: &str, outcome: RoomOutcome) {
        match outcome {
            RoomOutcome::Delivered => {
                if let Ok(mut counted) = self.delivered.lock() {
                    *counted
                        .entry((tenant.to_owned(), room.to_owned()))
                        .or_default() += 1;
                }
            }
            RoomOutcome::Abandoned(why) => {
                if let Ok(mut counted) = self.abandoned.lock() {
                    *counted
                        .entry((tenant.to_owned(), room.to_owned(), why.spelled()))
                        .or_default() += 1;
                }
            }
        }
    }

    /// Every room that was told, with how many times.
    #[must_use]
    pub fn delivered(&self) -> Vec<((String, String), u64)> {
        self.delivered.lock().map_or_else(
            |_| Vec::new(),
            |counted| counted.iter().map(|(at, n)| (at.clone(), *n)).collect(),
        )
    }

    /// Every room that was not told, with why and how many times.
    #[must_use]
    pub fn abandoned(&self) -> Vec<((String, String, &'static str), u64)> {
        self.abandoned.lock().map_or_else(
            |_| Vec::new(),
            |counted| counted.iter().map(|at| (at.0.clone(), *at.1)).collect(),
        )
    }

    /// Every loss reported so far, across every tenant and room.
    ///
    /// The one number an alert can be written against without knowing which
    /// rooms exist.
    #[must_use]
    pub fn losses(&self) -> u64 {
        self.abandoned
            .lock()
            .map_or(0, |counted| counted.values().sum())
    }
}

#[cfg(test)]
mod tests {
    use super::Outcomes;
    use crate::ports::{DispatchFailed, RoomOutcome};

    #[test]
    fn a_room_that_was_told_is_counted_against_its_own_tenant() {
        // Keyed by tenant AND room, because a room identity is unique only
        // within the tenant that configured it. Two tenants with an
        // `oncall-room` each must not be one number.
        let counted = Outcomes::new();

        counted.reported("devsecops", "oncall-room", RoomOutcome::Delivered);
        counted.reported("devsecops", "oncall-room", RoomOutcome::Delivered);
        counted.reported("platform", "oncall-room", RoomOutcome::Delivered);

        let delivered = counted.delivered();
        assert_eq!(delivered.len(), 2, "{delivered:?}");
        assert_eq!(
            delivered
                .iter()
                .find(|((tenant, _), _)| tenant == "devsecops")
                .map(|(_, n)| *n),
            Some(2)
        );
        assert_eq!(
            delivered
                .iter()
                .find(|((tenant, _), _)| tenant == "platform")
                .map(|(_, n)| *n),
            Some(1)
        );
        assert_eq!(counted.losses(), 0, "a delivery was counted as a loss");
    }

    #[test]
    fn a_loss_keeps_its_reason_rather_than_being_one_total() {
        // The distinction an operator acts on: a room that refused needs a
        // configuration change, a room that was never reached needs the network
        // looked at. One `abandoned_total` would have cost exactly that.
        let counted = Outcomes::new();

        counted.reported(
            "devsecops",
            "oncall-room",
            RoomOutcome::Abandoned(DispatchFailed::Rejected),
        );
        counted.reported(
            "devsecops",
            "oncall-room",
            RoomOutcome::Abandoned(DispatchFailed::TimedOut),
        );
        counted.reported(
            "devsecops",
            "oncall-room",
            RoomOutcome::Abandoned(DispatchFailed::TimedOut),
        );

        let abandoned = counted.abandoned();
        assert_eq!(abandoned.len(), 2, "{abandoned:?}");
        assert_eq!(
            abandoned
                .iter()
                .find(|((_, _, why), _)| *why == "timed_out")
                .map(|(_, n)| *n),
            Some(2)
        );
        assert_eq!(
            abandoned
                .iter()
                .find(|((_, _, why), _)| *why == "rejected")
                .map(|(_, n)| *n),
            Some(1)
        );
        // And the one number an alert can name without knowing the rooms.
        assert_eq!(counted.losses(), 3);
    }

    #[test]
    fn every_reason_has_a_label_of_its_own() {
        // A fifth DispatchFailed variant would not compile against
        // `DispatchFailed::spelled` until somebody chose its word, which is the
        // point: these words are a published interface — a stored row, a wire
        // format and a metric label — and a new one should be decided rather
        // than derived.
        let counted = Outcomes::new();
        for why in [
            DispatchFailed::Rejected,
            DispatchFailed::Intercepted,
            DispatchFailed::Unreachable,
            DispatchFailed::TimedOut,
        ] {
            counted.reported("a-tenant", "a-room", RoomOutcome::Abandoned(why));
        }

        let labels: Vec<&str> = counted
            .abandoned()
            .iter()
            .map(|((_, _, why), _)| *why)
            .collect();
        assert_eq!(labels.len(), 4, "two reasons share a label: {labels:?}");
        assert_eq!(counted.losses(), 4);
    }
}
