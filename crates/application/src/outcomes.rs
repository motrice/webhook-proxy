//! What each room was told, as its tenant reported it, and what nobody was
//! ever told because nobody collected it.
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
//!
//! AND NOT IN THIS PROCESS EITHER, SINCE BEAD gc-5px. That last sentence was
//! true of the agent and false of the platform: these were three counters in
//! process memory, so the apply that rolled the PROXY destroyed the same
//! evidence one layer up, and two replicas behind a Service each held a share
//! of numbers that read as cluster-wide. The store counts them now
//! ([`crate::ports::Handover::counted`]) and this type holds the last answer it
//! gave, so a scrape never touches the database — the same arrangement, and for
//! the same reasons, as [`crate::Backlog`].
//!
//! THE DROPPED COUNT MOVED HERE FROM [`crate::Backlog`] in that bead, and the
//! reason is which half of `Backlog` it belonged to. What is left there is an
//! exception list replaced wholesale every pass: a tenant that has caught up
//! must stop being reported. A count of Deliveries deleted uncollected is the
//! opposite — monotone, cumulative, and now read from the same store answer as
//! the other two. Keeping it beside the gauge would have meant one task writing
//! two types from one answer, and a reader having to learn that `losses` meant
//! something different in each.

use std::sync::Mutex;

use crate::ports::{Counted, PerReason, PerRoom, PerTenant};

/// The store's last word on what each room was told, and what was dropped.
///
/// Read by the metrics endpoint and written by the task that asks the store on
/// an interval, which is why it is shared rather than owned: a scrape must
/// never touch the store, because a monitoring system polling every fifteen
/// seconds would become load on the thing it is monitoring and would go quiet
/// exactly when the database is in trouble — which is when somebody is looking.
///
/// So what a scrape reads is at most one interval old. That is the whole cost
/// of these numbers being right at all, and it is a cost an operator can act on:
/// a number that is five seconds stale and cluster-wide beats one that is
/// current, one replica's share, and reset by the last deployment.
#[derive(Debug, Default)]
pub struct Outcomes {
    /// The last answer, whole.
    ///
    /// ONE LOCK OVER ALL THREE COUNTS rather than one each, because they are
    /// read together by one scrape and written together by one pass: three
    /// locks would let a scrape land between two of them and export a
    /// `delivered` from this pass beside an `abandoned` from the one before.
    counted: Mutex<Counted>,
}

impl Outcomes {
    /// Nothing read yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The store's latest answer, in place of the one before it.
    ///
    /// REPLACED WHOLESALE rather than merged, and this is the one thing an
    /// implementation here could get wrong: the store answers absolute totals,
    /// so merging would add every count to itself on the second pass. It is
    /// also what lets a key disappear — a room nobody has configured since the
    /// counts were last trimmed stops being exported rather than standing
    /// forever.
    pub fn counted(&self, counted: Counted) {
        if let Ok(mut held) = self.counted.lock() {
            *held = counted;
        }
    }

    /// Every room that was told, with how many times.
    #[must_use]
    pub fn delivered(&self) -> Vec<PerRoom> {
        self.counted
            .lock()
            .map_or_else(|_| Vec::new(), |counted| counted.delivered.clone())
    }

    /// Every room that was not told, with why and how many times.
    #[must_use]
    pub fn abandoned(&self) -> Vec<PerReason> {
        self.counted
            .lock()
            .map_or_else(|_| Vec::new(), |counted| counted.abandoned.clone())
    }

    /// Every Delivery deleted before its tenant ever collected it, by tenant.
    #[must_use]
    pub fn dropped(&self) -> Vec<PerTenant> {
        self.counted
            .lock()
            .map_or_else(|_| Vec::new(), |counted| counted.dropped.clone())
    }

    /// Every loss a tenant has reported, across every tenant and room.
    ///
    /// The one number an alert can be written against without knowing which
    /// rooms exist.
    #[must_use]
    pub fn losses(&self) -> u64 {
        self.counted.lock().map_or(0, |counted| {
            counted.abandoned.iter().map(|one| one.count).sum()
        })
    }

    /// Every Delivery deleted before anybody collected it, across every tenant.
    ///
    /// The same kind of number as [`Self::losses`] and for the same reason, and
    /// a loss just as much: nobody was told anything at all about these.
    #[must_use]
    pub fn never_collected(&self) -> u64 {
        self.counted.lock().map_or(0, |counted| {
            counted.dropped.iter().map(|one| one.count).sum()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::Outcomes;
    use crate::ports::{Counted, PerReason, PerRoom, PerTenant};

    #[test]
    fn the_newest_answer_replaces_the_one_before_it_rather_than_adding_to_it() {
        // THE PROPERTY THAT CHANGED IN BEAD gc-5px, and the one worth a test of
        // its own, because the method it replaced did the opposite. This used to
        // accumulate: a report arrived and the number went up by one. It now
        // holds whatever the store last said, and the store says an absolute
        // total — so an implementation that merged instead of replacing would
        // double every count on the second pass, and the metric would look like
        // traffic doubling rather than like a bug.
        let told = Outcomes::new();
        let answer = |delivered: u64| Counted {
            delivered: vec![PerRoom {
                tenant: "devsecops".to_owned(),
                room: "oncall-room".to_owned(),
                count: delivered,
            }],
            abandoned: Vec::new(),
            dropped: Vec::new(),
        };

        told.counted(answer(7));
        told.counted(answer(9));

        assert_eq!(
            told.delivered()
                .iter()
                .map(|one| one.count)
                .collect::<Vec<_>>(),
            vec![9],
            "two passes were added together instead of the second replacing the first"
        );
    }

    #[test]
    fn a_bare_total_is_every_rooms_number_added_up() {
        // THE LINE AN ALERT CAN BE WRITTEN AGAINST WITHOUT KNOWING WHICH ROOMS
        // EXIST, which is why the labelled series are not enough on their own:
        // a rule naming a room that has not been configured yet never fires.
        //
        // Summed HERE and not in the store, deliberately. The store answers the
        // labelled rows and nothing else, so there is exactly one place where
        // the relationship between a total and its parts is decided, and it is
        // the place with a test on it.
        let told = Outcomes::new();
        told.counted(Counted {
            delivered: Vec::new(),
            abandoned: vec![
                PerReason {
                    tenant: "devsecops".to_owned(),
                    room: "oncall-room".to_owned(),
                    reason: "timed_out".to_owned(),
                    count: 2,
                },
                PerReason {
                    tenant: "platform".to_owned(),
                    room: "oncall-room".to_owned(),
                    reason: "rejected".to_owned(),
                    count: 1,
                },
            ],
            dropped: vec![
                PerTenant {
                    tenant: "devsecops".to_owned(),
                    count: 4,
                },
                PerTenant {
                    tenant: "platform".to_owned(),
                    count: 1,
                },
            ],
        });

        assert_eq!(told.losses(), 3, "the losses of two tenants did not add up");
        // A DIFFERENT KIND OF LOSS AND A SEPARATE NUMBER. These were never told
        // to anybody at all — no room refused them and no network swallowed
        // them, their tenant never came for them — so folding them into
        // `losses` would send somebody reading a dashboard to look at a room
        // that was working fine.
        assert_eq!(told.never_collected(), 5);
    }
}
