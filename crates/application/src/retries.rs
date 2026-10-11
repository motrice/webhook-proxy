//! The second half of the promise: what happens to a Dispatch that failed.

use domain::DispatchId;

use crate::ports::{Attempt, Clock, Dispatcher, Outbox, StorageUnavailable};
use crate::relay::Retry;

/// What one pass over the outbox did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Attempted {
    /// Destinations that were told this time.
    pub delivered: Vec<domain::DestinationId>,
    /// Destinations that could not be told, and are due again later.
    pub retrying: Vec<domain::DestinationId>,
    /// Destinations that will not be told. These are losses.
    ///
    /// Named rather than counted, because the question anybody asks of these
    /// numbers is *which room*, and a worker that reported only totals would
    /// make a flooded or a failing room invisible.
    pub abandoned: Vec<domain::DestinationId>,
}

impl Attempted {
    /// Whether anything at all was tried.
    #[must_use]
    pub fn idle(&self) -> bool {
        self.delivered.is_empty() && self.retrying.is_empty() && self.abandoned.is_empty()
    }
}

/// Tries again, for Dispatches the inbound path could not deliver.
///
/// Separate from [`crate::Relay`] on purpose. The relay sends immediately,
/// because a Notice that waited for a poll would make every room slower in the
/// common case where nothing has failed. This is what makes a failure
/// survivable rather than what makes a success slow.
///
/// It holds no schedule. One pass is a value this returns; how often to make a
/// pass is the composition root's business, because sleeping is an effect and
/// this crate has none.
pub struct Retries<'a> {
    dispatcher: &'a dyn Dispatcher,
    outbox: &'a dyn Outbox,
    clock: &'a dyn Clock,
    retry: Retry,
}

impl<'a> Retries<'a> {
    /// Wires the worker to the outside world.
    #[must_use]
    pub fn new(
        dispatcher: &'a dyn Dispatcher,
        outbox: &'a dyn Outbox,
        clock: &'a dyn Clock,
        retry: Retry,
    ) -> Self {
        Self {
            dispatcher,
            outbox,
            clock,
            retry,
        }
    }

    /// Takes what is due, at most `limit` of it, and tries each once.
    ///
    /// Bounded rather than draining, so one pass cannot hold a connection or a
    /// replica for an unbounded time, and so two replicas share the work rather
    /// than one taking all of it.
    ///
    /// # Errors
    ///
    /// [`StorageUnavailable`] if the outbox could not be asked at all. Nothing
    /// was attempted, and the caller tries again on its next pass — there is no
    /// sender waiting on this, so unlike the inbound path there is nobody to
    /// refuse.
    pub async fn once(&self, limit: usize) -> Result<Attempted, StorageUnavailable> {
        let due = self.outbox.due(self.clock.now(), limit).await?;

        let mut attempted = Attempted::default();
        for record in &due {
            let dispatch = record.dispatch();
            let room = dispatch.destination().id().clone();
            let sent = self
                .dispatcher
                .dispatch(
                    dispatch.delivery(),
                    dispatch.event(),
                    dispatch.destination(),
                    // A retry is a first arrival that happens to be late:
                    // nobody has seen it, so marking it would be noise in a
                    // room. Only a replay says so (gc-6a5.3).
                    Attempt::First,
                )
                .await;

            if sent.is_ok() {
                self.settle_delivered(record.id()).await;
                attempted.delivered.push(room);
            // The attempts already spent, plus this one. The store counts them,
            // so a worker restarting does not reset a Dispatch's budget and
            // retry it forever.
            } else if self.settle_failed(record.id(), record.attempts() + 1).await {
                attempted.retrying.push(room);
            } else {
                attempted.abandoned.push(room);
            }
        }

        Ok(attempted)
    }

    /// Records that a Dispatch arrived.
    ///
    /// A store that cannot be told is not something to act on here: the Notice
    /// did arrive. The cost of staying quiet is that it stays due and is sent
    /// again — a duplicate, which gc-6a5.4 calls cosmetic.
    async fn settle_delivered(&self, id: &DispatchId) {
        let _ = self.outbox.delivered(id, self.clock.now()).await;
    }

    /// Records that a Dispatch failed. True if it will be tried again.
    async fn settle_failed(&self, id: &DispatchId, failures: u32) -> bool {
        let now = self.clock.now();
        if let Some(wait) = self.retry.again_after(failures) {
            let _ = self.outbox.failed(id, now, now.after(wait)).await;
            true
        } else {
            let _ = self.outbox.abandoned(id, now).await;
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use domain::{
        BranchName, Commit, CommitId, DeliveryId, Destination, DestinationId, DestinationKind,
        Dispatch, Event, OriginId, Pusher, RepositoryName, Summary, Timestamp,
    };

    use super::{Attempt, Clock, DispatchId, Dispatcher, Outbox, Retries, Retry};
    use crate::ports::{DispatchFailed, Outcome, Recorded, StorageUnavailable};

    const NOW: i64 = 1_759_000_000_000;

    struct FixedClock;
    impl Clock for FixedClock {
        fn now(&self) -> Timestamp {
            Timestamp::from_millis_since_epoch(NOW)
        }
    }

    /// Fails for the Destinations it was given, succeeds for the rest.
    struct Recorder {
        failing: Vec<&'static str>,
        sent: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl Dispatcher for Recorder {
        async fn dispatch(
            &self,
            _delivery: &DeliveryId,
            _event: &Event,
            destination: &Destination,
            _attempt: Attempt,
        ) -> Result<(), DispatchFailed> {
            let id = destination.id().as_str().to_owned();
            if self.failing.contains(&id.as_str()) {
                return Err(DispatchFailed::Unreachable);
            }
            self.sent.lock().expect("not poisoned").push(id);
            Ok(())
        }
    }

    /// An outbox holding exactly what a test put in it.
    struct Waiting {
        due: Vec<Recorded>,
        settled: Mutex<Vec<(String, &'static str)>>,
        available: bool,
    }

    impl Waiting {
        fn holding(due: Vec<Recorded>) -> Self {
            Self {
                due,
                settled: Mutex::new(Vec::new()),
                available: true,
            }
        }

        fn unavailable() -> Self {
            Self {
                available: false,
                ..Self::holding(Vec::new())
            }
        }

        fn settled(&self) -> Vec<(String, &'static str)> {
            self.settled.lock().expect("not poisoned").clone()
        }

        fn note(&self, id: &DispatchId, what: &'static str) {
            self.settled
                .lock()
                .expect("not poisoned")
                .push((id.as_str().to_owned(), what));
        }
    }

    #[async_trait]
    impl Outbox for Waiting {
        async fn accept(
            &self,
            _dispatches: &[Dispatch],
            _at: Timestamp,
        ) -> Result<Vec<Recorded>, StorageUnavailable> {
            Ok(Vec::new())
        }

        async fn accepted(
            &self,
            _delivery: &DeliveryId,
        ) -> Result<Vec<Recorded>, StorageUnavailable> {
            Ok(Vec::new())
        }

        async fn due(
            &self,
            _now: Timestamp,
            limit: usize,
        ) -> Result<Vec<Recorded>, StorageUnavailable> {
            if !self.available {
                return Err(StorageUnavailable);
            }
            Ok(self.due.iter().take(limit).cloned().collect())
        }

        async fn delivered(
            &self,
            id: &DispatchId,
            _at: Timestamp,
        ) -> Result<(), StorageUnavailable> {
            self.note(id, "delivered");
            Ok(())
        }

        async fn failed(
            &self,
            id: &DispatchId,
            _at: Timestamp,
            _again_at: Timestamp,
        ) -> Result<(), StorageUnavailable> {
            self.note(id, "failed");
            Ok(())
        }

        async fn abandoned(
            &self,
            id: &DispatchId,
            _at: Timestamp,
        ) -> Result<(), StorageUnavailable> {
            self.note(id, "abandoned");
            Ok(())
        }
    }

    fn waiting_for(id: &str, room: &str, attempts: u32) -> Recorded {
        Recorded::new(
            DispatchId::new(id).expect("a non-blank id"),
            Dispatch::new(
                DeliveryId::new("d-1").expect("a non-blank id"),
                OriginId::new("github").expect("a non-blank id"),
                Event::PushedCommits {
                    repository: RepositoryName::new("motrice/webhook-proxy").expect("a name"),
                    branch: BranchName::new("main").expect("a name"),
                    pusher: Pusher::new("bjornmolin").expect("a name"),
                    commits: vec![Commit::new(
                        CommitId::new("6113728f27ae").expect("an id"),
                        Summary::new("a change").expect("a summary"),
                    )],
                    permalink: None,
                },
                Destination::new(
                    DestinationId::new(room).expect("a non-blank id"),
                    DestinationKind::ChatRoom,
                ),
            ),
            attempts,
            Outcome::Waiting {
                again_at: Timestamp::from_millis_since_epoch(NOW),
            },
        )
    }

    fn generous() -> Retry {
        Retry::new(
            core::time::Duration::from_secs(1),
            core::time::Duration::from_mins(1),
            5,
        )
    }

    #[tokio::test]
    async fn what_is_due_is_tried_and_recorded_as_delivered() {
        let dispatcher = Recorder {
            failing: vec![],
            sent: Mutex::new(Vec::new()),
        };
        let outbox = Waiting::holding(vec![waiting_for("s-1", "a-room", 1)]);
        let retries = Retries::new(&dispatcher, &outbox, &FixedClock, generous());

        let attempted = retries.once(10).await.expect("the store answers");

        assert_eq!(attempted.delivered.len(), 1);
        assert_eq!(attempted.delivered[0].as_str(), "a-room");
        assert!(attempted.retrying.is_empty());
        assert!(attempted.abandoned.is_empty());
        assert_eq!(outbox.settled(), vec![("s-1".to_owned(), "delivered")]);
    }

    #[tokio::test]
    async fn a_dispatch_that_fails_again_keeps_its_place_in_the_queue() {
        let dispatcher = Recorder {
            failing: vec!["a-room"],
            sent: Mutex::new(Vec::new()),
        };
        let outbox = Waiting::holding(vec![waiting_for("s-1", "a-room", 1)]);
        let retries = Retries::new(&dispatcher, &outbox, &FixedClock, generous());

        let attempted = retries.once(10).await.expect("the store answers");

        assert_eq!(attempted.retrying.len(), 1);
        assert_eq!(attempted.retrying[0].as_str(), "a-room");
        assert_eq!(outbox.settled(), vec![("s-1".to_owned(), "failed")]);
    }

    #[tokio::test]
    async fn the_budget_counts_attempts_the_store_remembers_not_this_pass() {
        // The failure this prevents is a Dispatch retried forever. A worker that
        // counted only its own attempts would start from zero every restart, and
        // a Destination that is permanently gone would be tried until somebody
        // noticed the log.
        let dispatcher = Recorder {
            failing: vec!["a-room"],
            sent: Mutex::new(Vec::new()),
        };
        // Four already spent, of a budget of five: this attempt is the last.
        let outbox = Waiting::holding(vec![waiting_for("s-1", "a-room", 4)]);
        let retries = Retries::new(&dispatcher, &outbox, &FixedClock, generous());

        let attempted = retries.once(10).await.expect("the store answers");

        assert_eq!(attempted.abandoned.len(), 1);
        assert_eq!(attempted.abandoned[0].as_str(), "a-room");
        assert_eq!(outbox.settled(), vec![("s-1".to_owned(), "abandoned")]);
    }

    #[tokio::test]
    async fn no_more_than_the_limit_is_taken_in_one_pass() {
        // Bounded rather than draining, so one pass cannot hold a replica for an
        // unbounded time and two replicas share the work.
        let dispatcher = Recorder {
            failing: vec![],
            sent: Mutex::new(Vec::new()),
        };
        let outbox = Waiting::holding(vec![
            waiting_for("s-1", "a-room", 1),
            waiting_for("s-2", "b-room", 1),
            waiting_for("s-3", "c-room", 1),
        ]);
        let retries = Retries::new(&dispatcher, &outbox, &FixedClock, generous());

        assert_eq!(
            retries
                .once(2)
                .await
                .expect("the store answers")
                .delivered
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn a_store_that_cannot_be_asked_attempts_nothing_and_says_so() {
        // Unlike the inbound path there is no sender waiting, so there is nobody
        // to refuse. The caller tries again on its next pass.
        let dispatcher = Recorder {
            failing: vec![],
            sent: Mutex::new(Vec::new()),
        };
        let outbox = Waiting::unavailable();
        let retries = Retries::new(&dispatcher, &outbox, &FixedClock, generous());

        assert_eq!(retries.once(10).await, Err(StorageUnavailable));
        assert!(dispatcher.sent.lock().expect("not poisoned").is_empty());
    }

    #[tokio::test]
    async fn an_empty_outbox_is_an_idle_pass_and_not_an_error() {
        let dispatcher = Recorder {
            failing: vec![],
            sent: Mutex::new(Vec::new()),
        };
        let outbox = Waiting::holding(Vec::new());
        let retries = Retries::new(&dispatcher, &outbox, &FixedClock, generous());

        assert!(retries.once(10).await.expect("the store answers").idle());
    }
}
