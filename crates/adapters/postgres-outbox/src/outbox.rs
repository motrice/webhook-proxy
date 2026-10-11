//! The port, against a real database.

use application::ports::{Outbox, Outcome, Recorded, StorageUnavailable};
use async_trait::async_trait;
use domain::{
    DeliveryId, Destination, DestinationId, DestinationKind, Dispatch, DispatchId, OriginId,
    Timestamp,
};
use sqlx::Row;
use sqlx::postgres::{PgPool, PgPoolOptions};

use crate::stored;

/// Applied at start-up, behind an advisory lock sqlx takes for us.
///
/// That lock is the answer to "the schema is created by something two replicas
/// cannot race": both may run this, one waits, and the second finds the work
/// already done rather than doing it again.
static SCHEMA: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// How long a claimed Dispatch stays out of the due window.
///
/// `SELECT ... FOR UPDATE SKIP LOCKED` holds a row only until the transaction
/// ends, and the caller settles long after that — so the lock alone would let a
/// second worker take a Dispatch the first is still sending. Claiming therefore
/// pushes the row's due time forward, and this is how far.
///
/// Long enough that an attempt finishes first: the dispatch timeout is seconds.
/// Short enough that a worker killed mid-attempt does not strand its claims —
/// they come back by themselves, which is why nothing has to clean up after a
/// crash.
const LEASE: core::time::Duration = core::time::Duration::from_mins(5);

/// Dispatches, in `PostgreSQL`.
///
/// `Debug` prints what is safe and nothing else. A connection string carries a
/// password, and database drivers put theirs in error messages as a matter of
/// course — see bead gc-b0n. Nothing here will put one in a log.
pub struct PostgresOutbox {
    pool: PgPool,
}

impl core::fmt::Debug for PostgresOutbox {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PostgresOutbox({} connections)", self.pool.size())
    }
}

impl PostgresOutbox {
    /// Connects, and brings the schema up to date.
    ///
    /// # Errors
    ///
    /// [`StorageUnavailable`] if the database cannot be reached or the schema
    /// cannot be applied. Deliberately carries nothing else: the caller logs
    /// this, and the driver's own error would name the host and the password.
    pub async fn connect(url: &str, connections: u32) -> Result<Self, StorageUnavailable> {
        let pool = PgPoolOptions::new()
            .max_connections(connections)
            .connect(url)
            .await
            .map_err(|_| StorageUnavailable)?;

        SCHEMA.run(&pool).await.map_err(|_| StorageUnavailable)?;

        Ok(Self { pool })
    }

    /// Uses a pool somebody else made. For tests, which share one database.
    #[must_use]
    pub fn using(pool: PgPool) -> Self {
        Self { pool }
    }

    /// The pool, for a test that needs to look at the table itself.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Brings the schema up to date on a pool already connected.
    ///
    /// # Errors
    ///
    /// [`StorageUnavailable`] if the schema cannot be applied.
    pub async fn migrate(pool: &PgPool) -> Result<(), StorageUnavailable> {
        SCHEMA.run(pool).await.map_err(|_| StorageUnavailable)
    }
}

/// Reads one row back into what the port speaks.
fn recorded(row: &sqlx::postgres::PgRow) -> Result<Recorded, StorageUnavailable> {
    let id: i64 = row.try_get("id").map_err(|_| StorageUnavailable)?;
    let delivery: String = row.try_get("delivery").map_err(|_| StorageUnavailable)?;
    let origin: String = row.try_get("origin").map_err(|_| StorageUnavailable)?;
    let destination: String = row.try_get("destination").map_err(|_| StorageUnavailable)?;
    let kind: String = row.try_get("kind").map_err(|_| StorageUnavailable)?;
    let events: serde_json::Value = row.try_get("events").map_err(|_| StorageUnavailable)?;
    let outcome: String = row.try_get("outcome").map_err(|_| StorageUnavailable)?;
    let attempts: i32 = row.try_get("attempts").map_err(|_| StorageUnavailable)?;
    let again_at: Option<i64> = row.try_get("again_at_ms").map_err(|_| StorageUnavailable)?;
    let settled_at: Option<i64> = row
        .try_get("settled_at_ms")
        .map_err(|_| StorageUnavailable)?;

    let outcome = match outcome.as_str() {
        "waiting" => Outcome::Waiting {
            again_at: Timestamp::from_millis_since_epoch(again_at.ok_or(StorageUnavailable)?),
        },
        "delivered" => Outcome::Delivered {
            at: Timestamp::from_millis_since_epoch(settled_at.ok_or(StorageUnavailable)?),
        },
        "abandoned" => Outcome::Abandoned {
            at: Timestamp::from_millis_since_epoch(settled_at.ok_or(StorageUnavailable)?),
        },
        // The CHECK constraint forbids a fourth, so this is a row written by
        // something that is not this code.
        _ => return Err(StorageUnavailable),
    };

    let dispatch = Dispatch::new(
        DeliveryId::new(&delivery).map_err(|_| StorageUnavailable)?,
        OriginId::new(&origin).map_err(|_| StorageUnavailable)?,
        events
            .as_array()
            .ok_or(StorageUnavailable)?
            .iter()
            .map(|event| stored::read(event).map_err(|_| StorageUnavailable))
            .collect::<Result<Vec<_>, _>>()?,
        Destination::new(
            DestinationId::new(&destination).map_err(|_| StorageUnavailable)?,
            match kind.as_str() {
                "forge" => DestinationKind::Forge,
                _ => DestinationKind::ChatRoom,
            },
        ),
    )
    // A row with no events is one this code could not have written: a Dispatch
    // with nothing to say cannot be built. Refused rather than turned into an
    // empty message in somebody's room.
    .ok_or(StorageUnavailable)?;

    Ok(Recorded::new(
        DispatchId::new(&id.to_string()).map_err(|_| StorageUnavailable)?,
        dispatch,
        attempts.try_into().unwrap_or(u32::MAX),
        outcome,
    ))
}

/// How a Destination's kind is written down.
fn kind_of(destination: &Destination) -> &'static str {
    match destination.kind() {
        DestinationKind::ChatRoom => "chat_room",
        DestinationKind::Forge => "forge",
    }
}

/// The identity, as the database counts them.
fn row_id(id: &DispatchId) -> Result<i64, StorageUnavailable> {
    id.as_str().parse().map_err(|_| StorageUnavailable)
}

/// Columns every read needs, with the moments already in milliseconds so the
/// mapping back to `Timestamp` is one shape rather than three.
const COLUMNS: &str = "id, delivery, origin, destination, kind, events, outcome, attempts, \
     (EXTRACT(EPOCH FROM again_at) * 1000)::BIGINT AS again_at_ms, \
     (EXTRACT(EPOCH FROM settled_at) * 1000)::BIGINT AS settled_at_ms";

#[async_trait]
impl Outbox for PostgresOutbox {
    async fn accept(
        &self,
        dispatches: &[Dispatch],
        at: Timestamp,
    ) -> Result<Vec<Recorded>, StorageUnavailable> {
        // One transaction, so a Delivery is stored all together or not at all.
        // Half of it stored and then acknowledged would mean the sender believes
        // it delivered while the Destinations that were not recorded are never
        // attempted and never reported.
        let mut tx = self.pool.begin().await.map_err(|_| StorageUnavailable)?;

        let mut stored_rows = Vec::with_capacity(dispatches.len());
        for dispatch in dispatches {
            let row = sqlx::query(&format!(
                "INSERT INTO dispatch \
                     (delivery, origin, destination, kind, events, outcome, attempts, again_at, \
                      accepted_at) \
                 VALUES ($1, $6, $2, $3, $4, 'waiting', 0, to_timestamp($5::BIGINT / 1000.0), \
                         to_timestamp($5::BIGINT / 1000.0)) \
                 RETURNING {COLUMNS}"
            ))
            .bind(dispatch.delivery().as_str())
            .bind(dispatch.destination().id().as_str())
            .bind(kind_of(dispatch.destination()))
            .bind(serde_json::Value::Array(
                dispatch.events().iter().map(stored::written).collect(),
            ))
            .bind(at.millis_since_epoch())
            .bind(dispatch.origin().as_str())
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| StorageUnavailable)?;

            stored_rows.push(recorded(&row)?);
        }

        tx.commit().await.map_err(|_| StorageUnavailable)?;

        Ok(stored_rows)
    }

    async fn accepted(&self, delivery: &DeliveryId) -> Result<Vec<Recorded>, StorageUnavailable> {
        let rows = sqlx::query(&format!(
            "SELECT {COLUMNS} FROM dispatch WHERE delivery = $1 ORDER BY id"
        ))
        .bind(delivery.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(|_| StorageUnavailable)?;

        rows.iter().map(recorded).collect()
    }

    async fn due(&self, now: Timestamp, limit: usize) -> Result<Vec<Recorded>, StorageUnavailable> {
        // SKIP LOCKED is what stops two replicas colliding inside this
        // statement; pushing `again_at` forward is what stops them colliding
        // after it. The lock dies with the transaction and the caller settles
        // long after, so the lock alone would hand the same Dispatch to a second
        // worker while the first is still sending it.
        let rows = sqlx::query(&format!(
            "WITH claimed AS (
                 SELECT id FROM dispatch
                 WHERE outcome = 'waiting' AND again_at <= to_timestamp($1::BIGINT / 1000.0)
                 ORDER BY again_at, id
                 LIMIT $2
                 FOR UPDATE SKIP LOCKED
             )
             UPDATE dispatch SET again_at = to_timestamp($3::BIGINT / 1000.0)
             WHERE id IN (SELECT id FROM claimed)
             RETURNING {COLUMNS}"
        ))
        .bind(now.millis_since_epoch())
        .bind(i64::try_from(limit).unwrap_or(i64::MAX))
        .bind(now.after(LEASE).millis_since_epoch())
        .fetch_all(&self.pool)
        .await
        .map_err(|_| StorageUnavailable)?;

        // Returned in the order they were due, which the claiming statement
        // chose and which RETURNING does not promise to preserve.
        let mut claimed: Vec<Recorded> = rows.iter().map(recorded).collect::<Result<_, _>>()?;
        claimed.sort_by_key(|record| row_id(record.id()).unwrap_or(i64::MAX));
        Ok(claimed)
    }

    async fn delivered(&self, id: &DispatchId, at: Timestamp) -> Result<(), StorageUnavailable> {
        settle(&self.pool, id, at, "delivered").await
    }

    async fn failed(
        &self,
        id: &DispatchId,
        _at: Timestamp,
        again_at: Timestamp,
    ) -> Result<(), StorageUnavailable> {
        sqlx::query(
            "UPDATE dispatch
             SET attempts = attempts + 1, again_at = to_timestamp($2::BIGINT / 1000.0)
             WHERE id = $1",
        )
        .bind(row_id(id)?)
        .bind(again_at.millis_since_epoch())
        .execute(&self.pool)
        .await
        .map_err(|_| StorageUnavailable)?;

        Ok(())
    }

    async fn abandoned(&self, id: &DispatchId, at: Timestamp) -> Result<(), StorageUnavailable> {
        settle(&self.pool, id, at, "abandoned").await
    }
}

/// Ends a Dispatch's life, one way or the other.
///
/// `again_at` is cleared. Nothing depends on that — `due` filters on `outcome`,
/// so a settled row with a moment still in it would never be served — which is
/// exactly why it is worth saying: it is hygiene for whoever reads this table by
/// hand during an incident, and a mutation showed no test held it, so one does
/// now.
async fn settle(
    pool: &PgPool,
    id: &DispatchId,
    at: Timestamp,
    outcome: &'static str,
) -> Result<(), StorageUnavailable> {
    sqlx::query(
        "UPDATE dispatch
         SET outcome = $2, attempts = attempts + 1, again_at = NULL,
             settled_at = to_timestamp($3::BIGINT / 1000.0)
         WHERE id = $1",
    )
    .bind(row_id(id)?)
    .bind(outcome)
    .bind(at.millis_since_epoch())
    .execute(pool)
    .await
    .map_err(|_| StorageUnavailable)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use application::ports::Outcome;
    use domain::{BranchName, Commit, CommitId, Event, Pusher, RepositoryName, Summary};
    use sqlx::postgres::PgPoolOptions;

    use super::{
        DeliveryId, Destination, DestinationId, DestinationKind, Dispatch, OriginId, Outbox,
        PostgresOutbox, Timestamp,
    };

    /// A `PostgreSQL` of this test's own, and the outbox on it.
    ///
    /// Before bead gc-e5x these ten tests were `#[ignore]`d and ran only when
    /// somebody typed a recipe, which meant the store every Dispatch waits in
    /// was covered by tests no pipeline had ever executed. They now start their
    /// own database, so there is nothing to remember and nothing a pipeline can
    /// silently skip. A machine with no reachable Docker fails here, loudly,
    /// rather than reporting a pass for work it did not do — which is what the
    /// `#[ignore]` was reaching for and could not enforce.
    ///
    /// One container per test rather than one shared between them. Two reasons,
    /// and the first was found by trying the other way: a pool held in a static
    /// belongs to the runtime that built it, and `#[tokio::test]` gives every
    /// test its own runtime, so the second test to run inherits a pool whose
    /// runtime is shutting down and fails with "a Tokio 1.x context was found,
    /// but it is being shutdown". The second reason is the one that matters
    /// afterwards: a container per test is isolated by construction, so the
    /// `TRUNCATE` between tests goes, and with it the `--test-threads=1` that
    /// the shared table forced. These tests now run in parallel because nothing
    /// is shared, not because somebody remembered a flag.
    struct TestOutbox {
        /// Taken in `drop`, which is the only reason it is an `Option`.
        container:
            Option<testcontainers::ContainerAsync<testcontainers_modules::postgres::Postgres>>,
        outbox: PostgresOutbox,
    }

    /// Removes the container, and waits for the removal.
    ///
    /// The crate's own `Drop` hands the removal to `async_drop`, which spawns it
    /// on the current runtime and does not wait. `#[tokio::test]` shuts its
    /// runtime down the instant the test body returns, so that spawned task
    /// frequently never runs: a ten-test run left two postgres containers
    /// behind on the first attempt, which is a leak that accumulates on a
    /// developer's machine a run at a time.
    ///
    /// So the removal happens on a runtime of this drop's own, on its own
    /// thread, and this blocks until it is done. A thread per teardown is
    /// cheaper than the alternative was: the old harness kept one long-lived
    /// container that a second recipe had to be remembered to remove.
    ///
    /// Unwinding reaches here too, so a failing assertion cleans up as well as a
    /// passing one.
    impl Drop for TestOutbox {
        fn drop(&mut self) {
            let Some(container) = self.container.take() else {
                return;
            };

            let removed = std::thread::spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("a runtime to remove the container on")
                    .block_on(container.rm())
            })
            .join();

            // Never a panic from a destructor: a double panic aborts, which
            // would replace a legible test failure with a process abort. Loud on
            // stderr is enough -- `docker ps -a` is the other half of the story.
            match removed {
                Ok(Ok(())) => {}
                Ok(Err(why)) => eprintln!("test container was not removed: {why}"),
                Err(_) => eprintln!("the thread removing a test container panicked"),
            }
        }
    }

    /// So a test body says `outbox.accept(..)` and not `outbox.outbox.accept(..)`.
    impl std::ops::Deref for TestOutbox {
        type Target = PostgresOutbox;

        fn deref(&self) -> &Self::Target {
            &self.outbox
        }
    }

    async fn outbox() -> TestOutbox {
        use testcontainers::{ImageExt as _, runners::AsyncRunner as _};

        // Pinned to the major version this proxy is deployed against. The
        // module's own default is postgres 11, which would have tested the
        // adapter on a server five majors from the one it runs on -- and
        // `SELECT ... FOR UPDATE SKIP LOCKED`, which the claim depends on,
        // is exactly the kind of behaviour worth testing on the right one.
        let container = testcontainers_modules::postgres::Postgres::default()
            .with_tag("17-alpine")
            .start()
            .await
            .expect(
                "a PostgreSQL container: these tests bring their own database, so this \
                 needs a reachable Docker and nothing else",
            );
        let host = container.get_host().await.expect("the container's host");
        let port = container
            .get_host_port_ipv4(5432)
            .await
            .expect("the mapped port");

        // The module's own documented defaults, not read from the environment:
        // a test that silently used somebody's real database would be worse than
        // one that fails to connect.
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(&format!(
                "postgres://postgres:postgres@{host}:{port}/postgres"
            ))
            .await
            .expect("a connection to the container this test just started");

        PostgresOutbox::migrate(&pool).await.expect("the schema");

        TestOutbox {
            container: Some(container),
            outbox: PostgresOutbox::using(pool),
        }
    }

    fn at(millis: i64) -> Timestamp {
        Timestamp::from_millis_since_epoch(1_759_000_000_000 + millis)
    }

    fn a_push(summary: &str) -> Event {
        Event::PushedCommits {
            repository: RepositoryName::new("motrice/webhook-proxy").expect("a name"),
            branch: BranchName::new("main").expect("a name"),
            pusher: Pusher::new("bjornmolin").expect("a name"),
            commits: vec![Commit::new(
                CommitId::new("6113728f27ae").expect("an id"),
                Summary::new(summary).expect("a summary"),
            )],
            permalink: None,
        }
    }

    fn dispatch(delivery: &str, summary: &str, room: &str) -> Dispatch {
        Dispatch::new(
            DeliveryId::new(delivery).expect("a non-blank id"),
            OriginId::new("github").expect("a non-blank id"),
            vec![Event::PushedCommits {
                repository: RepositoryName::new("motrice/webhook-proxy").expect("a name"),
                branch: BranchName::new("main").expect("a name"),
                pusher: Pusher::new("bjornmolin").expect("a name"),
                commits: vec![Commit::new(
                    CommitId::new("6113728f27ae").expect("an id"),
                    Summary::new(summary).expect("a summary"),
                )],
                permalink: None,
            }],
            Destination::new(
                DestinationId::new(room).expect("a non-blank id"),
                DestinationKind::ChatRoom,
            ),
        )
        .expect("at least one event")
    }

    #[tokio::test]
    async fn what_was_accepted_comes_back_with_its_event_intact() {
        let outbox = outbox().await;
        let stored = dispatch("d-1", "feat: a change nobody should lose", "devsecops-room");

        let accepted = outbox
            .accept(std::slice::from_ref(&stored), at(0))
            .await
            .expect("the database is available");

        assert_eq!(accepted.len(), 1);
        let held = outbox
            .accepted(&DeliveryId::new("d-1").expect("a non-blank id"))
            .await
            .expect("available");
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].dispatch(), &stored);
        assert_eq!(held[0].attempts(), 0);
        assert_eq!(held[0].outcome(), Outcome::Waiting { again_at: at(0) });
    }

    #[tokio::test]
    async fn a_grouped_dispatch_keeps_every_event_and_their_order() {
        // One row is one message now (gc-smz), carrying the Events that selected
        // that room. Losing one, or reordering them, would change what a reader
        // sees when a stored message is finally delivered or replayed.
        let outbox = outbox().await;
        let grouped = Dispatch::new(
            DeliveryId::new("d-grouped").expect("a non-blank id"),
            OriginId::new("github").expect("a non-blank id"),
            vec![a_push("first"), a_push("second"), a_push("third")],
            Destination::new(
                DestinationId::new("a-room").expect("a non-blank id"),
                DestinationKind::ChatRoom,
            ),
        )
        .expect("at least one event");

        outbox
            .accept(std::slice::from_ref(&grouped), at(0))
            .await
            .expect("available");

        let held = outbox
            .accepted(&DeliveryId::new("d-grouped").expect("a non-blank id"))
            .await
            .expect("available");
        assert_eq!(held.len(), 1, "a grouped dispatch is one row");
        assert_eq!(held[0].dispatch(), &grouped);
        assert_eq!(held[0].dispatch().events().len(), 3);
    }

    #[tokio::test]
    async fn a_delivery_that_fanned_out_keeps_the_order_its_rules_fired_in() {
        let outbox = outbox().await;

        outbox
            .accept(
                &[
                    dispatch("d-2", "a change", "devsecops-room"),
                    dispatch("d-2", "a change", "platform-room"),
                    dispatch("d-2", "a change", "audit-room"),
                ],
                at(0),
            )
            .await
            .expect("available");

        let held = outbox
            .accepted(&DeliveryId::new("d-2").expect("a non-blank id"))
            .await
            .expect("available");
        let rooms: Vec<&str> = held
            .iter()
            .map(|record| record.dispatch().destination().id().as_str())
            .collect();
        assert_eq!(rooms, vec!["devsecops-room", "platform-room", "audit-room"]);
    }

    #[tokio::test]
    async fn two_workers_are_never_handed_the_same_dispatch() {
        // The criterion this bead exists to prove, and proved by running them at
        // once rather than by reasoning about SKIP LOCKED. The Deployment runs
        // two replicas, so this is the normal case; both sending would show a
        // room the same Notice twice.
        let outbox = outbox().await;
        let work: Vec<Dispatch> = (0..40)
            .map(|n| dispatch("d-3", &format!("change {n}"), "a-room"))
            .collect();
        outbox.accept(&work, at(0)).await.expect("available");

        // Eight workers, all asking at the same moment for everything.
        let asking = (0..8).map(|_| outbox.due(at(0), 40));
        let claimed: Vec<_> = futures::future::join_all(asking).await;

        let mut taken: Vec<String> = claimed
            .into_iter()
            .flat_map(|batch| batch.expect("available"))
            .map(|record| record.id().as_str().to_owned())
            .collect();
        let handed_out = taken.len();
        taken.sort();
        taken.dedup();

        assert_eq!(
            taken.len(),
            handed_out,
            "the same Dispatch was handed to more than one worker"
        );
        assert_eq!(handed_out, 40, "some work was never handed out at all");
    }

    #[tokio::test]
    async fn a_claim_outlives_the_statement_that_made_it() {
        // SKIP LOCKED holds a row only until its transaction ends, and the
        // caller settles long after. Without pushing the due time forward, a
        // second worker would take a Dispatch the first is still sending.
        let outbox = outbox().await;
        outbox
            .accept(&[dispatch("d-4", "a change", "a-room")], at(0))
            .await
            .expect("available");

        let first = outbox.due(at(0), 10).await.expect("available");
        let second = outbox.due(at(0), 10).await.expect("available");

        assert_eq!(first.len(), 1);
        assert!(second.is_empty(), "claimed twice: {second:?}");
    }

    #[tokio::test]
    async fn a_claim_that_is_never_settled_comes_back_by_itself() {
        // A worker killed mid-attempt strands its claims, and nothing cleans up
        // after a crash — so the lease has to expire rather than be released.
        let outbox = outbox().await;
        outbox
            .accept(&[dispatch("d-5", "a change", "a-room")], at(0))
            .await
            .expect("available");

        outbox.due(at(0), 10).await.expect("available");

        // Four minutes later it is still somebody's; six minutes later it is not.
        assert!(outbox.due(at(240_000), 10).await.expect("ok").is_empty());
        assert_eq!(outbox.due(at(360_000), 10).await.expect("ok").len(), 1);
    }

    #[tokio::test]
    async fn settling_says_what_happened_and_when_and_ends_it() {
        let outbox = outbox().await;
        outbox
            .accept(
                &[
                    dispatch("d-6", "one", "a-room"),
                    dispatch("d-6", "two", "b-room"),
                ],
                at(0),
            )
            .await
            .expect("available");
        let claimed = outbox.due(at(0), 10).await.expect("available");

        outbox
            .delivered(claimed[0].id(), at(500))
            .await
            .expect("told");
        outbox
            .abandoned(claimed[1].id(), at(700))
            .await
            .expect("told");

        let held = outbox
            .accepted(&DeliveryId::new("d-6").expect("a non-blank id"))
            .await
            .expect("available");
        assert_eq!(held[0].outcome(), Outcome::Delivered { at: at(500) });
        assert_eq!(held[1].outcome(), Outcome::Abandoned { at: at(700) });
        assert_eq!(held[0].attempts(), 1);
        // Settled for good: neither is ever due again, whatever the hour.
        assert!(outbox.due(at(99_999_999), 10).await.expect("ok").is_empty());
    }

    #[tokio::test]
    async fn a_failure_counts_an_attempt_and_waits_until_it_is_due() {
        // The budget has to be the store's, not the worker's: a worker counting
        // its own attempts would start from zero on every restart and retry a
        // dead Destination forever.
        let outbox = outbox().await;
        outbox
            .accept(&[dispatch("d-7", "a change", "a-room")], at(0))
            .await
            .expect("available");
        let claimed = outbox.due(at(0), 10).await.expect("available");

        outbox
            .failed(claimed[0].id(), at(100), at(1_000))
            .await
            .expect("told");

        assert!(outbox.due(at(999), 10).await.expect("ok").is_empty());
        let ready = outbox.due(at(1_000), 10).await.expect("ok");
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].attempts(), 1);
    }

    #[tokio::test]
    async fn a_settled_row_keeps_no_moment_it_will_never_act_on() {
        // Hygiene rather than a defence: `due` filters on outcome, so a settled
        // row with a due time still in it would never be served anyway. It is
        // tested because somebody reads this table by hand during an incident,
        // and a row that says both "delivered" and "due at 09:14" makes them
        // stop and work out which is true.
        let outbox = outbox().await;
        outbox
            .accept(&[dispatch("d-8", "a change", "a-room")], at(0))
            .await
            .expect("available");
        let claimed = outbox.due(at(0), 10).await.expect("available");
        outbox
            .delivered(claimed[0].id(), at(500))
            .await
            .expect("told");

        let left: Option<i64> = sqlx::query_scalar(
            "SELECT (EXTRACT(EPOCH FROM again_at) * 1000)::BIGINT FROM dispatch WHERE id = $1",
        )
        .bind(claimed[0].id().as_str().parse::<i64>().expect("a row id"))
        .fetch_one(outbox.pool())
        .await
        .expect("available");

        assert_eq!(left, None, "a delivered row is still claiming to be due");
    }

    #[tokio::test]
    async fn debug_prints_no_address_and_no_password() {
        // A connection string carries a password, and this is the value a log
        // line would be written from.
        let outbox = outbox().await;
        // The inner adapter, which is the value a log line would be written
        // from; the test wrapper around it is this file's business and nobody
        // else's.
        let printed = format!("{:?}", *outbox);

        assert!(!printed.contains("postgres://"), "{printed}");
        // No '@' at all, rather than a check for one particular password
        // followed by one. The old assertion named the password the harness
        // happened to use, so replacing the harness (gc-e5x) would have left it
        // passing while proving nothing; a connection string cannot carry a
        // credential and a host without joining them with this character.
        assert!(!printed.contains('@'), "{printed}");
        assert!(printed.starts_with("PostgresOutbox("), "{printed}");
    }
}
