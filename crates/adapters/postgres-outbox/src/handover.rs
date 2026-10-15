//! Deliveries owed to their tenants, against a real database.
//!
//! A second store beside [`crate::PostgresOutbox`], sharing its pool and its
//! migrator. In this crate rather than its own because an adapter may not
//! depend on another adapter: a separate crate could not reach this one's
//! connection pool, and two pools against one database is a worse thing to own
//! than one crate holding two tables.

use application::ports::{Handover, Offered, StorageUnavailable, TenantId};
use async_trait::async_trait;
use domain::{Correlation, DeliveryId, OriginId, Timestamp};
use sqlx::Row;
use sqlx::postgres::PgPool;

use crate::stored;

/// Deliveries waiting for their tenants, in `PostgreSQL`.
///
/// `Debug` prints what is safe and nothing else, for the reason
/// [`crate::PostgresOutbox`] gives: a connection string carries a password and
/// drivers put theirs in error messages as a matter of course.
pub struct PostgresHandover {
    pool: PgPool,
}

impl core::fmt::Debug for PostgresHandover {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PostgresHandover({} connections)", self.pool.size())
    }
}

impl PostgresHandover {
    /// Uses a pool somebody else made, which is how it shares one with the
    /// outbox: one pool, one migrator, one advisory lock at start-up.
    #[must_use]
    pub fn using(pool: PgPool) -> Self {
        Self { pool }
    }

    /// The pool, for a test that needs to look at the table itself.
    ///
    /// Not public: the schema is this module's business, and a caller reaching
    /// past the port would be writing a second adapter.
    #[cfg(test)]
    pub(crate) fn pool_for_test(&self) -> &PgPool {
        &self.pool
    }
}

/// Columns every read needs, with the moment already in milliseconds.
const COLUMNS: &str = "delivery, tenant, origin, events, trace, span, state, \
     (EXTRACT(EPOCH FROM accepted_at) * 1000)::BIGINT AS accepted_at_ms";

/// Reads one row back into what the port speaks.
fn offered(row: &sqlx::postgres::PgRow) -> Result<Offered, StorageUnavailable> {
    let delivery: String = row.try_get("delivery").map_err(|_| StorageUnavailable)?;
    let tenant: String = row.try_get("tenant").map_err(|_| StorageUnavailable)?;
    let origin: String = row.try_get("origin").map_err(|_| StorageUnavailable)?;
    let events: serde_json::Value = row.try_get("events").map_err(|_| StorageUnavailable)?;
    let trace: String = row.try_get("trace").map_err(|_| StorageUnavailable)?;
    let span: String = row.try_get("span").map_err(|_| StorageUnavailable)?;
    let state: Option<String> = row.try_get("state").map_err(|_| StorageUnavailable)?;
    let accepted_at: i64 = row
        .try_get("accepted_at_ms")
        .map_err(|_| StorageUnavailable)?;

    // Every failure below is a row this code did not write, and each is refused
    // rather than repaired. A tenant this build cannot read is the one that
    // matters most: handing it to whoever asked would be handing somebody
    // else's alert to a caller, which is the single thing this split exists to
    // prevent.
    Offered::new(
        DeliveryId::new(&delivery).map_err(|_| StorageUnavailable)?,
        TenantId::new(&tenant).map_err(|_| StorageUnavailable)?,
        OriginId::new(&origin).map_err(|_| StorageUnavailable)?,
        events
            .as_array()
            .ok_or(StorageUnavailable)?
            .iter()
            .map(|event| stored::read(event).map_err(|_| StorageUnavailable))
            .collect::<Result<Vec<_>, _>>()?,
        Correlation::new(&trace, &span, state.as_deref()).map_err(|_| StorageUnavailable)?,
        Timestamp::from_millis_since_epoch(accepted_at),
    )
    // A row with no Events is one this code could not have written: an Offered
    // with nothing in it cannot be built, because nobody could ever report
    // rooms for it and the queue would never drain.
    .ok_or(StorageUnavailable)
}

#[async_trait]
impl Handover for PostgresHandover {
    async fn offer(&self, offered: &Offered) -> Result<(), StorageUnavailable> {
        // One statement, so there is no half-written row to reason about. The
        // Events go in together for the reason the migration gives.
        sqlx::query(
            "INSERT INTO handover \
                 (delivery, tenant, origin, events, trace, span, state, accepted_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, to_timestamp($8::BIGINT / 1000.0))",
        )
        .bind(offered.delivery().as_str())
        .bind(offered.tenant().as_str())
        .bind(offered.origin().as_str())
        .bind(serde_json::Value::Array(
            offered.events().iter().map(stored::written).collect(),
        ))
        .bind(offered.correlation().trace())
        .bind(offered.correlation().span())
        .bind(offered.correlation().state())
        .bind(offered.accepted_at().millis_since_epoch())
        .execute(&self.pool)
        .await
        .map_err(|_| StorageUnavailable)?;

        Ok(())
    }

    async fn outstanding(
        &self,
        tenant: &TenantId,
        limit: usize,
    ) -> Result<Vec<Offered>, StorageUnavailable> {
        // The tenant is a bound parameter and the WHERE clause is not optional.
        // A query here that forgot it would compile, pass every test that asks
        // one tenant about its own work, and hand every tenant everything.
        let rows = sqlx::query(&format!(
            "SELECT {COLUMNS} FROM handover \
             WHERE tenant = $1 \
             ORDER BY accepted_at, delivery \
             LIMIT $2"
        ))
        .bind(tenant.as_str())
        .bind(i64::try_from(limit).unwrap_or(i64::MAX))
        .fetch_all(&self.pool)
        .await
        .map_err(|_| StorageUnavailable)?;

        rows.iter().map(offered).collect()
    }
}

#[cfg(test)]
mod tests {
    use application::ports::{Handover, Offered, TenantId};
    use domain::{
        BranchName, Commit, CommitId, Correlation, DeliveryId, Event, OriginId, Pusher,
        RepositoryName, Summary, Timestamp,
    };
    use sqlx::Row;

    use super::PostgresHandover;

    /// The handover, on a database this test started.
    struct TestHandover {
        /// Holds the container alive, and removes it on drop.
        _database: crate::testing::Database,
        handover: PostgresHandover,
    }

    impl std::ops::Deref for TestHandover {
        type Target = PostgresHandover;

        fn deref(&self) -> &Self::Target {
            &self.handover
        }
    }

    async fn handover() -> TestHandover {
        let database = crate::testing::started().await;
        let handover = PostgresHandover::using(database.pool().clone());
        TestHandover {
            _database: database,
            handover,
        }
    }

    fn at(millis: i64) -> Timestamp {
        Timestamp::from_millis_since_epoch(1_759_000_000_000 + millis)
    }

    fn tenant(id: &str) -> TenantId {
        TenantId::new(id).expect("a namespace name")
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

    fn offered(delivery: &str, whose: &str, when: i64, events: Vec<Event>) -> Offered {
        Offered::new(
            DeliveryId::new(delivery).expect("a non-blank id"),
            tenant(whose),
            OriginId::new("alertmanager").expect("a non-blank id"),
            events,
            Correlation::new("4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7", None)
                .expect("a well formed correlation"),
            at(when),
        )
        .expect("at least one event")
    }

    #[tokio::test]
    async fn a_tenant_is_offered_only_its_own() {
        // THE PROPERTY THE WHOLE SPLIT EXISTS FOR, against the SQL that has to
        // keep it. The in-memory adapter proves the same thing, and this proves
        // it where it would actually be lost: a `SELECT` that forgot its `WHERE
        // tenant = $1` compiles, passes every test that asks one tenant about
        // its own work, and hands every tenant everything.
        let store = handover().await;
        store
            .offer(&offered(
                "d-1",
                "wallet-lab-prod",
                1,
                vec![a_push("theirs")],
            ))
            .await
            .expect("stored");
        store
            .offer(&offered(
                "d-2",
                "wallet-hsm-prod",
                2,
                vec![a_push("not theirs")],
            ))
            .await
            .expect("stored");

        let theirs = store
            .outstanding(&tenant("wallet-lab-prod"), 10)
            .await
            .expect("asked");

        assert_eq!(theirs.len(), 1, "one tenant's work came back as two");
        assert_eq!(theirs[0].delivery().as_str(), "d-1");

        // The positive oracle, so this cannot pass by returning nothing: the
        // other row is in the table, and its own tenant is offered it.
        let held: i64 = sqlx::query("SELECT COUNT(*) FROM handover")
            .fetch_one(store.handover.pool_for_test())
            .await
            .expect("asked")
            .get(0);
        assert_eq!(held, 2);
        assert_eq!(
            store
                .outstanding(&tenant("wallet-hsm-prod"), 10)
                .await
                .expect("asked")
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn the_events_of_one_delivery_come_back_together_and_in_order() {
        // gc-smz's grouping, across the store. A sender that grouped three
        // alerts into one notification meant one message per room, and whoever
        // delivers can only honour that if these arrive as a group — so three
        // Events are one row, not three, and their order is the sender's.
        let store = handover().await;
        store
            .offer(&offered(
                "d-1",
                "wallet-lab-prod",
                1,
                vec![a_push("first"), a_push("second"), a_push("third")],
            ))
            .await
            .expect("stored");

        let outstanding = store
            .outstanding(&tenant("wallet-lab-prod"), 10)
            .await
            .expect("asked");

        assert_eq!(outstanding.len(), 1, "one Delivery came back as several");
        let summaries: Vec<String> = outstanding[0]
            .events()
            .iter()
            .map(|event| match event {
                Event::PushedCommits { commits, .. } => commits
                    .first()
                    .expect("a commit")
                    .summary()
                    .as_str()
                    .to_owned(),
                _ => unreachable!("these are pushes"),
            })
            .collect();
        assert_eq!(summaries, vec!["first", "second", "third"]);
    }

    #[tokio::test]
    async fn the_correlation_survives_the_store() {
        // What makes a room message traceable back through two services to the
        // sender's push. With no read API that chain is the entire diagnostic
        // story (gc-g9x), so losing it in a column would cost more than it looks.
        let store = handover().await;
        store
            .offer(&offered("d-1", "wallet-lab-prod", 1, vec![a_push("x")]))
            .await
            .expect("stored");

        let outstanding = store
            .outstanding(&tenant("wallet-lab-prod"), 10)
            .await
            .expect("asked");

        assert_eq!(
            outstanding[0].correlation().trace(),
            "4bf92f3577b34da6a3ce929d0e0e4736"
        );
        assert_eq!(outstanding[0].correlation().span(), "00f067aa0ba902b7");
        assert_eq!(outstanding[0].accepted_at(), at(1));
    }

    #[tokio::test]
    async fn the_oldest_is_offered_first_and_no_more_than_asked_for() {
        // Oldest first because that is the order it should be collected in, and
        // bounded because this queue grows without limit exactly when nobody is
        // collecting — which is the case it has to survive being asked about.
        let store = handover().await;
        // Offered out of order on purpose: the answer must be the acceptance
        // order, not the insertion order, and with three rows inserted
        // newest-first those two disagree.
        for (id, when) in [("d-3", 3), ("d-1", 1), ("d-2", 2)] {
            store
                .offer(&offered(id, "wallet-lab-prod", when, vec![a_push(id)]))
                .await
                .expect("stored");
        }

        let first_two = store
            .outstanding(&tenant("wallet-lab-prod"), 2)
            .await
            .expect("asked");

        assert_eq!(
            first_two
                .iter()
                .map(|o| o.delivery().as_str().to_owned())
                .collect::<Vec<_>>(),
            vec!["d-1", "d-2"]
        );
    }

    #[tokio::test]
    async fn nothing_stored_here_is_a_credential() {
        // Bead gc-81d forbids this hand-off carrying a secret value or a secret
        // NAME, and the way that is kept true is that the table has no column
        // one could be in. Asserted against the schema rather than against a
        // row, so adding such a column fails this test even before anything
        // writes to it.
        let store = handover().await;
        let columns: Vec<String> = sqlx::query(
            "SELECT column_name FROM information_schema.columns \
             WHERE table_name = 'handover'",
        )
        .fetch_all(store.handover.pool_for_test())
        .await
        .expect("asked")
        .iter()
        .map(|row| row.get::<String, _>(0))
        .collect();

        assert_eq!(
            columns.len(),
            8,
            "the handover table gained or lost a column: {columns:?}"
        );
        for forbidden in ["secret", "url", "webhook", "token", "destination", "room"] {
            assert!(
                !columns.iter().any(|name| name.contains(forbidden)),
                "{forbidden:?} appears in the handover table: {columns:?}"
            );
        }
    }
}
