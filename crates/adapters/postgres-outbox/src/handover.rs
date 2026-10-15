//! Deliveries owed to their tenants, against a real database.
//!
//! A second store beside [`crate::PostgresOutbox`], sharing its pool and its
//! migrator. In this crate rather than its own because an adapter may not
//! depend on another adapter: a separate crate could not reach this one's
//! connection pool, and two pools against one database is a worse thing to own
//! than one crate holding two tables.

use application::ports::{
    Behind, Claimed, Discharged, Handover, Offered, Reoffered, Report, RoomOutcome,
    StorageUnavailable, Swept, TenantId, Uncollected,
};
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
const COLUMNS: &str = "delivery, tenant, origin, events, trace, span, state, replayed, \
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
        //
        // Everything still owed, whether or not somebody is holding it: a claim
        // is not a discharge, and bead gc-wcw.3's count of what a tenant has
        // stopped collecting must not be fooled by an agent that claims and
        // then dies in a loop.
        let rows = sqlx::query(&format!(
            "SELECT {COLUMNS} FROM handover \
             WHERE tenant = $1 AND reported_at IS NULL \
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

    async fn claim(
        &self,
        tenant: &TenantId,
        limit: usize,
        now: Timestamp,
        lease: core::time::Duration,
    ) -> Result<Vec<Claimed>, StorageUnavailable> {
        let until = now.after(lease);

        // ONE STATEMENT, selecting and marking together.
        //
        // `FOR UPDATE SKIP LOCKED` in the inner query is what stops two agents
        // being handed the same Delivery: the second skips the rows the first
        // has locked rather than waiting for them and then taking them anyway.
        // The lock lasts only as long as the statement, which is why the update
        // also pushes `claimed_until` forward — the agent settles long after
        // this returns, and the lock alone would let a second agent take work
        // the first is still delivering. The outbox's `due` has the same shape
        // for the same reason; what differs is who the other claimant is.
        let rows = sqlx::query(&format!(
            "UPDATE handover SET claimed_until = to_timestamp($3::BIGINT / 1000.0) \
             WHERE delivery IN ( \
                 SELECT delivery FROM handover \
                 WHERE tenant = $1 \
                   AND reported_at IS NULL \
                   AND (claimed_until IS NULL \
                        OR claimed_until <= to_timestamp($4::BIGINT / 1000.0)) \
                 ORDER BY accepted_at, delivery \
                 LIMIT $2 \
                 FOR UPDATE SKIP LOCKED \
             ) \
             RETURNING {COLUMNS}"
        ))
        .bind(tenant.as_str())
        .bind(i64::try_from(limit).unwrap_or(i64::MAX))
        .bind(until.millis_since_epoch())
        .bind(now.millis_since_epoch())
        .fetch_all(&self.pool)
        .await
        .map_err(|_| StorageUnavailable)?;

        // `RETURNING` does not promise an order, so the ordering the inner
        // query asked for is applied again here. Oldest first is the order it
        // should be collected in, and an agent that honours it drains its
        // backlog rather than its newest alerts.
        let mut claimed: Vec<Claimed> = rows
            .iter()
            .map(|row| {
                let replayed: bool = row.try_get("replayed").map_err(|_| StorageUnavailable)?;
                offered(row).map(|offered| Claimed::new(offered, until, replayed))
            })
            .collect::<Result<Vec<_>, _>>()?;
        claimed.sort_by(|one, other| {
            one.offered()
                .accepted_at()
                .millis_since_epoch()
                .cmp(&other.offered().accepted_at().millis_since_epoch())
                .then_with(|| {
                    one.offered()
                        .delivery()
                        .as_str()
                        .cmp(other.offered().delivery().as_str())
                })
        });
        Ok(claimed)
    }

    async fn report(
        &self,
        tenant: &TenantId,
        delivery: &DeliveryId,
        report: &Report,
        at: Timestamp,
    ) -> Result<Discharged, StorageUnavailable> {
        // BOTH the identity and the tenant, and `reported_at IS NULL` as well.
        // The tenant is what stops one tenant discharging another's Delivery;
        // the NULL check is what makes a second report of the same Delivery
        // answer NotOutstanding rather than overwriting the first, so an agent
        // whose reply was lost can send it again without erasing what it said.
        let settled = sqlx::query(
            "UPDATE handover \
             SET reported_at = to_timestamp($4::BIGINT / 1000.0), report = $3, \
                 replayed = FALSE \
             WHERE delivery = $1 AND tenant = $2 AND reported_at IS NULL",
        )
        .bind(delivery.as_str())
        .bind(tenant.as_str())
        .bind(written_report(report))
        .bind(at.millis_since_epoch())
        .execute(&self.pool)
        .await
        .map_err(|_| StorageUnavailable)?
        .rows_affected();

        if settled == 0 {
            Ok(Discharged::NotOutstanding)
        } else {
            Ok(Discharged::Settled)
        }
    }

    async fn reoffer(&self, delivery: &DeliveryId) -> Result<Reoffered, StorageUnavailable> {
        // NO TENANT, which the port explains: this serves an operator holding a
        // Delivery identity out of a log line, not a request. It has no route.
        //
        // The previous `report` is deliberately LEFT where it is rather than
        // cleared. It is the record of what happened last time, and it stays
        // readable until a new report replaces it — which is strictly more than
        // clearing it would leave, and costs nothing: `reported_at IS NULL` is
        // what every other query reads, not this column.
        let offered = sqlx::query(
            "UPDATE handover \
             SET reported_at = NULL, claimed_until = NULL, replayed = TRUE \
             WHERE delivery = $1",
        )
        .bind(delivery.as_str())
        .execute(&self.pool)
        .await
        .map_err(|_| StorageUnavailable)?
        .rows_affected();

        if offered == 0 {
            Ok(Reoffered::NotStored)
        } else {
            Ok(Reoffered::Owed)
        }
    }

    async fn sweep(&self, accepted_before: Timestamp) -> Result<Swept, StorageUnavailable> {
        // ONE STATEMENT, and `RETURNING` is what makes this a reportable loss
        // rather than a silent one: the rows come back as they are deleted, so
        // there is no window in which something has gone and nothing knows
        // what. A `DELETE` followed by a `SELECT` would have that window, and
        // a `SELECT` followed by a `DELETE` would report rows it then failed
        // to remove.
        //
        // The uncollected rows and the settled ones go in the same pass
        // because they are the same rule — kept for a month from acceptance —
        // and separating them would invite the two periods to drift apart.
        let rows = sqlx::query(
            "DELETE FROM handover \
             WHERE accepted_at < to_timestamp($1::BIGINT / 1000.0) \
             RETURNING delivery, tenant, origin, trace, \
                       (EXTRACT(EPOCH FROM accepted_at) * 1000)::BIGINT AS accepted_at_ms, \
                       reported_at IS NULL AS uncollected",
        )
        .bind(accepted_before.millis_since_epoch())
        .fetch_all(&self.pool)
        .await
        .map_err(|_| StorageUnavailable)?;

        let mut swept = Swept::default();
        for row in &rows {
            // Read as text, and that is the port's decision rather than
            // laziness: a sweep that could fail to parse a row it is deleting
            // would stop working on exactly the row most worth reporting.
            let uncollected: bool = row.try_get("uncollected").map_err(|_| StorageUnavailable)?;
            if !uncollected {
                swept.settled += 1;
                continue;
            }
            swept.uncollected.push(Uncollected {
                delivery: row.try_get("delivery").map_err(|_| StorageUnavailable)?,
                tenant: row.try_get("tenant").map_err(|_| StorageUnavailable)?,
                origin: row.try_get("origin").map_err(|_| StorageUnavailable)?,
                trace: row.try_get("trace").map_err(|_| StorageUnavailable)?,
                accepted_at: Timestamp::from_millis_since_epoch(
                    row.try_get("accepted_at_ms")
                        .map_err(|_| StorageUnavailable)?,
                ),
            });
        }

        Ok(swept)
    }

    async fn behind(&self, accepted_before: Timestamp) -> Result<Vec<Behind>, StorageUnavailable> {
        // Grouped in the database rather than by reading rows and counting
        // here: the whole point of this query is the case where there are a lot
        // of rows, and a version that fetched them would be heaviest exactly
        // when the system is worst.
        //
        // No tenant filter, and this is the one query here that has none —
        // deliberately. It answers nothing to a caller: the composition root
        // asks it on an interval to write a log line and move a gauge, and a
        // tenant's agent never reaches it. Scoping it would mean asking once
        // per configured tenant to learn the same thing.
        let rows = sqlx::query(
            "SELECT tenant, COUNT(*) AS outstanding, \
                    (EXTRACT(EPOCH FROM MIN(accepted_at)) * 1000)::BIGINT AS oldest_ms \
             FROM handover \
             WHERE reported_at IS NULL \
               AND accepted_at < to_timestamp($1::BIGINT / 1000.0) \
             GROUP BY tenant \
             ORDER BY tenant",
        )
        .bind(accepted_before.millis_since_epoch())
        .fetch_all(&self.pool)
        .await
        .map_err(|_| StorageUnavailable)?;

        rows.iter()
            .map(|row| {
                let outstanding: i64 =
                    row.try_get("outstanding").map_err(|_| StorageUnavailable)?;
                let oldest: i64 = row.try_get("oldest_ms").map_err(|_| StorageUnavailable)?;
                Ok(Behind {
                    tenant: row.try_get("tenant").map_err(|_| StorageUnavailable)?,
                    outstanding: usize::try_from(outstanding).unwrap_or(usize::MAX),
                    oldest: Timestamp::from_millis_since_epoch(oldest),
                })
            })
            .collect()
    }
}

/// Writes a tenant's terminal statement down.
///
/// Two shapes rather than one with an empty list, because the port's two
/// variants mean different things and flattening them here would throw that
/// away: an agent that forgot to fill its room list in and an agent whose rules
/// matched no room would become the same row.
fn written_report(report: &Report) -> serde_json::Value {
    match report {
        Report::RoutedToNothing => serde_json::json!({ "outcome": "routed_to_nothing" }),
        Report::Reached(rooms) => serde_json::json!({
            "outcome": "reached",
            "rooms": rooms
                .iter()
                .map(|(room, outcome)| serde_json::json!({
                    "room": room.as_str(),
                    "outcome": match outcome {
                        RoomOutcome::Delivered => "delivered",
                        RoomOutcome::Abandoned => "abandoned",
                    },
                }))
                .collect::<Vec<_>>(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use application::ports::{
        Discharged, Handover, Offered, Reoffered, Report, RoomOutcome, TenantId,
    };
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

    /// The lease these tests claim under. Its length is the platform's choice
    /// and arrives as an argument, so a test can step past it.
    const FIVE_MINUTES: core::time::Duration = core::time::Duration::from_mins(5);

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
            12,
            "the handover table gained or lost a column: {columns:?}"
        );
        for forbidden in ["secret", "url", "webhook", "token", "destination"] {
            assert!(
                !columns.iter().any(|name| name.contains(forbidden)),
                "{forbidden:?} appears in the handover table: {columns:?}"
            );
        }
    }

    #[tokio::test]
    async fn two_agents_are_never_handed_the_same_delivery() {
        // The property `FOR UPDATE SKIP LOCKED` is there for, against the
        // server that implements it. Both agents would deliver what they were
        // handed, so a room would see it twice — and here the second claimant
        // is not another replica of this binary but a pod in another namespace.
        let store = handover().await;
        for (id, when) in [("d-1", 1), ("d-2", 2)] {
            store
                .offer(&offered(id, "wallet-lab-prod", when, vec![a_push(id)]))
                .await
                .expect("stored");
        }

        let first = store
            .claim(&tenant("wallet-lab-prod"), 1, at(10), FIVE_MINUTES)
            .await
            .expect("claimed");
        let second = store
            .claim(&tenant("wallet-lab-prod"), 1, at(10), FIVE_MINUTES)
            .await
            .expect("claimed");

        assert_eq!(first.len(), 1, "the first agent was handed nothing");
        assert_eq!(second.len(), 1, "the second agent was handed nothing");
        assert_ne!(
            first[0].offered().delivery(),
            second[0].offered().delivery(),
            "two agents were handed the same Delivery"
        );
    }

    #[tokio::test]
    async fn a_claim_nobody_ever_reports_comes_back_by_itself() {
        // Why nothing has to clean up after an agent that died mid-delivery,
        // and why the lease is the platform's: a claim lapses rather than being
        // released, so a namespace that never comes back costs this service
        // nothing to notice.
        let store = handover().await;
        store
            .offer(&offered("d-1", "wallet-lab-prod", 1, vec![a_push("x")]))
            .await
            .expect("stored");

        assert_eq!(
            store
                .claim(&tenant("wallet-lab-prod"), 10, at(0), FIVE_MINUTES)
                .await
                .expect("claimed")
                .len(),
            1
        );
        assert!(
            store
                .claim(&tenant("wallet-lab-prod"), 10, at(60_000), FIVE_MINUTES)
                .await
                .expect("asked")
                .is_empty(),
            "a Delivery under an unexpired claim was offered again"
        );
        assert_eq!(
            store
                .claim(
                    &tenant("wallet-lab-prod"),
                    10,
                    at(5 * 60_000 + 1),
                    FIVE_MINUTES
                )
                .await
                .expect("asked")
                .len(),
            1,
            "a lapsed claim did not come back"
        );
    }

    #[tokio::test]
    async fn a_claim_is_scoped_by_tenant_and_a_held_delivery_starves_nobody() {
        // The lease and the tenant scoping are independent, and a store that
        // confused them would be hard to notice from outside: one tenant
        // collecting would quietly starve another.
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

        let mine = store
            .claim(&tenant("wallet-lab-prod"), 10, at(0), FIVE_MINUTES)
            .await
            .expect("claimed");
        let theirs = store
            .claim(&tenant("wallet-hsm-prod"), 10, at(0), FIVE_MINUTES)
            .await
            .expect("claimed");

        assert_eq!(mine.len(), 1);
        assert_eq!(mine[0].offered().delivery().as_str(), "d-1");
        assert_eq!(theirs.len(), 1);
        assert_eq!(theirs[0].offered().delivery().as_str(), "d-2");
    }

    #[tokio::test]
    async fn a_reported_delivery_is_discharged_and_a_stranger_cannot_report_it() {
        let store = handover().await;
        store
            .offer(&offered("d-1", "wallet-lab-prod", 1, vec![a_push("x")]))
            .await
            .expect("stored");
        let delivery = DeliveryId::new("d-1").expect("an identity");
        let rooms = Report::Reached(vec![
            (
                domain::DestinationId::new("a-room").expect("an identity"),
                RoomOutcome::Delivered,
            ),
            (
                domain::DestinationId::new("another-room").expect("an identity"),
                RoomOutcome::Abandoned,
            ),
        ]);

        // Another tenant discharges nothing.
        assert_eq!(
            store
                .report(&tenant("wallet-hsm-prod"), &delivery, &rooms, at(2))
                .await
                .expect("asked"),
            Discharged::NotOutstanding
        );
        // Its own tenant does, which is the positive oracle: the row is there.
        assert_eq!(
            store
                .report(&tenant("wallet-lab-prod"), &delivery, &rooms, at(3))
                .await
                .expect("asked"),
            Discharged::Settled
        );
        // And reporting again says so rather than failing, so an agent whose
        // reply was lost can send it again without erasing what it said.
        assert_eq!(
            store
                .report(
                    &tenant("wallet-lab-prod"),
                    &delivery,
                    &Report::RoutedToNothing,
                    at(4)
                )
                .await
                .expect("asked"),
            Discharged::NotOutstanding
        );

        assert!(
            store
                .claim(&tenant("wallet-lab-prod"), 10, at(5), FIVE_MINUTES)
                .await
                .expect("asked")
                .is_empty(),
            "a discharged Delivery was offered again"
        );

        // What the tenant said survives, because gc-wcw.3's sweep must be able
        // to tell a settled row from one still owed, and because a room name is
        // the only record the platform has of where its alert went.
        let stored: (Option<serde_json::Value>, bool) = sqlx::query_as(
            "SELECT report, reported_at IS NOT NULL FROM handover WHERE delivery = 'd-1'",
        )
        .fetch_one(store.handover.pool_for_test())
        .await
        .expect("asked");
        assert!(stored.1, "a reported row kept no moment");
        let said = stored.0.expect("a report");
        assert_eq!(said["outcome"], "reached");
        assert_eq!(said["rooms"][0]["room"], "a-room");
        assert_eq!(said["rooms"][0]["outcome"], "delivered");
        assert_eq!(said["rooms"][1]["outcome"], "abandoned");
    }

    #[tokio::test]
    async fn routed_to_nothing_is_recorded_as_the_statement_it_is() {
        // Not an empty room list. A tenant whose rules matched no room and an
        // agent that forgot to fill the list in must not leave the same row:
        // one is a healthy tenant and the other is a bug worth finding.
        let store = handover().await;
        store
            .offer(&offered("d-1", "wallet-lab-prod", 1, vec![a_push("x")]))
            .await
            .expect("stored");

        store
            .report(
                &tenant("wallet-lab-prod"),
                &DeliveryId::new("d-1").expect("an identity"),
                &Report::RoutedToNothing,
                at(2),
            )
            .await
            .expect("reported");

        let said: serde_json::Value =
            sqlx::query_scalar("SELECT report FROM handover WHERE delivery = 'd-1'")
                .fetch_one(store.handover.pool_for_test())
                .await
                .expect("asked");
        assert_eq!(said["outcome"], "routed_to_nothing");
        assert!(said.get("rooms").is_none(), "{said}");
    }

    #[tokio::test]
    async fn retention_deletes_a_settled_row_quietly_and_an_uncollected_one_loudly() {
        // THE DISTINCTION THE WHOLE SWEEP TURNS ON, and the reason this bead
        // departed from gc-mnn's "never delete a row still waiting, however
        // old". A settled row's obligation was discharged before retention
        // reached it, so its deletion is nothing. An uncollected one is a loss,
        // and it comes back so somebody can be told — otherwise the one-month
        // sweep is a quiet shredder (gc-g9x).
        let store = handover().await;
        for (id, when) in [("settled", 1), ("never-collected", 2), ("recent", 3)] {
            store
                .offer(&offered(id, "wallet-lab-prod", when, vec![a_push(id)]))
                .await
                .expect("stored");
        }
        store
            .report(
                &tenant("wallet-lab-prod"),
                &DeliveryId::new("settled").expect("an identity"),
                &Report::RoutedToNothing,
                at(2),
            )
            .await
            .expect("reported");

        // A cutoff that catches the first two and leaves the third.
        let swept = store.sweep(at(3)).await.expect("swept");

        assert_eq!(swept.settled, 1, "the discharged row was not deleted");
        assert_eq!(
            swept.uncollected.len(),
            1,
            "an uncollected row was deleted without being reported: {swept:?}"
        );
        let lost = &swept.uncollected[0];
        assert_eq!(lost.delivery, "never-collected");
        assert_eq!(lost.tenant, "wallet-lab-prod");
        assert_eq!(lost.origin, "alertmanager");
        // The chain, so the loss can be followed back to the sender's own log —
        // which with no read API is the only way to learn what was in it.
        assert_eq!(lost.trace, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(lost.accepted_at, at(2));

        // And the row that was not old enough is still there and still owed,
        // which is the positive oracle: this did not pass by deleting
        // everything.
        assert_eq!(
            store
                .outstanding(&tenant("wallet-lab-prod"), 10)
                .await
                .expect("asked")
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn a_sweep_that_finds_nothing_old_enough_deletes_nothing() {
        let store = handover().await;
        store
            .offer(&offered("d-1", "wallet-lab-prod", 10, vec![a_push("x")]))
            .await
            .expect("stored");

        let swept = store.sweep(at(5)).await.expect("swept");

        assert_eq!(swept.settled, 0);
        assert!(swept.uncollected.is_empty());
        assert_eq!(
            store
                .outstanding(&tenant("wallet-lab-prod"), 10)
                .await
                .expect("asked")
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn a_backlog_is_reported_per_tenant_with_its_oldest() {
        // The count alone cannot distinguish a busy tenant from a stopped one,
        // so the oldest acceptance comes with it — that is the number an
        // operator acts on.
        let store = handover().await;
        for (id, whose, when) in [
            ("d-1", "wallet-lab-prod", 1),
            ("d-2", "wallet-lab-prod", 2),
            ("d-3", "wallet-hsm-prod", 3),
            // Reported, so it is not a backlog however old it is.
            ("d-4", "wallet-lab-prod", 1),
            // Too recent to count.
            ("d-5", "wallet-lab-prod", 99),
        ] {
            store
                .offer(&offered(id, whose, when, vec![a_push(id)]))
                .await
                .expect("stored");
        }
        store
            .report(
                &tenant("wallet-lab-prod"),
                &DeliveryId::new("d-4").expect("an identity"),
                &Report::RoutedToNothing,
                at(5),
            )
            .await
            .expect("reported");

        let behind = store.behind(at(50)).await.expect("asked");

        assert_eq!(behind.len(), 2, "{behind:?}");
        assert_eq!(behind[0].tenant, "wallet-hsm-prod");
        assert_eq!(behind[0].outstanding, 1);
        assert_eq!(behind[0].oldest, at(3));
        assert_eq!(behind[1].tenant, "wallet-lab-prod");
        assert_eq!(
            behind[1].outstanding, 2,
            "a reported Delivery was counted as a backlog"
        );
        assert_eq!(behind[1].oldest, at(1));
    }

    #[tokio::test]
    async fn a_tenant_that_is_keeping_up_does_not_appear_in_a_backlog() {
        // The answer is the exception list, not a row per tenant: what an
        // operator needs is the short list of names worth asking about, and a
        // line per healthy tenant every interval is how a log becomes unread.
        let store = handover().await;
        store
            .offer(&offered("d-1", "wallet-lab-prod", 1, vec![a_push("x")]))
            .await
            .expect("stored");
        store
            .report(
                &tenant("wallet-lab-prod"),
                &DeliveryId::new("d-1").expect("an identity"),
                &Report::RoutedToNothing,
                at(2),
            )
            .await
            .expect("reported");

        assert!(store.behind(at(50)).await.expect("asked").is_empty());
    }

    #[tokio::test]
    async fn a_reported_delivery_can_be_offered_again_marked_as_a_replay() {
        // What `replay` became. The Dispatch it used to re-send is gone, but a
        // reported handover row survives its report for a month — so the
        // Delivery is still there, and offering it again is one row changing
        // its mind about being settled.
        let store = handover().await;
        store
            .offer(&offered("d-1", "wallet-lab-prod", 1, vec![a_push("x")]))
            .await
            .expect("stored");
        store
            .report(
                &tenant("wallet-lab-prod"),
                &DeliveryId::new("d-1").expect("an identity"),
                &Report::Reached(vec![(
                    domain::DestinationId::new("a-room").expect("an identity"),
                    RoomOutcome::Delivered,
                )]),
                at(2),
            )
            .await
            .expect("reported");
        assert!(
            store
                .claim(&tenant("wallet-lab-prod"), 10, at(3), FIVE_MINUTES)
                .await
                .expect("asked")
                .is_empty(),
            "a reported Delivery was still being offered"
        );

        assert_eq!(
            store
                .reoffer(&DeliveryId::new("d-1").expect("an identity"))
                .await
                .expect("asked"),
            Reoffered::Owed
        );

        let again = store
            .claim(&tenant("wallet-lab-prod"), 10, at(4), FIVE_MINUTES)
            .await
            .expect("claimed");
        assert_eq!(again.len(), 1, "a re-offered Delivery was not handed out");
        // THE MARKING, which is the part gc-6a5.3 decided deliberately: a
        // replay that looked like a retry would be a lie told by a tool,
        // because an alert arriving twice is how a responder learns something
        // got worse.
        assert!(again[0].replayed(), "the replay was not marked as one");

        // And what it said last time is still readable, because the re-offer
        // leaves `report` where it is rather than clearing it.
        let said: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT report FROM handover WHERE delivery = 'd-1'")
                .fetch_one(store.handover.pool_for_test())
                .await
                .expect("asked");
        assert_eq!(said.expect("a report")["rooms"][0]["room"], "a-room");
    }

    #[tokio::test]
    async fn reporting_a_replay_clears_the_mark() {
        // The flag is a property of an OFFERING, not of the Delivery: the same
        // Delivery is a first delivery once and a replay afterwards. Left set,
        // every later offering of it would be marked.
        let store = handover().await;
        store
            .offer(&offered("d-1", "wallet-lab-prod", 1, vec![a_push("x")]))
            .await
            .expect("stored");
        let delivery = DeliveryId::new("d-1").expect("an identity");
        store.reoffer(&delivery).await.expect("asked");
        store
            .report(
                &tenant("wallet-lab-prod"),
                &delivery,
                &Report::RoutedToNothing,
                at(2),
            )
            .await
            .expect("reported");

        store.reoffer(&delivery).await.expect("asked");
        // Cleared by the report above, then set again by this re-offer: the
        // point is that the report cleared it rather than that it is set now.
        let marked: bool =
            sqlx::query_scalar("SELECT replayed FROM handover WHERE delivery = 'd-1'")
                .fetch_one(store.handover.pool_for_test())
                .await
                .expect("asked");
        assert!(marked);

        store
            .report(
                &tenant("wallet-lab-prod"),
                &delivery,
                &Report::RoutedToNothing,
                at(3),
            )
            .await
            .expect("reported");
        let marked: bool =
            sqlx::query_scalar("SELECT replayed FROM handover WHERE delivery = 'd-1'")
                .fetch_one(store.handover.pool_for_test())
                .await
                .expect("asked");
        assert!(!marked, "a report left the replay mark standing");
    }

    #[tokio::test]
    async fn offering_something_that_is_not_stored_again_says_so() {
        // Not a failure, and one answer for two cases: an operator cannot tell
        // a Delivery that never existed from one retention deleted, and both
        // mean there is nothing left to send again.
        let store = handover().await;

        assert_eq!(
            store
                .reoffer(&DeliveryId::new("never-existed").expect("an identity"))
                .await
                .expect("asked"),
            Reoffered::NotStored
        );
    }
}
