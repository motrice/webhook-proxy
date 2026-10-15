//! A `PostgreSQL` of a test's own.
//!
//! Shared by both stores' tests rather than written twice. The two bugs this
//! code already paid for are both in the parts that look incidental — the
//! container is removed on a runtime of its own because the crate's `Drop` does
//! not wait, and the image is pulled once because ten concurrent pulls of the
//! same layers failed in CI — so a second copy would be a second place for
//! either to come back.

use sqlx::postgres::{PgPool, PgPoolOptions};

/// The image tag, in one place.
///
/// Pinned to the major version this proxy is deployed against. The module's own
/// default is postgres 11, which would have tested these adapters on a server
/// five majors from the one they run on — and `SELECT ... FOR UPDATE SKIP
/// LOCKED`, which the outbox's claim depends on, is exactly the kind of
/// behaviour worth testing on the right one.
const TAG: &str = "17-alpine";

/// A database this test started, with the schema already applied.
///
/// One container per test rather than one shared between them. Two reasons, and
/// the first was found by trying the other way: a pool held in a static belongs
/// to the runtime that built it, and `#[tokio::test]` gives every test its own
/// runtime, so the second test to run inherits a pool whose runtime is shutting
/// down and fails with "a Tokio 1.x context was found, but it is being
/// shutdown" (bead gc-e5x). The second reason is the one that matters
/// afterwards: a container per test is isolated by construction, so there is no
/// `TRUNCATE` between tests and no `--test-threads=1`. These tests run in
/// parallel because nothing is shared, not because somebody remembered a flag.
pub struct Database {
    /// Taken in `drop`, which is the only reason it is an `Option`.
    container: Option<testcontainers::ContainerAsync<testcontainers_modules::postgres::Postgres>>,
    pool: PgPool,
}

impl Database {
    /// The pool, for building a store on.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

/// Removes the container, and waits for the removal.
///
/// The crate's own `Drop` hands the removal to `async_drop`, which spawns it on
/// the current runtime and does not wait. `#[tokio::test]` shuts its runtime
/// down the instant the test body returns, so that spawned task frequently
/// never runs: a ten-test run left two postgres containers behind on the first
/// attempt, which is a leak that accumulates on a developer's machine a run at
/// a time.
///
/// So the removal happens on a runtime of this drop's own, on its own thread,
/// and this blocks until it is done. A thread per teardown is cheaper than the
/// alternative was: the old harness kept one long-lived container that a second
/// recipe had to be remembered to remove.
///
/// Unwinding reaches here too, so a failing assertion cleans up as well as a
/// passing one.
impl Drop for Database {
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

        // Never a panic from a destructor: a double panic aborts, which would
        // replace a legible test failure with a process abort. Loud on stderr is
        // enough — `docker ps -a` is the other half of the story.
        match removed {
            Ok(Ok(())) => {}
            Ok(Err(why)) => eprintln!("test container was not removed: {why}"),
            Err(_) => eprintln!("the thread removing a test container panicked"),
        }
    }
}

/// Fetches the image once per test binary, before any container starts.
///
/// Every test starts a container, and a container start on a missing image
/// issues its own pull: `docker events` shows ten `pull postgres` in one cold
/// run. Concurrent pulls of the same layers are what failed in CI on 2026-10-13
/// with `PullImage { err: "bytes remaining on stream" }` — one test of twenty,
/// on a cold runner, which is why it is invisible from a warm laptop. Bead
/// gc-f62.
///
/// `OnceLock::get_or_init` blocks the other threads until the first finishes,
/// which serialises the PULL and nothing else: the containers still start in
/// parallel, which is the isolation they exist for.
///
/// Deliberately shells out rather than using the testcontainers client. That
/// client belongs to whichever test runtime created it, and reaching across
/// runtimes is exactly what made the shared-container design fail (gc-e5x).
/// `std::process::Command` has no runtime to belong to.
///
/// A machine with neither CLI falls through to the old behaviour rather than
/// failing: the pull is an optimisation against a race, not a requirement.
fn pulled_once() {
    static PULLED: std::sync::OnceLock<()> = std::sync::OnceLock::new();

    PULLED.get_or_init(|| {
        for cli in ["docker", "podman"] {
            let fetched = std::process::Command::new(cli)
                .args(["pull", &format!("postgres:{TAG}")])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();

            if matches!(fetched, Ok(code) if code.success()) {
                return;
            }
        }
        // Nothing to report: testcontainers will pull it, which is what
        // happened before this existed.
    });
}

/// Starts one, applies the schema, and hands it back.
///
/// Before bead gc-e5x these tests were `#[ignore]`d and ran only when somebody
/// typed a recipe, which meant the store every Dispatch waits in was covered by
/// tests no pipeline had ever executed. They now start their own database, so
/// there is nothing to remember and nothing a pipeline can silently skip. A
/// machine with no reachable Docker fails here, loudly, rather than reporting a
/// pass for work it did not do — which is what the `#[ignore]` was reaching for
/// and could not enforce.
pub async fn started() -> Database {
    use testcontainers::{ImageExt as _, runners::AsyncRunner as _};

    pulled_once();

    let container = testcontainers_modules::postgres::Postgres::default()
        .with_tag(TAG)
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

    // The module's own documented defaults, not read from the environment: a
    // test that silently used somebody's real database would be worse than one
    // that fails to connect.
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&format!(
            "postgres://postgres:postgres@{host}:{port}/postgres"
        ))
        .await
        .expect("a connection to the container this test just started");

    // The same migrator the process runs at start-up.
    crate::PostgresHandover::migrate(&pool)
        .await
        .expect("the schema");

    Database {
        container: Some(container),
        pool,
    }
}
