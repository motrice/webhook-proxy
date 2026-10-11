-- The outbox: one row per Dispatch, which is one Event bound for one
-- Destination from one Delivery.
--
-- Applied by sqlx's migrator, which takes an advisory lock first, so two
-- replicas starting together cannot race each other into a half-created schema.

CREATE TABLE IF NOT EXISTS dispatch (
    -- Assigned here rather than at the boundary. A Delivery is named when it
    -- arrives because a loss report must name what was lost even if nothing
    -- stored it; a Dispatch only needs a name once there is a row to settle.
    id          BIGSERIAL PRIMARY KEY,

    -- The Delivery that produced it. Not unique: one Delivery fans out, and a
    -- sender that retries produces a second set under the same identity, which
    -- is deliberate (gc-6a5.4 is where deduplication belongs).
    delivery    TEXT        NOT NULL,

    -- Where it is going. The identity and the kind, which is all a Destination
    -- is: no URL and no token, so nothing here is a credential.
    destination TEXT        NOT NULL,
    kind        TEXT        NOT NULL,

    -- What happened, as JSON, because an Event is a sum type and the shapes
    -- differ per variant. Deliberately opaque to SQL: nothing queries inside it,
    -- and a column per field would make every new Event variant a migration.
    event       JSONB       NOT NULL,

    -- 'waiting', 'delivered' or 'abandoned'. Three states and no fourth, as the
    -- port says; the CHECK is what stops a fourth arriving by accident.
    outcome     TEXT        NOT NULL CHECK (outcome IN ('waiting', 'delivered', 'abandoned')),

    -- Attempts already spent. The worker reads this rather than counting its
    -- own, so a restart cannot reset a Dispatch's budget and retry a dead
    -- Destination forever.
    attempts    INTEGER     NOT NULL DEFAULT 0,

    -- When it is next due, when it is waiting. Null once it is settled.
    again_at    TIMESTAMPTZ,

    -- When it was delivered or abandoned. Null while it is waiting.
    settled_at  TIMESTAMPTZ,

    accepted_at TIMESTAMPTZ NOT NULL
);

-- The query the worker makes on every sweep: what is waiting and due, oldest
-- first. Partial, because settled rows are the ones that accumulate and none of
-- them is ever due again — so the index stays the size of the backlog rather
-- than the size of history.
CREATE INDEX IF NOT EXISTS dispatch_due
    ON dispatch (again_at, id)
    WHERE outcome = 'waiting';

-- Reading back what one Delivery produced, which is what `accepted` does and
-- what the read API (gc-235) will want.
CREATE INDEX IF NOT EXISTS dispatch_by_delivery ON dispatch (delivery);
