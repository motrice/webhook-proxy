-- Deliveries owed to their tenants: one row per Delivery, with no Destination.
--
-- A second table beside `dispatch` rather than columns added to it, because the
-- unit differs. A `dispatch` row is one Delivery bound for one room, which this
-- service routed itself and will attempt itself. A `handover` row is one
-- Delivery owed to a tenant, which routes it in its own repository to rooms this
-- service does not know and may never learn. Bead gc-g9x decided that routing
-- leaves this service; this is the shape of what is left behind.
--
-- NOTHING HERE IS A CREDENTIAL, and that is structural. There is no destination
-- and no secret name, because the type this is written from has no field for
-- one: bead gc-81d forbids this hand-off returning a secret value or a secret
-- name, and a column that cannot exist cannot leak.

CREATE TABLE IF NOT EXISTS handover (
    -- The Delivery's own identity, as the boundary minted it, and the key a
    -- claim and a report will both name. Unique here where it is not in
    -- `dispatch`: there a Delivery fans out to one row per room, here one
    -- Delivery is one row. A sender that retries produces a new Delivery with a
    -- new identity, which is a second row and is deliberate — deduplication is
    -- gc-6a5.4's, and merging two alerts under one key would lose one of them.
    delivery    TEXT        PRIMARY KEY,

    -- Whose it is, and therefore whose agent may ever be offered it. From the
    -- Origin's registration, which the Origin's own secret authenticates, never
    -- from anything a sender said (bead gc-nkb).
    tenant      TEXT        NOT NULL,

    -- Who sent it, as a name. An identity and not an `Origin`: an Origin
    -- carries the verification that holds a sender's secret.
    origin      TEXT        NOT NULL,

    -- What it reported, as JSON, and ALL OF IT IN ONE ROW. Not one row per
    -- Event: a sender grouping twenty alerts into one notification meant one
    -- message per room (gc-lhh, gc-smz), and whoever delivers can only honour
    -- that if it receives them together. Opaque to SQL for the reason `dispatch`
    -- gives: nothing queries inside it, and a column per field would make every
    -- new Event variant a migration.
    events      JSONB       NOT NULL,

    -- The chain it arrived on, so the tenant's agent continues it rather than
    -- starting one. This is what keeps a room message traceable back through two
    -- services to the sender's push, which in a version with no read API is the
    -- whole diagnostic story (gc-g9x).
    trace       TEXT        NOT NULL,
    span        TEXT        NOT NULL,
    state       TEXT,

    -- When the store took it, which is when the sender was answered. The age of
    -- the oldest outstanding row per tenant is what bead gc-wcw.3 reports when
    -- an agent has stopped collecting — the only way anybody learns that, with
    -- no read API.
    accepted_at TIMESTAMPTZ NOT NULL
);

-- The query a claim makes: this tenant's, oldest first. Tenant leads because
-- every query is scoped by it and none is ever made across tenants.
CREATE INDEX IF NOT EXISTS handover_outstanding ON handover (tenant, accepted_at, delivery);
