-- A claim and a report, on the handover table.
--
-- Three columns and two indexes. What they add is the distinction between a
-- Delivery that is owed, one that somebody is currently holding, and one that
-- has been discharged — which is what makes `claim` a claim rather than a
-- query. Bead gc-wcw.2.

ALTER TABLE handover
    -- When the current claim lapses, if there is one. NULL means nobody holds
    -- it. A moment in the past means a claim that lapsed and has not been
    -- noticed, which every query here reads the same as NULL.
    --
    -- A LAPSING LEASE RATHER THAN A RELEASE, which is what makes an agent that
    -- dies mid-delivery cost this service nothing: the Delivery comes back by
    -- itself and there is no cleanup to run and nothing to time out. The
    -- claimant is a pod in somebody else's namespace that may never come back,
    -- so that is not a corner case.
    ADD COLUMN IF NOT EXISTS claimed_until TIMESTAMPTZ,

    -- When its tenant made its terminal statement. NULL while it is still owed.
    -- The retention sweep (bead gc-wcw.3) deletes settled rows only, and this is
    -- what tells it which they are; a row with this NULL is one still owed, and
    -- deleting one of those is a loss that has to be logged as such.
    ADD COLUMN IF NOT EXISTS reported_at TIMESTAMPTZ,

    -- What the tenant said: each room it reached and what became of it, or that
    -- its rules matched no room. JSON because it is a list of pairs with a sum
    -- type in it, and because nothing queries inside it.
    --
    -- ROOM NAMES LIVE HERE AND ROOM URLS NEVER DO. A Destination is a name with
    -- no address by construction, so there is nothing in a report that could be
    -- a credential even if a tenant sent one.
    ADD COLUMN IF NOT EXISTS report JSONB;

-- The query a claim makes: this tenant's, not yet reported, not currently held,
-- oldest first. Partial on `reported_at IS NULL` because settled rows are the
-- ones that accumulate and none of them is ever claimable again, so the index
-- stays the size of the backlog rather than the size of a month.
DROP INDEX IF EXISTS handover_outstanding;
CREATE INDEX IF NOT EXISTS handover_claimable
    ON handover (tenant, accepted_at, delivery)
    WHERE reported_at IS NULL;

-- The sweep's query, which gc-wcw.3 will make: what settled long enough ago to
-- delete. Separate from the one above because it wants the opposite rows.
CREATE INDEX IF NOT EXISTS handover_settled
    ON handover (reported_at)
    WHERE reported_at IS NOT NULL;
