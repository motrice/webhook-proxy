-- A Delivery offered again, on purpose, by a person.
--
-- Bead gc-72e.3.1. `replay` used to re-send a stored Dispatch; after the
-- cutover there are no stored Dispatches, but a handover row survives its
-- report for a month — so the Delivery is still there to offer again.

ALTER TABLE handover
    -- Whether THIS offering is a replay rather than a first delivery.
    --
    -- Carried to the agent so a room shows "(replayed)". Bead gc-6a5.3 decided
    -- that marking deliberately and it is the part worth keeping: an alert
    -- arriving twice is how a responder learns something got worse, so a replay
    -- that looked like a retry would be a lie told by a tool.
    --
    -- A property of the offering and not of the Delivery, which is why it is
    -- cleared when the row is reported: the same Delivery can be a first
    -- delivery once and a replay afterwards.
    ADD COLUMN IF NOT EXISTS replayed BOOLEAN NOT NULL DEFAULT FALSE;
