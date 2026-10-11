-- A Dispatch carries the Events that selected its room, not one Event.
--
-- Bead gc-smz: a sender that grouped twenty alerts into one notification meant
-- a room to get one message, and sending one per alert undid a decision it made
-- deliberately. So a row is now one message, and `event` becomes `events`.
--
-- Existing rows are wrapped rather than migrated away: a stored Dispatch held
-- exactly one Event, and a one-element array says the same thing. Nothing is
-- lost and a replay of something older still works.
ALTER TABLE dispatch ADD COLUMN IF NOT EXISTS events JSONB;

UPDATE dispatch SET events = jsonb_build_array(event) WHERE events IS NULL;

ALTER TABLE dispatch ALTER COLUMN events SET NOT NULL;

-- The old column goes, rather than being left to confuse whoever reads this
-- table during an incident. Two columns where one is authoritative is the kind
-- of thing nobody remembers the rule for.
ALTER TABLE dispatch DROP COLUMN IF EXISTS event;
