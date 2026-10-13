-- A Dispatch carries the call chain it belongs to.
--
-- Bead gc-4oo.5. The reason this has to be stored rather than held for the
-- length of a request: the sweep sends a Dispatch again minutes later, and that
-- onward call belongs to the same chain as the original push or alert. Without
-- these columns a retry would start a chain of its own, and the room message an
-- operator is looking at could not be traced back to what caused it.
--
-- `state` is nullable because it genuinely is optional: it carries whatever a
-- previous hop left for the next one, and most callers leave nothing.
ALTER TABLE dispatch ADD COLUMN IF NOT EXISTS trace TEXT;
ALTER TABLE dispatch ADD COLUMN IF NOT EXISTS span TEXT;
ALTER TABLE dispatch ADD COLUMN IF NOT EXISTS state TEXT;

-- Rows written before this migration had no correlation, so they are given one.
--
-- A generated chain rather than a NULL, and that is a deliberate choice worth
-- defending: it is exactly what this proxy already does for a sender that sends
-- no correlation of its own, so an old row ends up in the same state as a new
-- one from an uninstrumented sender. The alternative — a nullable correlation —
-- would put an Option through the domain, every port and both adapters to
-- describe rows that will age out of the table within the retry budget.
--
-- md5() of a random value is 32 lowercase hexadecimal characters, which is the
-- trace length the standard fixes; the first 16 of a second one is a span. Both
-- are vanishingly unlikely to be all zeroes, which the standard reserves.
UPDATE dispatch
SET trace = md5(random()::text || id::text),
    span = substr(md5(random()::text || id::text), 1, 16)
WHERE trace IS NULL;

ALTER TABLE dispatch ALTER COLUMN trace SET NOT NULL;
ALTER TABLE dispatch ALTER COLUMN span SET NOT NULL;
