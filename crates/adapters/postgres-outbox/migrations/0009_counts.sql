-- What each room was told, what it was not, and what nobody ever collected.
--
-- Bead gc-5px. These three numbers were counters in process memory beside the
-- metrics endpoint, and they were the last per-process state in a deployment
-- that names a database. That made them wrong in two ways nothing in the
-- exported text admitted to: with two replicas behind a Service -- the shape
-- bead gc-f7t declared supported -- a scrape reaches one pod and gets that
-- pod's share under a name that reads as cluster-wide, and an ordinary apply
-- zeroes the count of a real loss while the rows that prove it survive in
-- `handover`. The second one is the failure bead gc-556 was written against,
-- with the word "agent" replaced by "platform".
--
-- COUNTED HERE RATHER THAN DERIVED FROM `handover`, which is the question a
-- reader should ask, because `behind` derives its gauges exactly that way and
-- the reports are already stored: these could be a GROUP BY over
-- `report->'rooms'`. Retention deletes a settled row a month after acceptance,
-- so a count taken from those rows would go DOWN -- and a Prometheus counter
-- that decreases makes increase() nonsense over every window spanning the
-- drop. A summary table is the price of these staying counters.
--
-- WRITTEN IN THE SAME TRANSACTION as the report or the sweep that causes them,
-- which is what makes them trustworthy rather than merely durable: there is no
-- window in which a Delivery is settled and uncounted, or deleted and
-- uncounted. A report that arrives twice still counts once, because the
-- transaction only reaches these tables when the UPDATE on `handover` actually
-- discharged something.
--
-- THREE TABLES RATHER THAN ONE WITH A NULLABLE KEY, because each count may be
-- summed over exactly its own key and the key is the whole design content
-- here. A single table would need a NULL or an empty string standing in for
-- "no reason" and "no room", and a sentinel in a primary key is a place for
-- two different facts to collide.
--
-- NOTHING HERE IS A CREDENTIAL, structurally, as in `handover`: a tenant is a
-- namespace, a room is a name its tenant chose, and a Destination is a name
-- with no address by construction (bead gc-81d). There is no column an address
-- or a secret could be in, and no column holding what an alert said.

-- Rooms that were told, as their tenants reported it.
CREATE TABLE IF NOT EXISTS room_delivered (
    -- Whose room it is. Part of the key because a room identity is unique only
    -- within the tenant that configured it: two tenants may each have an
    -- `oncall-room`, and one key would add two teams' numbers together.
    tenant     TEXT   NOT NULL,
    -- The name that tenant gave it. A name, never an address.
    room       TEXT   NOT NULL,
    -- How many Deliveries its tenant reported it was told about. Monotone: it
    -- is the denominator of the loss ratio an operator alerts on, so an
    -- absolute number of losses can be read against the traffic that produced
    -- it (bead gc-556).
    deliveries BIGINT NOT NULL,

    PRIMARY KEY (tenant, room)
);

-- Rooms that were not told, and why. EVERY ROW HERE IS A LOSS.
CREATE TABLE IF NOT EXISTS room_abandoned (
    tenant TEXT   NOT NULL,
    room   TEXT   NOT NULL,
    -- How the tenant said the attempt ended, in the one spelling
    -- `DispatchFailed::spelled` writes everywhere.
    --
    -- PART OF THE KEY rather than a separate total, because the four are not
    -- interchangeable to whoever acts on one: a room that refused needs a
    -- configuration change, a room that was never reached needs the network
    -- looked at, and `intercepted` means something answered on the room's
    -- behalf and the room never saw it at all.
    reason TEXT   NOT NULL,
    -- How many losses that room reported under that reason.
    losses BIGINT NOT NULL,

    PRIMARY KEY (tenant, room, reason)
);

-- Deliveries retention deleted that their tenant never came for.
--
-- The third kind of loss bead gc-g9x enumerated, and the only one that happens
-- without anybody having attempted anything. Keyed by tenant alone because
-- such a Delivery never reached a room, so there is no room to name.
CREATE TABLE IF NOT EXISTS uncollected_dropped (
    tenant  TEXT   PRIMARY KEY,
    -- How many of that tenant's Deliveries were deleted uncollected. Counted
    -- per tenant and not only in total, so the bare number an alert fires on
    -- can be followed to whose agent stopped collecting.
    dropped BIGINT NOT NULL
);
