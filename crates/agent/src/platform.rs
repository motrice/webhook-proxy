//! The platform, over HTTP.
//!
//! The client half of the hand-off `docs/tenant-agent-api.md` describes, and
//! the other end of `crates/app/src/collecting.rs`.
//!
//! IN THE COMPOSITION ROOT RATHER THAN AN ADAPTER CRATE, for the same boundary
//! rule that put the server half in the platform's: a claim carries Events as
//! JSON, the only codec for an `Event` lives in `postgres-outbox`, and an
//! adapter may not depend on another adapter. Writing a second codec would mean
//! two descriptions of every Event variant drifting apart one release at a
//! time. Both ends of this wire therefore live in the two crates that are
//! deployed together, which is also the honest reading: this format is an
//! agreement between two deployments, not a reusable adapter.
//!
//! WHAT IT NEVER SENDS: a tenant. Not in a path, not in a body, not in a
//! header. The platform establishes who is calling from the mTLS identity the
//! sidecar presents, and bead gc-nkb refused a parameter — it would be a claim
//! where the identity is a fact. There is nowhere in this file for one to go,
//! which is the point: [`application::ports::Owed`] has no tenant field, so
//! there is nothing to send even by accident.

use application::ports::{Acknowledged, Offers, Owed, Report, RoomOutcome, Unreachable};
use async_trait::async_trait;
use domain::{Correlation, DeliveryId, OriginId, Timestamp};
use postgres_outbox::read;
use serde_json::{Value, json};

/// A client of one platform deployment.
///
/// `Debug` prints the address and nothing else. There is no credential to leak
/// here — the mesh authenticates this, not a token — and that absence is worth
/// saying out loud, because the obvious guess about a machine-to-machine client
/// is that it holds one.
pub struct Platform {
    claim: String,
    reports: String,
    client: reqwest::Client,
}

impl core::fmt::Debug for Platform {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Platform({})", self.claim)
    }
}

impl Platform {
    /// Reaches the platform at this base address.
    ///
    /// Plain HTTP, and deliberately: TLS is the sidecar's, which is also what
    /// makes the identity this agent presents unforgeable. A client doing its
    /// own TLS here would be a second trust decision in a process that should
    /// make none.
    ///
    /// # Errors
    ///
    /// [`Unreachable`] if a client cannot be built at all, which is a broken
    /// build rather than a broken network.
    pub fn at(base: &str, timeout: core::time::Duration) -> Result<Self, Unreachable> {
        let base = base.trim_end_matches('/');
        Ok(Self {
            claim: format!("{base}/deliveries/claim"),
            reports: format!("{base}/deliveries"),
            client: reqwest::Client::builder()
                .timeout(timeout)
                .build()
                .map_err(|_| Unreachable)?,
        })
    }
}

/// Reads one Delivery out of a claim response.
///
/// `None` for anything this build cannot act on, and the caller skips it rather
/// than failing the pass: one unreadable Delivery must not stop the others
/// being delivered, and a Delivery this agent cannot read will be offered again
/// when the lease lapses — by which time somebody may have fixed the version
/// skew that caused it.
fn owed(entry: &Value, lease_until: Timestamp) -> Option<Owed> {
    let events = entry
        .get("events")?
        .as_array()?
        .iter()
        .map(|event| read(event).ok())
        .collect::<Option<Vec<_>>>()?;

    Owed::new(
        DeliveryId::new(entry.get("delivery")?.as_str()?).ok()?,
        OriginId::new(entry.get("origin")?.as_str()?).ok()?,
        events,
        carried(entry)?,
        Timestamp::from_millis_since_epoch(entry.get("accepted_at_ms")?.as_i64()?),
        lease_until,
        // Absent means not a replay. A platform too old to send the field is
        // sending first deliveries, and defaulting the other way would mark
        // every message in every room.
        entry
            .get("replayed")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    )
}

/// The chain a Delivery arrived on, from the `traceparent` the platform sent.
///
/// Refused rather than replaced if it cannot be read, which is the opposite of
/// what the inbound side does with a sender's header — and the difference is
/// who sent it. A sender's malformed trace is worth less than its alert, so the
/// proxy generates one. This one comes from our own platform: a value we cannot
/// read means the two deployments disagree about the format, and inventing a
/// chain would hide that while breaking the trace it exists to carry.
fn carried(entry: &Value) -> Option<Correlation> {
    let traceparent = entry.get("traceparent")?.as_str()?;
    let mut fields = traceparent.split('-');
    let version = fields.next()?;
    if version != "00" {
        return None;
    }
    let trace = fields.next()?;
    let span = fields.next()?;
    let flags = fields.next()?;
    if flags.len() != 2 || fields.next().is_some() {
        return None;
    }

    // Absent, null and empty all mean "the sender set none", which is what the
    // platform sends when it has none to pass on.
    let state = entry
        .get("tracestate")
        .and_then(Value::as_str)
        .filter(|state| !state.is_empty());

    Correlation::new(trace, span, state).ok()
}

/// A report, as the platform reads it.
fn written(report: &Report) -> Value {
    match report {
        Report::RoutedToNothing => json!({ "outcome": "routed_to_nothing" }),
        Report::Reached(rooms) => json!({
            "outcome": "reached",
            "rooms": rooms
                .iter()
                .map(|(room, outcome)| match outcome {
                    RoomOutcome::Delivered => json!({
                        "room": room.as_str(),
                        "outcome": "delivered",
                    }),
                    // WHY, not just THAT. The platform turns this into a
                    // counter labelled by reason (bead gc-556), because the
                    // four are not interchangeable to whoever acts on one — a
                    // room that refused needs a configuration change, a room
                    // that was never reached needs the network looked at.
                    //
                    // The spelling is the reason's own (`DispatchFailed::
                    // spelled`), shared with the stored row and with the
                    // platform's metric label, so a reason cannot be one word
                    // on the wire and another in the database.
                    RoomOutcome::Abandoned(why) => json!({
                        "room": room.as_str(),
                        "outcome": "abandoned",
                        "reason": why.spelled(),
                    }),
                })
                .collect::<Vec<_>>(),
        }),
    }
}

#[async_trait]
impl Offers for Platform {
    async fn claim(&self) -> Result<Vec<Owed>, Unreachable> {
        let answered = self
            .client
            .post(&self.claim)
            .send()
            .await
            .map_err(|_| Unreachable)?;

        // A refusal is not a network failure, but there is nothing useful an
        // agent can do differently about either: both mean nothing was claimed.
        // The composition root logs the status so a 403 — which means the
        // platform does not serve this namespace — is diagnosable.
        if !answered.status().is_success() {
            return Err(Unreachable);
        }

        let body: Value = answered.json().await.map_err(|_| Unreachable)?;

        // No lease means nothing was claimed, so the list is empty and the
        // moment is never used. Reading it as the epoch rather than refusing
        // keeps an empty answer from looking like a broken one.
        let lease_until = Timestamp::from_millis_since_epoch(
            body.get("lease_expires_ms")
                .and_then(Value::as_i64)
                .unwrap_or(0),
        );

        Ok(body
            .get("deliveries")
            .and_then(Value::as_array)
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|entry| owed(entry, lease_until))
                    .collect()
            })
            .unwrap_or_default())
    }

    async fn report(
        &self,
        delivery: &DeliveryId,
        report: &Report,
    ) -> Result<Acknowledged, Unreachable> {
        let answered = self
            .client
            .post(format!("{}/{}/report", self.reports, delivery.as_str()))
            .json(&written(report))
            .send()
            .await
            .map_err(|_| Unreachable)?;

        // 404 is the platform saying nothing outstanding goes by that identity,
        // which is a fact and not a fault: the likeliest cause is that this
        // agent's lease lapsed and somebody else discharged it. Retrying would
        // be retrying something that will never be accepted.
        if answered.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(Acknowledged::NotOutstanding);
        }
        if !answered.status().is_success() {
            return Err(Unreachable);
        }
        Ok(Acknowledged::Recorded)
    }
}

#[cfg(test)]
mod tests {
    use application::ports::Owed;
    use domain::Timestamp;
    use serde_json::json;

    use super::{carried, owed, written};

    fn at(millis: i64) -> Timestamp {
        Timestamp::from_millis_since_epoch(millis)
    }

    fn a_delivery() -> serde_json::Value {
        json!({
            "delivery": "d-1",
            "origin": "alertmanager-a-tenant",
            "accepted_at_ms": 1_760_000_000_000_i64,
            "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "tracestate": null,
            "events": [{
                "kind": "pushed_commits",
                "repository": "motrice/webhook-proxy",
                "branch": "main",
                "pusher": "bjorn",
                "commits": [],
                "permalink": null,
            }],
        })
    }

    #[test]
    fn a_claimed_delivery_is_read_whole() {
        let one: Owed = owed(&a_delivery(), at(99)).expect("a readable Delivery");

        assert_eq!(one.delivery().as_str(), "d-1");
        // The origin as the PLATFORM spells it, which is longer than a tenant
        // expects: a shared sender is registered once per tenant (gc-nkb), and
        // this is the value a rule matching `origin` compares against.
        assert_eq!(one.origin().as_str(), "alertmanager-a-tenant");
        assert_eq!(one.events().len(), 1);
        assert_eq!(one.accepted_at(), at(1_760_000_000_000));
        // The lease is the platform's, read rather than assumed (gc-81d).
        assert_eq!(one.lease_until(), at(99));
        assert_eq!(
            one.correlation().trace(),
            "4bf92f3577b34da6a3ce929d0e0e4736"
        );
        // A first delivery unless the platform says otherwise, which is the
        // safe default: the other way round would mark every message in every
        // room.
        assert!(!one.replayed());
    }

    #[test]
    fn nothing_in_a_claim_carries_a_tenant() {
        // There is nowhere for one to go, and that is the point: `Owed` has no
        // tenant field, so this agent cannot hold one even if the platform sent
        // it. A field appearing here later would be a value nothing checks
        // against anything (bead gc-nkb).
        let mut entry = a_delivery();
        entry["tenant"] = json!("somebody-elses-tenant");

        let one = owed(&entry, at(99)).expect("a readable Delivery");

        assert!(
            !format!("{one:?}").contains("somebody-elses-tenant"),
            "a tenant reached the agent: {one:?}"
        );
    }

    #[test]
    fn a_delivery_this_build_cannot_read_is_skipped_rather_than_fatal() {
        // One unreadable Delivery must not stop the others being delivered. It
        // is offered again when the lease lapses, by which time somebody may
        // have fixed the version skew that caused it.
        for broken in [
            json!({ "delivery": "d-1" }),
            json!({ "delivery": "", "origin": "o", "accepted_at_ms": 0, "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", "events": [] }),
            json!({ "delivery": "d-1", "origin": "o", "accepted_at_ms": 0, "traceparent": "nonsense", "events": [] }),
        ] {
            assert!(owed(&broken, at(99)).is_none(), "{broken}");
        }
    }

    #[test]
    fn a_delivery_with_no_events_is_refused() {
        // Nobody could report rooms for it and the platform's queue would never
        // drain, so it cannot be built — the same refusal `Offered` makes on the
        // other side.
        let mut entry = a_delivery();
        entry["events"] = json!([]);

        assert!(owed(&entry, at(99)).is_none());
    }

    #[test]
    fn a_trace_this_build_cannot_read_is_refused_and_not_replaced() {
        // The opposite of what the inbound side does with a sender's header,
        // and the difference is who sent it. A sender's malformed trace is
        // worth less than its alert. This one is our own platform's: a value we
        // cannot read means the two deployments disagree, and inventing a chain
        // would hide that while breaking the trace it exists to carry.
        for traceparent in [
            "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra",
            "00-nothex-00f067aa0ba902b7-01",
        ] {
            let mut entry = a_delivery();
            entry["traceparent"] = json!(traceparent);
            assert!(carried(&entry).is_none(), "{traceparent}");
        }
    }

    #[test]
    fn a_tracestate_is_carried_when_there_is_one_and_not_invented_when_there_is_not() {
        let mut entry = a_delivery();
        entry["tracestate"] = json!("congo=t61rcWkgMzE");
        assert_eq!(
            carried(&entry).expect("a chain").state(),
            Some("congo=t61rcWkgMzE")
        );

        // Null, absent and empty all mean the sender set none.
        assert_eq!(carried(&a_delivery()).expect("a chain").state(), None);
        let mut blank = a_delivery();
        blank["tracestate"] = json!("");
        assert_eq!(carried(&blank).expect("a chain").state(), None);
    }

    #[test]
    fn a_report_is_written_the_way_the_platform_reads_it() {
        use application::ports::{DispatchFailed, Report, RoomOutcome};
        use domain::DestinationId;

        assert_eq!(
            written(&Report::RoutedToNothing),
            json!({ "outcome": "routed_to_nothing" })
        );
        assert_eq!(
            written(&Report::Reached(vec![
                (
                    DestinationId::new("team-room").expect("an identity"),
                    RoomOutcome::Delivered
                ),
                (
                    DestinationId::new("oncall-room").expect("an identity"),
                    RoomOutcome::Abandoned(DispatchFailed::Intercepted)
                ),
            ])),
            json!({
                "outcome": "reached",
                "rooms": [
                    { "room": "team-room", "outcome": "delivered" },
                    { "room": "oncall-room", "outcome": "abandoned", "reason": "intercepted" },
                ],
            })
        );

        // Every reason has a word, and it is the reason's own — the same one
        // the platform's metric label and the stored row use (bead gc-556). A
        // reason the platform cannot read back is a report it refuses whole, so
        // this is the agent's half of a wire format neither side owns alone.
        for (why, word) in [
            (DispatchFailed::Rejected, "rejected"),
            (DispatchFailed::Intercepted, "intercepted"),
            (DispatchFailed::Unreachable, "unreachable"),
            (DispatchFailed::TimedOut, "timed_out"),
        ] {
            assert_eq!(
                written(&Report::Reached(vec![(
                    DestinationId::new("team-room").expect("an identity"),
                    RoomOutcome::Abandoned(why)
                )])),
                json!({
                    "outcome": "reached",
                    "rooms": [{ "room": "team-room", "outcome": "abandoned", "reason": word }],
                })
            );
        }
    }
}
