//! The hand-off to a tenant's agent, over HTTP.
//!
//! Two operations and no third (bead gc-81d): claim a Delivery whole, report
//! its rooms terminally. Not part of the public interface — `docs/openapi.yaml`
//! describes what a *sender* may call, and `crates/app/tests/openapi.rs`
//! excludes these two paths by name with a reason each.
//!
//! IN THE APP CRATE, AND THE REASON IS A BOUNDARY RULE RATHER THAN CONVENIENCE.
//! The claim response carries Events as JSON, and the only JSON codec for an
//! `Event` lives in `postgres-outbox` — where the stored shape needed one
//! first. An adapter may not depend on another adapter, so an HTTP adapter
//! could not reuse it, and writing a second codec would mean two descriptions
//! of every Event variant drifting apart one release at a time. The app crate
//! may depend on both, so the interface is composed here beside `/health`,
//! `/api-info` and `/metrics`, which are here for the same kind of reason.
//!
//! The cost of that, named rather than discovered: the wire shape and the
//! stored shape are now the same JSON, so a storage migration is an interface
//! change. Acceptable while the only consumer is the agent in this workspace
//! (bead gc-72e) and the profile does not bind this interface; it would not be
//! if either changed.
//!
//! # What authenticates a caller
//!
//! **The service mesh, and nothing in this process.** Istio's sidecar verifies
//! the peer's certificate and then SETS `x-forwarded-client-cert` from it,
//! replacing whatever the request carried — so the header is a fact inside the
//! mesh and a claim anywhere else.
//!
//! That assumption is load-bearing and worth stating plainly: **a deployment
//! that runs this workload without the sidecar has no authentication on these
//! two paths at all**, because any caller could then write the header itself.
//! `deploy/webhook-proxy/README.md` says so, the `AuthorizationPolicy` beside
//! it is what restricts which service account may call, and the `HTTPRoute`
//! deliberately publishes only `/webhook` so the public gateway cannot reach
//! these paths even by mistake.
//!
//! One thing does hold without any of that, and it is why a public request
//! cannot become a tenant: the namespace in the identity must be a tenant this
//! deployment serves. A request arriving through the public gateway carries the
//! gateway's own identity, whose namespace is `istio-ingress`, and
//! `istio-ingress` is not a tenant.

use std::sync::Arc;

use application::ports::{Clock, DispatchFailed, Handover, Report, RoomOutcome, TenantId};
use application::{Collect, NotCollected, Outcomes};
use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use domain::{DeliveryId, DestinationId};
use postgres_outbox::written;
use serde_json::{Value, json};

/// How long a claim holds.
///
/// The platform's number, returned in every claim response and never assumed by
/// an agent (bead gc-81d). Not configurable, and that is deliberate: an
/// operator who set it too short would cause duplicate messages in somebody's
/// room, which is a worse failure than any this would let them tune away.
///
/// Five minutes against an agent retry budget of about thirty seconds — five
/// attempts, one second doubling to a cap of thirty. Long enough that an agent
/// finishes first; short enough that a pod killed mid-delivery is offered its
/// work again while somebody is still watching.
const LEASE: core::time::Duration = core::time::Duration::from_mins(5);

/// How many Deliveries one claim may take.
///
/// The platform's number as well, for the reason the use case gives: an agent
/// gains nothing from choosing it, because it can claim again.
const BATCH: usize = 64;

/// What the two paths need, shareable across requests.
#[derive(Clone)]
pub struct Collecting {
    handover: Arc<dyn Handover>,
    clock: Arc<dyn Clock>,
    tenants: Arc<std::collections::BTreeSet<TenantId>>,
    /// What each room was told, shared with the scrape endpoint.
    ///
    /// Here rather than in the agent because an agent has no scrape endpoint
    /// and bead gc-72e forbade it one; the outcomes already cross the wire in
    /// every report (bead gc-556).
    outcomes: Arc<Outcomes>,
}

impl Collecting {
    /// Wires the hand-off to the store and the configuration.
    #[must_use]
    pub fn new(
        handover: Arc<dyn Handover>,
        clock: Arc<dyn Clock>,
        tenants: std::collections::BTreeSet<TenantId>,
        outcomes: Arc<Outcomes>,
    ) -> Self {
        Self {
            handover,
            clock,
            tenants: Arc::new(tenants),
            outcomes,
        }
    }

    fn collect(&self) -> Collect<'_> {
        Collect::new(
            self.handover.as_ref(),
            self.clock.as_ref(),
            &self.tenants,
            LEASE,
            BATCH,
        )
    }
}

/// The tenant a caller speaks for, from the identity the mesh established.
///
/// `x-forwarded-client-cert` is Envoy's, and the field that matters is `URI=`:
/// the peer's SPIFFE identity, `spiffe://<trust domain>/ns/<namespace>/sa/<name>`.
/// A tenant is a namespace in this platform (bead gc-81d), so the namespace
/// segment IS the tenant — no mapping to configure and therefore none to drift.
///
/// THE SERVICE ACCOUNT IS READ AND NOT CHECKED, which is a decision rather than
/// an omission: restricting *which* account may call is the `AuthorizationPolicy`'s
/// job, so "any workload in that namespace" is not the boundary — the policy is.
/// Checking it here as well would put half a rule in two places.
///
/// `None` for anything this cannot read, and every such case is refused. There
/// is no fall-back to a parameter, a path or another header: a parameter would
/// be a claim, and this is a fact.
fn caller(headers: &HeaderMap) -> Option<TenantId> {
    let presented = headers.get("x-forwarded-client-cert")?.to_str().ok()?;

    // The peer is the FIRST certificate. Envoy appends one entry per
    // certificate in the chain, comma-separated, and a later entry is somebody
    // further up the path — trusting one of those would be trusting whatever
    // the peer's own peer was.
    let peer = presented.split(',').next()?;

    let uri = peer.split(';').find_map(|field| {
        let (name, value) = field.split_once('=')?;
        name.trim().eq_ignore_ascii_case("URI").then_some(value)
    })?;
    let uri = uri.trim().trim_matches('"');

    // spiffe://<trust domain>/ns/<namespace>/sa/<name>, and nothing looser: a
    // parser that accepted a path shaped differently would be guessing which
    // segment is the namespace.
    let path = uri.strip_prefix("spiffe://")?;
    let (_trust_domain, path) = path.split_once('/')?;
    let mut segments = path.split('/');
    if segments.next()? != "ns" {
        return None;
    }
    let namespace = segments.next()?;
    if segments.next()? != "sa" || segments.next().is_none() || segments.next().is_some() {
        return None;
    }

    // A namespace that is not a name a tenant could have is refused here rather
    // than compared and silently never matched.
    TenantId::new(namespace).ok()
}

/// What an unauthorised caller is told.
///
/// `403` and not `404`: the path exists, and saying so costs nothing — a caller
/// that reached it at all is inside the mesh. What it must not learn is which
/// tenants this deployment serves, and it does not: every caller speaking for a
/// namespace that is not a tenant here gets this same answer, whether that
/// namespace is unknown, misspelled, or the ingress gateway's own.
fn refused(why: &NotCollected) -> (StatusCode, Json<Value>) {
    match why {
        NotCollected::NotATenantHere => (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "this deployment serves no tenant for your namespace"
            })),
        ),
        NotCollected::StorageUnavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "the store could not be reached" })),
        ),
    }
}

/// Claim up to a batch of this tenant's undelivered Deliveries.
///
/// A `POST` because it mutates: what comes back is leased to the caller and
/// will not be offered to anybody else until the lease lapses.
async fn claim(
    State(collecting): State<Collecting>,
    headers: HeaderMap,
) -> (StatusCode, Json<Value>) {
    let Some(caller) = caller(&headers) else {
        // Deliberately not 403: there is nothing to authorise, because nothing
        // established who is calling. An operator seeing this in a log is
        // almost certainly looking at a pod with no sidecar.
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "no client identity was presented" })),
        );
    };

    match collecting.collect().claim(&caller).await {
        Ok(claimed) => {
            let until = claimed.first().map(application::ports::Claimed::until);
            let deliveries: Vec<Value> = claimed
                .iter()
                .map(|one| {
                    let offered = one.offered();
                    json!({
                        "delivery": offered.delivery().as_str(),
                        "origin": offered.origin().as_str(),
                        // Milliseconds since the epoch rather than a formatted
                        // moment: the only consumer is the tenant agent, and a
                        // number needs no date library in either process and
                        // cannot be read in the wrong time zone.
                        "accepted_at_ms": offered.accepted_at().millis_since_epoch(),
                        "traceparent": spelled(offered.correlation()),
                        "tracestate": offered.correlation().state(),
                        // Whether a person asked for this to be sent again, so
                        // the room can show it. The agent must not guess:
                        // marking a retry is what bead gc-6a5.3 refused,
                        // because an alert arriving twice is how a responder
                        // learns something got worse.
                        "replayed": one.replayed(),
                        "events": offered.events().iter().map(written).collect::<Vec<_>>(),
                    })
                })
                .collect();

            (
                StatusCode::OK,
                Json(json!({
                    // Present only when something was claimed, because a lease
                    // over nothing is not a fact about anything.
                    "lease_expires_ms": until.map(domain::Timestamp::millis_since_epoch),
                    "deliveries": deliveries,
                })),
            )
        }
        Err(why) => refused(&why),
    }
}

/// Report what became of one Delivery. Terminal.
async fn report(
    State(collecting): State<Collecting>,
    Path(delivery): Path<String>,
    headers: HeaderMap,
    body: Option<Json<Value>>,
) -> (StatusCode, Json<Value>) {
    let Some(caller) = caller(&headers) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "no client identity was presented" })),
        );
    };
    let Ok(delivery) = DeliveryId::new(&delivery) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "that is not a delivery identity" })),
        );
    };
    let Some(Json(body)) = body else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "a report is required" })),
        );
    };
    let Some(report) = read_report(&body) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "a report says either outcome=routed_to_nothing, or \
                          outcome=reached with a non-empty rooms list of \
                          {room, outcome}, where outcome is delivered, or \
                          abandoned with reason=rejected|intercepted|\
                          unreachable|timed_out"
            })),
        );
    };

    match collecting
        .collect()
        .report(&caller, &delivery, &report)
        .await
    {
        Ok(application::ports::Discharged::Settled) => {
            // COUNTED HERE AND NOWHERE EARLIER, because this is the only place
            // that knows the report discharged something. A report that arrives
            // twice — an agent whose first reply was lost, which this API
            // explicitly allows — answers `NotOutstanding` below and must not
            // count again, or a single loss becomes as many losses as the agent
            // had attempts to tell us about it (bead gc-556).
            if let Report::Reached(rooms) = &report {
                for (room, outcome) in rooms {
                    collecting
                        .outcomes
                        .reported(caller.as_str(), room.as_str(), *outcome);
                }
            }
            (StatusCode::NO_CONTENT, Json(Value::Null))
        }
        // One answer for three cases — another tenant's Delivery, one already
        // reported, one that never existed — because a caller that could tell
        // them apart could ask after another tenant's Delivery identities and
        // learn which exist.
        Ok(application::ports::Discharged::NotOutstanding) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "nothing outstanding goes by that identity" })),
        ),
        Err(why) => refused(&why),
    }
}

/// The four reasons an agent may report, read back from the one spelling
/// `DispatchFailed::spelled` writes.
///
/// `None` for anything else, which refuses the whole report. The alternative —
/// an "other" bucket — would absorb a spelling the two sides stopped agreeing
/// about and keep counting, which is how a metric becomes something nobody
/// trusts.
fn read_reason(said: &str) -> Option<DispatchFailed> {
    match said {
        "rejected" => Some(DispatchFailed::Rejected),
        "intercepted" => Some(DispatchFailed::Intercepted),
        "unreachable" => Some(DispatchFailed::Unreachable),
        "timed_out" => Some(DispatchFailed::TimedOut),
        _ => None,
    }
}

/// Reads a tenant's terminal statement, or refuses it.
///
/// `routed_to_nothing` is a named outcome and NOT an empty room list, which is
/// the distinction bead gc-g9x asked for: an agent that forgot to fill its list
/// in is the likeliest bug here, and accepting an empty list would make that
/// bug and a healthy no-match the same statement. So an empty list is refused
/// and the agent has to say which it meant.
fn read_report(body: &Value) -> Option<Report> {
    match body.get("outcome")?.as_str()? {
        "routed_to_nothing" => Some(Report::RoutedToNothing),
        "reached" => {
            let rooms = body.get("rooms")?.as_array()?;
            if rooms.is_empty() {
                return None;
            }
            rooms
                .iter()
                .map(|entry| {
                    let room = DestinationId::new(entry.get("room")?.as_str()?).ok()?;
                    let outcome = match entry.get("outcome")?.as_str()? {
                        "delivered" => RoomOutcome::Delivered,
                        // A reason is REQUIRED with an abandonment, and a
                        // report without one is refused rather than counted
                        // under a catch-all. An "unknown" bucket would fill up
                        // silently the first time the two sides disagreed about
                        // a spelling, and the counter exists precisely so a
                        // loss is not something somebody has to go and read a
                        // log to understand (bead gc-556).
                        "abandoned" => {
                            RoomOutcome::Abandoned(read_reason(entry.get("reason")?.as_str()?)?)
                        }
                        _ => return None,
                    };
                    Some((room, outcome))
                })
                .collect::<Option<Vec<_>>>()
                .map(Report::Reached)
        }
        _ => None,
    }
}

/// A correlation as a `traceparent`, so the agent continues the chain rather
/// than starting one.
///
/// The same spelling the inbound adapter answers with; written here rather than
/// shared because an adapter may not depend on another adapter, and because
/// four fields joined by dashes is not a thing worth a boundary.
fn spelled(correlation: &domain::Correlation) -> String {
    format!("00-{}-{}-01", correlation.trace(), correlation.span())
}

/// The two paths, added to the router the composition root builds.
pub fn routes(collecting: Collecting) -> axum::Router {
    use axum::routing::post;

    axum::Router::new()
        .route("/deliveries/claim", post(claim))
        .route("/deliveries/{delivery}/report", post(report))
        .with_state(collecting)
}
