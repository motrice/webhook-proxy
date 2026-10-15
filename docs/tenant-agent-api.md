# The hand-off to a tenant's agent

Two operations, in-cluster, machine to machine. This is **not** part of the
interface a sender calls — `docs/openapi.yaml` describes that one, and
`crates/app/tests/openapi.rs` excludes these two paths from it by name with a
reason each.

Documented here rather than there because bead `gc-81d` decided the national
REST API-profil does not bind this interface: `CLAUDE.md` scopes that profile to
an HTTP interface for a Swedish public-sector consumer, and an agent in the next
namespace is in-cluster machinery. The practical consequence is that
`just lint-api` still reports exactly the six known findings for the public
specification, and nothing here is measured against it.

## What authenticates a caller

**The service mesh, and nothing in the process.** Istio's sidecar verifies the
peer's certificate and then *sets* `x-forwarded-client-cert` from it, replacing
whatever the request carried. The process reads the `URI=` field of the first
certificate — the peer's SPIFFE identity,
`spiffe://<trust domain>/ns/<namespace>/sa/<name>` — and takes the **namespace**
as the tenant. A tenant is a namespace in this platform, so there is no mapping
to configure and therefore none to drift.

> **A deployment that runs this workload without the sidecar has no
> authentication on these two paths at all**, because any caller could then
> write the header itself. That assumption is load-bearing, and
> `deploy/webhook-proxy/README.md` states it where somebody deploying this will
> read it.

Three things narrow it further, and each is in its own file:

- **The namespace must be a tenant this deployment serves.** Checked in the
  process, against the same `tenants:` list the routing file already carries.
  This is what makes the public path harmless by construction: a request
  arriving through the ingress gateway carries the *gateway's* identity, and
  `istio-ingress` is not a tenant.
- **Which service account may call** is
  `deploy/webhook-proxy/istio/authorizationpolicy.yaml`. The process
  deliberately does not check it, so that half a rule does not live in two
  places — "any workload in that namespace" is not the boundary, the policy is.
- **Which namespaces can reach the pod at all** is
  `deploy/webhook-proxy/networkpolicy.yaml`, by a label rather than by listing
  tenants a second time.

**The tenant is never a parameter.** Not in a path, not in a body, not in a
header of its own. A parameter would be a claim; the identity is a fact.

## Claim

```http
POST /deliveries/claim
```

No request body. The batch size and the lease are the platform's, not the
caller's: an agent gains nothing from choosing either, because it can simply
claim again.

```json
{
  "lease_expires_ms": 1760000300000,
  "deliveries": [
    {
      "delivery": "01K7...",
      "origin": "alertmanager-devsecops",
      "accepted_at_ms": 1760000000000,
      "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
      "tracestate": null,
      "events": [{ "kind": "alert", "...": "..." }]
    }
  ]
}
```

- `200` with an empty `deliveries` list when there is nothing to collect, and
  `lease_expires_ms` is then `null` — a lease over nothing is not a fact.
- `401` when no identity was presented. In production that means a pod with no
  sidecar, not an attacker.
- `403` when the caller's namespace is not a tenant here. The same answer for an
  unknown namespace, a misspelled one, and the ingress gateway's own; it names
  no tenant, so a caller learns nothing about which exist.
- `503` when the store could not be reached.

**A Delivery arrives whole, with its Events together.** That is not a
convenience: a sender that grouped twenty alerts into one notification means one
message per room (beads `gc-lhh`, `gc-smz`), and an agent can only honour that
if it receives them as a group.

**The lease is returned and must not be assumed.** It belongs to the platform —
with two binaries that could disagree about its length, one of them has to own
it. It is **not renewable** in this version. A claim *lapses* rather than being
released, so an agent that dies mid-delivery costs the platform nothing to
notice: the Delivery is simply offered again.

**Moments are milliseconds since the epoch.** The only consumer is the agent in
this workspace, and a number needs no date library in either process and cannot
be read in the wrong time zone.

**Nothing in a claim is a credential.** No room URL, no token, no secret value
and no secret name (bead `gc-81d`). The platform holds the senders' secrets and
must not hand a tenant anything it did not already own. That is structural: the
type handed over has an origin *name* and no address, and the request body is
never stored, so there is nothing to leak.

## Report

```http
POST /deliveries/{delivery}/report
```

```json
{ "outcome": "reached", "rooms": [{ "room": "devsecops-room", "outcome": "delivered" }] }
```

or

```json
{ "outcome": "routed_to_nothing" }
```

- `204` when it was outstanding for this tenant and now is not.
- `400` when the report is not one of the two shapes above, or when
  `rooms` is empty.
- `404` when nothing outstanding for this caller goes by that identity. **One
  answer for three cases** — another tenant's Delivery, one already reported,
  one that never existed — because a caller that could tell them apart could ask
  after another tenant's Delivery identities and learn which exist.
- `401`, `403` and `503` as above.

**A report is terminal**, and it is what discharges the platform's obligation to
go on offering the Delivery. Room `outcome` is `delivered` or `abandoned`; there
is no "still trying", because an agent that has not finished has not reported and
the lease covers that gap.

**`routed_to_nothing` is a named outcome and not an empty room list.** A tenant
whose rules match no room must be able to say so, or the platform's queue never
drains and a healthy tenant is indistinguishable from a dead one (bead
`gc-g9x`). An empty `rooms` list is **refused**: an agent that forgot to fill it
in is the likeliest bug here, and accepting it would make that bug and a genuine
no-match the same statement.

**Reporting twice is safe**, and the second answers `404`. An agent whose reply
was lost on the way back must be able to send it again; an error would make a
retry look like a fault, and the agent's only other option would be to deliver
again.

**Neither side may give up on the other's behalf.** There is no verb for it in
either direction. An agent that exhausts its retry budget reports `abandoned` —
a loss it logs and counts where it happened. A tenant that stops collecting
leaves its Deliveries offered, and the platform counts and logs their age rather
than inventing a terminal state it cannot justify (bead `gc-g9x`; the count is
bead `gc-wcw.3`).

## What this costs, named rather than discovered

**An agent that delivers to one room and dies before the next loses that
progress.** The lease lapses, the Delivery is offered again, and the first room
sees a duplicate. Today — before the split — each (delivery, room) is its own
row and a crash between two rooms loses nothing, so this is a real regression.

Accepted knowingly for the first version (bead `gc-81d`) for two reasons:
duplicates are already permitted and documented — "repeats are possible …
nothing downstream should assume exactly-once" — and the exposure is bounded by
the lease. Incremental reporting is the right fix *if the duplicate rate warrants
it*, which is the same discipline `gc-6a5.4` already waits on.

**The wire shape of an Event is the stored shape.** One JSON codec serves the
`handover` table and this interface, because a second description of every Event
variant would drift apart one release at a time. The cost is that a storage
migration is an interface change — acceptable while the only consumer is the
agent in this workspace and nothing external is measured against it.
