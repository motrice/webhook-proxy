# Running the tenant agent

A second deployment, in a tenant's own namespace. It holds the only two things
that are genuinely the tenant's — which alerts reach which room, and those
rooms' URLs — and pulls everything else from the platform service. Bead
`gc-72e`.

**This is the only thing that reaches your rooms.** The platform verifies a
delivery and offers it to your team; it has no dispatcher, no outbox and no
retry loop of its own (`gc-72e.3.2`). If this agent does not deliver an alert,
nobody does.

It has run in a cluster: the agent claims, delivers, reports
`reached=N lost=N routed_to_nothing=N`, and a room receives exactly one copy per
delivery.

> **Where a loss shows up:** a room this agent gives up on is reported to the
> platform with its reason, and the platform counts it on its own `/metrics` as
> `webhook_proxy_room_abandoned_total{tenant,room,reason}`, beside
> `webhook_proxy_room_delivered_total{tenant,room}` so a ratio can be alerted on
> rather than an absolute. **Counted there and not here on purpose** — this pod
> has no Service, no HTTPRoute and no ingress NetworkPolicy (`gc-72e`), so
> nothing can scrape it, and a counter in this process would have been erased by
> the next restart along with the log. Bead `gc-556`.
>
> Two things that still only this log knows: the attempt-by-attempt detail, and
> a loss the agent never manages to report at all — if this pod dies before
> reporting, the delivery's lease lapses and it is offered again, so the work is
> not lost but that attempt's record is. The sender was told `202` long before
> either way.

This section said the opposite until bead `gc-uh0` — that nothing here delivered
yet, and that deploying it would double every message. It was true when written
and then stayed for a release after it stopped being true, which is worth
knowing if you find a copy of it quoted somewhere else.

## What it is deliberately not

| Not here | Because |
| -------- | ------- |
| A Service, an HTTPRoute, an ingress NetworkPolicy | It **pulls**. Nothing reaches it, which is most of what "thin" means. |
| A database | It is stateless. What has not been delivered is the platform's to remember. |
| Any `origins:` or `verify:` block | The platform authenticates senders. This agent holds no sender's secret and could not check one. |
| Any `tenant:` or `tenants:` key | The platform derives the tenant from the Origin's registration and from this agent's own mTLS identity. A name written here would be checked against nothing — bead `gc-nkb`. |

Each of those four keys is **refused by name with a reason**, not ignored. They
are not typos; they are what somebody reaches for having read the platform's
file.

## Checking it before deploying it

```sh
ALERT_AGENT_CONFIG=deploy/alert-agent/config.example.yaml \
ALERT_AGENT_SECRETS_DIR=/path/to/secrets \
  alert-agent check
```

It performs exactly the read a run does, then prints what the file would
actually route — including a room that nothing selects, and each label that only
a sender can supply. Run it in the tenant's own pipeline on every change to the
file: a mistake here is a quiet room, and nobody notices quiet.

## The one mistake worth warning about in advance

**Origin names are longer than you expect.** The platform registers a shared
sender once per tenant (bead `gc-nkb`), so what arrives is
`alertmanager-<your-namespace>` rather than `alertmanager`. A rule matching the
short name matches nothing, silently and forever.

Nothing in this file can catch it, and that is not an oversight: this agent
never sees the platform's list of senders, which is the same separation that
stops it seeing other tenants' alerts. `alert-agent check` prints the warning
unconditionally; the platform's own `webhook-proxy check` prints the real names.

## Where the room URLs come from

The secrets directory, one file per name this file mentions, rendered by an
agent beside this process from `secret/<tenant>/*`. **Every room URL is itself a
credential** (bead `gc-o61`): anyone holding it can post to that room, which is
why rooms are *named* here and their URLs are not.

That rendering pattern is the platform's intended one and, per
`tenant/wallet-devops-docs-prod/docs/secrets.md`, is still marked *"Unverified —
needs a first-tenant trial run"*. This deployment is its first real user.
Nothing in this repository has confirmed it works, and the cluster runs so far
do not settle it either way — so expect to find something there rather than to
have it confirmed.
