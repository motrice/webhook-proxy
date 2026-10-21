<!--
SPDX-FileCopyrightText: 2026 Motrice AB

SPDX-License-Identifier: CC-BY-4.0
-->

# Sending to this proxy

What a sender needs in order to reach a room through this proxy, written for
whoever configures the sender — which is usually a different repository and a
different person from whoever changes this one.

If this document and the code disagree, the code is right and this is a bug.
Every claim below names the test that holds it, so the disagreement is findable
rather than a matter of opinion.

## Where to post

```text
POST https://<host>/webhook/<sender>
```

`<sender>` is the `id` of an entry under `origins:` in the proxy's routing file.
It is not a product name: whoever deploys the proxy chooses it, and the same
Grafana could be two senders with two credentials if that were useful. Ask for
the routing file, or run `webhook-proxy check` against it, which prints one line
per sender showing exactly the path it answers on.

A path naming no configured sender answers `404`. That is not an invitation to
enumerate: a wrong credential for a real sender and a real credential for no
sender both end the conversation.

## How to prove who you are

Each sender declares **one** mechanism in the routing file. The proxy reads that
declaration before it looks at the request, so presenting the other mechanism's
credential is refused rather than retried under it.

| Mechanism | Header | Value |
| --------- | ------ | ----- |
| Signature over the body | `X-Hub-Signature-256` | `sha256=<hex HMAC-SHA256 of the exact bytes sent>` |
| Value shared in advance | `Authorization` | `Bearer <the shared value>` |

The scheme word in `Authorization` is matched case-insensitively, as RFC 7235
says it should be. The signature is computed over the bytes as sent — re-encoding
the body invalidates it, which is the point of a signature and the reason this
proxy never reformats what it receives.

A shared value proves possession and says nothing about the body, so anyone who
obtains one can send any content until it is replaced. Treat it as the credential
it is: hold it in a secret, rotate it by changing the routing file's secret and
restarting, and prefer a signing sender where you have the choice.

`Content-Type` is **not** checked. Send `application/json`; the proxy reads the
body as bytes and the translator decides whether it is JSON it understands.

## What you will get back

| Code | Means | What to do |
| ---- | ----- | ---------- |
| `202` | Accepted. **Not delivered.** | Nothing. See below. |
| `400` | The body is not a payload this sender's translator understands | Fix the payload. Retrying identical content will not help. |
| `401` | The credential is absent, malformed, or wrong | Fix the credential. Indistinguishable on purpose — the proxy will not tell you which. |
| `404` | No sender is configured at that path | Check the path against the routing file. |
| `413` | The body is larger than the configured limit | Send less. Refused before anything is verified or parsed. |
| `415` | The body does not say it is `application/json` | Change the setting, not the payload. GitHub offers two content types in its webhook settings; this service translates the one. |
| `503` | A secret the proxy needs could not be read, or the store it keeps deliveries in is unreachable | Not yours to fix. Tell whoever runs the proxy; retrying later is reasonable. |

**`202` means accepted, not delivered**, and the distinction is deliberate. The
proxy answers as soon as the request is verified, then dispatches to each
matching room independently. A room being unreachable afterwards does not turn
into a `5xx`, because a sender seeing `5xx` would retry and re-deliver to the
rooms that already succeeded.

**Send `application/json`.** It is the one format translated here, and a request
that says anything else — or says nothing — is refused with `415` rather than
`400`: a hook configured with form encoding is a setting to change, not a
payload to fix. A charset parameter is fine; `application/json; charset=utf-8`
is the same media type.

What `202` does promise is that the delivery is **written down**, and written
down means in a database — so a restart of the proxy does not lose it. You do
not have to ask which storage you are talking to: a deployment without its
database refuses to start, so a proxy that answered you at all is one that keeps
what it accepted. That is also why there is a second way to get a `503`. Rather
than accept something it cannot promise to keep, the proxy refuses everything
while the store is unreachable — a loud refusal instead of a quiet downgrade.

### What happens after it is written down

**It is offered to the team your sender belongs to**, whose own agent delivers
it to that team's rooms by that team's own rules. Each sender is registered as
belonging to exactly one team, and which rooms hear what is decided in that
team's repository — not here.

So `202` means **stored, and offered to the team whose sender you are.** That is
*weaker* than what this document promised until recently, and the weaker
statement is the honest one: this proxy no longer attempts a room itself, so a
team whose agent is broken leaves alerts sitting where this proxy would once
have tried and reported a loss. **Nobody will tell you that has happened** — it
is visible to whoever runs the proxy, as a count and a log, and to the team, in
its own agent's log. A room that was given up on is counted too, per room and
with its reason, by whoever runs the proxy. None of it is visible in anything
you get back.

Nothing about what you send or how you send it changed when that did.

**Two things worth knowing even so:**

- An alert nobody ever collects is kept for a month and then dropped, logged and
  counted as the loss it is. "Accepted" has never meant "kept indefinitely", and
  now it says so.
- A delivery can be sent to its team again, by identity, by somebody who runs
  the proxy. The room shows `(replayed)` when that happens, so a responder can
  tell a resend from a situation getting worse.

So: do not treat `202` as proof a human saw anything, and do not retry on it.

## If you trace your calls

Send a `traceparent` and it is carried through to the room, so a message there
can be traced back to the call that caused it — including when a retry delivers
it minutes later. `tracestate` rides along unchanged; it belongs to you.

Three things worth knowing:

- **It is never required.** No `traceparent` is fine. One this proxy cannot
  parse is also fine: it is replaced with a freshly generated chain rather than
  refused, because losing an alert over a trace header would be the wrong trade.
  A value we could not read is never passed on.
- **The answer tells you the chain.** A `202` carries a `traceparent`, so a
  sender that sent none still learns which chain its delivery was filed under
  and can put that in its own log.
- **The hop you see in the room is ours, not yours.** Same trace, different span:
  the call this proxy made to the room is a different call from the one you made
  to this proxy, and a trace that showed them as one could not show that one
  caused the other.

A loss is logged with the trace alongside the delivery and the room, so the two
questions a loss raises — *which message* and *what else was happening* — have
different answers in the same line.

## What is lost, in your terms

- **No retry beyond a bounded number of attempts.** A room that stays
  unreachable long enough loses that message. What is queued is retried until
  the attempts run out, and then abandoned.
- **A `503` means we did not take it.** The delivery was not stored, so nothing
  was promised and nothing was sent — whether that is a secret the proxy could
  not read or a store it could not reach. Send it again. If your sender does not
  retry — **GitHub does not** — somebody has to redeliver it by hand.
- **Repeats are possible.** Within the attempt budget a room can see the same
  message twice — when a request succeeded but its response was lost. Do not
  build anything that assumes exactly-once.
- **Order is not promised.** Two notifications can reach one room out of order.
- **An alert nobody collects is eventually dropped.** Retention is one month
  from the moment you were answered. A delivery still owed when it expires is
  deleted, and that deletion is logged and counted as a loss rather than
  happening quietly — but it is a loss, and no `5xx` ever told you about it.

Every loss is logged with the delivery's identity, the room's identity and the
reason, and counted. If you need to know whether something arrived, that log is
the answer, not the `202`.

A message you sent once can be sent to a room again, by an operator asking for
it. It arrives marked `(replayed)`, so a reader can tell it from something
happening a second time — which matters most for alerts, where a repeat is how
somebody learns a situation got worse.

A loss can also be something between this proxy and the room answering on its
behalf — a firewall returning a success status over a refusal. That is reported
as `Intercepted` rather than as the room refusing, because the room never saw the
message and its own logs will show nothing.

## Alertmanager

Schema **v4** (`"version": "4"`). A notification carrying a different version is
refused with `400` rather than read loosely — Grafana's payload has the same
outer shape, and a parser willing to read either would build messages from the
wrong conventions.

```yaml
receivers:
  - name: webhook-proxy-devsecops
    webhook_configs:
      - url: https://<host>/webhook/alertmanager-devsecops
        send_resolved: true
        http_config:
          authorization:
            type: Bearer
            credentials_file: /etc/alertmanager/secrets/webhook-proxy-devsecops-token
```

Reference the credential from a file rather than inlining it, so the value is not
in the repository that holds the rules.

**One receiver per team, each with its own credential**, and the shape of that
URL is the reason. Every sender this proxy serves belongs to exactly one team,
decided when the sender is registered and proved by the sender's own credential
— so one Alertmanager sending for several teams registers as several senders,
and chooses between them in its own `route` tree:

```yaml
route:
  routes:
    - matchers: [namespace =~ "devsecops-.*"]
      receiver: webhook-proxy-devsecops
    - matchers: [namespace =~ "platform-.*"]
      receiver: webhook-proxy-platform
```

That costs a receiver and a credential per team. What it buys is that the
decision is made here, in the routing you already own and can see, rather than
from a label on the alert — and a label is written by whoever can deploy the
workload that fires it, so a label deciding which team an alert belongs to would
let one team's deployer file alerts as another's. Bead `gc-nkb` records the
reasoning. A label is routing *input*; it is never an authorisation boundary.

Per alert, the proxy **requires**:

| Field | Missing or unreadable |
| ----- | --------------------- |
| `fingerprint` | the whole notification is refused with `400` |
| `status` — exactly `firing` or `resolved` | refused with `400`; never guessed |
| `startsAt` — RFC 3339 | refused with `400` |

It **uses, and tolerates the absence of**:

| Field | Absent |
| ----- | ------ |
| `annotations.summary` | falls back to `annotations.description`, then the `alertname` label |
| `labels.severity` | the alert is delivered with no severity stated, and a rule matching on severity will not select it |
| `generatorURL` | falls back to `annotations.runbook_url`, then no link |
| any other label | carried as sent; rules may match on any of them |

Held by `a_grouped_notification_yields_one_event_per_alert_in_the_order_sent`,
`description_is_used_when_there_is_no_summary_annotation`,
`an_alert_with_no_severity_label_is_unstated_rather_than_defaulted` and their
neighbours in `crates/adapters/alertmanager-payload/src/lib.rs`.

**One notification is all-or-nothing.** If any alert in it cannot be read, none
of them is delivered — better than a room hearing about two of three with nobody
knowing the third existed.

**Grouping is preserved.** `group_by` collapses many firing alerts into one
notification so a room gets one message, and that is what a room gets: one
message per room, carrying the alerts from your notification that its rules
selected.

Different alerts in one notification can select different rooms, so each room
sees its own subset — which means the group a room sees is one this proxy
composed, not the one you composed. A notification whose alerts all go to one
room arrives exactly as you grouped it.

A message carrying several alerts shows **one line each** rather than the full
rendering, with a count at the top; one carrying a single alert is rendered in
full, as before. At most eight are listed and the rest are counted — `(+12
more)` — because Alertmanager places no limit on alerts per notification and a
message longer than the room is no more readable than twenty separate ones. The
trade is deliberate: a grouped message is for scanning, and the links to each
alert are in your monitoring system.

## Grafana

Unified alerting, schema **v1** (`"version": "1"`).

```yaml
apiVersion: 1
contactPoints:
  - orgId: 1
    name: webhook-proxy
    receivers:
      - uid: webhook-proxy
        type: webhook
        settings:
          url: https://<host>/webhook/grafana
          httpMethod: POST
          authorization_scheme: Bearer
          authorization_credentials: $WEBHOOK_PROXY_TOKEN
```

`$WEBHOOK_PROXY_TOKEN` is read from Grafana's environment. Do not write the value
into the provisioning file.

The required fields are the same three as Alertmanager's. What differs is where
the text and the link come from:

| Wanted | Order tried |
| ------ | ----------- |
| The one line a room sees | `annotations.summary`, `annotations.description`, the notification's `title`, its `message`, the `alertname` label |
| The link | `panelURL`, `dashboardURL`, `generatorURL` |

An alert's own annotation beats the notification's `title` because the title
describes the whole group — three alerts would otherwise share one sentence. The
`title` beats the `message` because `message` is multi-line markdown whose first
line says nothing about what broke.

**`silenceURL` is never used as the link**, though Grafana sends one with every
alert. Pointing a notice at "silence this" invites silencing before reading.

Held by `the_title_wins_over_the_message_when_an_alert_says_nothing_itself`,
`the_panel_url_wins_then_the_dashboard_then_the_rule` and
`the_silence_link_is_never_offered_as_the_place_to_look` in
`crates/adapters/grafana-payload/src/lib.rs`.

## How a message is routed

A rule in the routing file names labels a message must carry. Every label an
alert sends is matchable, plus two the proxy derives from the typed fields it
read — `severity` and `status` — and one it sets itself:

**`origin` is reserved.** The proxy sets it from the verified request, and a
sender cannot. A label named `origin` in your payload is dropped before routing.
That is what makes a rule saying `origin: alertmanager-devsecops` trustworthy: an
alert from somewhere else cannot claim it, however it is annotated.

Values are compared for equality. There is no negation and no pattern matching —
a regular expression over text written by whoever can deploy a workload is a
denial of service waiting to be written.

If a room is not receiving what you expect, `webhook-proxy check` prints every
rule and marks each label that only a sender can supply. A rule whose every label
is sender-supplied, or a room with no rules at all, is visible there.

## Anything else

Markup in a summary, an annotation, a commit message or a label value arrives as
the characters it is made of. Line breaks inside a label value are escaped too, so
a value cannot forge what looks like a separate message.

Nothing you send becomes a link. A URL you write appears as text; the only link a
room ever shows is the permalink your payload published, and it is shown with its
address as its visible text, so a reader can see where it goes before clicking.

So: do not rely on formatting, and do not assume your markup is inert elsewhere.

What we promise about your payload ends at the chat server's door. A room's
webhook can be configured to transform what it receives before anybody reads it,
and a firewall on the path can refuse your notice for its contents — neither is
something this proxy sets, and neither tells us it happened. The escaping above
is a promise about what we send, not about what a reader finally sees.

Long values are cut: a summary at 200 characters, a label name or value at 60,
and at most 8 labels shown with any remainder counted rather than hidden.
