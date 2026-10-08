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
| `503` | A secret the proxy needs could not be read | Not yours to fix. Tell whoever runs the proxy; retrying later is reasonable. |

**`202` means accepted, not delivered**, and the distinction is deliberate. The
proxy answers as soon as the request is verified, then dispatches to each
matching room independently. A room being unreachable afterwards does not turn
into a `5xx`, because a sender seeing `5xx` would retry and re-deliver to the
rooms that already succeeded.

So: do not treat `202` as proof a human saw anything, and do not retry on it.

## What is lost, in your terms

- **No retry beyond a bounded number of attempts.** A room that stays
  unreachable loses that message. Nothing is queued for later.
- **Nothing is persisted.** A message in flight when the proxy restarts is gone.
- **Repeats are possible.** Within the attempt budget a room can see the same
  message twice — when a request succeeded but its response was lost. Do not
  build anything that assumes exactly-once.
- **Order is not promised.** Two notifications can reach one room out of order.

Every loss is logged with the delivery's identity, the room's identity and the
reason, and counted. If you need to know whether something arrived, that log is
the answer, not the `202`.

## Alertmanager

Schema **v4** (`"version": "4"`). A notification carrying a different version is
refused with `400` rather than read loosely — Grafana's payload has the same
outer shape, and a parser willing to read either would build messages from the
wrong conventions.

```yaml
receivers:
  - name: webhook-proxy
    webhook_configs:
      - url: https://<host>/webhook/alertmanager
        send_resolved: true
        http_config:
          authorization:
            type: Bearer
            credentials_file: /etc/alertmanager/secrets/webhook-proxy-token
```

Reference the credential from a file rather than inlining it, so the value is not
in the repository that holds the rules.

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
That is what makes a rule saying `origin: alertmanager` trustworthy: an alert
from somewhere else cannot claim it, however it is annotated.

Values are compared for equality. There is no negation and no pattern matching —
a regular expression over text written by whoever can deploy a workload is a
denial of service waiting to be written.

If a room is not receiving what you expect, `webhook-proxy check` prints every
rule and marks each label that only a sender can supply. A rule whose every label
is sender-supplied, or a room with no rules at all, is visible there.

## Anything else

Everything a room sees is sent as plain text. Markup in a summary, an
annotation or a label value arrives as the characters it is made of, and line
breaks inside a label value are escaped so a value cannot forge what looks
like a separate message. Do not rely on formatting; do not assume your markup
is inert elsewhere.

Long values are cut: a summary at 200 characters, a label name or value at 60,
and at most 8 labels shown with any remainder counted rather than hidden.
