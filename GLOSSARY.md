# Ubiquitous language

The vocabulary of this system. One term, one meaning, everywhere: in
conversation, in bead titles, in type names, in test names, in log messages.

This file is a hard constraint on naming, not documentation of it. An agent that
needs a word which is not here must add it in the same PR that first uses it —
and a reviewer who sees a new domain concept with no glossary entry should treat
that as the defect, ahead of anything about the code.

## Rules

- **A term means exactly one thing.** If the same word means two things in two
  contexts, those are two bounded contexts and the term needs qualifying in at
  least one of them.
- **Synonyms are forbidden.** Pick one word and delete the others. "User",
  "account" and "customer" as the same concept is the single most expensive
  naming mistake available.
- **The code spells it the same way.** A term here appears verbatim as the type,
  method or variant name — modulo Rust casing.
- **No technical nouns.** `Manager`, `Service`, `Helper`, `Data`, `Info`,
  `Handler` and `Processor` describe the solution, not the business. If no better
  name exists, the concept is not yet understood well enough to implement.

## Terms

| Term | Meaning | Not to be confused with |
| ---- | ------- | ----------------------- |
| **Origin** | An external system permitted to send us webhooks, together with the identity of the secret its signatures are checked against. GitHub is the first. | *Provider* — not used; pick Origin. |
| **Delivery** | One webhook as it arrived from an Origin: raw body bytes, headers, arrival time. Unverified by definition. | *Event* — a Delivery is a transport fact, an Event is a business fact. |
| **Body** | A Delivery's payload exactly as it arrived, as raw bytes. Never a `String`: a signature covers the bytes that were sent, so re-encoding destroys the evidence. | *Event* — the Body is bytes, the Event is meaning. |
| **Proof** | What a sender presents to show a Delivery is genuine, as raw bytes, independent of mechanism. The domain compares proofs; adapters produce them. | The *secret* — a Proof is presented, the value that produced or equals it is not. And a *signature*, which is one kind of Proof: a signature covers the Body, so replaying it with different content fails; a bearer token covers nothing, so it does not. |
| **DeliveryId** | A Delivery's identity, minted at the inbound boundary. What a log line, and one day a replay, refers to. | A sender's own event id — that is theirs, this is ours. |
| **VerifiedDelivery** | A Delivery whose signature has been checked and matched. Only constructible by a successful verification, never by a caller. | *Delivery* — the type distinction is the security boundary. |
| **Event** | What happened, stated independently of any Origin's payload format: `PushedCommits`, `DeletedBranch`, `Alert`. Every Event offers the Labels it can be routed by. | *Delivery*, and any Origin's own event name. |
| **PushedCommits** | An Event saying commits were pushed to a branch. The list may be empty, which means a push that changed nothing — a force-push to the commit that was already there. Carries a Permalink when the Origin published one. | **DeletedBranch** — an empty commit list is not a deletion. Only the sender's own flag tells them apart, and an inbound adapter is the only thing that sees it. |
| **DeletedBranch** | An Event saying a branch no longer exists. Carries no commits, and the type has no field for any: deleting a branch pushes nothing. | **PushedCommits** with an empty list — a reader needs a different sentence for each, which is why these are two variants and not one with a flag. |
| **Commit** | One commit, reduced to what a Destination needs to show: an identity and a one-line summary. | The full git object — the domain keeps no tree, no diff, no parents. |
| **Pusher** | Whoever pushed, as a name to show a reader. | *Origin* — an Origin is the system that told us, a Pusher is the person who acted. |
| **Summary** | One line describing what happened: a commit's first non-blank line, or an alert's. Always the first non-blank line, because a Destination shows one line. | The full commit message or alert body — everything after the first line is deliberately discarded at the boundary. |
| **Alert** | An Event reporting that a monitoring system noticed something: an identity, a Severity, an alert status, a Summary, the Labels the sender attached, when it started, and optionally a Permalink. | *Event* — an Alert is one kind of Event, not a parallel concept; there is one fan-out and one dispatch port for both. And not a *Delivery*: an alert can arrive twice in two Deliveries. |
| **Alert identity** | The sender's own name for an alert — a fingerprint, a rule identity. Opaque; the domain never parses or shortens one. | **DeliveryId**, which is *ours* and names one arrival. A loss report cites the DeliveryId; a human chasing the alert in the monitoring system cites this. Confusing them makes a loss report point at the wrong thing. |
| **Severity** | How urgent an alert says it is: critical, warning, info, or one of two honest absences — unstated when the sender said nothing, unrecognised when the sender said something we do not know, kept as written. | A *priority* we assign. Severity is the sender's claim. Unstated and unrecognised have no urgency rank at all: a low one would hide a critical alert behind a typo, a high one would promote noise. |
| **Alert status** | Firing or resolved, and nothing else. A resolution is reported by the sender, never inferred by us. | A *state machine* we run. A firing alert and a resolved one with the same identity are two facts, and neither is derivable from the other. |
| **Permalink** | Where a reader can go to see what happened, exactly as the Origin published it. Opaque: the domain never builds one, and never parses a scheme or a path out of one. | An *endpoint* — a Permalink is a reference to the subject of a fact, not the address of a system we talk to. A Destination still has no address, and `purity` forbids transport vocabulary in the domain. |
| **Destination** | An internal system that should be told about Events: an Element room, Forgejo, GitLab. | *Origin* — Origins send to us, Destinations receive from us. |
| **DestinationKind** | What shape an Event takes for a Destination: prose for people (a Notice) or structure for a machine. Decides which adapter handles it. | The product at the other end — a chat room is a chat room whichever vendor serves it. |
| **Label** | A name and a value saying what a fact is about, under which an Event can be routed. One value per name. Both halves are attacker-influenced text, and both are checked for presence and nothing else. | A *header* or any other transport metadata — a label describes the fact, never how it arrived. And not a sender's own label conventions: ours carries no matcher grammar. |
| **Reserved label** | A label name only the domain may set: `origin` so far, taken from the verified Delivery. A sender-supplied label using a reserved name is dropped before any matching. A *rule* may freely require one — that is the point of reserving it. | A forbidden name. Reserving `origin` is what makes a Subscription saying `origin=alertmanager` worth trusting, because a workload that can write its own annotations cannot claim to be another Origin. |
| **Filter** | The rule inside a Subscription that decides whether a Destination cares about a given Event: `Everything`, or `Labelled` with the labels a fact must carry. Values are compared for equality only — no negation, no regular expressions. | *Subscription* — the Subscription binds, the Filter selects. A `Labelled` filter requires *containment*, so a fact may carry labels no rule mentions. |
| **Subscription** | A rule binding a set of Events to one Destination, with the filter that decides whether a given Event matches. | *Destination* — one Destination may have several Subscriptions. |
| **Timestamp** | A moment, as milliseconds since the Unix epoch. Always an argument, never read from the clock inside the core. | The clock itself — that is a port. |
| **Dispatch** | One attempt to deliver one Event to one Destination. Succeeds or fails on its own; a sibling's failure never affects it. | *Delivery* — opposite direction. Dispatch goes out, Delivery comes in. |
| **Notice** | An Event rendered for a human-readable Destination such as a chat room. | *Event* — the Event is structured, the Notice is prose. |

Deliberately absent: *Message*, *Payload*, *Hook*, *Handler*, *Processor*. The
first three are ambiguous about direction, and the last two name mechanisms.

Also absent, and enforced rather than merely agreed: *URL*, *endpoint*, *header*,
*bearer*, *token* and *status code*. How a system is reached belongs to the
adapter that reaches it, and `crates/architecture/tests/purity.rs` fails the
build if one of those words appears in domain code. A fact may still carry a
Permalink, because a reference to what happened is part of the fact rather than
part of the mechanism — see bead gc-3pa.13 for why that line falls there. A Label
is on the same side of that line for the same reason: it says what the fact is
about, never how it arrived (`gc-ast.1`).

Routing deliberately no longer asks an Event for a typed field. It asks every
Event for its Labels, because a sender with no repository — an alert has a
namespace and a severity — could not answer the old question at all. For a push
the Labels are *projected* from the typed fields rather than stored, so they
cannot disagree with the fields they came from.

## Bounded contexts

One context for now. A webhook relay this size does not have two languages in it,
and splitting it early would buy ceremony instead of clarity. What it does have is
an anti-corruption layer at every edge: each Origin adapter translates a foreign
payload into an `Event`, and each Destination adapter translates an `Event` into
whatever that system accepts. No foreign vocabulary crosses into the core.

| Context | Owns | Talks to |
| ------- | ---- | -------- |
| Relay | Origin, Delivery, VerifiedDelivery, Event, Subscription, Destination, Dispatch, Notice | GitHub (inbound), Element / Forgejo / GitLab (outbound) |

Revisit this the moment a second language appears — for example if scheduling or
retention grows rules of its own.
