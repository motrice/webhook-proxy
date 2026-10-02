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
| **Signature** | A signature over a Body, as raw bytes, independent of algorithm or encoding. The domain compares signatures; adapters compute them. | The *secret* — a Signature is public, the key that produced it is not. |
| **DeliveryId** | A Delivery's identity, minted at the inbound boundary. What a log line, and one day a replay, refers to. | A sender's own event id — that is theirs, this is ours. |
| **VerifiedDelivery** | A Delivery whose signature has been checked and matched. Only constructible by a successful verification, never by a caller. | *Delivery* — the type distinction is the security boundary. |
| **Event** | What happened, stated independently of any Origin's payload format. `PushedCommits` is the first. | *Delivery*, and any Origin's own event name. |
| **Commit** | One commit, reduced to what a Destination needs to show: an identity and a one-line summary. | The full git object — the domain keeps no tree, no diff, no parents. |
| **Pusher** | Whoever pushed, as a name to show a reader. | *Origin* — an Origin is the system that told us, a Pusher is the person who acted. |
| **Summary** | A commit's first non-blank line. | The commit message — the body is deliberately discarded at the boundary. |
| **Destination** | An internal system that should be told about Events: an Element room, Forgejo, GitLab. | *Origin* — Origins send to us, Destinations receive from us. |
| **DestinationKind** | What shape an Event takes for a Destination: prose for people (a Notice) or structure for a machine. Decides which adapter handles it. | The product at the other end — a chat room is a chat room whichever vendor serves it. |
| **Filter** | The rule inside a Subscription that decides whether a Destination cares about a given Event. | *Subscription* — the Subscription binds, the Filter selects. |
| **Subscription** | A rule binding a set of Events to one Destination, with the filter that decides whether a given Event matches. | *Destination* — one Destination may have several Subscriptions. |
| **Dispatch** | One attempt to deliver one Event to one Destination. Succeeds or fails on its own; a sibling's failure never affects it. | *Delivery* — opposite direction. Dispatch goes out, Delivery comes in. |
| **Notice** | An Event rendered for a human-readable Destination such as a chat room. | *Event* — the Event is structured, the Notice is prose. |

Deliberately absent: *Message*, *Payload*, *Hook*, *Handler*, *Processor*. The
first three are ambiguous about direction, and the last two name mechanisms.

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
