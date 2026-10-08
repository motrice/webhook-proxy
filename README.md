# webhook-proxy

A relay that lets external senders reach an internal chat room, and the
authentication boundary in front of them.

It takes webhooks from several kinds of sender — a monitoring system's alerts, a
forge's pushes — verifies each against the mechanism that sender declared,
translates the payload into a fact of its own, routes that fact to whichever
rooms asked for it, and renders it as something a person can act on. Who may
send, and who hears what, is a file reviewed as a diff rather than a list of
environment variables.

Built by agents, under a workflow where the evidence is mechanical rather than
social: you merge because the checks passed, not because the diff looked
plausible.

## The idea in one paragraph

Agents are good at producing plausible code and bad at knowing when they are
wrong. So every judgement a reviewer would otherwise have to make by reading is
turned into something a machine decides: the architecture is a test, "done" is
one command, and the work queue is a dependency graph rather than a conversation.
What is left for the human is the only thing a human is actually better at —
deciding whether this was the right thing to build.

## What it promises

**A webhook is acknowledged once it is verified, then delivered to
each matching destination on a bounded number of attempts; nothing is persisted,
so a dispatch that exhausts its attempts or outlives the process is lost — and
every loss is logged and counted.**

That is best-effort, stated plainly, and the rest follows from it:

- **Acknowledgement means accepted, not delivered.** The sender gets a 2xx once
  verification succeeds. A destination failing afterwards must not turn into
  a 5xx, because the sender would retry and re-deliver to the destinations that
  already succeeded.
- **Losses are visible.** A dropped dispatch is logged with the delivery's
  identity, the destination's identity and the reason, and counted. A
  best-effort system whose losses are invisible is indistinguishable from a
  broken one; the log is what makes "best-effort" an engineering decision rather
  than an excuse. Which is why a success *status* is not taken as proof of
  delivery: there is a web application firewall in front of the destination and
  it refuses with `200 OK` and an HTML page, so a dispatch counts as delivered
  only when the destination itself says so, in the words it actually uses.
- **Duplicates are possible.** Inside the attempt budget a destination can see
  the same notice twice, when it accepted a request whose response was lost. For
  a chat room that is a cosmetic duplicate rather than corruption, but nothing
  downstream should assume exactly-once.
- **Order is not promised.** Destinations are dispatched to independently, so
  two events can reach one destination out of order.

Durability and replay are wanted eventually, and the shape here is chosen so
they can be added without reshaping the domain — see the `Durable delivery`
epic in `bd ready`. They are deliberately unscheduled until the loss counters
above say how much is actually being dropped.

## The security boundary

**This proxy is the authentication boundary, not a convenience.** The destination
it relays into — a hookshot generic webhook — supports no inbound
authentication at all: no token, no signature, no header check, no IP allowlist.
Possession of the URL is the only credential it has. That endpoint is gated by
internal network rules rather than by the open internet, which is what makes the
arrangement workable: this proxy is what lets an external sender reach an
internal alert channel, and it is therefore the thing that decides whether a
request is genuine.

Three obligations follow, and they are not negotiable:

- **Verification happens before anything else, and nothing can switch it off.**
  There is no configuration flag, environment variable, or debug mode that skips
  verification. `Delivery::verify` is the only route to a `VerifiedDelivery`, and
  translation is a port precisely so that nothing is parsed before it was
  verified. An Origin declares *which* mechanism proves it — a Proof computed over
  the body, or a value shared in advance — and that is read from configuration,
  never chosen by looking at the request.
- **Unknown senders are refused, and failure is closed.** An Origin we hold no
  secret for is `SecretUnavailable` — never "allow it through". A body larger
  than the configured limit is rejected before any work is done on it.
- **Content reaching a room is attacker-influenced even when the request is
  genuine.** Commit messages, branch names and repository names are written by
  whoever can push; an alert's summary and labels come from a workload
  annotation, so from whoever can deploy — a wider set of people still. A Notice
  therefore escapes everything it borrows, and neutralises line breaks in a label
  so a value cannot forge a line that looks like a separate message. Without
  that, the room is an injection target for anyone with commit or deploy access.
- **A link may appear only when its visible text is exactly its destination.**
  The defence used to be sending no markup at all, which was conditional on the
  destination not adding any — and that condition turned out to be false: the
  chat server renders markdown, so a commit message could put a link saying one
  thing and going to another into a room that trusts the forge. A Notice is now
  sent as both plain text and HTML, and the HTML says what is a link. The
  permalink qualifies because its text is its address; nothing a sender wrote
  ever does.

A room's URL is still handled as a secret — named in the routing file, its value
read from a mounted directory, never defaulted in code, never logged, never in a
test fixture — because the network perimeter is one line of defence and leaking
the URL would let anything already inside it post freely. The routing file is
reviewable precisely because it holds names and no values.

Rotation and expiry live on the hookshot instance and are not ours to set.
Accepted deliberately: the rooms in scope carry notifications, so the worst case
is nuisance or a convincing fake message, and whoever runs that instance owns the
fix if it ever becomes a problem.

## Layout

```text
crates/domain          pure rules. zero dependencies, enforced.
crates/application     use cases and ports (traits).
crates/adapters/*      implementations of ports:
  inbound-http           the front door. every sender arrives here.
  github-signatures      verifies a sender that signs its body.
  shared-values          verifies a sender that presents a shared value.
  github-payload         a forge push becomes Events.
  alertmanager-payload   a monitoring notification becomes Alerts.
  grafana-payload        a different monitoring notification. not the same.
  element-notices        an Event becomes prose in a chat room.
  yaml-config            the routing file becomes Origins and Subscriptions.
  system                 the clock and identity generation.
crates/app             composition root. wiring only.
crates/architecture    the dependency-direction test.

CLAUDE.md              the contract agents work under.
GLOSSARY.md            ubiquitous language. a constraint, not a document.
justfile               every command. `just verify` is the definition of done.
.claude/skills/        how to do the four recurring kinds of work.
.beads/                the work ledger (Dolt-backed).
```

## Running it

Configuration is entirely environment variables. Secrets have no defaults and no
fallbacks: a deployment missing one fails to start rather than running in a state
where it cannot authenticate what it receives.

| Variable | Required | Meaning |
| -------- | -------- | ------- |
| `WEBHOOK_PROXY_CONFIG` | no | default `/etc/webhook-proxy/config.yaml`; the routing file |
| `WEBHOOK_PROXY_SECRETS_DIR` | no | default `/etc/webhook-proxy/secrets`; one file per named secret |
| `WEBHOOK_PROXY_LISTEN` | no | default `127.0.0.1:8080`; `0.0.0.0:8080` in a container |
| `WEBHOOK_PROXY_MAX_BODY` | no | default 1 MiB, refused before anything is verified or parsed |
| `WEBHOOK_PROXY_TIMEOUT_MS` | no | default 5000, bounding each dispatch |

None of those is a secret, and none of them is policy. Who may send and who
hears what live in `WEBHOOK_PROXY_CONFIG` — see `deploy/webhook-proxy/config.example.yaml` —
because a human reviews routing as a diff rather than as a list of variables.
Secrets are named in that file and read by name from `WEBHOOK_PROXY_SECRETS_DIR`,
so no secret value appears in the file or in the environment.

A deployment whose routing file is absent, unparseable, or names a secret with no
value behind it exits non-zero before the socket is bound, naming the file and
the path to the field. A broken deployment never looks healthy.

### Configuring a sender

Whoever configures a sender — usually in another repository — needs
[docs/sending-to-this-proxy.md](docs/sending-to-this-proxy.md): the URL per
sender, which header carries which credential, the fields each payload must
carry and what happens when one is missing, the response codes and what to do
about each, and what is lost. It has copyable Alertmanager and Grafana blocks
with the credential referenced rather than inlined.

Every claim in it names the test that holds it, so a disagreement between the
document and the code is findable rather than a matter of opinion. It is also
the input to the OpenAPI specification in `gc-4oo.3` — that bead describes this
same interface formally rather than describing it a second time.

### Checking a routing file before deploying it

```bash
webhook-proxy check          # reads WEBHOOK_PROXY_CONFIG and _SECRETS_DIR
```

It performs exactly the read the process does at start-up, then prints what the
file would actually route:

```text
senders
  /webhook/alertmanager  presents a shared value, speaks alertmanager
  /webhook/github  signs its body, speaks github

rooms  (* marks a label only a sender can supply)
  audit-room
    - everything
  devsecops-room
    - branch=main origin=github repository=motrice/webhook-proxy
    - origin=alertmanager severity=critical
  platform-room
    - namespace*=platform origin=alertmanager

2 sender(s), 3 room(s), 4 rule(s), 5 secret(s) present
```

**The operations repository's pipeline should run this on every change to the
file**, and a reviewer should read its output on the pull request. It opens no
socket and reaches no network, so it is safe in a pipeline with no cluster
access, and it prints no secret value — only how many were found.

It exists because the most expensive mistake this file can carry cannot be
rejected. A rule may name any label, and must: an alert carries whatever the
sender attached, so `namespace` cannot be validated against anything. A mistyped
`repositry` is therefore a perfectly valid file describing a room that will never
hear anything. The table shows that as `repositry*=…` and as
`(nothing selects this room)` — obvious to a person, impossible as a rule.

To run it against a real repository: write a routing file and a secrets
directory as `deploy/webhook-proxy/config.example.yaml` shows, start it pointing at them,
expose the port to the internet however you normally would (`ssh -R`, a tunnel,
or an Ingress), then add a webhook to the repository pointing at
`https://<host>/webhook/github` with content type `application/json`, the same
secret, and just the push event. Push something. The room should say who pushed
what where; if it does not, `GET /health` tells you the process is alive and the
logs name any delivery that was dropped and why.

`GET /health` answers `ok` from the process alone, and deliberately does not
check the destination: a probe that failed when a chat server hiccupped would
restart a healthy proxy.

## Working on it

```bash
just ready          # what is workable now
just start gc-xxx   # claim a bead, get a worktree and a branch
just quick          # inner loop: boundaries + tests
just check          # correctness only
just verify         # check + hygiene linters. green == mergeable
just pr gc-xxx      # verify, push (retrying), open the PR
just ci             # watch CI for the commit you are on
```

An agent may open a pull request. Only a human merges one.

## The three mechanisms

**1. The architecture is executable.** `crates/architecture` reads the workspace
dependency graph and fails the build if an arrow points outward — if `domain`
grows a dependency, if an adapter depends on another adapter, if `application`
reaches for a crate outside its allowlist. Widening a boundary means editing that
test, which turns an architectural drift into a visible, reviewable act.

**2. Acceptance criteria are tests.** A bead's criteria name the tests that must
exist and pass. Grooming therefore hands the agent its red-green list, and review
becomes: do these tests exist, and do they assert what the criterion says.

**3. One definition of green.** `just verify` is `check` — formatting, the
boundary test, clippy with pedantic denied, the suite, unused dependencies —
plus `lint-all`, the devbase hygiene linters. CI runs the same two halves as two
jobs because they need different toolchains, so "works on my machine" has
nowhere to hide while neither job has to install the other's tools.

## CI

| Where | Runs | Why |
| ----- | ---- | --- |
| Forgejo (local) | `just check` | seconds, on every push, including bead branches |
| GitHub | `just check` + `diggsweden/reusable-ci` | correctness plus the policy layer: commit health, REUSE, SAST, dependency review, markdown/YAML/shell hygiene |

`reusable-ci` is pinned to a tag's full commit SHA (v3.0.0), never a moving ref.
It has no cargo build workflow, so it checks everything about a change except
whether the code works — which is what our own gate job is for.

## Prerequisites

```bash
brew install just gh mise   # mise pins the hygiene linters
cargo install cargo-machete # required by `just check`
just install                # fetch the pinned linters and devbase-check
```

`bd` (beads) and the Rust toolchain in `rust-toolchain.toml` do the rest.

One environment caveat worth knowing: on this machine `~/.local/bin/jq`,
`kubectl` and friends are wrappers that run inside the `k3s-toolbox` container
(`docker exec -i k3s-toolbox ...`). They read stdin fine but cannot see host
file paths, so pipe into them rather than passing a filename.

## Open decisions

`bd ready` is the real list. The ones worth knowing about up front:

- **`main` is not yet protected**, so the human-merges rule is currently only a
  sentence in `CLAUDE.md` (`gc-rdz`).
- **The hookshot endpoint has no authentication**, so possession of the URL is
  the only credential it has (`gc-fks`).
