# webhook-proxy

A Rust product, built by agents, under a workflow where the evidence is
mechanical rather than social: you merge because the checks passed, not because
the diff looked plausible.

The product itself is not here yet. What is here is the way of working.

## The idea in one paragraph

Agents are good at producing plausible code and bad at knowing when they are
wrong. So every judgement a reviewer would otherwise have to make by reading is
turned into something a machine decides: the architecture is a test, "done" is
one command, and the work queue is a dependency graph rather than a conversation.
What is left for the human is the only thing a human is actually better at —
deciding whether this was the right thing to build.

## What it promises

**A webhook is acknowledged once its signature is verified, then delivered to
each matching destination on a bounded number of attempts; nothing is persisted,
so a dispatch that exhausts its attempts or outlives the process is lost — and
every loss is logged and counted.**

That is best-effort, stated plainly, and the rest follows from it:

- **Acknowledgement means accepted, not delivered.** The sender gets a 2xx once
  the signature checks out. A destination failing afterwards must not turn into
  a 5xx, because the sender would retry and re-deliver to the destinations that
  already succeeded.
- **Losses are visible.** A dropped dispatch is logged with the delivery's
  identity, the destination's identity and the reason, and counted. A
  best-effort system whose losses are invisible is indistinguishable from a
  broken one; the log is what makes "best-effort" an engineering decision rather
  than an excuse.
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
  a signature check. `Delivery::verify` is the only route to a
  `VerifiedDelivery`, and translation is a port precisely so that nothing is
  parsed before its signature matched.
- **Unknown senders are refused, and failure is closed.** An Origin we hold no
  secret for is `SecretUnavailable` — never "allow it through". A body larger
  than the configured limit is rejected before any work is done on it.
- **Content reaching a room is attacker-influenced even when the request is
  genuine.** Commit messages, branch names and repository names are written by
  whoever can push, not by the sender we authenticated. A Notice therefore
  renders them as text, never as markup, or the room becomes an injection
  target for anyone with commit access.

The hookshot URL is still handled as a secret — injected from the environment or
a k3s Secret, never defaulted in code, never logged, never in a test fixture —
because the network perimeter is one line of defence and leaking the URL would
let anything already inside it post freely.

Rotation and expiry live on the hookshot instance and are not ours to set.
Accepted deliberately: the rooms in scope carry notifications, so the worst case
is nuisance or a convincing fake message, and whoever runs that instance owns the
fix if it ever becomes a problem.

## Layout

```text
crates/domain          pure rules. zero dependencies, enforced.
crates/application     use cases and ports (traits).
crates/adapters/*      implementations of ports. none yet.
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
| `GITHUB_WEBHOOK_SECRET` | yes | the shared secret configured on the GitHub webhook |
| `ELEMENT_WEBHOOK_URL` | yes | the hookshot webhook URL. A bearer credential — never commit it |
| `ELEMENT_ROOM` | yes | the Destination identity, used in routing and in logs |
| `WEBHOOK_PROXY_LISTEN` | no | default `127.0.0.1:8080`; `0.0.0.0:8080` in a container |
| `WEBHOOK_PROXY_MAX_BODY` | no | default 1 MiB, refused before anything is verified or parsed |
| `WEBHOOK_PROXY_TIMEOUT_MS` | no | default 5000, bounding each dispatch |

Three of those are on their way out. Many senders, many rooms and overlapping
routing rules do not fit in environment variables, and the point of a file is
that a human reviews the routing as a diff. `deploy/config.example.yaml` is the
shape that replaces them — `GITHUB_WEBHOOK_SECRET`, `ELEMENT_WEBHOOK_URL` and
`ELEMENT_ROOM` become entries in it, with secret *names* in the file and values
read from a mounted directory. The variables above still describe what runs
today; bead `gc-ast.11` is what makes the file real.

To run it against a real repository: start it with the three required variables
set, expose the port to the internet however you normally would (`ssh -R`, a
tunnel, or an Ingress), then add a webhook to the repository pointing at
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
