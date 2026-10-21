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

**A webhook is acknowledged once it is verified and stored, then delivered to
each matching destination and retried on a bounded number of attempts; a
dispatch that exhausts them is abandoned — and every abandoned dispatch is
logged and counted.**

That is at-least-once until the attempts run out, stated plainly, and the rest
follows from it:

- **A `202` means stored, not delivered.** The sender gets it once verification
  succeeds *and* the delivery is written down. That is what makes the retry a
  promise rather than a hope.
- **When it cannot be stored, the sender is refused.** A `503` with
  `Retry-After`, and nothing is sent. Accepting into memory instead would make a
  `202` mean two different things depending on state the sender cannot see, and
  a promise that is conditional on something invisible is not a promise.
  Senders differ in what that costs them: Alertmanager retries, and **GitHub
  does not auto-retry at all**, so a store outage needs somebody to redeliver
  from the repository's settings.
- **Acknowledgement means accepted, not delivered.** The sender gets a 2xx once
  verification succeeds. A destination failing afterwards must not turn into
  a 5xx, because the sender would retry and re-deliver to the destinations that
  already succeeded.
- **Each room's traffic is counted separately.** Two numbers per room —
  `delivered` and `abandoned`, the latter also by reason — because the question
  anybody asks is *which* room, and a single total says a thousand messages went
  somewhere.
  `delivered` is what a reader in that room actually saw — **messages, not
  alerts**: a sender that groups twenty alerts into one notification produces
  one message per room, so this counts what landed in the room rather than how
  many facts it carried. `abandoned` is a loss.
  The arithmetic that is right is `delivered + abandoned` = what a team has
  reported finishing; anything else is still waiting, and what is waiting is
  counted per team rather than per room — this service does not know a team's
  rooms until that team tells it.
  Nothing here can hold an address or a secret: a destination is a name, and
  where it lives belongs to the adapter that reaches it.

  They are scraped from `/metrics` on the pod's own port, in Prometheus's text
  format, as `webhook_proxy_room_delivered_total{tenant,room}` and
  `webhook_proxy_room_abandoned_total{tenant,room,reason}` — **counted from each
  team's own reports and not from anything this service observed**, because the
  agent that reaches a room runs in that team's namespace with no scrape
  endpoint of its own by design (beads `gc-72e`, `gc-556`). The honest
  consequences: a loss an agent never manages to report is not counted (its
  delivery is offered again, so the work survives and that attempt's record does
  not), and the numbers are as current as the last report. Attempts within a
  budget are counted nowhere central; they are in that agent's log.
  Like `/health`, it is **not published through the ingress**: both answer a
  machine that reaches the pod directly, and publishing either would say more
  about an internal service than anyone outside should be able to ask. A scrape
  reads a count and never the store, so polling it cannot become load on the
  thing it is monitoring.
- **Losses are visible, and a retry is not a loss.** A dispatch that failed and
  is due to be tried again is logged as that; only an abandoned one is counted
  as lost. Counting both would make the number rise for messages that then
  arrive, which is a number nobody can act on. An abandoned dispatch is logged
  with the delivery's identity, the destination's identity and the reason, and
  counted. A
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

Durability and replay are built — a PostgreSQL store a Delivery waits in until
its team's agent collects it, a retention sweep, and a `replay` subcommand that
offers a stored delivery to its team again, marked so the room shows
`(replayed)`.

**This service no longer delivers to a room itself** (`gc-72e.3.2`). It
verifies, stores, and offers; a thin agent in each team's own namespace holds
that team's rooms and rules and does the delivering. The shape above is what
made *that* cheap too: what left was a port and its two adapters, the domain
needed one type deleting and nothing changing, and the retry *policy* moved to
the agent unchanged while the loop that drove it did not — which is the clearest
evidence this workspace has produced that the seams were drawn in the right
places. Which store is used is still a choice at the composition root, in memory
unless a deployment names a database.

The manifests name one (`gc-vfz`), and the proxy refuses to start if the
secret holding its connection string is missing — so a deployment built from
them is durable or it is not running, with no third state a sender cannot see.
What that costs is deliberate and worth saying plainly: a database this proxy
cannot reach makes it refuse with `503` rather than accept what it cannot
promise to keep, so an outage of the store refuses traffic the memory outbox
would have taken and probably delivered. Durability is being bought with
availability, knowingly.

Deduplicating repeats is the one piece still unscheduled, and deliberately: it
waits on a duplicate rate nobody has measured.

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

**Everything above stops at the chat server's door.** This proxy verifies the
sender and routes by policy; past that door the room's own configuration
governs, and it is not ours to set. A hookshot generic webhook can run a
JavaScript transformation function over what it receives before the room sees
it — documented by hookshot, and offered as a checkbox to whoever adds the
webhook, so it is a choice made in the room rather than here. The webhook this
proxy posts to must be created with that off, which is a requirement on whoever
creates it and not something this proxy can check. The web application firewall
named above can also refuse a Notice for its contents, with a policy nobody
tells us about, so what a room displays is not even guaranteed to be what we
sent.

So the guarantees in this section describe what leaves this proxy, not what
appears in a room. That is a boundary rather than a weakness, and naming it is
what makes the guarantees on this side mean something: whoever can configure a
room's webhook is already inside the trust boundary of everything that room
displays, and no amount of escaping here protects a room from its own
configuration.

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
| `WEBHOOK_PROXY_LISTEN` | no | default `127.0.0.1:8080`; `0.0.0.0:8080` in a container. The senders' webhook and the tenant hand-off |
| `WEBHOOK_PROXY_OPERATOR_LISTEN` | no | default `127.0.0.1:9090`; `0.0.0.0:9090` in a container. `/metrics`, `/health`, `/ready` and `/api-info`, which must not be on a port every tenant may reach (bead `gc-wdt`) |
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

### The hand-off to a tenant's agent

A second interface, and deliberately not part of the one above:
[docs/tenant-agent-api.md](docs/tenant-agent-api.md). Two operations — claim a
Delivery whole, report its rooms terminally — called by an agent in a tenant's
own namespace, authenticated by the caller's mTLS identity rather than by a
sender's credential. The tenant is the namespace in that identity and is never
a parameter: a parameter would be a claim, and the identity is a fact.

`docs/openapi.yaml` does not describe these two paths, and
`crates/app/tests/openapi.rs` excludes them **by name with a reason each** —
never by a pattern, because a pattern would absorb the next internal path
somebody added without anyone deciding to. The same test checks that the mesh
policy protecting them names every one.

### Checking a routing file before deploying it

```bash
webhook-proxy check          # reads WEBHOOK_PROXY_CONFIG and _SECRETS_DIR
```

It performs exactly the read the process does at start-up, then prints what the
file would actually route:

```text
tenants  (* marks one no sender files alerts for)
  devsecops
  platform

senders
  /webhook/alertmanager-devsecops  presents a shared value, speaks alertmanager, for tenant devsecops
  /webhook/alertmanager-platform  presents a shared value, speaks alertmanager, for tenant platform
  /webhook/github  signs its body, speaks github, for tenant devsecops
  /webhook/grafana  presents a shared value, speaks grafana, for tenant platform

rooms  (* marks a label only a sender can supply)
  audit-room
    - everything
  devsecops-room
    - branch=main origin=github repository=motrice/webhook-proxy
    - origin=alertmanager-devsecops severity=critical
  platform-room
    - namespace*=platform origin=alertmanager-platform
    - grafana_folder*=Platform origin=grafana

2 tenant(s), 4 sender(s), 3 room(s), 5 rule(s), 7 secret(s) present
```

Two Alertmanager senders for one Alertmanager, because **one Origin serves one
tenant** (bead `gc-nkb`). A shared Alertmanager labels each alert with the
namespace it came from, so the tempting arrangement is one `alertmanager` Origin
with the tenant read off that label — and that is refused: a label comes from a
workload annotation, written by whoever can deploy, so a label as the tenant
would let a deployer file their alert under somebody else's. A label is routing
*input*; it is never an authorisation boundary. The cost is a receiver and a
credential per tenant in Alertmanager's own configuration, and the compensation
is that tenant selection happens in Alertmanager's routing rather than in this
proxy's authorisation boundary.

An Origin naming a tenant that `tenants:` does not list is a **startup error**,
not a request-time refusal, so request handling never meets an unknown tenant.
Tenants are listed rather than created by being mentioned, because inferring
them would make a one-letter typo produce a tenant nobody has an agent for —
with every step from verification to storage reporting success.

A past delivery can be sent again, by identity:

```sh
webhook-proxy replay <delivery-id>
```

**It offers the delivery to its team again rather than sending it itself**, and
the distinction is worth knowing before reading the output. Routing left this
service (bead `gc-g9x`), so there is no stored dispatch to re-send and no room
this process can reach — what it has is the delivery, which survives its report
for a month, and a team whose agent will deliver it by the rules in force now.
That is usually the point, because a replay happens after somebody changed
something.

It asks for no team name: whoever runs this has a delivery identity out of a
log line, and making them look up its team first would mean looking it up from
the thing they are already holding.

A replayed message still says `(replayed)` in the room — the flag travels with
the delivery and the team's agent writes it. A retry does not: nobody has seen
a retry, so it is a first arrival that happens to be late, and marking it would
put noise in the channel people rely on for alerts.

If nothing goes by that identity you are told so plainly, and it means one of
two things that cannot be told apart from here: it was never accepted, or
retention has already deleted it — one month from acceptance.

Only a person can start one. Nothing on the request path can.

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

**All three workflows pin the same commit**, and `crates/app/tests/release.rs`
asserts it. A release checked by one version of the policy layer and published
by another is two definitions of green, and the difference would surface as a
release that passed every gate and shipped something the gates would now
reject. Updating the pin belongs in one commit.

### Publishing

| Workflow | Fires on | Publishes |
| -------- | -------- | --------- |
| `dev-image.yml` | every commit to `main` | `ghcr.io/motrice/webhook-proxy:<version>-dev-main-<sha>` |
| `release.yml` | a `v*` tag | the released image, with SLSA provenance, SBOMs and a GitHub release |

One container and no binary (`gc-kow`): the only deployment target is a
cluster, and an artefact with no audience still has to be signed, SBOM'd and
patched. Both workflows build the same `runtime` stage of `deploy/Containerfile`
for `linux/amd64` and `linux/arm64`, and `release.rs` asserts that too — two
workflows building different stages would mean what is deployed from `main` is
not what is released from a tag.

**There is no floating `:main` tag.** `publish-dev-container.yml` has no
tag-override input, so every dev image carries a commit sha. That is why
`deploy/webhook-proxy/deployment.yaml` names a `REPLACE` image rather than a tag
that exists — bead `gc-6a1` records the decision, and the deploy README says
what to put there.

### Secrets a release needs

Repository secrets, settable only by someone with admin on the repository.
Every one is optional upstream, so a missing secret is a release that fails at
the step needing it rather than at the call — which is worse than failing early,
and is why they are listed here.

| Secret | For | Without it |
| ------ | --- | ---------- |
| `RELEASE_TOKEN` | creating the GitHub release and pushing the version-bump commit | the release cannot be created; `GITHUB_TOKEN` cannot push to a protected branch |
| `RELEASE_GPG_PRIVATE_KEY` | signing the release artefacts and the tag | artefacts publish unsigned |
| `RELEASE_GPG_PASSPHRASE` | unlocking that key | signing fails |
| `RELEASE_GPG_PUBLIC_KEY` | verifying the signed tag | verification is skipped |

The image itself needs no secret: `GITHUB_TOKEN` authenticates to `ghcr.io`.
**Pulling it does**, while this repository is private — the GHCR package matches
the repository's visibility, so a cluster needs the `ghcr-pull` secret
`deploy/webhook-proxy/README.md` describes. That goes away when the repository
goes public (`gc-rdz`).

`CODE_SCANNING_TOKEN` is an organisation secret and is not mapped here: without
it the Trivy scan still runs and its findings do not reach Code Scanning.

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
