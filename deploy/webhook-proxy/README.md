# Running the proxy

The manifests for the proxy itself: a Namespace, a Deployment, a Service, an
HTTPRoute and a NetworkPolicy. Bead gc-d01, with gc-hzn for the parts that only
matter on OpenShift.

They are written for this k3s development cluster and say, below, what differs on
the OpenShift platform they are headed for.

What is deliberately **not** here: the image, the ConfigMap, and the Secret. Each
is absent for its own reason, and each is the first thing someone looks for.

## The image is pulled, never built here

Bead gc-kow decided it: the release workflow publishes one container to
`ghcr.io/motrice/webhook-proxy`, and everything else consumes it. A manifest that
built its own image would be a second path to something that looks identical, and
the two diverge the first time only one of them is rebuilt.

**`deployment.yaml` names an image that does not exist**, and that is
deliberate (bead `gc-6a1`). It is shaped like what `dev-image.yml` publishes on
every commit to `main` — `<version>-dev-main-<short sha>` — and marked `REPLACE`,
because `publish-dev-container.yml` has no tag-override input and there is
therefore no floating `:main` to point at. This manifest used to name one, which
looked turnkey and was not.

Two places to get the real coordinate: the `dev image` workflow run's summary,
which prints the image and its digest, or a release tag. **Prefer the digest.**
`imagePullPolicy: Always` on a moving tag means a pod restart silently changes
version, which is the thing this paragraph used to warn about while the manifest
beside it did it. The manifest now sets `IfNotPresent`, which is correct for an
immutable reference and removes a registry round trip — and a dependency on the
registry being reachable — from every pod start.

### While the repository is private

The GHCR package matches the repository's visibility, so the pull needs a
credential. Create it once per namespace, with a classic token holding only
`read:packages`:

```sh
kubectl create secret docker-registry ghcr-pull \
  --namespace webhook-proxy \
  --docker-server=ghcr.io \
  --docker-username="$GITHUB_USER" \
  --docker-password="$GHCR_READ_PACKAGES_TOKEN"
```

Nothing about that secret is committed, the same rule `deploy/forgejo-runner`
follows for its registration token. When the repository becomes public, flip the
package to public and delete this secret along with the `imagePullSecrets` block
— bead gc-rdz carries the reminder, because a credential nobody needs is a
credential nobody audits.

## Configuration, and where the values come from

`deployment.yaml` mounts three volumes:

| Volume          | Holds                                   | Mounted at                   |
| --------------- | --------------------------------------- | ---------------------------- |
| `routing`       | the routing file, `config.yaml`         | `/etc/webhook-proxy/routing` |
| `vault-config`  | the agent's `vault-agent.hcl`           | `/vault/config`              |
| `vault-secrets` | the rendered secrets, on tmpfs          | `/vault/secrets`             |

Both ConfigMaps are **generated** by kustomize from the files in this directory,
so their names carry a hash of their contents and a routing change rolls the pods
by itself. There is no annotation to remember to bump.

The routing file is `config.example.yaml`, used directly rather than copied —
the same file `webhook-proxy check` validates and the acceptance tests read, so a
routing file that is deployed is a routing file something checks.

**There is no Secret object, and no placeholder for a secret value anywhere in
this repository.** Values live in the secret store; the `vault-agent` container
authenticates with the pod's service account and renders one file per secret into
`vault-secrets`, which is `emptyDir: { medium: Memory }` — tmpfs, so a secret
never reaches a disk.

**Every room URL is itself a credential.** Anyone holding it can post to that room
(bead gc-o61), which is why rooms are *named* in the routing file and their URLs
are not in it.

### What to replace when copying this into the GitOps repository

Everything marked `REPLACE` in `vault-agent.hcl` and `deployment.yaml`, which is:

- the secret store's address, the Kubernetes auth role, and the secret path and
  field names in all seven `template` stanzas
- the `vault-agent` container's image
- `config.example.yaml` itself, with the real routing — the example names rooms
  that do not exist
- `ghcr.io/motrice/webhook-proxy:main`, which should be pinned to a digest there;
  a moving tag cannot be rolled back to
- the namespace selectors in `networkpolicy.yaml` — the Gateway's namespace, and
  the scraper's if there is one

The role binding that lets this service account read those secrets lives in the
secret store, not here.

**This deployment needs a PostgreSQL database, and this repository does not
provide one.** `WEBHOOK_PROXY_DATABASE_SECRET` names `database-url`, and the
`database-url` stanza must resolve to a connection string for a database this
pod can reach. Bead `gc-vfz` decided that: deliveries wait in a database so a
restart does not lose what was still retrying. Two consequences to plan for
rather than discover:

- **The proxy will not start without it.** A named secret that nothing renders
  is a startup failure, not a fallback to memory. That is deliberate — a
  deployment is durable or it is not running — but it means the database has to
  exist before the proxy is rolled out, not after.
- **An unreachable database refuses traffic.** The proxy answers `503` rather
  than accepting what it cannot promise to keep, so the store's availability
  becomes the endpoint's availability. This cluster runs CloudNativePG; a
  `Cluster` of its own rather than a schema in somebody else's is the obvious
  shape, and its availability should be chosen with the above in mind.

The schema applies itself at startup, behind the advisory lock `sqlx` takes, so
two replicas cannot race it and there is no migration job to run.

Two things each `template` stanza must get right, both of which cost a working
deployment if missed, and both of which have already cost one once:

- **`perms = "0440"`.** The agent writes these files and the proxy reads them as
  a different process in the same group. Owner-only means nobody, and the symptom
  is a pod reporting a secret as *absent* for a file that is present and
  unreadable.
- **No leading whitespace in `contents`.** `yaml-config` trims a trailing newline
  from a secret value and nothing else. A byte in front of an HMAC secret produces
  `401` on every signed delivery and nothing in the log to explain it.

`crates/app/tests/manifests.rs` checks the first of those, and checks that the
files the agent renders are exactly the secrets this deployment asks for — the
secrets the routing file names, plus the database secret the environment names.
Add a room or a database and forget its stanza, and a named test fails rather
than a pod waiting for something nothing will ever write. The database is in
that set rather than checked beside it because it is the same mistake with a
worse blast radius: forget its stanza and the proxy refuses to start at all,
rather than refusing one Origin.

### Ordering

The agent is a plain container, matching the pattern this cluster's GitOps uses
for every service. It is deliberately not ordered before the proxy: the proxy
waits for its configuration to appear, bounded and polled, and says on stderr
what it is waiting for (bead gc-6b7). That works under a plain sidecar, a native
one, an injector, or a plainly mounted Secret, and leaves the choice to whoever
owns the platform.

## Who may reach the pods

`networkpolicy.yaml` allows ingress from the Gateway's namespace, and from a
metrics scraper's, on the **pod's** port. Nothing else.

On a cluster with no default-deny it changes nothing you can observe, which is
why it was missing until bead gc-hzn. On a cluster that denies ingress per
namespace — every namespace in the OpenShift estate below has a
`default-deny-ingress` — its absence is a pod that is Running, Ready, passing
both probes and unreachable, with an empty log because no request ever arrived
and a 503 from the Gateway as the only symptom.

Two things to keep right when editing it:

- **It names the pod's port, not the Service's.** The policy is evaluated after
  the Service has rewritten the destination. Here both numbers are 8080, so
  naming the wrong one would pass unnoticed until somebody made them differ.
- **Its `podSelector` has to match the Deployment's own selector.** A policy
  selecting no pod is accepted, reports nothing, and protects nothing.

`manifests.rs` checks both, and checks that every manifest in this directory is
one the kustomization applies — a policy committed and never applied fails in
exactly the way the missing policy did.

There is no `Egress` rule, deliberately. This pod reaches the secret store, the
database and every chat room it posts into, and only the first two have an
address this repository knows. An egress policy written from what is visible
here would deny the rooms, and the loss would be reported as the destination
refusing. Restricting egress means enumerating the rooms, which belongs where
the rooms are configured.

## Before applying the cutover: drain the outbox

**`0008_drop_dispatch.sql` drops a table, and it is irreversible.** Until bead
`gc-72e.3.2` this service delivered to rooms itself, from a `dispatch` table.
Anything still waiting there has been accepted from a sender and not yet
delivered, and the migration drops it with no log line and no counter.

That is free the first time, because nothing is deployed yet — `gc-lw3` has
published no image and `gc-ugm` has proved no real push. **It will not be free
the second time.** Before applying this to a deployment that has been running:

1. Stop sending to it, or accept that what arrives next is offered to a tenant
   rather than delivered here.
2. Wait for the outbox to drain — `SELECT count(*) FROM dispatch WHERE outcome =
   'waiting'` reaching zero — or decide deliberately that what is left is lost.
3. Deploy the tenant agents, or the alerts are stored and offered to nobody.
   They are counted and logged (`gc-wcw.3`), so this is visible rather than
   silent, but it is still nobody being told.

## The hand-off to a tenant's agent needs a service mesh

Two paths — `/deliveries/claim` and `/deliveries/{delivery}/report` — are a
tenant agent's, not a sender's, and `docs/tenant-agent-api.md` describes them.
What they need from a deployment is stated here because getting it wrong is
silent.

> **Do not run this workload without the mesh sidecar.** Those two paths are
> authenticated by the caller's mTLS identity, which the process reads from
> `x-forwarded-client-cert`. That header is a fact only because the sidecar sets
> it from the verified peer certificate, replacing whatever the request carried.
> With no sidecar in front, any caller that can reach the port can write the
> header itself and claim any tenant's alerts.

One thing holds without any of that, and it is why this is not a hole in the
public path: the namespace in the identity must be a tenant `config.yaml` lists.
A request arriving through the ingress gateway carries the *gateway's* identity,
whose namespace is `istio-ingress`, and `istio-ingress` is not a tenant. So even
a deployment that published these paths by mistake hands out nothing.

What to apply, and where each piece lives:

- `istio/authorizationpolicy.yaml` — **the boundary.** One principal per tenant
  agent, and `ALLOW` rather than `DENY` so a path nobody wrote a rule for is
  refused by default. Not in the kustomization below: this development cluster
  runs Cilium's Gateway API with no mesh, so the API server does not know the
  kind and `kubectl apply -k` would fail on it. `crates/app/tests/openapi.rs`
  checks that it names every path the code treats as internal.
- `networkpolicy.yaml` — which namespaces may reach the pod at all. A tenant
  agent's namespace is selected by **label**, not by name, so the list of
  tenants stays in `config.yaml` alone. The alternative was a second copy, whose
  failure mode is an agent that authenticates successfully and times out.
- `config.yaml`'s `tenants:` list — which tenants exist. Adding a tenant is two
  edits: a line there, saying the platform serves it, and a principal in the
  AuthorizationPolicy, saying which workload speaks for it. Deliberately two:
  they are different facts, owned by different people.

## An HTTPRoute, not an Ingress

gc-d01's acceptance criterion said Ingress. The target cluster has no Ingress
controller and no IngressClass: it runs Cilium's Gateway API implementation, and
every other workload attaches an HTTPRoute to the single `dev-local` Gateway in
`default`. An Ingress object here would be accepted by the API server and then
route nothing at all, which is the worst kind of wrong.

Only `/webhook` is published. `/health` is for the kubelet, which reaches the pod
directly; publishing it would hand anyone a liveness oracle for an internal
service.

`webhook-proxy.dev.test` resolves only on the development machine. **Reaching
this from a forge on the internet needs a real hostname and is the maintainer's
step**, not something a manifest in this repository can provide.

## Running it on OpenShift instead

The platform these manifests are headed for is OpenShift, and four things that
are correct on k3s are wrong there. Bead gc-hzn; two are fixed here and two
cannot be, because they are facts about the cluster rather than about this
workload.

**Fixed: no uid, gid or `fsGroup` is named.** `restricted-v2` assigns a uid from
the namespace's `openshift.io/sa.scc.uid-range` and *refuses* a pod that names
its own; `fsGroup` is range-checked the same way. This manifest named 65532
three times and was right to on a cluster that lets a workload choose. What is
left is `runAsNonRoot: true` and `seccompProfile: RuntimeDefault`, which say the
only thing this workload actually needs to say about who it runs as.

`fsGroup` went for a second reason worth recording: it was added by gc-d01 so
the proxy could read a Secret the kubelet mounted root-owned, and gc-ast.13
replaced that Secret with the agent rendering into a tmpfs the pod owns. The fix
had outlived its problem. What makes the rendered files readable now is
`perms = "0440"` plus the two containers sharing a group — which is the group
the platform assigns, not one named here.

> **On a cluster that assigns no uid — plain Kubernetes, k3s, this development
> cluster — the two containers fall back to their images' own `USER`, and if
> those differ the proxy cannot read what the agent wrote.** There, set a
> pod-level `runAsUser` and `fsGroup` to one value both containers share. The
> distroless `nonroot` tag this image uses declares 65532.

**Fixed: the image reference is checked for being published, not for being on
GHCR.** Cluster pods have no general route to the internet, so the image has to
come through the platform's own mirror. `manifests.rs` asks for a registry host
and a tag or digest, which a mirrored path satisfies and a locally built
`webhook-proxy:dev` does not.

**Not fixed, and not fixable here: the Gateway and the hostname.**
`httproute.yaml` attaches to `dev-local/default` with hostname
`webhook-proxy.dev.test`. The estate runs its Gateways in `istio-ingress`, whose
listeners select namespaces by label, and hostnames are
`<product>.<namespace>.<scope>`-shaped under a wildcard certificate. A new
namespace therefore needs *platform-side* work — a listener that selects it and
a SAN on that certificate — before any route here attaches to anything. The
GitOps copy of `httproute.yaml` names the real Gateway; this one cannot.

**Not fixed: the namespace's own labels.** `namespace.yaml` carries
`app.kubernetes.io/*` only. The estate's Gateway listeners select by label and
its service mesh injects by `istio.io/rev`, so the namespace this is applied
into needs whatever labels that platform requires — which are the platform's to
state, and change without this repository hearing about it.

A platform-owned database has its own requirements that are not ours either: a
CloudNativePG `Cluster` in that estate needs
`inheritedMetadata.annotations: sidecar.istio.io/inject: "false"`, an explicit
storage class and resources set, or its backup Jobs never complete.

## Applying it

```sh
kubectl apply -k deploy/webhook-proxy
```

**Replace the image first, or the pods will not start.** The committed value is
not a real coordinate (see above), so an apply of this directory unedited gives
`ImagePullBackOff` — loudly, which is the right failure: the alternative was a
manifest that pulled a moving tag and changed version on a restart without
anybody asking. `crates/app/tests/release.rs` checks that the registry path
here is the one CI actually publishes to, so what needs replacing is the tag
and nothing else.

## Proving it locally, before any image is published

There is a chicken-and-egg problem at the very start: gc-lw3 publishes the image
and is blocked on this bead, so the first apply has nothing to pull. Side-load a
locally built image for that one proof — and only for that proof, because this is
exactly the second path the decision above rejected:

```sh
docker buildx build -f deploy/Containerfile --target runtime \
  -t ghcr.io/motrice/webhook-proxy:main --load .
docker save ghcr.io/motrice/webhook-proxy:main |
  limactl shell k3s sudo k3s ctr images import -
kubectl -n webhook-proxy patch deployment webhook-proxy \
  --type=json -p '[{"op":"replace",
    "path":"/spec/template/spec/containers/0/imagePullPolicy","value":"Never"}]'
```

The patch is not committed. `Always` is correct for a moving tag and is exactly
what prevents the node from using a side-loaded image.

## Building the image

```sh
docker buildx build -f deploy/Containerfile --target runtime \
  --platform linux/amd64,linux/arm64 .
```

From the repository root: the context is the workspace, not `deploy/`. Both
architectures, because this development cluster is arm64 under Lima while CI and
anything production is amd64. `.dockerignore` keeps the host's `target/` out of
the context.

## What stops these manifests from rotting

`crates/app/tests/manifests.rs` reads the files in this directory and checks them
against the binary. It does not compare them to a list — a list would be a mirror
of the same mistake. It takes a value out of the manifest, hands it to the built
binary, and asserts the binary visibly obeys it:

- the readiness and liveness probe path is fetched from a running binary
- each `WEBHOOK_PROXY_*` name is pointed somewhere decisive, so a misspelled one
  shows up as the binary falling back to its own default
- the port is the same number in the environment, the `containerPort`, both
  probes and the Service
- the configured paths are paths something is actually mounted at, read-only
- the port is also the only port the NetworkPolicy allows, and the policy
  selects the pods the Deployment creates
- the image names a registry and a particular build, and is not `:latest`
- no uid, gid or `fsGroup` is hardcoded, while `runAsNonRoot` still holds
- every manifest in this directory is one the kustomization applies
- the route publishes `/webhook` and nothing else
- the Containerfile still names the `runtime` stage that gc-lw3's release
  configuration will ask for

Each of those was verified by mutation: break it in the manifest, and a named test
fails.
