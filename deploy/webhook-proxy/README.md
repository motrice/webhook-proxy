# Running the proxy on k3s

The manifests for the proxy itself: a Namespace, a Deployment, a Service and an
HTTPRoute. Bead gc-d01.

What is deliberately **not** here: the image, the ConfigMap, and the Secret. Each
is absent for its own reason, and each is the first thing someone looks for.

## The image is pulled, never built here

Bead gc-kow decided it: the release workflow publishes one container to
`ghcr.io/motrice/webhook-proxy`, and everything else consumes it. A manifest that
built its own image would be a second path to something that looks identical, and
the two diverge the first time only one of them is rebuilt.

`deployment.yaml` names the `main` tag, rebuilt on every commit to `main`, with
`imagePullPolicy: Always`. The copy of this manifest in the GitOps repository
should pin a digest instead — a moving tag cannot be rolled back to.

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
  field names in all five `template` stanzas
- the `vault-agent` container's image
- `config.example.yaml` itself, with the real routing — the example names rooms
  that do not exist
- `ghcr.io/motrice/webhook-proxy:main`, which should be pinned to a digest there;
  a moving tag cannot be rolled back to

The role binding that lets this service account read those secrets lives in the
secret store, not here.

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
files the agent renders are exactly the secrets the routing file names — add a
room and forget its stanza, and a named test fails rather than a pod waiting for
something nothing will ever write.

### Ordering

The agent is a plain container, matching the pattern this cluster's GitOps uses
for every service. It is deliberately not ordered before the proxy: the proxy
waits for its configuration to appear, bounded and polled, and says on stderr
what it is waiting for (bead gc-6b7). That works under a plain sidecar, a native
one, an injector, or a plainly mounted Secret, and leaves the choice to whoever
owns the platform.

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

## Applying it

```sh
kubectl apply -k deploy/webhook-proxy
```

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
- the image is the published one and is not `:latest`
- the route publishes `/webhook` and nothing else
- the Containerfile still names the `runtime` stage that gc-lw3's release
  configuration will ask for

Each of those was verified by mutation: break it in the manifest, and a named test
fails.
