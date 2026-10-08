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

## The ConfigMap and the Secret are bead gc-ast.13's

`deployment.yaml` mounts two volumes and will not start without them:

| Volume    | Object                                 | Mounted at                      |
| --------- | -------------------------------------- | ------------------------------- |
| `routing` | ConfigMap `webhook-proxy-routing`      | `/etc/webhook-proxy/routing`    |
| `secrets` | Secret `webhook-proxy-secrets`         | `/etc/webhook-proxy/secrets`    |

The routing file is `config.yaml` inside the ConfigMap; `deploy/config.example.yaml`
is the published shape of it, and `webhook-proxy check` validates one without
touching the network. The Secret holds one key per name that file refers to — a
webhook secret or shared token per sender, and one URL per room.

**Every room URL is itself a credential.** Anyone holding it can post to that
room (bead gc-o61), so it belongs in the Secret and never in the routing file.

gc-ast.13 commits both objects, with the checksum annotation that makes a routing
change actually roll the pods. Until then, create them by hand.

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
