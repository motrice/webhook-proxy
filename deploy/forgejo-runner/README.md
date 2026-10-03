# Forgejo Actions runner

`.forgejo/workflows/fast.yml` is the fast gate: `just check` on every push, in
seconds, without spending GitHub Actions minutes. Forgejo already parses it and
creates a workflow run on push — the run then sits at `status=waiting`, because
nothing is registered to execute it. This directory is that something.

## The decision this encodes

The workflow uses `runs-on: docker` with `container: image: rust:1.95-bookworm`,
so a job needs a container runtime. **k3s runs containerd, not Docker**, so the
usual lighter option — mounting the host's Docker socket — does not exist here.
What remains is a Docker-in-Docker sidecar, and that sidecar must be
`privileged: true`.

That is a real concession, so it is isolated rather than waved through: the runner
lives in its own namespace, so a policy protecting the Forgejo server is not
loosened to accommodate CI.

**The alternative was weighed and rejected.** `runs-on: host` removes the
privileged container, and the job can still install the toolchain with `rustup`,
which reads `rust-toolchain.toml` — so the toolchain stays pinned in the repo. The
real cost is subtler: the forgejo-runner image is Alpine/musl while GitHub builds
on ubuntu/glibc, so the fast gate would stop predicting the slow one, which is the
only reason to have a fast gate. Building a custom glibc runner image would fix
that, at the price of an image this repository has to build, publish and patch.

So the two findings OpenGrep raises — `privileged-container` and
`allow-privilege-escalation` — are suppressed with `# nosemgrep` and a written
reason beside them. They are **the only suppressed security findings in this
repository**, which is the point of saying so here: an exception that nobody can
find is indistinguishable from an oversight.

Two smaller choices, both to avoid solving problems that can be dodged:

- The runner talks to `http://forgejo.forgejo.svc.cluster.local:3000`, not
  `https://forgejo.dev.test:8443`. The external name is served with an mkcert
  certificate trusted only on the developer's machine; using the in-cluster
  service means no CA has to be mounted.
- Registration is written to a small PersistentVolumeClaim, so a restart reuses
  the existing registration rather than adding a new runner record to Forgejo
  every time the pod moves.

## Installing it

**On this machine `kubectl` is a wrapper**: `docker exec -i k3s-toolbox kubectl`.
It runs inside a container, so **it cannot see host file paths** — `kubectl apply
-f ./deploy/...` fails with "the path does not exist", and `kubectl apply -k` can
never work, because kustomize needs to read a directory the container has no
access to. Manifests must arrive on stdin, which the wrapper forwards.

The registration token is never committed, in any form. Mint it, hand it to
Kubernetes directly, and it exists in exactly one place:

```bash
# 1. The namespace first, so the rest has somewhere to live.
cat deploy/forgejo-runner/namespace.yaml | kubectl apply -f -

# 2. Repo settings -> Actions -> Runners -> "Create new runner" gives a token.
#    https://forgejo.dev.test:8443/bjomol/testa-webhook/settings/actions/runners
#    Repo-level is the tightest scope: this runner serves this repository only.
#
#    All arguments, no files, so the wrapper handles it unchanged.
kubectl -n forgejo-runner create secret generic forgejo-runner-token \
  --from-literal=token=PASTE_THE_TOKEN_HERE

# 3. The rest — one file per apply. See the warning below before changing this.
for manifest in pvc deployment; do
  cat "deploy/forgejo-runner/$manifest.yaml" | kubectl apply -f -
done
```

**Do not concatenate manifests into one `apply`.** `yamlfmt` — which `just
lint-fix` runs — strips the leading `---` from each file, so `cat a.yaml b.yaml`
produces a *single* YAML document rather than two. The later keys silently
override the earlier ones, so only the last resource is created and `kubectl`
reports success for it without mentioning the one it dropped. That happened the
first time these were applied: the PersistentVolumeClaim vanished, the Deployment
was created, and the pod sat unschedulable with "persistentvolumeclaim not found".
One file per apply is immune to it.

Being shell history, step 2 is worth a leading space if your shell is configured
to skip those, or `--from-file=token=/dev/stdin` with the token typed in.

`kustomization.yaml` is kept for a native `kubectl` or for ArgoCD later. It is
**not usable through the wrapper** — said here rather than discovered, since a
file that cannot work in the documented environment is otherwise a trap.

## Confirming it works

```bash
kubectl -n forgejo-runner rollout status deploy/forgejo-runner
kubectl -n forgejo-runner logs deploy/forgejo-runner -c register   # registration
kubectl -n forgejo-runner logs deploy/forgejo-runner -c runner -f  # picking up jobs
```

The runner should appear online under the repository's Actions settings, and the
run already waiting should start on its own. After that, `just mirror` from a
developer machine is the whole loop.

## Known unknown

Whether this runner resolves the GitHub action SHAs that `fast.yml` pins.
Forgejo resolves bare action names against whichever host it is configured for,
so `actions/checkout@<sha>` may or may not be found. If it is not, the fix is to
pin the equivalent Codeberg actions — **not** to revert to mutable tags, which is
what `.forgejo/workflows/fast.yml` already says in a comment and what
`gc-d69` established for the GitHub side.

## Not wired to ArgoCD

The cluster runs ArgoCD, and these manifests are deliberately not registered with
it. A runner that reconciles itself while holding a half-finished CI job is a
worse failure than one that needs a human to reapply it. Revisit when the runner
has proved boring.
