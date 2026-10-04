# The CI job image

`.forgejo/workflows/fast.yml` runs inside this image. It carries rust, node,
`just` and `cargo-machete`, so the job installs nothing — a fast gate that
installs a toolchain on every run is slower than the GitHub gate it exists to
pre-empt.

Node is the part that is easy to miss. `actions/checkout` is a **JavaScript**
action, and Forgejo's runner executes JS actions using a `node` binary inside the
*job* container. Without it a job fails in six seconds with
`exec: "node": executable file not found in $PATH`, before anything is built —
which is exactly how the first two runs of the fast gate died.

Debian rather than Alpine, deliberately: GitHub's runner is ubuntu/glibc, and a
gate that built against musl would stop predicting the gate it exists to predict.

## Building it

There is **no registry behind this tag**. The image lives in the runner's own
Docker storage, so it is built there directly:

```bash
cat deploy/ci-image/Containerfile \
  | kubectl -n forgejo-runner exec -i deploy/forgejo-runner -c dind -- sh -ec '
      rm -rf /tmp/ctx && mkdir -p /tmp/ctx && cat > /tmp/ctx/Containerfile
      docker build -t webhook-proxy-ci:1 -f /tmp/ctx/Containerfile /tmp/ctx'
```

The Containerfile needs no build context — everything comes from `FROM` and
`COPY --from` — which is why an empty directory is passed as the context rather
than the repository.

Validate changes locally first; the final `RUN` asserts every tool is present, so
a broken image fails at build time instead of in a confusing CI log:

```bash
docker build -f deploy/ci-image/Containerfile -t webhook-proxy-ci:local .
```

## It survives a pod replacement, and why that is not a registry

The runner's Docker storage is a PersistentVolumeClaim
(`forgejo-runner-docker`), so the image outlives the pod. It used to be an
`emptyDir`, which meant replacing the pod deleted the image and the fast gate
then failed with a pull error against a tag that resolves nowhere — see bead
`gc-guj`.

A registry was the obvious alternative and was rejected on the gate's own terms.
Publishing to `ghcr.io` would make a *local* gate depend on the internet, and
publishing to the Forgejo instance's own registry would need the mkcert CA
trusted inside dind, which is the problem the runner currently sidesteps by
talking to the in-cluster service. Keeping the layers on a volume means a
replaced pod needs no network at all, which is what a second opinion running
beside a developer should want.

What the volume costs is that a corrupted build cache now outlives a pod too.
That is one command to undo:

```bash
kubectl -n forgejo-runner delete pvc forgejo-runner-docker
kubectl -n forgejo-runner rollout restart deploy/forgejo-runner
```

The claim is recreated empty, and the image is rebuilt with the command above.
So corruption costs a rebuild, where the missing image cost a gate nobody could
diagnose.

**Rebuilding is manual.** Nothing watches this file. When it changes, bump the
tag — in the `docker build -t` above and in `image:` in
`.forgejo/workflows/fast.yml` — then build it again. The bump is what stops a
stale layer masquerading as a fresh one, and it is the one step that cannot be
skipped, because a tag that already exists locally is never re-pulled.
