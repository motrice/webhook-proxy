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

## The limitation worth knowing

The runner's Docker storage is an `emptyDir`, so **this image disappears when the
runner pod is replaced** and the fast gate then fails with an image-pull error
against a tag no registry serves. Rebuild with the command above.

That is a deliberate trade for now rather than an oversight: persisting it means
either a PersistentVolumeClaim for Docker's whole storage — which also persists a
corruptible build cache — or publishing to a registry, which means credentials in
the cluster and an image to keep patched. Filed rather than guessed at; bump the
tag when the image changes, so a stale cached layer can never masquerade as a
fresh one.
