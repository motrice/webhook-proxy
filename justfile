set shell := ["bash", "-uc"]

# The contract: CI runs `just gate` and nothing else. Local and CI cannot
# diverge, because there is only one definition of "green".

default:
    @just --list --unsorted

# ---------------------------------------------------------------------------
# The gate. Green here == mergeable. Ordered cheapest-first so you fail fast.
# ---------------------------------------------------------------------------

gate: fmt-check arch lint test deps

# Fast inner loop: the two things that fail most often while writing code.
quick: arch test

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all --check

lint:
    cargo clippy --workspace --all-targets --all-features -- -D warnings

test:
    cargo test --workspace --all-targets

# Hexagonal boundaries. Fails if the dependency arrows stop pointing inward.
arch:
    cargo test -p architecture --test boundaries

# Unused dependencies — often the first sign of a layer drifting.
deps:
    cargo machete

# Known advisories against the dependency tree.
audit:
    cargo audit

sbom:
    cargo sbom > sbom.spdx.json

# Licence/REUSE compliance — the same thing reusable-ci enforces on the PR.
licence:
    reuse lint

# ---------------------------------------------------------------------------
# Beads: the work queue. A bead is the unit of work, a branch, and a PR.
# ---------------------------------------------------------------------------

# What is workable right now (blockers resolved).
ready:
    bd ready

# Claim the next ready bead atomically and print it. The agent entrypoint.
next:
    bd ready --claim --json

# Begin a bead in its own worktree, so parallel agents never share a checkout.
start id:
    bd update {{id}} --claim
    bd worktree create {{id}} --branch "bead/{{id}}"
    bd worktree list

# Record progress without closing — keeps the lease alive on long work.
note id message:
    bd note {{id}} "{{message}}"
    bd heartbeat {{id}}

# Hand work back if you cannot finish it. Leaving a stale lease blocks others.
abandon id reason:
    bd note {{id}} "abandoned: {{reason}}"
    bd unclaim {{id}}

# ---------------------------------------------------------------------------
# Shipping. An agent may reach `pr`; only a human merges.
# ---------------------------------------------------------------------------

# Everything that must hold before a PR exists.
preflight: gate licence

# Open the PR for a bead. Requires `gh` and `jq`.
pr id: preflight
    #!/usr/bin/env bash
    set -euo pipefail
    id="{{id}}"
    bead=$(bd show "$id" --json)
    # bd show --json may return the issue or a single-element array.
    norm='if type=="array" then .[0] else . end'
    title=$(jq -r "$norm"' | .title // empty' <<<"$bead")
    accept=$(jq -r "$norm"' | .acceptance_criteria // empty' <<<"$bead")
    [[ -n "$title" ]] || { echo "bead $id has no title; is the id right?" >&2; exit 1; }
    git push -u origin "bead/$id"
    gh pr create --title "$title" --body "Closes bead $id.

    ## Acceptance
    $accept

    ## Evidence
    \`just gate\` green locally (fmt, arch, clippy -D warnings, tests, unused deps).

    ## Review focus
    Any diff under \`crates/architecture/\` widens an architectural boundary on
    purpose and deserves the most scrutiny in this PR."

# Mirror main to the local Forgejo remote for fast CI.
mirror:
    git push forgejo main
