# This repo follows the diggsweden devbase convention for hygiene linting and
# the Rust convention for everything about the compiler. Where the two collide,
# the division is written down rather than guessed at:
#
#   verify     everything. the human entrypoint and the definition of done.
#   check      correctness only — needs the Rust toolchain and nothing else.
#   lint-all   hygiene only — needs mise tools and devbase-check.
#
#   verify == check + lint-all, and CI composes it from two jobs for that reason:
#   the `check` job runs correctness, reusable-ci's devbase job runs hygiene.
#   There is one definition of green; it is simply checked in two places.

# Every devbase linter runs through `mise exec --`: the tools are pinned in
# .mise.toml, and a bare `just` recipe spawns a shell with no mise activation,
# so without this they are simply not on PATH and devbase reports them missing.
# Wrapping the top-level entry point is enough for the nested case — verify.sh
# calls back into these recipes, and children inherit the PATH — but each
# recipe wraps anyway so it can be run on its own.
mise := "mise exec --"

devtools_repo := env("DEVBASE_CHECK_REPO", "https://github.com/diggsweden/devbase-check")
devtools_dir := env("XDG_DATA_HOME", env("HOME") + "/.local/share") + "/devbase-check"
lint := devtools_dir + "/linters"

default:
    @just --list --unsorted

# ==========================================================================
# VERIFY
# ==========================================================================

# ▪ Everything. Green here means mergeable.
[group('verify')]
verify: check lint-all

# ▪ Correctness. What the CI `check` job runs; no mise, no devbase-check.
[group('verify')]
check: fmt-check arch clippy test deps

# ▪ Inner loop while writing code: boundaries plus the suite.
[group('verify')]
quick: arch test

# ==========================================================================
# SETUP
# ==========================================================================

# Clone devbase-check on first run, then let it update itself.
[group('setup')]
setup-devtools:
    @[ -d "{{ devtools_dir }}" ] || { mkdir -p "$(dirname "{{ devtools_dir }}")" && git clone --depth 1 "{{ devtools_repo }}" "{{ devtools_dir }}"; }
    @"{{ devtools_dir }}/scripts/setup.sh" "{{ devtools_repo }}" "{{ devtools_dir }}"

# Force devbase-check to its latest release (or --ref <branch/tag/sha>).
[group('setup')]
update-devtools *ARGS:
    @"{{ devtools_dir }}/scripts/update.sh" "{{ devtools_dir }}" {{ ARGS }}

# ▪ Install development tooling. reusable-ci's devbase job calls this by name.
[group('setup')]
install:
    mise install
    @just setup-devtools
    cargo fetch

# Confirm every tool the linters need is actually present.
[group('setup')]
check-tools: _ensure-devtools
    @{{ devtools_dir }}/scripts/check-tools.sh --check-devtools mise git just cargo rustc rustfmt rumdl yamlfmt actionlint gitleaks shellcheck shfmt gommitlint reuse

# ==========================================================================
# LINT — hygiene, via devbase-check
# ==========================================================================

# ▪ Every linter: the devbase base suite plus our own Rust lint.
[group('lint')]
lint-all: _ensure-devtools clippy
    # verify.sh lints the current working directory and uses its own location
    # only to find the linters, so it is called by absolute path from here —
    # the same way every individual lint-* recipe below calls its script.
    # Going through devbase-check's own justfile instead would run its
    # `./scripts/verify.sh`, relative to *its* checkout, and cheerfully report
    # that someone else's repository is clean.
    @{{ mise }} "{{ devtools_dir }}/scripts/verify.sh"

[group('lint')]
lint-commits:
    @{{ mise }} {{ lint }}/commits.sh

# Refuses to pass while the working tree is dirty, so a green `verify` always
# describes committed state rather than whatever happens to be on disk.
[doc("Refuse to pass while the working tree is dirty")]
[group('lint')]
lint-version-control:
    @{{ mise }} {{ lint }}/version-control.sh

[group('lint')]
lint-secrets:
    @{{ mise }} {{ lint }}/secrets.sh

[group('lint')]
lint-yaml:
    @{{ mise }} {{ lint }}/yaml.sh check

# MD013 is devbase's own default (line length). MD024 (duplicate headings) is
# ours: `bd` generates AGENTS.md and rewrites its managed block on upgrade, and
# that block repeats headings. We cannot fix it and we should not hand-edit a
# generated file, so the rule goes rather than the file — excluding AGENTS.md
# entirely would also drop the rules it *does* pass.
[doc("Markdown, with MD013 and MD024 disabled (see above)")]
[group('lint')]
lint-markdown:
    @{{ mise }} {{ lint }}/markdown.sh check MD013,MD024

[group('lint')]
lint-shell:
    @{{ mise }} {{ lint }}/shell.sh

[group('lint')]
lint-shell-fmt:
    @{{ mise }} {{ lint }}/shell-fmt.sh check

[group('lint')]
lint-actions:
    @{{ mise }} {{ lint }}/github-actions.sh

# No Dockerfile yet; the recipe exists because devbase's verify.sh calls it.
[group('lint')]
lint-container:
    @{{ mise }} {{ lint }}/container.sh

# No XML in a Rust workspace; same reason as lint-container.
[group('lint')]
lint-xml:
    @{{ mise }} {{ lint }}/xml.sh

[group('lint')]
lint-license:
    @{{ mise }} {{ lint }}/license.sh

# ==========================================================================
# LINT-FIX
# ==========================================================================

# ▪ Fix everything that can be fixed mechanically.
[group('lint-fix')]
lint-fix: _ensure-devtools fmt
    @{{ mise }} {{ lint }}/yaml.sh fix
    @{{ mise }} {{ lint }}/markdown.sh fix MD013,MD024
    @{{ mise }} {{ lint }}/shell-fmt.sh fix

# ==========================================================================
# RUST — correctness. Deliberately not delegated to devbase-check's rust
# scripts: the workspace lint table in Cargo.toml denies clippy::all and warns
# pedantic, and `-D warnings` here is what turns that into a wall. Running our
# own invocation keeps that strictness ours to set.
# ==========================================================================

[group('rust')]
fmt:
    cargo fmt --all

[group('rust')]
fmt-check:
    cargo fmt --all --check

[group('rust')]
clippy:
    cargo clippy --workspace --all-targets --all-features -- -D warnings

[group('rust')]
test:
    cargo test --workspace --all-targets

# The executable architecture rules: `boundaries` proves the dependency arrows
# point inward, `purity` proves the domain reaches for no effects. Run the whole
# crate rather than one test file, so a new rule is enforced the moment it lands
# instead of waiting for someone to remember to add it here.
[doc("Executable architecture rules: boundaries and domain purity")]
[group('rust')]
arch:
    cargo test -p architecture

# Unused dependencies — often the first sign of a layer drifting.
[group('rust')]
deps:
    cargo machete

# Known advisories against the dependency tree.
[group('rust')]
audit:
    cargo audit

[group('rust')]
build:
    cargo build --workspace --release

[group('rust')]
clean:
    cargo clean

# ==========================================================================
# BEADS — the work queue. A bead is the unit of work, a branch, and a PR.
# ==========================================================================

# What is workable right now (blockers resolved).
[group('beads')]
ready:
    bd ready

# Claim the next ready bead atomically and print it. The agent entrypoint.
[group('beads')]
next:
    bd ready --claim --json

# Begin a bead in its own worktree, so parallel agents never share a checkout.
[group('beads')]
start id:
    bd update {{ id }} --claim
    bd worktree create {{ id }} --branch "bead/{{ id }}"
    bd worktree list

# Record progress without closing — keeps the lease alive on long work.
[group('beads')]
note id message:
    bd note {{ id }} "{{ message }}"
    bd heartbeat {{ id }}

# Hand work back. Leaving a stale lease blocks everyone else.
[group('beads')]
abandon id reason:
    bd note {{ id }} "abandoned: {{ reason }}"
    bd unclaim {{ id }}

# ==========================================================================
# SHIP — an agent may reach `pr`; only a human merges.
# ==========================================================================

# ▪ Open the PR for a bead. Requires `gh` and `jq`.
#
# `base` defaults to main. Pass a bead branch to stack on an unmerged PR — and
# then do not delete that branch when merging it, because GitHub closes a PR
# whose base is gone and a closed PR with no base cannot be reopened.
[doc("Open the PR for a bead. Pass a base to stack on an unmerged PR")]
[group('ship')]
pr id base="main": verify
    #!/usr/bin/env bash
    set -euo pipefail
    id="{{ id }}"
    base="{{ base }}"
    bead=$(bd show "$id" --json)
    # bd show --json may return the issue or a single-element array.
    norm='if type=="array" then .[0] else . end'
    title=$(jq -r "$norm"' | .title // empty' <<<"$bead")
    accept=$(jq -r "$norm"' | .acceptance_criteria // empty' <<<"$bead")
    [[ -n "$title" ]] || { echo "bead $id has no title; is the id right?" >&2; exit 1; }

    just _push "bead/$id"

    body="Closes bead $id."
    body+=$'\n\n## Acceptance\n'"$accept"
    body+=$'\n\n## Evidence\n'
    body+='`just verify` green locally: correctness (fmt, boundaries, clippy -D '
    body+=$'warnings, tests, unused deps) and hygiene (devbase base linters).'
    body+=$'\n\n## Review focus\n'
    body+='Any diff under `crates/architecture/` widens an architectural boundary '
    body+=$'on purpose and deserves the most scrutiny in this PR.'
    if [[ "$base" != "main" ]]; then
        body+=$'\n\n## Stacked\n'
        body+="Based on \`$base\`, so the diff here is only this bead's work. "
        body+=$'Merge that PR first, and do not delete its branch while this PR is '
        body+=$'open: GitHub closes a PR whose base branch is deleted, and it '
        body+=$'cannot be reopened afterwards.'
    fi

    gh pr create --base "$base" --title "$title" --body "$body"

# ▪ Watch CI for the commit you are actually on.
#
# Resolves the run by head SHA rather than taking the newest run on the branch: a
# run needs a few seconds to appear after a push, so "newest" is often the
# previous commit's, and reading that as this commit's result has twice reported
# a stale failure as current.
[doc("Watch CI for the commit you are on, resolved by head SHA")]
[group('ship')]
ci:
    #!/usr/bin/env bash
    set -euo pipefail
    head=$(git rev-parse HEAD)
    branch=$(git branch --show-current)
    run=""
    for _ in $(seq 1 20); do
        run=$(gh run list --branch "$branch" --limit 20 --json databaseId,headSha \
              --jq "[.[] | select(.headSha==\"$head\")] | .[0].databaseId // empty")
        [[ -n "$run" ]] && break
        sleep 3
    done
    if [[ -z "$run" ]]; then
        printf 'no CI run for %s on %s after 60s\n' "${head:0:7}" "$branch" >&2
        exit 1
    fi
    printf 'watching run %s for %s\n' "$run" "${head:0:7}"
    gh run watch "$run" --exit-status --interval 15

[private]
_ensure-devtools:
    @just setup-devtools

# ▪ MAINTAINER ONLY. Approve a reviewed bead by signing its tip with the YubiKey.
#
# This is the only step in the workflow that cannot be automated, and that is the
# point. Every agent commit already carries the maintainer's name and email, so
# authorship distinguishes nothing; a FIDO2 signature cannot exist unless somebody
# physically touched the authenticator. Re-signing the tip is therefore the proof
# that a human was in the loop, and `land` refuses to proceed without it.
#
# The tip is amended rather than added to, so CI runs on the exact object that
# will become main.
[doc("Sign a reviewed bead tip with the YubiKey (maintainer only)")]
[group('ship')]
approve id:
    #!/usr/bin/env bash
    set -euo pipefail
    branch="bead/{{ id }}"
    key="${APPROVAL_KEY:-$HOME/.ssh/id_ed25519_sk_touch.pub}"
    if [[ ! -f "$key" ]]; then
        printf 'no approval key at %s\n' "$key" >&2
        printf 'set APPROVAL_KEY, or see docs/approval-keys for what land accepts\n' >&2
        exit 1
    fi
    git switch --quiet "$branch"
    printf 'touch the YubiKey when it blinks\n'
    git -c user.signingkey="$key" commit --amend --no-edit --quiet
    printf 'approved: %s\n' "$(git log --format='%h %G? signed-by=%GK' -1)"
    just _push "$branch"
    printf 'wait for CI to pass, then: just land %s\n' "{{ id }}"

# ▪ MAINTAINER ONLY. Land an approved bead on main, preserving its signature.
#
# Refuses unless the tip carries a good signature from a key in
# docs/approval-keys — all of which are hardware-backed, so landing without a
# human present is not merely discouraged but impossible.
#
# A fast-forward creates no commit, so the approved object becomes main unchanged.
# GitHub's merge buttons cannot do this: "Rebase and merge" rewrites every commit
# and does not re-sign it, which is how main came to carry twenty-one unsigned
# commits while every branch was signed.
[doc("Fast-forward main from an approved bead (maintainer only)")]
[group('ship')]
land id:
    #!/usr/bin/env bash
    set -euo pipefail
    branch="bead/{{ id }}"
    git fetch --quiet origin
    tip="origin/$branch"

    status=$(git log --format='%G?' -1 "$tip")
    signer=$(git log --format='%GK' -1 "$tip")
    if [[ "$status" != "G" ]]; then
        printf 'the tip of %s carries no good signature (git reports %s)\n' "$branch" "$status" >&2
        exit 1
    fi
    if ! ssh-keygen -lf docs/approval-keys | awk '{print $2}' | grep -qxF "$signer"; then
        printf 'the tip of %s is signed by %s,\n' "$branch" "$signer" >&2
        printf 'which is not a key listed in docs/approval-keys.\n' >&2
        printf 'a human has not approved this: just approve %s\n' "{{ id }}" >&2
        exit 1
    fi

    git switch --quiet main
    if ! git merge --ff-only "$tip"; then
        printf 'not a fast-forward. rebase %s onto main first:\n' "$branch" >&2
        printf '  git switch %s && git rebase origin/main && just verify\n' "$branch" >&2
        exit 1
    fi
    printf 'main is now %s\n' "$(git log --format='%h %G? %s' -1)"
    just _push main

# Push a branch, retrying only what is worth retrying.
#
# A bead branch is amended constantly while iterating, and approving amends it
# again, so pushing one is a force-push by nature — with a lease, so a push that
# would discard somebody else's work still fails. main is never force-pushed: a
# fast-forward is the only way it is meant to move.
#
# A rejection by the remote is permanent and is reported as such. The previous
# version retried one three times and then announced "this is not a transient
# problem", which read as a network verdict and sent me off testing SSH while the
# actual cause was an amended commit.
[private]
_push branch:
    #!/usr/bin/env bash
    set -euo pipefail
    branch="{{ branch }}"
    if [[ "$branch" == bead/* ]]; then
        args=(--force-with-lease -u origin "$branch")
    else
        args=(-u origin "$branch")
    fi
    for attempt in 1 2 3; do
        if output=$(git push "${args[@]}" 2>&1); then
            printf '%s\n' "$output"
            exit 0
        fi
        printf '%s\n' "$output" >&2
        if grep -qE 'rejected|non-fast-forward|stale info|fetch first' <<<"$output"; then
            printf 'the remote rejected this; that is not a connection problem, so not retrying\n' >&2
            exit 1
        fi
        printf 'push failed (attempt %d of 3), retrying\n' "$attempt" >&2
        sleep $((attempt * 3))
    done
    printf 'push failed three times\n' >&2
    exit 1
