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

# Hexagonal boundaries. Fails if the dependency arrows stop pointing inward.
[group('rust')]
arch:
    cargo test -p architecture --test boundaries

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
[group('ship')]
pr id: verify
    #!/usr/bin/env bash
    set -euo pipefail
    id="{{ id }}"
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
    \`just verify\` green locally: correctness (fmt, boundaries, clippy -D warnings,
    tests, unused deps) and hygiene (devbase base linters).

    ## Review focus
    Any diff under \`crates/architecture/\` widens an architectural boundary on
    purpose and deserves the most scrutiny in this PR."

# Mirror main to the local Forgejo remote for the fast gate.
[group('ship')]
mirror:
    git push forgejo main

[private]
_ensure-devtools:
    @just setup-devtools
