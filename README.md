# bjorn-gas-city

A Rust product, built by agents, under a workflow where the evidence is
mechanical rather than social: you merge because the checks passed, not because
the diff looked plausible.

The product itself is not here yet. What is here is the way of working.

## The idea in one paragraph

Agents are good at producing plausible code and bad at knowing when they are
wrong. So every judgement a reviewer would otherwise have to make by reading is
turned into something a machine decides: the architecture is a test, "done" is
one command, and the work queue is a dependency graph rather than a conversation.
What is left for the human is the only thing a human is actually better at —
deciding whether this was the right thing to build.

## Layout

```
crates/domain          pure rules. zero dependencies, enforced.
crates/application     use cases and ports (traits).
crates/adapters/*      implementations of ports. none yet.
crates/app             composition root. wiring only.
crates/architecture    the dependency-direction test.

CLAUDE.md              the contract agents work under.
GLOSSARY.md            ubiquitous language. a constraint, not a document.
justfile               every command. `just gate` is the definition of done.
.claude/skills/        how to do the four recurring kinds of work.
.beads/                the work ledger (Dolt-backed).
```

## Working on it

```bash
just ready          # what is workable now
just start gc-xxx   # claim a bead, get a worktree and a branch
just quick          # inner loop: boundaries + tests
just gate           # what CI runs. green == mergeable
just pr gc-xxx      # gate, push, open the PR
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

**3. One definition of green.** `just gate` runs formatting, the boundary test,
clippy with pedantic denied, the suite, and an unused-dependency check. The
Forgejo job and the GitHub job both run that same recipe, so "works on my
machine" has nowhere to hide.

## CI

| Where | Runs | Why |
| ----- | ---- | --- |
| Forgejo (local) | `just gate` | seconds, on every push, including bead branches |
| GitHub | `just gate` + `diggsweden/reusable-ci` | correctness plus the policy layer: conventional commits, REUSE, SAST, dependency review |

`reusable-ci` is pinned to a tag's full commit SHA (v3.0.0), never a moving ref.
It has no cargo build workflow, so it checks everything about a change except
whether the code works — which is what our own gate job is for.

## Prerequisites

```bash
brew install just gh        # gh is currently missing; `just pr` needs it
cargo install cargo-machete # required by `just gate`
```

`bd` (beads), `reuse`, `jq` and the Rust toolchain in `rust-toolchain.toml` are
already present.

## Open decisions

`bd ready` is the real list. The ones worth knowing about up front:

- **Licence and copyright holder are assumed, not confirmed** — EUPL-1.2 for
  code, CC-BY-4.0 for docs, CC0-1.0 for config, "Motrice AB" as the holder.
  Settle before the first public push (`gc-7kg`).
- **`main` is not yet protected**, so the human-merges rule is currently only a
  sentence in `CLAUDE.md` (`gc-rdz`).
- **The boundary test cannot see inside source files.** A domain file calling
  `SystemTime::now()` still compiles, because `std` needs no manifest entry
  (`gc-3ew`).
