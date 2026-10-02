# Project Instructions for AI Agents

This file provides instructions and context for AI coding agents working on this project.

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:1105d646 -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

**Architecture in one line:** issues live in a local Dolt DB; sync uses `refs/dolt/data` on your git remote; `.beads/issues.jsonl` is a passive export. See https://github.com/gastownhall/beads/blob/main/docs/core-concepts/sync-concepts.md for details and anti-patterns.

## Agent Context Profiles

The managed Beads block is task-tracking guidance, not permission to override repository, user, or orchestrator instructions.

- **Conservative (default)**: Use `bd` for task tracking. Do not run git commits, git pushes, or Dolt remote sync unless explicitly asked. At handoff, report changed files, validation, and suggested next commands.
- **Minimal**: Keep tool instruction files as pointers to `bd prime`; use the same conservative git policy unless active instructions say otherwise.
- **Team-maintainer**: Only when the repository explicitly opts in, agents may close beads, run quality gates, commit, and push as part of session close. A current "do not commit" or "do not push" instruction still wins.

## Session Completion

This protocol applies when ending a Beads implementation workflow. It is subordinate to explicit user, repository, and orchestrator instructions.

1. **File issues for remaining work** - Create beads for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **Handle git/sync by active profile**:
   ```bash
   # Conservative/minimal/default: report status and proposed commands; wait for approval.
   git status

   # Team-maintainer opt-in only, unless current instructions forbid it:
   git pull --rebase
   git push
   git status
   ```
5. **Hand off** - Summarize changes, validation, issue status, and any blocked sync/commit/push step

**Critical rules:**
- Explicit user or orchestrator instructions override this Beads block.
- Do not commit or push without clear authority from the active profile or the current user request.
- If a required sync or push is blocked, stop and report the exact command and error.
<!-- END BEADS INTEGRATION -->


## What this repo is

A Rust product built by agents, under a workflow designed so that a human can
trust a PR without reading every line of it. Three mechanisms do that work:
a dependency-direction test, acceptance criteria written as tests, and one
command that defines "green".

## How work flows

```
bd ready  ->  claim  ->  worktree  ->  red/green/refactor  ->  just gate  ->  PR  ->  human merges
```

1. **Take work from the ledger, never from prose.** `just ready` shows what is
   workable; `just next` claims the top of it atomically. If the user asks for
   something not in the ledger, groom it into beads first (`bead-grooming`).
2. **One bead, one worktree, one branch, one PR.** `just start <id>` does all
   three, so parallel agents never share a checkout.
3. **Code arrives only as the answer to a failing test** (`red-green-refactor`).
4. **`just gate` is the definition of done.** CI runs the same recipe, so local
   and CI cannot disagree.
5. **You open the PR. A human merges it.** Always.

## Authority

This repository explicitly grants more than the conservative default above, and
no more than this:

- **You may** commit, and push to a `bead/*` branch, and open a PR.
- **You must not** merge a PR, push to `main`, force-push a branch anyone else
  may have, or edit CI workflow files without a `decision` bead.
- **You must not** widen a boundary in `crates/architecture/tests/boundaries.rs`
  in the same commit as a feature. Separate commit, referencing a `decision`
  bead, so review sees that the architecture changed.

If the gate will not go green, stop and report the failure. Do not disable a
test, add `#[ignore]`, loosen an assertion, or reach for `--no-verify`. A red
gate honestly reported is a good outcome; a green gate obtained by weakening the
evidence is the one failure mode this whole setup exists to prevent.

## Architecture

Hexagonal, enforced by `cargo test -p architecture`:

| Crate | May depend on | Holds |
| ----- | ------------- | ----- |
| `crates/domain` | **nothing** | pure rules, invariants, ubiquitous language |
| `crates/application` | `domain` (+ `thiserror`, `async-trait`) | use cases and ports (traits) |
| `crates/adapters/*` | `domain`, `application`, anything external | implementations of ports |
| `crates/app` | all of the above | composition root; wiring only |

Adapters may not depend on each other. Nothing may depend on `architecture`.
The test fails the build with an explanation naming the fix, so read the message
before changing a manifest.

Time, randomness, I/O and serialisation are effects and live behind ports —
see the `port-and-adapter` skill. `GLOSSARY.md` is a hard constraint on naming,
not documentation of it.

## Commands

```bash
just            # list everything
just quick      # arch + tests — the inner loop
just gate       # fmt, arch, clippy -D warnings, tests, unused deps == CI
just ready      # workable beads
just start <id> # claim a bead and create its worktree
just pr <id>    # gate, push the branch, open the PR
```

Never run `cargo test` as your final check — run `just gate`. It is strictly
more than the tests and it is what CI will run.

## Conventions

- **Conventional commits**, enforced by CI. The bead goes in a trailer, so the
  ledger and the diff stay linked:

  ```
  feat(domain): reject withdrawals that would overdraw an account

  Bead: gc-a1c9
  ```

- **Clippy pedantic is denied, not warned.** Fix the lint rather than
  `#[allow]`-ing it; if an allow is genuinely right, the comment above it says
  why in terms of this code, not in terms of the lint.
- **`unsafe` is forbidden** workspace-wide.
- **No new dependency without a reason in the commit message.** In `domain`, no
  new dependency at all.

## Skills

Load the skill before doing the thing, not after:

| Doing | Skill |
| ----- | ----- |
| writing or changing any production code | `red-green-refactor` |
| adding a domain concept, type or invariant | `domain-modeling` |
| anything touching I/O, time, or randomness | `port-and-adapter` |
| turning a request into beads; splitting an epic | `bead-grooming` |
