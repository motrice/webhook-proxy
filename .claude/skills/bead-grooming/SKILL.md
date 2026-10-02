---
name: bead-grooming
description: Turn a request, idea or bug report into beads an agent can actually execute. Use when the user describes work in prose, when a bead you picked up turns out to be underspecified, when you discover follow-up work mid-task, or before starting any epic.
---

# Grooming beads

A bead is the unit of work, a branch, and a pull request. The whole workflow
depends on beads being executable without asking a human a question — so
grooming is where the quality of everything downstream is decided.

## A bead is ready when

- **It has one outcome.** If the title needs "and", it is two beads.
- **Its acceptance criteria are checkable by a machine.** Each criterion names a
  test that must exist and pass. "Handles errors well" is not a criterion;
  "withdrawing more than the balance returns `Overdraft::InsufficientFunds` and
  leaves the balance unchanged" is.
- **It names the layer.** Domain rule, use case, adapter, or wiring. If nobody
  can say which, the next step is a `spike`, not an attempt.
- **It fits in one PR a human will actually review.** Roughly a day of work.
  Bigger than that, make it an epic with children.
- **Its blockers are recorded as dependencies,** so `bd ready` never hands an
  agent work it cannot finish.

## Writing one

```bash
bd create "Reject withdrawals that would overdraw an account" \
  --type feature \
  --priority 1 \
  --skills "domain-modeling,red-green-refactor" \
  --acceptance "- [ ] domain test: withdrawal above balance returns Overdraft::InsufficientFunds
- [ ] domain test: a rejected withdrawal leaves the balance unchanged
- [ ] domain test: withdrawal of exactly the balance succeeds
- [ ] Overdraft and any new term are in GLOSSARY.md
- [ ] just gate is green" \
  --description "Why: the ledger currently permits a negative balance, which the
business says can never exist. Where: crates/domain, Account aggregate.
Out of scope: overdraft *facilities* (a separate concept, not yet modelled)."
```

Three habits that matter more than the flags:

- **Acceptance criteria are written as the tests themselves.** The agent then
  has its red-green list handed to it, and review is a matter of checking the
  tests exist and assert what the criterion says.
- **Include the boundary case and the "nothing happened" case.** Most defects
  that survive TDD live in what the bead forgot to ask for.
- **State what is out of scope.** This is the single most effective defence
  against an agent helpfully expanding the diff.

## Dependencies

Record ordering as data, not as a note someone has to read:

```bash
bd dep add gc-b4f2 --blocked-by gc-a1c9   # the adapter waits for its port
bd dep tree gc-a1c9                       # see the shape before starting
bd dep cycles                             # run after any bulk grooming
```

The natural grain in this architecture: domain rule → port → use case →
adapter → wiring. Beads that follow it are independently reviewable; beads that
cut across it produce PRs that touch every layer and get rubber-stamped.

For an epic, groom the whole graph in one pass with `bd create --graph plan.json`
rather than creating beads one at a time and linking them afterwards.

## Splitting an epic

```bash
bd create "Account ledger" --type epic
bd create "Model Money and Currency" --parent gc-e001 --skills domain-modeling
bd create "Accounts port"            --parent gc-e001 --skills port-and-adapter
```

Each child must be independently shippable and independently reviewable. A child
that cannot be merged on its own is not a child, it is a stage — and stages
belong inside one bead.

## Decisions

An architectural choice is a bead of type `decision`, not a comment in a PR:

```bash
bd create "Postgres as the Accounts adapter" --type decision \
  --description "Context / options considered / decision / consequences"
```

Any PR that widens a boundary in `crates/architecture/tests/boundaries.rs` must
reference a `decision` bead. That is the rule that keeps the hexagon from eroding
one reasonable-looking exception at a time.

## Mid-task discoveries

When you find work that is not yours, file it and keep going — do not expand the
current bead:

```bash
bd create "Account::freeze has no test for an already-frozen account" \
  --type bug --deps "discovered-from:gc-a1c9" --priority 2
```

Scope creep in an agent's diff is the hardest thing for a human reviewer to
catch, because it all looks like reasonable code. The ledger is where extra work
goes.

## Grooming someone else's vague request

Do not guess. Ask at most two questions, then write beads under stated
assumptions and say what you assumed. For genuine uncertainty about feasibility
or approach, the honest move is a timeboxed `spike` whose only deliverable is a
`decision` bead:

```bash
bd create "Spike: can k3s host the worker pool within the latency budget?" \
  --type spike --estimate 120 \
  --acceptance "- [ ] a decision bead exists recording the answer and why"
```
