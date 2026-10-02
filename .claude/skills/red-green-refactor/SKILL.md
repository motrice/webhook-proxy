---
name: red-green-refactor
description: The mandatory TDD loop for this repo. Use whenever you are about to write, change, or fix any production code in crates/ — including a one-line fix or a "trivial" change. Also use when a bug is reported, to reproduce it as a failing test first.
---

# Red, green, refactor

Production code in this repo only ever arrives as the answer to a failing test.
Not because tests are virtuous, but because a test written afterwards tests the
code you wrote, while a test written first tests the behaviour you wanted.

## The loop

**1. Red.** Write one test that fails for the right reason.

Run it and *read the failure message*. A test that fails to compile has not yet
failed — compilation errors are not evidence about behaviour. Get it to compile
with the smallest possible stub (`todo!()` is fine), then confirm the assertion
itself fails.

```bash
cargo test -p domain name_of_the_test   # must fail, with a message you believe
```

If the failure message would not tell a stranger what broke, fix the test before
fixing the code.

**2. Green.** Make it pass the dumbest way that works.

Hardcode the return value if that is what makes it green. Resist designing here:
you do not yet have enough tests to know the shape. The point of this step is to
prove the test can pass at all.

```bash
just quick    # arch + the whole suite
```

**3. Refactor.** Now, with a green suite, change the design.

This is the only step where you are allowed to make code "nicer", and you must
not change behaviour while doing it. The suite stays green the whole way. If you
need to change a test to refactor, you are not refactoring — stop, revert, and
go back to step 1 with a better test.

Repeat until the bead's acceptance criteria are all covered by passing tests.

## Rules that are not negotiable

- **One test at a time.** Writing six failing tests then making them all pass is
  not TDD; it is guessing with extra steps.
- **Never weaken a test to make it pass.** Deleting an assertion, loosening a
  comparison, or adding `#[ignore]` to get green is falsifying evidence. If a
  test is wrong, say so explicitly and explain why before changing it.
- **A bug fix starts with a reproducing test.** The test must fail before the
  fix and pass after. If you cannot reproduce it, you cannot claim to have fixed
  it — say that instead.
- **No test touches the network, the clock, the filesystem or a database.**
  Those live behind ports (see the `port-and-adapter` skill). A test that needs
  them is telling you the logic is in the wrong layer.

## Where tests live

| Layer | Test style | Doubles |
| ----- | ---------- | ------- |
| `domain` | unit tests in the same file, `#[cfg(test)] mod tests` | none needed — it is pure |
| `application` | unit tests driving a use case | hand-written in-memory fakes of the ports |
| `adapters/*` | integration tests proving the adapter honours its port | the real dependency, or nothing |
| `app` | acceptance tests driving the built binary | the real wiring |

Prefer hand-written fakes over mocking libraries. A fake that is 20 lines and
obviously correct beats a mock expectation that encodes call order nobody asked
for.

## Naming

Test names are sentences about behaviour, not labels for methods:

```rust
// no
#[test] fn test_withdraw() {}

// yes — reads as a claim that can be true or false
#[test] fn withdrawal_is_rejected_when_it_would_overdraw_the_account() {}
```

A test name mentioning a type or function name, rather than a rule, usually
means the test is checking implementation instead of behaviour.

## Before you say you are done

```bash
just gate
```

Green gate or it is not done. If the gate fails on something you believe is
unrelated to your change, that belief is a claim you have to check — say what
you found rather than retrying.
