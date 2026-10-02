---
name: port-and-adapter
description: How to reach the outside world — databases, HTTP, the clock, k3s, Forgejo, message queues. Use when a bead needs persistence, an API call, time, randomness, or any I/O; when adding a crate under crates/adapters/; or when the architecture test rejects a dependency.
---

# Ports and adapters

The hexagon has one rule: **dependencies point inward.** Adapters know about the
application; the application never knows about an adapter. Everything below is a
consequence of that rule.

## The port belongs to the consumer

A port is a trait declared in `crates/application`, in the language of the
domain, stating what the application *needs*. It is never a description of the
technology that will satisfy it.

```rust
// no — the port has leaked the database into the core.
// `Row` and `query` mean the application now depends on SQL's worldview, and
// swapping the store means rewriting the use case.
pub trait AccountTable {
    async fn query(&self, sql: &str) -> Result<Vec<Row>, SqlError>;
}

// yes — stated as a need, in domain words, with a domain error.
pub trait Accounts {
    async fn by_id(&self, id: AccountId) -> Result<Option<Account>, AccountsUnavailable>;
    async fn save(&self, account: &Account) -> Result<(), AccountsUnavailable>;
}
```

Tests for the error signature: if the trait names a vendor, a wire format, a
status code or a SQL construct, it is an adapter's internals wearing a port's
clothes. Rewrite it as what the use case wanted.

## Which side a thing goes on

- **Driving (inbound) adapters** call *into* the application: the HTTP server,
  the CLI, a queue consumer, a cron entry. They translate a request into a use
  case call and the result back into a response. They hold no rules.
- **Driven (outbound) adapters** are called *by* the application through a port:
  the database, an HTTP client, the clock, the random source, the k3s API.

A useful test: if deleting it means the application cannot be *reached*, it is
inbound. If deleting it means the application cannot *reach something*, it is
outbound and needs a port.

## Effects that people forget are effects

Time, randomness and identity generation are I/O. They get ports too:

```rust
pub trait Clock { fn now(&self) -> Timestamp; }
pub trait Ids { fn next(&self) -> AccountId; }
```

Production wires the real ones; tests wire a fixed clock and a counter. This is
why domain tests in this repo never sleep, never flake, and never need retries.

## Adding an adapter

1. Declare or extend the port in `crates/application`, in domain language.
2. Write the use-case test against an in-memory fake of the port. Hand-write the
   fake — it is usually a `HashMap` behind a mutex and under 30 lines.
3. Create the crate at `crates/adapters/<name>/` and add it to the workspace
   `members`. The architecture test classifies anything under that path as an
   adapter automatically; there is no registry to update.
4. Implement the port. Translate the technology's errors into the port's domain
   error at the boundary — `sqlx::Error` must not escape the adapter.
5. Write an integration test proving the adapter honours the port's contract,
   against the real dependency. Mark it `#[ignore]` only if it needs
   infrastructure CI cannot provide, and say in the bead how to run it.
6. Wire it in `crates/app`. That is the only crate permitted to name it.

```bash
just arch    # confirms the new crate did not break the direction of the arrows
```

## Two adapters must not depend on each other

If they need shared code, that code is either a domain concept (move it to
`domain`) or an application concern (move it to `application`). An adapter
depending on an adapter is how a layered codebase quietly becomes a ball of mud,
so the architecture test refuses it outright.

## The composition root

`crates/app` is wiring only: read configuration, construct adapters, inject them
into use cases, start the inbound adapter. If you are tempted to put an `if`
containing a business rule in `main`, that rule belongs in the domain.

Because `app` holds no logic, it has no unit tests. It is covered by acceptance
tests that run the real binary.

## When the architecture test rejects you

It is almost always right, and the fix is almost never to widen the allowlist.
Ask in order:

1. Is this an effect that should be behind a port? → declare the port.
2. Is this logic sitting in the wrong layer? → move the code, not the boundary.
3. Is this genuinely a new capability of the core? → then widening
   `allowed_external` in `crates/architecture/tests/boundaries.rs` is correct,
   and it must be its own commit, explaining why, so review can see the
   architecture changed rather than finding it buried in a feature diff.
