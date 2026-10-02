---
name: domain-modelling
description: How to add or change a concept in crates/domain. Use when introducing a new domain type, aggregate, invariant or state machine; when a bead describes a business rule; or when you catch yourself writing validation, `Option`-heavy structs, or a type named *Manager/Service/Data*.
---

# Domain modelling

`crates/domain` has zero dependencies and no I/O. That poverty is the feature: it
makes the core fast to test and impossible to couple to a framework. Everything
here is about keeping it that way.

## Start from the language, not the data

Before writing a type, find the word for it in `GLOSSARY.md`. If it is not there,
add it — in this PR, with a one-line meaning and what it must not be confused
with. A concept with no agreed word is a concept you will model twice.

Never name a domain type after its mechanism. `Manager`, `Service`, `Helper`,
`Handler`, `Processor`, `Data`, `Info` and `Util` are all signs that the business
concept has not been found yet. Ask what a domain expert would call the thing.

## Make illegal states unrepresentable

This is the highest-leverage habit in the whole repo, because every state you
make impossible is a test you never have to write and a bug that cannot ship.

```rust
// no — six fields, most combinations meaningless, every reader must guess
pub struct Shipment {
    pub dispatched_at: Option<Timestamp>,
    pub delivered_at: Option<Timestamp>,
    pub failure_reason: Option<String>,
}

// yes — the type only permits real situations
pub enum Shipment {
    AwaitingDispatch,
    InTransit { dispatched: Timestamp },
    Delivered { dispatched: Timestamp, delivered: Timestamp },
    Failed { dispatched: Timestamp, reason: DeliveryFailure },
}
```

Concretely:

- **Parse, don't validate.** A constructor takes loose input and returns
  `Result<Self, Error>`. Past that boundary the value is valid by construction,
  so nothing downstream re-checks it. If you find the same `if` guarding a value
  in three places, that guard belongs in its constructor.
- **No public fields on anything with an invariant.** Private fields plus
  accessors, so the only way in is through the validating constructor.
- **Wrap primitives that carry meaning.** `EmailAddress(String)` not `String`;
  `Money { amount: i64, currency: Currency }` not `f64`. A function taking
  `(String, String, String)` is one argument transposition away from a silent
  bug; three distinct newtypes make that a compile error.
- **`Option` means genuinely optional,** never "not loaded yet" or "invalid".

## Aggregates and invariants

An aggregate is the unit of consistency: the smallest cluster of objects that
must be changed together to keep a rule true.

- Each aggregate has one root. Outside code holds a reference only to the root,
  and reaches everything else through it.
- Reference *other* aggregates by identity, never by holding the object. If a
  method needs two aggregates loaded to decide something, the boundary is wrong,
  or the decision belongs in a use case.
- Every state change goes through a method named in business language that can
  refuse: `fn withdraw(&mut self, amount: Money) -> Result<(), Overdraft>`.
  Setters cannot enforce invariants, so there are no setters.
- Keep aggregates small. A large aggregate is a contention point and a sign that
  one rule is being used to justify bundling many unrelated ones.

## Errors

Domain errors are enumerated business outcomes, not strings and not `anyhow`:

```rust
pub enum Overdraft {
    InsufficientFunds { available: Money, requested: Money },
    AccountFrozen,
}
```

Each variant carries what a caller needs to react or to explain. A domain error
that only a human can interpret has lost information the type could have kept.
`thiserror` is allowed in `application` but not here — write the `Display` impl
by hand rather than adding a dependency to the core.

## Things that must not enter this crate

Time, randomness, the filesystem, the network, environment variables, logging,
serialisation, async. Every one of them is an effect, and effects belong behind a
port. If a rule depends on "now", take the timestamp as an argument — the use
case gets it from a `Clock` port and passes it in. That single habit is what lets
domain tests run in microseconds and never flake.

`crates/architecture` enforces both halves of this mechanically. `boundaries`
reads the dependency graph; `purity` reads the source text, because effects like
`SystemTime::now()` and `std::fs` live in `std` and so need no dependency entry
to sneak in. A violation names the file, the line and what to do instead.

Test modules are not exempt. A domain test that needs the clock or the
filesystem is evidence the logic under test is not pure, which is the thing the
rule exists to catch.

## Checklist before you commit

- [ ] Every new term is in `GLOSSARY.md`
- [ ] No type name describes a mechanism rather than a business concept
- [ ] Each invariant is enforced in exactly one constructor or method
- [ ] No public field on a type with an invariant
- [ ] No `Option` standing in for "invalid" or "not loaded"
- [ ] Tests are pure, with no fixtures and no async
