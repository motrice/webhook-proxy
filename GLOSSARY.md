# Ubiquitous language

The vocabulary of this system. One term, one meaning, everywhere: in
conversation, in bead titles, in type names, in test names, in log messages.

This file is a hard constraint on naming, not documentation of it. An agent that
needs a word which is not here must add it in the same PR that first uses it —
and a reviewer who sees a new domain concept with no glossary entry should treat
that as the defect, ahead of anything about the code.

## Rules

- **A term means exactly one thing.** If the same word means two things in two
  contexts, those are two bounded contexts and the term needs qualifying in at
  least one of them.
- **Synonyms are forbidden.** Pick one word and delete the others. "User",
  "account" and "customer" as the same concept is the single most expensive
  naming mistake available.
- **The code spells it the same way.** A term here appears verbatim as the type,
  method or variant name — modulo Rust casing.
- **No technical nouns.** `Manager`, `Service`, `Helper`, `Data`, `Info`,
  `Handler` and `Processor` describe the solution, not the business. If no better
  name exists, the concept is not yet understood well enough to implement.

## Terms

_Empty until the first domain concept lands. The first bead that introduces a
real concept populates this table._

| Term | Meaning | Not to be confused with |
| ---- | ------- | ----------------------- |

## Bounded contexts

_Empty. Add one row per context once there is more than one, naming the
translation that happens at each boundary._

| Context | Owns | Talks to |
| ------- | ---- | -------- |
