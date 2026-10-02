//! The domain. Pure logic, ubiquitous language, invariants.
//!
//! Rules enforced by `crates/architecture`:
//! - zero dependencies, including no `serde`, no `tokio`, no `anyhow`
//! - no `std::fs`, `std::net`, `std::time::SystemTime`, no randomness
//! - every type makes illegal states unrepresentable; constructors validate
//!   and return `Result`, so an existing value is always a valid value
//!
//! Terms used here MUST appear in `GLOSSARY.md` with the same meaning.
//! Tests for this crate are unit tests in-module; they need no fixtures,
//! no I/O and no async, which is what makes the TDD loop fast.

mod delivery;
mod event;
mod origin;
mod routing;
mod signature;

pub use delivery::{Body, Delivery, VerifiedDelivery};
pub use event::{Blank, BranchName, Commit, CommitId, Event, Pusher, RepositoryName, Summary};
pub use origin::{Origin, OriginId, SecretId};
pub use routing::{
    Destination, DestinationId, DestinationKind, Filter, Subscription, destinations_for,
};
pub use signature::{Signature, SignatureMismatch};
