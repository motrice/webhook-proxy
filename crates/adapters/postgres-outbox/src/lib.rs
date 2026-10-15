//! The durable store, in `PostgreSQL`.
//!
//! One store: the handover a tenant's agent collects from. There were two until
//! bead gc-72e.3.2 removed the delivery loop that read the other, along with
//! the `dispatch` table it kept.
//!
//! `stored` is the Event JSON codec, and it has two consumers: the `events`
//! column here, and the claim response the tenant agent reads. An adapter may
//! not depend on another adapter, so those two consumers are the two
//! composition roots — see `crates/agent/src/platform.rs`.
//!
//! THE CRATE NAME IS NOW WRONG and is left alone on purpose. Renaming it would
//! touch every manifest and import in the workspace inside a change that is
//! already large, so it is filed as its own small job instead.

mod handover;
mod stored;
#[cfg(test)]
mod testing;

pub use handover::PostgresHandover;
pub use stored::{Unreadable, read, written};
