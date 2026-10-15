//! The durable stores, in `PostgreSQL`.
//!
//! Two of them, sharing one pool and one migrator: the outbox this service
//! delivers from itself, and the handover a tenant's agent collects from. Bead
//! gc-g9x split them, and an adapter may not depend on another adapter, so they
//! share a crate rather than a connection across one.
//!
//! What makes the delivery promise survive the process. The port and its
//! guarantees are the same ones `memory-outbox` keeps; what is different is
//! that a restart does not lose what has not been sent, and that two replicas
//! work the same queue without sending anything twice.

mod handover;
mod outbox;
mod stored;
#[cfg(test)]
mod testing;

pub use handover::PostgresHandover;
pub use outbox::PostgresOutbox;
pub use stored::{Unreadable, read, written};
