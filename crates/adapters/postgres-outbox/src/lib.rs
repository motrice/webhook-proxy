//! The outbox, in `PostgreSQL`.
//!
//! What makes the delivery promise survive the process. The port and its
//! guarantees are the same ones `memory-outbox` keeps; what is different is
//! that a restart does not lose what has not been sent, and that two replicas
//! work the same queue without sending anything twice.

mod stored;

pub use stored::{Unreadable, read, written};
