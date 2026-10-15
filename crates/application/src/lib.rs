//! Use cases and ports.
//!
//! A *port* is a trait declared here, in the language of the domain, stating
//! what the application needs from the outside world. Adapters implement them.
//! Ports are declared by the side that *needs* them, never by the implementor —
//! that inversion is what keeps the dependency arrows pointing inward.
//!
//! A *use case* orchestrates domain objects through ports. It holds no business
//! rules of its own: if a rule can be stated without mentioning I/O, it belongs
//! in `domain`.
//!
//! Tests here use in-memory fakes of the ports, not mocks of a database.

mod backlog;
mod collect;
mod deliver;
pub mod ports;
mod relay;
mod retention;

pub use backlog::{Backlog, Outstanding};
pub use collect::{Collect, Refused as NotCollected};
pub use deliver::{Deliver, Delivered, Retry, idle_for};
pub use relay::{Refused, Relay, Relayed};
pub use retention::{Reaped, Retention};
