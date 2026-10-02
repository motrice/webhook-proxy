//! Composition root. The only crate permitted to name a concrete adapter.
//!
//! Everything here is wiring: read configuration, construct adapters, inject
//! them into use cases, start the inbound adapter. No business logic, and
//! therefore nothing here needs a unit test — it is covered by the
//! acceptance tests that drive the real binary.

fn main() {
    println!("composition root: no adapters wired yet");
}
