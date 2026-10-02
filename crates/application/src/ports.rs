//! What the application needs from the outside world, stated as what it needs
//! rather than as what will provide it.
//!
//! Every trait here is declared by the side that *needs* the capability, never
//! by the side that implements it. That inversion is the whole mechanism: it is
//! why `crates/architecture` can prove the arrows point inward, and why these
//! can be driven by twenty-line fakes in a test.

use async_trait::async_trait;
use domain::{
    Body, DeliveryId, Destination, Event, Origin, Signature, Timestamp, VerifiedDelivery,
};

/// The signature an Origin's secret produces over a body.
///
/// The port computes; the domain decides. `Delivery::verify` compares a claimed
/// signature against a computed one and is the only way to obtain a
/// `VerifiedDelivery`, so the security decision stays in the crate with no
/// dependencies while the arithmetic lives in an adapter.
///
/// Nothing here names a header, an encoding or an algorithm. An implementation
/// that needed to would be telling you it is a transport detail wearing a port's
/// clothes.
pub trait Signatures {
    /// The signature this Origin's secret produces over these bytes.
    ///
    /// # Errors
    ///
    /// [`SecretUnavailable`] if the Origin's secret cannot be obtained. This is
    /// deliberately not the same outcome as a mismatch: one means we could not
    /// check, the other means we checked and it was wrong.
    fn expected(&self, origin: &Origin, body: &Body) -> Result<Signature, SecretUnavailable>;
}

/// An Origin's secret could not be obtained, so no judgement was possible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecretUnavailable;

/// Turns a verified Delivery into the Events it reports.
///
/// A port rather than a step the inbound adapter takes on its own, so that the
/// use case controls *when* translation happens: only after a signature has
/// matched. Parsing bytes nobody has authenticated is a choice, and this makes
/// it impossible to take by accident.
///
/// The implementation lives in the adapter for each Origin, because mapping a
/// foreign payload onto an `Event` is exactly the anti-corruption layer.
pub trait Translator {
    /// The Events this Delivery reports.
    ///
    /// An empty result is success: a Delivery describing something we do not
    /// care about is not an error, and we are not the sender's error reporter.
    ///
    /// # Errors
    ///
    /// [`Untranslatable`] if the payload cannot be read at all.
    fn events(&self, delivery: &VerifiedDelivery) -> Result<Vec<Event>, Untranslatable>;
}

/// A Delivery's payload could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Untranslatable;

/// Tell one Destination about one Event.
///
/// Async because this is the only port that crosses a network. The others are
/// synchronous on purpose: a Clock that must be awaited buys nothing and costs
/// every caller.
#[async_trait]
pub trait Dispatcher {
    /// Deliver this Event to this Destination.
    ///
    /// The `delivery` identity is passed so an implementation can correlate its
    /// own logs with the inbound Delivery, and so a loss can be reported against
    /// something nameable.
    ///
    /// # Errors
    ///
    /// [`DispatchFailed`] in the Destination's terms. An implementation must
    /// translate its transport's failures into these before returning: a status
    /// code or a client-library error reaching the use case would mean the
    /// adapter had leaked.
    async fn dispatch(
        &self,
        delivery: &DeliveryId,
        event: &Event,
        destination: &Destination,
    ) -> Result<(), DispatchFailed>;
}

/// Why a Dispatch did not arrive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchFailed {
    /// The Destination was reached and would not accept it.
    Rejected,
    /// The Destination could not be reached.
    Unreachable,
    /// The Destination did not answer in time.
    TimedOut,
}

/// What time it is.
///
/// A port because reading the clock is an effect, and `purity` fails the build
/// if the domain or this crate tries it directly. A fixed implementation in a
/// test is what makes these tests fast and never flaky.
pub trait Clock {
    /// The current moment.
    fn now(&self) -> Timestamp;
}

/// Fresh identities.
pub trait Ids {
    /// A Delivery identity that has not been used before.
    ///
    /// Infallible by contract: an implementation that cannot produce a usable
    /// identity has no sensible fallback, and a blank one is rejected by
    /// `DeliveryId` anyway.
    fn next_delivery_id(&self) -> DeliveryId;
}
