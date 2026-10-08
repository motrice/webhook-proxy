//! What the application needs from the outside world, stated as what it needs
//! rather than as what will provide it.
//!
//! Every port requires `Send + Sync`. These are driven from an HTTP server that
//! handles requests concurrently, so a port that could not cross a thread would
//! be unusable in the only place it is ever used — and the compiler would report
//! it as an inscrutable "handler does not implement Handler" rather than as the
//! design mistake it is.
//!
//! Every trait here is declared by the side that *needs* the capability, never
//! by the side that implements it. That inversion is the whole mechanism: it is
//! why `crates/architecture` can prove the arrows point inward, and why these
//! can be driven by twenty-line fakes in a test.

use async_trait::async_trait;
use domain::{Body, DeliveryId, Destination, Event, Origin, Proof, Timestamp, VerifiedDelivery};

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
pub trait Proofs: Send + Sync {
    /// The signature this Origin's secret produces over these bytes.
    ///
    /// # Errors
    ///
    /// [`SecretUnavailable`] if the Origin's secret cannot be obtained. This is
    /// deliberately not the same outcome as a mismatch: one means we could not
    /// check, the other means we checked and it was wrong.
    fn expected(&self, origin: &Origin, body: &Body) -> Result<Proof, SecretUnavailable>;

    /// Read the signature a sender claimed, from whatever it presented.
    ///
    /// The application knows that a sender presents *something*; only the
    /// adapter knows how that something is spelled. Taking the presented value
    /// as text keeps the scheme — a prefix, an encoding, a digest length — on
    /// the adapter's side of the boundary.
    ///
    /// This lives on the same port as `expected` because reading a signature and
    /// computing one are halves of a single scheme. Splitting them would leave
    /// an inbound adapter needing to depend on a signature adapter, which the
    /// architecture test forbids and which would be wrong anyway.
    ///
    /// # Errors
    ///
    /// [`MalformedProof`] if the value is not a signature we can compare.
    /// Distinct from a mismatch: the sender presented nothing usable, so no
    /// comparison was possible.
    fn claimed(&self, presented: &str) -> Result<Proof, MalformedProof>;
}

/// A sender presented something that is not a signature we can compare.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MalformedProof {
    /// The scheme is absent or not one we recognise.
    UnknownScheme,
    /// The scheme was recognised, but the value could not be read.
    Unreadable,
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
pub trait Translator: Send + Sync {
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
pub trait Dispatcher: Send + Sync {
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
    /// Something that is not the Destination answered, and said yes.
    ///
    /// A success status whose body is not the Destination's own. Something on
    /// the path — a proxy, a web application firewall — answered on its behalf,
    /// so the Notice was not delivered and the Destination never saw it.
    ///
    /// Distinct from [`Self::Rejected`] because the difference is the whole
    /// value of knowing: an operator told a Dispatch was refused will go and
    /// read the Destination's logs, and find no trace of a request that never
    /// arrived.
    Intercepted,
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
pub trait Clock: Send + Sync {
    /// The current moment.
    fn now(&self) -> Timestamp;
}

/// Fresh identities.
pub trait Ids: Send + Sync {
    /// A Delivery identity that has not been used before.
    ///
    /// Infallible by contract: an implementation that cannot produce a usable
    /// identity has no sensible fallback, and a blank one is rejected by
    /// `DeliveryId` anyway.
    fn next_delivery_id(&self) -> DeliveryId;
}
