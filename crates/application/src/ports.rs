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
use domain::{
    Body, Correlation, DeliveryId, Destination, Dispatch, DispatchId, Event, Origin, Proof,
    Timestamp, VerifiedDelivery,
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
    /// Deliver these Events to this Destination, as one message.
    ///
    /// More than one when a sender grouped them. An implementation renders them
    /// together rather than once each: sending one message per Event would undo
    /// the grouping a sender configured deliberately, which is what bead gc-lhh
    /// decided against. Never empty.
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
    /// `correlation` is the chain the inbound call belongs to. An implementation
    /// passes it on as whatever its transport uses, having asked for a new hop:
    /// the call it makes is its own, and claiming the caller's hop would make
    /// two different calls look like one.
    async fn dispatch(
        &self,
        delivery: &DeliveryId,
        events: &[Event],
        destination: &Destination,
        attempt: Attempt,
        correlation: &Correlation,
    ) -> Result<(), DispatchFailed>;
}

/// Whether anyone at the Destination has plausibly seen this before.
///
/// Carried on the port rather than worked out by the adapter, because only the
/// application knows: an adapter sees one call and cannot tell a first send from
/// the third copy of something a person asked to be sent again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attempt {
    /// On its way for the first time.
    ///
    /// Including a retry of one that failed. A retry is the same message
    /// arriving late and nobody has seen it yet, so marking it would be noise
    /// in a room — and noise in an alert channel is the thing this product is
    /// most careful about.
    First,
    /// Sent again because somebody asked for it.
    ///
    /// A reader has probably seen this already, which is why it is marked: an
    /// alert arriving twice is how a responder learns that something got worse,
    /// and a replay that looked like one would be a lie told by a tool.
    Replay,
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

/// The store is not answering.
///
/// Separate from every other way storing can fail because the decision in
/// gc-mbr turns on it: a 202 means the Delivery is stored, so when it cannot be
/// stored the sender is refused rather than told something untrue. A caller that
/// could not tell this apart from "stored, but something else went wrong" could
/// not keep that promise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageUnavailable;

impl core::fmt::Display for StorageUnavailable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // No address, no credential, no driver message. gc-b0n has the long
        // version: database drivers put the connection string in their errors,
        // and this value is what a log line is written from.
        write!(f, "the delivery store is unavailable")
    }
}

impl std::error::Error for StorageUnavailable {}

/// What became of a Dispatch.
///
/// Three states and no fourth, which is the point: a Dispatch is waiting to be
/// tried, or it arrived, or it was given up on. There is no "failed" that is not
/// one of those — a failure either earns another attempt or ends it, and
/// collapsing them would make an abandoned Dispatch indistinguishable from one
/// still in the queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Not yet sent. Not to be tried again before this moment.
    Waiting {
        /// When it next becomes due.
        again_at: Timestamp,
    },
    /// The Destination took it.
    Delivered {
        /// When it did.
        at: Timestamp,
    },
    /// Attempted until the budget ran out, and it is a loss.
    Abandoned {
        /// When it was given up on.
        at: Timestamp,
    },
}

/// A Dispatch as the outbox holds it: what to send, and what has happened to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recorded {
    id: DispatchId,
    dispatch: Dispatch,
    attempts: u32,
    outcome: Outcome,
}

impl Recorded {
    /// Assembles what the store knows about one Dispatch.
    #[must_use]
    pub fn new(id: DispatchId, dispatch: Dispatch, attempts: u32, outcome: Outcome) -> Self {
        Self {
            id,
            dispatch,
            attempts,
            outcome,
        }
    }

    /// How the store refers to it.
    #[must_use]
    pub fn id(&self) -> &DispatchId {
        &self.id
    }

    /// What is to be sent, and where.
    #[must_use]
    pub fn dispatch(&self) -> &Dispatch {
        &self.dispatch
    }

    /// How many times it has been tried, including attempts that failed.
    #[must_use]
    pub fn attempts(&self) -> u32 {
        self.attempts
    }

    /// What became of it.
    #[must_use]
    pub fn outcome(&self) -> Outcome {
        self.outcome
    }
}

/// Where Dispatches wait until they have been sent.
///
/// The port the outbox needs. It holds what a verified Delivery *produced* — a
/// Dispatch per Event per Destination — and not the Delivery itself, which is
/// the one thing it cannot hold: a `VerifiedDelivery` exists only as the result
/// of presenting two matching proofs, and there is a `compile_fail` test
/// asserting no other way to make one. Reading one back from a store would
/// either need a constructor that forges it, or the proof kept alongside it, and
/// the proof is derived from a secret. Verification happens once, at the
/// boundary; what survives it is the intent to tell somebody something.
///
/// Nothing here decides *when* to try again or *how often* to give up. The store
/// is told the moment; the policy belongs to the use case, so that changing it
/// does not mean changing every implementation of this port.
#[async_trait]
pub trait Outbox: Send + Sync {
    /// Records everything one Delivery produced, before its sender is told.
    ///
    /// All of them or none. A Delivery whose Dispatches were half stored and
    /// then acknowledged is the failure this port exists to prevent: the sender
    /// believes it is delivered, and the Destinations that were not recorded are
    /// never attempted and never reported. An implementation that cannot do this
    /// atomically cannot implement this port.
    ///
    /// Each arrives [`Outcome::Waiting`] and due at `at`, so a Dispatch is
    /// attempted as soon as something looks rather than after a first delay.
    ///
    /// Returns what was stored, in the order given, so the caller can say what
    /// became of each without asking again. The caller sends immediately and
    /// reports the outcome; the store is what makes a failure survivable, not
    /// what makes a success slow.
    ///
    /// # Errors
    ///
    /// [`StorageUnavailable`] if nothing was stored. The caller refuses the
    /// sender; it does not fall back to sending without storing.
    async fn accept(
        &self,
        dispatches: &[Dispatch],
        at: Timestamp,
    ) -> Result<Vec<Recorded>, StorageUnavailable>;

    /// Everything accepted under this Delivery's identity, and what became of it.
    ///
    /// In the order it was accepted, because a reader comparing two runs should
    /// not have to sort them, and because the order a Delivery fanned out in is
    /// the order its rules are written in.
    ///
    /// # Errors
    ///
    /// [`StorageUnavailable`] if the store could not be asked. An identity that
    /// was never accepted is not an error; it is an empty answer.
    async fn accepted(&self, delivery: &DeliveryId) -> Result<Vec<Recorded>, StorageUnavailable>;

    /// Dispatches waiting and due to be tried, oldest first, at most `limit`.
    ///
    /// Claimed by the caller: two processes asking at once must not be handed
    /// the same Dispatch, because both would send it and a room would see it
    /// twice. The Deployment runs two replicas, so this is the normal case and
    /// not an edge one.
    ///
    /// # Errors
    ///
    /// [`StorageUnavailable`] if the store could not be asked.
    async fn due(&self, now: Timestamp, limit: usize) -> Result<Vec<Recorded>, StorageUnavailable>;

    /// It arrived.
    ///
    /// # Errors
    ///
    /// [`StorageUnavailable`] if the store could not be told. The Notice was
    /// still delivered; what is lost is the record of it, which is why the
    /// caller logs rather than retries — retrying would send it twice.
    async fn delivered(&self, id: &DispatchId, at: Timestamp) -> Result<(), StorageUnavailable>;

    /// It failed, and is worth another attempt at `again_at`.
    ///
    /// # Errors
    ///
    /// [`StorageUnavailable`] if the store could not be told.
    async fn failed(
        &self,
        id: &DispatchId,
        at: Timestamp,
        again_at: Timestamp,
    ) -> Result<(), StorageUnavailable>;

    /// It failed and will not be tried again. This is a loss.
    ///
    /// # Errors
    ///
    /// [`StorageUnavailable`] if the store could not be told.
    async fn abandoned(&self, id: &DispatchId, at: Timestamp) -> Result<(), StorageUnavailable>;
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

    /// A correlation for a call that arrived without one.
    ///
    /// A fresh chain and a first hop in it. Used when a sender sends no
    /// correlation, or sends one this code cannot make sense of: the delivery is
    /// worth more than the caller's header, so it is given a correlation rather
    /// than refused.
    ///
    /// Infallible by contract, like the identity above: there is no useful
    /// fallback for a generator that cannot generate.
    fn next_correlation(&self) -> Correlation;

    /// A new hop in a chain that already exists.
    ///
    /// What an onward call carries. Separate from [`Ids::next_correlation`]
    /// because the two mean different things to whoever reads the trace: one
    /// starts a chain, the other joins an existing one, and conflating them
    /// would make this proxy look like the origin of every call that passes
    /// through it.
    fn next_hop_in(&self, chain: &Correlation) -> Correlation;
}
