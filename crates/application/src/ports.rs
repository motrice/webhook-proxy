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
    Body, Correlation, DeliveryId, Destination, DestinationId, Dispatch, DispatchId, Event, Origin,
    OriginId, Proof, Timestamp, VerifiedDelivery,
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
    accepted_at: Timestamp,
}

impl Recorded {
    /// Assembles what the store knows about one Dispatch.
    #[must_use]
    pub fn new(
        id: DispatchId,
        dispatch: Dispatch,
        attempts: u32,
        outcome: Outcome,
        accepted_at: Timestamp,
    ) -> Self {
        Self {
            id,
            dispatch,
            attempts,
            outcome,
            accepted_at,
        }
    }

    /// When the store took it, which is when the sender was answered.
    ///
    /// Distinct from the moments in [`Outcome`], and the distinction is what a
    /// time query needs: those say when this proxy last did something about a
    /// Dispatch, this says when the sender sent it. A reader asking what arrived
    /// yesterday means the latter.
    #[must_use]
    pub fn accepted_at(&self) -> Timestamp {
        self.accepted_at
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

/// Which moments a query is interested in.
///
/// Both ends optional, so one shape serves "the most recent" and "between these
/// times" without a second method. Unbounded is the common case: the first
/// useful question about an outbox is what just happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Window {
    /// Nothing accepted before this moment.
    pub from: Option<Timestamp>,
    /// Nothing accepted after it.
    pub to: Option<Timestamp>,
}

/// How much of an answer to return, and where to carry on from.
///
/// Part of the port rather than bolted on later, because an outbox grows
/// without bound: a query with no limit is a query that works in testing and
/// takes a process down in a year. `after` is the last identity a caller
/// already has, not an offset — an offset shifts under a concurrent write and
/// silently skips a row, which for an audit answer is worse than a repeat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    /// At most this many.
    pub limit: usize,
    /// Carry on after this one, if a caller has been here before.
    pub after: Option<DispatchId>,
}

/// What arrived, and where it went.
///
/// The read side of the store, declared in the domain's vocabulary rather than
/// in a transport's: the questions worth asking are the same whether they come
/// over HTTP, from a command, or from a test, and declaring them here is what
/// stops the answers being shaped by what was convenient to serialise.
///
/// EVERY QUERY IS SCOPED BY ROOM, and that is not a convenience. Bead gc-mnn
/// decided a reader may see what the rooms named for it received, so the rooms
/// arrive as an argument and an implementation returns nothing outside them. A
/// port that returned everything and left filtering to its caller would put an
/// authorisation decision in an adapter, where forgetting it is a leak with no
/// test to catch it. An empty slice therefore answers empty: a reader with no
/// rooms is a reader who sees nothing, not a reader who sees all of it.
///
/// Nothing here can return a payload, an address or a credential, and that is
/// structural rather than careful: a [`Recorded`] carries a Dispatch, a
/// Dispatch carries a Destination, and a Destination is a name with no address.
/// The request body is never stored at all.
#[async_trait]
pub trait Archive: Send + Sync {
    /// What arrived, most recent first.
    ///
    /// # Errors
    ///
    /// [`StorageUnavailable`] if the store could not be asked.
    async fn arrived(
        &self,
        rooms: &[DestinationId],
        window: Window,
        page: &Page,
    ) -> Result<Vec<Recorded>, StorageUnavailable>;

    /// Where one Delivery went, and what became of it in each room.
    ///
    /// Empty when nothing is stored under that identity, which is deliberately
    /// indistinguishable from never having been accepted. Retention is one month
    /// (gc-mnn), so "it was here last quarter" and "it was never here" are the
    /// same answer, and a reader must not be able to tell a room it may not see
    /// from a delivery that does not exist.
    ///
    /// # Errors
    ///
    /// [`StorageUnavailable`] if the store could not be asked.
    async fn went(
        &self,
        delivery: &DeliveryId,
        rooms: &[DestinationId],
    ) -> Result<Vec<Recorded>, StorageUnavailable>;

    /// What has not been delivered yet, most recent first.
    ///
    /// Everything still [`Outcome::Waiting`] — owed, not lost. An abandoned
    /// Dispatch is a loss and is reported by the counters and the log, not here:
    /// a reader asking what is outstanding wants the queue, not the history.
    ///
    /// # Errors
    ///
    /// [`StorageUnavailable`] if the store could not be asked.
    async fn waiting(
        &self,
        rooms: &[DestinationId],
        page: &Page,
    ) -> Result<Vec<Recorded>, StorageUnavailable>;
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

/// Which tenant an alert belongs to, and therefore whose agent may collect it.
///
/// HERE AND NOT IN THE DOMAIN, by bead gc-g9x's decision. The domain models
/// facts a sender reported and where they should go; a tenant is about who may
/// claim what, which is authorisation. Putting it in `domain` would have made
/// every domain value carry a notion of ownership forever, and would have put
/// an authorisation concept in the one crate with no dependencies and no way to
/// check one.
///
/// A DNS LABEL, not any string, and the restriction earns its place rather than
/// being tidiness. In this platform a tenant *is* a namespace (bead gc-81d), so
/// the value in the configuration file is compared against the namespace in a
/// caller's identity. `Platform` and `platform` would then be two tenants that
/// look like one, and the symptom would be an agent that authenticates
/// successfully and is offered nothing — the hardest failure in this design to
/// diagnose, because every part of it reports success. Refusing the spelling
/// that cannot match is the cheapest place to stop it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TenantId(String);

impl TenantId {
    /// Names a tenant.
    ///
    /// # Errors
    ///
    /// [`NotATenant`] if this is not a name a namespace could have, and so not
    /// a name a caller's identity could ever present.
    pub fn new(id: &str) -> Result<Self, NotATenant> {
        if id.is_empty() {
            return Err(NotATenant::Blank);
        }
        // 63 is the limit on a DNS label, which is what a namespace name is.
        if id.len() > 63 {
            return Err(NotATenant::TooLong);
        }
        let labelled = id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        if !labelled || id.starts_with('-') || id.ends_with('-') {
            return Err(NotATenant::NotALabel);
        }
        Ok(Self(id.to_owned()))
    }

    /// The name as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TenantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why a name cannot be a tenant's.
///
/// Three variants rather than one, because each is a different mistake and the
/// configuration error naming the field is the whole operator experience of a
/// bad deploy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotATenant {
    /// Nothing was written.
    Blank,
    /// Not a name a namespace could have.
    NotALabel,
    /// Longer than a DNS label may be.
    TooLong,
}

impl std::fmt::Display for NotATenant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Blank => f.write_str("is empty"),
            Self::NotALabel => f.write_str(
                "is not a name a namespace could have; a tenant is a namespace here, \
                 so it is lowercase letters, digits and dashes, not starting or \
                 ending with a dash",
            ),
            Self::TooLong => {
                f.write_str("is longer than the 63 characters a namespace name may be")
            }
        }
    }
}

impl std::error::Error for NotATenant {}

/// A verified Delivery waiting for its tenant to collect it.
///
/// THE UNIT IS A DELIVERY AND NOT AN EVENT, which bead gc-g9x found was forced
/// rather than chosen: gc-lhh and gc-smz decided that a sender grouping twenty
/// alerts into one notification gets one message per room, and whoever delivers
/// can only honour that if it receives the Events of one Delivery together.
///
/// NO DESTINATION, and this is the shape of the whole split. The platform
/// cannot know a tenant's rooms — routing is the tenant's, in its own
/// repository — so what is stored is what arrived and whose it is, never where
/// it is going. Compare [`Recorded`], which carries a Dispatch and therefore a
/// Destination: that is the model the platform keeps for its own delivery loop,
/// and this is the model it keeps for somebody else's.
///
/// WHAT THIS CANNOT CARRY IS STRUCTURAL RATHER THAN CAREFUL. It holds an
/// `OriginId`, a name, and not an `Origin`, which carries the `Verification`
/// that holds a sender's secret. Bead gc-81d forbids this interface returning a
/// secret value *or a secret name*, and the way to keep that true is for the
/// type handed over to have no field one could be in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offered {
    delivery: DeliveryId,
    tenant: TenantId,
    origin: OriginId,
    events: Vec<Event>,
    correlation: Correlation,
    accepted_at: Timestamp,
}

impl Offered {
    /// What arrived, and whose it is.
    ///
    /// `None` when there are no Events, for the reason [`Dispatch::new`] gives:
    /// a Delivery that translated to nothing is not an error and is not a
    /// failure to report, it is simply nothing to hand over. A sender telling us
    /// about something we do not care about must not leave a row its tenant can
    /// never discharge.
    #[must_use]
    pub fn new(
        delivery: DeliveryId,
        tenant: TenantId,
        origin: OriginId,
        events: Vec<Event>,
        correlation: Correlation,
        accepted_at: Timestamp,
    ) -> Option<Self> {
        if events.is_empty() {
            return None;
        }
        Some(Self {
            delivery,
            tenant,
            origin,
            events,
            correlation,
            accepted_at,
        })
    }

    /// Which Delivery this was, which is how a report refers to it.
    #[must_use]
    pub fn delivery(&self) -> &DeliveryId {
        &self.delivery
    }

    /// Whose it is.
    #[must_use]
    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// Who sent it, as a name.
    #[must_use]
    pub fn origin(&self) -> &OriginId {
        &self.origin
    }

    /// What it reported, together and in the order the sender reported them.
    #[must_use]
    pub fn events(&self) -> &[Event] {
        &self.events
    }

    /// The chain it arrived on, so whoever delivers continues it rather than
    /// starting a new one.
    #[must_use]
    pub fn correlation(&self) -> &Correlation {
        &self.correlation
    }

    /// When the store took it, which is when the sender was answered.
    #[must_use]
    pub fn accepted_at(&self) -> Timestamp {
        self.accepted_at
    }
}

/// Where a verified Delivery waits for the tenant it belongs to.
///
/// Named for the thing that is actually new: a hand-off across a trust
/// boundary. [`Outbox`] is where this service's own delivery loop keeps work it
/// will attempt itself; this is where it keeps work somebody else will attempt,
/// in another namespace, under another team's control, possibly never. The two
/// are not the same port with a different column, because the unit differs — a
/// Dispatch there, a Delivery here — and so does who is owed.
///
/// WHAT IS NOT HERE YET, deliberately. There is no claim, no lease and no
/// report: bead gc-wcw.1 builds the record and bead gc-wcw.2 builds the
/// interface to it. `outstanding` exists so that what was written can be read
/// back and tested, and because the count it answers is what bead gc-wcw.3 will
/// need in order to log a tenant that has stopped collecting.
///
/// EVERY METHOD IS SCOPED BY TENANT, for the reason [`Archive`] is scoped by
/// room: a port that answered everything and left the filtering to its caller
/// would put an authorisation decision in an adapter, where forgetting it is a
/// leak with no test to catch it. Here it would be the exact leak this whole
/// split exists to prevent.
#[async_trait]
pub trait Handover: Send + Sync {
    /// Records one Delivery as owed to its tenant.
    ///
    /// Before the sender is told anything, so a `202` means what bead gc-g9x
    /// restated it to mean: stored, and will be offered to its tenant.
    ///
    /// # Errors
    ///
    /// [`StorageUnavailable`] if nothing was stored. The caller refuses the
    /// sender rather than accepting something it cannot hand over.
    async fn offer(&self, offered: &Offered) -> Result<(), StorageUnavailable>;

    /// What this tenant has not yet discharged, oldest first, at most `limit`.
    ///
    /// Oldest first because that is the order it should be collected in, and
    /// `limit` because an outstanding queue grows without bound when nobody
    /// collects — which is precisely the case this has to survive reporting on.
    ///
    /// Not a claim. Nothing is leased, nothing is hidden from a second caller,
    /// and two callers asking at once get the same answer. The claim that must
    /// not do that is bead gc-wcw.2's.
    ///
    /// # Errors
    ///
    /// [`StorageUnavailable`] if the store could not be asked. A tenant that
    /// has nothing outstanding is not an error; it is an empty answer.
    async fn outstanding(
        &self,
        tenant: &TenantId,
        limit: usize,
    ) -> Result<Vec<Offered>, StorageUnavailable>;
}

#[cfg(test)]
mod tenant_tests {
    use super::{NotATenant, TenantId};

    #[test]
    fn a_namespace_name_is_a_tenant() {
        // The names this platform actually uses, from its own terraform.tfvars.
        for name in ["wallet-lab-prod", "wallet-hsm-prod", "platform", "t7"] {
            assert_eq!(
                TenantId::new(name).map(|id| id.as_str().to_owned()),
                Ok(name.to_owned()),
                "{name} is a namespace name and must be a usable tenant"
            );
        }
    }

    #[test]
    fn a_spelling_no_namespace_could_have_is_refused() {
        // Each of these authenticates fine and is offered nothing, because the
        // namespace in a caller's identity can never equal it. Refusing it in
        // the configuration file is the only place the mistake is cheap.
        assert_eq!(TenantId::new(""), Err(NotATenant::Blank));
        assert_eq!(TenantId::new("Platform"), Err(NotATenant::NotALabel));
        assert_eq!(TenantId::new("wallet_lab_prod"), Err(NotATenant::NotALabel));
        assert_eq!(TenantId::new("wallet lab"), Err(NotATenant::NotALabel));
        assert_eq!(TenantId::new("-lab"), Err(NotATenant::NotALabel));
        assert_eq!(TenantId::new("lab-"), Err(NotATenant::NotALabel));
        assert_eq!(TenantId::new(&"a".repeat(64)), Err(NotATenant::TooLong));
        assert!(TenantId::new(&"a".repeat(63)).is_ok(), "63 is the limit");
    }

    #[test]
    fn each_refusal_says_which_mistake_it_was() {
        // The message is the operator experience of a bad deploy, so it is worth
        // a test that it says something specific rather than something true.
        assert!(
            NotATenant::NotALabel.to_string().contains("namespace"),
            "a refusal that does not say a tenant is a namespace leaves the \
             reader to guess what spelling is wanted: {}",
            NotATenant::NotALabel
        );
        assert!(NotATenant::TooLong.to_string().contains("63"));
    }
}

#[cfg(test)]
mod offered_tests {
    use super::{Offered, TenantId};
    use domain::{
        BranchName, Correlation, DeliveryId, Event, OriginId, Pusher, RepositoryName, Timestamp,
    };

    fn an_event() -> Event {
        Event::PushedCommits {
            repository: RepositoryName::new("webhook-proxy").expect("a name"),
            branch: BranchName::new("main").expect("a name"),
            pusher: Pusher::new("bjorn").expect("a name"),
            commits: vec![],
            permalink: None,
        }
    }

    fn a_correlation() -> Correlation {
        Correlation::new("4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7", None)
            .expect("a chain")
    }

    #[test]
    fn a_delivery_that_reported_nothing_is_not_offered() {
        // The counterpart of Dispatch::new's refusal. A sender telling us about
        // something we do not care about is success, and it must not leave a row
        // behind that its tenant can never discharge: nobody can report rooms
        // for a Delivery with no facts in it, so the queue would never drain.
        assert_eq!(
            Offered::new(
                DeliveryId::new("d-1").expect("an identity"),
                TenantId::new("platform").expect("a tenant"),
                OriginId::new("github").expect("a name"),
                Vec::new(),
                a_correlation(),
                Timestamp::from_millis_since_epoch(1),
            ),
            None
        );
    }

    #[test]
    fn what_is_offered_is_what_arrived_and_whose_it_is() {
        let offered = Offered::new(
            DeliveryId::new("d-1").expect("an identity"),
            TenantId::new("wallet-lab-prod").expect("a tenant"),
            OriginId::new("alertmanager").expect("a name"),
            vec![an_event()],
            a_correlation(),
            Timestamp::from_millis_since_epoch(7),
        )
        .expect("one event is enough");

        assert_eq!(offered.tenant().as_str(), "wallet-lab-prod");
        assert_eq!(offered.origin().as_str(), "alertmanager");
        assert_eq!(offered.events().len(), 1);
        assert_eq!(offered.accepted_at(), Timestamp::from_millis_since_epoch(7));
        // The chain arrives with it, so whoever delivers continues it rather
        // than starting one and breaking the trace at the hand-off.
        assert_eq!(offered.correlation().trace(), a_correlation().trace());
    }
}
