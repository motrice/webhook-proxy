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
    Body, Correlation, DeliveryId, Destination, DestinationId, Event, Origin, OriginId, Proof,
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

impl DispatchFailed {
    /// How this reason is written down, everywhere it is written down.
    ///
    /// ONE SPELLING FOR FOUR AUDIENCES: the stored report row, the wire format
    /// an agent sends, the word the platform reads back, and the `reason` label
    /// on the metric the platform exports (bead gc-556). Shared rather than
    /// written out per adapter so an operator who sees `unreachable` in a
    /// dashboard can grep the database for the same word, and so a rename can
    /// only happen deliberately and in one place.
    ///
    /// Not `Debug`. These four words are a published interface — a stored row
    /// somebody will read next year and a series somebody has alerted on — and
    /// renaming a Rust variant must not silently rename them.
    #[must_use]
    pub const fn spelled(self) -> &'static str {
        match self {
            Self::Rejected => "rejected",
            Self::Intercepted => "intercepted",
            Self::Unreachable => "unreachable",
            Self::TimedOut => "timed_out",
        }
    }
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
/// it is going. There used to be a second model beside this one, carrying a
/// Dispatch and therefore a Destination, for work this service delivered
/// itself; bead gc-72e.3.2 removed it, because this service no longer delivers
/// anything.
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

/// A Delivery handed to a tenant's agent, and until when.
///
/// The lease belongs to the platform and is returned rather than assumed, which
/// bead gc-81d decided for a plain reason: with two binaries that could
/// disagree about its length, one of them has to own it. Not renewable in this
/// version — an agent's whole retry budget is about half a minute, so five
/// minutes covers it, and renewal would let an agent hold work indefinitely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claimed {
    offered: Offered,
    until: Timestamp,
    replayed: bool,
}

impl Claimed {
    /// Hands one over, leased until `until`.
    ///
    /// `replayed` is a property of THIS OFFERING and not of the Delivery: the
    /// same Delivery is a first delivery once and a replay afterwards, if
    /// somebody asks for one.
    #[must_use]
    pub fn new(offered: Offered, until: Timestamp, replayed: bool) -> Self {
        Self {
            offered,
            until,
            replayed,
        }
    }

    /// Whether a person asked for this to be sent again.
    ///
    /// Carried so a room can show it. Bead gc-6a5.3 decided that marking
    /// deliberately: an alert arriving twice is how a responder learns
    /// something got worse, so a replay that looked like a retry would be a lie
    /// told by a tool.
    #[must_use]
    pub fn replayed(&self) -> bool {
        self.replayed
    }

    /// What was claimed.
    #[must_use]
    pub fn offered(&self) -> &Offered {
        &self.offered
    }

    /// When the claim lapses and it is offered again.
    #[must_use]
    pub fn until(&self) -> Timestamp {
        self.until
    }
}

/// What one room did with a Delivery, as its tenant reports it.
///
/// Two states and no third, because a report is TERMINAL. There is no "still
/// trying": an agent that has not finished has not reported, and the lease is
/// what covers that gap. Nor is there a "give up" an agent can ask the platform
/// for — bead gc-g9x refused to let either side abandon on the other's behalf,
/// and a third variant here would be inventing exactly that state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoomOutcome {
    /// It arrived.
    Delivered,
    /// Every attempt was spent and it did not arrive. This is a loss.
    ///
    /// CARRIES THE REASON, AND NOT OPTIONALLY. A tenant reporting an
    /// abandonment must say why, because the four [`DispatchFailed`] variants
    /// are not interchangeable to whoever has to act on one: `Rejected` means a
    /// room refused and somebody has to change a configuration, `Intercepted`
    /// means something on the path answered on the room's behalf and the room
    /// never saw it, `Unreachable` and `TimedOut` mean the room or the network.
    /// That distinction is already load-bearing in `DispatchFailed`'s own
    /// documentation, and collapsing it here would throw away the thing an
    /// operator needs (bead gc-556).
    ///
    /// An enum variant rather than a field, so it cannot be left out: a report
    /// that said "abandoned" and nothing else could not be made at all.
    Abandoned(DispatchFailed),
}

/// The terminal statement about one Delivery, which discharges the platform's
/// obligation to offer it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Report {
    /// Every room this Delivery reached, and what each did.
    Reached(Vec<(DestinationId, RoomOutcome)>),
    /// The tenant's rules matched no room at all.
    ///
    /// TERMINAL AND NOT AN ERROR, which bead gc-g9x found was forced: a tenant
    /// whose rules match nothing has nothing to report, so without this the
    /// platform's queue never drains and a correctly-behaving tenant is
    /// indistinguishable from a dead one.
    ///
    /// A variant rather than an empty [`Self::Reached`], and the difference is
    /// the point: an agent that forgot to fill the list in is the likeliest bug
    /// here, and an empty vector would make that bug and a genuine no-match the
    /// same statement. This one has to be said on purpose.
    RoutedToNothing,
}

/// A Delivery retention deleted that no tenant ever collected.
///
/// A LOSS, and the whole reason this type exists rather than the sweep
/// returning a number. Bead gc-g9x enumerated three kinds of loss and this is
/// the third: without it the one-month sweep is a quiet shredder, and gc-vfz's
/// argument was that an invisible loss is indistinguishable from a working
/// system.
///
/// TEXT RATHER THAN DOMAIN VALUES, and the reason is the sweep's reliability
/// rather than convenience. This is a report destined for a log, and a sweep
/// that could fail to parse a row it is deleting would stop working on exactly
/// the row most worth reporting — a tenant whose name this build no longer
/// reads is precisely the case somebody needs told about.
///
/// NO EVENTS. What a loss report must name is what was lost and whose, never
/// what it said: an Event carries an alert's summary and labels, which is other
/// people's words and has no place in a log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uncollected {
    /// Which Delivery, so the loss can be traced to the request that made it.
    pub delivery: String,
    /// Whose it was. The tenant whose agent never came for it.
    pub tenant: String,
    /// Who sent it, as a name.
    pub origin: String,
    /// The chain it arrived on, so a reader can follow it back to the sender's
    /// own log — which with no read API is the only way to learn what was in it.
    pub trace: String,
    /// When the sender was told it had been accepted.
    pub accepted_at: Timestamp,
}

/// What one pass of retention removed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Swept {
    /// Rows whose tenant had reported them. Not losses: the obligation was
    /// discharged before retention reached them.
    pub settled: usize,
    /// Rows no tenant ever collected. Every one of these is a loss.
    pub uncollected: Vec<Uncollected>,
}

/// A tenant that has stopped keeping up, and by how much.
///
/// THE ONLY WAY ANYBODY LEARNS AN AGENT HAS STOPPED, in a version with no read
/// API. Bead gc-g9x refused to let the platform invent "abandoned on the
/// tenant's behalf" — it keeps offering — so what it owes instead is this: a
/// count and an age, logged and exported, for a tenant whose work is piling up.
///
/// Text for the tenant, for the reason [`Uncollected`] gives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Behind {
    /// Whose backlog this is.
    pub tenant: String,
    /// How many Deliveries are outstanding and older than the threshold asked
    /// about.
    pub outstanding: usize,
    /// The oldest one's acceptance, which is the number an operator acts on: a
    /// count alone cannot distinguish a busy tenant from a stopped one.
    pub oldest: Timestamp,
}

/// Whether a re-offer found a Delivery to offer again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reoffered {
    /// It is owed to its tenant again, marked as a replay.
    Owed,
    /// Nothing goes by that identity any more.
    ///
    /// One answer for two cases, and here that is a kindness rather than a
    /// precaution: an operator cannot tell a Delivery that never existed from
    /// one retention has already deleted, and both mean the same thing — there
    /// is nothing left to send again.
    NotStored,
}

/// Whether a report discharged anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Discharged {
    /// It was outstanding for this tenant, and now it is not.
    Settled,
    /// Nothing outstanding for this tenant goes by that identity.
    ///
    /// ONE ANSWER FOR THREE CASES, deliberately: the Delivery belongs to
    /// another tenant, or it was already reported, or it never existed. A
    /// caller that could tell them apart could ask after another tenant's
    /// Delivery identities and learn which exist.
    NotOutstanding,
}

/// Where a verified Delivery waits for the tenant it belongs to.
///
/// Named for the thing that was actually new when it arrived: a hand-off across
/// a trust boundary. It is where this service keeps work SOMEBODY ELSE will
/// attempt, in another namespace, under another team's control, possibly never.
///
/// It is now the only store. There used to be an `Outbox` beside it holding
/// work this service attempted itself, one Dispatch per room; bead gc-72e.3.2
/// removed it with the delivery loop that read it. The two were never the same
/// port with a different column — the unit differed, and so did who was owed.
///
/// WHAT IS NOT HERE YET, deliberately. There is no claim, no lease and no
/// report: bead gc-wcw.1 builds the record and bead gc-wcw.2 builds the
/// interface to it. `outstanding` exists so that what was written can be read
/// back and tested, and because the count it answers is what bead gc-wcw.3 will
/// need in order to log a tenant that has stopped collecting.
///
/// EVERY METHOD THAT SERVES A REQUEST IS SCOPED BY TENANT. A port that answered
/// everything and left the filtering to its caller would put an authorisation
/// decision in an adapter, where forgetting it is a leak with no test to catch
/// it — and here it would be the exact leak this whole split exists to prevent.
///
/// The exceptions are the two methods no request can reach: [`Self::behind`],
/// which answers an operator's gauge, and [`Self::reoffer`], which answers an
/// operator's command. Each says so where it is declared.
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

    /// Hands this tenant up to `limit` of its own Deliveries, leased for
    /// `lease` from `now`, oldest first.
    ///
    /// CLAIMED, which `outstanding` is not: two agents asking at once must not
    /// be handed the same Delivery, because both would deliver it and a room
    /// would see it twice. Unlike [`Outbox::due`], the claimant is not another
    /// replica of this binary — it is a pod in somebody else's namespace that
    /// may never come back — which is why the lease is this side's and why a
    /// claim lapses rather than being released.
    ///
    /// # Errors
    ///
    /// [`StorageUnavailable`] if the store could not be asked. A tenant with
    /// nothing to collect is not an error; it is an empty answer.
    async fn claim(
        &self,
        tenant: &TenantId,
        limit: usize,
        now: Timestamp,
        lease: core::time::Duration,
    ) -> Result<Vec<Claimed>, StorageUnavailable>;

    /// Records this tenant's terminal statement about one of its Deliveries.
    ///
    /// SCOPED BY TENANT LIKE EVERY OTHER METHOD HERE, and it would be easy to
    /// think the identity is enough on its own: a `DeliveryId` is random, so
    /// guessing one is not a practical attack. It is still an argument, because
    /// authorisation that depends on an identifier being hard to guess is not
    /// authorisation — and because the identity travels, in a trace, in a log
    /// line, in a room message.
    ///
    /// # Errors
    ///
    /// [`StorageUnavailable`] if the store could not be told. Reporting again
    /// is safe and answers [`Discharged::NotOutstanding`]: an agent whose
    /// report was lost on the way back must be able to send it again, and the
    /// alternative — an error — would make a retry look like a fault.
    async fn report(
        &self,
        tenant: &TenantId,
        delivery: &DeliveryId,
        report: &Report,
        at: Timestamp,
    ) -> Result<Discharged, StorageUnavailable>;

    /// Removes everything accepted before `accepted_before`, and says what was
    /// lost doing it.
    ///
    /// UNCOLLECTED ROWS GO TOO, which departs from bead gc-mnn's "never delete
    /// a row still waiting, however old" — and the departure is deliberate,
    /// recorded on both beads. That rule was written about the [`Outbox`],
    /// where a waiting row is an attempt *this service* still owes and will
    /// make, so deleting it discharges an obligation silently. A row here is
    /// owed by a tenant that may never return, and keeping it forever
    /// reintroduces exactly the unbounded retention of other people's alert
    /// text gc-mnn rejected — through a side door, for the rows most likely to
    /// pile up. So it is deleted, and bead gc-g9x's requirement does the work
    /// gc-mnn's was reaching for: every such deletion is reported here so the
    /// caller can log and count it as the loss it is.
    ///
    /// Nothing is deleted on the caller's behalf quietly: an implementation
    /// that returned a count instead of the rows would make this a shredder
    /// with a number attached.
    ///
    /// # Errors
    ///
    /// [`StorageUnavailable`] if the store could not be asked. Nothing was
    /// deleted in that case — the caller tries again on the next pass rather
    /// than having to reconcile a half-finished sweep.
    async fn sweep(&self, accepted_before: Timestamp) -> Result<Swept, StorageUnavailable>;

    /// Offers one Delivery again, marked as a replay, whoever it belongs to.
    ///
    /// THE ONE METHOD HERE WITH NO TENANT, and the exception has a reason.
    /// Every other method serves a request and is scoped because the caller
    /// must only ever see its own. This serves an operator who already has the
    /// database in front of them, running `webhook-proxy replay` on a Delivery
    /// identity out of a log line — scoping it would mean asking them for a
    /// tenant they would have to look up from the thing they are already
    /// holding.
    ///
    /// NOTHING REACHABLE FROM AN HTTP HANDLER MAY CALL THIS. It is the one hole
    /// in the isolation the rest of this port exists to keep, and the thing
    /// that makes it safe is that it has no route — not that it checks
    /// anything.
    ///
    /// A Delivery still outstanding is offered again anyway and the flag is
    /// set: an operator asking for a replay of something nobody has collected
    /// yet means the marking, not the offering.
    ///
    /// # Errors
    ///
    /// [`StorageUnavailable`] if the store could not be told.
    async fn reoffer(&self, delivery: &DeliveryId) -> Result<Reoffered, StorageUnavailable>;

    /// Which tenants have work outstanding from before `accepted_before`.
    ///
    /// Asked on an interval and never at scrape time: a monitoring system
    /// polling every fifteen seconds would otherwise become load on the thing
    /// it is monitoring, and would go quiet exactly when the database is in
    /// trouble, which is when somebody is looking.
    ///
    /// A tenant that is keeping up does not appear. The answer is the exception
    /// list, not a row per tenant, because what an operator needs is the short
    /// list of names worth asking about.
    ///
    /// # Errors
    ///
    /// [`StorageUnavailable`] if the store could not be asked.
    async fn behind(&self, accepted_before: Timestamp) -> Result<Vec<Behind>, StorageUnavailable>;

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

    /// Whether this store can be used right now.
    ///
    /// FOR READINESS AND NOTHING ELSE (bead gc-28a). A pod whose store cannot
    /// be reached can do none of the work above: a sender that was going to be
    /// told `202` is told `503`, an agent's claim is handed nothing, and a
    /// report cannot settle. With more than one replica — which gc-f7t made a
    /// shape this repository endorses — that is a share of everything, failing
    /// intermittently, while the pod stays in the Service.
    ///
    /// NOT FOR LIVENESS. Restarting will not reach a database that is down, and
    /// a dependency failure that turned into a restart loop would replace a
    /// recoverable outage with a pod that is never up long enough to recover.
    /// That argument is `health`'s in the composition root and it stands.
    ///
    /// REQUIRED RATHER THAN DEFAULTED, deliberately. A default of "reachable"
    /// would be inherited in silence by the next store that has something to
    /// reach, and a readiness probe that is wrong in that direction reports
    /// health it has not checked. An in-memory store answers `Ok` because it is
    /// true of it, not because nobody thought about it.
    ///
    /// # Errors
    ///
    /// [`StorageUnavailable`] when the store cannot be used. It carries no
    /// address and no credential (gc-b0n), which is what makes it safe to put
    /// in a probe's answer.
    async fn reachable(&self) -> Result<(), StorageUnavailable>;
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

/// The platform could not be reached, or did not answer usefully.
///
/// Carries nothing else, for the reason [`StorageUnavailable`] carries nothing:
/// the address and the identity are the adapter's, and an error that named them
/// would put both in whatever log line touched it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unreachable;

impl core::fmt::Display for Unreachable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("the platform could not be reached")
    }
}

impl std::error::Error for Unreachable {}

/// What the platform said about a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Acknowledged {
    /// It was outstanding for this agent, and now it is discharged.
    Recorded,
    /// Nothing outstanding went by that identity.
    ///
    /// Not an error, and worth telling apart: the likeliest cause is that this
    /// agent's lease lapsed while it was delivering and somebody else has since
    /// discharged the Delivery. An agent that treated it as a failure would
    /// retry a report that will never be accepted.
    NotOutstanding,
}

/// A Delivery as the agent receives it: what to send, and until when.
///
/// NOT [`Claimed`], AND THE DIFFERENCE IS A TENANT. The platform's type carries
/// one because its store holds many tenants' work and must never mix them. What
/// comes back over the wire carries none: the platform established the tenant
/// from the caller's mTLS identity and has no reason to say it back, and bead
/// gc-nkb forbids the agent holding a tenant name at all — it would be a value
/// nothing checks against anything.
///
/// So the two sides of this hand-off have two types, which is honest rather
/// than duplicative: they describe the same Delivery from either side of a
/// trust boundary, and only one side is entitled to know whose it is. Reusing
/// the platform's type would have meant the client inventing a placeholder
/// tenant, which is exactly the value gc-nkb warns about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Owed {
    delivery: DeliveryId,
    origin: OriginId,
    events: Vec<Event>,
    correlation: Correlation,
    accepted_at: Timestamp,
    lease_until: Timestamp,
    replayed: bool,
}

impl Owed {
    /// What was claimed, and until when.
    ///
    /// `None` when there are no Events, for the reason [`Offered::new`] gives:
    /// there would be nothing to deliver and no room list to report, so the
    /// platform's queue could never drain. A response carrying one is a
    /// response this build cannot act on.
    #[must_use]
    pub fn new(
        delivery: DeliveryId,
        origin: OriginId,
        events: Vec<Event>,
        correlation: Correlation,
        accepted_at: Timestamp,
        lease_until: Timestamp,
        replayed: bool,
    ) -> Option<Self> {
        if events.is_empty() {
            return None;
        }
        Some(Self {
            delivery,
            origin,
            events,
            correlation,
            accepted_at,
            lease_until,
            replayed,
        })
    }

    /// Whether a person asked for this to be sent again, so the room is told.
    ///
    /// Read from the claim rather than decided here: whether something is a
    /// replay is the platform's knowledge, and an agent that guessed would mark
    /// a retry — which bead gc-6a5.3 refused, because an alert arriving twice is
    /// how a responder learns something got worse.
    #[must_use]
    pub fn replayed(&self) -> bool {
        self.replayed
    }

    /// Which Delivery, which is how a report refers to it.
    #[must_use]
    pub fn delivery(&self) -> &DeliveryId {
        &self.delivery
    }

    /// Who sent it, as a name. What a rule matching `origin` compares against.
    #[must_use]
    pub fn origin(&self) -> &OriginId {
        &self.origin
    }

    /// What it reported, together and in the sender's order.
    #[must_use]
    pub fn events(&self) -> &[Event] {
        &self.events
    }

    /// The chain it arrived on, to be continued rather than restarted.
    #[must_use]
    pub fn correlation(&self) -> &Correlation {
        &self.correlation
    }

    /// When the sender was answered.
    #[must_use]
    pub fn accepted_at(&self) -> Timestamp {
        self.accepted_at
    }

    /// When this claim lapses and the Delivery is offered again.
    ///
    /// The platform's number, read rather than assumed (bead gc-81d).
    #[must_use]
    pub fn lease_until(&self) -> Timestamp {
        self.lease_until
    }
}

/// What a tenant's agent needs from the platform.
///
/// THE PORT WITH NO TENANT IN IT, and that absence is the whole design rather
/// than an omission. Compare [`Handover`], the platform's own storage port,
/// where every method takes a `&TenantId` because it serves many. An agent
/// serves one, and which one is established by its mTLS identity at the other
/// end — so a tenant in any of these signatures would be a value the agent
/// asserts rather than a fact about who is calling, and bead gc-nkb refused
/// exactly that. An interface that accepted one would invite somebody to trust
/// it.
///
/// That difference is why the agent could not simply reuse `Handover`, which is
/// what bead gc-72e expected: two ports, because the two sides are not
/// symmetrical.
#[async_trait]
pub trait Offers: Send + Sync {
    /// Everything this agent is owed, leased to it.
    ///
    /// No bound and no lease length in the signature: both are the platform's
    /// to decide, and the expiry comes back on each [`Claimed`]. An agent that
    /// assumed a duration would be wrong the day the platform changed its mind
    /// (bead gc-81d).
    ///
    /// # Errors
    ///
    /// [`Unreachable`] if the platform could not be asked. Nothing is claimed
    /// then, so the next pass simply asks again.
    async fn claim(&self) -> Result<Vec<Owed>, Unreachable>;

    /// The terminal statement about one Delivery.
    ///
    /// # Errors
    ///
    /// [`Unreachable`] if the platform could not be told. The work was still
    /// done; what is lost is the record of it, and the Delivery will be offered
    /// again when the lease lapses — which is the duplicate bead gc-81d
    /// accepted knowingly.
    async fn report(
        &self,
        delivery: &DeliveryId,
        report: &Report,
    ) -> Result<Acknowledged, Unreachable>;
}

/// Somewhere to wait.
///
/// A port because sleeping is an effect, and the application layer is allowed
/// `thiserror` and `async-trait` and nothing else — so it could not reach a
/// runtime even if it wanted to. That restriction is doing its job here: the
/// agent's retry budget is a policy decision, and a test that had to wait
/// thirty-one real seconds to prove it would be a test nobody runs.
#[async_trait]
pub trait Pause: Send + Sync {
    /// Wait this long, then carry on.
    async fn rest(&self, how_long: core::time::Duration);
}
