//! Who should hear about an Event.

use crate::event::present;
use crate::label::{self, LabelName, LabelValue};
use crate::{Blank, Correlation, DeliveryId, Event, Labels, OriginId};

/// Identifies a [`Destination`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestinationId(String);

/// What kind of system a Destination is.
///
/// This decides how an Event is *shaped* for it — prose for people to read, or
/// structure for a machine to consume — and therefore which adapter handles it.
/// It deliberately says nothing about which product that adapter talks to: a
/// chat room is a chat room whether the other end is one vendor or another, and
/// the moment this enum names a product, every Destination inherits that
/// product's worldview.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestinationKind {
    /// A room where people read messages. An Event becomes a Notice.
    ChatRoom,
    /// Another forge, which consumes structure rather than prose.
    Forge,
}

/// A Dispatch's identity once something is keeping track of it.
///
/// Minted by whatever stores it rather than at the boundary, unlike
/// [`DeliveryId`], and for a reason worth stating: a Delivery is named when it
/// arrives because a loss report has to name what was lost even if nothing ever
/// stored it. A Dispatch only needs a name once there is something to refer to
/// it by — a row to mark delivered, a row to retry.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DispatchId(String);

impl DispatchId {
    /// Names a Dispatch.
    ///
    /// # Errors
    ///
    /// [`Blank`] if the identity is empty or only whitespace.
    pub fn new(id: &str) -> Result<Self, Blank> {
        present(id, "a dispatch identity").map(Self)
    }

    /// The identity as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What one Destination is to be told, from one Delivery.
///
/// The unit of work the delivery promise is about: one message, attempted and
/// succeeding or failing on its own. That is what lets a Dispatch be stored,
/// retried and reported on separately, which gc-mbr's promise requires — one
/// Delivery can be half delivered, and saying which half is the whole value of
/// recording it.
///
/// It carries the Events that selected *this* Destination rather than one Event,
/// because a sender that grouped them meant a room to get one message (gc-lhh).
/// Different alerts in one notification can select different rooms, so the set
/// differs per Destination and the group a room sees is one this proxy composed,
/// not the one the sender did.
///
/// It carries the Destination rather than only its identity because a
/// Destination is an identity and a kind and deliberately nothing else — no URL,
/// no token — so keeping it whole costs nothing and loses no secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dispatch {
    delivery: DeliveryId,
    origin: OriginId,
    events: Vec<Event>,
    destination: Destination,
    correlation: Correlation,
}

impl Dispatch {
    /// What is to be sent, where, and on whose behalf.
    ///
    /// `None` when there is nothing to say. A Dispatch with no Events would
    /// render an empty Notice and send it, which is a blank message in somebody's
    /// room — so it cannot be built rather than being guarded against at every
    /// place one is used.
    #[must_use]
    pub fn new(
        delivery: DeliveryId,
        origin: OriginId,
        events: Vec<Event>,
        destination: Destination,
        correlation: Correlation,
    ) -> Option<Self> {
        if events.is_empty() {
            return None;
        }
        Some(Self {
            delivery,
            origin,
            events,
            destination,
            correlation,
        })
    }

    /// Which Delivery this came from.
    #[must_use]
    pub fn delivery(&self) -> &DeliveryId {
        &self.delivery
    }

    /// The call chain this belongs to, which is the caller's and not ours.
    ///
    /// Carried on the Dispatch rather than alongside it because a Dispatch
    /// outlives the request that made it: the sweep sends one again minutes
    /// later, and that onward call belongs to the same chain as the original.
    /// Keeping the two together is what makes a retry traceable back to the push
    /// or the alert that caused it.
    #[must_use]
    pub fn correlation(&self) -> &Correlation {
        &self.correlation
    }

    /// Which Origin was verified as having sent it.
    ///
    /// Kept because a Dispatch is not enough to route one again without it.
    /// `origin` is the one label the proxy sets rather than reads, and every
    /// rule that names it relies on that — so sending this somewhere new later
    /// has to use the Origin that was *established* at the boundary, never one
    /// an operator typed when asking for a replay.
    #[must_use]
    pub fn origin(&self) -> &OriginId {
        &self.origin
    }

    /// Everything that happened, in the order the sender reported it.
    ///
    /// More than one when a sender grouped them. Alertmanager's `group_by`
    /// collapses many firing alerts into one notification precisely so a room
    /// gets one message, and sending one message per alert would undo a decision
    /// the sender made deliberately — see bead gc-lhh. Never empty.
    #[must_use]
    pub fn events(&self) -> &[Event] {
        &self.events
    }

    /// Where it is going.
    #[must_use]
    pub fn destination(&self) -> &Destination {
        &self.destination
    }
}

/// An internal system that should be told about Events.
///
/// An identity and a kind, and deliberately nothing else. There is no field for
/// a URL, a token or a header, because where a Destination lives and how it is
/// authenticated are configuration belonging to the adapter that reaches it —
/// and because a secret in a domain value is a secret in every log line that
/// ever prints one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    id: DestinationId,
    kind: DestinationKind,
}

/// Decides whether a Destination cares about a given Event.
///
/// There is one mechanism, because routing serves senders with nothing
/// structural in common. A rule names the labels a fact must carry, and every
/// Event can answer that whether it is a push or an alert. This replaced a
/// variant naming a `RepositoryName`, which only a sender that has a repository
/// could be asked about; bead gc-ast.1 records the choice and what it costs.
///
/// Values are compared for equality and nothing else — no negation, no regular
/// expressions. A regex engine would be a dependency in a crate that has none,
/// and it would run attacker-influenced text through a backtracking matcher,
/// which hands a denial of service to whoever can write a workload annotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Filter {
    /// Everything that arrives.
    Everything,
    /// Only Events carrying all of these labels.
    ///
    /// Containment, not equality: a fact may carry labels no rule mentions.
    /// Requiring an exact set would force a Subscription to enumerate every label
    /// a sender might ever add.
    Labelled(Labels),
}

/// A rule binding Events to one Destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscription {
    destination: Destination,
    filter: Filter,
}

impl DestinationId {
    /// Names a Destination.
    ///
    /// # Errors
    ///
    /// [`Blank`] if the name is empty or only whitespace.
    pub fn new(id: &str) -> Result<Self, Blank> {
        present(id, "a destination identity").map(Self)
    }

    /// The identity as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Destination {
    /// Registers a Destination.
    #[must_use]
    pub fn new(id: DestinationId, kind: DestinationKind) -> Self {
        Self { id, kind }
    }

    /// Which Destination this is.
    #[must_use]
    pub fn id(&self) -> &DestinationId {
        &self.id
    }

    /// What kind of system it is.
    #[must_use]
    pub fn kind(&self) -> DestinationKind {
        self.kind
    }
}

impl Filter {
    /// Does this filter admit a fact carrying these labels?
    ///
    /// Takes the labels rather than the Event, because what a fact is matched
    /// against is not quite what it offers: the reserved labels are the domain's
    /// to set, and [`routing_labels`] is where that happens. A Filter handed raw
    /// Event labels would be matching a sender's claim about its own Origin.
    #[must_use]
    pub fn admits(&self, labels: &Labels) -> bool {
        match self {
            Self::Everything => true,
            Self::Labelled(required) => labels.contain_all(required),
        }
    }
}

impl Subscription {
    /// Binds a Destination to the Events it cares about.
    #[must_use]
    pub fn new(destination: Destination, filter: Filter) -> Self {
        Self {
            destination,
            filter,
        }
    }

    /// Where matching Events go.
    #[must_use]
    pub fn destination(&self) -> &Destination {
        &self.destination
    }

    /// Which Events match.
    #[must_use]
    pub fn filter(&self) -> &Filter {
        &self.filter
    }
}

/// The labels a fact is matched against: what it offers, minus anything only the
/// domain may say, plus what the domain knows.
///
/// **This is the one place reserved labels are enforced.** Everything that routes
/// goes through it, so a sender cannot reach a room by claiming a label it is not
/// allowed to set. `origin` is taken from the verified Delivery, which is a fact
/// about who actually sent this rather than a claim inside what they sent.
///
/// Today every forge Event projects its labels from typed fields, so there is
/// nothing to drop. The drop matters the moment an Event stores labels a sender
/// chose — an Alert, whose labels come from workload annotations, and so from
/// whoever can deploy. Bead gc-srw.
fn routing_labels(origin: &OriginId, offered: Labels) -> Labels {
    // The drop stays even though `with` would overwrite a forged `origin`
    // anyway. The invariant wanted here is "a sender cannot set a reserved
    // label", and resting that on "every reserved label happens to be projected"
    // would make it depend on a property of a different function — true today,
    // silently false the first time a reserved name is added that is not always
    // set. Dropping makes it locally true instead.
    offered.without_reserved().with(
        LabelName::known(label::ORIGIN),
        LabelValue::present(origin.as_str()),
    )
}

/// Every Destination that should hear about this Event, each once.
///
/// Pure, so fan-out correctness is tested exhaustively and in microseconds. Two
/// Subscriptions can name the same Destination — that is a reasonable way to say
/// "this room wants these two repositories" — and the Destination must still be
/// told once, because a reader should not see the same message twice.
///
/// Order follows the Subscriptions as given, so the result is deterministic and
/// a test can assert it.
///
/// The Origin is passed separately rather than carried on the Event: who told us
/// is not part of what happened, and keeping it out of the Event means there is
/// exactly one way for it to reach a routing decision.
#[must_use]
pub fn destinations_for<'s>(
    origin: &OriginId,
    event: &Event,
    subscriptions: &'s [Subscription],
) -> Vec<&'s Destination> {
    // Once, not once per Subscription: the labels do not depend on the rule.
    let labels = routing_labels(origin, event.labels());

    let mut reached: Vec<&Destination> = Vec::new();
    for subscription in subscriptions {
        if subscription.filter.admits(&labels) {
            let destination = &subscription.destination;
            // Linear, because a Destination list is small and determinism is
            // worth more here than asymptotics: a test can assert the order.
            if !reached.iter().any(|already| already.id == destination.id) {
                reached.push(destination);
            }
        }
    }
    reached
}

#[cfg(test)]
mod tests {
    use super::{
        Correlation, Destination, DestinationId, DestinationKind, Dispatch, Filter, Subscription,
        destinations_for, routing_labels,
    };
    use crate::{
        AlertId, AlertStatus, BranchName, DeliveryId, Event, LabelName, LabelValue, Labels,
        OriginId, Pusher, RepositoryName, Severity, Summary, Timestamp,
    };

    fn destination(id: &str) -> Destination {
        Destination::new(
            DestinationId::new(id).expect("a non-blank id"),
            DestinationKind::ChatRoom,
        )
    }

    fn push_to(repository: &str) -> Event {
        Event::PushedCommits {
            repository: RepositoryName::new(repository).expect("a name"),
            branch: BranchName::new("main").expect("a name"),
            pusher: Pusher::new("bjorn").expect("a name"),
            commits: vec![],
            permalink: None,
        }
    }

    fn deletion_in(repository: &str) -> Event {
        Event::DeletedBranch {
            repository: RepositoryName::new(repository).expect("a name"),
            branch: BranchName::new("bead/gc-old").expect("a name"),
            pusher: Pusher::new("bjorn").expect("a name"),
        }
    }

    /// The Filter that the removed `Repository` variant used to be, expressed the
    /// new way.
    ///
    /// Its presence is the point: the tests below are the ones that guarded that
    /// variant, unchanged apart from this constructor, so nothing it could express
    /// has been lost.
    fn only_repository(name: &str) -> Filter {
        requiring(&[("repository", name)])
    }

    fn requiring(pairs: &[(&str, &str)]) -> Filter {
        Filter::Labelled(pairs.iter().fold(Labels::none(), |set, (name, value)| {
            set.with(
                LabelName::new(name).expect("a non-blank name"),
                LabelValue::new(value).expect("a non-blank value"),
            )
        }))
    }

    fn origin(id: &str) -> OriginId {
        OriginId::new(id).expect("a non-blank origin identity")
    }

    fn offering(pairs: &[(&str, &str)]) -> Labels {
        pairs.iter().fold(Labels::none(), |set, (name, value)| {
            set.with(
                LabelName::new(name).expect("a non-blank name"),
                LabelValue::new(value).expect("a non-blank value"),
            )
        })
    }

    #[test]
    fn the_origin_label_comes_from_the_delivery_and_not_from_the_fact() {
        // The security property this bead exists for, at the point it is
        // enforced. A fact claiming origin=trusted-forge is matched as the Origin
        // that actually sent it, so a workload able to annotate itself cannot
        // reach a room by pretending to be somebody else.
        let matched = routing_labels(
            &origin("alertmanager"),
            offering(&[("origin", "trusted-forge")]),
        );

        let name = LabelName::new("origin").expect("a name");
        assert_eq!(
            matched.get(&name).map(LabelValue::as_str),
            Some("alertmanager")
        );
    }

    #[test]
    fn a_forged_origin_does_not_cost_the_fact_its_other_labels() {
        let matched = routing_labels(
            &origin("alertmanager"),
            offering(&[("origin", "lies"), ("severity", "critical")]),
        );

        let severity = LabelName::new("severity").expect("a name");
        assert_eq!(
            matched.get(&severity).map(LabelValue::as_str),
            Some("critical")
        );
    }

    #[test]
    fn a_rule_requiring_one_origin_is_not_satisfied_by_another() {
        let rule = requiring(&[("origin", "alertmanager")]);
        let from_elsewhere =
            routing_labels(&origin("a-forge"), offering(&[("severity", "critical")]));

        assert!(!from_elsewhere.contain_all(&labels_of(&rule)));

        let from_alertmanager = routing_labels(&origin("alertmanager"), Labels::none());
        assert!(from_alertmanager.contain_all(&labels_of(&rule)));
    }

    /// The labels a `Labelled` filter requires, for tests that compare directly.
    fn labels_of(filter: &Filter) -> Labels {
        match filter {
            Filter::Labelled(required) => required.clone(),
            Filter::Everything => Labels::none(),
        }
    }

    #[test]
    fn a_subscription_can_require_the_origin_that_sent_the_event() {
        let room = destination("devsecops-room");
        let subscriptions = vec![Subscription::new(
            room.clone(),
            requiring(&[("origin", "a-forge")]),
        )];

        let reached = destinations_for(
            &origin("a-forge"),
            &push_to("webhook-proxy"),
            &subscriptions,
        );
        assert_eq!(reached, vec![&room]);

        let elsewhere = destinations_for(
            &origin("somebody-else"),
            &push_to("webhook-proxy"),
            &subscriptions,
        );
        assert!(elsewhere.is_empty());
    }

    #[test]
    fn a_senders_origin_label_is_overwritten_by_the_one_that_sent_it() {
        // An Alert stores the labels it was sent, and those come from workload
        // annotations — from whoever can deploy, a wider set than the sender
        // forwarding them. Here the projection overwrites the claim, because
        // `Labels::with` replaces. The *drop* is what covers the case where the
        // projection does not happen at all: see the test below.
        let forged = Event::Alert {
            id: AlertId::new("7b1a177c").expect("an identity"),
            severity: Severity::Critical,
            status: AlertStatus::Firing,
            summary: Summary::new("something is wrong").expect("a summary"),
            labels: Labels::none().with(
                LabelName::new("origin").expect("a name"),
                LabelValue::new("a-forge").expect("a value"),
            ),
            started: Timestamp::from_millis_since_epoch(1_759_000_000_000),
            permalink: None,
        };

        let room = destination("devsecops-room");
        let only_the_forge = vec![Subscription::new(
            room.clone(),
            requiring(&[("origin", "a-forge")]),
        )];

        // The alert says it came from a-forge. It did not.
        let reached = destinations_for(&origin("alertmanager"), &forged, &only_the_forge);
        assert!(
            reached.is_empty(),
            "a sender set its own origin label and reached a room with it"
        );

        // And it still routes as what it actually is.
        let its_own = vec![Subscription::new(
            room.clone(),
            requiring(&[("origin", "alertmanager"), ("severity", "critical")]),
        )];
        assert_eq!(
            destinations_for(&origin("alertmanager"), &forged, &its_own),
            vec![&room]
        );
    }

    #[test]
    fn a_destination_identity_cannot_be_blank() {
        assert!(DestinationId::new("  ").is_err());
    }

    #[test]
    fn a_destination_is_an_identity_and_a_kind_and_nothing_else() {
        // The real guarantee is structural — Destination has two fields and no
        // constructor that could accept a URL — and this pins the observable
        // half: nothing that looks like an address can come back out of one.
        let printed = format!("{:?}", destination("devsecops-room"));

        assert!(printed.contains("devsecops-room"), "{printed}");
        assert!(printed.contains("ChatRoom"), "{printed}");
        assert!(!printed.contains("://"), "{printed}");
    }

    #[test]
    fn a_repository_filter_admits_a_deletion_in_that_repository() {
        // The Filter reads the repository off the Event rather than off one
        // variant, so a room subscribed to a repository hears about a deleted
        // branch in it without the Filter having to learn the new variant.
        let filter = only_repository("webhook-proxy");

        assert!(filter.admits(&deletion_in("webhook-proxy").labels()));
        assert!(!filter.admits(&deletion_in("something-else").labels()));
    }

    #[test]
    fn everything_admits_a_deletion_too() {
        assert!(Filter::Everything.admits(&deletion_in("webhook-proxy").labels()));
    }

    #[test]
    fn everything_admits_any_event() {
        assert!(Filter::Everything.admits(&push_to("webhook-proxy").labels()));
    }

    #[test]
    fn a_repository_filter_admits_only_that_repository() {
        let filter = only_repository("webhook-proxy");

        assert!(filter.admits(&push_to("webhook-proxy").labels()));
        assert!(!filter.admits(&push_to("something-else").labels()));
    }

    #[test]
    fn a_filter_of_two_labels_admits_an_event_only_when_both_hold() {
        // One rule, not two. A room that wants main of one repository says so in a
        // single Filter, and a push matching only half of it is not admitted.
        let filter = requiring(&[("repository", "webhook-proxy"), ("branch", "main")]);

        assert!(filter.admits(&push_to("webhook-proxy").labels()));
        assert!(!filter.admits(&push_to("something-else").labels()));
        // deletion_in is on bead/gc-old, so its repository matches and its branch
        // does not.
        assert!(!filter.admits(&deletion_in("webhook-proxy").labels()));
    }

    #[test]
    fn a_filter_naming_a_label_the_event_does_not_carry_admits_nothing() {
        // A push has no severity. A rule asking for one must fail to match rather
        // than fail to run — and a mistyped label name lands here too, which is
        // why a typo makes a room go quiet instead of hearing the wrong thing.
        assert!(!requiring(&[("severity", "critical")]).admits(&push_to("webhook-proxy").labels()));
        assert!(
            !requiring(&[("repositry", "webhook-proxy")])
                .admits(&push_to("webhook-proxy").labels())
        );
    }

    #[test]
    fn a_filter_requiring_nothing_admits_everything() {
        // The degenerate case, stated because configuration can reach it: an empty
        // requirement is Everything by another name, not a rule that quietly
        // matches nothing.
        let filter = Filter::Labelled(Labels::none());

        assert!(filter.admits(&push_to("webhook-proxy").labels()));
        assert!(filter.admits(&deletion_in("anything").labels()));
    }

    #[test]
    fn filtering_by_branch_needs_no_new_filter_kind() {
        // This is bead gc-3pa.11, which asked for a Filter admitting only named
        // branches. It is a label requirement now, so the feature exists without
        // code of its own — which is why that bead is closed as superseded.
        let main_only = requiring(&[("branch", "main")]);

        assert!(main_only.admits(&push_to("webhook-proxy").labels()));
        assert!(!main_only.admits(&deletion_in("webhook-proxy").labels()));
    }

    #[test]
    fn an_event_matching_nothing_yields_no_destinations_and_is_not_an_error() {
        let subscriptions = vec![Subscription::new(
            destination("room"),
            only_repository("other"),
        )];

        assert!(
            destinations_for(
                &origin("a-forge"),
                &push_to("webhook-proxy"),
                &subscriptions
            )
            .is_empty()
        );
    }

    #[test]
    fn two_subscriptions_on_one_destination_yield_it_once() {
        let room = destination("room");
        let subscriptions = vec![
            Subscription::new(room.clone(), Filter::Everything),
            Subscription::new(room.clone(), only_repository("webhook-proxy")),
        ];

        let reached = destinations_for(
            &origin("a-forge"),
            &push_to("webhook-proxy"),
            &subscriptions,
        );

        assert_eq!(reached, vec![&room]);
    }

    #[test]
    fn destinations_follow_the_order_their_subscriptions_were_given() {
        let first = destination("first");
        let second = destination("second");
        let subscriptions = vec![
            Subscription::new(first.clone(), Filter::Everything),
            Subscription::new(second.clone(), Filter::Everything),
        ];

        let reached = destinations_for(&origin("a-forge"), &push_to("any"), &subscriptions);

        assert_eq!(reached, vec![&first, &second]);
    }

    #[test]
    fn a_subscription_exposes_what_it_binds() {
        let room = destination("room");
        let subscription = Subscription::new(room.clone(), Filter::Everything);

        assert_eq!(subscription.destination(), &room);
        assert_eq!(subscription.filter(), &Filter::Everything);
    }

    #[test]
    fn no_subscriptions_means_no_destinations() {
        assert!(destinations_for(&origin("a-forge"), &push_to("any"), &[]).is_empty());
    }

    #[test]
    fn a_dispatch_with_nothing_to_say_cannot_be_built() {
        // It would render an empty Notice and send it, which is a blank message
        // in somebody's room. Refused at construction rather than guarded
        // against everywhere one is used.
        assert!(
            Dispatch::new(
                DeliveryId::new("d-1").expect("a non-blank id"),
                OriginId::new("github").expect("a non-blank id"),
                Vec::new(),
                Destination::new(
                    DestinationId::new("a-room").expect("a non-blank id"),
                    DestinationKind::ChatRoom,
                ),
                Correlation::new("4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7", None)
                    .expect("a well formed correlation"),
            )
            .is_none()
        );
    }
}
