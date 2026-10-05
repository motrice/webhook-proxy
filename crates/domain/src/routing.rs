//! Who should hear about an Event.

use crate::event::present;
use crate::label::{self, LabelName, LabelValue};
use crate::{Blank, Event, Labels, OriginId};

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
    let labels = offered.without_reserved();

    // Unlike every other name in this crate, OriginId does not reject a blank —
    // see bead gc-qz6 — so this can fail, and the validating constructor is used
    // rather than the unchecked one. When it fails the label is simply absent, so
    // every rule naming an origin stops matching: the room goes quiet, which is
    // the safe direction for a value that decides who may reach it.
    match LabelValue::new(origin.as_str()) {
        Ok(value) => labels.with(LabelName::known(label::ORIGIN), value),
        Err(_) => labels,
    }
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
        Destination, DestinationId, DestinationKind, Filter, Subscription, destinations_for,
        routing_labels,
    };
    use crate::{
        BranchName, Event, LabelName, LabelValue, Labels, OriginId, Pusher, RepositoryName,
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
        OriginId::new(id)
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
    fn a_blank_origin_yields_no_origin_label_and_so_matches_no_origin_rule() {
        // OriginId does not reject a blank name (gc-qz6). The label is omitted
        // rather than invented, so a rule naming an origin stops matching and the
        // room goes quiet — never the opposite, where a blank would match
        // something.
        let matched = routing_labels(&OriginId::new("  "), offering(&[("severity", "critical")]));

        assert!(
            matched
                .get(&LabelName::new("origin").expect("a name"))
                .is_none()
        );
        // A rule requiring a blank origin is not constructible in the first
        // place, so the only case to pin is that a real one does not match.
        assert!(!requiring(&[("origin", "anything")]).admits(&matched));
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
}
