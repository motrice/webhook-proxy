//! Who should hear about an Event.

use crate::event::present;
use crate::{Blank, Event, RepositoryName};

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Filter {
    /// Everything that arrives.
    Everything,
    /// Only Events about one repository.
    Repository(RepositoryName),
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
    /// Does this filter admit the Event?
    #[must_use]
    pub fn admits(&self, event: &Event) -> bool {
        match self {
            Self::Everything => true,
            Self::Repository(wanted) => event.repository() == wanted,
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

/// Every Destination that should hear about this Event, each once.
///
/// Pure, so fan-out correctness is tested exhaustively and in microseconds. Two
/// Subscriptions can name the same Destination — that is a reasonable way to say
/// "this room wants these two repositories" — and the Destination must still be
/// told once, because a reader should not see the same message twice.
///
/// Order follows the Subscriptions as given, so the result is deterministic and
/// a test can assert it.
#[must_use]
pub fn destinations_for<'s>(
    event: &Event,
    subscriptions: &'s [Subscription],
) -> Vec<&'s Destination> {
    let mut reached: Vec<&Destination> = Vec::new();
    for subscription in subscriptions {
        if subscription.filter.admits(event) {
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
    };
    use crate::{BranchName, Event, Pusher, RepositoryName};

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
        }
    }

    fn deletion_in(repository: &str) -> Event {
        Event::DeletedBranch {
            repository: RepositoryName::new(repository).expect("a name"),
            branch: BranchName::new("bead/gc-old").expect("a name"),
            pusher: Pusher::new("bjorn").expect("a name"),
        }
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
        let filter = Filter::Repository(RepositoryName::new("webhook-proxy").expect("a name"));

        assert!(filter.admits(&deletion_in("webhook-proxy")));
        assert!(!filter.admits(&deletion_in("something-else")));
    }

    #[test]
    fn everything_admits_a_deletion_too() {
        assert!(Filter::Everything.admits(&deletion_in("webhook-proxy")));
    }

    #[test]
    fn everything_admits_any_event() {
        assert!(Filter::Everything.admits(&push_to("webhook-proxy")));
    }

    #[test]
    fn a_repository_filter_admits_only_that_repository() {
        let filter = Filter::Repository(RepositoryName::new("webhook-proxy").expect("a name"));

        assert!(filter.admits(&push_to("webhook-proxy")));
        assert!(!filter.admits(&push_to("something-else")));
    }

    #[test]
    fn an_event_matching_nothing_yields_no_destinations_and_is_not_an_error() {
        let subscriptions = vec![Subscription::new(
            destination("room"),
            Filter::Repository(RepositoryName::new("other").expect("a name")),
        )];

        assert!(destinations_for(&push_to("webhook-proxy"), &subscriptions).is_empty());
    }

    #[test]
    fn two_subscriptions_on_one_destination_yield_it_once() {
        let room = destination("room");
        let subscriptions = vec![
            Subscription::new(room.clone(), Filter::Everything),
            Subscription::new(
                room.clone(),
                Filter::Repository(RepositoryName::new("webhook-proxy").expect("a name")),
            ),
        ];

        let reached = destinations_for(&push_to("webhook-proxy"), &subscriptions);

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

        let reached = destinations_for(&push_to("any"), &subscriptions);

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
        assert!(destinations_for(&push_to("any"), &[]).is_empty());
    }
}
