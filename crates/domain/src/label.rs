//! The labels an Event can be routed by.
//!
//! Routing has to serve senders with nothing structural in common: a push is
//! about a repository and a branch, an alert about a namespace and a severity
//! and no repository at all. A set of name/value pairs is the smallest question
//! both can answer, so routing asks that one question of every Event and the
//! Filter needs no knowledge of which kind it has.
//!
//! The word is not a wire format borrowed inward. A label names what a fact is
//! about, never how the fact arrived, so it is subject rather than mechanism —
//! the distinction `crates/architecture`'s purity test enforces. Nothing of a
//! sender's own label conventions comes with it: no reserved spellings, no
//! matcher grammar, no regular expressions. See bead gc-ast.1.
//!
//! Both halves of a label are attacker-influenced text. An alert's label value
//! comes from a workload annotation, which comes from whoever can deploy; a
//! push's comes from a branch name, which comes from whoever can push. They are
//! checked for presence and nothing else: refusing a fact over a label we
//! disliked would lose real news, and the defence belongs where it already is,
//! in a renderer that emits no markup.

use std::collections::BTreeMap;

use crate::Blank;
use crate::event::present;

/// The label naming which Origin told us, set from the verified Delivery.
///
/// Reserved: see [`RESERVED`].
pub const ORIGIN: &str = "origin";

/// Label names only this crate may set.
///
/// A sender that could set one of these could lie about something the system
/// relies on. `origin` is the first and the reason the set exists: a workload
/// able to write its own annotations — a wider set of people than the sender
/// forwarding them — could otherwise claim to be any Origin and so reach every
/// room subscribed to one. Bead gc-srw.
///
/// Requiring a reserved label in a rule is fine and is the point; only *setting*
/// one is denied. A Subscription saying `origin=alertmanager` is exactly what
/// this makes trustworthy.
const RESERVED: &[&str] = &[ORIGIN];

/// The name a label is known by.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LabelName(String);

/// What a label says.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LabelValue(String);

/// The labels a fact carries, or the labels a rule requires.
///
/// One type for both, because both are a set of name/value pairs and the
/// question between them is containment. Using two would mean validating a name
/// twice and inventing a reason for them to differ.
///
/// One value per name: a map, which is what both kinds of sender already mean by
/// the word, and what keeps admission unambiguous.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Labels(BTreeMap<LabelName, LabelValue>);

impl LabelName {
    /// Names a label.
    ///
    /// # Errors
    ///
    /// [`Blank`] if the name is empty or only whitespace.
    pub fn new(name: &str) -> Result<Self, Blank> {
        present(name, "a label name").map(Self)
    }

    /// For a name this crate writes down itself, which is present by
    /// construction. Keeps [`Event::labels`](crate::Event::labels) free of a
    /// panic that could never fire.
    pub(crate) fn known(name: &'static str) -> Self {
        Self(name.to_owned())
    }

    /// The name as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl LabelValue {
    /// Takes what a label says.
    ///
    /// # Errors
    ///
    /// [`Blank`] if the value is empty or only whitespace.
    pub fn new(value: &str) -> Result<Self, Blank> {
        present(value, "a label value").map(Self)
    }

    /// For a value another type has already guaranteed is present — a
    /// `RepositoryName` cannot be blank, so projecting one needs no second check
    /// and no unreachable error path.
    pub(crate) fn present(value: &str) -> Self {
        Self(value.to_owned())
    }

    /// The value as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Labels {
    /// No labels at all. As a requirement this admits everything.
    #[must_use]
    pub fn none() -> Self {
        Self(BTreeMap::new())
    }

    /// The same labels with one more. A name already present takes the new value.
    #[must_use]
    pub fn with(mut self, name: LabelName, value: LabelValue) -> Self {
        self.0.insert(name, value);
        self
    }

    /// What this says under that name, if anything.
    #[must_use]
    pub fn get(&self, name: &LabelName) -> Option<&LabelValue> {
        self.0.get(name)
    }

    /// How many labels.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether there are none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The same labels with everything reserved removed.
    ///
    /// Called on whatever a fact offers, before matching and before the domain
    /// sets the reserved labels itself. Dropping rather than rejecting is
    /// deliberate: a sender including a reserved label must not be able to deny
    /// itself delivery by doing so, so it loses that label and nothing else.
    #[must_use]
    pub fn without_reserved(mut self) -> Self {
        self.0.retain(|name, _| !RESERVED.contains(&name.as_str()));
        self
    }

    /// Every label, by name, in a stable order.
    ///
    /// Ordered because a Destination renders them for a person: a room where the
    /// same alert reads differently each time is a room nobody trusts, and a test
    /// that cannot predict the order cannot pin the text.
    pub fn iter(&self) -> impl Iterator<Item = (&LabelName, &LabelValue)> {
        self.0.iter()
    }

    /// Whether every label in `required` is here with the same value.
    ///
    /// Containment, not equality: a fact may carry labels no rule mentions, and
    /// an alert will carry many. Requiring an exact match would force a
    /// Subscription to enumerate every label a sender might ever add.
    #[must_use]
    pub fn contain_all(&self, required: &Self) -> bool {
        required
            .0
            .iter()
            .all(|(name, value)| self.0.get(name) == Some(value))
    }
}

#[cfg(test)]
mod tests {
    use super::{LabelName, LabelValue, Labels};

    fn label(name: &str, value: &str) -> (LabelName, LabelValue) {
        (
            LabelName::new(name).expect("a non-blank name"),
            LabelValue::new(value).expect("a non-blank value"),
        )
    }

    fn labels(pairs: &[(&str, &str)]) -> Labels {
        pairs.iter().fold(Labels::none(), |set, (name, value)| {
            let (name, value) = label(name, value);
            set.with(name, value)
        })
    }

    #[test]
    fn labels_are_offered_in_a_stable_order() {
        // A Destination renders these for a person. A room where the same alert
        // reads differently each time is a room nobody trusts, so the order is
        // part of the contract rather than an accident of the map.
        let set = labels(&[
            ("service", "api"),
            ("alertname", "X"),
            ("namespace", "prod"),
        ]);

        let names: Vec<&str> = set.iter().map(|(name, _)| name.as_str()).collect();

        assert_eq!(names, vec!["alertname", "namespace", "service"]);
    }

    #[test]
    fn a_reserved_label_is_dropped_rather_than_honoured() {
        // The security property. A sender that could set `origin` could claim to
        // be another Origin and reach every room subscribed to it. Dropping is
        // the whole defence, and it happens before any matching.
        let forged = labels(&[("origin", "alertmanager"), ("severity", "critical")]);

        let safe = forged.without_reserved();

        assert_eq!(safe.len(), 1);
        assert!(
            safe.get(&LabelName::new("origin").expect("a name"))
                .is_none()
        );
    }

    #[test]
    fn dropping_a_reserved_label_keeps_everything_else() {
        // Dropped, not rejected: a sender including a reserved label must not be
        // able to deny itself delivery by doing so. It loses the label it was
        // never allowed to set, and nothing more.
        let forged = labels(&[
            ("origin", "lies"),
            ("namespace", "prod"),
            ("service", "api"),
        ]);

        let safe = forged.without_reserved();

        assert_eq!(safe.len(), 2);
        for (name, value) in [("namespace", "prod"), ("service", "api")] {
            let name = LabelName::new(name).expect("a name");
            assert_eq!(safe.get(&name).map(LabelValue::as_str), Some(value));
        }
    }

    #[test]
    fn labels_with_nothing_reserved_are_unchanged() {
        let honest = labels(&[("namespace", "prod")]);

        assert_eq!(honest.clone().without_reserved(), honest);
    }

    #[test]
    fn a_label_name_cannot_be_blank() {
        assert!(LabelName::new("").is_err());
        assert!(LabelName::new("  \t ").is_err());
    }

    #[test]
    fn a_label_value_cannot_be_blank() {
        assert!(LabelValue::new("").is_err());
        assert!(LabelValue::new("   ").is_err());
    }

    #[test]
    fn a_blank_label_says_which_concept_was_missing() {
        assert_eq!(
            LabelName::new("").expect_err("blank is rejected").concept(),
            "a label name"
        );
        assert_eq!(
            LabelValue::new("")
                .expect_err("blank is rejected")
                .concept(),
            "a label value"
        );
    }

    #[test]
    fn surrounding_whitespace_is_not_part_of_a_label() {
        let (name, value) = label("  severity \n", " critical ");

        assert_eq!(name.as_str(), "severity");
        assert_eq!(value.as_str(), "critical");
    }

    #[test]
    fn a_name_carries_one_value_and_a_later_one_replaces_it() {
        // Labels are a map, which is what both kinds of sender mean by the word.
        // Two values for one name would make admission ambiguous.
        let set = labels(&[("severity", "warning"), ("severity", "critical")]);

        assert_eq!(set.len(), 1);
        let name = LabelName::new("severity").expect("a name");
        assert_eq!(set.get(&name).map(LabelValue::as_str), Some("critical"));
    }

    #[test]
    fn nothing_is_required_of_an_event_by_an_empty_requirement() {
        // The degenerate case has to be stated: a Filter requiring nothing admits
        // everything, which is what makes Filter::Everything expressible twice
        // over rather than special.
        assert!(labels(&[("a", "1")]).contain_all(&Labels::none()));
        assert!(Labels::none().contain_all(&Labels::none()));
    }

    #[test]
    fn every_required_label_must_be_present_with_the_same_value() {
        let offered = labels(&[("repository", "motrice/webhook-proxy"), ("branch", "main")]);

        assert!(offered.contain_all(&labels(&[("branch", "main")])));
        assert!(offered.contain_all(&labels(&[
            ("branch", "main"),
            ("repository", "motrice/webhook-proxy"),
        ])));
    }

    #[test]
    fn a_required_label_the_event_does_not_carry_is_not_satisfied() {
        let offered = labels(&[("repository", "motrice/webhook-proxy")]);

        assert!(!offered.contain_all(&labels(&[("severity", "critical")])));
    }

    #[test]
    fn a_required_label_with_a_different_value_is_not_satisfied() {
        let offered = labels(&[("branch", "main")]);

        assert!(!offered.contain_all(&labels(&[("branch", "develop")])));
    }

    #[test]
    fn extra_labels_on_the_event_do_not_prevent_admission() {
        // An alert will carry labels nobody filters on. Requiring an exact match
        // would mean a Subscription had to enumerate every label a sender might
        // ever add.
        let offered = labels(&[("branch", "main"), ("repository", "r"), ("noise", "x")]);

        assert!(offered.contain_all(&labels(&[("branch", "main")])));
    }
}
