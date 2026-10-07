//! An alert from a monitoring system, as a business fact.
//!
//! An alert is a fact in the same sense a push is, so it lives in [`Event`] as a
//! variant rather than as a parallel concept: one fan-out, one routing function,
//! one dispatch port. What makes it different is where its labels come from. A
//! push projects its labels from typed fields, so there is nowhere to put one; an
//! alert *stores* the labels it was sent, and those come from workload
//! annotations — from whoever can deploy. That is why reserved names exist (bead
//! gc-srw), and this is the first variant where the dropping matters.
//!
//! [`Event`]: crate::Event

use crate::Blank;
use crate::event::present;

/// A sender's own identity for an alert.
///
/// Opaque: a fingerprint, a rule identity, whatever the sender calls it. The
/// domain neither parses nor shortens one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertId(String);

/// How urgent an alert says it is.
///
/// The three known levels are the ones monitoring systems conventionally use.
/// The other two variants are different facts and are kept apart deliberately:
/// a sender that said nothing is not the same as a sender that said something we
/// do not understand, and collapsing them would lose the only clue available for
/// telling a misconfiguration from a convention we have not met.
///
/// Neither of those two has an urgency. There is no honest rank for them: a low
/// one would hide a critical alert behind a typo, and a high one would promote
/// noise. Bead gc-ast.1 settled this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Severity {
    /// Act now.
    Critical,
    /// Act soon.
    Warning,
    /// Worth knowing.
    Info,
    /// The sender gave no severity.
    Unstated,
    /// The sender gave one we do not know, kept as they wrote it.
    Unrecognised(String),
}

/// Whether an alert is still firing or has resolved.
///
/// Two values and no third: an alert is one or the other, and there is no
/// "unknown" because a sender that cannot say which is not describing an alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertStatus {
    /// Still happening.
    Firing,
    /// Over.
    Resolved,
}

impl AlertId {
    /// Takes the sender's identity for an alert.
    ///
    /// # Errors
    ///
    /// [`Blank`] if the identity is empty or only whitespace.
    pub fn new(id: &str) -> Result<Self, Blank> {
        present(id, "an alert identity").map(Self)
    }

    /// The identity as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Severity {
    /// Reads a severity as a sender spelled it.
    ///
    /// Case and surrounding whitespace are ignored, because `Critical` and
    /// `critical` are the same claim and a sender's capitalisation is not a
    /// distinction worth carrying. Anything else is kept verbatim rather than
    /// refused: an alert with an odd severity is still an alert, and dropping it
    /// would mean a room hears nothing about something that is firing.
    #[must_use]
    pub fn from_label(stated: &str) -> Self {
        let trimmed = stated.trim();
        match trimmed.to_lowercase().as_str() {
            "" => Self::Unstated,
            "critical" => Self::Critical,
            "warning" => Self::Warning,
            "info" => Self::Info,
            _ => Self::Unrecognised(trimmed.to_owned()),
        }
    }

    /// How urgent, higher being more urgent, or `None` when there is no honest
    /// answer.
    ///
    /// For presentation and grouping. **Not** for filtering: a Filter compares
    /// labels for equality, so a rule naming `critical` selects critical alerts
    /// and nothing else. Ordering here never widens what a rule admits.
    #[must_use]
    pub fn urgency(&self) -> Option<u8> {
        match self {
            Self::Critical => Some(3),
            Self::Warning => Some(2),
            Self::Info => Some(1),
            Self::Unstated | Self::Unrecognised(_) => None,
        }
    }

    /// How this appears as a label value, or `None` when there is nothing to
    /// match on.
    #[must_use]
    pub fn as_label(&self) -> Option<&str> {
        match self {
            Self::Critical => Some("critical"),
            Self::Warning => Some("warning"),
            Self::Info => Some("info"),
            Self::Unrecognised(raw) => Some(raw),
            Self::Unstated => None,
        }
    }
}

impl AlertStatus {
    /// Reads a status as a sender spelled it.
    ///
    /// `None` for anything else, which is not the same as a default: a sender
    /// that cannot say whether something is still happening is not describing an
    /// alert, and guessing would mean telling a room "resolved" about something
    /// still firing. Every sender so far uses these two words.
    ///
    /// Lives here rather than in each inbound adapter because two senders want
    /// it and adapters may not depend on each other — and because it is the same
    /// kind of knowledge as [`Severity::from_label`], which was already here.
    #[must_use]
    pub fn from_label(stated: &str) -> Option<Self> {
        match stated.trim().to_lowercase().as_str() {
            "firing" => Some(Self::Firing),
            "resolved" => Some(Self::Resolved),
            _ => None,
        }
    }

    /// How this appears as a label value.
    #[must_use]
    pub fn as_label(&self) -> &'static str {
        match self {
            Self::Firing => "firing",
            Self::Resolved => "resolved",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AlertId, AlertStatus, Severity};

    #[test]
    fn an_alert_identity_cannot_be_blank() {
        assert!(AlertId::new("").is_err());
        assert!(AlertId::new("  \t ").is_err());
        assert_eq!(
            AlertId::new("").expect_err("blank is rejected").concept(),
            "an alert identity"
        );
    }

    #[test]
    fn an_alert_identity_is_kept_verbatim() {
        // It is the sender's own identity for the alert — a fingerprint, a rule
        // identity — and the domain neither parses nor shortens it.
        let id = AlertId::new("  7b1a177c8d03f9e9  ").expect("an identity");

        assert_eq!(id.as_str(), "7b1a177c8d03f9e9");
    }

    #[test]
    fn severity_reads_a_known_level_and_keeps_what_it_does_not_know() {
        assert_eq!(Severity::from_label("critical"), Severity::Critical);
        assert_eq!(Severity::from_label("  Warning "), Severity::Warning);
        assert_eq!(Severity::from_label("INFO"), Severity::Info);
        assert_eq!(
            Severity::from_label("page-the-duty-officer"),
            Severity::Unrecognised("page-the-duty-officer".to_owned())
        );
    }

    #[test]
    fn an_absent_severity_and_an_unknown_one_are_different_facts() {
        // Two different things happened: a sender said nothing, or a sender said
        // something we do not understand. Collapsing them would lose the only
        // information available for telling a misconfiguration from a convention
        // we have not met.
        assert_eq!(Severity::from_label("   "), Severity::Unstated);
        assert_ne!(Severity::Unstated, Severity::Unrecognised(String::new()));
    }

    #[test]
    fn the_known_levels_are_ordered_and_the_others_have_no_rank() {
        // Urgency is for presentation and grouping, never for filtering: filters
        // compare labels for equality. Unstated and Unrecognised have no honest
        // rank — inventing a low one would hide a critical alert behind a typo,
        // and inventing a high one would promote noise — so they have none.
        let critical = Severity::Critical.urgency().expect("a rank");
        let warning = Severity::Warning.urgency().expect("a rank");
        let info = Severity::Info.urgency().expect("a rank");

        assert!(critical > warning, "{critical} > {warning}");
        assert!(warning > info, "{warning} > {info}");

        assert_eq!(Severity::Unstated.urgency(), None);
        assert_eq!(Severity::Unrecognised("odd".to_owned()).urgency(), None);
    }

    #[test]
    fn severity_spells_itself_the_way_a_filter_would_be_written() {
        assert_eq!(Severity::Critical.as_label(), Some("critical"));
        assert_eq!(Severity::Warning.as_label(), Some("warning"));
        assert_eq!(Severity::Info.as_label(), Some("info"));
        // The raw text, so a rule can still match a convention we do not know.
        assert_eq!(
            Severity::Unrecognised("sev1".to_owned()).as_label(),
            Some("sev1")
        );
        // Nothing to match on, so no label at all rather than a blank one.
        assert_eq!(Severity::Unstated.as_label(), None);
    }

    #[test]
    fn a_status_is_read_however_the_sender_spelled_it() {
        assert_eq!(AlertStatus::from_label("firing"), Some(AlertStatus::Firing));
        assert_eq!(
            AlertStatus::from_label("  Resolved \n"),
            Some(AlertStatus::Resolved)
        );
        assert_eq!(AlertStatus::from_label("FIRING"), Some(AlertStatus::Firing));
    }

    #[test]
    fn a_status_we_do_not_know_is_none_rather_than_a_default() {
        // Guessing would mean telling a room "resolved" about something still
        // firing, which is the one mistake here with real consequences.
        for unknown in ["", "   ", "flapping", "pending", "alerting"] {
            assert_eq!(AlertStatus::from_label(unknown), None, "{unknown}");
        }
    }

    #[test]
    fn a_status_spells_itself_for_a_filter_too() {
        assert_eq!(AlertStatus::Firing.as_label(), "firing");
        assert_eq!(AlertStatus::Resolved.as_label(), "resolved");
    }
}
