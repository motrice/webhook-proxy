//! Who is allowed to send us webhooks.

use crate::Blank;
use crate::event::present;

/// Identifies an [`Origin`]: an external system permitted to send us webhooks.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OriginId(String);

/// Names the secret an Origin's signatures are checked against — the *name*,
/// never the value. The value lives in configuration and reaches only the
/// adapter that computes signatures, so no secret material can enter the
/// domain even by accident.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretId(String);

/// An external system permitted to send us webhooks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    id: OriginId,
    secret: SecretId,
}

impl OriginId {
    /// Names an Origin.
    ///
    /// # Errors
    ///
    /// [`Blank`] if the name is empty or only whitespace. These two took
    /// `impl Into<String>` and checked nothing, which made them the only names
    /// in this crate that could be blank — and a blank Origin identity is not a
    /// harmless oddity: it is projected as the `origin` label that decides which
    /// rooms a sender may reach. Bead gc-qz6.
    pub fn new(id: &str) -> Result<Self, Blank> {
        present(id, "an origin identity").map(Self)
    }

    /// The name as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl SecretId {
    /// Names the secret to check this Origin's signatures against.
    ///
    /// # Errors
    ///
    /// [`Blank`] if the name is empty or only whitespace. A blank one would be
    /// looked up, found missing, and reported as `SecretUnavailable` at the first
    /// request — turning a configuration mistake into a runtime failure that
    /// looks like an outage.
    pub fn new(id: &str) -> Result<Self, Blank> {
        present(id, "a secret name").map(Self)
    }

    /// The name as text, so an adapter can look the secret up. This is a
    /// lookup key and safe to print; the value it names never enters the
    /// domain at all.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Origin {
    /// Registers an Origin and the secret its signatures are checked against.
    #[must_use]
    pub fn new(id: OriginId, secret: SecretId) -> Self {
        Self { id, secret }
    }

    /// Which Origin this is.
    #[must_use]
    pub fn id(&self) -> &OriginId {
        &self.id
    }

    /// Which secret to check its signatures against.
    #[must_use]
    pub fn secret(&self) -> &SecretId {
        &self.secret
    }
}

#[cfg(test)]
mod tests {
    use super::{Origin, OriginId, SecretId};

    #[test]
    fn an_origin_identity_cannot_be_blank() {
        // These were the only names in the crate that could be. A blank one is
        // not a harmless oddity: it is projected as the `origin` label that
        // decides which rooms a sender may reach.
        assert!(OriginId::new("").is_err());
        assert!(OriginId::new("  \t ").is_err());
        assert_eq!(
            OriginId::new("").expect_err("blank is rejected").concept(),
            "an origin identity"
        );
    }

    #[test]
    fn a_secret_name_cannot_be_blank() {
        assert!(SecretId::new("").is_err());
        assert_eq!(
            SecretId::new("   ")
                .expect_err("blank is rejected")
                .concept(),
            "a secret name"
        );
    }

    #[test]
    fn surrounding_whitespace_is_not_part_of_either_name() {
        let id = OriginId::new("  a-forge \n").expect("an identity");
        let secret = SecretId::new(" its-secret ").expect("a name");

        assert_eq!(id.as_str(), "a-forge");
        assert_eq!(secret.as_str(), "its-secret");
    }

    #[test]
    fn an_origin_names_its_secret_rather_than_carrying_it() {
        let origin = Origin::new(
            OriginId::new("github").expect("a non-blank origin identity"),
            SecretId::new("github-webhook-secret").expect("a non-blank secret name"),
        );

        // The point is structural, not textual: there is no constructor, field
        // or accessor on Origin through which a secret *value* could travel.
        // The strongest thing a test can say is that what Origin reveals is a
        // name, and that the name is all it has.
        assert_eq!(
            origin.secret(),
            &SecretId::new("github-webhook-secret").expect("a non-blank secret name")
        );
        assert_eq!(
            origin.id(),
            &OriginId::new("github").expect("a non-blank origin identity")
        );
    }

    #[test]
    fn a_secret_id_can_be_read_as_text_because_an_adapter_must_look_it_up() {
        assert_eq!(
            SecretId::new("github-webhook-secret")
                .expect("a non-blank secret name")
                .as_str(),
            "github-webhook-secret"
        );
    }

    #[test]
    fn debug_output_shows_only_names_so_a_log_line_cannot_leak_a_secret() {
        let origin = Origin::new(
            OriginId::new("github").expect("a non-blank origin identity"),
            SecretId::new("github-webhook-secret").expect("a non-blank secret name"),
        );

        let printed = format!("{origin:?}");

        // A secret id is a lookup key and is safe to print; this asserts that
        // is genuinely all that appears.
        assert!(printed.contains("github-webhook-secret"), "{printed}");
        assert!(!printed.contains("hmac"), "{printed}");
    }
}
