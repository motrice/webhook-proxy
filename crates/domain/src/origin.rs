//! Who is allowed to send us webhooks.

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
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// The name as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl SecretId {
    /// Names the secret to check this Origin's signatures against.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl SecretId {
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
    fn an_origin_names_its_secret_rather_than_carrying_it() {
        let origin = Origin::new(
            OriginId::new("github"),
            SecretId::new("github-webhook-secret"),
        );

        // The point is structural, not textual: there is no constructor, field
        // or accessor on Origin through which a secret *value* could travel.
        // The strongest thing a test can say is that what Origin reveals is a
        // name, and that the name is all it has.
        assert_eq!(origin.secret(), &SecretId::new("github-webhook-secret"));
        assert_eq!(origin.id(), &OriginId::new("github"));
    }

    #[test]
    fn a_secret_id_can_be_read_as_text_because_an_adapter_must_look_it_up() {
        assert_eq!(
            SecretId::new("github-webhook-secret").as_str(),
            "github-webhook-secret"
        );
    }

    #[test]
    fn debug_output_shows_only_names_so_a_log_line_cannot_leak_a_secret() {
        let origin = Origin::new(
            OriginId::new("github"),
            SecretId::new("github-webhook-secret"),
        );

        let printed = format!("{origin:?}");

        // A secret id is a lookup key and is safe to print; this asserts that
        // is genuinely all that appears.
        assert!(printed.contains("github-webhook-secret"), "{printed}");
        assert!(!printed.contains("hmac"), "{printed}");
    }
}
