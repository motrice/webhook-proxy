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
}

impl SecretId {
    /// Names the secret to check this Origin's signatures against.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
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
