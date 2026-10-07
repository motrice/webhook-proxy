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

/// How an Origin proves a Delivery is genuine.
///
/// One variant per mechanism, which is what makes two things true without a
/// check: an Origin cannot declare no mechanism, and it cannot declare two.
///
/// The mechanism belongs to the Origin and is read from configuration. It is
/// never chosen by looking at the request — a sender presenting the weaker
/// mechanism to an Origin that declares the stronger one is refused, not retried.
/// Otherwise a downgrade would be something an attacker could ask for rather than
/// something a reviewer has to approve. Bead gc-ast.2.
///
/// Named for what the proof *is* rather than for the wire scheme that carries it.
/// `crates/architecture`'s purity test forbids transport vocabulary in this crate,
/// and the words the operator-facing configuration uses for these two are exactly
/// the kind it forbids — which is the right split anyway: the file names a wire
/// mechanism, the domain names a property.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verification {
    /// The proof is computed over the Body, so it is bound to what was sent.
    /// Replaying it against different content fails.
    Signed {
        /// Which secret produces it.
        secret: SecretId,
    },
    /// The proof is a value shared in advance, presented as it stands. It shows
    /// possession of that value and says nothing whatever about the Body, so a
    /// replay with different content still verifies.
    Shared {
        /// Which secret it must equal.
        secret: SecretId,
    },
}

/// An external system permitted to send us webhooks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    id: OriginId,
    verify: Verification,
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

impl Verification {
    /// Which secret this mechanism uses.
    #[must_use]
    pub fn secret(&self) -> &SecretId {
        match self {
            Self::Signed { secret } | Self::Shared { secret } => secret,
        }
    }
}

impl Origin {
    /// Registers an Origin and how it proves a Delivery is genuine.
    #[must_use]
    pub fn new(id: OriginId, verify: Verification) -> Self {
        Self { id, verify }
    }

    /// Which Origin this is.
    #[must_use]
    pub fn id(&self) -> &OriginId {
        &self.id
    }

    /// How it proves a Delivery is genuine.
    #[must_use]
    pub fn verify(&self) -> &Verification {
        &self.verify
    }

    /// Which secret to check it against, whichever mechanism it declares.
    #[must_use]
    pub fn secret(&self) -> &SecretId {
        self.verify.secret()
    }
}

#[cfg(test)]
mod tests {
    use super::{Origin, OriginId, SecretId, Verification};

    #[test]
    fn an_origin_declares_how_it_proves_itself() {
        // Not whether it proves itself — that is not a question an Origin can
        // answer. Which mechanism, and the secret that mechanism uses.
        let signing = Origin::new(
            OriginId::new("a-forge").expect("an identity"),
            Verification::Signed {
                secret: SecretId::new("its-secret").expect("a name"),
            },
        );
        let sharing = Origin::new(
            OriginId::new("a-monitor").expect("an identity"),
            Verification::Shared {
                secret: SecretId::new("its-value").expect("a name"),
            },
        );

        assert_eq!(signing.secret().as_str(), "its-secret");
        assert_eq!(sharing.secret().as_str(), "its-value");
        assert!(matches!(signing.verify(), Verification::Signed { .. }));
        assert!(matches!(sharing.verify(), Verification::Shared { .. }));
    }

    #[test]
    fn no_origin_can_declare_no_mechanism_or_two() {
        // Both halves are the type's doing rather than a check's. `verify()`
        // returns a Verification and not an Option, so there is no Origin without
        // one; and a Verification is one variant, so there is no Origin with two.
        // This test exists to say that out loud — the next person should not have
        // to infer it from the absence of a guard.
        let origin = Origin::new(
            OriginId::new("a-forge").expect("an identity"),
            Verification::Signed {
                secret: SecretId::new("its-secret").expect("a name"),
            },
        );

        let _: &Verification = origin.verify();
    }

    #[test]
    fn the_same_secret_under_two_mechanisms_is_two_different_declarations() {
        // The mechanism is part of what an Origin *is*. If these compared equal,
        // a configuration change from one to the other could pass review as a
        // no-op — which is the downgrade gc-ast.2 exists to prevent.
        let secret = || SecretId::new("shared").expect("a name");

        assert_ne!(
            Verification::Signed { secret: secret() },
            Verification::Shared { secret: secret() }
        );
    }

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
            Verification::Signed {
                secret: SecretId::new("github-webhook-secret").expect("a non-blank secret name"),
            },
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
            Verification::Signed {
                secret: SecretId::new("github-webhook-secret").expect("a non-blank secret name"),
            },
        );

        let printed = format!("{origin:?}");

        // A secret id is a lookup key and is safe to print; this asserts that
        // is genuinely all that appears.
        assert!(printed.contains("github-webhook-secret"), "{printed}");
        assert!(!printed.contains("hmac"), "{printed}");
    }
}
