//! A value shared in advance, presented as it stands.
//!
//! The second way an Origin can prove a Delivery is genuine, and the weaker one:
//! this proves possession of a value and says nothing whatever about the body, so
//! a value obtained once can be replayed against any content for as long as it
//! lives. That cost is accepted because the senders this exists for cannot sign
//! — see bead gc-ast.2, which records it rather than leaving it to be discovered.
//!
//! Like the signature adapter, this decides nothing. It hands the application two
//! [`Proof`]s and `Delivery::verify` in the domain compares them, so the security
//! judgement and the constant-time comparison stay in the crate with no
//! dependencies, tested there once for every mechanism rather than once per
//! adapter. Nothing in this file compares anything.
//!
//! **A mechanism is not a fallback.** An Origin that declares it signs is refused
//! here outright. If one were ever verified by presenting a value instead, every
//! guarantee in README would be void, and the refusal is what makes a mis-wiring
//! fail closed rather than silently downgrade.

use std::collections::HashMap;

use application::ports::{MalformedProof, Proofs, SecretUnavailable};
use domain::{Body, Origin, Proof, Verification};
use std::fmt;

/// The authorization scheme a sender presents this under.
///
/// Matched case-insensitively: RFC 7235 says the scheme is case-insensitive, and
/// refusing `bearer` from a sender that spells it that way would be our bug
/// dressed up as theirs.
const SCHEME: &str = "bearer";

/// Compares what a sender presented against the value its Origin shares.
///
/// Holds the values, keyed by the name an [`Origin`] refers to. They live here
/// and nowhere else: the domain holds only names, so none can reach a log line
/// by way of a `Debug` on a domain value.
pub struct SharedValues {
    secrets: HashMap<String, Vec<u8>>,
}

impl SharedValues {
    /// Holds the values this adapter can use, by the name Origins refer to.
    #[must_use]
    pub fn new(secrets: HashMap<String, Vec<u8>>) -> Self {
        Self { secrets }
    }
}

/// A count, never a value.
///
/// Written by hand rather than derived, and the derive is the reason: this type
/// holds credentials, and a derived `Debug` would put every one of them into
/// whatever log line touched it.
impl fmt::Debug for SharedValues {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SharedValues({} held)", self.secrets.len())
    }
}

impl Proofs for SharedValues {
    /// The value this Origin's secret is, which is the whole of the mechanism.
    ///
    /// The body is not read, and that is the difference from a signature stated
    /// in one line: there is nothing of what was sent in what is compared.
    ///
    /// # Errors
    ///
    /// [`SecretUnavailable`] if the Origin declares a different mechanism, or if
    /// no value of that name is held. Both mean no judgement was possible, which
    /// is not the same answer as a mismatch.
    fn expected(&self, origin: &Origin, _body: &Body) -> Result<Proof, SecretUnavailable> {
        // First, before anything else is looked at. An Origin that signs must
        // never be verifiable by presenting a value, whatever else is true.
        match origin.verify() {
            Verification::Shared { .. } => {}
            Verification::Signed { .. } => return Err(SecretUnavailable),
        }

        let secret = self
            .secrets
            .get(origin.secret().as_str())
            .ok_or(SecretUnavailable)?;

        Ok(Proof::from_bytes(secret.clone()))
    }

    /// Reads what a sender presented in an authorization header.
    ///
    /// # Errors
    ///
    /// [`MalformedProof::UnknownScheme`] if the value does not begin with the
    /// scheme this reads, including when nothing was presented at all;
    /// [`MalformedProof::Unreadable`] if the scheme was there but nothing
    /// followed it. The two are kept apart for an operator reading logs — a
    /// sender that sends no header is a different problem from one that sends an
    /// empty value — and are the same answer to whoever asked, because the
    /// inbound adapter maps every refusal to one status.
    fn claimed(&self, presented: &str) -> Result<Proof, MalformedProof> {
        let (scheme, value) = presented
            .split_once(' ')
            .ok_or(MalformedProof::UnknownScheme)?;

        if !scheme.eq_ignore_ascii_case(SCHEME) {
            return Err(MalformedProof::UnknownScheme);
        }

        // Surrounding whitespace is an editor's or a template's doing, not part
        // of what was shared.
        let value = value.trim();
        if value.is_empty() {
            return Err(MalformedProof::Unreadable);
        }

        Ok(Proof::from_bytes(value.as_bytes().to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use application::ports::{MalformedProof, Proofs, SecretUnavailable};
    use domain::{Body, Delivery, DeliveryId, Origin, OriginId, SecretId, Timestamp, Verification};

    use super::SharedValues;

    const VALUE: &str = "not-a-real-value-but-long-enough-to-be-one";

    fn holding(name: &str, value: &str) -> SharedValues {
        SharedValues::new(HashMap::from([(
            name.to_owned(),
            value.as_bytes().to_vec(),
        )]))
    }

    fn origin_sharing(id: &str, secret: &str) -> Origin {
        Origin::new(
            OriginId::new(id).expect("an identity"),
            Verification::Shared {
                secret: SecretId::new(secret).expect("a name"),
            },
        )
    }

    fn origin_signing(id: &str, secret: &str) -> Origin {
        Origin::new(
            OriginId::new(id).expect("an identity"),
            Verification::Signed {
                secret: SecretId::new(secret).expect("a name"),
            },
        )
    }

    /// Whether a presented value verifies for that Origin, decided by the domain
    /// exactly as the application decides it.
    fn verifies(adapter: &SharedValues, origin: &Origin, presented: &str) -> bool {
        let body = Body::from_bytes(b"irrelevant".to_vec());
        let Ok(expected) = adapter.expected(origin, &body) else {
            return false;
        };
        let Ok(claimed) = adapter.claimed(presented) else {
            return false;
        };
        Delivery::new(
            DeliveryId::new("d-1").expect("an identity"),
            origin.id().clone(),
            body,
            Timestamp::from_millis_since_epoch(0),
        )
        .verify(&claimed, &expected)
        .is_ok()
    }

    // ---- the downgrade case, written first --------------------------------
    //
    // If an Origin configured for signatures ever accepts a presented value,
    // every guarantee in README is void. A mechanism is not a fallback.

    #[test]
    fn an_origin_that_signs_is_never_verified_by_a_presented_value() {
        let adapter = holding("its-secret", VALUE);
        let signing = origin_signing("a-forge", "its-secret");

        // Even presenting exactly the right value, and even with the value held.
        assert!(!verifies(&adapter, &signing, &format!("Bearer {VALUE}")));

        // And the refusal is at the mechanism, before the value is looked at:
        // no judgement was possible, which is not the same as a mismatch.
        assert_eq!(
            adapter
                .expected(&signing, &Body::from_bytes(b"x".to_vec()))
                .err(),
            Some(SecretUnavailable)
        );
    }

    #[test]
    fn the_signature_adapter_does_not_accept_a_presented_value_either() {
        // The other half of "and vice versa". Stated here because this is the
        // bead that introduced a second mechanism; the assertion lives with the
        // reasoning rather than in a crate that predates it.
        //
        // GithubSignatures computes a digest over the body, so a presented value
        // can only match it by being that digest — which requires the secret. The
        // structural half is that it refuses an Origin declaring Shared, tested
        // in that crate.
        let adapter = holding("its-secret", VALUE);
        assert!(!verifies(
            &adapter,
            &origin_signing("a-forge", "its-secret"),
            &format!("Bearer {VALUE}")
        ));
    }

    // ---- the mechanism working ------------------------------------------

    #[test]
    fn the_configured_value_for_its_own_origin_verifies() {
        let adapter = holding("its-secret", VALUE);
        let origin = origin_sharing("a-monitor", "its-secret");

        assert!(verifies(&adapter, &origin, &format!("Bearer {VALUE}")));
    }

    #[test]
    fn the_scheme_is_read_however_the_sender_spelled_it() {
        // RFC 7235 says the scheme is case-insensitive. Refusing a sender that
        // writes it differently would be our bug dressed up as theirs.
        let adapter = holding("its-secret", VALUE);
        let origin = origin_sharing("a-monitor", "its-secret");

        for spelling in ["Bearer", "bearer", "BEARER", "BeArEr"] {
            assert!(
                verifies(&adapter, &origin, &format!("{spelling} {VALUE}")),
                "{spelling}"
            );
        }
    }

    // ---- everything that must be refused ---------------------------------

    #[test]
    fn a_wrong_value_is_refused() {
        let adapter = holding("its-secret", VALUE);
        let origin = origin_sharing("a-monitor", "its-secret");

        assert!(!verifies(&adapter, &origin, "Bearer not-the-right-value"));
        // One byte short, one byte over, one byte different.
        assert!(!verifies(
            &adapter,
            &origin,
            &format!("Bearer {}", &VALUE[..VALUE.len() - 1])
        ));
        assert!(!verifies(&adapter, &origin, &format!("Bearer {VALUE}x")));
        assert!(!verifies(
            &adapter,
            &origin,
            &format!("Bearer {}X", &VALUE[..VALUE.len() - 1])
        ));
    }

    #[test]
    fn nothing_presented_a_blank_value_and_another_scheme_are_each_refused() {
        let adapter = holding("its-secret", VALUE);
        let origin = origin_sharing("a-monitor", "its-secret");

        for presented in [
            "",
            "Bearer",
            "Bearer ",
            "Bearer    ",
            "Basic dXNlcjpwYXNz",
            "Token abc",
            VALUE,
        ] {
            assert!(
                !verifies(&adapter, &origin, presented),
                "accepted {presented:?}"
            );
        }
    }

    #[test]
    fn a_value_for_one_origin_does_not_verify_for_another() {
        let adapter = SharedValues::new(HashMap::from([
            ("a-secret".to_owned(), b"value-for-a".to_vec()),
            ("b-secret".to_owned(), b"value-for-b".to_vec()),
        ]));

        let a = origin_sharing("monitor-a", "a-secret");
        let b = origin_sharing("monitor-b", "b-secret");

        assert!(verifies(&adapter, &a, "Bearer value-for-a"));
        assert!(verifies(&adapter, &b, "Bearer value-for-b"));

        // The one that matters: each other's.
        assert!(!verifies(&adapter, &a, "Bearer value-for-b"));
        assert!(!verifies(&adapter, &b, "Bearer value-for-a"));
    }

    #[test]
    fn an_origin_whose_value_is_not_held_cannot_be_judged_rather_than_being_let_through() {
        let adapter = holding("its-secret", VALUE);
        let unknown = origin_sharing("a-monitor", "not-deployed");

        assert_eq!(
            adapter
                .expected(&unknown, &Body::from_bytes(b"x".to_vec()))
                .err(),
            Some(SecretUnavailable)
        );
        assert!(!verifies(&adapter, &unknown, &format!("Bearer {VALUE}")));
    }

    // ---- what must never be observable ----------------------------------

    #[test]
    fn nothing_here_compares_anything_so_the_timing_property_is_the_domains() {
        // This adapter hands over two Proofs and never compares them: Proof has
        // no PartialEq at all, and `matches` accumulates every difference with no
        // early return. That is tested once in the domain, with a compile_fail
        // doctest proving `==` does not exist, rather than once per adapter here
        // where it could drift.
        //
        // What this pins is that a difference anywhere in the value is refused —
        // first byte, last byte, length — so no position is privileged.
        let adapter = holding("its-secret", "abcdefgh");
        let origin = origin_sharing("a-monitor", "its-secret");

        for wrong in ["Xbcdefgh", "abcdefgX", "abcXefgh", "abcdefg", "abcdefghi"] {
            assert!(
                !verifies(&adapter, &origin, &format!("Bearer {wrong}")),
                "{wrong}"
            );
        }
        assert!(verifies(&adapter, &origin, "Bearer abcdefgh"));
    }

    #[test]
    fn no_part_of_a_value_appears_in_any_error_or_in_debug_output() {
        // Asserted on what is actually produced, not by reading the code.
        let adapter = holding("its-secret", VALUE);
        let origin = origin_sharing("a-monitor", "its-secret");

        let rendered = format!("{adapter:?}");
        assert!(!rendered.contains(VALUE), "{rendered}");
        // Not even a prefix of it: a partial credential is still a credential.
        assert!(!rendered.contains(&VALUE[..8]), "{rendered}");

        let errors = [
            format!("{:?}", adapter.claimed("").err()),
            format!("{:?}", adapter.claimed("Bearer ").err()),
            format!("{:?}", adapter.claimed(&format!("Bearer {VALUE}")).err()),
            format!("{:?}", adapter.claimed("Basic abc").err()),
            format!(
                "{:?}",
                adapter
                    .expected(&origin, &Body::from_bytes(b"x".to_vec()))
                    .err()
            ),
        ];
        for rendered in errors {
            assert!(!rendered.contains(VALUE), "{rendered}");
            assert!(!rendered.contains(&VALUE[..8]), "{rendered}");
        }

        // And the Proof itself, which is the value, must not print it either.
        let proof = adapter
            .claimed(&format!("Bearer {VALUE}"))
            .expect("a well-formed header");
        let rendered = format!("{proof:?}");
        assert!(!rendered.contains(VALUE), "{rendered}");
        assert!(!rendered.contains(&VALUE[..8]), "{rendered}");
    }

    #[test]
    fn the_two_malformed_cases_stay_apart_for_an_operator() {
        // Kept distinct on purpose, per gc-ast.2: a sender that sends no header
        // is a different problem from one that sends an empty value, and an
        // operator debugging a silent sender needs to tell them apart.
        //
        // They are the same answer to whoever asked — the inbound adapter maps
        // every refusal to one status — and that is asserted at the HTTP boundary
        // in gc-ast.12, because this crate cannot observe a status code and a
        // test here claiming otherwise would be theatre.
        let adapter = holding("its-secret", VALUE);

        assert_eq!(
            adapter.claimed("").err(),
            Some(MalformedProof::UnknownScheme)
        );
        assert_eq!(
            adapter.claimed("Basic abc").err(),
            Some(MalformedProof::UnknownScheme)
        );
        assert_eq!(
            adapter.claimed("Bearer ").err(),
            Some(MalformedProof::Unreadable)
        );
    }

    #[test]
    fn the_body_is_not_read_which_is_the_whole_weakness() {
        // Stated as a test because it is the cost gc-ast.2 accepted: the same
        // presented value verifies against any content, so a value obtained once
        // can be replayed with a different payload. A signature cannot be.
        let adapter = holding("its-secret", VALUE);
        let origin = origin_sharing("a-monitor", "its-secret");

        let one = adapter
            .expected(&origin, &Body::from_bytes(b"one thing".to_vec()))
            .expect("the value is held");
        let other = adapter
            .expected(
                &origin,
                &Body::from_bytes(b"something else entirely".to_vec()),
            )
            .expect("the value is held");

        assert!(one.matches(&other), "the body changed what is compared");
    }
}
