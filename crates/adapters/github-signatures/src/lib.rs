//! GitHub's signature scheme, in one place: computing the signature we expect
//! over a body, and reading the one a request claims.
//!
//! This adapter does not decide anything. It hands a computed [`Signature`] to
//! the application, and `Delivery::verify` in the domain compares it against the
//! claimed one — so the security judgement stays in the crate with no
//! dependencies, and the constant-time comparison is tested there, once, for
//! every Origin rather than once per adapter.

use std::collections::HashMap;

use application::ports::{SecretUnavailable, Signatures};
use domain::{Body, Origin, Signature};
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Length of a hex-encoded SHA-256 digest.
const HEX_DIGEST: usize = 64;

/// The header scheme GitHub uses for `X-Hub-Signature-256`.
const SCHEME: &str = "sha256=";

/// Computes the signature GitHub's secret would produce over a body.
///
/// Holds the secrets, keyed by the name an [`Origin`] refers to. The secret
/// values live here and nowhere else: the domain holds only names, so no secret
/// can reach a log line by way of a `Debug` on a domain value.
pub struct GithubSignatures {
    secrets: HashMap<String, Vec<u8>>,
}

/// A claimed signature header could not be read.
///
/// Not the same thing as a mismatch: this means the request did not present
/// something we could compare at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MalformedSignature {
    /// Missing or unrecognised `sha256=` prefix.
    UnknownScheme,
    /// The part after the prefix is not a hex-encoded SHA-256 digest.
    NotHex,
}

impl GithubSignatures {
    /// Holds the secrets this adapter can use, by the name Origins refer to.
    #[must_use]
    pub fn new(secrets: HashMap<String, Vec<u8>>) -> Self {
        Self { secrets }
    }
}

impl Signatures for GithubSignatures {
    fn expected(&self, origin: &Origin, body: &Body) -> Result<Signature, SecretUnavailable> {
        let secret = self
            .secrets
            .get(origin.secret().as_str())
            .ok_or(SecretUnavailable)?;

        // HMAC accepts a key of any length, so the only error here is one that
        // cannot happen; it is still mapped rather than unwrapped, because a
        // panic in the request path is a denial of service.
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).map_err(|_| SecretUnavailable)?;
        mac.update(body.as_bytes());

        Ok(Signature::from_bytes(
            mac.finalize().into_bytes().as_slice().to_vec(),
        ))
    }
}

/// Reads the signature a request claims, from the value GitHub sends in
/// `X-Hub-Signature-256`.
///
/// Lives here rather than in the HTTP adapter because the spelling of a
/// signature is part of GitHub's scheme, not part of being an HTTP server.
///
/// # Errors
///
/// [`MalformedSignature`] if the value is absent a known scheme or is not a
/// hex-encoded SHA-256 digest. A malformed header is never treated as a match,
/// and never panics: it arrives from the open internet.
pub fn claimed(header: &str) -> Result<Signature, MalformedSignature> {
    let digest = header
        .strip_prefix(SCHEME)
        .ok_or(MalformedSignature::UnknownScheme)?;

    // Check the length before decoding so a short-but-valid hex string cannot
    // produce a shorter signature that happens to compare equal to a truncated
    // one. The domain rejects differing lengths too; both is cheap.
    if digest.len() != HEX_DIGEST {
        return Err(MalformedSignature::NotHex);
    }

    hex::decode(digest)
        .map(Signature::from_bytes)
        .map_err(|_| MalformedSignature::NotHex)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use application::ports::Signatures;
    use domain::{Body, Origin, OriginId, SecretId};

    use super::{GithubSignatures, MalformedSignature, claimed};

    /// A real-shaped GitHub push payload, byte for byte as it would arrive.
    const BODY: &[u8] = include_bytes!("../fixtures/push.json");
    /// The `X-Hub-Signature-256` value for BODY under SECRET, computed by
    /// openssl and cross-checked against python's hmac — deliberately not by
    /// this crate, so the test is an oracle rather than a mirror.
    const SIGNATURE: &str = include_str!("../fixtures/push.signature");
    /// Test-only secret. Never used by any real deployment.
    const SECRET: &str = include_str!("../fixtures/push.secret");

    const SECRET_NAME: &str = "a-webhook-secret";

    fn verifier() -> GithubSignatures {
        let mut secrets = HashMap::new();
        secrets.insert(SECRET_NAME.to_owned(), SECRET.as_bytes().to_vec());
        GithubSignatures::new(secrets)
    }

    fn origin() -> Origin {
        Origin::new(OriginId::new("a-forge"), SecretId::new(SECRET_NAME))
    }

    #[test]
    fn the_expected_signature_matches_a_captured_delivery() {
        let expected = verifier()
            .expected(&origin(), &Body::from_bytes(BODY.to_vec()))
            .expect("the secret is known");

        assert!(expected.matches(&claimed(SIGNATURE).expect("a well-formed header")));
    }

    #[test]
    fn a_single_changed_byte_in_the_body_fails_verification() {
        let mut tampered = BODY.to_vec();
        let last = tampered.len() - 2;
        tampered[last] ^= 0x01;

        let expected = verifier()
            .expected(&origin(), &Body::from_bytes(tampered))
            .expect("the secret is known");

        assert!(!expected.matches(&claimed(SIGNATURE).expect("a well-formed header")));
    }

    #[test]
    fn a_body_that_is_valid_json_but_reserialised_fails_verification() {
        // The defect this guards against passes every happy-path test and fails
        // the first time a real payload round-trips differently: verifying a
        // re-encoded body rather than the bytes that arrived.
        let parsed: serde_json::Value = serde_json::from_slice(BODY).expect("valid JSON");
        let reserialised = serde_json::to_vec(&parsed).expect("serialisable");

        assert_ne!(
            reserialised, BODY,
            "the fixture must not already be compact"
        );

        let expected = verifier()
            .expected(&origin(), &Body::from_bytes(reserialised))
            .expect("the secret is known");

        assert!(!expected.matches(&claimed(SIGNATURE).expect("a well-formed header")));
    }

    #[test]
    fn an_unknown_secret_name_is_unavailable_rather_than_a_mismatch() {
        let unknown = Origin::new(OriginId::new("a-forge"), SecretId::new("not-configured"));

        let outcome = verifier().expected(&unknown, &Body::from_bytes(BODY.to_vec()));

        assert!(outcome.is_err());
    }

    #[test]
    fn a_header_without_the_scheme_is_malformed() {
        let digest = SIGNATURE.trim_start_matches("sha256=");

        assert_eq!(claimed(digest), Err(MalformedSignature::UnknownScheme));
        assert_eq!(claimed(""), Err(MalformedSignature::UnknownScheme));
        assert_eq!(
            claimed(&format!("sha1={digest}")),
            Err(MalformedSignature::UnknownScheme)
        );
    }

    #[test]
    fn a_header_that_is_not_a_sha256_digest_is_malformed() {
        assert_eq!(claimed("sha256="), Err(MalformedSignature::NotHex));
        assert_eq!(claimed("sha256=abcd"), Err(MalformedSignature::NotHex));
        assert_eq!(
            claimed(&format!("sha256={}", "z".repeat(64))),
            Err(MalformedSignature::NotHex)
        );
    }

    #[test]
    fn a_malformed_header_never_panics_on_anything_the_internet_can_send() {
        for value in [
            "sha256",
            "sha256==",
            "SHA256=deadbeef",
            "sha256=\u{00e9}",
            "sha256= 3c44f4b37e605fd32cbdf163352a8b98e088640043c79542c153281943fb1c4",
        ] {
            assert!(claimed(value).is_err(), "{value:?} should be rejected");
        }
    }

    #[test]
    fn no_secret_value_appears_in_an_error_or_in_debug_output() {
        let unknown = Origin::new(OriginId::new("a-forge"), SecretId::new("not-configured"));
        let error = verifier()
            .expected(&unknown, &Body::from_bytes(BODY.to_vec()))
            .expect_err("unknown secret");

        let printed = format!("{error:?}");

        assert!(!printed.contains(SECRET), "{printed}");
        assert!(!printed.contains("secret-not-used"), "{printed}");
    }
}
