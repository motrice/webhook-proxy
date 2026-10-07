//! What a sender presents to show a [`Delivery`](crate::Delivery) is genuine.

/// What a sender presented to show a Delivery is genuine.
///
/// Deliberately length-agnostic and mechanism-agnostic: the domain compares
/// proofs, it never computes them, so nothing here knows or cares that one
/// sender digests the body while another presents a shared value as it stands.
///
/// Those two are not equally strong, and the domain is the wrong place to pretend
/// otherwise — a proof computed over the body cannot be replayed against
/// different content, and one that is merely presented can. What the domain can
/// guarantee is that whichever it is, it is compared the same way and a
/// [`VerifiedDelivery`](crate::VerifiedDelivery) exists only when it matched.
///
/// **No `PartialEq`, on purpose.** Deriving it would hand every caller a
/// short-circuiting `==` that leaks where two proofs first differ, and the only
/// thing standing between that and a timing oracle would be everybody remembering
/// not to use it. Without the derive, [`Proof::matches`] is the only comparison
/// that exists, and the wrong one does not compile:
///
/// ```compile_fail
/// # use domain::Proof;
/// let a = Proof::from_bytes([1, 2, 3]);
/// let b = Proof::from_bytes([1, 2, 3]);
/// let _ = a == b;
/// ```
#[derive(Clone)]
pub struct Proof(Vec<u8>);

/// A Delivery whose presented proof did not match the expected one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProofMismatch;

impl Proof {
    /// Takes a proof as raw bytes, however the sender encoded it.
    #[must_use]
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Compares two proofs without leaking *where* they differ through timing.
    ///
    /// Differing lengths are rejected immediately. For a proof computed over the
    /// body that is free: its length is fixed by the algorithm and is not secret.
    /// For a proof that is a shared value presented as it stands, the length *is*
    /// the secret's length — acceptable because such values are generated at a
    /// mandated minimum length, so knowing it tells an attacker nothing they
    /// could not assume. If they ever become human-chosen, compare digests of
    /// both sides instead, which makes this length-independent. Bead gc-ast.2.
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        if self.0.len() != other.0.len() {
            return false;
        }
        // Accumulate every difference, then decide once: no early return, so
        // the time taken does not reveal how many leading bytes were right.
        self.0
            .iter()
            .zip(other.0.iter())
            .fold(0u8, |differences, (a, b)| differences | (a ^ b))
            == 0
    }
}

impl core::fmt::Debug for Proof {
    /// Prints the length and nothing else. A signature is not itself a secret,
    /// but printing one invites printing the secret next to it.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Proof({} bytes)", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::Proof;

    #[test]
    fn identical_signatures_match() {
        assert!(Proof::from_bytes([1, 2, 3]).matches(&Proof::from_bytes([1, 2, 3])));
    }

    #[test]
    fn a_single_differing_byte_does_not_match() {
        assert!(!Proof::from_bytes([1, 2, 3]).matches(&Proof::from_bytes([1, 2, 4])));
    }

    #[test]
    fn signatures_of_different_lengths_do_not_match() {
        assert!(!Proof::from_bytes([1, 2, 3]).matches(&Proof::from_bytes([1, 2, 3, 4])));
    }

    #[test]
    fn a_prefix_does_not_match_the_whole() {
        // Guards against a comparison that stops at the shorter length.
        assert!(!Proof::from_bytes([1, 2]).matches(&Proof::from_bytes([1, 2, 0])));
    }

    #[test]
    fn debug_output_does_not_reproduce_the_signature_bytes() {
        let printed = format!("{:?}", Proof::from_bytes([0xde, 0xad, 0xbe, 0xef]));

        assert!(printed.contains('4'), "{printed}");
        assert!(!printed.contains("de"), "{printed}");
    }
}
