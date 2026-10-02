//! Signatures over a [`Delivery`](crate::Delivery)'s body.

/// A signature over a Delivery's body.
///
/// Deliberately length-agnostic and algorithm-agnostic: the domain compares
/// signatures, it never computes them, so nothing here knows or cares that
/// GitHub happens to use HMAC-SHA256.
#[derive(Clone, PartialEq, Eq)]
pub struct Signature(Vec<u8>);

/// A Delivery whose claimed signature did not match the computed one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureMismatch;

impl Signature {
    /// Takes a signature as raw bytes, however the sender encoded it.
    #[must_use]
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Compares two signatures without leaking *where* they differ through
    /// timing. Differing lengths are rejected immediately: a signature's
    /// length is not secret, its contents are.
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

impl core::fmt::Debug for Signature {
    /// Prints the length and nothing else. A signature is not itself a secret,
    /// but printing one invites printing the secret next to it.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Signature({} bytes)", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::Signature;

    #[test]
    fn identical_signatures_match() {
        assert!(Signature::from_bytes([1, 2, 3]).matches(&Signature::from_bytes([1, 2, 3])));
    }

    #[test]
    fn a_single_differing_byte_does_not_match() {
        assert!(!Signature::from_bytes([1, 2, 3]).matches(&Signature::from_bytes([1, 2, 4])));
    }

    #[test]
    fn signatures_of_different_lengths_do_not_match() {
        assert!(!Signature::from_bytes([1, 2, 3]).matches(&Signature::from_bytes([1, 2, 3, 4])));
    }

    #[test]
    fn a_prefix_does_not_match_the_whole() {
        // Guards against a comparison that stops at the shorter length.
        assert!(!Signature::from_bytes([1, 2]).matches(&Signature::from_bytes([1, 2, 0])));
    }

    #[test]
    fn debug_output_does_not_reproduce_the_signature_bytes() {
        let printed = format!("{:?}", Signature::from_bytes([0xde, 0xad, 0xbe, 0xef]));

        assert!(printed.contains('4'), "{printed}");
        assert!(!printed.contains("de"), "{printed}");
    }
}
