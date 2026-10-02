//! What arrived, and what we are willing to act on.

use crate::event::present;
use crate::{Blank, Origin, OriginId, Signature, SignatureMismatch, Timestamp};

/// A Delivery's identity, minted at the inbound boundary.
///
/// It exists so that a loss can be reported: per the delivery promise a dropped
/// Dispatch is logged and counted, and a loss report that cannot name what was
/// lost is not a loss report. Replay and deduplication would both need this key
/// later, and retrofitting it once adapters exist would mean touching every
/// layer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DeliveryId(String);

impl DeliveryId {
    /// Names a Delivery.
    ///
    /// # Errors
    ///
    /// [`Blank`] if the identity is empty or only whitespace.
    pub fn new(id: &str) -> Result<Self, Blank> {
        present(id, "a delivery identity").map(Self)
    }

    /// The identity as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The body of a [`Delivery`], exactly as it arrived.
///
/// Raw bytes, never a `String`: a signature is computed over the bytes that were
/// sent, so any re-encoding — even a lossless-looking one — destroys the only
/// evidence we have that the sender is who they claim to be.
#[derive(Clone, PartialEq, Eq)]
pub struct Body(Vec<u8>);

/// One webhook as it arrived from an [`Origin`]. Unverified by definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivery {
    id: DeliveryId,
    origin: OriginId,
    body: Body,
    received_at: Timestamp,
}

/// A [`Delivery`] whose signature has been checked and matched.
///
/// There is no way to construct one except [`Delivery::verify`], and that
/// requires presenting two signatures that match. Forging one therefore means
/// computing a correct signature, which means holding the secret.
///
/// ```compile_fail
/// # use domain::{Delivery, VerifiedDelivery};
/// // The field is private, so the unverified path cannot be reached by
/// // forgetting to call something.
/// let forged = VerifiedDelivery { delivery: todo!() };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDelivery {
    delivery: Delivery,
}

impl Body {
    /// Takes the body as it arrived.
    #[must_use]
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// The bytes as they arrived.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Debug for Body {
    /// Prints the length only. Bodies carry other people's data and routinely
    /// end up in logs.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Body({} bytes)", self.0.len())
    }
}

impl Delivery {
    /// Records a webhook as it arrived.
    #[must_use]
    pub fn new(id: DeliveryId, origin: OriginId, body: Body, received_at: Timestamp) -> Self {
        Self {
            id,
            origin,
            body,
            received_at,
        }
    }

    /// Which Delivery this is.
    #[must_use]
    pub fn id(&self) -> &DeliveryId {
        &self.id
    }

    /// When it arrived.
    #[must_use]
    pub fn received_at(&self) -> Timestamp {
        self.received_at
    }

    /// Which Origin claims to have sent this.
    #[must_use]
    pub fn origin(&self) -> &OriginId {
        &self.origin
    }

    /// The body as it arrived.
    #[must_use]
    pub fn body(&self) -> &Body {
        &self.body
    }

    /// Accepts this Delivery only if the signature the sender claimed matches
    /// the one computed over its body.
    ///
    /// The domain makes the decision; an adapter does the arithmetic. That
    /// split is what keeps cryptography out of a crate with no dependencies
    /// while keeping the *rule* — unverified input is never acted on — in the
    /// one place the rules live.
    ///
    /// # Errors
    ///
    /// [`SignatureMismatch`] if the two signatures differ, including when they
    /// differ only in length. The Delivery is consumed either way, so a
    /// rejected one cannot be retried against another signature until it
    /// happens to match.
    pub fn verify(
        self,
        claimed: &Signature,
        computed: &Signature,
    ) -> Result<VerifiedDelivery, SignatureMismatch> {
        if claimed.matches(computed) {
            Ok(VerifiedDelivery { delivery: self })
        } else {
            Err(SignatureMismatch)
        }
    }
}

impl VerifiedDelivery {
    /// Which Delivery this is.
    #[must_use]
    pub fn id(&self) -> &DeliveryId {
        self.delivery.id()
    }

    /// When it arrived.
    #[must_use]
    pub fn received_at(&self) -> Timestamp {
        self.delivery.received_at()
    }

    /// Which Origin sent this, now established rather than claimed.
    #[must_use]
    pub fn origin(&self) -> &OriginId {
        self.delivery.origin()
    }

    /// The bytes whose signature matched.
    #[must_use]
    pub fn body(&self) -> &Body {
        self.delivery.body()
    }
}

/// Registers an Origin's own view of itself. Kept here so `Origin` and the
/// Delivery it signs stay legible together.
impl Origin {
    /// Does this Delivery claim to come from this Origin?
    #[must_use]
    pub fn sent(&self, delivery: &Delivery) -> bool {
        self.id() == delivery.origin()
    }
}

#[cfg(test)]
mod tests {
    use super::{Body, Delivery, DeliveryId};
    use crate::{Origin, OriginId, SecretId, Signature, Timestamp};

    fn an_origin() -> OriginId {
        OriginId::new("github")
    }

    fn an_id() -> DeliveryId {
        DeliveryId::new("d-1").expect("a non-blank identity")
    }

    fn arrived_at() -> Timestamp {
        Timestamp::from_millis_since_epoch(1_759_000_000_000)
    }

    fn delivery_of(bytes: impl Into<Vec<u8>>) -> Delivery {
        Delivery::new(an_id(), an_origin(), Body::from_bytes(bytes), arrived_at())
    }

    #[test]
    fn a_body_that_is_not_valid_utf8_survives_intact() {
        // A real payload can contain anything, and a signature is computed over
        // exactly these bytes. 0xff is not valid UTF-8 anywhere, so this fails
        // loudly the moment someone stores a body as a String.
        let raw: Vec<u8> = vec![0x7b, 0xff, 0xfe, 0x7d];

        let delivery = delivery_of(raw.clone());

        assert_eq!(delivery.body().as_bytes(), raw.as_slice());
    }

    #[test]
    fn a_body_is_preserved_byte_for_byte_including_insignificant_whitespace() {
        // Two JSON documents that are semantically equal but differently
        // encoded have different signatures. Preserving whitespace is what
        // makes verification possible at all.
        let raw = b"{ \"a\" : 1 }\n";

        assert_eq!(delivery_of(raw.to_vec()).body().as_bytes(), raw);
    }

    #[test]
    fn matching_signatures_yield_a_verified_delivery_over_the_same_bytes() {
        let raw = b"payload".to_vec();
        let claimed = Signature::from_bytes([9, 9, 9]);
        let computed = Signature::from_bytes([9, 9, 9]);

        let verified = delivery_of(raw.clone())
            .verify(&claimed, &computed)
            .expect("matching signatures are accepted");

        assert_eq!(verified.origin(), &an_origin());
        assert_eq!(verified.body().as_bytes(), raw.as_slice());
    }

    #[test]
    fn differing_signatures_are_rejected_and_produce_nothing_to_act_on() {
        let claimed = Signature::from_bytes([9, 9, 9]);
        let computed = Signature::from_bytes([9, 9, 8]);

        let outcome = delivery_of(b"payload".to_vec()).verify(&claimed, &computed);

        // The Delivery is consumed either way, so a rejected one cannot be
        // retried with a different signature until it matches.
        assert!(outcome.is_err());
    }

    #[test]
    fn an_origin_recognises_only_deliveries_that_claim_to_be_from_it() {
        let origin = Origin::new(an_origin(), SecretId::new("github-webhook-secret"));

        assert!(origin.sent(&delivery_of(b"x".to_vec())));
        assert!(!origin.sent(&Delivery::new(
            an_id(),
            OriginId::new("gitlab"),
            Body::from_bytes(b"x".to_vec()),
            arrived_at()
        )));
    }

    #[test]
    fn a_delivery_carries_its_identity_and_when_it_arrived() {
        let delivery = delivery_of(b"payload".to_vec());

        assert_eq!(delivery.id(), &an_id());
        assert_eq!(delivery.received_at(), arrived_at());
    }

    #[test]
    fn a_verified_delivery_keeps_the_identity_and_arrival_it_was_given() {
        // The identity has to survive verification, because the loss report that
        // names it is written after a Dispatch has failed, long past this point.
        let signature = Signature::from_bytes([7, 7, 7]);

        let verified = delivery_of(b"payload".to_vec())
            .verify(&signature, &signature)
            .expect("matching signatures are accepted");

        assert_eq!(verified.id(), &an_id());
        assert_eq!(verified.received_at(), arrived_at());
    }

    #[test]
    fn a_delivery_identity_cannot_be_blank() {
        assert!(DeliveryId::new("   ").is_err());
    }

    #[test]
    fn debug_output_does_not_reproduce_the_body() {
        // Bodies are other people's data and end up in logs.
        let printed = format!("{:?}", delivery_of(b"secret-ish payload".to_vec()));

        assert!(!printed.contains("secret-ish"), "{printed}");
    }
}
