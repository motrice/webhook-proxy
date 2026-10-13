//! Who else is involved in this, besides us.
//!
//! A [`DeliveryId`](crate::DeliveryId) is ours and names one Delivery. A
//! [`Correlation`] is the *caller's* and names a chain of calls that passes
//! through us on its way somewhere else. Two concepts, kept apart on purpose:
//! one answers "which message was lost", the other "what else was happening".
//!
//! The spelling on the wire is not this module's business. Whoever reads a
//! request builds one of these from whatever its standard says, and whoever
//! makes the onward call writes it back out — see the inbound and outbound
//! adapters. What lives here is the shape the rest of the code reasons about.

/// A correlation that could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotCorrelated {
    /// Not the length the standard fixes it at.
    WrongLength,
    /// Something other than lowercase hexadecimal.
    NotHexadecimal,
    /// All zeroes, which the standard reserves to mean "no trace".
    AllZeroes,
}

/// The chain a call belongs to, and this hop within it.
///
/// Both identities are fixed-length lowercase hexadecimal, and neither may be
/// all zeroes: the standard reserves that to mean the sender had nothing, and a
/// correlation that says "no trace" is worse than no correlation at all, because
/// it looks like one in a log.
///
/// `state` is opaque by design. It carries whatever a previous hop put there and
/// is passed on unexamined — reading it would make this code a participant in
/// somebody else's convention.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Correlation {
    trace: String,
    span: String,
    state: Option<String>,
}

/// How long a trace identity is, in hexadecimal characters.
const TRACE: usize = 32;

/// How long a span identity is, in hexadecimal characters.
const SPAN: usize = 16;

fn hexadecimal(value: &str, expected: usize) -> Result<String, NotCorrelated> {
    if value.len() != expected {
        return Err(NotCorrelated::WrongLength);
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(NotCorrelated::NotHexadecimal);
    }
    if value.bytes().all(|byte| byte == b'0') {
        return Err(NotCorrelated::AllZeroes);
    }
    Ok(value.to_owned())
}

impl Correlation {
    /// Builds a correlation from identities somebody else produced.
    ///
    /// # Errors
    ///
    /// [`NotCorrelated`] if either identity is the wrong length, is not
    /// lowercase hexadecimal, or is all zeroes. A caller that sends nonsense is
    /// given a fresh correlation instead of a refusal — losing a delivery over
    /// a malformed trace header would trade something that matters for something
    /// that does not.
    pub fn new(trace: &str, span: &str, state: Option<&str>) -> Result<Self, NotCorrelated> {
        Ok(Self {
            trace: hexadecimal(trace, TRACE)?,
            span: hexadecimal(span, SPAN)?,
            state: state.map(str::to_owned),
        })
    }

    /// The chain.
    #[must_use]
    pub fn trace(&self) -> &str {
        &self.trace
    }

    /// This hop in it.
    #[must_use]
    pub fn span(&self) -> &str {
        &self.span
    }

    /// Whatever a previous hop left for the next one.
    #[must_use]
    pub fn state(&self) -> Option<&str> {
        self.state.as_deref()
    }

    /// The same chain, a new hop.
    ///
    /// What an onward call carries: the caller's trace, so the two ends can be
    /// joined, and our own span, so the call we made is distinguishable from the
    /// call we received. State passes through untouched.
    #[must_use]
    pub fn continued_as(&self, span: &str) -> Option<Self> {
        Some(Self {
            trace: self.trace.clone(),
            span: hexadecimal(span, SPAN).ok()?,
            state: self.state.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{Correlation, NotCorrelated};

    const TRACE: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
    const SPAN: &str = "00f067aa0ba902b7";

    #[test]
    fn a_correlation_keeps_the_identities_it_was_given() {
        let carried = Correlation::new(TRACE, SPAN, None).expect("well formed");

        assert_eq!(carried.trace(), TRACE);
        assert_eq!(carried.span(), SPAN);
        assert_eq!(carried.state(), None);
    }

    #[test]
    fn state_is_carried_without_being_read() {
        // Deliberately not a shape this code understands: it belongs to whoever
        // put it there, and examining it would make us a participant.
        let carried =
            Correlation::new(TRACE, SPAN, Some("rojo=00f067aa0ba902b7,congo=t61")).expect("ok");

        assert_eq!(carried.state(), Some("rojo=00f067aa0ba902b7,congo=t61"));
    }

    #[test]
    fn an_identity_of_the_wrong_length_is_refused() {
        assert_eq!(
            Correlation::new("abc", SPAN, None),
            Err(NotCorrelated::WrongLength)
        );
        assert_eq!(
            Correlation::new(TRACE, "abc", None),
            Err(NotCorrelated::WrongLength)
        );
    }

    #[test]
    fn uppercase_is_refused_rather_than_lowered() {
        // The standard fixes the case. Accepting uppercase and lowering it would
        // make two spellings of one trace, which is how a chain quietly breaks
        // into two.
        assert_eq!(
            Correlation::new(&TRACE.to_uppercase(), SPAN, None),
            Err(NotCorrelated::NotHexadecimal)
        );
    }

    #[test]
    fn anything_outside_hexadecimal_is_refused() {
        assert_eq!(
            Correlation::new("4bf92f3577b34da6a3ce929d0e0e473g", SPAN, None),
            Err(NotCorrelated::NotHexadecimal)
        );
    }

    #[test]
    fn all_zeroes_is_refused_because_the_standard_reserves_it() {
        // "No trace", which must not be carried as though it were one: a log
        // line naming a zero trace looks correlated and is not.
        assert_eq!(
            Correlation::new(&"0".repeat(32), SPAN, None),
            Err(NotCorrelated::AllZeroes)
        );
        assert_eq!(
            Correlation::new(TRACE, &"0".repeat(16), None),
            Err(NotCorrelated::AllZeroes)
        );
    }

    #[test]
    fn continuing_keeps_the_chain_and_the_state_but_takes_a_new_hop() {
        let received = Correlation::new(TRACE, SPAN, Some("congo=t61")).expect("ok");
        let onward = received
            .continued_as("b7ad6b7169203331")
            .expect("a well formed span");

        assert_eq!(
            onward.trace(),
            TRACE,
            "the chain is what joins the two ends"
        );
        assert_eq!(onward.span(), "b7ad6b7169203331");
        assert_ne!(onward.span(), received.span(), "our call is not their call");
        assert_eq!(onward.state(), Some("congo=t61"));
    }

    #[test]
    fn continuing_with_a_bad_span_yields_nothing_rather_than_a_broken_chain() {
        let received = Correlation::new(TRACE, SPAN, None).expect("ok");

        assert_eq!(received.continued_as("not-hex"), None);
    }
}
