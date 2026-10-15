//! The driving adapter: an HTTP request in, the use case called, an answer out.
//!
//! This crate is the authentication boundary's front door. It holds no rules:
//! it captures the bytes that arrived, hands them to the use case, and turns the
//! outcome into a status code. Everything it must *not* do is in README under
//! "The security boundary", and two of those are structural here — the body is
//! never parsed in this crate, and there is no code path that reaches the
//! dispatcher without going through `Relay::relay`.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use application::ports::{Clock, Handover, Ids, Proofs, TenantId, Translator};
use application::{Refused, Relay};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::header::RETRY_AFTER;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::routing::post;
use domain::{Body, Correlation, Origin};

/// Where a sender's credential arrives.
///
/// One variant, because one is all any sender needs today. A mechanism that
/// presented a credential some other way would add one, and the compiler would
/// then find every place that has to decide — which is the point of its being a
/// type rather than an `Option<&str>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presented {
    /// In a header of this name, lowercased as hyper stores them.
    Header(&'static str),
}

/// Where a sender that signs its body presents the signature.
pub const SIGNATURE_HEADER: Presented = Presented::Header("x-hub-signature-256");

/// Where a sender that shares a value in advance presents it.
pub const AUTHORIZATION_HEADER: Presented = Presented::Header("authorization");

/// Everything that varies from one sender to the next.
///
/// The three things in here used to be properties of the deployment: one
/// verifier, one translator, one header for everybody. They are properties of a
/// *sender*, and saying so is what lets two senders prove themselves different
/// ways through one front door. Bead gc-dy4.
///
/// The composition root builds these from each Origin's declared mechanism, so
/// the verifier an Origin gets is derived from the same declaration that says
/// what it must prove — there is no second place for the two to drift.
#[derive(Clone)]
pub struct Sender {
    /// Who this is, and what it must prove.
    pub origin: Origin,
    /// Whose alerts this sender's are.
    ///
    /// On the sender rather than taken from the request, which is the whole of
    /// bead gc-nkb: the Origin's own secret proves the Origin, so a tenant read
    /// from its registration is derived from something already authenticated.
    /// Read from a path, a body or a header it would be a claim, and a deployer
    /// who can write an alert's labels could file it under somebody else's
    /// tenant.
    pub tenant: TenantId,
    /// What checks it.
    pub proofs: Arc<dyn Proofs>,
    /// What reads its payload, once verified.
    pub translator: Arc<dyn Translator>,
    /// Where its credential arrives.
    pub presented: Presented,
}

/// A count and the names, never a credential.
///
/// Written by hand because a derived one would print whatever a `Proofs`
/// implementation holds, and those hold secrets.
impl fmt::Debug for Sender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Sender({}, {:?})",
            self.origin.id().as_str(),
            self.presented
        )
    }
}

/// Everything the front door needs, shareable across requests.
///
/// Ports arrive as trait objects rather than generics so that the state stays
/// one concrete type: axum clones it per request, and a five-parameter generic
/// would be inflicted on every caller for no benefit.
#[derive(Clone)]
pub struct Inbound {
    /// Every sender permitted to reach this proxy, by the name in the request
    /// path. A path naming anything absent here cannot be authenticated and is
    /// therefore refused — which is also what keeps the set of senders
    /// unenumerable from outside.
    senders: Arc<HashMap<String, Sender>>,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn Ids>,
    /// Where a Delivery waits for the tenant it belongs to. The only store.
    handover: Arc<dyn Handover>,
    /// Senders refused because the store could not take their Delivery.
    ///
    /// Deliberately not counted as losses. A refusal is the promise working:
    /// the sender was told, and nothing was accepted that will not be tried.
    /// Adding them to the loss count would make both numbers useless — one
    /// measures what we dropped, the other what we declined to take.
    refusals: Arc<AtomicU64>,
    /// Whether the store was unavailable the last time anybody looked.
    ///
    /// Kept so the transition is logged rather than every request. During an
    /// outage every request fails, and an error line per request floods the one
    /// log somebody is reading to find out why. See gc-mbr.
    storage_was_down: Arc<AtomicBool>,
}

impl Inbound {
    /// Wires the front door to the application.
    /// Five arguments where there were seven.
    ///
    /// The verifier, the translator and the Origin table collapsed into
    /// `senders`, because each of them belongs to one sender rather than to the
    /// deployment.
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "the composition root names every collaborator once; grouping them into a \
                  struct would move the list rather than shorten it, and hide which of them \
                  are shared with the worker"
    )]
    pub fn new(
        senders: HashMap<String, Sender>,
        handover: Arc<dyn Handover>,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn Ids>,
    ) -> Self {
        Self {
            senders: Arc::new(senders),
            handover,
            clock,
            ids,
            refusals: Arc::new(AtomicU64::new(0)),
            storage_was_down: Arc::new(AtomicBool::new(false)),
        }
    }

    /// How many senders have been refused because the store would not take
    /// their Delivery.
    #[must_use]
    pub fn refusals(&self) -> u64 {
        self.refusals.load(Ordering::Relaxed)
    }
}

/// The HTTP surface.
///
/// `max_body` is enforced by a layer, so an oversized request is refused before
/// the handler runs — and therefore before any signature is computed and before
/// anything is parsed.
pub fn router(inbound: Inbound, max_body: usize) -> Router {
    Router::new()
        .route("/webhook/{origin}", post(receive))
        .layer(DefaultBodyLimit::max(max_body))
        .with_state(inbound)
}

/// Receive one webhook.
///
/// Status codes are chosen so that the sender does the right thing and an
/// operator can tell whose fault something is:
///
/// - `202` accepted. Verified and handed on; says nothing about delivery, by
///   design — see the delivery promise.
/// - `401` the signature was absent, unreadable, or did not match.
/// - `404` no such Origin is configured, so it cannot be authenticated.
/// - `503` we hold no usable secret for a configured Origin. Our fault, and
///   loud: a misconfigured deployment must not hide behind what looks like an
///   attack.
/// - `400` the payload could not be read at all.
///
/// A failed Dispatch does **not** change the answer. Returning an error would
/// make the sender retry and re-deliver to the Destinations that had already
/// succeeded.
/// Whether the body says it is JSON.
///
/// One content type, because this service translates one format. A missing
/// header is refused like an unexpected one: the rule names both, and a request
/// that does not say what it is cannot be taken at its word.
///
/// Parameters are allowed and ignored -- `application/json; charset=utf-8` is
/// the same media type, and refusing it would reject senders that are behaving
/// correctly. The comparison is case-insensitive because the standard says the
/// type is.
fn json(headers: &HeaderMap) -> bool {
    headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"))
        })
}

/// Reads a correlation out of what the caller sent, if it sent a usable one.
///
/// The wire format is W3C Trace Context: `version-trace-span-flags`, four
/// hyphen-separated fields, version `00`. This is the only place that spelling
/// appears — the rest of the code holds a [`Correlation`], which knows nothing
/// about hyphens.
///
/// `None` for anything it cannot read, and the caller then generates one. That
/// is deliberate and worth being explicit about: a malformed trace header is a
/// bad reason to lose an alert, so the header is never required and never a
/// cause of refusal. Nothing malformed is ever propagated, because nothing
/// malformed ever becomes a `Correlation`.
///
/// `tracestate` rides along unexamined. It belongs to whoever set it.
fn carried(headers: &HeaderMap) -> Option<Correlation> {
    let parent = headers.get("traceparent")?.to_str().ok()?;

    let mut fields = parent.split('-');
    let version = fields.next()?;
    let trace = fields.next()?;
    let span = fields.next()?;
    let flags = fields.next()?;
    // Exactly four. A fifth field means a version this code does not know, and
    // guessing at it would propagate something it cannot vouch for.
    if fields.next().is_some() || version != "00" || flags.len() != 2 {
        return None;
    }

    let state = headers
        .get("tracestate")
        .and_then(|value| value.to_str().ok());

    Correlation::new(trace, span, state).ok()
}

/// How a correlation is spelled on the way out.
///
/// Version `00` and flags `01`: sampled. This proxy makes no sampling decision
/// of its own -- it has no exporter and no spans -- so claiming the call is
/// worth recording is the honest default for something whose whole purpose is
/// to be followed later.
fn spelled(correlation: &Correlation) -> String {
    format!("00-{}-{}-01", correlation.trace(), correlation.span())
}

/// The headers a response carries.
///
/// SPA.04 of the national REST API-profil: the answer names the chain, so a
/// caller that generated nothing still learns which trace its delivery was
/// filed under and can put that in its own log.
fn answering(correlation: &Correlation) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Ok(value) = HeaderValue::from_str(&spelled(correlation)) {
        headers.insert("traceparent", value);
    }
    if let Some(state) = correlation.state()
        && let Ok(value) = HeaderValue::from_str(state)
    {
        headers.insert("tracestate", value);
    }
    headers
}

async fn receive(
    State(inbound): State<Inbound>,
    Path(origin): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> (StatusCode, HeaderMap) {
    // A path naming a sender we do not serve cannot be authenticated, so it is
    // refused here rather than anywhere further in.
    let Some(sender) = inbound.senders.get(&origin) else {
        return (StatusCode::NOT_FOUND, HeaderMap::new());
    };

    // Where the credential is read from follows from what this sender declared,
    // never from what the request happens to carry. A request bearing the other
    // mechanism's header is refused rather than retried under it — that is the
    // downgrade gc-ast.2 forbids, and this is the line that forbids it.
    let Presented::Header(name) = sender.presented;

    // Nothing below this point runs without something to compare. There is no
    // flag, no environment variable and no build feature that skips it.
    let Some(presented) = headers.get(name).and_then(|value| value.to_str().ok()) else {
        return (StatusCode::UNAUTHORIZED, HeaderMap::new());
    };
    let Ok(claimed) = sender.proofs.claimed(presented) else {
        return (StatusCode::UNAUTHORIZED, HeaderMap::new());
    };

    // Checked here, and the position is the point of bead gc-4oo.8.
    //
    // After the credential, so a caller with none learns nothing about what this
    // service accepts: it gets the same 401 whatever it sent, and the check
    // cannot be used to probe. Before the relay, because that is where
    // translation happens and an unsupported type is not a translation failure
    // -- a hook configured with form encoding used to come back Untranslatable,
    // which reads like a bad payload rather than a wrong setting.
    //
    // Said plainly, because the bead asked for "after verification" and this is
    // not quite that: the proof is PARSED above and COMPARED inside the relay,
    // so a caller holding a well-formed but wrong credential reaches this line
    // and can learn its content type was unsupported. It already knows the path
    // exists -- 404 and 401 tell it that -- so what leaks is that its own header
    // was wrong, which it set. Verifying earlier would mean comparing the proof
    // in this adapter, and verification belongs to the use case.
    //
    // SAK.29 is a BOR rather than a SKALL, so this is done because an accurate
    // refusal is worth having, not because a gate requires it.
    if !json(&headers) {
        return (StatusCode::UNSUPPORTED_MEDIA_TYPE, HeaderMap::new());
    }

    let relay = Relay::new(
        sender.proofs.as_ref(),
        sender.translator.as_ref(),
        inbound.handover.as_ref(),
        inbound.clock.as_ref(),
        inbound.ids.as_ref(),
    );

    // Read before anything is relayed, so the same correlation goes outward and
    // back. A caller that sent none gets one from the use case, which is why
    // this is an Option rather than a decision made here.
    let carried = carried(&headers);

    // The body is handed over as the bytes that arrived. This crate never parses
    // it: translation is a port, reached only after verification.
    match relay
        .relay(
            &sender.origin,
            &sender.tenant,
            Body::from_bytes(body.to_vec()),
            &claimed,
            carried.clone(),
        )
        .await
    {
        Ok(relayed) => {
            // The store answered, so if it had been failing it is not any more.
            // Logged once on the way back up, not once per request.
            if inbound.storage_was_down.swap(false, Ordering::Relaxed) {
                tracing::error!(
                    refused = inbound.refusals(),
                    "the delivery store is available again"
                );
            }

            // Nothing is logged per room here, and there are no rooms to log.
            // This service verified the Delivery and owes it to a tenant; what
            // became of each room is that tenant's agent to attempt, to report
            // and to log where it happened (bead gc-72e.3.2). The answer below
            // carries the chain, which is what lets those two logs be read
            // together across two namespaces.
            (StatusCode::ACCEPTED, answering(relayed.correlation()))
        }
        Err(Refused::ProofMismatch) => (StatusCode::UNAUTHORIZED, HeaderMap::new()),
        Err(Refused::SecretUnavailable) => (StatusCode::SERVICE_UNAVAILABLE, HeaderMap::new()),
        Err(Refused::Untranslatable) => (StatusCode::BAD_REQUEST, HeaderMap::new()),
        Err(Refused::StorageUnavailable) => {
            inbound.refusals.fetch_add(1, Ordering::Relaxed);

            // Once, on the way down. Every request fails during an outage, and
            // an error line per request floods the log somebody is reading to
            // find out why. The count is what says how many (gc-mbr).
            if !inbound.storage_was_down.swap(true, Ordering::Relaxed) {
                // No address, no credential, no driver message: this line is
                // written from StorageUnavailable, which carries none.
                tracing::error!("the delivery store is unavailable; refusing senders");
            }

            // The one thing a well-behaved sender can act on. It costs nothing
            // and GitHub will ignore it — that sender does not retry at all, so
            // a store outage needs a human to redeliver.
            let mut headers = HeaderMap::new();
            headers.insert(RETRY_AFTER, HeaderValue::from_static("30"));
            (StatusCode::SERVICE_UNAVAILABLE, headers)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io;
    use std::sync::{Arc, Mutex, OnceLock};

    use application::ports::{
        Behind, Claimed, Clock, Discharged, Handover, Ids, MalformedProof, Offered, Proofs,
        Reoffered, Report, SecretUnavailable, StorageUnavailable, Swept, TenantId, Translator,
        Untranslatable,
    };
    use async_trait::async_trait;
    use axum::Router;
    use axum::body::Body as AxumBody;
    use axum::http::{Request, StatusCode};
    use domain::{
        Body, BranchName, Correlation, DeliveryId, Event, Origin, OriginId, Proof, Pusher,
        RepositoryName, SecretId, Timestamp, Verification, VerifiedDelivery,
    };
    use tower::ServiceExt;
    use tracing_subscriber::fmt::MakeWriter;

    use super::{Inbound, SIGNATURE_HEADER, Sender, router};

    /// The shape of thing that must never reach a log line. There is no URL in
    /// this crate to leak — a `Destination` is an identity and a kind, with no
    /// field for an address — so the assertion below is a regression guard
    /// against someone later logging one, not a demonstration that one exists.
    const FORBIDDEN_IN_LOGS: &[&str] = &["https://", "secret", "token"];

    /// Reports a fixed expected signature, and records every body it was asked
    /// about so a test can prove the bytes were not re-encoded on the way.
    struct Sigs {
        expected: Result<Proof, SecretUnavailable>,
        seen: Mutex<Vec<Vec<u8>>>,
    }

    impl Sigs {
        fn matching() -> Arc<Self> {
            Arc::new(Self {
                expected: Ok(Proof::from_bytes(b"abc".to_vec())),
                seen: Mutex::new(Vec::new()),
            })
        }

        fn mismatching() -> Arc<Self> {
            Arc::new(Self {
                expected: Ok(Proof::from_bytes(b"xyz".to_vec())),
                seen: Mutex::new(Vec::new()),
            })
        }

        fn secretless() -> Arc<Self> {
            Arc::new(Self {
                expected: Err(SecretUnavailable),
                seen: Mutex::new(Vec::new()),
            })
        }

        fn seen(&self) -> Vec<Vec<u8>> {
            self.seen.lock().expect("not poisoned").clone()
        }
    }

    impl Proofs for Sigs {
        fn expected(&self, _origin: &Origin, body: &Body) -> Result<Proof, SecretUnavailable> {
            self.seen
                .lock()
                .expect("not poisoned")
                .push(body.as_bytes().to_vec());
            self.expected.clone()
        }

        /// A stand-in scheme: `ok:<bytes>`. Anything else is unreadable, which is
        /// how the malformed-header case is driven.
        fn claimed(&self, presented: &str) -> Result<Proof, MalformedProof> {
            presented
                .strip_prefix("ok:")
                .map(|rest| Proof::from_bytes(rest.as_bytes().to_vec()))
                .ok_or(MalformedProof::UnknownScheme)
        }
    }

    struct Says(Result<Vec<Event>, Untranslatable>);
    impl Translator for Says {
        fn events(&self, _delivery: &VerifiedDelivery) -> Result<Vec<Event>, Untranslatable> {
            self.0.clone()
        }
    }

    struct FixedClock;
    impl Clock for FixedClock {
        fn now(&self) -> Timestamp {
            Timestamp::from_millis_since_epoch(1_759_000_000_000)
        }
    }

    /// Records how often an identity was minted, so a test can prove the port is
    /// what produces it rather than something inside the core.
    struct CountingIds(Mutex<u32>);
    impl Ids for CountingIds {
        fn next_delivery_id(&self) -> DeliveryId {
            let mut minted = self.0.lock().expect("not poisoned");
            *minted += 1;
            DeliveryId::new(&format!("d-{minted}")).expect("a non-blank identity")
        }

        /// Fixed, so a test can name the chain it expects a response to carry.
        fn next_correlation(&self) -> Correlation {
            Correlation::new(GENERATED_TRACE, "00f067aa0ba902b7", None)
                .expect("a well formed correlation")
        }

        fn next_hop_in(&self, chain: &Correlation) -> Correlation {
            chain
                .continued_as("b7ad6b7169203331")
                .expect("a well formed span")
        }
    }

    /// The chain a generated correlation uses, so a test can recognise it.
    const GENERATED_TRACE: &str = "99999999999999999999999999999999";

    /// Collects log output in memory so a test can assert on what was written.
    #[derive(Clone)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    static LOGS: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();

    /// The buffer every log line in this binary is written to.
    ///
    /// One *global* subscriber, installed once, rather than a thread-local one
    /// per test. The reason is a race that cost a diagnosis: tracing caches each
    /// callsite's interest globally, so if any test reaches the `warn!` while no
    /// subscriber is installed, the callsite is cached as "nobody cares" and a
    /// thread-local subscriber set later is never consulted. Rebuilding the cache
    /// by hand loses the race against tests running in parallel; installing
    /// globally does not, because setting a global default rebuilds the cache for
    /// every thread at once.
    ///
    /// The cost is that all tests share one buffer, so an assertion must look for
    /// its own lines. The "nothing forbidden anywhere" assertion is strengthened
    /// by the sharing rather than weakened.
    fn captured_logs() -> Arc<Mutex<Vec<u8>>> {
        LOGS.get_or_init(|| {
            let buffer = Arc::new(Mutex::new(Vec::new()));
            tracing_subscriber::fmt()
                .with_writer(Captured(Arc::clone(&buffer)))
                .with_ansi(false)
                .init();
            buffer
        })
        .clone()
    }

    impl io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().expect("not poisoned").extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Captured {
        type Writer = Self;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    fn an_origin() -> (String, Origin) {
        (
            "github".to_owned(),
            Origin::new(
                OriginId::new("github").expect("a non-blank origin identity"),
                Verification::Signed {
                    secret: SecretId::new("a-secret").expect("a non-blank secret name"),
                },
            ),
        )
    }

    fn a_push() -> Event {
        Event::PushedCommits {
            repository: RepositoryName::new("motrice/webhook-proxy").expect("a name"),
            branch: BranchName::new("main").expect("a name"),
            pusher: Pusher::new("bjornmolin").expect("a name"),
            commits: vec![],
            permalink: None,
        }
    }

    /// Whose the alerts in these tests are. One tenant, because nothing here is
    /// about isolation between two — that is bead gc-wcw.2's test, over HTTP
    /// against a caller's identity rather than against a field.
    fn a_tenant() -> TenantId {
        TenantId::new("a-tenant").expect("a namespace name")
    }

    struct Wired {
        app: Router,
        inbound: Inbound,
        sigs: Arc<Sigs>,
        ids: Arc<CountingIds>,
    }

    /// Somewhere to owe a Delivery, which can be told to refuse.
    ///
    /// Its storing behaviour is proved against the real in-memory adapter in
    /// its own crate; adapters may not depend on each other, and what these
    /// tests need from it is only that it works, or that it does not.
    struct Store {
        available: bool,
    }

    #[async_trait]
    impl Handover for Store {
        async fn offer(&self, _offered: &Offered) -> Result<(), StorageUnavailable> {
            if self.available {
                Ok(())
            } else {
                Err(StorageUnavailable)
            }
        }

        async fn outstanding(
            &self,
            _tenant: &TenantId,
            _limit: usize,
        ) -> Result<Vec<Offered>, StorageUnavailable> {
            unreachable!("the front door never reads back")
        }

        async fn claim(
            &self,
            _tenant: &TenantId,
            _limit: usize,
            _now: Timestamp,
            _lease: core::time::Duration,
        ) -> Result<Vec<Claimed>, StorageUnavailable> {
            unreachable!("the front door never claims")
        }

        async fn report(
            &self,
            _tenant: &TenantId,
            _delivery: &DeliveryId,
            _report: &Report,
            _at: Timestamp,
        ) -> Result<Discharged, StorageUnavailable> {
            unreachable!("the front door never reports")
        }

        async fn reoffer(&self, _delivery: &DeliveryId) -> Result<Reoffered, StorageUnavailable> {
            unreachable!("the front door never re-offers")
        }

        async fn sweep(&self, _accepted_before: Timestamp) -> Result<Swept, StorageUnavailable> {
            unreachable!("the front door never sweeps")
        }

        async fn behind(
            &self,
            _accepted_before: Timestamp,
        ) -> Result<Vec<Behind>, StorageUnavailable> {
            unreachable!("the front door never asks after a backlog")
        }
    }

    fn wire(sigs: Arc<Sigs>, says: Result<Vec<Event>, Untranslatable>, max_body: usize) -> Wired {
        wire_with(sigs, says, max_body, Store { available: true })
    }

    /// The same, with an outbox the test chooses.
    fn wire_with(
        sigs: Arc<Sigs>,
        says: Result<Vec<Event>, Untranslatable>,
        max_body: usize,
        store: Store,
    ) -> Wired {
        let ids = Arc::new(CountingIds(Mutex::new(0)));
        let (name, origin) = an_origin();
        let inbound = Inbound::new(
            HashMap::from([(
                name,
                Sender {
                    origin,
                    tenant: a_tenant(),
                    proofs: sigs.clone(),
                    translator: Arc::new(Says(says)),
                    presented: SIGNATURE_HEADER,
                },
            )]),
            Arc::new(store),
            Arc::new(FixedClock),
            ids.clone(),
        );

        Wired {
            app: router(inbound.clone(), max_body),
            inbound,
            sigs,
            ids,
        }
    }

    /// A wired front door that accepts a signed push.
    ///
    /// No rooms, because this adapter knows none: it verifies and owes the
    /// Delivery to a tenant, and which rooms hear about it is decided in
    /// another namespace by another binary (bead gc-72e.3.2).
    fn a_push_request() -> Wired {
        wire(Sigs::matching(), Ok(vec![a_push()]), 64 * 1024)
    }

    async fn post(app: Router, path: &str, signature: Option<&str>, body: &[u8]) -> StatusCode {
        // application/json, because that is what every configured sender
        // actually sends and what this service translates. Stated here rather
        // than left off, so a test that cares about the content type says so.
        post_typed(app, path, signature, Some("application/json"), body).await
    }

    async fn post_typed(
        app: Router,
        path: &str,
        signature: Option<&str>,
        content_type: Option<&str>,
        body: &[u8],
    ) -> StatusCode {
        let mut request = Request::builder().method("POST").uri(path);
        if let Some(value) = signature {
            request = request.header("X-Hub-Signature-256", value);
        }
        if let Some(value) = content_type {
            request = request.header("content-type", value);
        }
        let request = request
            .body(AxumBody::from(body.to_vec()))
            .expect("a well-formed request");

        app.oneshot(request)
            .await
            .expect("the router answers")
            .status()
    }

    const BODY: &[u8] = br#"{ "ref" : "refs/heads/main" }"#;

    #[tokio::test]
    async fn a_signed_request_in_the_wrong_content_type_says_so() {
        // SAK.29, and more usefully an accurate refusal: a hook configured with
        // form encoding used to fail as Untranslatable, which reads like a
        // payload problem rather than a setup problem.
        let wired = a_push_request();
        let status = post_typed(
            wired.app,
            "/webhook/github",
            Some("ok:abc"),
            Some("text/plain"),
            BODY,
        )
        .await;

        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn a_signed_request_with_no_content_type_is_refused_too() {
        // The rule names a missing header alongside an unexpected one, and the
        // reason is the same: this service translates one format, and a request
        // that does not say what it is cannot be taken at its word.
        let wired = a_push_request();
        let status = post_typed(wired.app, "/webhook/github", Some("ok:abc"), None, BODY).await;

        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn githubs_other_content_type_says_what_is_wrong_rather_than_blaming_the_payload() {
        // The case this bead exists for. GitHub offers exactly two content types
        // in its webhook settings, and somebody will pick the other one. 415
        // tells them to change the setting; 400 told them their payload was bad,
        // which it was not.
        let wired = a_push_request();
        let status = post_typed(
            wired.app,
            "/webhook/github",
            Some("ok:abc"),
            Some("application/x-www-form-urlencoded"),
            BODY,
        )
        .await;

        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_ne!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn a_request_with_no_credential_is_refused_before_its_content_type_is_considered() {
        // The ordering is the point of this bead. A caller with no credential
        // learns nothing about what this service accepts: it gets the same 401
        // whatever content type it sent, so the check cannot be used to probe.
        let wired = a_push_request();
        let status = post_typed(wired.app, "/webhook/github", None, Some("text/plain"), BODY).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_body_too_large_is_refused_before_its_content_type_is_considered() {
        // The other half of the ordering: the limit is enforced by a layer before
        // anything is read, so an oversized body in the wrong content type is
        // still 413. Pinned because the two refusals are easy to reorder by
        // accident when either one moves.
        let wired = wire(Sigs::matching(), Ok(vec![a_push()]), 8);
        let status = post_typed(
            wired.app,
            "/webhook/github",
            Some("ok:abc"),
            Some("text/plain"),
            b"a body longer than eight bytes",
        )
        .await;

        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    }

    /// A real traceparent from the W3C Trace Context specification's examples.
    const CALLERS: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    const CALLERS_TRACE: &str = "4bf92f3577b34da6a3ce929d0e0e4736";

    /// Posts with whatever tracing headers a test wants, and returns the
    /// response whole so the answer's own headers can be read.
    async fn post_traced(
        app: Router,
        parent: Option<&str>,
        state: Option<&str>,
    ) -> axum::response::Response {
        let mut request = Request::builder()
            .method("POST")
            .uri("/webhook/github")
            .header("X-Hub-Signature-256", "ok:abc")
            // What a configured sender sends, and now required (gc-4oo.8).
            .header("content-type", "application/json");
        if let Some(value) = parent {
            request = request.header("traceparent", value);
        }
        if let Some(value) = state {
            request = request.header("tracestate", value);
        }

        app.oneshot(
            request
                .body(AxumBody::from(BODY.to_vec()))
                .expect("a well-formed request"),
        )
        .await
        .expect("the router answers")
    }

    fn traceparent_of(response: &axum::response::Response) -> &str {
        response
            .headers()
            .get("traceparent")
            .expect("the answer names the chain")
            .to_str()
            .expect("a header this code wrote is text")
    }

    #[tokio::test]
    async fn a_caller_that_sent_a_chain_is_answered_in_the_same_chain() {
        // SPA.02 and SPA.04: the chain is accepted and reported back, so a
        // sender can put the same trace in its own log and the two ends join up.
        let wired = a_push_request();
        let answered = post_traced(wired.app, Some(CALLERS), None).await;

        assert_eq!(answered.status(), StatusCode::ACCEPTED);
        let parent = traceparent_of(&answered);
        assert!(
            parent.contains(CALLERS_TRACE),
            "the answer left the caller's chain: {parent}"
        );
        assert!(parent.starts_with("00-"), "version 00: {parent}");
    }

    #[tokio::test]
    async fn a_caller_that_sent_no_chain_is_given_one_rather_than_refused() {
        // The header is never required. A sender with no tracing at all is a
        // sender, not a problem.
        let wired = a_push_request();
        let answered = post_traced(wired.app, None, None).await;

        assert_eq!(answered.status(), StatusCode::ACCEPTED);
        assert!(
            traceparent_of(&answered).contains(GENERATED_TRACE),
            "a chain was not generated: {}",
            traceparent_of(&answered)
        );
    }

    #[tokio::test]
    async fn a_malformed_chain_is_replaced_and_never_carried() {
        // Losing an alert because a header was wrong would trade something that
        // matters for something that does not. The malformed value must not
        // appear in the answer either, or it has been propagated after all.
        for nonsense in [
            "garbage",
            "00-tooshort-00f067aa0ba902b7-01",
            "99-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra",
        ] {
            let wired = a_push_request();
            let answered = post_traced(wired.app, Some(nonsense), None).await;

            assert_eq!(
                answered.status(),
                StatusCode::ACCEPTED,
                "refused over a trace header: {nonsense}"
            );
            let parent = traceparent_of(&answered);
            assert!(
                parent.contains(GENERATED_TRACE),
                "not replaced for {nonsense}: {parent}"
            );
            assert!(
                !parent.contains("tooshort") && !parent.starts_with("99-"),
                "a malformed value was carried: {parent}"
            );
        }
    }

    #[tokio::test]
    async fn state_a_caller_sent_comes_back_unchanged() {
        // Opaque, and belonging to whoever set it. Reading or rewriting it would
        // make this proxy a participant in somebody else's convention.
        let wired = a_push_request();
        let answered = post_traced(wired.app, Some(CALLERS), Some("congo=t61rcWkgMzE")).await;

        assert_eq!(
            answered
                .headers()
                .get("tracestate")
                .and_then(|value| value.to_str().ok()),
            Some("congo=t61rcWkgMzE")
        );
    }

    #[tokio::test]
    async fn a_valid_signed_push_is_accepted() {
        let wired = a_push_request();

        let status = post(wired.app, "/webhook/github", Some("ok:abc"), BODY).await;

        assert_eq!(status, StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn the_verifier_is_given_the_exact_bytes_that_arrived() {
        // The defect this guards against is re-encoding the body on the way in:
        // it passes every happy-path test and fails the first time a payload
        // round-trips differently.
        let wired = a_push_request();

        post(wired.app, "/webhook/github", Some("ok:abc"), BODY).await;

        assert_eq!(wired.sigs.seen(), vec![BODY.to_vec()]);
    }

    #[tokio::test]
    async fn an_identity_is_minted_through_the_ids_port() {
        let wired = a_push_request();

        post(wired.app, "/webhook/github", Some("ok:abc"), BODY).await;

        assert_eq!(*wired.ids.0.lock().expect("not poisoned"), 1);
    }

    #[tokio::test]
    async fn a_mismatched_signature_is_unauthorised_and_dispatches_nothing() {
        let wired = wire(Sigs::mismatching(), Ok(vec![a_push()]), 64 * 1024);

        let status = post(wired.app, "/webhook/github", Some("ok:abc"), BODY).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_request_with_no_signature_at_all_is_refused() {
        // There is no configuration under which this succeeds. This proxy is the
        // authentication boundary; an unsigned request is the thing it exists to
        // refuse.
        let wired = a_push_request();

        let status = post(wired.app, "/webhook/github", None, BODY).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(wired.sigs.seen().is_empty(), "nothing should be computed");
    }

    #[tokio::test]
    async fn an_unreadable_signature_header_is_refused() {
        let wired = a_push_request();

        let status = post(wired.app, "/webhook/github", Some("garbage"), BODY).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn an_origin_we_hold_no_secret_for_is_refused_never_forwarded() {
        let wired = a_push_request();

        let status = post(wired.app, "/webhook/gitlab", Some("ok:abc"), BODY).await;

        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn an_unusable_secret_is_our_fault_and_says_so() {
        // Distinct from a mismatch on purpose: a misconfigured deployment must
        // not hide behind what looks like an attack.
        let wired = wire(Sigs::secretless(), Ok(vec![a_push()]), 64 * 1024);

        let status = post(wired.app, "/webhook/github", Some("ok:abc"), BODY).await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn a_payload_we_cannot_read_is_a_bad_request() {
        let wired = wire(Sigs::matching(), Err(Untranslatable), 64 * 1024);

        let status = post(wired.app, "/webhook/github", Some("ok:abc"), BODY).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn a_payload_reporting_nothing_we_handle_is_still_accepted() {
        let wired = wire(Sigs::matching(), Ok(vec![]), 64 * 1024);

        let status = post(wired.app, "/webhook/github", Some("ok:abc"), BODY).await;

        assert_eq!(status, StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn a_body_over_the_limit_is_refused_before_anything_is_computed() {
        let wired = wire(Sigs::matching(), Ok(vec![a_push()]), 16);

        let status = post(wired.app, "/webhook/github", Some("ok:abc"), BODY).await;

        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert!(
            wired.sigs.seen().is_empty(),
            "the limit must bite before verification"
        );
    }

    #[tokio::test]
    async fn a_store_that_cannot_take_it_refuses_the_sender_and_sends_nothing() {
        // The promise, at the front door. A 202 means stored (gc-mbr), so when
        // nothing could be stored the sender is told so — and nothing is sent,
        // because sending without storing is the second meaning of 202 that
        // decision exists to forbid.
        let wired = wire_with(
            Sigs::matching(),
            Ok(vec![a_push()]),
            64 * 1024,
            Store { available: false },
        );

        let status = post(wired.app.clone(), "/webhook/github", Some("ok:abc"), BODY).await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        // Counted as a refusal, which is the promise working rather than
        // failing: the sender was told, and nothing was accepted that will not
        // be offered. There is no loss count here to compare it against any
        // more — a loss now happens in a tenant's agent, is logged there, and
        // the only kind this service can see is an alert nobody collected
        // (bead gc-wcw.3).
        assert_eq!(wired.inbound.refusals(), 1);
    }

    #[tokio::test]
    async fn a_refusal_tells_the_sender_when_to_come_back() {
        // The one thing a well-behaved sender can act on. GitHub will ignore it
        // -- it does not retry at all -- which is why the sender contract says a
        // store outage needs a human to redeliver.
        let wired = wire_with(
            Sigs::matching(),
            Ok(vec![a_push()]),
            64 * 1024,
            Store { available: false },
        );

        let response = wired
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhook/github")
                    .header("X-Hub-Signature-256", "ok:abc")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(BODY.to_vec()))
                    .expect("a request"),
            )
            .await
            .expect("the router answers");

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            response.headers().contains_key("retry-after"),
            "{:?}",
            response.headers()
        );
    }

    #[tokio::test]
    async fn nothing_this_adapter_logs_carries_a_secret() {
        // The loss line this used to check moved to the tenant's agent with the
        // delivering (bead gc-72e.3.2), and the property did not move with it:
        // what is left here still writes to a log an operator pastes into a
        // chat window — a store outage and a recovery — and neither may carry a
        // credential.
        //
        // Kept rather than deleted along with its old subject, because the
        // harness exists and the risk did not go anywhere: the next line
        // somebody adds to this file is the one this catches.
        let logs = captured_logs();
        let before = logs.lock().expect("not poisoned").len();

        // Down, then up: both transitions, which are the only two lines this
        // adapter writes.
        let refusing = wire_with(
            Sigs::matching(),
            Ok(vec![a_push()]),
            64 * 1024,
            Store { available: false },
        );
        let _ = post(
            refusing.app.clone(),
            "/webhook/github",
            Some("ok:abc"),
            BODY,
        )
        .await;

        let working = a_push_request();
        let _ = post(working.app.clone(), "/webhook/github", Some("ok:abc"), BODY).await;

        let written =
            String::from_utf8_lossy(&logs.lock().expect("not poisoned")[before..]).into_owned();

        assert!(
            !written.is_empty(),
            "nothing was logged, so nothing was checked"
        );
        for forbidden in FORBIDDEN_IN_LOGS {
            assert!(
                !written.contains(forbidden),
                "{forbidden:?} reached a log line: {written}"
            );
        }
    }
}
