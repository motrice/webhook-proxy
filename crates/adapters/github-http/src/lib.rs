//! The driving adapter: an HTTP request in, the use case called, an answer out.
//!
//! This crate is the authentication boundary's front door. It holds no rules:
//! it captures the bytes that arrived, hands them to the use case, and turns the
//! outcome into a status code. Everything it must *not* do is in README under
//! "The security boundary", and two of those are structural here — the body is
//! never parsed in this crate, and there is no code path that reaches the
//! dispatcher without going through `Relay::relay`.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use application::ports::{Clock, Dispatcher, Ids, Proofs, Translator};
use application::{Refused, Relay};
use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use domain::{Body, Origin, Subscription};

/// Where GitHub presents its signature.
const SIGNATURE_HEADER: &str = "x-hub-signature-256";

/// Everything the front door needs, shareable across requests.
///
/// Ports arrive as trait objects rather than generics so that the state stays
/// one concrete type: axum clones it per request, and a five-parameter generic
/// would be inflicted on every caller for no benefit.
#[derive(Clone)]
pub struct Inbound {
    signatures: Arc<dyn Proofs>,
    translator: Arc<dyn Translator>,
    dispatcher: Arc<dyn Dispatcher>,
    clock: Arc<dyn Clock>,
    ids: Arc<dyn Ids>,
    subscriptions: Arc<Vec<Subscription>>,
    /// The Origins we hold a secret for, by the name in the request path. An
    /// Origin absent here cannot be authenticated and is therefore refused.
    origins: Arc<HashMap<String, Origin>>,
    losses: Arc<AtomicU64>,
}

impl Inbound {
    /// Wires the front door to the application.
    #[must_use]
    pub fn new(
        signatures: Arc<dyn Proofs>,
        translator: Arc<dyn Translator>,
        dispatcher: Arc<dyn Dispatcher>,
        clock: Arc<dyn Clock>,
        ids: Arc<dyn Ids>,
        subscriptions: Vec<Subscription>,
        origins: HashMap<String, Origin>,
    ) -> Self {
        Self {
            signatures,
            translator,
            dispatcher,
            clock,
            ids,
            subscriptions: Arc::new(subscriptions),
            origins: Arc::new(origins),
            losses: Arc::new(AtomicU64::new(0)),
        }
    }

    /// How many Dispatches have been dropped since start.
    ///
    /// The delivery promise is best-effort, and a best-effort system whose
    /// losses are invisible is indistinguishable from a broken one. This is the
    /// count that makes the promise auditable.
    #[must_use]
    pub fn losses(&self) -> u64 {
        self.losses.load(Ordering::Relaxed)
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
async fn receive(
    State(inbound): State<Inbound>,
    Path(origin): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    // An Origin we hold no secret for cannot be authenticated, so it is refused
    // here rather than anywhere further in.
    let Some(origin) = inbound.origins.get(&origin) else {
        return StatusCode::NOT_FOUND;
    };

    // Nothing below this point runs without something to compare. There is no
    // flag, no environment variable and no build feature that skips it.
    let Some(presented) = headers
        .get(SIGNATURE_HEADER)
        .and_then(|value| value.to_str().ok())
    else {
        return StatusCode::UNAUTHORIZED;
    };
    let Ok(claimed) = inbound.signatures.claimed(presented) else {
        return StatusCode::UNAUTHORIZED;
    };

    let relay = Relay::new(
        inbound.signatures.as_ref(),
        inbound.translator.as_ref(),
        inbound.dispatcher.as_ref(),
        inbound.clock.as_ref(),
        inbound.ids.as_ref(),
        inbound.subscriptions.as_slice(),
    );

    // The body is handed over as the bytes that arrived. This crate never parses
    // it: translation is a port, reached only after verification.
    match relay
        .relay(origin, Body::from_bytes(body.to_vec()), &claimed)
        .await
    {
        Ok(relayed) => {
            for (destination, failure) in relayed.lost() {
                inbound.losses.fetch_add(1, Ordering::Relaxed);
                // Identities and a reason. A Destination holds no address, so
                // there is no credential here to spill.
                tracing::warn!(
                    delivery = relayed.delivery().as_str(),
                    destination = destination.as_str(),
                    failure = ?failure,
                    "dispatch lost"
                );
            }
            StatusCode::ACCEPTED
        }
        Err(Refused::ProofMismatch) => StatusCode::UNAUTHORIZED,
        Err(Refused::SecretUnavailable) => StatusCode::SERVICE_UNAVAILABLE,
        Err(Refused::Untranslatable) => StatusCode::BAD_REQUEST,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io;
    use std::sync::{Arc, Mutex, OnceLock};

    use application::ports::{
        Clock, DispatchFailed, Dispatcher, Ids, MalformedProof, Proofs, SecretUnavailable,
        Translator, Untranslatable,
    };
    use axum::Router;
    use axum::body::Body as AxumBody;
    use axum::http::{Request, StatusCode};
    use domain::{
        Body, BranchName, DeliveryId, Destination, DestinationId, DestinationKind, Event, Filter,
        Origin, OriginId, Proof, Pusher, RepositoryName, SecretId, Subscription, Timestamp,
        VerifiedDelivery,
    };
    use tower::ServiceExt;
    use tracing_subscriber::fmt::MakeWriter;

    use super::{Inbound, router};

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
    }

    /// Fails for the Destinations named, and records the rest.
    struct Recorder {
        sent: Mutex<Vec<String>>,
        failing: Vec<&'static str>,
    }

    impl Recorder {
        fn new(failing: Vec<&'static str>) -> Arc<Self> {
            Arc::new(Self {
                sent: Mutex::new(Vec::new()),
                failing,
            })
        }

        fn sent(&self) -> Vec<String> {
            self.sent.lock().expect("not poisoned").clone()
        }
    }

    #[async_trait::async_trait]
    impl Dispatcher for Recorder {
        async fn dispatch(
            &self,
            _delivery: &DeliveryId,
            _event: &Event,
            destination: &Destination,
        ) -> Result<(), DispatchFailed> {
            let id = destination.id().as_str().to_owned();
            if self.failing.contains(&id.as_str()) {
                // Carries the kind of failure, never the URL that produced it.
                return Err(DispatchFailed::Unreachable);
            }
            self.sent.lock().expect("not poisoned").push(id);
            Ok(())
        }
    }

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
                SecretId::new("a-secret").expect("a non-blank secret name"),
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

    fn to_rooms(ids: &[&str]) -> Vec<Subscription> {
        ids.iter()
            .map(|id| {
                Subscription::new(
                    Destination::new(
                        DestinationId::new(id).expect("a non-blank id"),
                        DestinationKind::ChatRoom,
                    ),
                    Filter::Everything,
                )
            })
            .collect()
    }

    struct Wired {
        app: Router,
        inbound: Inbound,
        sigs: Arc<Sigs>,
        dispatcher: Arc<Recorder>,
        ids: Arc<CountingIds>,
    }

    fn wire(
        sigs: Arc<Sigs>,
        says: Result<Vec<Event>, Untranslatable>,
        failing: Vec<&'static str>,
        rooms: &[&str],
        max_body: usize,
    ) -> Wired {
        let dispatcher = Recorder::new(failing);
        let ids = Arc::new(CountingIds(Mutex::new(0)));
        let (name, origin) = an_origin();
        let inbound = Inbound::new(
            sigs.clone(),
            Arc::new(Says(says)),
            dispatcher.clone(),
            Arc::new(FixedClock),
            ids.clone(),
            to_rooms(rooms),
            HashMap::from([(name, origin)]),
        );

        Wired {
            app: router(inbound.clone(), max_body),
            inbound,
            sigs,
            dispatcher,
            ids,
        }
    }

    fn a_push_to(rooms: &[&str]) -> Wired {
        wire(
            Sigs::matching(),
            Ok(vec![a_push()]),
            vec![],
            rooms,
            64 * 1024,
        )
    }

    async fn post(app: Router, path: &str, signature: Option<&str>, body: &[u8]) -> StatusCode {
        let mut request = Request::builder().method("POST").uri(path);
        if let Some(value) = signature {
            request = request.header("X-Hub-Signature-256", value);
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
    async fn a_valid_signed_push_is_accepted() {
        let wired = a_push_to(&["room"]);

        let status = post(wired.app, "/webhook/github", Some("ok:abc"), BODY).await;

        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(wired.dispatcher.sent(), vec!["room"]);
    }

    #[tokio::test]
    async fn the_verifier_is_given_the_exact_bytes_that_arrived() {
        // The defect this guards against is re-encoding the body on the way in:
        // it passes every happy-path test and fails the first time a payload
        // round-trips differently.
        let wired = a_push_to(&["room"]);

        post(wired.app, "/webhook/github", Some("ok:abc"), BODY).await;

        assert_eq!(wired.sigs.seen(), vec![BODY.to_vec()]);
    }

    #[tokio::test]
    async fn an_identity_is_minted_through_the_ids_port() {
        let wired = a_push_to(&["room"]);

        post(wired.app, "/webhook/github", Some("ok:abc"), BODY).await;

        assert_eq!(*wired.ids.0.lock().expect("not poisoned"), 1);
    }

    #[tokio::test]
    async fn a_mismatched_signature_is_unauthorised_and_dispatches_nothing() {
        let wired = wire(
            Sigs::mismatching(),
            Ok(vec![a_push()]),
            vec![],
            &["room"],
            64 * 1024,
        );

        let status = post(wired.app, "/webhook/github", Some("ok:abc"), BODY).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(wired.dispatcher.sent().is_empty());
    }

    #[tokio::test]
    async fn a_request_with_no_signature_at_all_is_refused() {
        // There is no configuration under which this succeeds. This proxy is the
        // authentication boundary; an unsigned request is the thing it exists to
        // refuse.
        let wired = a_push_to(&["room"]);

        let status = post(wired.app, "/webhook/github", None, BODY).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(wired.dispatcher.sent().is_empty());
        assert!(wired.sigs.seen().is_empty(), "nothing should be computed");
    }

    #[tokio::test]
    async fn an_unreadable_signature_header_is_refused() {
        let wired = a_push_to(&["room"]);

        let status = post(wired.app, "/webhook/github", Some("garbage"), BODY).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(wired.dispatcher.sent().is_empty());
    }

    #[tokio::test]
    async fn an_origin_we_hold_no_secret_for_is_refused_never_forwarded() {
        let wired = a_push_to(&["room"]);

        let status = post(wired.app, "/webhook/gitlab", Some("ok:abc"), BODY).await;

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(wired.dispatcher.sent().is_empty());
    }

    #[tokio::test]
    async fn an_unusable_secret_is_our_fault_and_says_so() {
        // Distinct from a mismatch on purpose: a misconfigured deployment must
        // not hide behind what looks like an attack.
        let wired = wire(
            Sigs::secretless(),
            Ok(vec![a_push()]),
            vec![],
            &["room"],
            64 * 1024,
        );

        let status = post(wired.app, "/webhook/github", Some("ok:abc"), BODY).await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(wired.dispatcher.sent().is_empty());
    }

    #[tokio::test]
    async fn a_payload_we_cannot_read_is_a_bad_request() {
        let wired = wire(
            Sigs::matching(),
            Err(Untranslatable),
            vec![],
            &["room"],
            64 * 1024,
        );

        let status = post(wired.app, "/webhook/github", Some("ok:abc"), BODY).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(wired.dispatcher.sent().is_empty());
    }

    #[tokio::test]
    async fn a_payload_reporting_nothing_we_handle_is_still_accepted() {
        let wired = wire(Sigs::matching(), Ok(vec![]), vec![], &["room"], 64 * 1024);

        let status = post(wired.app, "/webhook/github", Some("ok:abc"), BODY).await;

        assert_eq!(status, StatusCode::ACCEPTED);
        assert!(wired.dispatcher.sent().is_empty());
    }

    #[tokio::test]
    async fn a_body_over_the_limit_is_refused_before_anything_is_computed() {
        let wired = wire(Sigs::matching(), Ok(vec![a_push()]), vec![], &["room"], 16);

        let status = post(wired.app, "/webhook/github", Some("ok:abc"), BODY).await;

        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert!(
            wired.sigs.seen().is_empty(),
            "the limit must bite before verification"
        );
        assert!(wired.dispatcher.sent().is_empty());
    }

    #[tokio::test]
    async fn a_failed_dispatch_still_accepts_and_counts_the_loss() {
        let wired = wire(
            Sigs::matching(),
            Ok(vec![a_push()]),
            vec!["broken"],
            &["working", "broken"],
            64 * 1024,
        );

        let status = post(wired.app.clone(), "/webhook/github", Some("ok:abc"), BODY).await;

        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(wired.dispatcher.sent(), vec!["working"]);
        assert_eq!(wired.inbound.losses(), 1);
    }

    #[tokio::test]
    async fn a_loss_is_logged_by_identity_and_nothing_else() {
        let logs = captured_logs();

        let wired = wire(
            Sigs::matching(),
            Ok(vec![a_push()]),
            vec!["devsecops-room"],
            &["devsecops-room"],
            64 * 1024,
        );

        post(wired.app, "/webhook/github", Some("ok:abc"), BODY).await;

        let written = String::from_utf8(logs.lock().expect("not poisoned").clone())
            .expect("log output is text");

        // A loss must be recorded, and traceable to what was lost.
        assert!(
            written.contains("devsecops-room"),
            "a dropped Dispatch must name its Destination: {written}"
        );
        assert!(
            written.contains("Unreachable"),
            "a dropped Dispatch must say why: {written}"
        );

        for forbidden in FORBIDDEN_IN_LOGS {
            assert!(
                !written.to_lowercase().contains(forbidden),
                "`{forbidden}` reached the log: {written}"
            );
        }
    }
}
