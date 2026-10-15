//! The specification, checked against the code rather than against a list.
//!
//! A specification nobody checks is prose with a schema, and the failure it
//! invites is quiet: a path renamed, a status added, a mechanism changed, and
//! the document goes on describing an interface that no longer exists. Bead
//! gc-4oo.3. The pattern is `manifests.rs`'s — read the thing that ships and
//! ask whether the document still matches it.
//!
//! What this cannot check is whether the description is *good*. It can only
//! check that it is true.

use serde_yaml_ng::Value;

/// The specification itself.
const SPEC: &str = include_str!("../../../docs/openapi.yaml");

/// Where the webhook path and its statuses are decided.
const INBOUND: &str = include_str!("../../adapters/inbound-http/src/lib.rs");

/// Where the two operational paths are added to the router.
const APP: &str = include_str!("../src/main.rs");

/// Where the hand-off to a tenant's agent is added to the router.
const COLLECTING: &str = include_str!("../src/collecting.rs");

/// The mesh policy that is the actual boundary on the internal paths.
const POLICY: &str = include_str!("../../../deploy/webhook-proxy/istio/authorizationpolicy.yaml");

/// Paths this specification deliberately does not describe, and why each.
///
/// A NAMED LIST AND NEVER A PATTERN, which bead gc-81d insisted on. A rule like
/// "anything under /deliveries" would absorb the next internal path somebody
/// adds without anybody deciding to exclude it — the same failure as the
/// line-based route scan that missed `/metrics` in gc-4oo.3, where the test was
/// green because it was comparing two sets that agreed about everything it had
/// managed to find. Adding a path here is an edit a reviewer sees.
///
/// `docs/openapi.yaml` describes the interface a SENDER may call. These are the
/// interface a tenant's agent calls: in-cluster machinery, authenticated by the
/// service mesh rather than by a sender's credential, and not bound by the
/// national REST API-profil — which gc-81d decided explicitly, because
/// gc-4oo.2's MOG, AME, FNS and FEL verdicts would otherwise reactivate the
/// moment a JSON body existed.
const INTERNAL: &[(&str, &str)] = &[
    (
        "/deliveries/claim",
        "a tenant's agent claims its own undelivered Deliveries. Not a sender's          interface: authenticated by the caller's mTLS identity, and not          published by the HTTPRoute at all. Bead gc-wcw.2.",
    ),
    (
        "/deliveries/{delivery}/report",
        "a tenant's agent states terminally what each of its rooms did with one          Delivery. Internal for the same reasons as the claim above.",
    ),
];

/// The routing file this deployment ships, which names the mechanisms in use.
const ROUTING: &str = include_str!("../../../deploy/webhook-proxy/config.example.yaml");

fn spec() -> Value {
    serde_yaml_ng::from_str(SPEC).expect("the specification parses as YAML")
}

/// Every path the specification describes.
fn documented_paths() -> std::collections::BTreeSet<String> {
    spec()["paths"]
        .as_mapping()
        .expect("the specification has paths")
        .keys()
        .map(|key| key.as_str().expect("a path is a string").to_owned())
        .collect()
}

/// Every path the code routes, from both files that add one.
///
/// Read from the source rather than from a running binary on purpose: a request
/// to `/webhook/nothing-configured` answers 404 by design, so probing cannot
/// tell a path that does not exist from an Origin that is not configured.
fn routed_paths() -> std::collections::BTreeSet<String> {
    // Scans for the first string literal after each `.route(`, rather than
    // reading the line. `/metrics` takes a closure and is written across several
    // lines, so a line-based match silently missed it — and silently is the
    // point: the test then compared two sets that agreed about everything it had
    // managed to find. Fixed here rather than by reformatting main.rs to suit
    // the test, which would have left the next multi-line route invisible again.
    [INBOUND, APP, COLLECTING]
        .iter()
        .flat_map(|source| {
            source.match_indices(".route(").filter_map(|(at, marker)| {
                let rest = &source[at + marker.len()..];
                let opening = rest.find('"')?;
                let after = &rest[opening + 1..];
                // A route path cannot contain a quote, so the next one closes it.
                let closing = after.find('"')?;
                Some(after[..closing].to_owned())
            })
        })
        .collect()
}

#[test]
fn the_specification_describes_every_public_path_the_code_routes_and_no_others() {
    let internal: std::collections::BTreeSet<String> = INTERNAL
        .iter()
        .map(|(path, _)| (*path).to_owned())
        .collect();
    let public: std::collections::BTreeSet<String> =
        routed_paths().difference(&internal).cloned().collect();

    assert_eq!(
        documented_paths(),
        public,
        "the specification and the router disagree about which public paths exist"
    );
}

#[test]
fn every_excluded_path_is_one_the_code_actually_routes() {
    // The other half of the exclusion list, and the half that rots. A path
    // renamed or removed leaves a waiver behind that now excludes nothing, and
    // the next path to take that spelling is excluded without anybody deciding
    // to — which is the whole failure the named list exists to prevent, arrived
    // at from the other direction.
    let routed = routed_paths();
    for (path, why) in INTERNAL {
        assert!(
            routed.contains(*path),
            "{path:?} is excluded from the specification, and nothing routes it.              Remove the exclusion. Its stated reason was: {why}"
        );
    }
}

#[test]
fn no_excluded_path_is_also_documented() {
    // Belt and braces, and cheap: a path in both lists would make the exclusion
    // meaningless while looking deliberate from either side alone.
    let documented = documented_paths();
    for (path, _) in INTERNAL {
        assert!(
            !documented.contains(*path),
            "{path:?} is both documented as public and excluded as internal"
        );
    }
}

/// Every status the webhook handler can answer with.
///
/// Read from the handler's own source, up to its test module: the tests below it
/// assert on the same names, and counting those would make this pass for the
/// wrong reason — a status asserted only in a test is not a status the handler
/// returns.
fn returned_statuses() -> std::collections::BTreeSet<u16> {
    let handler = INBOUND
        .split_once("mod tests")
        .map_or(INBOUND, |(before, _)| before);

    // `map`, not `filter_map`: every arm either yields a status or panics, so
    // there is no such thing as a `StatusCode::` this quietly drops.
    handler
        .match_indices("StatusCode::")
        .map(|(at, marker)| {
            let rest = &handler[at + marker.len()..];
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_uppercase() || *c == '_')
                .collect();
            match name.as_str() {
                "ACCEPTED" => 202,
                "BAD_REQUEST" => 400,
                "UNAUTHORIZED" => 401,
                "NOT_FOUND" => 404,
                "PAYLOAD_TOO_LARGE" => 413,
                "UNSUPPORTED_MEDIA_TYPE" => 415,
                "SERVICE_UNAVAILABLE" => 503,
                // A status this test does not know is a status nobody documented
                // on purpose. Loud, because the quiet alternative is a response
                // the specification never mentions.
                other => {
                    panic!("the handler returns StatusCode::{other}, which this test cannot map")
                }
            }
        })
        .collect()
}

/// Every status the specification documents for the webhook path.
fn documented_statuses() -> std::collections::BTreeSet<u16> {
    spec()["paths"]["/webhook/{origin}"]["post"]["responses"]
        .as_mapping()
        .expect("the webhook operation documents responses")
        .keys()
        .map(|key| {
            key.as_str()
                .expect("a status is a string")
                .parse()
                .expect("a status is a number")
        })
        .collect()
}

#[test]
fn the_specification_documents_every_status_the_handler_returns() {
    // 413 is the exception that proves the rule: it comes from the body-limit
    // layer rather than from the handler, so it appears in the specification and
    // not in the handler's source. Any OTHER difference is drift.
    let returned = returned_statuses();
    let documented = documented_statuses();
    let undocumented: Vec<_> = returned.difference(&documented).collect();

    assert!(
        undocumented.is_empty(),
        "the handler returns statuses the specification does not mention: {undocumented:?}"
    );
    assert!(
        documented.contains(&413),
        "the body-limit layer refuses an oversized request with 413, and the \
         specification is the only place that can say so"
    );
}

/// The verification mechanisms this deployment's routing file actually uses.
fn configured_mechanisms() -> std::collections::BTreeSet<String> {
    let routing: Value = serde_yaml_ng::from_str(ROUTING).expect("the routing file parses");

    routing["origins"]
        .as_sequence()
        .expect("the routing file has origins")
        .iter()
        .flat_map(|origin| {
            origin["verify"]
                .as_mapping()
                .expect("every Origin declares how it is verified")
                .keys()
                .map(|key| key.as_str().expect("a mechanism is a string").to_owned())
                .collect::<Vec<_>>()
        })
        .collect()
}

#[test]
fn the_specification_describes_every_mechanism_a_sender_actually_uses() {
    // The senders define this interface, whether this proxy's authors like it or
    // not (gc-4oo.2): GitHub signs a body, Alertmanager and Grafana send a
    // token, and neither can be reconfigured to suit a profile. So the
    // specification carries two security schemes because there are two, and this
    // fails if one is dropped from either side.
    let schemes = spec()["components"]["securitySchemes"]
        .as_mapping()
        .expect("the specification declares security schemes")
        .clone();

    let described: Vec<String> = schemes
        .values()
        .map(|scheme| serde_yaml_ng::to_string(scheme).expect("a scheme renders"))
        .collect();
    let all = described.join("\n");

    for mechanism in configured_mechanisms() {
        assert!(
            all.contains(&mechanism),
            "the routing file verifies an Origin with {mechanism:?}, and no \
             security scheme in the specification names it: {all}"
        );
    }

    assert_eq!(
        schemes.len(),
        configured_mechanisms().len(),
        "the specification describes {} schemes for {} configured mechanisms",
        schemes.len(),
        configured_mechanisms().len()
    );
}

#[test]
fn each_scheme_names_the_header_the_code_actually_reads() {
    // The header name is the one thing a sender cannot guess and cannot recover
    // from getting wrong: a signature in the wrong header is an absent
    // credential, which answers 401 and says nothing further, on purpose.
    let presented: Vec<&str> = INBOUND
        .match_indices("Presented::Header(\"")
        .filter_map(|(at, marker)| {
            let rest = &INBOUND[at + marker.len()..];
            rest.find('"').map(|end| &rest[..end])
        })
        .collect();

    assert!(
        !presented.is_empty(),
        "no header constants found, so this test proves nothing"
    );

    let described = serde_yaml_ng::to_string(&spec()["components"]["securitySchemes"])
        .expect("the schemes render");

    for header in presented {
        // `authorization` is the http/bearer scheme's own header, which OpenAPI
        // names by type rather than spelling out, so accept either.
        let named = described.contains(header)
            || (header == "authorization" && described.contains("scheme: bearer"));
        assert!(
            named,
            "the code reads a credential from {header:?}, and the specification \
             does not say so: {described}"
        );
    }
}

/// A router path as a mesh policy spells it: `{delivery}` becomes `*`.
fn as_a_policy_spells_it(path: &str) -> String {
    path.split('/')
        .map(|segment| {
            if segment.starts_with('{') && segment.ends_with('}') {
                "*"
            } else {
                segment
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

#[test]
fn the_mesh_policy_names_every_internal_path() {
    // The exclusion list above says these paths are not a sender's to call. The
    // thing that makes that true is the AuthorizationPolicy, and nothing else
    // connects the two: a third internal path could be added, excluded from the
    // specification with a reason, and left unprotected — with every test
    // passing and the path reachable by anything in the mesh.
    //
    // Checked against the policy's own text rather than by parsing its rules,
    // because what matters is that the path is named somewhere in it, and a
    // structural read would have to model Istio's rule semantics to be any
    // stricter.
    for (path, why) in INTERNAL {
        let spelled = as_a_policy_spells_it(path);
        assert!(
            POLICY.contains(&spelled),
            "{path:?} is internal and deploy/webhook-proxy/istio/authorizationpolicy.yaml \
             does not name it (as {spelled:?}), so nothing restricts who may call it. \
             Its stated reason for being internal was: {why}"
        );
    }
}

#[test]
fn the_mesh_policy_allows_rather_than_denies() {
    // The property that makes the policy safe to forget to update: a path
    // nobody wrote a rule for is refused. A DENY list would publish every path
    // added afterwards, which is the same failure as a pattern in the exclusion
    // list above, one layer down.
    let policy: Value = serde_yaml_ng::from_str(POLICY).expect("the policy parses");
    assert_eq!(
        policy["spec"]["action"].as_str(),
        Some("ALLOW"),
        "the mesh policy denies named paths instead of allowing named ones, so a \
         path added later is reachable by anything in the mesh"
    );
}
