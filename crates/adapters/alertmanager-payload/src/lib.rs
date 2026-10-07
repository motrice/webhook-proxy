//! Alertmanager's v4 webhook payload, translated into the Alerts it reports.
//!
//! The anti-corruption layer for the first alert sender. Alertmanager's field
//! names, its grouping, and its notion of a notification stop here; what comes
//! out is a list of [`Event::Alert`]. Nothing in this crate is reachable from the
//! domain or the application — they see only the `Translator` port — and it sees
//! only a `VerifiedDelivery`, so nothing here runs before verification.
//!
//! Everything in the payload except the schema version is written by whoever
//! authored the alerting rule or annotated the workload. That is a wider set of
//! people than whoever holds the credential we checked, so every field that
//! reaches a reader is carried as text and nothing is interpreted.
//!
//! Decisions this crate makes, recorded in bead gc-ast.8:
//!
//! * **Labels are the alert's own, not merged with the group's.** `groupLabels`
//!   and `commonLabels` are *derived* from the alerts in the notification rather
//!   than additional to them — Alertmanager already repeats them inside each
//!   alert's `labels`. Merging would add nothing and would create a second place
//!   for the same fact to live.
//! * **`annotations.summary` becomes the Summary**, falling back to
//!   `annotations.description`, then to the `alertname` label. An alert with no
//!   usable annotation is still reported: silence about something that is firing
//!   is the worst outcome available.
//! * **`generatorURL` becomes the link**, falling back to
//!   `annotations.runbook_url`. The generator points at the query that fired,
//!   which is what a reader wants first; the runbook is the next best thing.
//! * **An unknown field is ignored, an unknown version is not.** A newer
//!   Alertmanager adding a field must not take the channel down. A v5 whose
//!   semantics changed would be misread silently, so it is refused and the
//!   operator sees a 400.
//! * **A status we do not understand is refused**, never guessed. Saying
//!   "resolved" about something still firing is the one mistake here with real
//!   consequences.

use application::ports::{Translator, Untranslatable};
use domain::{
    AlertId, AlertStatus, Event, Labels, Permalink, Severity, Summary, Timestamp, VerifiedDelivery,
};
use serde::Deserialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// The only schema this crate was written against.
const VERSION: &str = "4";

/// Where a severity is conventionally found.
const SEVERITY: &str = "severity";

/// Where an alert's name is conventionally found, and the last resort for a
/// summary.
const ALERTNAME: &str = "alertname";

/// Translates Alertmanager notifications. Stateless.
#[derive(Debug, Clone, Copy, Default)]
pub struct AlertmanagerPayload;

/// One notification: a group of alerts that Alertmanager decided belong together.
#[derive(Deserialize)]
struct Notification {
    version: String,
    alerts: Vec<Firing>,
}

/// One alert within a notification.
///
/// `labels` and `annotations` are taken as maps rather than as named fields: a
/// sender may add either at will, and naming them here would mean a new label
/// required a code change.
#[derive(Deserialize)]
struct Firing {
    status: String,
    fingerprint: String,
    #[serde(rename = "startsAt")]
    starts_at: String,
    #[serde(default)]
    labels: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    annotations: std::collections::BTreeMap<String, String>,
    #[serde(rename = "generatorURL", default)]
    generator_url: String,
}

impl Translator for AlertmanagerPayload {
    fn events(&self, delivery: &VerifiedDelivery) -> Result<Vec<Event>, Untranslatable> {
        let notification: Notification =
            serde_json::from_slice(delivery.body().as_bytes()).map_err(|_| Untranslatable)?;

        if notification.version != VERSION {
            return Err(Untranslatable);
        }

        // All or nothing. A half-mapped notification would mean a room hears
        // about two of three alerts and nobody knows the third existed, which is
        // worse than a visible refusal the sender will retry.
        notification.alerts.iter().map(translate_alert).collect()
    }
}

/// One alert, or nothing.
fn translate_alert(raw: &Firing) -> Result<Event, Untranslatable> {
    let id = AlertId::new(&raw.fingerprint).map_err(|_| Untranslatable)?;
    let status = AlertStatus::from_label(&raw.status).ok_or(Untranslatable)?;
    let started = started_at(&raw.starts_at).ok_or(Untranslatable)?;

    let severity = raw
        .labels
        .get(SEVERITY)
        .map_or(Severity::Unstated, |stated| Severity::from_label(stated));

    let summary = summary_of(raw).ok_or(Untranslatable)?;
    let permalink = permalink_of(raw);
    let labels = labels_of(raw);

    Ok(Event::Alert {
        id,
        severity,
        status,
        summary,
        labels,
        started,
        permalink,
    })
}

/// When the sender says it began, as milliseconds since the epoch.
///
/// Parsed rather than approximated by our arrival time: those are different
/// facts, and recording one as the other would put a quiet untruth into data a
/// human reads.
fn started_at(stated: &str) -> Option<Timestamp> {
    let moment = OffsetDateTime::parse(stated, &Rfc3339).ok()?;
    let millis = moment.unix_timestamp_nanos() / 1_000_000;
    i64::try_from(millis)
        .ok()
        .map(Timestamp::from_millis_since_epoch)
}

/// The one line a Destination shows.
///
/// `summary`, then `description`, then the alert's name. Each is tried through
/// the domain's own constructor, so a present-but-blank annotation falls through
/// to the next rather than being carried as emptiness.
fn summary_of(raw: &Firing) -> Option<Summary> {
    ["summary", "description"]
        .into_iter()
        .filter_map(|key| raw.annotations.get(key))
        .chain(raw.labels.get(ALERTNAME))
        .find_map(|candidate| Summary::new(candidate).ok())
}

/// Where a reader can go, if the sender published anywhere.
///
/// Read, never built: this crate knows no address scheme, and a blank value is
/// dropped rather than carried as a link that goes nowhere.
fn permalink_of(raw: &Firing) -> Option<Permalink> {
    [
        raw.generator_url.as_str(),
        raw.annotations
            .get("runbook_url")
            .map_or("", String::as_str),
    ]
    .into_iter()
    .find_map(|candidate| Permalink::new(candidate).ok())
}

/// The alert's labels, as sent.
///
/// The severity label is kept as sent even though a typed Severity was read from
/// it, because the typed value is projected over it when routing — so there is
/// one answer, and this crate does not have to decide what the sender meant.
/// Dropping an unusable pair rather than refusing the alert is
/// [`Labels::from_pairs`]'s doing, shared with every other inbound adapter.
fn labels_of(raw: &Firing) -> Labels {
    Labels::from_pairs(
        raw.labels
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str())),
    )
}

#[cfg(test)]
mod tests {
    use application::ports::{Translator, Untranslatable};
    use domain::{
        AlertStatus, Body, Delivery, DeliveryId, Event, LabelName, OriginId, Permalink, Proof,
        Severity, Timestamp, VerifiedDelivery,
    };

    use super::AlertmanagerPayload;

    const FIRING: &[u8] = include_bytes!("../fixtures/firing.json");

    fn verified(body: &[u8]) -> VerifiedDelivery {
        let proof = Proof::from_bytes([1, 2, 3]);
        Delivery::new(
            DeliveryId::new("d-1").expect("a non-blank identity"),
            OriginId::new("a-monitor").expect("a non-blank origin identity"),
            Body::from_bytes(body.to_vec()),
            Timestamp::from_millis_since_epoch(1_759_000_000_000),
        )
        .verify(&proof, &proof)
        .expect("matching proofs")
    }

    fn translate(body: &[u8]) -> Result<Vec<Event>, Untranslatable> {
        AlertmanagerPayload.events(&verified(body))
    }

    fn alerts(body: &[u8]) -> Vec<Event> {
        translate(body).expect("translatable")
    }

    fn at(events: &[Event], index: usize) -> &Event {
        events.get(index).expect("an alert at that position")
    }

    fn label(labels: &domain::Labels, name: &str) -> Option<String> {
        let name = LabelName::new(name).expect("a non-blank name");
        labels.get(&name).map(|v| v.as_str().to_owned())
    }

    #[test]
    fn a_grouped_notification_yields_one_event_per_alert_in_the_order_sent() {
        let events = alerts(FIRING);

        assert_eq!(events.len(), 3, "{events:?}");
        let ids: Vec<&str> = events
            .iter()
            .map(|e| match e {
                Event::Alert { id, .. } => id.as_str(),
                other => panic!("not an alert: {other:?}"),
            })
            .collect();
        assert_eq!(
            ids,
            vec!["7b1a177c8d03f9e9", "0adf246e0adf246e", "6113728f27ae82c7"]
        );
    }

    #[test]
    fn a_resolved_alert_says_resolved_rather_than_saying_nothing() {
        let events = alerts(FIRING);

        let Event::Alert { status, .. } = at(&events, 2) else {
            panic!("an alert");
        };
        assert_eq!(*status, AlertStatus::Resolved);

        let Event::Alert { status, .. } = at(&events, 0) else {
            panic!("an alert");
        };
        assert_eq!(*status, AlertStatus::Firing);
    }

    #[test]
    fn the_summary_annotation_becomes_the_summary_and_only_its_first_line() {
        // Named explicitly: annotations.summary is the one that becomes the
        // Summary. The fixture's first alert has a second line that must not
        // travel, because a Destination shows one line.
        let events = alerts(FIRING);
        let Event::Alert { summary, .. } = at(&events, 0) else {
            panic!("an alert");
        };

        assert_eq!(summary.as_str(), "api latency above target");
    }

    #[test]
    fn description_is_used_when_there_is_no_summary_annotation() {
        let events = alerts(FIRING);
        let Event::Alert { summary, .. } = at(&events, 1) else {
            panic!("an alert");
        };

        assert_eq!(
            summary.as_str(),
            "only a description, no summary annotation"
        );
    }

    #[test]
    fn an_alerts_own_labels_become_its_labels() {
        let events = alerts(FIRING);
        let Event::Alert { labels, .. } = at(&events, 0) else {
            panic!("an alert");
        };

        // Four, as sent, severity included: the typed severity is projected over
        // it when routing, so storing it as sent costs nothing and keeps this
        // adapter from deciding what the sender meant.
        assert_eq!(labels.len(), 4);
        for (name, value) in [
            ("alertname", "HighLatency"),
            ("severity", "critical"),
            ("namespace", "prod"),
            ("service", "api"),
        ] {
            assert_eq!(label(labels, name).as_deref(), Some(value));
        }
    }

    #[test]
    fn an_alert_with_no_severity_label_is_unstated_rather_than_defaulted() {
        let events = alerts(FIRING);
        let Event::Alert { severity, .. } = at(&events, 1) else {
            panic!("an alert");
        };

        assert_eq!(*severity, Severity::Unstated);
    }

    #[test]
    fn a_severity_we_do_not_know_is_kept_as_the_sender_wrote_it() {
        let events = alerts(FIRING);
        let Event::Alert { severity, .. } = at(&events, 2) else {
            panic!("an alert");
        };

        assert_eq!(
            *severity,
            Severity::Unrecognised("page-the-duty-officer".to_owned())
        );
    }

    #[test]
    fn the_generator_url_becomes_the_link_and_a_blank_one_is_not_an_error() {
        let events = alerts(FIRING);

        let Event::Alert { permalink, .. } = at(&events, 0) else {
            panic!("an alert");
        };
        assert_eq!(
            permalink.as_ref().map(Permalink::as_str),
            Some("https://prometheus.example/graph?g0.expr=latency")
        );

        // The second alert's generatorURL is blank and it has no runbook_url, so
        // there is no link: an absence, not a failure.
        let Event::Alert { permalink, .. } = at(&events, 1) else {
            panic!("an alert");
        };
        assert!(permalink.is_none());
    }

    #[test]
    fn a_runbook_url_is_used_when_there_is_no_generator_url() {
        let payload = br#"{"version":"4","status":"firing","alerts":[{
            "status":"firing",
            "labels":{"alertname":"X"},
            "annotations":{"summary":"something","runbook_url":"https://runbooks.example/x"},
            "startsAt":"2026-10-07T09:15:00Z",
            "generatorURL":"",
            "fingerprint":"abc123"}]}"#;

        let events = alerts(payload);
        let Event::Alert { permalink, .. } = at(&events, 0) else {
            panic!("an alert");
        };

        assert_eq!(
            permalink.as_ref().map(Permalink::as_str),
            Some("https://runbooks.example/x")
        );
    }

    #[test]
    fn the_senders_start_time_is_carried_and_not_replaced_by_our_arrival_time() {
        // The arrival time in `verified` is 1_759_000_000_000, deliberately none
        // of these. When an alert began is the sender's fact, not ours.
        let events = alerts(FIRING);

        let Event::Alert { started, .. } = at(&events, 0) else {
            panic!("an alert");
        };
        assert_eq!(started.millis_since_epoch(), 1_791_364_500_000);

        let Event::Alert { started, .. } = at(&events, 1) else {
            panic!("an alert");
        };
        // Milliseconds survive.
        assert_eq!(started.millis_since_epoch(), 1_791_364_590_500);

        let Event::Alert { started, .. } = at(&events, 2) else {
            panic!("an alert");
        };
        // An offset is not ignored: 2026-10-06T22:00:00+02:00 is 20:00 UTC.
        //
        // Worth knowing that 1_791_324_000_000 is the value this produces if the
        // offset is dropped and the local time read as UTC — two hours late. The
        // first draft of this test asserted exactly that, so the number below is
        // the one that tells the two behaviours apart rather than merely passing.
        assert_eq!(started.millis_since_epoch(), 1_791_316_800_000);
    }

    #[test]
    fn markup_in_what_a_sender_wrote_survives_as_text() {
        let events = alerts(FIRING);
        let Event::Alert { summary, .. } = at(&events, 2) else {
            panic!("an alert");
        };

        assert!(summary.as_str().contains("<b>cert</b>"), "{summary:?}");
        assert!(summary.as_str().contains("[here]("), "{summary:?}");
    }

    #[test]
    fn a_tab_in_a_label_value_survives_as_text_rather_than_being_cleaned_up() {
        let payload = br#"{"version":"4","status":"firing","alerts":[{
            "status":"firing",
            "labels":{"alertname":"X","note":"before\tafter"},
            "annotations":{"summary":"fine"},
            "startsAt":"2026-10-07T09:15:00Z",
            "fingerprint":"abc123"}]}"#;

        let events = alerts(payload);
        let Event::Alert { labels, .. } = at(&events, 0) else {
            panic!("an alert");
        };

        assert_eq!(label(labels, "note").as_deref(), Some("before\tafter"));
    }

    #[test]
    fn a_field_we_do_not_know_is_ignored_so_a_newer_sender_keeps_working() {
        let payload = br#"{"version":"4","status":"firing","somethingNew":{"a":1},
            "alerts":[{
            "status":"firing","somethingElseNew":true,
            "labels":{"alertname":"X"},
            "annotations":{"summary":"fine"},
            "startsAt":"2026-10-07T09:15:00Z",
            "fingerprint":"abc123"}]}"#;

        assert_eq!(alerts(payload).len(), 1);
    }

    #[test]
    fn something_that_is_not_json_cannot_be_read_at_all() {
        assert_eq!(translate(b"{not json"), Err(Untranslatable));
    }

    #[test]
    fn json_of_the_wrong_shape_is_untranslatable_rather_than_half_mapped() {
        // No alerts array at all.
        assert_eq!(
            translate(br#"{"version":"4","status":"firing"}"#),
            Err(Untranslatable)
        );
        // An alert with no fingerprint: nothing a loss report could name it by.
        assert_eq!(
            translate(
                br#"{"version":"4","status":"firing","alerts":[{
                    "status":"firing","labels":{"alertname":"X"},
                    "annotations":{"summary":"fine"},
                    "startsAt":"2026-10-07T09:15:00Z"}]}"#
            ),
            Err(Untranslatable)
        );
        // A start time we cannot read.
        assert_eq!(
            translate(
                br#"{"version":"4","status":"firing","alerts":[{
                    "status":"firing","labels":{"alertname":"X"},
                    "annotations":{"summary":"fine"},
                    "startsAt":"last Tuesday","fingerprint":"abc123"}]}"#
            ),
            Err(Untranslatable)
        );
    }

    #[test]
    fn a_status_we_do_not_understand_is_refused_rather_than_guessed() {
        assert_eq!(
            translate(
                br#"{"version":"4","status":"firing","alerts":[{
                    "status":"flapping","labels":{"alertname":"X"},
                    "annotations":{"summary":"fine"},
                    "startsAt":"2026-10-07T09:15:00Z","fingerprint":"abc123"}]}"#
            ),
            Err(Untranslatable)
        );
    }

    #[test]
    fn a_schema_version_we_were_not_written_against_is_refused() {
        // Unknown fields are tolerated; an unknown version is not. A v5 whose
        // semantics changed would be misread silently, and a 400 an operator can
        // see beats a room quietly hearing the wrong thing.
        assert_eq!(
            translate(
                br#"{"version":"5","status":"firing","alerts":[{
                    "status":"firing","labels":{"alertname":"X"},
                    "annotations":{"summary":"fine"},
                    "startsAt":"2026-10-07T09:15:00Z","fingerprint":"abc123"}]}"#
            ),
            Err(Untranslatable)
        );
    }

    #[test]
    fn an_alert_with_no_usable_annotation_is_still_reported() {
        // Its name rather than nothing: a room hearing silence about something
        // that is firing is the worst outcome available.
        let payload = br#"{"version":"4","status":"firing","alerts":[{
            "status":"firing","labels":{"alertname":"HighLatency"},
            "annotations":{},
            "startsAt":"2026-10-07T09:15:00Z","fingerprint":"abc123"}]}"#;

        let events = alerts(payload);
        let Event::Alert { summary, .. } = at(&events, 0) else {
            panic!("an alert");
        };

        assert_eq!(summary.as_str(), "HighLatency");
    }
}
