//! Grafana's unified alerting webhook, translated into the Alerts it reports.
//!
//! The second alert sender, and the one that makes "multiple alert senders" real.
//! Its payload resembles Alertmanager's closely enough to be mistaken for it —
//! the same outer shape, the same alerts array — and is not it: a different
//! schema version, its own per-alert URLs, an organisation identity, and a
//! group-level title and message that Alertmanager has no equivalent of.
//!
//! **Two senders are two Origins, not one lenient parser.** Because the outer
//! shapes are so alike, a parser willing to read either would half-read the
//! other's payload and build Events from the wrong conventions — Grafana's title
//! treated as an annotation, say. The schema version is what keeps them apart,
//! and tests in both directions assert it.
//!
//! What this crate does *not* reimplement: reading a status, building Labels from
//! loose pairs, and every value type's own validation all live in the domain,
//! which is where the Alertmanager adapter reaches for them too. Adapters may not
//! depend on each other, so anything genuinely shared belongs below them rather
//! than beside them.

use application::ports::{Translator, Untranslatable};
use domain::{
    AlertId, AlertStatus, Event, Labels, Permalink, Severity, Summary, Timestamp, VerifiedDelivery,
};
use serde::Deserialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// The only schema this crate was written against.
///
/// Grafana's unified alerting has sent `"1"` since it replaced the legacy
/// alerting webhook. Alertmanager sends `"4"`, which is what stops each parser
/// reading the other's payload.
const VERSION: &str = "1";

/// Where a severity is conventionally found.
const SEVERITY: &str = "severity";

/// Where an alert's name is conventionally found, and the last resort for a
/// summary.
const ALERTNAME: &str = "alertname";

/// Translates Grafana notifications. Stateless.
#[derive(Debug, Clone, Copy, Default)]
pub struct GrafanaPayload;

/// One notification: the alerts in a Grafana group, with the group's own text.
#[derive(Deserialize)]
struct Notification {
    version: String,
    alerts: Vec<Firing>,
    /// One line about the group. Grafana composes it, so it is the best thing
    /// available when an alert says nothing about itself.
    #[serde(default)]
    title: String,
    /// Multi-line markdown about the group. Useful to a human reading Grafana,
    /// less so as a one-line summary — its first line is a bold "Firing".
    #[serde(default)]
    message: String,
}

/// One alert within a notification.
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
    /// The panel that fired: the most specific place to look.
    #[serde(rename = "panelURL", default)]
    panel_url: String,
    /// The dashboard it is on.
    #[serde(rename = "dashboardURL", default)]
    dashboard_url: String,
    /// The rule's own view.
    #[serde(rename = "generatorURL", default)]
    generator_url: String,
}

impl Translator for GrafanaPayload {
    fn events(&self, delivery: &VerifiedDelivery) -> Result<Vec<Event>, Untranslatable> {
        let notification: Notification =
            serde_json::from_slice(delivery.body().as_bytes()).map_err(|_| Untranslatable)?;

        if notification.version != VERSION {
            return Err(Untranslatable);
        }

        // All or nothing: a half-mapped group means a room hears about two of
        // three alerts and nobody knows the third existed.
        notification
            .alerts
            .iter()
            .map(|raw| translate_alert(raw, &notification))
            .collect()
    }
}

/// One alert, or nothing.
fn translate_alert(raw: &Firing, group: &Notification) -> Result<Event, Untranslatable> {
    let id = AlertId::new(&raw.fingerprint).map_err(|_| Untranslatable)?;
    let status = AlertStatus::from_label(&raw.status).ok_or(Untranslatable)?;
    let started = started_at(&raw.starts_at).ok_or(Untranslatable)?;

    let severity = raw
        .labels
        .get(SEVERITY)
        .map_or(Severity::Unstated, |stated| Severity::from_label(stated));

    let summary = summary_of(raw, group).ok_or(Untranslatable)?;
    let permalink = permalink_of(raw);
    let labels = Labels::from_pairs(
        raw.labels
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str())),
    );

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

/// When the sender says it began.
///
/// Six lines that the Alertmanager adapter also has. Adapters may not depend on
/// each other and this needs a dependency the domain must never gain, so it is
/// duplicated rather than shared — see the commit message for why that was the
/// right call and what was pushed into the domain instead.
fn started_at(stated: &str) -> Option<Timestamp> {
    let moment = OffsetDateTime::parse(stated, &Rfc3339).ok()?;
    let millis = moment.unix_timestamp_nanos() / 1_000_000;
    i64::try_from(millis)
        .ok()
        .map(Timestamp::from_millis_since_epoch)
}

/// The one line a Destination shows.
///
/// The alert's own annotations first, because the group's title describes every
/// alert in the notification and an alert that says something about itself says
/// it better. Then the title, which Grafana composes as one line. Then the
/// message, whose first line is a bold "Firing" and says nothing about what
/// broke — last on purpose rather than by accident of ordering. Then the alert's
/// name, so an alert with nothing to say is still reported.
fn summary_of(raw: &Firing, group: &Notification) -> Option<Summary> {
    ["summary", "description"]
        .into_iter()
        .filter_map(|key| raw.annotations.get(key).map(String::as_str))
        .chain([group.title.as_str(), group.message.as_str()])
        .chain(raw.labels.get(ALERTNAME).map(String::as_str))
        .find_map(|candidate| Summary::new(candidate).ok())
}

/// Where a reader should look.
///
/// Most specific first: the panel that fired, then the dashboard it lives on,
/// then the rule's own view.
///
/// `silenceURL` is deliberately never offered. Grafana sends one with every
/// alert, and making "silence this" the link a notice points at invites
/// silencing before reading, which is the opposite of what a notice is for.
fn permalink_of(raw: &Firing) -> Option<Permalink> {
    [
        raw.panel_url.as_str(),
        raw.dashboard_url.as_str(),
        raw.generator_url.as_str(),
    ]
    .into_iter()
    .find_map(|candidate| Permalink::new(candidate).ok())
}

#[cfg(test)]
mod tests {
    use application::ports::{Translator, Untranslatable};
    use domain::{
        AlertStatus, Body, Delivery, DeliveryId, Event, LabelName, OriginId, Permalink, Proof,
        Severity, Timestamp, VerifiedDelivery,
    };

    use super::GrafanaPayload;

    const FIRING: &[u8] = include_bytes!("../fixtures/firing.json");
    /// Alertmanager's own notification, to prove the two are not interchangeable.
    const ALERTMANAGER: &[u8] = include_bytes!("../../alertmanager-payload/fixtures/firing.json");

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
        GrafanaPayload.events(&verified(body))
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
    fn a_notification_yields_one_event_per_alert_with_its_own_status() {
        let events = alerts(FIRING);

        assert_eq!(events.len(), 3, "{events:?}");
        let states: Vec<AlertStatus> = events
            .iter()
            .map(|e| match e {
                Event::Alert { status, .. } => *status,
                other => panic!("not an alert: {other:?}"),
            })
            .collect();
        assert_eq!(
            states,
            vec![
                AlertStatus::Firing,
                AlertStatus::Firing,
                AlertStatus::Resolved
            ]
        );
    }

    #[test]
    fn an_alerts_own_summary_annotation_wins_over_the_notifications_title() {
        // The notification's title describes the group — three alerts share it —
        // so an alert that says something about itself says it better.
        let events = alerts(FIRING);
        let Event::Alert { summary, .. } = at(&events, 0) else {
            panic!("an alert");
        };

        assert_eq!(summary.as_str(), "api latency above target");
    }

    #[test]
    fn the_title_wins_over_the_message_when_an_alert_says_nothing_itself() {
        // Both are present in the fixture and the title is the one that travels:
        // it is one line by design, where the message is multi-line markdown
        // whose first line is "**Firing**" and says nothing about what broke.
        let events = alerts(FIRING);
        let Event::Alert { summary, .. } = at(&events, 1) else {
            panic!("an alert");
        };

        assert_eq!(summary.as_str(), "[FIRING:2, RESOLVED:1] HighLatency");
        assert!(!summary.as_str().contains("Firing**"), "{summary:?}");
    }

    #[test]
    fn the_panel_url_wins_then_the_dashboard_then_the_rule() {
        let events = alerts(FIRING);

        // Most specific first: the panel that fired.
        let Event::Alert { permalink, .. } = at(&events, 0) else {
            panic!("an alert");
        };
        assert_eq!(
            permalink.as_ref().map(Permalink::as_str),
            Some("https://grafana.example/d/latency?viewPanel=3")
        );

        // No panel, so the dashboard.
        let Event::Alert { permalink, .. } = at(&events, 1) else {
            panic!("an alert");
        };
        assert_eq!(
            permalink.as_ref().map(Permalink::as_str),
            Some("https://grafana.example/d/disk")
        );

        // Neither, so the rule that fired.
        let Event::Alert { permalink, .. } = at(&events, 2) else {
            panic!("an alert");
        };
        assert_eq!(
            permalink.as_ref().map(Permalink::as_str),
            Some("https://grafana.example/alerting/grafana/def/view")
        );
    }

    #[test]
    fn the_silence_link_is_never_offered_as_the_place_to_look() {
        // Every alert in the fixture has one. Offering "silence this" as *the*
        // link invites silencing before reading, which is the opposite of what
        // a notice is for.
        for event in alerts(FIRING) {
            let Event::Alert { permalink, .. } = event else {
                panic!("an alert");
            };
            let link = permalink
                .as_ref()
                .map(Permalink::as_str)
                .unwrap_or_default();
            assert!(!link.contains("silence"), "{link}");
        }
    }

    #[test]
    fn a_notification_with_no_link_at_all_is_still_translated() {
        let bare = br#"{"version":"1","status":"firing","title":"something broke",
            "alerts":[{"status":"firing","labels":{"alertname":"X"},"annotations":{},
            "startsAt":"2026-10-07T09:15:00Z","fingerprint":"abc123"}]}"#;

        let events = alerts(bare);
        let Event::Alert { permalink, .. } = at(&events, 0) else {
            panic!("an alert");
        };

        assert!(permalink.is_none());
    }

    #[test]
    fn labels_and_severity_are_read_the_same_way_as_any_other_sender() {
        let events = alerts(FIRING);
        let Event::Alert {
            labels, severity, ..
        } = at(&events, 0)
        else {
            panic!("an alert");
        };

        assert_eq!(*severity, Severity::Critical);
        assert_eq!(label(labels, "namespace").as_deref(), Some("prod"));
        // Grafana adds its own, and it travels like any other label.
        assert_eq!(label(labels, "grafana_folder").as_deref(), Some("Platform"));
    }

    #[test]
    fn an_alert_with_no_severity_label_is_unstated() {
        let events = alerts(FIRING);
        let Event::Alert { severity, .. } = at(&events, 1) else {
            panic!("an alert");
        };

        assert_eq!(*severity, Severity::Unstated);
    }

    #[test]
    fn the_senders_start_time_is_carried_including_an_offset() {
        let events = alerts(FIRING);

        let Event::Alert { started, .. } = at(&events, 0) else {
            panic!("an alert");
        };
        assert_eq!(started.millis_since_epoch(), 1_791_364_500_000);

        let Event::Alert { started, .. } = at(&events, 2) else {
            panic!("an alert");
        };
        // 2026-10-06T22:00:00+02:00 is 20:00 UTC, not 22:00.
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
    fn markup_in_a_label_value_survives_as_text_too() {
        let payload = br#"{"version":"1","status":"firing","title":"t",
            "alerts":[{"status":"firing",
            "labels":{"alertname":"X","note":"<script>alert(1)</script>"},
            "annotations":{"summary":"fine"},
            "startsAt":"2026-10-07T09:15:00Z","fingerprint":"abc123"}]}"#;

        let events = alerts(payload);
        let Event::Alert { labels, .. } = at(&events, 0) else {
            panic!("an alert");
        };

        assert_eq!(
            label(labels, "note").as_deref(),
            Some("<script>alert(1)</script>")
        );
    }

    // ---- two senders are two Origins, not one lenient parser --------------

    #[test]
    fn an_alertmanager_notification_is_not_a_grafana_one() {
        // The outer shapes are nearly identical, which is exactly why this
        // matters: without the version check each parser would half-read the
        // other's payload and produce Events built from the wrong conventions.
        assert_eq!(translate(ALERTMANAGER), Err(Untranslatable));
    }

    #[test]
    fn a_grafana_notification_is_not_an_alertmanager_one() {
        // The reverse, asserted here rather than there because this is the bead
        // that introduced the second sender.
        use alertmanager_payload::AlertmanagerPayload;

        assert_eq!(
            AlertmanagerPayload.events(&verified(FIRING)),
            Err(Untranslatable)
        );
    }

    #[test]
    fn something_that_is_not_json_cannot_be_read_at_all() {
        assert_eq!(translate(b"{not json"), Err(Untranslatable));
    }

    #[test]
    fn json_of_the_wrong_shape_is_untranslatable_rather_than_half_mapped() {
        // No alerts array.
        assert_eq!(
            translate(br#"{"version":"1","status":"firing"}"#),
            Err(Untranslatable)
        );
        // No fingerprint: nothing a loss report could name it by.
        assert_eq!(
            translate(
                br#"{"version":"1","status":"firing","title":"t","alerts":[{
                    "status":"firing","labels":{"alertname":"X"},"annotations":{},
                    "startsAt":"2026-10-07T09:15:00Z"}]}"#
            ),
            Err(Untranslatable)
        );
        // A status neither sender uses.
        assert_eq!(
            translate(
                br#"{"version":"1","status":"firing","title":"t","alerts":[{
                    "status":"pending","labels":{"alertname":"X"},"annotations":{},
                    "startsAt":"2026-10-07T09:15:00Z","fingerprint":"abc"}]}"#
            ),
            Err(Untranslatable)
        );
        // A start time we cannot read.
        assert_eq!(
            translate(
                br#"{"version":"1","status":"firing","title":"t","alerts":[{
                    "status":"firing","labels":{"alertname":"X"},"annotations":{},
                    "startsAt":"last Tuesday","fingerprint":"abc"}]}"#
            ),
            Err(Untranslatable)
        );
    }

    #[test]
    fn a_field_we_do_not_know_is_ignored_so_a_newer_grafana_keeps_working() {
        let payload = br#"{"version":"1","status":"firing","title":"t","newThing":42,
            "alerts":[{"status":"firing","alsoNew":true,
            "labels":{"alertname":"X"},"annotations":{"summary":"fine"},
            "startsAt":"2026-10-07T09:15:00Z","fingerprint":"abc"}]}"#;

        assert_eq!(alerts(payload).len(), 1);
    }

    #[test]
    fn an_alert_with_nothing_to_say_falls_back_to_its_own_name() {
        let payload = br#"{"version":"1","status":"firing","alerts":[{
            "status":"firing","labels":{"alertname":"HighLatency"},"annotations":{},
            "startsAt":"2026-10-07T09:15:00Z","fingerprint":"abc"}]}"#;

        let events = alerts(payload);
        let Event::Alert { summary, .. } = at(&events, 0) else {
            panic!("an alert");
        };

        assert_eq!(summary.as_str(), "HighLatency");
    }
}
