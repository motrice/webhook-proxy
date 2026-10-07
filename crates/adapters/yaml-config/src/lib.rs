//! The routing file, read into the domain values it describes.
//!
//! The file is this product's interface to the Git-based operations
//! repository, so everything
//! a human gets wrong about this system, they will get wrong here. The error
//! messages are the feature: every one of them names the file and the path to
//! the field, and none of them ever prints a secret value.
//!
//! This crate owns the file format. The domain gains no serde and no notion that
//! a file exists; what comes out of here is `Origin`, `Destination` and
//! `Subscription`, plus the two lookup tables the outbound adapters need.
//!
//! Nothing is reloaded. A change to the file rolls the deployment, so the
//! start-up log always says what was actually loaded — see bead gc-ast.3.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};

use domain::{
    Destination, DestinationId, DestinationKind, Filter, LabelName, LabelValue, Labels, Origin,
    OriginId, SecretId, Subscription, Verification,
};
use serde::Deserialize;

/// The schema this crate reads.
const VERSION: u8 = 1;

/// What a secret's name may contain.
///
/// A name is used to build a path, and it comes from a file that more people can
/// edit than can read the Secret it names. Without this, a name that walked up
/// the tree would read something it was never meant to.
fn is_nameable(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// Everything the composition root needs in order to start.
#[derive(Clone)]
pub struct Configuration {
    origins: HashMap<String, Origin>,
    subscriptions: Vec<Subscription>,
    secrets: HashMap<String, String>,
    webhooks: HashMap<String, String>,
}

/// Counts, never contents.
///
/// Written by hand rather than derived, and the derive is the reason: this type
/// holds every secret value the deployment uses, so a derived `Debug` would put
/// all of them into whatever log line touched it — and a start-up log line is the
/// single most likely thing to be pasted into a chat window.
impl fmt::Debug for Configuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Configuration({} origins, {} destinations, {} rules, {} secrets loaded)",
            self.origins.len(),
            self.webhooks.len(),
            self.subscriptions.len(),
            self.secrets.len()
        )
    }
}

/// Why the file cannot be used.
///
/// Every variant carries the file it came from and the path to the field at
/// fault, because a startup failure is the whole operator experience of a bad
/// deploy. None of them carries a value: the one thing a secret must never do is
/// appear in a log line somebody pastes into a chat window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unusable {
    file: PathBuf,
    path: String,
    why: String,
}

impl Unusable {
    fn at(file: &Path, path: impl Into<String>, why: impl Into<String>) -> Self {
        Self {
            file: file.to_path_buf(),
            path: path.into(),
            why: why.into(),
        }
    }

    /// Which field, as a path into the file.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
}

impl fmt::Display for Unusable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}: {}", self.file.display(), self.path, self.why)
    }
}

impl std::error::Error for Unusable {}

// ---- what the file looks like -------------------------------------------
//
// These types exist only to be deserialised. `deny_unknown_fields` everywhere:
// a mistyped key in a routing rule that silently matches nothing is the worst
// failure this file can have, because the symptom is a quiet room and nobody
// notices quiet.

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u8,
    origins: Vec<OriginEntry>,
    destinations: Vec<DestinationEntry>,
    subscriptions: Vec<SubscriptionEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginEntry {
    id: String,
    /// A map of exactly one entry, not an enum.
    ///
    /// serde reads an externally tagged enum from a YAML *tag* — `!hmac_sha256`
    /// — rather than from the nested map the published example uses. The file
    /// shape is the one gc-ast.3 settled and a human reviews, so the parser bends
    /// rather than the file. Reading it as a map also means "declares no
    /// mechanism" and "declares two" become errors this crate phrases, instead of
    /// serde's wording for a shape it did not expect.
    verify: BTreeMap<String, MechanismEntry>,
}

/// The one field every mechanism has.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MechanismEntry {
    secret: String,
}

/// The mechanisms this build knows, spelled as the file spells them.
const SIGNED: &str = "hmac_sha256";
const SHARED: &str = "bearer";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DestinationEntry {
    id: String,
    kind: KindEntry,
    webhook: WebhookEntry,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
enum KindEntry {
    ChatRoom,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WebhookEntry {
    secret: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubscriptionEntry {
    destination: String,
    #[serde(default)]
    r#match: Option<BTreeMap<String, String>>,
    #[serde(default)]
    everything: Option<bool>,
}

impl Configuration {
    /// Reads the file, and the secrets it names, or says exactly what is wrong.
    ///
    /// # Errors
    ///
    /// [`Unusable`] for anything that would make the deployment behave
    /// differently from what the file appears to say — a field that cannot be
    /// read, a rule naming a Destination nobody declared, a secret with no value
    /// behind it. Every one names the file and the path.
    pub fn read(file: &Path, secrets: &Path) -> Result<Self, Unusable> {
        let text = std::fs::read_to_string(file)
            .map_err(|e| Unusable::at(file, "", format!("cannot be read: {e}")))?;

        let document: Document = serde_yaml_ng::from_str(&text)
            .map_err(|e| Unusable::at(file, "", format!("cannot be parsed: {e}")))?;

        if document.version != VERSION {
            return Err(Unusable::at(
                file,
                "version",
                format!("is {}, and this build reads {VERSION}", document.version),
            ));
        }

        let mut config = Self {
            origins: HashMap::new(),
            subscriptions: Vec::new(),
            secrets: HashMap::new(),
            webhooks: HashMap::new(),
        };

        config.read_origins(file, secrets, &document.origins)?;
        let declared = config.read_destinations(file, secrets, &document.destinations)?;
        config.read_subscriptions(file, &declared, &document.subscriptions)?;

        Ok(config)
    }

    fn read_origins(
        &mut self,
        file: &Path,
        secrets: &Path,
        entries: &[OriginEntry],
    ) -> Result<(), Unusable> {
        for (index, entry) in entries.iter().enumerate() {
            let at = |field: &str| format!("origins[{index}].{field}");

            let id = OriginId::new(&entry.id)
                .map_err(|blank| Unusable::at(file, at("id"), blank.to_string()))?;

            if self.origins.contains_key(id.as_str()) {
                return Err(Unusable::at(
                    file,
                    at("id"),
                    "is declared twice; an Origin's identity decides which secret \
                     checks it, so two would be ambiguous",
                ));
            }

            // Exactly one, so that an Origin declaring none and an Origin
            // declaring two are each refused with a sentence that says which.
            let mut declared = entry.verify.iter();
            let (mechanism, holder) = declared.next().ok_or_else(|| {
                Unusable::at(
                    file,
                    at("verify"),
                    format!(
                        "declares no mechanism; write {SIGNED} for a sender that \
                         signs the body, or {SHARED} for one that presents a shared \
                         value"
                    ),
                )
            })?;
            if declared.next().is_some() {
                return Err(Unusable::at(
                    file,
                    at("verify"),
                    "declares more than one mechanism; an Origin proves itself one \
                     way, and the mechanism is never chosen by the request",
                ));
            }

            let secret = self.read_secret(file, secrets, &at("verify"), &holder.secret)?;
            let verify = match mechanism.as_str() {
                SIGNED => Verification::Signed { secret },
                SHARED => Verification::Shared { secret },
                other => {
                    return Err(Unusable::at(
                        file,
                        at("verify"),
                        format!(
                            "names {other:?}, which this build does not know; \
                                 it reads {SIGNED} and {SHARED}"
                        ),
                    ));
                }
            };

            self.origins
                .insert(entry.id.trim().to_owned(), Origin::new(id, verify));
        }
        Ok(())
    }

    fn read_destinations(
        &mut self,
        file: &Path,
        secrets: &Path,
        entries: &[DestinationEntry],
    ) -> Result<HashMap<String, Destination>, Unusable> {
        let mut declared = HashMap::new();

        for (index, entry) in entries.iter().enumerate() {
            let at = |field: &str| format!("destinations[{index}].{field}");

            let id = DestinationId::new(&entry.id)
                .map_err(|blank| Unusable::at(file, at("id"), blank.to_string()))?;

            if declared.contains_key(id.as_str()) {
                return Err(Unusable::at(
                    file,
                    at("id"),
                    "is declared twice; a rule naming it could mean either",
                ));
            }

            let secret = self.read_secret(file, secrets, &at("webhook"), &entry.webhook.secret)?;
            // The address never enters the domain: a Destination is an identity
            // and a kind, and this table is what the outbound adapter reaches
            // for. Looked up by the secret's name so the value is held once.
            let address = self
                .secrets
                .get(secret.as_str())
                .expect("just read")
                .clone();
            self.webhooks.insert(entry.id.trim().to_owned(), address);

            let kind = match entry.kind {
                KindEntry::ChatRoom => DestinationKind::ChatRoom,
            };
            declared.insert(entry.id.trim().to_owned(), Destination::new(id, kind));
        }

        Ok(declared)
    }

    fn read_subscriptions(
        &mut self,
        file: &Path,
        declared: &HashMap<String, Destination>,
        entries: &[SubscriptionEntry],
    ) -> Result<(), Unusable> {
        if entries.is_empty() {
            return Err(Unusable::at(
                file,
                "subscriptions",
                "is empty; a proxy with no rules verifies every delivery and then \
                 drops it, reporting healthy while doing nothing",
            ));
        }

        for (index, entry) in entries.iter().enumerate() {
            let at = |field: &str| format!("subscriptions[{index}].{field}");

            let destination = declared.get(entry.destination.trim()).ok_or_else(|| {
                Unusable::at(
                    file,
                    at("destination"),
                    format!(
                        "names {:?}, which no destinations entry declares",
                        entry.destination
                    ),
                )
            })?;

            let filter = match (&entry.r#match, entry.everything) {
                (Some(_), Some(_)) => {
                    return Err(Unusable::at(
                        file,
                        format!("subscriptions[{index}]"),
                        "has both match and everything; a rule says one or the other",
                    ));
                }
                (None, None) => {
                    return Err(Unusable::at(
                        file,
                        format!("subscriptions[{index}]"),
                        "has neither match nor everything, so it selects nothing and \
                         the room it names would stay silent",
                    ));
                }
                (None, Some(true)) => Filter::Everything,
                (None, Some(false)) => {
                    return Err(Unusable::at(
                        file,
                        at("everything"),
                        "is false, which is a rule that means nothing; remove it or \
                         write the match it should have",
                    ));
                }
                (Some(required), None) => {
                    if required.is_empty() {
                        return Err(Unusable::at(
                            file,
                            at("match"),
                            "is empty. An empty match would admit everything, which \
                             a templating accident can produce and a reviewer will \
                             read as a formatting change. Write everything: true if \
                             that is what is meant",
                        ));
                    }
                    Filter::Labelled(labels_of(file, &at("match"), required)?)
                }
            };

            self.subscriptions
                .push(Subscription::new(destination.clone(), filter));
        }

        Ok(())
    }

    /// Reads one named secret, recording its value against its name.
    fn read_secret(
        &mut self,
        file: &Path,
        secrets: &Path,
        at: &str,
        named: &str,
    ) -> Result<SecretId, Unusable> {
        let id = SecretId::new(named)
            .map_err(|blank| Unusable::at(file, format!("{at}.secret"), blank.to_string()))?;

        if !is_nameable(id.as_str()) {
            return Err(Unusable::at(
                file,
                format!("{at}.secret"),
                format!(
                    "names {:?}, which is not a usable file name. A secret name may \
                     hold letters, digits, underscore, dot and hyphen only — it \
                     becomes a path, and this file is editable by more people than \
                     the secrets it names",
                    id.as_str()
                ),
            ));
        }

        if !self.secrets.contains_key(id.as_str()) {
            let path = secrets.join(id.as_str());
            let value = std::fs::read_to_string(&path).map_err(|_| {
                Unusable::at(
                    file,
                    format!("{at}.secret"),
                    format!(
                        "names {:?}, and no secret of that name is in {}",
                        id.as_str(),
                        secrets.display()
                    ),
                )
            })?;

            // Trailing whitespace is an editor's doing, not the secret's. A
            // blank one is a configuration mistake and is refused here rather
            // than failing every request later.
            let value = value.trim_end_matches(['\n', '\r']).to_owned();
            if value.trim().is_empty() {
                return Err(Unusable::at(
                    file,
                    format!("{at}.secret"),
                    format!("names {:?}, whose secret is empty", id.as_str()),
                ));
            }

            self.secrets.insert(id.as_str().to_owned(), value);
        }

        Ok(id)
    }

    /// Every Origin, by the identity a request names.
    #[must_use]
    pub fn origins(&self) -> &HashMap<String, Origin> {
        &self.origins
    }

    /// Every rule, in the order the file gave them.
    #[must_use]
    pub fn subscriptions(&self) -> &[Subscription] {
        &self.subscriptions
    }

    /// Every secret value, by the name the file used.
    #[must_use]
    pub fn secrets(&self) -> &HashMap<String, String> {
        &self.secrets
    }

    /// Where each Destination is reached, by its identity.
    #[must_use]
    pub fn webhooks(&self) -> &HashMap<String, String> {
        &self.webhooks
    }
}

/// The labels a rule requires.
fn labels_of(
    file: &Path,
    at: &str,
    required: &BTreeMap<String, String>,
) -> Result<Labels, Unusable> {
    required
        .iter()
        .try_fold(Labels::none(), |labels, (name, value)| {
            let name = LabelName::new(name)
                .map_err(|blank| Unusable::at(file, format!("{at}.{name}"), blank.to_string()))?;
            let value = LabelValue::new(value).map_err(|blank| {
                Unusable::at(file, format!("{at}.{}", name.as_str()), blank.to_string())
            })?;
            Ok(labels.with(name, value))
        })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use domain::{
        BranchName, Event, LabelName, LabelValue, Labels, OriginId, Pusher, RepositoryName,
        Verification, destinations_for,
    };

    use super::Configuration;

    /// The published example, parsed by the thing that has to read it.
    ///
    /// Deliberately the real file and not a copy: nothing else parses it, so a
    /// structural mistake in it would sit undetected until a deploy. Using it
    /// here makes the example and this parser incapable of drifting apart.
    const EXAMPLE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../deploy/config.example.yaml"
    );

    /// Every secret the example names, with values that are obviously not real.
    fn secrets_for_the_example(dir: &Path) {
        for name in [
            "github-webhook-secret",
            "alertmanager-token",
            "devsecops-room-url",
            "platform-room-url",
            "audit-room-url",
        ] {
            fs::write(dir.join(name), format!("not-a-real-value-for-{name}\n"))
                .expect("a writable temporary directory");
        }
    }

    fn written(dir: &Path, yaml: &str) -> PathBuf {
        let path = dir.join("config.yaml");
        fs::write(&path, yaml).expect("a writable temporary directory");
        path
    }

    /// A minimal file that parses, so each test can break one thing.
    fn sound() -> String {
        "
version: 1
origins:
  - id: a-forge
    verify:
      hmac_sha256:
        secret: a-secret
destinations:
  - id: a-room
    kind: chat_room
    webhook:
      secret: a-url
subscriptions:
  - destination: a-room
    match:
      origin: a-forge
"
        .to_owned()
    }

    fn sound_secrets(dir: &Path) {
        fs::write(dir.join("a-secret"), "shhh").expect("writable");
        fs::write(
            dir.join("a-url"),
            "https://rooms.example/hook/SUPERSECRETHOOKID",
        )
        .expect("writable");
    }

    fn push_to(repository: &str, branch: &str) -> Event {
        Event::PushedCommits {
            repository: RepositoryName::new(repository).expect("a name"),
            branch: BranchName::new(branch).expect("a name"),
            pusher: Pusher::new("bjorn").expect("a name"),
            commits: vec![],
            permalink: None,
        }
    }

    fn alert_labelled(pairs: &[(&str, &str)]) -> Event {
        Event::Alert {
            id: domain::AlertId::new("abc").expect("an identity"),
            severity: domain::Severity::Unstated,
            status: domain::AlertStatus::Firing,
            summary: domain::Summary::new("something").expect("a summary"),
            labels: pairs.iter().fold(Labels::none(), |set, (n, v)| {
                set.with(
                    LabelName::new(n).expect("a name"),
                    LabelValue::new(v).expect("a value"),
                )
            }),
            started: domain::Timestamp::from_millis_since_epoch(0),
            permalink: None,
        }
    }

    fn reached(config: &Configuration, origin: &str, event: &Event) -> Vec<String> {
        destinations_for(
            &OriginId::new(origin).expect("an identity"),
            event,
            config.subscriptions(),
        )
        .into_iter()
        .map(|d| d.id().as_str().to_owned())
        .collect()
    }

    // ---- the published example ------------------------------------------

    #[test]
    fn the_published_example_produces_the_routing_it_describes() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        secrets_for_the_example(dir.path());

        let config = Configuration::read(Path::new(EXAMPLE), dir.path())
            .unwrap_or_else(|e| panic!("the published example must parse: {e}"));

        assert_eq!(config.origins().len(), 2);
        assert_eq!(config.webhooks().len(), 3);
        assert_eq!(config.subscriptions().len(), 4);

        // Parsing is not the point; this is. A push to main of that repository,
        // from the forge, reaches the room watching it and the room watching
        // everything — and nothing else.
        assert_eq!(
            reached(&config, "github", &push_to("motrice/webhook-proxy", "main")),
            vec!["devsecops-room", "audit-room"]
        );

        // A push to another branch is not that rule's business.
        assert_eq!(
            reached(
                &config,
                "github",
                &push_to("motrice/webhook-proxy", "topic")
            ),
            vec!["audit-room"]
        );

        // A critical alert reaches the same room by a different rule, which is
        // the point of one mechanism serving both senders.
        assert_eq!(
            reached(
                &config,
                "alertmanager",
                &alert_labelled(&[("severity", "critical")])
            ),
            vec!["devsecops-room", "audit-room"]
        );

        // And one team's namespace reaches that team.
        assert_eq!(
            reached(
                &config,
                "alertmanager",
                &alert_labelled(&[("namespace", "platform")])
            ),
            vec!["platform-room", "audit-room"]
        );

        // A sender cannot reach a room by claiming to be the other Origin: the
        // origin label comes from the delivery, not from the payload.
        assert_eq!(
            reached(
                &config,
                "somebody-else",
                &alert_labelled(&[("severity", "critical")])
            ),
            vec!["audit-room"]
        );
    }

    #[test]
    fn the_example_declares_both_mechanisms_and_neither_is_a_default() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        secrets_for_the_example(dir.path());
        let config = Configuration::read(Path::new(EXAMPLE), dir.path()).expect("it parses");

        assert!(matches!(
            config.origins()["github"].verify(),
            Verification::Signed { .. }
        ));
        assert!(matches!(
            config.origins()["alertmanager"].verify(),
            Verification::Shared { .. }
        ));
    }

    #[test]
    fn no_secret_value_appears_in_the_configuration_debug_output() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        sound_secrets(dir.path());
        let file = written(dir.path(), &sound());
        let config = Configuration::read(&file, dir.path()).expect("it parses");

        // The values are held — that is the point of reading them — so this pins
        // the one thing that must never happen: them reaching a log line.
        let printed = format!("{config:?}");
        assert!(!printed.contains("SUPERSECRETHOOKID"), "{printed}");
        assert!(!printed.contains("shhh"), "{printed}");
    }

    // ---- what a human will get wrong -------------------------------------

    fn refused(yaml: &str) -> super::Unusable {
        let dir = tempfile::tempdir().expect("a temporary directory");
        sound_secrets(dir.path());
        let file = written(dir.path(), yaml);
        Configuration::read(&file, dir.path()).expect_err("this file must be refused")
    }

    #[test]
    fn every_refusal_names_the_file_and_the_path_to_the_field() {
        // The whole operator experience of a bad deploy is this one line.
        let bad = sound().replace("destination: a-room", "destination: no-such-room");
        let e = refused(&bad);

        let message = e.to_string();
        assert!(message.contains("config.yaml"), "{message}");
        assert!(
            message.contains("subscriptions[0].destination"),
            "{message}"
        );
        assert_eq!(e.path(), "subscriptions[0].destination");
    }

    #[test]
    fn a_rule_naming_a_destination_nobody_declared_is_refused() {
        let bad = sound().replace("destination: a-room", "destination: no-such-room");
        let e = refused(&bad);

        assert_eq!(e.path(), "subscriptions[0].destination");
        assert!(e.to_string().contains("no-such-room"), "{e}");
    }

    #[test]
    fn a_field_nobody_knows_is_refused_and_named() {
        let bad = sound().replace("  - id: a-room", "  - id: a-room\n    colour: blue");
        let e = refused(&bad);

        // serde names the field; this crate names the file.
        assert!(e.to_string().contains("colour"), "{e}");
        assert!(e.to_string().contains("config.yaml"), "{e}");
    }

    #[test]
    fn a_blank_required_value_is_refused_and_named() {
        let bad = sound().replace("  - id: a-forge", r#"  - id: "   ""#);
        let e = refused(&bad);

        assert_eq!(e.path(), "origins[0].id");
    }

    #[test]
    fn an_origin_declaring_no_mechanism_is_refused() {
        let bad = sound().replace(
            "    verify:\n      hmac_sha256:\n        secret: a-secret",
            "    verify: {}",
        );
        let e = refused(&bad);

        assert!(e.to_string().contains("config.yaml"), "{e}");
    }

    #[test]
    fn a_secret_with_no_value_behind_it_is_refused_by_name_and_never_by_value() {
        let bad = sound().replace("secret: a-secret", "secret: not-deployed");
        let e = refused(&bad);

        assert_eq!(e.path(), "origins[0].verify.secret");
        assert!(e.to_string().contains("not-deployed"), "{e}");
        // The directory is named so an operator can look; no value is.
        assert!(!e.to_string().contains("shhh"), "{e}");
    }

    #[test]
    fn a_secret_name_that_is_a_path_is_refused_before_it_is_opened() {
        let bad = sound().replace("secret: a-secret", "secret: ../../../etc/passwd");
        let e = refused(&bad);

        assert_eq!(e.path(), "origins[0].verify.secret");
        assert!(e.to_string().contains("not a usable file name"), "{e}");
    }

    #[test]
    fn a_file_with_no_rules_is_refused_rather_than_starting_silent() {
        let bad = sound().replace(
            "subscriptions:\n  - destination: a-room\n    match:\n      origin: a-forge",
            "subscriptions: []",
        );
        let e = refused(&bad);

        assert_eq!(e.path(), "subscriptions");
        assert!(e.to_string().contains("reporting healthy"), "{e}");
    }

    #[test]
    fn two_origins_with_one_identity_are_refused() {
        let bad = sound().replace(
            "destinations:",
            "  - id: a-forge\n    verify:\n      bearer:\n        secret: a-secret\ndestinations:",
        );
        let e = refused(&bad);

        assert_eq!(e.path(), "origins[1].id");
        assert!(e.to_string().contains("declared twice"), "{e}");
    }

    #[test]
    fn two_destinations_with_one_identity_are_refused() {
        let bad = sound().replace(
            "subscriptions:",
            "  - id: a-room\n    kind: chat_room\n    webhook:\n      secret: a-url\nsubscriptions:",
        );
        let e = refused(&bad);

        assert_eq!(e.path(), "destinations[1].id");
    }

    #[test]
    fn an_empty_match_is_refused_and_says_what_to_write_instead() {
        let bad = sound().replace("    match:\n      origin: a-forge", "    match: {}");
        let e = refused(&bad);

        assert_eq!(e.path(), "subscriptions[0].match");
        assert!(e.to_string().contains("everything: true"), "{e}");
    }

    #[test]
    fn a_rule_with_both_match_and_everything_is_refused() {
        let bad = sound().replace(
            "    match:\n      origin: a-forge",
            "    everything: true\n    match:\n      origin: a-forge",
        );
        let e = refused(&bad);

        assert_eq!(e.path(), "subscriptions[0]");
    }

    #[test]
    fn a_rule_with_neither_match_nor_everything_is_refused() {
        let bad = sound().replace("    match:\n      origin: a-forge", "");
        let e = refused(&bad);

        assert_eq!(e.path(), "subscriptions[0]");
        assert!(e.to_string().contains("stay silent"), "{e}");
    }

    #[test]
    fn a_version_this_build_does_not_read_is_refused() {
        let bad = sound().replace("version: 1", "version: 2");
        let e = refused(&bad);

        assert_eq!(e.path(), "version");
    }

    #[test]
    fn a_file_that_is_not_there_says_so_rather_than_starting_without_rules() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let e = Configuration::read(&dir.path().join("absent.yaml"), dir.path())
            .expect_err("an absent file is refused");

        assert!(e.to_string().contains("absent.yaml"), "{e}");
        assert!(e.to_string().contains("cannot be read"), "{e}");
    }
}
