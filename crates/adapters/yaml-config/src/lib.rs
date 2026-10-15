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
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use application::ports::TenantId;
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

/// Which vocabulary a sender speaks, so the composition root can pick the
/// translation.
///
/// Deliberately separate from the verification mechanism: how a sender proves
/// itself and what shape it sends are independent facts, and conflating them
/// would mean a sender that signed an Alertmanager notification was
/// untranslatable with nothing in the file saying why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Speaks {
    /// A forge push payload.
    Github,
    /// A monitoring notification.
    Alertmanager,
    /// A unified-alerting notification. Resembles the above and is not it.
    Grafana,
}

/// An Origin as the file declares it, with the vocabulary it speaks.
#[derive(Debug, Clone)]
pub struct Declared {
    /// Who it is and what it must prove.
    pub origin: Origin,
    /// What shape it sends.
    pub speaks: Speaks,
    /// Whose alerts these are.
    ///
    /// HERE RATHER THAN ON `Origin`, which is a domain value and gains nothing
    /// (bead gc-g9x). The tenant is read from this file, so a reviewer can see
    /// in a diff who an incoming alert will be filed under — and because it is
    /// read from the registration rather than from the request, the Origin's
    /// own secret is what proves it. A caller cannot assert it (bead gc-nkb).
    pub tenant: TenantId,
}

/// Everything the composition root needs in order to start.
#[derive(Clone)]
pub struct Configuration {
    /// The rooms, their rules and the secret values behind both. Shared with a
    /// tenant's configuration because it is the same reading.
    rooms: Rooms,
    /// Every tenant this deployment serves, as the file lists them.
    ///
    /// LISTED, NEVER INFERRED from the Origins that mention them (bead gc-nkb).
    /// Inferring would make a typo in one Origin create a tenant silently, and
    /// the symptom would be an alert filed under a tenant nobody has an agent
    /// for — stored, offered to nobody, and eventually swept.
    tenants: BTreeSet<TenantId>,
    origins: HashMap<String, Declared>,
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
            "Configuration({} tenants, {} origins, {} destinations, {} rules, {} secrets loaded)",
            self.tenants.len(),
            self.origins.len(),
            self.rooms.webhooks.len(),
            self.rooms.subscriptions.len(),
            self.rooms.secrets.len()
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
    tenants: Vec<String>,
    origins: Vec<OriginEntry>,
    destinations: Vec<DestinationEntry>,
    subscriptions: Vec<SubscriptionEntry>,
}

/// The tenant's half of the file, which is a different document.
///
/// Two documents rather than one with optional halves, and the omissions are
/// the whole point (bead gc-g9x): NEITHER HALF CAN NAME THE OTHER'S SECRETS,
/// which is the property that makes the split worth having. A single document
/// with everything optional would let a tenant's file hold a sender's verify
/// secret and a platform's file hold a room URL, and nothing would say so.
///
/// The four fields below exist only to be refused. `deny_unknown_fields`
/// already makes a mistyped key an error, but these are not typos — they are
/// the keys somebody copies across from the platform's file by habit, and each
/// deserves a sentence saying why a tenant does not have one.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantDocument {
    version: u8,
    destinations: Vec<DestinationEntry>,
    subscriptions: Vec<SubscriptionEntry>,

    #[serde(default)]
    origins: Option<serde_yaml_ng::Value>,
    #[serde(default)]
    tenants: Option<serde_yaml_ng::Value>,
    #[serde(default)]
    tenant: Option<serde_yaml_ng::Value>,
    #[serde(default)]
    verify: Option<serde_yaml_ng::Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginEntry {
    id: String,
    /// Which tenant this sender's alerts belong to. One Origin serves one
    /// tenant (bead gc-nkb), so this is a field and not a list.
    tenant: String,
    speaks: SpeaksEntry,
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

/// Which vocabulary a sender speaks.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
enum SpeaksEntry {
    Github,
    Alertmanager,
    Grafana,
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

/// The rooms half of either file: where each room is reached, which rules select
/// it, and the secret values behind both.
///
/// Shared by the platform's configuration and a tenant's, because it is
/// literally the same reading — and because the secret-name validation below is
/// the kind of rule that must exist once. Two copies of it would be two places
/// for a name that walks up the directory tree to stop being refused.
#[derive(Clone, Default)]
struct Rooms {
    subscriptions: Vec<Subscription>,
    secrets: HashMap<String, String>,
    webhooks: HashMap<String, String>,
}

impl Rooms {
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
            rooms: Rooms::default(),
            tenants: BTreeSet::new(),
            origins: HashMap::new(),
        };

        // Before the Origins, because an Origin is checked against this list.
        config.read_tenants(file, &document.tenants)?;
        config.read_origins(file, secrets, &document.origins)?;
        let declared = config
            .rooms
            .read_destinations(file, secrets, &document.destinations)?;
        config
            .rooms
            .read_subscriptions(file, &declared, &document.subscriptions)?;

        Ok(config)
    }

    /// The tenants this deployment serves.
    ///
    /// An empty list is refused. A platform serving nobody is a file somebody
    /// is halfway through writing, and every Origin below would fail anyway —
    /// with a message about the Origin rather than about the omission.
    fn read_tenants(&mut self, file: &Path, entries: &[String]) -> Result<(), Unusable> {
        if entries.is_empty() {
            return Err(Unusable::at(
                file,
                "tenants",
                "lists none; every Origin must name a tenant, so a deployment \
                 with no tenants can serve no sender",
            ));
        }

        for (index, entry) in entries.iter().enumerate() {
            let tenant = TenantId::new(entry)
                .map_err(|why| Unusable::at(file, format!("tenants[{index}]"), why.to_string()))?;
            if !self.tenants.insert(tenant) {
                return Err(Unusable::at(
                    file,
                    format!("tenants[{index}]"),
                    "is listed twice; a tenant is a namespace and there is only \
                     one of each",
                ));
            }
        }

        Ok(())
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

            let secret = self
                .rooms
                .read_secret(file, secrets, &at("verify"), &holder.secret)?;
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

            let speaks = match entry.speaks {
                SpeaksEntry::Github => Speaks::Github,
                SpeaksEntry::Alertmanager => Speaks::Alertmanager,
                SpeaksEntry::Grafana => Speaks::Grafana,
            };

            // A STARTUP ERROR, not a request-time refusal, and bead gc-nkb says
            // why: `webhook-proxy check` runs on every change to this file in
            // the operations repository, so a tenant that does not exist is
            // caught before anything deploys and request handling never meets
            // one. The alternative — accepting it and finding out later — makes
            // a mistake in the platform's own configuration look like a sender
            // problem, and the alert is already lost by then.
            let tenant = TenantId::new(&entry.tenant)
                .map_err(|why| Unusable::at(file, at("tenant"), why.to_string()))?;
            if !self.tenants.contains(&tenant) {
                let listed: Vec<&str> = self.tenants.iter().map(TenantId::as_str).collect();
                return Err(Unusable::at(
                    file,
                    at("tenant"),
                    format!(
                        "names {tenant:?}, which `tenants` does not list. \
                         Listed: {}. A tenant is listed rather than created by \
                         being mentioned, so that a typo here is this message \
                         rather than an alert filed under a tenant nobody has \
                         an agent for",
                        listed.join(", ")
                    ),
                ));
            }

            self.origins.insert(
                entry.id.trim().to_owned(),
                Declared {
                    origin: Origin::new(id, verify),
                    speaks,
                    tenant,
                },
            );
        }
        Ok(())
    }

    /// The routing this file actually produces, for a person to read.
    ///
    /// The honest substitute for a validation that cannot exist. gc-ast.1 wanted
    /// configuration to reject a matcher name no Event could ever offer, but an
    /// alert carries whatever the sender attached, so `namespace` cannot be
    /// validated against anything and rejecting it would make the file unable to
    /// express the main thing it is for.
    ///
    /// So instead of guessing at intent, this shows the consequence. A typo
    /// appears as a room with no rules, or as a rule every one of whose names
    /// only a sender can supply — both obvious to someone reading a pull
    /// request, neither expressible as a rule that could refuse the file.
    ///
    /// No secret value appears, only how many were found.
    #[must_use]
    pub fn routing_table(&self) -> String {
        let mut out = String::new();

        out.push_str("tenants  (* marks one no sender files alerts for)\n");
        for tenant in &self.tenants {
            let named = self
                .origins
                .values()
                .any(|declared| &declared.tenant == tenant);
            // The same honest-consequence reporting the rooms block below does.
            // A tenant nothing names is not an error — a team may be listed
            // before its first sender is registered — but it is worth seeing,
            // because the other way to arrive at it is a `tenants` entry
            // somebody added and then misspelled under an Origin.
            let _ = writeln!(out, "  {tenant}{}", if named { "" } else { "  *" });
        }

        out.push_str("\nsenders\n");
        let mut senders: Vec<_> = self.origins.iter().collect();
        senders.sort_by_key(|(path, _)| path.as_str());
        for (path, declared) in senders {
            let how = match declared.origin.verify() {
                Verification::Signed { .. } => "signs its body",
                Verification::Shared { .. } => "presents a shared value",
            };
            let speaks = match declared.speaks {
                Speaks::Github => "github",
                Speaks::Alertmanager => "alertmanager",
                Speaks::Grafana => "grafana",
            };
            let _ = writeln!(
                out,
                "  /webhook/{path}  {how}, speaks {speaks}, for tenant {}",
                declared.tenant
            );
        }

        out.push_str("\nrooms  (* marks a label only a sender can supply)\n");
        let mut rooms: Vec<&String> = self.rooms.webhooks.keys().collect();
        rooms.sort();
        for room in rooms {
            let _ = writeln!(out, "  {room}");
            let mut selected = 0usize;
            for subscription in &self.rooms.subscriptions {
                if subscription.destination().id().as_str() != room {
                    continue;
                }
                selected += 1;
                let _ = writeln!(out, "    - {}", describe(subscription.filter()));
            }
            if selected == 0 {
                // The failure this exists to make visible.
                out.push_str("    (nothing selects this room)\n");
            }
        }

        let _ = writeln!(
            out,
            "\n{} tenant(s), {} sender(s), {} room(s), {} rule(s), {} secret(s) present",
            self.tenants.len(),
            self.origins.len(),
            self.rooms.webhooks.len(),
            self.rooms.subscriptions.len(),
            self.rooms.secrets.len()
        );

        out
    }

    /// Every tenant this deployment serves.
    #[must_use]
    pub fn tenants(&self) -> &BTreeSet<TenantId> {
        &self.tenants
    }

    /// Every Origin, by the identity a request names.
    #[must_use]
    pub fn origins(&self) -> &HashMap<String, Declared> {
        &self.origins
    }

    /// Every rule, in the order the file gave them.
    #[must_use]
    pub fn subscriptions(&self) -> &[Subscription] {
        &self.rooms.subscriptions
    }

    /// Every secret value, by the name the file used.
    #[must_use]
    pub fn secrets(&self) -> &HashMap<String, String> {
        &self.rooms.secrets
    }

    /// Where each Destination is reached, by its identity.
    #[must_use]
    pub fn webhooks(&self) -> &HashMap<String, String> {
        &self.rooms.webhooks
    }
}

/// Everything a tenant's agent needs in order to deliver.
///
/// Its rooms and its rules, and nothing else. No Origin, because the platform
/// authenticates senders and a tenant holds no sender's secret. No tenant name
/// either, and that absence is bead gc-nkb's: the agent does not determine its
/// own tenant — the platform derives it from the Origin at acceptance and from
/// the caller's mTLS identity at claim time — so a tenant name here would be a
/// value nothing checks against anything.
#[derive(Clone)]
pub struct TenantConfiguration {
    rooms: Rooms,
}

/// Counts, never contents, for the reason [`Configuration`] gives: this holds
/// every room URL the agent uses, and a room URL is itself a credential.
impl fmt::Debug for TenantConfiguration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TenantConfiguration({} rooms, {} rules, {} secrets loaded)",
            self.rooms.webhooks.len(),
            self.rooms.subscriptions.len(),
            self.rooms.secrets.len()
        )
    }
}

impl TenantConfiguration {
    /// Reads the file, and the room URLs it names, or says exactly what is
    /// wrong.
    ///
    /// # Errors
    ///
    /// [`Unusable`] for anything that would make the agent behave differently
    /// from what the file appears to say, and for any of the four keys that
    /// belong to the platform's half rather than this one. Every one names the
    /// file and the path.
    pub fn read(file: &Path, secrets: &Path) -> Result<Self, Unusable> {
        let text = std::fs::read_to_string(file)
            .map_err(|e| Unusable::at(file, "", format!("cannot be read: {e}")))?;

        let document: TenantDocument = serde_yaml_ng::from_str(&text)
            .map_err(|e| Unusable::at(file, "", format!("cannot be parsed: {e}")))?;

        if document.version != VERSION {
            return Err(Unusable::at(
                file,
                "version",
                format!("is {}, and this build reads {VERSION}", document.version),
            ));
        }

        // Refused with a reason rather than ignored. Each of these is a key a
        // reader would reasonably expect to work, having seen the platform's
        // file, and each means something different is wrong.
        for (present, field, why) in [
            (
                document.origins.is_some(),
                "origins",
                "belongs to the platform's configuration, not a tenant's: the \
                 platform authenticates senders, and an agent holds no sender's \
                 secret and could not check one",
            ),
            (
                document.verify.is_some(),
                "verify",
                "belongs to an Origin, and a tenant declares none. Nothing here \
                 verifies a sender; what reaches this agent has already been \
                 verified by the platform",
            ),
            (
                document.tenants.is_some(),
                "tenants",
                "belongs to the platform's configuration: which tenants exist is \
                 the platform's to list, and an agent serves exactly one",
            ),
            (
                document.tenant.is_some(),
                "tenant",
                "is not an agent's to state. The platform derives the tenant from \
                 the Origin's registration and from the caller's identity, so a \
                 name written here would be checked against nothing — see bead \
                 gc-nkb",
            ),
        ] {
            if present {
                return Err(Unusable::at(file, field, why));
            }
        }

        let mut config = Self {
            rooms: Rooms::default(),
        };

        // The same two readers the platform uses, on the same entry types. A
        // second implementation would be a second place for the secret-name
        // validation to drift, which is what that validation exists to stop.
        let declared = config
            .rooms
            .read_destinations(file, secrets, &document.destinations)?;
        config
            .rooms
            .read_subscriptions(file, &declared, &document.subscriptions)?;

        Ok(config)
    }

    /// The routing this file actually produces, for a person to read.
    ///
    /// The same honest-consequence reporting [`Configuration::routing_table`]
    /// does, and for the same reason: a typo in a label name cannot be
    /// validated against anything, so what is shown is the consequence. A room
    /// with no rules, or a rule every one of whose names only a sender can
    /// supply, is obvious to somebody reading a pull request.
    #[must_use]
    pub fn routing_table(&self) -> String {
        let mut out = String::new();

        out.push_str("rooms  (* marks a label only a sender can supply)\n");
        let mut rooms: Vec<&String> = self.rooms.webhooks.keys().collect();
        rooms.sort();
        for room in rooms {
            let _ = writeln!(out, "  {room}");
            let mut selected = 0usize;
            for subscription in &self.rooms.subscriptions {
                if subscription.destination().id().as_str() != room {
                    continue;
                }
                selected += 1;
                let _ = writeln!(out, "    - {}", describe(subscription.filter()));
            }
            if selected == 0 {
                out.push_str("    (nothing selects this room)\n");
            }
        }

        // THE MISTAKE THIS LINE EXISTS FOR, and it is the likeliest one in a
        // tenant's first file. Under bead gc-nkb a shared sender is registered
        // once per tenant, so what arrives is `alertmanager-wallet-hsm-prod`
        // rather than `alertmanager` — and a rule matching the short name
        // matches nothing, silently, forever. Nothing can validate an origin
        // name here: this agent never sees the platform's list.
        let _ = writeln!(
            out,
            "\norigin names are the platform's, and are longer than you expect:\n  \
             a shared sender is registered once per tenant, so a rule wants\n  \
             `origin: alertmanager-<your-namespace>` and not `origin: alertmanager`"
        );

        let _ = writeln!(
            out,
            "\n{} room(s), {} rule(s), {} secret(s) present",
            self.rooms.webhooks.len(),
            self.rooms.subscriptions.len(),
            self.rooms.secrets.len()
        );

        out
    }

    /// Every rule, in the order the file gave them.
    #[must_use]
    pub fn subscriptions(&self) -> &[Subscription] {
        &self.rooms.subscriptions
    }

    /// Every secret value, by the name the file used.
    #[must_use]
    pub fn secrets(&self) -> &HashMap<String, String> {
        &self.rooms.secrets
    }

    /// Where each room is reached, by its identity.
    #[must_use]
    pub fn webhooks(&self) -> &HashMap<String, String> {
        &self.rooms.webhooks
    }
}

/// One rule, as the labels it requires.
fn describe(filter: &Filter) -> String {
    match filter {
        Filter::Everything => "everything".to_owned(),
        Filter::Labelled(required) => required
            .iter()
            .map(|(name, value)| {
                // The marker is the whole point: a name the system never produces
                // can only match if a sender chooses to send it.
                let mark = if name.is_projected() { "" } else { "*" };
                format!("{}{mark}={}", name.as_str(), value.as_str())
            })
            .collect::<Vec<_>>()
            .join(" "),
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
        "/../../../deploy/webhook-proxy/config.example.yaml"
    );

    /// Every secret the example names, with values that are obviously not real.
    /// Writes a value for every secret the published example names.
    ///
    /// Read out of the file rather than listed here. A list is a second place to
    /// keep in step, and it fails for the wrong reason the day the example gains
    /// a sender — which is what it did when it gained Grafana.
    fn secrets_for_the_example(dir: &Path) {
        fn walk(node: &serde_yaml_ng::Value, found: &mut std::collections::BTreeSet<String>) {
            match node {
                serde_yaml_ng::Value::Mapping(entries) => {
                    for (key, value) in entries {
                        if key.as_str() == Some("secret")
                            && let Some(name) = value.as_str()
                        {
                            found.insert(name.to_owned());
                        }
                        walk(value, found);
                    }
                }
                serde_yaml_ng::Value::Sequence(items) => items.iter().for_each(|i| walk(i, found)),
                _ => {}
            }
        }

        let text = fs::read_to_string(EXAMPLE).expect("the published example is readable");
        let parsed: serde_yaml_ng::Value =
            serde_yaml_ng::from_str(&text).expect("the published example parses");
        let mut named = std::collections::BTreeSet::new();
        walk(&parsed, &mut named);
        assert!(!named.is_empty(), "the example names no secrets at all");

        for name in named {
            fs::write(dir.join(&name), format!("not-a-real-value-for-{name}\n"))
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
tenants:
  - a-tenant
origins:
  - id: a-forge
    tenant: a-tenant
    speaks: github
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

        // Four senders for three products, because one Alertmanager serving two
        // tenants is two Origins here (bead gc-nkb). That is the shape, not an
        // accident, so the count is asserted rather than left to drift.
        assert_eq!(config.tenants().len(), 2);
        assert_eq!(config.origins().len(), 4);
        assert_eq!(config.webhooks().len(), 3);
        assert_eq!(config.subscriptions().len(), 5);

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
                "alertmanager-devsecops",
                &alert_labelled(&[("severity", "critical")])
            ),
            vec!["devsecops-room", "audit-room"]
        );

        // And one team's namespace reaches that team.
        assert_eq!(
            reached(
                &config,
                "alertmanager-platform",
                &alert_labelled(&[("namespace", "platform")])
            ),
            vec!["platform-room", "audit-room"]
        );

        // THE RULES ARE PER ORIGIN AND THE ORIGINS ARE PER TENANT, so one
        // tenant's Alertmanager cannot reach the other's room by sending the
        // other's label. That is bead gc-nkb's whole argument made executable:
        // `namespace: platform` on an alert from the devsecops credential
        // selects nothing but the room that takes everything, because the rule
        // naming that room also names which Origin it trusts.
        assert_eq!(
            reached(
                &config,
                "alertmanager-devsecops",
                &alert_labelled(&[("namespace", "platform")])
            ),
            vec!["audit-room"]
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
            config.origins()["github"].origin.verify(),
            Verification::Signed { .. }
        ));
        assert!(matches!(
            config.origins()["alertmanager-devsecops"].origin.verify(),
            Verification::Shared { .. }
        ));

        // And what each speaks, which is independent of how it proves itself.
        assert_eq!(config.origins()["github"].speaks, super::Speaks::Github);
        assert_eq!(
            config.origins()["alertmanager-devsecops"].speaks,
            super::Speaks::Alertmanager
        );
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

    // ---- the routing table ----------------------------------------------

    #[test]
    fn the_table_shows_what_the_published_example_actually_routes() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        secrets_for_the_example(dir.path());
        let config = Configuration::read(Path::new(EXAMPLE), dir.path()).expect("it parses");

        let table = config.routing_table();

        // Each sender, by the path it answers on and how it proves itself.
        assert!(
            table.contains("/webhook/github  signs its body, speaks github"),
            "{table}"
        );
        assert!(
            table.contains(
                "/webhook/alertmanager-devsecops  presents a shared value, \
                 speaks alertmanager, for tenant devsecops"
            ),
            "{table}"
        );

        // Whose each sender's alerts are, which is the thing a reviewer of this
        // file most needs to see and cannot infer: the tenant decides which
        // agent is ever offered the alert, and it is read from here.
        assert!(table.contains("for tenant platform"), "{table}");
        // And the tenants themselves, listed, with nothing marked — every one of
        // them has a sender in this example.
        assert!(table.contains("tenants  (*"), "{table}");
        assert!(!table.contains("platform  *"), "{table}");

        // Each room with the rules that select it.
        assert!(table.contains("devsecops-room"), "{table}");
        // Alphabetical, because Labels is a map and a table a reader compares
        // between deploys must not reorder itself.
        assert!(
            table.contains("- branch=main origin=github repository=motrice/webhook-proxy"),
            "{table}"
        );
        assert!(table.contains("everything"), "{table}");

        assert!(
            table.contains("2 tenant(s), 4 sender(s), 3 room(s), 5 rule(s), 7 secret(s) present"),
            "{table}"
        );
    }

    #[test]
    fn a_label_only_a_sender_can_supply_is_marked() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        secrets_for_the_example(dir.path());
        let config = Configuration::read(Path::new(EXAMPLE), dir.path()).expect("it parses");

        let table = config.routing_table();

        // namespace is the sender's, so it carries the marker; origin and
        // severity are ours, so they do not.
        assert!(table.contains("namespace*=platform"), "{table}");
        assert!(table.contains("severity=critical"), "{table}");
        assert!(!table.contains("severity*="), "{table}");
        assert!(!table.contains("origin*="), "{table}");
    }

    #[test]
    fn a_room_nothing_selects_says_so() {
        // The failure this whole subcommand exists to make visible: a typo in a
        // rule leaves a room that will never hear anything, and nothing about the
        // file is invalid.
        let dir = tempfile::tempdir().expect("a temporary directory");
        sound_secrets(dir.path());
        fs::write(dir.path().join("b-url"), "https://rooms.example/hook/B").expect("writable");

        let yaml = sound().replace(
            "destinations:\n  - id: a-room",
            "destinations:\n  - id: forgotten-room\n    kind: chat_room\n    webhook:\n      secret: b-url\n  - id: a-room",
        );
        let file = written(dir.path(), &yaml);
        let config = Configuration::read(&file, dir.path()).expect("it parses");

        let table = config.routing_table();

        assert!(table.contains("forgotten-room"), "{table}");
        assert!(table.contains("(nothing selects this room)"), "{table}");
        // And the room that is selected does not say it.
        let after = table.split("a-room").nth(1).expect("a-room appears");
        assert!(!after.starts_with("\n    (nothing"), "{table}");
    }

    #[test]
    fn the_table_never_prints_a_secret_value() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        sound_secrets(dir.path());
        let file = written(dir.path(), &sound());
        let config = Configuration::read(&file, dir.path()).expect("it parses");

        let table = config.routing_table();

        assert!(!table.contains("SUPERSECRETHOOKID"), "{table}");
        assert!(!table.contains("shhh"), "{table}");
        assert!(!table.contains("://"), "{table}");
        // The count is fine; the values are not.
        assert!(table.contains("2 secret(s) present"), "{table}");
    }

    #[test]
    fn a_third_vocabulary_is_readable_and_shown_in_the_table() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        sound_secrets(dir.path());
        let yaml = sound().replace("speaks: github", "speaks: grafana");
        let file = written(dir.path(), &yaml);

        let config = Configuration::read(&file, dir.path()).expect("it parses");

        assert_eq!(config.origins()["a-forge"].speaks, super::Speaks::Grafana);
        assert!(
            config.routing_table().contains("speaks grafana"),
            "{}",
            config.routing_table()
        );
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

    // ---- tenants ---------------------------------------------------------

    #[test]
    fn an_origin_naming_a_tenant_nobody_listed_is_refused_at_startup() {
        // THE FAILURE BEAD gc-nkb EXISTS TO PREVENT. If a tenant came into
        // being by being mentioned, this typo would create one: the alerts
        // would verify, be accepted, be stored, be offered to nobody, and
        // eventually be swept — every step reporting success. Listed, the typo
        // is this message, before anything deploys.
        let bad = sound().replace("tenant: a-tenant\n", "tenant: a-tennant\n");
        let e = refused(&bad);

        assert_eq!(e.path(), "origins[0].tenant");
        assert!(e.to_string().contains("a-tennant"), "{e}");
        assert!(
            e.to_string().contains("a-tenant"),
            "the refusal must say what IS listed, or the reader has to go and \
             look: {e}"
        );
    }

    #[test]
    fn a_tenant_that_could_not_be_a_namespace_is_refused() {
        // A tenant is a namespace here (gc-81d), and the tenant in this file is
        // compared against the namespace in a caller's identity. `Platform`
        // would authenticate an agent successfully and offer it nothing, with
        // every part reporting success — which is the hardest failure in this
        // design to diagnose and the cheapest one to refuse.
        let bad = sound().replace("  - a-tenant\n", "  - A-Tenant\n");
        let e = refused(&bad);

        assert_eq!(e.path(), "tenants[0]");
        assert!(e.to_string().contains("namespace"), "{e}");
    }

    #[test]
    fn a_tenant_listed_twice_is_refused() {
        let bad = sound().replace("  - a-tenant\n", "  - a-tenant\n  - a-tenant\n");
        let e = refused(&bad);

        assert_eq!(e.path(), "tenants[1]");
        assert!(e.to_string().contains("listed twice"), "{e}");
    }

    #[test]
    fn a_file_listing_no_tenants_is_refused_rather_than_serving_nobody() {
        let bad = sound().replace("tenants:\n  - a-tenant\n", "tenants: []\n");
        let e = refused(&bad);

        assert_eq!(e.path(), "tenants");
        assert!(e.to_string().contains("lists none"), "{e}");
    }

    #[test]
    fn an_origin_with_no_tenant_is_refused() {
        // The same house rule as a missing verify block: there is no third state
        // and nothing to default to. A default tenant would be the worst
        // possible one — every unlabelled sender filed under somebody.
        let bad = sound().replace("    tenant: a-tenant\n", "");
        let e = refused(&bad);

        assert!(
            e.to_string().contains("tenant"),
            "a file whose Origin names no tenant must say so: {e}"
        );
    }

    #[test]
    fn two_origins_with_one_identity_are_refused() {
        let bad = sound().replace(
            "destinations:",
            "  - id: a-forge\n    tenant: a-tenant\n    speaks: github\n    verify:\n      bearer:\n        secret: a-secret\ndestinations:",
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

#[cfg(test)]
mod tenant_tests {
    use std::fs;
    use std::path::Path;

    use super::TenantConfiguration;

    /// The published tenant example, and deliberately the real file: nothing
    /// else parses it, so a structural mistake in it would sit undetected until
    /// a tenant deployed it.
    const EXAMPLE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../deploy/alert-agent/config.example.yaml"
    );

    fn written(dir: &Path, yaml: &str) -> std::path::PathBuf {
        let file = dir.join("config.yaml");
        fs::write(&file, yaml).expect("writable");
        file
    }

    /// A minimal tenant file that parses, so each test can break one thing.
    fn sound() -> String {
        "
version: 1
destinations:
  - id: a-room
    kind: chat_room
    webhook:
      secret: a-url
subscriptions:
  - destination: a-room
    match:
      origin: a-forge-a-tenant
"
        .to_owned()
    }

    fn sound_secrets(dir: &Path) {
        fs::write(
            dir.join("a-url"),
            "https://rooms.example/hook/SUPERSECRETHOOKID",
        )
        .expect("writable");
    }

    fn refused(yaml: &str) -> super::Unusable {
        let dir = tempfile::tempdir().expect("a temporary directory");
        sound_secrets(dir.path());
        let file = written(dir.path(), yaml);
        TenantConfiguration::read(&file, dir.path()).expect_err("this file must be refused")
    }

    /// Every secret the example names, read out of the file rather than listed
    /// here — a list is a second place to keep in step.
    fn secrets_for_the_example(dir: &Path) {
        for name in secret_names(EXAMPLE) {
            fs::write(dir.join(&name), "https://rooms.example/hook/NOTAREALHOOK")
                .expect("writable");
        }
    }

    /// Every secret name a YAML file mentions, however deeply.
    ///
    /// Read out of the file rather than listed here: a list is a second place to
    /// keep in step, and it fails for the wrong reason the day an example gains
    /// a room. It is also what lets the test below assert that the two halves
    /// of the configuration name no secret in common.
    fn secret_names(file: &str) -> std::collections::BTreeSet<String> {
        fn walk(node: &serde_yaml_ng::Value, found: &mut std::collections::BTreeSet<String>) {
            match node {
                serde_yaml_ng::Value::Mapping(entries) => {
                    for (key, value) in entries {
                        if key.as_str() == Some("secret")
                            && let Some(name) = value.as_str()
                        {
                            found.insert(name.to_owned());
                        }
                        walk(value, found);
                    }
                }
                serde_yaml_ng::Value::Sequence(items) => {
                    for item in items {
                        walk(item, found);
                    }
                }
                _ => {}
            }
        }

        let text = fs::read_to_string(file).expect("the file is readable");
        let parsed: serde_yaml_ng::Value =
            serde_yaml_ng::from_str(&text).expect("the file parses as YAML");
        let mut found = std::collections::BTreeSet::new();
        walk(&parsed, &mut found);
        found
    }

    #[test]
    fn the_published_example_produces_the_routing_it_describes() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        secrets_for_the_example(dir.path());

        let config = TenantConfiguration::read(Path::new(EXAMPLE), dir.path())
            .unwrap_or_else(|e| panic!("the published tenant example must parse: {e}"));

        assert_eq!(config.webhooks().len(), 2);
        assert_eq!(config.subscriptions().len(), 3);
        assert_eq!(config.secrets().len(), 2);
    }

    // ---- what a tenant's file may not contain ----------------------------
    //
    // Four keys, each refused BY NAME with a reason. `deny_unknown_fields`
    // already makes a mistyped key an error, so these tests are not about
    // typos: they are about the keys somebody reaches for having read the
    // platform's file, where a serde "unknown field" would be true and useless.

    #[test]
    fn a_tenant_file_naming_origins_is_refused_and_told_why() {
        let bad = sound().replace(
            "destinations:",
            "origins:\n  - id: a-forge\n    tenant: a-tenant\n    speaks: github\ndestinations:",
        );
        let e = refused(&bad);

        assert_eq!(e.path(), "origins");
        assert!(e.to_string().contains("authenticates senders"), "{e}");
    }

    #[test]
    fn a_tenant_file_naming_a_verify_block_is_refused_and_told_why() {
        let bad = sound().replace(
            "destinations:",
            "verify:\n  hmac_sha256:\n    secret: a-secret\ndestinations:",
        );
        let e = refused(&bad);

        assert_eq!(e.path(), "verify");
        assert!(e.to_string().contains("already been verified"), "{e}");
    }

    #[test]
    fn a_tenant_file_listing_tenants_is_refused_and_told_why() {
        let bad = sound().replace("destinations:", "tenants:\n  - a-tenant\ndestinations:");
        let e = refused(&bad);

        assert_eq!(e.path(), "tenants");
        assert!(e.to_string().contains("serves exactly one"), "{e}");
    }

    #[test]
    fn a_tenant_file_naming_its_own_tenant_is_refused_and_told_why() {
        // The one that matters most (gc-nkb). A tenant name here is not merely
        // redundant: it is a value nothing checks against anything, and the
        // next reader would reasonably assume it was load-bearing.
        let bad = sound().replace("destinations:", "tenant: a-tenant\ndestinations:");
        let e = refused(&bad);

        assert_eq!(e.path(), "tenant");
        assert!(e.to_string().contains("checked against nothing"), "{e}");
        assert!(e.to_string().contains("gc-nkb"), "{e}");
    }

    #[test]
    fn neither_half_of_the_configuration_can_name_the_others_secrets() {
        // The property gc-g9x said makes the split worth having, as a test
        // rather than a reading of two files. The platform's example names
        // sender secrets and a database; the tenant's names room URLs. An
        // overlap would mean one side held a credential it has no business
        // holding, and nothing would say so.
        let platform = secret_names(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../deploy/webhook-proxy/config.example.yaml"
        ));
        let tenant = secret_names(EXAMPLE);

        assert!(
            !platform.is_empty(),
            "the platform example names no secrets"
        );
        assert!(!tenant.is_empty(), "the tenant example names no secrets");
        let shared: Vec<&String> = platform.intersection(&tenant).collect();
        assert!(
            shared.is_empty(),
            "both halves of the configuration name {shared:?}, so one of them \
             holds a credential it has no business holding"
        );
    }

    #[test]
    fn the_table_warns_about_origin_names_unconditionally() {
        // Nothing here can validate an origin name — this agent never sees the
        // platform's list, which is the same separation that stops it seeing
        // another tenant's alerts. So the warning is printed always, rather
        // than when something looks wrong, because nothing ever looks wrong.
        let dir = tempfile::tempdir().expect("a temporary directory");
        sound_secrets(dir.path());
        let file = written(dir.path(), &sound());
        let config = TenantConfiguration::read(&file, dir.path()).expect("it parses");

        let table = config.routing_table();

        assert!(table.contains("longer than you expect"), "{table}");
        assert!(
            table.contains("origin: alertmanager-<your-namespace>"),
            "{table}"
        );
    }

    #[test]
    fn a_room_nothing_selects_says_so() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        sound_secrets(dir.path());
        fs::write(dir.path().join("b-url"), "https://rooms.example/hook/B").expect("writable");
        let file = written(
            dir.path(),
            &sound().replace(
                "subscriptions:",
                "  - id: forgotten-room\n    kind: chat_room\n    webhook:\n      secret: b-url\nsubscriptions:",
            ),
        );
        let config = TenantConfiguration::read(&file, dir.path()).expect("it parses");

        assert!(
            config
                .routing_table()
                .contains("(nothing selects this room)"),
            "{}",
            config.routing_table()
        );
    }

    #[test]
    fn no_room_url_appears_in_the_table_or_the_debug_output() {
        // A room URL is itself a credential (gc-o61), and these are the two
        // strings most likely to be pasted into a chat window.
        let dir = tempfile::tempdir().expect("a temporary directory");
        sound_secrets(dir.path());
        let file = written(dir.path(), &sound());
        let config = TenantConfiguration::read(&file, dir.path()).expect("it parses");

        assert!(!config.routing_table().contains("SUPERSECRETHOOKID"));
        assert!(!format!("{config:?}").contains("SUPERSECRETHOOKID"));
    }
}
