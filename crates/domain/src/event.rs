//! What happened, stated without reference to whoever told us about it.

use crate::label::{LabelName, LabelValue, Labels};

/// A value that carries meaning may not be blank. Carries the concept that was
/// blank, so a caller can say which field the sender left out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blank(&'static str);

impl Blank {
    /// Which concept was blank.
    #[must_use]
    pub fn concept(&self) -> &'static str {
        self.0
    }
}

impl core::fmt::Display for Blank {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} must not be blank", self.0)
    }
}

/// A repository's name, as the people who work in it would say it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryName(String);

/// A branch's name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BranchName(String);

/// Whoever pushed. A name to show a reader, not an account to authorise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pusher(String);

/// A commit's identity. Opaque: the domain never parses or shortens it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitId(String);

/// A commit's one-line summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary(String);

/// Where a reader can go to see what happened, exactly as the Origin published
/// it.
///
/// Opaque on purpose. The domain never builds one — an Origin's address scheme
/// is that Origin's business, and constructing a link here would put one
/// vendor's knowledge in the core and make every future Origin inherit it. It
/// never parses one either: there is no scheme check and no path handling,
/// because a rule that read a reference apart would be claiming to know what
/// shape references have.
///
/// So the only invariant is the one every value type here shares: present and
/// trimmed. This is a reference to the subject of a fact, not the address of a
/// system we talk to — a `Destination` still has no address, and
/// `crates/architecture`'s purity test forbids the vocabulary of transport in
/// this crate. Bead gc-3pa.13 records why that line falls here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Permalink(String);

/// One commit, reduced to what a Destination needs to show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    id: CommitId,
    summary: Summary,
}

/// Something that happened, independent of any Origin's payload format.
///
/// Two different facts reach us carrying no commits: a branch was deleted, and a
/// push that changed nothing. A reader needs different words for them, so they
/// are separate variants rather than one variant with a flag. A flag would also
/// permit `deleted, and here are two commits`, which no sender means and no
/// renderer could sensibly show.
///
/// Which of the two it is, is visible only to an inbound adapter: the sender says
/// so in a field alongside the commit list. That is why the distinction is drawn
/// at the boundary and carried inward as a variant, rather than guessed here from
/// a count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Commits were pushed to a branch.
    PushedCommits {
        /// Which repository.
        repository: RepositoryName,
        /// Which branch.
        branch: BranchName,
        /// Who pushed.
        pusher: Pusher,
        /// What was pushed, oldest first.
        ///
        /// May be empty, meaning a push that changed nothing. A deletion is
        /// [`Event::DeletedBranch`] and never this with an empty list.
        commits: Vec<Commit>,
        /// Where a reader can see this push, if the Origin published a link.
        ///
        /// `None` means the Origin published none, not that we failed to read
        /// one: a missing link is no reason to drop a real push, so this is
        /// optional rather than required.
        permalink: Option<Permalink>,
    },
    /// A branch was deleted.
    ///
    /// Carries no commits, and cannot: deleting a branch pushes nothing. The
    /// absence of the field is what keeps a deletion from being confused with a
    /// push.
    DeletedBranch {
        /// Which repository.
        repository: RepositoryName,
        /// Which branch no longer exists.
        branch: BranchName,
        /// Who deleted it.
        pusher: Pusher,
    },
}

/// The label a forge Event is routed by when a rule names a repository.
const REPOSITORY: &str = "repository";

/// The label a forge Event is routed by when a rule names a branch.
const BRANCH: &str = "branch";

impl Event {
    /// The labels this can be routed by.
    ///
    /// Every Event answers this, so a new variant is bound by the compiler to
    /// say how it is routed rather than by somebody remembering to extend a
    /// match inside a Filter. It replaced an accessor that returned a
    /// `RepositoryName`, which only a sender that has a repository could answer —
    /// an alert has a namespace and a severity and no repository at all. Bead
    /// gc-ast.1 records why routing stopped asking for a typed field.
    ///
    /// For these variants the labels are *projected* from the typed fields, never
    /// stored. That is what keeps the mechanism safe: there is nowhere to put a
    /// label, so a label cannot disagree with the field it came from, and no
    /// adapter can misspell one into an Event. A sender whose labels are its own
    /// data — an alert — stores them instead, and the same question is asked of
    /// both.
    #[must_use]
    pub fn labels(&self) -> Labels {
        match self {
            Self::PushedCommits {
                repository, branch, ..
            }
            | Self::DeletedBranch {
                repository, branch, ..
            } => Labels::none()
                .with(
                    LabelName::known(REPOSITORY),
                    LabelValue::present(repository.as_str()),
                )
                .with(
                    LabelName::known(BRANCH),
                    LabelValue::present(branch.as_str()),
                ),
        }
    }
}

/// Trim and reject blank, so every one of these types means the same thing by
/// "present". Written once rather than five times, and shared with `routing`.
pub(crate) fn present(value: &str, concept: &'static str) -> Result<String, Blank> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(Blank(concept));
    }
    Ok(trimmed.to_owned())
}

impl RepositoryName {
    /// Names a repository.
    ///
    /// # Errors
    ///
    /// [`Blank`] if the name is empty or only whitespace.
    pub fn new(name: &str) -> Result<Self, Blank> {
        present(name, "a repository name").map(Self)
    }

    /// The name as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl BranchName {
    /// Names a branch.
    ///
    /// # Errors
    ///
    /// [`Blank`] if the name is empty or only whitespace.
    pub fn new(name: &str) -> Result<Self, Blank> {
        present(name, "a branch name").map(Self)
    }

    /// The name as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Pusher {
    /// Names whoever pushed.
    ///
    /// # Errors
    ///
    /// [`Blank`] if the name is empty or only whitespace.
    pub fn new(name: &str) -> Result<Self, Blank> {
        present(name, "a pusher's name").map(Self)
    }

    /// The name as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl CommitId {
    /// Takes a commit's identity as the sender spelled it.
    ///
    /// # Errors
    ///
    /// [`Blank`] if the identity is empty or only whitespace.
    pub fn new(id: &str) -> Result<Self, Blank> {
        present(id, "a commit identity").map(Self)
    }

    /// The identity as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Summary {
    /// Takes a commit's summary, keeping only its first non-blank line: a
    /// Destination shows one line, and a multi-line message would break every
    /// renderer that assumes otherwise.
    ///
    /// # Errors
    ///
    /// [`Blank`] if the summary is empty or only whitespace.
    pub fn new(summary: &str) -> Result<Self, Blank> {
        // The first line that says anything. Taking line one blindly would
        // reject a message that merely opens with a blank line, and a sender's
        // sloppiness is not a reason to drop an event.
        let headline = summary.lines().find(|line| !line.trim().is_empty());
        present(headline.unwrap_or_default(), "a commit summary").map(Self)
    }

    /// The summary as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Permalink {
    /// Takes a reference as the Origin published it.
    ///
    /// # Errors
    ///
    /// [`Blank`] if the reference is empty or only whitespace.
    pub fn new(reference: &str) -> Result<Self, Blank> {
        present(reference, "a permalink").map(Self)
    }

    /// The reference as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Commit {
    /// Records a commit.
    #[must_use]
    pub fn new(id: CommitId, summary: Summary) -> Self {
        Self { id, summary }
    }

    /// Which commit.
    #[must_use]
    pub fn id(&self) -> &CommitId {
        &self.id
    }

    /// Its one-line summary.
    #[must_use]
    pub fn summary(&self) -> &Summary {
        &self.summary
    }
}

#[cfg(test)]
mod tests {
    use super::{BranchName, Commit, CommitId, Event, Permalink, Pusher, RepositoryName, Summary};
    use crate::LabelName;

    fn commit(id: &str, summary: &str) -> Commit {
        Commit::new(
            CommitId::new(id).expect("a non-blank id"),
            Summary::new(summary).expect("a non-blank summary"),
        )
    }

    fn push(commits: Vec<Commit>) -> Event {
        Event::PushedCommits {
            repository: RepositoryName::new("webhook-proxy").expect("a name"),
            branch: BranchName::new("main").expect("a name"),
            pusher: Pusher::new("bjorn").expect("a name"),
            commits,
            permalink: None,
        }
    }

    fn deletion() -> Event {
        Event::DeletedBranch {
            repository: RepositoryName::new("webhook-proxy").expect("a name"),
            branch: BranchName::new("main").expect("a name"),
            pusher: Pusher::new("bjorn").expect("a name"),
        }
    }

    #[test]
    fn a_deletion_is_not_a_push_that_carried_no_commits() {
        // The point of the whole variant. Both arrive from the same sender with
        // an empty commit list; only the Event can keep them apart, and a
        // renderer that cannot tell them apart says something false about one.
        assert_ne!(deletion(), push(vec![]));
    }

    #[test]
    fn a_deletion_cannot_carry_commits() {
        // Expressed as a type, not a test: DeletedBranch has no commits field,
        // so `deleted but here are two commits` cannot be constructed. This
        // test exists to state the intent that keeps it that way.
        let Event::DeletedBranch {
            repository,
            branch,
            pusher,
        } = deletion()
        else {
            panic!("a deletion");
        };

        assert_eq!(repository.as_str(), "webhook-proxy");
        assert_eq!(branch.as_str(), "main");
        assert_eq!(pusher.as_str(), "bjorn");
    }

    fn label_of(event: &Event, name: &str) -> Option<String> {
        let name = LabelName::new(name).expect("a non-blank name");
        event
            .labels()
            .get(&name)
            .map(|value| value.as_str().to_owned())
    }

    #[test]
    fn every_event_offers_the_labels_it_can_be_routed_by() {
        // Routing asks this of any Event, so a new variant is bound by the
        // compiler to answer it rather than by somebody remembering to extend a
        // match inside a Filter. This replaced Event::repository(), which only a
        // sender that has a repository could answer — see bead gc-ast.1.
        for event in [push(vec![]), deletion()] {
            assert_eq!(
                label_of(&event, "repository").as_deref(),
                Some("webhook-proxy")
            );
            assert_eq!(label_of(&event, "branch").as_deref(), Some("main"));
            assert_eq!(event.labels().len(), 2);
        }
    }

    #[test]
    fn labels_are_projected_from_the_typed_fields_rather_than_stored() {
        // The property that makes label routing safe: there is nowhere to put a
        // label, so a label cannot disagree with the field it came from and no
        // adapter can misspell one into an Event. Changing the branch changes the
        // label, necessarily.
        let elsewhere = Event::PushedCommits {
            repository: RepositoryName::new("other/repo").expect("a name"),
            branch: BranchName::new("feature/x").expect("a name"),
            pusher: Pusher::new("bjorn").expect("a name"),
            commits: vec![],
            permalink: None,
        };

        assert_eq!(
            label_of(&elsewhere, "repository").as_deref(),
            Some("other/repo")
        );
        assert_eq!(label_of(&elsewhere, "branch").as_deref(), Some("feature/x"));
    }

    #[test]
    fn a_label_an_event_does_not_carry_is_simply_absent() {
        // Not an error and not a blank: a push has no severity, and a rule asking
        // for one must fail to match rather than fail to run.
        assert!(label_of(&push(vec![]), "severity").is_none());
    }

    #[test]
    fn a_permalink_cannot_be_blank() {
        assert!(Permalink::new("").is_err());
        assert!(Permalink::new("  \t ").is_err());
    }

    #[test]
    fn a_permalink_says_which_concept_was_missing() {
        let err = Permalink::new("").expect_err("blank is rejected");

        assert_eq!(err.concept(), "a permalink");
    }

    #[test]
    fn a_permalink_is_kept_verbatim_and_not_inspected() {
        // The domain does not know, and must not know, what an Origin's
        // addresses look like. It carries the reference whole and shows it; it
        // never parses a scheme or a path out of one.
        let link = Permalink::new("https://forge.example/motrice/webhook-proxy/compare/a...b")
            .expect("a reference");

        assert_eq!(
            link.as_str(),
            "https://forge.example/motrice/webhook-proxy/compare/a...b"
        );
    }

    #[test]
    fn surrounding_whitespace_is_not_part_of_a_permalink() {
        let link = Permalink::new("  https://forge.example/c/1 \n").expect("a reference");

        assert_eq!(link.as_str(), "https://forge.example/c/1");
    }

    #[test]
    fn a_push_may_carry_a_permalink_and_may_not() {
        // Optional because an Origin may publish no link, not because we failed
        // to read one. Refusing the Delivery over a missing link would mean a
        // room hears nothing about a real push.
        let Event::PushedCommits { permalink, .. } = push(vec![]) else {
            panic!("a push");
        };
        assert!(permalink.is_none());

        let linked = Event::PushedCommits {
            repository: RepositoryName::new("webhook-proxy").expect("a name"),
            branch: BranchName::new("main").expect("a name"),
            pusher: Pusher::new("bjorn").expect("a name"),
            commits: vec![],
            permalink: Some(Permalink::new("https://forge.example/c/1").expect("a reference")),
        };
        let Event::PushedCommits { permalink, .. } = &linked else {
            panic!("a push");
        };
        assert_eq!(
            permalink.as_ref().map(Permalink::as_str),
            Some("https://forge.example/c/1")
        );
    }

    #[test]
    fn a_deletion_cannot_carry_a_permalink() {
        // DeletedBranch has no such field, so `a deletion, and here is a
        // comparison link` cannot be built. A link comparing against a ref that
        // no longer exists would be useless even though a sender may send one.
        let Event::DeletedBranch { .. } = deletion() else {
            panic!("a deletion");
        };
    }

    #[test]
    fn a_repository_name_cannot_be_blank() {
        assert!(RepositoryName::new("").is_err());
        assert!(RepositoryName::new("   \t ").is_err());
    }

    #[test]
    fn a_blank_value_says_which_concept_was_missing() {
        let err = BranchName::new("").expect_err("blank is rejected");

        assert_eq!(err.concept(), "a branch name");
    }

    #[test]
    fn surrounding_whitespace_is_not_part_of_a_name() {
        // Normalise once, at the boundary, so nothing downstream has to wonder
        // whether " main" and "main" are the same branch.
        let name = BranchName::new("  main \n").expect("a name");

        assert_eq!(name.as_str(), "main");
    }

    #[test]
    fn a_summary_keeps_only_its_first_line() {
        let summary = Summary::new("fix the thing\n\nwith a longer body\n").expect("a summary");

        assert_eq!(summary.as_str(), "fix the thing");
    }

    #[test]
    fn a_summary_skips_a_leading_blank_line_rather_than_rejecting_the_commit() {
        let summary = Summary::new("\n\nfix the thing\n").expect("a summary");

        assert_eq!(summary.as_str(), "fix the thing");
    }

    #[test]
    fn a_commit_identity_is_kept_verbatim_and_not_shortened() {
        let id = CommitId::new("9b99d1affffffffffffffffffffffffffffffffff").expect("an id");

        assert_eq!(id.as_str(), "9b99d1affffffffffffffffffffffffffffffffff");
    }

    #[test]
    fn a_push_of_zero_commits_is_representable() {
        // This is how a branch deletion arrives. Refusing to represent it would
        // mean dropping a real event on the floor.
        let Event::PushedCommits { commits, .. } = push(vec![]) else {
            panic!("a push");
        };

        assert!(commits.is_empty());
    }

    #[test]
    fn a_push_of_zero_commits_is_distinguishable_from_a_push_of_one() {
        let empty = push(vec![]);
        let one = push(vec![commit("abc123", "fix the thing")]);

        assert_ne!(empty, one);

        let Event::PushedCommits { commits, .. } = &one else {
            panic!("a push");
        };
        assert_eq!(commits.len(), 1);
    }

    #[test]
    fn commits_keep_the_order_they_were_given() {
        let one = commit("aaa", "first");
        let two = commit("bbb", "second");

        let Event::PushedCommits { commits, .. } = push(vec![one.clone(), two.clone()]) else {
            panic!("a push");
        };

        assert_eq!(commits, vec![one, two]);
    }

    #[test]
    fn a_commit_exposes_its_identity_and_summary() {
        let c = commit("abc123", "fix the thing");

        assert_eq!(c.id().as_str(), "abc123");
        assert_eq!(c.summary().as_str(), "fix the thing");
    }
}
