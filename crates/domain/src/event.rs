//! What happened, stated without reference to whoever told us about it.

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

impl Event {
    /// Which repository this is about. Every Event concerns exactly one.
    ///
    /// Routing asks this of any Event, so a new variant is bound by the compiler
    /// to answer it, rather than by somebody remembering to extend a match
    /// inside a Filter.
    #[must_use]
    pub fn repository(&self) -> &RepositoryName {
        match self {
            Self::PushedCommits { repository, .. } | Self::DeletedBranch { repository, .. } => {
                repository
            }
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
    use super::{BranchName, Commit, CommitId, Event, Pusher, RepositoryName, Summary};

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

    #[test]
    fn every_event_says_which_repository_it_is_about() {
        // Routing asks this of any Event. Without it, each new variant would
        // have to be added to a match inside the Filter, which is the kind of
        // change that gets forgotten.
        assert_eq!(push(vec![]).repository().as_str(), "webhook-proxy");
        assert_eq!(deletion().repository().as_str(), "webhook-proxy");
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
