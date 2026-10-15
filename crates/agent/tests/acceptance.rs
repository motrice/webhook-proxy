//! The agent as a binary, run the way a tenant's pipeline runs it.
//!
//! Unit tests prove the parser; this proves the thing that ships. A binary that
//! reads the wrong environment variable, or exits zero on a bad file, would
//! pass every test in `yaml-config` and fail the one job it has.

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::process::Command;

/// The published example, and deliberately the real file.
const EXAMPLE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../deploy/alert-agent/config.example.yaml"
);

/// Runs the built binary with exactly this environment, and nothing inherited.
///
/// `env_clear` matters: a developer with `ALERT_AGENT_CONFIG` set in a shell
/// would otherwise get a different answer from CI, which is the kind of
/// difference that costs an afternoon.
fn run(argument: Option<&str>, env: &HashMap<&str, String>) -> (bool, String, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_alert-agent"));
    command.env_clear();
    for (name, value) in env {
        command.env(name, value);
    }
    if let Some(argument) = argument {
        command.arg(argument);
    }

    let done = command.output().expect("the binary runs");
    (
        done.status.success(),
        String::from_utf8_lossy(&done.stdout).into_owned(),
        String::from_utf8_lossy(&done.stderr).into_owned(),
    )
}

/// Every secret the example names, with values that are obviously not real.
fn secrets_for_the_example(dir: &Path) {
    let text = fs::read_to_string(EXAMPLE).expect("the published example is readable");
    for line in text.lines() {
        if let Some(name) = line.trim().strip_prefix("secret:") {
            fs::write(
                dir.join(name.trim()),
                "https://rooms.example/hook/NOTAREALHOOK",
            )
            .expect("writable");
        }
    }
}

fn pointed_at(file: &Path, secrets: &Path) -> HashMap<&'static str, String> {
    HashMap::from([
        (
            "ALERT_AGENT_CONFIG",
            file.to_str().expect("a utf-8 path").to_owned(),
        ),
        (
            "ALERT_AGENT_SECRETS_DIR",
            secrets.to_str().expect("a utf-8 path").to_owned(),
        ),
    ])
}

#[test]
fn check_reads_the_published_example_and_prints_what_it_routes() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    secrets_for_the_example(dir.path());

    let (ok, out, err) = run(Some("check"), &pointed_at(Path::new(EXAMPLE), dir.path()));

    assert!(ok, "{err}{out}");
    assert!(
        out.contains("2 room(s), 3 rule(s), 2 secret(s) present"),
        "{out}"
    );
    // The warning a first version of this file most needs, printed always
    // because nothing here can check an origin name against anything.
    assert!(out.contains("longer than you expect"), "{out}");
    // And no room URL, which is itself a credential (gc-o61).
    assert!(!out.contains("NOTAREALHOOK"), "{out}");
}

#[test]
fn check_refuses_a_file_naming_the_platforms_keys_and_says_which() {
    // The four keys somebody reaches for having read the platform's file. This
    // is the binary's view of it: a tenant's pipeline sees the message, and a
    // message that said "unknown field" would be true and useless.
    for (key, block, expected) in [
        (
            "origins",
            "origins:\n  - id: a-forge\n",
            "authenticates senders",
        ),
        (
            "verify",
            "verify:\n  bearer:\n    secret: a\n",
            "already been verified",
        ),
        ("tenants", "tenants:\n  - a-tenant\n", "serves exactly one"),
        ("tenant", "tenant: a-tenant\n", "checked against nothing"),
    ] {
        let dir = tempfile::tempdir().expect("a temporary directory");
        fs::write(dir.path().join("a-url"), "https://rooms.example/hook/A").expect("writable");
        let file = dir.path().join("config.yaml");
        fs::write(
            &file,
            format!(
                "version: 1
{block}destinations:
  - id: a-room
    kind: chat_room
    webhook:
      secret: a-url
subscriptions:
  - destination: a-room
    match:
      origin: a-forge-a-tenant
"
            ),
        )
        .expect("writable");

        let (ok, out, err) = run(Some("check"), &pointed_at(&file, dir.path()));

        assert!(!ok, "a file naming {key:?} was accepted: {out}");
        assert!(err.contains(key), "{err}");
        assert!(err.contains(expected), "{err}");
    }
}

#[test]
fn a_subcommand_this_build_does_not_have_is_refused_and_says_what_it_does() {
    // `serve`, `run` and `deliver` are the names somebody would guess for the
    // run mode, which has no name: no argument at all is the run mode, the way
    // a container entrypoint invokes it.
    let dir = tempfile::tempdir().expect("a temporary directory");
    secrets_for_the_example(dir.path());
    let env = pointed_at(Path::new(EXAMPLE), dir.path());

    for asked in ["serve", "deliver", "run", "--help"] {
        let (ok, out, err) = run(Some(asked), &env);

        assert!(!ok, "{asked:?} was accepted: {out}");
        assert!(err.contains("check"), "{err}");
        assert!(err.contains("claims, delivers and reports"), "{err}");
    }
}

#[test]
fn the_run_mode_will_not_guess_where_the_platform_is() {
    // The one variable with no sensible default. An agent that guessed would
    // either reach nothing or reach somebody else's platform, and the second is
    // worse than not starting.
    let dir = tempfile::tempdir().expect("a temporary directory");
    secrets_for_the_example(dir.path());

    let (ok, _out, err) = run(None, &pointed_at(Path::new(EXAMPLE), dir.path()));

    assert!(!ok, "it started without being told where the platform is");
    assert!(err.contains("ALERT_AGENT_PLATFORM"), "{err}");
}

#[test]
fn the_run_mode_refuses_a_file_it_cannot_use_before_reaching_anything() {
    // The whole operator experience of a bad deploy, and it must happen before
    // the first claim: an agent that started and then failed to route would
    // look healthy while delivering nothing.
    let dir = tempfile::tempdir().expect("a temporary directory");
    fs::write(dir.path().join("a-url"), "https://rooms.example/hook/SHHH").expect("writable");
    let file = dir.path().join("config.yaml");
    fs::write(&file, "version: 1\ndestinations: []\nsubscriptions: []\n").expect("writable");

    let mut env = pointed_at(&file, dir.path());
    // A platform that could not be reached even if it tried, so a failure here
    // can only be the file.
    env.insert("ALERT_AGENT_PLATFORM", "http://127.0.0.1:1".to_owned());

    let (ok, _out, err) = run(None, &env);

    assert!(!ok);
    assert!(err.contains("subscriptions"), "{err}");
    assert!(!err.contains("SHHH"), "{err}");
}

#[test]
fn an_unreadable_file_is_refused_with_the_path_and_no_secret_value() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    fs::write(dir.path().join("a-url"), "https://rooms.example/hook/SHHH").expect("writable");
    let missing = dir.path().join("not-written.yaml");

    let (ok, _out, err) = run(Some("check"), &pointed_at(&missing, dir.path()));

    assert!(!ok);
    assert!(err.contains("not-written.yaml"), "{err}");
    assert!(!err.contains("SHHH"), "{err}");
}
