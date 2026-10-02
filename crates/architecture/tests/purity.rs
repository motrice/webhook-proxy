//! Source-level purity of the domain.
//!
//! `boundaries.rs` proves the dependency *graph* is right, but it is blind to
//! the effects that need no dependency at all: `std::time::SystemTime::now()`,
//! `std::fs`, `std::env` and friends all live in `std`, which never appears in
//! a manifest. A domain crate can therefore read the clock, the filesystem and
//! the environment while still reporting zero dependencies.
//!
//! This closes that hole by reading the source text. The hard part is not
//! finding the needles — it is *not* finding them in prose, because the
//! domain's own documentation names the very things it forbids.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

/// An effect the domain may not reach for, and the reason, phrased as the
/// advice a reader needs at the moment the test fails.
struct Forbidden {
    needle: &'static str,
    why: &'static str,
}

/// Banning the *type* rather than the call catches both `SystemTime::now()` and
/// a `use std::time::SystemTime` followed by use elsewhere. `Duration` is
/// deliberately absent: a duration is a value, not an effect, and a domain is
/// entitled to say "thirty days".
const FORBIDDEN: &[Forbidden] = &[
    Forbidden {
        needle: "SystemTime",
        why: "reading the clock is an effect; take a Timestamp as an argument \
              and let a Clock port supply it",
    },
    Forbidden {
        needle: "Instant",
        why: "reading the clock is an effect; see the Clock port",
    },
    Forbidden {
        needle: "std::env",
        why: "configuration reaches the core as arguments, not from the \
              environment",
    },
    Forbidden {
        needle: "std::fs",
        why: "the filesystem belongs behind a port, implemented by an adapter",
    },
    Forbidden {
        needle: "std::net",
        why: "the network belongs behind a port, implemented by an adapter",
    },
    Forbidden {
        needle: "std::io",
        why: "input and output belong in adapters; the domain returns values",
    },
    Forbidden {
        needle: "std::thread",
        why: "concurrency is an adapter's concern; domain logic is sequential \
              and pure",
    },
    Forbidden {
        needle: "std::process",
        why: "spawning a process is an effect and belongs behind a port",
    },
];

/// Vendor vocabulary that must not reach the core. An `Event` is a business
/// fact; the moment a domain type is named after whoever reported it, the
/// anti-corruption layer has leaked and every future Origin inherits the first
/// one's worldview.
///
/// Matched case-insensitively, because `GitHub`, `Github` and `GITHUB` are the
/// same mistake.
///
/// Deliberately absent: `element` and `matrix`. Both are ordinary English words
/// that appear in honest code — an element of a collection, a matrix of cases —
/// and a gate with false positives gets switched off. Those two stay the
/// glossary's job and review's job.
const VENDOR: &[Forbidden] = &[
    Forbidden {
        needle: "github",
        why: "translate the payload into an Event in the inbound adapter; the \
              domain must not know who reported the fact",
    },
    Forbidden {
        needle: "gitlab",
        why: "see the inbound adapter; the domain names facts, not reporters",
    },
    Forbidden {
        needle: "forgejo",
        why: "see the inbound adapter; the domain names facts, not reporters",
    },
    Forbidden {
        needle: "gitea",
        why: "see the inbound adapter; the domain names facts, not reporters",
    },
    Forbidden {
        needle: "hookshot",
        why: "a Destination is identified by kind, never by the product that \
              happens to implement it",
    },
    Forbidden {
        needle: "bitbucket",
        why: "see the inbound adapter; the domain names facts, not reporters",
    },
    Forbidden {
        needle: "slack",
        why: "a Destination is identified by kind, never by the product that \
              happens to implement it",
    },
];

/// Where a forbidden effect was found.
#[derive(Debug, PartialEq, Eq)]
struct Violation {
    line: usize,
    needle: &'static str,
    why: &'static str,
}

/// Where the scanner currently is. `Block` and `Raw` carry depth and hash
/// count, because Rust nests block comments and lets a raw string choose its own
/// delimiter.
#[derive(Clone, Copy)]
enum Scan {
    Code,
    Line,
    Block(usize),
    Str,
    Char,
    Raw(usize),
}

/// Replace one character with a space, keeping newlines so that line numbers in
/// the output still match the input.
fn blank(out: &mut String, c: char) {
    out.push(if c == '\n' { '\n' } else { ' ' });
}

/// One step taken from inside code: either this character opens a comment or a
/// literal, or it is real code and survives into the output.
fn step_code(chars: &[char], i: usize, out: &mut String) -> (Scan, usize) {
    let c = chars[i];
    let next = chars.get(i + 1).copied();

    if c == '/' && next == Some('/') {
        out.push_str("  ");
        return (Scan::Line, i + 2);
    }
    if c == '/' && next == Some('*') {
        out.push_str("  ");
        return (Scan::Block(1), i + 2);
    }
    if let Some((hashes, after)) = raw_string_opener(chars, i) {
        for _ in i..after {
            out.push(' ');
        }
        return (Scan::Raw(hashes), after);
    }
    if c == '"' {
        out.push(' ');
        return (Scan::Str, i + 1);
    }
    if c == '\'' && opens_char_literal(chars, i) {
        out.push(' ');
        return (Scan::Char, i + 1);
    }
    // A lifetime lands here and stays as code, which is the point: treating
    // `'a` as a literal would swallow the rest of the file and make the gate
    // report success — the worst failure available to a gate.
    out.push(c);
    (Scan::Code, i + 1)
}

/// Blanks out everything that is not code — comments, string literals and
/// character literals — replacing each removed character with a space and
/// keeping newlines, so line numbers in the result still match the input.
///
/// Prose is the whole reason this exists: `crates/domain/src/lib.rs` documents
/// that it must not use `std::fs`, and a scanner that cannot tell a sentence
/// from a statement would fail on that sentence forever.
fn code_only(src: &str) -> String {
    let chars: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let mut state = Scan::Code;
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        match state {
            Scan::Code => {
                let (moved_to, moved_past) = step_code(&chars, i, &mut out);
                state = moved_to;
                i = moved_past;
            }
            Scan::Line => {
                if c == '\n' {
                    state = Scan::Code;
                }
                blank(&mut out, c);
                i += 1;
            }
            Scan::Block(depth) => {
                if c == '/' && next == Some('*') {
                    state = Scan::Block(depth + 1);
                    out.push_str("  ");
                    i += 2;
                } else if c == '*' && next == Some('/') {
                    state = if depth == 1 {
                        Scan::Code
                    } else {
                        Scan::Block(depth - 1)
                    };
                    out.push_str("  ");
                    i += 2;
                } else {
                    blank(&mut out, c);
                    i += 1;
                }
            }
            Scan::Str | Scan::Char => {
                let closer = if matches!(state, Scan::Str) {
                    '"'
                } else {
                    '\''
                };
                if c == '\\' {
                    // Keep a line continuation's newline so line numbers hold.
                    out.push(' ');
                    if let Some(escaped) = next {
                        blank(&mut out, escaped);
                    }
                    i += 2;
                } else if c == closer {
                    state = Scan::Code;
                    out.push(' ');
                    i += 1;
                } else {
                    blank(&mut out, c);
                    i += 1;
                }
            }
            Scan::Raw(hashes) => {
                if let Some(after) = raw_string_closer(&chars, i, hashes) {
                    for _ in i..after {
                        out.push(' ');
                    }
                    state = Scan::Code;
                    i = after;
                } else {
                    blank(&mut out, c);
                    i += 1;
                }
            }
        }
    }

    out
}

/// If a raw string starts at `i`, the number of hashes and the index just past
/// the opening quote. `r` must not be the tail of an identifier.
fn raw_string_opener(chars: &[char], i: usize) -> Option<(usize, usize)> {
    if chars[i] != 'r' {
        return None;
    }
    if i > 0 && (chars[i - 1].is_alphanumeric() || chars[i - 1] == '_') {
        return None;
    }
    let mut j = i + 1;
    let mut hashes = 0;
    while chars.get(j) == Some(&'#') {
        hashes += 1;
        j += 1;
    }
    (chars.get(j) == Some(&'"')).then_some((hashes, j + 1))
}

/// If a raw string with `hashes` hashes ends at `i`, the index just past it.
fn raw_string_closer(chars: &[char], i: usize, hashes: usize) -> Option<usize> {
    if chars[i] != '"' {
        return None;
    }
    let mut j = i + 1;
    let mut seen = 0;
    while seen < hashes && chars.get(j) == Some(&'#') {
        seen += 1;
        j += 1;
    }
    (seen == hashes).then_some(j)
}

/// Distinguishes `'x'` and `'\n'` from the lifetime `'a`.
fn opens_char_literal(chars: &[char], i: usize) -> bool {
    chars.get(i + 1) == Some(&'\\') || chars.get(i + 2) == Some(&'\'')
}

fn scan(src: &str, rules: &[Forbidden], fold_case: bool) -> Vec<Violation> {
    let code = code_only(src);
    let mut found = Vec::new();
    for (index, line) in code.lines().enumerate() {
        let haystack = if fold_case {
            line.to_lowercase()
        } else {
            line.to_owned()
        };
        for rule in rules {
            if haystack.contains(rule.needle) {
                found.push(Violation {
                    line: index + 1,
                    needle: rule.needle,
                    why: rule.why,
                });
            }
        }
    }
    found
}

/// Every forbidden effect reachable in the code of one file.
fn violations_in(src: &str) -> Vec<Violation> {
    scan(src, FORBIDDEN, false)
}

/// Every vendor name appearing in the code of one file.
fn vendor_names_in(src: &str) -> Vec<Violation> {
    scan(src, VENDOR, true)
}

#[cfg(test)]
mod scanner {
    use super::{code_only, vendor_names_in, violations_in};

    #[test]
    fn a_clock_read_is_a_violation() {
        let v = violations_in("let now = SystemTime::now();");

        assert_eq!(v.len(), 1, "{v:?}");
        assert_eq!(v[0].needle, "SystemTime");
        assert_eq!(v[0].line, 1);
    }

    #[test]
    fn a_line_comment_mentioning_an_effect_is_not_a_violation() {
        assert!(violations_in("// never call SystemTime::now() here\n").is_empty());
    }

    #[test]
    fn a_doc_comment_mentioning_an_effect_is_not_a_violation() {
        // This is the case that matters most: the domain's own module docs list
        // the things it forbids, so this test is the reason the scanner needs a
        // lexer rather than a substring search.
        let src = "//! Rules: no `std::fs`, no `std::net`, no `SystemTime`.\n\
                   /// Takes a timestamp rather than reading std::env.\n\
                   pub struct Delivery;\n";

        assert!(violations_in(src).is_empty(), "{:?}", violations_in(src));
    }

    #[test]
    fn a_block_comment_mentioning_an_effect_is_not_a_violation() {
        assert!(violations_in("/* std::fs::read is forbidden */\n").is_empty());
    }

    #[test]
    fn a_nested_block_comment_is_handled() {
        let src = "/* outer /* inner std::fs */ still comment std::net */ pub struct A;\n";

        assert!(violations_in(src).is_empty(), "{:?}", violations_in(src));
    }

    #[test]
    fn a_string_literal_mentioning_an_effect_is_not_a_violation() {
        assert!(violations_in(r#"let s = "std::fs is not allowed";"#).is_empty());
    }

    #[test]
    fn a_raw_string_literal_mentioning_an_effect_is_not_a_violation() {
        let src = "let s = r#\"std::fs::read(\"x\")\"#;\n";

        assert!(violations_in(src).is_empty(), "{:?}", violations_in(src));
    }

    #[test]
    fn a_lifetime_is_not_mistaken_for_a_character_literal() {
        // If `'a` opened a char literal, the scanner would swallow the rest of
        // the file and silently find nothing — the worst possible failure for a
        // gate, because it reports success.
        let src = "fn f<'a>(x: &'a str) -> &'a str { x }\nlet t = SystemTime::now();\n";

        let v = violations_in(src);

        assert_eq!(v.len(), 1, "{v:?}");
        assert_eq!(v[0].line, 2);
    }

    #[test]
    fn a_character_literal_is_still_skipped() {
        assert!(violations_in("let c = '\"'; let d = '\\\\';\n").is_empty());
    }

    #[test]
    fn duration_is_a_value_and_not_an_effect() {
        assert!(violations_in("use std::time::Duration;\n").is_empty());
    }

    #[test]
    fn the_reported_line_is_the_line_the_effect_is_on() {
        let src = "pub struct A;\n\npub fn f() {\n    std::fs::read(\"x\");\n}\n";

        let v = violations_in(src);

        assert_eq!(v.len(), 1, "{v:?}");
        assert_eq!(v[0].line, 4);
    }

    #[test]
    fn a_vendor_name_in_code_is_a_violation() {
        let v = vendor_names_in("pub struct GitHubPush;");

        assert_eq!(v.len(), 1, "{v:?}");
        assert_eq!(v[0].needle, "github");
    }

    #[test]
    fn a_vendor_name_is_caught_whatever_its_casing() {
        assert_eq!(vendor_names_in("let x = GITHUB_EVENT;").len(), 1);
        assert_eq!(vendor_names_in("let x = github_event;").len(), 1);
    }

    #[test]
    fn a_vendor_name_in_prose_is_not_a_violation() {
        // The domain is allowed to *explain* that it does not know about
        // GitHub — signature.rs does exactly that — it just may not name it in
        // a type, a field or a function.
        let src = "/// Nothing here knows that GitHub uses HMAC-SHA256.\n\
                   pub struct Signature;\n";

        assert!(
            vendor_names_in(src).is_empty(),
            "{:?}",
            vendor_names_in(src)
        );
    }

    #[test]
    fn ordinary_english_words_are_not_treated_as_vendors() {
        // `element` and `matrix` are deliberately not banned: a gate that cries
        // wolf on honest code is a gate someone will switch off.
        let src = "for element in rows { let matrix = element; }\n";

        assert!(
            vendor_names_in(src).is_empty(),
            "{:?}",
            vendor_names_in(src)
        );
    }

    #[test]
    fn blanking_preserves_line_count_so_numbers_stay_honest() {
        let src = "a\n// comment\n/* b\nc */\nd\n";

        assert_eq!(code_only(src).lines().count(), src.lines().count());
    }
}

/// Collect `**/*.rs` under a directory.
fn rust_files(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).expect("read domain source directory") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

/// The domain crate's `src` directory, located the same way `boundaries.rs`
/// finds crates: by asking cargo, so moving the crate cannot silently turn this
/// test into a no-op over an empty directory.
fn domain_src() -> PathBuf {
    let out = Command::new(env!("CARGO"))
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .output()
        .expect("run cargo metadata");
    let meta: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("parse cargo metadata");

    let manifest = meta["packages"]
        .as_array()
        .expect("packages array")
        .iter()
        .find(|p| p["name"] == "domain")
        .map(|p| {
            p["manifest_path"]
                .as_str()
                .expect("manifest_path")
                .to_owned()
        })
        .expect("a crate named `domain` must exist");

    let src = Path::new(&manifest)
        .parent()
        .expect("crate directory")
        .join("src");
    assert!(src.is_dir(), "{} is not a directory", src.display());
    src
}

/// The core speaks its own language, or the anti-corruption layer has leaked.
#[test]
fn the_domain_names_no_vendor() {
    let src = domain_src();
    let files = rust_files(&src);
    assert!(
        !files.is_empty(),
        "no Rust files found under {}",
        src.display()
    );

    let mut reported = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).expect("read domain source file");
        let name = file
            .strip_prefix(&src)
            .unwrap_or(file)
            .display()
            .to_string();
        for v in vendor_names_in(&text) {
            reported.push(format!(
                "  {name}:{} names `{}` — {}",
                v.line, v.needle, v.why
            ));
        }
    }

    assert!(
        reported.is_empty(),
        "the domain must not name a vendor — {} occurrence(s):\n{}\n\n\
         Translation from a vendor's payload into an Event belongs in that \
         Origin's inbound adapter, and translation from an Event into whatever \
         a product accepts belongs in that Destination's adapter. Naming it \
         here makes every future Origin inherit the first one's vocabulary.",
        reported.len(),
        reported.join("\n")
    );
}

/// Test modules are **not** exempt, by decision.
///
/// A domain test that needs the clock, the filesystem or a thread is evidence
/// that the logic under test is not pure — which is the thing this gate exists
/// to catch. Exempting `#[cfg(test)]` would make the gate blind exactly where
/// the temptation is strongest, and domain tests are supposed to be the fast,
/// never-flaky ones.
#[test]
fn the_domain_reaches_for_no_effects() {
    let src = domain_src();
    let files = rust_files(&src);
    assert!(
        !files.is_empty(),
        "no Rust files found under {}",
        src.display()
    );

    let mut reported = Vec::new();
    let mut offending_files = BTreeSet::new();
    for file in &files {
        let text = std::fs::read_to_string(file).expect("read domain source file");
        let name = file
            .strip_prefix(&src)
            .unwrap_or(file)
            .display()
            .to_string();
        for v in violations_in(&text) {
            reported.push(format!(
                "  {name}:{} uses `{}` — {}",
                v.line, v.needle, v.why
            ));
            offending_files.insert(name.clone());
        }
    }

    assert!(
        reported.is_empty(),
        "the domain must stay free of effects — {} violation(s) in {} of {} \
         file(s) scanned:\n{}\n\n\
         Every one of these belongs behind a port: declare the trait in \
         `crates/application` in domain language and implement it in an \
         adapter. See the `port-and-adapter` skill. If a rule depends on \
         \"now\", take the timestamp as an argument.",
        reported.len(),
        offending_files.len(),
        files.len(),
        reported.join("\n")
    );
}
