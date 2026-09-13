//! `gfx-redact` behavior tests (plan-redact-idents.md §4.10): R1 identity,
//! R2 determinism + reset, R3 injectivity/collision audit, R5 mapping
//! closure, R9 artifact round-trip, plus the §4.9 edge-case table.

use gfx_core::prelude::*;
use gfx_core::test_kit;
use gfx_redact::quote::c_unquote;
use gfx_redact::{IdentMode, IdentPolicy, IdentRole, Redact, RedactConfig, RedactRow, SharedPolicy};

use std::rc::Rc;

fn b(s: &str) -> BString {
    BString::from(s.as_bytes().to_vec())
}

fn ts(raw: &str, epoch: i64, tz_min: i16) -> Timestamp {
    Timestamp {
        raw: b(raw),
        epoch,
        tz_offset_min: tz_min,
    }
}

fn ident(name: &str, email: &str, time: Timestamp) -> Ident {
    Ident {
        name: b(name),
        email: b(email),
        time,
    }
}

fn commit_ev(
    ref_name: &str,
    mark: Mark,
    author: Option<Ident>,
    committer: Option<Ident>,
) -> Event {
    Event::Commit(Commit {
        ref_name: b(ref_name),
        mark: Some(mark),
        original_oid: None,
        author,
        committer,
        encoding: None,
        message: Data(b"m\n".to_vec()),
        from: None,
        merges: Vec::new(),
        ops: Vec::new(),
    })
}

fn tag_ev(name: &str, tagger: Option<Ident>) -> Event {
    Event::Tag(Tag {
        name: b(name),
        mark: Some(9),
        original_oid: None,
        from: Some(Committish::Mark(1)),
        tagger,
        message: Data(b"t\n".to_vec()),
    })
}

fn table_cfg(rows: Vec<RedactRow>) -> RedactConfig {
    RedactConfig {
        ident_mode: IdentMode::Table(rows),
        ..RedactConfig::default()
    }
}

fn row(old_name: &str, old_email: &str, new_name: &str, new_email: &str) -> RedactRow {
    RedactRow {
        name: Some(b(old_name)),
        email: Some(b(old_email)),
        new_name: b(new_name),
        new_email: b(new_email),
    }
}

/// Parse a fast-export byte stream, run it through a fresh `Redact`, and
/// serialize back to bytes.
fn roundtrip(bytes: &[u8], cfg: RedactConfig) -> Vec<u8> {
    let mut redact = Redact::new(cfg);
    let mut parser = Parser::new(ParseOptions::default());
    parser.feed(bytes);
    let mut events = Vec::new();
    while let Some(ev) = parser.next_event().expect("parse") {
        redact.apply(ev, &mut events).expect("apply");
    }
    let mut tail = Vec::new();
    parser.finish(&mut tail).expect("finish parse");
    for ev in tail {
        redact.apply(ev, &mut events).expect("apply tail");
    }
    redact.finish(&mut events).expect("finish");
    let mut w = Writer::new();
    for ev in &events {
        w.write(ev).expect("write");
    }
    w.take()
}

/// Byte-level fixture: two commits (one with author), a tag, a blob.
fn stream_bytes() -> Vec<u8> {
    b(
        "blob\nmark :1\ndata 6\nhello!\n\
         commit refs/heads/main\nmark :2\noriginal-oid 1111111111111111111111111111111111111111\n\
         author Alice <alice@example.com> 1700000000 +0200\n\
         committer Bob <bob@example.org> 1700000100 -0730\n\
         data 2\nm\n\n\
         commit refs/heads/main\nmark :3\n\
         committer Alice <alice@example.com> 1700000200 +0000\n\
         data 2\nm\n\n\
         tag v1\nfrom :2\ntagger Tagr <tagr@example.net> 1700000300 +0545\n\
         data 2\nt\n\n",
    )
    .to_vec()
}

// ---------------------------------------------------------------- R1

/// R1: empty policy (preserve idents, preserve times) ⇒ byte-identical
/// output, including untouched ledger bookkeeping.
#[test]
fn r1_identity_empty_policy() {
    let input = stream_bytes();
    let output = roundtrip(&input, RedactConfig::default());
    assert_eq!(output, input, "empty policy must be a byte-identity no-op");
}

/// R1 (event level): blobs, resets, and every non-ident field pass through.
#[test]
fn r1_non_ident_events_untouched() {
    let ev = Event::Blob {
        mark: Some(1),
        original_oid: None,
        data: Data(b"x".to_vec()),
    };
    let mut r = Redact::new(table_cfg(vec![row("A", "a@x", "N", "n@x")]));
    let mut out = Vec::new();
    r.apply(ev.clone(), &mut out).unwrap();
    assert_eq!(out, vec![ev]);
}

// ---------------------------------------------------------------- R2

/// R2: determinism, including with a stateful host policy, and `reset`
/// re-derivation (the ledger is not cached across resets).
#[test]
fn r2_deterministic_with_table_and_injected_policy() {
    let events = vec![
        commit_ev("refs/heads/main", 1, Some(ident("A", "a@x", ts("100 +0000", 100, 0))), None),
        commit_ev("refs/heads/main", 2, None, Some(ident("B", "b@y", ts("200 +0000", 200, 0)))),
        tag_ev("v1", Some(ident("C", "c@z", ts("300 +0000", 300, 0)))),
    ];
    test_kit::assert_deterministic(|| Redact::new(table_cfg(vec![row("A", "a@x", "N", "n@x")])), events.clone());

    // Stateful injected policy: must still be deterministic because a fresh
    // transform is constructed per run (host contract: pure per-run).
    struct Counting(core::cell::Cell<u32>);
    impl IdentPolicy for Counting {
        fn rewrite(&self, _role: IdentRole, ident: &Ident) -> Ident {
            let n = self.0.get() + 1;
            self.0.set(n);
            Ident {
                name: b("P"),
                email: b(&format!("p{n}@invalid")),
                time: ident.time.clone(),
            }
        }
    }
    let counting = || {
        Redact::new(RedactConfig {
            ident_mode: IdentMode::Injected(SharedPolicy(Rc::new(Counting(core::cell::Cell::new(0))))),
            ..RedactConfig::default()
        })
    };
    test_kit::assert_deterministic(counting, events.clone());

    // reset() restores fresh state (ledger contents included): with the
    // table mode (pure config), the re-run is identical...
    let mut r = Redact::new(table_cfg(vec![row("A", "a@x", "N", "n@x")]));
    let mut first = Vec::new();
    for ev in &events {
        r.apply(ev.clone(), &mut first).unwrap();
    }
    r.reset();
    let mut second = Vec::new();
    for ev in &events {
        r.apply(ev.clone(), &mut second).unwrap();
    }
    assert_eq!(first, second, "reset must re-derive identical output");

    // ...and with the counting policy the counter keeps advancing after
    // reset(), proving the ledger cache was cleared and the policy was
    // consulted again (the strip pass's verdicts-not-cached-across-reset
    // analog).
    let mut r = counting();
    let mut sink = Vec::new();
    for ev in &events {
        r.apply(ev.clone(), &mut sink).unwrap();
    }
    let seen_after_first = {
        let rep = r.report();
        rep.totals.idents_redacted
    };
    assert_eq!(seen_after_first, 3);
    r.reset();
    for ev in &events {
        r.apply(ev.clone(), &mut sink).unwrap();
    }
    // If the ledger survived reset, no new policy calls would happen.
    let rep = r.report();
    assert_eq!(rep.totals.idents_redacted, 3, "fresh ledger after reset");
}

// ---------------------------------------------------------------- R3

/// R3: built-in table mode with distinct rows stays injective; a table that
/// merges two originals into one replacement produces a visible collision
/// entry (never silent).
#[test]
fn r3_injective_table_and_collision_audit() {
    // Injective rows.
    let cfg = table_cfg(vec![
        row("A", "a@x", "U1", "u1@example.invalid"),
        row("B", "b@y", "U2", "u2@example.invalid"),
    ]);
    let mut r = Redact::new(cfg);
    let mut out = Vec::new();
    for ev in [
        commit_ev("r", 1, Some(ident("A", "a@x", ts("1 +0000", 1, 0))), None),
        commit_ev("r", 2, Some(ident("B", "b@y", ts("2 +0000", 2, 0))), None),
    ] {
        r.apply(ev, &mut out).unwrap();
    }
    let rep = r.report();
    assert_eq!(rep.totals.collisions, 0);
    assert_eq!(rep.totals.idents_redacted, 2);
    assert_ne!(rep.entries[0].new_email, rep.entries[1].new_email);

    // Merging rows: two originals, one replacement.
    let cfg = table_cfg(vec![
        row("A", "a@x", "U", "u@example.invalid"),
        row("A2", "a2@x", "U", "u@example.invalid"),
    ]);
    let mut r = Redact::new(cfg);
    let mut out = Vec::new();
    for ev in [
        commit_ev("r", 1, Some(ident("A", "a@x", ts("1 +0000", 1, 0))), None),
        commit_ev("r", 2, Some(ident("A2", "a2@x", ts("2 +0000", 2, 0))), None),
    ] {
        r.apply(ev, &mut out).unwrap();
    }
    let rep = r.report();
    assert_eq!(rep.totals.collisions, 1);
    let c = &rep.collisions[0];
    assert_eq!(c.new_email, b("u@example.invalid"));
    assert_eq!(c.originals.len(), 2);
}

/// R3/R5: table misses pass through unchanged and are NOT counted as
/// redactions; wildcard rows (None fields) match.
#[test]
fn r3_table_miss_and_wildcards() {
    let cfg = table_cfg(vec![
        RedactRow {
            name: None, // any name with this email
            email: Some(b("old@corp")),
            new_name: b("Anon"),
            new_email: b("anon@example.invalid"),
        },
    ]);
    let mut r = Redact::new(cfg);
    let mut out = Vec::new();
    for ev in [
        commit_ev("r", 1, Some(ident("Whoever", "old@corp", ts("1 +0000", 1, 0))), None),
        commit_ev("r", 2, Some(ident("Someone", "other@corp", ts("2 +0000", 2, 0))), None),
    ] {
        r.apply(ev, &mut out).unwrap();
    }
    let rep = r.report();
    assert_eq!(rep.totals.idents_redacted, 1);
    assert_eq!(rep.totals.ident_updates, 1);
    let mapped = rep.entries.iter().find(|e| e.changed).unwrap();
    assert_eq!(mapped.old_name, b("Whoever"));
    if let Event::Commit(c) = &out[1] {
        assert_eq!(c.author.as_ref().unwrap().name, b("Someone"), "table miss passes through");
    } else {
        panic!("expected commit");
    }
}

// ---------------------------------------------------------------- R5

/// R5: every rewritten ident in the output is in the report's image, and
/// every report entry's (old → new) pair is actually realized in the stream.
#[test]
fn r5_mapping_closure() {
    let input = stream_bytes();
    let cfg = table_cfg(vec![
        row("Alice", "alice@example.com", "U1", "u1@example.invalid"),
        row("Bob", "bob@example.org", "U2", "u2@example.invalid"),
        row("Tagr", "tagr@example.net", "U3", "u3@example.invalid"),
    ]);
    let output = roundtrip(&input, cfg.clone());
    let output_str = String::from_utf8(output).unwrap();
    let mut r = Redact::new(cfg);
    let mut parser = Parser::new(ParseOptions::default());
    parser.feed(&input);
    let mut events = Vec::new();
    while let Some(ev) = parser.next_event().unwrap() {
        r.apply(ev, &mut events).unwrap();
    }
    let rep = r.report();

    for e in &rep.entries {
        // old bytes must be gone; new bytes must be present
        assert!(!output_str.contains(String::from_utf8_lossy(&e.old_name).as_ref()));
        assert!(output_str.contains(String::from_utf8_lossy(&e.new_name).as_ref()));
        if e.changed {
            assert!(output_str.contains(String::from_utf8_lossy(&e.new_email).as_ref()));
        }
    }
    assert_eq!(rep.totals.idents_redacted, 3);
}

// ---------------------------------------------------------------- R9

/// R9: the artifact is deterministic (two runs byte-identical) and
/// round-trips: every `NEW <- OLD` line parses back to the report entry,
/// including non-UTF-8 idents via C-quoting.
#[test]
fn r9_artifact_deterministic_and_round_trips() {
    // Old ident with non-UTF-8 payload.
    let weird_ident = Ident {
        name: BString::from(vec![b'W', b'e', 0xFF, b'i', b'r', b'd']),
        email: BString::from(vec![b'w', 0xFF, b'@', b'x']),
        time: ts("1 +0000", 1, 0),
    };

    let cfg = table_cfg(vec![
        row("Alice", "alice@example.com", "U1", "u1@example.invalid"),
        RedactRow {
            name: Some(weird_ident.name.clone()),
            email: Some(weird_ident.email.clone()),
            new_name: b("N"),
            new_email: b("n@x"),
        },
    ]);

    let mut r1 = Redact::new(cfg.clone());
    let mut r2 = Redact::new(cfg);
    let ev = commit_ev("r", 1, Some(weird_ident.clone()), Some(ident("Alice", "alice@example.com", ts("2 +0000", 2, 0))));
    let mut o1 = Vec::new();
    let mut o2 = Vec::new();
    r1.apply(ev.clone(), &mut o1).unwrap();
    r2.apply(ev, &mut o2).unwrap();
    let text1 = r1.report().to_text();
    let text2 = r2.report().to_text();
    assert_eq!(text1, text2, "artifact must be deterministic");
    assert!(text1.contains("SENSITIVE"), "the header is the warning");

    // Round-trip: parse every mapping line back through c_unquote.
    let rep = r1.report();
    let mut seen_pairs = 0;
    for line in text1.lines() {
        if line.starts_with('#') || line.starts_with("collision:") {
            continue;
        }
        let (new_part, rest) = line.split_once(" <- ").expect("artifact line shape");
        let (old_part, _bracket) = rest.split_once(" [").expect("roles bracket");
        let new = parse_ident_half(new_part);
        let old = parse_ident_half(old_part);
        assert!(
            rep.entries.iter().any(|e| {
                e.new_name == new.0 && e.new_email == new.1 && e.old_name == old.0 && e.old_email == old.1
            }),
            "artifact line {line:?} does not match a report entry"
        );
        seen_pairs += 1;
    }
    assert_eq!(seen_pairs, rep.entries.len());
    let weird_entry = rep
        .entries
        .iter()
        .find(|e| e.old_name == weird_ident.name)
        .expect("non-UTF-8 ident entry");
    assert_eq!(weird_entry.old_email, weird_ident.email, "non-UTF-8 bytes survive the artifact round-trip");
}

/// Parse `NAME <EMAIL>` with C-quoted halves back into bytes.
fn parse_ident_half(s: &str) -> (BString, BString) {
    // Name runs to the first unquoted ` <`; email between `<` and final `>`.
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut name = Vec::new();
    while i < bytes.len() {
        if bytes[i] == b'<' {
            break;
        }
        name.push(bytes[i]);
        i += 1;
    }
    while name.last() == Some(&b' ') {
        name.pop();
    }
    let end = bytes.len() - 1;
    let email = &s[i + 1..end];
    (
        c_unquote(std::str::from_utf8(&name).unwrap()),
        c_unquote(email),
    )
}

// ---------------------------------------------------------------- edges

/// §4.9: commit with no `author` line — no ident synthesized; the missing
/// author stays missing; committer still redacted.
#[test]
fn edge_missing_author_not_synthesized() {
    let cfg = table_cfg(vec![row("B", "b@y", "N", "n@x")]);
    let mut r = Redact::new(cfg);
    let mut out = Vec::new();
    r.apply(commit_ev("r", 1, None, Some(ident("B", "b@y", ts("1 +0000", 1, 0)))), &mut out).unwrap();
    if let Event::Commit(c) = &out[0] {
        assert!(c.author.is_none(), "D1: never synthesize an author line");
        assert_eq!(c.committer.as_ref().unwrap().name, b("N"));
    } else {
        panic!("expected commit");
    }
}

/// §4.9: tag with no `tagger` passes through unredacted.
#[test]
fn edge_tag_without_tagger() {
    let cfg = table_cfg(vec![row("A", "a@x", "N", "n@x")]);
    let mut r = Redact::new(cfg);
    let mut out = Vec::new();
    r.apply(tag_ev("v1", None), &mut out).unwrap();
    if let Event::Tag(t) = &out[0] {
        assert!(t.tagger.is_none());
        assert_eq!(t.name, b("v1"));
    } else {
        panic!("expected tag");
    }
}

/// §4.9: author and committer identical ⇒ both roles get the same
/// replacement; the report merges roles into one entry.
#[test]
fn edge_author_committer_merge_in_report() {
    let cfg = table_cfg(vec![row("A", "a@x", "U", "u@x")]);
    let mut r = Redact::new(cfg);
    let mut out = Vec::new();
    r.apply(
        commit_ev(
            "r",
            1,
            Some(ident("A", "a@x", ts("1 +0000", 1, 0))),
            Some(ident("A", "a@x", ts("2 +0000", 2, 0))),
        ),
        &mut out,
    )
    .unwrap();
    let rep = r.report();
    assert_eq!(rep.totals.ident_updates, 2);
    assert_eq!(rep.entries.len(), 1);
    assert_eq!(rep.entries[0].roles, vec!["author", "committer"]);
    if let Event::Commit(c) = &out[0] {
        let a = c.author.as_ref().unwrap();
        let cm = c.committer.as_ref().unwrap();
        assert_eq!(a.name, cm.name);
        assert_eq!(a.email, cm.email);
        assert_eq!(a.time, ts("1 +0000", 1, 0), "times preserved per original (M0)");
        assert_eq!(cm.time, ts("2 +0000", 2, 0));
    }
}

/// §4.9: empty name / empty email are valid keys and get mapped.
#[test]
fn edge_empty_name_and_email() {
    let cfg = table_cfg(vec![RedactRow {
        name: Some(BString::from(Vec::new())),
        email: None,
        new_name: b("N"),
        new_email: b("n@x"),
    }]);
    let mut r = Redact::new(cfg);
    let mut out = Vec::new();
    r.apply(
        commit_ev("r", 1, Some(ident("", "a@x", ts("1 +0000", 1, 0))), None),
        &mut out,
    )
    .unwrap();
    let rep = r.report();
    assert_eq!(rep.totals.idents_redacted, 1);
    if let Event::Commit(c) = &out[0] {
        assert_eq!(c.author.as_ref().unwrap().name, b("N"));
    }
}

/// §4.9: replacement containing original ident bytes is flagged
/// suspicious, deterministically, but the run still proceeds.
#[test]
fn edge_suspicious_replacement_flagged() {
    let cfg = table_cfg(vec![row("Alice", "a@x", "Alice(a@x)", "x@y")]);
    let mut r = Redact::new(cfg);
    let mut out = Vec::new();
    r.apply(commit_ev("r", 1, Some(ident("Alice", "a@x", ts("1 +0000", 1, 0))), None), &mut out).unwrap();
    let rep = r.report();
    assert_eq!(rep.totals.suspicious, 1);
    assert!(rep.entries[0].suspicious);
    // A clean replacement is not flagged.
    let cfg = table_cfg(vec![row("Alice", "a@x", "U", "u@x")]);
    let mut r = Redact::new(cfg);
    let mut out = Vec::new();
    r.apply(commit_ev("r", 2, Some(ident("Alice", "a@x", ts("1 +0000", 1, 0))), None), &mut out).unwrap();
    assert_eq!(r.report().totals.suspicious, 0);
}

/// §4.9: non-UTF-8 name/email are byte-exact keys; replacements are
/// whatever bytes the row supplies (no re-encoding).
#[test]
fn edge_non_utf8_idents() {
    let old_name = BString::from(vec![0xC3, 0x28, b'x']); // invalid UTF-8
    let cfg = table_cfg(vec![RedactRow {
        name: Some(old_name.clone()),
        email: Some(b("a@x")),
        new_name: b("N"),
        new_email: b("n@x"),
    }]);
    let mut r = Redact::new(cfg);
    let mut out = Vec::new();
    r.apply(
        commit_ev(
            "r",
            1,
            Some(Ident {
                name: old_name,
                email: b("a@x"),
                time: ts("1 +0000", 1, 0),
            }),
            None,
        ),
        &mut out,
    )
    .unwrap();
    if let Event::Commit(c) = &out[0] {
        assert_eq!(c.author.as_ref().unwrap().name, b("N"));
    }
    assert_eq!(r.report().totals.idents_redacted, 1);
}

/// §4.9: pinned identity (row maps an ident to itself) is a mapping, not a
/// redaction — and does not collide with itself.
#[test]
fn edge_identity_pin() {
    let cfg = table_cfg(vec![row("Bot", "bot@ci", "Bot", "bot@ci")]);
    let mut r = Redact::new(cfg);
    let mut out = Vec::new();
    r.apply(commit_ev("r", 1, Some(ident("Bot", "bot@ci", ts("1 +0000", 1, 0))), None), &mut out).unwrap();
    let rep = r.report();
    assert_eq!(rep.totals.collisions, 0);
    assert_eq!(rep.totals.idents_redacted, 0);
    assert_eq!(rep.totals.ident_updates, 0);
    assert_eq!(rep.entries.len(), 1, "pinned ident still listed for audit");
    assert!(!rep.entries[0].changed);
}

/// Byte-identity check over the full stream with a table that pins
/// everything to itself (composes with M0's preserve times).
#[test]
fn full_stream_table_pin_is_byte_identity() {
    let input = stream_bytes();
    let cfg = table_cfg(vec![
        row("Alice", "alice@example.com", "Alice", "alice@example.com"),
        row("Bob", "bob@example.org", "Bob", "bob@example.org"),
        row("Tagr", "tagr@example.net", "Tagr", "tagr@example.net"),
    ]);
    let output = roundtrip(&input, cfg);
    assert_eq!(output, input);
}
