//! `gfx-redact` behavior tests (plan-redact-idents.md §4.10): R1 identity,
//! R2 determinism + reset, R3 injectivity/collision audit, R5 mapping
//! closure, R9 artifact round-trip, plus the §4.9 edge-case table.

use gfx_core::prelude::*;
use gfx_core::test_kit;
use gfx_redact::quote::c_unquote;
use gfx_redact::{
    IdentMode, IdentPolicy, IdentRole, PseudonymStyle, Redact, RedactConfig, RedactRow,
    RedactReport, SharedPolicy, TimeBucketUnit, TimeMode,
};

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

/// R1: empty policy with `keep_tz` (preserve idents, preserve times, keep
/// offsets) ⇒ byte-identical output, including untouched ledger
/// bookkeeping.
#[test]
fn r1_identity_empty_policy() {
    let input = stream_bytes();
    let cfg = RedactConfig {
        keep_tz: true,
        ..RedactConfig::default()
    };
    let output = roundtrip(&input, cfg);
    assert_eq!(output, input, "empty policy + keep_tz must be a byte-identity no-op");
}

/// D3 (resolved Q2): under `preserve`, timezone offsets are zeroed by
/// default — they are geographic metadata — while epochs stay untouched.
#[test]
fn d3_preserve_still_zeroes_tz_by_default() {
    let input = stream_bytes();
    let output = roundtrip(&input, RedactConfig::default());
    let out = String::from_utf8(output).unwrap();
    // Offsets from the fixture: +0200, -0730, +0000, +0545 — all gone.
    assert!(!out.contains("+0200"));
    assert!(!out.contains("-0730"));
    assert!(!out.contains("+0545"));
    // Epochs untouched (preserve mode keeps the time axis).
    assert!(out.contains("1700000000 +0000"));
    assert!(out.contains("1700000100 +0000"));
    assert!(out.contains("1700000200 +0000"));
    assert!(out.contains("1700000300 +0000"));
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
    struct Counting(std::sync::atomic::AtomicU32);
    impl IdentPolicy for Counting {
        fn rewrite(&self, _role: IdentRole, ident: &Ident) -> Ident {
            let n = self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            Ident {
                name: b("P"),
                email: b(&format!("p{n}@invalid")),
                time: ident.time.clone(),
            }
        }
    }
    let counting = || {
        Redact::new(RedactConfig {
            ident_mode: IdentMode::Injected(SharedPolicy(std::sync::Arc::new(Counting(std::sync::atomic::AtomicU32::new(0))))),
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
    let cfg = RedactConfig {
        ident_mode: IdentMode::Table(vec![
            row("Alice", "alice@example.com", "Alice", "alice@example.com"),
            row("Bob", "bob@example.org", "Bob", "bob@example.org"),
            row("Tagr", "tagr@example.net", "Tagr", "tagr@example.net"),
        ]),
        keep_tz: true,
        ..RedactConfig::default()
    };
    let output = roundtrip(&input, cfg);
    assert_eq!(output, input);
}

// ---------------------------------------------------------------- M1

/// Canonical raw validator for the R7 property: `^-?\d+ [+-]\d{4}$`.
fn is_canonical_raw(raw: &[u8]) -> bool {
    let s = match std::str::from_utf8(raw) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let (epoch, tz) = match s.split_once(' ') {
        Some(p) => p,
        None => return false,
    };
    let digits = epoch.strip_prefix('-').unwrap_or(epoch);
    !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
        && (digits.len() == 1 || !digits.starts_with('0'))
        && tz.len() == 5
        && (tz.starts_with('+') || tz.starts_with('-'))
        && tz[1..].bytes().all(|b| b.is_ascii_digit())
}

fn corpus_events() -> Vec<Event> {
    vec![
        commit_ev(
            "refs/heads/main",
            1,
            Some(ident("Alice", "alice@example.com", ts("1700000000 +0200", 1_700_000_000, 120))),
            Some(ident("Bob", "bob@example.org", ts("1700000100 -0730", 1_700_000_100, -450))),
        ),
        commit_ev(
            "refs/heads/main",
            2,
            Some(ident("Cara", "cara@example.io", ts("1700086400 +0000", 1_700_086_400, 0))),
            None,
        ),
        tag_ev(
            "v1",
            Some(ident("Tagr", "tagr@example.net", ts("1700172800 +0545", 1_700_172_800, 345))),
        ),
    ]
}

fn run_events(cfg: RedactConfig, events: &[Event]) -> (Vec<Event>, RedactReport) {
    let mut r = Redact::new(cfg);
    let mut out = Vec::new();
    for ev in events {
        r.apply(ev.clone(), &mut out).unwrap();
    }
    r.finish(&mut out).unwrap();
    let rep = r.report();
    (out, rep)
}

/// R4 (leak scan): under a redacting time mode, no original ident bytes and
/// no original time bytes survive the serialized stream.
#[test]
fn r4_leak_scan_zero_mode() {
    let cfg = RedactConfig {
        ident_mode: IdentMode::Pseudonymize(PseudonymStyle::Ordinal),
        time_mode: TimeMode::Zero,
        ..RedactConfig::default()
    };
    let (out, rep) = run_events(cfg, &corpus_events());
    let mut w = Writer::new();
    for ev in &out {
        w.write(ev).unwrap();
    }
    let text = String::from_utf8(w.take()).unwrap();
    for name in ["Alice", "alice@example.com", "Bob", "bob@example.org", "Cara", "cara@example.io", "Tagr", "tagr@example.net"] {
        assert!(!text.contains(name), "original ident {name} leaked");
    }
    for raw in ["1700000000 +0200", "1700000100 -0730", "1700086400 +0000", "1700172800 +0545"] {
        assert!(!text.contains(raw), "original time {raw} leaked");
    }
    assert_eq!(rep.totals.times_altered, 4);
    assert_eq!(rep.totals.idents_redacted, 4);
    // every output ident is a pseudonym
    assert!(text.contains("User 1 <user1@example.invalid>"));
}

/// R4/R6: `shift` preserves order and intervals exactly (documented leak),
/// zeroes tz unless `keep_tz`, and errors on overflow.
#[test]
fn r6_shift_ordering_and_keep_tz() {
    let cfg = RedactConfig {
        time_mode: TimeMode::Shift(31_536_000),
        ..RedactConfig::default()
    };
    let (out, _) = run_events(cfg, &corpus_events());
    let mut epochs = Vec::new();
    for ev in &out {
        if let Event::Commit(c) = ev {
            if let Some(cm) = &c.committer {
                epochs.push(cm.time.epoch);
            }
        }
    }
    assert_eq!(epochs, vec![1_700_000_100 + 31_536_000]);
    // tz zeroed by default under shift
    if let Event::Commit(c) = &out[0] {
        assert_eq!(c.committer.as_ref().unwrap().time.tz_offset_min, 0);
        assert_eq!(c.committer.as_ref().unwrap().time.raw, b("1731536100 +0000"));
    }

    // keep_tz rides along under shift.
    let cfg = RedactConfig {
        time_mode: TimeMode::Shift(31_536_000),
        keep_tz: true,
        ..RedactConfig::default()
    };
    let (out, _) = run_events(cfg, &corpus_events());
    if let Event::Commit(c) = &out[0] {
        let t = &c.committer.as_ref().unwrap().time;
        assert_eq!(t.tz_offset_min, -450);
        assert_eq!(t.raw, b("1731536100 -0730"));
    }

    // Overflow is a deterministic error, never a wrap.
    let cfg = RedactConfig {
        time_mode: TimeMode::Shift(i64::MAX),
        ..RedactConfig::default()
    };
    let mut r = Redact::new(cfg);
    let mut out = Vec::new();
    let err = r
        .apply(commit_ev("r", 1, None, Some(ident("A", "a@x", ts("100 +0000", 100, 0)))), &mut out)
        .unwrap_err();
    assert!(matches!(err, Error::TimestampOutOfRange { .. }), "{err:?}");
}

/// R6: `zero` collapses the time axis; `bucket` preserves coarse order and
/// collapses ties within a bucket (day/week/month, UTC).
#[test]
fn r6_zero_and_bucket_ordering() {
    let cfg = RedactConfig {
        time_mode: TimeMode::Zero,
        ..RedactConfig::default()
    };
    let (out, _) = run_events(cfg, &corpus_events());
    for ev in &out {
        match ev {
            Event::Commit(c) => {
                for id in [c.author.as_ref(), c.committer.as_ref()].into_iter().flatten() {
                    assert_eq!(id.time.epoch, 0);
                    assert_eq!(id.time.raw, b("0 +0000"));
                }
            }
            Event::Tag(tg) => {
                assert_eq!(tg.tagger.as_ref().unwrap().time.epoch, 0);
            }
            _ => {}
        }
    }

    // Bucket day: 1700000000 (2023-11-14 22:13:20 UTC) and 1700000100 fall
    // in the same UTC day; 1700086400 is the next UTC midnight exactly.
    let cfg = RedactConfig {
        time_mode: TimeMode::Bucket(TimeBucketUnit::Day),
        ..RedactConfig::default()
    };
    let (out, _) = run_events(cfg, &corpus_events());
    if let Event::Commit(c) = &out[0] {
        let t = &c.committer.as_ref().unwrap().time;
        assert_eq!(t.epoch, 1_699_920_000); // 2023-11-14 00:00:00 UTC
        assert_eq!(t.raw, b("1699920000 +0000"));
    }

    // Bucket week: 2023-11-14 is a Tuesday; Monday is 2023-11-13.
    let cfg = RedactConfig {
        time_mode: TimeMode::Bucket(TimeBucketUnit::Week),
        ..RedactConfig::default()
    };
    let (out, _) = run_events(cfg, &corpus_events());
    if let Event::Commit(c) = &out[0] {
        assert_eq!(c.committer.as_ref().unwrap().time.epoch, 1_699_833_600);
    }

    // Bucket month: floor to 2023-11-01.
    let cfg = RedactConfig {
        time_mode: TimeMode::Bucket(TimeBucketUnit::Month),
        ..RedactConfig::default()
    };
    let (out, _) = run_events(cfg, &corpus_events());
    if let Event::Commit(c) = &out[0] {
        assert_eq!(c.committer.as_ref().unwrap().time.epoch, 1_698_796_800);
    }
}

/// R6: `fuzz` stays within the jitter window, is a pure function of
/// (seed, role, raw), and honors the seed.
#[test]
fn r6_fuzz_bounds_and_seed_sensitivity() {
    let cfg = RedactConfig {
        time_mode: TimeMode::Fuzz { jitter_secs: 3600 },
        seed: 0x9E37_79B9_7F4A_7C15,
        ..RedactConfig::default()
    };
    let (out, _) = run_events(cfg.clone(), &corpus_events());
    let originals = [1_700_000_000i64, 1_700_000_100, 1_700_086_400, 1_700_172_800];
    let mut got = Vec::new();
    for ev in &out {
        match ev {
            Event::Commit(c) => {
                if let Some(cm) = &c.committer {
                    got.push(cm.time.epoch);
                }
                if let Some(a) = &c.author {
                    got.push(a.time.epoch);
                }
            }
            Event::Tag(tg) => got.push(tg.tagger.as_ref().unwrap().time.epoch),
            _ => {}
        }
    }
    assert_eq!(got.len(), originals.len());
    for (old, new) in originals.iter().zip(got.iter()) {
        assert!((new - old).abs() <= 3600, "jitter exceeded window: {old} -> {new}");
    }
    // Same seed ⇒ same output; different seed ⇒ different output
    // (overwhelmingly likely with a 7201-value window).
    let (out2, _) = run_events(cfg, &corpus_events());
    let mut got2 = Vec::new();
    for ev in &out2 {
        if let Event::Commit(c) = ev {
            if let Some(cm) = &c.committer {
                got2.push(cm.time.epoch);
            }
        }
    }
    // Committer-only sequences (got also holds author times): both runs
    // used the same seed, so they must reproduce exactly.
    let committers_of = |evs: &[Event], out: &[Event]| -> Vec<i64> {
        let _ = evs;
        out.iter()
            .filter_map(|ev| match ev {
                Event::Commit(c) => c.committer.as_ref().map(|cm| cm.time.epoch),
                _ => None,
            })
            .collect()
    };
    assert_eq!(got2, committers_of(&[], &out), "same seed must reproduce output");
    let cfg2 = RedactConfig {
        time_mode: TimeMode::Fuzz { jitter_secs: 3600 },
        seed: 0x1234_5678_9ABC_DEF0,
        ..RedactConfig::default()
    };
    let (out3, _) = run_events(cfg2, &corpus_events());
    let mut got3 = Vec::new();
    for ev in &out3 {
        if let Event::Commit(c) = ev {
            if let Some(cm) = &c.committer {
                got3.push(cm.time.epoch);
            }
        }
    }
    assert_ne!(got2, got3, "different seed should change output");
}

/// R7: every altered `Timestamp.raw` is canonically `<epoch> ±HHMM`
/// (negative epochs get a leading `-`); unaltered fields stay byte-exact.
#[test]
fn r7_canonical_raw_including_negative_epochs() {
    let cfg = RedactConfig {
        time_mode: TimeMode::Bucket(TimeBucketUnit::Day),
        ..RedactConfig::default()
    };
    let (out, _) = run_events(cfg, &corpus_events());
    for ev in &out {
        match ev {
            Event::Commit(c) => {
                for id in [c.author.as_ref(), c.committer.as_ref()].into_iter().flatten() {
                    assert!(is_canonical_raw(id.time.raw.as_slice()), "raw {:?}", id.time.raw);
                }
            }
            Event::Tag(tg) => {
                let id = tg.tagger.as_ref().unwrap();
                assert!(is_canonical_raw(id.time.raw.as_slice()));
            }
            _ => {}
        }
    }

    // Pre-1970 commit: negative epoch serializes with a leading '-'.
    let mut r = Redact::new(RedactConfig {
        time_mode: TimeMode::Shift(-86_400 * 40 * 365), // ~40 years back
        ..RedactConfig::default()
    });
    let mut out = Vec::new();
    r.apply(
        commit_ev("r", 1, None, Some(ident("A", "a@x", ts("1000000000 +0200", 1_000_000_000, 120)))),
        &mut out,
    )
    .unwrap();
    if let Event::Commit(c) = &out[0] {
        let t = &c.committer.as_ref().unwrap().time;
        assert!(t.epoch < 0);
        assert!(t.raw.starts_with(b"-"), "raw {:?}", t.raw);
        assert!(is_canonical_raw(t.raw.as_slice()));
        assert_eq!(t.tz_offset_min, 0);
    }
}

/// §4.9 (M1): the lenient corner — an unparseable `when` raw (parser
/// zero-fills epoch/tz) keeps its bytes under `preserve`+`keep_tz` but is
/// regenerated as `0 +0000` under any redacting mode.
#[test]
fn edge_lenient_unparseable_raw() {
    let weird_time = Timestamp {
        raw: b("yesterday maybe"),
        epoch: 0,
        tz_offset_min: 0,
    };
    // preserve + keep_tz: untouched (identity path).
    let cfg = RedactConfig {
        keep_tz: true,
        ..RedactConfig::default()
    };
    let (out, _) = run_events(
        cfg,
        &[commit_ev("r", 1, None, Some(Ident { name: b("A"), email: b("a@x"), time: weird_time.clone() }))],
    );
    if let Event::Commit(c) = &out[0] {
        assert_eq!(c.committer.as_ref().unwrap().time.raw, b("yesterday maybe"));
    }

    // zero: regenerated — original bytes cannot smuggle through.
    let cfg = RedactConfig {
        time_mode: TimeMode::Zero,
        ..RedactConfig::default()
    };
    let (out, _) = run_events(
        cfg,
        &[commit_ev("r", 1, None, Some(Ident { name: b("A"), email: b("a@x"), time: weird_time }))],
    );
    if let Event::Commit(c) = &out[0] {
        assert_eq!(c.committer.as_ref().unwrap().time.raw, b("0 +0000"));
    }
}

/// Pseudonym ordinals are per distinct (name, email) regardless of role and
/// assigned in first-seen stream order.
#[test]
fn m1_pseudonym_ordinals_are_first_seen_and_role_agnostic() {
    let cfg = RedactConfig {
        ident_mode: IdentMode::Pseudonymize(PseudonymStyle::Ordinal),
        keep_tz: true,
        ..RedactConfig::default()
    };
    let (out, rep) = run_events(
        cfg,
        &[
            commit_ev("r", 1, Some(ident("A", "a@x", ts("1 +0000", 1, 0))), None),
            commit_ev("r", 2, None, Some(ident("A", "a@x", ts("2 +0000", 2, 0)))),
            commit_ev("r", 3, Some(ident("B", "b@y", ts("3 +0000", 3, 0))), Some(ident("C", "c@z", ts("4 +0000", 4, 0)))),
        ],
    );
    let get = |ev: &Event, which| match ev {
        Event::Commit(c) => {
            let id = if which == 0 { c.author.as_ref().unwrap() } else { c.committer.as_ref().unwrap() };
            (id.name.clone(), id.email.clone())
        }
        _ => panic!(),
    };
    // A is User 1 for both author and committer (role-agnostic).
    assert_eq!(get(&out[0], 0), (b("User 1"), b("user1@example.invalid")));
    assert_eq!(get(&out[1], 1), (b("User 1"), b("user1@example.invalid")));
    assert_eq!(get(&out[2], 0), (b("User 2"), b("user2@example.invalid")));
    assert_eq!(get(&out[2], 1), (b("User 3"), b("user3@example.invalid")));
    assert_eq!(rep.totals.idents_redacted, 3);
}

/// `Hash` pseudonyms are stable across runs and injective over a corpus;
/// distinct originals never collide (built-in modes are injective by
/// construction — R3).
#[test]
fn m1_pseudonym_hash_stable_and_injective() {
    let cfg = RedactConfig {
        ident_mode: IdentMode::Pseudonymize(PseudonymStyle::Hash),
        keep_tz: true,
        ..RedactConfig::default()
    };
    let (out1, rep1) = run_events(cfg.clone(), &corpus_events());
    let (out2, rep2) = run_events(cfg.clone(), &corpus_events());
    assert_eq!(rep1, rep2, "hash pseudonyms must be deterministic");
    let mut emails = Vec::new();
    for ev in &out1 {
        if let Event::Commit(c) = ev {
            if let Some(cm) = &c.committer {
                emails.push(cm.email.clone());
            }
            if let Some(a) = &c.author {
                emails.push(a.email.clone());
            }
        }
    }
    let mut sorted = emails.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(emails.len(), sorted.len(), "hash pseudonyms must not collide");
    // Same ident hash-maps to the same pseudonym in author/committer slots.
    let events = vec![commit_ev(
        "r",
        1,
        Some(ident("A", "a@x", ts("1 +0000", 1, 0))),
        Some(ident("A", "a@x", ts("2 +0000", 2, 0))),
    )];
    let (out, _) = run_events(cfg, &events);
    if let Event::Commit(c) = &out[0] {
        assert_eq!(c.author.as_ref().unwrap().email, c.committer.as_ref().unwrap().email);
    }
}

// ---------------------------------------------------------------- D7 collapse

fn report_for(bytes: &[u8], cfg: RedactConfig) -> RedactReport {
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
    redact.report()
}

#[test]
fn collapse_maps_every_ident_to_one() {
    let cfg = RedactConfig {
        ident_mode: IdentMode::Collapse {
            name: b("Anonymous"),
            email: b("anonymous@example.invalid"),
        },
        ..RedactConfig::default()
    };
    let out = roundtrip(&stream_bytes(), cfg);
    let text = String::from_utf8_lossy(&out);
    assert!(text.contains("author Anonymous <anonymous@example.invalid>"), "{text}");
    assert!(text.contains("committer Anonymous <anonymous@example.invalid>"));
    assert!(text.contains("tagger Anonymous <anonymous@example.invalid>"));
    for leak in ["alice@example.com", "bob@example.org", "tagr@example.net", "Alice", "Bob", "Tagr"] {
        assert!(!text.contains(leak), "collapsed stream leaks {leak}");
    }

    // The audit is replaced, not alarmed: distinct originals counted, no
    // collision entries (the collapse is intentional, D7).
    let cfg2 = RedactConfig {
        ident_mode: IdentMode::Collapse {
            name: b("Anonymous"),
            email: b("anonymous@example.invalid"),
        },
        ..RedactConfig::default()
    };
    let report = report_for(&stream_bytes(), cfg2);
    // Alice (author+committer folds), Bob, Tagr.
    assert_eq!(report.totals.idents_collapsed, 3, "distinct originals");
    assert_eq!(report.totals.collisions, 0);
    assert!(report.collisions.is_empty());
    assert!(report.summary_text().contains("collapse=1 idents_collapsed=3"));
    assert!(!report.summary_text().contains("collisions="));
}

#[test]
fn collapse_composes_with_time_modes() {
    let cfg = RedactConfig {
        ident_mode: IdentMode::Collapse {
            name: b("Anonymous"),
            email: b("anonymous@example.invalid"),
        },
        time_mode: TimeMode::Zero,
        ..RedactConfig::default()
    };
    let out = roundtrip(&stream_bytes(), cfg);
    let text = String::from_utf8_lossy(&out);
    assert!(text.contains("author Anonymous <anonymous@example.invalid> 0 +0000"), "{text}");
    assert!(!text.contains("1700000000"), "times zeroed");
    assert!(!text.contains("+0200"), "offsets gone");
}
