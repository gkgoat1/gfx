//! `gfx-blob-xform` behavior tests (plan-blob-xform.md §5): the Transform
//! contract suite, built-in tables, D1 chain atomicity, D4 guards, D5
//! special-mode skips, G3 no-op elision, event coverage (standalone +
//! inline `M` + `N`), report truthfulness, and the idempotence/never-panic
//! properties.

use gfx_blob_xform::{
    builtins, BlobTransform, BlobXform, BlobXformConfig, SharedBlobTransform, TextTransform,
};
use gfx_core::prelude::*;
use gfx_core::test_kit;

fn b(s: &str) -> BString {
    BString::from(s.as_bytes().to_vec())
}

fn oid(hex: &[u8]) -> Oid {
    Oid::from_hex(hex, ObjectFormat::Sha1).unwrap()
}

fn blob_ev(mark: Mark, data: &[u8], original: Option<Oid>) -> Event {
    Event::Blob {
        mark: Some(mark),
        original_oid: original,
        data: Data(data.to_vec()),
    }
}

fn commit_ev(ref_name: &str, mark: Mark, ops: Vec<FileOp>) -> Event {
    Event::Commit(Commit {
        ref_name: b(ref_name),
        mark: Some(mark),
        original_oid: None,
        author: None,
        committer: Some(Ident {
            name: b("T"),
            email: b("t@t"),
            time: Timestamp {
                raw: b"1112912053 +0000".to_vec().into(),
                epoch: 1112912053,
                tz_offset_min: 0,
            },
        }),
        encoding: None,
        message: Data(b"m\n".to_vec()),
        from: None,
        merges: Vec::new(),
        ops,
    })
}

fn modify_ev(mode: Mode, path: &str, data: &[u8]) -> FileOp {
    FileOp::Modify {
        mode,
        path: b(path),
        source: FileSource::Inline(Data(data.to_vec())),
    }
}

fn cfg_with(t: Vec<SharedBlobTransform>) -> BlobXformConfig {
    BlobXformConfig { transforms: t, ..Default::default() }
}

fn shared<T: BlobTransform + 'static>(t: T) -> SharedBlobTransform {
    SharedBlobTransform(std::sync::Arc::new(t))
}

fn blob_data(ev: &Event) -> &[u8] {
    match ev {
        Event::Blob { data, .. } => data.as_slice(),
        other => panic!("expected blob, got {other:?}"),
    }
}

fn inline_data(ev: &Event, op: usize) -> &[u8] {
    match ev {
        Event::Commit(c) => match &c.ops[op] {
            FileOp::Modify { source: FileSource::Inline(d), .. } => d.as_slice(),
            other => panic!("expected inline modify, got {other:?}"),
        },
        other => panic!("expected commit, got {other:?}"),
    }
}

fn sample_stream() -> Vec<Event> {
    vec![
        blob_ev(1, b"a\r\nb \r\nc", Some(oid(b"4a58007052a65fbc2fc3f910f2855f45a4058e74"))),
        commit_ev(
            "refs/heads/main",
            2,
            vec![
                modify_ev(Mode::Regular, "f.txt", b"x\r\n"),
                modify_ev(Mode::Symlink, "link", b"/target/path \r\n"),
            ],
        ),
        Event::Reset { ref_name: b("refs/heads/main"), from: Some(Committish::Mark(2)) },
        Event::Done,
    ]
}

// ---------------------------------------------------------------------------
// Contract suite (plan §5: the test-kit invariants)

#[test]
fn contract_suite() {
    let events = sample_stream();
    test_kit::assert_deterministic(
        || BlobXform::new(cfg_with(builtins::all())),
        events.clone(),
    );
    test_kit::assert_finish_idempotent(
        || BlobXform::new(cfg_with(builtins::all())),
        events.clone(),
    );
    test_kit::assert_reset_restores_fresh(
        || BlobXform::new(cfg_with(builtins::all())),
        events,
    );
}

// ---------------------------------------------------------------------------
// Built-in tables

#[test]
fn crlf_to_lf_table() {
    let t = builtins::CrlfToLf;
    let cases: &[(&[u8], &[u8])] = &[
        (b"a\r\nb\r\n", b"a\nb\n"),     // CRLF pairs
        (b"a\rb\rc\r", b"a\nb\nc\n"),   // lone CRs
        (b"a\r\n\rb", b"a\n\nb"),       // CRLF then lone CR
        (b"a\nb\n", b"a\nb\n"),         // already LF (no-op)
        (b"", b""),                     // empty
        (b"\x00\x01\xff\r\n", b"\x00\x01\xff\n"), // binary bytes pass through
    ];
    for (input, want) in cases {
        assert_eq!(t.apply(input).as_deref(), Ok(*want), "input {input:?}");
    }
}

#[test]
fn trim_trailing_whitespace_table() {
    let t = builtins::TrimTrailingWhitespace;
    let cases: &[(&[u8], Option<&[u8]>, &str)] = &[
        (b"a  \nb\t\n", Some(b"a\nb\n"), "trailing runs removed"),
        (b"  keep lead \t \n", Some(b"  keep lead\n"), "leading kept"),
        (b"a\n", Some(b"a\n"), "final newline preserved"),
        (b"a \n\n", Some(b"a\n\n"), "blank line preserved"),
        (b"", Some(b""), "empty"),
        (b"no trailing", Some(b"no trailing"), "no-op"),
        (b"\xff\xfe ", None, "non-UTF-8 retains"),
        (b"a\x00b \n", Some(b"a\x00b\n"), "interior NUL is valid UTF-8"),
    ];
    for (input, want, why) in cases {
        match want {
            Some(w) => assert_eq!(t.apply(input).as_deref(), Ok(*w), "{why}"),
            None => assert!(t.apply(input).is_err(), "{why}"),
        }
    }
}

#[test]
fn ensure_final_newline_table() {
    let t = builtins::EnsureFinalNewline;
    let cases: &[(&[u8], Option<&[u8]>, &str)] = &[
        (b"a", Some(b"a\n"), "missing newline added"),
        (b"a\n", Some(b"a\n"), "already terminated (no-op)"),
        (b"a\n\n\n", Some(b"a\n"), "multiple trailing collapsed to one"),
        (b"", Some(b""), "empty stays empty"),
        (b"\n", Some(b"\n"), "lone newline"),
        (b"\xff", None, "non-UTF-8 retains"),
    ];
    for (input, want, why) in cases {
        match want {
            Some(w) => assert_eq!(t.apply(input).as_deref(), Ok(*w), "{why}"),
            None => assert!(t.apply(input).is_err(), "{why}"),
        }
    }
}

// ---------------------------------------------------------------------------
// D1 — fail-open, atomic to the original

struct AlwaysFails;
impl BlobTransform for AlwaysFails {
    fn name(&self) -> &'static str {
        "always-fails"
    }
    fn apply(&self, _blob: &[u8]) -> Result<Vec<u8>, ()> {
        Err(())
    }
}

#[test]
fn chain_failure_is_atomic_to_original() {
    // crlf-to-lf succeeds (stage 1), always-fails fails (stage 2): the
    // event must carry the ORIGINAL bytes, not the stage-1 result.
    let mut pass = BlobXform::new(cfg_with(vec![shared(builtins::CrlfToLf), shared(AlwaysFails)]));
    let mut out = Vec::new();
    pass.apply(blob_ev(1, b"a\r\nb", None), &mut out).unwrap();
    assert_eq!(blob_data(&out[0]), b"a\r\nb");
    let r = pass.report();
    assert_eq!((r.altered, r.retained_failed), (0, 1));
}

#[test]
fn all_failures_give_identity_stream() {
    let events = sample_stream();
    let out = test_kit::run_through(
        || BlobXform::new(cfg_with(vec![shared(AlwaysFails)])),
        events.clone(),
    )
    .unwrap();
    assert_eq!(out, events, "every blob retained ⇒ byte-identical stream");
}

// ---------------------------------------------------------------------------
// G3 — no-op elision

#[test]
fn no_op_transform_is_identity_and_counted_unchanged() {
    // Input already LF-only: crlf-to-lf output == input.
    let mut pass = BlobXform::new(cfg_with(vec![shared(builtins::CrlfToLf)]));
    let mut out = Vec::new();
    pass.apply(blob_ev(1, b"a\nb\n", Some(oid(b"4a58007052a65fbc2fc3f910f2855f45a4058e74"))), &mut out)
        .unwrap();
    assert_eq!(blob_data(&out[0]), b"a\nb\n");
    // Marks and original-oid untouched.
    match &out[0] {
        Event::Blob { mark, original_oid, .. } => {
            assert_eq!(*mark, Some(1));
            assert!(original_oid.is_some());
        }
        _ => unreachable!(),
    }
    let r = pass.report();
    assert_eq!((r.unchanged, r.altered), (1, 0));
}

// ---------------------------------------------------------------------------
// D4 — guards are retentions, not errors

#[test]
fn skip_larger_than_retains_without_running_chain() {
    let cfg = BlobXformConfig {
        transforms: vec![shared(AlwaysFails)], // would fail if run
        skip_larger_than: Some(4),
        ..Default::default()
    };
    let mut pass = BlobXform::new(cfg);
    let mut out = Vec::new();
    pass.apply(blob_ev(1, b"123456789", None), &mut out).unwrap();
    pass.apply(blob_ev(2, b"tiny", None), &mut out).unwrap();
    assert_eq!(blob_data(&out[0]), b"123456789");
    let r = pass.report();
    assert_eq!((r.retained_guard, r.retained_failed), (1, 1)); // big: guard; tiny: chain ran
}

#[test]
fn max_output_bytes_discards_inflating_result() {
    let cfg = BlobXformConfig {
        transforms: vec![shared(|blob: &[u8]| {
            let mut v = blob.to_vec();
            v.extend_from_slice(&[b'x'; 1024]);
            Ok(v)
        })],
        max_output_bytes: Some(100),
        ..Default::default()
    };
    let mut pass = BlobXform::new(cfg);
    let mut out = Vec::new();
    pass.apply(blob_ev(1, b"seed", None), &mut out).unwrap();
    assert_eq!(blob_data(&out[0]), b"seed", "inflated output discarded");
    assert_eq!(pass.report().retained_guard, 1);
}

// ---------------------------------------------------------------------------
// D5 — special modes skipped on inline ops; standalone blobs always run

#[test]
fn inline_symlink_skipped_by_default() {
    let events = vec![commit_ev(
        "refs/heads/main",
        1,
        vec![modify_ev(Mode::Symlink, "link", b"/target \r\n")],
    )];
    let mut pass = BlobXform::new(cfg_with(vec![shared(builtins::CrlfToLf)]));
    let mut out = Vec::new();
    for ev in events {
        pass.apply(ev, &mut out).unwrap();
    }
    assert_eq!(inline_data(&out[0], 0), b"/target \r\n", "symlink payload untouched");
    assert_eq!(pass.report().retained_guard, 1);

    let mut pass = BlobXform::new(BlobXformConfig {
        transforms: vec![shared(builtins::CrlfToLf)],
        include_special_modes: true,
        ..Default::default()
    });
    let mut out = Vec::new();
    pass.apply(
        commit_ev("refs/heads/main", 1, vec![modify_ev(Mode::Symlink, "link", b"/t \r\n")]),
        &mut out,
    )
    .unwrap();
    assert_eq!(inline_data(&out[0], 0), b"/t \n", "opt-out transforms symlinks");
}

#[test]
fn include_inline_false_leaves_ops_alone() {
    let cfg = BlobXformConfig {
        transforms: vec![shared(builtins::CrlfToLf)],
        include_inline: false,
        ..Default::default()
    };
    let mut pass = BlobXform::new(cfg);
    let mut out = Vec::new();
    pass.apply(blob_ev(1, b"a\r\n", None), &mut out).unwrap();
    pass.apply(
        commit_ev("refs/heads/main", 2, vec![modify_ev(Mode::Regular, "f", b"x\r\n")]),
        &mut out,
    )
    .unwrap();
    assert_eq!(blob_data(&out[0]), b"a\n", "standalone blob transformed");
    assert_eq!(inline_data(&out[1], 0), b"x\r\n", "inline left alone");
}

// ---------------------------------------------------------------------------
// Coverage — inline M and N ops both transform

#[test]
fn note_inline_data_is_transformed() {
    let op = FileOp::Note {
        data: FileSource::Inline(Data(b"note text\r\n".to_vec())),
        commit: Committish::Mark(9),
    };
    let mut pass = BlobXform::new(cfg_with(vec![shared(builtins::CrlfToLf)]));
    let mut out = Vec::new();
    pass.apply(commit_ev("refs/heads/main", 1, vec![op]), &mut out).unwrap();
    match &out[0] {
        Event::Commit(c) => match &c.ops[0] {
            FileOp::Note { data: FileSource::Inline(d), .. } => {
                assert_eq!(d.as_slice(), b"note text\n")
            }
            other => panic!("{other:?}"),
        },
        other => panic!("{other:?}"),
    }
}

#[test]
fn structural_events_pass_through_untouched() {
    let events = vec![
        Event::Progress { bytestring: b("working") },
        Event::Feature { name: b("done"), arg: None },
        Event::Checkpoint,
        Event::Done,
    ];
    let out = test_kit::run_through(
        || BlobXform::new(cfg_with(vec![shared(builtins::CrlfToLf)])),
        events.clone(),
    )
    .unwrap();
    assert_eq!(out, events);
}

// ---------------------------------------------------------------------------
// Report truthfulness + byte totals

#[test]
fn report_counts_and_bytes_are_exact() {
    let mut pass = BlobXform::new(BlobXformConfig {
        transforms: vec![shared(builtins::CrlfToLf), shared(AlwaysFails)],
        skip_larger_than: Some(100),
        ..Default::default()
    });
    let mut out = Vec::new();
    // altered: chain 1 succeeds... no — AlwaysFails makes everything fail.
    // Use separate passes per scenario instead; here: everything fails or guards.
    pass.apply(blob_ev(1, b"abc", None), &mut out).unwrap(); // failed
    pass.apply(blob_ev(2, &vec![b'x'; 200], None), &mut out).unwrap(); // guard
    let r = pass.report().clone();
    assert_eq!(r.blobs_examined, 2);
    assert_eq!(r.retained_failed, 1);
    assert_eq!(r.retained_guard, 1);
    assert_eq!(r.bytes_in, 203);
    assert_eq!(r.bytes_out, 203);
    assert!(r.detail().contains("retained=2 (failed=1 guard=1)"));

    // Altered path: crlf-to-lf alone.
    let mut pass = BlobXform::new(cfg_with(vec![shared(builtins::CrlfToLf)]));
    let mut out = Vec::new();
    pass.apply(blob_ev(1, b"a\r\n", None), &mut out).unwrap(); // 3 -> 2
    pass.apply(blob_ev(2, b"b\n", None), &mut out).unwrap(); // unchanged 2 -> 2
    let r = pass.report().clone();
    assert_eq!((r.altered, r.unchanged), (1, 1));
    assert_eq!(r.bytes_in, 5);
    assert_eq!(r.bytes_out, 4);
}

// ---------------------------------------------------------------------------
// Properties — never panics, idempotent built-ins, failure ⇒ identity

fn prng(seed: &mut u64) -> u64 {
    let mut x = *seed;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *seed = x;
    x.wrapping_mul(0x2545F4914F6CDD1D)
}

#[test]
fn builtins_never_panic_and_are_idempotent_on_arbitrary_bytes() {
    let all: Vec<Box<dyn BlobTransform>> = vec![
        Box::new(builtins::CrlfToLf),
        Box::new(builtins::TrimTrailingWhitespace),
        Box::new(builtins::EnsureFinalNewline),
    ];
    let mut seed = 0x1234_5678_9abc_def0u64;
    for case in 0..512 {
        let len = (prng(&mut seed) % 200) as usize;
        let mut blob = vec![0u8; len];
        for byte in &mut blob {
            // Bias toward interesting bytes: newlines, CR, space, tab, NUL, 0xff.
            *byte = match prng(&mut seed) % 8 {
                0 => b'\n',
                1 => b'\r',
                2 => b' ',
                3 => b'\t',
                4 => 0,
                5 => 0xff,
                _ => (prng(&mut seed) % 256) as u8,
            };
        }
        for t in &all {
            if let Ok(out1) = t.apply(&blob) {
                let out2 = t.apply(&out1).unwrap_or_else(|_| {
                    panic!("case {case}: {} not idempotent (2nd apply failed)", t.name())
                });
                assert_eq!(out1, out2, "case {case}: {} not idempotent", t.name());
            }
        }
    }
}

#[test]
fn arbitrary_chains_never_panic_and_failure_is_identity() {
    let mut seed = 0xdead_beef_cafe_f00du64;
    for case in 0..64 {
        // Random chain: 1..=3 stages from the built-ins + maybe a failing stage.
        let n = 1 + (prng(&mut seed) % 3) as usize;
        let mut chain: Vec<SharedBlobTransform> = Vec::new();
        for i in 0..n {
            let t: SharedBlobTransform = match prng(&mut seed) % 4 {
                0 => shared(builtins::CrlfToLf),
                1 => shared(builtins::TrimTrailingWhitespace),
                2 => shared(builtins::EnsureFinalNewline),
                _ => shared(AlwaysFails),
            };
            let _ = i;
            chain.push(t);
        }
        let len = (prng(&mut seed) % 512) as usize;
        let mut blob = vec![0u8; len];
        for byte in &mut blob {
            *byte = (prng(&mut seed) % 256) as u8;
        }
        let mut pass = BlobXform::new(BlobXformConfig {
            transforms: chain,
            skip_larger_than: if prng(&mut seed) % 2 == 0 { Some(256) } else { None },
            max_output_bytes: if prng(&mut seed) % 3 == 0 { Some(384) } else { None },
            ..Default::default()
        });
        let mut out = Vec::new();
        pass.apply(blob_ev(1, &blob, None), &mut out)
            .unwrap_or_else(|e| panic!("case {case}: pass errored on blob content: {e:?}"));
        let r = pass.report();
        assert_eq!(r.blobs_examined, 1);
        if r.altered == 0 {
            assert_eq!(
                blob_data(&out[0]),
                blob.as_slice(),
                "case {case}: retained blob must be the original bytes"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// D3 — the TextTransform adapter

#[test]
fn text_transform_adapter_decodes_and_fails_clean() {
    let upper = TextTransform {
        name: "upper",
        f: |s: &str| -> Result<String, core::convert::Infallible> { Ok(s.to_uppercase()) },
    };
    assert_eq!(upper.apply(b"abc\n").as_deref(), Ok(&b"ABC\n"[..]));
    assert!(upper.apply(b"\xff\xfe").is_err(), "decode failure ⇒ retain");

    let reject = TextTransform {
        name: "reject",
        f: |_s: &str| -> Result<String, ()> { Err(()) },
    };
    assert!(reject.apply(b"fine utf-8").is_err());
}

// ---------------------------------------------------------------------------
// Path rules (plan-blob-xform-paths.md): create-once, D2 originals pass
// through, D6 mode-awareness, D1/D5 fail-open + matching, D3 mark_base.

use gfx_blob_xform::PathRule;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

struct Upper;
impl BlobTransform for Upper {
    fn name(&self) -> &'static str {
        "upper"
    }
    fn apply(&self, blob: &[u8]) -> Result<Vec<u8>, ()> {
        Ok(blob.iter().map(u8::to_ascii_uppercase).collect())
    }
}

/// Counting transform: proves create-once (G2) at the execution level.
struct CountingUpper(Arc<AtomicU64>);
impl BlobTransform for CountingUpper {
    fn name(&self) -> &'static str {
        "counting-upper"
    }
    fn apply(&self, blob: &[u8]) -> Result<Vec<u8>, ()> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(blob.iter().map(u8::to_ascii_uppercase).collect())
    }
}

struct FailOnKeep;
impl BlobTransform for FailOnKeep {
    fn name(&self) -> &'static str {
        "fail-on-keep"
    }
    fn apply(&self, blob: &[u8]) -> Result<Vec<u8>, ()> {
        if blob.windows(6).any(|w| w == b"KEEPME") {
            Err(())
        } else {
            Ok(blob.iter().map(u8::to_ascii_uppercase).collect())
        }
    }
}

fn rule_rs<T: BlobTransform + 'static>(t: T) -> PathRule {
    PathRule {
        extension: b"rs".to_vec(),
        transforms: vec![shared(t)],
        skip_larger_than: None,
        max_output_bytes: None,
    }
}

fn rules_cfg(rules: Vec<PathRule>, mark_base: u64) -> BlobXformConfig {
    BlobXformConfig { path_rules: rules, mark_base: Some(mark_base), ..Default::default() }
}

fn mark_op(mode: Mode, path: &str, mark: Mark) -> FileOp {
    FileOp::Modify {
        mode,
        path: b(path),
        source: FileSource::DataRef(DataRef::Mark(mark)),
    }
}

fn op_mark<'a>(ev: &'a Event, op: usize) -> Mark {
    match ev {
        Event::Commit(c) => match &c.ops[op] {
            FileOp::Modify { source: FileSource::DataRef(DataRef::Mark(m)), .. } => *m,
            other => panic!("expected mark-sourced modify, got {other:?}"),
        },
        other => panic!("expected commit, got {other:?}"),
    }
}

fn drive(cfg: BlobXformConfig, stream: Vec<Event>) -> (Vec<Event>, gfx_blob_xform::BlobXformReport) {
    let mut x = BlobXform::new(cfg);
    let mut out = Vec::new();
    for ev in stream {
        x.apply(ev, &mut out).unwrap();
    }
    x.finish(&mut out).unwrap();
    (out, x.report().clone())
}

#[test]
fn first_use_creates_synthetic_blob_immediately_before_commit() {
    // Stream max mark is 3 → base 4.
    let stream = vec![
        blob_ev(1, b"fn main() {}", None),
        commit_ev("refs/heads/main", 2, vec![mark_op(Mode::Regular, "src/a.rs", 1)]),
        commit_ev("refs/heads/main", 3, vec![mark_op(Mode::Regular, "src/b.rs", 1)]),
    ];
    let (out, report) = drive(rules_cfg(vec![rule_rs(CountingUpper(Arc::new(AtomicU64::new(0))))], 4), stream);

    // blob(1) passes through (D2); synthetic blob(4) inserted immediately
    // before commit 2; commit 3 reuses the mark without a new blob event.
    assert!(matches!(&out[0], Event::Blob { mark: Some(1), data, .. } if data.as_slice() == b"fn main() {}"));
    assert!(matches!(&out[1], Event::Blob { mark: Some(4), data, original_oid: None } if data.as_slice() == b"FN MAIN() {}"));
    assert!(matches!(&out[2], Event::Commit(c) if c.mark == Some(2)));
    assert!(matches!(&out[3], Event::Commit(c) if c.mark == Some(3)));
    assert_eq!(out.len(), 4, "no second synthetic blob");
    assert_eq!(op_mark(&out[2], 0), 4);
    assert_eq!(op_mark(&out[3], 0), 4, "second matching use reuses the synthetic mark");
    let r = &report.rules[0];
    assert_eq!(r.ops_examined, 2);
    assert_eq!(r.ops_rewritten, 2);
    assert_eq!(r.blobs_created, 1);
}

#[test]
fn transform_executes_at_most_once_per_blob_and_rule() {
    let calls = Arc::new(AtomicU64::new(0));
    let stream = vec![
        blob_ev(1, b"fn a() {}", None),
        commit_ev(
            "refs/heads/main",
            2,
            vec![
                mark_op(Mode::Regular, "a.rs", 1),
                mark_op(Mode::Regular, "b.rs", 1),
                mark_op(Mode::Regular, "c.rs", 1),
            ],
        ),
    ];
    let (out, _) = drive(
        rules_cfg(vec![rule_rs(CountingUpper(calls.clone()))], 3),
        stream,
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1, "G2: create-once");
    // out = [orig blob(1), synthetic blob(3), commit(2)]
    assert_eq!(op_mark(&out[2], 0), 3);
    assert_eq!(op_mark(&out[2], 1), 3);
    assert_eq!(op_mark(&out[2], 2), 3);
}

#[test]
fn same_blob_matching_and_nonmatching_paths_both_work() {
    let stream = vec![
        blob_ev(1, b"data", None),
        commit_ev(
            "refs/heads/main",
            2,
            vec![mark_op(Mode::Regular, "a.rs", 1), mark_op(Mode::Regular, "d.txt", 1)],
        ),
    ];
    let (out, report) = drive(rules_cfg(vec![rule_rs(Upper)], 3), stream);
    assert!(matches!(&out[0], Event::Blob { mark: Some(1), data, .. } if data.as_slice() == b"data"),
        "D2: original blob passes through unaltered");
    assert!(matches!(&out[1], Event::Blob { mark: Some(3), data, .. } if data.as_slice() == b"DATA"));
    assert_eq!(op_mark(&out[2], 0), 3, ".rs op rewritten");
    assert_eq!(op_mark(&out[2], 1), 1, ".txt op keeps the original mark");
    assert_eq!(report.rules[0].ops_examined, 1, "only the matching op is judged");
}

#[test]
fn same_blob_two_extensions_get_two_synthetics() {
    let stream = vec![
        blob_ev(1, b"ab", None),
        commit_ev(
            "refs/heads/main",
            2,
            vec![mark_op(Mode::Regular, "x.rs", 1), mark_op(Mode::Regular, "y.py", 1)],
        ),
    ];
    let cfg = rules_cfg(
        vec![
            rule_rs(Upper),
            PathRule {
                extension: b"py".to_vec(),
                transforms: vec![shared(builtins::EnsureFinalNewline)],
                skip_larger_than: None,
                max_output_bytes: None,
            },
        ],
        3,
    );
    let (out, report) = drive(cfg, stream);
    assert!(matches!(&out[1], Event::Blob { mark: Some(3), data, .. } if data.as_slice() == b"AB"));
    assert!(matches!(&out[2], Event::Blob { mark: Some(4), data, .. } if data.as_slice() == b"ab\n"));
    assert_eq!(op_mark(&out[3], 0), 3);
    assert_eq!(op_mark(&out[3], 1), 4);
    assert_eq!(report.rules[0].blobs_created, 1);
    assert_eq!(report.rules[1].blobs_created, 1);
}

#[test]
fn failure_keeps_original_mark_and_is_counted() {
    let stream = vec![
        blob_ev(1, b"KEEPME secret", None),
        blob_ev(2, b"ok", None),
        commit_ev(
            "refs/heads/main",
            3,
            vec![mark_op(Mode::Regular, "a.rs", 1), mark_op(Mode::Regular, "b.rs", 2)],
        ),
        commit_ev("refs/heads/main", 4, vec![mark_op(Mode::Regular, "again.rs", 1)]),
    ];
    let (out, report) = drive(rules_cfg(vec![rule_rs(FailOnKeep)], 5), stream);
    assert_eq!(op_mark(&out[3], 0), 1, "D1: failed blob keeps original mark");
    assert_eq!(op_mark(&out[3], 1), 5);
    assert_eq!(op_mark(&out[4], 0), 1, "retention verdict is cached (no re-execution)");
    let r = &report.rules[0];
    assert_eq!((r.ops_examined, r.ops_rewritten, r.retained_failed), (3, 1, 2));
}

#[test]
fn unchanged_chain_output_keeps_original_mark() {
    // Upper is a no-op on already-uppercase content.
    let stream = vec![
        blob_ev(1, b"ALREADY", None),
        commit_ev("refs/heads/main", 2, vec![mark_op(Mode::Regular, "a.rs", 1)]),
    ];
    let (out, report) = drive(rules_cfg(vec![rule_rs(Upper)], 3), stream);
    assert_eq!(out.len(), 2, "no synthetic blob for an unchanged verdict");
    assert_eq!(op_mark(&out[1], 0), 1);
    assert_eq!(report.rules[0].unchanged, 1);
    assert_eq!(report.rules[0].blobs_created, 0);
}

#[test]
fn special_modes_skipped_by_default_opt_in_works() {
    let stream = vec![
        blob_ev(1, b"/target/x", None),
        commit_ev(
            "refs/heads/main",
            2,
            vec![
                mark_op(Mode::Symlink, "link.rs", 1),
                mark_op(Mode::Gitlink, "sub.rs", 1),
            ],
        ),
    ];
    let (out, report) = drive(rules_cfg(vec![rule_rs(Upper)], 3), stream.clone());
    assert_eq!(op_mark(&out[1], 0), 1, "D6: symlink skipped by default");
    assert_eq!(op_mark(&out[1], 1), 1, "D6: gitlink skipped by default");
    assert_eq!(report.rules[0].retained_guard, 2);

    let mut cfg = rules_cfg(vec![rule_rs(Upper)], 3);
    cfg.include_special_modes = true;
    let (out, report) = drive(cfg, stream);
    assert_eq!(op_mark(&out[2], 0), 3);
    assert_eq!(op_mark(&out[2], 1), 3);
    assert_eq!(report.rules[0].ops_rewritten, 2);
}

#[test]
fn inline_ops_rewrite_in_place_when_path_matches() {
    let stream = vec![commit_ev(
        "refs/heads/main",
        1,
        vec![
            modify_ev(Mode::Regular, "a.rs", b"fn f() {}"),
            modify_ev(Mode::Regular, "b.txt", b"fn f() {}"),
            modify_ev(Mode::Symlink, "l.rs", b"/t/x"),
        ],
    )];
    let (out, report) = drive(rules_cfg(vec![rule_rs(Upper)], 2), stream);
    assert_eq!(inline_data(&out[0], 0), b"FN F() {}", "D7: matching inline rewritten in place");
    assert_eq!(inline_data(&out[0], 1), b"fn f() {}", "non-matching inline untouched");
    assert_eq!(inline_data(&out[0], 2), b"/t/x", "symlink inline guarded by default");
    assert_eq!(report.rules[0].ops_rewritten, 1);
    assert_eq!(report.rules[0].retained_guard, 1);
    assert_eq!(report.rules[0].blobs_created, 0, "inline needs no synthetic blob");
}

#[test]
fn extension_matching_is_final_component_after_last_dot() {
    for (path, want) in [
        ("a.rs", true),
        ("dir/sub/b.rs", true),
        ("archive.rs.bak", false),
        ("noext", false),
        ("trailing.", false),
        (".rs", false), // a dotfile named ".rs" has no extension (D5)
        (".hidden.rs", true),
        ("UPPER.RS", false), // case-sensitive (D5)
    ] {
        let stream = vec![
            blob_ev(1, b"ab", None),
            commit_ev("refs/heads/main", 2, vec![mark_op(Mode::Regular, path, 1)]),
        ];
        let (out, _) = drive(rules_cfg(vec![rule_rs(Upper)], 3), stream);
        // out = [orig blob(1), (synthetic blob(3) if matched), commit(2)]
        let got = out.len() == 3;
        assert_eq!(got, want, "path {path:?}");
        assert_eq!(op_mark(out.last().unwrap(), 0), if want { 3 } else { 1 }, "path {path:?}");
    }
}

#[test]
fn mark_reference_without_cached_original_is_retained() {
    // Adversarial/fuzz case: op references a mark whose blob never flowed.
    let stream = vec![commit_ev(
        "refs/heads/main",
        1,
        vec![mark_op(Mode::Regular, "a.rs", 42)],
    )];
    let (out, report) = drive(rules_cfg(vec![rule_rs(Upper)], 50), stream);
    assert_eq!(op_mark(&out[0], 0), 42, "unknown mark kept");
    assert_eq!(report.rules[0].retained_failed, 1);
}

#[test]
fn missing_mark_base_with_path_rules_is_a_config_error() {
    let mut cfg = rules_cfg(vec![rule_rs(Upper)], 0);
    cfg.mark_base = None;
    let mut x = BlobXform::new(cfg);
    let mut out = Vec::new();
    x.apply(commit_ev("refs/heads/main", 1, vec![]), &mut out).unwrap();
    let err = x.finish(&mut out).unwrap_err();
    assert!(matches!(err, gfx_core::Error::Internal(_)), "D3: refuse to guess a base");
}

#[test]
fn rules_report_is_exact_and_partition_holds() {
    let stream = vec![
        blob_ev(1, b"fn a() {}", None),
        blob_ev(2, b"KEEPME", None),
        commit_ev(
            "refs/heads/main",
            3,
            vec![
                mark_op(Mode::Regular, "a.rs", 1),
                mark_op(Mode::Regular, "b.rs", 2),
                mark_op(Mode::Regular, "c.rs", 1),
                mark_op(Mode::Regular, "d.txt", 2),
            ],
        ),
    ];
    let (_, report) = drive(rules_cfg(vec![rule_rs(FailOnKeep)], 4), stream);
    let r = &report.rules[0];
    assert_eq!(
        r.ops_examined,
        r.ops_rewritten + r.unchanged + r.retained_failed + r.retained_guard,
        "counter partition (D9)"
    );
    assert_eq!(r.ops_examined, 3, "d.txt is not examined by the rs rule");
    assert_eq!(r.ops_rewritten, 2);
    assert_eq!(r.retained_failed, 1);
    assert_eq!(r.blobs_created, 1);
    assert_eq!(r.bytes_in, "fn a() {}".len() as u64 + "KEEPME".len() as u64);
}

#[test]
fn zero_rule_alterations_is_event_identity() {
    // Everything fails → output equals input exactly (G3 lifted to rules).
    let stream = vec![
        blob_ev(1, b"KEEPME a", None),
        blob_ev(2, b"KEEPME b", None),
        commit_ev(
            "refs/heads/main",
            3,
            vec![mark_op(Mode::Regular, "a.rs", 1), mark_op(Mode::Regular, "b.rs", 2)],
        ),
        Event::Done,
    ];
    let (out, _) = drive(rules_cfg(vec![rule_rs(FailOnKeep)], 4), stream.clone());
    assert_eq!(out, stream);
}

#[test]
fn whole_blob_stage_feeds_path_rules_post_transform_bytes() {
    // D8: whole-blob chain runs first; the rule sees its output.
    let mut cfg = rules_cfg(vec![rule_rs(Upper)], 3);
    cfg.transforms = vec![shared(builtins::CrlfToLf)];
    let stream = vec![
        blob_ev(1, b"a\r\nb", None),
        commit_ev("refs/heads/main", 2, vec![mark_op(Mode::Regular, "a.rs", 1)]),
    ];
    let (out, _) = drive(cfg, stream);
    assert!(matches!(&out[0], Event::Blob { data, .. } if data.as_slice() == b"a\nb"),
        "whole-blob stage altered the original");
    assert!(matches!(&out[1], Event::Blob { data, .. } if data.as_slice() == b"A\nB"),
        "rule ran on post-whole-blob bytes");

    // Same order for inline ops: whole-blob chain first, then the rule.
    let mut cfg = rules_cfg(vec![rule_rs(Upper)], 3);
    cfg.transforms = vec![shared(builtins::CrlfToLf)];
    let stream = vec![commit_ev(
        "refs/heads/main",
        1,
        vec![modify_ev(Mode::Regular, "a.rs", b"x\r\n")],
    )];
    let (out, _) = drive(cfg, stream);
    assert_eq!(inline_data(&out[0], 0), b"X\n", "inline: whole-blob then rule (D8)");
}

#[test]
fn reset_clears_rule_state_and_allocator() {
    let mut cfg = rules_cfg(vec![rule_rs(Upper)], 3);
    let mk = || {
        vec![
            blob_ev(1, b"ab", None),
            commit_ev("refs/heads/main", 2, vec![mark_op(Mode::Regular, "a.rs", 1)]),
        ]
    };
    cfg.mark_base = Some(3);
    let mut x = BlobXform::new(cfg);
    let mut out1 = Vec::new();
    for ev in mk() {
        x.apply(ev, &mut out1).unwrap();
    }
    x.finish(&mut out1).unwrap();
    let r1 = x.report().clone();
    x.reset();
    assert_eq!(x.report().rules[0].ops_examined, 0);
    let mut out2 = Vec::new();
    for ev in mk() {
        x.apply(ev, &mut out2).unwrap();
    }
    x.finish(&mut out2).unwrap();
    assert_eq!(out1, out2, "reset restores fresh state, allocator included");
    assert_eq!(*x.report(), r1);
}
