//! `gfx-strip-blobs` behavior tests (plan §5.7): S1 identity-noop, S3
//! determinism (incl. stateful injected predicate), S4 orphan guarantee,
//! S6 report truthfulness, plus the §5.6 edge-case table.

use gfx_core::prelude::*;
use gfx_core::test_kit;
use gfx_strip_blobs::{
    glob_match, BlobPredicate, ContentSignals, Reason, SharedMatcher, SharedPredicate,
    StripBlobs, StripBlobsConfig,
};

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

fn commit_ev(
    ref_name: &str,
    mark: Mark,
    original: Option<Oid>,
    from: Option<Committish>,
    ops: Vec<FileOp>,
) -> Event {
    Event::Commit(Commit {
        ref_name: b(ref_name),
        mark: Some(mark),
        original_oid: original,
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
        from,
        merges: Vec::new(),
        ops,
    })
}

fn reset_ev(ref_name: &str, from: Committish) -> Event {
    Event::Reset {
        ref_name: b(ref_name),
        from: Some(from),
    }
}

fn modify_dataref(mode: Mode, path: &str, mark: Mark) -> FileOp {
    FileOp::Modify {
        mode,
        path: b(path),
        source: FileSource::DataRef(DataRef::Mark(mark)),
    }
}

fn modify_inline(mode: Mode, path: &str, data: &[u8]) -> FileOp {
    FileOp::Modify {
        mode,
        path: b(path),
        source: FileSource::Inline(Data(data.to_vec())),
    }
}

fn run(cfg: StripBlobsConfig, events: Vec<Event>) -> (StripBlobs, Vec<Event>) {
    let mut t = StripBlobs::new(cfg);
    let mut out = Vec::new();
    for ev in events {
        t.apply(ev, &mut out).expect("apply");
    }
    t.finish(&mut out).expect("finish");
    (t, out)
}

fn size_cfg(threshold: u64) -> StripBlobsConfig {
    StripBlobsConfig {
        size_threshold: Some(threshold),
        ..StripBlobsConfig::default()
    }
}

fn serialize(events: &[Event]) -> Vec<u8> {
    let mut w = Writer::new();
    for ev in events {
        w.write(ev).expect("write");
    }
    w.take()
}

const OID1: &[u8] = b"1111111111111111111111111111111111111111";
const OID2: &[u8] = b"2222222222222222222222222222222222222222";

/// A basic history: blob1 small at a.txt, blob2 big at big.bin, second
/// commit modifies a.txt and deletes big.bin... no — plan §5.6 shapes:
/// commit 2 modifies big.bin (delta-style re-modify must drop too).
fn sample_history() -> Vec<Event> {
    vec![
        blob_ev(1, b"hello\n", Some(oid(OID1))),
        blob_ev(2, &vec![b'x'; 100], Some(oid(OID2))),
        commit_ev(
            "refs/heads/main",
            3,
            Some(oid(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")),
            None,
            vec![
                modify_dataref(Mode::Regular, "a.txt", 1),
                modify_dataref(Mode::Regular, "big.bin", 2),
            ],
        ),
        commit_ev(
            "refs/heads/main",
            4,
            Some(oid(b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")),
            Some(Committish::Mark(3)),
            vec![
                modify_dataref(Mode::Regular, "a.txt", 1), // re-modify (same blob)
                modify_dataref(Mode::Exec, "big.bin", 2),  // re-modify of selected blob
            ],
        ),
    ]
}

#[test]
fn s1_identity_when_nothing_selected() {
    // Threshold above every payload → nothing selected → byte-identical.
    let cfg = size_cfg(1 << 40);
    let input = sample_history();
    let (_, out) = run(cfg, input.clone());
    let input_bytes = serialize(&input);
    let output_bytes = serialize(&out);
    assert_eq!(output_bytes, input_bytes, "S1: nothing selected ⇒ identity");
}

#[test]
fn size_selection_drops_every_op_carrying_the_blob() {
    let cfg = size_cfg(50);
    let (_, out) = run(cfg, sample_history());

    // Every op touching big.bin (blob 2) is dropped; a.txt ops survive.
    let mut survives = Vec::new();
    for ev in out {
        if let Event::Commit(c) = ev {
            for op in &c.ops {
                survives.push(match op {
                    FileOp::Modify { path, .. } => path.to_vec(),
                    FileOp::Delete { path } => path.to_vec(),
                    _ => b"?".to_vec(),
                });
            }
        }
    }
    assert_eq!(
        survives,
        vec![b"a.txt".to_vec(), b"a.txt".to_vec()],
        "blob-selected ops dropped at every site"
    );
}

#[test]
fn s6_report_truthfulness() {
    let cfg = size_cfg(50);
    let (_, out) = run(cfg, sample_history());
    let _ = out;
    // (fresh run to observe the report)
    let (t, _) = run(size_cfg(50), sample_history());
    let report = t.report();
    // Two dropped M ops, each carrying the 100-byte blob.
    assert_eq!(report.totals.ops_dropped, 2);
    assert_eq!(report.totals.bytes_saved, 200);
    assert_eq!(report.totals.paths_affected, 2);
    // Re-modify drops are divergent under D1 (path reverts).
    assert_eq!(report.totals.divergences, 2);
    for e in &report.entries {
        assert_eq!(e.reason, Reason::Size { bytes: 100 });
    }
}

#[test]
fn inline_readd_is_rejudged_and_dropped() {
    // Plan §5.6: blob selected, later commit re-adds it inline → dropped.
    let events = vec![
        blob_ev(1, b"small\n", None),
        commit_ev(
            "refs/heads/main",
            2,
            None,
            None,
            vec![modify_dataref(Mode::Regular, "a.txt", 1)],
        ),
        commit_ev(
            "refs/heads/main",
            3,
            None,
            Some(Committish::Mark(2)),
            vec![modify_inline(Mode::Regular, "big.bin", &vec![b'z'; 100])],
        ),
    ];
    let (t, out) = run(size_cfg(50), events);
    assert_eq!(t.report().totals.ops_dropped, 1);
    let last = out.last().unwrap();
    match last {
        Event::Commit(c) => assert!(c.ops.is_empty(), "inline re-add dropped"),
        other => panic!("expected commit, got {other:?}"),
    }
}

#[test]
fn path_glob_selection_and_protection() {
    let cfg = StripBlobsConfig {
        path_globs: vec![b"**/*.min.js".to_vec().into()],
        protect_globs: vec![b"keep/**".to_vec().into()],
        ..StripBlobsConfig::default()
    };
    let events = vec![
        blob_ev(1, b"small\n", None),
        blob_ev(2, b"small\n", None),
        commit_ev(
            "refs/heads/main",
            3,
            None,
            None,
            vec![
                modify_dataref(Mode::Regular, "x/y.min.js", 1),
                modify_dataref(Mode::Regular, "keep/z.min.js", 2),
                modify_dataref(Mode::Regular, "src.js", 1),
            ],
        ),
    ];
    let (t, _) = run(cfg, events);
    let report = t.report();
    assert_eq!(report.totals.ops_dropped, 1);
    assert_eq!(report.entries[0].path, b("x/y.min.js"));
    match &report.entries[0].reason {
        Reason::PathGlob { glob } => {
            assert_eq!(glob.as_slice(), b"**/*.min.js");
        }
        other => panic!("expected PathGlob, got {other:?}"),
    }
}

#[test]
fn protected_path_keeps_even_selected_blob() {
    // Plan §5.6: same blob at two paths, one protected.
    let cfg = StripBlobsConfig {
        size_threshold: Some(50),
        protect_globs: vec![b"**/vendor/**".to_vec().into()],
        ..StripBlobsConfig::default()
    };
    let events = vec![
        blob_ev(1, &vec![b'x'; 100], None),
        commit_ev(
            "refs/heads/main",
            2,
            None,
            None,
            vec![
                modify_dataref(Mode::Regular, "src/big.bin", 1),
                modify_dataref(Mode::Regular, "vendor/big.bin", 1),
            ],
        ),
    ];
    let (t, out) = run(cfg, events);
    assert_eq!(t.report().totals.ops_dropped, 1);
    match &out[1] {
        Event::Commit(c) => {
            assert_eq!(c.ops.len(), 1);
            match &c.ops[0] {
                FileOp::Modify { path, .. } => assert_eq!(path.as_slice(), b"vendor/big.bin"),
                other => panic!("expected the protected op to survive, got {other:?}"),
            }
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn kept_deletes_target_live_paths_only() {
    // Plan §5.6: D of a path our own drops erased → normalized away.
    // Path-selection keeps ops off `gone.bin`; the later D of `gone.bin`
    // must be dropped; the D of `kept.txt` must survive.
    let cfg = StripBlobsConfig {
        path_globs: vec![b"gone.bin".to_vec().into()],
        ..StripBlobsConfig::default()
    };
    let events = vec![
        commit_ev(
            "refs/heads/main",
            1,
            None,
            None,
            vec![
                modify_inline(Mode::Regular, "gone.bin", b"x\n"),
                modify_inline(Mode::Regular, "kept.txt", b"y\n"),
            ],
        ),
        commit_ev(
            "refs/heads/main",
            2,
            None,
            Some(Committish::Mark(1)),
            vec![
                FileOp::Delete { path: b("gone.bin") },
                FileOp::Delete { path: b("kept.txt") },
            ],
        ),
    ];
    let (t, out) = run(cfg, events);
    // Two counted drops: the M of the selected path and the D of it (D of
    // a selected path is dropped, plan §5.1). The D of kept.txt survives
    // (live in the rewritten view); deletes of paths erased only by our
    // own drops of *unselected* paths would be normalized silently.
    assert_eq!(t.report().totals.ops_dropped, 2);
    match out.last().unwrap() {
        Event::Commit(c) => {
            assert_eq!(c.ops.len(), 1);
            assert!(matches!(&c.ops[0], FileOp::Delete { path } if path.as_slice() == b"kept.txt"));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn copy_of_selected_source_is_dropped_and_reported_divergent() {
    // Plan §5.6: C/R under blob selection.
    let cfg = size_cfg(50);
    let events = vec![
        blob_ev(1, &vec![b'x'; 100], None),
        blob_ev(2, b"ok\n", None),
        commit_ev(
            "refs/heads/main",
            3,
            None,
            None,
            vec![
                modify_dataref(Mode::Regular, "big.bin", 1),
                modify_dataref(Mode::Regular, "ok.txt", 2),
            ],
        ),
        commit_ev(
            "refs/heads/main",
            4,
            None,
            Some(Committish::Mark(3)),
            vec![
                FileOp::Copy {
                    from: b("big.bin"),
                    to: b("copy.bin"),
                },
                FileOp::Copy {
                    from: b("ok.txt"),
                    to: b("copy2.txt"),
                },
            ],
        ),
    ];
    let (t, out) = run(cfg, events);
    // Two drops: the M of big.bin (commit 3) and the C from big.bin
    // (commit 4, source holds a selected blob per the original view).
    assert_eq!(t.report().totals.ops_dropped, 2);
    assert_eq!(t.report().totals.divergences, 2, "both drops are D1 divergences");
    match out.last().unwrap() {
        Event::Commit(c) => {
            assert_eq!(c.ops.len(), 1);
            assert!(
                matches!(&c.ops[0], FileOp::Copy { to, .. } if to.as_slice() == b"copy2.txt")
            );
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn gitlinks_never_content_judged_but_path_selected() {
    let cfg = StripBlobsConfig {
        size_threshold: Some(0), // selects everything content-shaped
        path_globs: vec![b"submod".to_vec().into()],
        ..StripBlobsConfig::default()
    };
    let events = vec![
        commit_ev(
            "refs/heads/main",
            1,
            None,
            None,
            vec![
                modify_inline(Mode::Gitlink, "dep", b"0123456789012345678901234567890123456789"),
                modify_inline(Mode::Regular, "submod", b"x"),
            ],
        ),
    ];
    let (t, _) = run(cfg, events);
    // Gitlink survives (never content-judged); path-selected submod dropped.
    assert_eq!(t.report().totals.ops_dropped, 1);
    assert_eq!(t.report().entries[0].path, b("submod"));
}

#[test]
fn symlinks_not_judged_by_default() {
    let cfg = size_cfg(0);
    let events = vec![commit_ev(
        "refs/heads/main",
        1,
        None,
        None,
        vec![
            modify_inline(Mode::Symlink, "link", b"../target/that/is/quite/long/actually"),
            modify_inline(Mode::Regular, "file", b"data"),
        ],
    )];
    let (t, _) = run(cfg, events.clone());
    assert_eq!(t.report().totals.ops_dropped, 1, "only the regular file is size-stripped");

    let cfg_too = StripBlobsConfig {
        size_threshold: Some(0),
        strip_symlinks_too: true,
        ..StripBlobsConfig::default()
    };
    let (t2, _) = run(cfg_too, events);
    assert_eq!(t2.report().totals.ops_dropped, 2, "strip_symlinks_too judges links");
}

#[test]
fn content_signal_selection_inline() {
    let cfg = StripBlobsConfig {
        content_signals: ContentSignals::default(),
        ..StripBlobsConfig::default()
    };
    let events = vec![commit_ev(
        "refs/heads/main",
        1,
        None,
        None,
        vec![
            modify_inline(Mode::Regular, "gen.rs", b"// Generated by the codegen. DO NOT EDIT.\nfn x() {}\n"),
            modify_inline(Mode::Regular, "hand.rs", b"fn hand_written() {}\n"),
        ],
    )];
    let (t, _) = run(cfg, events);
    assert_eq!(t.report().totals.ops_dropped, 1);
    assert_eq!(t.report().entries[0].path, b("gen.rs"));
}

#[test]
fn s3_deterministic_with_injected_predicate() {
    // P6 with the injection machinery in play: a *pure* predicate keeps
    // two fresh runs byte-identical.
    struct PureBig;
    impl BlobPredicate for PureBig {
        fn judge(&self, _path: Option<&BString>, data: &[u8]) -> bool {
            data.len() > 50
        }
    }
    let cfg = StripBlobsConfig {
        extra_predicates: vec![SharedPredicate(std::rc::Rc::new(PureBig))],
        ..StripBlobsConfig::default()
    };
    let events = sample_history();
    test_kit::assert_deterministic(|| StripBlobs::new(cfg.clone()), events.clone());
    let (_, out1) = run(cfg.clone(), events.clone());
    let (_, out2) = run(cfg, events);
    assert_eq!(serialize(&out1), serialize(&out2));
}

#[test]
fn verdicts_are_not_cached_across_reset() {
    // The plan's cache check: a call-counting predicate proves reset()
    // clears the verdict registry — pass 2 must consult the predicate
    // again (calls increase) and reach the same verdicts.
    use core::cell::Cell;
    struct Counting {
        calls: Cell<u64>,
    }
    impl BlobPredicate for Counting {
        fn judge(&self, _path: Option<&BString>, data: &[u8]) -> bool {
            self.calls.set(self.calls.get() + 1);
            data.len() > 50
        }
    }
    let counter = std::rc::Rc::new(Counting {
        calls: Cell::new(0),
    });
    let cfg = StripBlobsConfig {
        extra_predicates: vec![SharedPredicate(counter.clone())],
        ..StripBlobsConfig::default()
    };
    let events = sample_history();

    let mut t = StripBlobs::new(cfg);
    let mut out1 = Vec::new();
    for ev in &events {
        t.apply(ev.clone(), &mut out1).unwrap();
    }
    t.finish(&mut out1).unwrap();
    let calls_pass1 = counter.calls.get();
    assert!(calls_pass1 > 0, "predicate consulted during pass 1");

    t.reset();
    let mut out2 = Vec::new();
    for ev in events {
        t.apply(ev, &mut out2).unwrap();
    }
    t.finish(&mut out2).unwrap();
    let calls_pass2 = counter.calls.get();
    assert!(
        calls_pass2 > calls_pass1,
        "reset() must clear cached verdicts; predicate was not consulted again"
    );
    assert_eq!(serialize(&out1), serialize(&out2), "same verdicts ⇒ same output");
}

#[test]
fn s4_no_surviving_op_references_selected_blob_mark() {
    let cfg = size_cfg(50);
    let (_, out) = run(cfg, sample_history());
    for ev in &out {
        if let Event::Commit(c) = ev {
            for op in &c.ops {
                if let FileOp::Modify { source, .. } = op {
                    if let FileSource::DataRef(DataRef::Mark(2)) = source {
                        panic!("S4 violated: surviving M references selected blob mark 2");
                    }
                }
            }
        }
    }
}

#[test]
fn s5_absence_via_independent_vindex_replay() {
    // Replay the rewritten stream through gfx-vindex (a separate
    // implementation used by the plan's simulator harness) and assert no
    // tree contains the selected blob.
    let cfg = size_cfg(50);
    let (_, out) = run(cfg, sample_history());
    let mut idx = gfx_vindex::Index::new();
    for ev in &out {
        if let Event::Commit(c) = ev {
            idx.apply_ops(c.ref_name.as_slice(), &c.ops);
        }
    }
    let violations = idx.paths_with_mark(2);
    assert!(violations.is_empty(), "S5: selected blob still present at {violations:?}");
    // a.txt (mark 1) must remain.
    assert_eq!(idx.paths_with_mark(1).len(), 1);
}

#[test]
fn transform_contract_via_test_kit() {
    let events = sample_history();
    test_kit::assert_finish_idempotent(|| StripBlobs::new(size_cfg(50)), events.clone());
    test_kit::assert_deterministic(|| StripBlobs::new(size_cfg(50)), events);
}

#[test]
fn report_limit_caps_listings_but_not_totals() {
    let cfg = StripBlobsConfig {
        size_threshold: Some(1),
        report_limit: 2,
        ..StripBlobsConfig::default()
    };
    let events = sample_history();
    let (t, _) = run(cfg, events);
    assert!(t.report().truncated);
    assert_eq!(t.report().entries.len(), 2, "listings capped");
    assert_eq!(t.report().totals.ops_dropped, 4, "totals stay exact");
}

#[test]
fn glob_bytes_not_utf8() {
    assert!(glob_match(b"**/*.bin", b"\xff\xfe/x.bin"));
    assert!(!glob_match(b"**/*.bin", b"\xff\xfe/x.txt"));
}
