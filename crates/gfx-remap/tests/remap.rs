//! Builtin #1 behavior (plan §7): mapping, rewriting, identity-noop,
//! finalization from marks, plus core Transform-contract checks via the
//! test kit.

use gfx_core::prelude::*;
use gfx_remap::{Remap, RemapConfig, RemapOutcome};

fn oid(hex: &[u8]) -> Oid {
    Oid::from_hex(hex, ObjectFormat::Sha1).unwrap()
}

fn commit_ev(ref_name: &str, mark: Option<Mark>, original: Option<Oid>) -> Event {
    Event::Commit(Commit {
        ref_name: BString::from(ref_name.as_bytes().to_vec()),
        mark,
        original_oid: original,
        author: None,
        committer: None,
        encoding: None,
        message: Data(b"m\n".to_vec()),
        from: None,
        merges: Vec::new(),
        ops: Vec::new(),
    })
}

fn run_remap(cfg: RemapConfig, events: Vec<Event>) -> (Remap, Vec<Event>) {
    let mut r = Remap::new(cfg);
    let mut out = Vec::new();
    for ev in events {
        r.apply(ev, &mut out).expect("apply");
    }
    r.finish(&mut out).expect("finish");
    (r, out)
}

fn sample_stream() -> Vec<Event> {
    let old1 = oid(b"1111111111111111111111111111111111111111");
    let old2 = oid(b"2222222222222222222222222222222222222222");
    vec![
        commit_ev("refs/heads/main", Some(1), Some(old1)),
        commit_ev("refs/heads/main", Some(2), Some(old2)),
        Event::Reset {
            ref_name: BString::from(b"refs/tags/v1".to_vec()),
            from: Some(Committish::Oid(old2)),
        },
    ]
}

#[test]
fn records_mapping_from_original_oids() {
    let old1 = oid(b"1111111111111111111111111111111111111111");
    let (r, _) = run_remap(RemapConfig::default(), sample_stream());
    assert_eq!(r.stats().commits_observed, 2);
    assert_eq!(r.outcome(1), Some(RemapOutcome::Unchanged));
    assert_eq!(r.outcome(2), Some(RemapOutcome::Unchanged));
    let cm = r.commit_map();
    assert_eq!(cm.get(&old1), Some(Some(&old1)));
}

#[test]
fn fresh_commits_without_original_oid_are_rewritten() {
    let (r, _) = run_remap(
        RemapConfig::default(),
        vec![commit_ev("refs/heads/x", Some(7), None)],
    );
    assert_eq!(r.outcome(7), Some(RemapOutcome::Rewritten));
}

#[test]
fn host_flagging_marks_rewritten() {
    let mut r = Remap::new(RemapConfig::default());
    let old = oid(b"3333333333333333333333333333333333333333");
    r.apply(
        commit_ev("refs/heads/x", Some(1), Some(old)),
        &mut Vec::new(),
    )
    .unwrap();
    r.flag_mark_rewritten(1); // canonical-digest bookkeeping (decision 1)
    assert_eq!(r.outcome(1), Some(RemapOutcome::Rewritten));
    let cm = r.commit_map();
    assert_eq!(
        cm.get(&old),
        Some(None),
        "rewritten commits have no new OID yet"
    );
}

#[test]
fn identity_noop_passthrough() {
    let (_, out) = run_remap(RemapConfig::default(), sample_stream());
    let input = sample_stream();
    assert_eq!(
        out[..2],
        input[..2],
        "unchanged commits pass through untouched"
    );
    // The reset passes through too (its tip lineage is unchanged).
    assert_eq!(out[2], input[2]);
}

#[test]
fn finish_emits_reset_for_rewritten_tips() {
    let old2 = oid(b"2222222222222222222222222222222222222222");
    let mut r = Remap::new(RemapConfig::default());
    for ev in sample_stream() {
        r.apply(ev, &mut Vec::new()).unwrap();
    }
    r.flag_mark_rewritten(2);
    let mut out = Vec::new();
    r.finish(&mut out).unwrap();
    assert_eq!(
        out,
        vec![Event::Reset {
            ref_name: BString::from(b"refs/tags/v1".to_vec()),
            from: Some(Committish::Mark(2)),
        }]
    );
    // map bookkeeping: tip oid resolves to mark 2
    let maps = r.ref_maps();
    assert_eq!(maps[0].old_tip, Some(old2));
    assert_eq!(maps[0].new_tip, Some(2));
}

#[test]
fn finalize_from_marks_completes_map() {
    let old1 = oid(b"1111111111111111111111111111111111111111");
    let new2 = oid(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let mut r = Remap::new(RemapConfig::default());
    for ev in sample_stream() {
        r.apply(ev, &mut Vec::new()).unwrap();
    }
    r.flag_mark_rewritten(2);

    let mut marks = MarkFile::new();
    marks.insert(1, old1);
    marks.insert(2, new2); // fast-import materialized the new commit
    r.finalize_from_marks(&marks);

    let cm = r.final_commit_map();
    assert_eq!(
        cm.get(&old1),
        Some(Some(&old1)),
        "unchanged commits keep their hash"
    );
    assert_eq!(
        cm.get(&oid(b"2222222222222222222222222222222222222222")),
        Some(Some(&new2)),
        "rewritten commits map to their new hash"
    );
}

#[test]
fn message_oid_harvesting() {
    let cfg = RemapConfig {
        track_message_oids: true,
        ..RemapConfig::default()
    };
    let mut r = Remap::new(cfg);
    let referenced = oid(b"4444444444444444444444444444444444444444");
    let mut c = match commit_ev("refs/heads/x", Some(1), None) {
        Event::Commit(c) => c,
        _ => unreachable!(),
    };
    c.message = Data(b"Reverts commit 4444444444444444444444444444444444444444\n".to_vec());
    r.apply(Event::Commit(c), &mut Vec::new()).unwrap();
    assert_eq!(r.message_oids().count(), 1);
    assert!(r.message_oids().any(|o| *o == referenced));
}

#[test]
fn transform_contract() {
    use gfx_core::test_kit;
    let events = sample_stream();
    test_kit::assert_deterministic(|| Remap::new(RemapConfig::default()), events.clone());
    test_kit::assert_finish_idempotent(|| Remap::new(RemapConfig::default()), events);
}

#[test]
fn reset_returns_to_fresh_state() {
    let mut r = Remap::new(RemapConfig::default());
    for ev in sample_stream() {
        r.apply(ev, &mut Vec::new()).unwrap();
    }
    assert_eq!(r.stats().commits_observed, 2);
    r.reset();
    assert_eq!(r.stats().commits_observed, 0, "reset restores fresh state");
    assert_eq!(r.outcome(1), None);
}
