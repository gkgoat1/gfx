//! Facade-level properties: P3 (identity pipeline) through `rewrite`, plus
//! end-to-end remap through the single-call API.

#![cfg(feature = "std")]

use gfx::prelude::*;

fn fast_export_stream() -> Vec<u8> {
    let mut s = Vec::new();
    s.extend_from_slice(b"blob\nmark :1\ndata 6\nhello\n\n");
    s.extend_from_slice(b"commit refs/heads/main\n");
    s.extend_from_slice(b"mark :2\n");
    s.extend_from_slice(b"original-oid 1111111111111111111111111111111111111111\n");
    s.extend_from_slice(b"committer C O Mitter <c@example.com> 1112912053 +0000\n");
    s.extend_from_slice(b"data 8\ninitial\n");
    s.extend_from_slice(b"M 100644 :1 file.txt\n\n");
    s.extend_from_slice(b"commit refs/heads/main\n");
    s.extend_from_slice(b"mark :3\n");
    s.extend_from_slice(b"original-oid 2222222222222222222222222222222222222222\n");
    s.extend_from_slice(b"committer C O Mitter <c@example.com> 1112912053 +0000\n");
    s.extend_from_slice(b"data 7\nsecond\n");
    s.extend_from_slice(b"from :2\n");
    s.extend_from_slice(b"M 100644 inline data.bin\n");
    s.extend_from_slice(b"data 4\n\x00\x01\x02\x03\n");
    s
}

#[test]
fn p3_identity_pipeline_through_rewrite() {
    let input = fast_export_stream();
    let mut pipeline = Pipeline::builder().build();
    let out = gfx::rewrite(&input, &mut pipeline).expect("rewrite");
    assert_eq!(out, input, "identity pipeline must be byte-identical (P3)");
}

#[cfg(feature = "remap")]
#[test]
fn rewrite_with_remap_is_identity_when_nothing_rewritten() {
    // identity_is_noop: unchanged subgraphs pass through untouched (P4).
    let input = fast_export_stream();
    let mut pipeline = Pipeline::builder()
        .push(Box::new(gfx_remap::Remap::new(
            gfx_remap::RemapConfig::default(),
        )))
        .build();
    let out = gfx::rewrite(&input, &mut pipeline).expect("rewrite");
    assert_eq!(out, input);
}

#[cfg(feature = "remap")]
#[test]
fn remap_flags_fresh_commits_and_trips_tip_resets_at_finish() {
    use gfx_core::Transform;

    // A fresh commit (no `original-oid`) is rewritten by definition; the
    // trailing `reset` to its mark is emitted at pipeline finish.
    let mut s = Vec::new();
    s.extend_from_slice(b"reset refs/heads/main\n");
    s.extend_from_slice(b"from 1111111111111111111111111111111111111111\n\n");
    s.extend_from_slice(b"commit refs/heads/main\n");
    s.extend_from_slice(b"mark :1\n");
    s.extend_from_slice(b"data 6\nfresh\n\n");

    let remap = gfx_remap::Remap::new(gfx_remap::RemapConfig::default());
    let mut pipeline = Pipeline::builder().push(Box::new(remap)).build();

    let mut parser = Parser::new(ParseOptions::default());
    parser.feed(&s);
    let mut events = Vec::new();
    while let Some(ev) = parser.next_event().expect("parse") {
        pipeline.apply(ev, &mut events).expect("apply");
    }
    let mut tail = Vec::new();
    parser.finish(&mut tail).expect("finish");
    for ev in tail {
        pipeline.apply(ev, &mut events).expect("apply");
    }
    pipeline.finish(&mut events).expect("pipeline finish");

    // A tip given as an OID that was never carried by a commit is
    // unmapped, so the stream passes through and no trailing reset fires.
    let mut w = Writer::new();
    for ev in &events {
        w.write(ev).expect("write");
    }
    assert_eq!(w.take(), s);
}
