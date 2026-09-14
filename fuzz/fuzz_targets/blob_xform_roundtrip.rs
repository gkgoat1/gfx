#![no_main]
//! Fuzz target: arbitrary fast-export streams must parse and flow through
//! the blob-xform pass without panicking, under rotating configs
//! (plan-blob-xform.md §5): the built-in transforms × size guards × inline
//! knobs, plus an injected adversarial transform that alternately fails,
//! inflates, and uppercases. Invariant: when the pass reports zero
//! alterations, its output event sequence equals the parsed input
//! sequence (G3 no-op elision / D1 retention is byte-exact).

use libfuzzer_sys::fuzz_target;

fn xform_base(evs: &[gfx_core::Event]) -> Option<u64> {
    use gfx_core::Event;
    evs.iter()
        .filter_map(|ev| match ev {
            Event::Commit(c) => c.mark,
            Event::Tag(t) => t.mark,
            Event::Blob { mark, .. } => *mark,
            _ => None,
        })
        .max()
        .and_then(|m| m.checked_add(1))
}

fuzz_target!(|data: &[u8]| {
    use gfx_blob_xform::{
        builtins, BlobTransform, BlobXform, BlobXformConfig, PathRule, SharedBlobTransform,
    };
    use gfx_core::{Event, Parser, ParseOptions, Transform};
    use std::sync::Arc;

    /// Adversarial injected transform driven by content bytes: fails when
    /// the first byte is odd, inflates when the second byte is >= 0xF0,
    /// otherwise uppercases.
    struct Adversarial;
    impl BlobTransform for Adversarial {
        fn name(&self) -> &'static str {
            "adversarial"
        }
        fn apply(&self, blob: &[u8]) -> Result<Vec<u8>, ()> {
            match (blob.first(), blob.get(1)) {
                (Some(f), _) if f % 2 == 1 => Err(()),
                (Some(_), Some(s)) if *s >= 0xF0 => Ok(vec![b'x'; 4096]),
                _ => Ok(blob.iter().map(u8::to_ascii_uppercase).collect()),
            }
        }
    }

    let rule = |ext: &[u8]| PathRule {
        extension: ext.to_vec(),
        transforms: vec![SharedBlobTransform(Arc::new(Adversarial))],
        skip_larger_than: None,
        max_output_bytes: None,
    };
    // Rotate configurations on stream nibble 0; variants 4–7 add path
    // rules (plan-blob-xform-paths.md): synthetic marks, cached
    // judgments, and mode guards under adversarial streams.
    let mut cfg = match data.first().map(|b| b % 8) {
        Some(0) => BlobXformConfig {
            transforms: vec![SharedBlobTransform(Arc::new(builtins::CrlfToLf))],
            ..Default::default()
        },
        Some(1) => BlobXformConfig {
            transforms: vec![
                SharedBlobTransform(Arc::new(builtins::CrlfToLf)),
                SharedBlobTransform(Arc::new(builtins::TrimTrailingWhitespace)),
                SharedBlobTransform(Arc::new(builtins::EnsureFinalNewline)),
            ],
            max_output_bytes: Some(1024),
            ..Default::default()
        },
        Some(2) => BlobXformConfig {
            transforms: vec![SharedBlobTransform(Arc::new(Adversarial))],
            skip_larger_than: Some(512),
            include_special_modes: true,
            ..Default::default()
        },
        Some(3) => BlobXformConfig {
            transforms: vec![
                SharedBlobTransform(Arc::new(Adversarial)),
                SharedBlobTransform(Arc::new(builtins::CrlfToLf)),
            ],
            include_inline: false,
            ..Default::default()
        },
        Some(4) => BlobXformConfig { path_rules: vec![rule(b"rs")], ..Default::default() },
        Some(5) => BlobXformConfig {
            transforms: vec![SharedBlobTransform(Arc::new(builtins::CrlfToLf))],
            path_rules: vec![rule(b"rs"), rule(b"py")],
            ..Default::default()
        },
        Some(6) => BlobXformConfig {
            path_rules: vec![rule(b"rs")],
            include_special_modes: true,
            include_inline: false,
            ..Default::default()
        },
        _ => BlobXformConfig {
            path_rules: vec![PathRule {
                skip_larger_than: Some(64),
                ..rule(b"rs")
            }],
            ..Default::default()
        },
    };

    let mut parser = Parser::new(ParseOptions::default());
    parser.feed(data);
    let mut input_evs = Vec::new();
    while let Ok(Some(ev)) = parser.next_event() {
        input_evs.push(ev);
    }

    // D3: the driver computes this in production; mirror it here.
    if !cfg.path_rules.is_empty() {
        let max_mark = input_evs
            .iter()
            .filter_map(|ev| match ev {
                Event::Commit(c) => c.mark,
                Event::Tag(t) => t.mark,
                Event::Blob { mark, .. } => *mark,
                _ => None,
            })
            .max()
            .unwrap_or(0);
        let Some(base) = max_mark.checked_add(1) else {
            return; // u64::MAX marks: the driver errors; nothing to fuzz
        };
        cfg.mark_base = Some(base);
    }

    let mut xform = BlobXform::new(cfg);
    let mut out = Vec::new();
    for ev in input_evs.iter().cloned() {
        if xform.apply(ev, &mut out).is_err() {
            return; // stream-level errors are fine; panics are not
        }
    }
    if xform.finish(&mut out).is_err() {
        return;
    }

    let report = xform.report();
    let rule_rewrites: u64 = report.rules.iter().map(|r| r.ops_rewritten).sum();
    if report.altered == 0 && rule_rewrites == 0 {
        assert_eq!(out, input_evs, "zero alterations ⇒ byte-exact retention");
    }
    // Synthetic marks: ≥ base, and each defined (as a blob) before any
    // commit references it (R2/R3 made total).
    if let Some(base) = xform_base(&input_evs) {
        let mut defined: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
        for ev in &out {
            match ev {
                Event::Blob { mark: Some(m), .. } => {
                    defined.insert(*m);
                }
                Event::Commit(c) => {
                    for op in &c.ops {
                        if let gfx_core::FileOp::Modify {
                            source: gfx_core::FileSource::DataRef(gfx_core::DataRef::Mark(m)),
                            ..
                        } = op
                        {
                            if *m >= base {
                                assert!(defined.contains(m), "synthetic :{m} used before definition");
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
});
