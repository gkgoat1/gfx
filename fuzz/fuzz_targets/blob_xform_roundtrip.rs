#![no_main]
//! Fuzz target: arbitrary fast-export streams must parse and flow through
//! the blob-xform pass without panicking, under rotating configs
//! (plan-blob-xform.md §5): the built-in transforms × size guards × inline
//! knobs, plus an injected adversarial transform that alternately fails,
//! inflates, and uppercases. Invariant: when the pass reports zero
//! alterations, its output event sequence equals the parsed input
//! sequence (G3 no-op elision / D1 retention is byte-exact).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    use gfx_blob_xform::{builtins, BlobTransform, BlobXform, BlobXformConfig, SharedBlobTransform};
    use gfx_core::{Parser, ParseOptions, Transform};
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

    // Rotate configurations on stream nibble 0.
    let cfg = match data.first().map(|b| b % 4) {
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
        _ => BlobXformConfig {
            transforms: vec![
                SharedBlobTransform(Arc::new(Adversarial)),
                SharedBlobTransform(Arc::new(builtins::CrlfToLf)),
            ],
            include_inline: false,
            ..Default::default()
        },
    };

    let mut parser = Parser::new(ParseOptions::default());
    parser.feed(data);
    let mut input_evs = Vec::new();
    while let Ok(Some(ev)) = parser.next_event() {
        input_evs.push(ev);
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

    if xform.report().altered == 0 {
        assert_eq!(out, input_evs, "zero alterations ⇒ byte-exact retention");
    }
});
