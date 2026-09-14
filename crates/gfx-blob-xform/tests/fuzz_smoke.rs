//! Fuzz smoke for blob-xform (plan-blob-xform.md §5, M3): runs the same
//! invariant as `fuzz/fuzz_targets/blob_xform_roundtrip.rs` as a normal
//! `#[test]`, so CI needs no libFuzzer install. Random byte streams are
//! parsed and driven through rotating configs; when the pass reports zero
//! alterations, its output event sequence must equal the parsed input
//! sequence (G3 no-op elision / D1 retention is byte-exact).

use gfx_blob_xform::{builtins, BlobTransform, BlobXform, BlobXformConfig, SharedBlobTransform};
use gfx_core::{Parser, ParseOptions, Transform};
use std::sync::Arc;

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
}

/// Same adversary as the fuzz target: fails on odd first byte, inflates
/// on a large second byte, otherwise uppercases.
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

fn config(n: u8) -> BlobXformConfig {
    match n % 4 {
        0 => BlobXformConfig {
            transforms: vec![SharedBlobTransform(Arc::new(builtins::CrlfToLf))],
            ..Default::default()
        },
        1 => BlobXformConfig {
            transforms: vec![
                SharedBlobTransform(Arc::new(builtins::CrlfToLf)),
                SharedBlobTransform(Arc::new(builtins::TrimTrailingWhitespace)),
                SharedBlobTransform(Arc::new(builtins::EnsureFinalNewline)),
            ],
            max_output_bytes: Some(1024),
            ..Default::default()
        },
        2 => BlobXformConfig {
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
    }
}

#[test]
fn random_streams_never_panic_and_retention_is_exact() {
    let mut rng = XorShift(0x9E37_79B9_7F4A_7C15);
    for case in 0..256u32 {
        // A "stream": a config byte followed by random bytes biased toward
        // fast-export tokens so the parser frequently accepts chunks.
        let len = (rng.next() % 512) as usize;
        let mut data = Vec::with_capacity(len + 1);
        data.push((rng.next() % 256) as u8); // config selector
        for _ in 0..len {
            data.push(match rng.next() % 10 {
                0 => b'\n',
                1 => b':',
                2 => b' ',
                3 => b'a' + (rng.next() % 26) as u8,
                4 => b'0' + (rng.next() % 10) as u8,
                5 => 0xff,
                _ => (rng.next() % 256) as u8,
            });
        }

        let mut parser = Parser::new(ParseOptions::default());
        parser.feed(&data);
        let mut input_evs = Vec::new();
        while let Ok(Some(ev)) = parser.next_event() {
            input_evs.push(ev);
        }

        let mut xform = BlobXform::new(config(data[0]));
        let mut out = Vec::new();
        let mut stream_failed = false;
        for ev in input_evs.iter().cloned() {
            if xform.apply(ev, &mut out).is_err() {
                stream_failed = true;
                break;
            }
        }
        if stream_failed || xform.finish(&mut out).is_err() {
            continue; // stream-level errors are fine; panics are not
        }
        if xform.report().altered == 0 {
            assert_eq!(out, input_evs, "case {case}: zero alterations ⇒ byte-exact retention");
        }
        // Counter sanity: examined == altered + unchanged + retained.
        let r = xform.report();
        assert_eq!(
            r.blobs_examined,
            r.altered + r.unchanged + r.retained_failed + r.retained_guard,
            "case {case}: counters must partition the examined blobs"
        );
    }
}
