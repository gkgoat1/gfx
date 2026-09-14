//! Fuzz smoke for blob-xform (plan-blob-xform.md §5, M3): runs the same
//! invariant as `fuzz/fuzz_targets/blob_xform_roundtrip.rs` as a normal
//! `#[test]`, so CI needs no libFuzzer install. Random byte streams are
//! parsed and driven through rotating configs; when the pass reports zero
//! alterations, its output event sequence must equal the parsed input
//! sequence (G3 no-op elision / D1 retention is byte-exact).

use gfx_blob_xform::{
    builtins, BlobTransform, BlobXform, BlobXformConfig, PathRule, SharedBlobTransform,
};
use gfx_core::{DataRef, Event, FileOp, FileSource, Parser, ParseOptions, Transform};
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

fn rule(ext: &[u8]) -> PathRule {
    PathRule {
        extension: ext.to_vec(),
        transforms: vec![SharedBlobTransform(Arc::new(Adversarial))],
        skip_larger_than: None,
        max_output_bytes: None,
    }
}

fn config(n: u8) -> BlobXformConfig {
    match n % 8 {
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
        3 => BlobXformConfig {
            transforms: vec![
                SharedBlobTransform(Arc::new(Adversarial)),
                SharedBlobTransform(Arc::new(builtins::CrlfToLf)),
            ],
            include_inline: false,
            ..Default::default()
        },
        4 => BlobXformConfig { path_rules: vec![rule(b"rs")], ..Default::default() },
        5 => BlobXformConfig {
            transforms: vec![SharedBlobTransform(Arc::new(builtins::CrlfToLf))],
            path_rules: vec![rule(b"rs"), rule(b"py")],
            ..Default::default()
        },
        6 => BlobXformConfig {
            path_rules: vec![rule(b"rs")],
            include_special_modes: true,
            include_inline: false,
            ..Default::default()
        },
        _ => BlobXformConfig {
            path_rules: vec![PathRule { skip_larger_than: Some(64), ..rule(b"rs") }],
            ..Default::default()
        },
    }
}

/// A valid blob + commit fragment referencing the blob at an .rs path
/// (and, for odd marks, a .py path), so path-rule machinery engages.
fn alloc_fragment(mark: u64, bytes: &[u8; 3]) -> Vec<u8> {
    let py = if mark % 2 == 1 { format!("M 100644 :{mark} b.py\n") } else { String::new() };
    format!(
        "blob\nmark :{mark}\ndata 3\n{}\ncommit refs/heads/main\nmark :{}\n\
         committer T <t@t> 1112912053 +0000\ndata 2\nmx\nM 100644 :{mark} a.rs\n{py}",
        String::from_utf8_lossy(bytes),
        mark + 1,
    )
    .into_bytes()
}

fn max_mark(evs: &[Event]) -> Option<u64> {
    evs.iter()
        .filter_map(|ev| match ev {
            Event::Commit(c) => c.mark,
            Event::Tag(t) => t.mark,
            Event::Blob { mark, .. } => *mark,
            _ => None,
        })
        .max()
}

#[test]
fn random_streams_never_panic_and_retention_is_exact() {
    let mut rng = XorShift(0x9E37_79B9_7F4A_7C15);
    let mut created_total = 0u64;
    let mut examined_total = 0u64;
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
        // Every fourth case: splice a syntactically valid blob+commit
        // fragment (with an .rs M op) into the noise, so path rules
        // actually fire — pure noise almost never parses to M ops.
        if case % 4 == 3 {
            let mark = (rng.next() % 50) + 1;
            let fragment = alloc_fragment(mark, &[(rng.next() % 256) as u8; 3]);
            let at = (rng.next() as usize) % (data.len() + 1);
            data.splice(at..at, fragment);
        }

        let mut parser = Parser::new(ParseOptions::default());
        parser.feed(&data);
        let mut input_evs = Vec::new();
        while let Ok(Some(ev)) = parser.next_event() {
            input_evs.push(ev);
        }

        let mut cfg = config(data[0]);
        // D3: mirror the driver's mark_base injection.
        if !cfg.path_rules.is_empty() {
            let Some(base) = max_mark(&input_evs).unwrap_or(0).checked_add(1) else {
                continue; // u64::MAX marks: the driver errors; skip
            };
            cfg.mark_base = Some(base);
        }
        let mut xform = BlobXform::new(cfg);
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
        let rule_rewrites: u64 = xform.report().rules.iter().map(|r| r.ops_rewritten).sum();
        if xform.report().altered == 0 && rule_rewrites == 0 {
            assert_eq!(out, input_evs, "case {case}: zero alterations ⇒ byte-exact retention");
        }
        // Synthetic marks: ≥ base, defined (as blobs) before use (R2/R3).
        if let Some(base) = max_mark(&input_evs).and_then(|m| m.checked_add(1)) {
            let mut defined: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
            for ev in &out {
                match ev {
                    Event::Blob { mark: Some(m), .. } => {
                        defined.insert(*m);
                    }
                    Event::Commit(c) => {
                        for op in &c.ops {
                            if let FileOp::Modify {
                                source: FileSource::DataRef(DataRef::Mark(m)), ..
                            } = op
                            {
                                if *m >= base {
                                    assert!(
                                        defined.contains(m),
                                        "case {case}: synthetic :{m} used before definition"
                                    );
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        // Counter sanity: examined == altered + unchanged + retained.
        let r = xform.report();
        assert_eq!(
            r.blobs_examined,
            r.altered + r.unchanged + r.retained_failed + r.retained_guard,
            "case {case}: counters must partition the examined blobs"
        );
        created_total += r.rules.iter().map(|x| x.blobs_created).sum::<u64>();
        examined_total += r.rules.iter().map(|x| x.ops_examined).sum::<u64>();
        for rule in &r.rules {
            assert_eq!(
                rule.ops_examined,
                rule.ops_rewritten + rule.unchanged + rule.retained_failed + rule.retained_guard,
                "case {case}: per-rule counter partition (D9)"
            );
        }
    }
}
