//! Fuzz/property smoke for the redact pass (plan-redact-idents.md R10).
//! Runs as a normal `#[test]` so CI needs no libFuzzer install; the
//! cargo-fuzz target `fuzz/fuzz_targets/redact_roundtrip.rs` exercises the
//! same entry points with arbitrary bytes on nightly.

use gfx_core::prelude::*;
use gfx_redact::{
    IdentMode, PseudonymStyle, Redact, RedactConfig, TimeBucketUnit, TimeMode,
};

/// Deterministic pseudo-random byte generator (xorshift64*).
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

    fn byte(&mut self) -> u8 {
        (self.next() >> 24) as u8
    }

    fn choose<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[(self.next() % xs.len() as u64) as usize]
    }
}

/// Feed generated ident lines and time raws through every built-in mode:
/// no panics, errors only where documented (overflow), and determinism
/// holds for every accepted input.
#[test]
fn fuzz_smoke_no_panic_across_modes() {
    let mut rng = XorShift(0x9E37_79B9_7F4A_7C15);
    let modes = [
        TimeMode::Preserve,
        TimeMode::Zero,
        TimeMode::Shift(31_536_000),
        TimeMode::Shift(-31_536_000),
        TimeMode::Bucket(TimeBucketUnit::Day),
        TimeMode::Bucket(TimeBucketUnit::Week),
        TimeMode::Bucket(TimeBucketUnit::Month),
        TimeMode::Fuzz {
            jitter_secs: 86_400,
        },
        TimeMode::Fuzz { jitter_secs: u64::MAX }, // span math must not overflow
    ];
    let ident_modes = [
        IdentMode::Preserve,
        IdentMode::Pseudonymize(PseudonymStyle::Ordinal),
        IdentMode::Pseudonymize(PseudonymStyle::Hash),
    ];

    for _ in 0..2_000 {
        let mode = *rng.choose(&modes);
        let ident_mode = rng.choose(&ident_modes).clone();
        let cfg = RedactConfig {
            ident_mode,
            time_mode: mode,
            seed: rng.next(),
            ..RedactConfig::default()
        };
        // Random but self-consistent time: raw always encodes (epoch, tz)
        // exactly as the parser would produce, so preserve-mode pass-through
        // keeps the raw/epoch agreement invariant meaningful. The lenient
        // corner (unparseable raw, zero-filled fields) is covered too.
        let epoch: i64 = match rng.next() % 3 {
            0 => i64::MAX - (rng.next() % 10) as i64,
            1 => -((rng.next() % 10) as i64),
            _ => (rng.next() % 2_000_000_000) as i64,
        };
        let tz: i16 = (rng.next() % 24 * 60) as i16 - 720;
        let (raw, epoch, tz) = if rng.next() % 8 == 0 {
            ("not a timestamp".to_string(), 0, 0)
        } else {
            (
                format!("{epoch} {}{:02}{:02}", if tz < 0 { '-' } else { '+' }, tz.abs() / 60, tz.abs() % 60),
                epoch,
                tz,
            )
        };
        let ev = Event::Commit(Commit {
            ref_name: BString::from(b"refs/heads/main".to_vec()),
            mark: Some(1),
            original_oid: None,
            author: Some(Ident {
                name: BString::from(vec![rng.byte(), rng.byte(), b'x']),
                email: BString::from(b"a@x".to_vec()),
                time: Timestamp {
                    raw: BString::from(raw.into_bytes()),
                    epoch,
                    tz_offset_min: tz,
                },
            }),
            committer: None,
            encoding: None,
            message: Data(b"m\n".to_vec()),
            from: None,
            merges: Vec::new(),
            ops: Vec::new(),
        });

        let mut a = Redact::new(cfg.clone());
        let mut b = Redact::new(cfg);
        let mut out_a = Vec::new();
        let mut out_b = Vec::new();
        let ra = a.apply(ev.clone(), &mut out_a);
        let rb = b.apply(ev, &mut out_b);
        assert_eq!(ra.is_err(), rb.is_err(), "same input must accept identically");
        if let Ok(()) = ra {
            assert_eq!(out_a, out_b, "determinism under fuzz inputs");
            // Whenever the raw is canonical `<int> <±HHMM>`, the parsed
            // epoch must agree with it (writer/parser round-trip honesty).
            for e in &out_a {
                if let Event::Commit(c) = e {
                    for id in [c.author.as_ref(), c.committer.as_ref()].into_iter().flatten() {
                        let t = &id.time;
                        if let Ok(text) = std::str::from_utf8(t.raw.as_slice()) {
                            if let Some((num, tz)) = text.split_once(' ') {
                                let canonical = tz.len() == 5
                                    && (tz.starts_with('+') || tz.starts_with('-'))
                                    && tz[1..].bytes().all(|b| b.is_ascii_digit());
                                if canonical {
                                    if let Ok(parsed) = num.parse::<i64>() {
                                        assert_eq!(
                                            parsed, t.epoch,
                                            "raw {text:?} disagrees with epoch {}",
                                            t.epoch
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
