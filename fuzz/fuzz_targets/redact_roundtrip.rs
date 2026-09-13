#![no_main]
//! Fuzz target: arbitrary fast-export streams must parse and flow through
//! the redact pass without panicking — including the checked time
//! arithmetic (TimestampOutOfRange surfaces as an error, never a wrap) and
//! the pseudonym/ledger machinery (plan-redact-idents.md R10).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    use gfx_core::{Parser, ParseOptions, Transform};
    use gfx_redact::{IdentMode, Redact, RedactConfig, TimeMode};

    // Rotate through the interesting configurations on stream nibble 0.
    let cfg = match data.first().map(|b| b % 4) {
        Some(0) => RedactConfig {
            ident_mode: IdentMode::Pseudonymize(gfx_redact::PseudonymStyle::Ordinal),
            time_mode: TimeMode::Zero,
            ..RedactConfig::default()
        },
        Some(1) => RedactConfig {
            ident_mode: IdentMode::Pseudonymize(gfx_redact::PseudonymStyle::Hash),
            time_mode: TimeMode::Shift(i64::from(data.first().copied().unwrap_or(0)) - 128),
            ..RedactConfig::default()
        },
        Some(2) => RedactConfig {
            ident_mode: IdentMode::Preserve,
            time_mode: TimeMode::Bucket(gfx_redact::TimeBucketUnit::Month),
            keep_tz: true,
            ..RedactConfig::default()
        },
        _ => RedactConfig {
            ident_mode: IdentMode::Preserve,
            time_mode: TimeMode::Fuzz {
                jitter_secs: u64::from(data.first().copied().unwrap_or(0)) * 3600,
            },
            seed: 0x9E37_79B9_7F4A_7C15,
            ..RedactConfig::default()
        },
    };

    let mut parser = Parser::new(ParseOptions::default());
    parser.feed(data);
    let mut redact = Redact::new(cfg);
    let mut out = Vec::new();
    while let Ok(Some(ev)) = parser.next_event() {
        if redact.apply(ev, &mut out).is_err() {
            return; // deterministic errors (e.g. overflow) are fine; panics are not
        }
    }
    let _ = parser.finish(&mut out);
    for ev in out.drain(..) {
        if redact.apply(ev, &mut out).is_err() {
            return;
        }
    }
    let _ = redact.finish(&mut out);
    let _ = redact.report();
});
