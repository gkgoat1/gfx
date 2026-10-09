#![no_main]
//! Fuzz target: arbitrary fast-export streams must flow through the
//! enforce-ignore pass (external rules + stream-carried rule tracking)
//! without panicking (plan-stream-files.md M6). Rules are fuzzed too:
//! the first NUL-separated chunk is the external ruleset.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    use gfx_core::{Parser, ParseOptions, Transform};
    use gfx_enforce_ignore::{EnforceIgnore, EnforceIgnoreConfig};
    let (rules, stream) = match data.iter().position(|&b| b == 0x00) {
        Some(i) => (&data[..i], &data[i + 1..]),
        None => (&data[..], &[][..]),
    };
    let mut parser = Parser::new(ParseOptions::default());
    parser.feed(stream);
    let mut pass = EnforceIgnore::new(EnforceIgnoreConfig {
        external_rules: vec![gfx_ignore::BString::from(rules)],
        stream_rules: true,
        ..Default::default()
    });
    let mut out = Vec::new();
    while let Ok(Some(ev)) = parser.next_event() {
        if pass.apply(ev, &mut out).is_err() {
            return;
        }
    }
    let _ = parser.finish(&mut out);
    let _ = pass.finish(&mut out);
});
