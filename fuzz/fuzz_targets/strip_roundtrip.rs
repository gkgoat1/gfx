#![no_main]
//! Fuzz target: arbitrary fast-export streams must parse and flow through
//! the strip pass without panicking (parser-robustness property P7 in the
//! presence of a content pass).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    use gfx_core::{Parser, ParseOptions, Transform};
    use gfx_strip_blobs::StripBlobs;
    let mut parser = Parser::new(ParseOptions::default());
    parser.feed(data);
    let mut strip = StripBlobs::new(Default::default());
    let mut out = Vec::new();
    while let Ok(Some(ev)) = parser.next_event() {
        if strip.apply(ev, &mut out).is_err() {
            return;
        }
    }
    let _ = parser.finish(&mut out);
    let _ = strip.finish(&mut out);
});
