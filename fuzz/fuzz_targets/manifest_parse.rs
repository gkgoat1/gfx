#![no_main]
//! Fuzz target: the archive manifest is the one attacker-controlled parse
//! surface gfx-pack introduces (plan-multistream-pack.md M5). Arbitrary
//! bytes must never panic `Manifest::parse`; anything that parses must
//! round-trip through `to_text` → `parse` to an equal value with identical
//! text (the writer is a fixed point of the parser).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(m) = gfx_pack::Manifest::parse(text) else {
        return;
    };
    let text2 = m.to_text();
    let m2 = gfx_pack::Manifest::parse(&text2).expect("own output must reparse");
    assert_eq!(m, m2, "parse(to_text(parse(x))) must be the identity");
    let text3 = m2.to_text();
    assert_eq!(text2, text3, "to_text must be a fixed point");
});
