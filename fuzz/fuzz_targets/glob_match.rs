#![no_main]
//! Fuzz target: the byte glob matcher must be total (no panics) over
//! arbitrary glob/path bytes (plan §7 P3).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let split = (data[0] as usize) % data.len();
    let (glob, path) = data.split_at(split);
    let _ = gfx_strip_blobs::glob_match(glob, path);
});
