#![no_main]
//! Fuzz target: the gitignore matcher must be total (no panics, no hangs)
//! over arbitrary rule bytes and path bytes (plan-stream-files.md M2/M6).
//!
//! Layout: `n_rules | rule line 1 \n ... \n 0x00 | path`. A ruleset is
//! parsed from the rule section, then the path is judged both directly
//! and with ancestors.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some(sep) = data.iter().position(|&b| b == 0x00) else {
        return;
    };
    let (rules, path) = data.split_at(sep);
    let path = &path[1..];
    let mut rs = gfx_ignore::Ruleset::new();
    rs.push_file(gfx_ignore::BString::from(""), gfx_ignore::parse_rules(rules));
    let _ = rs.judge(path, false);
    let _ = rs.judge_with_ancestors(path, false);
    let _ = rs.judge_with_ancestors(path, true);
});
