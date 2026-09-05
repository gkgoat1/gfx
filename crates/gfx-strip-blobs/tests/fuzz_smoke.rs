//! Fuzz/property smoke for the byte glob matcher (plan §7 P3). Runs as a
//! normal `#[test]` so CI needs no libFuzzer install; the cargo-fuzz target
//! in `fuzz/` exercises the same entry point with arbitrary bytes on
//! nightly (see docs/plan-pass-driver-strip-blobs.md P3).

use gfx_strip_blobs::glob_match;

/// Deterministic pseudo-random byte generator (xorshift64*); no external
/// RNG dependency in the test suite.
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
}

/// Property: the matcher must never panic, and must never match a path
/// that a plain literal scan rules out.
#[test]
fn fuzz_smoke_no_panic_and_literal_soundness() {
    let mut rng = XorShift(0x9E3779B97F4A7C15);
    for _ in 0..50_000 {
        let g_len = (rng.next() % 24) as usize;
        let p_len = (rng.next() % 24) as usize;
        let glob: Vec<u8> = (0..g_len).map(|_| glob_byte(&mut rng)).collect();
        let path: Vec<u8> = (0..p_len).map(|_| path_byte(&mut rng)).collect();
        let matched = glob_match(&glob, &path);
        // Soundness: a glob with no metacharacters must match iff equal.
        let plain = !glob.iter().any(|&b| matches!(b, b'*' | b'?' | b'[' | b']'));
        if plain {
            assert_eq!(matched, glob == path, "literal glob {glob:?} vs {path:?}");
        }
        // Additional invariant: empty glob matches only the empty path.
        if glob.is_empty() {
            assert_eq!(matched, path.is_empty());
        }
    }
}

fn glob_byte(rng: &mut XorShift) -> u8 {
    const SPECIAL: &[u8] = b"*?[]!/";
    if rng.next() % 4 == 0 {
        SPECIAL[(rng.next() as usize) % SPECIAL.len()]
    } else {
        (b'a' + (rng.next() % 26) as u8)
    }
}

fn path_byte(rng: &mut XorShift) -> u8 {
    if rng.next() % 6 == 0 {
        b'/'
    } else {
        (b'a' + (rng.next() % 26) as u8)
    }
}

/// The documented examples from the matcher's table must hold (regression
/// anchors for the fuzz corpus).
#[test]
fn documented_examples() {
    for (g, p) in [
        ("**/Cargo.lock", "Cargo.lock"),
        ("**/Cargo.lock", "a/b/Cargo.lock"),
        ("vendor/**", "vendor/x/y.bin"),
        ("a/**/b", "a/x/y/b"),
        ("*.txt", "a.txt"),
        ("?.txt", "a.txt"),
        ("[a-c].txt", "b.txt"),
        ("[!a-c].txt", "d.txt"),
    ] {
        assert!(glob_match(g.as_bytes(), p.as_bytes()), "{g} vs {p}");
    }
    for (g, p) in [
        ("*.txt", "dir/a.txt"),
        ("vendor/**", "vendorx/y.bin"),
        ("a/**/b", "a/x/b/c"),
        ("[a-c].txt", "d.txt"),
    ] {
        assert!(!glob_match(g.as_bytes(), p.as_bytes()), "{g} vs {p}");
    }
}
