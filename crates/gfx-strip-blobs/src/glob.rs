//! Byte glob matcher for path selection (plan §5.2): dependency-free,
//! `no_std`, operating on raw bytes — never UTF-8 assumptions.
//!
//! Syntax (the documented v1 subset):
//!
//! | Pattern | Matches |
//! |---|---|
//! | `?` | exactly one byte (never `/`) |
//! | `*` | zero or more bytes (never `/`) |
//! | `**` | zero or more path segments, when it forms a whole component (`a/**/b` ≈ `a/b` too; `**/x` matches at any depth); a trailing `**` (`a/**`) matches everything below `a/` |
//! | `[abc]`, `[a-z]`, `[!a-z]` | one byte from (not from) the set |
//! | anything else | literal byte |
//!
//! Matching is anchored: the whole path must match. `a**b` is two single
//! stars, not a doublestar. Implementation is a plain recursive matcher —
//! recursion depth is bounded by path length, which is fine for
//! history-rewriting tools (paths are small; this is not a hot loop).

/// Does `path` (raw bytes) match `glob` (raw bytes)?
pub fn glob_match(glob: &[u8], path: &[u8]) -> bool {
    match_one(glob, path)
}

fn match_one(glob: &[u8], path: &[u8]) -> bool {
    if glob.is_empty() {
        return path.is_empty();
    }
    match glob[0] {
        b'*' if is_doublestar(glob, 0) && segment_doublestar(glob, 0) => {
            let after = if glob.get(2) == Some(&b'/') { 3 } else { 2 };
            // Trailing `**` (or `**/`): everything remaining matches.
            if after >= glob.len() {
                return true;
            }
            // Zero segments.
            if match_one(&glob[after..], path) {
                return true;
            }
            // One-or-more segments: retry after each `/`.
            for (i, &b) in path.iter().enumerate() {
                if b == b'/' && match_one(glob, &path[i + 1..]) {
                    return true;
                }
            }
            false
        }
        b'*' => {
            // Zero or more non-`/` bytes.
            for i in 0..=path.len() {
                if i > 0 && path[i - 1] == b'/' {
                    break;
                }
                if match_one(&glob[1..], &path[i..]) {
                    return true;
                }
            }
            false
        }
        b'?' => !path.is_empty() && path[0] != b'/' && match_one(&glob[1..], &path[1..]),
        b'[' => {
            if path.is_empty() {
                return false;
            }
            match match_class(glob, 0, path[0]) {
                Some(next) => path[0] != b'/' && match_one(&glob[next..], &path[1..]),
                None => false,
            }
        }
        c => !path.is_empty() && path[0] == c && match_one(&glob[1..], &path[1..]),
    }
}

fn is_doublestar(glob: &[u8], i: usize) -> bool {
    glob.get(i) == Some(&b'*') && glob.get(i + 1) == Some(&b'*')
}

/// A `**` that is a whole component: preceded by start-or-`/` and followed
/// by end-or-`/`.
fn segment_doublestar(glob: &[u8], i: usize) -> bool {
    let prev_ok = i == 0 || glob[i - 1] == b'/';
    let next_ok = i + 2 >= glob.len() || glob[i + 2] == b'/';
    prev_ok && next_ok
}

/// Match a `[...]` class at `glob[gi]` against byte `b`; returns the glob
/// index just past the class on success. Unterminated classes never match.
fn match_class(glob: &[u8], gi: usize, b: u8) -> Option<usize> {
    let mut i = gi + 1;
    let negate = glob.get(i) == Some(&b'!') || glob.get(i) == Some(&b'^');
    if negate {
        i += 1;
    }
    let mut matched = false;
    let mut first = true;
    while i < glob.len() && (glob[i] != b']' || first) {
        first = false;
        // Range a-z (raw byte ranges; both endpoints literal). `]` as first
        // byte is a literal (handled by `first`).
        if glob.get(i + 1) == Some(&b'-') && glob.get(i + 2).is_some_and(|&c| c != b']') {
            let (lo, hi) = (glob[i], glob[i + 2]);
            if lo <= b && b <= hi {
                matched = true;
            }
            i += 3;
        } else {
            if glob[i] == b {
                matched = true;
            }
            i += 1;
        }
    }
    if i >= glob.len() {
        return None; // unterminated class
    }
    if matched != negate {
        Some(i + 1) // past ']'
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    fn m(glob: &str, path: &str) -> bool {
        super::glob_match(glob.as_bytes(), path.as_bytes())
    }

    #[test]
    fn literals() {
        assert!(m("a.txt", "a.txt"));
        assert!(!m("a.txt", "b.txt"));
        assert!(!m("a.txt", "dir/a.txt"), "anchored, not basename");
        assert!(m("", ""));
        assert!(!m("", "x"));
    }

    #[test]
    fn single_star_never_crosses_slash() {
        assert!(m("*.txt", "a.txt"));
        assert!(m("*.txt", ".txt"));
        assert!(!m("*.txt", "dir/a.txt"));
        assert!(m("dir/*.txt", "dir/a.txt"));
        assert!(!m("dir/*.txt", "dir/sub/a.txt"));
    }

    #[test]
    fn doublestar_matches_any_depth() {
        assert!(m("**/Cargo.lock", "Cargo.lock"));
        assert!(m("**/Cargo.lock", "a/b/Cargo.lock"));
        assert!(m("**/Cargo.lock", "vendor/Cargo.lock"));
        assert!(m("vendor/**", "vendor/x/y.bin"));
        assert!(m("vendor/**", "vendor/"));
        assert!(!m("vendor/**", "vendorx/y.bin"));
        assert!(!m("vendor/**", "vendor"));
        assert!(m("a/**/b", "a/b"));
        assert!(m("a/**/b", "a/x/y/b"));
        assert!(!m("a/**/b", "a/x/b/c"));
    }

    #[test]
    fn question_mark_and_classes() {
        assert!(m("?.txt", "a.txt"));
        assert!(!m("?.txt", "/.txt"));
        assert!(m("[abc].txt", "b.txt"));
        assert!(!m("[abc].txt", "d.txt"));
        assert!(m("[a-c].txt", "b.txt"));
        assert!(!m("[a-c].txt", "d.txt"));
        assert!(m("[!a-c].txt", "d.txt"));
        assert!(!m("[!a-c].txt", "a.txt"));
        assert!(m("[]]x", "]x"), "']' first in class is literal");
        assert!(!m("[", "x"), "unterminated class never matches");
    }

    #[test]
    fn bytes_not_utf8() {
        let glob: &[u8] = b"data/\x80\xff.bin";
        assert!(super::glob_match(glob, b"data/\x80\xff.bin"));
        assert!(super::glob_match(b"**/*.bin", b"\xc3\x28/x.bin"));
        assert!(!super::glob_match(b"**/*.bin", b"\xc3\x28/x.txn"));
    }
}
