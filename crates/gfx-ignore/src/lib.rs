#![no_std]
#![forbid(unsafe_code)]
//! `gfx-ignore` — a `no_std`, byte-exact gitignore matcher
//! (plan-stream-files.md D6).
//!
//! This is *not* a glob library; gitignore semantics differ from
//! doublestar globs in the ways that matter (research finding R7):
//!
//! - a pattern without a `/` matches the **basename** at any depth
//!   (`*.log` ignores `a/b/x.log`);
//! - a pattern with a `/` (anywhere) **anchors** at the rule file's
//!   directory (`doc/*.html` does not match `x/doc/a.html`);
//! - a trailing `/` restricts the pattern to **directories** — in path
//!   space that is the directory itself (so descendant ops are judged)
//!   and never a file of the same name;
//! - a leading `!` **negates**; last matching pattern wins across the
//!   stacked rule set;
//! - `\` escapes `!`, `#`, and a trailing space; `#` starts a comment
//!   when unescaped.
//!
//! Wildcards are git's wildmatch subset: `*` and `?` never cross `/`,
//! `**` matches across directories when it forms a whole path component
//! (leading `**/`, trailing `/**`, or mid-pattern `a/**/b` — including
//! zero directories), and `[...]` classes follow the same rules as the
//! gfx doublestar matcher. Anything else in the pattern is a literal byte.
//!
//! Matching is per **stacked ruleset**: a list of rule files, outermost
//! first, each with the directory it is anchored at (empty = repo root).
//! The last matching pattern over the whole stack decides, mirroring
//! git's ordering ("within one file last wins; deeper files override
//! shallower ones; command-line/external rules are checked before
//! in-tree files" — here the caller orders the stack: external files
//! first, then root `.gitignore`, then deeper rule files).
//!
//! Deterministic, sans-IO, no clocks, no allocation outside the parsed
//! rule set and the verdict.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

pub use bstr::{BStr, BString};
use bstr::ByteSlice;

/// One parsed gitignore pattern.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    /// Pattern text with `!`/anchor/escape handling applied.
    pub pattern: BString,
    /// `!pattern` — a match *un*-ignores.
    pub negated: bool,
    /// Trailing `/` — directories only. In path space: matches the
    /// directory itself (never a file of that name), and thereby every
    /// path beneath it (the walker judges the ancestor directory first).
    pub dir_only: bool,
    /// Pattern contains a `/` (after unescaping) ⇒ anchored at the rule
    /// file's directory. Otherwise it matches basenames at any depth.
    pub anchored: bool,
}

/// One rule file's worth of patterns, anchored at a directory.
///
/// `dir` is the directory the file conceptually lives in, relative to the
/// tree root, with no leading or trailing `/` (empty = root). Anchored
/// patterns are matched against the path *relative to* `dir`; paths
/// outside `dir` never match this file's rules.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuleFile {
    pub dir: BString,
    pub rules: Vec<Rule>,
}

/// Parse gitignore-format bytes into rules (D6). Line-based; `#` comments
/// and blank lines drop out; `\` unescapes `!`, `#`, and trailing space;
/// a leading `/` anchors (and is stripped); a trailing `/` marks
/// directories-only (and is stripped). Everything is bytes — no UTF-8
/// assumptions.
pub fn parse_rules(bytes: &[u8]) -> Vec<Rule> {
    let mut out = Vec::new();
    for raw_line in bytes.split_str(b"\n") {
        let mut line: &[u8] = raw_line;
        if line.last() == Some(&b'\r') {
            line = &line[..line.len() - 1];
        }
        if line.is_empty() {
            continue;
        }
        if line[0] == b'#' {
            continue;
        }
        // Trailing spaces are stripped unless the last one is escaped
        // (`\ `); checked on the raw line, like git's parse_path_pattern.
        while line.len() >= 1
            && line[line.len() - 1] == b' '
            && (line.len() < 2 || line[line.len() - 2] != b'\\')
        {
            line = &line[..line.len() - 1];
        }
        // Negation is decided on the raw line: an escaped `\!` is a
        // literal exclamation mark, never a negator.
        let mut negated = false;
        if line[0] == b'!' {
            negated = true;
            line = &line[1..];
        }
        if line.is_empty() {
            continue; // bare `!`
        }
        // Unescape the documented set (`\!`, `\#`, `\\`, `\ `); other
        // backslashes stay literal.
        let mut pat: Vec<u8> = Vec::with_capacity(line.len());
        let mut i = 0usize;
        while i < line.len() {
            if line[i] == b'\\' && i + 1 < line.len() {
                match line[i + 1] {
                    b'!' | b'#' | b'\\' | b' ' => {
                        pat.push(line[i + 1]);
                        i += 2;
                        continue;
                    }
                    _ => {}
                }
            }
            pat.push(line[i]);
            i += 1;
        }
        let mut body = &pat[..];
        let mut anchored = false;
        if body[0] == b'/' {
            anchored = true;
            body = &body[1..];
        }
        let mut dir_only = false;
        if body.last() == Some(&b'/') {
            dir_only = true;
            body = &body[..body.len() - 1];
        }
        if body.contains(&b'/') {
            anchored = true;
        }
        if body.is_empty() {
            continue; // pattern was only "/"
        }
        out.push(Rule {
            pattern: BString::from(body),
            negated,
            dir_only,
            anchored,
        });
    }
    out
}

/// The outcome of judging a path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    /// Ignored (`Some`) or not (`None`). When ignored, `rule` names the
    /// winning pattern for reports.
    pub ignored: bool,
    /// The deciding pattern's source: `(rule-file dir, pattern text,
    /// negated)`. `None` when no rule matched.
    pub decided_by: Option<Deciding>,
}

/// The rule that produced a verdict (for pass reports).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Deciding {
    /// Directory the rule file is anchored at (empty = root / external).
    pub file_dir: BString,
    /// The pattern as written (post-unescape, pre-anchor-strip is
    /// internal; this is the matched body).
    pub pattern: BString,
    pub negated: bool,
    /// The pattern was directories-only (`foo/`).
    pub dir_only: bool,
}

/// A stacked set of rule files (outermost first). Immutably shareable:
/// passes hold one `Arc<Ruleset>` per live mark (plan-stream-files.md D6).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ruleset {
    pub files: Vec<RuleFile>,
}

impl Ruleset {
    pub fn new() -> Self {
        Ruleset { files: Vec::new() }
    }

    /// Number of patterns across the stack.
    pub fn rule_count(&self) -> usize {
        self.files.iter().map(|f| f.rules.len()).sum()
    }

    /// Push a rule file anchored at `dir` (empty = root). The caller
    /// orders the stack: external rules first, then root, then deeper
    /// directories (last match wins across the whole stack).
    pub fn push_file(&mut self, dir: impl Into<BString>, rules: Vec<Rule>) {
        self.files.push(RuleFile {
            dir: dir.into(),
            rules,
        });
    }

    /// A ruleset with this file appended (copy-on-write helper for
    /// persistent rule-state propagation).
    pub fn with_file(&self, dir: impl Into<BString>, rules: Vec<Rule>) -> Self {
        let mut next = self.clone();
        next.push_file(dir, rules);
        next
    }

    /// Judge `path` (repo-root-relative, `/`-separated, no leading slash)
    /// directly — the single-level verdict with no ancestor walk.
    /// `is_dir` — pass `true` when judging a directory itself. Most
    /// callers want [`Self::judge_with_ancestors`]; this is the primitive
    /// the pass layer uses to judge and memoize each directory once.
    ///
    /// Last matching pattern across the stacked files wins (D6).
    pub fn judge(&self, path: &[u8], is_dir: bool) -> Verdict {
        let mut decided: Option<(&RuleFile, &Rule)> = None;
        for file in &self.files {
            for rule in &file.rules {
                if rule_matches(file, rule, path, is_dir) {
                    decided = Some((file, rule));
                }
            }
        }
        match decided {
            None => Verdict {
                ignored: false,
                decided_by: None,
            },
            Some((file, rule)) => Verdict {
                ignored: !rule.negated,
                decided_by: Some(Deciding {
                    file_dir: file.dir.clone(),
                    pattern: rule.pattern.clone(),
                    negated: rule.negated,
                    dir_only: rule.dir_only,
                }),
            },
        }
    }

    /// Full gitignore verdict for `path`: a path is ignored when **any
    /// ancestor directory** is ignored (gitignore(5): "It is not possible
    /// to re-include a file if a parent directory of that file is
    /// excluded") or the path's own direct verdict is ignored.
    ///
    /// The ancestor walk runs shallowest-first; the first excluded
    /// ancestor decides (its rule is reported as the decider). The
    /// per-level direct verdicts already implement last-match-wins across
    /// the stacked rule files, so a deeper `.gitignore` that re-includes
    /// the directory itself (`!bin/`) wins over a shallower exclusion and
    /// the walk proceeds (plan-stream-files.md D6, R7).
    pub fn judge_with_ancestors(&self, path: &[u8], is_dir: bool) -> Verdict {
        for (i, &b) in path.iter().enumerate() {
            if b == b'/' {
                let v = self.judge(&path[..i], true);
                if v.ignored {
                    return v;
                }
            }
        }
        self.judge(path, is_dir)
    }
}

/// Does `rule` (from `file`) match `path`?
fn rule_matches(file: &RuleFile, rule: &Rule, path: &[u8], is_dir: bool) -> bool {
    if rule.dir_only && !is_dir {
        return false;
    }
    if rule.anchored {
        // Path must live under the rule file's directory; match the
        // remainder against the full pattern.
        let rel = match relative_to(path, &file.dir) {
            Some(r) => r,
            None => return false,
        };
        wildmatch(&rule.pattern, rel)
    } else {
        // Basename rule: any depth, any rule-file directory the path is
        // under.
        if relative_to(path, &file.dir).is_none() {
            return false;
        }
        let base = match path.rfind_byte(b'/') {
            Some(i) => &path[i + 1..],
            None => path,
        };
        wildmatch(&rule.pattern, base)
    }
}

/// `path` relative to directory `dir` (empty dir = the path itself);
/// `None` when the path is not under `dir`.
fn relative_to<'a>(path: &'a [u8], dir: &[u8]) -> Option<&'a [u8]> {
    if dir.is_empty() {
        return Some(path);
    }
    if path.len() > dir.len() && path.starts_with(dir) && path[dir.len()] == b'/' {
        return Some(&path[dir.len() + 1..]);
    }
    None
}

/// Wildmatch subset over bytes (D6): `*`/`?` never cross `/`; `**` as a
/// whole component crosses directories (zero or more); `[...]` classes
/// follow the gfx glob rules; everything else is literal.
pub fn wildmatch(pattern: &[u8], text: &[u8]) -> bool {
    match_one(pattern, text)
}

fn match_one(pat: &[u8], text: &[u8]) -> bool {
    if pat.is_empty() {
        return text.is_empty();
    }
    match pat[0] {
        b'*' if is_component_doublestar(pat, 0) => {
            // `**/x` or `**` or `x/**/y` …: consume `**` (+ one `/`).
            let after = if pat.get(2) == Some(&b'/') { 3 } else { 2 };
            if after >= pat.len() {
                // Trailing `**` / `**/`: everything remaining matches.
                return true;
            }
            // Zero directories.
            if match_one(&pat[after..], text) {
                return true;
            }
            // One or more: retry after each `/`.
            for (i, &b) in text.iter().enumerate() {
                if b == b'/' && match_one(pat, &text[i + 1..]) {
                    return true;
                }
            }
            false
        }
        b'*' => {
            for i in 0..=text.len() {
                if i > 0 && text[i - 1] == b'/' {
                    break;
                }
                if match_one(&pat[1..], &text[i..]) {
                    return true;
                }
            }
            false
        }
        b'?' => !text.is_empty() && text[0] != b'/' && match_one(&pat[1..], &text[1..]),
        b'[' => {
            if text.is_empty() || text[0] == b'/' {
                return false;
            }
            match match_class(pat, 0, text[0]) {
                Some(next) => match_one(&pat[next..], &text[1..]),
                None => false,
            }
        }
        c => !text.is_empty() && text[0] == c && match_one(&pat[1..], &text[1..]),
    }
}

/// A `**` forming a whole path component (start/end or `/`-bounded).
fn is_component_doublestar(pat: &[u8], i: usize) -> bool {
    if !(pat.get(i) == Some(&b'*') && pat.get(i + 1) == Some(&b'*')) {
        return false;
    }
    let prev_ok = i == 0 || pat[i - 1] == b'/';
    let next_ok = i + 2 >= pat.len() || pat[i + 2] == b'/';
    prev_ok && next_ok
}

/// `[...]` class against byte `b`; returns the pattern index past `]`.
/// Unterminated classes never match. `]` first is literal; `!`/`^` first
/// negate; `a-z` ranges on raw bytes.
fn match_class(pat: &[u8], pi: usize, b: u8) -> Option<usize> {
    let mut i = pi + 1;
    let negate = pat.get(i) == Some(&b'!') || pat.get(i) == Some(&b'^');
    if negate {
        i += 1;
    }
    let mut matched = false;
    let mut first = true;
    while i < pat.len() && (pat[i] != b']' || first) {
        first = false;
        if pat.get(i + 1) == Some(&b'-') && pat.get(i + 2).is_some_and(|&c| c != b']') {
            let (lo, hi) = (pat[i], pat[i + 2]);
            if lo <= b && b <= hi {
                matched = true;
            }
            i += 3;
        } else {
            if pat[i] == b {
                matched = true;
            }
            i += 1;
        }
    }
    if i >= pat.len() {
        return None;
    }
    if matched != negate {
        Some(i + 1)
    } else {
        None
    }
}

/// Debug rendering for reports: `dir:pattern` (root dir renders empty).
pub fn describe(d: &Deciding) -> String {
    let bang = if d.negated { "!" } else { "" };
    let slash = if d.dir_only { "/" } else { "" };
    if d.file_dir.is_empty() {
        alloc::format!("{}{}{}", bang, String::from_utf8_lossy(&d.pattern), slash)
    } else {
        alloc::format!(
            "{}:{}{}{}",
            String::from_utf8_lossy(&d.file_dir),
            bang,
            String::from_utf8_lossy(&d.pattern),
            slash
        )
    }
}

/// Convenience: parse a `.gitignore` payload and its anchor directory
/// into a [`RuleFile`].
pub fn rule_file(dir: impl Into<BString>, contents: &[u8]) -> RuleFile {
    RuleFile {
        dir: dir.into(),
        rules: parse_rules(contents),
    }
}

/// Byte-string helper re-exported for callers building paths.
pub fn as_bstr(bytes: &[u8]) -> &BStr {
    BStr::new(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn judge(files: &[(&str, &str)], path: &str, is_dir: bool) -> Verdict {
        let mut rs = Ruleset::new();
        for (dir, text) in files {
            rs.push_file(BString::from(*dir), parse_rules(text.as_bytes()));
        }
        rs.judge(path.as_bytes(), is_dir)
    }

    fn ignored(files: &[(&str, &str)], path: &str, is_dir: bool) -> bool {
        judge(files, path, is_dir).ignored
    }

    #[test]
    fn basename_patterns_match_at_any_depth() {
        let f = [("", "*.log")];
        assert!(ignored(&f, "x.log", false));
        assert!(ignored(&f, "a/b/x.log", false));
        assert!(!ignored(&f, "a/b/x.logx", false));
    }

    #[test]
    fn mid_slash_patterns_anchor() {
        let f = [("", "doc/*.html")];
        assert!(ignored(&f, "doc/a.html", false));
        assert!(!ignored(&f, "x/doc/a.html", false));
        assert!(!ignored(&f, "doc/sub/a.html", false), "* never crosses /");
    }

    #[test]
    fn leading_slash_anchors_to_rule_dir() {
        let f = [("t2", "/build")];
        assert!(ignored(&f, "t2/build", true));
        assert!(!ignored(&f, "t2/x/build", true));
        assert!(!ignored(&f, "build", true), "outside the rule file's dir");
    }

    #[test]
    fn dir_only_patterns() {
        let f = [("", "build/")];
        assert!(ignored(&f, "build", true));
        assert!(!ignored(&f, "build", false), "a file named build is not the dir");
        assert!(ignored(&f, "a/build", true), "dir-only basename rule, any depth");
    }

    #[test]
    fn negation_last_match_wins() {
        let f = [("", "*.o\n!keep.o")];
        assert!(ignored(&f, "a.o", false));
        assert!(!ignored(&f, "keep.o", false));
        // Last match wins, not first:
        let f2 = [("", "!keep.o\n*.o")];
        assert!(ignored(&f2, "keep.o", false));
    }

    #[test]
    fn deeper_files_override_shallower() {
        // Stack order: external/root first, deeper last.
        let f = [("", "bin/"), ("sub", "!bin/")];
        assert!(ignored(&f, "bin", true));
        assert!(!ignored(&f, "sub/bin", true), "deeper file re-includes");
        // Re-include survives descendant judging: the directory itself is
        // judged not-ignored, so its contents are judged on their own.
        assert!(!ignored(&f, "sub/bin/x", false));
    }

    #[test]
    fn doublestar_component_semantics() {
        assert!(wildmatch(b"**/gen", b"gen"));
        assert!(wildmatch(b"**/gen", b"a/gen"));
        assert!(wildmatch(b"**/gen", b"a/b/gen"));
        assert!(!wildmatch(b"**/gen", b"a/genx"));
        assert!(wildmatch(b"a/**/b", b"a/b"), "zero directories");
        assert!(wildmatch(b"a/**/b", b"a/x/y/b"));
        assert!(!wildmatch(b"a/**/b", b"a/x/b/c"));
        assert!(wildmatch(b"a/**", b"a/f"));
        assert!(wildmatch(b"a/**", b"a/x/y"));
        assert!(!wildmatch(b"a/**", b"a"), "trailing ** needs the dir's contents");
        assert!(!wildmatch(b"a**b", b"a/x/b"), "a**b is two stars, not doublestar");
    }

    #[test]
    fn escapes_and_comments() {
        let rules = parse_rules(b"# comment\n\\!literal\n\\#hash\nfoo\\ bar\nsp   \n");
        let pats: Vec<&[u8]> = rules.iter().map(|r| r.pattern.as_slice()).collect();
        assert_eq!(
            pats,
            alloc::vec![b"!literal".as_slice(), b"#hash", b"foo bar", b"sp"]
        );
        assert!(!rules[0].negated, "escaped ! is literal");
        let neg = parse_rules(b"!x");
        assert!(neg[0].negated && neg[0].pattern.as_slice() == b"x");
    }

    #[test]
    fn classes_and_question() {
        assert!(wildmatch(b"[a-c].txt", b"b.txt"));
        assert!(!wildmatch(b"[a-c].txt", b"d.txt"));
        assert!(wildmatch(b"[!a-c].txt", b"d.txt"));
        assert!(wildmatch(b"?.o", b"x.o"));
        assert!(!wildmatch(b"?.o", b"d/x.o"));
    }

    #[test]
    fn bytes_not_utf8() {
        assert!(wildmatch(b"*.bin", b"\xc3\x28.bin"));
        let rs_files = [("", "caf\u{e9}/")];
        let mut rs = Ruleset::new();
        for (dir, text) in rs_files {
            rs.push_file(BString::from(dir), parse_rules(text.as_bytes()));
        }
        assert!(rs.judge(b"caf\xc3\xa9", true).ignored);
        assert!(!rs.judge(b"caf\xc3\xa9", false).ignored);
    }

    #[test]
    fn verdict_reports_the_deciding_rule() {
        let mut rs = Ruleset::new();
        rs.push_file(BString::from(""), parse_rules(b"*.log"));
        rs.push_file(BString::from("sub"), parse_rules(b"!keep.log"));
        let v = rs.judge(b"sub/keep.log", false);
        assert!(!v.ignored);
        let d = v.decided_by.expect("a rule decided");
        assert_eq!(d.file_dir.as_slice(), b"sub");
        assert!(d.negated);
        assert_eq!(describe(&d), "sub:!keep.log");
    }
}
