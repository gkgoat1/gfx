//! Parity against `git check-ignore` (plan-stream-files.md M2): one repo,
//! many `.gitignore` files at several depths, every candidate path judged
//! by git and by `gfx-ignore` — verdicts must agree exactly.
//!
//! Requires `git` in PATH. `core.excludesFile` is pinned to /dev/null so
//! the host's global excludes cannot leak in; `.git/info/exclude` is
//! empty in a fresh init.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use gfx_ignore::{parse_rules, Ruleset};

fn tmpdir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "gfx-ignore-parity-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

/// One test case: rule files as `(dir, contents)` and candidate paths as
/// `(path, is_dir)`. Dirs are created, files touched.
struct Case {
    files: &'static [(&'static str, &'static str)],
    paths: &'static [(&'static str, bool)],
}

const CASES: &[Case] = &[
    // Basename rule at any depth.
    Case {
        files: &[("c1", "*.log")],
        paths: &[
            ("c1/x.log", false),
            ("c1/a/b/x.log", false),
            ("c1/a/b/x.logx", false),
            ("c1/y.log", true), // a *directory* named y.log: still matched (not dir-only)
        ],
    },
    // Directory-only rule.
    Case {
        files: &[("c2", "build/")],
        paths: &[
            ("c2/build", true),
            ("c2/buildfile", false),
            ("c2/build/f", false),
            ("c2/a/build/f", false),
            ("c2/buildx/f", false),
        ],
    },
    // Anchored by leading slash.
    Case {
        files: &[("c3", "/build")],
        paths: &[
            ("c3/build", true),
            ("c3/build/f", false),
            ("c3/x/build", true),
            ("c3/x/build/f", false),
        ],
    },
    // Mid-slash anchors; * never crosses /.
    Case {
        files: &[("c4", "doc/*.html")],
        paths: &[
            ("c4/doc/a.html", false),
            ("c4/x/doc/a.html", false),
            ("c4/doc/sub/b.html", false),
        ],
    },
    // Leading ** component.
    Case {
        files: &[("c5", "**/gen")],
        paths: &[
            ("c5/gen/f", false),
            ("c5/a/gen/f", false),
            ("c5/a/b/gen/f", false),
            ("c5/a/genx", false),
        ],
    },
    // Mid ** component, zero directories included.
    Case {
        files: &[("c6", "a/**/b")],
        paths: &[
            ("c6/a/b/f", false),
            ("c6/a/x/y/b/f", false),
            ("c6/a/x/b/c/f", false),
        ],
    },
    // Slash pattern without leading slash anchors too.
    Case {
        files: &[("c7", "foo/bar")],
        paths: &[("c7/foo/bar", false), ("c7/x/foo/bar", false)],
    },
    // Negation, last match wins.
    Case {
        files: &[("c8", "*.o\n!keep.o")],
        paths: &[
            ("c8/a.o", false),
            ("c8/keep.o", false),
            ("c8/d/keep.o", false),
        ],
    },
    // Deeper file re-includes what a shallower file ignored.
    Case {
        files: &[("c9", "bin/"), ("c9/sub", "!bin/")],
        paths: &[("c9/bin/x", false), ("c9/sub/bin/x", false)],
    },
    // Escapes and comments.
    Case {
        files: &[("c10", "# comment\n\\!literal\n\\#hash\nfoo\\ bar\n")],
        paths: &[
            ("c10/!literal", false),
            ("c10/#hash", false),
            ("c10/foo bar", false),
            ("c10/foo", false),
        ],
    },
    // Classes and question marks.
    Case {
        files: &[("c11", "[a-c].txt\n?.o\n")],
        paths: &[
            ("c11/b.txt", false),
            ("c11/d.txt", false),
            ("c11/x.o", false),
            ("c11/xx.o", false),
        ],
    },
    // Trailing ** matches everything below, not the dir itself.
    Case {
        files: &[("c12", "a/**\n")],
        paths: &[("c12/a/f", false), ("c12/a/x/y", false), ("c12/ab/f", false)],
    },
    // Re-include a dir; contents then judged on their own rules.
    Case {
        files: &[("c13", "*.log\n!yes.log\n")],
        paths: &[("c13/no.log", false), ("c13/yes.log", false)],
    },
];

fn git_ignored(repo: &Path, paths: &[&str]) -> BTreeSet<String> {
    let mut input = Vec::new();
    for p in paths {
        input.extend_from_slice(p.as_bytes());
        input.push(0);
    }
    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(repo)
        .arg("-c")
        .arg("core.excludesFile=/dev/null")
        .arg("check-ignore")
        .arg("-z")
        .arg("--stdin")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped());
    let mut child = cmd.spawn().expect("spawn git check-ignore");
    use std::io::Write;
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(&input)
        .expect("write paths");
    let out = child.wait_with_output().expect("wait");
    assert!(
        out.status.code() == Some(0) || out.status.code() == Some(1),
        "git check-ignore failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

#[test]
fn parity_with_git_check_ignore() {
    let repo = tmpdir();
    Command::new("git")
        .arg("-C")
        .arg(&repo)
        .args(["init", "-q", "."])
        .output()
        .expect("git init");

    // Materialize rule files and candidate paths on disk.
    let mut all_paths: Vec<&str> = Vec::new();
    for case in CASES {
        for (dir, contents) in case.files {
            let d = repo.join(dir);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join(".gitignore"), contents).unwrap();
        }
        for (path, is_dir) in case.paths {
            let p = repo.join(path);
            if *is_dir {
                std::fs::create_dir_all(&p).unwrap();
            } else {
                std::fs::create_dir_all(p.parent().unwrap()).unwrap();
                std::fs::write(&p, b"").unwrap();
            }
            all_paths.push(path);
        }
    }

    // git's verdicts.
    let git_set = git_ignored(&repo, &all_paths);

    // gfx-ignore's verdicts: one stack, layers in root→deep order.
    let mut rs = Ruleset::new();
    let mut layers: Vec<(&str, &str)> = Vec::new();
    for case in CASES {
        layers.extend(case.files.iter().copied());
    }
    layers.sort_by_key(|(dir, _)| dir.matches('/').count());
    for (dir, contents) in layers {
        rs.push_file(
            gfx_ignore::BString::from(dir),
            parse_rules(contents.as_bytes()),
        );
    }
    let mut ours: BTreeSet<String> = BTreeSet::new();
    for case in CASES {
        for (path, is_dir) in case.paths {
            if rs.judge_with_ancestors(path.as_bytes(), *is_dir).ignored {
                ours.insert((*path).to_string());
            }
        }
    }

    let missing: Vec<_> = git_set.difference(&ours).collect();
    let extra: Vec<_> = ours.difference(&git_set).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "parity mismatch\n  git-only (we missed): {missing:?}\n  ours-only (we added): {extra:?}\n  git: {git_set:?}\n  ours: {ours:?}"
    );
}
