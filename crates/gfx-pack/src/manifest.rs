//! Archive manifest model (plan-multistream-pack.md D4): the audit record
//! of a pack run — what passes ran, with what flags, over which repos, and
//! what each stream must hash to and resolve to on unpack (D8).
//!
//! The writer is hand-rolled and fully deterministic: fixed key order,
//! entries in manifest (user) order, flags sorted, no clocks. Parsing goes
//! through the `toml` crate plus strict validation; the manifest is the one
//! attacker-controlled parse surface in an archive, so every field is
//! range- and shape-checked here before the unpack driver trusts it.

use std::collections::BTreeMap;
use std::string::String;
use std::vec::Vec;

use gfx::core::ObjectFormat;

use crate::PackError;

/// The only format version this build reads and writes.
pub const FORMAT_VERSION: u32 = 1;

/// Zip path of the manifest entry.
pub const MANIFEST_ENTRY: &str = "manifest.toml";

/// Repo slugs: `[A-Za-z0-9._-]+`, excluding `.` and `..`. Slugs become zip
/// path components and default destination directory names, so this is both
/// a UI rule and a zip-slip guard.
pub fn is_valid_slug(s: &str) -> bool {
    !s.is_empty()
        && s != "."
        && s != ".."
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

/// The zip path of a repo's transformed stream.
pub fn stream_entry(name: &str) -> String {
    std::format!("streams/{name}.fi")
}

fn m_err(msg: impl Into<String>) -> PackError {
    PackError::Manifest(msg.into())
}

/// One ref tip recorded at pack time (D8): the pre-rewrite tip OID, plus
/// the fast-export mark when the tip's lineage was rewritten. On unpack the
/// expected new tip is `marks[mark]` when `mark` is set, else `old`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefTip {
    pub name: String,
    /// Hex OID of the tip in the source repo.
    pub old: String,
    pub mark: Option<u64>,
}

/// Per-repo manifest entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepoEntry {
    pub name: String,
    /// Zip path of the transformed stream; must equal
    /// `streams/<name>.fi` (enforced on parse).
    pub stream: String,
    pub object_format: ObjectFormat,
    /// Lowercase hex SHA-256 of the *uncompressed* stream bytes.
    pub sha256: String,
    pub bytes: u64,
    pub commits: u64,
    pub rewritten: u64,
    /// The pass pipeline left the stream byte-identical to the export.
    pub identity: bool,
    pub refs: Vec<RefTip>,
}

/// The archive manifest.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Manifest {
    /// Pipeline as run, in order, remap last (auto-appended by the driver).
    pub passes: Vec<String>,
    /// Explicitly-set pass/global flags, sorted — the D2 audit record.
    pub flags: BTreeMap<String, String>,
    pub repos: Vec<RepoEntry>,
}

fn push_toml_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&std::format!("\\u{:04X}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn object_format_label(f: ObjectFormat) -> &'static str {
    match f {
        ObjectFormat::Sha1 => "sha1",
        ObjectFormat::Sha256 => "sha256",
    }
}

fn object_format_hex_len(f: ObjectFormat) -> usize {
    match f {
        ObjectFormat::Sha1 => 40,
        ObjectFormat::Sha256 => 64,
    }
}

impl Manifest {
    /// Deterministic TOML serialization.
    pub fn to_text(&self) -> String {
        let mut s = String::new();
        s.push_str(&std::format!("format = {FORMAT_VERSION}\n"));
        s.push_str("passes = [");
        for (i, p) in self.passes.iter().enumerate() {
            if i > 0 {
                s.push_str(", ");
            }
            push_toml_string(&mut s, p);
        }
        s.push_str("]\n");
        if !self.flags.is_empty() {
            s.push_str("\n[flags]\n");
            for (k, v) in &self.flags {
                push_toml_string(&mut s, k);
                s.push_str(" = ");
                push_toml_string(&mut s, v);
                s.push('\n');
            }
        }
        for r in &self.repos {
            s.push_str("\n[[repo]]\n");
            s.push_str("name = ");
            push_toml_string(&mut s, &r.name);
            s.push('\n');
            s.push_str("stream = ");
            push_toml_string(&mut s, &r.stream);
            s.push('\n');
            s.push_str("object-format = ");
            push_toml_string(&mut s, object_format_label(r.object_format));
            s.push('\n');
            s.push_str("sha256 = ");
            push_toml_string(&mut s, &r.sha256);
            s.push('\n');
            s.push_str(&std::format!("bytes = {}\n", r.bytes));
            s.push_str(&std::format!("commits = {}\n", r.commits));
            s.push_str(&std::format!("rewritten = {}\n", r.rewritten));
            s.push_str(&std::format!("identity = {}\n", r.identity));
            for t in &r.refs {
                s.push_str("\n[[repo.refs]]\n");
                s.push_str("name = ");
                push_toml_string(&mut s, &t.name);
                s.push('\n');
                s.push_str("old = ");
                push_toml_string(&mut s, &t.old);
                s.push('\n');
                if let Some(m) = t.mark {
                    s.push_str(&std::format!("mark = {m}\n"));
                }
            }
        }
        s
    }

    /// Parse and fully validate. Structural problems are `Manifest` errors;
    /// the checks here are what let the unpack driver trust the data.
    pub fn parse(text: &str) -> Result<Manifest, PackError> {
        let value: toml::Value = text
            .parse()
            .map_err(|e| m_err(format!("not valid TOML: {e}")))?;
        let root = value
            .as_table()
            .ok_or_else(|| m_err("top level must be a table"))?;

        let format = root
            .get("format")
            .and_then(|v| v.as_integer())
            .ok_or_else(|| m_err("missing integer `format`"))?;
        if format != FORMAT_VERSION as i64 {
            return Err(m_err(format!(
                "unsupported format version {format} (this build reads {FORMAT_VERSION})"
            )));
        }

        let passes = root
            .get("passes")
            .and_then(|v| v.as_array())
            .ok_or_else(|| m_err("missing array `passes`"))?
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| m_err("`passes` entries must be strings"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if passes.is_empty() {
            return Err(m_err("`passes` must not be empty"));
        }

        let mut flags = BTreeMap::new();
        if let Some(f) = root.get("flags") {
            let t = f
                .as_table()
                .ok_or_else(|| m_err("`flags` must be a table"))?;
            for (k, v) in t {
                let v = v
                    .as_str()
                    .ok_or_else(|| m_err(format!("flag {k:?} must be a string")))?;
                flags.insert(k.clone(), v.to_string());
            }
        }

        let repos_v = root
            .get("repo")
            .and_then(|v| v.as_array())
            .ok_or_else(|| m_err("missing `[[repo]]` entries"))?;
        if repos_v.is_empty() {
            return Err(m_err("at least one `[[repo]]` entry is required"));
        }
        let mut repos = Vec::with_capacity(repos_v.len());
        for (i, rv) in repos_v.iter().enumerate() {
            let ctx = || std::format!("repo #{i}");
            let t = rv.as_table().ok_or_else(|| m_err(format!("{}: not a table", ctx())))?;
            let get_str = |k: &str| -> Result<String, PackError> {
                t.get(k)
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
                    .ok_or_else(|| m_err(format!("{}: missing string `{k}`", ctx())))
            };
            let get_u64 = |k: &str| -> Result<u64, PackError> {
                let v = t
                    .get(k)
                    .and_then(|v| v.as_integer())
                    .ok_or_else(|| m_err(format!("{}: missing integer `{k}`", ctx())))?;
                u64::try_from(v)
                    .map_err(|_| m_err(format!("{}: `{k}` must be non-negative", ctx())))
            };
            let name = get_str("name")?;
            if !is_valid_slug(&name) {
                return Err(m_err(format!("{}: invalid slug {name:?}", ctx())));
            }
            if repos.iter().any(|r: &RepoEntry| r.name == name) {
                return Err(m_err(format!("duplicate repo slug {name:?}")));
            }
            let stream = get_str("stream")?;
            if stream != stream_entry(&name) {
                return Err(m_err(format!(
                    "repo {name:?}: stream path {stream:?} does not match {:?}",
                    stream_entry(&name)
                )));
            }
            crate::zip::validate_entry_name(&stream).map_err(|e| m_err(std::format!("{e}")))?;
            let object_format = match get_str("object-format")?.as_str() {
                "sha1" => ObjectFormat::Sha1,
                "sha256" => ObjectFormat::Sha256,
                other => return Err(m_err(format!("repo {name:?}: bad object-format {other:?}"))),
            };
            let sha256 = get_str("sha256")?;
            if sha256.len() != 64
                || !sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(m_err(format!("repo {name:?}: sha256 must be 64 lowercase hex")));
            }
            let identity = t
                .get("identity")
                .and_then(|v| v.as_bool())
                .ok_or_else(|| m_err(format!("repo {name:?}: missing bool `identity`")))?;

            let mut refs = Vec::new();
            if let Some(rf) = t.get("refs") {
                let arr = rf
                    .as_array()
                    .ok_or_else(|| m_err(format!("repo {name:?}: `refs` must be an array")))?;
                for rv in arr {
                    let rt = rv
                        .as_table()
                        .ok_or_else(|| m_err(format!("repo {name:?}: ref entry not a table")))?;
                    let rname = rt
                        .get("name")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| m_err(format!("repo {name:?}: ref missing `name`")))?;
                    if rname.is_empty() || rname.bytes().any(|b| b < 0x20) {
                        return Err(m_err(format!("repo {name:?}: bad ref name {rname:?}")));
                    }
                    let old = rt
                        .get("old")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| m_err(format!("repo {name:?}: ref missing `old`")))?;
                    if old.len() != object_format_hex_len(object_format)
                        || !old.bytes().all(|b| b.is_ascii_hexdigit())
                    {
                        return Err(m_err(format!(
                            "repo {name:?}: ref old OID must be {}-hex",
                            object_format_hex_len(object_format)
                        )));
                    }
                    let mark = match rt.get("mark") {
                        None => None,
                        Some(v) => {
                            let m = v
                                .as_integer()
                                .ok_or_else(|| m_err(format!("repo {name:?}: `mark` must be an integer")))?;
                            Some(
                                u64::try_from(m)
                                    .map_err(|_| m_err(format!("repo {name:?}: negative mark")))?,
                            )
                        }
                    };
                    refs.push(RefTip {
                        name: rname.to_string(),
                        old: old.to_string(),
                        mark,
                    });
                }
            }

            repos.push(RepoEntry {
                stream,
                object_format,
                sha256,
                bytes: get_u64("bytes")?,
                commits: get_u64("commits")?,
                rewritten: get_u64("rewritten")?,
                name,
                identity,
                refs,
            });
        }

        Ok(Manifest { passes, flags, repos })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Manifest {
        let mut flags = BTreeMap::new();
        flags.insert("redact.time-mode".to_string(), "bucket".to_string());
        Manifest {
            passes: vec!["redact".into(), "remap".into()],
            flags,
            repos: vec![RepoEntry {
                name: "alpha".into(),
                stream: stream_entry("alpha"),
                object_format: ObjectFormat::Sha1,
                sha256: "ab".repeat(32),
                bytes: 1234,
                commits: 5,
                rewritten: 2,
                identity: false,
                refs: vec![
                    RefTip {
                        name: "refs/heads/main".into(),
                        old: "cd".repeat(20),
                        mark: Some(7),
                    },
                    RefTip {
                        name: "refs/tags/v1".into(),
                        old: "ef".repeat(20),
                        mark: None,
                    },
                ],
            }],
        }
    }

    #[test]
    fn round_trip_is_byte_stable() {
        let m = sample();
        let text = m.to_text();
        let back = Manifest::parse(&text).expect("parse");
        assert_eq!(m, back);
        assert_eq!(back.to_text(), text, "serialization is a fixed point");
    }

    #[test]
    fn rejects_bad_version_and_slugs() {
        let m = sample();
        assert!(Manifest::parse(&m.to_text().replace("format = 1", "format = 2")).is_err());

        let mut bad = sample();
        bad.repos[0].name = "../evil".into();
        assert!(Manifest::parse(&bad.to_text()).is_err());

        let mut dup = sample();
        dup.repos.push(dup.repos[0].clone());
        assert!(Manifest::parse(&dup.to_text()).is_err());
    }

    #[test]
    fn rejects_stream_path_tampering() {
        let mut m = sample();
        m.repos[0].stream = "streams/other.fi".into();
        assert!(Manifest::parse(&m.to_text()).is_err());
    }

    #[test]
    fn slug_rules() {
        assert!(is_valid_slug("alpha"));
        assert!(is_valid_slug("my.repo_2-x"));
        assert!(!is_valid_slug(""));
        assert!(!is_valid_slug("."));
        assert!(!is_valid_slug(".."));
        assert!(!is_valid_slug("a/b"));
        assert!(!is_valid_slug("a b"));
    }
}
