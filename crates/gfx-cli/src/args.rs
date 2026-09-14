



//! Argument model (plan §4.2): declared flag specs, parsed values.
//!
//! Hand-rolled to keep the CLI dependency-light (the `no_std` crates already
//! set that precedent). Long-form flags only; `--flag value` or
//! `--flag=value`; repeatable flags accumulate.
//!
//! Namespacing: in a composed binary each pass's flags are reached as
//! `--<pass>.<flag>`; the flat form `--<flag>` is also accepted when exactly
//! one registered pass declares that flag (error when ambiguous). Helpers
//! document the canonical form per binary type.


extern crate alloc;
extern crate std;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::error::CliError;

/// The value shape of a declared flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArgKind {
    /// Boolean presence flag.
    Flag,
    /// Single string value.
    Value,
    /// Repeatable string values.
    Multi,
    /// Single value parsed as a byte size (`1024`, `512K`, `1M`, `2G`;
    /// case-insensitive suffix, plain numbers are bytes).
    Size,
}

/// One declared flag.
#[derive(Clone, Debug)]
pub struct ArgSpec {
    /// Flag name without leading `--` and without pass namespace.
    pub flag: &'static str,
    pub kind: ArgKind,
    /// Default (canonical string form) used when absent.
    pub default: Option<&'static str>,
    pub help: &'static str,
    /// Dynamic-key spec: `flag` contains exactly one `<ext>` placeholder
    /// and matches any concrete flag whose placeholder segment is
    /// `[A-Za-z0-9]+` (e.g. `ext.<ext>.cmd` matches `ext.rs.cmd`). The
    /// ArgMap records the *concrete* key. Used by blob-xform path rules
    /// (plan-blob-xform-paths.md §5.3).
    pub dynamic: bool,
}

impl ArgSpec {
    pub fn flag(flag: &'static str, help: &'static str) -> Self {
        ArgSpec {
            flag,
            kind: ArgKind::Flag,
            default: None,
            help,
            dynamic: false,
        }
    }

    /// Dynamic-key boolean flag: `flag` must contain one `<ext>`.
    pub fn dynamic_flag(flag: &'static str, help: &'static str) -> Self {
        assert!(flag.matches("<ext>").count() == 1, "dynamic flag needs one <ext>");
        ArgSpec { kind: ArgKind::Flag, dynamic: true, ..Self::flag(flag, help) }
    }

    /// Dynamic-key repeatable value flag.
    pub fn dynamic_multi(flag: &'static str, help: &'static str) -> Self {
        assert!(flag.matches("<ext>").count() == 1, "dynamic flag needs one <ext>");
        ArgSpec { kind: ArgKind::Multi, dynamic: true, ..Self::flag(flag, help) }
    }

    /// Dynamic-key size flag.
    pub fn dynamic_size(flag: &'static str, help: &'static str) -> Self {
        assert!(flag.matches("<ext>").count() == 1, "dynamic flag needs one <ext>");
        ArgSpec { kind: ArgKind::Size, dynamic: true, ..Self::flag(flag, help) }
    }

    pub fn value(flag: &'static str, default: Option<&'static str>, help: &'static str) -> Self {
        ArgSpec {
            flag,
            kind: ArgKind::Value,
            default,
            help,
            dynamic: false,
        }
    }

    pub fn multi(flag: &'static str, help: &'static str) -> Self {
        ArgSpec {
            flag,
            kind: ArgKind::Multi,
            default: None,
            help,
            dynamic: false,
        }
    }

    pub fn size(flag: &'static str, default: Option<&'static str>, help: &'static str) -> Self {
        ArgSpec {
            flag,
            kind: ArgKind::Size,
            default,
            help,
            dynamic: false,
        }
    }
}

/// A declared flag with its namespace already resolved (`"repo"` globally,
/// `"strip-blobs.size-threshold"` for a pass flag).
#[derive(Clone, Debug)]
pub struct CliArg {
    pub key: String,
    pub spec: ArgSpec,
}

/// Parsed flag values keyed by canonical key.
#[derive(Clone, Debug, Default)]
pub struct ArgMap {
    values: BTreeMap<String, Vec<String>>,
    present: std::collections::BTreeSet<String>,
    /// Every explicitly-given flag, in the order given (repeats included;
    /// config-file entries append after argv entries). The value is `Some`
    /// for value/size/multi flags, `None` for boolean flags. Passes whose
    /// flags are order-sensitive (blob-xform's transform chain) read this.
    order: Vec<(String, Option<String>)>,
}

impl ArgMap {
    /// All keys that carry a value or were marked present (for the
    /// unused-flag guard, plan-redact-idents.md §5.1).
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.values
            .keys()
            .chain(self.present.iter())
            .map(|s| s.as_str())
    }

    /// Whether a `Flag` was given.
    pub fn flag(&self, key: &str) -> bool {
        self.present.contains(key)
    }

    pub fn value(&self, key: &str) -> Option<&str> {
        self.values.get(key).and_then(|v| v.first()).map(|s| s.as_str())
    }

    pub fn multi(&self, key: &str) -> &[String] {
        self.values.get(key).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Parse a `Size` flag; `None` when absent.
    pub fn size(&self, key: &str) -> Result<Option<u64>, CliError> {
        match self.value(key) {
            None => Ok(None),
            Some(s) => parse_size(s)
                .map(Some)
                .ok_or_else(|| CliError::BadSize {
                    value: s.to_string(),
                    flag: key.to_string(),
                }),
        }
    }

    /// Explicitly-given keys, in the order given (repeats included).
    pub fn ordered_keys(&self) -> impl Iterator<Item = &str> {
        self.order.iter().map(|(k, _)| k.as_str())
    }

    /// Explicitly-given flags with values, in the order given.
    pub fn ordered_entries(&self) -> &[(String, Option<String>)] {
        &self.order
    }

    pub(crate) fn put(&mut self, key: &str, value: String) {
        self.values.entry(key.to_string()).or_default().push(value.clone());
        self.present.insert(key.to_string());
        self.order.push((key.to_string(), Some(value)));
    }

    pub(crate) fn mark_present(&mut self, key: &str) {
        self.present.insert(key.to_string());
        self.order.push((key.to_string(), None));
    }
}

/// Parse `1024`, `512K`, `1M`, `2G` (case-insensitive, `B` suffix allowed)
/// into bytes. Overflow-safe.
/// Parse a duration in seconds: decimal, or with `d`/`w` suffix
/// (d=86400, w=604800). Optional leading `+`/`-`. Used by redact's
/// `--redact.time-shift` / `--redact.time-jitter` (same parser family as
/// [`parse_size`]).
pub fn parse_duration_secs(s: &str) -> Option<i64> {
    let (neg, rest) = match s.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    let (num, mult): (&str, i64) = if let Some(n) = rest.strip_suffix('d').or_else(|| rest.strip_suffix('D')) {
        (n, 86_400)
    } else if let Some(n) = rest.strip_suffix('w').or_else(|| rest.strip_suffix('W')) {
        (n, 604_800)
    } else {
        (rest, 1)
    };
    let secs: i64 = num.parse::<i64>().ok()?.checked_mul(mult)?;
    Some(if neg { -secs } else { secs })
}

/// Parse a seed: decimal or `0x`-prefixed hex, `u64`.
pub fn parse_seed(s: &str) -> Option<u64> {
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => s.parse().ok(),
    }
}

pub fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    let (digits, mult) = match s.get(s.len().saturating_sub(2)..)? {
        "KB" | "kb" | "Kb" | "kB" => (&s[..s.len() - 2], 1u64 << 10),
        "MB" | "mb" | "Mb" | "mB" => (&s[..s.len() - 2], 1u64 << 20),
        "GB" | "gb" | "Gb" | "gB" => (&s[..s.len() - 2], 1u64 << 30),
        _ => match s.chars().last()? {
            'K' | 'k' => (&s[..s.len() - 1], 1u64 << 10),
            'M' | 'm' => (&s[..s.len() - 1], 1u64 << 20),
            'G' | 'g' => (&s[..s.len() - 1], 1u64 << 30),
            'B' | 'b' => (&s[..s.len() - 1], 1),
            _ => (s, 1),
        },
    };
    if digits.is_empty() {
        return None;
    }
    let n: u64 = digits.parse().ok()?;
    n.checked_mul(mult)
}

/// Resolution rule for a `--flag` token: exact key match first, then a flat
/// name that exactly one namespaced spec claims.
/// The outcome of resolving a flag name: the matched spec plus the key
/// to record in the ArgMap (the *concrete* key for dynamic specs).
struct Resolved<'a> {
    spec: &'a ArgSpec,
    key: String,
}

fn resolve<'a>(specs: &'a [CliArg], name: &str) -> Result<Resolved<'a>, CliError> {
    if let Some(arg) = specs.iter().find(|a| a.key == name) {
        return Ok(Resolved { spec: &arg.spec, key: arg.key.clone() });
    }
    let matches: Vec<&CliArg> = specs
        .iter()
        .filter(|a| !a.spec.dynamic && a.key.contains('.') && a.key.rsplit('.').next() == Some(name))
        .collect();
    match matches.as_slice() {
        [one] => return Ok(Resolved { spec: &one.spec, key: one.key.clone() }),
        [_one, ..] => return Err(CliError::AmbiguousFlag { flag: name.to_string() }),
        [] => {}
    }
    // Dynamic specs: `blob-xform.ext.<ext>.cmd` matches
    // `blob-xform.ext.rs.cmd` when the placeholder segment is [A-Za-z0-9]+.
    for arg in specs {
        if !arg.spec.dynamic {
            continue;
        }
        let Some((pre, post)) = arg.key.split_once("<ext>") else { continue };
        let Some(middle) = name.strip_prefix(pre).and_then(|r| r.strip_suffix(post)) else {
            continue;
        };
        if !middle.is_empty()
            && middle.bytes().all(|b| b.is_ascii_alphanumeric())
        {
            return Ok(Resolved { spec: &arg.spec, key: name.to_string() });
        }
    }
    Err(CliError::UnknownFlag {
        flag: name.to_string(),
        available: specs.iter().map(|a| a.key.clone()).collect(),
    })
}

/// Parse `argv` (no program name) against the declared specs. Defaults are
/// filled in for absent `Value`/`Size`/`Multi` specs so accessors see them.
pub fn parse_argv(specs: &[CliArg], argv: &[std::ffi::OsString]) -> Result<ArgMap, CliError> {
    let mut map = ArgMap::default();
    let mut i = 0usize;
    while i < argv.len() {
        let tok = argv[i].to_string_lossy().into_owned();
        i += 1;
        if !tok.starts_with("--") || tok.len() <= 2 {
            return Err(CliError::UnexpectedPositional(tok));
        }
        let body = &tok[2..];
        let (name, inline) = match body.split_once('=') {
            Some((n, v)) => (n, Some(v.to_string())),
            None => (body, None),
        };
        let arg = resolve(specs, name)?;
        match arg.spec.kind {
            ArgKind::Flag => {
                if inline.is_some() {
                    return Err(CliError::MissingValue {
                        flag: format!("{} (boolean flag takes no value)", arg.key),
                    });
                }
                map.mark_present(&arg.key);
            }
            ArgKind::Value | ArgKind::Size => {
                let v = match inline {
                    Some(v) => v,
                    None => {
                        if i >= argv.len() {
                            return Err(CliError::MissingValue { flag: arg.key.clone() });
                        }
                        let v = argv[i].to_string_lossy().into_owned();
                        i += 1;
                        v
                    }
                };
                if arg.spec.kind == ArgKind::Size {
                    parse_size(&v).ok_or_else(|| CliError::BadSize {
                        value: v.clone(),
                        flag: arg.key.clone(),
                    })?;
                }
                map.put(&arg.key, v);
            }
            ArgKind::Multi => {
                let v = match inline {
                    Some(v) => v,
                    None => {
                        if i >= argv.len() {
                            return Err(CliError::MissingValue { flag: arg.key.clone() });
                        }
                        let v = argv[i].to_string_lossy().into_owned();
                        i += 1;
                        v
                    }
                };
                map.put(&arg.key, v);
            }
        }
    }
    // Fill defaults for absent value-bearing specs.
    for arg in specs {
        if !map.present.contains(&arg.key) {
            if let Some(d) = arg.spec.default {
                map.values
                    .entry(arg.key.clone())
                    .or_default()
                    .push(d.to_string());
            }
        }
    }
    Ok(map)
}
