



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
}

impl ArgSpec {
    pub fn flag(flag: &'static str, help: &'static str) -> Self {
        ArgSpec {
            flag,
            kind: ArgKind::Flag,
            default: None,
            help,
        }
    }

    pub fn value(flag: &'static str, default: Option<&'static str>, help: &'static str) -> Self {
        ArgSpec {
            flag,
            kind: ArgKind::Value,
            default,
            help,
        }
    }

    pub fn multi(flag: &'static str, help: &'static str) -> Self {
        ArgSpec {
            flag,
            kind: ArgKind::Multi,
            default: None,
            help,
        }
    }

    pub fn size(flag: &'static str, default: Option<&'static str>, help: &'static str) -> Self {
        ArgSpec {
            flag,
            kind: ArgKind::Size,
            default,
            help,
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
}

impl ArgMap {
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

    fn put(&mut self, key: &str, value: String) {
        self.values.entry(key.to_string()).or_default().push(value);
        self.present.insert(key.to_string());
    }

    fn mark(&mut self, key: &str) {
        self.present.insert(key.to_string());
    }
}

/// Parse `1024`, `512K`, `1M`, `2G` (case-insensitive, `B` suffix allowed)
/// into bytes. Overflow-safe.
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
fn resolve<'a>(specs: &'a [CliArg], name: &str) -> Result<&'a CliArg, CliError> {
    if let Some(arg) = specs.iter().find(|a| a.key == name) {
        return Ok(arg);
    }
    let matches: Vec<&CliArg> = specs
        .iter()
        .filter(|a| a.key.contains('.') && a.key.rsplit('.').next() == Some(name))
        .collect();
    match matches.as_slice() {
        [one] => Ok(one),
        [] => Err(CliError::UnknownFlag {
            flag: name.to_string(),
            available: specs.iter().map(|a| a.key.clone()).collect(),
        }),
        _ => Err(CliError::AmbiguousFlag {
            flag: name.to_string(),
        }),
    }
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
                map.mark(&arg.key);
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
