



//! Flag-to-`PassSpec` factories for the compiled-in builtins.
//!
//! These live here (std side) rather than in the `no_std` builtin crates:
//! the crates stay free of CLI concerns, and the registry is the single
//! place that maps flags to configurations.


extern crate alloc;
extern crate std;

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use crate::args::{parse_duration_secs, parse_seed, ArgMap, ArgSpec};
use crate::error::CliError;
use crate::registry::PassFactory;
use gfx::driver::PassSpec;
use gfx::gfx_redact::{IdentMode, PseudonymStyle, TimeBucketUnit, TimeMode};

/// Builtin (plan §5): retroactive removal of large/generated blobs.
pub struct StripBlobsFactory;

/// `Box<dyn PassFactory>` for the registry.
pub fn strip_blobs_factory() -> Box<dyn PassFactory> {
    Box::new(StripBlobsFactory)
}

impl PassFactory for StripBlobsFactory {
    fn name(&self) -> &'static str {
        "strip-blobs"
    }

    fn arg_spec(&self) -> Vec<ArgSpec> {
        vec![
            ArgSpec::size(
                "larger-than",
                None,
                "strip blobs strictly larger than this (e.g. 1M, 512K)",
            ),
            ArgSpec::multi("path-glob", "strip paths matching this glob (repeatable)"),
            ArgSpec::flag("content-signals", "enable generated-code content signals (§5.2)"),
            ArgSpec::multi("protect-glob", "never strip paths matching this glob (repeatable)"),
            ArgSpec::flag(
                "strip-symlinks-too",
                "also judge symlink payloads against content signals",
            ),
        ]
    }

    fn build(&self, args: &ArgMap) -> Result<PassSpec, CliError> {
        let cfg = gfx_strip_blobs::StripBlobsConfig {
            size_threshold: args.size("strip-blobs.larger-than")?,
            path_globs: args
                .multi("strip-blobs.path-glob")
                .iter()
                .map(|g| gfx::core::BString::from(g.as_bytes()))
                .collect(),
            content_signals: if args.flag("strip-blobs.content-signals") {
                gfx_strip_blobs::ContentSignals::default()
            } else {
                // CLI keeps signals opt-in; the library default enables them.
                gfx_strip_blobs::ContentSignals::all_off()
            },
            protect_globs: args
                .multi("strip-blobs.protect-glob")
                .iter()
                .map(|g| gfx::core::BString::from(g.as_bytes()))
                .collect(),
            strip_symlinks_too: args.flag("strip-blobs.strip-symlinks-too"),
            ..gfx_strip_blobs::StripBlobsConfig::default()
        };
        Ok(PassSpec::StripBlobs(cfg))
    }
}

/// Builtin #1 (plan §7): commit-hash remapping.
pub struct RemapFactory;

/// `Box<dyn PassFactory>` for the registry.
pub fn remap_factory() -> Box<dyn PassFactory> {
    Box::new(RemapFactory)
}

impl PassFactory for RemapFactory {
    fn name(&self) -> &'static str {
        "remap"
    }

    fn arg_spec(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::flag(
            "track-message-oids",
            "harvest old OIDs referenced in commit messages (feeds a later message-rewrite pass)",
        )]
    }

    fn build(&self, args: &ArgMap) -> Result<PassSpec, CliError> {
        Ok(PassSpec::Remap(gfx::gfx_remap::RemapConfig {
            track_message_oids: args.flag("remap.track-message-oids"),
            ..gfx::gfx_remap::RemapConfig::default()
        }))
    }
}

/// Builtin: commit-metadata redaction (plan-redact-idents.md §5). Flags:
///
/// ```text
/// --redact.map <toml>                  exact rows (mutually exclusive with --redact.pseudonymize)
/// --redact.pseudonymize                built-in pseudonyms for every ident
/// --redact.pseudonym-style ordinal|hash
/// --redact.time-mode preserve|zero|shift|bucket|fuzz
/// --redact.time-shift <secs>           shift amount (decimal / 1d / 2w)
/// --redact.time-bucket day|week|month
/// --redact.time-jitter <secs>          fuzz window
/// --redact.seed <n>                    fuzz seed (required for fuzz; never defaulted)
/// --redact.keep-tz                     opt out of timezone-offset zeroing
/// ```
pub struct RedactFactory;

/// `Box<dyn PassFactory>` for the registry.
pub fn redact_factory() -> Box<dyn PassFactory> {
    Box::new(RedactFactory)
}

/// Parse the `--redact.map` TOML file: an array of `[[row]]` tables with
/// optional wildcard fields.
///
/// ```toml
/// [[row]]
/// name = "Alice"               # omit for a name wildcard
/// email = "alice@example.com"  # omit for an email wildcard
/// new_name = "User 1"
/// new_email = "user1@example.invalid"
/// ```
///
/// TOML is UTF-8, so rows cannot express non-UTF-8 ident bytes — host code
/// injects an `IdentPolicy` for that (documented v1 limitation).
fn parse_redact_map(path: &str) -> Result<Vec<gfx::gfx_redact::RedactRow>, CliError> {
    let bytes = std::fs::read(path)?;
    let text = String::from_utf8(bytes)
        .map_err(|e| CliError::BadConfig { file: path.to_string(), msg: format!("not valid UTF-8: {e}") })?;
    let value: toml::Value = text
        .parse()
        .map_err(|e| CliError::BadConfig { file: path.to_string(), msg: format!("not valid TOML: {e}") })?;
    let rows = value
        .get("row")
        .and_then(|v| v.as_array())
        .ok_or_else(|| CliError::BadConfig {
            file: path.to_string(),
            msg: "want one or more [[row]] tables with name?, email?, new_name, new_email".into(),
        })?;
    let mut out = Vec::new();
    for (i, item) in rows.iter().enumerate() {
        let t = item.as_table().ok_or_else(|| CliError::BadConfig {
            file: path.to_string(),
            msg: format!("row #{i} must be a table"),
        })?;
        let get = |k: &str| t.get(k).and_then(|v| v.as_str()).map(|s| s.as_bytes().to_vec());
        let new_name = get("new_name").ok_or_else(|| CliError::BadConfig {
            file: path.to_string(),
            msg: format!("row #{i} is missing new_name"),
        })?;
        let new_email = get("new_email").ok_or_else(|| CliError::BadConfig {
            file: path.to_string(),
            msg: format!("row #{i} is missing new_email"),
        })?;
        out.push(gfx::gfx_redact::RedactRow {
            name: get("name").map(gfx::core::BString::from),
            email: get("email").map(gfx::core::BString::from),
            new_name: gfx::core::BString::from(new_name),
            new_email: gfx::core::BString::from(new_email),
        });
    }
    Ok(out)
}

fn conflict(msg: impl Into<String>) -> CliError {
    CliError::FlagConflict(msg.into())
}

impl PassFactory for RedactFactory {
    fn name(&self) -> &'static str {
        "redact"
    }

    fn in_default(&self) -> bool {
        // Decision D2: redaction is always opt-in.
        false
    }

    fn arg_spec(&self) -> Vec<ArgSpec> {
        vec![
            ArgSpec::value("map", None, "TOML file of exact [[row]] ident mappings"),
            ArgSpec::flag("pseudonymize", "replace every ident with a deterministic pseudonym"),
            ArgSpec::value(
                "pseudonym-style",
                None,
                "ordinal (default) or hash — hash is cross-repo-stable but brute-forceable",
            ),
            ArgSpec::value(
                "time-mode",
                None,
                "preserve (default) | zero | shift | bucket | fuzz",
            ),
            ArgSpec::value("time-shift", None, "seconds for time-mode=shift (e.g. 365d)"),
            ArgSpec::value("time-bucket", None, "day | week | month for time-mode=bucket (UTC)"),
            ArgSpec::value("time-jitter", None, "seconds for time-mode=fuzz (e.g. 2d)"),
            ArgSpec::value("seed", None, "fuzz seed (required for fuzz; e.g. 0x9E3779B97F4A7C15)"),
            ArgSpec::flag("keep-tz", "keep timezone offsets (they are zeroed by default)"),
        ]
    }

    fn build(&self, args: &ArgMap) -> Result<PassSpec, CliError> {
        // Ident mode (plan §5.1 rules).
        let map_path = args.value("redact.map");
        let pseudonymize = args.flag("redact.pseudonymize");
        if map_path.is_some() && pseudonymize {
            return Err(conflict(
                "--redact.map and --redact.pseudonymize are mutually exclusive (table wins or generate-all, not both)",
            ));
        }
        let style_str = args.value("redact.pseudonym-style");
        if style_str.is_some() && !pseudonymize {
            return Err(conflict(
                "--redact.pseudonym-style requires --redact.pseudonymize",
            ));
        }
        let ident_mode = match (map_path, pseudonymize) {
            (Some(path), false) => IdentMode::Table(parse_redact_map(path)?),
            (None, true) => IdentMode::Pseudonymize(match style_str.unwrap_or("ordinal") {
                "ordinal" => PseudonymStyle::Ordinal,
                "hash" => PseudonymStyle::Hash,
                other => {
                    return Err(conflict(format!(
                        "unknown --redact.pseudonym-style {other:?} (want ordinal|hash)"
                    )))
                }
            }),
            (None, false) => {
                // Time-only redaction is a legitimate half-measure (§4.4:
                // identity and time are independent axes).
                IdentMode::Preserve
            }
            _ => unreachable!(),
        };

        // Time mode.
        let time_mode = match args.value("redact.time-mode").unwrap_or("preserve") {
            "preserve" => TimeMode::Preserve,
            "zero" => TimeMode::Zero,
            "shift" => {
                let raw = args.value("redact.time-shift").ok_or_else(|| {
                    conflict("--redact.time-mode shift requires --redact.time-shift <secs>")
                })?;
                let secs = parse_duration_secs(raw)
                    .ok_or_else(|| conflict(format!("bad --redact.time-shift {raw:?} (want decimal seconds, or 1d / 2w)")))?;
                TimeMode::Shift(secs)
            }
            "bucket" => {
                let raw = args.value("redact.time-bucket").ok_or_else(|| {
                    conflict("--redact.time-mode bucket requires --redact.time-bucket day|week|month")
                })?;
                TimeMode::Bucket(match raw {
                    "day" => TimeBucketUnit::Day,
                    "week" => TimeBucketUnit::Week,
                    "month" => TimeBucketUnit::Month,
                    other => {
                        return Err(conflict(format!(
                            "unknown --redact.time-bucket {other:?} (want day|week|month)"
                        )))
                    }
                })
            }
            "fuzz" => {
                let raw = args.value("redact.time-jitter").ok_or_else(|| {
                    conflict("--redact.time-mode fuzz requires --redact.time-jitter <secs>")
                })?;
                let secs = parse_duration_secs(raw)
                    .ok_or_else(|| conflict(format!("bad --redact.time-jitter {raw:?} (want decimal seconds, or 1d / 2w)")))?;
                if secs < 0 {
                    return Err(conflict("--redact.time-jitter must be non-negative"));
                }
                TimeMode::Fuzz {
                    jitter_secs: secs as u64,
                }
            }
            other => {
                return Err(conflict(format!(
                    "unknown --redact.time-mode {other:?} (want preserve|zero|shift|bucket|fuzz)"
                )))
            }
        };

        // Seed rules (plan §5.1): required for fuzz, invalid otherwise.
        let seed_str = args.value("redact.seed");
        let seed = match seed_str {
            Some(raw) => parse_seed(raw)
                .ok_or_else(|| conflict(format!("bad --redact.seed {raw:?} (want decimal or 0x-hex u64)")))?,
            None => 0,
        };
        if seed_str.is_some() && !matches!(time_mode, TimeMode::Fuzz { .. }) {
            return Err(conflict(
                "--redact.seed is only valid with --redact.time-mode fuzz",
            ));
        }
        if matches!(time_mode, TimeMode::Fuzz { .. }) && seed_str.is_none() {
            return Err(conflict(
                "--redact.time-mode fuzz requires --redact.seed (a silently-fixed default seed would be shared across every user's repos)",
            ));
        }

        Ok(PassSpec::Redact(gfx::gfx_redact::RedactConfig {
            ident_mode,
            time_mode,
            keep_tz: args.flag("redact.keep-tz"),
            seed,
            ..gfx::gfx_redact::RedactConfig::default()
        }))
    }
}
