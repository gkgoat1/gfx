



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

// ---------------------------------------------------------------------------
// blob-xform (plan-blob-xform.md §4.3)

pub struct BlobXformFactory;

pub fn blob_xform_factory() -> Box<dyn PassFactory> {
    Box::new(BlobXformFactory)
}

impl PassFactory for BlobXformFactory {
    fn name(&self) -> &'static str {
        "blob-xform"
    }

    fn in_default(&self) -> bool {
        // Content rewriting is always opt-in (same stance as redact's D2).
        false
    }

    fn arg_spec(&self) -> Vec<ArgSpec> {
        vec![
            ArgSpec::flag("crlf-to-lf", "chain: CRLF/CR line endings become LF"),
            ArgSpec::flag(
                "trim-trailing-whitespace",
                "chain: strip trailing spaces/tabs per line (text blobs)",
            ),
            ArgSpec::flag(
                "ensure-final-newline",
                "chain: end text blobs with exactly one newline",
            ),
            ArgSpec::size("skip-larger-than", None, "leave blobs larger than this alone"),
            ArgSpec::size(
                "max-output-bytes",
                None,
                "discard a chain result larger than this (retain the original)",
            ),
            ArgSpec::flag(
                "include-special-modes",
                "also transform inline symlink/gitlink payloads (plan-blob-xform.md D5)",
            ),
            ArgSpec::multi(
                "cmd",
                "chain: pipe each blob through this shell command (repeatable); non-zero exit retains the blob",
            ),
            // Path rules (plan-blob-xform-paths.md §5.3): dynamic keys —
            // <ext> is the literal extension ([A-Za-z0-9]+).
            ArgSpec::dynamic_multi(
                "ext.<ext>.cmd",
                "path rule: pipe blobs used at *.<ext> paths through this shell command (repeatable)",
            ),
            ArgSpec::dynamic_flag("ext.<ext>.crlf-to-lf", "path rule chain stage for *.<ext>"),
            ArgSpec::dynamic_flag("ext.<ext>.trim-trailing-whitespace", "path rule chain stage for *.<ext>"),
            ArgSpec::dynamic_flag("ext.<ext>.ensure-final-newline", "path rule chain stage for *.<ext>"),
            ArgSpec::dynamic_size("ext.<ext>.skip-larger-than", "path rule guard for *.<ext>"),
            ArgSpec::dynamic_size("ext.<ext>.max-output-bytes", "path rule output bound for *.<ext>"),
        ]
    }

    fn build(&self, args: &ArgMap) -> Result<PassSpec, CliError> {
        use gfx::gfx_blob_xform::{builtins, SharedBlobTransform};
        fn shared<T: gfx::gfx_blob_xform::BlobTransform + 'static>(t: T) -> SharedBlobTransform {
            SharedBlobTransform(std::sync::Arc::new(t))
        }
        let max_output = args.size("blob-xform.max-output-bytes")?;
        // Chain order = argv order (plan §4.3); `--blob-xform.cmd` stages
        // interleave with the built-ins exactly as given. Path-rule
        // stages group by extension, each extension's chain in argv order
        // (plan-blob-xform-paths.md §5.3).
        let mut transforms: Vec<SharedBlobTransform> = Vec::new();
        let mut rule_exts: Vec<String> = Vec::new(); // first-seen order
        let mut rule_stages: std::collections::BTreeMap<String, Vec<SharedBlobTransform>> =
            std::collections::BTreeMap::new();
        let push_rule_stage = |ext: &str, t: SharedBlobTransform, rule_exts: &mut Vec<String>, rule_stages: &mut std::collections::BTreeMap<String, Vec<SharedBlobTransform>>| {
            if !rule_stages.contains_key(ext) {
                rule_exts.push(ext.to_string());
            }
            rule_stages.entry(ext.to_string()).or_default().push(t);
        };
        for (key, value) in args.ordered_entries() {
            let t = match key.as_str() {
                "blob-xform.crlf-to-lf" => Some(shared(builtins::CrlfToLf)),
                "blob-xform.trim-trailing-whitespace" => {
                    Some(shared(builtins::TrimTrailingWhitespace))
                }
                "blob-xform.ensure-final-newline" => Some(shared(builtins::EnsureFinalNewline)),
                "blob-xform.cmd" => Some(shared(crate::cmd::CmdTransform {
                    cmd: value.clone().expect("multi flag carries a value"),
                    capture_limit: max_output.unwrap_or(crate::cmd::DEFAULT_CAPTURE_LIMIT),
                })),
                _ => None,
            };
            if let Some(t) = t {
                transforms.push(t);
                continue;
            }
            if let Some(rest) = key.strip_prefix("blob-xform.ext.") {
                let (ext, sub) = rest.rsplit_once('.').expect("dynamic key has ext and sub-key");
                let rule_max = args
                    .size(&format!("blob-xform.ext.{ext}.max-output-bytes"))?
                    .or(max_output);
                match sub {
                    "cmd" => push_rule_stage(ext, shared(crate::cmd::CmdTransform {
                        cmd: value.clone().expect("multi flag carries a value"),
                        capture_limit: rule_max.unwrap_or(crate::cmd::DEFAULT_CAPTURE_LIMIT),
                    }), &mut rule_exts, &mut rule_stages),
                    "crlf-to-lf" => push_rule_stage(ext, shared(builtins::CrlfToLf), &mut rule_exts, &mut rule_stages),
                    "trim-trailing-whitespace" => push_rule_stage(ext, shared(builtins::TrimTrailingWhitespace), &mut rule_exts, &mut rule_stages),
                    "ensure-final-newline" => push_rule_stage(ext, shared(builtins::EnsureFinalNewline), &mut rule_exts, &mut rule_stages),
                    "skip-larger-than" | "max-output-bytes" => {
                        if !rule_stages.contains_key(ext) && !rule_exts.contains(&ext.to_string()) {
                            rule_exts.push(ext.to_string());
                        }
                    }
                    other => {
                        return Err(CliError::UnknownFlag {
                            flag: format!("blob-xform.ext.{ext}.{other}"),
                            available: vec![],
                        })
                    }
                }
            }
        }
        let mut path_rules: Vec<gfx::gfx_blob_xform::PathRule> = Vec::new();
        for ext in &rule_exts {
            let stages = rule_stages.remove(ext).unwrap_or_default();
            if stages.is_empty() {
                return Err(CliError::FlagConflict(format!(
                    "--blob-xform.ext.{ext}.* declares guards but no transform stages;                      a path rule needs at least one stage (e.g. --blob-xform.ext.{ext}.cmd)"
                )));
            }
            path_rules.push(gfx::gfx_blob_xform::PathRule {
                extension: ext.as_bytes().to_vec(),
                transforms: stages,
                skip_larger_than: args.size(&format!("blob-xform.ext.{ext}.skip-larger-than"))?,
                max_output_bytes: args.size(&format!("blob-xform.ext.{ext}.max-output-bytes"))?,
            });
        }
        if transforms.is_empty() && path_rules.is_empty() {
            return Err(CliError::FlagConflict(
                "blob-xform needs at least one transform flag \
                 (e.g. --blob-xform.crlf-to-lf or --blob-xform.ext.rs.cmd …); \
                 nothing to do otherwise"
                    .into(),
            ));
        }
        Ok(PassSpec::BlobXform(gfx::gfx_blob_xform::BlobXformConfig {
            transforms,
            skip_larger_than: args.size("blob-xform.skip-larger-than")?,
            max_output_bytes: max_output,
            include_inline: true,
            include_special_modes: args.flag("blob-xform.include-special-modes"),
            path_rules,
            ..Default::default()
        }))
    }
}

// ---------------------------------------------------------------------------
// enforce-ignore (plan-stream-files.md D6)

/// Builtin: retroactive `.gitignore` enforcement. Flags:
///
/// ```text
/// --enforce-ignore.rules <file>   gitignore-format rules, root-anchored
///                                 from stream start (repeatable)
/// ```
///
/// Rule files are read by the host (this crate) and injected as bytes —
/// the pass itself stays sans-IO (C1).
pub struct EnforceIgnoreFactory;

pub fn enforce_ignore_factory() -> Box<dyn PassFactory> {
    Box::new(EnforceIgnoreFactory)
}

impl PassFactory for EnforceIgnoreFactory {
    fn name(&self) -> &'static str {
        "enforce-ignore"
    }

    fn in_default(&self) -> bool {
        // Enforcement rewrites history contents; opt-in like redact (C7:
        // default flows stay byte-identical to pre-M3 gfx).
        false
    }

    fn arg_spec(&self) -> Vec<ArgSpec> {
        vec![ArgSpec::multi(
            "rules",
            "gitignore-format rule file, applied root-anchored from stream start (repeatable)",
        )]
    }

    fn build(&self, args: &ArgMap) -> Result<PassSpec, CliError> {
        let mut external_rules = Vec::new();
        for path in args.multi("enforce-ignore.rules") {
            let bytes = std::fs::read(path)?;
            external_rules.push(gfx::core::BString::from(bytes));
        }
        if external_rules.is_empty() {
            return Err(CliError::FlagConflict(
                "enforce-ignore needs at least one rule source \
                 (--enforce-ignore.rules <file>); a pass with no rules is a no-op you didn't mean"
                    .into(),
            ));
        }
        Ok(PassSpec::EnforceIgnore(
            gfx::gfx_enforce_ignore::EnforceIgnoreConfig {
                external_rules,
                ..Default::default()
            },
        ))
    }
}
