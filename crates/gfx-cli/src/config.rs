//! `--config` file surface (plan §7 P3): a TOML file mapping pass names to
//! flag tables, merged under the CLI flags (CLI wins — flags are the more
//! specific intent).
//!
//! ```toml
//! # gfx-rewrite.toml
//! [strip-blobs]
//! larger-than = "1M"
//! path-glob = ["**/Cargo.lock", "*.min.js"]
//! content-signals = true
//!
//! [remap]
//! track-message-oids = false
//! ```
//!
//! Keys are the *flat* flag names (`arg_spec().flag`), not namespaced: the
//! table name supplies the namespace. Unknown pass or flag keys are hard
//! errors, mirroring the CLI's refusal to silently skip.

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::args::ArgMap;
use crate::error::CliError;
use crate::registry::PassRegistry;

/// Load a TOML config into the `ArgMap` as namespaced keys. Called after
/// CLI parsing so the CLI values simply overwrite (or accumulate for
/// `Multi` — CLI entries are appended after file entries, keeping the
/// file as base and CLI as override in both senses).
pub fn apply_config_file(
    registry: &PassRegistry,
    path: &std::path::Path,
    map: &mut ArgMap,
) -> Result<(), CliError> {
    let bytes = std::fs::read(path)?;
    let text = String::from_utf8(bytes).map_err(|e| CliError::BadConfig {
        file: path.display().to_string(),
        msg: format!("not valid UTF-8: {e}"),
    })?;
    let value: toml::Value = text.parse().map_err(|e| CliError::BadConfig {
        file: path.display().to_string(),
        msg: format!("not valid TOML: {e}"),
    })?;
    let Some(table) = value.as_table() else {
        return Err(CliError::BadConfig {
            file: path.display().to_string(),
            msg: "top level must be a table of pass names".into(),
        });
    };

    let names: Vec<&'static str> = registry.names();
    for (pass, entries) in table {
        if !names.contains(&pass.as_str()) {
            return Err(CliError::UnknownPass {
                name: pass.clone(),
                available: names.iter().map(|s| s.to_string()).collect(),
            });
        }
        let Some(entries) = entries.as_table() else {
            return Err(CliError::BadConfig {
                file: path.display().to_string(),
                msg: format!("[{pass}] must be a table of flag = value"),
            });
        };
        let known = registry
            .flag_kinds(pass)
            .expect("pass name checked above");
        for (flag, value) in entries {
            let kind = known
                .iter()
                .find(|(f, _)| f == flag)
                .map(|(_, k)| *k)
                .ok_or_else(|| CliError::BadConfig {
                    file: path.display().to_string(),
                    msg: format!("[{pass}] has no flag {flag:?}"),
                })?;
            let _ = kind;
            let key = format!("{pass}.{flag}");
            match value {
                toml::Value::Boolean(b) => {
                    if !*b {
                        continue; // flag = false means "leave off"
                    }
                    map.mark_present(&key);
                }
                toml::Value::String(s) => map.put(&key, s.clone()),
                toml::Value::Integer(i) => map.put(&key, i.to_string()),
                toml::Value::Array(items) => {
                    for item in items {
                        match item {
                            toml::Value::String(s) => map.put(&key, s.clone()),
                            toml::Value::Integer(i) => map.put(&key, i.to_string()),
                            other => {
                                return Err(CliError::BadConfig {
                                    file: path.display().to_string(),
                                    msg: format!("unsupported list element in {key}: {other:?}"),
                                })
                            }
                        }
                    }
                }
                other => {
                    return Err(CliError::BadConfig {
                        file: path.display().to_string(),
                        msg: format!("unsupported value type for {key}: {other:?}"),
                    })
                }
            }
        }
    }
    Ok(())
}
