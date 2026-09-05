



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

use crate::args::{ArgMap, ArgSpec};
use crate::error::CliError;
use crate::registry::PassFactory;
use gfx::driver::PassSpec;

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
