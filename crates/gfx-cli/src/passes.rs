



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
