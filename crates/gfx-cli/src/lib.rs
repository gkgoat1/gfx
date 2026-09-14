//! `gfx-cli` — the pass-driver CLI *library* (plan §4, decision D4).
//!
//! Any set of passes can be wrapped into a customized binary via the
//! [`rewrite_binary!`] macro; this crate's default binary `gfx`
//! (`src/bin/gfx.rs`) is itself just the macro over every compiled-in pass —
//! dogfooding, zero special-casing.
//!
//! Layering: `gfx` (facade) owns the driver round and the passes; this crate
//! owns the CLI surface — argument model ([`args`]), pass registry
//! ([`registry`]), flag-to-`PassSpec` factories ([`passes`]), and the
//! generated-`main` entry point ([`cli`]).

extern crate std;

pub mod args;
pub mod cli;
pub mod cmd;
pub mod config;
pub mod error;
pub mod pack_cli;
pub mod passes;
pub mod registry;
pub mod unpack_cli;

mod macros;

pub use args::{parse_argv, ArgKind, ArgMap, ArgSpec};
pub use cli::{resolve_passes_checked, run_rewrite_cli_to, EXIT_FAILURE, EXIT_OK, EXIT_USAGE};
pub use error::CliError;
pub use pack_cli::run_pack_cli_to;
pub use unpack_cli::run_unpack_cli_to;
pub use registry::{PassFactory, PassRegistry};

/// Convenience re-exports for generated binaries.
pub mod prelude {
    pub use crate::{rewrite_binary, ArgMap, PassFactory, PassRegistry};
}
