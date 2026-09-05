



//! CLI error surface.


extern crate alloc;
extern crate std;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use gfx::driver::DriverError;

#[derive(Debug)]
pub enum CliError {
    /// `--flag` that no registry pass or global spec declares.
    UnknownFlag {
        flag: String,
        available: Vec<String>,
    },
    /// Flat `--<flag>` matched more than one pass's namespaced flag.
    AmbiguousFlag { flag: String },
    /// A value-bearing flag was given without a value.
    MissingValue { flag: String },
    /// A size flag value did not parse (`1024`, `512K`, `1M`, `2G`).
    BadSize { value: String, flag: String },
    /// A bare argument where a flag was expected.
    UnexpectedPositional(String),
    /// Pass list referenced a name not in the registry.
    UnknownPass { name: String, available: Vec<String> },
    /// Pass list violated driver ordering (remap not last, duplicated).
    PassOrder(String),
    /// Driver/validation failures.
    Driver(DriverError),
    /// Artifact/report writing failure.
    Io(std::io::Error),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::UnknownFlag { flag, available } => {
                write!(f, "unknown flag --{flag}; available: {}", available.join(", "))
            }
            CliError::AmbiguousFlag { flag } => write!(
                f,
                "flag --{flag} is ambiguous (several passes declare it); \
                 use the namespaced form --<pass>.{flag}"
            ),
            CliError::MissingValue { flag } => write!(f, "flag --{flag} requires a value"),
            CliError::BadSize { value, flag } => {
                write!(f, "invalid size {value:?} for --{flag} (want e.g. 1024, 512K, 1M, 2G)")
            }
            CliError::UnexpectedPositional(tok) => {
                write!(f, "unexpected argument {tok:?} (expected a --flag)")
            }
            CliError::UnknownPass { name, available } => {
                write!(f, "unknown pass {name:?}; available: {}", available.join(", "))
            }
            CliError::PassOrder(msg) => write!(f, "{msg}"),
            CliError::Driver(e) => write!(f, "{e}"),
            CliError::Io(e) => write!(f, "i/o error: {e}"),
        }
    }
}

impl std::error::Error for CliError {}

impl From<DriverError> for CliError {
    fn from(e: DriverError) -> Self {
        CliError::Driver(e)
    }
}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        CliError::Io(e)
    }
}
