//! Parsing configuration: strictness, limits, object format.

/// Hash algorithm in effect for the stream.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ObjectFormat {
    #[default]
    Sha1,
    Sha256,
}

/// How the parser decides the object format.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ObjectFormatMode {
    /// Fixed SHA-1: a conflicting `feature object-format=` line is an error.
    Sha1,
    Sha256,
    /// Infer from `feature object-format=`; before any feature line, both hex
    /// lengths are accepted (default).
    #[default]
    Auto,
}

/// `Lenient` (default) preserves raw text where possible and passes unknown
/// `feature` lines through; `Strict` enforces fast-import's documented
/// validations.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ParseMode {
    #[default]
    Lenient,
    Strict,
}

/// Resource guards. Defaults follow the plan (§5.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Maximum `data` payload, bytes (default 1 GiB).
    pub max_data: u64,
    /// Maximum line length outside `data` payloads (default 1 MiB).
    pub max_line: usize,
    /// Maximum `merge` headers per commit.
    pub max_merges: usize,
    /// Maximum file operations per commit.
    pub max_ops: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_data: 1 << 30,
            max_line: 1 << 20,
            max_merges: 1024,
            max_ops: 100_000,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParseOptions {
    pub mode: ParseMode,
    /// Capture `#` lines as [`Event::Comment`](crate::Event::Comment)
    /// (line-level granularity).
    pub keep_comments: bool,
    pub limits: Limits,
    pub object_format: ObjectFormatMode,
}

impl ParseOptions {
    pub fn strict() -> Self {
        ParseOptions {
            mode: ParseMode::Strict,
            ..ParseOptions::default()
        }
    }
}
