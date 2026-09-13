



//! Pass registry (plan §4.2, decision D4): passes are discovered through
//! declared factories, never a hardcoded match — this is what lets
//! [`crate::rewrite_binary!`] build a binary around any pass subset.


extern crate alloc;
extern crate std;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::args::{ArgMap, ArgSpec};
use crate::error::CliError;
use gfx::driver::PassSpec;

/// Declares and builds one pass.
pub trait PassFactory: Send + Sync {
    /// Registry name used in `--passes`.
    fn name(&self) -> &'static str;

    /// This pass's flags. In a composed binary the registry namespaces them
    /// as `--<pass>.<flag>`; the flat `--<flag>` form is accepted when
    /// unambiguous (see [`crate::args`]).
    fn arg_spec(&self) -> Vec<ArgSpec>;

    /// Whether this pass belongs in the composed binary's implicit default
    /// `--passes`. Redaction must always be opt-in (plan-redact-idents.md
    /// decision D2), so `redact` overrides this to `false` while staying
    /// registered (discoverable via `--passes redact`).
    fn in_default(&self) -> bool {
        true
    }

    /// Build the pass configuration from the parsed args. Implementations
    /// read only their own (namespaced) keys.
    fn build(&self, args: &ArgMap) -> Result<PassSpec, CliError>;
}

/// Lets already-boxed factories (e.g. `passes::remap_factory()`) be passed
/// to [`crate::rewrite_binary!`] directly.
impl PassFactory for Box<dyn PassFactory> {
    fn name(&self) -> &'static str {
        (**self).name()
    }

    fn in_default(&self) -> bool {
        (**self).in_default()
    }

    fn arg_spec(&self) -> Vec<ArgSpec> {
        (**self).arg_spec()
    }

    fn build(&self, args: &ArgMap) -> Result<PassSpec, CliError> {
        (**self).build(args)
    }
}

/// An ordered set of factories. The listed order is the default `--passes`
/// value and the pipeline order when the user does not override it.
pub struct PassRegistry {
    factories: Vec<Box<dyn PassFactory>>,
}

impl PassRegistry {
    /// Build a registry; duplicate pass names are a construction error.
    pub fn new(factories: Vec<Box<dyn PassFactory>>) -> Result<Self, CliError> {
        let mut seen = alloc::collections::BTreeSet::new();
        for f in &factories {
            if !seen.insert(f.name()) {
                return Err(CliError::PassOrder(format!(
                    "pass {:?} registered more than once",
                    f.name()
                )));
            }
        }
        Ok(PassRegistry { factories })
    }

    pub fn names(&self) -> Vec<&'static str> {
        self.factories.iter().map(|f| f.name()).collect()
    }

    /// A pass's declared flags (name, kind), for config-file validation.
    pub fn flag_kinds(&self, pass: &str) -> Option<Vec<(&'static str, crate::args::ArgKind)>> {
        self.factories
            .iter()
            .find(|f| f.name() == pass)
            .map(|f| f.arg_spec().into_iter().map(|s| (s.flag, s.kind)).collect())
    }

    /// The default `--passes` value: every registered pass, in registry
    /// order (factories are expected to be listed in valid pipeline order —
    /// content passes first, remap last).
    pub fn default_spec(&self) -> String {
        self.factories
            .iter()
            .filter(|f| f.in_default())
            .map(|f| f.name())
            .collect::<Vec<_>>()
            .join(",")
    }

    /// All flags (namespaced) plus the global CLI flags.
    pub fn all_args(&self, globals: &[ArgSpec]) -> Vec<crate::args::CliArg> {
        let mut out: Vec<crate::args::CliArg> = globals
            .iter()
            .map(|s| crate::args::CliArg {
                key: s.flag.to_string(),
                spec: s.clone(),
            })
            .collect();
        for f in &self.factories {
            for spec in f.arg_spec() {
                out.push(crate::args::CliArg {
                    key: format!("{}.{}", f.name(), spec.flag),
                    spec,
                });
            }
        }
        out
    }

    /// Resolve a `--passes` spec (comma-separated names, order matters) to
    /// configured passes. An unknown name is a hard error listing available
    /// passes — never silently skipped (plan §4.2).
    pub fn resolve(&self, spec: &str, args: &ArgMap) -> Result<Vec<PassSpec>, CliError> {
        let mut out = Vec::new();
        for raw in spec.split(',') {
            let name = raw.trim();
            if name.is_empty() {
                return Err(CliError::PassOrder(
                    "empty pass name in --passes (want comma-separated names)".into(),
                ));
            }
            let factory = self
                .factories
                .iter()
                .find(|f| f.name() == name)
                .ok_or_else(|| CliError::UnknownPass {
                    name: name.to_string(),
                    available: self.names().into_iter().map(String::from).collect(),
                })?;
            out.push(factory.build(args)?);
        }
        Ok(out)
    }

    /// Usage text derived from the registry (help output stays in sync with
    /// declared specs by construction).
    pub fn usage(&self, binary: &str, about: &str, globals: &[ArgSpec]) -> String {
        let mut s = alloc::format!("{binary} — {about}\n\n");
        s.push_str(&format!(
            "usage: {binary} [--repo <path>] [--force] [--dry-run] \
             [--passes <spec>] [--pass.<flag> <value>]...\n\n"
        ));
        s.push_str("global flags:\n");
        for g in globals {
            s.push_str(&format!("  --{:<28} {}\n", g.flag, g.help));
        }
        s.push_str("\npass flags (namespaced; flat form accepted when unambiguous):\n");
        for f in &self.factories {
            s.push_str(&format!("  {}:\n", f.name()));
            for spec in f.arg_spec() {
                let def = spec
                    .default
                    .map(|d| alloc::format!(" (default: {d})"))
                    .unwrap_or_default();
                s.push_str(&format!(
                    "    --{}.{:<22} {}{}\n",
                    f.name(),
                    spec.flag,
                    spec.help,
                    def
                ));
            }
        }
        s.push_str(&format!(
            "\ndefault passes: {}\n",
            self.default_spec()
        ));
        s
    }
}
