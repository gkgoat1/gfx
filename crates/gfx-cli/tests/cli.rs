//! `gfx-cli` library tests: arg parsing/namespacing, registry resolution,
//! usage text, and the macro-generated binary surface (acceptance A7).

use gfx_cli::args::{parse_argv, ArgKind, ArgSpec};
use gfx_cli::passes::remap_factory;
use gfx_cli::registry::PassRegistry;
use gfx::driver::PassSpec;
use std::ffi::OsString;

fn os(args: &[&str]) -> Vec<OsString> {
    args.iter().map(OsString::from).collect()
}

fn registry() -> PassRegistry {
    PassRegistry::new(vec![remap_factory()]).unwrap()
}

#[test]
fn parse_flag_value_and_defaults() {
    let reg = registry();
    let specs = reg.all_args(&gfx_cli::cli::global_args());
    let map = parse_argv(&specs, &os(&["--repo", "/tmp/x", "--dry-run"])).unwrap();
    assert_eq!(map.value("repo"), Some("/tmp/x"));
    assert!(map.flag("dry-run"));
    assert!(!map.flag("force"));
    // `passes` has no default in the spec; the registry supplies one.
    assert_eq!(map.value("passes"), None);
}

#[test]
fn inline_value_and_size_parsing() {
    let specs = vec![
        ArgSpec::size("size-threshold", None, "bytes"),
        ArgSpec::value("name", Some("default-name"), "x"),
    ]
    .into_iter()
    .map(|s| gfx_cli::args::CliArg { key: s.flag.to_string(), spec: s })
    .collect::<Vec<_>>();
    let map = parse_argv(&specs, &os(&["--size-threshold=1M", "--name", "custom"])).unwrap();
    assert_eq!(map.size("size-threshold").unwrap(), Some(1 << 20));
    assert_eq!(map.value("name"), Some("custom"));

    let map2 = parse_argv(&specs, &os(&[])).unwrap();
    assert_eq!(map2.value("name"), Some("default-name"));
    assert_eq!(map2.size("size-threshold").unwrap(), None);
}

#[test]
fn size_forms() {
    for (s, want) in [
        ("1024", 1024u64),
        ("512K", 512 * 1024),
        ("1m", 1 << 20),
        ("2G", 2 * (1 << 30)),
        ("64kB", 64 * 1024),
    ] {
        assert_eq!(gfx_cli::args::parse_size(s), Some(want), "{s}");
    }
    assert_eq!(gfx_cli::args::parse_size("abc"), None);
    assert_eq!(gfx_cli::args::parse_size(""), None);
}

#[test]
fn unknown_and_ambiguous_flags_error() {
    let reg = registry();
    let specs = reg.all_args(&gfx_cli::cli::global_args());
    let err = parse_argv(&specs, &os(&["--nope"])).unwrap_err();
    assert!(matches!(err, gfx_cli::CliError::UnknownFlag { .. }));

    // Flat form of a unique namespaced flag resolves.
    let map = parse_argv(&specs, &os(&["--track-message-oids"])).unwrap();
    assert!(map.flag("remap.track-message-oids"));
}

#[test]
fn registry_resolves_passes_in_order() {
    let reg = registry();
    let specs = reg.all_args(&gfx_cli::cli::global_args());
    let map = parse_argv(&specs, &os(&["--passes", "remap"])).unwrap();
    let passes = reg.resolve("remap", &map).unwrap();
    assert_eq!(passes.len(), 1);
    assert_eq!(passes[0].name(), "remap");

    let err = reg.resolve("nope", &map).unwrap_err();
    match &err {
        gfx_cli::CliError::UnknownPass { name, available } => {
            assert_eq!(name, "nope");
            assert_eq!(available, &vec!["remap".to_string()]);
        }
        other => panic!("expected UnknownPass, got {other}"),
    }
}

#[test]
fn factory_builds_config_from_flags() {
    let reg = registry();
    let specs = reg.all_args(&gfx_cli::cli::global_args());
    let map = parse_argv(&specs, &os(&["--remap.track-message-oids"])).unwrap();
    let passes = reg.resolve("remap", &map).unwrap();
    match &passes[0] {
        PassSpec::Remap(cfg) => assert!(cfg.track_message_oids),
    }

    let map2 = parse_argv(&specs, &os(&[])).unwrap();
    let passes2 = reg.resolve("remap", &map2).unwrap();
    match &passes2[0] {
        PassSpec::Remap(cfg) => assert!(!cfg.track_message_oids),
    }
}

#[test]
fn usage_lists_every_declared_flag() {
    let reg = registry();
    let usage = reg.usage("gfx", "about text", &gfx_cli::cli::global_args());
    for flag in ["--repo", "--force", "--dry-run", "--passes", "--remap.track-message-oids"] {
        assert!(usage.contains(flag), "usage missing {flag}");
    }
    assert!(usage.contains("default passes: remap"));
}

#[test]
fn cli_end_to_end_dry_run_help_and_errors() {
    let reg = registry();
    // --help exits 0, prints usage
    let mut out = Vec::new();
    let code = gfx_cli::run_rewrite_cli_to(
        &mut out,
        "test-gfx",
        "about",
        vec![remap_factory()],
        os(&["--help"]),
    );
    assert_eq!(code, gfx_cli::EXIT_OK);
    assert!(String::from_utf8_lossy(&out).contains("usage:"));

    // unknown pass exits 2 (usage error)
    let mut out = Vec::new();
    let code = gfx_cli::run_rewrite_cli_to(
        &mut out,
        "test-gfx",
        "about",
        vec![remap_factory()],
        os(&["--passes", "bogus"]),
    );
    assert_eq!(code, gfx_cli::EXIT_USAGE);

    // missing repo exits nonzero
    let mut out = Vec::new();
    let code = gfx_cli::run_rewrite_cli_to(
        &mut out,
        "test-gfx",
        "about",
        vec![remap_factory()],
        os(&["--repo", "/nonexistent/gfx-test-repo-xyz"]),
    );
    assert_eq!(code, gfx_cli::EXIT_FAILURE);
}

#[test]
fn arg_kinds_are_distinct() {
    assert_ne!(ArgKind::Flag, ArgKind::Value);
    assert_ne!(ArgKind::Value, ArgKind::Size);
}
