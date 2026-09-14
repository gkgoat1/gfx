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
        other => panic!("expected remap, got {other:?}"),
    }

    let map2 = parse_argv(&specs, &os(&[])).unwrap();
    let passes2 = reg.resolve("remap", &map2).unwrap();
    match &passes2[0] {
        PassSpec::Remap(cfg) => assert!(!cfg.track_message_oids),
        other => panic!("expected remap, got {other:?}"),
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
fn composed_registry_defaults_to_strip_then_remap() {
    let reg = PassRegistry::new(vec![
        gfx_cli::passes::strip_blobs_factory(),
        gfx_cli::passes::remap_factory(),
    ])
    .unwrap();
    assert_eq!(reg.default_spec(), "strip-blobs,remap");
    let specs = reg.all_args(&gfx_cli::cli::global_args());
    let map = parse_argv(&specs, &os(&[])).unwrap();
    let passes = reg.resolve(&reg.default_spec(), &map).unwrap();
    assert_eq!(passes.len(), 2);
    assert_eq!(passes[0].name(), "strip-blobs");
    assert_eq!(passes[1].name(), "remap");

    // Wrong order through the CLI → usage error (A4).
    let mut out = Vec::new();
    let code = gfx_cli::run_rewrite_cli_to(
        &mut out,
        "test-gfx",
        "about",
        vec![
            gfx_cli::passes::strip_blobs_factory(),
            gfx_cli::passes::remap_factory(),
        ],
        os(&["--repo", "/tmp", "--passes", "remap,strip-blobs"]),
    );
    assert_eq!(code, gfx_cli::EXIT_USAGE);
}

#[test]
fn strip_flags_reach_the_pass_through_the_cli() {
    let mut out = Vec::new();
    let code = gfx_cli::run_rewrite_cli_to(
        &mut out,
        "test-gfx",
        "about",
        vec![
            gfx_cli::passes::strip_blobs_factory(),
            gfx_cli::passes::remap_factory(),
        ],
        os(&["--repo", "/definitely/not/a/repo", "--dry-run", "--strip-blobs.larger-than", "1M", "--strip-blobs.path-glob", "**/Cargo.lock"]),
    );
    // Fails at the repo check, not at flag parsing — flags were accepted.
    assert_eq!(code, gfx_cli::EXIT_FAILURE);
}

#[test]
fn config_file_supplies_flags_cli_wins() {
    let dir = std::env::temp_dir().join(format!("gfx-cli-cfg-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("gfx-rewrite.toml");
    std::fs::write(
        &cfg,
        r#"
[strip-blobs]
larger-than = "2M"
path-glob = ["**/Cargo.lock", "*.min.js"]
content-signals = true

[remap]
track-message-oids = true
"#,
    )
    .unwrap();

    // Config alone → unknown pass in file is an error.
    let bad = dir.join("bad.toml");
    std::fs::write(&bad, "[nope]
x = 1
").unwrap();
    let mut out = Vec::new();
    let code = gfx_cli::run_rewrite_cli_to(
        &mut out,
        "test-gfx",
        "about",
        vec![remap_factory()],
        os(&["--repo", "/definitely/not/a/repo", "--config", bad.to_str().unwrap()]),
    );
    assert_eq!(code, gfx_cli::EXIT_USAGE, "bad config pass name is a usage error");

    // Unknown flag in a known pass table is also an error.
    let bad2 = dir.join("bad2.toml");
    std::fs::write(&bad2, "[remap]
no-such-flag = true
").unwrap();
    let mut out = Vec::new();
    let code = gfx_cli::run_rewrite_cli_to(
        &mut out,
        "test-gfx",
        "about",
        vec![remap_factory()],
        os(&["--repo", "/definitely/not/a/repo", "--config", bad2.to_str().unwrap()]),
    );
    assert_eq!(code, gfx_cli::EXIT_USAGE, "bad config flag name is a usage error");

    // Valid config parses (fails later at the repo check — which is also a
    // usage-domain failure here, EXIT_USAGE, not a driver failure).
    let mut out = Vec::new();
    let code = gfx_cli::run_rewrite_cli_to(
        &mut out,
        "test-gfx",
        "about",
        vec![remap_factory()],
        os(&["--repo", "/definitely/not/a/repo", "--config", cfg.to_str().unwrap()]),
    );
    assert_eq!(code, gfx_cli::EXIT_USAGE);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn arg_kinds_are_distinct() {
    assert_ne!(ArgKind::Flag, ArgKind::Value);
    assert_ne!(ArgKind::Value, ArgKind::Size);
}

// ------------------------------------------------------- redact (M2)

fn redact_registry() -> PassRegistry {
    PassRegistry::new(vec![
        gfx_cli::passes::strip_blobs_factory(),
        gfx_cli::passes::redact_factory(),
        gfx_cli::passes::remap_factory(),
    ])
    .unwrap()
}

/// Decision D2: redact is registered but NOT in the default --passes.
#[test]
fn redact_registered_but_not_in_default_passes() {
    let reg = redact_registry();
    assert_eq!(reg.default_spec(), "strip-blobs,remap");
    // ...and still discoverable/resolvable when named explicitly.
    let specs = reg.all_args(&gfx_cli::cli::global_args());
    let map = parse_argv(&specs, &os(&[])).unwrap();
    let passes = reg.resolve("strip-blobs,redact,remap", &map).unwrap();
    assert_eq!(
        passes.iter().map(|p| p.name()).collect::<Vec<_>>(),
        vec!["strip-blobs", "redact", "remap"]
    );
}

/// §5.1 rules: mutual exclusions, context-invalid flags, fuzz seed policy.
#[test]
fn redact_flag_rules_are_enforced() {
    let reg = redact_registry();
    let specs = reg.all_args(&gfx_cli::cli::global_args());
    let cases: &[(&[&str], bool)] = &[
        // valid: pseudonymize + zero
        (&["--redact.pseudonymize", "--redact.time-mode", "zero"], true),
        // valid: time-only redaction (independent axes, §4.4)
        (&["--redact.time-mode", "shift", "--redact.time-shift", "365d"], true),
        // map + pseudonymize conflict
        (
            &["--redact.map", "m.toml", "--redact.pseudonymize"],
            false,
        ),
        // style without pseudonymize
        (&["--redact.pseudonym-style", "hash"], false),
        // shift without amount
        (&["--redact.time-mode", "shift"], false),
        // bucket without unit
        (&["--redact.time-mode", "bucket"], false),
        // fuzz without seed
        (&["--redact.time-mode", "fuzz", "--redact.time-jitter", "2d"], false),
        // seed without fuzz
        (&["--redact.seed", "7"], false),
        // fuzz with seed → ok
        (
            &[
                "--redact.time-mode",
                "fuzz",
                "--redact.time-jitter",
                "3600",
                "--redact.seed",
                "0x9E3779B97F4A7C15",
            ],
            true,
        ),
        // unknown enum values
        (&["--redact.time-mode", "yesterday"], false),
        (&["--redact.pseudonym-style", "rot13", "--redact.pseudonymize"], false),
    ];
    for (argv, ok) in cases {
        let map = parse_argv(&specs, &os(argv)).unwrap();
        let passes = reg.resolve("redact,remap", &map);
        assert_eq!(passes.is_ok(), *ok, "argv {argv:?} -> {passes:?}");
    }
}

/// The unused-flag guard (§5.1, mandatory for redact): --redact.* flags
/// without `redact` in --passes are a usage error — never silently skipped.
#[test]
fn redact_flags_without_redact_pass_are_usage_errors() {
    let mut out = Vec::new();
    let code = gfx_cli::run_rewrite_cli_to(
        &mut out,
        "test-gfx",
        "about",
        redact_registry_factories(),
        os(&["--repo", "/definitely/not/a/repo", "--dry-run", "--redact.pseudonymize"]),
    );
    assert_eq!(code, gfx_cli::EXIT_USAGE);
    // The explanation goes to stderr (eprintln!), so stdout stays empty.
    assert!(out.is_empty());
}

/// Redact flags ride through the CLI to the pass config (fails only at the
/// repo check, proving parsing/validation accepted the flags).
#[test]
fn redact_flags_reach_the_pass_through_the_cli() {
    let mut out = Vec::new();
    let code = gfx_cli::run_rewrite_cli_to(
        &mut out,
        "test-gfx",
        "about",
        redact_registry_factories(),
        os(&[
            "--repo",
            "/definitely/not/a/repo",
            "--dry-run",
            "--passes",
            "redact,remap",
            "--redact.pseudonymize",
            "--redact.time-mode",
            "bucket",
            "--redact.time-bucket",
            "month",
        ]),
    );
    assert_eq!(code, gfx_cli::EXIT_FAILURE, "{}", String::from_utf8_lossy(&out));
}

fn redact_registry_factories() -> Vec<Box<dyn gfx_cli::PassFactory>> {
    vec![
        gfx_cli::passes::strip_blobs_factory(),
        gfx_cli::passes::redact_factory(),
        gfx_cli::passes::remap_factory(),
    ]
}

/// The `--redact.map` TOML file parses into exact rows, with wildcards.
#[test]
fn redact_map_file_parses_with_wildcards() {
    let dir = std::env::temp_dir().join(format!("gfx-redact-map-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let map_path = dir.join("idents.toml");
    std::fs::write(
        &map_path,
        "[[row]]\nname = \"Alice\"\nemail = \"alice@example.com\"\nnew_name = \"Bot 1\"\nnew_email = \"bot1@ci\"\n\n[[row]]\nemail = \"@contractors\"\nnew_name = \"Ext\"\nnew_email = \"ext@example.invalid\"\n",
    )
    .unwrap();

    let reg = redact_registry();
    let specs = reg.all_args(&gfx_cli::cli::global_args());
    let map = parse_argv(
        &specs,
        &os(&["--passes", "redact,remap", "--redact.map", map_path.to_str().unwrap()]),
    )
    .unwrap();
    let passes = reg.resolve("redact,remap", &map).unwrap();
    match &passes[0] {
        PassSpec::Redact(cfg) => match &cfg.ident_mode {
            gfx::gfx_redact::IdentMode::Table(rows) => {
                assert_eq!(rows.len(), 2);
                assert_eq!(rows[0].name.as_deref().map(|v| v.as_slice()), Some(&b"Alice"[..]));
                assert_eq!(rows[1].name, None, "omitted name is a wildcard");
                assert_eq!(rows[1].new_name.as_slice(), b"Ext");
            }
            other => panic!("want table mode, got {other:?}"),
        },
        other => panic!("want redact spec, got {other:?}"),
    }

    // Missing required fields are hard errors.
    std::fs::write(&map_path, "[[row]]\nname = \"X\"\n").unwrap();
    let map = parse_argv(
        &specs,
        &os(&["--passes", "redact,remap", "--redact.map", map_path.to_str().unwrap()]),
    )
    .unwrap();
    let err = reg.resolve("redact,remap", &map).unwrap_err();
    assert!(matches!(err, gfx_cli::CliError::BadConfig { .. }), "{err}");
}

/// The `[redact]` table in the `--config` TOML file supplies flags, CLI
/// wins, and unknown keys are rejected.
#[test]
fn config_file_redact_table() {
    let dir = std::env::temp_dir().join(format!("gfx-cli-redact-cfg-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cfg_path = dir.join("gfx.toml");
    std::fs::write(
        &cfg_path,
        "[redact]\npseudonymize = true\ntime-mode = \"zero\"\n",
    )
    .unwrap();

    let mut out = Vec::new();
    let code = gfx_cli::run_rewrite_cli_to(
        &mut out,
        "test-gfx",
        "about",
        redact_registry_factories(),
        os(&[
            "--repo",
            "/definitely/not/a/repo",
            "--dry-run",
            "--config",
            cfg_path.to_str().unwrap(),
            "--passes",
            "redact,remap",
        ]),
    );
    // Config accepted; run fails only at the repo check.
    assert_eq!(code, gfx_cli::EXIT_FAILURE, "{}", String::from_utf8_lossy(&out));

    // Unknown key in [redact] is a usage error.
    std::fs::write(&cfg_path, "[redact]\nnope = true\n").unwrap();
    let mut out = Vec::new();
    let code = gfx_cli::run_rewrite_cli_to(
        &mut out,
        "test-gfx",
        "about",
        redact_registry_factories(),
        os(&[
            "--config",
            cfg_path.to_str().unwrap(),
            "--passes",
            "redact,remap",
        ]),
    );
    assert_eq!(code, gfx_cli::EXIT_USAGE);
}

// ---------------------------------------------------------------------------
// blob-xform wiring (plan-blob-xform.md §4.3)

fn blob_xform_registry() -> PassRegistry {
    PassRegistry::new(vec![
        gfx_cli::passes::strip_blobs_factory(),
        gfx_cli::passes::redact_factory(),
        gfx_cli::passes::blob_xform_factory(),
        gfx_cli::passes::remap_factory(),
    ])
    .unwrap()
}

#[test]
fn blob_xform_chain_follows_argv_order() {
    let reg = blob_xform_registry();
    let specs = reg.all_args(&gfx_cli::cli::global_args());
    let map = parse_argv(
        &specs,
        &os(&[
            "--passes", "blob-xform",
            "--blob-xform.ensure-final-newline",
            "--blob-xform.crlf-to-lf",
            "--blob-xform.skip-larger-than", "1M",
        ]),
    )
    .unwrap();
    let passes = reg.resolve("blob-xform", &map).unwrap();
    match &passes[0] {
        PassSpec::BlobXform(cfg) => {
            let names: Vec<String> =
                cfg.transforms.iter().map(|t| t.0.describe()).collect();
            assert_eq!(names, ["ensure-final-newline", "crlf-to-lf"], "chain = argv order");
            assert_eq!(cfg.skip_larger_than, Some(1 << 20));
            assert_eq!(cfg.max_output_bytes, None);
            assert!(cfg.include_inline);
            assert!(!cfg.include_special_modes);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn blob_xform_without_transform_flags_is_a_usage_error() {
    let reg = blob_xform_registry();
    let specs = reg.all_args(&gfx_cli::cli::global_args());
    let map = parse_argv(&specs, &os(&["--passes", "blob-xform"])).unwrap();
    let err = reg.resolve("blob-xform", &map).unwrap_err();
    assert!(matches!(err, gfx_cli::CliError::FlagConflict(_)), "{err:?}");
}

#[test]
fn blob_xform_flags_without_the_pass_are_rejected() {
    let reg = blob_xform_registry();
    let specs = reg.all_args(&gfx_cli::cli::global_args());
    let map = parse_argv(
        &specs,
        &os(&["--passes", "strip-blobs", "--blob-xform.crlf-to-lf"]),
    )
    .unwrap();
    let err = gfx_cli::resolve_passes_checked(&reg, &map).unwrap_err();
    match err {
        gfx_cli::CliError::FlagConflict(msg) => {
            assert!(msg.contains("blob-xform"), "{msg}");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn blob_xform_is_registered_but_never_default() {
    let reg = blob_xform_registry();
    assert!(!reg.default_spec().contains("blob-xform"), "opt-in only");
    assert!(reg.names().contains(&"blob-xform"), "discoverable");
}
