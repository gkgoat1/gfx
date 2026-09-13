//! Pack driver (plan-multistream-pack.md §3, M1): fan-out N repos through
//! one uniform pass pipeline into a single deterministic archive.
//!
//! Flow: validate → export each repo to a spool file → (D3) shared ordinal
//! ident pre-scan → per repo: transform → spool output + checksum →
//! assemble the zip in manifest order → atomic rename. Pack never modifies
//! its sources (export is read-only) and never leaves a partial archive
//! behind (D7).

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use gfx::core::{BString, Event, ParseOptions, Parser};
use gfx::driver::{transform_stream, PassSpec, PassSummary};
use gfx::git::process as git;
use gfx_redact::{IdentMode, PseudonymStyle, RedactConfig, RedactReport};

use crate::manifest::{is_valid_slug, stream_entry, Manifest, RefTip, RepoEntry, MANIFEST_ENTRY};
use crate::zip::{Method, ZipWriter};
use crate::{PackError, Sha256};

/// One repo to pack: a slug (zip path / default dest name) and a source path.
#[derive(Clone, Debug)]
pub struct PackRepo {
    pub name: String,
    pub path: PathBuf,
}

/// Pack invocation.
#[derive(Clone, Debug)]
pub struct PackOptions {
    pub repos: Vec<PackRepo>,
    /// Validated pass sequence (content passes first, remap last — the
    /// CLI/registry path already enforces this via `PassDriver` rules).
    pub passes: Vec<PassSpec>,
    /// Explicitly-set flags, recorded in the manifest as the D2 audit record.
    pub flags_audit: BTreeMap<String, String>,
    /// Archive destination. Written atomically (tmp + rename).
    pub out: PathBuf,
    /// Run everything but write no archive.
    pub dry_run: bool,
    /// Record original source paths in `meta/source-hints.toml` (off by
    /// default — archives do not leak the pack host's layout).
    pub record_source_paths: bool,
    /// Whole-archive encryption (D5). When set, the archive is age-encrypted
    /// as it is written and the destination gets an `.age` suffix unless it
    /// already has one.
    pub encrypt: Option<crate::crypto::EncryptSpec>,
}

/// Per-repo outcome summary.
#[derive(Clone, Debug)]
pub struct RepoPackReport {
    pub name: String,
    pub commits: u64,
    pub rewritten: u64,
    pub input_bytes: usize,
    pub output_bytes: usize,
    pub identity: bool,
    pub sha256: String,
    pub passes: Vec<PassSummary>,
}

/// What a pack run did.
#[derive(Clone, Debug)]
pub struct PackReport {
    pub repos: Vec<RepoPackReport>,
    /// None on dry runs.
    pub archive: Option<PathBuf>,
    pub archive_bytes: u64,
}

impl PackReport {
    /// Deterministic, path-free report text (same discipline as
    /// `RunReport::to_text`).
    pub fn to_text(&self) -> String {
        let mut s = String::new();
        s.push_str("gfx pack report\n");
        s.push_str(&std::format!(
            "mode: {}\n",
            if self.archive.is_some() { "pack" } else { "dry-run" }
        ));
        s.push_str(&std::format!("repos: {}\n", self.repos.len()));
        s.push_str(&std::format!("archive-bytes: {}\n", self.archive_bytes));
        for r in &self.repos {
            s.push_str(&std::format!(
                "repo {}: commits={} rewritten={} identity={} stream-bytes={} sha256={}\n",
                r.name, r.commits, r.rewritten, r.identity, r.output_bytes, r.sha256
            ));
            s.push_str("  passes:\n");
            for p in &r.passes {
                s.push_str(&std::format!("    - {}: {}\n", p.name, p.detail));
            }
        }
        s
    }
}

/// Temp spool directory, removed on drop (best-effort).
struct SpoolDir(PathBuf);

impl SpoolDir {
    fn new(tag: &str) -> Result<Self, PackError> {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(std::format!("gfx-pack-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)?;
        Ok(SpoolDir(dir))
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for SpoolDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn usage(msg: impl Into<String>) -> PackError {
    PackError::Usage(msg.into())
}

/// Write `data` to `path`, streaming through a SHA-256 hasher; returns the
/// hex digest.
fn spool_write(data: &[u8], path: &Path) -> Result<String, PackError> {
    let mut f = std::fs::File::create(path)?;
    let mut h = Sha256::new();
    let mut rest = data;
    while !rest.is_empty() {
        let n = f.write(rest)?;
        h.update(&rest[..n]);
        rest = &rest[n..];
    }
    f.flush()?;
    Ok(h.finish_hex())
}

/// Validate the repo list: non-empty, unique + valid slugs, real git repos.
fn validate_repos(repos: &[PackRepo]) -> Result<(), PackError> {
    if repos.is_empty() {
        return Err(usage("at least one --repo is required"));
    }
    let mut seen = BTreeSet::new();
    for r in repos {
        if !is_valid_slug(&r.name) {
            return Err(usage(std::format!(
                "invalid repo name {:?} (want [A-Za-z0-9._-]+, not \".\" or \"..\")",
                r.name
            )));
        }
        if !seen.insert(r.name.clone()) {
            return Err(usage(std::format!("duplicate repo name {:?}", r.name)));
        }
        git::git_dir(&r.path)
            .map_err(|_| usage(std::format!("not a git repository: {}", r.path.display())))?;
    }
    Ok(())
}

/// D3: when the redact pass uses ordinal pseudonyms, pre-scan every export
/// (in repo order) and replace the mode with an exact Table whose ordinals
/// are assigned archive-wide — the same source ident becomes the same
/// pseudonym in every stream, deterministically and parallel-safe.
///
/// All other modes need no sharing: `Hash` pseudonyms are digest-derived,
/// tables are already shared config, and time modes are pure functions of
/// the (uniform) config.
fn resolve_shared_idents(
    export_spools: &[PathBuf],
    passes: &[PassSpec],
) -> Result<(Vec<PassSpec>, bool), PackError> {
    let needs = passes.iter().any(|p| {
        matches!(
            p,
            PassSpec::Redact(RedactConfig {
                ident_mode: IdentMode::Pseudonymize(PseudonymStyle::Ordinal),
                ..
            })
        )
    });
    if !needs {
        return Ok((passes.to_vec(), false));
    }

    // First-seen (name, email) order across all streams, author before
    // committer before tagger — mirroring `Redact::apply` exactly so the
    // table is indistinguishable from one shared pseudonymizer instance.
    let mut seen: BTreeSet<(BString, BString)> = BTreeSet::new();
    let mut order: Vec<(BString, BString)> = Vec::new();
    let mut note = |name: &BString, email: &BString| {
        let key = (name.clone(), email.clone());
        if seen.insert(key.clone()) {
            order.push(key);
        }
    };
    for spool in export_spools {
        let bytes = std::fs::read(spool)?;
        let mut parser = Parser::new(ParseOptions::default());
        parser.feed(&bytes);
        while let Some(ev) = parser.next_event()? {
            match ev {
                Event::Commit(c) => {
                    if let Some(a) = &c.author {
                        note(&a.name, &a.email);
                    }
                    if let Some(cm) = &c.committer {
                        note(&cm.name, &cm.email);
                    }
                }
                Event::Tag(t) => {
                    if let Some(tg) = &t.tagger {
                        note(&tg.name, &tg.email);
                    }
                }
                _ => {}
            }
        }
    }

    let rows: Vec<gfx_redact::RedactRow> = order
        .iter()
        .enumerate()
        .map(|(i, (name, email))| {
            let (new_name, new_email) = gfx_redact::ordinal_pseudonym(i as u64 + 1);
            gfx_redact::RedactRow {
                name: Some(name.clone()),
                email: Some(email.clone()),
                new_name,
                new_email,
            }
        })
        .collect();
    let rewritten_passes = passes
        .iter()
        .map(|p| match p {
            PassSpec::Redact(cfg)
                if matches!(
                    cfg.ident_mode,
                    IdentMode::Pseudonymize(PseudonymStyle::Ordinal)
                ) =>
            {
                PassSpec::Redact(RedactConfig {
                    ident_mode: IdentMode::Table(rows.clone()),
                    ..cfg.clone()
                })
            }
            other => other.clone(),
        })
        .collect();
    Ok((rewritten_passes, true))
}

/// Serialize a pre-finalization commit map in the driver's artifact format:
/// `old_hex new_hex|-` per line.
fn commit_map_text(map: &gfx::gfx_remap::CommitMap) -> String {
    let mut s = String::new();
    for (old, new) in map.iter() {
        let new = new.map_or_else(|| "-".to_string(), |n| n.to_hex().to_string());
        s.push_str(&std::format!("{} {}\n", old.to_hex(), new));
    }
    s
}

/// Source-repo ref tips, resolved against remap's tracking (D8). Branch
/// tips never appear as OID-form resets in a full export, so tips come from
/// `for-each-ref` on the source; remap supplies the rewritten-ness and the
/// mark. Refs whose target is not a commit/tag in the stream (e.g. blob
/// refs) are skipped — there is nothing for unpack to assert.
fn ref_tips(
    repo: &Path,
    fmt: gfx::core::ObjectFormat,
    remap: &gfx::gfx_remap::Remap,
) -> Result<Vec<RefTip>, PackError> {
    let mut out = Vec::new();
    for (oid_hex, name) in git::refs(repo)? {
        let Some(oid) = gfx::core::Oid::from_hex(oid_hex.as_bytes(), fmt) else {
            continue;
        };
        let Some(mark) = remap.mark_for(&oid) else {
            continue;
        };
        let rewritten = remap.outcome(mark) == Some(gfx::gfx_remap::RemapOutcome::Rewritten);
        out.push(RefTip {
            name,
            old: oid_hex,
            mark: rewritten.then_some(mark),
        });
    }
    Ok(out)
}

/// The archive-side ref-map: `old_hex new|- refname`. New tips are unknown
/// until unpack's import finalizes them, so the new side is `-` whenever the
/// lineage was rewritten (and the old OID itself when it was not).
fn ref_map_text(tips: &[RefTip]) -> String {
    let mut s = String::new();
    for t in tips {
        let new = if t.mark.is_some() { "-" } else { t.old.as_str() };
        s.push_str(&std::format!("{} {} {}\n", t.old, new, t.name));
    }
    s
}

/// Merge per-repo redact reports into the archive-level `maps/_idents`
/// artifact (D3): entries keyed by original ident, roles unioned, uses
/// summed. A disagreement about a replacement is a bug in the shared policy
/// — fail closed.
fn merge_redact_reports(reports: &[(String, RedactReport)]) -> Option<RedactReport> {
    if reports.is_empty() {
        return None;
    }
    let mut entries: BTreeMap<(BString, BString), gfx_redact::RedactEntry> = BTreeMap::new();
    let mut collisions: BTreeMap<(BString, BString), BTreeSet<(BString, BString)>> =
        BTreeMap::new();
    let mut totals = gfx_redact::RedactTotals::default();
    let mut truncated = false;
    for (_, r) in reports {
        for e in &r.entries {
            let key = (e.old_name.clone(), e.old_email.clone());
            match entries.get_mut(&key) {
                None => {
                    entries.insert(key, e.clone());
                }
                Some(m) => {
                    for role in &e.roles {
                        if !m.roles.contains(role) {
                            m.roles.push(role);
                        }
                    }
                    m.roles.sort_unstable();
                    m.uses += e.uses;
                    m.changed |= e.changed;
                    m.suspicious |= e.suspicious;
                }
            }
        }
        for c in &r.collisions {
            collisions
                .entry((c.new_name.clone(), c.new_email.clone()))
                .or_default()
                .extend(c.originals.iter().cloned());
        }
        totals.idents_redacted += r.totals.idents_redacted;
        totals.ident_updates += r.totals.ident_updates;
        totals.collisions += r.totals.collisions;
        totals.suspicious += r.totals.suspicious;
        totals.times_altered += r.totals.times_altered;
        truncated |= r.truncated;
    }
    let collisions = collisions
        .into_iter()
        .map(|((new_name, new_email), originals)| gfx_redact::CollisionEntry {
            new_name,
            new_email,
            originals: originals.into_iter().collect(),
        })
        .collect();
    Some(RedactReport {
        totals,
        entries: entries.into_values().collect(),
        collisions,
        truncated,
    })
}

/// The pack-side ordering contract, mirroring `PassDriver::with_passes`:
/// content passes first, remap last; remap auto-appended when unnamed.
fn validate_passes(passes: &[PassSpec]) -> Result<Vec<PassSpec>, PackError> {
    let mut remap_seen = false;
    for (i, p) in passes.iter().enumerate() {
        if p.is_remap() {
            if remap_seen {
                return Err(usage("remap named more than once"));
            }
            if i + 1 != passes.len() {
                return Err(usage(
                    "remap must be the last pass (content passes must precede it)",
                ));
            }
            remap_seen = true;
        }
    }
    let mut out = passes.to_vec();
    if !remap_seen {
        out.push(PassSpec::Remap(gfx::gfx_remap::RemapConfig::default()));
    }
    Ok(out)
}

/// Run a pack. See module docs for the flow.
pub fn pack(opts: &PackOptions) -> Result<PackReport, PackError> {
    validate_repos(&opts.repos)?;
    let passes = validate_passes(&opts.passes)?;
    let spools = SpoolDir::new("run")?;

    // 1. Export each repo (read-only) to a spool; record object format.
    let mut exports: Vec<(&PackRepo, PathBuf, gfx::core::ObjectFormat)> = Vec::new();
    for r in &opts.repos {
        let fmt = git::object_format(&r.path)?;
        let bytes = git::export_stream(&r.path, &[])?;
        let spool = spools.join(&std::format!("export-{}.fi", r.name));
        std::fs::write(&spool, &bytes)?;
        exports.push((r, spool, fmt));
    }

    // 2. D3 shared ordinal idents.
    let spool_paths: Vec<PathBuf> = exports.iter().map(|(_, p, _)| p.clone()).collect();
    let (passes, shared_idents) = resolve_shared_idents(&spool_paths, &passes)?;

    // 3. Transform each repo; spool the output with its checksum.
    let mut entries: Vec<RepoEntry> = Vec::new();
    let mut reports: Vec<RepoPackReport> = Vec::new();
    let mut out_spools: Vec<PathBuf> = Vec::new();
    let mut commit_maps: Vec<String> = Vec::new();
    let mut ref_maps: Vec<String> = Vec::new();
    let mut redact_reports: Vec<(String, RedactReport)> = Vec::new();
    let mut redact_texts: Vec<Option<String>> = Vec::new();
    for (r, spool_in, fmt) in &exports {
        let input = std::fs::read(spool_in)?;
        let out = transform_stream(&input, &passes)?;
        let spool_out = spools.join(&std::format!("stream-{}.fi", r.name));
        let sha256 = spool_write(&out.output, &spool_out)?;

        let remap = out.remap.as_ref().expect("remap always composes last");
        let commit_map = out.commit_map.as_ref().expect("remap always composes last");
        let tips = ref_tips(&r.path, *fmt, remap)?;
        let cm_text = commit_map_text(commit_map);
        let rm_text = ref_map_text(&tips);

        let mut passes_summary = out.passes.clone();
        if shared_idents {
            for p in &mut passes_summary {
                if p.name == "redact" {
                    p.detail.push_str(" (archive-shared ordinals)");
                }
            }
        }
        entries.push(RepoEntry {
            name: r.name.clone(),
            stream: stream_entry(&r.name),
            object_format: *fmt,
            sha256: sha256.clone(),
            bytes: out.output.len() as u64,
            commits: out.commits_observed as u64,
            rewritten: out.commits_rewritten as u64,
            identity: out.identity,
            refs: tips,
        });
        reports.push(RepoPackReport {
            name: r.name.clone(),
            commits: out.commits_observed as u64,
            rewritten: out.commits_rewritten as u64,
            input_bytes: out.input_bytes,
            output_bytes: out.output.len(),
            identity: out.identity,
            sha256,
            passes: passes_summary.clone(),
        });
        if let Some(rr) = &out.redact_report {
            redact_reports.push((r.name.clone(), rr.clone()));
            redact_texts.push(Some(rr.to_text()));
        } else {
            redact_texts.push(None);
        }
        commit_maps.push(cm_text);
        ref_maps.push(rm_text);
        out_spools.push(spool_out);
    }

    // 4. Manifest.
    let manifest = Manifest {
        passes: passes.iter().map(|p| p.name().to_string()).collect(),
        flags: opts.flags_audit.clone(),
        repos: entries,
    };
    let manifest_text = manifest.to_text();

    if opts.dry_run {
        return Ok(PackReport {
            repos: reports,
            archive: None,
            archive_bytes: 0,
        });
    }

    // 5. Assemble the zip in manifest order, atomically (tmp + rename).
    //    With encryption (D5) the zip is written *through* the age stream —
    //    plaintext never touches disk — and the destination gains `.age`.
    let out_path = match &opts.encrypt {
        Some(_) if !opts.out.extension().is_some_and(|e| e == "age") => {
            let mut p = opts.out.clone().into_os_string();
            p.push(".age");
            PathBuf::from(p)
        }
        _ => opts.out.clone(),
    };
    let tmp_out = out_path.with_extension(std::format!(
        "partial-{}",
        std::process::id()
    ));
    let result = (|| -> Result<u64, PackError> {
        // The two arms differ only in the sink type; `finish_archive`
        // carries the shared entry-writing logic. The encrypted arm must
        // run age's own `finish` after the zip's — it writes the STREAM
        // trailer, without which the file is undecryptable.
        match &opts.encrypt {
            Some(spec) => {
                let file = std::fs::File::create(&tmp_out)?;
                let age = crate::crypto::encrypt_writer(file, spec)?;
                let mut zip = ZipWriter::new(age);
                finish_archive(&mut zip, &exports, &out_spools, &commit_maps, &ref_maps, &redact_reports, &redact_texts, &reports, &manifest_text, &opts)?;
                zip.finish()?.finish()?;
            }
            None => {
                let file = std::fs::File::create(&tmp_out)?;
                let mut zip = ZipWriter::new(file);
                finish_archive(&mut zip, &exports, &out_spools, &commit_maps, &ref_maps, &redact_reports, &redact_texts, &reports, &manifest_text, &opts)?;
                zip.finish()?;
            }
        }
        Ok(std::fs::metadata(&tmp_out)?.len())
    })();
    let archive_bytes = match result {
        Ok(n) => n,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp_out);
            return Err(e);
        }
    };
    std::fs::rename(&tmp_out, &out_path)?;

    Ok(PackReport {
        repos: reports,
        archive: Some(out_path),
        archive_bytes,
    })
}

/// Write every archive entry in manifest order. Generic over the sink so
/// the encryption path is a transparent wrapper (D5).
#[allow(clippy::too_many_arguments)]
fn finish_archive<W: Write>(
    zip: &mut ZipWriter<W>,
    exports: &[(&PackRepo, PathBuf, gfx::core::ObjectFormat)],
    out_spools: &[PathBuf],
    commit_maps: &[String],
    ref_maps: &[String],
    redact_reports: &[(String, RedactReport)],
    redact_texts: &[Option<String>],
    reports: &[RepoPackReport],
    manifest_text: &str,
    opts: &PackOptions,
) -> Result<(), PackError> {
    zip.write_entry_bytes(MANIFEST_ENTRY, Method::Deflate, manifest_text.as_bytes())?;
        for (i, (r, _, _)) in exports.iter().enumerate() {
            zip.write_entry(
                &stream_entry(&r.name),
                Method::Deflate,
                std::fs::File::open(&out_spools[i])?,
            )?;
            zip.write_entry_bytes(
                &std::format!("maps/{}/commit-map", r.name),
                Method::Deflate,
                commit_maps[i].as_bytes(),
            )?;
            zip.write_entry_bytes(
                &std::format!("maps/{}/ref-map", r.name),
                Method::Deflate,
                ref_maps[i].as_bytes(),
            )?;
            let report_text = repo_report_text(&reports[i]);
            zip.write_entry_bytes(
                &std::format!("reports/{}/report.txt", r.name),
                Method::Deflate,
                report_text.as_bytes(),
            )?;
            if let Some(text) = &redact_texts[i] {
                zip.write_entry_bytes(
                    &std::format!("maps/{}/redact-map.txt", r.name),
                    Method::Deflate,
                    text.as_bytes(),
                )?;
            }
        }
        if let Some(merged) = merge_redact_reports(&redact_reports) {
            zip.write_entry_bytes("maps/_idents", Method::Deflate, merged.to_text().as_bytes())?;
        }
        if opts.record_source_paths {
            let mut hints = String::from("[sources]\n");
            for (r, _, _) in exports {
                hints.push_str(&std::format!(
                    "{:?} = {:?}\n",
                    r.name,
                    r.path.display().to_string()
                ));
            }
            zip.write_entry_bytes("meta/source-hints.toml", Method::Deflate, hints.as_bytes())?;
        }
        Ok(())
}

/// Per-repo archived report text (mirrors `RunReport::to_text`).
fn repo_report_text(r: &RepoPackReport) -> String {
    let mut s = String::new();
    s.push_str("gfx pack report\n");
    s.push_str(&std::format!("repo: {}\n", r.name));
    s.push_str(&std::format!("input-bytes: {}\n", r.input_bytes));
    s.push_str(&std::format!("output-bytes: {}\n", r.output_bytes));
    s.push_str(&std::format!("identity: {}\n", r.identity));
    s.push_str(&std::format!("commits-observed: {}\n", r.commits));
    s.push_str(&std::format!("commits-rewritten: {}\n", r.rewritten));
    s.push_str("passes:\n");
    for p in &r.passes {
        s.push_str(&std::format!("  - {}: {}\n", p.name, p.detail));
    }
    s
}
