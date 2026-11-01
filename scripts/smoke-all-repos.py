#!/usr/bin/env python3
"""Run every gfx builtin against every Git repo below a directory.

The default root is the current user's home directory. Each repo/pass pair
runs independently in parallel: gfx exports to a gzipped stream in a private
temporary workspace, transforms it, imports it into a fresh bare repo, then
checks the imported repo with `git fsck --strict` and pass-specific checks.

The source repos are read-only. Successful task directories are removed as
they finish; the run workspace is deleted on full success. Failed task
artifacts and logs are retained and their path is printed for diagnosis.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from collections.abc import Sequence


@dataclass(frozen=True)
class PassCase:
    name: str
    flags: tuple[str, ...]


PASS_CASES = (
    # Select paths, not blob sizes: this exercises an actual path-removal
    # rewrite on any non-empty tree. The pass's default carrier protections
    # keep .gitignore/.gitattributes/.gitmodules intact.
    PassCase("strip-blobs", ("--strip-blobs.path-glob", "**/*")),
    PassCase(
        "redact",
        (
            "--redact.collapse",
            "--redact.time-mode",
            "zero",
        ),
    ),
    PassCase("blob-xform", ("--blob-xform.ensure-final-newline",)),
    PassCase("enforce-ignore", ("--enforce-ignore.stream-rules",)),
    PassCase("remap", ()),
)


class SmokeFailure(Exception):
    pass


def clean_env() -> dict[str, str]:
    env = os.environ.copy()
    # Do not let a caller's inherited repo-selection variables redirect the
    # source or destination. Never lazy-fetch promisor objects during a local
    # smoke; optional locks are unnecessary for these read-only source runs.
    for key in (
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_COMMON_DIR",
        "GIT_PREFIX",
    ):
        env.pop(key, None)
    env["GIT_NO_LAZY_FETCH"] = "1"
    env["GIT_OPTIONAL_LOCKS"] = "0"
    return env


def run(
    argv: Sequence[str],
    *,
    env: dict[str, str],
    timeout: int,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            list(argv),
            cwd=cwd,
            env=env,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise SmokeFailure(f"timed out after {timeout}s: {argv!r}") from exc
    if result.returncode:
        raise SmokeFailure(
            f"command exited {result.returncode}: {argv!r}\n"
            f"stdout:\n{result.stdout.decode(errors='replace')}\n"
            f"stderr:\n{result.stderr.decode(errors='replace')}"
        )
    return result


def git(
    repo: Path,
    args: Sequence[str],
    *,
    env: dict[str, str],
    timeout: int,
) -> bytes:
    return run(["git", "-C", str(repo), *args], env=env, timeout=timeout).stdout


def discover_repositories(root: Path, excluded: Path) -> tuple[list[Path], list[str]]:
    """Find worktrees, linked worktrees, and bare repos without walking .git internals."""
    repos: dict[str, Path] = {}
    errors: list[str] = []
    excluded_real = excluded.resolve()

    def onerror(exc: OSError) -> None:
        errors.append(f"cannot scan {exc.filename or root}: {exc}")

    for raw_dir, dirnames, filenames in os.walk(root, topdown=True, followlinks=False, onerror=onerror):
        here = Path(raw_dir)
        try:
            if here.resolve() == excluded_real or excluded_real in here.resolve().parents:
                dirnames[:] = []
                continue
        except OSError as exc:
            errors.append(f"cannot resolve {here}: {exc}")
            dirnames[:] = []
            continue

        # Never traverse repository metadata. Continue through worktrees so
        # nested repositories (including initialized submodules) are found.
        dirnames[:] = sorted(
            d for d in dirnames
            if d != ".git" and not (here / d).is_symlink()
        )

        git_marker = (here / ".git").exists()
        bare_marker = (
            "HEAD" in filenames
            and "config" in filenames
            and "objects" in dirnames
        )
        if not (git_marker or bare_marker):
            continue

        probe = subprocess.run(
            ["git", "-C", str(here), "rev-parse", "--absolute-git-dir"],
            env=clean_env(),
            capture_output=True,
            timeout=30,
            check=False,
        )
        if probe.returncode == 0:
            try:
                real = here.resolve()
                repos[str(real)] = real
            except OSError as exc:
                errors.append(f"cannot resolve repository {here}: {exc}")

    return sorted(repos.values(), key=lambda p: str(p).casefold()), errors


def repo_size_mib(repo: Path, env: dict[str, str], timeout: int) -> float:
    """Cheap object-store size estimate (packs + loose) in MiB.

    The gfx driver buffers whole streams in memory, so this gates which
    repos are safe to smoke under concurrency.
    """
    raw = git(repo, ["count-objects", "-v"], env=env, timeout=timeout)
    kib = 0
    for line in raw.decode(errors="replace").splitlines():
        key, _, value = line.partition(":")
        if key.strip() in ("size", "size-pack", "size-promisor"):
            with contextlib.suppress(ValueError):
                kib += int(value.strip())
    return kib / 1024.0


def source_snapshot(repo: Path, env: dict[str, str], timeout: int) -> tuple[bytes, str, int]:
    refs = git(
        repo,
        ["for-each-ref", "--format=%(refname) %(objectname)"],
        env=env,
        timeout=timeout,
    )
    object_format = git(repo, ["rev-parse", "--show-object-format"], env=env, timeout=timeout)
    count = git(repo, ["rev-list", "--all", "--count"], env=env, timeout=timeout)
    return refs, object_format.decode().strip(), int(count.strip() or b"0")


def verify_redacted(repo: Path, env: dict[str, str], timeout: int) -> None:
    raw = git(
        repo,
        ["log", "--all", "--format=%x00%an%x00%ae%x00%cn%x00%ce%x00%at%x00%ct"],
        env=env,
        timeout=timeout,
    )
    fields = raw.split(b"\0")
    if fields and fields[0] == b"":
        fields.pop(0)
    if len(fields) % 6:
        raise SmokeFailure(f"redact verification: malformed git log fields ({len(fields)})")
    for i in range(0, len(fields), 6):
        name, email, committer, committer_email, author_time, commit_time = fields[i : i + 6]
        commit_time = commit_time.rstrip(b"\n")
        expected = b"Anonymous", b"anonymous@example.invalid"
        if (name, email) != expected or (committer, committer_email) != expected:
            raise SmokeFailure(
                "redact verification: ident did not collapse: "
                f"{[v.decode(errors='replace') for v in fields[i:i + 4]]!r}"
            )
        if author_time != b"0" or commit_time != b"0":
            raise SmokeFailure(
                f"redact verification: timestamps not zero: {author_time!r}, {commit_time!r}"
            )

    # Verify annotated-tag taggers too; lightweight tags have no tagger.
    refs = git(repo, ["for-each-ref", "--format=%(objecttype) %(objectname)", "refs/tags"], env=env, timeout=timeout)
    for line in refs.splitlines():
        kind, oid = line.split(b" ", 1)
        if kind != b"tag":
            continue
        tag = git(repo, ["cat-file", "tag", oid.decode()], env=env, timeout=timeout)
        if b"tagger Anonymous <anonymous@example.invalid> 0 +0000\n" not in tag:
            raise SmokeFailure(f"redact verification: annotated tagger not collapsed for {oid.decode()}")


def check_pass_artifacts(case: PassCase, stream: Path, output: str) -> None:
    if f"- {case.name}:" not in output:
        raise SmokeFailure(f"gfx report did not include pass {case.name!r}")
    artifacts = Path(f"{stream}.gfx")
    required = {
        "strip-blobs": "strip-report.txt",
        "redact": "redact-map.txt",
        "enforce-ignore": "ignore-report.txt",
    }.get(case.name)
    if required and not (artifacts / required).is_file():
        raise SmokeFailure(f"missing {case.name} artifact: {artifacts / required}")
    if not (artifacts / "commit-marks").is_file():
        raise SmokeFailure(f"missing stream-sink commit-marks artifact: {artifacts / 'commit-marks'}")


def smoke_one(
    *,
    gfx: Path,
    root_tmp: Path,
    repo_index: int,
    repo: Path,
    case: PassCase,
    source_refs: bytes,
    object_format: str,
    source_commits: int,
    timeout: int,
    env: dict[str, str],
) -> str:
    task_dir = root_tmp / f"repo-{repo_index:05d}" / case.name
    task_dir.mkdir(parents=True, exist_ok=False)
    stream = task_dir / "transformed.feat.gz"
    dest = task_dir / "imported.git"
    log_path = task_dir / "smoke.log"
    transcript: list[str] = []

    def checked(argv: Sequence[str]) -> subprocess.CompletedProcess[bytes]:
        transcript.append("$ " + " ".join(argv))
        result = run(argv, env=env, timeout=timeout)
        if result.stdout:
            transcript.append(result.stdout.decode(errors="replace").rstrip())
        if result.stderr:
            transcript.append(result.stderr.decode(errors="replace").rstrip())
        return result

    try:
        transform_cmd = [
            str(gfx),
            "--repo", str(repo),
            "--out", str(stream),
            "--passes", case.name,
            *case.flags,
        ]
        transformed = checked(transform_cmd)
        transform_report = transformed.stdout.decode(errors="replace")
        check_pass_artifacts(case, stream, transform_report)

        checked([
            "git", "init", "-q", "--bare",
            f"--object-format={object_format}",
            str(dest),
        ])
        imported = checked([
            str(gfx),
            "--in", str(stream),
            "--repo", str(dest),
            "--passes", "remap",
        ])
        import_report = imported.stdout.decode(errors="replace")
        if "artifacts:" not in import_report:
            raise SmokeFailure("file→repo import did not report its artifact directory")

        checked(["git", "-C", str(dest), "fsck", "--strict"])
        imported_count_raw = git(dest, ["rev-list", "--all", "--count"], env=env, timeout=timeout)
        imported_count = int(imported_count_raw.strip() or b"0")
        if imported_count != source_commits:
            raise SmokeFailure(
                f"commit count changed across {case.name}: source={source_commits}, imported={imported_count}"
            )
        # Ensure refs remain usable (empty repositories are valid smoke inputs).
        checked(["git", "-C", str(dest), "for-each-ref", "--format=%(refname) %(objectname)"])

        if case.name == "redact":
            verify_redacted(dest, env, timeout)

        # Verify gfx's read-only repo→file source contract for every pass.
        after_refs = git(repo, ["for-each-ref", "--format=%(refname) %(objectname)"], env=env, timeout=timeout)
        if after_refs != source_refs:
            raise SmokeFailure("source repository refs changed during repo→file smoke")

        log_path.write_text("\n\n".join(transcript) + "\n", encoding="utf-8")
        shutil.rmtree(task_dir)
        return f"PASS {case.name:14} {repo}"
    except Exception as exc:
        transcript.append(f"FAIL: {type(exc).__name__}: {exc}")
        with contextlib.suppress(OSError):
            log_path.write_text("\n\n".join(transcript) + "\n", encoding="utf-8")
        raise SmokeFailure(f"{repo} [{case.name}]: {exc}; artifacts retained at {task_dir}") from exc


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.home(),
        help="directory recursively scanned for Git repos (default: home directory)",
    )
    parser.add_argument(
        "--gfx",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "target" / "release" / "gfx",
        help="gfx executable (default: this checkout's target/release/gfx)",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=min(4, max(1, os.cpu_count() or 1)),
        help="maximum repositories tested in parallel (passes run sequentially per repo; default: min(4, CPU count))",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=1800,
        help="per-command timeout (default: 1800 seconds)",
    )
    parser.add_argument(
        "--max-repo-mib",
        type=float,
        default=1024.0,
        help="skip repos whose object store exceeds this size in MiB "
        "(gfx buffers whole streams in RAM; default: 1024)",
    )
    parser.add_argument(
        "--allow-incomplete-scan",
        action="store_true",
        help="continue if some directories cannot be read (those paths may contain untested repos)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.root.expanduser().resolve()
    gfx = args.gfx.expanduser().resolve()
    if not root.is_dir():
        print(f"error: root is not a directory: {root}", file=sys.stderr)
        return 2
    try:
        gfx_ok = gfx.is_file() and os.access(gfx, os.X_OK)
    except OSError:
        gfx_ok = False
    if not gfx_ok:
        print(f"error: gfx executable not found or not executable: {gfx}", file=sys.stderr)
        print("build it with: cargo build --release --bin gfx", file=sys.stderr)
        return 2
    if args.jobs < 1 or args.timeout_seconds < 1:
        print("error: --jobs and --timeout-seconds must be positive", file=sys.stderr)
        return 2

    # Place the workspace under the system temp root, not the scanned tree.
    run_root = Path(tempfile.mkdtemp(prefix="gfx-smoke-all-repos-"))
    repos, scan_errors = discover_repositories(root, run_root)
    if scan_errors:
        level = "warning" if args.allow_incomplete_scan else "error"
        print(
            f"{level}: repository scan was incomplete ({len(scan_errors)} unreadable path(s)):",
            file=sys.stderr,
        )
        for error in scan_errors[:12]:
            print(f"  {error}", file=sys.stderr)
        if len(scan_errors) > 12:
            print(f"  ... {len(scan_errors) - 12} more", file=sys.stderr)
        if not args.allow_incomplete_scan:
            print("rerun with --allow-incomplete-scan to test only readable paths", file=sys.stderr)
            print(f"workspace retained at: {run_root}", file=sys.stderr)
            return 1
        print("continuing; repositories in unreadable directories will not be tested", file=sys.stderr)
    if not repos:
        with contextlib.suppress(OSError):
            shutil.rmtree(run_root)
        print(f"no Git repositories found under {root}", file=sys.stderr)
        return 1

    env = clean_env()
    print(f"root: {root}")
    print(f"gfx: {gfx}")
    print(f"repositories: {len(repos)}; passes: {len(PASS_CASES)}; jobs: {args.jobs}")
    print(f"temporary workspace: {run_root}")

    skipped: list[tuple[Path, float]] = []
    if args.max_repo_mib > 0:
        kept: list[Path] = []
        for repo in repos:
            try:
                size = repo_size_mib(repo, env, args.timeout_seconds)
            except Exception as exc:
                print(f"error: cannot size {repo}: {exc}", file=sys.stderr)
                shutil.rmtree(run_root, ignore_errors=True)
                return 1
            if size > args.max_repo_mib:
                skipped.append((repo, size))
            else:
                kept.append(repo)
        if skipped:
            print(f"skipping {len(skipped)} oversize repos (>{args.max_repo_mib:.0f} MiB object store):")
            for repo, size in skipped:
                print(f"  {size:9.1f} MiB  {repo}")
        repos = kept

    baselines: list[tuple[bytes, str, int]] = []
    try:
        for repo in repos:
            baselines.append(source_snapshot(repo, env, args.timeout_seconds))
    except Exception as exc:
        print(f"error: cannot snapshot source repos: {exc}", file=sys.stderr)
        shutil.rmtree(run_root, ignore_errors=True)
        return 1

    def smoke_repo(repo_index: int) -> tuple[list[str], list[str]]:
        repo = repos[repo_index]
        refs, object_format, commit_count = baselines[repo_index]
        successes: list[str] = []
        errors: list[str] = []
        # Serialize passes for a single source repo to bound peak disk use;
        # different repositories are still tested concurrently.
        for case in PASS_CASES:
            try:
                successes.append(
                    smoke_one(
                        gfx=gfx,
                        root_tmp=run_root,
                        repo_index=repo_index,
                        repo=repo,
                        case=case,
                        source_refs=refs,
                        object_format=object_format,
                        source_commits=commit_count,
                        timeout=args.timeout_seconds,
                        env=env,
                    )
                )
            except Exception as exc:
                errors.append(str(exc))
                print(f"FAIL {case.name:14} {repo}: {exc}", file=sys.stderr, flush=True)
        return successes, errors

    started = time.monotonic()
    failures: list[str] = []
    completed = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = {pool.submit(smoke_repo, i): repos[i] for i in range(len(repos))}
        for future in concurrent.futures.as_completed(futures):
            repo = futures[future]
            try:
                successes, errors = future.result()
                for message in successes:
                    print(message, flush=True)
                failures.extend(errors)
            except Exception as exc:
                failures.append(f"{repo}: {exc}")
                print(f"FAIL repo {repo}: {exc}", file=sys.stderr, flush=True)
            completed += 1
            print(f"progress: {completed}/{len(repos)} repositories", flush=True)

    elapsed = time.monotonic() - started
    total_jobs = len(repos) * len(PASS_CASES)
    if failures:
        print(f"FAILED: {len(failures)} failure(s) across {total_jobs} repo/pass jobs in {elapsed:.1f}s", file=sys.stderr)
        print(f"temporary workspace retained at: {run_root}", file=sys.stderr)
        return 1

    try:
        shutil.rmtree(run_root)
    except OSError as exc:
        print(f"warning: could not remove workspace {run_root}: {exc}", file=sys.stderr)
    note = ""
    if scan_errors or skipped:
        bits = []
        if scan_errors:
            bits.append(f"{len(scan_errors)} unreadable paths")
        if skipped:
            bits.append(f"{len(skipped)} oversize repos skipped")
        note = f" (partial: {', '.join(bits)})"
    print(f"SUCCESS{note}: {total_jobs} repo/pass jobs in {elapsed:.1f}s; removed {run_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
