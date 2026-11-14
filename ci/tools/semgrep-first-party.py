#!/usr/bin/env python3
"""Semgrep every tracked first-party code/workflow input with full accounting."""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
from datetime import UTC, datetime

ROOT = pathlib.Path(__file__).resolve().parents[2]
CONFIG = ROOT / "ci/semgrep/first-party.yml"
SUFFIXES = {".c", ".h", ".py", ".sh", ".t", ".json", ".yml", ".yaml"}
EXACT = {".githooks/pre-commit", "config"}
C_AST_TARGETS = [
    "src/ngx_http_shield_ban.c",
    "src/ngx_http_shield_cve.h",
    "src/ngx_http_shield_gzip.h",
    "src/ngx_http_shield_negotiate.h",
    "src/ngx_shield_probe_hooks.c",
    "src/ngx_shield_probe_hooks.h",
]
C_GENERIC_ONLY = [
    "src/ngx_http_shield_ban.h",
    "src/ngx_http_shield_module.c",
    "src/ngx_http_shield_patterns.h",
    "src/ngx_http_shield_scan.c",
    "src/ngx_http_shield_scan.h",
    "src/ngx_http_shield_status.h",
]


def validate_c_partition(tracked: list[str]) -> None:
    # Every tracked first-party C/header path must be in exactly one parser
    # class; additions and renames fail closed with the affected path names.
    classified = set(C_AST_TARGETS + C_GENERIC_ONLY)
    tracked_set = set(tracked)
    if tracked_set != classified:
        unclassified = sorted(tracked_set - classified)
        stale = sorted(classified - tracked_set)
        raise ValueError(
            "C AST/fallback accounting does not match tracked src/*.[ch]; "
            f"unclassified={unclassified}, stale={stale}"
        )


def git(*args: str) -> bytes:
    return subprocess.check_output(["git", *args], cwd=ROOT)


def targets() -> tuple[list[str], list[str]]:
    gitlinks = set()
    executable = set()
    for raw in git("ls-files", "--stage", "-z").split(b"\0"):
        if not raw:
            continue
        metadata, path = raw.decode().split("\t", 1)
        mode = metadata.split(" ", 1)[0]
        if mode == "160000":
            gitlinks.add(path)
        elif mode == "100755":
            executable.add(path)
    result = []
    for raw in git("ls-files", "-z").split(b"\0"):
        if not raw:
            continue
        path = raw.decode()
        if any(path == link or path.startswith(link + "/") for link in gitlinks):
            continue
        if (
            pathlib.PurePosixPath(path).suffix in SUFFIXES
            or path in EXACT
            or path in executable
        ):
            result.append(path)
    if not result:
        raise ValueError("no first-party Semgrep targets found")
    return sorted(result), sorted(gitlinks)


def run_semgrep(
    name: str,
    configs: list[str],
    paths: list[str],
    *,
    strict: bool = False,
    allow_partial_parsing: bool = False,
) -> dict[str, object]:
    command = [
        "semgrep",
        "scan",
        "--json",
        "--error",
        "--metrics=off",
        "--jobs=1",
        "--scan-unknown-extensions",
    ]
    if strict:
        command.append("--strict")
    for config in configs:
        command.extend(["--config", config])
    command.extend(paths)
    completed = subprocess.run(
        command, cwd=ROOT, text=True, capture_output=True, check=False
    )
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"{name}: Semgrep did not return JSON: {completed.stderr.strip()}"
        ) from exc
    errors = result.get("errors")
    findings = result.get("results")
    scanned = (
        result.get("paths", {}).get("scanned")
        if isinstance(result.get("paths"), dict)
        else None
    )
    if (
        not isinstance(errors, list)
        or not isinstance(findings, list)
        or not isinstance(scanned, list)
    ):
        raise TypeError(f"{name}: incomplete Semgrep result")
    if errors and not allow_partial_parsing:
        raise ValueError(f"{name}: Semgrep reported {len(errors)} parse/engine errors")
    if errors and any(
        not (
            error.get("type") == "PartialParsing"
            or (
                isinstance(error.get("type"), list)
                and error["type"]
                and error["type"][0] == "PartialParsing"
            )
        )
        for error in errors
        if isinstance(error, dict)
    ):
        raise ValueError(f"{name}: non-parsing Semgrep error in fallback scan")
    if errors and any(not isinstance(error, dict) for error in errors):
        raise TypeError(f"{name}: malformed Semgrep error row")
    if completed.returncode not in ({0, 1} if findings else {0}):
        raise ValueError(
            f"{name}: Semgrep exited {completed.returncode}: {completed.stderr.strip()}"
        )
    scanned_set = set(scanned)
    requested_set = set(paths)
    if scanned_set != requested_set:
        missing = sorted(requested_set - scanned_set)
        extra = sorted(scanned_set - requested_set)
        raise ValueError(
            f"{name}: input accounting mismatch; missing={missing}, extra={extra}"
        )
    finding_summaries = []
    for finding in findings:
        if not isinstance(finding, dict):
            raise TypeError(f"{name}: malformed Semgrep finding row")
        finding_summaries.append(
            {
                "check_id": finding.get("check_id"),
                "path": finding.get("path"),
                "line": finding.get("start", {}).get("line"),
                "message": finding.get("extra", {}).get("message"),
            }
        )
    error_summaries = [
        {
            "type": error.get("type"),
            "path": error.get("path"),
            "message": error.get("message"),
        }
        for error in errors
    ]
    return {
        "name": name,
        "target_count": len(scanned),
        "targets": sorted(scanned),
        "finding_count": len(finding_summaries),
        "findings": finding_summaries,
        "parse_error_count": len(error_summaries),
        "parse_errors": error_summaries,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    try:
        all_targets, gitlinks = targets()
        generic = run_semgrep(
            "generic-complete", [str(CONFIG.relative_to(ROOT))], all_targets
        )
        python_targets = [path for path in all_targets if path.endswith(".py")]
        python = run_semgrep("python-security", ["p/python"], python_targets)
        c_tracked = sorted(
            path
            for path in all_targets
            if path.startswith("src/")
            and pathlib.PurePosixPath(path).suffix in {".c", ".h"}
        )
        validate_c_partition(c_tracked)
        c_ast = run_semgrep(
            "c-security-ast",
            ["p/c", "p/security-audit"],
            C_AST_TARGETS,
            strict=True,
        )
        c_partial = run_semgrep(
            "c-security-parser-limited",
            ["p/c", "p/security-audit"],
            C_GENERIC_ONLY,
            allow_partial_parsing=True,
        )
        receipt = {
            "schema_version": 1,
            "generated_at": datetime.now(UTC).isoformat(),
            "gitlinks_excluded": gitlinks,
            "first_party_target_count": len(all_targets),
            "scans": [generic, python, c_ast, c_partial],
            "c_generic_only": C_GENERIC_ONLY,
            "c_generic_only_reason": "The pinned Semgrep parser cannot fully parse nginx macro/type shapes in these files. Their parseable regions retain the C registry rules, while the complete generic scan, flawfinder, cppcheck, clang-tidy, GCC -fanalyzer, and CodeQL cover the full files.",
        }
        rendered = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            print(rendered, end="")
        finding_count = sum(scan["finding_count"] for scan in receipt["scans"])
        if finding_count:
            for scan in receipt["scans"]:
                for finding in scan["findings"]:
                    print(
                        f"{scan['name']}: {finding['check_id']} "
                        f"{finding['path']}:{finding['line']}: {finding['message']}",
                        file=sys.stderr,
                    )
            return 1
        return 0
    except (OSError, subprocess.CalledProcessError, TypeError, ValueError) as exc:
        print(f"first-party Semgrep unavailable: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
