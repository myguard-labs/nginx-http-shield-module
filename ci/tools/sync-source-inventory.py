#!/usr/bin/env python3
"""Synchronize source-package inventory rows from the central version pins."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path

HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")

SOURCES = {
    "nginx-mainline": ("NGINX_VERSION", "NGINX_VERSION_SHA256", "release-"),
    "nginx-stable": ("NGINX_STABLE", "NGINX_STABLE_SHA256", "release-"),
    "angie": ("ANGIE_VERSION", "ANGIE_VERSION_SHA256", "Angie-"),
}


def update_pin_check(
    data: dict[str, object], key: str, value: str, source_path: str
) -> None:
    checks = data.get("pin_checks")
    if not isinstance(checks, list):
        raise SystemExit("dependency inventory has no pin_checks")
    probe = f"{key}={value}\n"
    matches: list[dict[str, object]] = []
    for check in checks:
        if not isinstance(check, dict) or check.get("path") != source_path:
            continue
        pattern = check.get("pattern")
        if not isinstance(pattern, str):
            continue
        try:
            captured = re.findall(pattern, probe)
        except re.error as exc:
            raise SystemExit(
                f"invalid pin-check pattern for {source_path}: {exc}"
            ) from exc
        if captured == [value]:
            matches.append(check)
    if len(matches) != 1:
        raise SystemExit(f"pin-check owner missing or ambiguous: {source_path}:{key}")
    matches[0]["expected"] = value


def read_versions(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator:
            raise SystemExit(f"malformed version pin: {raw}")
        values[key] = value
    return values


def resolve_tag(upstream: str, ref: str) -> str:
    result = subprocess.run(
        ["git", "ls-remote", f"{upstream}.git", ref, f"{ref}^{{}}"],
        check=True,
        capture_output=True,
        text=True,
    )
    refs = {}
    for line in result.stdout.splitlines():
        sha, separator, name = line.partition("\t")
        if separator and HEX40.fullmatch(sha):
            refs[name] = sha
    resolved = refs.get(f"{ref}^{{}}", refs.get(ref, ""))
    if not HEX40.fullmatch(resolved):
        raise SystemExit(f"could not resolve {upstream} {ref} to a commit")
    return resolved


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--versions", type=Path, default=Path(".github/versions.env"))
    parser.add_argument(
        "--inventory", type=Path, default=Path("ci/dependency-inventory.json")
    )
    args = parser.parse_args()

    versions = read_versions(args.versions)
    data = json.loads(args.inventory.read_text(encoding="utf-8"))
    dependencies = data.get("dependencies", [])

    for dependency_id, (version_key, digest_key, tag_prefix) in SOURCES.items():
        matches = [item for item in dependencies if item.get("id") == dependency_id]
        if len(matches) != 1:
            raise SystemExit(
                f"source inventory entry missing or ambiguous: {dependency_id}"
            )
        version = versions.get(version_key, "")
        digest = versions.get(digest_key, "")
        if not version or not HEX64.fullmatch(digest):
            raise SystemExit(f"missing or malformed pins for {dependency_id}")
        dependency = matches[0]
        upstream = dependency.get("upstream", "")
        if not upstream.startswith("https://github.com/"):
            raise SystemExit(f"unsupported source upstream for {dependency_id}")
        ref = f"refs/tags/{tag_prefix}{version}"
        commit = resolve_tag(upstream, ref)
        dependency.update(
            version=version,
            archive_sha256=digest,
            upstream_ref=ref,
            resolved_commit=commit,
        )
        dependency["osv_query"] = {"commit": commit}
        update_pin_check(data, version_key, version, ".github/versions.env")
        update_pin_check(data, digest_key, digest, ".github/versions.env")

    args.inventory.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
