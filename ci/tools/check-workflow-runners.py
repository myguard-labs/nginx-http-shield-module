#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Check every job reachable from a pull request uses a hosted runner."""

import pathlib
import sys

import yaml

root = pathlib.Path(__file__).resolve().parents[2]
workflow_dir = root / ".github" / "workflows"
paths = sorted([*workflow_dir.glob("*.yml"), *workflow_dir.glob("*.yaml")])
try:
    if not paths:
        raise ValueError("no workflows found")
    docs = {p.name: yaml.safe_load(p.read_text()) for p in paths}
    if any(not isinstance(d, dict) for d in docs.values()):
        raise ValueError("workflow must be a mapping")

    def triggers(doc):
        value = doc.get("on", doc.get(True, {}))
        return {value} if isinstance(value, str) else set(value or [])

    pending = [
        n
        for n, d in docs.items()
        if triggers(d) & {"pull_request", "pull_request_target"}
    ]
    if not pending:
        raise ValueError("no pull request entry point")
    visited = set()
    while pending:
        name = pending.pop()
        if name in visited:
            continue
        visited.add(name)
        jobs = docs[name].get("jobs")
        if not isinstance(jobs, dict) or not jobs:
            raise ValueError(f"{name}: missing jobs")
        for job, node in jobs.items():
            if not isinstance(node, dict):
                raise TypeError(f"{name}:{job}: invalid job")
            if "uses" in node:
                uses = node["uses"]
                prefixes = ("./.github/workflows/", "$/.github/workflows/")
                if not isinstance(uses, str) or not uses.startswith(prefixes):
                    raise ValueError(
                        f"{name}:{job}: cannot verify reusable workflow {uses!r}"
                    )
                target = uses.split("/")[-1]
                if target not in docs:
                    raise ValueError(
                        f"{name}:{job}: missing reusable workflow {target}"
                    )
                pending.append(target)
                continue
            runner = node.get("runs-on")
            if runner not in ("ubuntu-latest", "windows-latest", "macos-latest"):
                raise ValueError(
                    f"{name}:{job}: runner is not an approved hosted runner: {runner!r}"
                )
    print(f"OK: {len(visited)} PR-reachable workflows use hosted runners.")
except (ValueError, TypeError, OSError, yaml.YAMLError) as exc:
    print(f"ERROR: {exc}", file=sys.stderr)
    sys.exit(1)
