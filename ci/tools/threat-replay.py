#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Compare real offline scanners; labels come from content/sink contracts."""

import argparse
import hashlib
import json
import shlex
import sqlite3
import subprocess
import tempfile
from collections import Counter
from contextlib import closing
from pathlib import Path
from urllib.parse import parse_qs

ROOT = Path(__file__).resolve().parents[2]
BASE = "189bd9e5f8af78f86cfaa6ae456159d239a1c653"
SCAN_INPUTS = (
    "src/ngx_http_shield_scan.c",
    "src/ngx_http_shield_scan.h",
    "src/ngx_http_shield_patterns.h",
)
FORM = "application/x-www-form-urlencoded"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sql_semantics(body):
    """Only this dummy sink: public query vs parameterized query, no I/O."""
    fields = parse_qs(body, strict_parsing=True)
    if set(fields) != {"id"} or len(fields["id"]) != 1:
        raise ValueError("SQLite fixture requires exactly one id")
    value = fields["id"][0]
    with closing(sqlite3.connect(":memory:")) as db:
        db.executescript(
            "CREATE TABLE public_data(id INTEGER, value TEXT);"
            "INSERT INTO public_data VALUES(1, 'public-dummy');"
            "CREATE TABLE private_data(value TEXT);"
            "INSERT INTO private_data VALUES('private-dummy');"
        )
        # Deliberately vulnerable test oracle, restricted to this in-memory DB.
        # The parameterized twin below must not return the private dummy.
        # This exact-rule exception permits testing the vulnerability itself.
        try:
            # nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query
            vulnerable = db.execute(
                "SELECT value FROM public_data WHERE id = " + value
            ).fetchall()
        except sqlite3.Error as exc:
            raise ValueError("invalid toy query; no presumed attack label") from exc
        fixed = db.execute(
            "SELECT value FROM public_data WHERE id = ?", (value,)
        ).fetchall()
    if ("private-dummy",) in vulnerable and ("private-dummy",) not in fixed:
        label = "attack"
    elif vulnerable == fixed == [("public-dummy",)]:
        label = "benign"
    else:
        label = "unclassified"
    return label, {"vulnerable": vulnerable, "parameterized": fixed}


def label_for(case, fixture):
    oracle = case["oracle"]
    if oracle == "authored-content":
        if fixture["source_role"] != "benign_authored_content":
            raise ValueError("authored-content provenance mismatch")
        return "benign", {"contract": "store authored bytes without evaluation"}
    if oracle == "scanner-only":
        if fixture["source_role"] != "positive_attack_control":
            raise ValueError("scanner-only provenance mismatch")
        return "unclassified", {"contract": "sink unknown; scanner hit is no oracle"}
    if oracle == "sqlite-query":
        if fixture["source_role"] != "controlled-sqlite-pair":
            raise ValueError("SQLite provenance mismatch")
        return sql_semantics(fixture["body"])
    raise ValueError("unknown semantic oracle")


def load_corpus(root=ROOT):
    corpus = json.loads((root / "ci/replay/corpus.json").read_text())
    if corpus["version"] != 1 or corpus["baseline"] != BASE:
        raise ValueError("unsupported corpus version or baseline")
    if corpus["fixtures"] != "ci/replay/bodies.json":
        raise ValueError("unexpected fixture path")
    fixtures = json.loads((root / corpus["fixtures"]).read_text())
    cases = corpus["cases"]
    if not cases or len(cases) > 256:
        raise ValueError("empty or oversized corpus")
    seen, groups, used = set(), {}, set()
    for case in cases:
        if case["id"] in seen:
            raise ValueError("duplicate case id")
        seen.add(case["id"])
        fixture = fixtures.get(case["fixture"])
        if not fixture:
            raise ValueError("missing fixture: " + case["id"])
        used.add(case["fixture"])
        if not isinstance(fixture["body"], str) or len(fixture["body"].encode()) > 4096:
            raise ValueError("invalid or oversized body")
        if fixture["content_type"] not in (FORM, "text/plain"):
            raise ValueError("unsupported content type")
        split = case["split"]
        if split not in ("development", "heldout"):
            raise ValueError("unknown split")
        group = case["source_group"]
        if not group or groups.setdefault(group, split) != split:
            raise ValueError("source-group leakage")
        expected, _ = label_for(case, fixture)
        if case["label"] != expected:
            raise ValueError("false semantic label: " + case["id"])
    historical = [c for c in cases if c["source_group"] == "body-authored-20261115"]
    if len(historical) != corpus["source"]["case_count"] or len(historical) != 36:
        raise ValueError("historical corpus omission")
    if used != set(fixtures):
        raise ValueError("unmapped fixtures")
    if set(groups.values()) != {"development", "heldout"}:
        raise ValueError("both splits required")
    return corpus, fixtures


def run(command, **kwargs):
    return subprocess.run(command, check=True, capture_output=True, **kwargs).stdout


def build_scanner(root, nginx, output, baseline=False, causal=False):
    """Compile both revisions independently against the same real nginx core."""
    output.mkdir()
    identities = {}
    for relative in SCAN_INPUTS:
        data = (
            run(["git", "-C", str(root), "show", BASE + ":" + relative])
            if baseline
            else (root / relative).read_bytes()
        )
        identities[relative] = digest(data)
        if causal and relative.endswith("patterns.h"):
            for typename in ("catdef", "ruledef"):
                old = f"static const ngx_http_shield_{typename}_t  "
                if data.count(old.encode()) != 1:
                    raise ValueError("causal table instrumentation no longer exact")
                data = data.replace(old.encode(), old.replace("const ", "").encode())
            identities["instrumented_header"] = digest(data)
        (output / Path(relative).name).write_bytes(data)
    includes = ["-I" + str(output)]
    for name in (
        "src/core",
        "src/event",
        "src/event/modules",
        "src/os/unix",
        "objs",
        "src/http",
        "src/http/modules",
    ):
        includes.append("-I" + str(nginx / name))
    sources = (
        [root / "ci/causal/scan.c"]
        if causal
        else [root / "ci/replay/scan.c", output / "ngx_http_shield_scan.c"]
    )
    owned_sources = len(sources)
    sources += [
        nginx / name
        for name in (
            "src/core/ngx_string.c",
            "src/core/ngx_palloc.c",
            "src/os/unix/ngx_alloc.c",
        )
    ]
    dependencies = set()
    for index, source in enumerate(sources):
        obj = output / f"{index}.o"
        flags = ["-std=c99", "-O1", "-g", "-Wall", "-Wextra"]
        if index < owned_sources:
            flags += ["-Werror", "-Wshadow", "-Wstrict-prototypes"]
        depfile = output / f"{index}.d"
        run(
            [
                "cc",
                *flags,
                *includes,
                "-MMD",
                "-MF",
                str(depfile),
                "-c",
                str(source),
                "-o",
                str(obj),
            ]
        )
        dependency_text = depfile.read_text().replace("\\\n", " ").split(":", 1)[1]
        dependencies.update(Path(p) for p in shlex.split(dependency_text))
    binary = output / "scan"
    run(
        [
            "cc",
            *[str(output / f"{i}.o") for i in range(len(sources))],
            "-o",
            str(binary),
        ]
    )
    identities["binary"] = digest(binary.read_bytes())
    identities["adapter"] = digest(sources[0].read_bytes())
    identities["nginx_inputs"] = {
        str(p.relative_to(nginx)): digest(p.read_bytes())
        for p in sorted(dependencies)
        if p.is_relative_to(nginx)
    }
    return binary, identities


def scan(binary, cases, fixtures):
    lines = []
    for case in cases:
        fixture = fixtures[case["fixture"]]
        lines.append(
            f"{int(fixture['content_type'] == FORM)}:{fixture['body'].encode().hex()}\n"
        )
    categories = run([str(binary)], input="".join(lines).encode()).decode().splitlines()
    if len(categories) != len(cases) or any(not c for c in categories):
        raise ValueError("incomplete scanner results")
    return categories


def compare(corpus, fixtures, baseline, candidate):
    if len(baseline) != len(corpus["cases"]) or len(candidate) != len(baseline):
        raise ValueError("incomplete comparison")
    results, counts, regressions = [], Counter(), []
    for case, old, new in zip(corpus["cases"], baseline, candidate, strict=True):
        label, semantics = label_for(case, fixtures[case["fixture"]])
        for revision, category in (("baseline", old), ("candidate", new)):
            verdict = (
                ("TP" if category != "clean" else "FN")
                if label == "attack"
                else ("FP" if category != "clean" else "TN")
                if label == "benign"
                else "unexplained"
            )
            counts[f"{revision}/{case['split']}/body/{category}/{verdict}"] += 1
        if label == "benign" and new != "clean" and old != new:
            regressions.append(case["id"] + ": new benign match")
        if label == "attack" and old != "clean" and new == "clean":
            regressions.append(case["id"] + ": lost attack match")
        results.append(
            {
                "id": case["id"],
                "label": label,
                "split": case["split"],
                "source_group": case["source_group"],
                "surface": "body",
                "body_sha256": digest(fixtures[case["fixture"]]["body"].encode()),
                "baseline": old,
                "candidate": new,
                "semantics": semantics,
            }
        )
    return {
        "baseline_commit": BASE,
        "results": results,
        "counts": dict(sorted(counts.items())),
        "regressions": regressions,
        "promotion_eligible": not any(
            r["label"] == "benign" and r["candidate"] != "clean" for r in results
        ),
        "limits": (
            "scanner body matches, not HTTP denials; toy SQLite only; "
            "no population FP rate or per-rule causal proof"
        ),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validate", action="store_true")
    parser.add_argument("--nginx-source", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    corpus, fixtures = load_corpus()
    if args.validate:
        print(f"validated {len(corpus['cases'])} independently labeled fixtures")
        return 0
    if not args.nginx_source or not args.output:
        parser.error("comparison requires --nginx-source and --output")
    with tempfile.TemporaryDirectory(prefix="shield-replay-") as scratch:
        paths = Path(scratch)
        base, base_identity = build_scanner(
            ROOT, args.nginx_source, paths / "baseline", True
        )
        candidate, candidate_identity = build_scanner(
            ROOT, args.nginx_source, paths / "candidate"
        )
        result = compare(
            corpus,
            fixtures,
            scan(base, corpus["cases"], fixtures),
            scan(candidate, corpus["cases"], fixtures),
        )
        result["identities"] = {
            "baseline": base_identity,
            "candidate": candidate_identity,
        }
        result["corpus_sha256"] = digest((ROOT / "ci/replay/corpus.json").read_bytes())
        result["fixtures_sha256"] = digest((ROOT / corpus["fixtures"]).read_bytes())
        result["compiler"] = run(["cc", "--version"]).decode().splitlines()[0]
        result["sqlite"] = sqlite3.sqlite_version
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(
        f"replayed {len(corpus['cases'])} cases; "
        f"regressions={len(result['regressions'])}; "
        f"promotion_eligible={result['promotion_eligible']}"
    )
    return int(bool(result["regressions"]))


if __name__ == "__main__":
    raise SystemExit(main())
