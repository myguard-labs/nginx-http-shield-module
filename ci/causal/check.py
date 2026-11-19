#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Causal scanner attribution and bounded, independently labelled toy variants."""

import argparse
import importlib.util
import json
import tempfile
from pathlib import Path
from urllib.parse import parse_qs, quote, urlencode

ROOT = Path(__file__).resolve().parents[2]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load required capability module")
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


replay = module("replay", ROOT / "ci/tools/threat-replay.py")
ledger = module("ledger", ROOT / "ci/tools/threat-ledger.py")
diagnostics = module("diagnostics", ROOT / "ci/causal/diagnostics.py")
TRANSFORMS = ("identity", "percent", "form-plus", "sql-case")


def inventory(binary):
    entries = {}
    for line in replay.run([str(binary), "--list"]).decode().splitlines():
        kind, row, item, name, category, terms = line.split("\t")
        identity = name + ":" + terms
        key = kind + ":" + identity
        if key in entries:
            raise ValueError("duplicate compiled identity")
        entries[key] = {
            "kind": kind,
            "identity": identity,
            "row": row,
            "item": item,
            "category": category,
            "terms": terms.split(","),
        }
    expected = {
        kind + ":" + identity
        for kind, identity in ledger.shipped(
            (ROOT / "src/ngx_http_shield_patterns.h").read_text(),
            (ROOT / "src/ngx_http_shield_module.c").read_text(),
        )
        if kind != "profile"
    }
    if set(entries) != expected:
        raise ValueError("compiled inventory differs from shipped ledger")
    return entries


def load_cases(entries, root=ROOT):
    cases = json.loads((root / "ci/causal/cases.json").read_text())
    if cases["version"] != 1 or not 1 <= len(cases["cases"]) <= 64:
        raise ValueError("unsupported or unbounded causal cases")
    used = set()
    for case in cases["cases"]:
        key = case["entry"]
        if key not in entries or key in used:
            raise ValueError("missing or duplicate causal identity")
        used.add(key)
        entry = entries[key]
        if not 1 <= len(entry["terms"]) <= 4:
            raise ValueError("causal term subset bound exceeded")
        if case["terms"] != entry["terms"] or case["category"] != entry["category"]:
            raise ValueError("causal identity/term drift")
        body = bytes.fromhex(case["positive_hex"])
        if not body or len(body) > 4096:
            raise ValueError("empty or oversized causal positive")
        if any(bytes.fromhex(term) not in body for term in entry["terms"]):
            raise ValueError("positive omits a candidate term")
    return cases["cases"]


def observe(binary, args, bodies, form=False):
    wire = "".join(f"{int(form)}:{body.hex()}\n" for body in bodies).encode()
    results = replay.run([str(binary), *args], input=wire).decode().splitlines()
    if len(results) != len(bodies):
        raise ValueError("incomplete causal scanner results")
    return results


def require(actual, expected, reason):
    if actual != expected:
        raise ValueError(f"{reason}: expected {expected!r}, got {actual!r}")


def causal(binary, entries, cases):
    results = []
    for case in cases:
        entry = entries[case["entry"]]
        args = [entry["kind"], entry["row"], entry["item"]]
        positive = bytes.fromhex(case["positive_hex"])
        terms = [bytes.fromhex(t) for t in entry["terms"]]
        positive_inputs = [positive, b" | ".join(reversed(terms))]
        require(
            observe(binary, [*args, "on"], positive_inputs),
            [entry["category"]] * 2,
            "isolated intended rule positive " + case["entry"],
        )
        require(
            observe(binary, [*args, "off"], positive_inputs),
            ["clean"] * 2,
            "positive-removal " + case["entry"],
        )
        neighbors = [b"ordinary content", b""]
        if entry["kind"] == "and-rule":
            # Every proper subset, including each term alone and each omitted
            # term. Separate input lines also prove no cross-buffer term state.
            neighbors += [
                b" | ".join(t for i, t in enumerate(terms) if mask & (1 << i))
                for mask in range(1, (1 << len(terms)) - 1)
            ]
            neighbors += terms
        require(
            observe(binary, [*args, "on"], neighbors),
            ["clean"] * len(neighbors),
            "AND proper-subset/clean control " + case["entry"],
        )
        whole = observe(binary, ["--full"], [positive])[0]
        if whole == "clean":
            raise ValueError("whole engine lost a covered positive")
        results.append(
            {
                "entry": case["entry"],
                "positive_sha256": replay.digest(positive),
                "isolated": entry["category"],
                "removed": "clean",
                "whole_engine": whole,
                "negative_buffers": len(neighbors),
            }
        )
    covered = {c["entry"] for c in cases}
    return {
        "results": results,
        "covered_entries": sorted(covered),
        "uncovered_entries": sorted(set(entries) - covered),
        "shipped_entries": len(entries),
        "limits": "scanner table causality only; no exploit or HTTP identity proof",
    }


def value_for(body):
    fields = parse_qs(body, strict_parsing=True)
    if set(fields) != {"id"} or len(fields["id"]) != 1:
        raise ValueError("paired fixture requires exactly one id")
    return fields["id"][0]


def transform(body, name):
    value = value_for(body)
    if name == "identity":
        return body
    if name == "percent":
        return "id=" + "".join(f"%{c:02X}" for c in value.encode())
    if name == "form-plus":
        return urlencode({"id": value})
    if name == "sql-case":
        return "id=" + quote(value.upper(), safe="")
    raise ValueError("unsupported semantics-preserving transform")


def generate_variants(corpus, fixtures):
    seeds = [
        (case, fixtures[case["fixture"]]["body"])
        for case in corpus["cases"]
        if case["oracle"] == "sqlite-query"
    ]
    if {case["id"] for case, _ in seeds} != {"sqlite_public", "sqlite_union_private"}:
        raise ValueError("paired toy source seed drift")
    # Explicitly uncertain root in the SAME toy source group; never a new
    # independent held-out source. The query is valid but proves no attack.
    parent = dict(seeds[0][0], id="sqlite_uncertain", label="unclassified")
    seeds.append((parent, "id=2"))
    variants = []
    for parent, body in seeds:
        label, semantics = replay.sql_semantics(body)
        require(label, parent["label"], "seed semantic label")
        for name in TRANSFORMS:
            changed = transform(body, name)
            require(
                replay.sql_semantics(changed), (label, semantics), "transform semantics"
            )
            for endpoint in ("content-store", "sqlite-query"):
                variants.append(
                    {
                        "id": f"{parent['id']}/{name}/{endpoint}",
                        "parent": parent["id"],
                        "source_group": parent["source_group"],
                        "split": parent["split"],
                        "transform": name,
                        "endpoint": endpoint,
                        "body": changed,
                        "label": "benign" if endpoint == "content-store" else label,
                        "parent_body_sha256": replay.digest(body.encode()),
                    }
                )
    return {"version": 1, "variants": variants}


def load_variants(corpus, fixtures, root=ROOT):
    actual = json.loads((root / "ci/causal/variants.json").read_text())
    expected = generate_variants(corpus, fixtures)
    if actual.get("version") != 1 or len(actual.get("variants", [])) != 24:
        raise ValueError("variant version/count drift")
    seen = set()
    for row, wanted in zip(actual["variants"], expected["variants"], strict=True):
        if row["id"] in seen:
            raise ValueError("duplicate variant identity")
        seen.add(row["id"])
        if (
            row["source_group"] != wanted["source_group"]
            or row["split"] != wanted["split"]
        ):
            raise ValueError("source-group variant leakage")
        if row["label"] != wanted["label"]:
            raise ValueError("false paired semantic label")
        if row != wanted or len(row["body"].encode()) > 4096:
            raise ValueError("variant transform/parent/bytes drift")
    return actual["variants"]


def paired_semantics(row):
    value = value_for(row["body"])
    if row["endpoint"] == "content-store":
        # Inert round trip: store as data, never interpolate into an evaluator.
        stored = json.loads(json.dumps({"id": value}))
        return {"stored": stored["id"], "evaluation": False}
    label, outcomes = replay.sql_semantics(row["body"])
    require(label, row["label"], "paired sink label")
    return outcomes


def variant_report(binary, rows):
    categories = observe(
        binary, ["--full"], [r["body"].encode() for r in rows], form=True
    )
    results = []
    for row, category in zip(rows, categories, strict=True):
        # Only independently proven attack variants require detection. Content
        # can still collide with current policy; report it without relabelling.
        if row["label"] == "attack" and category != "sqli":
            raise ValueError("semantics-preserving attack variant lost detection")
        if row["label"] == "benign" and row["parent"] == "sqlite_public":
            require(category, "clean", "benign variant must stay accepted")
        results.append(
            dict(row, scanner_category=category, semantics=paired_semantics(row))
        )
    return {
        "results": results,
        "independent_source_groups": sorted({r["source_group"] for r in rows}),
        "promotion_eligible": False,
        "limits": (
            "toy SQLite only; derived variants are correlated, not independent samples; "
            "content collisions remain FPs; HTTP content acceptance needs explicit skip policy; "
            "four historical positives remain unclassified; no population validation"
        ),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validate", action="store_true")
    parser.add_argument("--nginx-source", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    corpus, fixtures = replay.load_corpus()
    variants = load_variants(corpus, fixtures)
    if args.validate:
        print(f"validated {len(variants)} paired variants; labels from toy semantics")
        return 0
    if not args.nginx_source or not args.output:
        parser.error("causal check requires --nginx-source and --output")
    with tempfile.TemporaryDirectory(prefix="shield-causal-") as scratch:
        binary, identity = replay.build_scanner(
            ROOT, args.nginx_source, Path(scratch) / "candidate", causal=True
        )
        entries = inventory(binary)
        cases = load_cases(entries)
        report = {
            "causal": causal(binary, entries, cases),
            "diagnostics": diagnostics.check(binary, replay.run),
            "variants": variant_report(binary, variants),
            "build": identity,
            "inputs": {
                name: replay.digest((ROOT / name).read_bytes())
                for name in (
                    "ci/causal/cases.json",
                    "ci/causal/variants.json",
                    "ci/causal/check.py",
                    "ci/causal/diagnostics.py",
                    "ci/causal/scan.c",
                    "ci/tools/threat-replay.py",
                    "ci/replay/corpus.json",
                    "ci/replay/bodies.json",
                )
            },
        }
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(
        f"causal {len(cases)}/{len(entries)} entries; {len(variants)} paired variants"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
