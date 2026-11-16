#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Generate and validate the inherited Shield inventory and research ledger."""

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from datetime import date
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
BASE = "189bd9e5f8af78f86cfaa6ae456159d239a1c653"
LEDGER = "ci/threat-ledger.json"
SHARDS = ("ci/threat-ledger/001.json", "ci/threat-ledger/002.json")
SCHEMA = "ci/threat-ledger.schema.json"
UNKNOWN = "unknown"
SOURCES = ["ci/definitions-2025-2026.md", "ci/cve-controls.md"]

spec = importlib.util.spec_from_file_location(
    "fuzz_dict", ROOT / "ci/tools/gen-fuzz-dict.py"
)
if spec is None or spec.loader is None:
    raise RuntimeError("cannot load required ledger module")
fuzz_dict = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fuzz_dict)

ARRAY = re.compile(
    r"static const ngx_http_shield_sig_t\s+(ngx_http_shield_\w+)\[\]"
    r"\s*=\s*\{(.*?)\n\};",
    re.DOTALL,
)
TABLE = re.compile(
    r'NGX_HTTP_SHIELD_TABLE\(\s*\w+\s*,\s*"([^"]+)"\s*,'
    r"\s*(ngx_http_shield_\w+)\s*,",
    re.DOTALL,
)
RULE = re.compile(
    r'X\(\s*\w+\s*,\s*"([^"]+)"\s*,\s*\\\s*'
    r"(ngx_http_shield_rule_\w+)\s*,",
    re.DOTALL,
)


def shipped(header, module):
    """Extract table-bound entries and fail closed on incomplete extraction."""
    arrays = {
        name: fuzz_dict.SIG_RE.findall(body) for name, body in ARRAY.findall(header)
    }
    categories = TABLE.findall(header)
    rules = RULE.findall(header)
    block = re.search(
        r"static ngx_conf_bitmask_t\s+profiles\[\]\s*=\s*\{(.*?)\n    \};",
        module,
        re.DOTALL,
    )
    if not block:
        raise ValueError("profile table missing")
    profiles = re.findall(r'\{\s*ngx_string\("([a-z0-9_]+)"\)', block.group(1))
    if not categories or not rules or not profiles:
        raise ValueError("empty category, rule or profile table")
    used = [a for _, a in categories + rules]
    if len(used) != len(set(used)) or set(used) != set(arrays):
        raise ValueError("signature arrays and table references differ")
    entries = []
    for category, name in categories:
        if not arrays[name]:
            raise ValueError("empty signature array: " + name)
        for literal in arrays[name]:
            entries.append(
                ("signature", f"{category}:{fuzz_dict.unescape_c(literal).hex()}")
            )
    for name, array in rules:
        if not arrays[array]:
            raise ValueError("empty rule array: " + array)
        terms = [fuzz_dict.unescape_c(term).hex() for term in arrays[array]]
        entries.append(("and-rule", name + ":" + ",".join(terms)))
    entries.extend(("profile", name) for name in profiles)
    if len(entries) != len(set(entries)):
        raise ValueError("duplicate shipped entry")
    return entries


def row(kind, identity):
    stable = hashlib.sha256((kind + ":" + identity).encode()).hexdigest()
    return {
        "id": "shield-" + stable,
        "kind": kind,
        "identity": identity,
        "era": UNKNOWN,
        "family": UNKNOWN,
        "affected": UNKNOWN,
        "cves": [],
        "products": [],
        "advisory": UNKNOWN,
        "patch": UNKNOWN,
        "disclosure_date": UNKNOWN,
        "review_cutoff": UNKNOWN,
        "surfaces": UNKNOWN,
        "backend_interpretation": UNKNOWN,
        "coverage_overlap": UNKNOWN,
        "predicate": UNKNOWN,
        "benign_counterexample": UNKNOWN,
        "action_class": UNKNOWN,
        "test_ids": [],
        "performance_budget": UNKNOWN,
        "rationale": UNKNOWN,
        "mitigation_owner": UNKNOWN,
        "evidence": "inherited-unreviewed",
        "parser_backend_versions": UNKNOWN,
        "inspection_phase": UNKNOWN,
        "site_contract": UNKNOWN,
        "inspection_limits": UNKNOWN,
        "rule_revision": UNKNOWN,
        "owning_bundle": UNKNOWN,
        "supersedes": [],
        "disposition": "existing coverage",
        "sources": SOURCES,
    }


REVIEWED_FIELDS = (
    "era",
    "family",
    "affected",
    "advisory",
    "patch",
    "disclosure_date",
    "review_cutoff",
    "surfaces",
    "backend_interpretation",
    "coverage_overlap",
    "predicate",
    "benign_counterexample",
    "performance_budget",
    "rationale",
    "mitigation_owner",
    "parser_backend_versions",
    "inspection_phase",
    "site_contract",
    "inspection_limits",
    "rule_revision",
    "owning_bundle",
)
ACTIONS = {
    "existing coverage": {"default candidate", "deployment opt-in", "observe only"},
    "new default candidate": {"default candidate"},
    "deployment opt-in": {"deployment opt-in"},
    "observe only": {"observe only"},
    "outside visibility": {"outside visibility"},
    "patch/configuration mitigation": {"patch/configuration mitigation"},
    "insufficient evidence": {"insufficient evidence"},
}


def reference_exists(name, root, fixture=False):
    """Check references without network access.

    Fixtures are nonempty files under ci/tests, ci/t, or ci/fuzz. They map to
    a whole file, not a test selector or proof that the file exercises a row.
    HTTPS references are checked for structure, not remote content or authority.
    """
    if "::" in name or any(ch.isspace() for ch in name):
        return False
    if not fixture and name.startswith("https://"):
        try:
            url = urlsplit(name)
            return bool(
                url.hostname
                and "." in url.hostname
                and url.path.strip("/")
                and not url.username
                and not url.password
                and url.port in (None, 443)
            )
        except ValueError:
            return False
    path = Path(name)
    allowed = ("ci/tests/", "ci/t/", "ci/fuzz/") if fixture else ("ci/",)
    if not name.startswith(allowed) or path.is_absolute():
        return False
    target = (root / path).resolve()
    return (
        any(
            target.is_relative_to((root / directory).resolve()) for directory in allowed
        )
        and target.is_file()
        and target.stat().st_size > 0
    )


def validate_reviewed(entry, root):
    for field in REVIEWED_FIELDS:
        if not entry[field].strip() or entry[field].strip().lower() in {
            "unknown",
            "unreviewed",
            "n/a",
        }:
            raise ValueError(
                "reviewed entry lacks provenance or decision evidence: " + field
            )
    for field in ("advisory", "patch"):
        if not reference_exists(entry[field], root):
            raise ValueError("invalid provenance reference: " + field)
    for field in ("disclosure_date", "review_cutoff"):
        try:
            date.fromisoformat(entry[field])
        except ValueError as exc:
            raise ValueError("invalid date: " + field) from exc
    if date.fromisoformat(entry["disclosure_date"]) > date.fromisoformat(
        entry["review_cutoff"]
    ):
        raise ValueError("disclosure after review cutoff")
    if not entry["test_ids"]:
        raise ValueError("reviewed entry lacks fixture mapping")
    if entry["action_class"] not in ACTIONS[entry["disposition"]]:
        raise ValueError("incompatible action and disposition")


def validate(ledger, schema, root):
    """Validate the deliberately small schema vocabulary used by this ledger."""

    def check(value, rule, path):
        kind = rule.get("type")
        types = {"object": dict, "array": list, "string": str, "integer": int}
        if kind and (not isinstance(value, types[kind]) or isinstance(value, bool)):
            raise ValueError(f"{path}: expected {kind}")
        if "const" in rule and value != rule["const"]:
            raise ValueError(f"{path}: wrong constant")
        if "enum" in rule and value not in rule["enum"]:
            raise ValueError(f"{path}: invalid value")
        if isinstance(value, str):
            if (
                not rule.get("minLength", 0)
                <= len(value)
                <= rule.get("maxLength", 4096)
            ):
                raise ValueError(f"{path}: invalid length")
            if "pattern" in rule and not re.fullmatch(rule["pattern"], value):
                raise ValueError(f"{path}: invalid format")
        if isinstance(value, list):
            if not rule.get("minItems", 0) <= len(value) <= rule.get("maxItems", 10000):
                raise ValueError(f"{path}: invalid item count")
            for index, item in enumerate(value):
                check(item, rule["items"], f"{path}[{index}]")
        if isinstance(value, dict):
            props = rule["properties"]
            if set(value) != set(rule["required"]) or set(value) != set(props):
                raise ValueError(f"{path}: missing or unknown fields")
            for key, item in value.items():
                check(item, props[key], f"{path}.{key}")

    check(ledger, schema, "ledger")
    ids, identities = set(), set()
    for entry in ledger["entries"]:
        identity = (entry["kind"], entry["identity"])
        if entry["id"] in ids or identity in identities:
            raise ValueError("duplicate ID or shipped identity")
        ids.add(entry["id"])
        identities.add(identity)
        for source in entry["sources"]:
            if not reference_exists(source, root):
                raise ValueError("invalid source mapping: " + source)
        for fixture in entry["test_ids"]:
            if not reference_exists(fixture, root, fixture=True):
                raise ValueError("invalid fixture mapping: " + fixture)
        if entry["evidence"] == "inherited-unreviewed":
            if (
                entry["action_class"] != UNKNOWN
                or entry["disposition"] != "existing coverage"
            ):
                raise ValueError("unreviewed entry cannot be promoted")
        else:
            validate_reviewed(entry, root)
    for entry in ledger["entries"]:
        if any(link not in ids or link == entry["id"] for link in entry["supersedes"]):
            raise ValueError("invalid supersession link")
    return {identity for identity in identities if identity[0] != "mechanism"}


def read_json(path):
    if path.stat().st_size > 8_000_000:
        raise ValueError(f"{path}: input exceeds size limit")

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)


def read_ledger(root):
    """Read the fixed shard index, returning the original expanded schema shape."""

    def bound(name):
        path = root / name
        if not path.resolve().is_relative_to(root.resolve()):
            raise ValueError("ledger path escapes root")
        return path

    index = read_json(bound(LEDGER))
    if (
        not isinstance(index, dict)
        or set(index) != {"base", "shards"}
        or index["base"] != BASE
        or index["shards"] != list(SHARDS)
    ):
        raise ValueError("invalid ledger index, base or shard paths")
    entries = []
    for name in SHARDS:
        part = read_json(bound(name))
        if (
            not isinstance(part, dict)
            or set(part) != {"base", "entries"}
            or part["base"] != BASE
            or not isinstance(part["entries"], list)
            or not part["entries"]
        ):
            raise ValueError("invalid ledger shard")
        entries.extend(part["entries"])
    return {"base": BASE, "entries": entries}


def seed(root, entries):
    """Write deterministic bounded shards; refuse all existing output targets."""
    targets = [root / name for name in (LEDGER, *SHARDS)]
    if any(not path.resolve().is_relative_to(root.resolve()) for path in targets):
        raise ValueError("ledger seed path escapes root")
    if any(path.exists() or path.is_symlink() for path in targets):
        raise FileExistsError("ledger seed target already exists")
    rows = [row(*entry) for entry in entries]
    middle = len(rows) // 2
    documents = [
        {"base": BASE, "shards": list(SHARDS)},
        {"base": BASE, "entries": rows[:middle]},
        {"base": BASE, "entries": rows[middle:]},
    ]
    encoded = [json.dumps(doc, indent=2, ensure_ascii=True) + "\n" for doc in documents]
    if any(len(text.encode()) > 512 * 1024 for text in encoded):
        raise ValueError("ledger seed exceeds shard size bound")
    for path, text in zip(targets, encoded, strict=True):
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("x", encoding="utf-8") as out:
            out.write(text)


def check_readme(readme, entries, header):
    match = re.search(
        r"(\w+) categories contain\s+([\d,]+) standalone table entries "
        r"\(([\d,]+) unique byte\s+strings\) and (\w+) AND rules "
        r"with (\d+) terms",
        readme,
        re.DOTALL,
    )
    numbers = {"thirty": 30, "six": 6, "five": 5, "seven": 7}
    if not match:
        raise ValueError("README counts missing")
    enum = re.search(
        r"typedef enum \{(.*?)\} ngx_http_shield_cat_e;", header, re.DOTALL
    )
    if not enum:
        raise ValueError("category enum missing")
    categories = re.findall(r"NGX_HTTP_SHIELD_CAT_(?!N\b)[A-Z_]+", enum.group(1))
    signatures = [
        identity.split(":", 1)[1] for kind, identity in entries if kind == "signature"
    ]
    rules = [identity for kind, identity in entries if kind == "and-rule"]
    terms = sum(len(rule.split(":", 1)[1].split(",")) for rule in rules)

    def number(text):
        return (
            int(text.replace(",", ""))
            if text[0].isdigit()
            else numbers.get(text.lower())
        )

    documented = tuple(number(value) for value in match.groups())
    actual = (len(categories), len(signatures), len(set(signatures)), len(rules), terms)
    if documented != actual:
        raise ValueError("README count mismatch")
    block = re.search(
        r"\| Profile \| Inspected form \| Reported category \|(.*?)(?:\n\n)",
        readme,
        re.DOTALL,
    )
    names = (
        re.findall(r"^\| `([a-z0-9_]+)` \|", block.group(1), re.MULTILINE)
        if block
        else []
    )
    if set(names) != {name for kind, name in entries if kind == "profile"} or len(
        names
    ) != len(set(names)):
        raise ValueError("README profile count or names mismatch")


def check_drift(identities, entries):
    expected = set(entries)
    if identities != expected:
        raise ValueError(
            f"shipped drift: missing={len(expected - identities)}, "
            f"removed={len(identities - expected)}"
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--seed", action="store_true", help="create initial ledger; refuse to overwrite"
    )
    args = parser.parse_args()
    try:
        header = (ROOT / "src/ngx_http_shield_patterns.h").read_text()
        entries = shipped(header, (ROOT / "src/ngx_http_shield_module.c").read_text())
        check_readme((ROOT / "README.md").read_text(), entries, header)
        if args.seed:
            seed(ROOT, entries)
        ledger = read_ledger(ROOT)
        identities = validate(ledger, read_json(ROOT / SCHEMA), ROOT)
        check_drift(identities, entries)
        print(f"threat ledger: {len(entries)} shipped entries validated")
        return 0
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"threat ledger: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
