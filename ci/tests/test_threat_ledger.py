#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Contract and drift controls for the threat ledger."""

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "threat_ledger", ROOT / "ci/tools/threat-ledger.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load required ledger module")
ledger_tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ledger_tool)


class ThreatLedgerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = ledger_tool.read_json(ROOT / ledger_tool.SCHEMA)
        cls.ledger = ledger_tool.read_ledger(ROOT)
        cls.header = (ROOT / "src/ngx_http_shield_patterns.h").read_text()
        cls.module = (ROOT / "src/ngx_http_shield_module.c").read_text()
        cls.readme = (ROOT / "README.md").read_text()
        cls.entries = ledger_tool.shipped(cls.header, cls.module)

    def test_seed_and_readme(self):
        self.assertEqual(
            ledger_tool.validate(self.ledger, self.schema, ROOT), set(self.entries)
        )
        ledger_tool.check_readme(self.readme, self.entries, self.header)
        self.assertTrue(
            all(r["evidence"] == "inherited-unreviewed" for r in self.ledger["entries"])
        )
        self.assertEqual(ledger_tool.fuzz_dict.unescape_c(r"\xff"), b"\xff")

    def test_missing_and_malformed_fields(self):
        for mutate in (
            lambda r: r.pop("advisory"),
            lambda r: r.update(test_ids="bad"),
            lambda r: r.update(disposition="clean"),
            lambda r: r.update(id=""),
        ):
            with self.subTest(mutate=mutate):
                data = copy.deepcopy(self.ledger)
                mutate(data["entries"][0])
                with self.assertRaises(ValueError):
                    ledger_tool.validate(data, self.schema, ROOT)

    def test_duplicate_ids_and_identities(self):
        for field in ("id", "identity"):
            data = copy.deepcopy(self.ledger)
            data["entries"][1][field] = data["entries"][0][field]
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(ValueError, "duplicate"),
            ):
                ledger_tool.validate(data, self.schema, ROOT)

    def test_missing_fixture_and_promotion(self):
        data = copy.deepcopy(self.ledger)
        data["entries"][0]["test_ids"] = ["ci/tests/no-such-fixture"]
        with self.assertRaisesRegex(ValueError, "fixture mapping"):
            ledger_tool.validate(data, self.schema, ROOT)
        data["entries"][0]["test_ids"] = []
        data["entries"][0]["action_class"] = "default candidate"
        with self.assertRaisesRegex(ValueError, "cannot be promoted"):
            ledger_tool.validate(data, self.schema, ROOT)
        data["entries"][0]["evidence"] = "reviewed"
        with self.assertRaisesRegex(ValueError, "lacks provenance"):
            ledger_tool.validate(data, self.schema, ROOT)

    def reviewed_row(self):
        result = copy.deepcopy(self.ledger["entries"][0])
        result.update(
            evidence="reviewed",
            disposition="new default candidate",
            action_class="default candidate",
            era="2020-2026",
            family="example",
            affected="example application 1.0",
            advisory="https://example.org/advisory",
            patch="https://example.org/patch",
            disclosure_date="2025-01-01",
            review_cutoff="2026-01-01",
            surfaces="query",
            backend_interpretation="example sink",
            coverage_overlap="existing signature",
            predicate="example predicate",
            benign_counterexample="inert example",
            performance_budget="bounded by scan limit",
            rationale="fixture example",
            mitigation_owner="operator",
            parser_backend_versions="example 1.0",
            inspection_phase="request",
            site_contract="example route",
            inspection_limits="configured scan limit",
            rule_revision="example revision 1",
            owning_bundle="test",
            test_ids=["ci/tests/test_threat_ledger.py"],
        )
        return result

    def test_reviewed_complete_entry(self):
        data = copy.deepcopy(self.ledger)
        data["entries"][0] = self.reviewed_row()
        ledger_tool.validate(data, self.schema, ROOT)

    def test_reviewed_rejects_incomplete_evidence(self):
        fields = (
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
        for field in fields:
            data = copy.deepcopy(self.ledger)
            data["entries"][0] = self.reviewed_row()
            data["entries"][0][field] = "unknown"
            with self.subTest(field=field), self.assertRaises(ValueError):
                ledger_tool.validate(data, self.schema, ROOT)

    def test_reviewed_rejects_invalid_references_and_decisions(self):
        cases = (
            {"advisory": "not-a-source"},
            {"patch": "https://"},
            {"test_ids": ["ci/tests/test_threat_ledger.py::nonexistent_test"]},
            {"test_ids": ["ci/cve-controls.md"]},
            {"test_ids": ["ci/tests/../cve-controls.md"]},
            {"test_ids": []},
            {"disclosure_date": "invalid"},
            {"review_cutoff": "2000-01-01"},
            {"sources": ["https://"]},
            {"action_class": "observe only"},
        )
        for change in cases:
            data = copy.deepcopy(self.ledger)
            data["entries"][0] = self.reviewed_row()
            data["entries"][0].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                ledger_tool.validate(data, self.schema, ROOT)

    def test_reported_false_review_rejected(self):
        data = copy.deepcopy(self.ledger)
        data["entries"][0].update(
            evidence="reviewed",
            disposition="new default candidate",
            action_class="default candidate",
            advisory="not-a-source",
            backend_interpretation="some sink",
            test_ids=["ci/tests/test_threat_ledger.py::nonexistent_test"],
        )
        with self.assertRaises(ValueError):
            ledger_tool.validate(data, self.schema, ROOT)

    def test_shipped_missing_from_ledger(self):
        data = copy.deepcopy(self.ledger)
        data["entries"].pop()
        found = ledger_tool.validate(data, self.schema, ROOT)
        with self.assertRaisesRegex(ValueError, "missing=1, removed=0"):
            ledger_tool.check_drift(found, self.entries)

    def test_removed_shipped_entry(self):
        found = ledger_tool.validate(self.ledger, self.schema, ROOT)
        with self.assertRaisesRegex(ValueError, "missing=0, removed=1"):
            ledger_tool.check_drift(found, self.entries[:-1])

    def test_readme_count_mismatch(self):
        bad = self.readme.replace(
            "651 standalone table entries", "652 standalone table entries", 1
        )
        self.assertNotEqual(bad, self.readme)
        with self.assertRaisesRegex(ValueError, "README count mismatch"):
            ledger_tool.check_readme(bad, self.entries, self.header)

    def test_profile_and_array_parser_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "profile table missing"):
            ledger_tool.shipped(
                self.header,
                self.module.replace("profiles[] = {", "profiles_missing[] = {"),
            )
        with self.assertRaisesRegex(ValueError, "table references differ"):
            ledger_tool.shipped(
                self.header.replace(
                    "ngx_http_shield_sqli[]", "ngx_http_shield_missing[]", 1
                ),
                self.module,
            )
        with self.assertRaisesRegex(ValueError, "profile count"):
            ledger_tool.check_readme(
                self.readme.replace("| `php_cgi` |", "| `removed` |", 1),
                self.entries,
                self.header,
            )

    def test_shard_layout_and_roundtrip(self):
        self.assertEqual(ledger_tool.read_ledger(ROOT), self.ledger)
        self.assertEqual(len(self.ledger["entries"]), 663)
        for name in (ledger_tool.LEDGER, *ledger_tool.SHARDS):
            self.assertLessEqual((ROOT / name).stat().st_size, 512 * 1024)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            ledger_tool.seed(root, self.entries)
            self.assertEqual(ledger_tool.read_ledger(root), self.ledger)
            before = {
                name: (root / name).read_bytes()
                for name in (ledger_tool.LEDGER, *ledger_tool.SHARDS)
            }
            with self.assertRaises(FileExistsError):
                ledger_tool.seed(root, self.entries)
            self.assertEqual(
                before, {name: (root / name).read_bytes() for name in before}
            )

    def test_seed_preflight_preserves_existing_partial_layout(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            existing = root / ledger_tool.SHARDS[1]
            existing.parent.mkdir(parents=True)
            existing.write_text("preserve-existing")
            with self.assertRaises(FileExistsError):
                ledger_tool.seed(root, self.entries)
            self.assertEqual(existing.read_text(), "preserve-existing")
            self.assertFalse((root / ledger_tool.LEDGER).exists())
            self.assertFalse((root / ledger_tool.SHARDS[0]).exists())

    def test_seed_rejects_escaping_directory_before_writing(self):
        with (
            tempfile.TemporaryDirectory() as temp,
            tempfile.TemporaryDirectory() as other,
        ):
            root = Path(temp)
            (root / "ci").mkdir()
            (root / "ci/threat-ledger").symlink_to(other, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "seed path escapes root"):
                ledger_tool.seed(root, self.entries)
            self.assertEqual(list(Path(other).iterdir()), [])
            self.assertFalse((root / ledger_tool.LEDGER).exists())

    def test_shards_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            ledger_tool.seed(root, self.entries)
            index = root / ledger_tool.LEDGER
            original = ledger_tool.read_json(index)
            for change in (
                {"shards": []},
                {"shards": [ledger_tool.SHARDS[0]] * 2},
                {"shards": ["../outside.json", ledger_tool.SHARDS[1]]},
                {"shards": list(reversed(ledger_tool.SHARDS))},
                {"base": "HEAD"},
                {"extra": True},
            ):
                index.write_text(json.dumps(dict(original, **change)))
                with self.subTest(change=change), self.assertRaises(ValueError):
                    ledger_tool.read_ledger(root)
            index.write_text(json.dumps(original))
            shard = root / ledger_tool.SHARDS[1]
            part = ledger_tool.read_json(shard)
            for change in ({"base": "HEAD"}, {"entries": []}, {"extra": True}):
                shard.write_text(json.dumps(dict(part, **change)))
                with self.subTest(change=change), self.assertRaises(ValueError):
                    ledger_tool.read_ledger(root)
            part["entries"][0] = copy.deepcopy(self.ledger["entries"][0])
            shard.write_text(json.dumps(part))
            with self.assertRaisesRegex(ValueError, "duplicate"):
                ledger_tool.validate(ledger_tool.read_ledger(root), self.schema, ROOT)
            shard.unlink()
            outside = root / "outside.json"
            outside.write_text(json.dumps(part))
            shard.symlink_to(outside)
            # A path inside the checkout is allowed; a symlink out is rejected.
            self.assertEqual(len(ledger_tool.read_ledger(root)["entries"]), 663)
            shard.unlink()
            with tempfile.TemporaryDirectory() as other:
                target = Path(other) / "outside.json"
                target.write_text(json.dumps(part))
                shard.symlink_to(target)
                with self.assertRaisesRegex(ValueError, "escapes root"):
                    ledger_tool.read_ledger(root)
                shard.unlink()
            with self.assertRaises(OSError):
                ledger_tool.read_ledger(root)

    def test_invalid_and_duplicate_json(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "ledger.json"
            for text in ('{"base":', '{"base": "a", "base": "b"}'):
                path.write_text(text)
                with self.subTest(text=text), self.assertRaises(ValueError):
                    ledger_tool.read_json(path)

    def test_json_size_bound(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "large.json"
            path.write_bytes(b" " * 8_000_001)
            with self.assertRaisesRegex(ValueError, "size limit"):
                ledger_tool.read_json(path)


if __name__ == "__main__":
    unittest.main()
