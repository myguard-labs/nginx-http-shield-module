#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Semantic labels and comparison integrity, independent of scanner guesses."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "replay", ROOT / "ci/tools/threat-replay.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load required replay module")
replay = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(replay)


class ReplayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "ci/replay").mkdir(parents=True)
        self.corpus, self.fixtures = replay.load_corpus()

    def write(self):
        for filename, value in (("corpus", self.corpus), ("bodies", self.fixtures)):
            (self.root / f"ci/replay/{filename}.json").write_text(json.dumps(value))

    def rejected(self, message):
        self.write()
        with self.assertRaisesRegex(ValueError, message):
            replay.load_corpus(self.root)

    def test_retains_historical_rows_and_downgrades_scanner_only_labels(self):
        cases = self.corpus["cases"]
        historical = [c for c in cases if c["source_group"] == "body-authored-20261115"]
        self.assertEqual(len(historical), 36)
        self.assertEqual(sum(c["label"] == "unclassified" for c in historical), 4)
        self.assertEqual(
            sum(
                c["historical_scanner_category"] != "clean" and c["label"] == "benign"
                for c in historical
            ),
            8,
        )

    def test_sqlite_attack_has_forbidden_result_only_in_vulnerable_query(self):
        label, result = replay.sql_semantics(
            self.fixtures["sqlite_union_private"]["body"]
        )
        self.assertEqual(label, "attack")
        self.assertEqual(result["vulnerable"], [("private-dummy",)])
        self.assertEqual(result["parameterized"], [])

    def test_sqlite_benign_pair(self):
        label, result = replay.sql_semantics("id=1")
        self.assertEqual(label, "benign")
        self.assertEqual(result["vulnerable"], result["parameterized"])

    def test_sqlite_unknown_is_neither_attack_nor_clean_proof(self):
        self.assertEqual(replay.sql_semantics("id=2")[0], "unclassified")

    def test_sqlite_errors_and_duplicate_parameters(self):
        for body in ("id=invalid_sql", "id=1&id=2", "x=1", "invalid"):
            with self.subTest(body=body), self.assertRaises(ValueError):
                replay.sql_semantics(body)

    def test_false_label_rejected(self):
        self.corpus["cases"][0]["label"] = "attack"
        self.rejected("false semantic label")

    def test_false_scanner_attack_label_rejected(self):
        self.corpus["cases"][32]["label"] = "attack"
        self.rejected("false semantic label")

    def test_false_sink_attack_label_rejected(self):
        self.fixtures["sqlite_union_private"]["body"] = "id=1"
        self.rejected("false semantic label")

    def test_missing_fixture_rejected(self):
        del self.fixtures["profile_plain"]
        self.rejected("missing fixture")

    def test_group_leakage_rejected(self):
        self.corpus["cases"][0]["split"] = "heldout"
        self.rejected("source-group leakage")

    def test_duplicate_case_rejected(self):
        self.corpus["cases"].append(self.corpus["cases"][0])
        self.rejected("duplicate case")

    def test_historical_omission_rejected(self):
        del self.corpus["cases"][0]
        del self.fixtures["profile_plain"]
        self.rejected("historical corpus omission")

    def test_unknown_oracle_rejected(self):
        self.corpus["cases"][0]["oracle"] = "guess"
        self.rejected("unknown semantic oracle")

    def test_bad_provenance_rejected(self):
        self.fixtures["profile_plain"]["source_role"] = "scanner-positive"
        self.rejected("provenance mismatch")

    def test_oversized_body_rejected(self):
        self.fixtures["profile_plain"]["body"] = "x" * 4097
        self.rejected("oversized body")

    def test_boundary_body_allowed(self):
        self.fixtures["profile_plain"]["body"] = "x" * 4096
        self.write()
        replay.load_corpus(self.root)

    def test_unknown_content_type_split_and_baseline_rejected(self):
        self.fixtures["profile_plain"]["content_type"] = "unknown"
        self.rejected("unsupported content type")
        self.fixtures["profile_plain"]["content_type"] = "text/plain"
        self.corpus["cases"][0]["split"] = "unknown"
        self.rejected("unknown split")
        self.corpus["cases"][0]["split"] = "development"
        self.corpus["baseline"] = "HEAD"
        self.rejected("unsupported corpus")

    def test_unmapped_and_missing_split_rejected(self):
        self.fixtures["extra"] = self.fixtures["profile_plain"]
        self.rejected("unmapped fixtures")
        del self.fixtures["extra"]
        for case in self.corpus["cases"]:
            case["split"] = "development"
        self.rejected("both splits required")

    def test_metadata_sanitization_does_not_claim_original_collision(self):
        case = next(
            c for c in self.corpus["cases"] if c["id"] == "post_metadata_tutorial"
        )
        body = self.fixtures[case["fixture"]]["body"]
        self.assertTrue(case["sanitized"])
        self.assertIn("192.0.2.1", body)
        self.assertNotEqual(replay.digest(body.encode()), case["original_body_sha256"])
        self.assertEqual(case["historical_scanner_category"], "ssrf_meta")

    def test_comparison_counts_unknowns_and_rejects_known_fp_promotion(self):
        categories = ["clean"] * 38
        categories[0] = "sqli"
        categories[-1] = "sqli"
        result = replay.compare(self.corpus, self.fixtures, categories, categories)
        self.assertFalse(result["promotion_eligible"])
        self.assertEqual(result["regressions"], [])
        self.assertEqual(result["counts"]["candidate/heldout/body/sqli/TP"], 1)
        self.assertEqual(
            sum(
                v
                for k, v in result["counts"].items()
                if k.startswith("candidate/") and k.endswith("unexplained")
            ),
            4,
        )

    def test_new_false_positive_and_lost_positive_fail_comparison(self):
        old, new = ["clean"] * 38, ["clean"] * 38
        old[-1] = "sqli"
        new[0] = "sqli"
        result = replay.compare(self.corpus, self.fixtures, old, new)
        self.assertEqual(len(result["regressions"]), 2)

    def test_incomplete_results_rejected(self):
        with self.assertRaisesRegex(ValueError, "incomplete comparison"):
            replay.compare(self.corpus, self.fixtures, [], [])


if __name__ == "__main__":
    unittest.main()
