#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Reject corrupt labels, transformations, group splits and causal identities."""

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("capability", ROOT / "ci/causal/check.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load required capability module")
cap = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cap)


class CapabilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "ci/causal").mkdir(parents=True)
        self.corpus, self.fixtures = cap.replay.load_corpus()
        self.variants = cap.generate_variants(self.corpus, self.fixtures)
        self.cases = json.loads((ROOT / "ci/causal/cases.json").read_text())
        self.entries = {}
        for row in self.cases["cases"]:
            kind, identity = row["entry"].split(":", 1)
            self.entries[row["entry"]] = dict(
                row, kind=kind, identity=identity, row="0", item="0"
            )

    def write(self):
        (self.root / "ci/causal/cases.json").write_text(json.dumps(self.cases))
        (self.root / "ci/causal/variants.json").write_text(json.dumps(self.variants))

    def reject_variant(self, message):
        self.write()
        with self.assertRaisesRegex(ValueError, message):
            cap.load_variants(self.corpus, self.fixtures, self.root)

    def test_paired_labels_come_from_sink_not_detector(self):
        rows = cap.load_variants(self.corpus, self.fixtures)
        self.assertEqual(len(rows), 24)
        self.assertEqual(sum(r["label"] == "attack" for r in rows), 4)
        self.assertEqual(sum(r["label"] == "unclassified" for r in rows), 4)
        attack, content = rows[9], rows[8]
        self.assertEqual(attack["body"], content["body"])
        self.assertEqual(content["label"], "benign")
        self.assertFalse(cap.paired_semantics(content)["evaluation"])
        semantics = cap.paired_semantics(attack)
        self.assertEqual(semantics["vulnerable"], [("private-dummy",)])
        self.assertEqual(semantics["parameterized"], [])

    def test_known_transform_bytes_and_bounded_generation(self):
        self.assertEqual(
            cap.transform("id=union+select", "percent"),
            "id=%75%6E%69%6F%6E%20%73%65%6C%65%63%74",
        )
        self.assertEqual(
            cap.transform("id=union%20select", "form-plus"), "id=union+select"
        )
        self.assertEqual(
            cap.transform("id=union+select", "sql-case"), "id=UNION%20SELECT"
        )
        with self.assertRaisesRegex(ValueError, "unsupported"):
            cap.transform("id=1", "double-decode")
        for invalid in ("id=", "id=1&id=2", "x=1", "invalid"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                cap.value_for(invalid)

    def test_generated_variants_reproducible_and_all_derived_stay_heldout(self):
        self.assertEqual(
            self.variants, cap.generate_variants(self.corpus, self.fixtures)
        )
        rows = self.variants["variants"]
        self.assertEqual({r["split"] for r in rows}, {"heldout"})
        self.assertEqual({r["source_group"] for r in rows}, {"sqlite-toy-sink-v1"})

    def test_false_content_and_sink_labels_rejected(self):
        self.variants["variants"][0]["label"] = "attack"
        self.reject_variant("false paired semantic label")
        self.variants = cap.generate_variants(self.corpus, self.fixtures)
        self.variants["variants"][9]["label"] = "benign"
        self.reject_variant("false paired semantic label")

    def test_unknown_never_promoted_to_attack_or_benign(self):
        self.variants["variants"][-1]["label"] = "benign"
        self.reject_variant("false paired semantic label")

    def test_broken_transform_and_parent_hash_rejected(self):
        self.variants["variants"][10]["body"] = "id=1"
        self.reject_variant("transform/parent/bytes drift")
        self.variants = cap.generate_variants(self.corpus, self.fixtures)
        self.variants["variants"][0]["parent_body_sha256"] = "0" * 64
        self.reject_variant("transform/parent/bytes drift")

    def test_broken_split_and_group_rejected(self):
        self.variants["variants"][0]["split"] = "development"
        self.reject_variant("source-group variant leakage")
        self.variants["variants"][0]["split"] = "heldout"
        self.variants["variants"][0]["source_group"] = "pretend-independent"
        self.reject_variant("source-group variant leakage")

    def test_missing_duplicate_reordered_or_extra_variant_rejected(self):
        del self.variants["variants"][0]
        self.reject_variant("version/count drift")
        self.variants = cap.generate_variants(self.corpus, self.fixtures)
        self.variants["variants"][1] = copy.deepcopy(self.variants["variants"][0])
        self.reject_variant("duplicate variant")
        self.variants = cap.generate_variants(self.corpus, self.fixtures)
        self.variants["variants"][0]["extra"] = True
        self.reject_variant("transform/parent/bytes drift")

    def test_causal_cases_pin_terms_and_report_partial_coverage(self):
        self.write()
        cases = cap.load_cases(self.entries, self.root)
        self.assertEqual(len(cases), 10)
        self.assertEqual(sum(c["entry"].startswith("and-rule:") for c in cases), 6)

    def test_missing_candidate_or_term_drift_rejected(self):
        key = self.cases["cases"][0]["entry"]
        entry = self.entries.pop(key)
        self.write()
        with self.assertRaisesRegex(ValueError, "missing or duplicate causal identity"):
            cap.load_cases(self.entries, self.root)
        self.entries[key] = entry
        self.cases["cases"][0]["terms"] = ["00"]
        self.write()
        with self.assertRaisesRegex(ValueError, "identity/term drift"):
            cap.load_cases(self.entries, self.root)

    def test_missing_term_empty_and_oversized_positive_rejected(self):
        for value, error in (
            ("61", "omits"),
            ("", "empty or oversized"),
            ("61" * 4097, "empty or oversized"),
        ):
            with self.subTest(value=value[:8]):
                self.cases["cases"][0]["positive_hex"] = value
                self.write()
                with self.assertRaisesRegex(ValueError, error):
                    cap.load_cases(self.entries, self.root)

    def test_causal_subset_count_is_bounded(self):
        key = self.cases["cases"][0]["entry"]
        self.entries[key]["terms"] = ["61"] * 5
        self.write()
        with self.assertRaisesRegex(ValueError, "subset bound exceeded"):
            cap.load_cases(self.entries, self.root)

    def test_missing_toy_parent_rejected(self):
        corpus = copy.deepcopy(self.corpus)
        corpus["cases"] = [c for c in corpus["cases"] if c["id"] != "sqlite_public"]
        with self.assertRaisesRegex(ValueError, "toy source seed drift"):
            cap.generate_variants(corpus, self.fixtures)

    def test_causal_assertion_rejects_masked_positive_and_single_term(self):
        case = next(
            c for c in self.cases["cases"] if c["entry"].startswith("and-rule:")
        )
        category = case["category"]
        with (
            patch.object(cap, "observe", return_value=["clean", "clean"]),
            self.assertRaisesRegex(ValueError, "isolated intended rule positive"),
        ):
            cap.causal(Path("unused"), self.entries, [case])
        with (
            patch.object(
                cap,
                "observe",
                side_effect=[
                    [category, category],
                    ["clean", "clean"],
                    [category] * 6,
                ],
            ),
            self.assertRaisesRegex(ValueError, "AND proper-subset/clean control"),
        ):
            cap.causal(Path("unused"), self.entries, [case])

    def test_incomplete_observation_and_invalid_predicate_rejected(self):
        with (
            patch.object(cap.replay, "run", return_value=b""),
            self.assertRaisesRegex(ValueError, "incomplete causal"),
        ):
            cap.observe(Path("unused"), [], [b"positive"])
        with self.assertRaisesRegex(ValueError, "expected"):
            cap.require("clean", "sqli", "wrong rule")

    def test_lost_attack_variant_fails_even_when_content_is_allowed(self):
        rows = cap.load_variants(self.corpus, self.fixtures)
        with (
            patch.object(cap, "observe", return_value=["clean"] * len(rows)),
            self.assertRaisesRegex(ValueError, "attack variant lost detection"),
        ):
            cap.variant_report(Path("unused"), rows)


if __name__ == "__main__":
    unittest.main()
