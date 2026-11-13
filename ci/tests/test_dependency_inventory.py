#!/usr/bin/env python3
"""Causal controls for the dependency inventory and OSV receipt gate."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
CHECK = ROOT / "ci/tools/check-advisories.py"
INVENTORY = ROOT / "ci/dependency-inventory.json"


def load_checker():
    spec = importlib.util.spec_from_file_location("check_advisories", CHECK)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DependencyInventoryTest(unittest.TestCase):
    def run_check(
        self,
        response: dict[str, object],
        inventory: dict[str, object] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "response.json"
            path.write_text(json.dumps(response), encoding="utf-8")
            inventory_path = INVENTORY
            if inventory is not None:
                inventory_path = pathlib.Path(tmp) / "inventory.json"
                inventory_path.write_text(json.dumps(inventory), encoding="utf-8")
            return subprocess.run(
                [
                    "python3",
                    str(CHECK),
                    "--inventory",
                    str(inventory_path),
                    "--response",
                    str(path),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

    def count(self) -> int:
        return len(json.loads(INVENTORY.read_text(encoding="utf-8"))["dependencies"])

    def test_clean_complete_response_passes(self) -> None:
        result = self.run_check({"results": [{} for _ in range(self.count())]})
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt["dependency_count"], self.count())
        self.assertEqual(receipt["undisposed_count"], 0)

    def test_advisory_hit_blocks(self) -> None:
        results = [{} for _ in range(self.count())]
        results[0] = {"vulns": [{"id": "OSV-TEST-1"}]}
        result = self.run_check({"results": results})
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("nginx-mainline", result.stderr)

    def test_pcre2_osv_2026_343_causal_fix_is_retained(self) -> None:
        results = [{} for _ in range(self.count())]
        inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
        index = next(
            i for i, dep in enumerate(inventory["dependencies"]) if dep["id"] == "pcre2"
        )
        results[index] = {"vulns": [{"id": "OSV-2026-343"}]}
        result = self.run_check({"results": results})
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt["observed_vulnerability_count"], 1)
        self.assertEqual(receipt["undisposed_count"], 0)
        pcre2 = next(dep for dep in receipt["dependencies"] if dep["id"] == "pcre2")
        self.assertEqual(pcre2["dispositions"][0]["status"], "fixed")
        self.assertEqual(
            pcre2["dispositions"][0]["fixed_commit"],
            "ec9c286d5c10cf1c388b58a442ccefded42254fd",
        )

    def test_free_form_not_affected_disposition_is_rejected(self) -> None:
        inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
        disposition = inventory["advisory_dispositions"][0]
        disposition["status"] = "not_affected"
        disposition.pop("fixed_commit")
        result = self.run_check(
            {"results": [{} for _ in range(self.count())]}, inventory
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("unsupported advisory disposition status", result.stderr)

    def test_fixed_disposition_requires_full_commit(self) -> None:
        inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
        inventory["advisory_dispositions"][0]["fixed_commit"] = "ec9c286d"
        result = self.run_check(
            {"results": [{} for _ in range(self.count())]}, inventory
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("requires a full fix commit", result.stderr)

    def test_fixed_disposition_is_bound_to_reviewed_dependency_commit(self) -> None:
        inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
        pcre2 = next(
            dependency
            for dependency in inventory["dependencies"]
            if dependency["id"] == "pcre2"
        )
        affected = "a2b146a3245a930aa4c8ea8b33c0d83092daa7c9"
        pcre2["resolved_commit"] = affected
        pcre2["osv_query"]["commit"] = affected
        result = self.run_check(
            {"results": [{} for _ in range(self.count())]}, inventory
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("not bound to the resolved dependency commit", result.stderr)

    def test_workflow_actions_must_all_be_in_inventory(self) -> None:
        inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
        inventory["dependencies"] = [
            dependency
            for dependency in inventory["dependencies"]
            if dependency["id"] != "actions-cache"
        ]
        result = self.run_check(
            {"results": [{} for _ in range(self.count())]}, inventory
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("workflow action inventory mismatch", result.stderr)
        self.assertIn("actions/cache", result.stderr)

    def test_quoted_workflow_action_is_accounted_for(self) -> None:
        checker = load_checker()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            workflow = root / ".github/workflows/test.yml"
            workflow.parent.mkdir(parents=True)
            commit = "1" * 40
            workflow.write_text(
                f'jobs:\n  test:\n    steps:\n      - uses: "owner/action@{commit}"\n',
                encoding="utf-8",
            )
            (root / "pin.txt").write_text(f"pin={commit}\n", encoding="utf-8")
            inventory = {
                "schema_version": 1,
                "dependencies": [
                    {
                        "id": "quoted-action",
                        "scope": "ci-action",
                        "upstream": "https://github.com/owner/action",
                        "resolved_commit": commit,
                        "osv_query": {"commit": commit},
                    }
                ],
                "pin_checks": [
                    {
                        "path": "pin.txt",
                        "pattern": r"pin=([0-9a-f]{40})",
                        "expected": commit,
                    }
                ],
            }
            self.assertEqual(
                checker.validate_inventory(inventory, root),
                inventory["dependencies"],
            )

    def test_missing_result_is_unavailable_not_clean(self) -> None:
        result = self.run_check({"results": []})
        self.assertEqual(result.returncode, 2)
        self.assertIn("result count mismatch", result.stderr)

    def test_malformed_vulnerability_is_unavailable_not_clean(self) -> None:
        results = [{} for _ in range(self.count())]
        results[0] = {"vulns": [{}]}
        result = self.run_check({"results": results})
        self.assertEqual(result.returncode, 2)
        self.assertIn("malformed OSV vulnerability row", result.stderr)

    def test_paginated_result_is_unavailable_not_clean(self) -> None:
        results = [{} for _ in range(self.count())]
        results[0] = {"next_page_token": "more"}
        result = self.run_check({"results": results})
        self.assertEqual(result.returncode, 2)
        self.assertIn("paginated OSV result is unsupported", result.stderr)


if __name__ == "__main__":
    unittest.main()
