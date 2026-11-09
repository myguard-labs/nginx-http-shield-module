#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the CI census, cadence and transitive runner checks."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        shutil.copytree(
            ROOT / ".github" / "workflows", self.root / ".github" / "workflows"
        )
        shutil.copytree(ROOT / "ci" / "tools", self.root / "ci" / "tools")

    def policy(self, name):
        return subprocess.run(
            ["python3", str(ROOT / "ci/linter/workflow_policy.py"), name],
            env={**os.environ, "WORKFLOW_POLICY_ROOT": str(self.root)},
            capture_output=True,
            text=True,
            check=False,
        )

    def runners(self):
        return subprocess.run(
            ["bash", str(self.root / "ci/tools/check-workflow-runners.sh")],
            capture_output=True,
            text=True,
            check=False,
        )

    def mutate(self, name, old, new):
        path = self.root / ".github/workflows" / name
        content = path.read_text()
        self.assertIn(old, content)
        path.write_text(content.replace(old, new, 1))

    def test_missing_job(self):
        self.assertEqual(self.policy("coverage").returncode, 0)
        self.mutate("build-test.yml", "  ban-unit:", "  removed-ban-unit:")
        result = self.policy("coverage")
        self.assertEqual(result.returncode, 1)
        self.assertIn("ban-unit: required job missing", result.stderr)

    def test_missing_required_trigger(self):
        self.mutate("ci-deep.yml", "  schedule:", "  disabled_schedule:")
        result = self.policy("coverage")
        self.assertEqual(result.returncode, 1)
        self.assertIn("ci-deep.yml: required schedule trigger missing", result.stderr)

    def test_missing_required_workflow(self):
        (self.root / ".github/workflows/valgrind.yml").unlink()
        result = self.policy("coverage")
        self.assertEqual(result.returncode, 1)
        self.assertIn("valgrind.yml: required workflow missing", result.stderr)

    def test_redirected_call(self):
        self.mutate("ci.yml", "workflows/asan.yml", "workflows/lint.yml")
        result = self.policy("coverage")
        self.assertEqual(result.returncode, 1)
        self.assertIn("required call to asan.yml missing", result.stderr)

    def test_duplicate_trigger(self):
        self.assertEqual(self.policy("cadence").returncode, 0)
        self.mutate("asan.yml", "  workflow_call:", "  push: {}\n  workflow_call:")
        result = self.policy("cadence")
        self.assertEqual(result.returncode, 1)
        self.assertIn("also triggers on `push`", result.stderr)

    def test_unsafe_called_runner(self):
        self.assertEqual(self.runners().returncode, 0)
        self.mutate("asan.yml", "runs-on: ubuntu-latest", "runs-on: self-hosted")
        result = self.runners()
        self.assertEqual(result.returncode, 1)
        self.assertIn("runner is not an approved hosted runner", result.stderr)

    def test_coverage_wrapper_checks_when_git_listing_fails(self):
        self.mutate("build-test.yml", "  ban-unit:", "  removed-ban-unit:")
        bindir = self.root / "bin"
        bindir.mkdir()
        git = bindir / "git"
        real_git = shutil.which("git")
        self.assertIsNotNone(real_git)
        git.write_text(
            '#!/bin/sh\nif [ "$1" = ls-files ]; then exit 42; fi\n'
            f'exec {real_git} "$@"\n'
        )
        git.chmod(0o755)
        env = {
            **os.environ,
            "WORKFLOW_POLICY_ROOT": str(self.root),
            "PATH": f"{bindir}:{os.environ['PATH']}",
            "LINT_MODE": "all",
        }
        result = subprocess.run(
            ["bash", str(ROOT / "ci/linter/lint-ci-coverage.sh")],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("ban-unit: required job missing", result.stderr)

    def test_missing_callee_fails_closed(self):
        self.mutate("ci.yml", "workflows/asan.yml", "workflows/missing.yml")
        self.assertNotEqual(self.runners().returncode, 0)


if __name__ == "__main__":
    unittest.main()
