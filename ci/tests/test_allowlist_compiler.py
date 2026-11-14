#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise compiler argv handling in the direct-call harness."""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class CompilerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "ci/t").mkdir(parents=True)
        shutil.copy(ROOT / "ci/t/run-allowlist-unit.sh", self.root / "ci/t")
        self.compiler = self.root / "fake compiler"
        self.compiler.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, pathlib, sys\n"
            "with open(os.environ['CALLS'], 'a') as out:\n"
            "    out.write(json.dumps(sys.argv[1:]) + '\\n')\n"
            "if '--version' in sys.argv:\n"
            "    print('gcc')\n"
            "else:\n"
            "    binary = pathlib.Path(sys.argv[sys.argv.index('-o') + 1])\n"
            "    binary.write_text('#!/bin/sh\\nexit 0\\n')\n"
            "    binary.chmod(0o755)\n"
        )
        self.compiler.chmod(0o755)
        self.calls = self.root / "calls"

    def run_runner(self, cc):
        env = os.environ.copy()
        env.update(CC=cc, CALLS=str(self.calls), EXTRA_CFLAGS="--coverage")
        return subprocess.run(
            ["bash", str(self.root / "ci/t/run-allowlist-unit.sh"), str(self.root)],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_plain_and_launcher_options_are_passed_to_both_calls(self):
        for prefix, expected in (
            (f"'{self.compiler}'", []),
            (
                f"'{self.compiler}' 'compiler option' -DNAME=1",
                ["compiler option", "-DNAME=1"],
            ),
        ):
            with self.subTest(prefix=prefix):
                self.calls.unlink(missing_ok=True)
                result = self.run_runner(prefix)
                self.assertEqual(result.returncode, 0, result.stderr)
                calls = [
                    json.loads(line) for line in self.calls.read_text().splitlines()
                ]
                self.assertEqual(calls[0], [*expected, "--version"])
                self.assertEqual(calls[1][: len(expected)], expected)
                self.assertIn("--coverage", calls[1])
                self.assertIn("--param=asan-globals=0", calls[1])

    def test_empty_malformed_and_command_substitution(self):
        for cc in ("", "   ", "'unterminated"):
            with self.subTest(cc=cc):
                result = self.run_runner(cc)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.calls.exists())
        marker = self.root / "executed"
        result = self.run_runner(f"'{self.compiler}' '$(touch {marker})'")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(marker.exists())
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertEqual(calls[0][0], f"$(touch {marker})")


if __name__ == "__main__":
    unittest.main()
