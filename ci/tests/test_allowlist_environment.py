#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the actual workflow shell with recording child processes."""

import json
import os
import re
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/build-test.yml"


class AllowlistEnvironmentTests(unittest.TestCase):
    def run_step(self, options, *, mode="asan", fail_live=False):
        workflow = Path(os.environ.get("ALLOWLIST_WORKFLOW", WORKFLOW)).read_text()
        match = re.search(
            r"      - name: Check metric counters, slab pressure and concurrent snapshots\n"
            r"(?P<step>.*?)(?=\n      - name:)",
            workflow,
            re.DOTALL,
        )
        self.assertIsNotNone(match)
        step = match.group("step")
        self.assertIn("ASAN_OPTIONS: halt_on_error=1:abort_on_error=1", step)
        script = textwrap.dedent(step.split("        run: |\n", 1)[1])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bindir = root / "bin"
            bindir.mkdir()
            recorder = bindir / "python3"
            recorder.write_text(
                "#!/usr/bin/python3\n"
                "import json, os, sys\n"
                "with open(os.environ['RECORD'], 'a') as f:\n"
                "    f.write(json.dumps([sys.argv[1:], os.environ.get('ASAN_OPTIONS'), "
                "os.environ.get('UBSAN_OPTIONS')]) + '\\n')\n"
                "if os.environ.get('FAIL_LIVE') and 'ci/tests/test_allowlist.py' in sys.argv:\n"
                "    sys.exit(23)\n"
            )
            recorder.chmod(0o755)
            (bindir / "bash").symlink_to(recorder)
            build = root / f".build/nginx-test-{mode}/objs"
            build.mkdir(parents=True)
            binary = build / "nginx"
            binary.touch(mode=0o755)
            record = root / "record"
            env = os.environ.copy()
            env.update(
                PATH=f"{bindir}:{env['PATH']}",
                RECORD=str(record),
                MATRIX_FLAVOR="nginx",
                MATRIX_MODE=mode,
                VER="test",
                ASAN_OPTIONS=options,
                UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1",
            )
            if fail_live:
                env["FAIL_LIVE"] = "1"
            result = subprocess.run(
                ["/bin/bash", "-eo", "pipefail", "-c", script],
                cwd=root,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            children = [json.loads(line) for line in record.read_text().splitlines()]
            return result, children

    def test_live_scope_and_following_direct_child(self):
        for options in (
            "halt_on_error=1:abort_on_error=1",
            "detect_leaks=1:halt_on_error=1:abort_on_error=1",
        ):
            for mode in ("asan", "release"):
                with self.subTest(options=options, mode=mode):
                    result, children = self.run_step(options, mode=mode)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(len(children), 4)
                    self.assertIn("test_allowlist.py", children[2][0][0])
                    self.assertIn("run-allowlist-unit.sh", children[3][0][0])
                    self.assertEqual(children[2][1], options + ":detect_leaks=0")
                    for child in (children[3], children[0], children[1]):
                        self.assertEqual(child[1], options)
                    for child in children:
                        self.assertEqual(child[2], "halt_on_error=1:print_stacktrace=1")

    def test_live_failure_stops_before_direct_child(self):
        result, children = self.run_step(
            "detect_leaks=1:halt_on_error=1:abort_on_error=1", fail_live=True
        )
        self.assertEqual(result.returncode, 23)
        self.assertEqual(len(children), 3)
        self.assertTrue(children[-1][1].endswith(":detect_leaks=0"))


if __name__ == "__main__":
    unittest.main()
