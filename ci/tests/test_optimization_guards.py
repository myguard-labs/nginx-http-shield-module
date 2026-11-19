# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Inert controls for assertion-dependent test drivers."""

import ast
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DRIVERS = (ROOT / "ci/t/callback-reset/run.py", ROOT / "ci/tests/test_cve_controls.py")


def function(path, name, env):
    tree = ast.parse(path.read_text(), filename=str(path))
    nodes = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == name
    ]
    if len(nodes) != 1:
        raise RuntimeError(f"expected one {name} in {path}")
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), "exec"), env)  # noqa: S102
    return env[name]


class OptimizationGuards(unittest.TestCase):
    def test_optimized_import_rejected_before_driver_work(self):
        for path in DRIVERS:
            for mode in ("-O", "-OO", "env1", "env2"):
                with self.subTest(driver=path.name, mode=mode):
                    env = os.environ.copy()
                    env.pop("PYTHONOPTIMIZE", None)
                    flag = []
                    if mode.startswith("env"):
                        env["PYTHONOPTIMIZE"] = mode[-1]
                    else:
                        flag = [mode]
                    result = subprocess.run(
                        [
                            sys.executable,
                            *flag,
                            "-c",
                            "import runpy,sys; sys.path.insert(0, sys.argv[1]); runpy.run_path(sys.argv[2], run_name='inert_control')",
                            str(path.parent),
                            str(path),
                        ],
                        env=env,
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("requires Python assertions enabled", result.stderr)

    def test_callback_response_oracles(self):
        check = function(DRIVERS[0], "check_response", {})
        good = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        check(good, 200, b"ok")
        for response, status, body in (
            (good, 403, b"ok"),
            (good, 200, b"no"),
            (b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok", 200, b"ok"),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nok",
                200,
                b"ok",
            ),
            (b"HTTP/1.1 200 OK", 200, b"ok"),
        ):
            with (
                self.subTest(response=response, status=status, body=body),
                self.assertRaises(AssertionError),
            ):
                check(response, status, body)

    def test_cve_status_oracle(self):
        env = {
            "root": Path("/nonexistent-inert-control"),
            "port": 0,
            "EXPECTED_HITS": {},
            "results": [],
            "request": lambda *args: (200, b""),
            "json": json,
        }
        check = function(DRIVERS[1], "check", env)
        check("positive", "/", 200, hit=False)
        with self.assertRaises(AssertionError):
            check("wrong-status", "/", 403, hit=False)


if __name__ == "__main__":
    unittest.main()
