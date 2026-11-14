# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Check the allowlist driver's Python assertion requirement."""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

DRIVER = Path(__file__).with_name("test_allowlist.py")


class AllowlistModeTest(unittest.TestCase):
    def test_python_optimization_refused_before_nginx(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sentinel = root / "started"
            nginx = root / "nginx"
            nginx.write_text(f"#!/bin/sh\ntouch '{sentinel}'\n")
            nginx.chmod(0o755)
            base_env = os.environ.copy()
            base_env.pop("PYTHONOPTIMIZE", None)
            normal = subprocess.run(
                [sys.executable, str(DRIVER), "--help"],
                env=base_env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(normal.returncode, 0, normal.stderr)
            for flag, env_value in (
                ("-O", None),
                ("-OO", None),
                (None, "1"),
                (None, "2"),
            ):
                with self.subTest(flag=flag, env_value=env_value):
                    env = base_env.copy()
                    if env_value:
                        env["PYTHONOPTIMIZE"] = env_value
                    command = [sys.executable]
                    if flag:
                        command.append(flag)
                    command.extend(
                        [
                            str(DRIVER),
                            "--nginx",
                            str(nginx),
                            "--config-only",
                            "--output",
                            str(root / "output"),
                        ]
                    )
                    result = subprocess.run(
                        command,
                        env=env,
                        capture_output=True,
                        text=True,
                        check=False,
                        timeout=10,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("requires Python assertions", result.stderr)
                    self.assertFalse(sentinel.exists(), "nginx started")
                    self.assertFalse((root / "output").exists(), "output created")


if __name__ == "__main__":
    unittest.main()
