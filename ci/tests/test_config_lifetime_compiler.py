#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Compiler selection for the configuration lifetime harness."""

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "config_lifetime", ROOT / "ci/t/run-config-lifetime.py"
)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class CompilerSelectionTests(unittest.TestCase):
    def test_configured_default_and_override(self):
        for configured, environment, expected in (
            ("clang --driver-mode=gcc", {}, ["clang", "--driver-mode=gcc"]),
            ("cc", {}, ["cc"]),
            ("clang", {"CC": "ccache gcc"}, ["ccache", "gcc"]),
        ):
            with (
                self.subTest(configured=configured, environment=environment),
                patch.dict(os.environ, environment, clear=True),
            ):
                self.assertEqual(
                    RUNNER.compiler_command(f"CC = {configured}\n"), expected
                )

    def test_malformed_and_empty_commands(self):
        for makefile, environment in (
            ("CFLAGS = -O2\n", {}),
            ("CC =\n", {}),
            ("CC = 'unterminated\n", {}),
            ("CC = cc\n", {"CC": ""}),
            ("CC = cc\n", {"CC": "'unterminated"}),
        ):
            with (
                self.subTest(makefile=makefile, environment=environment),
                patch.dict(os.environ, environment, clear=True),
                self.assertRaises(ValueError),
            ):
                RUNNER.compiler_command(makefile)

    def test_selected_compiler_drives_compile_and_link(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree = Path(tmp) / "tree"
            (tree / "objs").mkdir(parents=True)
            (tree / "src").mkdir()
            (tree / "objs/Makefile").write_text(
                "CC = configured-clang\nCFLAGS = -O2\nALL_INCS =\n"
                "\t$(LINK) -o objs/nginx objs/src/core/nginx.o "
                "objs/addon/src/ngx_http_shield_module.o\n"
            )
            commands = []

            def capture(command, output, label, cwd):
                commands.append((label, command))
                return 0

            with (
                patch.dict(os.environ, {}, clear=True),
                patch.object(
                    sys, "argv", ["runner", str(tree), "--output", tmp + "/out"]
                ),
                patch.object(RUNNER, "digest", return_value="hash"),
                patch.object(RUNNER, "run", side_effect=capture),
                self.assertRaises(FileNotFoundError),
            ):
                RUNNER.main()
            self.assertEqual(
                [label for label, _ in commands],
                ["compile-driver", "compile-module", "link-driver"],
            )
            for _, command in commands:
                self.assertEqual(command[0], "configured-clang")


if __name__ == "__main__":
    unittest.main()
