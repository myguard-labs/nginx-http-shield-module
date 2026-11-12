# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Regression tests for the generated Makefile dependency checker."""

import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
CHECKER = ROOT / "ci/tests/test_module_dependencies.py"


class ModuleDependenciesTests(unittest.TestCase):
    def check_makefile(self, link, rules, deps=None, headers=True):
        header_list = " ".join(str(path) for path in (ROOT / "src").glob("*.h"))
        if not headers:
            header_list = ""
        if deps is None:
            deps = " ".join(
                token for token in link.split() if token.endswith("/libz.a")
            )
        text = (
            f"ADDON_DEPS = {header_list}\n"
            f"objs/ngx_http_shield_module.so: {deps}\n\tcc -shared {link}\n{rules}"
        )
        with tempfile.TemporaryDirectory() as directory:
            makefile = pathlib.Path(directory) / "Makefile"
            makefile.write_text(text, encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(CHECKER), str(makefile)],
                capture_output=True,
                text=True,
                check=False,
            )

    def test_unrelated_pic_does_not_validate_archive(self):
        result = self.check_makefile(
            "/z/libz.a",
            '/z/libz.a:\n\tCFLAGS="-O2" ./configure\nother:\n\tCFLAGS="-O2 -fPIC" ./configure\n',
        )
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertIn("must be built as PIC", result.stderr)

    def test_each_archive_needs_pic(self):
        rules = '/a/libz.a:\n\tCFLAGS="-fPIC" ./configure\n/b/libz.a:\n\tCFLAGS="-O2" ./configure\n'
        self.assertNotEqual(
            self.check_makefile("/a/libz.a /b/libz.a", rules).returncode, 0
        )
        self.assertEqual(
            self.check_makefile(
                "/a/libz.a /b/libz.a", rules.replace("-O2", "-O2 -fPIC")
            ).returncode,
            0,
        )

    def test_flag_tokens_and_continuations(self):
        for flags, valid in [
            ("-fPIC", True),
            ("-O2 -fPIC -g", True),
            ("-fPICextra", False),
            ("-fpic", False),
            ("", False),
        ]:
            with self.subTest(flags=flags):
                rules = (
                    f'/z/libz.a: dep\n\tcd /z \\\n\t&& CFLAGS="{flags}" ./configure\n'
                )
                result = self.check_makefile("/z/libz.a", rules)
                self.assertEqual(result.returncode == 0, valid, result.stderr)

    def test_missing_rule_dependency_and_headers_fail(self):
        self.assertNotEqual(self.check_makefile("/z/libz.a", "").returncode, 0)
        self.assertNotEqual(
            self.check_makefile(
                "/z/libz.a", '/z/libz.a:\n\tCFLAGS="-fPIC" ./configure\n', deps=""
            ).returncode,
            0,
        )
        self.assertNotEqual(self.check_makefile("-lz", "", headers=False).returncode, 0)

    def test_system_zlib(self):
        self.assertEqual(self.check_makefile("-lz", "").returncode, 0)
        self.assertNotEqual(self.check_makefile("module.o", "").returncode, 0)


if __name__ == "__main__":
    unittest.main()
