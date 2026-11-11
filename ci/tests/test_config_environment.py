#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Keep configuration-exit leak handling scoped to the actual -t subprocess."""

from __future__ import annotations

import os
import unittest
from pathlib import Path
from unittest.mock import patch

from test_stats_zone import config_controls, config_test_environment


class ConfigEnvironmentTests(unittest.TestCase):
    def test_copy_keeps_runtime_policy_and_other_detectors(self):
        original = "halt_on_error=1:detect_leaks=1:abort_on_error=1"
        with patch.dict(
            os.environ, {"ASAN_OPTIONS": original, "UBSAN_OPTIONS": "halt_on_error=1"}
        ):
            environment = config_test_environment()
            self.assertEqual(environment["ASAN_OPTIONS"], original + ":detect_leaks=0")
            self.assertEqual(environment["UBSAN_OPTIONS"], "halt_on_error=1")
            self.assertEqual(os.environ["ASAN_OPTIONS"], original)

    def test_missing_policy(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(
                config_test_environment()["ASAN_OPTIONS"], "detect_leaks=0"
            )
            self.assertNotIn("ASAN_OPTIONS", os.environ)

    def test_actual_config_child_uses_scoped_environment(self):
        class ReachedChild(Exception):
            pass

        def child(command, **kwargs):
            self.assertEqual(command[-1], "-t")
            self.assertTrue(kwargs["env"]["ASAN_OPTIONS"].endswith(":detect_leaks=0"))
            self.assertIn("halt_on_error=1", kwargs["env"]["ASAN_OPTIONS"])
            raise ReachedChild

        with patch.dict(os.environ, {"ASAN_OPTIONS": "halt_on_error=1:detect_leaks=1"}):
            with (
                patch("test_stats_zone.subprocess.run", side_effect=child),
                self.assertRaises(ReachedChild),
            ):
                config_controls(Path("/inert-nginx"), None)
            self.assertEqual(
                os.environ["ASAN_OPTIONS"], "halt_on_error=1:detect_leaks=1"
            )


if __name__ == "__main__":
    unittest.main()
