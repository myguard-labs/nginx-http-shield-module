#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Keep configuration-exit leak handling scoped to the actual -t subprocess."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from test_stats_zone import (
    config_controls,
    config_test_environment,
    reload,
    wait_until_ready,
)


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


class ReloadReadiness(unittest.TestCase):
    def test_waits_for_every_old_worker(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "error.log"
            log.write_text("start worker process 11\nstart worker process 12\n")
            process = Mock()
            process.send_signal.side_effect = lambda _: log.write_text(
                log.read_text()
                + "signal 1 (SIGHUP) received, reconfiguring\nstart worker process 13\nmaster: reconfiguring\nworker process 11 exited with code 0\n"
            )

            drains = iter((12, 13))

            def drain(_) -> None:
                log.write_text(
                    log.read_text()
                    + f"worker process {next(drains)} exited with code 0\n"
                )

            with (
                patch("test_stats_zone.request", return_value=(200, b"after")),
                patch("test_stats_zone.time.sleep", side_effect=drain) as sleep,
            ):
                reload(1, process, root, "new config")
                self.assertEqual(sleep.call_count, 2)
            self.assertEqual((root / "nginx.conf").read_text(), "new config")


class StartupReadiness(unittest.TestCase):
    def run_wait(self, request_result, *, poll=None):
        process = Mock()
        process.poll.return_value = poll
        with tempfile.TemporaryFile(mode="w+") as stderr:
            stderr.write("startup failed")
            clock = iter((0.0, 0.0, 11.0))
            with (
                patch(
                    "test_stats_zone.time.monotonic",
                    side_effect=lambda: next(clock),
                ),
                patch("test_stats_zone.time.sleep"),
                patch("test_stats_zone.request", side_effect=request_result),
            ):
                return wait_until_ready(process, stderr, 1)

    def test_ready_response_returns(self):
        self.run_wait([(200, b"before")])

    def test_persistent_refusal_obeys_deadline(self):
        with self.assertRaises(TimeoutError):
            self.run_wait([ConnectionRefusedError])

    def test_wrong_response_obeys_deadline(self):
        with self.assertRaises(TimeoutError):
            self.run_wait([(503, b"later")])

    def test_early_exit_reports_stderr(self):
        with self.assertRaisesRegex(RuntimeError, "startup failed"):
            self.run_wait([], poll=1)


if __name__ == "__main__":
    unittest.main()
