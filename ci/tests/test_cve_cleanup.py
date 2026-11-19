# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Lifecycle controls for the CVE driver's owned subprocess."""

import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from test_cve_controls import cleanup_process


class CleanupProcessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "error.log").write_text("")
        self.stderr = self.enterContext(tempfile.TemporaryFile(mode="w+"))

    def child(self, body):
        process = subprocess.Popen(
            [sys.executable, "-u", "-c", body],
            stdout=subprocess.PIPE,
            stderr=self.stderr,
            text=True,
        )
        self.addCleanup(self.reap_if_needed, process)
        self.addCleanup(process.stdout.close)
        self.assertEqual(process.stdout.readline().strip(), "ready")
        return process

    @staticmethod
    def reap_if_needed(process):
        if process.poll() is None:
            process.kill()
        process.wait()

    def test_graceful_cleanup(self):
        process = self.child(
            "import signal,time; signal.signal(signal.SIGQUIT, "
            "lambda *_: exit(0)); print('ready'); time.sleep(30)"
        )
        cleanup_process(process, self.stderr, self.root)
        self.assertEqual(process.returncode, 0)

    def test_startup_and_request_exceptions_still_cleanup(self):
        for phase in ("startup", "request"):
            with self.subTest(phase=phase):
                process = self.child(
                    "import signal,time; signal.signal(signal.SIGQUIT, "
                    "lambda *_: exit(0)); print('ready'); time.sleep(30)"
                )
                with self.assertRaisesRegex(ValueError, f"^{phase} failed$"):
                    try:
                        raise ValueError(f"{phase} failed")
                    finally:
                        cleanup_process(process, self.stderr, self.root)
                self.assertEqual(process.returncode, 0)

    def test_already_exited(self):
        process = self.child("print('ready')")
        process.wait()
        cleanup_process(process, self.stderr, self.root)
        self.assertEqual(process.returncode, 0)

    def test_timeout_kills_and_reaps_owned_child(self):
        process = self.child(
            "import signal,time; signal.signal(signal.SIGQUIT, signal.SIG_IGN); "
            "print('ready'); time.sleep(30)"
        )
        with self.assertRaises(subprocess.TimeoutExpired):
            cleanup_process(process, self.stderr, self.root, timeout=0.05)
        self.assertEqual(process.returncode, -signal.SIGKILL)
        with self.assertRaises(ChildProcessError):
            import os

            os.waitpid(process.pid, os.WNOHANG)

    def test_sanitizer_and_abnormal_exit_failures(self):
        for log, status in (
            ("AddressSanitizer: error", 0),
            ("runtime error: bad", 0),
            ("", 3),
        ):
            with self.subTest(log=log, status=status):
                (self.root / "error.log").write_text(log)
                process = self.child(f"print('ready'); raise SystemExit({status})")
                process.wait()
                with self.assertRaises(AssertionError):
                    cleanup_process(process, self.stderr, self.root)


if __name__ == "__main__":
    unittest.main()
