#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise automaton ownership across a rejected nginx reload.

The decisive sequence needs process control that Test::Nginx cannot express:
build a candidate cycle through HTTP postconfiguration, reject it later while
opening a listener, keep serving from the unchanged old worker, then replace
only that worker before any successful reload.  The replacement must inherit
the old cycle from the same master and safely scan a nonempty request.

Run this with the repository's static ASan/UBSan nginx build.  ``--module`` is
available for a dynamic debug build, but the CI sanitizer build links shield
statically and therefore omits it.
"""

from __future__ import annotations

import argparse
import http.client
import os
import pathlib
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from typing import BinaryIO

MARKER = "union select password from users"
BLOCKED = 403
ALLOWED = 200
WAIT_S = 30.0


class Failure(Exception):
    """The runtime sequence did not satisfy its oracle."""


def request(port: int, query: str) -> int:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5.0)
    try:
        conn.request("GET", f"/scan?q={query}")
        response = conn.getresponse()
        response.read()
        return response.status
    finally:
        conn.close()


class Server:
    def __init__(self, nginx: str, module: str | None, port: int) -> None:
        self.nginx = os.path.abspath(nginx)
        self.module = os.path.abspath(module) if module else None
        self.port = port
        self.prefix = pathlib.Path(tempfile.mkdtemp(prefix="shield-reload-"))
        self.conf = self.prefix / "nginx.conf"
        self.stderr = self.prefix / "stderr.log"
        self.proc: subprocess.Popen[bytes] | None = None
        self.stderr_file: BinaryIO | None = None

    def write_config(self, rejected_port: int | None = None) -> None:
        load = f"load_module {self.module};\n" if self.module else ""
        rejected = ""
        if rejected_port is not None:
            rejected = f"""
    server {{
        listen 127.0.0.1:{rejected_port};
        location / {{ empty_gif; }}
    }}
"""
        self.conf.write_text(
            f"""daemon off;
master_process on;
worker_processes 1;
error_log {self.prefix}/error.log info;
pid {self.prefix}/nginx.pid;
{load}
events {{
    worker_connections 64;
}}

http {{
    access_log off;
    server {{
        listen 127.0.0.1:{self.port};
        location /scan {{
            shield block;
            shield_status 403;
            empty_gif;
        }}
    }}
{rejected}}}
"""
        )

    def start(self) -> None:
        (self.prefix / "logs").mkdir()
        self.write_config()
        self.stderr_file = self.stderr.open("wb")
        self.proc = subprocess.Popen(
            [self.nginx, "-p", str(self.prefix), "-c", str(self.conf)],
            stdout=subprocess.DEVNULL,
            stderr=self.stderr_file,
        )
        self.wait_until(
            lambda: (
                self.proc is not None
                and self.proc.poll() is not None
                or self.can_connect()
            ),
            "nginx startup",
        )
        if self.proc.poll() is not None:
            raise Failure(f"nginx exited during startup with {self.proc.returncode}")

    def can_connect(self) -> bool:
        try:
            with socket.create_connection(("127.0.0.1", self.port), 0.2):
                return True
        except OSError:
            return False

    def error_log(self) -> str:
        path = self.prefix / "error.log"
        return path.read_text(errors="replace") if path.exists() else ""

    def sanitizer_log(self) -> str:
        if self.stderr_file is not None:
            self.stderr_file.flush()
        return self.stderr.read_text(errors="replace") if self.stderr.exists() else ""

    def children(self) -> list[int]:
        assert self.proc is not None
        path = pathlib.Path(f"/proc/{self.proc.pid}/task/{self.proc.pid}/children")
        try:
            return [int(pid) for pid in path.read_text(encoding="ascii").split()]
        except FileNotFoundError:
            return []

    def sole_worker(self) -> int:
        workers = self.children()
        if len(workers) != 1:
            raise Failure(f"expected one worker child, found {workers}")
        return workers[0]

    def wait_until(self, predicate, what: str) -> None:
        deadline = time.monotonic() + WAIT_S
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.05)
        raise Failure(f"timed out waiting for {what}")

    def reload(self) -> None:
        assert self.proc is not None
        self.proc.send_signal(signal.SIGHUP)

    def stop(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGQUIT)
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        if self.stderr_file is not None:
            self.stderr_file.close()
            self.stderr_file = None

    def cleanup(self) -> None:
        shutil.rmtree(self.prefix, ignore_errors=True)


def expect_status(port: int, query: str, expected: int, where: str) -> None:
    try:
        actual = request(port, query)
    except OSError as exc:
        raise Failure(f"{where}: request failed: {exc}") from exc
    if actual != expected:
        raise Failure(f"{where}: status {actual}, want {expected}")


def test_rejected_reload_replacement(srv: Server) -> None:
    marker = MARKER.replace(" ", "%20")
    expect_status(srv.port, marker, BLOCKED, "initial shield scan")
    expect_status(srv.port, "harmless", ALLOWED, "initial clean control")

    assert srv.proc is not None
    master = srv.proc.pid
    old_worker = srv.sole_worker()

    occupied = socket.socket()
    occupied.bind(("127.0.0.1", 0))
    occupied.listen()
    rejected_port = occupied.getsockname()[1]
    try:
        srv.write_config(rejected_port)
        srv.reload()
        srv.wait_until(
            lambda: "still could not bind()" in srv.error_log(),
            "late reload rejection",
        )

        if srv.proc is None or srv.proc.pid != master:
            raise Failure("reload replaced the master process")
        if srv.sole_worker() != old_worker:
            raise Failure("rejected reload replaced the old worker")
        expect_status(
            srv.port,
            marker,
            BLOCKED,
            "unchanged old worker after rejected reload",
        )

        os.kill(old_worker, signal.SIGTERM)
        srv.wait_until(
            lambda: len(srv.children()) == 1 and srv.children()[0] != old_worker,
            "replacement worker from unchanged master",
        )
        replacement = srv.sole_worker()
        if srv.proc is None or srv.proc.pid != master:
            raise Failure("worker replacement changed the master process")

        expect_status(
            srv.port,
            marker,
            BLOCKED,
            "replacement worker scan before any successful reload",
        )
    finally:
        occupied.close()

    srv.write_config()
    srv.reload()
    srv.wait_until(
        lambda: len(srv.children()) == 1 and srv.children()[0] != replacement,
        "worker from successful reload",
    )
    expect_status(srv.port, marker, BLOCKED, "scan after successful reload")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nginx", required=True)
    parser.add_argument("--module")
    parser.add_argument("--port", type=int, default=19584)
    args = parser.parse_args()

    srv = Server(args.nginx, args.module, args.port)
    failed: Exception | None = None
    try:
        srv.start()
        test_rejected_reload_replacement(srv)
    except (Failure, OSError, http.client.HTTPException) as exc:
        failed = exc
        time.sleep(0.5)
    finally:
        srv.stop()

    errors = srv.error_log()
    sanitizer = srv.sanitizer_log()
    if failed is not None:
        print(f"FAIL test_rejected_reload_replacement: {failed}")
        print("\n--- nginx error.log ---")
        print(errors or "(empty)")
        print("\n--- nginx stderr / sanitizer output ---")
        print(sanitizer or "(empty)")
        srv.cleanup()
        return 1

    detector_output = errors + sanitizer
    if (
        "ERROR: AddressSanitizer" in detector_output
        or "runtime error:" in detector_output
    ):
        print("FAIL test_rejected_reload_replacement: sanitizer report on green path")
        print(sanitizer)
        srv.cleanup()
        return 1

    print("ok   test_rejected_reload_replacement")
    srv.cleanup()
    return 0


if __name__ == "__main__":
    sys.exit(main())
