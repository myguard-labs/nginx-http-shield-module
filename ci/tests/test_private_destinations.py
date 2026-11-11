#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise native destination permissions with real unprivileged HTTP workers."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import pwd
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import contextmanager
from pathlib import Path

RECIPE = Path(__file__).resolve().parents[2] / "contrib/private-destinations"
PRIVATE = b"PRIVATE-INVOICE-8b29da04\x00\xff\n"
PUBLIC = b"PUBLIC-ASSET-57ca19e0\x00\xfe\n"
PRIVATE_ROUTES = (
    "/vault/invoice.txt",
    "/%76ault/invoice.txt",
    "/download.txt",
    "/down%6coad.txt",
    "/rewrite.txt",
    "/jump.txt",
    "/error.txt",
    "/named.txt",
    "/file-link.txt",
    "/dir-link/invoice.txt",
    "/standalone.txt",
    "/hardlink.txt",
)
PUBLIC_ROUTES = (
    "/asset.txt",
    "/assets/asset.txt",
    "/public-rewrite.txt",
    "/public-jump.txt",
    "/public-error.txt",
    "/public-named.txt",
    "/public-link.txt",
    "/mixed-owner-link.txt",
    "/public-dir/asset.txt",
    "/public-hardlink.txt",
    "/public/%61sset.txt",
)
OPTIONS: argparse.Namespace


class Site:
    """Own one master, its temporary filesystem, and byte-level response receipts."""

    def __init__(self, root: Path, protected: bool, symlinks: str = "off"):
        self.root = root
        self.process: subprocess.Popen | None = None
        self.responses: list[dict] = []
        root.mkdir(mode=0o755)
        root.chmod(0o755)
        for name in ("public", "vault"):
            (root / name).mkdir(mode=0o755)
            (root / name).chmod(0o755)
        (root / "public/asset.txt").write_bytes(PUBLIC)
        (root / "vault/invoice.txt").write_bytes(PRIVATE)
        (root / "standalone.txt").write_bytes(PRIVATE)
        os.link(root / "standalone.txt", root / "public/hardlink.txt")
        os.link(root / "public/asset.txt", root / "public/public-hardlink.txt")
        for name, target in (
            ("file-link.txt", root / "vault/invoice.txt"),
            ("dir-link", root / "vault"),
            ("public-link.txt", root / "public/asset.txt"),
            ("mixed-owner-link.txt", root / "public/asset.txt"),
            ("public-dir", root / "public"),
        ):
            (root / "public" / name).symlink_to(target)
        worker = pwd.getpwnam("www-data")
        os.chown(
            root / "public/mixed-owner-link.txt",
            worker.pw_uid,
            worker.pw_gid,
            follow_symlinks=False,
        )
        # Explicit modes do not depend on the caller's umask. All data is root-owned;
        # only the mixed-owner *link*, never its target, belongs to the worker.
        for name in ("public/asset.txt", "vault/invoice.txt", "standalone.txt"):
            (root / name).chmod(0o644)
        if protected:
            (root / "vault").chmod(0o700)
            (root / "vault/invoice.txt").chmod(0o600)
            (root / "standalone.txt").chmod(0o600)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            self.port = listener.getsockname()[1]
        # Copy the include so nginx's worker can traverse it even if the source
        # checkout is under a private parent. Never modify the source recipe.
        (root / "serving.conf").write_bytes((RECIPE / "serving.conf").read_bytes())
        (root / "serving.conf").chmod(0o644)
        override = f"disable_symlinks {symlinks};" if symlinks != "off" else ""
        if symlinks == "cache-control":
            override = "open_file_cache max=16 inactive=1m; open_file_cache_valid 1m;"
        configuration = f"""user www-data www-data;
worker_processes 1;
daemon off;
pid {root}/nginx.pid;
error_log {root}/error.log notice;
events {{ worker_connections 64; }}
http {{
    access_log off;
    client_body_temp_path {root}/body;
    proxy_temp_path {root}/proxy;
    fastcgi_temp_path {root}/fastcgi;
    uwsgi_temp_path {root}/uwsgi;
    scgi_temp_path {root}/scgi;
    include "{root}/serving.conf";
    server {{
        listen 127.0.0.1:{self.port};
        root {root}/public;
        {override}
        location = /ready {{ return 200 ready; }}
        location / {{ }}
        location /vault/ {{ root {root}; }}
        location /public/ {{ alias {root}/public/; }}
        location /assets/ {{ alias {root}/public/; }}
        location = /download.txt {{ alias {root}/vault/invoice.txt; }}
        location = /standalone.txt {{ alias {root}/standalone.txt; }}
        location = /rewrite.txt {{ rewrite ^ /download.txt last; }}
        location = /jump.txt {{ rewrite ^ /internal-private last; }}
        location = /internal-private {{ internal; alias {root}/vault/invoice.txt; }}
        location = /error.txt {{ error_page 418 = /internal-private; return 418; }}
        location = /named.txt {{ try_files /absent @private; }}
        location @private {{ root {root}; try_files /vault/invoice.txt =404; }}
        location = /public-rewrite.txt {{ rewrite ^ /asset.txt last; }}
        location = /public-jump.txt {{ rewrite ^ /internal-public last; }}
        location = /internal-public {{ internal; alias {root}/public/asset.txt; }}
        location = /public-error.txt {{ error_page 418 = /internal-public; return 418; }}
        location = /public-named.txt {{ try_files /absent @public; }}
        location @public {{ try_files /asset.txt =404; }}
    }}
}}
"""
        self.configuration = root / "nginx.conf"
        self.configuration.write_text(configuration, encoding="utf-8")
        identities = {}
        for name in (
            "public/asset.txt",
            "vault/invoice.txt",
            "standalone.txt",
            "public/hardlink.txt",
        ):
            path = root / name
            stat = path.stat()
            identities[name] = {
                "device": stat.st_dev,
                "inode": stat.st_ino,
                "mode": oct(stat.st_mode & 0o777),
                "uid": stat.st_uid,
                "gid": stat.st_gid,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        (root / "identities.json").write_text(json.dumps(identities, indent=2) + "\n")

    def start(self):
        command = [
            str(OPTIONS.nginx),
            "-p",
            str(self.root),
            "-c",
            str(self.configuration),
        ]
        with (self.root / "config-test.log").open("wb") as log:
            subprocess.run(
                command + ["-t"], check=True, stdout=log, stderr=log, timeout=10
            )
        with (self.root / "master.log").open("wb") as log:
            self.process = subprocess.Popen(command, stdout=log, stderr=log)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError("HTTP master exited before readiness")
            try:
                if self.request("/ready")[0] == 200:
                    return
            except ConnectionRefusedError:
                time.sleep(0.02)
        raise RuntimeError("HTTP worker readiness deadline exceeded")

    def request(self, path: str, method: str = "GET", headers: dict | None = None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.request(method, path, headers=headers or {})
            response = connection.getresponse()
            body = response.read()
            result = (response.status, body, dict(response.getheaders()))
        finally:
            connection.close()
        self.responses.append(
            {
                "path": path,
                "method": method,
                "headers": headers or {},
                "status": result[0],
                "body_hex": body.hex(),
                "body_sha256": hashlib.sha256(body).hexdigest(),
            }
        )
        return result

    def close(self):
        if self.process is not None:
            if self.process.poll() is None:
                self.process.send_signal(signal.SIGQUIT)
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
                raise
        (self.root / "responses.json").write_text(
            json.dumps(self.responses, indent=2) + "\n"
        )


@contextmanager
def site(name: str, protected: bool = True, symlinks: str = "off"):
    fixture = Site(OPTIONS.output / name, protected, symlinks)
    try:
        fixture.start()
        yield fixture
    finally:
        fixture.close()


class PrivateDestinations(unittest.TestCase):
    def test_private(self):
        with site("private", protected=not OPTIONS.disable_permissions) as fixture:
            for path in PRIVATE_ROUTES:
                with self.subTest(path=path):
                    status, body, _ = fixture.request(path)
                    self.assertNotIn(PRIVATE, body)
                    self.assertIn(status, (403, 404))

    def test_public(self):
        expected = (
            b"DELIBERATELY-WRONG-IDENTITY" if OPTIONS.wrong_public_oracle else PUBLIC
        )
        with site("public") as fixture:
            for path in PUBLIC_ROUTES:
                with self.subTest(path=path):
                    status, body, _ = fixture.request(path)
                    self.assertEqual(status, 200)
                    self.assertEqual(body, expected)

    def test_disabled_permissions_leak_same_destinations(self):
        with site("disabled", protected=False) as fixture:
            for path in PRIVATE_ROUTES:
                with self.subTest(path=path):
                    status, body, _ = fixture.request(path)
                    self.assertEqual(status, 200)
                    self.assertEqual(body, PRIVATE)

    def test_native_symlink_scope(self):
        # DAC-disabled data deliberately isolates the symlink control's scope.
        for policy in ("off", "if_not_owner", "on"):
            with site(
                f"symlinks-{policy}", protected=False, symlinks=policy
            ) as fixture:
                for path, allowed in (
                    ("/file-link.txt", policy != "on"),
                    ("/public-link.txt", policy != "on"),
                    ("/mixed-owner-link.txt", policy == "off"),
                    ("/dir-link/invoice.txt", policy != "on"),
                ):
                    with self.subTest(policy=policy, path=path):
                        status, body, _ = fixture.request(path)
                        if allowed:
                            self.assertEqual(status, 200)
                            self.assertEqual(
                                body,
                                PRIVATE
                                if "public" not in path and "mixed" not in path
                                else PUBLIC,
                            )
                        else:
                            self.assertIn(status, (403, 404))
                            self.assertNotIn(PRIVATE, body)

    def test_cached_descriptor_control(self):
        for cached in (False, True):
            with site(
                f"cache-{cached}",
                protected=False,
                symlinks="cache-control" if cached else "off",
            ) as fixture:
                self.assertEqual(fixture.request("/standalone.txt")[:2], (200, PRIVATE))
                (fixture.root / "standalone.txt").chmod(0o600)
                status, body, _ = fixture.request("/standalone.txt")
                if cached:
                    self.assertEqual((status, body), (200, PRIVATE))
                else:
                    self.assertIn(status, (403, 404))
                    self.assertNotIn(PRIVATE, body)

    def test_independent_dac_layers(self):
        with site("dac-layers") as fixture:
            # Search permission alone cannot bypass the private file's read mode.
            (fixture.root / "vault").chmod(0o755)
            self.assertIn(fixture.request("/vault/invoice.txt")[0], (403, 404))
            # A readable file alone cannot bypass its private parent directory.
            (fixture.root / "vault").chmod(0o700)
            (fixture.root / "vault/invoice.txt").chmod(0o644)
            self.assertIn(fixture.request("/vault/invoice.txt")[0], (403, 404))
            (fixture.root / "vault").chmod(0o755)
            self.assertEqual(fixture.request("/vault/invoice.txt")[:2], (200, PRIVATE))

    def test_restrictive_umask(self):
        previous = os.umask(0o077)
        try:
            with site("restrictive-umask", protected=False) as fixture:
                for path, expected in (
                    ("/asset.txt", PUBLIC),
                    ("/vault/invoice.txt", PRIVATE),
                    ("/hardlink.txt", PRIVATE),
                    ("/public-link.txt", PUBLIC),
                ):
                    with self.subTest(path=path):
                        self.assertEqual(fixture.request(path)[:2], (200, expected))
        finally:
            os.umask(previous)

    def test_boundaries_and_errors(self):
        with site("boundaries") as fixture:
            status, body, headers = fixture.request("/asset.txt", method="HEAD")
            self.assertEqual(
                (status, body, int(headers["Content-Length"])), (200, b"", len(PUBLIC))
            )
            status, body, _ = fixture.request(
                "/asset.txt", headers={"Range": "bytes=0-5"}
            )
            self.assertEqual((status, body), (206, PUBLIC[:6]))
            for path in ("/download.txt", "/standalone.txt"):
                status, body, _ = fixture.request(path, method="HEAD")
                self.assertIn(status, (403, 404))
                self.assertEqual(body, b"")
                status, body, _ = fixture.request(path, headers={"Range": "bytes=0-5"})
                self.assertIn(status, (403, 404))
                self.assertNotIn(PRIVATE[:6], body)
            for path, expected in (
                ("/internal-private", 404),
                ("/missing.txt", 404),
                ("/%00", 400),
            ):
                status, body, _ = fixture.request(path)
                self.assertEqual(status, expected)
                self.assertNotIn(PRIVATE, body)
            (fixture.root / "public/dangling.txt").symlink_to(fixture.root / "absent")
            self.assertEqual(fixture.request("/dangling.txt")[0], 404)


def main():
    global OPTIONS
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nginx", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--disable-permissions", action="store_true")
    parser.add_argument("--wrong-public-oracle", action="store_true")
    OPTIONS, arguments = parser.parse_known_args()
    if os.geteuid() != 0:
        parser.error(
            "run as root only in a disposable container; worker runs as www-data"
        )
    OPTIONS.nginx = OPTIONS.nginx.resolve(strict=True)
    OPTIONS.output.mkdir(parents=True, exist_ok=True)
    # A fresh traversable parent, not the potentially private evidence/checkout path.
    with tempfile.TemporaryDirectory(prefix="shield-private-", dir="/tmp") as temporary:
        original_output = OPTIONS.output.resolve()
        OPTIONS.output = Path(temporary)
        OPTIONS.output.chmod(0o755)
        try:
            runner = unittest.main(argv=[__file__, *arguments], exit=False)
        finally:
            archive = (
                Path(tempfile.mkdtemp(prefix="run-", dir=original_output)) / "fixtures"
            )
            shutil.copytree(OPTIONS.output, archive, symlinks=True)
            print(f"Evidence: {archive}")
        # unittest's exit=False retains lifecycle control; propagate its real verdict.
        sys.exit(not runner.result.wasSuccessful() or runner.result.testsRun == 0)


if __name__ == "__main__":
    main()
