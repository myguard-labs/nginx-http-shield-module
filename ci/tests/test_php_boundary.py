#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise the shipped native recipe against real nginx/Angie and inert FastCGI.

Usage: python3 ci/tests/test_php_boundary.py --nginx /path/to/nginx
       [--output /path/to/evidence] [--disable-guards] [-k test_final_script]
       [--disable-body] [-k test_post_body]
The disabled-guards invocation intentionally fails the protection assertion.
No PHP is executed. Every allowed response is the recorded FastCGI PARAMS.
"""

from __future__ import annotations

import argparse
import http.client
import json
import shutil
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager
from pathlib import Path

RECIPE = Path(__file__).resolve().parents[2] / "contrib/php-boundary"
BINARY = Path("nginx")
OUTPUT: Path | None = None
DISABLE_GUARDS = False
DISABLE_BODY = False


def read_exact(stream, length):
    """FastCGI records can be split across arbitrary TCP reads."""
    data = stream.read(length)
    if len(data) != length:
        raise EOFError("incomplete FastCGI record")
    return data


def parameters(data):
    """Decode PARAMS without collapsing duplicate names (an unsafe integration)."""
    result = []
    offset = 0
    while offset < len(data):
        lengths = []
        for _ in range(2):
            size = data[offset]
            offset += 1
            if size & 128:
                size = struct.unpack("!I", data[offset - 1 : offset + 3])[0]
                size &= 0x7FFFFFFF
                offset += 3
            lengths.append(size)
        key_size, value_size = lengths
        key = data[offset : offset + key_size].decode()
        offset += key_size
        value = data[offset : offset + value_size].decode()
        offset += value_size
        result.append((key, value))
    return result


def record(kind, request_id, payload):
    return struct.pack("!BBHHBB", 1, kind, request_id, len(payload), 0, 0) + payload


class Recorder(socketserver.StreamRequestHandler):
    """One inert request per connection, response carries exact parameter pairs."""

    def handle(self):
        self.connection.settimeout(5)
        encoded = bytearray()
        body = bytearray()
        while True:
            header = read_exact(self.rfile, 8)
            version, kind, request_id, size, padding, _ = struct.unpack(
                "!BBHHBB", header
            )
            if version != 1:
                raise ValueError("unexpected FastCGI version")
            payload = read_exact(self.rfile, size)
            read_exact(self.rfile, padding)
            if kind == 4:
                encoded.extend(payload)
            if kind == 5:
                body.extend(payload)
            if kind == 5 and not size:
                pairs = parameters(encoded)
                with self.server.lock:
                    self.server.requests.append(pairs)
                    self.server.bodies.append(bytes(body))
                response = b"Content-Type: application/json\r\n\r\n"
                response += json.dumps(pairs).encode()
                self.wfile.write(record(6, request_id, response))
                self.wfile.write(record(6, request_id, b""))
                self.wfile.write(record(3, request_id, bytes(8)))
                return


class Backend(socketserver.ThreadingTCPServer):
    """Capture threads finish before the fixture returns."""

    def __init__(self):
        super().__init__(("127.0.0.1", 0), Recorder)
        self.requests = []
        self.bodies = []
        self.lock = threading.Lock()


def fetch(port, target, method="GET", body=None, headers=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(method, target, body=body, headers=headers or {})
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


@contextmanager
def fixture(
    *, disable_guards=False, disable_body=False, clear_proxy=False, invalid=None
):
    """Render copies of the shipped files; only test routes extend their maps."""
    with tempfile.TemporaryDirectory(prefix="shield-php-") as directory:
        root = Path(directory)
        html = root / "site"
        for name in ("public", "app", "uploads", "media", "cache", "uploads2"):
            (html / name).mkdir(parents=True)
        for name in (
            "app/index.php",
            "app/health.php",
            "app/other.php",
            "uploads/shell.php",
            "media/shell.php",
            "cache/shell.php",
            "uploads/allowed.php",
            "uploads2/index.php",
        ):
            (html / name).write_text("inert fixture; never executed\n")
        for name in (
            "public/style.css",
            "uploads/photo.jpg",
            "media/clip.txt",
            "uploads/Case.txt",
        ):
            (html / name).write_text("public content\n")
        copied = root / "recipe"
        copied.mkdir()
        for source in RECIPE.glob("*.conf"):
            text = source.read_text().replace("/srv/shield-site", str(html))
            text = text.replace("/etc/nginx/shield-php-boundary", str(copied))
            (copied / source.name).write_text(text)
        maps = (copied / "maps.conf").read_text()
        # Legacy/generated mappings test the FINAL filename guard, not a URI ban.
        routes = {
            "alias.txt": "$request_filename",
            "root-dispatch": "$document_root/uploads/shell.php",
            "named.php": f"{html}/cache/shell.php",
            "error.php": f"{html}/media/shell.php",
            "unapproved.php": f"{html}/app/other.php",
            "uploads/allowed.php": f"{html}/uploads/allowed.php",
            "uploads2/index.php": f"{html}/uploads2/index.php",
        }
        additions = "".join(
            f"    ~^/{key.replace('.', '[.]')}$ {value};\n"
            for key, value in routes.items()
        )
        maps = maps.replace('    default "";', additions + '    default "";', 1)
        maps = maps.replace(
            "    default 0;",
            "    default 0;\n"
            f"    ~^{html}/uploads/allowed[.]php$ 1;\n"
            f"    ~^{html}/uploads2/index[.]php$ 1;",
            1,
        )
        (copied / "maps.conf").write_text(maps)
        dispatch = copied / "dispatch.conf"
        if disable_guards:
            dispatch.write_text(
                "\n".join(
                    line
                    for line in dispatch.read_text().splitlines()
                    if not line.startswith("if (")
                )
                + "\n"
            )
        if clear_proxy:
            params = copied / "params.conf"
            params.write_text(params.read_text() + 'fastcgi_param HTTP_PROXY "";\n')
        with Backend() as backend:
            thread = threading.Thread(target=backend.serve_forever)
            thread.start()
            try:
                with socket.socket() as listener:
                    listener.bind(("127.0.0.1", 0))
                    port = listener.getsockname()[1]
                include = f"include {copied}/dispatch.conf;"
                config = f"""daemon off;
master_process off;
pid {root}/nginx.pid;
error_log {root}/error.log notice;
events {{ worker_connections 64; }}
http {{
    access_log off;
    client_body_temp_path {root}/body;
    fastcgi_temp_path {root}/fastcgi;
    include {copied}/maps.conf;
    upstream shield_php_backend {{ server 127.0.0.1:{backend.server_address[1]}; }}
    server {{
        listen 127.0.0.1:{port};
        include {copied}/server.conf;
        location = /ready {{ return 200 ready; }}
        location = /alias.txt {{ alias {html}/uploads/shell.php; {include} }}
        location = /root-dispatch {{ root {html}; {include} }}
        location = /rewrite {{ rewrite ^ /uploads/shell.php last; }}
        location = /to-front {{ rewrite ^ /index.php/path last; }}
        location = /named.php {{ try_files /missing @guarded; }}
        location @guarded {{ {include} }}
        location = /named-front {{ try_files /missing @front; }}
        location @front {{ rewrite ^ /index.php last; }}
        location = /error.php {{ error_page 418 = @error; return 418; }}
        location @error {{ {include} }}
        location = /error-front {{ error_page 418 = /index.php$is_args$args; return 418; }}
        location = /internal-front {{ internal; {include} }}
    }}
}}
"""
                if disable_body:
                    config = config.replace(
                        "access_log off;",
                        "access_log off;\nfastcgi_pass_request_body off;",
                    )
                if invalid == "missing-maps":
                    config = config.replace(f"include {copied}/maps.conf;", "")
                elif invalid == "wrong-context":
                    config += f"include {copied}/dispatch.conf;\n"
                path = root / "nginx.conf"
                path.write_text(config)
                command = [str(BINARY), "-p", f"{root}/", "-c", str(path)]
                check = subprocess.run(
                    command + ["-t"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                if invalid:
                    yield check
                    return
                if check.returncode:
                    raise RuntimeError(check.stderr)
                with (root / "stderr.log").open("w+") as stderr:
                    process = subprocess.Popen(command, stdout=stderr, stderr=stderr)
                    try:
                        deadline = time.monotonic() + 10
                        while True:
                            if process.poll() is not None:
                                stderr.seek(0)
                                raise RuntimeError(stderr.read())
                            try:
                                if fetch(port, "/ready")[0] == 200:
                                    break
                            except ConnectionRefusedError:
                                time.sleep(0.02)
                            if time.monotonic() >= deadline:
                                raise TimeoutError("nginx did not become ready")
                        yield port, backend, html
                    finally:
                        process.terminate()
                        try:
                            process.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=5)
                        if OUTPUT:
                            OUTPUT.mkdir(parents=True, exist_ok=True)
                            case = str(time.time_ns())
                            shutil.copytree(root, OUTPUT / case)
                            (OUTPUT / case / "requests.json").write_text(
                                json.dumps(backend.requests, indent=2) + "\n"
                            )
                            (OUTPUT / case / "stdin.json").write_text(
                                json.dumps([body.hex() for body in backend.bodies])
                                + "\n"
                            )
            finally:
                backend.shutdown()
                thread.join(timeout=10)


class PhpBoundaryTests(unittest.TestCase):
    def assert_dispatch(self, port, target, script, path_info="", query="", **kwargs):
        status, body = fetch(port, target, **kwargs)
        self.assertEqual(status, 200, (target, status, body))
        pairs = json.loads(body)
        values = dict(pairs)
        self.assertEqual(len(values), len(pairs), "duplicate FastCGI parameters")
        self.assertEqual(values["SCRIPT_FILENAME"], str(script))
        self.assertEqual(values["PATH_INFO"], path_info)
        self.assertEqual(values["QUERY_STRING"], query)
        return values

    def test_approved_routes(self):
        with fixture(disable_guards=DISABLE_GUARDS) as (port, _, html):
            for target, suffix, query in (
                ("/index.php", "", ""),
                ("/index%2ephp/a%20b?x=1&x=2", "/a b", "x=1&x=2"),
                ("/index.php/", "/", ""),
                ("/index.php/a.php/b", "/a.php/b", ""),
                ("/route?x=%2F", "", "x=%2F"),
                ("/to-front?x=1", "/path", "x=1"),
                ("/named-front?x=1", "", "x=1"),
                ("/error-front?x=1", "", "x=1"),
                ("/", "", ""),
            ):
                with self.subTest(target=target):
                    self.assert_dispatch(
                        port, target, html / "app/index.php", suffix, query
                    )
            self.assert_dispatch(
                port, "/health.php?ok=1", html / "app/health.php", query="ok=1"
            )
            long_query = "q=" + "a" * 260
            self.assert_dispatch(
                port,
                "/index.php?" + long_query,
                html / "app/index.php",
                query=long_query,
            )

    def test_newline_route_boundaries(self):
        with fixture() as (port, backend, html):
            for target in (
                "/health.php%0A",
                "/health.php%0a?ok=1",
                "/index.php%0A",
                "/index.php%0a?q=1",
            ):
                with self.subTest(target=target):
                    before = len(backend.requests)
                    self.assertEqual(fetch(port, target)[0], 404, target)
                    self.assertEqual(len(backend.requests), before, target)
            for target, suffix in (
                ("/index.php/", "/"),
                ("/index.php/%0A", "/\n"),
                ("/index.php/path%0A", "/path\n"),
                ("/index.php/a%0Ab", "/a\nb"),
                ("/index.php/a%0D%0Ab.php", "/a\r\nb.php"),
            ):
                with self.subTest(target=target):
                    values = self.assert_dispatch(
                        port, target, html / "app/index.php", suffix
                    )
                    self.assertEqual(values["SCRIPT_NAME"], "/index.php")
                    self.assertEqual(values["REQUEST_URI"], target)
            self.assert_dispatch(port, "/health.php", html / "app/health.php")
            self.assert_dispatch(port, "/index.php", html / "app/index.php")
            self.assert_dispatch(
                port,
                "/health.php?ok=%0A",
                html / "app/health.php",
                query="ok=%0A",
            )

    def test_post_body(self):
        with fixture(disable_body=DISABLE_BODY) as (port, backend, html):
            for body in (b"", b"data", bytes(range(256)) * 300):
                with self.subTest(length=len(body)):
                    values = self.assert_dispatch(
                        port,
                        "/index.php/post?q=1",
                        html / "app/index.php",
                        "/post",
                        "q=1",
                        method="POST",
                        body=body,
                    )
                    self.assertEqual(values["REQUEST_METHOD"], "POST")
                    self.assertEqual(values["CONTENT_LENGTH"], str(len(body)))
                    self.assertEqual(values["SCRIPT_NAME"], "/index.php")
                    self.assertEqual(values["REQUEST_URI"], "/index.php/post?q=1")
                    self.assertEqual(backend.bodies[-1], body, "FastCGI STDIN differs")

    def test_proxy_header_contract(self):
        # Default header semantics and an explicitly chosen site policy differ.
        for clear_proxy in (False, True):
            with (
                self.subTest(clear_proxy=clear_proxy),
                fixture(clear_proxy=clear_proxy) as (port, _, html),
            ):
                values = self.assert_dispatch(
                    port,
                    "/index.php",
                    html / "app/index.php",
                    headers={
                        "Proxy": "application-value",
                        "X-Ordinary": "ordinary-value",
                    },
                )
                if clear_proxy:
                    self.assertNotIn("HTTP_PROXY", values)
                else:
                    self.assertEqual(values["HTTP_PROXY"], "application-value")
                self.assertEqual(values["HTTP_X_ORDINARY"], "ordinary-value")

    def test_final_script(self):
        with fixture(disable_guards=DISABLE_GUARDS) as (port, backend, _):
            for target in (
                "/alias.txt",
                "/root-dispatch",
                "/named.php",
                "/error.php",
                "/uploads/allowed.php",
                "/unapproved.php",
            ):
                with self.subTest(target=target):
                    before = len(backend.requests)
                    status, _ = fetch(port, target)
                    self.assertIn(
                        status, (403, 404), f"forbidden backend dispatch: {target}"
                    )
                    self.assertEqual(
                        len(backend.requests),
                        before,
                        f"forbidden SCRIPT_FILENAME reached backend: {target}",
                    )

    def test_uri_variants(self):
        with fixture() as (port, backend, _):
            for tree in ("uploads", "media", "cache"):
                for path in (
                    f"/{tree}/shell.php",
                    f"/{tree}/shell.PHP",
                    f"/{tree}/shell.php/path",
                    f"/{tree}/shell%2ephp",
                    f"/{tree}/shell.php%2fpath",
                    f"/{tree.upper()}/shell.php",
                    f"/%{ord(tree[0]):02x}{tree[1:]}/shell.php",
                ):
                    with self.subTest(path=path):
                        before = len(backend.requests)
                        self.assertIn(fetch(port, path)[0], (403, 404))
                        self.assertEqual(len(backend.requests), before)
            for path in (
                "/INDEX.PHP",
                "/health.php/path",
                "/rewrite",
                "/internal-front",
            ):
                with self.subTest(path=path):
                    before = len(backend.requests)
                    self.assertIn(fetch(port, path)[0], (403, 404))
                    self.assertEqual(len(backend.requests), before)
            self.assertEqual(fetch(port, "/uploads/bad%zz.php")[0], 400)
            self.assertEqual(fetch(port, "/uploads/%00.php")[0], 400)
            self.assertEqual(backend.requests, [])

    def test_public_data_and_tree_boundary(self):
        with fixture() as (port, backend, html):
            for target in (
                "/style.css",
                "/uploads/photo.jpg",
                "/media/clip.txt",
                "/uploads/Case.txt",
            ):
                self.assertEqual(fetch(port, target), (200, b"public content\n"))
            self.assertEqual(fetch(port, "/uploads/case.txt")[0], 404)
            self.assertEqual(backend.requests, [])
            self.assert_dispatch(
                port, "/uploads2/index.php", html / "uploads2/index.php"
            )

    def test_config_integration_errors(self):
        for invalid in ("missing-maps", "wrong-context"):
            with self.subTest(invalid=invalid), fixture(invalid=invalid) as result:
                self.assertNotEqual(result.returncode, 0)
                self.assertRegex(
                    result.stderr, "unknown .+ variable|directive is not allowed here"
                )

    def test_disabled_guards_reach_forbidden_scripts(self):
        with fixture(disable_guards=True) as (port, backend, html):
            for target, script in (
                ("/alias.txt", "uploads/shell.php"),
                ("/root-dispatch", "uploads/shell.php"),
                ("/named.php", "cache/shell.php"),
                ("/error.php", "media/shell.php"),
                ("/uploads/allowed.php", "uploads/allowed.php"),
                ("/unapproved.php", "app/other.php"),
            ):
                self.assert_dispatch(port, target, html / script)
            self.assertEqual(len(backend.requests), 6)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nginx", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--disable-guards", action="store_true")
    parser.add_argument("--disable-body", action="store_true")
    args, remaining = parser.parse_known_args()
    BINARY = args.nginx.resolve(strict=True)
    OUTPUT = args.output.resolve() if args.output else None
    DISABLE_GUARDS = args.disable_guards
    DISABLE_BODY = args.disable_body
    unittest.main(argv=[__file__, *remaining])
