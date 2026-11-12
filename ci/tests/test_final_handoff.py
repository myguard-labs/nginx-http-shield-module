#!/usr/bin/env python3
"""Final PARAMS recording oracle; no PHP or application code is executed."""

import argparse
import asyncio
import errno
import importlib.util
import json
import socket
import struct
import sys
import tempfile
import time
import tracemalloc
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "fastcgi_guard", ROOT / "contrib/final-handoff/fastcgi_guard.py"
)
assert SPEC is not None and SPEC.loader is not None
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)
NGINX = None
MODULE = None
OUTPUT = None
DISABLED = False
SCRIPT = b"/srv/shield-site/app/index.php"
ADMIN = b"open_basedir=/srv/shield-site\nmemory_limit=128M"
POLICY = {SCRIPT: {b"PHP_VALUE": [], b"PHP_ADMIN_VALUE": [ADMIN]}}
GOOD = [(b"SCRIPT_FILENAME", SCRIPT), (b"PHP_ADMIN_VALUE", ADMIN)]


def encoded(pairs):
    def length(size):
        return bytes([size]) if size < 128 else struct.pack("!I", size | 0x80000000)

    return b"".join(length(len(k)) + length(len(v)) + k + v for k, v in pairs)


def request(pairs=None, body=b"", ident=7, split=False):
    params = encoded(GOOD if pairs is None else pairs)
    chunks = (
        [params[i : i + 1] for i in range(len(params))]
        if split
        else [params[i : i + 60000] for i in range(0, len(params), 60000)]
    )
    return (
        guard.record(1, ident, b"\0\1\0" + bytes(5))
        + b"".join(guard.record(4, ident, chunk) for chunk in chunks)
        + guard.record(4, ident, b"")
        + b"".join(
            guard.record(5, ident, body[i : i + 60000])
            for i in range(0, len(body), 60000)
        )
        + guard.record(5, ident, b"")
    )


class Fixture(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="handoff-")
        self.root = Path(self.tmp.name)
        self.captures = []
        self.partial = []
        self.recorded = asyncio.Event()
        self.early = False
        self.expected = b"Content-Type: text/plain\r\n\r\nbackend-marker"
        self.backend = await asyncio.start_unix_server(
            self.record, path=self.root / "backend"
        )
        self.sites = []

    async def asyncTearDown(self):
        for site in self.sites:
            site.close()
            await site.wait_closed()
        self.backend.close()
        await self.backend.wait_closed()
        self.tmp.cleanup()

    async def record(self, reader, writer):
        wire = bytearray()
        try:
            while True:
                header = await reader.readexactly(8)
                _, kind, ident, size, pad, _ = struct.unpack("!BBHHBB", header)
                data = await reader.readexactly(size + pad)
                wire.extend(header + data)
                if (
                    kind == 2
                    or (kind == 5 and size == 0)
                    or (self.early and kind == 4 and size == 0)
                ):
                    self.captures.append(bytes(wire))
                    writer.write(
                        b"".join(
                            guard.record(6, ident, self.expected[i : i + 60000])
                            for i in range(0, len(self.expected), 60000)
                        )
                        + guard.record(6, ident, b"")
                        + guard.record(3, ident, bytes(8))
                    )
                    await writer.drain()
                    return
        except (asyncio.IncompleteReadError, ConnectionError):
            return
        finally:
            self.partial.append(bytes(wire))
            await guard.close(writer)
            self.recorded.set()

    async def exchange(
        self, wire, mode="block", policy=None, timeout=2, backend=None, eof=True
    ):
        instance = guard.Guard(
            backend or self.root / "backend",
            POLICY if policy is None else policy,
            "off" if DISABLED else mode,
            timeout=timeout,
        )
        path = self.root / f"front-{len(self.sites)}"
        finished = asyncio.Event()

        async def handle(reader, writer):
            try:
                await instance.handle(reader, writer)
            finally:
                finished.set()

        site = await asyncio.start_unix_server(handle, path=path)
        self.sites.append(site)
        reader, writer = await asyncio.open_unix_connection(path)
        writer.write(wire)
        await writer.drain()
        if eof:
            writer.write_eof()
        result = await asyncio.wait_for(reader.read(), 4)
        await guard.close(writer)
        await asyncio.wait_for(finished.wait(), 4)
        self.assertEqual(instance.active, 0)
        return result


class ProtocolTests(Fixture):
    async def test_final_generated_privileged_value_is_blocked(self):
        bad = GOOD + [(b"PHP_VALUE", b"auto_prepend_file=/unapproved.php")]
        result = await self.exchange(request(bad))
        self.assertIn(b"403 Forbidden", result)
        self.assertEqual(self.captures, [])

    async def test_modes_and_exact_wire_preservation(self):
        bad = GOOD + [(b"PHP_VALUE", b"auto_prepend_file=/unapproved.php")]
        for mode in ("detect", "off"):
            wire = request(bad, b"\0binary\xff\n" * 5000)
            result = await self.exchange(wire, mode)
            self.assertIn(b"backend-marker", result)
            self.assertEqual(self.captures[-1], wire)
        wire = request(
            GOOD
            + [
                (b"HTTP_PHP_VALUE", b"anything"),
                (b"HTTP_PHP_ADMIN_VALUE", b"ordinary"),
            ],
            split=True,
        )
        result = await self.exchange(wire)
        self.assertIn(b"backend-marker", result)
        self.assertEqual(self.captures[-1], wire)

    async def test_rejection_drains_large_upload(self):
        bad = GOOD + [(b"PHP_VALUE", b"unapproved")]
        result = await self.exchange(request(bad, body=b"x" * (2 * 1024 * 1024)))
        self.assertIn(b"403 Forbidden", result)
        self.assertEqual(self.captures, [])

    async def test_duplicate_policy_and_script_identity(self):
        for extra in (
            [(b"SCRIPT_FILENAME", SCRIPT)],
            [(b"PHP_ADMIN_VALUE", ADMIN)],
            [(b"PHP_VALUE", b"")],
        ):
            self.assertIn(b"403", await self.exchange(request(GOOD + extra)))
        for name in (b"script_filename", b"HTTP_SCRIPT_FILENAME"):
            self.assertIn(b"403", await self.exchange(request([(name, SCRIPT)])))
        self.assertIn(
            b"403",
            await self.exchange(request([(b"SCRIPT_FILENAME", SCRIPT + b"/tail")])),
        )
        policy = {SCRIPT: {b"PHP_VALUE": [b"one", b"two"], b"PHP_ADMIN_VALUE": [ADMIN]}}
        duplicates = GOOD + [(b"PHP_VALUE", b"one"), (b"PHP_VALUE", b"two")]
        wire = request(duplicates)
        self.assertIn(b"backend-marker", await self.exchange(wire, policy=policy))
        self.assertEqual(self.captures[-1], wire)
        self.assertIn(
            b"403", await self.exchange(request(duplicates[::-1]), policy=policy)
        )

    async def test_framing_errors_and_late_params(self):
        begin = guard.record(1, 7, b"\0\1\0" + bytes(5))
        for wire in (
            guard.record(1, 7, b"\0\1\1" + bytes(5)),
            guard.record(1, 7, b"\0\2\0" + bytes(5)),
            begin + guard.record(4, 8, b""),
            begin + guard.record(5, 7, b""),
            begin + guard.record(4, 7, b"\x80") + guard.record(4, 7, b""),
            begin + guard.record(4, 7, b"\1\2x") + guard.record(4, 7, b""),
            begin
            + guard.record(4, 7, encoded([(b"x", b"\0")]))
            + guard.record(4, 7, b""),
        ):
            with self.subTest(wire=wire[:16]):
                self.assertIn(b"400 Bad Request", await self.exchange(wire))
        for wire in (b"short", guard.record(1, 0, bytes(8))):
            self.assertEqual(await self.exchange(wire), b"")
        self.assertEqual(self.captures, [])
        # A second PARAMS stream after admission must never reach the backend.
        late_record = guard.record(4, 7, encoded([(b"PHP_VALUE", b"late")]))
        late = request()[:-8] + late_record
        await self.exchange(late)
        self.assertEqual(self.captures, [])
        await asyncio.wait_for(self.recorded.wait(), 3)
        self.assertTrue(self.partial)
        self.assertNotIn(late_record, b"".join(self.partial))

    async def test_stalled_backend_cleanup_is_bounded(self):
        release = asyncio.Event()
        finished = asyncio.Event()
        peers = []

        async def stall(reader, writer):
            peers.append(writer)
            await release.wait()
            writer.transport.abort()

        backend_path = self.root / "stalled"
        backend = await asyncio.start_unix_server(stall, path=backend_path)
        self.sites.append(backend)
        instance = guard.Guard(backend_path, POLICY, timeout=0.1)

        async def handle(reader, writer):
            try:
                await instance.handle(reader, writer)
            finally:
                finished.set()

        endpoint = self.root / "stalled-front"
        server = await asyncio.start_unix_server(handle, path=endpoint)
        self.sites.append(server)
        _, writer = await asyncio.open_unix_connection(endpoint)
        writer.write(request(body=b"x" * (2 * 1024 * 1024)))
        try:
            await asyncio.wait_for(finished.wait(), 2)
            self.assertEqual(instance.active, 0)
            self.assertTrue(peers)
        finally:
            writer.transport.abort()
            release.set()
            for peer in peers:
                peer.transport.abort()
            await asyncio.wait_for(finished.wait(), 3)

    async def test_listener_bind_is_atomic(self):
        endpoint = self.root / "existing.sock"
        contract = ROOT / "contrib/final-handoff/site-contract.json"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(endpoint))
            inode = endpoint.stat().st_ino
            args = SimpleNamespace(
                backend=self.root / "backend",
                contract=contract,
                listen=endpoint,
                mode="block",
            )
            # Simulate an existing socket appearing after any advisory exists().
            with (
                mock.patch.object(Path, "exists", return_value=False),
                self.assertRaises(OSError) as failure,
            ):
                await asyncio.wait_for(guard.serve(args), 0.2)
            self.assertEqual(failure.exception.errno, errno.EADDRINUSE)
            self.assertEqual(endpoint.stat().st_ino, inode)

    async def test_early_backend_response_cancels_upload(self):
        self.early = True
        result = await self.exchange(request()[:-8], eof=False)
        expected = (
            guard.record(6, 7, self.expected)
            + guard.record(6, 7, b"")
            + guard.record(3, 7, bytes(8))
        )
        self.assertEqual(result, expected)
        self.assertEqual(self.captures[-1], request()[:-8])

    async def test_early_backend_response_during_upload(self):
        self.early = True
        self.expected += b"response-chunk" * 100000
        instance = guard.Guard(self.root / "backend", POLICY, timeout=2)
        endpoint = self.root / "concurrent-front"
        site = await asyncio.start_unix_server(instance.handle, path=endpoint)
        self.sites.append(site)
        loop = asyncio.get_running_loop()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.setblocking(False)
            await loop.sock_connect(client, str(endpoint))
            sender = asyncio.create_task(
                loop.sock_sendall(client, request(body=b"x" * (2 * 1024 * 1024)))
            )
            response = bytearray()
            try:
                while True:
                    try:
                        part = await asyncio.wait_for(loop.sock_recv(client, 65536), 3)
                    except ConnectionResetError:
                        break
                    if not part:
                        break
                    response.extend(part)
                expected = (
                    b"".join(
                        guard.record(6, 7, self.expected[i : i + 60000])
                        for i in range(0, len(self.expected), 60000)
                    )
                    + guard.record(6, 7, b"")
                    + guard.record(3, 7, bytes(8))
                )
                self.assertEqual(bytes(response), expected)
            finally:
                sender.cancel()
                client.close()
                await asyncio.gather(sender, return_exceptions=True)

    async def test_budgets_boundary_and_padding(self):
        base = encoded(GOOD)
        # Four-byte lengths and exactly 65536 PARAMS bytes are supported.
        value_size = guard.MAX_PARAMS - len(base) - 6
        wire = request(GOOD + [(b"x", b"a" * value_size)])
        self.assertIn(b"backend-marker", await self.exchange(wire))
        self.assertEqual(self.captures[-1], wire)
        # One byte over requires multiple records, each legal on its own.
        params = encoded(GOOD + [(b"x", b"a" * (value_size + 1))])
        begin = guard.record(1, 7, b"\0\1\0" + bytes(5))
        oversized = (
            begin
            + guard.record(4, 7, params[:60000])
            + guard.record(4, 7, params[60000:])
            + guard.record(4, 7, b"")
        )
        before = len(self.captures)
        self.assertIn(b"400", await self.exchange(oversized))
        self.assertEqual(len(self.captures), before)
        raw = encoded(GOOD)
        padded = (
            begin
            + struct.pack("!BBHHBB", 1, 4, 7, len(raw), 3, 0)
            + raw
            + b"pad"
            + guard.record(4, 7, b"")
            + guard.record(5, 7, b"")
        )
        self.assertIn(b"backend-marker", await self.exchange(padded))
        self.assertEqual(self.captures[-1], padded)
        many = [(b"x", b"")] * (guard.MAX_PAIRS - len(GOOD))
        self.assertIn(b"backend-marker", await self.exchange(request(GOOD + many)))
        self.assertIn(b"400", await self.exchange(request(GOOD + many + [(b"x", b"")])))
        padded_record = struct.pack("!BBHHBB", 1, 4, 7, 1, 255, 0) + b"x" + bytes(255)
        self.assertIn(b"400", await self.exchange(begin + padded_record * 512))
        records = begin + guard.record(4, 7, b"x") * guard.MAX_RECORDS
        self.assertIn(b"400", await self.exchange(records))

    async def test_abort_timeout_backend_error_and_new_connection(self):
        begin = guard.record(1, 7, b"\0\1\0" + bytes(5))
        self.assertEqual(await self.exchange(begin + guard.record(2, 7, b"")), b"")
        self.assertEqual(self.captures, [])
        await self.exchange(begin, timeout=0.01)
        self.assertEqual(
            await self.exchange(request(), backend=self.root / "missing"), b""
        )
        self.assertIn(b"backend-marker", await self.exchange(request()))
        self.assertIn(b"backend-marker", await self.exchange(request(ident=9)))

    async def test_live_timeout_capacity_and_admitted_abort(self):
        instance = guard.Guard(
            self.root / "backend", POLICY, connections=1, timeout=0.1
        )
        path = self.root / "capacity"
        first_finished = asyncio.Event()

        async def handle(reader, writer):
            try:
                await instance.handle(reader, writer)
            finally:
                if instance.active == 0:
                    first_finished.set()

        site = await asyncio.start_unix_server(handle, path=path)
        self.sites.append(site)
        first_reader, first_writer = await asyncio.open_unix_connection(path)
        first_writer.write(guard.record(1, 7, b"\0\1\0" + bytes(5)))
        await first_writer.drain()
        second_reader, second_writer = await asyncio.open_unix_connection(path)
        self.assertEqual(await asyncio.wait_for(second_reader.read(), 1), b"")
        self.assertEqual(instance.active, 1)
        self.assertEqual(await asyncio.wait_for(first_reader.read(), 1), b"")
        await guard.close(first_writer)
        await guard.close(second_writer)
        await asyncio.wait_for(first_finished.wait(), 3)
        self.assertEqual(instance.active, 0)
        # After admission the backend receives ABORT with the original ID.
        wire = request()[:-8] + guard.record(2, 7, b"")
        await self.exchange(wire)
        self.assertEqual(self.captures[-1], wire)

    async def test_deployable_cli_and_startup_failures(self):
        contract = self.root / "site.json"
        contract.write_text(
            json.dumps(
                {
                    "scripts": {
                        SCRIPT.decode(): {
                            "PHP_VALUE": [],
                            "PHP_ADMIN_VALUE": [ADMIN.decode()],
                        }
                    }
                }
            )
        )
        executable = ROOT / "contrib/final-handoff/fastcgi_guard.py"
        endpoint = self.root / "cli.sock"
        command = [
            sys.executable,
            str(executable),
            "--listen",
            str(endpoint),
            "--backend",
            str(self.root / "backend"),
            "--contract",
            str(contract),
        ]
        process = await asyncio.create_subprocess_exec(
            *command, stderr=asyncio.subprocess.PIPE
        )
        try:
            deadline = time.monotonic() + 3
            while not endpoint.exists():
                if process.returncode is not None or time.monotonic() > deadline:
                    self.fail("companion startup failed")
                await asyncio.sleep(0.01)
            reader, writer = await asyncio.open_unix_connection(endpoint)
            wire = request()
            writer.write(wire)
            await writer.drain()
            self.assertIn(b"backend-marker", await asyncio.wait_for(reader.read(), 2))
            await guard.close(writer)
            self.assertEqual(self.captures[-1], wire)
            # Refuse the live socket, preserving the first process's endpoint.
            duplicate = await asyncio.create_subprocess_exec(
                *command, stderr=asyncio.subprocess.PIPE
            )
            _, stderr = await duplicate.communicate()
            self.assertEqual(duplicate.returncode, 2)
            self.assertIn(b"handoff startup failed", stderr)
            self.assertTrue(endpoint.is_socket())
        finally:
            process.terminate()
            await asyncio.wait_for(process.communicate(), 3)
        endpoint.unlink()
        contract.write_text('{"scripts":{"DO_NOT_PRINT_THIS_VALUE": {}}}')
        invalid = await asyncio.create_subprocess_exec(
            *command, stderr=asyncio.subprocess.PIPE
        )
        _, stderr = await invalid.communicate()
        self.assertEqual(invalid.returncode, 2)
        self.assertNotIn(b"DO_NOT_PRINT_THIS_VALUE", stderr)

    def test_bounded_parameter_allocation(self):
        data = encoded(GOOD + [(b"x", b"a" * 60000)])
        tracemalloc.start()
        started = time.process_time()
        decoded = guard.pairs(data)
        elapsed = time.process_time() - started
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        self.assertEqual(decoded[-1][1], b"a" * 60000)
        self.assertLess(peak, 1024 * 1024)
        print(
            f"PARAMS bytes={len(data)} peak_traced_bytes={peak} cpu_seconds={elapsed:.6f}"
        )

    def test_contract_schema_and_decoder_errors(self):
        self.assertEqual(
            guard.load_contract(ROOT / "contrib/final-handoff/site-contract.json"),
            POLICY,
        )
        path = self.root / "contract.json"
        valid = {
            "scripts": {
                SCRIPT.decode(): {"PHP_VALUE": [], "PHP_ADMIN_VALUE": [ADMIN.decode()]}
            }
        }
        path.write_text(json.dumps(valid))
        self.assertEqual(guard.load_contract(path), POLICY)
        for bad in (
            '{"scripts":{},"scripts":{}}',
            "{}",
            '{"scripts":[]}',
            '{"scripts":{"/a":{}}}',
            '{"scripts":{"relative":{}}}',
            '{"scripts":{"/a":{"PHP_VALUE":[1],"PHP_ADMIN_VALUE":[]}}}',
            "x" * (guard.MAX_PARAMS + 1),
        ):
            path.write_text(bad)
            with self.assertRaises(ValueError):
                guard.load_contract(path)
        for bad in (b"\x80", b"\1", b"\0\0", b"\1\0\0"):
            with self.assertRaises(guard.ProtocolError):
                guard.pairs(bad)


def stream_content(wire, expected):
    parts = []
    while wire:
        _, kind, _, size, pad, _ = struct.unpack("!BBHHBB", wire[:8])
        if kind == expected:
            parts.append(wire[8 : 8 + size])
        wire = wire[8 + size + pad :]
    return b"".join(parts)


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


class NginxTests(Fixture):
    """Use the real server to generate parameters after rewrite and PRECONTENT."""

    async def test_nginx_final_handoff(self):
        if NGINX is None:
            self.skipTest("--nginx is required for the real-server oracle")
        path = self.root / "front"
        instance = guard.Guard(
            self.root / "backend", POLICY, "off" if DISABLED else "block"
        )
        site = await asyncio.start_unix_server(instance.handle, path=path)
        self.sites.append(site)
        port = free_port()
        module = f"load_module {MODULE};" if MODULE else ""
        dispatch = (
            (ROOT / "contrib/final-handoff/dispatch.conf")
            .read_text()
            .replace(
                "fastcgi_pass unix:/run/shield-handoff/guard.sock;",
                "fastcgi_pass retry_guard;",
            )
        )
        # shield runs PRECONTENT, but PHP_VALUE is generated by fastcgi_param.
        text = f"""{module}
daemon off;
master_process off;
pid {self.root}/pid;
error_log {self.root}/error.log notice;
events {{ worker_connections 64; }}
http {{
access_log off;
client_max_body_size 0;
client_body_temp_path {self.root}/body;
fastcgi_temp_path {self.root}/fastcgi;
shield block;
map $uri $generated {{ default ""; /unsafe "auto_prepend_file=/unapproved.php"; }}
upstream retry_guard {{ server unix:{self.root}/absent; server unix:{path} backup; }}
server {{
listen 127.0.0.1:{port};
location = /ready {{ return 200 ready; }}
location = /rewrite {{ rewrite ^ /unsafe last; }}
location = /named {{ try_files /nonexistent @unsafe; }}
location @unsafe {{ rewrite ^ /unsafe last; }}
location = /error {{ error_page 418 = /unsafe; return 418; }}
location / {{
{dispatch}
fastcgi_next_upstream error timeout;
fastcgi_next_upstream_tries 2;
fastcgi_param SCRIPT_FILENAME {SCRIPT.decode()};
fastcgi_param PHP_VALUE $generated if_not_empty;
fastcgi_param REQUEST_METHOD $request_method;
fastcgi_param CONTENT_LENGTH $content_length;
fastcgi_param QUERY_STRING $query_string;
}}
}}
}}
"""
        config = self.root / "nginx.conf"
        config.write_text(text)
        stderr = (self.root / "stderr").open("wb")
        process = await asyncio.create_subprocess_exec(
            str(NGINX),
            "-p",
            f"{self.root}/",
            "-c",
            str(config),
            stdout=stderr,
            stderr=stderr,
        )

        async def fetch(target, body=None):
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            data = body or b""
            writer.write(
                f"POST {target} HTTP/1.0\r\nHost: localhost\r\nContent-Length: {len(data)}\r\nPHP-Value: ordinary-header\r\n\r\n".encode()
                + data
            )
            await writer.drain()
            result = await asyncio.wait_for(reader.read(), 5)
            await guard.close(writer)
            return result

        try:
            deadline = time.monotonic() + 5
            while True:
                if process.returncode is not None:
                    self.fail((self.root / "stderr").read_text())
                try:
                    if b"200 OK" in await fetch("/ready"):
                        break
                except ConnectionRefusedError:
                    pass
                if time.monotonic() >= deadline:
                    self.fail("nginx startup timeout")
                await asyncio.sleep(0.02)
            self.assertIn(
                b"200 OK", await fetch("/legitimate?x=1", b"\0\xffbody" * 10000)
            )
            captured = self.captures[-1]
            self.assertIn(b"ordinary-header", captured)
            self.assertIn(b"x=1", captured)
            self.assertEqual(stream_content(captured, 5), b"\0\xffbody" * 10000)
            count = len(self.captures)
            for route in ("/unsafe", "/rewrite", "/named", "/error"):
                with self.subTest(route=route):
                    self.assertIn(b"403 Forbidden", await fetch(route))
            with self.subTest(route="/unsafe-with-body"):
                self.assertIn(
                    b"403 Forbidden", await fetch("/unsafe", b"x" * (2 * 1024 * 1024))
                )
            self.assertEqual(len(self.captures), count)
            self.assertIn("connect() to unix:", (self.root / "error.log").read_text())
            self.assertIn("/absent failed", (self.root / "error.log").read_text())
            # Removing only final-parameter enforcement admits the generated value
            # while the same server retains shield block in PRECONTENT.
            instance.mode = "off"
            self.assertIn(b"200 OK", await fetch("/rewrite"))
            self.assertIn(b"auto_prepend_file=/unapproved.php", self.captures[-1])
            instance.mode = "detect"
            self.assertIn(b"200 OK", await fetch("/unsafe"))

        finally:
            process.terminate()
            await asyncio.wait_for(process.wait(), 5)
            stderr.close()
            if OUTPUT:
                OUTPUT.mkdir(parents=True, exist_ok=True)
                (OUTPUT / "nginx.conf").write_text(text)
                for name in ("error.log", "stderr"):
                    if (self.root / name).exists():
                        (OUTPUT / name).write_bytes((self.root / name).read_bytes())
                for index, capture in enumerate(self.captures):
                    (OUTPUT / f"backend-{index}.fcgi").write_bytes(capture)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nginx", type=Path)
    parser.add_argument("--module", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--disable-enforcement", action="store_true")
    args, remaining = parser.parse_known_args()
    NGINX, MODULE, OUTPUT, DISABLED = (
        args.nginx,
        args.module,
        args.output,
        args.disable_enforcement,
    )
    unittest.main(argv=[sys.argv[0], *remaining])
