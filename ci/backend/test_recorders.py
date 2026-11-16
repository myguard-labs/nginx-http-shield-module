#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Positive, boundary and invalid protocol controls for the recording oracle."""

import asyncio
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from check import CASES, config, finish_after_route, module_arg, verify
from recorders import LIMIT, Recorder, fcgi_record, fcgi_request, http_request, params


def reader(data):
    stream = asyncio.StreamReader(limit=LIMIT)
    stream.feed_data(data)
    stream.feed_eof()
    return stream


def pair(key, value):
    def length(n):
        return bytes([n]) if n < 128 else struct.pack("!I", n | 0x80000000)

    return length(len(key)) + length(len(value)) + key + value


def wire(values=b"", body=b""):
    return (
        fcgi_record(1, b"\0\1\0" + bytes(5))
        + (fcgi_record(4, values) if values else b"")
        + fcgi_record(4, b"")
        + (fcgi_record(5, body) if body else b"")
        + fcgi_record(5, b"")
    )


class Params(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(params(b""), {})

    def test_short_and_long_lengths(self):
        value = b"v" * 128
        self.assertEqual(params(pair(b"name", value)), {b"name": value})

    def test_invalid(self):
        for data, message in [
            (b"\x80", "truncated PARAMS long length"),
            (b"\x01", "truncated PARAMS length"),
            (b"\x01\x01k", "truncated PARAMS value"),
            (b"\x00\x00", "field bound"),
            (pair(b"k", b"v") * 2, "duplicate PARAMS"),
            (b"A" * (LIMIT + 1), "PARAMS exceed bound"),
        ]:
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(ValueError, message),
            ):
                params(data)

    def test_record_bound(self):
        self.assertEqual(len(fcgi_record(5, b"A" * LIMIT)), LIMIT + 8)
        with self.assertRaisesRegex(ValueError, "record exceeds bound"):
            fcgi_record(5, b"A" * (LIMIT + 1))


class Attribution(unittest.TestCase):
    def test_static_empty_module_argument_omits_load_directive(self):
        empty = module_arg("")
        self.assertIsNone(empty)
        self.assertNotIn("load_module", config(Path("/fixture"), 1, 2, 3, 4, empty))
        module = module_arg("/fixture/shield.so")
        self.assertEqual(module, Path("/fixture/shield.so"))
        self.assertIn(
            "load_module /fixture/shield.so;",
            config(Path("/fixture"), 1, 2, 3, 4, module),
        )

    def test_server_rejection_and_false_hit(self):
        row = next(row for row in CASES if row["id"] == "core-return-status")
        response = b"HTTP/1.1 418 fixture\r\n\r\n"
        views = [{"status": 418, "upstream": ""}]
        got = verify(row, response, [], views, [], [], 1, 2)
        self.assertEqual(got["action"], "server-rejection")
        self.assertFalse(got["promotion_eligible"])
        self.assertIsNone(got["sink_label"])
        with self.assertRaisesRegex(ValueError, "Shield hit attribution differs"):
            verify(row, response, [{"cat": "sqli"}], views, [], [], 1, 2)
        with self.assertRaisesRegex(ValueError, "upstream differs"):
            verify(
                row,
                response,
                [],
                [{"status": 418, "upstream": "127.0.0.1:9"}],
                [],
                [],
                1,
                2,
            )
        with self.assertRaisesRegex(ValueError, "receipt count differs"):
            verify(row, response, [], views, [{"closed": True}], [], 1, 2)


class Protocols(unittest.IsolatedAsyncioTestCase):
    async def test_shutdown_waits_for_complete_route_record(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "view.jsonl"
            proc = SimpleNamespace(
                pid=424242,
                returncode=None,
                send_signal=Mock(),
                wait=AsyncMock(return_value=0),
            )
            task = asyncio.create_task(finish_after_route(proc, path))
            try:
                await asyncio.sleep(0.003)
                proc.send_signal.assert_not_called()
                path.write_bytes(b'{"status":200}')
                await asyncio.sleep(0.003)
                proc.send_signal.assert_not_called()
                path.write_bytes(b'{"status":200}\n')
                await task
                proc.send_signal.assert_called_once()
                proc.wait.assert_awaited_once()
            finally:
                if not task.done():
                    task.cancel()
                await asyncio.gather(task, return_exceptions=True)

    async def test_route_wait_fails_on_exit_or_incomplete_deadline(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "view.jsonl"
            proc = SimpleNamespace(
                pid=424243, returncode=1, send_signal=Mock(), wait=AsyncMock()
            )
            with self.assertRaisesRegex(ValueError, "exited before final route log: 1"):
                await finish_after_route(proc, path)
            proc.returncode = None
            path.write_bytes(b"partial")
            timeout = asyncio.timeout
            with (
                patch("check.asyncio.timeout", side_effect=lambda _: timeout(0.01)),
                self.assertRaisesRegex(
                    TimeoutError, "final route log incomplete: b'partial'"
                ),
            ):
                await finish_after_route(proc, path)
            proc.send_signal.assert_not_called()

    async def test_http_complete_bytes(self):
        data = b"POST /raw?x=%41 HTTP/1.1\r\nContent-Length: 7\r\n\r\nA%00z+!"
        got = await http_request(reader(data))
        self.assertEqual(got["wire"], data)
        self.assertEqual(got["body"], b"A%00z+!")
        self.assertEqual(got["target"], b"/raw?x=%41")

    async def test_http_empty(self):
        got = await http_request(reader(b"GET / HTTP/1.1\r\n\r\n"))
        self.assertEqual(got["body"], b"")

    async def test_http_invalid(self):
        for data, error, message in [
            (
                b"POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\na",
                asyncio.IncompleteReadError,
                "bytes read",
            ),
            (
                b"GET / HTTP/1.1\r\nX: a\r\nX: b\r\n\r\n",
                ValueError,
                "duplicate HTTP header",
            ),
            (
                b"GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
                ValueError,
                "unsupported transfer",
            ),
            (
                b"GET / HTTP/1.1\r\nContent-Length: -1\r\n\r\n",
                ValueError,
                "invalid content length",
            ),
            (
                b"GET / HTTP/1.1\r\nContent-Length: 16385\r\n\r\n",
                ValueError,
                "read bound",
            ),
            (b"broken\r\n\r\n", ValueError, "invalid HTTP request line"),
            (b"GET / HTTP/1.1\r\nbroken\r\n\r\n", ValueError, "invalid HTTP header"),
        ]:
            with self.subTest(message=message), self.assertRaisesRegex(error, message):
                await http_request(reader(data))

    async def test_fcgi_complete_fragmented_params(self):
        values = pair(b"SCRIPT_FILENAME", b"/inert")
        data = (
            fcgi_record(1, b"\0\1\0" + bytes(5))
            + b"".join(fcgi_record(4, bytes([c])) for c in values)
            + fcgi_record(4, b"")
            + fcgi_record(5, b"a%00z+!")
            + fcgi_record(5, b"")
        )
        got = await fcgi_request(reader(data))
        self.assertEqual(got["wire"], data)
        self.assertEqual(got["params"], {b"SCRIPT_FILENAME": b"/inert"})
        self.assertEqual(got["body"], b"a%00z+!")

    async def test_fcgi_empty(self):
        got = await fcgi_request(reader(wire()))
        self.assertEqual(got["body"], b"")
        self.assertEqual(got["params"], {})

    async def test_fcgi_invalid(self):
        for data, error, message in [
            (wire()[:-1], asyncio.IncompleteReadError, "bytes read"),
            (
                fcgi_record(1, b"\0\1\0" + bytes(5), ident=2),
                ValueError,
                "invalid FastCGI header",
            ),
            (fcgi_record(4, b""), ValueError, "invalid PARAMS order"),
            (fcgi_record(5, b""), ValueError, "STDIN before PARAMS"),
            (fcgi_record(1, b""), ValueError, "invalid BEGIN"),
            (fcgi_record(1, bytes(8)), ValueError, "unsupported FastCGI role"),
            (fcgi_record(2, b""), ValueError, "unsupported FastCGI record"),
            (
                fcgi_record(1, b"\0\1\0" + bytes(5)) + fcgi_record(4, b"a") * 128,
                ValueError,
                "record count exceeds",
            ),
            (
                fcgi_record(1, b"\0\1\0" + bytes(5)) + fcgi_record(4, b"a" * LIMIT),
                ValueError,
                "request exceeds bound",
            ),
        ]:
            with self.subTest(message=message), self.assertRaisesRegex(error, message):
                await fcgi_request(reader(data))

    async def test_raw_direct_http_recorder(self):
        recorder = Recorder("http")
        port = await recorder.start()
        try:
            stream, writer = await asyncio.open_connection("127.0.0.1", port)
            data = b"POST /direct HTTP/1.1\r\nContent-Length: 3\r\n\r\nx+y"
            writer.write(data)
            await writer.drain()
            response = await stream.read()
            writer.close()
            await writer.wait_closed()
            await recorder.stop()
            self.assertEqual(len(recorder.receipts), 1)
            self.assertEqual(recorder.receipts[0]["wire"], data)
            self.assertTrue(recorder.receipts[0]["closed"])
            self.assertIn(b"inert-marker", response)
            self.assertEqual(recorder.errors, [])
        finally:
            await recorder.stop()

    async def test_error_connection_is_not_a_receipt(self):
        recorder = Recorder("fcgi")
        port = await recorder.start()
        try:
            stream, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(fcgi_record(5, b""))
            await writer.drain()
            self.assertEqual(await stream.read(), b"")
            writer.close()
            await writer.wait_closed()
            await recorder.stop()
            self.assertEqual(recorder.receipts, [])
            self.assertEqual(recorder.errors, ["STDIN before PARAMS completion"])
        finally:
            await recorder.stop()


if __name__ == "__main__":
    unittest.main()
