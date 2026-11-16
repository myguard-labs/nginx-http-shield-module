# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Finite inert HTTP/FastCGI recorders. They never interpret application data."""

import asyncio
import struct

LIMIT = 16384
TIMEOUT = 10


def require(ok, message):
    if not ok:
        raise ValueError(message)


async def exact(reader, size):
    require(0 <= size <= LIMIT, "read bound exceeded")
    return await reader.readexactly(size)


async def http_request(reader):
    head = await reader.readuntil(b"\r\n\r\n")
    require(len(head) <= LIMIT, "HTTP headers exceed bound")
    lines = head[:-4].split(b"\r\n")
    require(len(lines[0].split(b" ")) == 3, "invalid HTTP request line")
    fields = {}
    for line in lines[1:]:
        key, sep, value = line.partition(b":")
        require(bool(sep), "invalid HTTP header")
        key = key.lower()
        require(key not in fields, "duplicate HTTP header")
        fields[key] = value.strip()
    require(b"transfer-encoding" not in fields, "unsupported transfer encoding")
    size = fields.get(b"content-length", b"0")
    require(size.isdigit(), "invalid content length")
    body = await exact(reader, int(size))
    require(len(head) + len(body) <= LIMIT, "HTTP request exceeds bound")
    return {
        "wire": head + body,
        "target": lines[0].split(b" ")[1],
        "body": body,
        "method": lines[0].split(b" ")[0],
    }


def fcgi_record(kind, data, ident=1):
    require(len(data) <= LIMIT, "FastCGI record exceeds bound")
    return struct.pack("!BBHHBB", 1, kind, ident, len(data), 0, 0) + data


def params(data):
    """Decode bounded name/value pairs; reject duplicates instead of hiding them."""
    require(len(data) <= LIMIT, "PARAMS exceed bound")
    pos = 0
    result = {}

    def length():
        nonlocal pos
        require(pos < len(data), "truncated PARAMS length")
        value = data[pos]
        pos += 1
        if value & 128:
            require(pos + 3 <= len(data), "truncated PARAMS long length")
            value = ((value & 127) << 24) | int.from_bytes(data[pos : pos + 3], "big")
            pos += 3
        return value

    while pos < len(data):
        nlen, vlen = length(), length()
        require(0 < nlen <= LIMIT and vlen <= LIMIT, "PARAMS field bound exceeded")
        require(pos + nlen + vlen <= len(data), "truncated PARAMS value")
        key = data[pos : pos + nlen]
        value = data[pos + nlen : pos + nlen + vlen]
        require(key not in result, "duplicate PARAMS name")
        result[key] = value
        pos += nlen + vlen
    return result


async def fcgi_request(reader):
    wire, values, body = bytearray(), bytearray(), bytearray()
    began = ended = False
    for _ in range(128):
        head = await exact(reader, 8)
        version, kind, ident, size, pad, reserved = struct.unpack("!BBHHBB", head)
        require(version == 1 and ident == 1 and reserved == 0, "invalid FastCGI header")
        require(len(wire) + 8 + size + pad <= LIMIT, "FastCGI request exceeds bound")
        data = await exact(reader, size)
        padding = await exact(reader, pad)
        wire.extend(head + data + padding)
        if kind == 1:
            require(not began and len(data) == 8, "invalid BEGIN_REQUEST")
            require(data == b"\0\1\0" + bytes(5), "unsupported FastCGI role/flags")
            began = True
        elif kind == 4:
            require(began and not ended, "invalid PARAMS order")
            values.extend(data)
            ended = size == 0
        elif kind == 5:
            require(ended, "STDIN before PARAMS completion")
            body.extend(data)
            if size == 0:
                return {
                    "wire": bytes(wire),
                    "params": params(bytes(values)),
                    "body": bytes(body),
                }
        else:
            raise ValueError("unsupported FastCGI record")
    raise ValueError("FastCGI record count exceeds bound")


class Recorder:
    """One bounded request per connection; a receipt is published after close."""

    def __init__(self, kind):
        self.kind = kind
        self.receipts = []
        self.errors = []
        self.tasks = set()
        self.server = None

    async def start(self):
        self.server = await asyncio.start_server(
            self.accept, "127.0.0.1", 0, limit=LIMIT
        )
        return self.server.sockets[0].getsockname()[1]

    def accept(self, reader, writer):
        task = asyncio.create_task(self.handle(reader, writer))
        self.tasks.add(task)

    async def handle(self, reader, writer):
        receipt = None
        try:
            async with asyncio.timeout(TIMEOUT):
                if self.kind == "http":
                    receipt = await http_request(reader)
                    writer.write(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n"
                        b"Connection: close\r\n\r\ninert-marker"
                    )
                else:
                    receipt = await fcgi_request(reader)
                    writer.write(
                        fcgi_record(6, b"Content-Type: text/plain\r\n\r\ninert-marker")
                        + fcgi_record(6, b"")
                        + fcgi_record(3, bytes(8))
                    )
                await writer.drain()
        except (
            ValueError,
            OSError,
            EOFError,
            TimeoutError,
            asyncio.LimitOverrunError,
        ) as exc:
            self.errors.append(str(exc))
        finally:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), TIMEOUT)
            except (OSError, TimeoutError) as exc:
                self.errors.append(str(exc))
            if receipt is not None:
                receipt["closed"] = True
                self.receipts.append(receipt)

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        if self.tasks:
            tasks = tuple(self.tasks)
            self.tasks.clear()
            await asyncio.wait_for(asyncio.gather(*tasks), TIMEOUT + 1)
