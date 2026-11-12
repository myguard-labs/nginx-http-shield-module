#!/usr/bin/env python3
"""Bounded, single-request FastCGI responder handoff for a declared site contract."""

import argparse
import asyncio
import contextlib
import json
import logging
import socket
import struct
from pathlib import Path

LOGGER = logging.getLogger(__name__)
HEADER = struct.Struct("!BBHHBB")
MAX_PARAMS = 65536
MAX_WIRE = 131072
MAX_PAIRS = 1024
MAX_RECORDS = 1024
PRIVILEGED = (b"PHP_VALUE", b"PHP_ADMIN_VALUE")


class ProtocolError(ValueError):
    """The input is outside the supported FastCGI transport contract."""


def record(kind, request_id, content):
    return HEADER.pack(1, kind, request_id, len(content), 0, 0) + content


def pairs(data):
    """Decode the complete PARAMS stream, retaining duplicate order and bytes."""
    result = []
    offset = 0
    while offset < len(data):
        sizes = []
        for _ in range(2):
            if offset >= len(data):
                raise ProtocolError("length")
            size = data[offset]
            if size & 128:
                if len(data) - offset < 4:
                    raise ProtocolError("length")
                size = struct.unpack_from("!I", data, offset)[0] & 0x7FFFFFFF
                offset += 4
            else:
                offset += 1
            sizes.append(size)
        key_size, value_size = sizes
        if not key_size or key_size + value_size > len(data) - offset:
            raise ProtocolError("pair")
        key = bytes(data[offset : offset + key_size])
        offset += key_size
        value = bytes(data[offset : offset + value_size])
        offset += value_size
        if b"\0" in key or b"\0" in value:
            raise ProtocolError("nul")
        result.append((key, value))
        if len(result) > MAX_PAIRS:
            raise ProtocolError("pairs")
    return result


def load_contract(path):
    """Fail startup on unknown keys, duplicate JSON keys or oversized policy."""

    def unique(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate contract key")
            result[key] = value
        return result

    with path.open("rb") as stream:
        raw = stream.read(MAX_PARAMS + 1)
    if len(raw) > MAX_PARAMS:
        raise ValueError("contract size")
    data = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(data, dict) or set(data) != {"scripts"}:
        raise ValueError("contract schema")
    scripts = data["scripts"]
    if not isinstance(scripts, dict) or not scripts:
        raise ValueError("contract scripts")
    policy = {}
    for script, settings in scripts.items():
        if not script.startswith("/") or "\0" in script:
            raise ValueError("contract script")
        if not isinstance(settings, dict) or set(settings) != {
            "PHP_VALUE",
            "PHP_ADMIN_VALUE",
        }:
            raise ValueError("contract settings")
        approved = {}
        for key, values in settings.items():
            if not isinstance(values, list) or any(
                not isinstance(v, str) or "\0" in v for v in values
            ):
                raise ValueError("contract values")
            approved[key.encode()] = [v.encode() for v in values]
        policy[script.encode()] = approved
    return policy


def violation(parameters, policy):
    """Exact vectors avoid assuming which duplicate a particular PHP build uses."""
    scripts = [v for k, v in parameters if k == b"SCRIPT_FILENAME"]
    if len(scripts) != 1 or scripts[0] not in policy:
        return "script"
    approved = policy[scripts[0]]
    for name in PRIVILEGED:
        if [v for k, v in parameters if k == name] != approved[name]:
            return "privileged"
    return None


async def read_record(reader, request_id=None):
    header = await reader.readexactly(8)
    version, kind, ident, size, padding, reserved = HEADER.unpack(header)
    if (
        version != 1
        or not ident
        or reserved
        or (request_id is not None and ident != request_id)
    ):
        raise ProtocolError("header")
    content = await reader.readexactly(size)
    pad = await reader.readexactly(padding)
    return kind, ident, content, header + content + pad


async def close(writer, *, abort=False):
    """Cleanup cannot wait indefinitely for a stalled peer's write buffer."""
    if writer is None:
        return
    if abort:
        writer.transport.abort()
    else:
        writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), 1)
    except (OSError, TimeoutError):
        writer.transport.abort()


async def stdin_record(reader, ident):
    kind, _, content, raw = await read_record(reader, ident)
    if kind not in (2, 5) or (kind == 2 and content):
        raise ProtocolError("stdin order")
    return kind, content, raw


class Guard:
    """Connection-local state: BEGIN -> PARAMS -> admitted STDIN -> response.

    No backend is opened before the complete PARAMS verdict. One active request
    owns both streams; no multiplexing, reuse or companion retry. A new nginx
    retry/redirect creates a new verdict. Policy is immutable for this process.
    Block verdicts are terminal; detect verdicts are advisory. Later PARAMS are
    never forwarded. ABORT before admission closes locally; after admission it
    is forwarded and closes. Failure closes both streams; no fallback backend.
    """

    def __init__(self, backend, policy, mode="block", connections=64, timeout=60):
        self.backend = backend
        self.policy = policy
        self.mode = mode
        self.connections = connections
        self.timeout = timeout
        self.active = 0

    async def response(self, writer, ident, status):
        payload = f"Status: {status}\r\nContent-Type: text/plain\r\n\r\nHandoff rejected\n".encode()
        writer.write(
            record(6, ident, payload)
            + record(6, ident, b"")
            + record(3, ident, bytes(8))
        )
        await writer.drain()

    async def handle(self, reader, writer):
        if self.active >= self.connections:
            await close(writer)
            return
        self.active += 1
        backend_writer = None
        ident = None
        rejected = False
        tasks = []
        try:
            async with asyncio.timeout(self.timeout):
                kind, ident, begin, wire = await read_record(reader)
                if (
                    kind != 1
                    or len(begin) != 8
                    or begin[:3] != b"\0\1\0"
                    or any(begin[3:])
                ):
                    raise ProtocolError("begin")
                pending = bytearray(wire)
                encoded = bytearray()
                for _ in range(MAX_RECORDS):
                    kind, _, content, wire = await read_record(reader, ident)
                    if kind == 2 and not content:
                        return
                    if kind != 4:
                        raise ProtocolError("params order")
                    if (
                        len(encoded) + len(content) > MAX_PARAMS
                        or len(pending) + len(wire) > MAX_WIRE
                    ):
                        raise ProtocolError("params budget")
                    pending.extend(wire)
                    encoded.extend(content)
                    if not content:
                        break
                else:
                    raise ProtocolError("record budget")
                parameters = pairs(encoded)
                reason = (
                    violation(parameters, self.policy) if self.mode != "off" else None
                )
                if reason:
                    # Fixed identifiers only; never log parameter or policy values.
                    LOGGER.warning("handoff violation=%s mode=%s", reason, self.mode)
                    if self.mode == "block":
                        await self.response(writer, ident, "403 Forbidden")
                        rejected = True
                        writer.write_eof()
                        # Consume the remaining framed upload under the same
                        # deadline so unread STDIN does not reset the response.
                        while True:
                            kind, content, _ = await stdin_record(reader, ident)
                            if kind == 2 or not content:
                                return
                backend_reader, backend_writer = await asyncio.open_unix_connection(
                    self.backend, limit=65536
                )
                backend_writer.write(pending)
                await backend_writer.drain()

                async def upload():
                    while True:
                        kind, content, raw = await stdin_record(reader, ident)
                        backend_writer.write(raw)
                        await backend_writer.drain()
                        if kind == 2 or not content:
                            return

                async def download():
                    while chunk := await backend_reader.read(65536):
                        writer.write(chunk)
                        await writer.drain()

                tasks = [asyncio.create_task(upload()), asyncio.create_task(download())]
                done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    task.result()
                if tasks[0] in done:
                    await tasks[1]
        except (ProtocolError, asyncio.IncompleteReadError):
            LOGGER.warning("handoff transport=invalid")
            if backend_writer is None and ident is not None and not rejected:
                with contextlib.suppress(OSError):
                    await self.response(writer, ident, "400 Bad Request")
        except (OSError, TimeoutError):
            # Do not append a second response after a partial backend response.
            LOGGER.warning("handoff transport=unavailable")
        finally:
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            await close(backend_writer, abort=True)
            await close(writer)
            self.active -= 1


async def serve(args):
    guard = Guard(args.backend, load_contract(args.contract), args.mode)
    # bind() atomically refuses an existing pathname. Passing a bound socket
    # avoids asyncio's path-based stale-socket unlink (including startup races).
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(args.listen))
        listener.listen(socket.SOMAXCONN)
        listener.setblocking(False)
        server = await asyncio.start_unix_server(
            guard.handle, sock=listener, limit=65536
        )
        async with server:
            await server.serve_forever()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", required=True, type=Path)
    parser.add_argument("--backend", required=True, type=Path)
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--mode", choices=("off", "detect", "block"), default="block")
    args = parser.parse_args()
    # Both UNIX sockets require a trusted operator-owned parent directory.
    if (
        not args.listen.is_absolute()
        or not args.backend.is_absolute()
        or args.listen == args.backend
    ):
        parser.error("distinct absolute socket paths required")
    logging.basicConfig(level=logging.WARNING)
    try:
        asyncio.run(serve(args))
    except (ValueError, UnicodeError, OSError, RecursionError):
        parser.exit(2, "handoff startup failed: validate contract and socket paths\n")


if __name__ == "__main__":
    main()
