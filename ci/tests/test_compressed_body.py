#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Actual gzip-accepting backend, byte identity and decoded-policy controls."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import http.client
import json
import os
import signal
import socket
import subprocess
import tempfile
import threading
import time
import zlib
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import ClassVar

from test_cve_controls import CRAFT25

ATTACK = CRAFT25.encode()
BENIGN = b"hello from a compressed application request"


class Backend(BaseHTTPRequestHandler):
    """Record the actual forwarded representation and decode accepted gzip."""

    records: ClassVar[list[dict]] = []

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        fields = self.headers.get_all("Content-Encoding", [])
        try:
            decoded = (
                gzip.decompress(body)
                if len(fields) == 1 and fields[0].strip().lower() == "gzip"
                else None
            )
        except (OSError, EOFError):
            decoded = None
        record = {
            "path": self.path,
            "sha256": hashlib.sha256(body).hexdigest(),
            "length": len(body),
            "encodings": fields,
            "decoded": decoded.hex() if decoded is not None else None,
        }
        self.records.append(record)
        payload = json.dumps(record).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args):
        """Keep fixture logs bounded."""


def snapshot(port: int) -> dict:
    """Read incomplete-inspection counters without changing them."""
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request("GET", "/stats")
        response = connection.getresponse()
        assert response.status == 200
        return json.loads(response.read())
    finally:
        connection.close()


def stop_server(process, root: Path, output: Path, fault: str | None) -> None:
    """Retain shutdown evidence and reject process or sanitizer failures."""
    try:
        if process.poll() is None:
            if fault == "exit":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.send_signal(signal.SIGTERM)
        try:
            status = process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise
    finally:
        # Deliberate log faults prove both channels are checked, independently
        # of the normally successful master exit status.
        if fault in ("stderr-asan", "error-log-ubsan"):
            name, diagnostic = (
                ("stderr", "AddressSanitizer: injected teardown control")
                if fault == "stderr-asan"
                else ("error.log", "runtime error: injected teardown control")
            )
            with (root / name).open("a") as log:
                log.write(diagnostic + "\n")
        output.mkdir(parents=True, exist_ok=True)
        logs = b""
        for name in ("error.log", "hits.jsonl", "stderr"):
            source = root / name
            if source.exists():
                data = source.read_bytes()
                (output / name).write_bytes(data)
                if name != "hits.jsonl":
                    logs += data
    assert status == 0, ("nginx shutdown status", status, logs.decode(errors="replace"))
    assert not any(
        marker in logs
        for marker in (
            b"AddressSanitizer",
            b"LeakSanitizer",
            b"UndefinedBehaviorSanitizer",
            b"runtime error:",
        )
    ), ("sanitizer diagnostics", logs.decode(errors="replace"))


def gzip_header(
    body: bytes, flags: int, optional: bool = False, bad_crc: bool = False
) -> bytes:
    """Prepare accepted backend forms without changing the compressed payload."""
    header = body[:3] + bytes([flags | (0x1E if optional else 0)]) + body[4:10]
    if optional:
        header += b"\x03\x00abcname\x00comment\x00"
        crc = (zlib.crc32(header) & 0xFFFF) ^ int(bad_crc)
        header += crc.to_bytes(2, "little")
    return header + body[10:]


def run(
    binary: Path,
    module: Path | None,
    output: Path,
    disable: bool,
    wrong_oracle: bool,
    fault_teardown: str | None = None,
) -> None:
    """Every allowed body must reach the backend with its original bytes."""
    results = []
    Backend.records = []
    backend = HTTPServer(("127.0.0.1", 0), Backend)
    thread = threading.Thread(target=backend.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="shield-gzip-") as directory:
            root = Path(directory)
            root.chmod(0o755)
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
            load = f'load_module "{module}";' if module else ""
            gzip_directive = "" if disable else "shield_gzip on;"
            locations = {
                "enabled": "",
                "disabled": "shield_gzip off;",
                "detect": "shield detect;",
                "off": "shield off;",
                "skip": "shield_skip deserial;",
                "no-body": "shield_body off;",
                "limited": "shield_max_body 8;",
                "input-cap": "shield_max_encoded_body 12;",
                "trailer-cap": f"shield_max_encoded_body {len(gzip.compress(ATTACK, mtime=0)) - 1};",
                "member-cap": f"shield_max_encoded_body {len(gzip.compress(ATTACK, mtime=0))};",
                "both-caps": "shield_max_encoded_body 64; shield_max_body 8;",
                "zero": "shield_max_body 0;",
                "zero-input": "shield_max_encoded_body 0;",
                "custom-status": "shield_status 419;",
                "file": "client_body_in_file_only clean;",
            }
            routes = "\n".join(
                f"location /{name}/ {{ {settings} proxy_pass "
                f"http://127.0.0.1:{backend.server_port}; }}"
                for name, settings in locations.items()
            )
            config = f"""{load}
daemon off;
worker_processes 1;
pid {root}/nginx.pid;
error_log {root}/error.log notice;
events {{ worker_connections 64; }}
http {{
    access_log off;
    client_body_temp_path {root}/body;
    shield_stats_zone gzip_stats 64k;
    server {{
        listen 127.0.0.1:{port};
        shield block;
        shield_cve craft_cms;
        {gzip_directive}
        shield_log {root}/hits.jsonl;
        client_body_buffer_size 1k;
        location = /ready {{ shield off; return 200 ready; }}
        location = /stats {{ shield off; shield_ban_status gzip_stats; }}
        {routes}
    }}
}}
"""
            (root / "nginx.conf").write_text(config)
            # The upper limit is an inspection budget; reject unsafe config,
            # never a request merely because decoding was incomplete.
            bad = root / "bad.conf"
            bad.write_text(
                config.replace(gzip_directive, "").replace(
                    "shield block;",
                    "shield block; shield_gzip on; shield_max_body 17m;",
                    1,
                )
            )
            rejected = subprocess.run(
                [str(binary), "-p", f"{root}/", "-c", str(bad), "-t"],
                capture_output=True,
                check=False,
            )
            assert rejected.returncode != 0 and b"budgets" in rejected.stderr
            with (root / "stderr").open("w+") as stderr:
                process = subprocess.Popen(
                    [str(binary), "-p", f"{root}/", "-c", "nginx.conf"],
                    stdout=stderr,
                    stderr=stderr,
                    start_new_session=True,
                )
                try:
                    deadline = time.monotonic() + 10
                    while True:
                        if process.poll() is not None:
                            stderr.seek(0)
                            raise RuntimeError(stderr.read())
                        try:
                            connection = http.client.HTTPConnection(
                                "127.0.0.1", port, timeout=5
                            )
                            connection.request("GET", "/ready")
                            response = connection.getresponse()
                            assert response.status == 200
                            response.read()
                            connection.close()
                            break
                        except ConnectionRefusedError:
                            assert time.monotonic() < deadline, "nginx readiness"
                            time.sleep(0.02)

                    def check(
                        name,
                        body,
                        status=200,
                        route="enabled",
                        encodings=None,
                        chunked=False,
                        expected_decoded=None,
                        content_type="application/json",
                        decoded_rejected=False,
                    ):
                        if encodings is None:
                            encodings = ["gzip"]
                        before = len(Backend.records)
                        connection = http.client.HTTPConnection(
                            "127.0.0.1", port, timeout=5
                        )
                        connection.putrequest("POST", f"/{route}/{name}")
                        connection.putheader("Content-Type", content_type)
                        for value in encodings:
                            connection.putheader("Content-Encoding", value)
                        connection.putheader("Connection", "close")
                        if chunked:
                            connection.putheader("Transfer-Encoding", "chunked")
                        else:
                            connection.putheader("Content-Length", str(len(body)))
                        connection.endheaders()
                        if chunked:
                            # Cross every header/deflate/trailer boundary on the wire.
                            for byte in body:
                                connection.send(b"1\r\n" + bytes([byte]) + b"\r\n")
                            connection.send(b"0\r\n\r\n")
                        else:
                            connection.send(body)
                        response = connection.getresponse()
                        payload = response.read()
                        connection.close()
                        assert response.status == status, (
                            name,
                            response.status,
                            payload,
                        )
                        if status == 200:
                            record = json.loads(payload)
                            expected = b"wrong oracle" if wrong_oracle else body
                            assert (
                                record["sha256"] == hashlib.sha256(expected).hexdigest()
                            ), name
                            assert record["length"] == len(body), name
                            # nginx may coalesce duplicate fields before proxying.
                            if len(encodings) == 1:
                                assert record["encodings"] == encodings, name
                            if decoded_rejected:
                                assert record["decoded"] is None, name
                            if expected_decoded is not None:
                                assert record["decoded"] == expected_decoded.hex(), name
                            assert len(Backend.records) == before + 1, name
                        else:
                            assert len(Backend.records) == before, name
                        results.append({"name": name, "status": status})

                    benign = gzip.compress(BENIGN, mtime=0)
                    attack = gzip.compress(ATTACK, mtime=0)
                    check("benign", benign, expected_decoded=BENIGN)
                    if fault_teardown:
                        return
                    check("attack", attack, 403)
                    for flags in (0x01, 0x20, 0x40, 0x80, 0xE0):
                        check(
                            f"flags-{flags:02x}-benign",
                            gzip_header(benign, flags),
                            expected_decoded=BENIGN,
                        )
                        check(
                            f"flags-{flags:02x}-attack", gzip_header(attack, flags), 403
                        )
                    for flags, bad_crc in (
                        (0, False),
                        (0, True),
                        (0xE0, False),
                        (0xE0, True),
                    ):
                        check(
                            f"optional-{flags:02x}-{bad_crc}-benign",
                            gzip_header(benign, flags, True, bad_crc),
                            expected_decoded=BENIGN,
                        )
                        check(
                            f"optional-{flags:02x}-{bad_crc}-attack",
                            gzip_header(attack, flags, True, bad_crc),
                            403,
                        )
                    check(
                        "flags-second-member",
                        benign + gzip_header(attack, 0xE0, True, True),
                        403,
                    )
                    check(
                        "flags-second-benign",
                        benign + gzip_header(benign, 0xE0, True, True),
                        expected_decoded=BENIGN * 2,
                    )
                    flagged_bad_crc = bytearray(gzip_header(attack, 0xE0, True, True))
                    flagged_bad_crc[-8] ^= 1
                    check(
                        "flags-payload-crc",
                        bytes(flagged_bad_crc),
                        decoded_rejected=True,
                    )
                    flagged_bad_size = bytearray(gzip_header(attack, 0xE0, True, True))
                    flagged_bad_size[-4] ^= 1
                    check(
                        "flags-payload-size",
                        bytes(flagged_bad_size),
                        decoded_rejected=True,
                    )
                    check(
                        "flags-truncated-header",
                        gzip_header(benign, 0xE0, True)[:15],
                        decoded_rejected=True,
                    )
                    optional_header = gzip_header(benign, 0xE0, True)
                    header_size = len(optional_header) - len(benign[10:])
                    check(
                        "fhcrc-absent",
                        optional_header[: header_size - 2],
                        decoded_rejected=True,
                    )
                    check(
                        "fhcrc-one-byte",
                        optional_header[: header_size - 1],
                        decoded_rejected=True,
                    )
                    # A complete member at max_body+1 must classify known trailing
                    # non-member data before treating the output as a partial view.
                    for label, plain in (
                        ("benign", b"a" * 8193),
                        ("attack", ATTACK + b"a" * (8193 - len(ATTACK))),
                    ):
                        coded = gzip.compress(plain, mtime=0)
                        before_trailing = snapshot(port)["body_uninspected"]
                        check(
                            f"cap-trailing-{label}", coded + b"x", decoded_rejected=True
                        )
                        check(
                            f"cap-magic-{label}",
                            coded + b"\x1fx",
                            decoded_rejected=True,
                        )
                        after_trailing = snapshot(port)["body_uninspected"]
                        assert (
                            after_trailing["encoding"]
                            == before_trailing["encoding"] + 2
                        )
                        assert (
                            after_trailing["too_large"] == before_trailing["too_large"]
                        )
                        assert after_trailing["error"] == before_trailing["error"]
                    check(
                        "cap-valid-next-member",
                        gzip.compress(ATTACK + b"a" * (8193 - len(ATTACK)), mtime=0)
                        + benign,
                        403,
                    )
                    # Valid full uploads whose inspection prefix ends inside a
                    # later member header must retain earlier decoded text.
                    empty_member = gzip.compress(b"", mtime=0)
                    long_header = (
                        empty_member[:3]
                        + b"\x10"
                        + empty_member[4:10]
                        + b"a" * 70000
                        + b"\x00"
                        + empty_member[10:]
                    )
                    check("input-header-attack", attack + long_header, 403)
                    before_input = snapshot(port)["body_uninspected"]
                    check(
                        "input-header-benign",
                        benign + long_header,
                        expected_decoded=BENIGN,
                    )
                    check(
                        "input-header-chunked",
                        benign + long_header,
                        expected_decoded=BENIGN,
                        chunked=True,
                    )
                    after_input = snapshot(port)["body_uninspected"]
                    assert after_input["encoding"] == before_input["encoding"] + 2
                    assert after_input["too_large"] == before_input["too_large"]
                    assert after_input["error"] == before_input["error"]
                    check("input-trailer-attack", attack, 403, route="trailer-cap")
                    check(
                        "input-member-boundary",
                        attack + benign,
                        403,
                        route="member-cap",
                    )
                    # Content wholly beyond the input budget remains incomplete;
                    # a cap does not become a new upload rejection policy.
                    check(
                        "input-header-late-attack",
                        long_header + attack,
                        expected_decoded=ATTACK,
                    )
                    check("custom-status", attack, 419, route="custom-status")
                    check(
                        "case-token",
                        benign,
                        encodings=["GZip"],
                        expected_decoded=BENIGN,
                    )
                    check("empty", gzip.compress(b"", mtime=0), expected_decoded=b"")
                    check("identity", BENIGN, encodings=["identity"])
                    check("absent", BENIGN, encodings=[])
                    check(
                        "binary",
                        attack,
                        content_type="application/octet-stream",
                        expected_decoded=ATTACK,
                    )
                    for route in ("disabled", "detect", "off", "skip", "no-body"):
                        check(route, attack, route=route, expected_decoded=ATTACK)
                    check("chunked", benign, chunked=True, expected_decoded=BENIGN)
                    check("chunked-attack", attack, 403, chunked=True)
                    check("file-benign", benign, route="file", expected_decoded=BENIGN)
                    check("file-attack", attack, 403, route="file")
                    check("truncated", benign[:-1], decoded_rejected=True)
                    check("truncated-attack", attack[:-8], decoded_rejected=True)
                    invalid_attack = bytearray(attack)
                    invalid_attack[-8] ^= 1
                    check("crc-attack", bytes(invalid_attack), decoded_rejected=True)
                    corrupt = bytearray(benign)
                    corrupt[-8] ^= 1
                    check("malformed", bytes(corrupt), decoded_rejected=True)
                    check("not-gzip", b"benign non-gzip bytes")
                    check("unsupported", benign, encodings=["br"])
                    check("stacked", benign, encodings=["gzip, gzip"])
                    check("duplicate", benign, encodings=["gzip", "gzip"])
                    check(
                        "duplicate-identity", benign, encodings=["identity", "identity"]
                    )
                    check("members", benign + benign, expected_decoded=BENIGN * 2)
                    check("member-attack", benign + attack, 403)
                    check("padding-attack", attack + b"\x00" * 16, 403)
                    check("inter-member-padding", benign + b"\x00" * 3 + attack, 403)
                    check(
                        "skip-members",
                        benign + attack,
                        route="skip",
                        expected_decoded=BENIGN + ATTACK,
                    )
                    check(
                        "member-trailing-attack",
                        attack + gzip.compress(b"", mtime=0) * 63 + b"x",
                        decoded_rejected=True,
                    )
                    check(
                        "member-trailing-benign",
                        benign + gzip.compress(b"", mtime=0) * 63 + b"x",
                        decoded_rejected=True,
                    )
                    before_members = snapshot(port)["body_uninspected"]
                    check(
                        "member-limit",
                        gzip.compress(b"", mtime=0) * 64 + attack,
                        expected_decoded=ATTACK,
                    )
                    after_members = snapshot(port)["body_uninspected"]
                    assert after_members["encoding"] == before_members["encoding"] + 1
                    assert after_members["too_large"] == before_members["too_large"]
                    assert after_members["error"] == before_members["error"]
                    before_both = snapshot(port)["body_uninspected"]
                    check(
                        "both-caps",
                        gzip.compress(b"a" * 65536 + ATTACK, mtime=0),
                        route="both-caps",
                    )
                    after_both = snapshot(port)["body_uninspected"]
                    assert after_both["encoding"] == before_both["encoding"] + 1
                    assert after_both["too_large"] == before_both["too_large"]
                    check("trailing", benign + b"extra", decoded_rejected=True)
                    check("trailing-attack", attack + b"x", decoded_rejected=True)
                    check(
                        "exact-fit",
                        gzip.compress(b"a" * 8192, mtime=0),
                        expected_decoded=b"a" * 8192,
                    )
                    check("output-cap", gzip.compress(b"a" * 65536 + ATTACK, mtime=0))
                    check(
                        "partial-attack",
                        gzip.compress(ATTACK + b"a" * 65536, mtime=0),
                        403,
                    )
                    check(
                        "late-attack",
                        gzip.compress(b"a" * 32 + ATTACK, mtime=0),
                        route="limited",
                    )
                    check(
                        "input-cap", benign, route="input-cap", expected_decoded=BENIGN
                    )
                    check("zero", attack, route="zero", expected_decoded=ATTACK)
                    check(
                        "zero-input",
                        attack,
                        route="zero-input",
                        expected_decoded=ATTACK,
                    )
                    check("unsupported-attack", attack, encodings=["br"])
                    check("stacked-attack", attack, encodings=["gzip, gzip"])
                    check("duplicate-attack", attack, encodings=["gzip", "gzip"])
                    # Force encoded collection across buffer and temp-file boundaries.
                    large = bytes(
                        97 + (index * 73 + index // 251) % 26 for index in range(24000)
                    )
                    check(
                        "buffer-boundary",
                        gzip.compress(large, compresslevel=0, mtime=0),
                        expected_decoded=large,
                    )
                    stats = snapshot(port)
                    output.mkdir(parents=True, exist_ok=True)
                    (output / "stats.json").write_text(json.dumps(stats, indent=2))
                    # Bind incomplete inspection to the externally visible counters.
                    counters = stats["body_uninspected"]
                    assert counters["encoding"] >= 9, counters
                    assert counters["too_large"] >= 3, counters
                    (output / "results.json").write_text(json.dumps(results, indent=2))
                    (output / "backend.json").write_text(
                        json.dumps(Backend.records, indent=2)
                    )
                finally:
                    stop_server(process, root, output, fault_teardown)
                print(f"compressed body: {len(results)} named HTTP assertions passed")
    finally:
        backend.shutdown()
        backend.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive(), "backend thread was not reaped"


def main():
    """Expose causal decoder-disable and byte-oracle-fault controls."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nginx", type=Path, required=True)
    parser.add_argument("--module", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--disable-decoder", action="store_true")
    parser.add_argument("--wrong-byte-oracle", action="store_true")
    parser.add_argument(
        "--fault-teardown", choices=("exit", "stderr-asan", "error-log-ubsan")
    )
    args = parser.parse_args()
    run(
        args.nginx.resolve(),
        args.module.resolve() if args.module else None,
        args.output.resolve(),
        args.disable_decoder,
        args.wrong_byte_oracle,
        args.fault_teardown,
    )


if __name__ == "__main__":
    main()
