#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Real HTTP/1 body callbacks across nginx error_page context resets.

The small content fixture owns one async reference and completes independently
of Shield. No core or Shield callbacks are replaced. Run via prove or directly;
CALLBACK_RESET_OUTPUT retains per-case logs and the compiler command for review.
"""

if not __debug__:
    raise RuntimeError("callback-reset requires Python assertions enabled")

import json
import os
import shlex
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
TIMEOUT = float(os.environ.get("TEST_NGINX_TIMEOUT", "20"))


def wait_log(path, marker, proc):
    deadline = time.monotonic() + TIMEOUT
    while time.monotonic() < deadline:
        text = path.read_text(errors="replace") if path.exists() else ""
        if marker in text:
            return text
        if proc.poll() is not None:
            raise AssertionError(f"nginx exited {proc.returncode} before {marker!r}")
        time.sleep(0.01)
    raise AssertionError(f"timeout waiting for {marker!r}")


def read_response(client):
    data = b""
    while True:
        part = client.recv(65536)
        if not part:
            return data
        data += part


def check_response(response, status, body=None):
    header, sep, actual_body = response.partition(b"\r\n\r\n")
    assert sep, f"response missing headers: {response!r}"
    assert header.split(b"\r\n")[0].split()[1] == str(status).encode(), response
    lengths = [
        line.split(b":", 1)[1].strip()
        for line in header.split(b"\r\n")
        if line.lower().startswith(b"content-length:")
    ]
    assert len(lengths) == 1, f"missing/duplicate Content-Length: {header!r}"
    assert len(actual_body) == int(lengths[0]), "incomplete HTTP response"
    if body is not None:
        assert actual_body == body, actual_body


def build_fixture(nginx, output):
    build = nginx.parent
    source = build.parent
    includes = [
        source / "src" / sub
        for sub in (
            "core",
            "event",
            "event/modules",
            "event/quic",
            "os/unix",
            "http",
            "http/modules",
            "http/v2",
            "http/v3",
        )
    ]
    compiler = shutil.which("cc")
    assert compiler is not None, "callback-reset requires cc"
    command = [
        compiler,
        "-shared",
        "-fPIC",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-Wshadow",
        "-I",
        str(build),
    ]
    for include in includes:
        command += ["-I", str(include)]
    module = output / "ngx_http_callback_reset_module.so"
    command += [str(HERE / "ngx_http_callback_reset_module.c"), "-o", str(module)]
    (output / "compile.json").write_text(json.dumps(command, indent=2) + "\n")
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    (output / "compile.stdout").write_text(result.stdout)
    (output / "compile.stderr").write_text(result.stderr)
    assert result.returncode == 0, f"fixture compile failed: {result.stderr}"
    return module


def run_case(
    nginx,
    module,
    root,
    name,
    redirect=None,
    early="off",
    dest_limit=0,
    body=b"union select",
    status=200,
    strict=False,
    malformed=False,
    ban=False,
):
    case = root / name
    case.mkdir()
    (case / "body_temp").mkdir()
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    target = "/destination" if redirect == "uri" else "@destination"
    destination = (
        "location = /destination" if redirect == "uri" else "location @destination"
    )
    policy = (
        "shield off;" if early == "off" else "shield block; shield_allow 127.0.0.1;"
    )
    if ban:
        policy = "shield block; shield_ban zone=reset count=1 window=60s bantime=60s;"
    routing = f"error_page 413 = {target};" if redirect else ""
    limit = 4 if redirect else 0
    extra = (
        (
            f"{destination} {{ {policy} shield_body_strict on; "
            f"client_max_body_size {dest_limit}; callback_reset_suspend; }}"
        )
        if redirect
        else ""
    )
    loads = [
        f'load_module "{path}";'
        for path in shlex.split(os.environ.get("TEST_NGINX_LOAD_MODULES", ""))
        + [str(module)]
    ]
    config = (
        "\n".join(loads)
        + f"""
daemon off;
master_process off;
error_log stderr debug;
pid nginx.pid;
events {{ worker_connections 32; }}
http {{
    access_log off;
    client_body_temp_path body_temp;
    shield_ban_zone reset:1m;
    server {{
        listen 127.0.0.1:{port};
        location = /seed {{ shield block;
            shield_ban zone=reset count=1 window=60s bantime=60s;
            callback_reset_suspend; }}
        location = /start {{ shield block; shield_body on;
            shield_body_strict {"on" if strict else "off"};
            client_max_body_size {limit}; {routing} callback_reset_suspend; }}
        {extra}
    }}
}}
"""
    )
    conf = case / "nginx.conf"
    conf.write_text(config)
    log_path = case / "nginx.stderr"
    result = {"name": name, "status": "FAIL"}
    client = None
    with log_path.open("wb") as stderr, (case / "nginx.stdout").open("wb") as stdout:
        command = [str(nginx), "-p", str(case), "-c", str(conf)]
        result["command"] = command
        proc = subprocess.Popen(command, stdout=stdout, stderr=stderr)
        result["pid"] = proc.pid
        try:
            wait_log(log_path, "using the", proc)
            if ban:
                with socket.create_connection(
                    ("127.0.0.1", port), timeout=TIMEOUT
                ) as seed:
                    seed.sendall(
                        b"GET /seed?x=union%20select HTTP/1.1\r\nHost: reset\r\nConnection: close\r\n\r\n"
                    )
                    check_response(read_response(seed), 403)
            client = socket.create_connection(("127.0.0.1", port), timeout=TIMEOUT)
            client.sendall(
                b"POST /start HTTP/1.1\r\nHost: reset\r\n"
                b"Content-Type: text/plain\r\nTransfer-Encoding: chunked\r\n"
                b"Expect: 100-continue\r\nConnection: close\r\n\r\n"
            )
            interim = b""
            while b"\r\n\r\n" not in interim:
                part = client.recv(1)
                assert part, "closed before 100 Continue"
                interim += part
            assert interim == b"HTTP/1.1 100 Continue\r\n\r\n", interim
            if malformed:
                client.sendall(b"Z\r\nbad\r\n0\r\n\r\n")
            elif redirect:
                client.sendall(f"{len(body):x}\r\n".encode() + body[:4])
                marker = "shield: banned request" if ban else "callback-reset suspend"
                log = wait_log(log_path, marker, proc)
                assert "client intended to send too large chunked body" in log
                if not ban:
                    method = 2 if redirect == "uri" else 8
                    assert f"callback-reset suspend method={method}" in log, log
                client.sendall(body[4:] + b"\r\n0\r\n\r\n")
            else:
                wire = (
                    f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n"
                    if body
                    else b"0\r\n\r\n"
                )
                client.sendall(wire)
            response = read_response(client)
            (case / "response.bin").write_bytes(response)
            check_response(
                response, status, b"destination-complete\n" if status == 200 else None
            )
            if status == 200 or (redirect and not ban):
                log = wait_log(log_path, "callback-reset cleanup", proc)
            else:
                log = log_path.read_text(errors="replace")
            assert proc.poll() is None, f"nginx exited {proc.returncode}"
            assert "AddressSanitizer" not in log, "sanitizer failure"
            assert "runtime error:" not in log, "undefined behavior"
            assert "unexpected content reentry" not in log, (
                "destination phases restarted"
            )
            if status == 200:
                assert log.count("callback-reset suspend method=") == 1, (
                    "content handler reran"
                )
                assert log.count("callback-reset complete count=1") == 1, (
                    "unbalanced async reference"
                )
                assert log.count("callback-reset cleanup") == 1, (
                    "request pool not freed exactly once"
                )
                if not redirect and body == b"union select":
                    assert (
                        "category=sqli source=body verdict=suspicious action=observe"
                        in log
                    )
                if redirect:
                    assert "shield: observed" not in log, (
                        "stale callback inspected destination body"
                    )
                    assert "shield: blocked" not in log, (
                        "stale callback enforced destination policy"
                    )
            elif status == 403:
                assert "callback-reset suspend" not in log, (
                    "blocked request entered content"
                )
                assert (
                    "shield: banned request" if ban else "category=sqli source=body"
                ) in log
            elif malformed:
                assert "client sent invalid chunked body" in log
                assert "callback-reset suspend" not in log
            elif status == 413:
                assert log.count("client intended to send too large chunked body") == 2
                assert "callback-reset complete" not in log, (
                    "limited destination completed body"
                )
            result.update(status="PASS", expected_http=status)
        except Exception as exc:
            result["failure"] = str(exc)
            raise
        finally:
            if client is not None:
                client.close()
            if proc.poll() is None:
                proc.terminate()  # Only this Popen-owned child, never a PID read from a file.
            try:
                proc.wait(timeout=TIMEOUT)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=TIMEOUT)
            result["final_returncode"] = proc.returncode
            (case / "result.json").write_text(json.dumps(result, indent=2) + "\n")


def main():
    nginx = Path(shutil.which(os.environ.get("TEST_NGINX_BINARY", "nginx")) or "")
    assert nginx.is_file(), "TEST_NGINX_BINARY must identify a built server"
    selected = os.environ.get("CALLBACK_RESET_OUTPUT")
    temporary = (
        None
        if selected
        else tempfile.TemporaryDirectory(prefix="shield-callback-reset-")
    )
    root = Path(selected or temporary.name).resolve()
    root.mkdir(parents=True, exist_ok=True)
    try:
        module = build_fixture(nginx, root)
        cases = [
            (f"{redirect}-{early}", {"redirect": redirect, "early": early})
            for redirect in ("uri", "named")
            for early in ("off", "allowlist")
        ]
        cases += [
            ("destination-limit", {"redirect": "uri", "dest_limit": 4, "status": 413}),
            ("active-ban", {"redirect": "uri", "ban": True, "status": 403}),
            ("normal-empty", {"body": b""}),
            ("normal-limit-four", {"body": b"ABCD"}),
            ("normal-observe", {}),
            ("normal-strict-block", {"strict": True, "status": 403}),
            ("malformed-chunk", {"malformed": True, "status": 400}),
        ]
        print(f"1..{len(cases)}", flush=True)
        failures = 0
        for index, (name, kwargs) in enumerate(cases, 1):
            try:
                run_case(nginx, module, root, name, **kwargs)
                print(f"ok {index} - {name}", flush=True)
            except (AssertionError, OSError, subprocess.SubprocessError) as exc:
                failures += 1
                print(
                    f"not ok {index} - {name}\n# {str(exc)!r}\n# artifacts: {root / name}",
                    flush=True,
                )
        return bool(failures)
    finally:
        if temporary is not None:
            temporary.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
