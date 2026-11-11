#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Focused counters-only shared-memory configuration and live HTTP controls."""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import socket
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path

from test_metrics_counters import request, snapshot


def configuration(root: Path, port: int, module: Path | None, declaration: str) -> str:
    """Keep test status/readiness endpoints excluded from inspection."""
    load = f'load_module "{module}";' if module else ""
    return f"""{load}
worker_processes 4;
daemon off;
pid {root}/nginx.pid;
error_log {root}/error.log notice;
events {{ worker_connections 128; }}
http {{
    access_log off;
    server {{
        listen 127.0.0.1:{port};
        root {root}/html;
        shield block;
        location /t {{ empty_gif; }}
        location /detect {{ shield detect; empty_gif; }}
        location /off {{ shield off; empty_gif; }}
        location /body {{ shield_body on; shield_max_body 3; empty_gif; }}
        location /mixed {{
            shield_ban zone=ban count=2 window=60s bantime=60s;
            empty_gif;
        }}
        location /redirect/ {{ index index.html; }}
        location = /ready {{ shield off; return 200 "before"; }}
        location = /json {{ shield off; shield_ban_status stats; }}
        location = /ban-json {{ shield off; shield_ban_status ban; }}
        location = /metrics {{
            shield off; shield_ban_status stats;
            shield_ban_status_format prometheus;
        }}
    }}
    {declaration}
    shield_ban_zone ban:32k;
}}
"""


@contextmanager
def server(
    binary: Path, module: Path | None, *, kind: str = "stats", mixed: bool = True
):
    """Own only this foreground nginx master and its temporary prefix."""
    with tempfile.TemporaryDirectory(prefix="shield-stats-") as directory:
        root = Path(directory)
        (root / "html/redirect").mkdir(parents=True)
        (root / "html/redirect/index.html").write_text("redirect response\n")
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        declaration = (
            "shield_stats_zone stats 32k;"
            if kind == "stats"
            else "shield_ban_zone stats:32k;"
        )
        config = root / "nginx.conf"
        text = configuration(root, port, module, declaration)
        if not mixed:
            text = (
                text.replace("shield_ban_zone ban:32k;", "")
                .replace("shield_ban zone=ban count=2 window=60s bantime=60s;", "")
                .replace(
                    "location = /ban-json { shield off; shield_ban_status ban; }", ""
                )
            )
        config.write_text(text)
        with (root / "stderr.log").open("w+") as stderr:
            process = subprocess.Popen(
                [str(binary), "-p", f"{root}/", "-c", "nginx.conf"],
                stdout=stderr,
                stderr=stderr,
            )
            try:
                deadline = time.monotonic() + 10
                while True:
                    if process.poll() is not None:
                        stderr.seek(0)
                        raise RuntimeError(stderr.read())
                    try:
                        if request(port, "/ready") == (200, b"before"):
                            break
                    except ConnectionRefusedError:
                        time.sleep(0.02)
                        continue
                    assert time.monotonic() < deadline, "nginx did not start"
                    time.sleep(0.02)
                yield port, process, root
            finally:
                if process.poll() is None:
                    process.send_signal(signal.SIGQUIT)
                try:
                    result = process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                    raise
                stderr.seek(0)
                logs = stderr.read() + (root / "error.log").read_text()
                assert result == 0, logs
                assert "AddressSanitizer" not in logs, logs
                assert "runtime error:" not in logs, logs


def config_test_environment() -> dict[str, str]:
    """Only nginx -t children skip its intentionally retained cycle-pool leaks.

    nginx returns before cycle cleanup in config-test mode. Keep address/UB
    checks and the parent's live-server LeakSanitizer policy unchanged.
    """
    environment = os.environ.copy()
    existing = environment.get("ASAN_OPTIONS", "")
    environment["ASAN_OPTIONS"] = ":".join(
        option for option in (existing, "detect_leaks=0") if option
    )
    return environment


def config_controls(binary: Path, module: Path | None) -> None:
    """Observe positive minimum/forward binding and explicit rejected contracts."""
    minimum = 8 * os.sysconf("SC_PAGE_SIZE")
    cases = [
        (f"shield_stats_zone stats {minimum};", True, ""),
        ("shield_stats_zone stats 0;", False, "minimum 8 pages"),
        (f"shield_stats_zone stats {minimum - 1};", False, "minimum 8 pages"),
        ("shield_stats_zone stats nonsense;", False, "minimum 8 pages"),
        (
            "shield_stats_zone stats 999999999999999999999999g;",
            False,
            "minimum 8 pages",
        ),
        ('shield_stats_zone "" 32k;', False, "minimum 8 pages"),
        ("shield_stats_zone stats;", False, "invalid number of arguments"),
        (
            "shield_stats_zone stats 32k; shield_stats_zone other 32k;",
            False,
            "is duplicate",
        ),
        (
            "shield_ban_zone stats:32k; shield_stats_zone stats 32k;",
            False,
            "already defined",
        ),
        (
            "shield_stats_zone stats 32k; shield_ban_zone stats:32k;",
            False,
            "already defined",
        ),
        ("shield_stats_zone stats 32k;", False, "requires a ban zone"),
        ("shield_stats_zone stats 32k;", False, "requires a ban zone"),
        ("shield_stats_zone stats 32k;", False, "is not allowed here"),
        ("", False, "zero size"),
        (
            "limit_req_zone $binary_remote_addr zone=stats:32k rate=1r/s;",
            False,
            "already declared",
        ),
    ]
    with tempfile.TemporaryDirectory(prefix="shield-stats-config-") as directory:
        root = Path(directory)
        for number, (declaration, valid, message) in enumerate(cases):
            text = configuration(root, 18081, module, declaration)
            if number == 10:
                text = text.replace("shield_ban zone=ban", "shield_ban zone=stats")
            if number == 11:
                text = text.replace("shield_ban_status stats;", "shield_probe stats;")
            if number == 12:
                text = text.replace(declaration, "").replace(
                    "shield block;", f"shield block; {declaration}", 1
                )
            (root / "nginx.conf").write_text(text)
            result = subprocess.run(
                [str(binary), "-p", f"{root}/", "-c", "nginx.conf", "-t"],
                capture_output=True,
                text=True,
                check=False,
                env=config_test_environment(),
            )
            assert (result.returncode == 0) == valid, (number, result.stderr)
            if not valid:
                assert message in result.stderr, (number, result.stderr)
    print("stats config: minimum, forward references and 14 rejection controls passed")


def reload(
    port: int,
    process: subprocess.Popen,
    root: Path,
    text: str,
    *,
    rejected: bool = False,
) -> None:
    """Prove reload completion via a new worker response or a fresh error."""
    old_logs = (root / "error.log").read_text()
    previous = len(old_logs)
    old_workers = set(re.findall(r"start worker process (\d+)", old_logs))
    old_workers.difference_update(re.findall(r"worker process (\d+) exited", old_logs))
    (root / "nginx.conf").write_text(text)
    process.send_signal(signal.SIGHUP)
    deadline = time.monotonic() + 10
    while True:
        if rejected:
            logs = (root / "error.log").read_text()[previous:]
            if "cannot change kind on reload" in logs:
                assert request(port, "/ready") == (200, b"before")
                return
        elif request(port, "/ready") == (200, b"after"):
            # A new worker can respond while old workers still accept requests.
            # Resized zones differ between generations: drain the old set
            # before asserting exact counters in the new shared storage.
            fresh_logs = (root / "error.log").read_text()[previous:]
            exited = set(re.findall(r"worker process (\d+) exited", fresh_logs))
            if old_workers <= exited:
                return
        assert time.monotonic() < deadline, (root / "error.log").read_text()
        time.sleep(0.02)


def checks(binary: Path, module: Path | None, output: Path) -> None:
    """Run stats-only, mixed, concurrent scrape, reload and kind controls."""
    config_controls(binary, module)
    with server(binary, module) as (port, process, root):
        initial = snapshot(port)
        assert initial["inspected"] == initial["blocked"] == 0
        assert initial["nodes"] == initial["bans"] == initial["ban_refused"] == 0
        assert initial["banned"] == []
        assert request(port, "/off")[0] == 200
        assert snapshot(port)["inspected"] == 0
        assert request(port, "/t")[0] == 200
        assert request(port, "/redirect/")[0] == 200
        assert snapshot(port)["inspected"] == 2, "redirect counted twice"
        assert request(port, "/t", {"Proxy": "bad"})[0] == 403
        assert request(port, "/detect", {"Proxy": "bad"})[0] == 200
        assert request(port, "/body", method="POST", body="abcd")[0] == 405
        assert (
            request(port, "/body", {"Content-Encoding": "gzip"}, "POST", "a")[0] == 405
        )
        before = snapshot(port)
        assert before["inspected"] == 6
        assert before["blocked"] == 1
        assert before["categories"]["httpoxy"] == 2
        assert before["detections"]["httpoxy"] == {"detect": 1, "block": 1}
        assert before["body_uninspected"] == {"too_large": 1, "encoding": 1, "error": 0}
        for _ in range(2):
            assert request(port, "/mixed", {"Proxy": "bad"})[0] == 403
        assert request(port, "/mixed")[0] == 403
        mixed = snapshot(port)
        ban = snapshot(port, "/ban-json")
        assert mixed["inspected"] == 8 and mixed["ban_refused"] == 1
        assert mixed["blocked"] == 3 and mixed["bans"] == 0
        assert mixed["nodes"] == 0 and mixed["banned"] == []
        assert ban["inspected"] == 2 and ban["ban_refused"] == ban["bans"] == 1
        assert ban["blocked"] == 2
        # Concurrent request updates and live scrape reads must not lose counts.
        with ThreadPoolExecutor(max_workers=5) as executor:

            def traffic(detect: bool) -> None:
                for _ in range(25):
                    assert request(
                        port, "/detect" if detect else "/t", {"Proxy": "bad"}
                    )[0] == (200 if detect else 403)

            futures = [executor.submit(traffic, bool(i % 2)) for i in range(4)]
            observed = mixed["inspected"]
            for _ in range(20):
                document = snapshot(port)
                assert observed <= document["inspected"] <= 108
                observed = document["inspected"]
            for future in futures:
                future.result()
        final = snapshot(port)
        assert final["inspected"] == 108, "concurrent atomic updates lost"
        assert final["categories"]["httpoxy"] == 104
        assert final["detections"]["httpoxy"] == {"detect": 51, "block": 53}
        assert final["blocked"] == 53
        assert final["evictions"] == final["alloc_failures"] == 0
        status, prometheus = request(port, "/metrics")
        assert status == 200 and b"# EOF" not in prometheus
        status, om = request(
            port, "/metrics", {"Accept": "application/openmetrics-text"}
        )
        assert status == 200 and om.endswith(b"# EOF\n")
        marker = b'shield_source_hits_total{zone="stats",category="httpoxy",source="header"} 104'
        assert marker in prometheus and marker in om
        (output / "stats.prom").write_bytes(prometheus)
        (output / "stats.om").write_bytes(om)
        (output / "stats.json").write_text(json.dumps(final, sort_keys=True))
        config = (root / "nginx.conf").read_text()
        # Swap definition order to change per-cycle indexed marker assignment.
        changed = config.replace("shield_ban_zone ban:32k;", "").replace(
            "shield_stats_zone stats 32k;",
            "shield_ban_zone ban:32k; shield_stats_zone stats 32k;",
        )
        reload(port, process, root, changed.replace('"before"', '"after"'))
        assert snapshot(port) == final, "stats counters changed across reload"
        assert request(port, "/t")[0] == 200
        assert snapshot(port)["inspected"] == 109
    with server(binary, module, mixed=False) as (port, _, _):
        assert request(port, "/t", {"Proxy": "bad"})[0] == 403
        assert request(port, "/t")[0] == 200
        document = snapshot(port)
        assert document["inspected"] == 2 and document["blocked"] == 1
        assert document["bans"] == document["nodes"] == 0
    for kind in ("stats", "ban"):
        with server(binary, module, kind=kind) as (port, process, root):
            text = (root / "nginx.conf").read_text()
            if kind == "stats":
                text = text.replace(
                    "shield_stats_zone stats 32k;", "shield_ban_zone stats:32k;"
                )
            else:
                text = text.replace(
                    "shield_ban_zone stats:32k;", "shield_stats_zone stats 32k;"
                )
            reload(port, process, root, text, rejected=True)
            assert snapshot(port)["inspected"] == 0
    resize_controls(binary, module)
    print(
        "stats live: block-only, detect, body, mixed, concurrent scrape, "
        "reload and kind guards passed"
    )


def resize_controls(binary: Path, module: Path | None) -> None:
    """Nginx allocates fresh storage on resize, allowing either new zone kind."""
    for old_kind, new_kind in (
        ("stats", "stats"),
        ("stats", "ban"),
        ("ban", "stats"),
        ("ban", "ban"),
    ):
        with server(binary, module, kind=old_kind) as (port, process, root):
            assert request(port, "/t", {"Proxy": "bad"})[0] == 403
            before = snapshot(port)
            assert before["inspected"] == (1 if old_kind == "stats" else 0)
            old = (
                "shield_stats_zone stats 32k;"
                if old_kind == "stats"
                else "shield_ban_zone stats:32k;"
            )
            new = (
                "shield_stats_zone stats 64k;"
                if new_kind == "stats"
                else "shield_ban_zone stats:64k;"
            )
            text = (root / "nginx.conf").read_text().replace(old, new)
            reload(port, process, root, text.replace('"before"', '"after"'))
            fresh = snapshot(port)
            assert fresh["size"] == 65536
            for field in ("inspected", "blocked", "ban_refused", "bans", "nodes"):
                assert fresh[field] == 0, (old_kind, new_kind, field, fresh)
            assert not any(fresh["categories"].values())
            assert request(port, "/t", {"Proxy": "bad"})[0] == 403
            after = snapshot(port)
            assert after["inspected"] == (1 if new_kind == "stats" else 0)
            assert after["blocked"] == (1 if new_kind == "stats" else 0)
    print(
        "stats resize: same-kind and changed-kind fresh storage in both directions passed"
    )


def main() -> None:
    """Allow independent replay and mutation selection without the other suite."""
    if not __debug__:
        raise RuntimeError("run stats controls without Python -O")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nginx", type=Path, required=True)
    parser.add_argument("--module", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    checks(
        args.nginx.resolve(),
        args.module.resolve() if args.module else None,
        args.output,
    )


if __name__ == "__main__":
    main()
