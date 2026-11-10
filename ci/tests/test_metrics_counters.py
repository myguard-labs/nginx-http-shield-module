#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Focused live counter, slab-pressure and concurrent-snapshot controls.

Requires a TEST_HARNESS=1 debug or ASan build. An optional baseline module
runs the same bounded, serial unbanned-request benchmark before and after.
"""

from __future__ import annotations

import argparse
import http.client
import json
import signal
import socket
import statistics
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def server(
    binary: Path, module: Path | None, *, workers: int = 4, check_reload: bool = False
):
    """Own one foreground master, its workers and its temporary prefix."""
    with tempfile.TemporaryDirectory(prefix="shield-metrics-") as directory:
        root = Path(directory)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        (root / "html/ab").mkdir(parents=True)
        (root / "html/off-index").mkdir()
        (root / "html/hidden").mkdir()
        (root / "html/index.html").write_text("index response\n")
        (root / "html/ab/index.html").write_text("second zone\n")
        (root / "html/off-index/index.html").write_text("first activation\n")
        (root / "html/hidden/.env").write_text("must not be served\n")
        (root / "html/done.gif").write_text("first zone again\n")
        load = f'load_module "{module}";' if module else ""
        (root / "nginx.conf").write_text(
            f"""{load}
worker_processes {workers};
daemon off;
pid {root}/nginx.pid;
error_log {root}/error.log warn;
events {{ worker_connections 128; }}
http {{
    access_log off;
    shield_ban_zone main:1m;
    shield_ban_zone pressure:32k;
    shield_ban_zone redirects:1m;
    shield_ban_zone second:1m;
    shield_ban_zone refusals:1m;
    server {{
        listen 127.0.0.1:{port};
        root {root}/html;
        index index.html;
        shield block;
        shield_ban zone=redirects count=99999 window=60s bantime=30s;
        location /off-index/ {{ shield off; }}
        location = /reload-ready {{ shield off; return 200 "before"; }}
        location = /off-index/index.html {{ shield block; }}
        location /hidden/ {{ index .env; }}
        location /named {{ error_page 405 = @named; empty_gif; }}
        location @named {{ empty_gif; }}
        location = /ab/index.html {{
            shield_ban zone=second count=99999 window=60s bantime=30s;
            error_page 405 = /done.gif;
            empty_gif;
        }}
        location /redirect-json {{ shield off; shield_ban_status redirects; }}
        location /second-json {{ shield off; shield_ban_status second; }}
        location /arm {{
            shield_ban zone=refusals count=1 window=60s bantime=30s;
            empty_gif;
        }}
        location /ban-redirect {{
            shield_ban zone=refusals count=1 window=60s bantime=30s;
            error_page 403 = @ban-recheck;
            empty_gif;
        }}
        location @ban-recheck {{
            shield_ban zone=refusals count=1 window=60s bantime=30s;
            empty_gif;
        }}
        location /refusal-json {{ shield off; shield_ban_status refusals; }}
        location /t {{
            shield block;
            shield_body on;
            shield_ban zone=main count=2 window=60s bantime=30s;
            empty_gif;
        }}
        location /off {{ shield off; empty_gif; }}
        location /json {{ shield off; shield_ban_status main; }}
        location /metrics {{
            shield off;
            shield_ban_status main;
            shield_ban_status_format prometheus;
        }}
        location /pressure {{
            shield block;
            shield_ban zone=pressure count=99999 window=60s bantime=1s
                       key=forwarded trusted=127.0.0.1;
            empty_gif;
        }}
        location /expire {{
            shield block;
            shield_ban zone=pressure count=99999 window=1s bantime=1s
                       key=forwarded trusted=127.0.0.1;
            empty_gif;
        }}
        location /pressure-json {{ shield off; shield_ban_status pressure; }}
        location /probe {{ shield off; shield_probe pressure; }}
    }}
}}
"""
        )
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
                        request(port, "/json")
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise TimeoutError("nginx did not start") from None
                        time.sleep(0.02)
                yield port
                if check_reload:
                    reload_controls(port, process, root)
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
                output = stderr.read() + (root / "error.log").read_text()
                assert result == 0, output
                assert "AddressSanitizer" not in output, output
                assert "runtime error:" not in output, output


def request(
    port: int, path: str, headers: dict | None = None, method: str = "GET"
) -> tuple[int, bytes]:
    """Make a bounded request and release its connection."""
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(method, path, headers=headers or {})
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def snapshot(port: int, path: str = "/json") -> dict:
    """Read an owned JSON snapshot and enforce the slab gauge invariant."""
    status, body = request(port, path)
    assert status == 200
    document = json.loads(body)
    assert 0 < document["used"] <= document["size"], document
    return document


def controls(port: int, output: Path) -> None:
    """Exercise successful, refused, forced-failure and pressure paths."""
    initial = snapshot(port)
    assert initial["inspected"] == initial["ban_refused"] == 0
    assert initial["size"] == 1048576
    assert request(port, "/off")[0] == 200
    assert snapshot(port)["inspected"] == 0
    assert request(port, "/t")[0] == 200
    assert snapshot(port)["inspected"] == 1

    # Four processes update the same zone while readers take owned snapshots.
    def benign() -> None:
        for _ in range(100):
            assert request(port, "/t")[0] == 200

    previous = 1
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(benign) for _ in range(4)]
        for _ in range(100):
            current = snapshot(port)["inspected"]
            assert previous <= current <= 401
            previous = current
        for future in futures:
            future.result()
    assert snapshot(port)["inspected"] == 401, "concurrent inspections lost updates"
    attack = "/t?id=1%20union%20select%20pw"
    assert request(port, attack)[0] == 403
    assert request(port, attack)[0] == 403
    with ThreadPoolExecutor(max_workers=4) as executor:
        refused_futures = [executor.submit(request, port, "/t") for _ in range(40)]
        for refused_future in refused_futures:
            assert refused_future.result()[0] == 403
    document = snapshot(port)
    assert document["inspected"] == 403, "active bans must skip inspection"
    assert document["ban_refused"] == 40, "active-ban refusals lost updates"
    assert document["blocked"] == 2 and document["bans"] == 1

    redirect_controls(port)
    pressure_controls(port)
    status, payload = request(port, "/metrics")
    assert status == 200
    (output / "metrics.om").write_bytes(payload)
    (output / "metrics.json").write_text(json.dumps(snapshot(port), sort_keys=True))
    print(
        "live: exact inspections/refusals, four-worker snapshots, forced error, "
        "real slab exhaustion and eviction passed"
    )


def redirect_controls(port: int) -> None:
    """Count once per main request per zone without disabling reinspection."""
    initial = snapshot(port, "/redirect-json")
    assert request(port, "/")[0] == 200
    current = snapshot(port, "/redirect-json")
    assert current["inspected"] - initial["inspected"] == 1, (
        "index redirect counted twice"
    )
    assert request(port, "/named", method="POST")[0] == 405
    named = snapshot(port, "/redirect-json")
    assert named["inspected"] - current["inspected"] == 1, (
        "named redirect counted twice"
    )
    assert request(port, "/off-index/")[0] == 200
    active = snapshot(port, "/redirect-json")
    assert active["inspected"] - named["inspected"] == 1, (
        "off-to-active inspection was lost"
    )
    second_before = snapshot(port, "/second-json")
    assert request(port, "/ab/", method="POST")[0] == 200
    revisited = snapshot(port, "/redirect-json")
    second = snapshot(port, "/second-json")
    assert revisited["inspected"] - active["inspected"] == 1, (
        "A-to-B-to-A counted A twice"
    )
    assert second["inspected"] - second_before["inspected"] == 1, (
        "second zone was not counted"
    )
    # Index changes a benign directory URI into a forbidden dotfile. Counting
    # only once must not suppress that second URI inspection.
    assert request(port, "/hidden/")[0] == 403, "redirected URI was not inspected"
    hidden = snapshot(port, "/redirect-json")
    assert hidden["inspected"] - revisited["inspected"] == 1
    assert hidden["blocked"] - revisited["blocked"] == 1
    assert request(port, "/arm?id=1%20union%20select%20pw")[0] == 403
    assert request(port, "/ban-redirect")[0] == 403
    refused = snapshot(port, "/refusal-json")
    assert refused["inspected"] == 1 and refused["ban_refused"] == 1, (
        "redirected refusal counted twice"
    )
    print(
        "redirects: index, named, off-to-active, A-to-B-to-A, URI reinspection "
        "and repeated ban refusal passed"
    )


def reload_controls(port: int, process: subprocess.Popen, root: Path) -> None:
    """Preserve zone totals while a new cycle assigns different marker slots."""
    paths = ("/json", "/redirect-json", "/second-json", "/pressure-json")
    before = {path: snapshot(port, path) for path in paths}
    assert request(port, "/reload-ready") == (200, b"before")
    config = root / "nginx.conf"
    text = config.read_text()
    second = "    shield_ban_zone second:1m;\n"
    assert text.count(second) == 1
    text = text.replace(second, "").replace(
        "    shield_ban_zone main:1m;", second + "    shield_ban_zone main:1m;"
    )
    config.write_text(text.replace('return 200 "before";', 'return 200 "after";'))
    process.send_signal(signal.SIGHUP)
    deadline = time.monotonic() + 10
    while True:
        if request(port, "/reload-ready") == (200, b"after"):
            break
        assert time.monotonic() < deadline, (root / "error.log").read_text()
        time.sleep(0.02)
    for path in paths:
        after = snapshot(port, path)
        for field in (
            "inspected",
            "ban_refused",
            "blocked",
            "bans",
            "evictions",
            "alloc_failures",
            "nodes",
            "used",
            "size",
        ):
            assert after[field] == before[path][field], (path, field, before, after)
    assert request(port, "/t")[0] == 403
    main_zone = snapshot(port)
    assert main_zone["inspected"] == before["/json"]["inspected"]
    assert main_zone["ban_refused"] == before["/json"]["ban_refused"] + 1
    assert request(port, "/off-index/")[0] == 200
    assert request(port, "/ab/", method="POST")[0] == 200
    first = snapshot(port, "/redirect-json")
    second_zone = snapshot(port, "/second-json")
    assert first["inspected"] == before["/redirect-json"]["inspected"] + 2
    assert second_zone["inspected"] == before["/second-json"]["inspected"] + 1
    print("reload: counters, active ban and reassigned per-zone markers preserved")


def pressure_controls(port: int) -> None:
    """Force an allocation error, exhaust real slab pages, and reclaim nodes."""
    # The real hook injects the allocator error without altering vendor code.
    assert request(port, "/probe?fault_slab=1")[0] == 200
    attack = "/pressure?id=1%20union%20select%20pw"
    assert request(port, attack)[0] == 403
    document = snapshot(port, "/pressure-json")
    assert document["alloc_failures"] == 1 and document["nodes"] == 0
    assert document["blocked"] == 1, "allocation failure must retain blocking"
    assert request(port, "/probe?fault_slab=-1")[0] == 200
    assert request(port, attack)[0] == 403
    assert snapshot(port, "/pressure-json")["alloc_failures"] == 1

    # Real slab exhaustion, with distinct trusted forwarded addresses. A 32k
    # zone can hold fewer than 1024 nodes; a fixed bound prevents runaway work.
    for index in range(1, 1025):
        address = f"10.0.{index // 256}.{index % 256}"
        assert request(port, attack, {"X-Forwarded-For": address})[0] == 403
        if index % 16 == 0:
            document = snapshot(port, "/pressure-json")
            if document["alloc_failures"] > 1:
                break
    assert document["alloc_failures"] > 1, "real slab exhaustion was not reached"
    assert document["evictions"] == 0, "live nodes must not be evicted"
    assert document["size"] == 32768
    # The expiry call uses its current one-second counting window.
    time.sleep(1.1)
    assert (
        request(
            port, "/expire?id=1%20union%20select%20pw", {"X-Forwarded-For": "192.0.2.1"}
        )[0]
        == 403
    )
    assert snapshot(port, "/pressure-json")["evictions"] > 0


def benchmark(port: int, count: int) -> list[float]:
    """Measure serial keepalive requests; no concurrent load generator."""
    samples = []
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        for iteration in range(8):
            start = time.perf_counter_ns()
            for _ in range(count):
                connection.request("GET", "/t")
                response = connection.getresponse()
                assert response.status == 200
                response.read()
            elapsed = (time.perf_counter_ns() - start) / count
            if iteration:
                samples.append(elapsed)
    finally:
        connection.close()
    return samples


def main() -> None:
    """Run the requested evidence against explicit binary/module identities."""
    if not __debug__:
        raise RuntimeError(
            "run metric controls without Python -O; assertions are required"
        )
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nginx", type=Path, required=True)
    parser.add_argument("--module", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline-module", type=Path)
    parser.add_argument("--benchmark-only", action="store_true")
    args = parser.parse_args()
    if args.benchmark_only and (not args.baseline_module or not args.module):
        parser.error("--benchmark-only requires --baseline-module and --module")
    args.output.mkdir(parents=True, exist_ok=True)
    if not args.benchmark_only:
        with server(
            args.nginx.resolve(),
            args.module.resolve() if args.module else None,
            check_reload=True,
        ) as port:
            controls(port, args.output)
    if args.baseline_module:
        samples: dict[str, list[float]] = {"baseline": [], "candidate": []}
        # Alternate order across rounds to expose scheduling/drift noise.
        for order in (("baseline", "candidate"), ("candidate", "baseline")):
            for name in order:
                module = args.baseline_module if name == "baseline" else args.module
                with server(args.nginx.resolve(), module.resolve(), workers=1) as port:
                    samples[name].extend(benchmark(port, 2000))
        report: dict[str, object] = dict(samples)
        report["median_ratio"] = statistics.median(
            samples["candidate"]
        ) / statistics.median(samples["baseline"])
        report["baseline_median_ns"] = statistics.median(samples["baseline"])
        report["candidate_median_ns"] = statistics.median(samples["candidate"])
        (args.output / "benchmark.json").write_text(json.dumps(report, indent=2))
        print(json.dumps(report))


if __name__ == "__main__":
    main()
