#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Focused native allowlist configuration, trust, side-effect and reload controls."""

from __future__ import annotations

import argparse
import gzip
import http.client
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from test_compressed_body import stop_server
from test_cve_controls import CRAFT25
from test_stats_zone import config_test_environment

ATTACK = "?q=union%20select"
FORM = b"q=union+select"

# Empty octets must never acquire nginx's implicit zero value.
EMPTY_OCTET_ADDRESSES = [
    "...",
    ".../24",
    ".0.2.1",
    ".0.2.1/24",
    "192..2.1",
    "192..2.1/24",
    "192.0..1",
    "192.0..1/24",
    "192.0.2.",
    "192.0.2./24",
    "192..2.0",
    "192..2.0/24",
    ".../0",
    "::ffff:...",
    "::ffff:.../120",
    "::ffff:.0.2.1",
    "::ffff:.0.2.1/120",
    "::ffff:192..2.1",
    "::ffff:192..2.1/120",
    "::ffff:192.0..1",
    "::ffff:192.0..1/120",
    "::ffff:192.0.2.",
    "::ffff:192.0.2./120",
    "::ffff:192..2.0",
    "::ffff:192..2.0/120",
    "2001:db8::...",
    "2001:db8::.../120",
    "2001:db8::.0.2.1",
    "2001:db8::.0.2.1/120",
    "2001:db8::192..2.1",
    "2001:db8::192..2.1/120",
    "2001:db8::192.0..1",
    "2001:db8::192.0..1/120",
    "2001:db8::192.0.2.",
    "2001:db8::192.0.2./120",
    "2001:db8::192..2.0",
    "2001:db8::192..2.0/120",
]


def request(port, path, *, source="127.0.0.1", headers=None, body=None, unix=None):
    """Complete each response before returning; use a fresh connection per probe."""
    connection = http.client.HTTPConnection(
        "127.0.0.1", port, timeout=5, source_address=(source, 0)
    )
    try:
        if unix is not None:
            connection.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            connection.sock.settimeout(5)
            connection.sock.connect(str(unix))
        connection.request(
            "POST" if body is not None else "GET", path, body, headers or {}
        )
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def wait_for(process, predicate, description):
    """A bounded readiness predicate also detects an unexpectedly exited master."""
    deadline = time.monotonic() + 10
    while True:
        assert process.poll() is None, (description, "nginx exited", process.returncode)
        try:
            if predicate():
                return
        except (OSError, http.client.HTTPException):
            pass
        assert time.monotonic() < deadline, description
        time.sleep(0.02)


def activate_config(process, root, port, text, marker):
    """Retire old workers before testing a changed policy on new connections."""
    (root / "nginx.conf").write_text(text)
    log = root / "error.log"
    exits = log.read_text().count("exited with code 0")
    process.send_signal(signal.SIGHUP)
    wait_for(
        process,
        lambda: log.read_text().count("exited with code 0") > exits,
        "old worker drained after reload",
    )
    wait_for(
        process, lambda: request(port, "/ready") == (200, marker), "new worker ready"
    )


def config_controls(binary, module, output):
    """Run real nginx -t, checking accepted grammar and each fatal class."""
    valid = [
        "192.0.2.10",
        "192.0.2.0/24",
        "2001:db8::1",
        "2001:db8::/32",
        "0:0:1::/48",  # Nonzero second word in nginx's V4MAPPED guard.
        "0.0.0.0/0",
        "192.0.2.10/32",
        "::/0",
        "2001:db8::1/128",
        "::ffff:192.0.2.10",
        "::ffff:192.0.2.0/120",
        "::ffff:0.0.0.0/96",
        "::ffff:192.0.2.10/128",
        "off",
        "192.0.2.10 2001:db8::/32",
    ]
    cases = [(f"shield_allow {value};", True, "") for value in valid]
    cases += [
        ("shield_allow 192.0.2.7/24;", True, "low address bits"),
        ("shield_allow 2001:db8::7/32;", True, "low address bits"),
        ("shield_allow 192.0.2.1; shield_allow 2001:db8::1;", True, ""),
    ]
    invalid = EMPTY_OCTET_ADDRESSES + [
        "",
        "all",
        "localhost",
        "$remote_addr",
        "192.0.2.1:80",
        "[::1]:80",
        "192.0.2.256",
        "192.0.2",
        "192.0.2.1/33",
        "192.0.2.1/-1",
        "192.0.2.1/",
        "192.0.2.1/24/1",
        "2001:db8::1/129",
        "2001:db8:::1",
        "off 192.0.2.1",
        "192.0.2.1 off",
        "off off",
        "unix:/tmp/client.sock",
    ]
    cases += [(f"shield_allow {value};", False, "") for value in invalid]
    cases += [
        ("shield_allow off; shield_allow 192.0.2.1;", False, "cannot follow off"),
        ("shield_allow 192.0.2.1; shield_allow off;", False, "must be used alone"),
    ]
    results = []
    with tempfile.TemporaryDirectory(prefix="shield-allow-config-") as directory:
        root = Path(directory)
        (root / "logs").mkdir()
        load = f'load_module "{module}";' if module else ""
        for context in ("http", "server", "location"):
            for declaration, accepted, message in cases:
                location = (
                    f"location / {{ {declaration if context == 'location' else ''} }}"
                )
                server = f"server {{ {declaration if context == 'server' else ''} {location} }}"
                main = declaration if context == "http" else ""
                text = (
                    f"{load}\nerror_log stderr; events {{}} http {{ {main} {server} }}"
                )
                config = root / "nginx.conf"
                config.write_text(text)
                result = subprocess.run(
                    [str(binary), "-t", "-p", f"{root}/", "-c", str(config)],
                    capture_output=True,
                    text=True,
                    env=config_test_environment(),
                    check=False,
                )
                label = f"{context}: {declaration}"
                with (output / "config.log").open("a") as log:
                    log.write(f"{label}\nexit={result.returncode}\n{result.stderr}\n")
                assert (result.returncode == 0) == accepted, (label, result.stderr)
                assert message in result.stderr, (label, message, result.stderr)
                results.append(label)
    return results


def configuration(root, port, module, ipv6):
    """Exercise the same route with direct, trusted and forged client identities."""
    load = f'load_module "{module}";' if module else ""
    listen6 = f"listen [::1]:{port};" if ipv6 else ""
    return f"""{load}
env GCOV_PREFIX;
worker_processes 1;
daemon off;
pid {root}/nginx.pid;
error_log {root}/error.log notice;
events {{ worker_connections 128; }}
http {{
    access_log {root}/access.log;
    shield block;
    shield_allow 127.0.0.1;
    shield_log {root}/hits.jsonl;
    shield_stats_zone stats 32k;
    shield_ban_zone bans:32k;
    server {{
        listen 127.0.0.1:{port};
        {listen6}
        listen unix:{root}/nginx.sock;
        root {root}/html;
        location = /ready {{ shield off; return 200 "before"; }}
        location = /stats {{ shield off; shield_ban_status stats; }}
        location = /metrics {{
            shield off; shield_ban_status stats;
            shield_ban_status_format prometheus;
        }}
        location = /ban-stats {{ shield off; shield_ban_status bans; }}
        location /t {{ empty_gif; }}
        location /off {{ shield off; empty_gif; }}
        location /clear {{ shield_allow off; empty_gif; }}
        location /replace {{ shield_allow 127.0.0.2; empty_gif; }}
        location /append {{
            shield_allow 127.0.0.2;
            shield_allow 127.0.0.3 2001:db8::1;
            empty_gif;
        }}
        location /ipv6 {{ shield_allow ::1; empty_gif; }}
        location /zero {{ shield_allow 0.0.0.0/0 ::/0; empty_gif; }}
        location /trusted/ {{
            set_real_ip_from 127.0.0.1;
            real_ip_header X-Forwarded-For;
            real_ip_recursive on;
            shield_allow 192.0.2.0/24 2001:db8::/127;
            location /trusted/exact {{ shield_allow 192.0.2.10/32 2001:db8::1/128; empty_gif; }}
            location /trusted/hostbits {{ shield_allow 192.0.2.7/24 2001:db8::7/127; empty_gif; }}
            location /trusted/mapped96 {{ shield_allow ::ffff:0.0.0.0/96; empty_gif; }}
            location /trusted/mapped128 {{ shield_allow ::ffff:192.0.2.10/128; empty_gif; }}
            location /trusted/mapped {{ shield_allow ::ffff:192.0.2.0/120; empty_gif; }}
            empty_gif;
        }}
        location /forged {{ shield_allow 192.0.2.0/24 2001:db8::/127; empty_gif; }}
        location /ban-forwarded {{
            shield_allow 192.0.2.0/24;
            shield_ban zone=bans count=1 window=60s bantime=60s key=forwarded trusted=127.0.0.1;
            empty_gif;
        }}
        location /body {{ shield_gzip on; shield_cve craft_cms; empty_gif; }}
        location /limited {{ shield_max_body 1; empty_gif; }}
        location /php/ {{ shield_cve php_cgi; empty_gif; }}
        location /ban {{ shield_ban zone=bans count=1 window=60s bantime=60s; empty_gif; }}
        location /redirect/ {{ index index.html; }}
        location = /redirect/index.html {{ shield_allow off; }}
        location /inherit-redirect/ {{ index index.html; }}
        location = /ssi.html {{ shield off; ssi on; default_type text/html; }}
        location /sub {{ shield_allow off; empty_gif; }}
    }}
    server {{
        listen 127.0.0.1:{port};
        server_name cleared;
        shield_allow off;
        location / {{ empty_gif; }}
    }}
    server {{
        listen 127.0.0.1:{port};
        server_name replaced;
        shield_allow 127.0.0.2;
        location / {{ empty_gif; }}
    }}
}}
"""


def runtime_controls(binary, module, output):
    """Pair bypass assertions with live inspection, logging and ban controls."""
    results = []
    with tempfile.TemporaryDirectory(prefix="shield-allow-runtime-") as directory:
        root = Path(directory)
        (root / "logs").mkdir()
        root.chmod(0o755)
        (root / "html/redirect").mkdir(parents=True)
        (root / "html/redirect/index.html").write_text("redirect response")
        (root / "html/inherit-redirect").mkdir()
        (root / "html/inherit-redirect/index.html").write_text("inherited response")
        (root / "html/ssi.html").write_text(f'<!--# include virtual="/sub{ATTACK}" -->')
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        try:
            with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as listener:
                listener.bind(("::1", port))
            ipv6 = True
        except OSError:
            ipv6 = False
        config = root / "nginx.conf"
        text = configuration(root, port, module, ipv6)
        config.write_text(text)
        (output / "runtime.conf").write_text(text)
        with (root / "stderr").open("w+") as stderr:
            process = subprocess.Popen(
                [str(binary), "-p", f"{root}/", "-c", "nginx.conf"],
                stdout=stderr,
                stderr=stderr,
                start_new_session=True,
            )
            try:
                wait_for(
                    process,
                    lambda: request(port, "/ready") == (200, b"before"),
                    "startup",
                )

                def check(name, path, status, **kwargs):
                    actual, body = request(port, path, **kwargs)
                    assert actual == status, (name, actual, status, body[:200])
                    results.append(name)
                    return body

                def stats(route="/stats"):
                    status, body = request(port, route)
                    assert status == 200, (route, status, body)
                    return json.loads(body)

                def hits():
                    return (root / "hits.jsonl").read_bytes()

                initial_metrics = check("initial source metrics", "/metrics", 200)
                initial, initial_bans, initial_hits = (
                    stats(),
                    stats("/ban-stats"),
                    hits(),
                )
                check("direct IPv4 inherited bypass", "/t" + ATTACK, 200)
                check(
                    "Shield off remains cheapest",
                    "/off" + ATTACK,
                    200,
                    source="127.0.0.2",
                )
                surfaces = [
                    ("header", "/t", {"X-Note": "() { :;}; /bin/bash -c id"}, None),
                    ("CVE query", "/php/?-d+auto_prepend_file", {}, None),
                    (
                        "form",
                        "/body",
                        {"Content-Type": "application/x-www-form-urlencoded"},
                        FORM,
                    ),
                    (
                        "JSON",
                        "/body",
                        {"Content-Type": "application/json"},
                        b'{"q":"union select"}',
                    ),
                    (
                        "CVE body",
                        "/body",
                        {"Content-Type": "application/json"},
                        CRAFT25.encode(),
                    ),
                    (
                        "gzip",
                        "/body",
                        {
                            "Content-Type": "application/json",
                            "Content-Encoding": "gzip",
                        },
                        gzip.compress(CRAFT25.encode(), mtime=0),
                    ),
                    (
                        "body budget",
                        "/limited",
                        {"Content-Type": "application/json"},
                        b'{"q":1}',
                    ),
                    (
                        "unsupported encoding",
                        "/body",
                        {"Content-Type": "application/json", "Content-Encoding": "br"},
                        b"benign",
                    ),
                ]
                for name, route, headers, body in surfaces:
                    check(
                        f"allowlisted {name}",
                        route,
                        405 if body is not None else 200,
                        headers=headers,
                        body=body,
                    )
                check("allowlisted cannot arm ban", "/ban" + ATTACK, 200)
                assert stats() == initial, (
                    "allowlisted requests changed global Shield counters"
                )
                assert stats("/ban-stats") == initial_bans, (
                    "allowlisted requests changed ban state/counters"
                )
                assert hits() == initial_hits, (
                    "allowlisted requests wrote a Shield hit log"
                )
                assert (
                    check("allowlisted source counters unchanged", "/metrics", 200)
                    == initial_metrics
                )
                access = (root / "access.log").read_text()
                assert "/ban" + ATTACK in access, (
                    "allowlisted requests missing from nginx access log"
                )

                check("neighbor blocked", "/t" + ATTACK, 403, source="127.0.0.2")
                for name, route, headers, body in surfaces:
                    check(
                        f"unallowlisted {name}",
                        route,
                        405 if name in ("body budget", "unsupported encoding") else 403,
                        source="127.0.0.2",
                        headers=headers,
                        body=body,
                    )
                after = stats()
                assert after["inspected"] > initial["inspected"], after
                assert after["blocked"] > initial["blocked"], after
                assert (
                    after["body_uninspected"]["too_large"]
                    > initial["body_uninspected"]["too_large"]
                ), after
                assert (
                    after["body_uninspected"]["encoding"]
                    > initial["body_uninspected"]["encoding"]
                ), after
                assert hits() != initial_hits, (
                    "unallowlisted attacks did not write hit logs"
                )
                metrics = check("unallowlisted source metrics live", "/metrics", 200)
                source_metrics = {
                    label: int(value)
                    for line in metrics.decode().splitlines()
                    if line.startswith("shield_source_hits_total{")
                    for label, value in [line.rsplit(" ", 1)]
                }
                for source in ("uri", "header", "body"):
                    assert (
                        sum(
                            value
                            for label, value in source_metrics.items()
                            if f'source="{source}"' in label
                        )
                        > 0
                    ), source_metrics
                (output / "sources.prom").write_bytes(metrics)
                records = [json.loads(line) for line in hits().splitlines()]
                assert {record["src"] for record in records} >= {
                    "uri",
                    "header",
                    "body",
                }, records
                assert any(record["cat"] == "deserial" for record in records), records
                check(
                    "unallowlisted arms ban", "/ban" + ATTACK, 403, source="127.0.0.2"
                )
                before_refusal = stats("/ban-stats")
                check("unallowlisted ban is live", "/ban", 403, source="127.0.0.2")
                banned = stats("/ban-stats")
                assert banned["bans"] > initial_bans["bans"] and banned["banned"], (
                    banned
                )
                assert banned["ban_refused"] == before_refusal["ban_refused"] + 1, (
                    banned
                )
                # Add the already-banned address locally: bypass must beat ban lookup.
                text = text.replace(
                    "location /ban {",
                    "location /ban { shield_allow 127.0.0.1 127.0.0.2;",
                )
                activate_config(
                    process,
                    root,
                    port,
                    text.replace('return 200 "before"', 'return 200 "ban-ready"'),
                    b"ban-ready",
                )
                before_bypass, before_ban_bypass, before_logs = (
                    stats(),
                    stats("/ban-stats"),
                    hits(),
                )
                check(
                    "allowlisted active ban bypass",
                    "/ban" + ATTACK,
                    200,
                    source="127.0.0.2",
                )
                assert (
                    stats() == before_bypass
                    and stats("/ban-stats") == before_ban_bypass
                )
                assert hits() == before_logs

                for name, path, source, expected in [
                    ("child off clears", "/clear", "127.0.0.1", 403),
                    ("child replaces parent", "/replace", "127.0.0.1", 403),
                    ("child replacement matches", "/replace", "127.0.0.2", 200),
                    ("append first retained", "/append", "127.0.0.2", 200),
                    ("append second matches", "/append", "127.0.0.3", 200),
                    ("append excludes parent", "/append", "127.0.0.1", 403),
                    ("IPv4 zero prefix", "/zero", "127.0.0.2", 200),
                    ("redirect rechecks clear", "/redirect/", "127.0.0.1", 403),
                    ("redirect inherits", "/inherit-redirect/", "127.0.0.1", 200),
                    ("subrequest main blocked", "/sub", "127.0.0.1", 403),
                ]:
                    check(name, path + ATTACK, expected, source=source)
                ssi = check("subrequest remains excluded", "/ssi.html", 200)
                assert ssi.startswith(b"GIF"), ssi
                check(
                    "non-IP Unix peer fails closed",
                    "/zero" + ATTACK,
                    403,
                    unix=root / "nginx.sock",
                )
                check(
                    "server off clears http list",
                    "/t" + ATTACK,
                    403,
                    headers={"Host": "cleared"},
                )
                check(
                    "server replacement drops http entry",
                    "/t" + ATTACK,
                    403,
                    headers={"Host": "replaced"},
                )
                check(
                    "server replacement matches",
                    "/t" + ATTACK,
                    200,
                    source="127.0.0.2",
                    headers={"Host": "replaced"},
                )
                check(
                    "ban forwarded trust grants no allowlist bypass",
                    "/ban-forwarded" + ATTACK,
                    403,
                    headers={"X-Forwarded-For": "192.0.2.10"},
                )
                if ipv6:
                    connection = http.client.HTTPConnection("::1", port, timeout=5)
                    try:
                        connection.request("GET", "/ipv6" + ATTACK)
                        response = connection.getresponse()
                        assert response.status == 200, response.read()
                        response.read()
                    finally:
                        connection.close()
                    results.append("direct IPv6 bypass")
                else:
                    results.append(
                        "direct IPv6 unavailable; realip IPv6 controls remain mandatory"
                    )

                for address, expected in [
                    ("192.0.2.0", 200),
                    ("192.0.2.255", 200),
                    ("192.0.3.0", 403),
                    ("192.0.1.255", 403),
                    ("2001:db8::", 200),
                    ("2001:db8::1", 200),
                    ("2001:db8::2", 403),
                    ("::ffff:192.0.2.10", 200),
                    ("::ffff:192.0.3.10", 403),
                    ("garbage", 403),
                ]:
                    headers = {"X-Forwarded-For": address}
                    check(
                        f"trusted {address}",
                        "/trusted/t" + ATTACK,
                        expected,
                        headers=headers,
                    )
                    check(f"forged {address}", "/forged" + ATTACK, 403, headers=headers)
                    check(
                        f"untrusted peer {address}",
                        "/trusted/t" + ATTACK,
                        403,
                        source="127.0.0.2",
                        headers=headers,
                    )
                for route, address, expected in [
                    ("exact", "192.0.2.10", 200),
                    ("exact", "192.0.2.11", 403),
                    ("exact", "2001:db8::1", 200),
                    ("exact", "2001:db8::", 403),
                    ("hostbits", "192.0.2.255", 200),
                    ("hostbits", "2001:db8::6", 200),
                    ("hostbits", "2001:db8::8", 403),
                    ("mapped", "::ffff:192.0.2.10", 200),
                    ("mapped", "192.0.2.10", 200),
                    ("mapped", "192.0.3.10", 403),
                    ("mapped", "::ffff:192.0.2.255", 200),
                    ("mapped", "::ffff:192.0.3.0", 403),
                    ("mapped96", "::ffff:203.0.113.10", 200),
                    ("mapped96", "203.0.113.10", 200),
                    ("mapped96", "::fffe:203.0.113.10", 403),
                    ("mapped128", "::ffff:192.0.2.10", 200),
                    ("mapped128", "192.0.2.10", 200),
                    ("mapped128", "::ffff:192.0.2.11", 403),
                ]:
                    check(
                        f"{route} {address}",
                        f"/trusted/{route}" + ATTACK,
                        expected,
                        headers={"X-Forwarded-For": address},
                    )

                # A failed parse on reload must leave the old workers and policy active.
                for malformed in (
                    "invalid",
                    ".../0",
                    "192..2.0/24",
                    "192.0.2./24",
                    "::ffff:192.0.2./120",
                ):
                    old_errors = (
                        (root / "error.log")
                        .read_text()
                        .count("invalid shield_allow address")
                    )
                    config.write_text(
                        text.replace(
                            "shield_allow 127.0.0.1;", f"shield_allow {malformed};", 1
                        )
                    )
                    process.send_signal(signal.SIGHUP)
                    wait_for(
                        process,
                        lambda old_errors=old_errors: (
                            (root / "error.log")
                            .read_text()
                            .count("invalid shield_allow address")
                            > old_errors
                        ),
                        f"failed reload must be observed: {malformed}",
                    )
                    check("failed reload retained allow", "/t" + ATTACK, 200)
                    check(
                        "failed reload retained block",
                        "/t" + ATTACK,
                        403,
                        source="127.0.0.2",
                    )
                    assert (
                        check("failed reload retained workers", "/ready", 200)
                        == b"ban-ready"
                    )
                changed = text.replace(
                    "shield_allow 127.0.0.1;", "shield_allow 127.0.0.2;", 1
                )
                activate_config(
                    process,
                    root,
                    port,
                    changed.replace('return 200 "before"', 'return 200 "after"'),
                    b"after",
                )
                check("valid reload removes old allow", "/t" + ATTACK, 403)
                check(
                    "valid reload activates new allow",
                    "/t" + ATTACK,
                    200,
                    source="127.0.0.2",
                )
                # Remove the root directive entirely: default behavior must still block.
                activate_config(
                    process,
                    root,
                    port,
                    changed.replace("shield_allow 127.0.0.2;", "", 1).replace(
                        'return 200 "before"', 'return 200 "absent"'
                    ),
                    b"absent",
                )
                check(
                    "absent directive blocks former allow",
                    "/t" + ATTACK,
                    403,
                    source="127.0.0.2",
                )
                check("absent directive blocks neighbor", "/t" + ATTACK, 403)
                (output / "stats.json").write_text(json.dumps(stats(), indent=2))
                (output / "ban-stats.json").write_text(
                    json.dumps(stats("/ban-stats"), indent=2)
                )
            finally:
                stop_server(process, root, output, None)
                if (root / "access.log").exists():
                    (output / "access.log").write_bytes(
                        (root / "access.log").read_bytes()
                    )
                if os.environ.get("GCOV_PREFIX"):
                    assert "profiling:" not in (output / "error.log").read_text(), (
                        "gcov runtime collection failed; inspect error.log"
                    )
    return results


def main():
    if sys.flags.optimize:
        raise SystemExit(
            "test_allowlist.py requires Python assertions; disable optimization"
        )
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nginx", required=True, type=Path)
    parser.add_argument("--module", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--config-only", action="store_true")
    selection.add_argument("--runtime-only", action="store_true")
    args = parser.parse_args()
    binary = args.nginx.resolve()
    module = args.module.resolve() if args.module else None
    args.output.mkdir(parents=True, exist_ok=True)
    results = {}
    if not args.runtime_only:
        results["config"] = config_controls(binary, module, args.output)
    if not args.config_only:
        results["runtime"] = runtime_controls(binary, module, args.output)
    (args.output / "results.json").write_text(json.dumps(results, indent=2))
    print(f"allowlist: {sum(map(len, results.values()))} named controls passed")


if __name__ == "__main__":
    main()
