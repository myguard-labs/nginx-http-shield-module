#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Inert CVE fixtures against the actual module, including policy boundaries."""

from __future__ import annotations

import argparse
import json
import signal
import socket
import subprocess
import tempfile
import time
from pathlib import Path

from test_metrics_counters import request
from test_stats_zone import config_test_environment

PROFILES = "php_cgi craft_cms geoserver nextjs_middleware tomcat_put json_escapes"
CRAFT25 = json.dumps(
    {
        "assetId": 11,
        "handle": {
            "as session": {
                "class": "craft\\behaviors\\FieldLayoutBehavior",
                "__class": "GuzzleHttp\\Psr7\\FnStream",
                "__construct()": [[]],
                "_fn_close": "shield_fixture_no_such_callable",
            }
        },
    }
)
CRAFT26 = (
    "criteria[withTransforms][0][class]=yii%5Crbac%5CPhpManager&"
    "criteria[withTransforms][0][itemFile]=/shield-fixture-does-not-exist&"
    "criteria[limit]=1&viewState[static]=1&source=volume:1"
)
FLIGHT = r'{"value":"$1:\u005f_proto__:\u0074hen"}'
GEO = "<GetFeature><PropertyName>java.lang.Thread.sleep(0)</PropertyName></GetFeature>"
JSON_HEADER = {"Content-Type": "application/json"}


def configuration(root: Path, port: int, module: Path | None) -> str:
    """Opt-in policy inheritance is independent of Shield's action mode."""
    load = f'load_module "{module}";' if module else ""
    return f"""{load}
daemon off;
worker_processes 1;
pid {root}/nginx.pid;
error_log {root}/error.log notice;
events {{ worker_connections 64; }}
http {{
    access_log off;
    shield_stats_zone counters 64k;
    server {{
        listen 127.0.0.1:{port};
        shield block;
        shield_log {root}/hits.jsonl;
        location = /ready {{ shield off; return 200 ready; }}
        location = /stats {{ shield off; shield_ban_status counters; }}
        location / {{ empty_gif; }}
        location /enabled/ {{
            shield_cve {PROFILES};
            empty_gif;
            location /enabled/inherit/ {{ empty_gif; }}
            location /enabled/reset/ {{ shield_cve off; empty_gif; }}
            location /enabled/skip/ {{
                shield_skip deserial java_eval php_rce exploit_path;
                empty_gif;
            }}
            location /enabled/detect/ {{ shield detect; empty_gif; }}
            location /enabled/off/ {{ shield off; empty_gif; }}
            location /enabled/no-body/ {{ shield_body off; empty_gif; }}
            location /enabled/limited/ {{ shield_max_body 8; empty_gif; }}
            location /enabled/status/ {{ shield_status 419; empty_gif; }}
        }}
        location /craft/ {{ shield_cve craft_cms; empty_gif; }}
        location /geo/ {{ shield_cve geoserver; empty_gif; }}
        location /json/ {{ shield_cve json_escapes; empty_gif; }}
        location /next/ {{ shield_cve nextjs_middleware; empty_gif; }}
        location /put/ {{ shield_cve tomcat_put; empty_gif; }}
        location /php/ {{ shield_cve php_cgi; empty_gif; }}
    }}
}}
"""


def duplicate_request(port: int, headers: list[tuple[str, str]], body: str) -> int:
    """Send actual repeated fields without a dict silently combining them."""
    payload = body.encode()
    fields = "".join(f"{key}: {value}\r\n" for key, value in headers)
    head = (
        f"POST /json/ HTTP/1.1\r\nHost: localhost\r\n{fields}"
        f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n"
    )
    with socket.create_connection(("127.0.0.1", port), timeout=5) as connection:
        connection.sendall(head.encode() + payload)
        response = b""
        while b"\r\n" not in response:
            block = connection.recv(4096)
            assert block, "missing HTTP status"
            response += block
            assert len(response) <= 8192, "oversized status line"
    return int(response.split(b" ", 2)[1])


def run(binary: Path, module: Path | None, output: Path) -> None:
    """Require named assertions and always reap the owned nginx process."""
    results = []
    with tempfile.TemporaryDirectory(prefix="shield-cve-") as directory:
        root = Path(directory)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        config = root / "nginx.conf"
        text = configuration(root, port, module)
        config.write_text(text)
        with (root / "stderr").open("w+") as stderr:
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
                        if request(port, "/ready") == (200, b"ready"):
                            break
                    except ConnectionRefusedError:
                        pass
                    assert time.monotonic() < deadline, "nginx readiness"
                    time.sleep(0.02)

                def check(
                    name, path, expected, *, body=None, headers=None, method=None
                ):
                    verb = method or ("POST" if body is not None else "GET")
                    actual = request(port, path, headers, verb, body)[0]
                    assert actual == expected, (name, actual, expected)
                    results.append({"case": name, "status": actual})

                for prefix in ("enabled", "enabled/inherit"):
                    check("PHP query prefix", f"/{prefix}/?%ADd+foo", 403)
                    check("UTF8 option prefix", f"/{prefix}/?%C2%AD%6e", 403)
                    check(
                        "Craft 2025 JSON",
                        f"/{prefix}/",
                        403,
                        body=CRAFT25,
                        headers=JSON_HEADER,
                    )
                    check(
                        "Craft 2026 form",
                        f"/{prefix}/",
                        403,
                        body=CRAFT26,
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                    )
                    check(
                        "GeoServer XML",
                        f"/{prefix}/",
                        403,
                        body=GEO,
                        headers={"Content-Type": "application/xml"},
                    )
                    check(
                        "GeoServer query",
                        f"/{prefix}/?value=java.lang.Thread.sleep(0)",
                        403,
                    )
                    check(
                        "Flight escapes",
                        f"/{prefix}/",
                        403,
                        body=FLIGHT,
                        headers=JSON_HEADER,
                    )
                    check(
                        "Next internal header",
                        f"/{prefix}/",
                        403,
                        headers={"X-Middleware-Subrequest": "middleware"},
                    )
                    check(
                        "Next empty header",
                        f"/{prefix}/",
                        403,
                        headers={"x-middleware-subrequest": ""},
                    )
                    check(
                        "Tomcat partial PUT",
                        f"/{prefix}/",
                        403,
                        method="PUT",
                        body="inert",
                        headers={"Content-Range": "bytes 0-4/5"},
                    )

                for prefix in (
                    "default",
                    "enabled/reset",
                    "enabled/skip",
                    "enabled/off",
                    "enabled/detect",
                ):
                    check("compatible query", f"/{prefix}/?%ADd+foo", 200)
                    check(
                        "compatible header",
                        f"/{prefix}/",
                        200,
                        headers={"x-middleware-subrequest": "middleware"},
                    )
                    check(
                        "compatible Craft",
                        f"/{prefix}/",
                        405,
                        body=CRAFT25,
                        headers=JSON_HEADER,
                    )
                    check(
                        "compatible GeoServer",
                        f"/{prefix}/",
                        405,
                        body=GEO,
                        headers={"Content-Type": "application/xml"},
                    )
                    check(
                        "compatible Flight",
                        f"/{prefix}/",
                        405,
                        body=FLIGHT,
                        headers=JSON_HEADER,
                    )
                    check(
                        "compatible partial PUT",
                        f"/{prefix}/",
                        405,
                        method="PUT",
                        body="inert",
                        headers={"Content-Range": "bytes 0-4/5"},
                    )

                for prefix in ("enabled/no-body", "enabled/limited"):
                    check(
                        "body scope limit",
                        f"/{prefix}/",
                        405,
                        body=CRAFT25,
                        headers=JSON_HEADER,
                    )
                    check(
                        "Flight scope limit",
                        f"/{prefix}/",
                        405,
                        body=FLIGHT,
                        headers=JSON_HEADER,
                    )
                for target in (
                    "/?q=%ADd",
                    "/?%ADz",
                    "/?%AD",
                    "/?%C2%AD",
                    "/?name=soft%ADhyphen",
                ):
                    check("benign PHP near miss", "/php" + target, 200)
                check(
                    "ordinary header text",
                    "/next/",
                    200,
                    headers={"X-Note": "x-middleware-subrequest"},
                )
                check("ordinary PUT", "/put/", 405, method="PUT", body="inert")
                check(
                    "range on GET",
                    "/put/",
                    200,
                    headers={"Content-Range": "bytes 0-4/5"},
                )
                check(
                    "range on POST",
                    "/put/",
                    405,
                    body="inert",
                    headers={"Content-Range": "bytes 0-4/5"},
                )
                check(
                    "custom status",
                    "/enabled/status/",
                    419,
                    headers={"x-middleware-subrequest": "middleware"},
                )
                check(
                    "ordinary Craft transform",
                    "/craft/",
                    405,
                    body='{"assetId":11,"handle":"thumbnail"}',
                    headers=JSON_HEADER,
                )
                check(
                    "ordinary class",
                    "/craft/",
                    405,
                    body='{"class":"card","__class":"example"}',
                    headers=JSON_HEADER,
                )
                check(
                    "Craft gadget missing key",
                    "/craft/",
                    405,
                    body=CRAFT25.replace("_fn_close", "ordinary"),
                    headers=JSON_HEADER,
                )
                check(
                    "ordinary GeoServer XPath",
                    "/geo/",
                    405,
                    body="<PropertyName>eg:complexAttribute/eg:rootAttribute</PropertyName>",
                    headers={"Content-Type": "application/xml"},
                )
                check(
                    "Flight ordinary references",
                    "/json/",
                    405,
                    body='{"then":"$1:then","constructor":"class","__proto__":"text"}',
                    headers=JSON_HEADER,
                )
                check(
                    "Flight escaped literal",
                    "/json/",
                    405,
                    body=json.dumps({"value": r"$1:\u005f_proto__:\u0074hen"}),
                    headers=JSON_HEADER,
                )
                check(
                    "Flight malformed escape",
                    "/json/",
                    405,
                    body=r'{"value":"$1:\u00xx_proto__:\u0074hen"}',
                    headers=JSON_HEADER,
                )
                check(
                    "Flight wrong media type",
                    "/json/",
                    405,
                    body=FLIGHT,
                    headers={"Content-Type": "text/plain"},
                )
                check(
                    "Flight binary media",
                    "/json/",
                    405,
                    body=FLIGHT,
                    headers={"Content-Type": "application/octet-stream"},
                )
                check(
                    "Flight vendor JSON",
                    "/json/",
                    403,
                    body=FLIGHT,
                    headers={"Content-Type": "application/vnd.api+json; charset=utf-8"},
                )
                check(
                    "Flight second gadget",
                    "/json/",
                    403,
                    body=r'{"value":"$2:\u0063onstructor:\u0063onstructor"}',
                    headers=JSON_HEADER,
                )
                multipart = (
                    '--fixture\r\nContent-Disposition: form-data; name="0"\r\n\r\n'
                    + FLIGHT
                    + "\r\n--fixture--\r\n"
                )
                check(
                    "Flight multipart",
                    "/json/",
                    403,
                    body=multipart,
                    headers={"Content-Type": "multipart/form-data; boundary=fixture"},
                )
                check(
                    "isolated Craft profile",
                    "/craft/",
                    405,
                    body=FLIGHT,
                    headers=JSON_HEADER,
                )
                check(
                    "isolated JSON profile",
                    "/json/",
                    405,
                    body=CRAFT25,
                    headers=JSON_HEADER,
                )
                check(
                    "isolated GeoServer profile",
                    "/geo/",
                    405,
                    body=CRAFT25,
                    headers=JSON_HEADER,
                )
                craft26json = json.dumps(
                    {
                        "criteria": {
                            "withTransforms": [
                                {
                                    "class": "yii\\rbac\\PhpManager",
                                    "itemFile": "/shield-fixture-does-not-exist",
                                }
                            ]
                        }
                    }
                )
                check(
                    "Craft 2026 JSON",
                    "/craft/",
                    403,
                    body=craft26json,
                    headers=JSON_HEADER,
                )
                check(
                    "Craft Unicode class",
                    "/craft/",
                    403,
                    body=craft26json.replace("PhpManager", r"\u0050hpManager"),
                    headers=JSON_HEADER,
                )
                noisy = (
                    '--fixture\r\nContent-Disposition: form-data; name="noise"\r\n\r\n"\r\n'
                    + multipart
                )
                check(
                    "Flight preceding malformed field",
                    "/json/",
                    403,
                    body=noisy,
                    headers={"Content-Type": "multipart/form-data; boundary=fixture"},
                )
                check(
                    "Flight quoted boundary",
                    "/json/",
                    403,
                    body=noisy,
                    headers={
                        "Content-Type": 'multipart/form-data; note="a;b"; boundary="fixture"'
                    },
                )
                check(
                    "Flight duplicate boundary rejected",
                    "/json/",
                    500,
                    body=noisy,
                    headers={
                        "Content-Type": "multipart/form-data; boundary=fixture; boundary=other"
                    },
                )
                check(
                    "Flight missing boundary rejected",
                    "/json/",
                    500,
                    body=noisy,
                    headers={"Content-Type": "multipart/form-data"},
                )
                check(
                    "detect malformed multipart",
                    "/enabled/detect/",
                    405,
                    body=noisy,
                    headers={"Content-Type": "multipart/form-data"},
                )
                check(
                    "Flight trailing boundary OWS",
                    "/json/",
                    403,
                    body=noisy,
                    headers={"Content-Type": "multipart/form-data; boundary=fixture\t"},
                )
                check(
                    "Flight trailing semicolon",
                    "/json/",
                    403,
                    body=noisy,
                    headers={"Content-Type": "multipart/form-data; boundary=fixture;"},
                )
                repeated = [("Content-Type", "application/json")] * 64
                assert duplicate_request(port, repeated, FLIGHT) == 403
                assert duplicate_request(port, repeated, '{"value":"ordinary"}') == 405
                differing = [
                    ("Content-Type", "multipart/form-data; boundary=fixture"),
                    ("Content-Type", "multipart/form-data; boundary=other"),
                ]
                assert duplicate_request(port, differing, noisy) == 500
                results.extend(
                    [
                        {"case": "duplicate JSON hit", "status": 403},
                        {"case": "duplicate JSON benign", "status": 405},
                        {"case": "ambiguous MIME boundary", "status": 500},
                    ]
                )
                padded = multipart.replace("--fixture\r\n", "--fixture \t\r\n").replace(
                    "--fixture--\r\n", "--fixture-- \t\r\n"
                )
                check(
                    "Flight MIME transport padding",
                    "/json/",
                    403,
                    body=padded,
                    headers={"Content-Type": "multipart/form-data; boundary=fixture"},
                )
                padded_noise = noisy.replace(
                    "--fixture\r\n", "--fixture \t\r\n"
                ).replace("--fixture--\r\n", "--fixture-- \t\r\n")
                check(
                    "Flight padded malformed field",
                    "/json/",
                    403,
                    body=padded_noise,
                    headers={"Content-Type": "multipart/form-data; boundary=fixture"},
                )
                headers = {f"X-Note-{i}": "ordinary" for i in range(40)}
                headers["x-middleware-subrequest"] = "middleware"
                check("Next later header part", "/next/", 403, headers=headers)
                headers.pop("x-middleware-subrequest")
                headers["Content-Range"] = "bytes 0-4/5"
                check(
                    "Tomcat later header part",
                    "/put/",
                    403,
                    method="PUT",
                    body="inert",
                    headers=headers,
                )
                check(
                    "normal transform endpoint",
                    "/craft/actions/assets/generate-transform",
                    200,
                )
                check(
                    "Craft second gadget missing key",
                    "/craft/",
                    405,
                    body=craft26json.replace("itemFile", "ordinary"),
                    headers=JSON_HEADER,
                )
                hits = [
                    json.loads(line)
                    for line in (root / "hits.jsonl").read_text().splitlines()
                ]
                assert {"php_rce", "deserial", "java_eval", "exploit_path"} <= {
                    h["cat"] for h in hits
                }
                assert {"uri", "body", "header"} <= {h["src"] for h in hits}
                stats = json.loads(request(port, "/stats")[1])
                assert (
                    stats["blocked"] > 0
                    and sum(v["detect"] for v in stats["detections"].values()) > 0
                ), stats
                output.mkdir(parents=True, exist_ok=True)
                (output / "http.json").write_text(json.dumps(results, indent=2) + "\n")
            finally:
                if process.poll() is None:
                    process.send_signal(signal.SIGQUIT)
                process.wait(timeout=10)
                stderr.seek(0)
                logs = stderr.read() + (root / "error.log").read_text()
                assert process.returncode == 0, logs
                assert (
                    "AddressSanitizer" not in logs and "runtime error:" not in logs
                ), logs
        for invalid in (
            "unknown",
            "php_cgi php_cgi",
            "off php_cgi",
            "json_escapes off",
        ):
            config.write_text(text.replace(PROFILES, invalid))
            result = subprocess.run(
                [str(binary), "-p", f"{root}/", "-c", "nginx.conf", "-t"],
                check=False,
                env=config_test_environment(),
                capture_output=True,
                text=True,
            )
            assert (
                result.returncode != 0
                and "invalid or duplicate shield_cve profile" in result.stderr
            ), result.stderr
        config.write_text(
            text.replace(
                f"shield_cve {PROFILES};", "shield_cve php_cgi; shield_cve geoserver;"
            )
        )
        result = subprocess.run(
            [str(binary), "-p", f"{root}/", "-c", "nginx.conf", "-t"],
            check=False,
            env=config_test_environment(),
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0 and "is duplicate" in result.stderr, result.stderr
    print(
        f"CVE controls: {len(results)} HTTP assertions and 5 config rejections passed"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nginx", type=Path, required=True)
    parser.add_argument("--module", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    run(
        args.nginx.resolve(),
        args.module.resolve() if args.module else None,
        args.output,
    )


if __name__ == "__main__":
    main()
