#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Correlate raw client input, Shield hits, final nginx route and inert sinks."""

import argparse
import asyncio
import hashlib
import json
import os
import signal
import socket
import tempfile
from pathlib import Path

from recorders import LIMIT, Recorder, require

ATTACK = b"id=-1+union+select+value+from+private_data"
BENIGN = b"id=%31&note=Plain+content%21"


def case(name, target=b"/http/item?x=%41", body=BENIGN, **kw):
    return {
        "id": name,
        "target": target,
        "body": body,
        "status": 200,
        "sink": "http",
        "final": target.replace(b"/http/", b"/sink/", 1),
        "mode": "block",
        "hit": False,
        "front": False,
        **kw,
    }


CASES = [
    case("http-direct"),
    case("http-via-proxy", front=True),
    case("normalized-route", target=b"/http/%62?x=%41", final=b"/sink/b?x=%41"),
    case(
        "internal-redirect",
        target=b"/jump?x=%41",
        final=b"/sink/final",
        body=b"",
        method=b"GET",
        uri="/http/final",
    ),
    case("fastcgi-handoff", target=b"/fcgi/%62?x=%41", sink="fcgi", final=b"/fcgi/b"),
    case(
        "fastcgi-via-proxy",
        target=b"/fcgi/item?x=%41",
        sink="fcgi",
        final=b"/fcgi/item",
        front=True,
    ),
    case("empty-body-boundary", body=b""),
    case("maximum-body-boundary", body=b"A" * 1024),
    case("shield-block-body", body=ATTACK, status=403, sink=None, hit=True),
    case(
        "shield-block-via-proxy",
        body=ATTACK,
        status=403,
        sink=None,
        hit=True,
        front=True,
    ),
    case(
        "shield-detect-body",
        target=b"/detect/item?x=%41",
        body=ATTACK,
        mode="detect",
        hit=True,
        final=b"/sink/item?x=%41",
    ),
    case(
        "shield-detect-fastcgi",
        target=b"/fcgi-detect/item?x=%41",
        body=ATTACK,
        mode="detect",
        hit=True,
        sink="fcgi",
        final=b"/fcgi-detect/item",
    ),
    case("core-invalid-escape", target=b"/http/%ZZ", body=b"", status=400, sink=None),
    case("core-oversize-body", body=b"A" * 1025, status=413, sink=None),
    case(
        "core-malformed-header",
        raw=b"GET /http/item HTTP/1.1\r\nHost: fixture\r\nBad Header: value\r\n\r\n",
        body=b"",
        status=400,
        sink=None,
    ),
    case(
        "core-return-status",
        target=b"/core-return",
        body=b"",
        method=b"GET",
        status=418,
        sink=None,
    ),
]


def config(root, port, front, hp, fp, module):
    load = f"load_module {module};" if module else ""
    user = "user root;" if os.geteuid() == 0 else ""
    return f"""{load}
{user}
worker_processes 1;
daemon off;
master_process off;
pid {root}/nginx.pid;
error_log {root}/error.log notice;
events {{ worker_connections 64; }}
http {{
    log_format view escape=json '{{"request":"$request",'
        '"original":"$request_uri","uri":"$uri",'
        '"status":$status,"upstream":"$upstream_addr"}}';
    access_log off;
    client_max_body_size 1024;
    client_body_buffer_size 4k;
    server {{
        listen 127.0.0.1:{front};
        location / {{
            shield off;
            proxy_pass http://127.0.0.1:{port};
            proxy_http_version 1.1;
            proxy_set_header Connection close;
            proxy_set_header Host fixture;
        }}
    }}
    upstream inert_fcgi {{ server 127.0.0.1:{fp}; }}
    server {{
        listen 127.0.0.1:{port};
        shield block;
        # This transport oracle exercises an explicitly enforced SQL sink.
        shield_body_strict on;
        shield_log {root}/shield.jsonl;
        access_log {root}/view.jsonl view;
        location /http/ {{
            proxy_pass http://127.0.0.1:{hp}/sink/;
            proxy_http_version 1.1;
            proxy_set_header Connection close;
            proxy_set_header Host fixture;
        }}
        location /detect/ {{
            shield detect;
            proxy_pass http://127.0.0.1:{hp}/sink/;
            proxy_http_version 1.1;
            proxy_set_header Connection close;
            proxy_set_header Host fixture;
        }}
        location = /jump {{ error_page 418 = /http/final; return 418; }}
        location = /core-return {{ return 418; }}
        location /fcgi {{
            fastcgi_pass inert_fcgi;
            fastcgi_keep_conn off;
            fastcgi_pass_request_headers off;
            fastcgi_param HTTP_HOST fixture;
            fastcgi_param SCRIPT_FILENAME /srv/inert$uri;
            fastcgi_param REQUEST_URI $request_uri;
            fastcgi_param QUERY_STRING $args;
            fastcgi_param REQUEST_METHOD $request_method;
            fastcgi_param CONTENT_LENGTH $content_length;
            fastcgi_param CONTENT_TYPE $content_type;
        }}
        location /fcgi-detect {{
            shield detect;
            fastcgi_pass inert_fcgi;
            fastcgi_keep_conn off;
            fastcgi_pass_request_headers off;
            fastcgi_param HTTP_HOST fixture;
            fastcgi_param SCRIPT_FILENAME /srv/inert$uri;
            fastcgi_param REQUEST_URI $request_uri;
            fastcgi_param QUERY_STRING $args;
            fastcgi_param REQUEST_METHOD $request_method;
            fastcgi_param CONTENT_LENGTH $content_length;
            fastcgi_param CONTENT_TYPE $content_type;
        }}
    }}
}}
"""


async def raw(port, wire):
    require(len(wire) <= LIMIT, "client request exceeds bound")
    async with asyncio.timeout(15):
        reader, writer = await asyncio.open_connection("127.0.0.1", port, limit=LIMIT)
        try:
            writer.write(wire)
            await writer.drain()
            response = bytearray()
            while chunk := await reader.read(4096):
                response.extend(chunk)
                require(len(response) <= LIMIT, "client response exceeds bound")
            return bytes(response)
        finally:
            writer.close()
            await writer.wait_closed()


def request(row):
    if "raw" in row:
        return row["raw"]
    return (
        row.get("method", b"POST")
        + b" "
        + row["target"]
        + b" HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n"
        + b"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: "
        + str(len(row["body"])).encode()
        + b"\r\n\r\n"
        + row["body"]
    )


def json_lines(path):
    return (
        [json.loads(line) for line in path.read_text().splitlines()]
        if path.exists()
        else []
    )


def verify(row, response, hits, views, http, fcgi, hp, fp):
    name = row["id"]
    status = int(response.split(b" ", 2)[1])
    require(status == row["status"], f"{name}: response status {status}")
    require(
        len(views) == 1,
        f"{name}: expected one Shield-server route observation, got {views!r}",
    )
    view = views[0]
    require(view["status"] == status, f"{name}: route status differs")
    require(bool(hits) == row["hit"], f"{name}: Shield hit attribution differs")
    if row["hit"]:
        require(len(hits) == 1, f"{name}: unexpected hit count")
        hit = hits[0]
        require(
            (hit["cat"], hit["src"], hit["mode"], hit["status"])
            == ("sqli", "body", row["mode"], 0 if row["mode"] == "detect" else 403),
            f"{name}: Shield action differs",
        )
        require(
            hit.get("req") == "",
            f"{name}: Shield request view differs",
        )
    require(len(http) == (row["sink"] == "http"), f"{name}: HTTP receipt count differs")
    require(
        len(fcgi) == (row["sink"] == "fcgi"), f"{name}: FastCGI receipt count differs"
    )
    receipt = (http + fcgi)[0] if row["sink"] else None
    if receipt:
        require(receipt["closed"], f"{name}: receipt before close")
        require(receipt["body"] == row["body"], f"{name}: final backend body differs")
        require(b"inert-marker" in response, f"{name}: backend response marker missing")
        sink_port = hp if row["sink"] == "http" else fp
        require(
            view["upstream"] == f"127.0.0.1:{sink_port}",
            f"{name}: upstream route differs",
        )
        require(
            view["original"].encode() == row["target"], f"{name}: original URI differs"
        )
        uri = row.get(
            "uri",
            row["final"].split(b"?", 1)[0].decode().replace("/sink/", "/http/", 1),
        )
        if row["target"].startswith(b"/detect/"):
            uri = uri.replace("/http/", "/detect/", 1)
        require(
            view["uri"] == uri, f"{name}: normalized nginx route differs: {view['uri']}"
        )
        if row["sink"] == "http":
            require(
                receipt["method"] == row.get("method", b"POST"),
                f"{name}: final HTTP method differs",
            )
            require(
                receipt["target"] == row["final"],
                f"{name}: final HTTP route differs: {receipt['target']!r}",
            )
        else:
            expected = {
                b"HTTP_HOST": b"fixture",
                b"SCRIPT_FILENAME": b"/srv/inert" + row["final"],
                b"REQUEST_URI": row["target"],
                b"QUERY_STRING": row["target"].partition(b"?")[2],
                b"REQUEST_METHOD": row.get("method", b"POST"),
                b"CONTENT_LENGTH": str(len(row["body"])).encode(),
                b"CONTENT_TYPE": b"application/x-www-form-urlencoded",
            }
            require(
                receipt["params"] == expected,
                f"{name}: final FastCGI PARAMS differ: {receipt['params']!r}",
            )
    else:
        require(
            view["upstream"] == "",
            f"{name}: rejected request upstream differs: {view['upstream']!r}",
        )
    return {
        "id": name,
        "status": status,
        "action": "shield-" + row["mode"]
        if hits
        else ("server-rejection" if receipt is None else "allowed-no-hit"),
        "shield": hits,
        "view": view,
        "sink": row["sink"],
        "sink_label": "inert-content" if receipt else None,
        "backend_wire_hex": receipt["wire"].hex() if receipt else None,
        "backend_params_hex": {k.hex(): v.hex() for k, v in receipt["params"].items()}
        if fcgi
        else None,
        "backend_target_hex": receipt["target"].hex() if http else None,
        "backend_body_hex": receipt["body"].hex() if receipt else None,
        "client_wire_hex": request(row).hex(),
        "promotion_eligible": False,
    }


async def finish_after_route(proc, path):
    """Wait for request logging before terminating a single-process server."""
    try:
        async with asyncio.timeout(10):
            while not (path.exists() and path.read_bytes().endswith(b"\n")):
                require(
                    proc.returncode is None,
                    f"nginx exited before final route log: {proc.returncode}",
                )
                await asyncio.sleep(0.001)
    except TimeoutError as exc:
        content = path.read_bytes() if path.exists() else b""
        raise TimeoutError(f"final route log incomplete: {content!r}") from exc
    proc.send_signal(signal.SIGQUIT)
    require(await asyncio.wait_for(proc.wait(), 10) == 0, "nginx shutdown failed")


async def run_one(row, nginx, module):
    with tempfile.TemporaryDirectory(prefix="shield-backend-") as tmp:
        root = Path(tmp)
        http, fcgi = Recorder("http"), Recorder("fcgi")
        proc = None
        reservations = []
        try:
            hp, fp = await http.start(), await fcgi.start()
            for _ in range(2):
                sock = socket.socket()
                sock.bind(("127.0.0.1", 0))
                reservations.append(sock)
            port, front = [s.getsockname()[1] for s in reservations]
            (root / "nginx.conf").write_text(config(root, port, front, hp, fp, module))
            for sock in reservations:
                sock.close()
            with (root / "process.log").open("wb") as log:
                proc = await asyncio.create_subprocess_exec(
                    str(nginx),
                    "-p",
                    str(root),
                    "-c",
                    str(root / "nginx.conf"),
                    stdout=log,
                    stderr=log,
                )
                async with asyncio.timeout(10):
                    while True:
                        if proc.returncode is not None:
                            raise ValueError((root / "process.log").read_text())
                        if (root / "nginx.pid").exists():
                            break
                        await asyncio.sleep(0.01)
                response = await raw(front if row["front"] else port, request(row))
                await finish_after_route(proc, root / "view.jsonl")
            await http.stop()
            await fcgi.stop()
            require(
                not http.errors and not fcgi.errors,
                f"recorder errors: {http.errors + fcgi.errors}",
            )
            return verify(
                row,
                response,
                json_lines(root / "shield.jsonl"),
                json_lines(root / "view.jsonl"),
                http.receipts,
                fcgi.receipts,
                hp,
                fp,
            )
        finally:
            for sock in reservations:
                sock.close()
            if proc and proc.returncode is None:
                proc.kill()
                await proc.wait()
            await http.stop()
            await fcgi.stop()


def module_arg(value):
    """An empty optional module path denotes a statically linked server."""
    return Path(value) if value else None


async def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nginx", required=True, type=Path)
    parser.add_argument("--module", type=module_arg)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--only", choices=[row["id"] for row in CASES])
    args = parser.parse_args()
    results = []
    for row in CASES:
        if not args.only or args.only == row["id"]:
            results.append(
                await run_one(
                    row,
                    args.nginx.resolve(),
                    args.module.resolve() if args.module else None,
                )
            )
            print("PASS", row["id"])
    args.output.write_text(
        json.dumps(
            {
                "cases": results,
                "count": len(results),
                "fixture_sha256": {
                    name: hashlib.sha256(
                        Path(__file__).with_name(name).read_bytes()
                    ).hexdigest()
                    for name in ("check.py", "recorders.py", "test_recorders.py")
                },
                "nginx_sha256": hashlib.sha256(args.nginx.read_bytes()).hexdigest(),
                "module_sha256": hashlib.sha256(args.module.read_bytes()).hexdigest()
                if args.module
                else None,
                "limits": (
                    "Inert transport receipts only; "
                    "no application vulnerability or population labels."
                ),
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    asyncio.run(main())
