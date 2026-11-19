#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Prove exact-location policy rollback and dedicated-zone retirement on reload.

No production ban attribution is implied: a zone may contain hits from every
signature enabled in its locations. Only an exclusively owned trial zone can
be retired as a unit. Run process-control tests inside a disposable container.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import pathlib
import pwd
import socket
import subprocess

from test_reload_lifetime import Failure, Server

MARKER = b"union select"
TRIAL_CLIENT = "127.0.0.2"
PRODUCTION_CLIENT = "127.0.0.3"
INFLIGHT_CLIENT = "127.0.0.4"
CLEAN_CLIENT = "127.0.0.5"


class PolicyServer(Server):
    """Keep production state separate from an explicitly owned trial zone."""

    generation = "observe"
    trial_zone = "trial_v1"
    attached = True
    strict = False

    def write_config(self, rejected_port: int | None = None) -> None:
        load = f'load_module "{self.module}";' if self.module else ""
        trial = ""
        status = ""
        binding = ""
        if self.trial_zone:
            trial = f"shield_ban_zone {self.trial_zone}:64k;"
            status = f"""location = /trial-status {{
                shield off; shield_ban_status {self.trial_zone};
            }}"""
            if self.attached:
                binding = (
                    f"shield_ban zone={self.trial_zone} count=2 window=1m bantime=1h;"
                )
        strict = "on" if self.strict else "off"
        self.conf.write_text(f"""{load}
daemon off;
user {pwd.getpwuid(os.geteuid()).pw_name};
master_process on;
worker_processes 1;
error_log {self.prefix}/error.log info;
pid {self.prefix}/nginx.pid;
events {{ worker_connections 64; }}
http {{
    access_log off;
    shield_ban_zone production:64k;
    {trial}
    server {{
        listen 127.0.0.1:{self.port};
        shield block;
        shield_body_strict on;
        shield_log {self.prefix}/hits.jsonl;
        add_header X-Worker $pid always;
        add_header X-Generation {self.generation} always;
        location = /ready {{ shield off; return 200 ready; }}
        location = /production-status {{
            shield off; shield_ban_status production;
        }}
        {status}
        location = /trial {{
            shield_body_strict {strict};
            {binding}
            empty_gif;
        }}
        location / {{
            shield_ban zone=production count=2 window=1m bantime=1h;
            empty_gif;
        }}
    }}
}}
""")

    def fetch(self, path="/ready", *, client=CLEAN_CLIENT, body=None, headers=None):
        conn = http.client.HTTPConnection(
            "127.0.0.1", self.port, timeout=5, source_address=(client, 0)
        )
        try:
            conn.request("GET" if body is None else "POST", path, body, headers or {})
            response = conn.getresponse()
            payload = response.read()
            return response.status, payload, dict(response.getheaders())
        finally:
            conn.close()

    def transition(self, generation, *, strict=False, attached=True, zone="trial_v1"):
        old = set(self.children())
        self.generation = generation
        self.strict = strict
        self.attached = attached
        self.trial_zone = zone
        self.write_config()
        tested = subprocess.run(
            [self.nginx, "-t", "-p", str(self.prefix), "-c", str(self.conf)],
            capture_output=True,
            check=False,
        )
        require(tested.returncode == 0, "valid reload configuration", tested.stderr)
        self.reload()
        self.wait_until(lambda: bool(set(self.children()) - old), "new policy worker")
        # A new worker can accept before the master signals the old one.
        # Synchronize on actual listener closure, while keeping held body
        # requests alive in the old worker; one new /ready reply is no barrier.
        listeners = {
            f"socket:[{fields[9]}]"
            for line in pathlib.Path("/proc/net/tcp")
            .read_text(encoding="ascii")
            .splitlines()[1:]
            if (fields := line.split())[1] == f"0100007F:{self.port:04X}"
            and fields[3] == "0A"
        }
        require(bool(listeners), "owned listener inode found")

        def old_listeners_closed():
            for pid in old:
                try:
                    descriptors = list(pathlib.Path(f"/proc/{pid}/fd").iterdir())
                except FileNotFoundError:
                    continue
                for descriptor in descriptors:
                    try:
                        if str(descriptor.readlink()) in listeners:
                            return False
                    except FileNotFoundError:
                        continue
            return True

        self.wait_until(old_listeners_closed, "old workers close their listeners")
        self.wait_until(
            lambda: self.fetch()[2].get("X-Generation") == generation,
            "new generation serving requests",
        )
        return old

    def snapshot(self, name):
        status, payload, _ = self.fetch(f"/{name}-status")
        require(status == 200, f"{name} status endpoint", status)
        return json.loads(payload)

    def hold_body(self, client=CLEAN_CLIENT):
        connection = socket.create_connection(
            ("127.0.0.1", self.port), 5, source_address=(client, 0)
        )
        try:
            connection.sendall(
                (
                    "POST /trial HTTP/1.1\r\nHost: localhost\r\n"
                    f"Content-Length: {len(MARKER)}\r\n"
                    "Content-Type: text/plain\r\nExpect: 100-continue\r\n"
                    "Connection: close\r\n\r\n"
                ).encode()
            )
            interim = b""
            while not interim.endswith(b"\r\n\r\n"):
                part = connection.recv(1)
                require(bool(part), "in-flight request receives interim response")
                interim += part
                require(len(interim) <= 1024, "bounded interim response")
            require(
                interim == b"HTTP/1.1 100 Continue\r\n\r\n",
                "body reader reached before reload",
                interim,
            )
            return connection
        except BaseException:
            connection.close()
            raise


def require(condition, name, detail=None):
    if not condition:
        raise Failure(f"{name}: {detail}")


def finish_body(connection, expected, worker):
    with connection:
        connection.sendall(MARKER)
        response = http.client.HTTPResponse(connection)
        try:
            response.begin()
            response.read()
            require(
                response.status == expected, "in-flight old policy", response.status
            )
            require(
                response.getheader("X-Worker") == str(worker), "old worker ownership"
            )
        finally:
            response.close()


def run(srv: PolicyServer):
    checks = []

    def check(name, path="/trial", expected=405, **kwargs):
        actual, _, _ = srv.fetch(path, **kwargs)
        require(actual == expected, name, {"actual": actual, "expected": expected})
        checks.append(name)

    def production_preserved():
        check(
            "unrelated production ban retained",
            "/protected",
            403,
            client=PRODUCTION_CLIENT,
        )
        snapshot = srv.snapshot("production")
        require(
            snapshot["bans"] == 1, "production ban not rearmed or flushed", snapshot
        )
        require(
            [row["addr"] for row in snapshot["banned"]] == [PRODUCTION_CLIENT],
            "unrelated production address retained",
            snapshot,
        )
        checks.append("production zone identity and ban preserved")

    srv.start()
    old = srv.sole_worker()
    check("body marker observed only in exact exception", body=MARKER)
    check(
        "longer sibling path remains strict",
        "/trial/sibling",
        403,
        body=MARKER,
        client="127.0.0.6",
    )
    check(
        "strict sibling remains protected",
        "/protected",
        403,
        body=MARKER,
        client="127.0.0.7",
    )
    check(
        "URI protection in exception",
        "/trial?x=union%20select",
        403,
        client=TRIAL_CLIENT,
    )
    check(
        "header protection in exception",
        expected=403,
        client=TRIAL_CLIENT,
        headers={"User-Agent": "union select"},
    )
    check(
        "existing trial ban takes priority over observation",
        expected=403,
        client=TRIAL_CLIENT,
    )
    for _ in range(2):
        check(
            "production trigger",
            "/protected?x=union%20select",
            403,
            client=PRODUCTION_CLIENT,
        )
    production_preserved()
    held = srv.hold_body()
    try:
        srv.transition("strict", strict=True)
        finish_body(held, 405, old)
    finally:
        held.close()
    srv.wait_until(
        lambda: srv.has_sole_worker_other_than(old), "observe worker drained"
    )
    require(srv.snapshot("trial")["bans"] == 1, "old observation has no ban effect")
    checks.append("promotion preserves old in-flight observation without ban")
    check(
        "new requests use strict policy",
        expected=403,
        body=MARKER,
        client=INFLIGHT_CLIENT,
    )
    old = srv.sole_worker()
    held = srv.hold_body(INFLIGHT_CLIENT)
    try:
        srv.transition("withdrawn")
        check("withdrawal observes new body", body=MARKER)
        check("withdrawal does not erase trial ban", expected=403, client=TRIAL_CLIENT)
        finish_body(held, 403, old)
    finally:
        held.close()
    srv.wait_until(lambda: srv.has_sole_worker_other_than(old), "strict worker drained")
    check(
        "old in-flight request can arm ban after withdrawal",
        expected=403,
        client=INFLIGHT_CLIENT,
    )
    snapshot = srv.snapshot("trial")
    require(
        snapshot["bans"] == 2,
        "both trial bans still attributable to trial zone",
        snapshot,
    )
    require(
        {row["addr"] for row in snapshot["banned"]} == {TRIAL_CLIENT, INFLIGHT_CLIENT},
        "trial zone records both addresses",
        snapshot,
    )
    checks.append("withdrawal retains existing and late old-worker trial bans")
    production_preserved()

    # A syntactically invalid candidate fails nginx -t and a real reload;
    # the current workers and shared zone continue to serve unchanged.
    old = srv.sole_worker()
    before = srv.error_log().count("invalid value")
    valid = srv.conf.read_text()
    srv.conf.write_text(
        valid.replace("shield_body_strict off;", "shield_body_strict invalid;")
    )
    tested = subprocess.run(
        [srv.nginx, "-t", "-p", str(srv.prefix), "-c", str(srv.conf)],
        capture_output=True,
        check=False,
    )
    require(tested.returncode != 0, "invalid candidate rejected by config check")
    require(b"invalid value" in tested.stderr, "specific config error", tested.stderr)
    srv.reload()
    srv.wait_until(
        lambda: srv.error_log().count("invalid value") > before,
        "invalid reload rejection",
    )
    require(srv.sole_worker() == old, "rejected reload retains worker")
    check("rejected reload keeps trial ban", expected=403, client=TRIAL_CLIENT)
    production_preserved()
    srv.conf.write_text(valid)
    checks.append("invalid configuration and reload preserve prior policy")

    old = srv.sole_worker()
    srv.transition("detached", attached=False)
    srv.wait_until(
        lambda: srv.has_sole_worker_other_than(old), "attached worker drained"
    )
    for client in (TRIAL_CLIENT, INFLIGHT_CLIENT):
        check(
            "detached trial no longer refuses old address", expected=200, client=client
        )
    require(
        srv.snapshot("trial")["bans"] == 2, "detaching is not shared state deletion"
    )
    check("detached exception still protects URI", "/trial?x=union%20select", 403)
    check(
        "detached exception still protects sibling",
        "/trial/sibling",
        403,
        body=MARKER,
        client="127.0.0.8",
    )
    production_preserved()
    old = srv.sole_worker()
    srv.transition("retired", attached=False, zone="")
    srv.wait_until(lambda: srv.has_sole_worker_other_than(old), "trial mapping retired")
    production_preserved()
    old = srv.sole_worker()
    srv.transition("fresh", zone="trial_v2")
    srv.wait_until(lambda: srv.has_sole_worker_other_than(old), "fresh trial worker")
    snapshot = srv.snapshot("trial")
    require(
        snapshot["bans"] == 0,
        "new dedicated generation starts with zero bans",
        snapshot,
    )
    require(
        snapshot["nodes"] == 0,
        "new dedicated generation starts with zero nodes",
        snapshot,
    )
    for client in (TRIAL_CLIENT, INFLIGHT_CLIENT):
        check(
            "retired trial ban absent from fresh generation",
            expected=200,
            client=client,
        )
    check("fresh generation still observes ambiguous marker", body=MARKER)
    production_preserved()
    checks.append("dedicated trial state retired without flushing production")
    return checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nginx", required=True)
    parser.add_argument("--module")
    parser.add_argument("--port", type=int, default=19585)
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    srv = PolicyServer(args.nginx, args.module, args.port)
    checks = []
    failed = None
    try:
        checks = run(srv)
    except (Failure, OSError, http.client.HTTPException, ValueError) as exc:
        failed = str(exc)
    finally:
        srv.stop()
    errors = srv.error_log() + srv.sanitizer_log()
    if "ERROR: AddressSanitizer" in errors or "runtime error:" in errors:
        failed = "sanitizer report"
    if args.output:
        args.output.mkdir(parents=True, exist_ok=True)
        for path in srv.prefix.glob("*"):
            if path.is_file():
                (args.output / path.name).write_bytes(path.read_bytes())
        (args.output / "results.json").write_text(
            json.dumps({"checks": checks, "failure": failed}, indent=2) + "\n"
        )
    srv.cleanup()
    if failed:
        print(f"FAIL test_policy_rollback: {failed}")
        return 1
    for name in checks:
        print(f"ok   {name}")
    print(f"PASS test_policy_rollback: {len(checks)} named checks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
