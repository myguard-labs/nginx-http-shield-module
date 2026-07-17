#!/usr/bin/env python3
"""Tail a shield_log JSON file and report attackers to AbuseIPDB.

This runs OUT OF BAND from nginx, deliberately: the module only writes a file
(one JSON object per line), and this unprivileged process owns everything the
request hot path must not -- the API key, rate limiting, per-IP de-duplication
and private-IP suppression.

  shield_log  ->  /var/log/nginx/shield.json  ->  this daemon  ->  AbuseIPDB

Design
------
* Follows the file with tail -F semantics: survives logrotate (the module
  reopens on SIGUSR1) by detecting inode/truncation changes and reopening.
* Persists a byte offset in a state file so a restart never re-reports lines it
  already processed, and never re-scans from the top.
* Suppression (all local, to protect a small free-tier quota):
    - skip RFC1918 / loopback / link-local / ULA / unspecified addresses;
    - de-dupe each IP for a window (default 15 min, matching AbuseIPDB's own
      per-IP rate limit) so a flood of hits from one IP is one report;
    - a hard daily cap (default 1000, the free-tier limit) after which reports
      are dropped until the UTC day rolls over.
* Maps the shield category to AbuseIPDB category IDs (mostly 21 Web App Attack;
  sqli adds 16). Unknown categories fall back to 21.

The API key is read from ABUSEIPDB_API_KEY in the environment (populate it from
/etc/myguard-build-env; never put it on the command line or in the unit file
literally). --dry-run prints what would be sent and calls nothing.
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import os
import signal
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API_URL = "https://api.abuseipdb.com/api/v2/report"

# shield category -> AbuseIPDB category IDs.
# https://www.abuseipdb.com/categories  (21 = Web App Attack, 16 = SQL Injection,
# 15 = Hacking). Everything shield blocks is a web-app attack; the ones that map
# to a more specific ID carry it in addition to 21.
CAT_MAP: dict[str, list[int]] = {
    "sqli": [21, 16],
    "xss": [21],
    "cmdi": [21],
    "lfi": [21],
    "traversal": [21],
    "rce": [21],
    "php_rce": [21],
    "java_rce": [21],
    "java_eval": [21],
    "template": [21],
    "deserial": [21],
    "ssrf_meta": [21],
    "exploit_path": [21],
    "sensitive_file": [21],
    "webshell": [21],
    "ctrl_char": [21],
    "httpoxy": [21],
    "range_dos": [21, 4],   # 4 = DDoS Attack
    "shellshock": [21],
    "log4shell": [21],
    "nullbyte": [21],
    "overlong": [21],
    "crlf": [21],
    "ssi": [21],
}
DEFAULT_CATS = [21]

# AbuseIPDB comment cap is 1024 chars; stay well under and never leak internals.
COMMENT_MAX = 500

_stop = False


def _handle_stop(signum, frame):  # noqa: ARG001
    global _stop
    _stop = True


def is_reportable_ip(ip: str) -> bool:
    """False for addresses AbuseIPDB will reject or that are ours to begin with."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def categories_for(cat: str) -> list[int]:
    return CAT_MAP.get(cat, DEFAULT_CATS)


def build_comment(entry: dict) -> str:
    """A public, non-sensitive one-liner. Never echo secrets or internal hosts."""
    cat = str(entry.get("cat", "?"))
    src = str(entry.get("src", "?"))
    req = str(entry.get("req", ""))
    comment = f"nginx-http-shield: {cat} attack in {src}; request line: {req}"
    return comment[:COMMENT_MAX]


class Suppressor:
    """Local quota protection: private-IP skip, per-IP window, daily cap."""

    def __init__(self, window_s: int, daily_cap: int):
        self.window_s = window_s
        self.daily_cap = daily_cap
        self._last: dict[str, float] = {}
        self._day: str | None = None
        self._count = 0

    def _roll_day(self, now: float) -> None:
        today = dt.datetime.fromtimestamp(now, dt.timezone.utc).strftime("%Y-%m-%d")
        if today != self._day:
            self._day = today
            self._count = 0
            self._last.clear()

    def allow(self, ip: str, now: float) -> tuple[bool, str]:
        self._roll_day(now)
        if self._count >= self.daily_cap:
            return False, "daily-cap"
        prev = self._last.get(ip)
        if prev is not None and (now - prev) < self.window_s:
            return False, "deduped"
        return True, ""

    def record(self, ip: str, now: float) -> None:
        self._last[ip] = now
        self._count += 1


class Reporter:
    def __init__(self, api_key: str, timeout: float, dry_run: bool):
        self.api_key = api_key
        self.timeout = timeout
        self.dry_run = dry_run

    def report(self, ip: str, cats: list[int], comment: str, ts: str) -> tuple[bool, str]:
        payload = {
            "ip": ip,
            "categories": ",".join(str(c) for c in cats),
            "comment": comment,
        }
        if ts:
            payload["timestamp"] = ts
        if self.dry_run:
            return True, "dry-run " + json.dumps(payload)

        data = urllib.parse.urlencode(payload).encode()
        req = urllib.request.Request(
            API_URL,
            data=data,
            headers={
                "Key": self.api_key,
                "Accept": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8", "replace")
            return True, body
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")
            # 429 = we hit AbuseIPDB's own rate limit; treat as soft failure.
            return False, f"HTTP {e.code}: {body}"
        except (urllib.error.URLError, OSError) as e:
            return False, f"network: {e}"


def load_offset(state_path: str, log_path: str) -> tuple[int, int]:
    """Return (offset, inode) previously persisted for this log, else (0, -1)."""
    try:
        with open(state_path, "r", encoding="utf-8") as fh:
            st = json.load(fh)
        if st.get("path") == os.path.abspath(log_path):
            return int(st.get("offset", 0)), int(st.get("inode", -1))
    except (FileNotFoundError, ValueError, KeyError):
        pass
    return 0, -1


def save_offset(state_path: str, log_path: str, offset: int, inode: int) -> None:
    tmp = state_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(
            {"path": os.path.abspath(log_path), "offset": offset, "inode": inode},
            fh,
        )
    os.replace(tmp, state_path)


def process_line(line: str, sup: Suppressor, reporter: Reporter, now: float, log) -> None:
    line = line.strip()
    if not line:
        return
    try:
        entry = json.loads(line)
    except ValueError:
        log(f"skip: malformed JSON: {line[:120]!r}")
        return

    ip = str(entry.get("ip", ""))
    if not is_reportable_ip(ip):
        return

    ok, why = sup.allow(ip, now)
    if not ok:
        return

    cats = categories_for(str(entry.get("cat", "")))
    comment = build_comment(entry)
    ts = str(entry.get("ts", ""))

    sent, detail = reporter.report(ip, cats, comment, ts)
    if sent:
        sup.record(ip, now)
        log(f"reported {ip} cats={cats}: {detail[:200]}")
    else:
        # Do NOT record on failure, so a transient error retries next time the
        # same IP reappears; but avoid a hot retry loop by not re-reading.
        log(f"FAILED  {ip} cats={cats}: {detail[:200]}")


def follow(args, reporter: Reporter, sup: Suppressor, log) -> None:
    log_path = args.logfile
    offset, saved_inode = load_offset(args.state, log_path)

    fh = None
    cur_inode = -1
    last_save = 0.0

    while not _stop:
        # (Re)open if not open, or if the file was rotated/truncated.
        if fh is None:
            try:
                fh = open(log_path, "r", encoding="utf-8", errors="replace")
                stat = os.fstat(fh.fileno())
                cur_inode = stat.st_ino
                if cur_inode == saved_inode and offset <= stat.st_size:
                    fh.seek(offset)          # resume where we left off
                else:
                    fh.seek(0)               # new/rotated file: start at top
                    offset = 0
                saved_inode = cur_inode
                log(f"opened {log_path} inode={cur_inode} at offset={offset}")
            except FileNotFoundError:
                time.sleep(args.poll)
                continue

        line = fh.readline()
        if line:
            offset = fh.tell()
            process_line(line, sup, reporter, time.time(), log)
            continue

        # EOF: persist offset, then check for rotation/truncation.
        now = time.time()
        if now - last_save >= 2.0:
            save_offset(args.state, log_path, offset, cur_inode)
            last_save = now
        try:
            disk = os.stat(log_path)
            if disk.st_ino != cur_inode or disk.st_size < offset:
                log("rotation/truncation detected; reopening")
                fh.close()
                fh = None
                offset = 0
                saved_inode = -1
                continue
        except FileNotFoundError:
            fh.close()
            fh = None
            continue
        time.sleep(args.poll)

    if fh is not None:
        save_offset(args.state, log_path, offset, cur_inode)
        fh.close()
    log("stopped")


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("logfile", help="shield_log JSON file to follow")
    p.add_argument("--state", default="/var/lib/shield-reporter/offset.json",
                   help="offset state file (default: %(default)s)")
    p.add_argument("--dedup-window", type=int, default=900,
                   help="seconds to suppress repeat reports per IP (default 900)")
    p.add_argument("--daily-cap", type=int, default=1000,
                   help="max reports per UTC day (default 1000, the free tier)")
    p.add_argument("--poll", type=float, default=1.0,
                   help="seconds to sleep at EOF (default 1.0)")
    p.add_argument("--timeout", type=float, default=10.0,
                   help="HTTP timeout seconds (default 10)")
    p.add_argument("--dry-run", action="store_true",
                   help="do not call AbuseIPDB; log the payload that would be sent")
    args = p.parse_args(argv)

    api_key = os.environ.get("ABUSEIPDB_API_KEY", "")
    if not api_key and not args.dry_run:
        print("ABUSEIPDB_API_KEY not set in environment "
              "(populate from /etc/myguard-build-env)", file=sys.stderr)
        return 2

    def log(msg: str) -> None:
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        print(f"{stamp} {msg}", flush=True)

    os.makedirs(os.path.dirname(args.state) or ".", exist_ok=True)

    signal.signal(signal.SIGTERM, _handle_stop)
    signal.signal(signal.SIGINT, _handle_stop)

    reporter = Reporter(api_key, args.timeout, args.dry_run)
    sup = Suppressor(args.dedup_window, args.daily_cap)

    log(f"shield reporter starting: {args.logfile} "
        f"(dedup={args.dedup_window}s cap={args.daily_cap}/day "
        f"dry_run={args.dry_run})")
    follow(args, reporter, sup, log)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
