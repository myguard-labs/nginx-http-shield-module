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
/etc/shield-abuseipdb.env; never put it on the command line or in the unit file
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

# After a rotation is detected, keep reading the OLD (renamed) inode until it
# returns this many consecutive empty reads a poll apart -- a "stable EOF" --
# before switching to the new file. This drains records nginx appends to the
# renamed inode between our last read and its SIGUSR1 reopen, and tolerates a
# send cooldown mid-drain (we simply keep the old fd open across it).
ROTATION_EOF_GRACE = 2

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


def sanitize_req(req: str) -> str:
    """Reduce a request line to `METHOD /first-segment` for a PUBLIC report.

    The raw request line is sent to a third party (AbuseIPDB), whose TOS
    requires stripping PII. Two layers of reduction:

    * the query string is dropped entirely -- URLs routinely carry session
      tokens, API keys, e-mail addresses and other PII in query params;
    * only the FIRST path segment is kept. Deeper segments routinely carry
      per-request PII -- password-reset tokens (/reset/<token>), e-mail
      addresses, tenant/customer IDs (/u/<id>/...), and absolute-form requests
      leak the internal host (GET http://internal.host/...). The first segment
      is enough to identify the attack pattern (/wp-login.php, /.env,
      /cgi-bin) without shipping the sensitive tail;
    * non-origin-form targets are reduced to the method alone -- authority-form
      (CONNECT internal.corp:443) is nothing but an internal hostname.

    The path may still be hostile bytes, so control/newline chars are stripped.
    """
    parts = req.split(" ", 2)
    method = parts[0] if parts else ""
    target = parts[1] if len(parts) > 1 else ""
    path = target.split("?", 1)[0]          # drop the query string (PII)

    # Absolute-form (GET http://host/path): drop the scheme+authority, which
    # would leak an internal hostname, and keep only the path.
    scheme = path.find("://")
    if scheme != -1:
        rest = path[scheme + 3:]
        slash = rest.find("/")
        path = rest[slash:] if slash != -1 else "/"

    # Keep the leading slash and the first path segment only.
    if path.startswith("/"):
        seg = path[1:].split("/", 1)[0]
        path = "/" + seg
    else:
        # Not origin-form. After the absolute-form strip above, anything left
        # without a leading "/" is authority-form (CONNECT internal.corp:443),
        # asterisk-form (OPTIONS *), or junk -- none of which carry a path
        # worth reporting, and the authority form leaks an internal hostname.
        # Report the method alone.
        path = ""

    method = "".join(ch for ch in method if ch.isalnum())[:16]
    path = "".join(ch for ch in path if 0x20 <= ord(ch) < 0x7f)[:128]
    out = (method + " " + path).strip()
    return out


def build_comment(entry: dict) -> str:
    """A public, non-sensitive one-liner. Never echo secrets, PII or internal hosts."""
    cat = str(entry.get("cat", "?"))
    src = str(entry.get("src", "?"))
    req = sanitize_req(str(entry.get("req", "")))
    comment = f"nginx-http-shield: {cat} attack in {src}; {req}"
    return comment[:COMMENT_MAX]


class Suppressor:
    """Local quota protection: private-IP skip, per-IP window, daily cap.

    Persisted to `state_path` so a restart does NOT reset the per-IP window or
    the daily count -- otherwise a crash-loop would bypass both and blow the
    quota. Saved after every recorded report (cheap: the map is bounded by the
    dedup window). Loaded on construction.
    """

    def __init__(self, window_s: int, daily_cap: int, state_path: str | None = None) -> None:
        self.window_s = window_s
        self.daily_cap = daily_cap
        self.state_path = state_path
        self._last: dict[str, float] = {}
        self._day: str | None = None
        self._count = 0
        self._load()

    def _load(self) -> None:
        if not self.state_path:
            return
        try:
            with open(self.state_path, "r", encoding="utf-8") as fh:
                st = json.load(fh)
            self._day = st.get("day")
            self._count = int(st.get("count", 0))
            self._last = {k: float(v) for k, v in st.get("last", {}).items()}
        except (FileNotFoundError, ValueError, KeyError, TypeError):
            pass

    def _save(self) -> None:
        if not self.state_path:
            return
        tmp = self.state_path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump({"day": self._day, "count": self._count,
                           "last": self._last}, fh)
            os.replace(tmp, self.state_path)
        except OSError:
            pass

    def _roll_day(self, now: float) -> None:
        today = dt.datetime.fromtimestamp(now, dt.timezone.utc).strftime("%Y-%m-%d")
        if today != self._day:
            self._day = today
            self._count = 0
            self._last.clear()

    def _prune(self, now: float) -> None:
        """Drop entries older than the dedup window so the map stays bounded."""
        cutoff = now - self.window_s
        self._last = {ip: t for ip, t in self._last.items() if t >= cutoff}

    def allow(self, ip: str, now: float) -> tuple[bool, str]:
        self._roll_day(now)
        if self._count >= self.daily_cap:
            return False, "daily-cap"
        prev = self._last.get(ip)
        if prev is not None and (now - prev) < self.window_s:
            return False, "deduped"
        return True, ""

    def record(self, ip: str, now: float) -> None:
        self._roll_day(now)
        self._last[ip] = now
        self._count += 1
        self._prune(now)
        self._save()


class Reporter:
    """POSTs to AbuseIPDB with a global cooldown after 429 / network failures.

    A failure sets `cooldown_until`; the caller must consult `in_cooldown()`
    before the next send so one unreachable/rate-limited API does not get
    hammered by every subsequent log line. 429 honours Retry-After; other
    failures use bounded exponential backoff.
    """

    BACKOFF_BASE = 5.0
    BACKOFF_MAX = 300.0

    def __init__(self, api_key: str, timeout: float, dry_run: bool) -> None:
        self.api_key = api_key
        self.timeout = timeout
        self.dry_run = dry_run
        self.cooldown_until = 0.0
        self._fail_streak = 0

    def in_cooldown(self, now: float) -> float:
        """Return seconds remaining in cooldown (0 if clear)."""
        return max(0.0, self.cooldown_until - now)

    def _note_success(self) -> None:
        self._fail_streak = 0
        self.cooldown_until = 0.0

    def _note_failure(self, now: float, retry_after: float | None) -> None:
        self._fail_streak += 1
        if retry_after is not None:
            delay = retry_after
        else:
            # Cap the exponent: without this an unbounded fail streak computes a
            # huge int in 2**(streak-1) and eventually raises OverflowError in
            # the float multiply. BACKOFF_MAX already caps the delay, so any
            # exponent past the saturation point is wasted work.
            exp = min(self._fail_streak - 1, 32)
            delay = min(self.BACKOFF_MAX,
                        self.BACKOFF_BASE * (2 ** exp))
        self.cooldown_until = now + delay

    # report() outcomes.
    OK = "ok"          # accepted; record + advance offset
    RETRY = "retry"    # transient (429/5xx/network); keep offset, retry after cooldown
    DROP = "drop"      # permanent (4xx != 429); log + advance, never retryable

    def report(self, ip: str, cats: list[int], comment: str, ts: str,
               now: float) -> tuple[str, str]:
        """POST one report. Returns (outcome, detail) where outcome is one of
        OK / RETRY / DROP.

        A permanent client error -- 400/401/403/422 etc. (a bad API key, a
        report older than AbuseIPDB's 60-day policy, a malformed payload) -- can
        never succeed on replay, so it is classified DROP: the caller advances
        past the record instead of rewinding to it forever (which would wedge
        the daemon and process no later line). Only 429 (rate limit, honours
        Retry-After), 5xx (server-side, transient) and network errors are
        RETRY. 429 is NOT a 4xx-drop: it clears once the window resets."""
        payload = {
            "ip": ip,
            "categories": ",".join(str(c) for c in cats),
            "comment": comment,
        }
        if ts:
            payload["timestamp"] = ts
        if self.dry_run:
            return self.OK, "dry-run " + json.dumps(payload)

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
            self._note_success()
            return self.OK, body
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")
            if e.code == 429:
                retry_after = None
                ra = e.headers.get("Retry-After")
                if ra and ra.isdigit():
                    retry_after = float(ra)
                self._note_failure(now, retry_after)
                return self.RETRY, f"HTTP 429: {body}"
            if 500 <= e.code < 600:
                # Server-side error: transient -> retry with backoff.
                self._note_failure(now, None)
                return self.RETRY, f"HTTP {e.code}: {body}"
            # Anything else (permanent 4xx, or a non-followed 3xx redirect
            # failure): retrying never helps. DROP -- log, advance, and do NOT
            # set a cooldown or bump the backoff streak, so one bad record can
            # never stall the whole queue. Only 429 and 5xx are retryable.
            return self.DROP, f"HTTP {e.code} (permanent, dropped): {body}"
        except (urllib.error.URLError, OSError) as e:
            self._note_failure(now, None)
            return self.RETRY, f"network: {e}"


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


def process_line(line: str, sup: Suppressor, reporter: Reporter, now: float, log) -> bool:
    """Process one log line. Return True if the line is done with (advance the
    offset past it), False if it must be retried later (a send failed / API in
    cooldown) so the caller keeps the offset on this line."""
    line = line.strip()
    if not line:
        return True
    try:
        entry = json.loads(line)
    except ValueError:
        log(f"skip: malformed JSON: {line[:120]!r}")
        return True   # never parseable; do not retry

    ip = str(entry.get("ip", ""))
    if not is_reportable_ip(ip):
        return True

    ok, why = sup.allow(ip, now)
    if not ok:
        return True   # deduped / capped -- intentionally dropped, not retried

    cats = categories_for(str(entry.get("cat", "")))
    comment = build_comment(entry)
    ts = str(entry.get("ts", ""))

    outcome, detail = reporter.report(ip, cats, comment, ts, now)
    if outcome == Reporter.OK:
        # Record (and durably checkpoint suppression) only on a confirmed send.
        sup.record(ip, now)
        log(f"reported {ip} cats={cats}: {detail[:200]}")
        return True

    if outcome == Reporter.DROP:
        # Permanent client error (4xx != 429). Retrying can never succeed, so
        # advance past this record rather than wedging the queue on it forever.
        log(f"DROP    {ip} cats={cats}: {detail[:200]}")
        return True

    # RETRY: reporter has set a cooldown. Do NOT advance past this line -- it is
    # retried once the cooldown clears, giving at-least-once delivery.
    log(f"FAILED  {ip} cats={cats} (retry after cooldown): {detail[:200]}")
    return False


def follow(args, reporter: Reporter, sup: Suppressor, log) -> None:
    log_path = args.logfile
    offset, saved_inode = load_offset(args.state, log_path)

    fh = None
    cur_inode = -1
    last_save = 0.0
    rotation_eofs = 0     # consecutive stable-EOF polls after rotation detected

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

        # Respect a global cooldown from a prior 429/network failure: pause
        # here without reading, so we don't advance past unsent lines.
        now = time.time()
        wait = reporter.in_cooldown(now)
        if wait > 0:
            time.sleep(min(wait, args.poll))
            continue

        pos = fh.tell()
        line = fh.readline()
        if line:
            # A line was available: if we were counting down a post-rotation
            # EOF grace, a late write just arrived on the old inode -> the fd is
            # not stable yet, restart the grace count.
            rotation_eofs = 0
            if process_line(line, sup, reporter, time.time(), log):
                offset = fh.tell()
                # Checkpoint the offset periodically DURING a backlog, not only
                # at EOF. A sustained flood can keep us in this branch for hours;
                # without a mid-stream checkpoint a crash would replay everything
                # since the last EOF and re-POST already-sent reports (quota
                # waste). Cheap: a small JSON write at most every 2s.
                now = time.time()
                if now - last_save >= 2.0:
                    save_offset(args.state, log_path, offset, cur_inode)
                    last_save = now
            else:
                # Send failed: rewind to retry this exact line after cooldown.
                fh.seek(pos)
                time.sleep(args.poll)
            continue

        # EOF: persist offset, then check for rotation/truncation.
        now = time.time()
        if now - last_save >= 2.0:
            save_offset(args.state, log_path, offset, cur_inode)
            last_save = now
        try:
            disk = os.stat(log_path)
            if disk.st_ino != cur_inode or disk.st_size < offset:
                # Rotation (new inode) or truncation detected on the path. Do NOT
                # close the old descriptor yet: nginx may still be appending to
                # the renamed inode until it reopens on SIGUSR1, and we may have a
                # failed line rewound for retry. We keep reading the OLD fh (which
                # still points at the rotated inode) on subsequent loop passes --
                # the normal read branch above drains it and honours cooldown /
                # retry-rewind -- and only switch to the new file once the old fd
                # has reached a STABLE EOF (rotation_eofs consecutive empty reads
                # a poll apart) with no send pending. On truncation (same inode,
                # shrunk) there is nothing to drain, so switch immediately.
                if disk.st_ino == cur_inode:
                    log("truncation detected; reopening")
                    fh.close()
                    fh = None
                    offset = 0
                    saved_inode = -1
                    continue

                rotation_eofs += 1
                if rotation_eofs < ROTATION_EOF_GRACE:
                    # Give the old inode another poll to flush late writes; the
                    # read branch will pick them up before we count another EOF.
                    time.sleep(args.poll)
                    continue

                # Stable EOF on the rotated inode: safe to switch now.
                log("rotation detected; old file drained, reopening")
                save_offset(args.state, log_path, offset, cur_inode)
                fh.close()
                fh = None
                offset = 0
                saved_inode = -1
                rotation_eofs = 0
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
              "(populate from /etc/shield-abuseipdb.env)", file=sys.stderr)
        return 2

    def log(msg: str) -> None:
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        print(f"{stamp} {msg}", flush=True)

    os.makedirs(os.path.dirname(args.state) or ".", exist_ok=True)

    signal.signal(signal.SIGTERM, _handle_stop)
    signal.signal(signal.SIGINT, _handle_stop)

    # Suppression state lives next to the offset state so dedup window and daily
    # cap survive a restart (a crash-loop must not reset them and blow the quota).
    sup_state = os.path.join(os.path.dirname(args.state) or ".", "suppress.json")

    reporter = Reporter(api_key, args.timeout, args.dry_run)
    sup = Suppressor(args.dedup_window, args.daily_cap, sup_state)

    log(f"shield reporter starting: {args.logfile} "
        f"(dedup={args.dedup_window}s cap={args.daily_cap}/day "
        f"dry_run={args.dry_run})")
    follow(args, reporter, sup, log)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
