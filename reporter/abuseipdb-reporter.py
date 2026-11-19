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
* Reports only explicitly promoted block-mode exploit evidence. The promotion
  registry is empty: current signature-match logs and legacy logs report nothing.
* Maps admitted categories to AbuseIPDB category IDs (sqli adds 16 to 21).
  Comments are constant; no request, category or source text is forwarded.

The API key is read from ABUSEIPDB_API_KEY in the environment (populate it from
/etc/shield-abuseipdb.env; never put it on the command line or in the unit file
literally). --dry-run prints what would be sent and calls nothing.
"""

from __future__ import annotations

import argparse
import datetime as dt
import email.utils
import ipaddress
import json
import math
import os
import re
import signal
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API_URL = "https://api.abuseipdb.com/api/v2/report"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every 3xx redirect.

    The default opener follows redirects and copies our request headers --
    including the "Key" API credential -- to the redirect target, possibly
    cross-origin, and turns the report POST into a GET whose 200 we would then
    record as a false success. AbuseIPDB has one fixed POST endpoint, so a
    redirect is never legitimate: surface it as an HTTPError instead of
    following it, so report() classifies it as a permanent DROP and the key is
    never re-sent. See audit s43 F1.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# Module-scoped opener so the credential-bearing POST never follows a redirect.
_OPENER = urllib.request.build_opener(_NoRedirect)

# Category IDs apply only AFTER explicit evidence promotion, never to raw hits.
CAT_MAP: dict[str, list[int]] = {
    "sqli": [21, 16],  # 16 = SQL Injection
    "range_dos": [21, 4],  # 4 = DDoS Attack (Apache-Killer Range)
}
DEFAULT_CATS = [21]

# Deliberately empty: inherited signatures and causal fixtures have no promoted
# exploit evidence. Promotion requires review of exact (ruleset, rule, revision,
# category), plus a producer that emits verdict=exploit. No inferred promotion.
PROMOTED_RULES: frozenset[tuple[str, str, int, str]] = frozenset()


# AbuseIPDB comment cap is 1024 chars; stay well under and never leak internals.
COMMENT_MAX = 500
MAX_LOG_LINE = 8192  # module records fit below this; cap damaged/untrusted files
MAX_STATE_COUNT = (1 << 63) - 1
MAX_STATE_OFFSET = (1 << 63) - 1  # seekable signed file offset
MAX_STATE_INODE = (1 << 64) - 1

# After a rotation is detected, keep reading the OLD (renamed) inode until it
# returns this many consecutive empty reads a poll apart -- a "stable EOF" --
# before switching to the new file. This drains records nginx appends to the
# renamed inode between our last read and its SIGUSR1 reopen, and tolerates a
# send cooldown mid-drain (we simply keep the old fd open across it).
ROTATION_EOF_GRACE = 2

_stop = False


def _state_int(value, minimum: int, maximum: int) -> int:
    """Accept only an integer emitted by our JSON state writer, within range."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("invalid state integer")
    if not minimum <= value <= maximum:
        raise ValueError("state integer out of range")
    return value


def _handle_stop(signum, frame):
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
    path = target.split("?", 1)[0]  # drop the query string (PII)

    # Absolute-form (GET http://host/path): drop the scheme+authority, which
    # would leak an internal hostname, and keep only the path.
    scheme = path.find("://")
    if scheme != -1:
        rest = path[scheme + 3 :]
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
    path = "".join(ch for ch in path if 0x20 <= ord(ch) < 0x7F)[:128]
    return (method + " " + path).strip()


def build_comment(_entry: dict) -> str:
    """Constant public text: no request fragments or arbitrary log fields."""
    return "nginx-http-shield: promoted block-mode exploit evidence"


def is_promoted_exploit(entry: dict) -> bool:
    """Fail closed on legacy, ambiguous, malformed or nonpromoted evidence."""
    if (entry.get("mode"), entry.get("action"), entry.get("verdict")) != (
        "block",
        "block",
        "exploit",
    ):
        return False
    ruleset, rule, revision, category = (
        entry.get("ruleset"),
        entry.get("rule"),
        entry.get("rev"),
        entry.get("cat"),
    )
    if not all(isinstance(v, str) for v in (ruleset, rule, category)):
        return False
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
        return False
    if (ruleset, rule, revision, category) not in PROMOTED_RULES:
        return False
    # The timestamp is the only free text other than IP sent to the API. Accept
    # only nginx's bounded ISO-8601 shape, then validate its calendar values.
    ts = entry.get("ts")
    if (
        not isinstance(ts, str)
        or re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:Z|[+-][0-9]{2}:[0-9]{2})",
            ts,
        )
        is None
    ):
        return False
    try:
        dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return False
    return isinstance(entry.get("ip"), str)


def _parse_retry_after(value: str | None, now: float) -> float | None:
    """Parse a Retry-After header into a delay in seconds.

    RFC 9110 allows both forms: delta-seconds ("120") and an HTTP-date
    ("Wed, 21 Oct 2015 07:28:00 GMT"). Returns None when the header is
    absent or unparsable, which leaves the caller on exponential backoff.

    The result is NOT clamped here -- Reporter._note_failure applies
    RETRY_AFTER_MAX, so every path into the cooldown shares one bound.
    """
    if not value:
        return None
    value = value.strip()
    # str.isdigit() accepts Unicode digits (e.g. "²", "③") that float() then
    # rejects with a ValueError outside this function's guard -- a hostile or
    # buggy Retry-After would crash the daemon into a restart loop (F2). Require
    # plain ASCII digits before the unguarded float().
    if value.isascii() and value.isdigit():
        return float(value)
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when is None:
        return None
    # A date without a timezone is GMT per RFC 9110.
    if when.tzinfo is None:
        when = when.replace(tzinfo=dt.timezone.utc)
    return max(0.0, when.timestamp() - now)


class Suppressor:
    """Local quota protection: private-IP skip, per-IP window, daily cap.

    Persisted to `state_path` so a restart does NOT reset the per-IP window or
    the daily count -- otherwise a crash-loop would bypass both and blow the
    quota. Saved after every recorded report (cheap: the map is bounded by the
    dedup window). Loaded on construction.
    """

    def __init__(
        self, window_s: int, daily_cap: int, state_path: str | None = None
    ) -> None:
        self.window_s = window_s
        self.daily_cap = daily_cap
        self.state_path = state_path
        self._last: dict[str, float] = {}
        self._day: str | None = None
        self._count = 0
        self._load()

    # Single-owner protocol: confirmed reports live in _count/_last; each
    # pending intent independently debits its UTC day and original IP window.
    # reserve() is the only permission-granting transition: append intent,
    # atomically replace the state file, then grant one transport attempt.
    # A failed save grants nothing and restores the prior pending set.
    # Loading validates all fields before publishing any state. Unavailable or
    # unready state forbids every save, including legacy record()/dry-run saves:
    # unknown debt must never be replaced with empty or partial knowledge.
    # Missing state cannot distinguish first install from lost established state.
    # A verified first install needs explicit offline empty-state provisioning;
    # an established install needs its current authoritative state restored.
    # No runtime path initializes state or clears a block. A restored stale
    # suppression snapshot cannot be detected without an external trust anchor;
    # an offset checkpoint is advisory and replay still passes suppression.
    # Unknown outcomes
    # stay pending; neither record() nor day rollover confirms or releases them.
    # One Suppressor owns the file; concurrent writers/stale instances are not
    # supported. process_line confirms only the exact attempt it just reserved.
    # Confirmation replaces pending debt and confirmed counters in one save;
    # failed settlement restores the pending debit. No attempted POST result
    # proves no send, so RETRY/DROP/exception never release pending debt.
    # Legacy record() never settles an intent; startup recovery is separate.
    STATE_VERSION = 2
    MAX_STATE_CHARS = 16 * 1024 * 1024

    @staticmethod
    def _unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate suppression state key")
            result[key] = value
        return result

    @staticmethod
    def _state_day(value) -> str:
        if (
            not isinstance(value, str)
            or dt.date.fromisoformat(value).isoformat() != value
        ):
            raise ValueError("invalid suppression day")
        return value

    @staticmethod
    def _state_ip(value) -> str:
        if (
            not isinstance(value, str)
            or "%" in value
            or str(ipaddress.ip_address(value)) != value
        ):
            raise ValueError("invalid suppression IP")
        return value

    @staticmethod
    def _legacy_state_ip(value) -> str:
        if not isinstance(value, str) or "%" in value:
            raise ValueError("invalid legacy suppression IP")
        return str(ipaddress.ip_address(value))

    @staticmethod
    def _state_timestamp(value, latest: float) -> float:
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or not 0 <= value <= min(latest, 253402300799.0)
        ):
            raise ValueError("invalid suppression timestamp")
        return float(value)

    def _load(self) -> None:
        self._pending: list[dict] = []
        self._state_valid = False
        if not self.state_path:
            return
        try:
            with open(self.state_path, "r", encoding="utf-8") as fh:
                raw = fh.read(self.MAX_STATE_CHARS + 1)
            if len(raw) > self.MAX_STATE_CHARS:
                raise ValueError("suppression state too large")
            st = json.loads(raw, object_pairs_hook=self._unique_object)
            if not isinstance(st, dict):
                raise TypeError("invalid suppression state")
            legacy = set(st) == {"day", "count", "last"}
            if not legacy:
                if set(st) != {
                    "version",
                    "day",
                    "count",
                    "last",
                    "pending",
                    "reservation_ready",
                }:
                    raise ValueError("invalid suppression schema")
                _state_int(st["version"], self.STATE_VERSION, self.STATE_VERSION)
                if not isinstance(st["reservation_ready"], bool):
                    raise ValueError("invalid reservation readiness")
            count = _state_int(st["count"], 0, MAX_STATE_COUNT)
            day = None if st["day"] is None else self._state_day(st["day"])
            if not isinstance(st["last"], dict):
                raise TypeError("invalid suppression map")
            latest = time.time() + self.window_s
            last = {}
            for ip, value in st["last"].items():
                canonical = self._legacy_state_ip(ip) if legacy else self._state_ip(ip)
                timestamp = self._state_timestamp(value, latest)
                last[canonical] = max(last.get(canonical, timestamp), timestamp)
            pending = [] if legacy else st["pending"]
            if not isinstance(pending, list):
                raise TypeError("invalid pending intents")
            identities = set()
            for intent in pending:
                if not isinstance(intent, dict) or set(intent) != {
                    "day",
                    "ip",
                    "started_at",
                    "window_s",
                }:
                    raise ValueError("invalid pending intent schema")
                self._state_ip(intent["ip"])
                started = self._state_timestamp(intent["started_at"], latest)
                window = _state_int(intent["window_s"], 1, MAX_STATE_COUNT)
                intent_day = self._state_day(intent["day"])
                if (
                    intent_day
                    != dt.datetime.fromtimestamp(started, dt.timezone.utc)
                    .date()
                    .isoformat()
                ):
                    raise ValueError("pending intent day mismatch")
                identity = (intent["ip"], started, window)
                if identity in identities:
                    raise ValueError("duplicate pending intent")
                identities.add(identity)
            if day is None and (count or last or pending):
                raise ValueError("missing suppression day")
            self._day, self._count, self._last = day, count, last
            self._pending = pending
            self._state_valid = legacy or st["reservation_ready"]
        except FileNotFoundError:
            pass
        except (
            OSError,
            ValueError,
            KeyError,
            TypeError,
            OverflowError,
            RecursionError,
        ):
            # Legacy allow()/record() remain nonthrowing in-memory APIs. Neither
            # reserve() nor _save() may act on this incomplete view of debt.
            pass

    def _save(self) -> bool:
        if not self.state_path or not self._state_valid:
            return False
        tmp = self.state_path + ".tmp"
        try:
            state = {
                "version": self.STATE_VERSION,
                "day": self._day,
                "count": self._count,
                "last": self._last,
                "pending": self._pending,
                "reservation_ready": self._state_valid,
            }
            raw = json.dumps(state, allow_nan=False, sort_keys=True)
            if len(raw) > self.MAX_STATE_CHARS:
                return False
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.write(raw)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.state_path)
            parent = os.path.dirname(os.path.abspath(self.state_path))
            parent_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
            return True
        except (OSError, ValueError, TypeError, OverflowError):
            return False

    def reserve(self, ip: str, now: float) -> tuple[bool, str]:
        """Persist one pending attempt before granting permission to send once.

        Requires existing validated state. First-install/lost-state decisions
        must be made by startup recovery, never inferred from an absent file.
        A false result forbids sending. This API never performs transport or
        counts a report as confirmed; unresolved intents remain conservative.
        """
        if not self.state_path or not self._state_valid:
            return False, "state-unavailable"
        try:
            now = self._state_timestamp(now, time.time() + self.window_s)
            window = _state_int(self.window_s, 1, MAX_STATE_COUNT)
            _state_int(self.daily_cap, 1, MAX_STATE_COUNT)
            ip = self._state_ip(str(ipaddress.ip_address(ip)))
        except (ValueError, TypeError, OverflowError):
            return False, "invalid-reservation"
        allowed, reason = self.allow(ip, now)
        if not allowed:
            return False, reason
        previous = self._pending
        # Expired same-day intents still debit the daily cap; previous-day
        # intents still protect the IP until their ORIGINAL window expires.
        self._pending = [
            intent
            for intent in previous
            if intent["day"] >= self._day
            or now - intent["started_at"] < intent["window_s"]
        ]
        self._pending.append(
            {"day": self._day, "ip": ip, "started_at": now, "window_s": window}
        )
        if not self._save():
            self._pending = previous
            return False, "state-persistence"
        return True, ""

    def confirm(self, ip: str, now: float) -> bool:
        """Settle this reserved attempt only after a confirmed transport success.

        If saving fails, retain its original pending debt in memory and on disk.
        Legacy record() remains independent and never consumes a reservation.
        """
        ip = str(ipaddress.ip_address(ip))
        intent = next(
            (
                item
                for item in self._pending
                if item["ip"] == ip and item["started_at"] == now
            ),
            None,
        )
        if intent is None:
            return False
        previous = self._day, self._count, self._last.copy(), self._pending
        self._pending = [item for item in self._pending if item is not intent]
        self._roll_day(now)
        self._last[ip] = now
        self._count += 1
        self._prune(now)
        if not self._save():
            self._day, self._count, self._last, self._pending = previous
            return False
        return True

    def _roll_day(self, now: float) -> None:
        today = dt.datetime.fromtimestamp(now, dt.timezone.utc).strftime("%Y-%m-%d")
        if today != self._day:
            self._day = today
            self._count = 0

    def _prune(self, now: float) -> None:
        """Drop entries older than the dedup window so the map stays bounded."""
        cutoff = now - self.window_s
        self._last = {ip: t for ip, t in self._last.items() if t >= cutoff}

    def allow(self, ip: str, now: float) -> tuple[bool, str]:
        self._roll_day(now)
        pending_count = sum(intent["day"] == self._day for intent in self._pending)
        if self._count + pending_count >= self.daily_cap:
            return False, "daily-cap"
        prev = self._last.get(ip)
        if prev is not None and (now - prev) < self.window_s:
            return False, "deduped"
        if any(
            intent["ip"] == ip and now - intent["started_at"] < intent["window_s"]
            for intent in self._pending
        ):
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
    # Upper bound on a server-supplied Retry-After. The value is remote input:
    # a buggy or hostile intermediary answering "Retry-After: 99999999" would
    # otherwise park the reporter for years, silently dropping every hit for
    # the lifetime of the process. An hour is well past any real rate-limit
    # window AbuseIPDB applies.
    RETRY_AFTER_MAX = 3600.0

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
            # Clamp: remote-supplied, see RETRY_AFTER_MAX. Negative values
            # (a past HTTP-date, or a malformed negative int) mean "now".
            delay = max(0.0, min(retry_after, self.RETRY_AFTER_MAX))
        else:
            # Cap the exponent: without this an unbounded fail streak computes a
            # huge int in 2**(streak-1) and eventually raises OverflowError in
            # the float multiply. BACKOFF_MAX already caps the delay, so any
            # exponent past the saturation point is wasted work.
            exp = min(self._fail_streak - 1, 32)
            delay = min(self.BACKOFF_MAX, self.BACKOFF_BASE * (2**exp))
        self.cooldown_until = now + delay

    # report() outcomes.
    OK = "ok"  # accepted; record + advance offset
    RETRY = "retry"  # transient (429/5xx/network); keep offset, retry after cooldown
    DROP = "drop"  # permanent (4xx != 429); log + advance, never retryable

    def report(
        self, ip: str, cats: list[int], comment: str, ts: str, now: float
    ) -> tuple[str, str]:
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
            with _OPENER.open(req, timeout=self.timeout):
                pass
            self._note_success()
            return self.OK, "HTTP success"
        except urllib.error.HTTPError as e:
            # The response is remote input. It can be arbitrarily large and may
            # echo the credential or submitted request, so never read or log it.
            e.close()
            if e.code == 429:
                self._note_failure(
                    now, _parse_retry_after(e.headers.get("Retry-After"), now)
                )
                return self.RETRY, "HTTP 429"
            if 500 <= e.code < 600:
                # Server-side error: transient -> retry with backoff.
                self._note_failure(now, None)
                return self.RETRY, f"HTTP {e.code}"
            # Anything else (permanent 4xx, or a 3xx redirect that _NoRedirect
            # refused before the Key header could be re-sent -- F1): retrying
            # never helps. DROP -- log, advance, and do NOT
            # set a cooldown or bump the backoff streak, so one bad record can
            # never stall the whole queue. Only 429 and 5xx are retryable.
            return self.DROP, f"HTTP {e.code} (permanent, dropped)"
        except (urllib.error.URLError, OSError):
            self._note_failure(now, None)
            return self.RETRY, "network: request failed"


def load_offset(state_path: str, log_path: str) -> tuple[int, int]:
    """Return (offset, inode) previously persisted for this log, else (0, -1)."""
    try:
        with open(state_path, "r", encoding="utf-8") as fh:
            st = json.load(fh)
        if not isinstance(st, dict):
            raise TypeError("invalid offset state")
        if st.get("path") == os.path.abspath(log_path):
            offset = _state_int(st.get("offset", 0), 0, MAX_STATE_OFFSET)
            inode = _state_int(st.get("inode", -1), -1, MAX_STATE_INODE)
            return offset, inode
    except (
        FileNotFoundError,
        ValueError,
        KeyError,
        TypeError,
        OverflowError,
        RecursionError,
    ):
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


def _unique_object(pairs):
    """Duplicate keys cannot override a conflicting evidence disposition."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def process_line(
    line: str, sup: Suppressor, reporter: Reporter, now: float, log
) -> bool:
    """Process one log line. Return True if the line is done with (advance the
    offset past it), False if it must be retried later (a send failed / API in
    cooldown or unavailable durable state) so the caller keeps the offset on
    this line. Replay remains subject to pending quota/dedup debt."""
    if len(line) > MAX_LOG_LINE:
        log("skip: oversized log record")
        return True
    line = line.strip()
    if not line:
        return True
    try:
        entry = json.loads(line, object_pairs_hook=_unique_object)
    except (ValueError, RecursionError):
        log("skip: malformed JSON")
        return True  # never parseable; do not retry

    if not isinstance(entry, dict):
        log("skip: JSON record is not an object")
        return True

    if not is_promoted_exploit(entry):
        log("skip: record is not promoted block-mode exploit evidence")
        return True

    ip = entry["ip"]
    if not is_reportable_ip(ip):
        return True
    ip = str(ipaddress.ip_address(ip))

    ok, _why = sup.allow(ip, now)
    if not ok:
        return True  # deduped / capped -- intentionally dropped, not retried

    cats = categories_for(str(entry.get("cat", "")))
    comment = build_comment(entry)
    ts = str(entry.get("ts", ""))

    # Only the built-in dry-run implementation is known to perform no I/O.
    # Call it directly so an overridden report() cannot bypass the barrier.
    dry_run = type(reporter) is Reporter and reporter.dry_run
    if dry_run:
        outcome, detail = Reporter.report(reporter, ip, cats, comment, ts, now)
    else:
        reserved, reason = sup.reserve(ip, now)
        if not reserved:
            log(f"STATE   {ip}: {reason}")
            return reason in ("deduped", "daily-cap")
        outcome, detail = reporter.report(ip, cats, comment, ts, now)

    if outcome == Reporter.OK:
        if dry_run:
            sup.record(ip, now)
        elif not sup.confirm(ip, now):
            log(f"STATE   {ip}: confirmation pending; attempt debt retained")
        log(f"reported {ip} cats={cats}: {detail[:200]}")
        return True

    if outcome == Reporter.DROP:
        # Permanent client error (4xx != 429). Retrying can never succeed, so
        # advance past this record rather than wedging the queue on it forever.
        log(f"DROP    {ip} cats={cats}: {detail[:200]}")
        return True

    # RETRY (or an unknown outcome) keeps the offset, but not permission to
    # resend: every attempted POST remains pending unless confirmed. A server
    # error or network failure cannot prove the remote end did not accept it.
    log(f"FAILED  {ip} cats={cats} (retry after cooldown): {detail[:200]}")
    return False


def _read_log_line(fh, discarding=False):
    """Read bounded chunks; defer incomplete lines across transient EOF."""
    start = fh.tell()
    line = fh.readline(MAX_LOG_LINE + 1)
    if not line:
        return "", discarding, 0
    if not discarding and len(line) <= MAX_LOG_LINE:
        if not line.endswith("\n"):
            # A short write may stop before its newline. Re-read the whole
            # bounded fragment on the next paced EOF poll, so an appended tail
            # cannot be mistaken for a separate record.
            end = fh.tell()
            fh.seek(start)
            return "", False, end
        return line, False, 0
    while line and not line.endswith("\n"):
        line = fh.readline(MAX_LOG_LINE + 1)
    return None, not line.endswith("\n"), 0


def follow(args, reporter: Reporter, sup: Suppressor, log) -> None:
    log_path = args.logfile
    offset, saved_inode = load_offset(args.state, log_path)

    fh = None
    cur_inode = -1
    last_save = 0.0
    rotation_eofs = 0  # consecutive stable-EOF polls after rotation detected
    discarding = False  # an oversized record has not reached its newline yet
    partial_end = 0  # farthest read position of a deferred short fragment

    try:
        while not _stop:
            # (Re)open if not open, or if the file was rotated/truncated.
            if fh is None:
                try:
                    # The handle spans loop iterations; the enclosing finally
                    # closes it on stop or exception, including checkpoint failures.
                    fh = open(log_path, "r", encoding="utf-8", errors="replace")  # noqa: SIM115
                    discarding = False
                    partial_end = 0
                    stat = os.fstat(fh.fileno())
                    cur_inode = stat.st_ino
                    if cur_inode == saved_inode and offset <= stat.st_size:
                        fh.seek(offset)  # resume where we left off
                    else:
                        fh.seek(0)  # new/rotated file: start at top
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

            if partial_end:
                # A deferred line is rewound to its start. Check the farthest
                # position read before trying again, or a shorter replacement
                # could be consumed without detecting same-inode truncation.
                try:
                    disk = os.stat(log_path)
                    if disk.st_ino == cur_inode and disk.st_size < partial_end:
                        log("truncation detected; reopening")
                        fh.close()
                        fh = None
                        offset = 0
                        saved_inode = -1
                        continue
                except FileNotFoundError:
                    pass

            assert fh is not None
            pos = fh.tell()
            was_discarding = discarding
            line, discarding, seen_partial_end = _read_log_line(fh, discarding)
            if seen_partial_end > partial_end:
                # New bytes on a rotated old inode restart its stable-EOF grace,
                # even while the record is still waiting for a newline.
                rotation_eofs = 0
            partial_end = seen_partial_end
            if line is not None and line:
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

            if line is None:
                # Consuming a late oversized record is still activity on the old
                # inode. Restart the stable-EOF grace before deciding to rotate.
                rotation_eofs = 0
                if not was_discarding:
                    log("skip: oversized log record")
                # Do not checkpoint a position inside an incomplete record: after
                # restart that would make its valid-looking tail a new report.
                if not discarding:
                    offset = fh.tell()
                continue

            # EOF: persist offset, then check for rotation/truncation.
            now = time.time()
            if now - last_save >= 2.0:
                save_offset(args.state, log_path, offset, cur_inode)
                last_save = now
            try:
                disk = os.stat(log_path)
                # `offset` stays at the last complete line, including while a
                # damaged record is being discarded. Truncation must compare with
                # the current or deferred reader position, which may be farther on.
                if disk.st_ino != cur_inode or disk.st_size < max(
                    fh.tell(), partial_end
                ):
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
                # The path is temporarily gone: logrotate has renamed the file but
                # nginx has not yet reopened a fresh one on SIGUSR1. Do NOT close the
                # old fd -- nginx may still append late hits to the renamed inode in
                # this gap, and closing now discards the exact descriptor needed to
                # drain them. Apply the SAME stable-EOF grace as a new-inode rotation:
                # keep reading the old fh (the read branch drains late writes and
                # resets rotation_eofs) and only switch once we have counted
                # ROTATION_EOF_GRACE consecutive empty reads with the path absent.
                rotation_eofs += 1
                if rotation_eofs < ROTATION_EOF_GRACE:
                    time.sleep(args.poll)
                    continue
                assert fh is not None
                log("rotation detected (path absent); old file drained, reopening")
                save_offset(args.state, log_path, offset, cur_inode)
                fh.close()
                fh = None
                offset = 0
                saved_inode = -1
                rotation_eofs = 0
                continue
            time.sleep(args.poll)

        if fh is not None:
            save_offset(args.state, log_path, offset, cur_inode)
    finally:
        if fh is not None:
            fh.close()
    log("stopped")


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("logfile", help="shield_log JSON file to follow")
    p.add_argument(
        "--state",
        default="/var/lib/shield-reporter/offset.json",
        help="offset state file (default: %(default)s)",
    )
    p.add_argument(
        "--dedup-window",
        type=int,
        default=900,
        help="seconds to suppress repeat reports per IP (default 900)",
    )
    p.add_argument(
        "--daily-cap",
        type=int,
        default=1000,
        help="max reports per UTC day (default 1000, the free tier)",
    )
    p.add_argument(
        "--poll", type=float, default=1.0, help="seconds to sleep at EOF (default 1.0)"
    )
    p.add_argument(
        "--timeout", type=float, default=10.0, help="HTTP timeout seconds (default 10)"
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="do not call AbuseIPDB; log the payload that would be sent",
    )
    args = p.parse_args(argv)

    if args.dedup_window <= 0:
        p.error("--dedup-window must be positive")
    if args.daily_cap < 0:
        p.error("--daily-cap must be nonnegative")
    if not math.isfinite(args.poll) or args.poll <= 0:
        p.error("--poll must be finite and positive")
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        p.error("--timeout must be finite and positive")

    api_key = os.environ.get("ABUSEIPDB_API_KEY", "")
    if not api_key and not args.dry_run:
        print(
            "ABUSEIPDB_API_KEY not set in environment "
            "(populate from /etc/shield-abuseipdb.env)",
            file=sys.stderr,
        )
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
    if not args.dry_run and not sup._state_valid:
        print(
            f"suppression state unavailable: {sup_state}. Reporting stopped. "
            "For an established installation restore the current authoritative "
            "state; never reset it to empty. Only for a verified first install, "
            "offline create this file exclusively (do not overwrite) with "
            '{"version":2,"day":null,"count":0,"last":{},"pending":[], '
            '"reservation_ready":true}. No automatic initialization is performed.',
            file=sys.stderr,
        )
        return 2

    log(
        f"shield reporter starting: {args.logfile} "
        f"(dedup={args.dedup_window}s cap={args.daily_cap}/day "
        f"dry_run={args.dry_run})"
    )
    follow(args, reporter, sup, log)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
