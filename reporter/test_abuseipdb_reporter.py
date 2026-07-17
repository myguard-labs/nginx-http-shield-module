#!/usr/bin/env python3
"""Unit tests for reporter/abuseipdb-reporter.py.

The module has a hyphenated filename (not importable by name), so it is loaded
via importlib. No network is touched: Reporter is exercised in dry-run mode or
with its urlopen call monkeypatched, and time is passed in explicitly (the code
takes `now` as a parameter everywhere), so the tests are deterministic.
"""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path

import pytest

_HERE = Path(__file__).resolve().parent
_SRC = _HERE / "abuseipdb-reporter.py"

spec = importlib.util.spec_from_file_location("shield_reporter", _SRC)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


# --------------------------------------------------------------------------- #
# is_reportable_ip
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "ip,expected",
    [
        ("8.8.8.8", True),
        ("1.2.3.4", True),
        ("2606:4700:4700::1111", True),
        ("10.0.0.1", False),          # RFC1918
        ("192.168.1.1", False),       # RFC1918
        ("172.16.5.5", False),        # RFC1918
        ("127.0.0.1", False),         # loopback
        ("169.254.0.1", False),       # link-local
        ("::1", False),               # loopback v6
        ("fe80::1", False),           # link-local v6
        ("fd00::1", False),           # ULA (private v6)
        ("0.0.0.0", False),           # unspecified
        ("224.0.0.1", False),         # multicast
        ("not-an-ip", False),         # garbage
        ("", False),
    ],
)
def test_is_reportable_ip(ip, expected):
    assert mod.is_reportable_ip(ip) is expected


# --------------------------------------------------------------------------- #
# categories_for
# --------------------------------------------------------------------------- #
def test_categories_for_known():
    assert mod.categories_for("sqli") == [21, 16]
    assert mod.categories_for("xss") == [21]
    assert mod.categories_for("range_dos") == [21, 4]


def test_categories_for_unknown_falls_back():
    assert mod.categories_for("totally-made-up") == mod.DEFAULT_CATS == [21]


# --------------------------------------------------------------------------- #
# sanitize_req  (PII strip + hostile-byte strip)
# --------------------------------------------------------------------------- #
def test_sanitize_req_drops_query_string():
    # query string can carry tokens/PII -> must be dropped entirely
    out = mod.sanitize_req("GET /login?token=SECRET123&email=a@b.co HTTP/1.1")
    assert out == "GET /login"
    assert "SECRET" not in out
    assert "@" not in out


def test_sanitize_req_strips_control_and_high_bytes():
    out = mod.sanitize_req("POST /a\x00b\x1f\x7f\xffc HTTP/1.1")
    assert out == "POST /abc"


def test_sanitize_req_method_alnum_only():
    out = mod.sanitize_req("GE\tT /x")
    assert out == "GET /x"


def test_sanitize_req_empty_and_partial():
    assert mod.sanitize_req("") == ""
    assert mod.sanitize_req("GET") == "GET"
    assert mod.sanitize_req("GET /only/path") == "GET /only/path"


def test_sanitize_req_length_caps():
    long_path = "/" + "a" * 5000
    out = mod.sanitize_req("GET " + long_path + "?x=1")
    method, path = out.split(" ", 1)
    assert len(path) <= 256


# --------------------------------------------------------------------------- #
# build_comment
# --------------------------------------------------------------------------- #
def test_build_comment_shape_and_no_query_leak():
    entry = {"cat": "sqli", "src": "uri",
             "req": "GET /x?password=hunter2 HTTP/1.1", "ip": "8.8.8.8"}
    c = mod.build_comment(entry)
    assert c.startswith("nginx-http-shield: sqli attack in uri; GET /x")
    assert "hunter2" not in c
    assert len(c) <= mod.COMMENT_MAX


def test_build_comment_missing_fields():
    c = mod.build_comment({})
    assert c.startswith("nginx-http-shield: ? attack in ?;")


def test_build_comment_truncates():
    entry = {"cat": "x", "src": "y", "req": "GET /" + "a" * 5000}
    assert len(mod.build_comment(entry)) <= mod.COMMENT_MAX


# --------------------------------------------------------------------------- #
# Suppressor: dedup window, daily cap, day roll, persistence
# --------------------------------------------------------------------------- #
def test_suppressor_dedup_window():
    sup = mod.Suppressor(window_s=900, daily_cap=1000)
    ok, _ = sup.allow("8.8.8.8", now=1000.0)
    assert ok
    sup.record("8.8.8.8", now=1000.0)

    ok, why = sup.allow("8.8.8.8", now=1000.0 + 899)   # inside window
    assert not ok and why == "deduped"

    ok, _ = sup.allow("8.8.8.8", now=1000.0 + 901)      # past window
    assert ok


def test_suppressor_distinct_ips_not_deduped():
    sup = mod.Suppressor(window_s=900, daily_cap=1000)
    sup.record("8.8.8.8", now=1000.0)
    ok, _ = sup.allow("1.1.1.1", now=1000.0)
    assert ok


def test_suppressor_daily_cap():
    sup = mod.Suppressor(window_s=1, daily_cap=3)
    now = 1000.0
    for i in range(3):
        ok, _ = sup.allow(f"8.8.8.{i}", now)
        assert ok
        sup.record(f"8.8.8.{i}", now)
        now += 10          # past the 1s window so dedup doesn't interfere
    ok, why = sup.allow("8.8.8.9", now)
    assert not ok and why == "daily-cap"


def test_suppressor_day_roll_resets_count():
    sup = mod.Suppressor(window_s=1, daily_cap=1)
    # day 0
    day0 = 0.0                         # 1970-01-01 UTC
    ok, _ = sup.allow("8.8.8.8", day0)
    assert ok
    sup.record("8.8.8.8", day0)
    ok, why = sup.allow("8.8.8.9", day0 + 5)
    assert not ok and why == "daily-cap"
    # next UTC day -> count resets
    day1 = 86400.0 + 5
    ok, _ = sup.allow("8.8.8.9", day1)
    assert ok


def test_suppressor_persists_across_restart(tmp_path):
    state = str(tmp_path / "suppress.json")
    sup = mod.Suppressor(window_s=900, daily_cap=1000, state_path=state)
    sup.allow("8.8.8.8", now=1000.0)     # sets _day (real call order)
    sup.record("8.8.8.8", now=1000.0)
    assert os.path.exists(state)

    # fresh instance loads the state: the dedup window and count survive
    sup2 = mod.Suppressor(window_s=900, daily_cap=1000, state_path=state)
    ok, why = sup2.allow("8.8.8.8", now=1000.0 + 100)
    assert not ok and why == "deduped"
    assert sup2._count == 1


def test_suppressor_record_without_allow_sets_day(tmp_path):
    # record() called without a prior allow() must still stamp the UTC day,
    # else state persists day=null and reload wipes count/window on day-roll.
    state = str(tmp_path / "suppress.json")
    sup = mod.Suppressor(window_s=900, daily_cap=1000, state_path=state)
    sup.record("8.8.8.8", now=1000.0)     # no allow() first
    assert sup._day == "1970-01-01"       # now=1000.0 -> that UTC day, stamped

    sup2 = mod.Suppressor(window_s=900, daily_cap=1000, state_path=state)
    # same day on reload -> count/window survive, not wiped
    ok, why = sup2.allow("8.8.8.8", now=1000.0 + 100)
    assert not ok and why == "deduped"
    assert sup2._count == 1


def test_suppressor_corrupt_state_ignored(tmp_path):
    state = tmp_path / "suppress.json"
    state.write_text("{ not valid json")
    sup = mod.Suppressor(window_s=900, daily_cap=1000, state_path=str(state))
    # falls back to empty state, still works
    ok, _ = sup.allow("8.8.8.8", now=1000.0)
    assert ok


def test_suppressor_prune_bounds_map():
    sup = mod.Suppressor(window_s=10, daily_cap=1000)
    sup.record("8.8.8.1", now=1000.0)
    sup.record("8.8.8.2", now=1005.0)
    # record well past the window -> old entries pruned
    sup.record("8.8.8.3", now=1100.0)
    assert set(sup._last) == {"8.8.8.3"}


# --------------------------------------------------------------------------- #
# Reporter: cooldown / backoff / dry-run  (no network)
# --------------------------------------------------------------------------- #
def test_reporter_dry_run_sends_nothing():
    r = mod.Reporter(api_key="", timeout=1.0, dry_run=True)
    ok, detail = r.report("8.8.8.8", [21], "c", "2026-01-01T00:00:00+00:00", now=0.0)
    assert ok
    assert detail.startswith("dry-run ")
    payload = json.loads(detail[len("dry-run "):])
    assert payload["ip"] == "8.8.8.8"
    assert payload["categories"] == "21"
    assert payload["timestamp"] == "2026-01-01T00:00:00+00:00"
    assert r.in_cooldown(now=0.0) == 0.0


def test_reporter_backoff_grows_and_resets():
    r = mod.Reporter(api_key="k", timeout=1.0, dry_run=False)
    r._note_failure(now=0.0, retry_after=None)
    first = r.in_cooldown(now=0.0)
    assert first == mod.Reporter.BACKOFF_BASE           # 5s

    r._note_failure(now=0.0, retry_after=None)
    second = r.in_cooldown(now=0.0)
    assert second == mod.Reporter.BACKOFF_BASE * 2       # 10s

    # capped
    for _ in range(20):
        r._note_failure(now=0.0, retry_after=None)
    assert r.in_cooldown(now=0.0) == mod.Reporter.BACKOFF_MAX

    r._note_success()
    assert r.in_cooldown(now=0.0) == 0.0
    # streak reset -> next failure is base again
    r._note_failure(now=0.0, retry_after=None)
    assert r.in_cooldown(now=0.0) == mod.Reporter.BACKOFF_BASE


def test_reporter_retry_after_honoured():
    r = mod.Reporter(api_key="k", timeout=1.0, dry_run=False)
    r._note_failure(now=100.0, retry_after=42.0)
    assert r.in_cooldown(now=100.0) == 42.0
    assert r.in_cooldown(now=100.0 + 42.0) == 0.0


def test_reporter_http_error_sets_cooldown(monkeypatch):
    import urllib.error

    def boom(req, timeout):
        raise urllib.error.HTTPError(mod.API_URL, 429, "Too Many", {"Retry-After": "30"},
                                     _FakeBody(b'{"errors":[]}'))

    monkeypatch.setattr(mod.urllib.request, "urlopen", boom)
    r = mod.Reporter(api_key="k", timeout=1.0, dry_run=False)
    ok, detail = r.report("8.8.8.8", [21], "c", "", now=0.0)
    assert not ok
    assert "HTTP 429" in detail
    assert r.in_cooldown(now=0.0) == 30.0


def test_reporter_network_error_sets_cooldown(monkeypatch):
    import urllib.error

    def boom(req, timeout):
        raise urllib.error.URLError("unreachable")

    monkeypatch.setattr(mod.urllib.request, "urlopen", boom)
    r = mod.Reporter(api_key="k", timeout=1.0, dry_run=False)
    ok, detail = r.report("8.8.8.8", [21], "c", "", now=0.0)
    assert not ok
    assert "network:" in detail
    assert r.in_cooldown(now=0.0) == mod.Reporter.BACKOFF_BASE


def test_reporter_success_clears_cooldown(monkeypatch):
    def okresp(req, timeout):
        return _FakeResp(b'{"data":{"abuseConfidenceScore":42}}')

    r = mod.Reporter(api_key="k", timeout=1.0, dry_run=False)
    r._note_failure(now=0.0, retry_after=None)          # arm a cooldown
    monkeypatch.setattr(mod.urllib.request, "urlopen", okresp)
    ok, detail = r.report("8.8.8.8", [21], "c", "", now=0.0)
    assert ok
    assert "abuseConfidenceScore" in detail
    assert r.in_cooldown(now=0.0) == 0.0


# --------------------------------------------------------------------------- #
# offset persistence
# --------------------------------------------------------------------------- #
def test_offset_roundtrip(tmp_path):
    state = str(tmp_path / "offset.json")
    log = str(tmp_path / "shield.json")
    Path(log).write_text("")

    assert mod.load_offset(state, log) == (0, -1)       # nothing saved yet
    mod.save_offset(state, log, offset=1234, inode=99)
    assert mod.load_offset(state, log) == (1234, 99)


def test_offset_ignores_different_logpath(tmp_path):
    state = str(tmp_path / "offset.json")
    mod.save_offset(state, str(tmp_path / "a.json"), offset=500, inode=7)
    # a different logfile -> must NOT resume at the stale offset
    assert mod.load_offset(state, str(tmp_path / "b.json")) == (0, -1)


def test_offset_corrupt_state(tmp_path):
    state = tmp_path / "offset.json"
    state.write_text("garbage{")
    assert mod.load_offset(str(state), "whatever.json") == (0, -1)


# --------------------------------------------------------------------------- #
# process_line: the integration point of parse + suppress + report
# --------------------------------------------------------------------------- #
def _dry_reporter():
    return mod.Reporter(api_key="", timeout=1.0, dry_run=True)


def test_process_line_reports_and_records():
    sup = mod.Suppressor(window_s=900, daily_cap=1000)
    r = _dry_reporter()
    logs = []
    entry = json.dumps({"ip": "8.8.8.8", "cat": "sqli", "src": "uri",
                        "req": "GET /x?p=1 HTTP/1.1", "ts": "2026-01-01T00:00:00+00:00"})
    done = mod.process_line(entry, sup, r, now=1000.0, log=logs.append)
    assert done is True
    # recorded -> a repeat is now deduped
    ok, why = sup.allow("8.8.8.8", now=1000.0)
    assert not ok and why == "deduped"
    assert any("reported 8.8.8.8" in m for m in logs)


def test_process_line_skips_private_ip():
    sup = mod.Suppressor(window_s=900, daily_cap=1000)
    r = _dry_reporter()
    entry = json.dumps({"ip": "10.0.0.5", "cat": "sqli", "req": "GET /x"})
    done = mod.process_line(entry, sup, r, now=1000.0, log=lambda m: None)
    assert done is True
    assert sup._count == 0          # never recorded


def test_process_line_malformed_json_dropped():
    sup = mod.Suppressor(window_s=900, daily_cap=1000)
    r = _dry_reporter()
    logs = []
    done = mod.process_line("{ not json", sup, r, now=1000.0, log=logs.append)
    assert done is True             # dropped, not retried
    assert any("malformed JSON" in m for m in logs)


def test_process_line_blank_line_ok():
    sup = mod.Suppressor(window_s=900, daily_cap=1000)
    r = _dry_reporter()
    assert mod.process_line("   ", sup, r, now=1000.0, log=lambda m: None) is True


def test_process_line_deduped_not_retried():
    sup = mod.Suppressor(window_s=900, daily_cap=1000)
    sup.record("8.8.8.8", now=1000.0)
    r = _dry_reporter()
    entry = json.dumps({"ip": "8.8.8.8", "cat": "xss", "req": "GET /x"})
    done = mod.process_line(entry, sup, r, now=1000.0 + 10, log=lambda m: None)
    assert done is True             # deduped -> dropped, offset advances


def test_process_line_send_failure_retried(monkeypatch):
    import urllib.error
    sup = mod.Suppressor(window_s=900, daily_cap=1000)
    r = mod.Reporter(api_key="k", timeout=1.0, dry_run=False)

    def boom(req, timeout):
        raise urllib.error.URLError("down")

    monkeypatch.setattr(mod.urllib.request, "urlopen", boom)
    logs = []
    entry = json.dumps({"ip": "8.8.8.8", "cat": "sqli", "req": "GET /x"})
    done = mod.process_line(entry, sup, r, now=1000.0, log=logs.append)
    assert done is False            # must be retried -> offset kept
    assert sup._count == 0          # NOT recorded (at-least-once delivery)
    assert any("FAILED" in m for m in logs)


# --------------------------------------------------------------------------- #
# tiny fakes for the urlopen monkeypatches
# --------------------------------------------------------------------------- #
class _FakeResp:
    def __init__(self, body: bytes):
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return self._body


class _FakeBody:
    """Minimal fp for HTTPError (its .read() is called)."""

    def __init__(self, body: bytes):
        self._body = body

    def read(self):
        return self._body

    def close(self):
        pass


# --------------------------------------------------------------------------- #
# _handle_stop
# --------------------------------------------------------------------------- #
def test_handle_stop_sets_flag():
    mod._stop = False
    try:
        mod._handle_stop(15, None)
        assert mod._stop is True
    finally:
        mod._stop = False


# --------------------------------------------------------------------------- #
# follow()  -- the tail loop. Driven for a bounded number of iterations by a
# fake time.sleep that flips _stop, so the `while not _stop` loop terminates.
# No real sleeping, no network.
# --------------------------------------------------------------------------- #
def _mk_args(tmp_path, **over):
    import argparse
    a = argparse.Namespace(
        logfile=str(tmp_path / "shield.log"),
        state=str(tmp_path / "offset.json"),
        poll=0.01,
        dedup_window=900,
        daily_cap=1000,
        timeout=1.0,
        dry_run=True,
    )
    for k, v in over.items():
        setattr(a, k, v)
    return a


def _stopping_sleep(monkeypatch, after=1):
    """Patch mod.time.sleep so the follow() loop runs `after` iterations then stops."""
    calls = {"n": 0}

    def fake_sleep(_):
        calls["n"] += 1
        if calls["n"] >= after:
            mod._stop = True

    monkeypatch.setattr(mod.time, "sleep", fake_sleep)
    return calls


def _run_follow(args, monkeypatch):
    mod._stop = False
    logs = []
    rep = mod.Reporter(api_key="k", timeout=1.0, dry_run=True)
    sup = mod.Suppressor(900, 1000, str(args.state) + ".sup")
    try:
        mod.follow(args, rep, sup, logs.append)
    finally:
        mod._stop = False
    return logs


def test_follow_missing_logfile_waits_then_stops(tmp_path, monkeypatch):
    # logfile does not exist -> FileNotFoundError branch sleeps; we stop it.
    args = _mk_args(tmp_path)
    _stopping_sleep(monkeypatch, after=1)
    logs = _run_follow(args, monkeypatch)
    assert any("stopped" in m for m in logs)


def test_follow_processes_a_line(tmp_path, monkeypatch):
    args = _mk_args(tmp_path)
    entry = {"ts": "2026-07-17T00:00:00Z", "ip": "8.8.8.8",
             "cat": "sqli", "src": "uri",
             "req": "GET /x HTTP/1.1", "mode": "block", "status": 403}
    Path(args.logfile).write_text(json.dumps(entry) + "\n")
    # one readline processes the line, next readline hits EOF -> sleep -> stop
    _stopping_sleep(monkeypatch, after=1)
    logs = _run_follow(args, monkeypatch)
    assert any("reported 8.8.8.8" in m or "dry-run" in m for m in logs)
    # offset advanced past the consumed line and was persisted
    off, _ = mod.load_offset(args.state, args.logfile)
    assert off > 0


def test_follow_rewinds_on_failed_send(tmp_path, monkeypatch):
    args = _mk_args(tmp_path, dry_run=False)
    entry = {"ts": "2026-07-17T00:00:00Z", "ip": "8.8.8.8",
             "cat": "sqli", "src": "uri",
             "req": "GET /x HTTP/1.1", "mode": "block", "status": 403}
    Path(args.logfile).write_text(json.dumps(entry) + "\n")
    mod._stop = False
    logs = []
    rep = mod.Reporter(api_key="k", timeout=1.0, dry_run=False)
    # force report() to fail -> process_line returns False -> follow rewinds
    monkeypatch.setattr(rep, "report",
                        lambda *a, **k: (False, "boom"))
    sup = mod.Suppressor(900, 1000, str(args.state) + ".sup")
    _stopping_sleep(monkeypatch, after=1)
    try:
        mod.follow(args, rep, sup, logs.append)
    finally:
        mod._stop = False
    # line was NOT consumed: offset stays at 0 (rewound)
    off, _ = mod.load_offset(args.state, args.logfile)
    assert off == 0


def test_follow_respects_cooldown(tmp_path, monkeypatch):
    args = _mk_args(tmp_path, dry_run=True)
    Path(args.logfile).write_text("")   # empty, but open succeeds
    mod._stop = False
    logs = []
    rep = mod.Reporter(api_key="k", timeout=1.0, dry_run=True)
    # pretend we're in a cooldown so the in_cooldown>0 branch is taken
    monkeypatch.setattr(rep, "in_cooldown", lambda now: 5.0)
    sup = mod.Suppressor(900, 1000, str(args.state) + ".sup")
    _stopping_sleep(monkeypatch, after=1)
    try:
        mod.follow(args, rep, sup, logs.append)
    finally:
        mod._stop = False
    assert any("opened" in m for m in logs)


# --------------------------------------------------------------------------- #
# main()
# --------------------------------------------------------------------------- #
def test_main_requires_api_key_when_not_dry_run(tmp_path, monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    rc = mod.main([str(tmp_path / "shield.log"),
                   "--state", str(tmp_path / "st" / "offset.json")])
    assert rc == 2


def test_main_dry_run_runs_and_returns_zero(tmp_path, monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    logfile = tmp_path / "shield.log"
    logfile.write_text("")
    _stopping_sleep(monkeypatch, after=1)
    mod._stop = False
    try:
        rc = mod.main([str(logfile),
                       "--state", str(tmp_path / "st" / "offset.json"),
                       "--dry-run", "--poll", "0.01"])
    finally:
        mod._stop = False
    assert rc == 0


def test_suppressor_save_swallows_oserror(tmp_path, monkeypatch):
    # _save must never raise: a broken state path is logged-nowhere, not fatal.
    sup = mod.Suppressor(900, 1000, str(tmp_path / "sup.json"))

    def boom(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(mod, "open", boom, raising=False)
    monkeypatch.setattr(os, "replace", boom)
    sup.record("8.8.8.8", now=0.0)   # triggers _save internally, must not raise


def test_follow_resumes_from_saved_offset(tmp_path, monkeypatch):
    args = _mk_args(tmp_path)
    logfile = Path(args.logfile)
    logfile.write_text("line-one-already-consumed\n")
    inode = os.stat(logfile).st_ino
    # persist an offset at EOF for THIS inode -> follow() takes the resume branch
    mod.save_offset(args.state, args.logfile, logfile.stat().st_size, inode)
    _stopping_sleep(monkeypatch, after=1)
    logs = _run_follow(args, monkeypatch)
    assert any(f"at offset={logfile.stat().st_size}" in m for m in logs)


def test_follow_detects_rotation(tmp_path, monkeypatch):
    args = _mk_args(tmp_path)
    logfile = Path(args.logfile)
    logfile.write_text("")   # empty: open ok, first readline is EOF

    mod._stop = False
    logs = []
    rep = mod.Reporter(api_key="k", timeout=1.0, dry_run=True)
    sup = mod.Suppressor(900, 1000, str(args.state) + ".sup")

    real_stat = os.stat
    calls = {"n": 0}

    def fake_stat(p, *a, **k):
        st = real_stat(p, *a, **k)
        # On the EOF rotation check, report a different inode to force reopen.
        if str(p) == args.logfile:
            calls["n"] += 1
            if calls["n"] == 1:
                class S:
                    st_ino = st.st_ino + 12345
                    st_size = st.st_size
                    st_mode = st.st_mode
                return S()
        return st

    monkeypatch.setattr(os, "stat", fake_stat)
    _stopping_sleep(monkeypatch, after=1)
    try:
        mod.follow(args, rep, sup, logs.append)
    finally:
        mod._stop = False
        monkeypatch.setattr(os, "stat", real_stat)
    assert any("rotation/truncation detected" in m for m in logs)
