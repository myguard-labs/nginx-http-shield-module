#!/usr/bin/env python3
"""Unit tests for reporter/abuseipdb-reporter.py.

The module has a hyphenated filename (not importable by name), so it is loaded
via importlib. No network is touched: Reporter is exercised in dry-run mode or
with its urlopen call monkeypatched, and time is passed in explicitly (the code
takes `now` as a parameter everywhere), so the tests are deterministic.
"""

from __future__ import annotations

import datetime as dt
import importlib.util
import json
import os
import stat
from pathlib import Path

import pytest

_HERE = Path(__file__).resolve().parent
_SRC = _HERE / "abuseipdb-reporter.py"

spec = importlib.util.spec_from_file_location("shield_reporter", _SRC)
if spec is None or spec.loader is None:
    raise RuntimeError("cannot load reporter module")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


# Fixture-only admission for existing transport tests. Production registry stays
# empty; ci/tests/test_reporter_verdicts.py tests the actual promotion boundary.
FIXTURE_EVIDENCE = {
    "mode": "block",
    "action": "block",
    "verdict": "exploit",
    "ruleset": "1111111111111111",
    "rule": "2222222222222222",
    "rev": 1,
    "ts": "2026-01-01T00:00:00+00:00",
}


@pytest.fixture(autouse=True)
def admit_transport_fixture(monkeypatch):
    monkeypatch.setattr(
        mod,
        "PROMOTED_RULES",
        frozenset(
            {
                ("1111111111111111", "2222222222222222", 1, "sqli"),
                ("1111111111111111", "2222222222222222", 1, "xss"),
            }
        ),
    )


# --------------------------------------------------------------------------- #
# is_reportable_ip
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "ip,expected",
    [
        ("8.8.8.8", True),
        ("1.2.3.4", True),
        ("2606:4700:4700::1111", True),
        ("10.0.0.1", False),  # RFC1918
        ("192.168.1.1", False),  # RFC1918
        ("172.16.5.5", False),  # RFC1918
        ("127.0.0.1", False),  # loopback
        ("169.254.0.1", False),  # link-local
        ("::1", False),  # loopback v6
        ("fe80::1", False),  # link-local v6
        ("fd00::1", False),  # ULA (private v6)
        ("0.0.0.0", False),  # unspecified
        ("224.0.0.1", False),  # multicast
        ("not-an-ip", False),  # garbage
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


def test_sanitize_req_keeps_only_first_segment():
    # Deeper path segments carry PII (reset tokens, e-mails, tenant IDs) and
    # must be dropped; only the first segment (the attack-pattern signal) stays.
    assert mod.sanitize_req("GET /reset/TOKEN-abc123 HTTP/1.1") == "GET /reset"
    assert mod.sanitize_req("GET /u/12345/profile HTTP/1.1") == "GET /u"
    assert mod.sanitize_req("POST /wp-login.php HTTP/1.1") == "POST /wp-login.php"
    assert mod.sanitize_req("GET /.env HTTP/1.1") == "GET /.env"
    assert mod.sanitize_req("GET / HTTP/1.1") == "GET /"


def test_sanitize_req_first_segment_hides_pii():
    out = mod.sanitize_req("GET /account/user@example.com/reset/deadbeef HTTP/1.1")
    assert out == "GET /account"
    assert "@" not in out
    assert "deadbeef" not in out


def test_sanitize_req_absolute_form_drops_internal_host():
    # absolute-form request line leaks the internal host in the authority.
    out = mod.sanitize_req("GET http://internal.corp:8080/admin/secret HTTP/1.1")
    assert out == "GET /admin"
    assert "internal.corp" not in out


def test_sanitize_req_authority_form_drops_internal_host():
    # authority-form (CONNECT) has no scheme and no leading "/", so the target
    # IS the internal host -- it must never reach AbuseIPDB.
    out = mod.sanitize_req("CONNECT internal.corp:443 HTTP/1.1")
    assert out == "CONNECT"
    assert "internal.corp" not in out

    out = mod.sanitize_req("CONNECT 10.0.0.5:22 HTTP/1.1")
    assert out == "CONNECT"
    assert "10.0.0.5" not in out


def test_sanitize_req_asterisk_form():
    assert mod.sanitize_req("OPTIONS * HTTP/1.1") == "OPTIONS"


def test_sanitize_req_length_caps():
    long_seg = "/" + "a" * 5000
    out = mod.sanitize_req("GET " + long_seg + "?x=1")
    _method, path = out.split(" ", 1)
    assert len(path) <= 128


# --------------------------------------------------------------------------- #
# build_comment
# --------------------------------------------------------------------------- #
def test_build_comment_shape_and_no_query_leak():
    entry = {
        **FIXTURE_EVIDENCE,
        "cat": "sqli",
        "src": "uri",
        "req": "GET /x?password=hunter2 HTTP/1.1",
        "ip": "8.8.8.8",
    }
    c = mod.build_comment(entry)
    assert c == "nginx-http-shield: promoted block-mode exploit evidence"
    assert "hunter2" not in c
    assert len(c) <= mod.COMMENT_MAX


def test_build_comment_missing_fields():
    c = mod.build_comment({})
    assert c == "nginx-http-shield: promoted block-mode exploit evidence"


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

    ok, why = sup.allow("8.8.8.8", now=1000.0 + 899)  # inside window
    assert not ok and why == "deduped"

    ok, _ = sup.allow("8.8.8.8", now=1000.0 + 901)  # past window
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
        now += 10  # past the 1s window so dedup doesn't interfere
    ok, why = sup.allow("8.8.8.9", now)
    assert not ok and why == "daily-cap"


def test_suppressor_day_roll_resets_count():
    sup = mod.Suppressor(window_s=1, daily_cap=1)
    # day 0
    day0 = 0.0  # 1970-01-01 UTC
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
    sup, path = _reservation_suppressor(tmp_path)
    state = str(path)
    sup.allow("8.8.8.8", now=1000.0)  # sets _day (real call order)
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
    sup, path = _reservation_suppressor(tmp_path)
    state = str(path)
    sup.record("8.8.8.8", now=1000.0)  # no allow() first
    assert sup._day == "1970-01-01"  # now=1000.0 -> that UTC day, stamped

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


def _reservation_suppressor(tmp_path, *, window=900, cap=1000):
    state = tmp_path / "reservation.json"
    state.write_text(json.dumps({"day": None, "count": 0, "last": {}}))
    return mod.Suppressor(window, cap, str(state)), state


def test_suppressor_reservation_persists_before_permission(tmp_path, monkeypatch):
    sup, state = _reservation_suppressor(tmp_path)
    replacements = []
    replace = mod.os.replace

    def observed_replace(src, dst):
        assert json.loads(state.read_text()) == {"day": None, "count": 0, "last": {}}
        prepared = json.loads(Path(src).read_text())
        assert prepared["pending"] == [
            {
                "day": "1970-01-01",
                "ip": "8.8.8.8",
                "started_at": 1000.0,
                "window_s": 900,
            }
        ]
        assert prepared["count"] == 0 and prepared["last"] == {}
        replacements.append((src, dst))
        replace(src, dst)

    monkeypatch.setattr(mod.os, "replace", observed_replace)
    assert sup.reserve("8.8.8.8", 1000.0) == (True, "")
    assert len(replacements) == 1
    persisted = json.loads(state.read_text())
    assert persisted["version"] == 2
    assert persisted["pending"] == sup._pending
    assert sup._count == 0 and sup._last == {}


def test_suppressor_reservation_syncs_file_and_parent_before_permission(
    tmp_path, monkeypatch
):
    sup, _state = _reservation_suppressor(tmp_path)
    events = []
    fsync = mod.os.fsync
    replace = mod.os.replace

    def observed_fsync(fd):
        events.append(
            "directory-sync" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file-sync"
        )
        fsync(fd)

    def observed_replace(src, dst):
        events.append("replace")
        replace(src, dst)

    monkeypatch.setattr(mod.os, "fsync", observed_fsync)
    monkeypatch.setattr(mod.os, "replace", observed_replace)
    assert sup.reserve("8.8.8.8", 1000.0) == (True, "")
    assert events == ["file-sync", "replace", "directory-sync"]


def test_suppressor_reservation_fsync_failure_denies_permission(tmp_path, monkeypatch):
    sup, state = _reservation_suppressor(tmp_path)
    before = state.read_bytes()
    monkeypatch.setattr(mod.os, "fsync", lambda _fd: _boom())
    assert sup.reserve("8.8.8.8", 1000.0) == (False, "state-persistence")
    assert sup._pending == []
    assert state.read_bytes() == before


def test_suppressor_reservation_roundtrip_and_legacy_save(tmp_path):
    sup, state = _reservation_suppressor(tmp_path)
    sup.record("9.9.9.9", 999)
    assert sup.reserve("8.8.8.8", 1000) == (True, "")
    pending = list(sup._pending)
    sup.record("1.1.1.1", 1001)  # legacy save must retain every unresolved intent
    resumed = mod.Suppressor(900, 1000, str(state))
    assert resumed._state_valid
    assert resumed._pending == pending
    assert resumed._count == 2
    assert resumed._last == {"9.9.9.9": 999, "1.1.1.1": 1001}
    assert resumed.reserve("8.8.8.8", 1002) == (False, "deduped")
    assert resumed._count == 2


def test_suppressor_reservation_migrates_legacy_ipv6_aliases(tmp_path):
    state = tmp_path / "reservation.json"
    state.write_text(
        json.dumps(
            {
                "day": "1970-01-01",
                "count": 2,
                "last": {
                    "2606:4700:4700:0:0:0:0:1111": 999,
                    "2606:4700:4700::1111": 1000,
                },
            }
        )
    )
    sup = mod.Suppressor(900, 1000, str(state))
    assert sup._state_valid
    assert sup._last == {"2606:4700:4700::1111": 1000.0}
    assert sup.reserve("2606:4700:4700:0:0:0:0:1111", 1001) == (
        False,
        "deduped",
    )
    assert sup.reserve("9.9.9.9", 1001) == (True, "")
    persisted = json.loads(state.read_text())
    assert persisted["version"] == 2
    assert persisted["last"] == {"2606:4700:4700::1111": 1000.0}


@pytest.mark.parametrize("ip", ["bad", "fe80::1%eth0"])
def test_suppressor_reservation_rejects_invalid_legacy_ip(tmp_path, ip):
    state = tmp_path / "reservation.json"
    original = json.dumps({"day": "1970-01-01", "count": 1, "last": {ip: 1000}})
    state.write_text(original)
    sup = mod.Suppressor(900, 1000, str(state))
    assert not sup._state_valid
    assert sup.reserve("9.9.9.9", 1001) == (False, "state-unavailable")
    assert state.read_text() == original


def test_suppressor_reservation_daily_cap_includes_expired_pending(tmp_path):
    sup, state = _reservation_suppressor(tmp_path, window=1, cap=2)
    sup.record("1.1.1.1", 999)
    assert sup.reserve("8.8.8.8", 1000) == (True, "")
    assert sup.reserve("9.9.9.9", 1002) == (False, "daily-cap")
    assert sup._count == 1  # a pending attempt never becomes a confirmation
    resumed = mod.Suppressor(1, 2, str(state))
    assert resumed.reserve("9.9.9.9", 1002) == (False, "daily-cap")
    assert len(resumed._pending) == 1


def test_suppressor_reservation_midnight_original_window_and_exact_expiry(tmp_path):
    sup, state = _reservation_suppressor(tmp_path, cap=1)
    assert sup.reserve("8.8.8.8", 86340) == (True, "")
    assert sup.reserve("9.9.9.9", 86341) == (False, "daily-cap")
    resumed = mod.Suppressor(
        1, 1, str(state)
    )  # reducing config cannot shrink an intent
    assert resumed.reserve("8.8.8.8", 86400) == (False, "deduped")
    assert resumed._count == 0
    assert resumed.reserve("8.8.8.8", 87239) == (False, "deduped")
    assert resumed.reserve("8.8.8.8", 87240) == (True, "")
    assert resumed._pending == [
        {
            "day": "1970-01-02",
            "ip": "8.8.8.8",
            "started_at": 87240.0,
            "window_s": 1,
        }
    ]
    assert resumed._count == 0 and resumed._last == {}
    reloaded = mod.Suppressor(1, 1, str(state))
    assert reloaded.reserve("9.9.9.9", 87242) == (False, "daily-cap")


def test_suppressor_reservation_midnight_other_ip_retains_unexpired_intent(tmp_path):
    sup, state = _reservation_suppressor(tmp_path, cap=1)
    assert sup.reserve("8.8.8.8", 86340) == (True, "")
    assert sup.reserve("9.9.9.9", 86400) == (True, "")
    assert len(sup._pending) == 2
    resumed = mod.Suppressor(900, 2, str(state))
    assert resumed.reserve("8.8.8.8", 86401) == (False, "deduped")
    assert resumed._count == 0


def test_suppressor_reservation_schema_empty_registry_zero_sends(tmp_path, monkeypatch):
    sup, state = _reservation_suppressor(tmp_path)
    before = state.read_bytes()
    reporter = mod.Reporter(api_key="", timeout=1, dry_run=False)
    sends = []

    def transport(*a, **kw):
        sends.append(a)
        pytest.fail("empty registry reached transport")

    monkeypatch.setattr(mod, "PROMOTED_RULES", frozenset())
    monkeypatch.setattr(reporter, "report", transport)
    entry = {**FIXTURE_EVIDENCE, "ip": "8.8.8.8", "cat": "sqli"}
    logs = []
    assert mod.process_line(json.dumps(entry), sup, reporter, 1000, logs.append)
    assert sends == [] and sup._pending == [] and sup._count == 0
    assert state.read_bytes() == before


def test_suppressor_reservation_canonical_ipv6(tmp_path):
    sup, state = _reservation_suppressor(tmp_path)
    assert sup.reserve("2606:4700:4700:0:0:0:0:1111", 1000) == (True, "")
    assert json.loads(state.read_text())["pending"][0]["ip"] == "2606:4700:4700::1111"
    assert sup.reserve("2606:4700:4700::1111", 1001) == (False, "deduped")


@pytest.mark.parametrize("stage", ["open", "write", "close", "replace", "serialize"])
def test_suppressor_reservation_persistence_failure_forbids_send(
    tmp_path, monkeypatch, stage
):
    sup, state = _reservation_suppressor(tmp_path)
    assert sup.reserve("9.9.9.9", 999) == (True, "")
    before = state.read_bytes()
    pending = list(sup._pending)
    real_open = open

    def fail(*a, **kw):
        raise OSError("injected persistence failure")

    class BrokenWriter:
        def __init__(self, *a, **kw):
            self.handle = real_open(*a, **kw)

        def __enter__(self):
            return self

        def write(self, raw):
            if stage == "write":
                fail()
            return self.handle.write(raw)

        def __exit__(self, *a):
            self.handle.close()
            if stage == "close":
                fail()

    if stage == "open":
        monkeypatch.setattr(mod, "open", fail, raising=False)
    elif stage in ("write", "close"):
        monkeypatch.setattr(mod, "open", BrokenWriter, raising=False)
    elif stage == "replace":
        monkeypatch.setattr(mod.os, "replace", fail)
    else:

        def bad_json(*a, **kw):
            raise ValueError("injected serialization failure")

        monkeypatch.setattr(mod.json, "dumps", bad_json)
    sends = []
    permission, reason = sup.reserve("8.8.8.8", 1000)
    if permission:
        sends.append("mock transport")
    assert (permission, reason) == (False, "state-persistence")
    assert sends == []
    assert state.read_bytes() == before
    assert sup._pending == pending
    assert sup._count == 0 and sup._last == {}


def test_suppressor_reservation_failed_save_can_retry_without_erasing_debit(
    tmp_path, monkeypatch
):
    sup, state = _reservation_suppressor(tmp_path, cap=1)
    replace = mod.os.replace
    monkeypatch.setattr(mod.os, "replace", _boom)
    assert sup.reserve("8.8.8.8", 1000) == (False, "state-persistence")
    monkeypatch.setattr(mod.os, "replace", replace)
    assert sup.reserve("8.8.8.8", 1001) == (True, "")
    assert sup.reserve("9.9.9.9", 1002) == (False, "daily-cap")
    assert len(json.loads(state.read_text())["pending"]) == 1


@pytest.mark.parametrize("kind", ["no-path", "missing", "unreadable"])
def test_suppressor_reservation_requires_existing_valid_state(
    tmp_path, monkeypatch, kind
):
    state = tmp_path / "reservation.json"
    if kind == "unreadable":

        def denied(*a, **kw):
            raise PermissionError("injected state read denial")

        monkeypatch.setattr(mod, "open", denied, raising=False)
    sup = mod.Suppressor(900, 1000, None if kind == "no-path" else str(state))
    assert sup.reserve("8.8.8.8", 1000) == (False, "state-unavailable")
    assert not state.exists()
    assert sup._pending == [] and sup._count == 0


# Each malformed state must refuse reservation as a whole, never silently erase
# a damaged debit and publish the remaining fields as a valid empty state.
@pytest.mark.parametrize(
    "mutation",
    [
        lambda st: [],
        lambda st: {**st, "version": 3},
        lambda st: {**st, "version": True},
        lambda st: {**st, "reservation_ready": 1},
        lambda st: {**st, "reservation_ready": "false"},
        lambda st: {**st, "extra": 0},
        lambda st: {key: value for key, value in st.items() if key != "pending"},
        lambda st: {**st, "day": "1970-1-01"},
        lambda st: {**st, "day": "1970-02-30"},
        lambda st: {**st, "day": None},
        lambda st: {**st, "day": True},
        lambda st: {**st, "count": -1},
        lambda st: {**st, "count": True},
        lambda st: {**st, "count": 1 << 63},
        lambda st: {**st, "last": []},
        lambda st: {**st, "last": {"not-an-ip": 1000}},
        lambda st: {**st, "last": {"8.8.8.8": float("inf")}},
        lambda st: {**st, "pending": {}},
        lambda st: {**st, "pending": [None]},
        lambda st: {**st, "pending": [{**st["pending"][0], "extra": 0}]},
        lambda st: {**st, "pending": [{"ip": "8.8.8.8"}]},
        lambda st: {**st, "pending": [{**st["pending"][0], "ip": "bad"}]},
        lambda st: {**st, "pending": [{**st["pending"][0], "ip": "fe80::1%eth0"}]},
        lambda st: {
            **st,
            "pending": [{**st["pending"][0], "ip": "2606:4700:4700:0:0:0:0:1111"}],
        },
        lambda st: {**st, "pending": [{**st["pending"][0], "day": "1970-01-02"}]},
        lambda st: {**st, "pending": [{**st["pending"][0], "started_at": True}]},
        lambda st: {**st, "pending": [{**st["pending"][0], "started_at": -1}]},
        lambda st: {
            **st,
            "pending": [{**st["pending"][0], "started_at": float("nan")}],
        },
        lambda st: {**st, "pending": [{**st["pending"][0], "started_at": 1e300}]},
        lambda st: {**st, "pending": [{**st["pending"][0], "window_s": 0}]},
        lambda st: {**st, "pending": [{**st["pending"][0], "window_s": True}]},
        lambda st: {**st, "pending": [{**st["pending"][0], "window_s": 1.5}]},
        lambda st: {**st, "pending": [{**st["pending"][0], "window_s": 1 << 63}]},
        lambda st: {**st, "pending": st["pending"] * 2},
    ],
)
def test_suppressor_reservation_malformed_schema_refuses_without_rewrite(
    tmp_path, mutation
):
    state = tmp_path / "reservation.json"
    valid = {
        "version": 2,
        "reservation_ready": True,
        "day": "1970-01-01",
        "count": 1,
        "last": {"9.9.9.9": 999},
        "pending": [
            {
                "day": "1970-01-01",
                "ip": "8.8.8.8",
                "started_at": 1000,
                "window_s": 900,
            }
        ],
    }
    state.write_text(json.dumps(mutation(valid)))
    before = state.read_bytes()
    sup = mod.Suppressor(900, 1000, str(state))
    assert not sup._state_valid
    assert sup._count == 0 and sup._last == {} and sup._pending == []
    assert sup.reserve("1.1.1.1", 1001) == (False, "state-unavailable")
    assert state.read_bytes() == before
    sup.record("1.1.1.1", 1001)  # legacy save cannot bless an invalid load
    assert sup.reserve("8.8.8.8", 1002) == (False, "state-unavailable")
    assert sup._count == 1  # legacy API still updates memory without throwing
    assert state.read_bytes() == before  # never replace unknown durable debt
    resumed = mod.Suppressor(900, 1000, str(state))
    assert resumed._count == 0 and resumed._last == {}
    assert resumed.reserve("8.8.8.8", 1002) == (False, "state-unavailable")


@pytest.mark.parametrize(
    "raw",
    [
        '{"day":null,"count":1,"count":0,"last":{}}',
        '{"day":"1970-01-01","count":1,"last":{"8.8.8.8":1000,"8.8.8.8":0}}',
        "not JSON",
        "[" * 1100 + "]" * 1100,
    ],
)
def test_suppressor_reservation_invalid_json_refuses(tmp_path, raw):
    state = tmp_path / "reservation.json"
    state.write_text(raw)
    sup = mod.Suppressor(900, 1000, str(state))
    assert sup.reserve("8.8.8.8", 1001) == (False, "state-unavailable")
    assert state.read_text() == raw


@pytest.mark.parametrize(
    "ip,now",
    [
        ("bad", 1000),
        ("fe80::1%eth0", 1000),
        ("8.8.8.8", True),
        ("8.8.8.8", -1),
        ("8.8.8.8", float("nan")),
        ("8.8.8.8", float("inf")),
        ("8.8.8.8", 1e300),
    ],
)
def test_suppressor_reservation_invalid_arguments_refuse(tmp_path, ip, now):
    sup, state = _reservation_suppressor(tmp_path)
    before = state.read_bytes()
    assert sup.reserve(ip, now) == (False, "invalid-reservation")
    assert state.read_bytes() == before
    assert sup._pending == [] and sup._count == 0


@pytest.mark.parametrize(
    "field,value",
    [
        ("window_s", 0),
        ("window_s", True),
        ("daily_cap", 0),
        ("daily_cap", True),
    ],
)
def test_suppressor_reservation_invalid_config_refuses(tmp_path, field, value):
    sup, state = _reservation_suppressor(tmp_path)
    setattr(sup, field, value)
    before = state.read_bytes()
    assert sup.reserve("8.8.8.8", 1000) == (False, "invalid-reservation")
    assert state.read_bytes() == before


def test_suppressor_reservation_size_limits_refuse_read_and_write(
    tmp_path, monkeypatch
):
    sup, state = _reservation_suppressor(tmp_path)
    before = state.read_bytes()
    monkeypatch.setattr(mod.Suppressor, "MAX_STATE_CHARS", len(before))
    assert sup.reserve("8.8.8.8", 1000) == (False, "state-persistence")
    assert state.read_bytes() == before and sup._pending == []
    state.write_bytes(before + b" ")
    resumed = mod.Suppressor(900, 1000, str(state))
    assert resumed.reserve("8.8.8.8", 1000) == (False, "state-unavailable")


# --------------------------------------------------------------------------- #
# Reporter: cooldown / backoff / dry-run  (no network)
# --------------------------------------------------------------------------- #
def test_reporter_dry_run_sends_nothing():
    r = mod.Reporter(api_key="", timeout=1.0, dry_run=True)
    outcome, detail = r.report(
        "8.8.8.8", [21], "c", "2026-01-01T00:00:00+00:00", now=0.0
    )
    assert outcome == mod.Reporter.OK
    assert detail.startswith("dry-run ")
    payload = json.loads(detail[len("dry-run ") :])
    assert payload["ip"] == "8.8.8.8"
    assert payload["categories"] == "21"
    assert payload["timestamp"] == "2026-01-01T00:00:00+00:00"
    assert r.in_cooldown(now=0.0) == 0.0


def test_reporter_backoff_grows_and_resets():
    r = mod.Reporter(api_key="k", timeout=1.0, dry_run=False)
    r._note_failure(now=0.0, retry_after=None)
    first = r.in_cooldown(now=0.0)
    assert first == mod.Reporter.BACKOFF_BASE  # 5s

    r._note_failure(now=0.0, retry_after=None)
    second = r.in_cooldown(now=0.0)
    assert second == mod.Reporter.BACKOFF_BASE * 2  # 10s

    # capped
    for _ in range(20):
        r._note_failure(now=0.0, retry_after=None)
    assert r.in_cooldown(now=0.0) == mod.Reporter.BACKOFF_MAX

    r._note_success()
    assert r.in_cooldown(now=0.0) == 0.0
    # streak reset -> next failure is base again
    r._note_failure(now=0.0, retry_after=None)
    assert r.in_cooldown(now=0.0) == mod.Reporter.BACKOFF_BASE


def test_reporter_backoff_no_overflow_on_huge_streak():
    # A very long fail streak must not raise OverflowError computing 2**exp;
    # the exponent is capped and the delay stays clamped at BACKOFF_MAX.
    r = mod.Reporter(api_key="k", timeout=1.0, dry_run=False)
    r._fail_streak = 100000
    r._note_failure(now=0.0, retry_after=None)
    assert r.in_cooldown(now=0.0) == mod.Reporter.BACKOFF_MAX


def test_reporter_retry_after_honoured():
    r = mod.Reporter(api_key="k", timeout=1.0, dry_run=False)
    r._note_failure(now=100.0, retry_after=42.0)
    assert r.in_cooldown(now=100.0) == 42.0
    assert r.in_cooldown(now=100.0 + 42.0) == 0.0


def test_reporter_retry_after_is_clamped():
    """A hostile/buggy Retry-After must not park the reporter for years."""
    r = mod.Reporter(api_key="k", timeout=1.0, dry_run=False)
    r._note_failure(now=0.0, retry_after=99999999.0)
    assert r.in_cooldown(now=0.0) == mod.Reporter.RETRY_AFTER_MAX


def test_reporter_retry_after_negative_is_floored():
    r = mod.Reporter(api_key="k", timeout=1.0, dry_run=False)
    r._note_failure(now=0.0, retry_after=-5.0)
    assert r.in_cooldown(now=0.0) == 0.0


def test_parse_retry_after_delta_seconds():
    assert mod._parse_retry_after("120", now=0.0) == 120.0
    assert mod._parse_retry_after("  120  ", now=0.0) == 120.0


def test_parse_retry_after_http_date():
    # 60s in the future relative to the supplied `now`.
    when = "Wed, 21 Oct 2015 07:29:00 GMT"
    now = dt.datetime(2015, 10, 21, 7, 28, 0, tzinfo=dt.UTC).timestamp()
    assert mod._parse_retry_after(when, now=now) == 60.0


def test_parse_retry_after_past_http_date_is_zero():
    when = "Wed, 21 Oct 2015 07:00:00 GMT"
    now = dt.datetime(2015, 10, 21, 7, 28, 0, tzinfo=dt.UTC).timestamp()
    assert mod._parse_retry_after(when, now=now) == 0.0


def test_parse_retry_after_unparsable_is_none():
    for bad in (None, "", "   ", "soon", "-30", "12.5", "Wed, 99 Xxx 9999"):
        assert mod._parse_retry_after(bad, now=0.0) is None


def test_parse_retry_after_unicode_digits_are_none_not_crash():
    """str.isdigit() accepts these; float() would raise outside the guard (F2).

    A hostile/buggy Retry-After must degrade to None (fall back to backoff),
    never propagate a ValueError that restart-loops the daemon.
    """
    for bad in ("²", "②", "½", "１２３"):
        assert mod._parse_retry_after(bad, now=0.0) is None


def test_reporter_429_unicode_retry_after_does_not_crash(monkeypatch):
    """Full 429 path with a Unicode-digit Retry-After: RETRY, not a crash (F2)."""
    import urllib.error

    def boom(req, timeout):
        raise urllib.error.HTTPError(
            mod.API_URL,
            429,
            "Too Many",
            {"Retry-After": "²"},
            _FakeBody(b'{"errors":[]}'),
        )

    monkeypatch.setattr(mod._OPENER, "open", boom)
    r = mod.Reporter(api_key="k", timeout=1.0, dry_run=False)
    outcome, _ = r.report("8.8.8.8", [21], "c", "", now=0.0)
    assert outcome == mod.Reporter.RETRY
    # Unparsable Retry-After -> exponential backoff base, not a stall/crash.
    assert r.in_cooldown(now=0.0) == mod.Reporter.BACKOFF_BASE


def test_noredirect_refuses_every_3xx():
    """The credential-bearing opener must not follow any redirect (F1).

    redirect_request returning None makes urllib raise the 3xx as an HTTPError
    instead of re-issuing the request (with the Key header) to the target.
    """
    h = mod._NoRedirect()
    req = mod.urllib.request.Request(mod.API_URL, method="POST")
    for code in (301, 302, 303, 307, 308):
        assert (
            h.redirect_request(
                req,
                _FakeBody(b""),
                code,
                "redir",
                {"Location": "https://evil.example/"},
                "https://evil.example/",
            )
            is None
        )


def test_reporter_redirect_is_dropped_key_not_resent(monkeypatch):
    """A 3xx surfaces as a permanent DROP; no success is recorded (F1).

    The real _OPENER raises HTTPError on a refused redirect, so report() lands
    in the permanent branch: DROP, advance, and crucially no _note_success().
    """
    import urllib.error

    def redir(req, timeout):
        # Assert the credential is present on the request the opener refused --
        # proving the guard fires BEFORE any redirect target could receive it.
        assert req.get_header("Key") == "k"
        raise urllib.error.HTTPError(
            mod.API_URL,
            302,
            "Found",
            {"Location": "https://evil.example/"},
            _FakeBody(b""),
        )

    monkeypatch.setattr(mod._OPENER, "open", redir)
    r = mod.Reporter(api_key="k", timeout=1.0, dry_run=False)
    outcome, _ = r.report("8.8.8.8", [21], "c", "", now=0.0)
    assert outcome == mod.Reporter.DROP
    assert r.in_cooldown(now=0.0) == 0.0  # DROP sets no cooldown


def test_reporter_429_http_date_retry_after(monkeypatch):
    """The HTTP-date form is honoured, not silently downgraded to backoff."""
    import urllib.error

    now = dt.datetime(2015, 10, 21, 7, 28, 0, tzinfo=dt.UTC).timestamp()

    def boom(req, timeout):
        raise urllib.error.HTTPError(
            mod.API_URL,
            429,
            "Too Many",
            {"Retry-After": "Wed, 21 Oct 2015 07:29:00 GMT"},
            _FakeBody(b'{"errors":[]}'),
        )

    monkeypatch.setattr(mod._OPENER, "open", boom)
    r = mod.Reporter(api_key="k", timeout=1.0, dry_run=False)
    outcome, _ = r.report("8.8.8.8", [21], "c", "", now=now)
    assert outcome == mod.Reporter.RETRY
    assert r.in_cooldown(now=now) == 60.0


def test_reporter_429_is_retry_with_cooldown(monkeypatch):
    import urllib.error

    def boom(req, timeout):
        raise urllib.error.HTTPError(
            mod.API_URL,
            429,
            "Too Many",
            {"Retry-After": "30"},
            _FakeBody(b'{"errors":[]}'),
        )

    monkeypatch.setattr(mod._OPENER, "open", boom)
    r = mod.Reporter(api_key="k", timeout=1.0, dry_run=False)
    outcome, detail = r.report("8.8.8.8", [21], "c", "", now=0.0)
    assert outcome == mod.Reporter.RETRY
    assert "HTTP 429" in detail
    assert r.in_cooldown(now=0.0) == 30.0


def test_reporter_permanent_4xx_is_dropped(monkeypatch):
    # A 4xx that is not 429 (bad key, malformed, report too old) can never
    # succeed on replay -> DROP, no cooldown, no backoff-streak bump. Otherwise
    # a single poison record would wedge the whole queue forever (S27-3).
    import urllib.error

    for code in (400, 401, 403, 422):

        def boom(req, timeout, _code=code):
            raise urllib.error.HTTPError(
                mod.API_URL, _code, "Bad", {}, _FakeBody(b'{"errors":[]}')
            )

        monkeypatch.setattr(mod._OPENER, "open", boom)
        r = mod.Reporter(api_key="k", timeout=1.0, dry_run=False)
        outcome, detail = r.report("8.8.8.8", [21], "c", "", now=0.0)
        assert outcome == mod.Reporter.DROP, code
        assert f"HTTP {code}" in detail
        assert "permanent" in detail
        # No cooldown and no streak: a bad record must not stall the queue.
        assert r.in_cooldown(now=0.0) == 0.0
        assert r._fail_streak == 0


def test_reporter_3xx_is_dropped(monkeypatch):
    # A non-followed 3xx redirect failure is not transient; only 429 and 5xx
    # retry. Everything else (incl. 3xx) is DROP, no cooldown, no streak bump.
    import urllib.error

    def boom(req, timeout):
        raise urllib.error.HTTPError(mod.API_URL, 302, "Found", {}, _FakeBody(b"{}"))

    monkeypatch.setattr(mod._OPENER, "open", boom)
    r = mod.Reporter(api_key="k", timeout=1.0, dry_run=False)
    outcome, detail = r.report("8.8.8.8", [21], "c", "", now=0.0)
    assert outcome == mod.Reporter.DROP
    assert "HTTP 302" in detail
    assert r.in_cooldown(now=0.0) == 0.0
    assert r._fail_streak == 0


def test_reporter_5xx_is_retry(monkeypatch):
    # Server-side errors are transient -> RETRY with backoff.
    import urllib.error

    def boom(req, timeout):
        raise urllib.error.HTTPError(
            mod.API_URL, 503, "Down", {}, _FakeBody(b'{"errors":[]}')
        )

    monkeypatch.setattr(mod._OPENER, "open", boom)
    r = mod.Reporter(api_key="k", timeout=1.0, dry_run=False)
    outcome, detail = r.report("8.8.8.8", [21], "c", "", now=0.0)
    assert outcome == mod.Reporter.RETRY
    assert "HTTP 503" in detail
    assert r.in_cooldown(now=0.0) == mod.Reporter.BACKOFF_BASE


def test_reporter_network_error_is_retry(monkeypatch):
    import urllib.error

    def boom(req, timeout):
        raise urllib.error.URLError("unreachable")

    monkeypatch.setattr(mod._OPENER, "open", boom)
    r = mod.Reporter(api_key="k", timeout=1.0, dry_run=False)
    outcome, detail = r.report("8.8.8.8", [21], "c", "", now=0.0)
    assert outcome == mod.Reporter.RETRY
    assert "network:" in detail
    assert r.in_cooldown(now=0.0) == mod.Reporter.BACKOFF_BASE


def test_reporter_success_clears_cooldown(monkeypatch):
    def okresp(req, timeout):
        return _FakeResp(b'{"data":{"abuseConfidenceScore":42}}')

    r = mod.Reporter(api_key="k", timeout=1.0, dry_run=False)
    r._note_failure(now=0.0, retry_after=None)  # arm a cooldown
    monkeypatch.setattr(mod._OPENER, "open", okresp)
    outcome, detail = r.report("8.8.8.8", [21], "c", "", now=0.0)
    assert outcome == mod.Reporter.OK
    assert detail == "HTTP success"
    assert r.in_cooldown(now=0.0) == 0.0


# --------------------------------------------------------------------------- #
# offset persistence
# --------------------------------------------------------------------------- #
def test_offset_roundtrip(tmp_path):
    state = str(tmp_path / "offset.json")
    log = str(tmp_path / "shield.json")
    Path(log).write_text("")

    assert mod.load_offset(state, log) == (0, -1)  # nothing saved yet
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
    entry = json.dumps(
        {
            **FIXTURE_EVIDENCE,
            "ip": "8.8.8.8",
            "cat": "sqli",
            "src": "uri",
            "req": "GET /x?p=1 HTTP/1.1",
            "ts": "2026-01-01T00:00:00+00:00",
        }
    )
    done = mod.process_line(entry, sup, r, now=1000.0, log=logs.append)
    assert done is True
    # recorded -> a repeat is now deduped
    ok, why = sup.allow("8.8.8.8", now=1000.0)
    assert not ok and why == "deduped"
    assert any("reported 8.8.8.8" in m for m in logs)


def test_process_line_skips_private_ip():
    sup = mod.Suppressor(window_s=900, daily_cap=1000)
    r = _dry_reporter()
    entry = json.dumps(
        {**FIXTURE_EVIDENCE, "ip": "10.0.0.5", "cat": "sqli", "req": "GET /x"}
    )
    done = mod.process_line(entry, sup, r, now=1000.0, log=lambda m: None)
    assert done is True
    assert sup._count == 0  # never recorded


def test_process_line_malformed_json_dropped():
    sup = mod.Suppressor(window_s=900, daily_cap=1000)
    r = _dry_reporter()
    logs = []
    done = mod.process_line("{ not json", sup, r, now=1000.0, log=logs.append)
    assert done is True  # dropped, not retried
    assert any("malformed JSON" in m for m in logs)


def test_process_line_blank_line_ok():
    sup = mod.Suppressor(window_s=900, daily_cap=1000)
    r = _dry_reporter()
    assert mod.process_line("   ", sup, r, now=1000.0, log=lambda m: None) is True


def test_process_line_deduped_not_retried():
    sup = mod.Suppressor(window_s=900, daily_cap=1000)
    sup.record("8.8.8.8", now=1000.0)
    r = _dry_reporter()
    entry = json.dumps(
        {**FIXTURE_EVIDENCE, "ip": "8.8.8.8", "cat": "xss", "req": "GET /x"}
    )
    done = mod.process_line(entry, sup, r, now=1000.0 + 10, log=lambda m: None)
    assert done is True  # deduped -> dropped, offset advances


def test_process_line_send_failure_retried(tmp_path, monkeypatch):
    import urllib.error

    sup, _ = _reservation_suppressor(tmp_path)
    r = mod.Reporter(api_key="k", timeout=1.0, dry_run=False)

    def boom(req, timeout):
        raise urllib.error.URLError("down")

    monkeypatch.setattr(mod._OPENER, "open", boom)
    logs = []
    entry = json.dumps(
        {**FIXTURE_EVIDENCE, "ip": "8.8.8.8", "cat": "sqli", "req": "GET /x"}
    )
    done = mod.process_line(entry, sup, r, now=1000.0, log=logs.append)
    assert done is False  # must be retried -> offset kept
    assert sup._count == 0  # no confirmation; pending attempt still debits quota
    assert any("FAILED" in m for m in logs)


def test_process_line_permanent_4xx_advances(tmp_path, monkeypatch):
    # A permanent 4xx must advance the offset (return True) so the daemon does
    # not wedge on a poison record -- but must NOT record it as a sent report.
    import urllib.error

    sup, _ = _reservation_suppressor(tmp_path)
    r = mod.Reporter(api_key="k", timeout=1.0, dry_run=False)

    def boom(req, timeout):
        raise urllib.error.HTTPError(
            mod.API_URL, 422, "Unprocessable", {}, _FakeBody(b'{"errors":[]}')
        )

    monkeypatch.setattr(mod._OPENER, "open", boom)
    logs = []
    entry = json.dumps(
        {**FIXTURE_EVIDENCE, "ip": "8.8.8.8", "cat": "sqli", "req": "GET /x"}
    )
    done = mod.process_line(entry, sup, r, now=1000.0, log=logs.append)
    assert done is True  # advance past the poison record
    assert sup._count == 0  # not counted as a real report
    assert r.in_cooldown(now=1000.0) == 0.0  # no queue-wide stall
    assert any("DROP" in m for m in logs)


def _transport_entry(ip="8.8.8.8"):
    return json.dumps({**FIXTURE_EVIDENCE, "ip": ip, "cat": "sqli", "req": "GET /x"})


@pytest.mark.parametrize(
    "ip,canonical",
    [
        ("8.8.8.8", "8.8.8.8"),
        ("2606:4700:4700:0:0:0:0:1111", "2606:4700:4700::1111"),
    ],
    ids=["ipv4", "canonical-ipv6"],
)
def test_transport_barrier_persists_before_open_and_confirms_once(
    tmp_path, monkeypatch, ip, canonical
):
    sup, state = _reservation_suppressor(tmp_path, cap=1)
    reporter = mod.Reporter("fixture", 1, False)
    calls = []

    def opened(request, timeout):
        persisted = json.loads(state.read_text())
        assert persisted.get("pending") == [
            {
                "ip": canonical,
                "day": "1970-01-01",
                "started_at": 1000.0,
                "window_s": 900,
            }
        ], "durable reservation must exist before the real transport boundary"
        assert persisted["count"] == 0
        assert persisted["last"] == {}
        assert request.full_url == mod.API_URL
        assert request.method == "POST"
        assert timeout == 1
        calls.append(request.data)
        return _FakeResp(b"")

    monkeypatch.setattr(mod._OPENER, "open", opened)
    logs = []
    assert mod.process_line(_transport_entry(ip), sup, reporter, 1000, logs.append)
    assert len(calls) == 1
    persisted = json.loads(state.read_text())
    assert persisted["pending"] == []
    assert persisted["count"] == 1
    assert persisted["last"] == {canonical: 1000}
    assert sup._pending == []
    assert sup._count == 1
    assert sup.confirm(ip, 1000) is False
    resumed = mod.Suppressor(900, 1, str(state))
    assert mod.process_line(_transport_entry(), resumed, reporter, 1001, logs.append)
    assert len(calls) == 1
    assert resumed._count == 1


@pytest.mark.parametrize("failure", ["open", "replace"], ids=["write", "rename"])
def test_transport_failed_reservation_never_calls_open(tmp_path, monkeypatch, failure):
    sup, state = _reservation_suppressor(tmp_path)
    assert sup.reserve("9.9.9.9", 999) == (True, "")
    before = state.read_bytes()
    pending = list(sup._pending)
    calls = []
    monkeypatch.setattr(mod._OPENER, "open", lambda *a, **kw: calls.append(a))

    def fail(*a, **kw):
        raise OSError("injected persistence failure")

    if failure == "open":
        monkeypatch.setattr(mod, "open", fail, raising=False)
    else:
        monkeypatch.setattr(mod.os, "replace", fail)
    logs = []
    reporter = mod.Reporter("fixture", 1, False)
    assert (
        mod.process_line(_transport_entry(), sup, reporter, 1000, logs.append) is False
    )
    assert calls == [], "reservation persistence failure must forbid actual send"
    assert state.read_bytes() == before
    assert sup._pending == pending
    assert sup._count == 0
    assert logs == ["STATE   8.8.8.8: state-persistence"]


@pytest.mark.parametrize(
    "state_kind",
    ["missing", "corrupt", "unready", "no-path"],
    ids=["missing", "corrupt", "unready", "no-path"],
)
def test_transport_unready_state_never_bootstraps(tmp_path, monkeypatch, state_kind):
    state = tmp_path / "state.json"
    if state_kind == "corrupt":
        state.write_text("{")
    elif state_kind == "unready":
        state.write_text(
            json.dumps(
                {
                    "version": 2,
                    "day": None,
                    "count": 0,
                    "last": {},
                    "pending": [],
                    "reservation_ready": False,
                }
            )
        )
    before = state.read_bytes() if state.exists() else None
    sup = mod.Suppressor(900, 1000, None if state_kind == "no-path" else str(state))
    calls = []
    monkeypatch.setattr(mod._OPENER, "open", lambda *a, **kw: calls.append(a))
    logs = []
    assert (
        mod.process_line(
            _transport_entry(),
            sup,
            mod.Reporter("fixture", 1, False),
            1000,
            logs.append,
        )
        is False
    )
    assert calls == []
    assert sup._count == 0
    assert sup._pending == []
    assert (state.read_bytes() if state.exists() else None) == before
    assert logs == ["STATE   8.8.8.8: state-unavailable"]


@pytest.mark.parametrize(
    "result,done",
    [
        (302, True),
        (422, True),
        (429, False),
        (503, False),
        ("url-error", False),
        ("os-error", False),
    ],
    ids=["redirect", "permanent", "rate-limit", "server-error", "network", "io"],
)
def test_transport_attempted_outcome_keeps_debt_after_reload(
    tmp_path, monkeypatch, result, done
):
    sup, state = _reservation_suppressor(tmp_path, cap=1, window=1)
    reporter = mod.Reporter("fixture", 1, False)
    calls = []

    def opened(request, timeout):
        assert json.loads(state.read_text())["pending"]
        calls.append(request.data)
        if result == "url-error":
            raise mod.urllib.error.URLError("unknown delivery")
        if result == "os-error":
            raise OSError("unknown delivery")
        raise mod.urllib.error.HTTPError(
            mod.API_URL, result, "fixture", {"Retry-After": "1"}, _FakeBody(b"")
        )

    monkeypatch.setattr(mod._OPENER, "open", opened)
    logs = []
    assert (
        mod.process_line(_transport_entry(), sup, reporter, 1000, logs.append) is done
    )
    assert len(calls) == 1
    assert sup._count == 0
    assert sup._last == {}
    assert len(sup._pending) == 1
    resumed = mod.Suppressor(1, 1, str(state))
    assert resumed._pending == sup._pending
    assert resumed._count == 0
    # Even after dedup expiry, this UTC day's unknown send consumes quota.
    assert mod.process_line(_transport_entry(), resumed, reporter, 1002, logs.append)
    assert mod.process_line(
        _transport_entry("9.9.9.9"), resumed, reporter, 1002, logs.append
    )
    assert len(calls) == 1
    assert resumed._count == 0


@pytest.mark.parametrize(
    "failure",
    ["before-response", "after-response"],
    ids=["during-open", "during-close"],
)
def test_transport_interrupted_attempt_retains_debt(tmp_path, monkeypatch, failure):
    sup, state = _reservation_suppressor(tmp_path)
    reporter = mod.Reporter("fixture", 1, False)
    calls = []

    class InterruptedResponse(_FakeResp):
        def __exit__(self, *a):
            raise KeyboardInterrupt("injected transport interruption")

    def opened(request, timeout):
        calls.append(request.data)
        assert json.loads(state.read_text())["pending"]
        if failure == "before-response":
            raise KeyboardInterrupt("injected transport interruption")
        return InterruptedResponse(b"")

    monkeypatch.setattr(mod._OPENER, "open", opened)
    with pytest.raises(KeyboardInterrupt, match="injected transport interruption"):
        mod.process_line(_transport_entry(), sup, reporter, 1000, lambda m: None)
    assert len(calls) == 1
    assert sup._count == 0
    resumed = mod.Suppressor(900, 1000, str(state))
    assert resumed._pending == sup._pending
    assert resumed.allow("8.8.8.8", 1001) == (False, "deduped")
    assert resumed._count == 0


def test_transport_unknown_outcome_retains_pending(tmp_path, monkeypatch):
    sup, state = _reservation_suppressor(tmp_path)
    reporter = mod.Reporter("fixture", 1, False)
    monkeypatch.setattr(reporter, "report", lambda *a: ("unknown", "fixture"))
    assert (
        mod.process_line(_transport_entry(), sup, reporter, 1000, lambda m: None)
        is False
    )
    assert sup._count == 0
    assert len(json.loads(state.read_text())["pending"]) == 1
    assert mod.Suppressor(900, 1000, str(state)).allow("8.8.8.8", 1001) == (
        False,
        "deduped",
    )


def test_transport_confirmation_write_failure_restores_debt(tmp_path, monkeypatch):
    sup, state = _reservation_suppressor(tmp_path, cap=2)
    sup.record("9.9.9.9", 990)
    saved = []
    replace = mod.os.replace

    def persist(src, dst):
        saved.append(json.loads(Path(src).read_text()))
        if len(saved) == 2:
            assert saved[-1]["pending"] == []
            assert saved[-1]["count"] == 2
            raise OSError("injected confirmation persistence failure")
        replace(src, dst)

    monkeypatch.setattr(mod.os, "replace", persist)
    monkeypatch.setattr(mod._OPENER, "open", lambda *a, **kw: _FakeResp(b""))
    logs = []
    assert mod.process_line(
        _transport_entry(), sup, mod.Reporter("fixture", 1, False), 1000, logs.append
    )
    assert len(saved) == 2
    assert sup._count == 1
    assert sup._last == {"9.9.9.9": 990}
    assert sup._pending == saved[0]["pending"]
    resumed = mod.Suppressor(900, 2, str(state))
    assert resumed._pending == sup._pending
    assert resumed._count == 1
    assert resumed.allow("1.1.1.1", 1001) == (False, "daily-cap")
    assert "STATE   8.8.8.8: confirmation pending; attempt debt retained" in logs


def test_transport_noncanonical_ipv6_replay_advances_without_send(
    tmp_path, monkeypatch
):
    sup, state = _reservation_suppressor(tmp_path)
    reporter = mod.Reporter("fixture", 1, False)
    calls = []

    def opened(*a, **kw):
        calls.append(a)
        return _FakeResp(b"")

    monkeypatch.setattr(mod._OPENER, "open", opened)
    entry = _transport_entry("2606:4700:4700:0:0:0:0:1111")
    assert mod.process_line(entry, sup, reporter, 1000, lambda m: None)
    resumed = mod.Suppressor(900, 1000, str(state))
    assert mod.process_line(entry, resumed, reporter, 1001, lambda m: None)
    assert len(calls) == 1
    assert resumed._count == 1
    assert resumed._pending == []


def test_transport_confirm_matches_only_current_intent(tmp_path):
    sup, state = _reservation_suppressor(tmp_path)
    assert sup.reserve("8.8.8.8", 1000) == (True, "")
    assert sup.reserve("9.9.9.9", 1001) == (True, "")
    before = state.read_bytes()
    assert sup.confirm("8.8.8.8", 1001) is False
    assert sup.confirm("1.1.1.1", 1000) is False
    assert state.read_bytes() == before
    assert sup.confirm("8.8.8.8", 1000) is True
    assert sup._count == 1
    assert [item["ip"] for item in sup._pending] == ["9.9.9.9"]
    assert json.loads(state.read_text())["pending"] == sup._pending
    assert sup.confirm("8.8.8.8", 1000) is False
    assert sup._count == 1


def test_transport_pending_original_window_at_midnight(tmp_path, monkeypatch):
    sup, state = _reservation_suppressor(tmp_path, cap=1)
    reporter = mod.Reporter("fixture", 1, False)
    calls = []

    def opened(*a, **kw):
        calls.append(a)
        raise mod.urllib.error.URLError("unknown delivery")

    monkeypatch.setattr(mod._OPENER, "open", opened)
    assert (
        mod.process_line(_transport_entry(), sup, reporter, 86340, lambda m: None)
        is False
    )
    resumed = mod.Suppressor(1, 1, str(state))
    assert mod.process_line(
        _transport_entry(), resumed, reporter, 87239, lambda m: None
    )
    assert len(calls) == 1
    # Exactly at the original window's expiry on a new UTC day, sending is legal.
    assert (
        mod.process_line(_transport_entry(), resumed, reporter, 87240, lambda m: None)
        is False
    )
    assert len(calls) == 2
    assert resumed._count == 0
    assert len(resumed._pending) == 1
    assert resumed._pending[0]["started_at"] == 87240


def test_transport_dry_run_uses_builtin_no_send_without_bootstrap(
    tmp_path, monkeypatch
):
    state = tmp_path / "missing.json"
    sup = mod.Suppressor(900, 1000, str(state))
    reporter = _dry_reporter()
    calls = []
    monkeypatch.setattr(mod._OPENER, "open", lambda *a, **kw: calls.append("open"))
    monkeypatch.setattr(reporter, "report", lambda *a: calls.append("overridden"))
    assert mod.process_line(_transport_entry(), sup, reporter, 1000, lambda m: None)
    assert calls == []
    assert sup._count == 1
    assert sup._pending == []
    assert sup._state_valid is False
    assert not state.exists()  # even dry-run cannot initialize durable state
    resumed = mod.Suppressor(900, 1000, str(state))
    assert (
        mod.process_line(
            _transport_entry("9.9.9.9"),
            resumed,
            mod.Reporter("fixture", 1, False),
            1001,
            lambda m: None,
        )
        is False
    )
    assert calls == []


def test_transport_dry_run_persists_canonical_ipv6(tmp_path):
    sup, state = _reservation_suppressor(tmp_path)
    expanded = "2606:4700:4700:0:0:0:0:1111"
    canonical = "2606:4700:4700::1111"
    assert mod.process_line(
        _transport_entry(expanded), sup, _dry_reporter(), 1000, lambda _message: None
    )
    persisted = json.loads(state.read_text())
    assert persisted["last"] == {canonical: 1000}
    resumed = mod.Suppressor(900, 1000, str(state))
    assert resumed._state_valid
    assert resumed._last == {canonical: 1000}


def test_transport_dry_run_dedupes_repeated_expanded_ipv6(tmp_path):
    sup, _state = _reservation_suppressor(tmp_path)
    reporter = _dry_reporter()
    expanded = "2606:4700:4700:0:0:0:0:1111"
    entry = _transport_entry(expanded)
    logs = []
    assert mod.process_line(entry, sup, reporter, 1000, logs.append)
    assert mod.process_line(entry, sup, reporter, 1001, logs.append)
    assert sup._count == 1
    assert sup._last == {"2606:4700:4700::1111": 1000}
    assert len(logs) == 1


@pytest.mark.parametrize("kind", ["subclass", "duck"], ids=["subclass", "duck"])
def test_transport_dry_run_claim_cannot_bypass_barrier(tmp_path, kind):
    calls = []

    class ClaimedDryRun:
        dry_run = True

        def report(self, *a):
            calls.append(a)
            return mod.Reporter.OK, "untrusted dry-run claim"

    class OverriddenReporter(mod.Reporter, ClaimedDryRun):
        def report(self, *a):
            return ClaimedDryRun.report(self, *a)

    reporter = (
        OverriddenReporter("fixture", 1, True)
        if kind == "subclass"
        else ClaimedDryRun()
    )
    sup = mod.Suppressor(900, 1000, str(tmp_path / "missing.json"))
    assert (
        mod.process_line(_transport_entry(), sup, reporter, 1000, lambda m: None)
        is False
    )
    assert calls == []
    assert sup._count == 0


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


@pytest.mark.parametrize(
    "stage",
    [
        "fstat",
        "opened_log",
        "cooldown",
        "read",
        "process",
        "checkpoint",
        "final_checkpoint",
    ],
)
def test_follow_closes_handle_on_exception(tmp_path, monkeypatch, stage):
    args = _mk_args(tmp_path)
    Path(args.logfile).write_text("line\n")
    handles = []
    logs = []
    saves = []
    failure = OSError(f"injected {stage} failure")
    real_open = open

    def tracked_open(*a, **kw):
        handle = real_open(*a, **kw)
        if str(a[0]) == args.logfile:
            handles.append(handle)
        return handle

    def fail(*a, **kw):
        raise failure

    def log(message):
        logs.append(message)
        if stage == "opened_log":
            fail()

    def save(*a):
        saves.append(a)
        # Distinguish the final save from an EOF or backlog checkpoint.
        assert mod._stop is (stage == "final_checkpoint")
        fail()

    monkeypatch.setattr(mod, "open", tracked_open, raising=False)
    monkeypatch.setattr(mod, "_stop", False)
    rep = _dry_reporter()
    sup = mod.Suppressor(900, 1000, str(args.state) + ".sup")
    if stage == "fstat":
        monkeypatch.setattr(mod.os, "fstat", fail)
    elif stage == "cooldown":
        monkeypatch.setattr(rep, "in_cooldown", fail)
    elif stage == "read":
        monkeypatch.setattr(mod, "_read_log_line", fail)
    elif stage == "process":
        monkeypatch.setattr(mod, "process_line", fail)
    elif stage in ("checkpoint", "final_checkpoint"):
        monkeypatch.setattr(mod, "process_line", lambda *a: True)
        monkeypatch.setattr(mod, "save_offset", save)
        monkeypatch.setattr(
            mod.time, "time", lambda: 0.0 if stage == "final_checkpoint" else 10.0
        )
        _stopping_sleep(monkeypatch)

    try:
        with pytest.raises(OSError, match=f"injected {stage} failure") as caught:
            mod.follow(args, rep, sup, log)
        assert caught.value is failure
        assert len(handles) == 1
        assert handles[0].closed, (
            "follow must explicitly close while traceback is retained"
        )
        assert "stopped" not in logs
        if stage in ("checkpoint", "final_checkpoint"):
            assert len(saves) == 1
            assert saves[0][2] == len("line\n")
    finally:
        # A failing negative control must not leave its own fixture open.
        for handle in handles:
            handle.close()


@pytest.mark.parametrize("pre_stopped", [False, True])
def test_follow_closes_handle_on_stop(tmp_path, monkeypatch, pre_stopped):
    args = _mk_args(tmp_path)
    logfile = Path(args.logfile)
    logfile.write_text("line\n")
    handles = []
    real_open = open

    def tracked_open(*a, **kw):
        handle = real_open(*a, **kw)
        if str(a[0]) == args.logfile:
            handles.append(handle)
        return handle

    monkeypatch.setattr(mod, "open", tracked_open, raising=False)
    monkeypatch.setattr(mod, "_stop", pre_stopped)
    monkeypatch.setattr(mod, "process_line", lambda *a: True)
    _stopping_sleep(monkeypatch)
    logs = []
    mod.follow(args, _dry_reporter(), object(), logs.append)
    assert logs[-1] == "stopped"
    assert len(handles) == (0 if pre_stopped else 1)
    assert all(handle.closed for handle in handles)
    if not pre_stopped:
        assert mod.load_offset(args.state, args.logfile) == (
            len("line\n"),
            logfile.stat().st_ino,
        )


def test_follow_missing_logfile_waits_then_stops(tmp_path, monkeypatch):
    # logfile does not exist -> FileNotFoundError branch sleeps; we stop it.
    args = _mk_args(tmp_path)
    _stopping_sleep(monkeypatch, after=1)
    logs = _run_follow(args, monkeypatch)
    assert any("stopped" in m for m in logs)


def test_follow_processes_a_line(tmp_path, monkeypatch):
    args = _mk_args(tmp_path)
    entry = {
        **FIXTURE_EVIDENCE,
        "ts": "2026-07-17T00:00:00Z",
        "ip": "8.8.8.8",
        "cat": "sqli",
        "src": "uri",
        "req": "GET /x HTTP/1.1",
        "mode": "block",
        "status": 403,
    }
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
    entry = {
        **FIXTURE_EVIDENCE,
        "ts": "2026-07-17T00:00:00Z",
        "ip": "8.8.8.8",
        "cat": "sqli",
        "src": "uri",
        "req": "GET /x HTTP/1.1",
        "mode": "block",
        "status": 403,
    }
    Path(args.logfile).write_text(json.dumps(entry) + "\n")
    mod._stop = False
    logs = []
    rep = mod.Reporter(api_key="k", timeout=1.0, dry_run=False)
    # force report() to fail -> process_line returns False -> follow rewinds
    monkeypatch.setattr(rep, "report", lambda *a, **k: (mod.Reporter.RETRY, "boom"))
    sup, _ = _reservation_suppressor(tmp_path)
    _stopping_sleep(monkeypatch, after=1)
    try:
        mod.follow(args, rep, sup, logs.append)
    finally:
        mod._stop = False
    # line was NOT consumed: offset stays at 0 (rewound)
    off, _ = mod.load_offset(args.state, args.logfile)
    assert off == 0

    assert any("FAILED" in m for m in logs)
    assert len(sup._pending) == 1


def test_follow_respects_cooldown(tmp_path, monkeypatch):
    args = _mk_args(tmp_path, dry_run=True)
    # A real, reportable line: if the cooldown check were absent, follow() would
    # consume it and call report(). An empty file would pass this test even with
    # the cooldown removed, so it must carry a genuine hit.
    Path(args.logfile).write_text(
        json.dumps(
            {
                **FIXTURE_EVIDENCE,
                "ip": "8.8.8.8",
                "cat": "sqli",
                "src": "uri",
                "req": "GET /x HTTP/1.1",
                "mode": "block",
                "status": 403,
            }
        )
        + "\n"
    )
    mod._stop = False
    logs = []
    rep = mod.Reporter(api_key="k", timeout=1.0, dry_run=True)
    # pretend we're in a cooldown so the in_cooldown>0 branch is taken
    monkeypatch.setattr(rep, "in_cooldown", lambda now: 5.0)
    called = []
    monkeypatch.setattr(
        rep, "report", lambda *a, **k: called.append(a) or (mod.Reporter.OK, "ok")
    )
    sup = mod.Suppressor(900, 1000, str(args.state) + ".sup")
    _stopping_sleep(monkeypatch, after=1)
    try:
        mod.follow(args, rep, sup, logs.append)
    finally:
        mod._stop = False
    assert any("opened" in m for m in logs)
    # Cooldown active -> the line must NOT have been consumed/reported, and the
    # offset stays at 0 so it is retried once the cooldown clears.
    assert called == []
    off, _ = mod.load_offset(args.state, args.logfile)
    assert off == 0


# --------------------------------------------------------------------------- #
# main()
# --------------------------------------------------------------------------- #
def test_main_requires_api_key_when_not_dry_run(tmp_path, monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    rc = mod.main(
        [str(tmp_path / "shield.log"), "--state", str(tmp_path / "st" / "offset.json")]
    )
    assert rc == 2


def test_main_dry_run_runs_and_returns_zero(tmp_path, monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    # main() installs SIGTERM/SIGINT handlers; stub signal.signal so it does not
    # replace the test process's handlers (which would leak into later tests and
    # the runner's own shutdown).
    monkeypatch.setattr(mod.signal, "signal", lambda *_: None)
    logfile = tmp_path / "shield.log"
    logfile.write_text("")
    _stopping_sleep(monkeypatch, after=1)
    mod._stop = False
    try:
        rc = mod.main(
            [
                str(logfile),
                "--state",
                str(tmp_path / "st" / "offset.json"),
                "--dry-run",
                "--poll",
                "0.01",
            ]
        )
    finally:
        mod._stop = False
    assert rc == 0


def _boom(*a, **k):
    raise OSError("disk full")


def test_suppressor_save_swallows_open_oserror(tmp_path, monkeypatch):
    # _save must never raise when opening the temp file fails.
    sup, state = _reservation_suppressor(tmp_path)
    before = state.read_bytes()
    attempts = []

    def failed_open(*args, **kwargs):
        attempts.append(args[0])
        _boom()

    monkeypatch.setattr(mod, "open", failed_open, raising=False)
    sup.record("8.8.8.8", now=0.0)  # triggers _save internally, must not raise
    assert attempts == [str(state) + ".tmp"]
    assert state.read_bytes() == before


def test_suppressor_save_swallows_replace_oserror(tmp_path, monkeypatch):
    # _save must never raise when the atomic os.replace() fails -- open() and the
    # write succeed, so this exercises the rename path independently of the open
    # path above. A regression moving os.replace() outside the try would surface
    # here even though the open-failure test still passes.
    sup, state = _reservation_suppressor(tmp_path)
    before = state.read_bytes()
    attempts = []

    def failed_replace(*args):
        attempts.append(args)
        _boom()

    monkeypatch.setattr(os, "replace", failed_replace)
    sup.record("8.8.8.8", now=0.0)  # triggers _save internally, must not raise
    assert attempts == [(str(state) + ".tmp", str(state))]
    assert state.read_bytes() == before


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


def _persistent_new_inode(args, real_stat, delta=12345, extra_size=0):
    """os.stat replacement that ALWAYS reports a different inode for the log
    path (a rotation that stays rotated), so the grace loop eventually switches.
    Other paths pass through unchanged."""

    def fake_stat(p, *a, **k):
        st = real_stat(p, *a, **k)
        if str(p) == args.logfile:

            class S:
                st_ino = st.st_ino + delta
                st_size = st.st_size + extra_size
                st_mode = st.st_mode

            return S()
        return st

    return fake_stat


def test_follow_detects_rotation(tmp_path, monkeypatch):
    # Rotation switches only after a STABLE EOF grace (ROTATION_EOF_GRACE empty
    # polls). Empty file + a persistently-new inode -> grace elapses -> switch.
    args = _mk_args(tmp_path)
    logfile = Path(args.logfile)
    logfile.write_text("")  # empty: open ok, readline is EOF each pass

    mod._stop = False
    logs = []
    rep = mod.Reporter(api_key="k", timeout=1.0, dry_run=True)
    sup = mod.Suppressor(900, 1000, str(args.state) + ".sup")

    real_stat = os.stat
    monkeypatch.setattr(os, "stat", _persistent_new_inode(args, real_stat))
    # Needs > ROTATION_EOF_GRACE sleeps to let the grace elapse before we stop.
    _stopping_sleep(monkeypatch, after=mod.ROTATION_EOF_GRACE + 2)
    try:
        mod.follow(args, rep, sup, logs.append)
    finally:
        mod._stop = False
        monkeypatch.setattr(os, "stat", real_stat)
    assert any("rotation detected" in m for m in logs)


def test_follow_truncation_reopens_immediately(tmp_path, monkeypatch):
    # Same inode but size shrank below our offset (in-place truncation): there is
    # nothing to drain, so follow() reopens at once (no grace window).
    args = _mk_args(tmp_path)
    logfile = Path(args.logfile)
    logfile.write_text("some-old-content\n")

    mod._stop = False
    logs = []
    rep = mod.Reporter(api_key="k", timeout=1.0, dry_run=True)
    sup = mod.Suppressor(900, 1000, str(args.state) + ".sup")
    # Resume at EOF so the first read is EOF and we hit the rotation/trunc check.
    inode = os.stat(logfile).st_ino
    mod.save_offset(args.state, args.logfile, logfile.stat().st_size, inode)

    real_stat = os.stat
    calls = {"n": 0}

    def fake_stat(p, *a, **k):
        st = real_stat(p, *a, **k)
        if str(p) == args.logfile:
            calls["n"] += 1
            if calls["n"] == 1:  # report truncation ONCE, then real

                class S:
                    st_ino = st.st_ino  # SAME inode
                    st_size = 0  # shrank below offset
                    st_mode = st.st_mode

                return S()
        return st

    monkeypatch.setattr(os, "stat", fake_stat)

    # Stop the moment truncation is logged, so the post-reopen loop can't spin.
    def stop_on_trunc(msg):
        logs.append(msg)
        if "truncation detected" in msg:
            mod._stop = True

    _stopping_sleep(monkeypatch, after=3)
    try:
        mod.follow(args, rep, sup, stop_on_trunc)
    finally:
        mod._stop = False
        monkeypatch.setattr(os, "stat", real_stat)
    assert any("truncation detected" in m for m in logs)


def test_follow_drains_late_lines_before_rotating(tmp_path, monkeypatch):
    # S27-8 grace drain: nginx can append to the renamed inode between our last
    # read and its SIGUSR1 reopen. follow() must NOT close the old fd on the
    # first rotation stat -- it keeps reading the old inode across the grace
    # window, so a line written after rotation is detected is still consumed
    # (and the grace count restarts on any late read).
    args = _mk_args(tmp_path, dry_run=True)
    logfile = Path(args.logfile)
    logfile.write_text("")  # empty: open ok, first readline is EOF

    mod._stop = False
    logs = []
    rep = mod.Reporter(api_key="k", timeout=1.0, dry_run=True)
    sup = mod.Suppressor(900, 1000, str(args.state) + ".sup")

    late = (
        json.dumps(
            {
                **FIXTURE_EVIDENCE,
                "ts": "2026-07-17T00:00:00Z",
                "ip": "8.8.8.8",
                "cat": "sqli",
                "src": "uri",
                "req": "GET /x HTTP/1.1",
                "mode": "block",
                "status": 403,
            }
        )
        + "\n"
    )

    real_stat = os.stat
    calls = {"n": 0}

    def fake_stat(p, *a, **k):
        st = real_stat(p, *a, **k)
        if str(p) == args.logfile:
            calls["n"] += 1
            # First rotation check: append a late line to the OLD inode so the
            # next read-loop pass picks it up during the grace window.
            if calls["n"] == 1:
                with open(args.logfile, "a", encoding="utf-8") as fh:
                    fh.write(late)
            new_size = real_stat(args.logfile).st_size

            class S:
                st_ino = st.st_ino + 12345  # persistently rotated
                st_size = new_size
                st_mode = st.st_mode

            return S()
        return st

    monkeypatch.setattr(os, "stat", fake_stat)
    _stopping_sleep(monkeypatch, after=mod.ROTATION_EOF_GRACE + 4)
    try:
        mod.follow(args, rep, sup, logs.append)
    finally:
        mod._stop = False
        monkeypatch.setattr(os, "stat", real_stat)

    # The late line appended after rotation was still read from the old fd.
    assert any("reported 8.8.8.8" in m or "dry-run" in m for m in logs)
    assert any("rotation detected" in m for m in logs)


def test_follow_drains_late_lines_when_path_absent(tmp_path, monkeypatch):
    # F4 (audit s43): during the rename -> SIGUSR1-reopen gap, os.stat(log_path)
    # raises FileNotFoundError. follow() must NOT close the old fd on that first
    # absent-path poll -- it keeps reading the renamed inode across the same
    # stable-EOF grace, so a late hit written to the old inode in the gap is
    # still consumed before we switch to the (eventually recreated) path.
    args = _mk_args(tmp_path, dry_run=True)
    logfile = Path(args.logfile)
    logfile.write_text("")  # empty: open ok, first readline is EOF

    mod._stop = False
    logs = []
    rep = mod.Reporter(api_key="k", timeout=1.0, dry_run=True)
    sup = mod.Suppressor(900, 1000, str(args.state) + ".sup")

    late = (
        json.dumps(
            {
                **FIXTURE_EVIDENCE,
                "ts": "2026-07-17T00:00:00Z",
                "ip": "9.9.9.9",
                "cat": "sqli",
                "src": "uri",
                "req": "GET /y HTTP/1.1",
                "mode": "block",
                "status": 403,
            }
        )
        + "\n"
    )

    real_stat = os.stat
    calls = {"n": 0}

    def fake_stat(p, *a, **k):
        if str(p) == args.logfile:
            calls["n"] += 1
            # First absent-path poll: nginx appends a late hit to the renamed
            # (still-open) inode before the new path exists. The read branch must
            # pick it up during the grace window rather than losing it.
            if calls["n"] == 1:
                with open(args.logfile, "a", encoding="utf-8") as fh:
                    fh.write(late)
            # Path is gone for the whole gap -> stat keeps raising.
            raise FileNotFoundError(args.logfile)
        return real_stat(p, *a, **k)

    monkeypatch.setattr(os, "stat", fake_stat)
    _stopping_sleep(monkeypatch, after=mod.ROTATION_EOF_GRACE + 4)
    try:
        mod.follow(args, rep, sup, logs.append)
    finally:
        mod._stop = False
        monkeypatch.setattr(os, "stat", real_stat)

    # The late line written to the old inode during the absent-path gap was
    # still drained, and only then did follow() switch on the stable EOF.
    assert any("reported 9.9.9.9" in m or "dry-run" in m for m in logs)
    assert any("path absent" in m for m in logs)
