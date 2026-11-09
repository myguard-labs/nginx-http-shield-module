"""Untrusted log and HTTP response boundaries for the AbuseIPDB reporter."""

import importlib.util
import io
import json
import os
import urllib.error
from argparse import Namespace
from datetime import datetime, timezone
from pathlib import Path

import pytest

SOURCE = Path(__file__).resolve().parents[2] / "reporter/abuseipdb-reporter.py"
spec = importlib.util.spec_from_file_location("shield_reporter_boundaries", SOURCE)
if spec is None or spec.loader is None:
    raise RuntimeError("cannot load reporter module")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def test_json_record_shape_and_malformed_line_never_log_raw_input():
    sup = mod.Suppressor(window_s=900, daily_cap=1000)
    reporter = mod.Reporter(api_key="", timeout=1, dry_run=True)
    logs = []
    for line in ('{"req":"private-token"', "[]", "null", '"private-token"'):
        assert mod.process_line(line, sup, reporter, 1000, logs.append)
    assert sup._count == 0
    assert logs
    assert all("private-token" not in message for message in logs)


def test_valid_record_still_reports():
    sup = mod.Suppressor(window_s=900, daily_cap=1000)
    reporter = mod.Reporter(api_key="", timeout=1, dry_run=True)
    logs = []
    line = json.dumps({"ip": "8.8.8.8", "cat": "sqli", "req": "GET /x"})
    assert mod.process_line(line, sup, reporter, 1000, logs.append)
    assert sup._count == 1


def test_oversized_record_is_discarded_in_bounded_chunks():
    valid = json.dumps({"ip": "8.8.8.8", "cat": "sqli", "req": "GET /x"}) + "\n"
    fh = io.StringIO("x" * (mod.MAX_LOG_LINE * 3) + "\n" + valid)
    assert mod._read_log_line(fh) == (None, False)
    assert mod._read_log_line(fh) == (valid, False)

    sup = mod.Suppressor(window_s=900, daily_cap=1000)
    reporter = mod.Reporter(api_key="", timeout=1, dry_run=True)
    logs = []
    assert mod.process_line(
        "x" * (mod.MAX_LOG_LINE + 1), sup, reporter, 1000, logs.append
    )
    assert sup._count == 0
    assert logs == ["skip: oversized log record"]


def test_split_oversized_record_discards_tail_and_reports_next(tmp_path, monkeypatch):
    logfile = tmp_path / "shield.log"
    logfile.write_text("x" * (mod.MAX_LOG_LINE + 1))  # no newline yet
    args = Namespace(
        logfile=str(logfile), state=str(tmp_path / "offset.json"), poll=0.01
    )
    sup = mod.Suppressor(window_s=900, daily_cap=1000)
    reporter = mod.Reporter(api_key="", timeout=1, dry_run=True)
    logs = []
    sleeps = 0
    checkpoint_offsets = []
    forged_tail = json.dumps({"ip": "8.8.8.8", "cat": "sqli", "req": "GET /tail"})
    next_record = json.dumps({"ip": "9.9.9.9", "cat": "sqli", "req": "GET /next"})

    def append_during_eof(_seconds):
        nonlocal sleeps
        sleeps += 1
        if sleeps == 1:
            checkpoint_offsets.append(mod.load_offset(args.state, args.logfile)[0])
            with logfile.open("a") as fh:
                fh.write(forged_tail + "\n")
        elif sleeps == 2:
            with logfile.open("a") as fh:
                fh.write(next_record + "\n")
        elif sleeps >= 3:
            mod._stop = True

    monkeypatch.setattr(mod.time, "sleep", append_during_eof)
    mod._stop = False
    try:
        mod.follow(args, reporter, sup, logs.append)
    finally:
        mod._stop = False
    assert sleeps >= 3  # no busy spin at the transient EOF
    assert checkpoint_offsets == [0]  # resume from the whole rejected line
    assert "skip: oversized log record" in logs
    assert not any("reported 8.8.8.8" in message for message in logs)
    assert any("reported 9.9.9.9" in message for message in logs)
    assert set(sup._last) == {"9.9.9.9"}
    assert mod.load_offset(args.state, args.logfile)[0] == logfile.stat().st_size


def test_follow_skips_oversized_record_then_reports_next(tmp_path, monkeypatch):
    logfile = tmp_path / "shield.log"
    logfile.write_text(
        "x" * (mod.MAX_LOG_LINE * 3)
        + "\n"
        + json.dumps({"ip": "8.8.8.8", "cat": "sqli", "req": "GET /x"})
        + "\n"
    )
    args = Namespace(
        logfile=str(logfile), state=str(tmp_path / "offset.json"), poll=0.01
    )
    sup = mod.Suppressor(window_s=900, daily_cap=1000)
    reporter = mod.Reporter(api_key="", timeout=1, dry_run=True)
    logs = []

    def stop_on_idle(_seconds):
        mod._stop = True

    monkeypatch.setattr(mod.time, "sleep", stop_on_idle)
    mod._stop = False
    try:
        mod.follow(args, reporter, sup, logs.append)
    finally:
        mod._stop = False
    assert sup._count == 1
    assert any(message == "skip: oversized log record" for message in logs)
    assert mod.load_offset(args.state, args.logfile)[0] == logfile.stat().st_size


def test_oversized_late_record_restarts_rotation_grace(tmp_path, monkeypatch):
    logfile = tmp_path / "shield.log"
    rotated = tmp_path / "shield.log.1"
    logfile.write_text("")
    args = Namespace(
        logfile=str(logfile), state=str(tmp_path / "offset.json"), poll=0.01
    )
    sup = mod.Suppressor(window_s=900, daily_cap=1000)
    reporter = mod.Reporter(api_key="", timeout=1, dry_run=True)
    logs = []
    stat_calls = 0
    sleep_calls = 0
    real_stat = os.stat

    def rotating_stat(path, *a, **kw):
        nonlocal stat_calls
        if str(path) == args.logfile:
            stat_calls += 1
            if stat_calls == 1:
                logfile.rename(rotated)
                logfile.write_text("")
            elif stat_calls == 2:
                # This is the EOF after the oversized line. nginx can still
                # append to its open old inode before the reporter closes it.
                with rotated.open("a") as fh:
                    fh.write(
                        json.dumps({"ip": "8.8.8.8", "cat": "sqli", "req": "GET /late"})
                        + "\n"
                    )
        return real_stat(path, *a, **kw)

    def sleep_during_grace(_seconds):
        nonlocal sleep_calls
        sleep_calls += 1
        if sleep_calls == 1:
            with rotated.open("a") as fh:
                fh.write("x" * (mod.MAX_LOG_LINE + 1) + "\n")
        if sleep_calls >= 4:
            mod._stop = True

    monkeypatch.setattr(mod.os, "stat", rotating_stat)
    monkeypatch.setattr(mod.time, "sleep", sleep_during_grace)
    mod._stop = False
    try:
        mod.follow(args, reporter, sup, logs.append)
    finally:
        mod._stop = False
    assert stat_calls >= 2
    assert "skip: oversized log record" in logs
    assert any("reported 8.8.8.8" in message for message in logs)
    assert sup._count == 1


def test_malformed_persisted_state_does_not_crash_or_accept_negative_count(tmp_path):
    suppress = tmp_path / "suppress.json"
    offset = tmp_path / "offset.json"
    for value in (
        "[]",
        '{"day":"1970-01-01","count":-3,"last":{}}',
        '{"day":"1970-01-01","count":1,"last":[]}',
    ):
        suppress.write_text(value)
        sup = mod.Suppressor(window_s=900, daily_cap=1, state_path=str(suppress))
        assert sup._count == 0
        assert sup.allow("8.8.8.8", 1000) == (True, "")

    for value in ("[]", '{"path":"log","offset":-2,"inode":4}'):
        offset.write_text(value)
        assert mod.load_offset(str(offset), "log") == (0, -1)


def test_valid_persisted_numeric_boundaries_remain_accepted(tmp_path):
    suppress = tmp_path / "suppress.json"
    day = datetime.fromtimestamp(1000, timezone.utc).strftime("%Y-%m-%d")
    suppress.write_text(
        json.dumps({"day": day, "count": 1, "last": {"8.8.8.8": 1000.0}})
    )
    sup = mod.Suppressor(window_s=900, daily_cap=1000, state_path=str(suppress))
    assert sup.allow("8.8.8.8", 1050) == (False, "deduped")
    assert sup._count == 1

    offset = tmp_path / "offset.json"
    path = str(tmp_path / "shield.log")
    offset.write_text(json.dumps({"path": path, "offset": 0, "inode": -1}))
    assert mod.load_offset(str(offset), path) == (0, -1)
    offset.write_text(
        json.dumps({"path": path, "offset": (1 << 63) - 1, "inode": (1 << 64) - 1})
    )
    assert mod.load_offset(str(offset), path) == ((1 << 63) - 1, (1 << 64) - 1)


@pytest.mark.parametrize("count", ["Infinity", "NaN", "1.5", "true", str(1 << 63)])
def test_invalid_persisted_counts_reset(tmp_path, count):
    state = tmp_path / "suppress.json"
    state.write_text('{"day":"1970-01-01","count":' + count + ',"last":{}}')
    sup = mod.Suppressor(window_s=900, daily_cap=1000, state_path=str(state))
    assert sup._count == 0
    assert sup.allow("8.8.8.8", 1000) == (True, "")


@pytest.mark.parametrize("timestamp", ["Infinity", "NaN", "1e300", "-1"])
def test_invalid_persisted_last_timestamps_reset(tmp_path, timestamp):
    state = tmp_path / "suppress.json"
    state.write_text(
        '{"day":"1970-01-01","count":1,"last":{"8.8.8.8":' + timestamp + "}}"
    )
    sup = mod.Suppressor(window_s=900, daily_cap=1000, state_path=str(state))
    assert sup._last == {}
    assert sup.allow("8.8.8.8", 1000) == (True, "")


@pytest.mark.parametrize(
    "field,value",
    [
        ("offset", "Infinity"),
        ("offset", "NaN"),
        ("offset", "1.5"),
        ("offset", "true"),
        ("offset", str(1 << 63)),
        ("inode", "Infinity"),
        ("inode", "NaN"),
        ("inode", "1.5"),
        ("inode", "true"),
        ("inode", "-2"),
        ("inode", str(1 << 64)),
    ],
)
def test_invalid_persisted_offset_numbers_reset(tmp_path, field, value):
    state = tmp_path / "offset.json"
    path = str(tmp_path / "shield.log")
    values = {"offset": "0", "inode": "-1"}
    values[field] = value
    state.write_text(
        '{"path":'
        + json.dumps(path)
        + ',"offset":'
        + values["offset"]
        + ',"inode":'
        + values["inode"]
        + "}"
    )
    assert mod.load_offset(str(state), path) == (0, -1)


@pytest.mark.parametrize(
    "option,value",
    [
        ("--dedup-window", "0"),
        ("--dedup-window", "-1"),
        ("--daily-cap", "-1"),
        ("--poll", "0"),
        ("--poll", "nan"),
        ("--timeout", "-1"),
        ("--timeout", "inf"),
    ],
)
def test_invalid_runtime_limits_are_rejected(option, value, tmp_path, monkeypatch):
    monkeypatch.setattr(mod, "follow", lambda *args: None)
    with pytest.raises(SystemExit) as exc:
        mod.main(
            [
                str(tmp_path / "missing.log"),
                "--state",
                str(tmp_path / "offset.json"),
                "--dry-run",
                option,
                value,
            ]
        )
    assert exc.value.code == 2


class UnreadableBody:
    def read(self, *args):
        raise AssertionError("response body must not be read or logged")

    def close(self):
        pass


class Response(UnreadableBody):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_success_response_body_is_not_read(monkeypatch):
    monkeypatch.setattr(mod._OPENER, "open", lambda request, timeout: Response())
    reporter = mod.Reporter(api_key="key", timeout=1, dry_run=False)
    outcome, detail = reporter.report("8.8.8.8", [21], "comment", "", now=0)
    assert outcome == mod.Reporter.OK
    assert detail == "HTTP success"


def test_error_response_body_is_not_read_and_retry_policy_holds(monkeypatch):
    for code, expected in (
        (302, mod.Reporter.DROP),
        (429, mod.Reporter.RETRY),
        (503, mod.Reporter.RETRY),
    ):

        def fail(request, timeout, status=code):
            raise urllib.error.HTTPError(
                mod.API_URL, status, "error", {"Retry-After": "30"}, UnreadableBody()
            )

        monkeypatch.setattr(mod._OPENER, "open", fail)
        reporter = mod.Reporter(api_key="key", timeout=1, dry_run=False)
        outcome, detail = reporter.report("8.8.8.8", [21], "comment", "", now=0)
        assert outcome == expected
        assert detail.startswith(f"HTTP {code}")
        if code == 429:
            assert reporter.in_cooldown(0) == 30


def test_network_error_detail_cannot_echo_credential(monkeypatch):
    def fail(request, timeout):
        raise urllib.error.URLError("credential=private-token")

    monkeypatch.setattr(mod._OPENER, "open", fail)
    reporter = mod.Reporter(api_key="private-token", timeout=1, dry_run=False)
    outcome, detail = reporter.report("8.8.8.8", [21], "comment", "", now=0)
    assert outcome == mod.Reporter.RETRY
    assert "private-token" not in detail
