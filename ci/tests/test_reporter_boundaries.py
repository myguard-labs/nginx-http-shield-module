"""Untrusted log and HTTP response boundaries for the AbuseIPDB reporter."""

import builtins
import importlib.util
import io
import json
import os
import subprocess
import sys
import urllib.error
from argparse import Namespace
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

import pytest

SOURCE = Path(__file__).resolve().parents[2] / "reporter/abuseipdb-reporter.py"
spec = importlib.util.spec_from_file_location("shield_reporter_boundaries", SOURCE)
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


@pytest.mark.parametrize(
    ("offset", "expected"),
    [(-60, 60.0), (0, 0.0), (60, 0.0)],
    ids=["future", "now", "past"],
)
def test_parse_retry_after_timezone_less_http_date_is_utc(
    monkeypatch, offset, expected
):
    when = "Wed Oct 21 07:29:00 2015"  # Valid asctime HTTP-date has no timezone.
    now = datetime(2015, 10, 21, 7, 29, tzinfo=UTC).timestamp() + offset
    try:
        with monkeypatch.context() as timezone:
            # A local UTC clock would hide missing UTC normalization.
            timezone.setenv("TZ", "EST5")
            mod.time.tzset()
            assert mod._parse_retry_after(when, now=now) == expected
    finally:
        # Restore the process timezone after monkeypatch restores the environment.
        mod.time.tzset()


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
    line = json.dumps(
        {**FIXTURE_EVIDENCE, "ip": "8.8.8.8", "cat": "sqli", "req": "GET /x"}
    )
    assert mod.process_line(line, sup, reporter, 1000, logs.append)
    assert sup._count == 1


def test_oversized_record_is_discarded_in_bounded_chunks():
    valid = (
        json.dumps(
            {**FIXTURE_EVIDENCE, "ip": "8.8.8.8", "cat": "sqli", "req": "GET /x"}
        )
        + "\n"
    )
    fh = io.StringIO("x" * (mod.MAX_LOG_LINE * 3) + "\n" + valid)
    assert mod._read_log_line(fh) == (None, False, 0)
    assert mod._read_log_line(fh) == (valid, False, 0)

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
    forged_tail = json.dumps(
        {**FIXTURE_EVIDENCE, "ip": "8.8.8.8", "cat": "sqli", "req": "GET /tail"}
    )
    next_record = json.dumps(
        {**FIXTURE_EVIDENCE, "ip": "9.9.9.9", "cat": "sqli", "req": "GET /next"}
    )

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


def test_short_partial_line_waits_for_newline_and_keeps_checkpoint(
    tmp_path, monkeypatch
):
    logfile = tmp_path / "shield.log"
    logfile.write_text("bad-json: ")  # ten bytes, no newline
    args = Namespace(
        logfile=str(logfile), state=str(tmp_path / "offset.json"), poll=0.01
    )
    sup = mod.Suppressor(window_s=900, daily_cap=1000)
    reporter = mod.Reporter(api_key="", timeout=1, dry_run=True)
    logs = []
    first_poll = []
    sleeps = 0
    tail = json.dumps(
        {**FIXTURE_EVIDENCE, "ip": "8.8.8.8", "cat": "sqli", "req": "GET /tail"}
    )
    next_record = json.dumps(
        {**FIXTURE_EVIDENCE, "ip": "9.9.9.9", "cat": "sqli", "req": "GET /next"}
    )

    def append_during_eof(_seconds):
        nonlocal sleeps
        sleeps += 1
        if sleeps == 1:
            first_poll.append(
                (mod.load_offset(args.state, args.logfile)[0], list(logs))
            )
            with logfile.open("a") as fh:
                fh.write(tail + "\n")
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
    assert sleeps >= 3  # the deferred fragment is polled, not spun on
    assert first_poll[0][0] == 0
    assert not any("malformed JSON" in message for message in first_poll[0][1])
    assert logs.count("skip: malformed JSON") == 1
    assert not any("reported 8.8.8.8" in message for message in logs)
    assert any("reported 9.9.9.9" in message for message in logs)
    assert set(sup._last) == {"9.9.9.9"}
    assert mod.load_offset(args.state, args.logfile)[0] == logfile.stat().st_size


def test_short_partial_growth_restarts_rotation_grace(tmp_path, monkeypatch):
    logfile = tmp_path / "shield.log"
    rotated = tmp_path / "shield.log.1"
    logfile.write_text('{"ip":"8.8.8.8",')
    args = Namespace(
        logfile=str(logfile), state=str(tmp_path / "offset.json"), poll=0.01
    )
    sup = mod.Suppressor(window_s=900, daily_cap=1000)
    reporter = mod.Reporter(api_key="", timeout=1, dry_run=True)
    logs = []
    stat_calls = 0
    sleeps = 0
    real_stat = os.stat

    def rotating_stat(path, *a, **kw):
        nonlocal stat_calls
        if str(path) == args.logfile:
            stat_calls += 1
            if stat_calls == 1:
                logfile.rename(rotated)
                logfile.write_text("")
        return real_stat(path, *a, **kw)

    def append_during_grace(_seconds):
        nonlocal sleeps
        sleeps += 1
        if sleeps == 1:
            with rotated.open("a") as fh:
                fh.write('"cat":"sqli",')
        elif sleeps == 2:
            with rotated.open("a") as fh:
                fh.write(json.dumps(FIXTURE_EVIDENCE)[1:-1] + ',"req":"GET /late"}\n')
        elif sleeps >= 4:
            mod._stop = True

    monkeypatch.setattr(mod.os, "stat", rotating_stat)
    monkeypatch.setattr(mod.time, "sleep", append_during_grace)
    mod._stop = False
    try:
        mod.follow(args, reporter, sup, logs.append)
    finally:
        mod._stop = False
    assert stat_calls >= 2
    assert sleeps >= 3
    assert any("reported 8.8.8.8" in message for message in logs)
    assert sup._count == 1


def test_copy_truncate_reopens_while_discarding_oversized_line(tmp_path, monkeypatch):
    logfile = tmp_path / "shield.log"
    logfile.write_text("x" * (mod.MAX_LOG_LINE + 1))  # no newline
    inode = logfile.stat().st_ino
    replacement = (
        json.dumps(
            {**FIXTURE_EVIDENCE, "ip": "8.8.8.8", "cat": "sqli", "req": "GET /new"}
        )
        + "\n"
    )
    args = Namespace(
        logfile=str(logfile), state=str(tmp_path / "offset.json"), poll=0.01
    )
    sup = mod.Suppressor(window_s=900, daily_cap=1000)
    reporter = mod.Reporter(api_key="", timeout=1, dry_run=True)
    logs = []
    sleeps = 0

    def copy_truncate_during_eof(_seconds):
        nonlocal sleeps
        sleeps += 1
        if sleeps == 1:
            logfile.write_text(replacement)
            assert logfile.stat().st_ino == inode  # same inode, shorter file
        elif sleeps >= 3:
            mod._stop = True

    monkeypatch.setattr(mod.time, "sleep", copy_truncate_during_eof)
    mod._stop = False
    try:
        mod.follow(args, reporter, sup, logs.append)
    finally:
        mod._stop = False
    assert sleeps >= 2  # EOF polling remains paced
    assert "truncation detected; reopening" in logs
    assert sum(message.startswith("opened ") for message in logs) == 2
    assert any("reported 8.8.8.8" in message for message in logs)
    assert sup._count == 1
    assert mod.load_offset(args.state, args.logfile) == (len(replacement), inode)


def test_copy_truncate_reopens_while_short_line_is_deferred(tmp_path, monkeypatch):
    logfile = tmp_path / "shield.log"
    logfile.write_text("x" * 500)  # short, unterminated line
    inode = logfile.stat().st_ino
    replacement = (
        json.dumps(
            {**FIXTURE_EVIDENCE, "ip": "8.8.8.8", "cat": "sqli", "req": "GET /new"}
        )
        + "\n"
    )
    assert len(replacement) < 500
    args = Namespace(
        logfile=str(logfile), state=str(tmp_path / "offset.json"), poll=0.01
    )
    sup = mod.Suppressor(window_s=900, daily_cap=1000)
    reporter = mod.Reporter(api_key="", timeout=1, dry_run=True)
    logs = []
    sleeps = 0

    def copy_truncate_during_eof(_seconds):
        nonlocal sleeps
        sleeps += 1
        if sleeps == 1:
            logfile.write_text(replacement)
            assert logfile.stat().st_ino == inode
        elif sleeps >= 3:
            mod._stop = True

    monkeypatch.setattr(mod.time, "sleep", copy_truncate_during_eof)
    mod._stop = False
    try:
        mod.follow(args, reporter, sup, logs.append)
    finally:
        mod._stop = False
    assert sleeps >= 2
    assert "truncation detected; reopening" in logs
    assert any("reported 8.8.8.8" in message for message in logs)
    assert sup._count == 1
    assert mod.load_offset(args.state, args.logfile) == (len(replacement), inode)


def test_follow_skips_oversized_record_then_reports_next(tmp_path, monkeypatch):
    logfile = tmp_path / "shield.log"
    logfile.write_text(
        "x" * (mod.MAX_LOG_LINE * 3)
        + "\n"
        + json.dumps(
            {**FIXTURE_EVIDENCE, "ip": "8.8.8.8", "cat": "sqli", "req": "GET /x"}
        )
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
                        json.dumps(
                            {
                                **FIXTURE_EVIDENCE,
                                "ip": "8.8.8.8",
                                "cat": "sqli",
                                "req": "GET /late",
                            }
                        )
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
    day = datetime.fromtimestamp(1000, UTC).strftime("%Y-%m-%d")
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


@pytest.fixture
def recursive_json_decoder(monkeypatch):
    # Use the real Python decoder to exercise recursion handling consistently:
    # newer CPython C decoders permit deeper input than older supported runtimes.
    monkeypatch.setattr(json.scanner, "make_scanner", json.scanner.py_make_scanner)
    decoder = json.JSONDecoder()
    monkeypatch.setattr(mod.json, "_default_decoder", decoder)


@contextmanager
def standard_recursion_limit():
    # pytest can raise this above the interpreter default; exercise the daemon's
    # normal decoder limit without leaking the setting into other tests.
    previous = sys.getrecursionlimit()
    sys.setrecursionlimit(1000)
    try:
        yield
    finally:
        sys.setrecursionlimit(previous)


@pytest.mark.parametrize("restart", [False, True], ids=["live", "restart"])
def test_suppressor_midnight_preserves_window_until_exact_expiry(tmp_path, restart):
    state = str(tmp_path / "suppress.json")
    Path(state).write_text(json.dumps({"day": None, "count": 0, "last": {}}))
    sup = mod.Suppressor(window_s=900, daily_cap=1000, state_path=state)
    reported_at = 86400 - 60  # 23:59 UTC
    sup.record("8.8.8.8", reported_at)
    if restart:
        sup = mod.Suppressor(window_s=900, daily_cap=1000, state_path=state)

    assert sup.allow("8.8.8.8", 86400) == (False, "deduped")
    assert sup._count == 0  # only the daily quota resets at midnight
    assert sup.allow("8.8.8.8", reported_at + 899) == (False, "deduped")
    assert sup.allow("8.8.8.8", reported_at + 900) == (True, "")
    sup.record("9.9.9.9", reported_at + 901)
    assert sup._last == {"9.9.9.9": reported_at + 901}


def test_suppressor_midnight_resets_cap_and_persists_previous_day_dedup(tmp_path):
    state = str(tmp_path / "suppress.json")
    Path(state).write_text(json.dumps({"day": None, "count": 0, "last": {}}))
    sup = mod.Suppressor(window_s=900, daily_cap=1, state_path=state)
    sup.record("8.8.8.8", 86340)
    assert sup.allow("9.9.9.9", 86341) == (False, "daily-cap")
    assert sup.allow("8.8.8.8", 86400) == (False, "deduped")
    assert sup.allow("9.9.9.9", 86400) == (True, "")
    sup.record("9.9.9.9", 86400)
    assert sup.allow("1.1.1.1", 86401) == (False, "daily-cap")

    resumed = mod.Suppressor(window_s=900, daily_cap=1, state_path=state)
    assert resumed.allow("1.1.1.1", 86401) == (False, "daily-cap")
    # Raising the cap makes the retained per-IP window independently observable.
    resumed.daily_cap = 2
    assert resumed.allow("8.8.8.8", 86401) == (False, "deduped")
    assert resumed.allow("9.9.9.9", 86401) == (False, "deduped")


def test_deep_json_record_is_consumed_as_malformed(recursive_json_decoder):
    with standard_recursion_limit():
        line = "[" * 1100 + "]" * 1100
        assert len(line) < mod.MAX_LOG_LINE
        sup = mod.Suppressor(window_s=900, daily_cap=1000)
        reporter = mod.Reporter(api_key="", timeout=1, dry_run=True)
        logs = []
        assert mod.process_line(line, sup, reporter, 1000, logs.append)
        assert logs == ["skip: malformed JSON"]
        assert sup._count == 0


def test_deep_json_record_followed_by_valid_line_advances_offset(
    tmp_path, monkeypatch, recursive_json_decoder
):
    with standard_recursion_limit():
        logfile = tmp_path / "shield.log"
        poison = "[" * 1100 + "]" * 1100 + "\n"
        valid = (
            json.dumps(
                {**FIXTURE_EVIDENCE, "ip": "8.8.8.8", "cat": "sqli", "req": "GET /x"}
            )
            + "\n"
        )
        logfile.write_text(poison + valid)
        args = Namespace(
            logfile=str(logfile), state=str(tmp_path / "offset.json"), poll=0.01
        )
        sup = mod.Suppressor(window_s=900, daily_cap=1000)
        reporter = mod.Reporter(api_key="", timeout=1, dry_run=True)
        logs = []
        monkeypatch.setattr(mod.time, "time", lambda: 1000)
        monkeypatch.setattr(
            mod.time, "sleep", lambda _seconds: setattr(mod, "_stop", True)
        )
        mod._stop = False
        try:
            mod.follow(args, reporter, sup, logs.append)
        finally:
            mod._stop = False
        assert logs.count("skip: malformed JSON") == 1
        assert sum("reported 8.8.8.8" in message for message in logs) == 1
        assert sup._count == 1
        assert mod.load_offset(args.state, args.logfile) == (
            logfile.stat().st_size,
            logfile.stat().st_ino,
        )


@pytest.mark.parametrize(
    "state_kind", ["suppression", "offset"], ids=["suppression", "offset"]
)
def test_deep_json_persisted_state_is_ignored(
    tmp_path, state_kind, recursive_json_decoder
):
    with standard_recursion_limit():
        state = tmp_path / "state.json"
        state.write_text("[" * 1100 + "]" * 1100)
        if state_kind == "suppression":
            sup = mod.Suppressor(window_s=900, daily_cap=1, state_path=str(state))
            assert sup._count == 0
            assert sup._last == {}
            assert sup.allow("8.8.8.8", 1000) == (True, "")
            sup.record("8.8.8.8", 1000)
            assert state.read_text() == "[" * 1100 + "]" * 1100
            resumed = mod.Suppressor(window_s=900, daily_cap=1, state_path=str(state))
            assert resumed.reserve("9.9.9.9", 1001) == (False, "state-unavailable")
        else:
            assert mod.load_offset(str(state), "shield.log") == (0, -1)
            mod.save_offset(str(state), "shield.log", 42, 7)
            assert mod.load_offset(str(state), "shield.log") == (42, 7)


# A fresh interpreter owns each attempt; os._exit targets only that interpreter.
# All transport is replaced, and no signal or process-group operation is used.
_RESTART_WORKER = r"""
import builtins
import importlib.util
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

cfg = json.loads(sys.stdin.read())
spec = importlib.util.spec_from_file_location("restart_reporter", cfg["source"])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
root = Path(cfg["root"])
state = root / "suppress.json"
logfile = root / "shield.log"
checkpoint = root / "offset.json"
now = cfg.get("now", 1000)
mod.time.time = lambda: now
if cfg.get("promote", True):
    mod.PROMOTED_RULES = frozenset({("1111111111111111", "2222222222222222", 1, "sqli")})
if cfg.get("deny_read"):
    real_open = builtins.open
    def opened(path, *args, **kwargs):
        if str(path) == str(state) and (not args or args[0] == "r"):
            raise PermissionError("fixture state read denied")
        return real_open(path, *args, **kwargs)
    mod.open = opened

sends = root / "sends.jsonl"
def transport(request, timeout):
    with sends.open("a") as fh:
        fh.write(json.dumps({"body": request.data.decode(), "at": now}) + "\n")
    if cfg.get("crash") == "after-post":
        os._exit(79)
    if cfg.get("outcome") == "retry":
        raise mod.urllib.error.URLError("unknown delivery")
    if cfg.get("outcome") == "drop":
        raise mod.urllib.error.HTTPError(mod.API_URL, 422, "fixture", {}, None)
    return SimpleNamespace(__enter__=lambda self: self, __exit__=lambda *a: None)

# Special methods must live on the type for the real with-statement boundary.
class Response:
    def __enter__(self): return self
    def __exit__(self, *args): return None

def opened_transport(*args, **kwargs):
    transport(*args, **kwargs)
    return Response()
mod._OPENER.open = opened_transport
logs = []
if cfg["operation"] == "main":
    calls = []
    mod.follow = lambda *args: calls.append("follow")
    mod.signal.signal = lambda *args: None
    os.environ["ABUSEIPDB_API_KEY"] = "fixture"
    argv = [str(logfile), "--state", str(checkpoint)]
    if cfg.get("dry_run"):
        argv.append("--dry-run")
    rc = mod.main(argv)
    print(json.dumps({"rc": rc, "calls": calls}))
else:
    sup = mod.Suppressor(cfg.get("window", 900), cfg.get("cap", 1), str(state))
    if cfg["operation"] == "record":
        result = sup.record("8.8.8.8", now)
        print(json.dumps({"record_result": result, "saved": sup._save(),
                          "reserve": sup.reserve("9.9.9.9", now), "count": sup._count}))
    else:
        if cfg.get("settlement_failure"):
            real_save = sup._save
            def save():
                return False if sends.exists() else real_save()
            sup._save = save
        if cfg.get("crash") == "before-post":
            real_reserve = sup.reserve
            def reserve(*args):
                allowed = real_reserve(*args)
                if allowed[0]: os._exit(79)
                return allowed
            sup.reserve = reserve
        if cfg.get("crash") == "before-reserve-save":
            sup._save = lambda: os._exit(79)
        real_process = mod.process_line
        def process(*args):
            done = real_process(*args)
            if cfg.get("crash") == "after-settlement": os._exit(79)
            return done
        mod.process_line = process
        mod.time.sleep = lambda *args: setattr(mod, "_stop", True)
        mod.follow(SimpleNamespace(logfile=str(logfile), state=str(checkpoint), poll=.01),
                   mod.Reporter("fixture", 1, cfg.get("dry_run", False)), sup, logs.append)
        print(json.dumps({"count": sup._count, "pending": sup._pending,
                          "ready": sup._state_valid, "logs": logs,
                          "offset": mod.load_offset(str(checkpoint), str(logfile))[0]}))
"""


def _restart_process(tmp_path, operation="follow", expected=0, **config):
    result = subprocess.run(
        [sys.executable, "-c", _RESTART_WORKER],
        input=json.dumps(
            {
                "root": str(tmp_path),
                "source": str(SOURCE),
                "operation": operation,
                **config,
            }
        ),
        text=True,
        capture_output=True,
        check=False,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        timeout=10,
    )
    assert result.returncode == expected, (result.stdout, result.stderr)
    if expected:
        return None
    return json.loads(result.stdout.splitlines()[-1]), result.stderr


def _restart_fixture(tmp_path):
    state = tmp_path / "suppress.json"
    # Explicit fixture provisioning models offline initialization, never startup.
    state.write_text(
        json.dumps(
            {
                "version": 2,
                "reservation_ready": True,
                "day": None,
                "count": 0,
                "last": {},
                "pending": [],
            }
        )
    )
    log = tmp_path / "shield.log"
    log.write_text(
        json.dumps({**FIXTURE_EVIDENCE, "ip": "8.8.8.8", "cat": "sqli"}) + "\n"
    )
    mod.save_offset(str(tmp_path / "offset.json"), str(log), 0, log.stat().st_ino)
    return state, log


def _restart_sends(tmp_path):
    path = tmp_path / "sends.jsonl"
    return path.read_text().splitlines() if path.exists() else []


def _restart_main_in_process(tmp_path, monkeypatch, *, deny_read=False, dry_run=False):
    """Direct twin of the process oracle makes startup branch coverage visible."""
    calls = []
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "fixture")
    monkeypatch.setattr(mod.signal, "signal", lambda *args: None)
    monkeypatch.setattr(mod, "follow", lambda *args: calls.append("follow"))
    if deny_read:
        real_open = open

        def opened(path, *args, **kwargs):
            if str(path) == str(tmp_path / "suppress.json"):
                raise PermissionError("fixture state read denied")
            return real_open(path, *args, **kwargs)

        monkeypatch.setattr(mod, "open", opened, raising=False)
    argv = [str(tmp_path / "shield.log"), "--state", str(tmp_path / "offset.json")]
    if dry_run:
        argv.append("--dry-run")
    return {"rc": mod.main(argv), "calls": calls}


@pytest.mark.parametrize(
    "kind", ["first-install", "missing", "corrupt", "unreadable", "unready"]
)
def test_restart_main_blocks_unavailable_without_bootstrap(
    tmp_path, kind, monkeypatch, capsys
):
    state, _ = _restart_fixture(tmp_path)
    if kind in ("first-install", "missing"):
        state.unlink()
        if kind == "first-install":
            (tmp_path / "offset.json").unlink()
    elif kind == "corrupt":
        state.write_bytes(b"{damaged unknown debt\xff")
    elif kind == "unready":
        data = json.loads(state.read_text())
        data["reservation_ready"] = False
        state.write_text(json.dumps(data))
    before = state.read_bytes() if state.exists() else None
    checkpoint = tmp_path / "offset.json"
    before_offset = checkpoint.read_bytes() if checkpoint.exists() else None
    data, error = _restart_process(tmp_path, "main", deny_read=kind == "unreadable")
    assert data == {"rc": 2, "calls": []}, "unavailable state must stop before follow"
    assert (
        _restart_main_in_process(tmp_path, monkeypatch, deny_read=kind == "unreadable")
        == data
    )
    assert capsys.readouterr().err == error
    assert "established installation restore the current authoritative state" in error
    assert "Only for a verified first install" in error
    assert '"reservation_ready":true' in error
    assert (state.read_bytes() if state.exists() else None) == before
    assert (checkpoint.read_bytes() if checkpoint.exists() else None) == before_offset
    assert _restart_sends(tmp_path) == []


@pytest.mark.parametrize("kind", ["missing", "corrupt", "unreadable", "unready"])
def test_restart_legacy_record_preserves_unavailable_bytes(tmp_path, kind):
    state, _ = _restart_fixture(tmp_path)
    if kind == "missing":
        state.unlink()
    elif kind == "corrupt":
        state.write_text("{unknown debt")
    elif kind == "unready":
        data = json.loads(state.read_text())
        data["reservation_ready"] = False
        state.write_text(json.dumps(data))
    before = state.read_bytes() if state.exists() else None
    data, _ = _restart_process(tmp_path, "record", deny_read=kind == "unreadable")
    assert data["record_result"] is None and data["count"] == 1
    assert data["saved"] is False, "unavailable state must refuse every save"
    assert data["reserve"] == [False, "state-unavailable"]
    assert (state.read_bytes() if state.exists() else None) == before, (
        "legacy record must not overwrite unavailable suppression debt"
    )
    assert not (tmp_path / "suppress.json.tmp").exists()


@pytest.mark.parametrize("dry_run", [False, True])
def test_restart_main_accepts_explicit_provision_or_network_free_dry_run(
    tmp_path, dry_run, monkeypatch
):
    state, _ = _restart_fixture(tmp_path)
    if dry_run:
        state.unlink()
    before = state.read_bytes() if state.exists() else None
    data, error = _restart_process(tmp_path, "main", dry_run=dry_run)
    assert data == {"rc": 0, "calls": ["follow"]}
    assert _restart_main_in_process(tmp_path, monkeypatch, dry_run=dry_run) == data
    assert error == ""
    assert (state.read_bytes() if state.exists() else None) == before
    assert _restart_sends(tmp_path) == []


@pytest.mark.parametrize(
    "crash", ["before-reserve-save", "before-post", "after-post", "after-settlement"]
)
@pytest.mark.parametrize("checkpoint_kind", ["stale", "missing", "corrupt"])
def test_restart_crash_replay_uses_durable_debt(tmp_path, crash, checkpoint_kind):
    state, log = _restart_fixture(tmp_path)
    stale = (tmp_path / "offset.json").read_bytes()
    _restart_process(tmp_path, expected=79, crash=crash)
    assert (tmp_path / "offset.json").read_bytes() == stale
    sent = crash in ("after-post", "after-settlement")
    assert len(_restart_sends(tmp_path)) == int(sent)
    disk = json.loads(state.read_text())
    assert disk["count"] == int(crash == "after-settlement")
    assert len(disk["pending"]) == int(crash in ("before-post", "after-post"))
    if checkpoint_kind == "missing":
        (tmp_path / "offset.json").unlink()
    elif checkpoint_kind == "corrupt":
        (tmp_path / "offset.json").write_text("{bad offset")
    replay, _ = _restart_process(tmp_path, now=1001)
    assert len(_restart_sends(tmp_path)) == int(crash != "before-post")
    assert replay["offset"] == log.stat().st_size
    assert replay["count"] == int(crash in ("before-reserve-save", "after-settlement"))
    assert len(replay["pending"]) == int(crash in ("before-post", "after-post"))


def test_restart_failed_settlement_retains_debt_and_blocks_replay(tmp_path):
    state, log = _restart_fixture(tmp_path)
    data, _ = _restart_process(tmp_path, settlement_failure=True)
    assert data["count"] == 0 and len(data["pending"]) == 1
    assert json.loads(state.read_text())["pending"] == data["pending"]
    assert any("confirmation pending" in line for line in data["logs"])
    mod.save_offset(str(tmp_path / "offset.json"), str(log), 0, log.stat().st_ino)
    replay, _ = _restart_process(tmp_path, now=1001)
    assert replay["count"] == 0 and replay["pending"] == data["pending"]
    assert replay["offset"] == log.stat().st_size
    assert len(_restart_sends(tmp_path)) == 1


@pytest.mark.parametrize("outcome", ["retry", "drop"])
def test_restart_unknown_attempt_debits_cap_after_window_expires(tmp_path, outcome):
    state, log = _restart_fixture(tmp_path)
    first, _ = _restart_process(tmp_path, now=1000, outcome=outcome)
    assert first["count"] == 0 and len(first["pending"]) == 1
    assert first["offset"] == (0 if outcome == "retry" else log.stat().st_size)
    # A stale offset may replay a different IP, but the same-day debt still caps.
    log.write_text(log.read_text().replace("8.8.8.8", "9.9.9.9"))
    mod.save_offset(str(tmp_path / "offset.json"), str(log), 0, log.stat().st_ino)
    replay, _ = _restart_process(tmp_path, now=1900, window=1)
    assert replay["count"] == 0 and len(replay["pending"]) == 1
    assert len(_restart_sends(tmp_path)) == 1
    assert json.loads(state.read_text())["count"] == 0


def test_restart_midnight_preserves_original_pending_window_until_exact_expiry(
    tmp_path,
):
    state, log = _restart_fixture(tmp_path)
    _restart_process(tmp_path, expected=79, crash="after-post", now=86340)
    for now in (86400, 87239, 87240):
        # Replay a stale offset; the first two starts must retain the original window.
        mod.save_offset(str(tmp_path / "offset.json"), str(log), 0, log.stat().st_ino)
        replay, _ = _restart_process(tmp_path, now=now, window=1)
        assert len(_restart_sends(tmp_path)) == (2 if now == 87240 else 1)
        assert replay["count"] == (1 if now == 87240 else 0)
    disk = json.loads(state.read_text())
    assert disk["day"] == "1970-01-02" and disk["pending"] == []
    assert disk["last"] == {"8.8.8.8": 87240}


@pytest.mark.parametrize("dry_run", [False, True])
def test_restart_empty_production_registry_never_sends_or_changes_suppression(
    tmp_path, dry_run
):
    state, log = _restart_fixture(tmp_path)
    before = state.read_bytes()
    data, _ = _restart_process(tmp_path, promote=False, dry_run=dry_run)
    assert data["count"] == 0 and data["pending"] == []
    assert data["offset"] == log.stat().st_size
    assert _restart_sends(tmp_path) == []
    assert state.read_bytes() == before


def test_partial_path_disappears_then_continues(tmp_path, monkeypatch):
    path = tmp_path / "shield.log"
    args = Namespace(logfile=str(path), state=str(tmp_path / "offset.json"), poll=0.01)
    sup = mod.Suppressor(window_s=900, daily_cap=1000)
    reporter = mod.Reporter(api_key="", timeout=1, dry_run=True)
    path.write_text("bad-json: ")
    real_stat, real_open = os.stat, builtins.open
    handles, checkpoints, sleeps, missing = [], [], [], []

    def track_open(file, *a, **kw):
        handle = real_open(file, *a, **kw)
        if str(file) == args.logfile:
            handles.append(handle)
        return handle

    def stat(file, *a, **kw):
        if str(file) == args.logfile and sleeps and not missing:
            missing.append(True)
            raise FileNotFoundError(args.logfile)
        return real_stat(file, *a, **kw)

    def sleep(_):
        sleeps.append(True)
        if len(sleeps) == 1:
            checkpoints.append(mod.load_offset(args.state, args.logfile)[0])
            with path.open("a") as f:
                f.write("tail\n")
        else:
            mod._stop = True

    monkeypatch.setattr(builtins, "open", track_open)
    monkeypatch.setattr(mod.os, "stat", stat)
    monkeypatch.setattr(mod.time, "sleep", sleep)
    logs = []
    mod._stop = False
    try:
        mod.follow(args, reporter, sup, logs.append)
    finally:
        mod._stop = False
    assert missing == [True]
    assert checkpoints == [0]
    assert logs.count("skip: malformed JSON") == 1
    assert mod.load_offset(args.state, args.logfile)[0] == path.stat().st_size
    assert len(handles) == 1 and handles[0].closed
    assert logs[-1] == "stopped"


def test_oversized_continuation_without_newline(tmp_path, monkeypatch):
    path = tmp_path / "shield.log"
    args = Namespace(logfile=str(path), state=str(tmp_path / "offset.json"), poll=0.01)
    sup = mod.Suppressor(window_s=900, daily_cap=1000)
    reporter = mod.Reporter(api_key="", timeout=1, dry_run=True)
    path.write_text("x" * (mod.MAX_LOG_LINE + 1))
    sleeps, checkpoints, logs = [], [], []

    def sleep(_):
        sleeps.append(True)
        checkpoints.append(mod.load_offset(args.state, args.logfile)[0])
        if len(sleeps) == 1:
            with path.open("a") as f:
                f.write("continued")
        elif len(sleeps) == 2:
            with path.open("a") as f:
                f.write("\n")
        else:
            mod._stop = True

    monkeypatch.setattr(mod.time, "sleep", sleep)
    mod._stop = False
    try:
        mod.follow(args, reporter, sup, logs.append)
    finally:
        mod._stop = False
    assert len(sleeps) >= 3
    assert checkpoints[:2] == [0, 0]
    assert logs.count("skip: oversized log record") == 1
    assert mod.load_offset(args.state, args.logfile)[0] == path.stat().st_size
