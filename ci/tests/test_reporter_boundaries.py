"""Untrusted log and HTTP response boundaries for the AbuseIPDB reporter."""

import importlib.util
import io
import json
import urllib.error
from argparse import Namespace
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
    assert mod._read_log_line(fh) is None
    assert mod._read_log_line(fh) == valid

    sup = mod.Suppressor(window_s=900, daily_cap=1000)
    reporter = mod.Reporter(api_key="", timeout=1, dry_run=True)
    logs = []
    assert mod.process_line(
        "x" * (mod.MAX_LOG_LINE + 1), sup, reporter, 1000, logs.append
    )
    assert sup._count == 0
    assert logs == ["skip: oversized log record"]


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
