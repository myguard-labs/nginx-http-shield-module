"""Evidence admission and monitoring contracts; no real rule is promoted here."""

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "shield_reporter_verdicts", ROOT / "reporter/abuseipdb-reporter.py"
)
if spec is None or spec.loader is None:
    raise RuntimeError("cannot load reporter module")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

# An invented rule identity admitted ONLY by individual tests.
IDENTITY = ("1111111111111111", "2222222222222222", 1, "sqli")
EVIDENCE = {
    "ip": "8.8.8.8",
    "cat": "sqli",
    "mode": "block",
    "action": "block",
    "verdict": "exploit",
    "ruleset": IDENTITY[0],
    "rule": IDENTITY[1],
    "rev": 1,
    "ts": "2026-01-01T00:00:00+00:00",
    "req": "GET /private-token?secret=value HTTP/1.1",
    "src": "private-source",
    "body": "private-body",
    "header": "private-header",
}


def consume(entry):
    sup = mod.Suppressor(window_s=900, daily_cap=1000)
    reporter = mod.Reporter(api_key="", timeout=1, dry_run=True)
    logs = []
    done = mod.process_line(json.dumps(entry), sup, reporter, 1000, logs.append)
    return done, sup, logs


def test_production_registry_does_not_promote_any_rule():
    assert mod.PROMOTED_RULES == frozenset()
    done, sup, logs = consume(EVIDENCE)
    assert done
    assert sup._count == 0
    assert logs == ["skip: record is not promoted block-mode exploit evidence"]


def test_fixture_promoted_exploit_dry_run_has_no_request_text(monkeypatch, capsys):
    monkeypatch.setattr(mod, "PROMOTED_RULES", frozenset({IDENTITY}))

    # Calling a network boundary is forbidden even with this admitted fixture.
    def no_network(*args, **kwargs):
        pytest.fail("dry-run attempted network access")

    monkeypatch.setattr(mod._OPENER, "open", no_network)
    done, sup, logs = consume(EVIDENCE)
    assert done
    assert sup._count == 1
    assert any("reported 8.8.8.8" in line for line in logs)
    output = "\n".join(logs) + capsys.readouterr().out
    assert "promoted block-mode exploit evidence" in output
    assert '"categories": "21,16"' in output
    for secret in (
        "private-token",
        "secret=value",
        "private-source",
        "private-body",
        "private-header",
    ):
        assert secret not in output
        assert all(secret not in line for line in logs)
    assert (
        mod.build_comment(EVIDENCE)
        == "nginx-http-shield: promoted block-mode exploit evidence"
    )


@pytest.mark.parametrize(
    "change",
    [
        {"verdict": "suspicious"},
        {"verdict": "signature-match"},
        {"verdict": "resource"},
        {"verdict": "not-inspected"},
        {"verdict": "unknown"},
        {"verdict": ""},
        {"verdict": None},
        {"verdict": ["exploit"]},
        {"mode": "detect"},
        {"mode": "off"},
        {"mode": None},
        {"action": "detect"},
        {"action": "observe"},
        {"action": "resource"},
        {"action": None},
        {"rule": "unpromoted"},
        {"ruleset": "unpromoted"},
        {"rev": 2},
        {"rev": True},
        {"rev": 0},
        {"rev": "1"},
        {"rule": []},
        {"ruleset": {}},
        {"cat": "xss"},
        {"cat": []},
        {"ts": "private-token"},
        {"ts": None},
        {"ts": "2026-02-30T00:00:00+00:00"},
        {"ip": None},
        {"ip": "127.0.0.1"},
        {"ip": "garbage"},
    ],
    ids=[
        "suspicious",
        "signature-match",
        "resource",
        "not-inspected",
        "unknown",
        "empty",
        "null",
        "array",
        "detect",
        "off",
        "mode-null",
        "action-detect",
        "observe",
        "action-resource",
        "action-null",
        "rule-unpromoted",
        "ruleset-unpromoted",
        "rev-mismatch",
        "rev-bool",
        "rev-zero",
        "rev-string",
        "rule-array",
        "ruleset-object",
        "category-mismatch",
        "category-array",
        "timestamp-secret",
        "timestamp-null",
        "timestamp-invalid-calendar",
        "ip-null",
        "ip-private",
        "ip-invalid",
    ],
)
def test_nonpromoted_or_malformed_never_reports(change, monkeypatch, capsys):
    monkeypatch.setattr(mod, "PROMOTED_RULES", frozenset({IDENTITY}))
    done, sup, logs = consume({**EVIDENCE, **change})
    assert done
    assert sup._count == 0
    assert not any("reported" in line for line in logs)
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize(
    "key", ["mode", "action", "verdict", "rule", "ruleset", "rev", "cat", "ts", "ip"]
)
def test_missing_required_field_fails_closed(key, monkeypatch):
    monkeypatch.setattr(mod, "PROMOTED_RULES", frozenset({IDENTITY}))
    entry = dict(EVIDENCE)
    del entry[key]
    done, sup, _ = consume(entry)
    assert done
    assert sup._count == 0


def test_legacy_and_duplicate_dispositions_fail_closed(monkeypatch):
    monkeypatch.setattr(mod, "PROMOTED_RULES", frozenset({IDENTITY}))
    done, sup, logs = consume({"ip": "8.8.8.8", "cat": "sqli"})
    assert done
    assert sup._count == 0
    assert logs == ["skip: record is not promoted block-mode exploit evidence"]
    raw = (
        json.dumps({**EVIDENCE, "verdict": "suspicious"})[:-1]
        + ', "verdict": "exploit"}'
    )
    assert mod.process_line(raw, sup, mod.Reporter("", 1, True), 1000, logs.append)
    assert logs[-1] == "skip: malformed JSON"
    assert sup._count == 0


@pytest.mark.parametrize("ts", ["2026-01-01T00:00:00Z", "2026-01-01T01:00:00+01:00"])
def test_bounded_nginx_timestamps_admitted(ts, monkeypatch):
    monkeypatch.setattr(mod, "PROMOTED_RULES", frozenset({IDENTITY}))
    _, sup, _ = consume({**EVIDENCE, "ts": ts})
    assert sup._count == 1


def test_dashboard_distinguishes_evidence_without_filling_absent_exploit_rates():
    dashboard = json.loads((ROOT / "contrib/grafana-dashboard.json").read_text())
    panels = {p["title"]: p for p in dashboard["panels"]}
    promoted = panels["Promoted exploit blocks"]
    assert (
        promoted["targets"][0]["expr"]
        == 'rate(shield_detections_total{class="exploit",mode="block"}[5m])'
    )
    assert "empty panel" in promoted["description"]
    assert (
        panels["Suspicious blocked requests"]["targets"][0]["expr"]
        == 'rate(shield_blocked_total{class="suspicious"}[5m])'
    )
