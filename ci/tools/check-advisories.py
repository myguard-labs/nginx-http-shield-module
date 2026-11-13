#!/usr/bin/env python3
"""Validate the pinned dependency inventory and query OSV's supported API."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_INVENTORY = ROOT / "ci/dependency-inventory.json"
OSV_QUERY_BATCH = "https://api.osv.dev/v1/querybatch"
ACTION_PATTERN = re.compile(
    r"uses:\s*[\"']?([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)"
    r"(?:/[^@\s\"']+)?@([^\s#\"']+)"
)


def load_json(path: pathlib.Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read JSON {path}: {exc}") from exc


def validate_inventory(
    inventory: dict[str, object], root: pathlib.Path
) -> list[dict[str, object]]:
    if inventory.get("schema_version") != 1:
        raise ValueError("dependency inventory schema_version must be 1")
    dependencies = inventory.get("dependencies")
    if not isinstance(dependencies, list) or not dependencies:
        raise ValueError("dependency inventory has no dependencies")
    workflows = [
        *(root / ".github").rglob("*.yml"),
        *(root / ".github").rglob("*.yaml"),
    ]
    workflow_actions: dict[str, set[str]] = {}
    for workflow in workflows:
        for action, pin in ACTION_PATTERN.findall(workflow.read_text(encoding="utf-8")):
            workflow_actions.setdefault(action, set()).add(pin)

    ids: set[str] = set()
    inventory_actions: set[str] = set()
    for dependency in dependencies:
        if not isinstance(dependency, dict):
            raise TypeError("dependency entry is not an object")
        dep_id = dependency.get("id")
        query = dependency.get("osv_query")
        if not isinstance(dep_id, str) or not dep_id or dep_id in ids:
            raise ValueError(f"invalid or duplicate dependency id: {dep_id!r}")
        if not isinstance(query, dict) or not query:
            raise ValueError(f"{dep_id}: missing supported osv_query")
        resolved_commit = dependency.get("resolved_commit")
        if resolved_commit is not None and query.get("commit") != resolved_commit:
            raise ValueError(
                f"{dep_id}: osv_query.commit does not match resolved_commit"
            )
        ids.add(dep_id)

        if dependency.get("scope") == "ci-action":
            upstream = dependency.get("upstream")
            commit = dependency.get("resolved_commit")
            if not isinstance(upstream, str) or not upstream.startswith(
                "https://github.com/"
            ):
                raise ValueError(f"{dep_id}: invalid GitHub Action upstream")
            if (
                not isinstance(commit, str)
                or re.fullmatch(r"[0-9a-f]{40}", commit) is None
            ):
                raise ValueError(f"{dep_id}: invalid GitHub Action commit")
            action = upstream.removeprefix("https://github.com/").rstrip("/")
            inventory_actions.add(action)
            uses = workflow_actions.get(action, set())
            if not uses:
                raise ValueError(f"{dep_id}: action is absent from workflows")
            if uses != {commit}:
                raise ValueError(
                    f"{dep_id}: workflow pins {sorted(uses)}, inventory has {commit}"
                )

    if set(workflow_actions) != inventory_actions:
        missing = sorted(set(workflow_actions) - inventory_actions)
        extra = sorted(inventory_actions - set(workflow_actions))
        raise ValueError(
            f"workflow action inventory mismatch: missing={missing}, extra={extra}"
        )

    checks = inventory.get("pin_checks")
    if not isinstance(checks, list) or not checks:
        raise ValueError("dependency inventory has no pin_checks")
    for check in checks:
        if not isinstance(check, dict):
            raise TypeError("pin check is not an object")
        rel = check.get("path")
        pattern = check.get("pattern")
        expected = check.get("expected")
        if not all(isinstance(value, str) for value in (rel, pattern, expected)):
            raise ValueError("pin check requires string path, pattern, and expected")
        path = root / str(rel)
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ValueError(f"pin source unavailable: {rel}: {exc}") from exc
        matches = re.findall(str(pattern), text)
        if not matches or any(not isinstance(match, str) for match in matches):
            raise ValueError(
                f"pin check did not match one capture group: {rel}: {pattern}"
            )
        values = sorted(set(matches))
        if values != [expected]:
            raise ValueError(
                f"pin drift in {rel}: inventory has {expected}, source has {values}"
            )
    return dependencies


def dispositions(
    inventory: dict[str, object], dependencies: list[dict[str, object]]
) -> dict[tuple[str, str], dict[str, object]]:
    raw = inventory.get("advisory_dispositions", [])
    if not isinstance(raw, list):
        raise TypeError("advisory_dispositions is not an array")
    dependency_commits = {
        str(dependency["id"]): dependency.get("resolved_commit")
        for dependency in dependencies
    }
    result: dict[tuple[str, str], dict[str, object]] = {}
    for item in raw:
        if not isinstance(item, dict):
            raise TypeError("advisory disposition is not an object")
        dep_id = item.get("dependency_id")
        advisory_id = item.get("advisory_id")
        reason = item.get("reason")
        evidence = item.get("evidence")
        fixed_commit = item.get("fixed_commit")
        reviewed_commit = item.get("reviewed_commit")
        if item.get("status") != "fixed":
            raise ValueError(
                f"unsupported advisory disposition status: {item.get('status')}"
            )
        if not all(
            isinstance(value, str) and value for value in (dep_id, advisory_id, reason)
        ):
            raise ValueError(
                "advisory disposition requires dependency_id, advisory_id, and reason"
            )
        if (
            not isinstance(fixed_commit, str)
            or re.fullmatch(r"[0-9a-f]{40}", fixed_commit) is None
        ):
            raise ValueError(
                f"{dep_id}/{advisory_id}: fixed disposition requires a full fix commit"
            )
        if (
            not isinstance(reviewed_commit, str)
            or re.fullmatch(r"[0-9a-f]{40}", reviewed_commit) is None
            or dependency_commits.get(str(dep_id)) != reviewed_commit
        ):
            raise ValueError(
                f"{dep_id}/{advisory_id}: disposition is not bound to the resolved dependency commit"
            )
        if (
            not isinstance(evidence, list)
            or not evidence
            or not all(isinstance(value, str) for value in evidence)
        ):
            raise ValueError(f"{dep_id}/{advisory_id}: disposition requires evidence")
        key = (str(dep_id), str(advisory_id))
        if key in result:
            raise ValueError(f"duplicate advisory disposition: {dep_id}/{advisory_id}")
        result[key] = item
    return result


def query_osv(queries: list[dict[str, object]]) -> dict[str, object]:
    payload = json.dumps({"queries": queries}, separators=(",", ":")).encode()
    request = urllib.request.Request(
        OSV_QUERY_BATCH,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "shield-advisory-check/1",
        },
        method="POST",
    )
    last_error: Exception | None = None
    for _attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.load(response)
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
            last_error = exc
    raise ValueError(f"OSV query failed after 3 attempts: {last_error}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", type=pathlib.Path, default=DEFAULT_INVENTORY)
    parser.add_argument(
        "--response", type=pathlib.Path, help="use a retained OSV response"
    )
    parser.add_argument(
        "--output", type=pathlib.Path, help="write machine-readable receipt"
    )
    args = parser.parse_args()

    try:
        raw = args.inventory.read_bytes()
        inventory = json.loads(raw)
        if not isinstance(inventory, dict):
            raise TypeError("dependency inventory root is not an object")
        dependencies = validate_inventory(inventory, ROOT)
        disposition_map = dispositions(inventory, dependencies)
        queries = [dependency["osv_query"] for dependency in dependencies]
        response = load_json(args.response) if args.response else query_osv(queries)
        if not isinstance(response, dict) or not isinstance(
            response.get("results"), list
        ):
            raise TypeError("OSV response has no results array")
        results = response["results"]
        if len(results) != len(dependencies):
            raise ValueError(
                f"OSV result count mismatch: wanted {len(dependencies)}, got {len(results)}"
            )
        receipt_dependencies = []
        observed = []
        undisposed: list[tuple[str, str]] = []
        for dependency, result in zip(dependencies, results, strict=True):
            if not isinstance(result, dict):
                raise TypeError(f"{dependency['id']}: OSV result is not an object")
            if result.get("next_page_token"):
                raise ValueError(
                    f"{dependency['id']}: paginated OSV result is unsupported"
                )
            vulns = result.get("vulns", [])
            if not isinstance(vulns, list):
                raise TypeError(f"{dependency['id']}: OSV vulns is not an array")
            for vuln in vulns:
                if (
                    not isinstance(vuln, dict)
                    or not isinstance(vuln.get("id"), str)
                    or not vuln["id"]
                ):
                    raise TypeError(
                        f"{dependency['id']}: malformed OSV vulnerability row"
                    )
            vuln_ids = sorted(vuln["id"] for vuln in vulns)
            entry = {
                "id": dependency["id"],
                "version": dependency.get("version"),
                "scope": dependency.get("scope"),
                "query": dependency["osv_query"],
                "vulnerabilities": vuln_ids,
                "dispositions": [
                    disposition_map[(str(dependency["id"]), vuln_id)]
                    for vuln_id in vuln_ids
                    if (str(dependency["id"]), vuln_id) in disposition_map
                ],
            }
            receipt_dependencies.append(entry)
            if vuln_ids:
                observed.append(entry)
            undisposed.extend(
                (str(dependency["id"]), vuln_id)
                for vuln_id in vuln_ids
                if (str(dependency["id"]), vuln_id) not in disposition_map
            )
        receipt = {
            "schema_version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "source": OSV_QUERY_BATCH if not args.response else str(args.response),
            "inventory_sha256": hashlib.sha256(raw).hexdigest(),
            "dependency_count": len(dependencies),
            "observed_vulnerability_count": sum(
                len(entry["vulnerabilities"]) for entry in observed
            ),
            "undisposed_count": len(undisposed),
            "dependencies": receipt_dependencies,
        }
        rendered = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            print(rendered, end="")
        if undisposed:
            print(
                "undisposed advisory hits: "
                + ", ".join(f"{dep_id}/{vuln_id}" for dep_id, vuln_id in undisposed),
                file=sys.stderr,
            )
            return 1
        return 0
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        print(f"advisory check unavailable: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
