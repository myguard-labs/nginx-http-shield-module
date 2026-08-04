#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Repo-policy checks over .github/workflows/ that no off-the-shelf linter makes.

    ci/linter/workflow_policy.py ports       per-job test port bands
    ci/linter/workflow_policy.py docs        README <-> workflows drift

Each subcommand is wrapped by a ci/linter/lint-*.sh so run-all.sh picks it up by
glob and a human can select it with LINT_ONLY. Exit: 0 clean, 1 findings,
2 could not run.

WHY THESE ARE NOT actionlint OR zizmor RULES. Both of those read a workflow
against GENERAL knowledge -- syntax, and a catalogue of known attack shapes.
The checks here encode facts about THIS repo that no general tool can know:
which port band each job owns, and which files document the pipeline. They are
the checks that go red when a NEW workflow is added without the property every
existing one happens to have -- the case where copying an existing file is the
only thing standing between the repo and a regression, and nothing enforces
the copy.

NO `runners` SUBCOMMAND HERE, unlike the skeleton this was ported from. This
repo already has ci/tools/check-workflow-runners.sh enforcing the identical
trust boundary (no pull_request-reachable workflow may select a self-hosted
runner) against shield's ACTUAL runner-pool inventory. The skeleton's
`runners` check encodes ITS OWN pool labels in a TRUST_SPLITS set; porting
that logic here would create a second, competing source of truth for the same
boundary with a label inventory that has to be kept in sync with the real
one by hand. ci/linter/lint-ci-runners.sh instead wraps
check-workflow-runners.sh directly. See that script and lint-ci-runners.sh
for the runner-trust rule and reasoning.
"""

from __future__ import annotations

import os
import pathlib
import re
import sys

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover - exercised by the selftest doc
    print(
        "workflow_policy: PyYAML not installed (apt-get install python3-yaml).\n"
        "  Refusing to run rather than degrading to a regex scan: every check\n"
        "  here was bypassable by VALID YAML while it parsed workflows by\n"
        "  regex, which is the vacuous-gate shape this file exists to prevent.",
        file=sys.stderr,
    )
    raise SystemExit(2) from None

# WORKFLOW_POLICY_ROOT points the checks at a fixture tree instead of the repo.
# It exists so ci/linter/selftest.sh can assert the FAILING direction of every
# check against a committed, readable fixture -- rather than by planting a file
# in the live .github/workflows/ and hoping the cleanup runs. A check whose red
# path is never exercised is indistinguishable from one that cannot go red.
ROOT = pathlib.Path(
    os.environ.get("WORKFLOW_POLICY_ROOT")
    or pathlib.Path(__file__).resolve().parents[2]
)
WORKFLOWS = ROOT / ".github" / "workflows"


class PolicyError(Exception):
    """Could not run the check (exit 2) -- never confused with "clean"."""


# The runtime driver. A job that starts it is a "runtime-bearing" job and owes
# the port-band declaration checked below.
RUNTIME_DRIVER = "ci/tools/test_runtime.py"

# The band verifier, and everything that BINDS the band. The ordering check
# below needs both: a verify step is only a guard for the binders that come
# after it, and `prove` is a binder even though it is not the runtime driver.
BAND_VERIFIER = "ci/tools/max-port.sh"
# Word-bounded on purpose: a bare "prove" substring also matches `approve`,
# `improve` and `prover`, and a run block that merely says "improve the fixture"
# is not a binder. A shell comment inside a run block still counts -- treating a
# commented-out binder as absent is the safe direction here, since the finding is
# about the step that DOES bind.
BINDERS = (
    re.escape(RUNTIME_DRIVER),
    r"(?<![\w./-])prove(?![\w./-])",
    re.escape("ci/tools/coverage.sh"),
)
BINDER_RE = re.compile("|".join(BINDERS))


def workflows() -> list[pathlib.Path]:
    """Every workflow file, BOTH extensions.

    GitHub reads `*.yml` and `*.yaml` alike. Globbing one of them made all three
    checks below skip a `.yaml` workflow entirely -- an undocumented, unchecked,
    possibly self-hosted PR entry point that reported clean.
    """
    return sorted(
        [*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")],
        key=lambda p: p.name,
    )


def load(path: pathlib.Path) -> dict:
    """Parse a workflow. A file that will not parse is exit 2, never clean."""
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise PolicyError(f"{path.name}: unparsable YAML: {exc}") from exc
    if not isinstance(doc, dict):
        raise PolicyError(f"{path.name}: top level is not a mapping")
    return doc


def events(doc: dict) -> set[str]:
    """The trigger names, from any of the three legal `on:` spellings.

    `on: [pull_request]`, `on: pull_request` and the indented mapping form mean
    exactly the same thing to GitHub. Only the mapping form was recognised
    before, so the two others walked past the runner-trust check.

    PyYAML resolves the bare key `on` to the boolean True (YAML 1.1 truthiness),
    so the True key is where the node actually lands unless it was quoted.
    """
    node = doc.get("on", doc.get(True))
    if isinstance(node, str):
        return {node}
    if isinstance(node, list):
        return {str(e) for e in node}
    if isinstance(node, dict):
        return {str(k) for k in node}
    return set()


def jobs(doc: dict) -> list[tuple[str, dict]]:
    """(name, node) for every job. A non-mapping `jobs:` yields nothing."""
    node = doc.get("jobs")
    if not isinstance(node, dict):
        return []
    return [(str(k), v) for k, v in node.items() if isinstance(v, dict)]


def report(name: str, errors: list[str], ok_msg: str) -> int:
    if errors:
        print(f"{name}: {len(errors)} finding(s)", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        return 1
    print(f"{name}: {ok_msg}")
    return 0


# --------------------------------------------------------------------------
# ports


def _body(node: dict) -> str:
    """A job node re-serialised, for the substring questions asked below.

    The job SPLIT is structural (see jobs()); only the "does this job mention
    the driver / --port" questions are textual, and those are asked of this
    normalised dump rather than of the file. Two consequences, both wanted: a
    comment can no longer hide a job from the split -- `runtime: # note` used
    to yield ZERO jobs and a cheerful "no runtime-bearing jobs" -- and a port
    mentioned only in a comment no longer counts as a declaration.
    """
    return yaml.safe_dump(node, default_flow_style=False, sort_keys=False)


def _steps(node: dict) -> list[str]:
    """Each step's `run:` text, in declaration order. Non-run steps keep their
    slot as an empty string so an index comparison stays an ORDER comparison."""
    out: list[str] = []
    for step in node.get("steps") or []:
        if not isinstance(step, dict):
            out.append("")
            continue
        run = step.get("run")
        out.append(run if isinstance(run, str) else "")
    return out


def _order_finding(where: str, node: dict) -> str | None:
    """A band verifier that runs after something has already bound the band.

    The verify step is not a property of the job, it is a property of a
    POSITION: it can only speak for the steps below it. `build-test.yml` shipped
    it between `prove` and the runtime suite, which reads as guarded and left
    the first binder unguarded -- the failure max-port.sh exists to name still
    arrived inside `prove` as a bind error or a timeout with no cause attached.
    Only jobs that already carry the verifier are checked here; whether a
    binding job must carry one at all is the declaration check above.
    """
    runs = _steps(node)
    verify = next((i for i, r in enumerate(runs) if BAND_VERIFIER in r), None)
    if verify is None:
        return None
    first_bind = next((i for i, r in enumerate(runs) if BINDER_RE.search(r)), None)
    if first_bind is None or first_bind > verify:
        return None
    # Same step: a multi-line `run:` block may legitimately verify and then bind.
    # Index order cannot separate those, so fall back to position within the text.
    if first_bind == verify:
        run = runs[verify]
        if run.index(BAND_VERIFIER) < BINDER_RE.search(run).start():
            return None
        return (
            f"{where} binds the band earlier in the same step than it runs "
            f"{BAND_VERIFIER} (step {verify + 1}) -- verify first, then bind"
        )
    return (
        f"{where} runs {BAND_VERIFIER} at step {verify + 1}, after step "
        f"{first_bind + 1} has already bound the band -- the verifier only "
        "guards the steps below it, so move it above the FIRST binder"
    )


def check_ports() -> int:
    errors: list[str] = []
    bands: dict[str, str] = {}  # port value -> "file:job" that claimed it

    for path in workflows():
        doc = load(path)
        for job, node in jobs(doc):
            body = _body(node)
            declared = re.search(r"(?m)^\s*TEST_BASE_PORT:\s*[\"']?(\d+)", body)
            starts_runtime = RUNTIME_DRIVER in body
            where = f"{path.name}:{job}"

            order = _order_finding(where, node)
            if order:
                errors.append(order)

            # THE CHECK THAT MATTERS MOST. A new runtime-bearing job added later
            # with no band is invisible to the uniqueness check below (it
            # declares nothing to collide), silently takes the driver's default
            # --port, and reintroduces exactly the cross-job collision the bands
            # exist to prevent: two jobs pinned to the same runner, disjoint
            # concurrency groups, nothing serialising them, both binding 18880.
            if starts_runtime and not declared:
                errors.append(
                    f"{where} starts {RUNTIME_DRIVER} without declaring "
                    "TEST_BASE_PORT -- it would take the driver's default port "
                    "and collide with any other runtime job on the same runner"
                )
                continue

            if not declared:
                continue

            port = declared.group(1)
            if port in bands:
                errors.append(
                    f"{where} and {bands[port]} both claim TEST_BASE_PORT "
                    f"{port} -- bands must be disjoint across ALL workflows"
                )
            else:
                bands[port] = where

            # A declared band that is not passed through is decoration: the
            # driver still binds its default.
            if starts_runtime and "--port" not in body:
                errors.append(
                    f"{where} declares TEST_BASE_PORT but never passes --port; "
                    "the driver would bind its default anyway"
                )
            if starts_runtime and "TEST_BASE_PORT" not in body.split("--port")[-1][:40]:
                errors.append(
                    f"{where} passes --port with something other than "
                    "$TEST_BASE_PORT -- the declaration and the bind must be "
                    "the same value or they drift"
                )

    return report(
        "lint-ci-ports",
        errors,
        f"{len(bands)} runtime job(s), all with distinct port bands"
        if bands
        else "no runtime-bearing jobs",
    )


# --------------------------------------------------------------------------
# docs


def check_docs() -> int:
    """Every workflow is documented, and every documented workflow exists.

    The drift this catches is silent in both directions and neither direction
    fails anything else: a workflow added without a README row is a gate nobody
    knows exists (so nobody notices when it is later removed), and a README row
    for a deleted workflow is a badge that 404s and a claim of coverage the repo
    does not have. Structural facts only -- deliberately NOT exact job counts or
    durations, which are the brittle claims that get a drift check deleted.
    """
    errors: list[str] = []
    readme = ROOT / "README.md"
    if not readme.is_file():
        print("lint-docs-drift: no README.md", file=sys.stderr)
        return 2
    text = readme.read_text(encoding="utf-8")

    names = {p.name for p in workflows()}
    for name in sorted(names):
        if name not in text:
            errors.append(
                f"{name} exists under .github/workflows/ but is not mentioned "
                "in README.md -- an undocumented gate"
            )
    # Only PATH-QUALIFIED references. A bare "ci.yml" in prose could mean any
    # file; ".github/workflows/ci.yml" is unambiguously a claim that this repo
    # has that workflow, which is the claim worth checking.
    for ref in sorted(set(re.findall(r"\.github/workflows/([\w.-]+\.ya?ml)", text))):
        if ref not in names:
            errors.append(
                f"README.md references .github/workflows/{ref}, which does not "
                "exist -- a dead link or a stale badge"
            )
    return report(
        "lint-docs-drift",
        errors,
        f"{len(names)} workflow(s), all documented in README.md",
    )


COMMANDS = {
    "ports": check_ports,
    "docs": check_docs,
}


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in COMMANDS:
        print(f"usage: {argv[0]} {{{'|'.join(COMMANDS)}}}", file=sys.stderr)
        return 2
    if not WORKFLOWS.is_dir():
        print(f"no {WORKFLOWS} -- wrong tree?", file=sys.stderr)
        return 2
    try:
        return COMMANDS[argv[1]]()
    except PolicyError as exc:
        # 2, not 1: the check did not RUN. A workflow this file cannot parse is
        # also a workflow GitHub may read differently, so reporting "clean" or
        # even "findings" over the rest of the tree would be a claim the run
        # cannot support.
        print(f"workflow_policy: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
