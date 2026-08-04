# fixture: a workflow with the .yaml extension

GitHub reads `*.yml` and `*.yaml` alike; `workflows()` used to glob `*.yml`
only, so this self-hosted, PR-triggered, undocumented workflow was invisible to
every policy check. `docs` must go red here (this repo's `workflow_policy.py`
carries no `runners` subcommand -- see `ci/linter/lint-ci-runners.sh`).

The documented workflow list deliberately mentions no file: `docs` must report
the undocumented gate.
