# Local lint gate

`ci/linter/run-all.sh` runs every tracked `lint-*.sh` checker and reports their
results in deterministic order. `.githooks/pre-commit` invokes the staged form.

Important entry points:

- `run-all.sh` — full, staged, selected-file, or `LINT_ONLY` dispatch;
- `selftest.sh` — positive and negative controls for the gate itself;
- `install-linters.sh` — install or check pinned/local tools;
- `lint-c.sh` and `lint-nginx.sh` — C security and nginx-style checks;
- `lint-directives.sh` — source-to-README directive parity;
- `lint-ci-*.sh` — workflow cadence, runner trust, port, and docs policy;
- language checkers — ShellCheck/shfmt, Ruff, Perl::Critic, YAML/actionlint/zizmor,
  codespell, and generated-asset drift.

Run:

```sh
ci/linter/install-linters.sh --check
ci/linter/selftest.sh
ci/linter/run-all.sh
LINT_ONLY="c nginx directives" ci/linter/run-all.sh
```

Exit 0 means all selected checks ran cleanly, 1 means findings, and 2 means the
gate could not run (for example, a missing tool or an empty selector). A missing
tool is never treated as a clean scan. `clang-tidy` and GCC `-fanalyzer` use the
real compilation database in remote security-scanner CI; `.clang-tidy` is the
single tracked check profile. Local and remote Semgrep are pinned to 1.184.0 and
use bounded single-job execution with metrics disabled where the gate invokes
Semgrep directly.
