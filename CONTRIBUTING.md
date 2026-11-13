# Contributing

Contributions are welcome. Keep each pull request focused, preserve nginx
style, and include the regression control with every behavior change.

## Before opening a pull request

1. Build the pinned debug target with `ci/tools/ci-build.sh`.
2. Run affected native, Python, Test::Nginx, fuzz, sanitizer, or policy tests.
3. Run `ci/linter/run-all.sh`; do not suppress or weaken a failing control.
4. Update the README when behavior, directives, defaults, or CI changes.

CI has one pull-request entry point, `.github/workflows/ci.yml`. Its reusable
members cover lint, Linux builds and runtime tests, fuzzing, sanitizers,
Valgrind, static scanners, CodeQL, and both Windows toolchains. Expensive deep
campaigns remain scheduled or manually dispatched. Pull-request-reachable jobs
use hosted runners; scheduled maintenance may use the owned pool.

Native fixes need normal, boundary, malformed/error, negative, and compatibility
controls where applicable. A security or correctness regression test must be
seen failing against the faulty behavior before it is credited. New untrusted
parsers need a fuzz target or an explicit evidence-backed reason one cannot
exercise shipped code.

Commits must be signed, use an imperative subject of at most 72 characters, and
contain no authorship trailers unrelated to the human author. Never put secret
values in source, logs, command arguments, commits, or pull-request text.

Security reports and questions that should not be public can be sent to
`github@myguard.nl`.
