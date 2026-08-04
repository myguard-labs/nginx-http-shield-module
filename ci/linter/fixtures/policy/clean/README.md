# fixture: clean

Positive control for ci/linter/selftest.sh. Both policy checks this repo
carries (`ports`, `docs`) must report clean against this tree, so that a RED
result on a sibling fixture is attributable to the bypass that fixture encodes
and not to the fixture shape.

Workflow: `.github/workflows/ci.yml`.
