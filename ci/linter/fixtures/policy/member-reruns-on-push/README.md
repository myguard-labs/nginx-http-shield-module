# fixture: member-reruns-on-push

Encodes the bypass `lint-ci-cadence` exists to catch: `gate.yml` is a perfectly
well-formed `workflow_call` member of the `pull_request` entry point AND carries
its own `push: branches: [main]` trigger.

Both runs are green in real life, which is why nothing else notices. The second
one tests a merge commit identical to the PR head that already passed, and the
differing concurrency keys mean `cancel-in-progress` does not collapse them.

`second-entry.yml` covers the other half of the rule: a called member that also
declares its own `pull_request:` trigger, so a single PR runs it twice.

Red on the current checker. A checker that only looked at file names, or that
assumed every `workflow_call` file is a member, walks straight past both.
