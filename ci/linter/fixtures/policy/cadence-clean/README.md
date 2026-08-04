# fixture: cadence-clean

Positive control for `lint-ci-cadence`. A `pull_request` entry point calling one
`workflow_call`-only member, plus a scheduled scan that is NOT a member.

Without this, a red on `member-reruns-on-push` could be the fixture shape rather
than the bypass. It also pins the deliberate exemption: `schedule` on a
non-member is allowed, because a periodic scan is not a merge gate.
