# Deploying Shield

Shield is a compiled request filter for nginx and Angie. This guide covers a
first deployment and a local policy change. The [README](../README.md) remains
the directive and scanner reference.

## 1. Establish the application boundary

Build the module against the source and build options for the deployed server,
then follow the [installation instructions](../README.md#install). Save the
module commit, server version and reviewed configuration with the deployment. A
log's `build` field identifies nginx, not the module commit.

Identify the locations that accept uploads, code snippets, JSON APIs and
compressed request bodies. Check trusted-proxy configuration before attributing
a client address. Shield does not replace patching, nginx request-size limits,
application authorization or PHP execution restrictions.

## 2. Start with detection and a private metrics endpoint

Use the [detect-only example](../README.md#configuration). Keep the
application's existing handler. Validate the complete configuration with `nginx
-t` or `angie -t`, reload through the site's normal procedure, and exercise
legitimate requests before enabling enforcement. Include administration,
scheduled clients, uploads and API requests in that trial.

`shield detect` records enforceable matches without rejecting for those
matches. It also leaves requests unchanged on internal inspection errors.
An attached ban policy still counts hits and refuses already-banned clients.
The default `shield off` does no inspection. Enable `shield_log` explicitly if
you need its
JSON feed; normal nginx access logs have their own privacy policy.

Use a counters-only `shield_stats_zone` when bans are unnecessary. Protect the
status location with access controls and set `shield off` there. Size every
shared zone for at least eight host memory pages: the `64k` example needs
`128k` or more on a host with 16 KiB pages. Do not expose client-address ban
lists or operational counters publicly.

## 3. Choose the body policy deliberately

`shield_body` defaults to on. Eligible bodies are scanned only up to
`shield_max_body`, which defaults to `8k`. Larger bodies continue after that
prefix is inspected; bytes beyond the budget remain uninspected. Enforce upload
size separately with nginx's `client_max_body_size`. Unknown and binary media
types are outside the body scanner.

Several categories are target/header-only because code and path examples are
ordinary body content. `shield_body_strict on` does not change those
exclusions. See the [source-specific
policy](../README.md#not-every-category-is-scanned-in-the-body).

Eight additional body markers are ambiguous: `%c0%af`, `union select`,
`{"$where":`, `{{7*7}}`, `169.254.169.254`, `/latest/meta-data/`, `<!--#include
virtual` and `!ruby/object:`. By default they emit local `suspicious`/`observe`
notices to file sinks. They do not reject, count toward bans, increment attack
counters or enter the JSON reporter feed. This remains true in `shield block`
mode.

The tradeoff is real: an attack relying only on these markers can pass with the
default policy. Enable `shield_body_strict on` only where the actual SQL,
template, fetch, SSI, YAML or other evaluating sink justifies enforcement. The
setting changes all eight markers together and inherits per location. Other
enforceable matches still take precedence over observation.

Choose `shield_cve` profiles only for the corresponding application. They are
off by default and inspect the documented forms, not every exploit of a named
CVE. Gzip inspection is also off by default and needs the [backend integrity
contract](../README.md#optional-gzip-request-inspection). It does not rewrite
forwarded request bytes or add Brotli/response inspection.

## 4. Enable one location, then measure

After reviewing legitimate traffic, change one location to `shield block`. A
configured match normally returns `shield_status` (403 by default). An internal
allocation or body-file read error returns 500 in block mode. A documented scan
cap is incomplete inspection, not that internal error.

Watch both failure and incomplete-inspection counters. They describe different
conditions: the former needs fault investigation; the latter tells you where
the declared inspection boundary was reached. Do not interpret either a quiet
log or a successful request as proof of complete coverage.

Increase body budgets only after measuring the deployed build and traffic mix.
Scanning and normalization consume CPU and request-pool memory synchronously in
an nginx worker. The automaton avoids a separate pass per signature; it does
not make an arbitrarily large body cheap.

## 5. Keep exceptions narrower than trust

A local nonempty `shield_skip` list replaces the inherited list; it does not
append to it. A child without a local list inherits its parent's. Skipping a
category affects every eligible surface, so it is broader than changing the
eight-marker body policy.

`shield_allow` is broader still: a matching address bypasses all Shield checks,
bans, counters and hit logs. Trust only a validated connection address. An
untrusted forwarded header must never select an allowlisted identity.

If a trial needs bans, use a separate trial zone and attach policies at the
intended locations. There is no `shield_ban off` override for an inherited ban
policy. Follow the exact [trial and rollback
recipe](../README.md#scoped-trial-and-rollback) to keep production bans and
counters separate.

Rollback changes future policy; it does not undo past responses, erase shared
bans or recall an external report. `shield detect` alone does not stop refusals
from active bans or stop new bans accumulating. Detach the trial location's
`shield_ban` binding and reload, then verify the new workers and wait for old
workers to drain. Follow steps 4 and 5 of the [trial and rollback
recipe](../README.md#scoped-trial-and-rollback) before retiring the trial zone.
Validate and reload the complete configuration each time.

## 6. Read evidence without exporting request content

The [hit log](../README.md#hit-log) includes client IP, category, source, mode,
status, static rule identity and byte view. `req` is always empty. Request
targets, bodies, cookies, authorization values and hashes of those values are
omitted. Rule fingerprints identify public predicate definitions, not request
content or proof of exploitation. IP addresses still need appropriate access
controls and retention.

Observation notices are separate from the JSON hit feed. `signature-match`
means a predicate matched, not that a vulnerable sink executed. An inspection
error is different again. Keep those distinctions in dashboards and alerts.

The optional AbuseIPDB reporter is a separate process. Its reviewed promotion
registry is currently empty, so current signature matches, detections,
observations and legacy records send no reports. Do not loosen that registry to
make the counter rise. Future promotion needs exact reviewed identity and
producer evidence; the public comment is constant and contains no request text.
See the [reporter setup and state
contract](../README.md#reporting-to-abuseipdb).

## 7. Validate deployment controls separately

The [PHP boundary](../contrib/php-boundary/README.md),
[private-destination](../contrib/private-destinations/README.md) and [final
FastCGI handoff](../contrib/final-handoff/README.md) companions protect
different deployment contracts. None is enabled by loading Shield. Follow and
test the full recipe for the chosen server and application.

The [deployment checker](../contrib/deployment-checker/README.md) reads an
explicit configuration snapshot and contract without starting nginx. A clean
result covers only its supported static analysis. Unsupported or unknown inputs
fail the check; it cannot certify arbitrary application behavior.
