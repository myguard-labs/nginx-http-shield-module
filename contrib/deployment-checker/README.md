# Deployment configuration checker

Run the Python 3.11+ companion against an explicit, reviewed configuration
snapshot and deployment contract. It reads files and prints JSON; it does not
start nginx, execute directives, install configuration, inspect live workers or
change the filesystem. First validate the actual deployment with `nginx -t` or
`angie -t` yourself. This companion is an additional configuration analysis,
not an nginx validator or an arbitrary-application safety certificate.

From the Shield checkout, try the shipped safe fixture:

```sh
contrib/check-deployment \
  --root ci/tests/fixtures/deployment-checker \
  --config safe.conf --contract site.json
```

Keep `check-deployment` beside the `deployment-checker` directory when copying
the companion. For a real site, copy a complete snapshot into a private input
directory and adapt the [example contract](../../ci/tests/fixtures/deployment-checker/site.json).
Paths passed as `--config`, `--contract`, includes and handoff policy references
are relative to `--root`, including includes within subdirectories. This matches
nginx's prefix-relative include behavior: choose the input root deliberately.
The checker refuses absolute includes rather than reading arbitrary host files;
adapt the snapshot's include paths locally. It never invokes `nginx -T`, whose
output can contain credentials. Run the checker as an unprivileged user over
trusted, stable regular input files; it does not lock out concurrent writers.

Exit 0 means the supported static analysis found no contradiction with the
supplied contract. Exit 1 means a coverage hole, input failure or unknown.
Exit 2 means invalid command arguments. Unknown input never produces a clean
verdict, even when other scopes were analyzed successfully. An unsupported
include or malformed input stops analysis; earlier diagnostics are partial.

## Declare the analyzed contract

All top-level fields are required; unknown and duplicate JSON keys are errors.
An empty list explicitly declares that the corresponding obligation is absent.
This single contract applies to every analyzed server, including its default
handler and every location; use a separate snapshot for independently declared
sites. Lists and guard policies have at most 128 entries each.

- `version`: integer `1`.
- `required_categories`: fixed Shield category identifiers that must have
  `shield block` and remain unskipped in every server/location.
- `required_body_categories`: categories that must additionally have
  `shield_body on` and a body scanner.
- `approved_scripts`: exact absolute final script strings permitted by the
  PHP execution contract.
- `nonexec_roots`: absolute trees excluded from PHP dispatch, with directory
  boundaries.
- `private_roots`: explicitly private trees under the private-destination recipe.
- `private_dac_verified`: boolean operator assertion that the complete
  private-destination deployment contract has been established.
- `internal_routes`: literal URI prefixes that must have an analyzed internal
  prefix location in every server; public narrower locations are diagnosed.
- `handoffs`: declared final FastCGI guard instances, or an empty list when
  there are no FastCGI handlers.

Category coverage means **configured enablement**, not complete request/body
inspection. Existing content-type admission, scan-byte limits, `NO_BODY`,
source-specific restrictions and other runtime limits remain in force. The
checker reports body requirements for target/header-only categories as holes;
this includes structural categories such as `httpoxy`. It does not promise all
categories inspect all sources. Required categories cover intentional skips too;
leave a legitimately disabled category out of the required list. Every local
and inherited skip is still reported. Multiple local `shield_skip` directives
union their tokens; any nonempty local mask replaces the entire parent mask.
A child with no tokens inherits; an empty directive is invalid.

Each handoff entry has exactly `endpoint`, `mode`, `isolated` and `policy`:

```json
{
  "endpoint": "unix:/run/shield/guard.sock",
  "mode": "block",
  "isolated": true,
  "policy": "handoff.json"
}
```

`policy` is a bounded input file with the final companion's exact `scripts` /
`PHP_VALUE` / `PHP_ADMIN_VALUE` schema; see the
[final-handoff contract](../final-handoff/README.md). Guard script strings must
be approved and outside every nonexec tree. Constant privileged vectors are
compared in order, retaining duplicates and empty values. For a dynamic script,
constant vectors must agree with every candidate policy entry; differing policies
remain unknown because static route selection is not evaluated. Ordinary parameters,
including `HTTP_PHP_VALUE`, are separate names. Conditional or variable
privileged vectors are unknown because this checker does not evaluate nginx.

`mode` and `isolated` are **operator assertions**, not discoveries from nginx
configuration. The operator must verify the actual service uses that exact
policy in block mode, only trusted nginx workers can access its socket, the
PHP backend is reachable exclusively through the companion, and the trusted
script/backend namespace obligations hold. `detect`, `off`, a direct backend,
upstream groups/retry peers, or `fastcgi_keep_conn on` do not satisfy this
analyzed final-handoff contract. Every effective FastCGI handler must use a
declared guard. Local parameter lists replace the whole parent list, so each
handler must retain exactly one unconditional `SCRIPT_FILENAME`.

Constant scripts are checked directly. Built-in variable script expressions
can be accepted only through an isolated block-mode final guard whose entire
policy is within the declared approved/nonexec sets. Their actual final
membership is checked by the **running guard**, never inferred from a URI.
Unknown variables stay nonclean even behind a guard. This is a supported
integration with the [PHP boundary](../php-boundary/README.md), not static
proof of its maps: custom maps, regex script selection and the shipped map/`if`
recipe themselves produce unknown diagnostics in this conservative parser.
They can still be reviewed locally and tested with that recipe's recording
fixture; an unknown checker result does not authorize deployment certification.

For private data, `private_dac_verified` asserts the **entire**
[private-destination contract](../private-destinations/README.md): Linux DAC,
unprivileged dedicated workers without bypass capabilities, separate trusted
owners, correct file/directory modes and ACLs/groups/mounts, no readable copies,
trusted replacement writers, and public files remaining readable. The checker
does not stat private files or infer DAC from path names. Literal root/alias
mappings that can reach a declared private tree are reported, including an
innocuous alias. Dynamic destinations remain unknown. `open_file_cache off`
and `disable_symlinks off` must be retained where that recipe applies, preserving
legitimate public symlinks. Trusted setup before serving and removal of old
open descriptors are external obligations; a clean result cannot prove them.

## Supported configuration and diagnostics

The parser handles main, `events`, `http`, `server` and nested `location` blocks;
literal includes; single/double quoted arguments, comments and nginx escapes;
and the limited directives listed in `INERT` and `SINGLE` in
[check_deployment.py](check_deployment.py). It never expands variables or globs,
reads environment values, loads modules, evaluates regexes or invokes a shell.
Braced variables must have the exact `${name}` form; malformed references are
nonclean even where nginx accepts their bytes as literal parameter names.
Backslash-space remains literal, and a closing brace inside an unquoted word
is data, matching nginx tokenization; only ASCII nginx whitespace separates
arguments. Nested locations inherit the native `internal` flag, while ordinary
URI/named locations select their own content handler; FastCGI/status handlers
are not carried into nested locations automatically.
Compact location modifiers and predicate/variable locations are unsupported.
Only a single-argument `@name` is a named location; a regex pattern beginning
with `@` remains a regex. Unknown directives, custom variables, maps, `if`,
alternate serving modules,
stream/mail configuration and other unmodeled constructs are nonclean.
Known built-in variable tokens can be retained in FastCGI values, but dynamic
root/alias values are unknown. Relative filesystem destinations are unknown.
Run native syntax validation first: accepted inert directives are checked for
context and arity, not every nginx/module-specific value constraint.

Every server/location gets a numeric scope identifier. Diagnostics use fixed
codes/messages, fixed category identifiers and numeric `file`/`line`/`scope`
fields. File 1 is the supplied config; `INCLUDED` at a parent's include line
assigns the next `related_file` number, in encounter order. Repeated includes
receive separate numbers. Contract-wide errors use file/line 0. This lets an
operator locate an issue locally without printing file names, URI patterns,
script paths, upstream endpoints, parameter vectors, credentials or raw errors.
The checker emits no configuration values, including on malformed input or
argument errors. Treat the input snapshot and contract as private.

Declared internal prefixes are checked in every server. Missing declarations,
public exact/prefix descendants and public status handlers (`stub_status` and
`shield_ban_status`) are nonclean. Named locations are inherently internal.
Public regex locations can overlap a declared prefix, so their coverage is
unknown rather than claimed safe. No general route simulation is attempted.

Bounds are fixed per invocation: 65,536 bytes per input file, 1,048,576 total
bytes, 64 file reads including contracts/policies/repeated includes, include
depth 8, total block depth 32, 32,768 total tokens, 4,096 characters per token,
8,192 directives, and 2,048 diagnostics. Limit exhaustion is nonclean. Includes
must stay inside the selected directory with no `..`, symlink components,
devices, FIFOs or directories; reads use nonblocking regular-file checks.
Work is bounded by those limits; no request-path work is added to nginx.

## Focused verification

```sh
python3 ci/tests/test_deployment_checker.py -v
python3 ci/tests/test_deployment_checker.py --faulty-expected -k test_unsafe_golden
```

The first command covers safe/unsafe/unknown fixtures, skip and parameter
inheritance/replacement, final guards, private obligations, internal overrides,
quoting, variables, malformed/oversized input, include traversal/cycles/depth,
special files and redaction. The second must fail with `missing expected
diagnostic`: it deliberately asks for an impossible diagnostic. CI runs both
and checks the specific failure. The suite also checks category/`NO_BODY`
parity against the current native source so future category changes require
an explicit checker update.
