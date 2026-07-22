# nginx-http-shield-module

[![Build and Test](https://github.com/myguard-labs/nginx-http-shield-module/actions/workflows/build-test.yml/badge.svg)](https://github.com/myguard-labs/nginx-http-shield-module/actions/workflows/build-test.yml)
[![Security scanners](https://github.com/myguard-labs/nginx-http-shield-module/actions/workflows/security-scanners.yml/badge.svg)](https://github.com/myguard-labs/nginx-http-shield-module/actions/workflows/security-scanners.yml)
[![Fuzzing](https://github.com/myguard-labs/nginx-http-shield-module/actions/workflows/fuzzing.yml/badge.svg)](https://github.com/myguard-labs/nginx-http-shield-module/actions/workflows/fuzzing.yml)
[![Valgrind](https://github.com/myguard-labs/nginx-http-shield-module/actions/workflows/valgrind.yml/badge.svg)](https://github.com/myguard-labs/nginx-http-shield-module/actions/workflows/valgrind.yml)
[![CI Deep](https://github.com/myguard-labs/nginx-http-shield-module/actions/workflows/ci-deep.yml/badge.svg)](https://github.com/myguard-labs/nginx-http-shield-module/actions/workflows/ci-deep.yml)
[![CodeQL](https://github.com/myguard-labs/nginx-http-shield-module/actions/workflows/codeql.yml/badge.svg)](https://github.com/myguard-labs/nginx-http-shield-module/actions/workflows/codeql.yml)

> 📖 **Read the article:** [nginx-http-shield-module: Block Ancient Exploits Without a WAF](https://deb.myguard.nl/articles/nginx-http-shield-module/)
> — what it blocks, why the engine is an Aho-Corasick automaton, and how to roll it out from `detect` to `block`.

A small nginx dynamic module that blocks exploitation of web vulnerabilities
that were **patched years ago** — SQL injection, ancient PHP/Java RCE chains,
Log4Shell, Shellshock, path traversal, cloud-metadata SSRF, and more.

It is deliberately **not a general-purpose WAF**. There is no rules language,
no regex engine, no external ruleset to keep updated — just a fixed set of
compiled-in signatures, each chosen so that **no legitimate client ever sends
it**. That keeps the false-positive rate near zero and makes it safe to switch
on in front of a large, mixed, not-fully-patched customer base, where a
full WAF like ModSecurity or Coraza would be too heavy or too noisy to run
everywhere.

Think of it as a **legacy-exploit floor**: cheap, always-on, catches the
internet background radiation of exploit scanners hammering CVEs from 2012.
Run a real WAF on top where you need one.

## What it blocks

29 categories (633 signatures), all matched case-insensitively after
percent-decoding:

| Category | Examples |
|----------|----------|
| `sqli` | `union select` plus comment/control-whitespace evasions, `' or 1=1`, `into outfile`, time-based calls in quote or operator context (`' and sleep(`, `;sleep(`, `pg_sleep(`, `benchmark(`, `waitfor delay`), database escape APIs such as `sp_oacreate` and `pg_read_file(` |
| `xss` | `<script`, `javascript:`, entity-encoded `javascript&#x3a;`, `data:text/html`, `onerror=`, `onpointerenter=` |
| `traversal` | the traversal **gadget**: `../`, `..\`, `..;/`, `.%2e/` (CVE-2021-41773), `....//` |
| `overlong` | overlong-UTF-8 `/`, `\`, `.` and NUL in every width (`%c0%af`, `%e0%80%af`, `%f0%80%80%af`, `%c1%9c`, `%c0%80`), IIS `%u002f` — illegal UTF-8 by definition, so attack-only |
| `cmdi` | `;wget`, `&&curl`, `\|\|wget`, `$(whoami`, `/bin/sh`, `powershell.exe -enc`, `/winnt/system32` |
| `lfi` | `php://filter`, `data://`, `expect://`, `phar://` |
| `crlf` | `%0d%0a`, response-splitting `\r\nSet-Cookie:` |
| `nullbyte` | `%00`, `%u0000`, double- and triple-encoded `.` / `/` / `\` (`%252e`, `%25252f`, `%25%32%65`) |
| `template` | `${jndi:` + `jndi:ldap/rmi/dns/iiop`, `${env:`, `${::-`, nested `${${` |
| `deserial` | Java stream magic, gadget classes (`jdbcRowSetImpl`, `TemplatesImpl`, commons-collections), Fastjson `@type` autotype, WebLogic/XStream, Joomla obj-injection (CVE-2015-8562), XXE `<!entity` |
| `shellshock` | the exported-function prologue with a **shell** body — `() { :;}` and its spacing variants, `() { echo`, `() { /bin/`, CVE-2014-6278's `() { _;} >_[$($())]`. Not the bare `() {`: that is also JavaScript's anonymous-function token, and this module scans `text/*` and JSON bodies |
| `php_rce` | PHP-CGI `-d allow_url_include` (CVE-2012-1823), PHPUnit `eval-stdin.php`, ThinkPHP |
| `java_rce` | Struts OGNL `%{(#` (CVE-2017-5638), Spring4Shell `class.module.classloader`, Confluence OGNL `@java.lang.runtime@getruntime().exec(` (CVE-2022-26134) |
| `java_eval` | `java.lang.runtime`, `getruntime().exec` |
| `rails_yaml` | `!ruby/object:`, `!ruby/hash:` (CVE-2013-0156) |
| `drupal` | `[#post_render]`, `[#markup]` (Drupalgeddon2, CVE-2018-7600) |
| `vbulletin` | `widgetConfig[code]` (CVE-2019-16759) |
| `xmlrpc` | `system.multicall` (WordPress credential-stuffing) |
| `ssi` | `<!--#exec`, `<!--#include virtual` |
| `imagetragick` | `push graphic-context` (CVE-2016-3714) |
| `httpoxy` | a request-borne `Proxy:` header (CVE-2016-5385) |
| `range_dos` | a `Range:` header with more than 10 ranges (CVE-2011-3192) |
| `ctrl_char` | a C0 control byte in the decoded path (`%01`, `%1b`, …) — nginx itself rejects the *raw* form, so only the encoded one gets this far |
| `sensitive_file` | `/.env`, `/.git/`, package/cloud/CLI credential stores, Terraform state, AI-agent config dirs, and traversal **targets** — `/etc/passwd`, `/proc/self/maps`, `/etc/ssh/sshd_config`, `win.ini` |
| `webshell` | `c99.php`, `r57.php`, `wso.php`, `weevely`, `behinder`, `shell.php?cmd=` |
| `ssrf_meta` | cloud metadata hosts/paths, IMDSv2 tokens/credentials, Unicode-dot/IP-number evasions, wildcard-DNS forms, and loopback Docker/etcd/Lambda control endpoints |
| `nosql` | MongoDB operator injection `[$ne]`, `[$where]`, `{"$where":`, `$func:` |
| `ssti` | template-probe forms `{{7*7}}`, `${7*7}`, `{{''.__class__`, `<%= 7*7`, `#set($` |
| `exploit_path` | fixed n-day paths: `/wls-wsat/`, `/remote/fgt_lang`…`sslvpn_websession`, `/actuator/gateway/routes`, `/_ignition/execute-solution`, `/api/jsonws/invoke`, F5 `/tmui/login.jsp/..;/` (CVE-2020-5902), vCenter `uploadova` (CVE-2021-21972), Citrix `/vpn/../vpns/` (CVE-2019-19781), OFBiz `/webtools/control/xmlrpc`, Ivanti `user-backup-code/..`, GPON/HNAP/Zyxel probes |

What is inspected: the request line and query string; `User-Agent` and
`Referer` with the full ruleset; `Content-Type` for header-borne exploits such
as Struts OGNL; URI-bearing `Destination`, `X-Original-URL` and `X-Rewrite-URL`
with the full ruleset; injection-shaped cookie values; and every other
request-header value for Log4Shell and Shellshock. Opaque header values
deliberately do not run short gadget/webshell tokens that would eventually
collide with random credentials or multipart boundary entropy. When enabled,
text-shaped request bodies are inspected too.

What is **not** done: scanner-name blocking (User-Agent strings like `sqlmap`
are trivially spoofed, so they are not matched — but payloads carried *inside*
those headers, like Shellshock, are).

## Install

Build as a dynamic module against your nginx (or Angie) source:

```sh
./configure --add-dynamic-module=/path/to/nginx-http-shield-module
make modules
```

Then load it:

```nginx
load_module modules/ngx_http_shield_module.so;
```

Or use the helper for a throwaway build:

```sh
tools/ci-build.sh nginx 1.31.3        # dynamic .so under .build/
```

## Configuration

```nginx
http {
    # Turn on globally in detect mode first, watch the logs, then switch to block.
    shield detect;

    # Optional: a shared-memory zone for the repeat-offender ban list.
    shield_ban_zone shield:10m;

    server {
        location / {
            shield block;          # off | detect | block
            shield_body on;        # inspect request body (default on)
            shield_max_body 8k;    # bytes of body scanned (default 8k)
            shield_status 403;      # 403 | 404 | 419 | 429 | 444 (default 403)
            shield_log /var/log/nginx/shield.json;  # JSON hit log (off by default)

            # Ban an IP for 1h once it trips 5 signatures within 1 minute.
            shield_ban zone=shield count=5 window=1m bantime=1h;
        }

        location /legacy-app/ {
            shield block;
            shield_skip sqli xss;  # disable specific categories here
        }
    }
}
```

### Directives

| Directive | Context | Default | Description |
|-----------|---------|---------|-------------|
| `shield` | http, server, location | `off` | `off` disables; `detect` logs only; `block` rejects. |
| `shield_body` | http, server, location | `on` | Inspect the request body (text-shaped content types only). |
| `shield_max_body` | http, server, location | `8k` | Bytes of body scanned. Larger bodies are passed through unscanned — uploads are never blocked for being big. **Raise with care:** scan cost is linear in this value and the body is attacker-controlled (see [Cost](#cost)). |
| `shield_status` | http, server, location | `403` | Status returned in `block` mode. One of 403, 404, 419, 429, 444. |
| `shield_skip` | http, server, location | — | Space-separated category names to disable (see table above, plus `httpoxy`, `range_dos` and `ctrl_char`). A child block that sets `shield_skip` **replaces** the inherited list wholesale (masks do not merge); a child that omits it inherits the parent's. An empty child cannot clear an inherited skip — to un-skip, re-state the categories you still want disabled. |
| `shield_log` | http, server, location | — | Append one JSON object per hit (block **and** detect) to a **file** or a **syslog** server, for out-of-band reporting (e.g. AbuseIPDB). `off` disables. See [Hit log](#hit-log). |
| `shield_ban_zone` | http | — | Define a shared-memory zone `name:size` (e.g. `shield:10m`) for the ban list. See [Repeat-offender banning](#repeat-offender-banning). |
| `shield_ban` | http, server, location | — | `zone=<name> count=<n> window=<time> bantime=<time>` — ban a client for `bantime` once it produces `count` shield hits within a fixed `window`. |

### Repeat-offender banning

In block mode, a single shield hit blocks that request. `shield_ban` escalates a **persistent**
attacker to a hard ban: after `count` hits inside a `window`, the client
IP is refused for `bantime` — with the configured `shield_status`, **before any
signature scanning**, so a known-bad IP costs only a shared-memory lookup.

The `window` is **fixed (tumbling), not sliding**: the first hit starts it, and
once it elapses the counter resets wholesale rather than ageing out individual
hits. An attacker who paces hits across a window boundary — `count - 1` at the
end of one window and `count - 1` at the start of the next — stays under the
trigger. Size `window` for the burst you want to catch rather than assuming a
rolling count.

```nginx
http {
    shield_ban_zone shield:10m;          # one zone, shared by all workers
    server {
        location / {
            shield block;
            shield_ban zone=shield count=5 window=1m bantime=1h;
        }
    }
}
```

- **What counts as a hit:** any shield signature trip, in **both** `block` and
  `detect` mode — so a detect-only deployment can still ban repeat attackers
  while it stays in observation mode for everyone else.
- **Keyed on the client IP** (IPv4 or IPv6), stored in the shm zone, shared
  across all worker processes. A `10m` zone holds on the order of 10⁵ addresses;
  the least-recently-seen entries are evicted when it fills.
- **The ban takes effect on the attacker's _next_ request** — the hit that
  reaches the threshold is still handled on its own merits.
- **`window` and `bantime`** take nginx time units (`s`, `m`, `h`, `d`).
- Put `shield_ban_zone` in the `http{}` block once; reference it by name from as
  many locations as you like. **One policy per zone:** a zone holds a single
  `hits`/`window`/`banned_until` state per client IP, so all locations sharing a
  zone must use the same `count`/`window`/`bantime` — mixing different policies
  against one zone cross-applies whichever location handled the request and
  corrupts the count. Locations that need different policies must each reference
  their own zone.
- **Zone state is per-instance and non-persistent.** The shm zone is an anonymous
  mapping: it does not survive a binary upgrade or a full restart, and bans are
  lost with it. A reload keeps the zone (and so the bans) as long as the zone
  name and size are unchanged.
- **Shared-zone availability:** every zone access takes the zone's slab mutex,
  so a worker killed (`SIGKILL`, OOM) while holding it leaves the mutex held and
  further access to that zone blocks — the same exposure as nginx's own
  `limit_req`/`limit_conn` zones, which use the identical slab-mutex pattern. No
  code path here can hold the lock across an operation that blocks or faults:
  the critical sections are bounded rbtree/queue work with no allocation beyond
  `ngx_slab_alloc_locked` and no I/O. Recovery is a restart.

### Hit log

`shield_log /var/log/nginx/shield.json;` writes one JSON object per line for
every hit, in both `block` and `detect` mode:

```json
{"ts":"2026-07-17T14:22:05+02:00","ip":"203.0.113.7","cat":"sqli","src":"uri","mode":"block","status":403,"req":"GET /?id=1 union select pw HTTP/1.1"}
```

Fields: `ts` (ISO-8601 with timezone — AbuseIPDB's `timestamp`), `ip` (the peer;
map `X-Forwarded-For` in the reporter if behind a trusted proxy), `cat` shield
category, `src` where it matched (`uri`/`user-agent`/`body`/…), `mode`, `status`
(0 in detect mode), and `req` the request line. `req` is the only
attacker-controlled field: it is JSON-string-escaped (`"`, `\`, and every byte
below `0x20` become `\uXXXX`), so a hostile request line can neither inject a
second record nor break the JSON. The file is reopened on `SIGUSR1`
(logrotate-safe).

**No `| command` form.** shield runs in `PRECONTENT` on every request inside
root-started workers; piping attacker-influenced bytes into a forked shell would
reintroduce exactly the command-injection and fork-storm/DoS class this module
exists to block — so `shield_log "| ..."` is rejected at config load. Log to a
file and let a **separate, unprivileged** process tail it and call the reporting
API. That process owns the API key, rate-limiting, IP de-duplication and
private-IP suppression — none of which belong on the request hot path. For
AbuseIPDB, map each `cat` to a category ID (most → `21` Web App Attack; `sqli`
also → `16` SQL Injection).

#### Syslog transport

Instead of a file, ship the same JSON records to a syslog server:

```nginx
shield_log syslog:server=10.0.0.1:514,tag=shield,nohostname;
```

The `syslog:` options are nginx's standard [`ngx_syslog`
set](https://nginx.org/en/docs/syslog.html) (`server=`, `facility=`, `tag=`,
`severity=`, `nohostname`). One datagram per hit (capped at 4096 bytes, no
trailing newline — syslog frames it). File and syslog are mutually exclusive per
directive; use `off` to disable, and a child `off` overrides an inherited
parent.

#### Reporting to AbuseIPDB

`reporter/abuseipdb-reporter.py` is a ready-to-run reporter for the file sink. It
tails the JSON log (surviving logrotate via an inode/offset state file), skips
private/loopback/reserved IPs, de-duplicates each IP for 15 minutes (matching
AbuseIPDB's own per-IP limit), enforces a daily cap (default 1000, the free
tier), maps the shield category to AbuseIPDB IDs, and POSTs to
`/api/v2/report`. The public report comment carries only `METHOD /path` — the
query string is stripped, since URLs routinely carry tokens/PII you must not
forward to a third party. Suppression and daily-cap state are persisted, so a
restart cannot reset them and overrun the quota; a 429 or network failure backs
off (honouring `Retry-After`) and the unsent line is retried, not dropped. The
API key comes from `ABUSEIPDB_API_KEY` in the environment — never the command
line. A hardened `systemd` unit is provided:

```bash
sudo cp reporter/abuseipdb-reporter.py /usr/local/bin/shield-abuseipdb-reporter
sudo cp reporter/shield-abuseipdb-reporter.service /etc/systemd/system/
sudo install -m600 /dev/null /etc/shield-abuseipdb.env
sudoedit /etc/shield-abuseipdb.env    # add: ABUSEIPDB_API_KEY=...  (editor, not echo)
sudo systemctl enable --now shield-abuseipdb-reporter
```

Use `--dry-run` to see exactly what would be sent without calling the API. The
reporter's suppression, backoff, PII-strip and offset-persistence logic are
covered by `reporter/test_abuseipdb_reporter.py` (run `pytest reporter/`), which
also runs as a CI gate.

### Rollout

1. `shield detect;` at the `http` level.
2. Watch `error.log` for `shield: detected attack ...` lines. Each names the
   `category` and `source` but never echoes attacker bytes (log-injection safe).
3. If a legitimate request trips a category, `shield_skip` it in that location.
4. Switch to `shield block;`.

## How it works

The module runs in the `PRECONTENT` phase. For each request it builds two
normalized copies of every inspected input — a lowercased raw copy and a
percent-decoded (once), `+`→space, lowercased copy — and runs every enabled
category's patterns over them in a **single Aho-Corasick pass per buffer**. Three
categories (`httpoxy`, `range_dos`, `ctrl_char`) are structural checks rather than
literal matches. There is no regex and no per-request allocation beyond the two
scratch buffers per inspected value, so the cost is a few microseconds on
typical request sizes.

Body inspection reads the buffered request body (up to `shield_max_body`) and
scans it the same way, then resumes phase processing — the same mechanism the
stock `ngx_http_mirror_module` uses.

Scannable media types include form and multipart data, `text/*`, JSON and XML,
structured `application/*+json` / `application/*+xml` types, GraphQL, NDJSON,
JSON text sequences, and YAML. Binary and unknown application media types are
left alone.

### Not every category is scanned in the body

A signature's meaning depends on **where** it appears.

A request *target* containing `/bin/sh` is an attack — there is no reading of a
URI in which that string is content. A `text/…` or `application/json` **body**
containing `/bin/sh` is a Tuesday: it is a CI config, a Dockerfile paste, a
shell script in an editor, a snippet in a docs API. The same is true of
`<script` and `document.cookie` in a CMS saving a page, of `${jndi:` in a blog
post *about* Log4Shell, and of `<?php system(` in a code-review tool.

So each category declares whether its tokens are attack-only in *any* position,
or only in a request target. Ten are request-target-and-header only:

`cmdi` · `xss` · `template` · `lfi` · `php_rce` · `java_rce` · `java_eval` · `sensitive_file` · `exploit_path` · `traversal`

`traversal` is on that list because its signatures are pure gadgets (`../`,
`..\`, `..;/`) that legitimately appear in bodies — a JSON source map or an
asset manifest carrying `{"path":"../logo.png"}` is not an attack. In a request
target the same token has no benign reading.

Every other category is scanned in the body too, and that is where the body scan
earns its keep — SQL injection in a form POST, the Java deserialization gadget
classes, SSI injection, webshell names, and the encoding-evasion categories.
None of those have a benign reading in a body either.

This narrows *where* a category applies, never *whether* it matches: a
body-exempt category still blocks at full strength in the request target and in
the scanned headers. It costs nothing at runtime — the exempt set is folded into
the same skip bitmask `shield_skip` already uses, so there is still one
automaton and one lookup per byte.

It is also why `/etc/passwd` is a `sensitive_file` and not a `traversal`:
traversal owns the *gadget* (`../`), `sensitive_file` owns the *target*. They
were previously in the same table, which made the filename impossible to exempt
from the body scan without also exempting `../`.

### AND-rules

Some exploits are only distinguishable from ordinary traffic by a *combination*
of tokens. Grafana's path-traversal CVE-2021-43798 rides on `/public/plugins/`
— which is also how every Grafana instance serves its plugin assets on every
page load. As a plain signature it blocks the product; left out, the exploit is
uncovered. Neither is acceptable for a near-zero-FP floor.

An **AND-rule** requires a *set* of terms to co-occur in the same buffer before
its category fires:

> **Same buffer, literally.** The request line/query and the body are scanned
> independently, with no term state carried between them, so an AND-rule whose
> terms arrive in different parts of the request cannot fire. A rule that pairs
> a request *path* with a *body* gadget is dead by construction — pick terms
> that travel together (this is why `metabase_jdbc_rce` keys on the H2 INIT
> gadget rather than on Metabase's setup endpoint).

| Rule | Category | Fires only when the buffer has… |
|---|---|---|
| `ofbiz_authbypass` | `exploit_path` | `requirepasswordchange=y` **and** `/webtools/control/` |
| `metabase_jdbc_rce` | `deserial` | `jdbc:h2:` **and** `init=` |
| `jenkins_cli_read` | `exploit_path` | `/cli?` **and** `remoting=true` |
| `vmware_wsone_ssti` | `exploit_path` | `/catalog-portal/ui/oauth/verify` **and** `${` |
| `ssrf_wildcard_dns` | `ssrf_meta` | `.nip.io` **and** `169-254-169-254` |

Rule terms are **not** signatures: a term never fires on its own, and none of
the left-hand tokens above will block a request by itself. That is checked
in both directions — `t/07-and-rules.t` proves the full set blocks, and
`t/05-fp-negative.t` proves each term alone does not.

**Every term must be specific enough that co-occurrence *is* the attack.** The
engine checks that a rule's terms appear in the same buffer, not that they form
one expression, so two low-specificity terms will match traffic that merely
mentions both — which is why the rule set has no `sleep(` + `select ` pairing
(both are ordinary English; the standalone `sqli` table catches the real
attack in quote context instead) and why the Jenkins and VMware rules use
`/cli?` and `${` rather than `/cli` and `freemarker`. Distance does not rescue a
vague term: benign mentions and real payloads sit at overlapping byte gaps.
`t/05-fp-negative.t` TESTS 64-69 pin the benign co-occurrence shapes.

The terms are matched by the same single automaton pass, so a rule costs no
extra scan time: the pass just records which terms it saw and evaluates the sets
once at the end. Rules are same-buffer only (a term in the URI and a term in the
body do not combine), and `shield_skip <category>` disables that category's
rules along with its signatures.

### When inspection itself fails

If the module cannot inspect a buffer at all — a pool allocation fails under
memory pressure, or a request-body temp file cannot be read — then the request
was never actually scanned, and an unscanned request is not a clean one.

* `shield block` **fails closed**: the request is rejected with `500` and
  `error.log` gets `shield: could not inspect <what>, failing closed`.
* `shield detect` never changes the response by definition, so it logs
  `shield: could not inspect <what>, request left unscanned` and serves the
  request.

This is the only case in which `block` mode returns something other than
`shield_status`. A body larger than `shield_max_body` is **not** an inspection
failure — that is the documented cap, and the request is passed through.

## Cost

All signatures are matched in a **single pass** per buffer by an Aho-Corasick
automaton, so scan time is O(bytes) and does **not** grow with the number of
signatures — the table can be extended for free.

Measured over the scan core:

| buffer | bytes | µs/scan |
|---|---|---|
| typical URI + user-agent | 358 | 1.0 |
| 8 KB body (default cap) | 8 192 | 23 |
| hostile all-`/` buffer | 512 | 1.4 |

A worker is single-threaded, so scan time is blocking — whatever it costs, that
worker serves nobody else. Two properties keep that safe:

- **No pathological input.** Cost depends only on length, never on content. The
  hostile all-`/` case above costs the same as benign traffic. (The previous
  naive engine ran one linear sweep *per signature* — ~500 per buffer — and its
  first-byte prefilter was defeated by `/`, the most common byte in a URI. That
  buffer cost 120 µs; it now costs 1.4.)
- **Bounded body work.** `shield_max_body` (default 8k) caps the largest buffer
  an attacker can hand you. Still treat it as a DoS budget: both the body length
  and the `Content-Type` that opts a request into body scanning are
  attacker-controlled.

Set `shield_body off` on endpoints that take large uploads.

The two automatons cost ~5.2 MiB, built once at configuration load and shared
read-only by every worker. Matching state itself needs no per-request
allocation; normalization uses the two bounded scratch buffers described above.

## Adding a signature

Signatures live in [`src/ngx_http_shield_patterns.h`](src/ngx_http_shield_patterns.h).
Store them lowercase, and never as a bare keyword — always a multi-token
combination that only appears in an attack. `t/05-fp-negative.t` exists to
catch signatures that are too broad. Adding a whole category is an enum value,
a table, and one row in `ngx_http_shield_categories[]`; no engine change.

## Testing

```sh
tools/ci-build.sh nginx 1.31.3
export TEST_NGINX_BINARY="$PWD/.build/nginx-1.31.3/objs/nginx"
export TEST_NGINX_LOAD_MODULES="$PWD/.build/nginx-1.31.3/objs/ngx_http_shield_module.so"
export TEST_NGINX_TIMEOUT=20
prove t/
```

### Continuous testing

This is hostile-input parser code, so every change runs through a layered gate:

| Workflow | Trigger | What it does |
|----------|---------|--------------|
| **Build and Test** | PR/push | Multi-job build, strict-warning compile, full Test::Nginx suite, and the same suite again under AddressSanitizer + UndefinedBehaviorSanitizer. |
| **Fuzzing** | PR/push | 120 s libFuzzer run of `fuzz_scan` — the real normalize + Aho-Corasick scan core, differentially checked against a naive reference matcher, with nginx's own `ngx_unescape_uri()` decoder linked in. |
| **Valgrind** | PR/push | 60 s Memcheck soak of a mixed attack/benign request storm against the debug build. |
| **Security scanners** | PR/push | flawfinder (gate on ≥4), clang-tidy (`cert-*`, `security.*`), semgrep. |
| **CodeQL** | PR/push + monthly | `security-extended` C/C++ analysis. |
| **CI Deep** | monthly + dispatch | 4 h fuzz, 10 min Memcheck **and** Helgrind soaks, scanners. |

Fuzz the scan core locally:

```sh
tools/ci-build.sh nginx 1.31.3          # populate .build/ (fuzz needs headers)
CC=clang bash fuzz/build.sh
fuzz/fuzz_scan -max_total_time=60 -dict=fuzz/fuzz.dict fuzz/corpus/fuzz_scan
```

Soak under Valgrind locally:

```sh
tools/ci-build.sh nginx 1.31.3 debug
USE_VALGRIND=1 tools/soak.sh .build/nginx-1.31.3/objs/nginx 120 4
```

## See also

- [nginx-http-shield-module: Block Ancient Exploits Without a WAF](https://deb.myguard.nl/articles/nginx-http-shield-module/)
  — the full article: what it blocks, the engine design, and a detect-to-block rollout guide.
- [NGINX for Debian & Ubuntu](https://deb.myguard.nl/nginx-modules/) and
  [Angie](https://deb.myguard.nl/angie-modules-optimized-extended/) — the prebuilt APT stack this
  module is packaged for: HTTP/3, hardening patches, 100+ curated dynamic modules, no compiling.
- [Where to find us](https://deb.myguard.nl/where-to-find-us/) — every repo, Docker image and
  download URL we publish, in one place.

## License

BSD-2-Clause (same terms as nginx and Angie). See [LICENSE](LICENSE).
