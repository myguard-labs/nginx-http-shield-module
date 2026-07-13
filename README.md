# nginx-http-shield-module

[![Build and Test](https://github.com/myguard-labs/nginx-http-shield-module/actions/workflows/build-test.yml/badge.svg)](https://github.com/myguard-labs/nginx-http-shield-module/actions/workflows/build-test.yml)
[![Security scanners](https://github.com/myguard-labs/nginx-http-shield-module/actions/workflows/security-scanners.yml/badge.svg)](https://github.com/myguard-labs/nginx-http-shield-module/actions/workflows/security-scanners.yml)
[![Fuzzing](https://github.com/myguard-labs/nginx-http-shield-module/actions/workflows/fuzzing.yml/badge.svg)](https://github.com/myguard-labs/nginx-http-shield-module/actions/workflows/fuzzing.yml)
[![Valgrind](https://github.com/myguard-labs/nginx-http-shield-module/actions/workflows/valgrind.yml/badge.svg)](https://github.com/myguard-labs/nginx-http-shield-module/actions/workflows/valgrind.yml)
[![CI Deep](https://github.com/myguard-labs/nginx-http-shield-module/actions/workflows/ci-deep.yml/badge.svg)](https://github.com/myguard-labs/nginx-http-shield-module/actions/workflows/ci-deep.yml)
[![CodeQL](https://github.com/myguard-labs/nginx-http-shield-module/actions/workflows/codeql.yml/badge.svg)](https://github.com/myguard-labs/nginx-http-shield-module/actions/workflows/codeql.yml)

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

28 categories (≈400 signatures), all matched case-insensitively after
percent-decoding:

| Category | Examples |
|----------|----------|
| `sqli` | `union select`, `' or 1=1`, `sleep(`, `into outfile`, `information_schema` |
| `xss` | `<script`, `javascript:`, `onerror=`, `document.cookie` |
| `traversal` | `../`, `..\`, `..;/`, `.%2e/` (CVE-2021-41773), `/etc/passwd` |
| `overlong` | overlong-UTF-8 `/` and `\` (`%c0%af`, `%c1%9c`) — IIS/Nimda era |
| `cmdi` | `;wget `, `$(curl`, `/bin/sh`, `chmod 777`, `/winnt/system32` |
| `lfi` | `php://filter`, `data://`, `expect://`, `phar://` |
| `crlf` | `%0d%0a`, response-splitting `\r\nSet-Cookie:` |
| `nullbyte` | `%00`, double-encoded `.` / `/` |
| `template` | `${jndi:` + `jndi:ldap/rmi/dns/iiop`, `${env:`, `${::-`, nested `${${` |
| `deserial` | Java stream magic, gadget classes (`jdbcRowSetImpl`, `TemplatesImpl`, commons-collections), Fastjson `@type` autotype, WebLogic/XStream, Joomla obj-injection (CVE-2015-8562), XXE `<!entity` |
| `shellshock` | `() {` (CVE-2014-6271) |
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
| `sensitive_file` | `/.env`, `/.git/`, `wp-config.php.bak`, `/.aws/credentials` |
| `webshell` | `c99.php`, `r57.php`, `wso.php`, `weevely`, `behinder`, `shell.php?cmd=` |
| `ssrf_meta` | `169.254.169.254`, `100.100.100.200` (Alibaba), `192.0.0.192` (Oracle), `metadata.google.internal`, IMDSv2 `/latest/api/token`, `iam/security-credentials/`, decimal/hex IMDS IPs |
| `nosql` | MongoDB operator injection `[$ne]`, `[$where]`, `{"$where":`, `$func:` |
| `ssti` | template-probe forms `{{7*7}}`, `${7*7}`, `{{''.__class__`, `<%= 7*7`, `#set($` |
| `exploit_path` | fixed n-day paths: `/wls-wsat/`, `/remote/fgt_lang`…`sslvpn_websession`, `/actuator/gateway/routes`, `/_ignition/execute-solution`, `/api/jsonws/invoke`, F5 `/tmui/login.jsp/..;/` (CVE-2020-5902), vCenter `uploadova` (CVE-2021-21972), Citrix `/vpn/../vpns/` (CVE-2019-19781), OFBiz `/webtools/control/xmlrpc`, Ivanti `user-backup-code/..`, GPON/HNAP/Zyxel probes |

What is inspected: the request line and query string, the `User-Agent`,
`Referer` and `Content-Type` headers, and — when enabled — the request body.

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
tools/ci-build.sh nginx 1.31.1        # dynamic .so under .build/
```

## Configuration

```nginx
http {
    # Turn on globally in detect mode first, watch the logs, then switch to block.
    shield detect;

    server {
        location / {
            shield block;          # off | detect | block
            shield_body on;        # inspect request body (default on)
            shield_max_body 8k;    # bytes of body scanned (default 8k)
            shield_status 403;      # 403 | 404 | 419 | 429 | 444 (default 403)
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
| `shield_skip` | http, server, location | — | Space-separated category names to disable (see table above, plus `httpoxy` and `range_dos`). |

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
category's patterns over them in a **single Aho-Corasick pass per buffer**. Two
categories (`httpoxy`, `range_dos`) are structural checks rather than
literal matches. There is no regex and no per-request allocation beyond the two
scratch buffers, so the cost is a few microseconds on typical request sizes.

Body inspection reads the buffered request body (up to `shield_max_body`) and
scans it the same way, then resumes phase processing — the same mechanism the
stock `ngx_http_mirror_module` uses.

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

The automaton costs ~3.4 MB, built once at configuration load and shared
read-only by every worker. There is no per-request allocation for matching.

## Adding a signature

Signatures live in [`src/ngx_http_shield_patterns.h`](src/ngx_http_shield_patterns.h).
Store them lowercase, and never as a bare keyword — always a multi-token
combination that only appears in an attack. `t/05-fp-negative.t` exists to
catch signatures that are too broad. Adding a whole category is an enum value,
a table, and one row in `ngx_http_shield_categories[]`; no engine change.

## Testing

```sh
tools/ci-build.sh nginx 1.31.1
export TEST_NGINX_BINARY="$PWD/.build/nginx-1.31.1/objs/nginx"
export TEST_NGINX_LOAD_MODULES="$PWD/.build/nginx-1.31.1/objs/ngx_http_shield_module.so"
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
tools/ci-build.sh nginx 1.31.1          # populate .build/ (fuzz needs headers)
CC=clang bash fuzz/build.sh
fuzz/fuzz_scan -max_total_time=60 -dict=fuzz/fuzz.dict fuzz/corpus/fuzz_scan
```

Soak under Valgrind locally:

```sh
tools/ci-build.sh nginx 1.31.1 debug
USE_VALGRIND=1 tools/soak.sh .build/nginx-1.31.1/objs/nginx 120 4
```

## See also

- Blog article: [nginx-http-shield-module: Block Ancient Exploits Without a WAF](https://deb.myguard.nl/articles/nginx-http-shield-module/) —
  what it blocks, the Aho-Corasick engine design, and a detect-to-block rollout guide.

## License

MIT. See [LICENSE](LICENSE).
