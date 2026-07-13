# nginx-http-shield-module

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

28 categories (≈370 signatures), all matched case-insensitively after
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
| `java_rce` | Struts OGNL `%{(#` (CVE-2017-5638), Spring4Shell `class.module.classloader` |
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
| `ssrf_meta` | `169.254.169.254`, `100.100.100.200` (Alibaba), `192.0.0.192` (Oracle), `metadata.google.internal`, decimal/hex IMDS IPs |
| `nosql` | MongoDB operator injection `[$ne]`, `[$where]`, `{"$where":`, `$func:` |
| `ssti` | template-probe forms `{{7*7}}`, `${7*7}`, `{{''.__class__`, `<%= 7*7`, `#set($` |
| `exploit_path` | fixed n-day paths: `/wls-wsat/`, `/remote/fgt_lang`, `/actuator/gateway/routes`, `/_ignition/execute-solution`, `/api/jsonws/invoke`, GPON/HNAP/Zyxel probes |

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
            shield_max_body 64k;   # bytes of body scanned (default 64k)
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
| `shield_max_body` | http, server, location | `64k` | Bytes of body scanned. Larger bodies are passed through unscanned — uploads are never blocked for being big. |
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
percent-decoded, `+`→space, lowercased copy — and runs a plain substring scan
of every enabled category's patterns over them. Two categories (`httpoxy`,
`range_dos`) are structural checks rather than substring matches. There is no
regex and no per-request allocation beyond the two scratch buffers, so the
cost is a few microseconds on typical request sizes.

Body inspection reads the buffered request body (up to `shield_max_body`) and
scans it the same way, then resumes phase processing — the same mechanism the
stock `ngx_http_mirror_module` uses.

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

CI additionally builds under AddressSanitizer + UndefinedBehaviorSanitizer and
runs the full suite through it, and runs CodeQL — this is hostile-input parser
code, so it is fuzzed against malformed encodings on every change.

## License

MIT. See [LICENSE](LICENSE).
