# Final FastCGI handoff

This optional Python 3.11+ companion checks nginx/Angie's actual FastCGI
`PARAMS` stream before opening the PHP backend. Use it when generated
`fastcgi_param` values need a final safety check. Shield's PRECONTENT scanner
inspects client request inputs; it does not inspect that generated stream.
The companion uses the public [FastCGI protocol specification](https://fastcgi-archives.github.io/FastCGI_Specification.html)
and nginx's supported [fastcgi_pass](https://nginx.org/en/docs/http/ngx_http_fastcgi_module.html#fastcgi_pass)
UNIX-socket transport. It neither intercepts private callbacks nor modifies core.

## Declare the site contract first

The operator must enumerate every legitimate absolute `SCRIPT_FILENAME` and
its complete, ordered `PHP_VALUE` and `PHP_ADMIN_VALUE` vectors in
[site-contract.json](site-contract.json). Empty vectors mean those parameters
are absent, including empty-valued occurrences. Multiple occurrences are
allowed only when the exact ordered vector is declared. This avoids assuming
which duplicate a PHP build uses. Arrays contain exact UTF-8 bytes, including
newlines and whitespace. No INI parsing, case folding, path resolution or
normalization takes place. Protect the contract and script tree from writes by
untrusted application accounts. Verify backend path/INI semantics yourself.

For each request, exactly one final `SCRIPT_FILENAME` must match a declared
script. Each privileged vector must match its declared vector. All other
parameters, duplicates, headers, record padding and STDIN body bytes pass
unchanged. For example, `HTTP_PHP_VALUE` remains an ordinary HTTP header; it
cannot satisfy or replace `PHP_VALUE`. Provenance is the actual named parameter
in the stream emitted by the trusted nginx FastCGI handler. The protocol does
not carry the source nginx directive or a taint label: the companion cannot tell
whether a handler intentionally copied a client value into a privileged name.
It checks that final value regardless of its source. An attacker choosing an
already approved value receives no additional privilege under this contract.

The acceptance argument is exact set membership: a legitimate
request is one with a declared final script, its declared complete privileged
vectors, and the supported transport described below. Every such combination
passes regardless of ordinary header, query or body content. Tests are evidence
for the implementation, not proof that your declaration covers your entire
application. A missing legitimate script/override in the contract will be
rejected. This is no claim about arbitrary applications, PHP includes, filesystem
aliases, all possible PHP configuration hazards, or universal absence of false
positives. Retain the [PHP execution boundary](../php-boundary/README.md) recipe
for its separate filesystem/routing contract.

## Deploy explicitly

Adapt these files inside Shield before installing reviewed copies. The example
approves one front controller and one legitimate administrator override; change
both the JSON and nginx directive together when your site differs.

1. Run the companion under an unprivileged service identity. Use operator-owned
   local directories and UNIX socket permissions so only trusted nginx workers
   can connect to the companion, and only the companion's identity can connect
   to the PHP socket. Keep the backend inaccessible through other handlers or
   network listeners. Do not expose the companion directly to HTTP clients.
2. Start with a reviewed contract and distinct absolute socket paths:

   ```sh
   umask 0007
   python3 /opt/shield/final-handoff/fastcgi_guard.py \
     --listen /run/shield-handoff/guard.sock \
     --backend /run/php/shield.sock \
     --contract /etc/shield/site-contract.json --mode detect
   ```

   Before starting, have the operator create `/run/shield-handoff` owned by the
   companion identity, with the trusted nginx group and mode `2750` (setgid,
   group traversal, no nginx group write). The socket inherits that group and
   `umask 0007` creates it with group access before listening. The backend socket
   needs its own exclusive companion permissions. Verify these actual owners
   and modes in staging; do not use a shared or application-writable directory.
   Startup refuses an existing listener path without unlinking it. On Python
   3.13+, a graceful asyncio server close can remove its own listener (with an
   inode check); older runtimes and abrupt exits can leave a stale socket.
   The service operator must verify a leftover is stale before removing it.
   Reload by restarting with a reviewed contract and ordinary upstream
   availability management.
3. In every PHP location, replace the PHP boundary recipe's `fastcgi_pass` with
   the include in [dispatch.conf](dispatch.conf), retaining its final-script
   guards and complete other FastCGI parameters. Audit named/error/internal
   locations and retry peers as well. No duplicate `fastcgi_pass` directive.
   The final script and ordered privileged vectors must match the JSON.
4. Validate nginx configuration, exercise all legitimate routes/overrides in
   detect mode against a staging backend, then choose `--mode block` explicitly.
   The tool applies no nginx, PHP, service or host configuration itself.

`block` returns FastCGI HTTP 403 for a contract mismatch without connecting to
PHP. It drains the remaining framed upload within the same connection deadline
and half-closes its response so nginx can consume the rejection while still
uploading. `detect` logs a fixed reason identifier and forwards unchanged. `off`
disables the script/privileged-vector check; supported protocol validation and
resource limits remain active in every mode. Logs never print parameter values,
paths from requests, body bytes or contract values. A transport error before
admission attempts HTTP 400 when a valid request identifier is available;
otherwise it closes. Malformed transport can surface as nginx 502. Backend
failures and deadline expiry close the connection
without inventing a response after potentially partial output; nginx normally
reports 502 and may retry under its own configured rules. Never configure an
unguarded fallback peer. The companion does not retry requests itself.

## Supported transport and bounds

Only FastCGI v1 Responder, one nonzero request ID per connection, no multiplexing
and `fastcgi_keep_conn off` are supported. BEGIN flags and reserved fields must
be zero. Management records, Authorizer/Filter roles and connection reuse are
unsupported. Requests must be BEGIN, PARAMS records, empty PARAMS terminator,
then STDIN records and an empty STDIN terminator. No later parameter stream is
forwarded. ABORT before admission closes without reaching PHP; after admission
it is forwarded and the backend may finish or close. Fresh nginx retries and
internal redirects are independently checked on each new FastCGI connection;
no verdict is cached by URI or client. Backend response records are relayed
unchanged; the backend is trusted to produce valid FastCGI, with nginx retaining
its normal response validation. This is not a backend protocol firewall.

Limits per connection are 65,536 decoded PARAMS bytes, 1,024 pairs, 1,024 PARAMS
records including the terminator, and 131,072 buffered BEGIN/PARAMS wire bytes
including padding. Names must be nonempty; names and values cannot contain NUL
(CGI strings). Both short and four-byte lengths and pairs split across records
are supported. Malformed, truncated or over-budget streams close/reject without
reaching PHP. These are explicit deployment transport limits, not ordinary
header or upload bans, and need staging validation for your site. Large policy
files above 65,536 bytes and unknown/missing/duplicate JSON fields fail startup.

At most 64 connections are active; additional connections are closed before
parsing. Each has an absolute 60-second lifetime covering admission, upload and
response; slow/long-lived requests beyond that are unsupported. Cleanup adds at
most one second per writer (two seconds total); failed backend writes are
aborted rather than flushed indefinitely. Bodies and
responses stream in bounded record/read chunks, with asyncio backpressure and
no total-body buffering or companion byte-size cap. Parameter work is linear
in the bounded stream/pair count; upload work is linear in bytes received.
Python runtime/socket overhead also consumes memory. The component is intended
for this explicit bounded deployment, not unmeasured high-throughput replacement
of nginx's event loop.

## Recording oracle

`ci/tests/test_final_handoff.py --nginx /path/to/nginx --module /path/to/module.so`
runs an inert backend that records exact final FastCGI wire bytes and never
executes PHP. The real-server case keeps `shield block` active in PRECONTENT,
generates an unapproved `PHP_VALUE` through `fastcgi_param` after rewrite,
and proves that only disabling final enforcement admits it. It covers named and
error redirects, an actual failed first upstream connection followed by a
protected retry, ordinary headers, a binary POST body, approved admin overrides,
and detect/off behavior. Protocol tests cover duplicate order, framing, split
lengths, limits, abort and failures. `--disable-enforcement` is the deliberate
negative control: the named blocking assertion must fail.
