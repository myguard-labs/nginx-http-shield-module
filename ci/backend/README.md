# Backend transport contract

`python3 ci/backend/test_recorders.py` checks the finite recording protocols.
Run the real integration in a disposable container with Python 3.11+:

```sh
python3 ci/backend/check.py --nginx /path/to/nginx \
    --module /path/to/ngx_http_shield_module.so --output /tmp/backend.json
```

The raw TCP client sends fixed HTTP bytes to Shield directly or through an
inert nginx reverse proxy. HTTP proxy URI replacement and percent
normalization, an error-page internal redirect, and named FastCGI upstream
handoff have literal final route/PARAMS expectations. The recorders retain the
complete received request wire and body. FastCGI PARAMS and STDIN are reassembled
across records; duplicate parameters, unsupported protocol forms, oversized or
truncated messages fail. Receipts appear only after connection closure. All
servers, tasks and nginx processes are joined before a result is accepted.

The report correlates client bytes, Shield's JSON hit (request line, category,
source, mode and action), final nginx access-log URI/upstream/status, and sink
bytes. A clean request has no hit-log observation; the route log is nginx's
view, not a claim that Shield exposed its internal decoded buffer. Block-mode
SQL body matches must produce no sink receipt; detect-mode matches must retain
the exact body at the sink. Invalid escapes/headers, the 1024-byte body boundary,
and a core return distinguish nginx rejection from Shield action. Shield's
body is observed through its source/category hit plus final sink bytes, not an
instrumented copy of scanner internals. Existing causal scanner tests own exact
rule attribution and decoded scanner buffers.

The HTTP and FastCGI endpoints only record inert bytes and return a marker.
There is no PHP interpreter, SQL service or vulnerable application. Inputs are
at most 16 KiB, requests have deadlines, and FastCGI records are capped at 128.
The core error-page redirect intentionally drops the original query string.
FastCGI header forwarding is disabled and HTTP_HOST is explicitly pinned, so
the complete PARAMS map is compared without implicit-header ambiguity.
Ports are loopback/ephemeral inside the container; no host ports are published.
The brief release/rebind window for nginx listener allocation remains a local
fixture limitation. A startup collision fails the test rather than retrying.
All sink labels remain inert content; no unknown label, historical replay label,
application exploit claim or population promotion is inferred from transport.
