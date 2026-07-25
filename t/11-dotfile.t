# Structural dotfile/dotdir check: any path segment starting with '.'.
#
# Requests use an unenumerated dotfile name (.myshieldtest, .customcache/...)
# rather than /.env or /.git/ -- those already match the sensitive_file
# signature table, which would fire regardless of this check and mask a
# skip-mask bug (a real one this test file caught: TEST 7 originally used
# /.env and passed even with the dotfile bit still set, because sensitive_file
# blocked it independently).
use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_long_string();
run_tests();

__DATA__

=== TEST 1: a dotfile in the path is blocked
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/.myshieldtest
--- error_code: 403

=== TEST 2: a dotdir in the path is blocked
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/.customcache/config
--- error_code: 403

=== TEST 3: the dotfile check reports the dotfile category
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/.myshieldtest
--- error_log
category=dotfile
--- error_code: 403

=== TEST 4: a leading dotfile segment is blocked
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/.myshieldtest/deeper
--- error_code: 403

=== TEST 5: a normal path is allowed
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/plain/path
--- error_code: 200

=== TEST 6: a filename containing a dot (not leading) is allowed
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/report.pdf
--- error_code: 200

=== TEST 7: the dotfile check can be skipped
--- config
    location /t { shield block; shield_skip dotfile; empty_gif; }
--- request
GET /t/.myshieldtest
--- error_code: 200

=== TEST 9: ACME HTTP-01 challenge is served, not blocked
# RFC 8555 s8.3 fixes this prefix; blocking it fails certificate renewal.
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/.well-known/acme-challenge/evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA
--- error_code: 200

=== TEST 10: security.txt is served, not blocked
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/.well-known/security.txt
--- error_code: 200

=== TEST 11: a bare .well-known segment at end of URI is allowed
# Exercises the rest == strlen(".well-known") arm (no trailing '/').
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/.well-known
--- error_code: 200

=== TEST 12: a .well-known directory listing path is allowed
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/.well-known/
--- error_code: 200

=== TEST 13: .well-known is exempt at any depth, not only at the root
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/nested/.well-known/openid-configuration
--- error_code: 200

=== TEST 14: a dotfile UNDER .well-known is still blocked
# The exemption covers the one segment; the walk continues.
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/.well-known/.myshieldtest
--- error_log
category=dotfile
--- error_code: 403

=== TEST 15: a dotdir under .well-known is still blocked
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/.well-known/.customcache/config
--- error_code: 403

=== TEST 16: the exemption is whole-segment, not a prefix
# ".well-knownXYZ" is an ordinary dotfile and must not inherit the exemption.
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/.well-knownXYZ
--- error_log
category=dotfile
--- error_code: 403

=== TEST 17: a .well-known prefix followed by a dot is not the exempt segment
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/.well-known.bak/x
--- error_code: 403

=== TEST 18: a shorter dot-segment sharing a .well-known prefix is blocked
# Exercises the rest < strlen(".well-known") arm.
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/.well
--- error_log
category=dotfile
--- error_code: 403

=== TEST 19: the .well-known exemption is case-sensitive
# RFC 8615 registers the lowercase name; a cased variant is not it.
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/.Well-Known/acme-challenge/x
--- error_code: 403

=== TEST 20: the Citrix exploit path under .well-known is still blocked
# CVE-2023-4966 / CVE-2025-5777. Caught by the exploit_path signature table,
# which the structural exemption does not touch -- this is the regression that
# proves exempting the namespace did not open the known exploit.
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/oauth/idp/.well-known/openid-configuration
--- error_log
category=exploit_path
--- error_code: 403

=== TEST 21: sensitive_file under .well-known still blocks independently
# /.env is on the signature table, so it must block even though the structural
# dotfile check now walks past the .well-known segment.
--- config
    location /t { shield block; shield_skip dotfile; empty_gif; }
--- request
GET /t/.well-known/.env
--- error_log
category=sensitive_file
--- error_code: 403

=== TEST 22: a traversal payload under .well-known is still traversal
# The payload MUST sit in the query, not in a path segment. nginx normalizes
# the path (decode, then resolve dot-segments) before r->uri, so an encoded
# ".." in path position is collapsed away and the request 404s without ever
# reaching the scanner -- verified, not assumed. It does NOT normalize the
# query, which is why the traversal category scans the raw request target and
# why query position is the only one that proves anything here.
# Path-position traversal is covered by t/02-uri.t and by TEST 8 below.
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/.well-known/x?f=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
--- error_log
category=traversal
--- error_code: 403

=== TEST 8: dotfile check does not take over the traversal category's bytes
# ".." in a query value is traversal's own territory (see t/02-uri.t TEST 3);
# dotfile must not report it under its own category name.
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?file=../../../../etc/passwd
--- error_log
category=traversal
--- error_code: 403

=== TEST 23: an encoded lone "." segment is not a dotfile
# ngx_http_parse_complex_uri() percent-decodes AND resolves dot-segments before
# r->uri, so this never reaches the check's lone-"." arm -- that arm is
# defence in depth against a future caller with a non-normalized URI. What this
# pins is the observable contract: an encoded "." must not produce a dotfile hit
# by any route.
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/%2e/plain
--- error_code: 200

=== TEST 24: an encoded ".." segment is not claimed by dotfile
# As TEST 23: nginx resolves the segment away before the check runs, so the
# ".."-arm is not reached from HTTP either. Traversal owns those bytes and
# scans the raw target instead (TEST 8/22). The request simply leaves the
# location -- a 404, and above all NOT a dotfile hit.
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/%2e%2e/plain
--- error_code: 404
--- no_error_log
category=dotfile
