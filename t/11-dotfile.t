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
GET /t/.well-known/acme-challenge/x
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
