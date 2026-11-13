# Context-specific plus normalization, including escaped executable permissions.
use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_long_string();
run_tests();

__DATA__

=== TEST 1: encoded plus in query
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?q=chmod+%2Bx
--- error_code: 403

=== TEST 2: literal query plus is form space
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?q=chmod++x
--- error_code: 200

=== TEST 3: literal path plus
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/chmod%20+x
--- error_code: 403

=== TEST 4: literal header plus
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
Referer: chmod +x
--- error_code: 403

=== TEST 5: encoded header plus
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
Referer: chmod%20%2Bx
--- error_code: 403

=== TEST 6: encoded form plus remains a SQL unary-plus operator
--- config
    location /t { shield block; empty_gif; }
--- request
POST /t
q=x' or%2B1=1--
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- error_code: 403

=== TEST 7: malformed percent stays clean
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?q=chmod%20%2
--- error_code: 200

=== TEST 8: cmdi skip still applies
--- config
    location /t { shield block; shield_skip cmdi; empty_gif; }
--- request
GET /t?q=chmod+%2Bx
--- error_code: 200

=== TEST 9: form SQLi uses raw plus as space
--- config
    location /t { shield block; empty_gif; }
--- request
POST /t
q=x' or+1=1--
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- error_code: 403

=== TEST 10: JSON literal plus preserves a valid SQL unary-plus tautology
--- config
    location /t { shield block; empty_gif; }
--- request
POST /t
{"note":"x' or+1=1--"}
--- more_headers
Content-Type: application/json
--- error_code: 403

=== TEST 11: text literal plus preserves a valid SQL unary-plus tautology
--- config
    location /t { shield block; empty_gif; }
--- request
POST /t
x' or+1=1--
--- more_headers
Content-Type: text/plain
--- error_code: 403

=== TEST 12: proxy URL query plus uses request-target form semantics
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
X-Original-URL: /t?q=x'+or+1=1--
--- error_code: 403

=== TEST 13: proxy URL query plus boundary stays clean
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
X-Original-URL: /t?q=chmod%20+x
--- error_code: 200

=== TEST 14: WebDAV destination path preserves literal plus
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
Destination: /a/chmod%20+x
--- error_code: 403

=== TEST 15: WebDAV destination query folds raw plus
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
Destination: /t?q=x'+or+1=1--
--- error_code: 403

=== TEST 16: proxy URL path keeps raw plus before query
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
X-Original-URL: /chmod%20+x?q=1
--- error_code: 403

=== TEST 17: proxy URL uses first question mark as query boundary
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
X-Rewrite-URL: /t?ignored?x=x'+or+1=1--
--- error_code: 403

=== TEST 18: encoded plus in proxy URL query remains literal
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
Destination: /t?q=chmod%20%2Bx
--- error_code: 403

=== TEST 19: non-form body plus does not become SQL whitespace
--- config
    location /t { shield block; empty_gif; }
--- request
POST /t
id=1+union+select+1,2,3--
--- more_headers
Content-Type: text/plain
--- error_code: 405
