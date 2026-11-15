# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
# Body encoding is content, not proof of a vulnerable application sink.
# POSTs that reach empty_gif return 405; Shield rejects with 403.
use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_long_string();
run_tests();

__DATA__

=== TEST 1: a multiline WordPress-style form is accepted
--- config
    location /wp-admin/post.php { shield block; empty_gif; }
--- request
POST /wp-admin/post.php
content=First+paragraph%0D%0ASecond+paragraph
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- error_code: 405
--- no_error_log
category=crlf

=== TEST 2: an encoded URL in a profile form is accepted
--- config
    location /wp-admin/user-edit.php { shield block; empty_gif; }
--- request
POST /wp-admin/user-edit.php
description=https%3A%2F%2Fexample.test%2Fa%252Fb
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- error_code: 405
--- no_error_log
category=nullbyte

=== TEST 3: literal encoded-NUL examples in JSON are accepted
--- config
    location /t { shield block; empty_gif; }
--- request
POST /t
{"text":"%00, %u0000 and %252f are literal examples"}
--- more_headers
Content-Type: application/json
--- error_code: 405
--- no_error_log
category=nullbyte

=== TEST 4: a header example inside plain text is accepted
--- config
    location /t { shield block; empty_gif; }
--- request eval
"POST /t\nA header example:\r\nSet-Cookie: example=value"
--- more_headers
Content-Type: text/plain
--- error_code: 405
--- no_error_log
category=crlf

=== TEST 5: a temp-file-buffered multiline form is accepted
--- config
    location /t {
        client_body_buffer_size 512;
        shield block;
        shield_max_body 64k;
        empty_gif;
    }
--- request eval
"POST /t\ncontent=" . ("a" x 12000) . "%0D%0ASecond+paragraph"
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- error_code: 405
--- no_error_log
category=crlf

=== TEST 6: body policy does not exempt CRLF in the request target
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?next=%0d%0a
--- error_code: 403
--- error_log
category=crlf source=uri

=== TEST 7: body policy does not exempt encoded NUL in the request target
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?file=photo.php%00.jpg
--- error_code: 403
--- error_log
category=nullbyte source=uri

=== TEST 8: body policy does not exempt CRLF in a scanned header
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
User-Agent: example%0d%0a
--- error_code: 403
--- error_log
category=crlf source=user-agent

=== TEST 9: an unrelated attack still matches after ordinary newlines
--- config
    location /t { shield block; empty_gif; }
--- request
POST /t
content=First%0D%0ASecond&id=1+union+select+password
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- error_code: 403
--- error_log
category=sqli source=body

=== TEST 10: accepted content does not accumulate a detect-mode ban
--- http_config
    shield_ban_zone bodycontent:1m;
--- config
    location /t {
        shield detect;
        shield_ban zone=bodycontent count=2 window=60s bantime=30s;
        empty_gif;
    }
--- request eval
[
    "POST /t\ncontent=First%0D%0ASecond",
    "POST /t\nprofile=https%3A%2F%2Fexample.test%2Fa%252Fb",
    "GET /t",
]
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- error_code eval
[405, 405, 200]
--- no_error_log
shield: detected attack

=== TEST 11: body policy does not exempt encoded NUL in a scanned header
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
User-Agent: example%00
--- error_code: 403
--- error_log
category=nullbyte source=user-agent

=== TEST 12: gzip inspection applies the same body-only exclusions
--- config
    location /t { shield block; shield_gzip on; empty_gif; }
--- request eval
"POST /t\n" . pack("H*", "1f8b08000000000002ff4bcecf2b49cd2bb175cb2c2a2e5135705135700c4e4dcecf4b512b28ca4fcbcc49b5cd2829292856357654357203a2d48ac4dc829c54bd9254a07223b74455235323b7240013755dc446000000")
--- more_headers
Content-Type: application/x-www-form-urlencoded
Content-Encoding: gzip
--- error_code: 405
--- no_error_log
shield: blocked request

=== TEST 13: encoded NUL in a body is deliberately outside this heuristic
--- config
    location /t { shield block; empty_gif; }
--- request
POST /t
file=photo.php%00.jpg
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- error_code: 405
--- no_error_log
category=nullbyte
