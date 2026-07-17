# shield_log -- structured JSON hit log for out-of-band reporting (AbuseIPDB).
#
# One JSON object per hit is appended to the configured file, in both block and
# detect mode. The request line is the only attacker-controlled field and is
# JSON-string-escaped, so a raw quote or control byte in the request line can
# never inject a second line or break the JSON. `off` (and no directive) write
# nothing. The "|command" form is rejected at config load.
#
# Each test logs to its OWN file: Test::Nginx clears servroot only between
# files, not between tests, so a shared path would leak lines across tests. The
# log is read back through a /dump location that `alias`es the file;
# Test::Nginx substitutes $TEST_NGINX_SERVER_ROOT in the config blocks.
use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_long_string();
run_tests();

__DATA__

=== TEST 1: block writes one JSON hit line
--- config
    location /t {
        shield block;
        shield_log $TEST_NGINX_SERVER_ROOT/logs/hit1.json;
        empty_gif;
    }
    location /dump {
        alias $TEST_NGINX_SERVER_ROOT/logs/hit1.json;
        default_type text/plain;
    }
--- request eval
["GET /t?id=1%20union%20select%20pw", "GET /dump"]
--- error_code eval
[403, 200]
--- response_body_like eval
[qr//, qr/"cat":"sqli".*"src":"uri".*"mode":"block".*"status":403/]

=== TEST 2: detect mode also logs, with mode=detect and status 0
--- config
    location /t {
        shield detect;
        shield_log $TEST_NGINX_SERVER_ROOT/logs/hit2.json;
        empty_gif;
    }
    location /dump {
        alias $TEST_NGINX_SERVER_ROOT/logs/hit2.json;
        default_type text/plain;
    }
--- request eval
["GET /t?id=1%20union%20select%20pw", "GET /dump"]
--- error_code eval
[200, 200]
--- response_body_like eval
[qr//, qr/"mode":"detect","status":0/]

=== TEST 3: benign request writes nothing (log file opened at load stays empty)
# ngx_conf_open_file creates the file at config load, so /dump returns 200; the
# point is that a benign request appends no record -> the body is empty.
--- config
    location /t {
        shield block;
        shield_log $TEST_NGINX_SERVER_ROOT/logs/hit3.json;
        empty_gif;
    }
    location /dump {
        alias $TEST_NGINX_SERVER_ROOT/logs/hit3.json;
        default_type text/plain;
    }
--- request eval
["GET /t?sort=order&page=2", "GET /dump"]
--- error_code eval
[200, 200]
--- response_body_like eval
[qr//, qr/^$/]

=== TEST 4: no shield_log directive -> no file, request still handled
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?id=1%20union%20select%20pw
--- error_code: 403

=== TEST 5: shield_log off writes nothing
--- config
    location /t {
        shield block;
        shield_log off;
        empty_gif;
    }
--- request
GET /t?id=1%20union%20select%20pw
--- error_code: 403

=== TEST 6: a raw quote in the request line is JSON-escaped, one line only
# Raw (undecoded) request line carrying a literal double-quote. It reaches the
# log via r->request_line verbatim, so the escaper must turn " into \" and keep
# the record on a single physical line terminated by exactly one newline.
--- config
    location /t {
        shield block;
        shield_log $TEST_NGINX_SERVER_ROOT/logs/hit6.json;
        empty_gif;
    }
    location /dump {
        alias $TEST_NGINX_SERVER_ROOT/logs/hit6.json;
        default_type text/plain;
    }
--- raw_request eval
["GET /t?id=1%20union%20select%20pw&x=\"evil\" HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
 "GET /dump HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"]
--- error_code eval
[403, 200]
# One JSON object, closing }\n at end, and the raw quote stored as \" not bare ".
--- response_body_like eval
[qr//, qr/^\{.*\\"evil\\".*\}\n\z/s]

=== TEST 7: shield_log with a piped command is rejected at config load
--- config
    location /t {
        shield block;
        shield_log "| /bin/logger";
        empty_gif;
    }
--- must_die
--- error_log
does not support piping to a command
