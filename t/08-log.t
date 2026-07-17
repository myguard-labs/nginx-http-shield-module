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

=== TEST 8: a raw high byte in the request line is \uXXXX-escaped (valid JSON)
# 0xC0 is invalid UTF-8; it must be escaped, not copied verbatim, or the record
# is malformed JSON. Sent raw in the request target via a %-less literal byte.
--- config
    location /t {
        shield block;
        shield_log $TEST_NGINX_SERVER_ROOT/logs/hit8.json;
        empty_gif;
    }
    location /dump {
        alias $TEST_NGINX_SERVER_ROOT/logs/hit8.json;
        default_type text/plain;
    }
--- raw_request eval
["GET /t?id=1%20union%20select%20pw&z=\xc0\xff HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
 "GET /dump HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"]
--- error_code eval
[403, 200]
# high bytes appear as À / ÿ, never as raw bytes; one JSON object.
--- response_body_like eval
[qr//, qr/^\{.*\\u00c0\\u00ff.*\}\n\z/s]

=== TEST 9: child `shield_log off` overrides an inherited parent log
# Parent server logs; child location turns it off. No record must be written
# for a hit in the child, and the child's own log file must stay empty/absent.
--- config
    shield_log $TEST_NGINX_SERVER_ROOT/logs/parent9.json;
    location /t {
        shield block;
        shield_log off;
        empty_gif;
    }
    location /dumpparent {
        alias $TEST_NGINX_SERVER_ROOT/logs/parent9.json;
        default_type text/plain;
    }
--- request eval
["GET /t?id=1%20union%20select%20pw", "GET /dumpparent"]
--- error_code eval
[403, 200]
# parent log opened at load (200) but the child hit wrote nothing -> empty body.
--- response_body_like eval
[qr//, qr/^$/]

=== TEST 10: shield_log syslog: config loads and a hit is served
# Delivery to a UDP syslog server is not asserted here (no mock listener); this
# pins that `syslog:` parses, the module loads, and a hit still returns 403 --
# i.e. the syslog send path runs without breaking the request.
--- config
    location /t {
        shield block;
        shield_log syslog:server=127.0.0.1:5514,tag=shield,nohostname;
        empty_gif;
    }
--- request
GET /t?id=1%20union%20select%20pw
--- error_code: 403

=== TEST 11: syslog and file are distinct sinks; file still works alongside
# A file sink configured the normal way still writes when syslog is available
# in the build (sanity that the dual-sink refactor didn't break the file path).
--- config
    location /t {
        shield block;
        shield_log $TEST_NGINX_SERVER_ROOT/logs/hit11.json;
        empty_gif;
    }
    location /dump {
        alias $TEST_NGINX_SERVER_ROOT/logs/hit11.json;
        default_type text/plain;
    }
--- request eval
["GET /t?id=1%20union%20select%20pw", "GET /dump"]
--- error_code eval
[403, 200]
--- response_body_like eval
[qr//, qr/"cat":"sqli".*"mode":"block".*"status":403/]

=== TEST 12: an oversized request line is bounded and stays valid one-line JSON
# The request line is capped (600 bytes) before escaping so the record always
# fits a syslog datagram whole and can never be truncated mid-\uXXXX. Here a
# ~4KB attack query must still yield exactly one JSON object ending in }\n, with
# the `req` field present and closed -- i.e. the bound never split the record.
--- config
    location /t {
        shield block;
        shield_log $TEST_NGINX_SERVER_ROOT/logs/hit12.json;
        empty_gif;
    }
    location /dump {
        alias $TEST_NGINX_SERVER_ROOT/logs/hit12.json;
        default_type text/plain;
    }
--- request eval
["GET /t?id=1%20union%20select%20pw&pad=" . ("a" x 4000), "GET /dump"]
--- error_code eval
[403, 200]
# one object, req field opened and the record closed with "}\n -- not cut off.
--- response_body_like eval
[qr//, qr/^\{.*"req":".*"\}\n\z/s]
