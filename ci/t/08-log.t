# shield_log -- structured JSON hit log for out-of-band reporting (AbuseIPDB).
#
# One content-free JSON object per hit is appended in block and detect modes.
# Hostile request bytes cannot enter fixed metadata. `off` (and no directive)
# write nothing. The "|command" form is rejected at config load.
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

=== TEST 6: a raw quote never enters content-free JSON
# A hostile request target must not become diagnostic content.
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
# One bounded JSON object; legacy req key is empty.
--- response_body_like eval
[qr//, qr/^\{.*"req":"".*"rule":"[0-9a-f]{16}".*\}\n\z/s]

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

=== TEST 8: raw high bytes never enter content-free JSON
# Invalid UTF-8 is sent raw in the target and must be absent from metadata.
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
# High bytes are discarded with the request content; the object stays ASCII.
--- response_body_like eval
[qr//, qr/^\{.*"req":"".*"rule":"[0-9a-f]{16}".*\}\n\z/s]

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
# A large hostile target cannot increase the content-free record size.
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
# One complete bounded metadata record, independent of the request size.
--- response_body_like eval
[qr//, qr/^\{.{1,766}\}\n\z/s]

=== TEST 13: a failing file sink (/dev/full, ENOSPC) still serves and alerts once
# audit s43 F6: a write to a full disk must NOT change the request outcome (still
# 403) but must NOT vanish silently either -- it emits one rate-limited [alert]
# naming the sink. /dev/full always fails writes with ENOSPC while opening fine,
# so ngx_conf_open_file succeeds at load and every hit's write_fd returns -1.
--- config
    location /t {
        shield block;
        shield_log /dev/full;
        empty_gif;
    }
--- request
GET /t?id=1%20union%20select%20pw
--- error_code: 403
--- error_log
to shield_log "/dev/full" failed
--- no_error_log
[emerg]

=== TEST 14: raw X-Forwarded-For does not replace the logged peer
--- config
    location /t {
        shield block;
        shield_log $TEST_NGINX_SERVER_ROOT/logs/hit14.json;
        empty_gif;
    }
    location /dump {
        alias $TEST_NGINX_SERVER_ROOT/logs/hit14.json;
        default_type text/plain;
    }
--- request eval
["GET /t?id=1%20union%20select%20pw", "GET /dump"]
--- more_headers eval
["X-Forwarded-For: 198.51.100.7", ""]
--- error_code eval
[403, 200]
--- response_body_like eval
[qr//, qr/"ip":"127\.0\.0\.1"/]

=== TEST 15: nginx real-IP processing supplies the trusted logged client
--- config
    set_real_ip_from 127.0.0.1;
    real_ip_header X-Forwarded-For;
    location /t {
        shield block;
        shield_log $TEST_NGINX_SERVER_ROOT/logs/hit15.json;
        empty_gif;
    }
    location /dump {
        alias $TEST_NGINX_SERVER_ROOT/logs/hit15.json;
        default_type text/plain;
    }
--- request eval
["GET /t?id=1%20union%20select%20pw", "GET /dump"]
--- more_headers eval
["X-Forwarded-For: 198.51.100.7", ""]
--- error_code eval
[403, 200]
--- response_body_like eval
[qr//, qr/"ip":"198\.51\.100\.7"/]

=== TEST 16: strict body and ban accounting have explicit effective context
--- http_config
    shield_ban_zone diagnostics:1m;
--- config
    location /t {
        shield block;
        shield_status 419;
        shield_body_strict on;
        shield_ban zone=diagnostics count=10 window=60s bantime=30s;
        shield_log $TEST_NGINX_SERVER_ROOT/logs/hit16.json;
        empty_gif;
    }
    location /dump {
        alias $TEST_NGINX_SERVER_ROOT/logs/hit16.json;
        default_type text/plain;
    }
--- request eval
["POST /t\nunion select", "GET /dump"]
--- more_headers eval
["Content-Type: text/plain", ""]
--- error_code eval
[419, 200]
--- response_body_like eval
[qr//, qr/"cat":"sqli","src":"body","mode":"block","status":419,"req":"","rule":"c5d8b739bdf9c83d","rev":1.*"view":"decoded","verdict":"signature-match","action":"block","body_policy":"strict","ban":"on"/]

=== TEST 17: structural rule keeps its category and has a bounded identity
--- config
    location /t {
        shield block;
        shield_log $TEST_NGINX_SERVER_ROOT/logs/hit17.json;
        empty_gif;
    }
    location /dump {
        alias $TEST_NGINX_SERVER_ROOT/logs/hit17.json;
        default_type text/plain;
    }
--- request eval
["GET /t", "GET /dump"]
--- more_headers eval
["Proxy: http://ht19_secret_canary.invalid", ""]
--- error_code eval
[403, 200]
--- response_body_like eval
[qr//, qr/"cat":"httpoxy".*"rule":"[0-9a-f]{16}".*"view":"structural"/]
