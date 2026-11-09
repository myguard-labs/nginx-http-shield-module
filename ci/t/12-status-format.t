# Native OpenMetrics status; exact empty exposition also guards stable zero series.
use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_long_string();
run_tests();

__DATA__

=== TEST 1: default JSON and explicit JSON remain identical
--- http_config
    shield_ban_zone metrics1:1m;
--- config
    location /default { shield_ban_status metrics1; }
    location /explicit {
        shield_ban_status metrics1;
        shield_ban_status_format json;
    }
--- request eval
["GET /default", "GET /explicit"]
--- response_body_like eval
[(qr/^\{"zone":"metrics1","nodes":0,"blocked":0,"bans":0,"categories":\{.*\},"banned":\[\]\}$/) x 2]
--- response_headers eval
["Content-Type: application/json", "Content-Type: application/json"]
--- error_code eval
[200, 200]

=== TEST 2: empty OpenMetrics has every category, metadata, zero gauge and EOF
--- http_config
    shield_ban_zone metrics2:1m;
--- config
    location /metrics {
        shield_ban_status metrics2;
        shield_ban_status_format prometheus;
    }
--- request
GET /metrics
--- response_body eval
my @cats = qw(sqli xss traversal overlong cmdi lfi crlf nullbyte template
              deserial shellshock php_rce java_rce java_eval rails_yaml drupal
              vbulletin xmlrpc ssi imagetragick httpoxy range_dos sensitive_file
              webshell ssrf_meta nosql ssti exploit_path ctrl_char dotfile);
"# HELP shield_hits Shield signature hits by category.\n"
. "# TYPE shield_hits counter\n"
. CORE::join('', map { "shield_hits_total{zone=\"metrics2\",category=\"$_\"} 0\n" } @cats)
. "# HELP shield_blocked Shield requests blocked.\n"
. "# TYPE shield_blocked counter\n"
. "shield_blocked_total{zone=\"metrics2\"} 0\n"
. "# HELP shield_bans Shield bans armed.\n"
. "# TYPE shield_bans counter\n"
. "shield_bans_total{zone=\"metrics2\"} 0\n"
. "# HELP shield_zone_nodes Shield zone nodes in use.\n"
. "# TYPE shield_zone_nodes gauge\n"
. "shield_zone_nodes{zone=\"metrics2\"} 0\n"
. "# HELP shield_banned_clients Shield clients currently banned.\n"
. "# TYPE shield_banned_clients gauge\n"
. "shield_banned_clients{zone=\"metrics2\"} 0\n"
. "# EOF\n"
--- response_headers
Content-Type: application/openmetrics-text; version=1.0.0; charset=utf-8
--- error_code: 200

=== TEST 3: hits, blocks, bans and gauges share the JSON zone
--- http_config
    shield_ban_zone metrics3:1m;
--- config
    location /t {
        shield block;
        shield_ban zone=metrics3 count=2 window=60s bantime=30s;
        empty_gif;
    }
    location /metrics {
        shield_ban_status metrics3;
        shield_ban_status_format prometheus;
    }
    location /json { shield_ban_status metrics3; }
--- request eval
["GET /t?id=1%20union%20select%20pw", "GET /t?id=1%20union%20select%20pw",
 "GET /t", "GET /metrics", "GET /json"]
--- response_body_like eval
[qr/./, qr/./, qr/./,
 qr/shield_hits_total\{zone="metrics3",category="sqli"\} 2\n.*shield_blocked_total\{zone="metrics3"\} 2\n.*shield_bans_total\{zone="metrics3"\} 1\n.*shield_zone_nodes\{zone="metrics3"\} 1\n.*shield_banned_clients\{zone="metrics3"\} 1\n# EOF\n\z/s,
 qr/"nodes":1,"blocked":2,"bans":1.*"sqli":2.*"banned":\[\{"addr":"127\.0\.0\.1"/s]
--- error_code eval
[403, 403, 403, 200, 200]

=== TEST 4: detect mode has hits and counting nodes but no blocked or banned clients
--- http_config
    shield_ban_zone metrics4:1m;
--- config
    location /t {
        shield detect;
        shield_ban zone=metrics4 count=9 window=60s bantime=30s;
        empty_gif;
    }
    location /metrics {
        shield_ban_status metrics4;
        shield_ban_status_format prometheus;
    }
--- request eval
["GET /t?id=1%20union%20select%20pw", "GET /metrics"]
--- response_body_like eval
[qr/./, qr/category="sqli"\} 1\n.*shield_blocked_total\{zone="metrics4"\} 0\n.*shield_bans_total\{zone="metrics4"\} 0\n.*shield_zone_nodes\{zone="metrics4"\} 1\n.*shield_banned_clients\{zone="metrics4"\} 0\n/s]
--- error_code eval
[200, 200]

=== TEST 5: HEAD returns the OpenMetrics headers without a body
--- http_config
    shield_ban_zone metrics5:1m;
--- config
    location /metrics {
        shield_ban_status metrics5;
        shield_ban_status_format prometheus;
    }
--- request
HEAD /metrics
--- response_body
--- response_headers
Content-Type: application/openmetrics-text; version=1.0.0; charset=utf-8
--- error_code: 200

=== TEST 6: POST remains rejected in prometheus mode
--- http_config
    shield_ban_zone metrics6:1m;
--- config
    location /metrics {
        shield_ban_status metrics6;
        shield_ban_status_format prometheus;
    }
--- request
POST /metrics
--- error_code: 405

=== TEST 7: invalid format is rejected
--- config
    location /metrics { shield_ban_status_format xml; }
--- must_die
--- error_log
invalid value "xml"

=== TEST 8: duplicate format is rejected
--- config
    location /metrics {
        shield_ban_status_format json;
        shield_ban_status_format prometheus;
    }
--- must_die
--- error_log
"shield_ban_status_format" directive is duplicate

=== TEST 9: format is location-only
--- config
    shield_ban_status_format prometheus;
--- must_die
--- error_log
"shield_ban_status_format" directive is not allowed here

=== TEST 10: missing argument is rejected
--- config
    location /metrics { shield_ban_status_format; }
--- must_die
--- error_log
invalid number of arguments in "shield_ban_status_format" directive

=== TEST 11: nested location inherits format and can override it
--- http_config
    shield_ban_zone metrics11:1m;
--- config
    location /status {
        shield_ban_status_format prometheus;
        location /status/metrics { shield_ban_status metrics11; }
        location /status/json {
            shield_ban_status_format json;
            shield_ban_status metrics11;
        }
    }
--- request eval
["GET /status/metrics", "GET /status/json"]
--- response_body_like eval
[qr/\nshield_banned_clients\{zone="metrics11"\} 0\n# EOF\n\z/,
 qr/^\{"zone":"metrics11",.*"banned":\[\]\}$/]
--- error_code eval
[200, 200]

=== TEST 12: label quotes, backslashes and line feeds are escaped
--- http_config
    shield_ban_zone 'zone"\\name\nline:1m';
--- config
    location /metrics {
        shield_ban_status 'zone"\\name\nline';
        shield_ban_status_format prometheus;
    }
--- request
GET /metrics
--- response_body_like chomp
shield_hits_total\{zone="zone\\"\\\\name\\nline",category="sqli"\} 0\n
--- error_code: 200

=== TEST 13: long zone label cannot truncate a metrics document
--- http_config eval
"shield_ban_zone " . ("z" x 4000) . ":1m;"
--- config eval
"location /metrics { shield_ban_status " . ("z" x 4000)
. "; shield_ban_status_format prometheus; }"
--- request
GET /metrics
--- response_body_like eval
qr/shield_banned_clients\{zone="z{4000}"\} 0\n# EOF\n\z/
--- error_code: 200

=== TEST 14: expired bans remain nodes but are not currently banned
--- http_config
    shield_ban_zone metrics14:1m;
--- config
    location /t {
        shield block;
        shield_ban zone=metrics14 count=1 window=60s bantime=1s;
        empty_gif;
    }
    location /metrics {
        shield_ban_status metrics14;
        shield_ban_status_format prometheus;
    }
--- request eval
["GET /t?id=1%20union%20select%20pw", "GET /metrics"]
--- wait: 2
--- response_body_like eval
[qr/./, qr/shield_bans_total\{zone="metrics14"\} 1\n.*shield_zone_nodes\{zone="metrics14"\} 1\n.*shield_banned_clients\{zone="metrics14"\} 0\n# EOF\n\z/s]
--- error_code eval
[403, 200]

=== TEST 15: structural category counters are included
--- http_config
    shield_ban_zone metrics15:1m;
--- config
    location /t {
        shield block;
        shield_ban zone=metrics15 count=9 window=60s bantime=30s;
        empty_gif;
    }
    location /metrics {
        shield_ban_status metrics15;
        shield_ban_status_format prometheus;
    }
--- more_headers
Proxy: attacker.example
--- request eval
["GET /t", "GET /metrics"]
--- response_body_like eval
[qr/./, qr/category="httpoxy"\} 1\n.*shield_blocked_total\{zone="metrics15"\} 1\n.*shield_bans_total\{zone="metrics15"\} 0\n/s]
--- error_code eval
[403, 200]

=== TEST 16: format is not allowed in http context
--- http_config
    shield_ban_status_format prometheus;
--- config
    location /t { empty_gif; }
--- must_die
--- error_log
"shield_ban_status_format" directive is not allowed here

=== TEST 17: extra argument is rejected
--- config
    location /metrics { shield_ban_status_format json prometheus; }
--- must_die
--- error_log
invalid number of arguments in "shield_ban_status_format" directive
