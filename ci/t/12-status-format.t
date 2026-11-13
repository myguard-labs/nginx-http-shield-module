# Native JSON and negotiated metrics status; exact empty exposition also guards stable zero series.
use Test::Nginx::Socket 'no_plan';
use JSON::PP qw(decode_json);
use Test::More ();

add_response_body_check(sub {
    my ($block, $body, $req_idx, $repeated_req_idx, $dry_run) = @_;
    my $expected = $block->json_zone;

    return if !defined $expected;

    SKIP: {
        Test::More::skip(
            $block->name . " - parsed JSON checks skipped due to $dry_run", 2
        ) if $dry_run;

        my $decoded = eval { decode_json($body) };
        my $error = $@;

        Test::More::ok(!$error, $block->name . ' - response parses as JSON');
        Test::More::is(
            defined $decoded ? $decoded->{zone} : undef,
            $expected,
            $block->name . ' - parsed zone preserves configured bytes'
        );
    }
});

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
[(qr/^\{"zone":"metrics1","nodes":0,"blocked":0,"bans":0,"inspected":0,"ban_refused":0,"evictions":0,"alloc_failures":0,"used":\d+,"size":1048576,"body_uninspected":\{"too_large":0,"encoding":0,"error":0\},"categories":\{.*\},"detections":\{.*\},"banned":\[\]\}$/) x 2]
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
--- more_headers
Accept: application/openmetrics-text
--- request
GET /metrics
--- response_body_like eval
my @cats = qw(sqli xss traversal overlong cmdi lfi crlf nullbyte template
              deserial shellshock php_rce java_rce java_eval rails_yaml drupal
              vbulletin xmlrpc ssi imagetragick httpoxy range_dos sensitive_file
              webshell ssrf_meta nosql ssti exploit_path ctrl_char dotfile);
my $expected = "# HELP shield_hits Shield signature hits by category.\n"
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
. "# HELP shield_requests Shield requests inspected.\n"
. "# TYPE shield_requests counter\n"
. "shield_requests_total{zone=\"metrics2\"} 0\n"
. "# HELP shield_ban_refusals Shield requests refused by an active ban.\n"
. "# TYPE shield_ban_refusals counter\n"
. "shield_ban_refusals_total{zone=\"metrics2\"} 0\n"
. "# HELP shield_zone_evictions Shield zone nodes evicted.\n"
. "# TYPE shield_zone_evictions counter\n"
. "shield_zone_evictions_total{zone=\"metrics2\"} 0\n"
. "# HELP shield_zone_alloc_failures Shield zone node allocation failures.\n"
. "# TYPE shield_zone_alloc_failures counter\n"
. "shield_zone_alloc_failures_total{zone=\"metrics2\"} 0\n"
. "# HELP shield_zone_used_bytes Shield zone bytes reserved including slab overhead.\n"
. "# TYPE shield_zone_used_bytes gauge\n"
. "shield_zone_used_bytes{zone=\"metrics2\"} USED\n"
. "# HELP shield_zone_size_bytes Shield zone size in bytes.\n"
. "# TYPE shield_zone_size_bytes gauge\n"
. "shield_zone_size_bytes{zone=\"metrics2\"} 1048576\n"
. "# HELP shield_detections Shield detections by category and mode.\n"
. "# TYPE shield_detections counter\n"
. CORE::join('', map { "shield_detections_total{zone=\"metrics2\",category=\"$_\",mode=\"detect\"} 0\nshield_detections_total{zone=\"metrics2\",category=\"$_\",mode=\"block\"} 0\n" } @cats)
. "# HELP shield_source_hits Shield signature hits by category and source.\n"
. "# TYPE shield_source_hits counter\n"
. CORE::join('', map { my $cat = $_; map { "shield_source_hits_total{zone=\"metrics2\",category=\"$cat\",source=\"$_\"} 0\n" } qw(uri header range user-agent referer content-type body) } @cats)
. "# HELP shield_body_uninspected Shield bodies with incomplete inspection by reason.\n"
. "# TYPE shield_body_uninspected counter\n"
. CORE::join('', map { "shield_body_uninspected_total{zone=\"metrics2\",reason=\"$_\"} 0\n" } qw(too_large encoding error))
. "# EOF\n";
my $pattern = quotemeta($expected);
$pattern =~ s/USED/[1-9][0-9]*/;
qr/\A$pattern\z/
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
--- more_headers
Accept: application/openmetrics-text
--- request eval
["GET /t?id=1%20union%20select%20pw", "GET /t?id=1%20union%20select%20pw",
 "GET /t", "GET /metrics", "GET /json"]
--- response_body_like eval
[qr/./, qr/./, qr/./,
 qr/shield_hits_total\{zone="metrics3",category="sqli"\} 2\n.*shield_blocked_total\{zone="metrics3"\} 2\n.*shield_bans_total\{zone="metrics3"\} 1\n.*shield_zone_nodes\{zone="metrics3"\} 1\n.*shield_banned_clients\{zone="metrics3"\} 1\n.*shield_requests_total\{zone="metrics3"\} 2\n.*shield_ban_refusals_total\{zone="metrics3"\} 1\n.*category="sqli",mode="detect"\} 0\n.*category="sqli",mode="block"\} 2\n.*shield_source_hits_total\{zone="metrics3",category="sqli",source="uri"\} 2\n.*# EOF\n\z/s,
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
--- more_headers
Accept: application/openmetrics-text
--- request eval
["GET /t?id=1%20union%20select%20pw", "GET /metrics"]
--- response_body_like eval
[qr/./, qr/category="sqli"\} 1\n.*shield_blocked_total\{zone="metrics4"\} 0\n.*shield_bans_total\{zone="metrics4"\} 0\n.*shield_zone_nodes\{zone="metrics4"\} 1\n.*shield_banned_clients\{zone="metrics4"\} 0\n.*category="sqli",mode="detect"\} 1\n.*category="sqli",mode="block"\} 0\n/s]
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
--- more_headers
Accept: application/openmetrics-text
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
--- more_headers
Accept: application/openmetrics-text
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
--- more_headers
Accept: application/openmetrics-text
--- request eval
["GET /status/metrics", "GET /status/json"]
--- response_body_like eval
[qr/\nshield_banned_clients\{zone="metrics11"\} 0\n.*# EOF\n\z/s,
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
--- more_headers
Accept: application/openmetrics-text
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
--- more_headers
Accept: application/openmetrics-text
--- request
GET /metrics
--- response_body_like eval
qr/shield_banned_clients\{zone="z{4000}"\} 0\n.*# EOF\n\z/s
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
--- more_headers
Accept: application/openmetrics-text
--- request eval
["GET /t?id=1%20union%20select%20pw", "GET /metrics"]
--- wait: 2
--- response_body_like eval
[qr/./, qr/shield_bans_total\{zone="metrics14"\} 1\n.*shield_zone_nodes\{zone="metrics14"\} 1\n.*shield_banned_clients\{zone="metrics14"\} 0\n.*# EOF\n\z/ss]
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
Accept: application/openmetrics-text
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

=== TEST 18: default JSON escapes a legal quote and backslash zone name
--- http_config
    shield_ban_zone 'json"\\name:1m';
--- config
    location /status { shield_ban_status 'json"\\name'; }
--- request
GET /status
--- json_zone eval
"json\"\\name"
--- response_headers
Content-Type: application/json
--- error_code: 200

=== TEST 19: exact body cap is complete; one byte more counts once
--- http_config
    shield_ban_zone body19:1m;
--- config
    location /t {
        shield block;
        shield_max_body 4;
        shield_ban zone=body19 count=9 window=60s bantime=30s;
        empty_gif;
    }
    location /metrics { shield_ban_status body19; }
--- request eval
["POST /t\nabcd", "GET /metrics", "POST /t\nabcde", "GET /metrics"]
--- response_body_like eval
[qr/./, qr/"body_uninspected":\{"too_large":0,"encoding":0,"error":0\}/,
 qr/./, qr/"body_uninspected":\{"too_large":1,"encoding":0,"error":0\}/]
--- error_code eval
[405, 200, 405, 200]

=== TEST 20: unsupported encoding takes precedence over oversized body
--- http_config
    shield_ban_zone body20:1m;
--- config
    location /t {
        shield block;
        shield_max_body 4;
        shield_ban zone=body20 count=9 window=60s bantime=30s;
        empty_gif;
    }
    location /metrics { shield_ban_status body20; }
--- more_headers
Content-Encoding: gzip
--- request eval
["POST /t\nabcde", "GET /metrics"]
--- response_body_like eval
[qr/./, qr/"body_uninspected":\{"too_large":0,"encoding":1,"error":0\}/]
--- error_code eval
[405, 200]

=== TEST 21: identity encoding is complete at the cap
--- http_config
    shield_ban_zone body21:1m;
--- config
    location /t {
        shield block;
        shield_max_body 4;
        shield_ban zone=body21 count=9 window=60s bantime=30s;
        empty_gif;
    }
    location /metrics { shield_ban_status body21; }
--- more_headers
Content-Encoding: Identity
--- request eval
["POST /t\nabcd", "GET /metrics"]
--- response_body_like eval
[qr/./, qr/"body_uninspected":\{"too_large":0,"encoding":0,"error":0\}/]
--- error_code eval
[405, 200]

=== TEST 22: duplicate encodings include an unsupported value
--- http_config
    shield_ban_zone body22:1m;
--- config
    location /t {
        shield block;
        shield_ban zone=body22 count=9 window=60s bantime=30s;
        empty_gif;
    }
    location /metrics { shield_ban_status body22; }
--- more_headers
Content-Encoding: identity
Content-Encoding: gzip
--- request eval
["POST /t\nabcd", "GET /metrics"]
--- response_body_like eval
[qr/./, qr/"body_uninspected":\{"too_large":0,"encoding":1,"error":0\}/]
--- error_code eval
[405, 200]

=== TEST 23: named redirect does not count the same body twice
--- http_config
    shield_ban_zone body23:1m;
--- config
    shield block;
    shield_max_body 4;
    shield_ban zone=body23 count=9 window=60s bantime=30s;
    location /t { error_page 405 = @again; empty_gif; }
    location @again { empty_gif; }
    location /metrics { shield off; shield_ban_status body23; }
--- request eval
["POST /t\nabcde", "GET /metrics"]
--- response_body_like eval
[qr/./, qr/"body_uninspected":\{"too_large":1,"encoding":0,"error":0\}/]
--- error_code eval
[405, 200]

=== TEST 24: redirect counts incomplete inspection in each distinct zone
--- http_config
    shield_ban_zone body24a:1m;
    shield_ban_zone body24b:1m;
--- config
    shield block;
    shield_max_body 4;
    location /t {
        shield_ban zone=body24a count=9 window=60s bantime=30s;
        error_page 405 = @again;
        empty_gif;
    }
    location @again {
        shield_ban zone=body24b count=9 window=60s bantime=30s;
        empty_gif;
    }
    location /a { shield off; shield_ban_status body24a; }
    location /b { shield off; shield_ban_status body24b; }
--- request eval
["POST /t\nabcde", "GET /a", "GET /b"]
--- response_body_like eval
[qr/./, (qr/"body_uninspected":\{"too_large":1,"encoding":0,"error":0\}/) x 2]
--- error_code eval
[405, 200, 200]

=== TEST 25: JSON default ignores Accept
--- http_config
    shield_ban_zone negotiate18:1m;
--- config
    location /m {
        shield_ban_status negotiate18;
    }
--- more_headers
Accept: application/openmetrics-text
--- request
GET /m
--- response_body_like: ^\{"zone":
--- response_headers
Content-Type: application/json
Vary: Accept
--- error_code: 200

=== TEST 26: query overrides JSON default
--- http_config
    shield_ban_zone negotiate19:1m;
--- config
    location /m {
        shield_ban_status negotiate19;
    }
--- request
GET /m?format=prometheus
--- response_body_like: \A# HELP shield_hits_total .*reason="error"\} 0\n\z
--- response_headers
Content-Type: text/plain; version=0.0.4; charset=utf-8
Vary: Accept
--- error_code: 200

=== TEST 27: query overrides metrics directive
--- http_config
    shield_ban_zone negotiate20:1m;
--- config
    location /m {
        shield_ban_status negotiate20;
        shield_ban_status_format prometheus;
    }
--- more_headers
Accept: application/openmetrics-text
--- request
GET /m?format=json
--- response_body_like: ^\{"zone":
--- response_headers
Content-Type: application/json
Vary: Accept
--- error_code: 200

=== TEST 28: metrics default without Accept
--- http_config
    shield_ban_zone negotiate21:1m;
--- config
    location /m {
        shield_ban_status negotiate21;
        shield_ban_status_format prometheus;
    }
--- request
GET /m
--- response_body_like: \A# HELP shield_hits_total .*reason="error"\} 0\n\z
--- response_headers
Content-Type: text/plain; version=0.0.4; charset=utf-8
Vary: Accept
--- error_code: 200

=== TEST 29: wildcard does not opt into OM
--- http_config
    shield_ban_zone negotiate22:1m;
--- config
    location /m {
        shield_ban_status negotiate22;
        shield_ban_status_format prometheus;
    }
--- more_headers
Accept: */*
--- request
GET /m
--- response_body_like: \A# HELP shield_hits_total .*reason="error"\} 0\n\z
--- response_headers
Content-Type: text/plain; version=0.0.4; charset=utf-8
Vary: Accept
--- error_code: 200

=== TEST 30: exact OM media type case insensitive
--- http_config
    shield_ban_zone negotiate23:1m;
--- config
    location /m {
        shield_ban_status negotiate23;
        shield_ban_status_format prometheus;
    }
--- more_headers
Accept: APPLICATION/OPENMETRICS-TEXT
--- request
GET /m
--- response_body_like: \A# HELP shield_hits .*# EOF\n\z
--- response_headers
Content-Type: application/openmetrics-text; version=1.0.0; charset=utf-8
Vary: Accept
--- error_code: 200

=== TEST 31: OM parameters and q
--- http_config
    shield_ban_zone negotiate24:1m;
--- config
    location /m {
        shield_ban_status negotiate24;
    }
--- more_headers
Accept: application/openmetrics-text;version="1.0.0";charset=UTF-8;q=0.999
--- request
GET /m?format=prometheus
--- response_body_like: \A# HELP shield_hits .*# EOF\n\z
--- response_headers
Content-Type: application/openmetrics-text; version=1.0.0; charset=utf-8
Vary: Accept
--- error_code: 200

=== TEST 32: q zero excludes OM
--- http_config
    shield_ban_zone negotiate25:1m;
--- config
    location /m {
        shield_ban_status negotiate25;
        shield_ban_status_format prometheus;
    }
--- more_headers
Accept: application/openmetrics-text;q=0
--- request
GET /m
--- response_body_like: \A# HELP shield_hits_total .*reason="error"\} 0\n\z
--- response_headers
Content-Type: text/plain; version=0.0.4; charset=utf-8
Vary: Accept
--- error_code: 200

=== TEST 33: plain higher priority
--- http_config
    shield_ban_zone negotiate26:1m;
--- config
    location /m {
        shield_ban_status negotiate26;
        shield_ban_status_format prometheus;
    }
--- more_headers
Accept: application/openmetrics-text;q=0.5, text/plain;q=0.9
--- request
GET /m
--- response_body_like: \A# HELP shield_hits_total .*reason="error"\} 0\n\z
--- response_headers
Content-Type: text/plain; version=0.0.4; charset=utf-8
Vary: Accept
--- error_code: 200

=== TEST 34: OM higher priority
--- http_config
    shield_ban_zone negotiate27:1m;
--- config
    location /m {
        shield_ban_status negotiate27;
        shield_ban_status_format prometheus;
    }
--- more_headers
Accept: text/plain;q=0.1, application/openmetrics-text;q=0.9
--- request
GET /m
--- response_body_like: \A# HELP shield_hits .*# EOF\n\z
--- response_headers
Content-Type: application/openmetrics-text; version=1.0.0; charset=utf-8
Vary: Accept
--- error_code: 200

=== TEST 35: OM wins tie
--- http_config
    shield_ban_zone negotiate28:1m;
--- config
    location /m {
        shield_ban_status negotiate28;
        shield_ban_status_format prometheus;
    }
--- more_headers
Accept: text/plain, application/openmetrics-text
--- request
GET /m
--- response_body_like: \A# HELP shield_hits .*# EOF\n\z
--- response_headers
Content-Type: application/openmetrics-text; version=1.0.0; charset=utf-8
Vary: Accept
--- error_code: 200

=== TEST 36: unsupported OM version
--- http_config
    shield_ban_zone negotiate29:1m;
--- config
    location /m {
        shield_ban_status negotiate29;
        shield_ban_status_format prometheus;
    }
--- more_headers
Accept: application/openmetrics-text;version=2.0.0
--- request
GET /m
--- response_body_like: \A# HELP shield_hits_total .*reason="error"\} 0\n\z
--- response_headers
Content-Type: text/plain; version=0.0.4; charset=utf-8
Vary: Accept
--- error_code: 200

=== TEST 37: invalid quality
--- http_config
    shield_ban_zone negotiate30:1m;
--- config
    location /m {
        shield_ban_status negotiate30;
        shield_ban_status_format prometheus;
    }
--- more_headers
Accept: application/openmetrics-text;q=1.1
--- request
GET /m
--- response_body_like: \A# HELP shield_hits_total .*reason="error"\} 0\n\z
--- response_headers
Content-Type: text/plain; version=0.0.4; charset=utf-8
Vary: Accept
--- error_code: 200

=== TEST 38: duplicate quality
--- http_config
    shield_ban_zone negotiate31:1m;
--- config
    location /m {
        shield_ban_status negotiate31;
        shield_ban_status_format prometheus;
    }
--- more_headers
Accept: application/openmetrics-text;q=1;q=0
--- request
GET /m
--- response_body_like: \A# HELP shield_hits_total .*reason="error"\} 0\n\z
--- response_headers
Content-Type: text/plain; version=0.0.4; charset=utf-8
Vary: Accept
--- error_code: 200

=== TEST 39: unclosed quoted parameter
--- http_config
    shield_ban_zone negotiate32:1m;
--- config
    location /m {
        shield_ban_status negotiate32;
        shield_ban_status_format prometheus;
    }
--- more_headers
Accept: application/openmetrics-text;version="1.0.0
--- request
GET /m
--- response_body_like: \A# HELP shield_hits_total .*reason="error"\} 0\n\z
--- response_headers
Content-Type: text/plain; version=0.0.4; charset=utf-8
Vary: Accept
--- error_code: 200

=== TEST 40: substring is not a media match
--- http_config
    shield_ban_zone negotiate33:1m;
--- config
    location /m {
        shield_ban_status negotiate33;
        shield_ban_status_format prometheus;
    }
--- more_headers
Accept: application/openmetrics-text-extra
--- request
GET /m
--- response_body_like: \A# HELP shield_hits_total .*reason="error"\} 0\n\z
--- response_headers
Content-Type: text/plain; version=0.0.4; charset=utf-8
Vary: Accept
--- error_code: 200

=== TEST 41: unrelated args allowed
--- http_config
    shield_ban_zone negotiate34:1m;
--- config
    location /m {
        shield_ban_status negotiate34;
    }
--- more_headers
Accept: application/openmetrics-text
--- request
GET /m?x=1&format=prometheus&y=2
--- response_body_like: \A# HELP shield_hits .*# EOF\n\z
--- response_headers
Content-Type: application/openmetrics-text; version=1.0.0; charset=utf-8
Vary: Accept
--- error_code: 200

=== TEST 42: empty query rejected
--- http_config
    shield_ban_zone negotiate35:1m;
--- config
    location /m {
        shield_ban_status negotiate35;
    }
--- request
GET /m?format=
--- error_code: 400

=== TEST 43: bare query rejected
--- http_config
    shield_ban_zone negotiate36:1m;
--- config
    location /m {
        shield_ban_status negotiate36;
    }
--- request
GET /m?format
--- error_code: 400

=== TEST 44: invalid query rejected
--- http_config
    shield_ban_zone negotiate37:1m;
--- config
    location /m {
        shield_ban_status negotiate37;
    }
--- request
GET /m?format=xml
--- error_code: 400

=== TEST 45: duplicate query rejected
--- http_config
    shield_ban_zone negotiate38:1m;
--- config
    location /m {
        shield_ban_status negotiate38;
    }
--- request
GET /m?format=json&format=prometheus
--- error_code: 400

=== TEST 46: identical duplicate rejected
--- http_config
    shield_ban_zone negotiate39:1m;
--- config
    location /m {
        shield_ban_status negotiate39;
    }
--- request
GET /m?format=json&format=json
--- error_code: 400

=== TEST 47: encoded value not decoded
--- http_config
    shield_ban_zone negotiate40:1m;
--- config
    location /m {
        shield_ban_status negotiate40;
    }
--- request
GET /m?format=%6ason
--- error_code: 400

=== TEST 48: query names case sensitive
--- http_config
    shield_ban_zone negotiate41:1m;
--- config
    location /m {
        shield_ban_status negotiate41;
    }
--- request
GET /m?FORMAT=prometheus
--- response_body_like: ^\{"zone":
--- response_headers
Content-Type: application/json
Vary: Accept
--- error_code: 200

=== TEST 49: malformed later member falls back
--- http_config
    shield_ban_zone negotiate42:1m;
--- config
    location /m {
        shield_ban_status negotiate42;
        shield_ban_status_format prometheus;
    }
--- more_headers
Accept: application/openmetrics-text, broken
--- request
GET /m
--- response_body_like: \A# HELP shield_hits_total .*reason="error"\} 0\n\z
--- response_headers
Content-Type: text/plain; version=0.0.4; charset=utf-8
Vary: Accept
--- error_code: 200

=== TEST 50: repeated Accept fields combined
--- http_config
    shield_ban_zone negotiate43:1m;
--- config
    location /m {
        shield_ban_status negotiate43;
        shield_ban_status_format prometheus;
    }
--- more_headers
Accept: text/plain;q=0.2
Accept: application/openmetrics-text;q=0.9
--- request
GET /m
--- response_body_like: \A# HELP shield_hits .*# EOF\n\z
--- response_headers
Content-Type: application/openmetrics-text; version=1.0.0; charset=utf-8
Vary: Accept
--- error_code: 200

=== TEST 51: HEAD Prometheus
--- http_config
    shield_ban_zone negotiate44:1m;
--- config
    location /m {
        shield_ban_status negotiate44;
    }
--- request
HEAD /m?format=prometheus
--- response_body
--- response_headers
Content-Type: text/plain; version=0.0.4; charset=utf-8
Vary: Accept
--- error_code: 200

=== TEST 52: Accept item limit
--- http_config
    large_client_header_buffers 4 16k;
    shield_ban_zone budget:1m;
--- config
    location /m {
        shield_ban_status budget;
        shield_ban_status_format prometheus;
    }
--- more_headers
Accept: text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,application/openmetrics-text
--- request
GET /m
--- response_body_like: \A# HELP shield_hits .*# EOF\n\z
--- response_headers
Content-Type: application/openmetrics-text; version=1.0.0; charset=utf-8
Vary: Accept
--- error_code: 200

=== TEST 53: Accept over item limit
--- http_config
    large_client_header_buffers 4 16k;
    shield_ban_zone budget:1m;
--- config
    location /m {
        shield_ban_status budget;
        shield_ban_status_format prometheus;
    }
--- more_headers
Accept: text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,text/plain;q=0,application/openmetrics-text
--- request
GET /m
--- response_body_like: \A# HELP shield_hits_total .*reason="error"\} 0\n\z
--- response_headers
Content-Type: text/plain; version=0.0.4; charset=utf-8
Vary: Accept
--- error_code: 200

=== TEST 54: Accept malformed second field
--- http_config
    large_client_header_buffers 4 16k;
    shield_ban_zone budget:1m;
--- config
    location /m {
        shield_ban_status budget;
        shield_ban_status_format prometheus;
    }
--- more_headers
Accept: application/openmetrics-text
Accept: broken
--- request
GET /m
--- response_body_like: \A# HELP shield_hits_total .*reason="error"\} 0\n\z
--- response_headers
Content-Type: text/plain; version=0.0.4; charset=utf-8
Vary: Accept
--- error_code: 200

=== TEST 55: Accept combined bytes limit
--- http_config
    large_client_header_buffers 4 16k;
    shield_ban_zone budget:1m;
--- config
    location /m {
        shield_ban_status budget;
        shield_ban_status_format prometheus;
    }
--- more_headers eval
"Accept: application/openmetrics-text;q=1;x=" . ("a" x 4900) . "\nAccept: text/plain;q=0;x=" . ("b" x 4900)
--- request
GET /m
--- response_body_like: \A# HELP shield_hits_total .*reason="error"\} 0\n\z
--- response_headers
Content-Type: text/plain; version=0.0.4; charset=utf-8
Vary: Accept
--- error_code: 200

=== TEST 56: Accept exact bytes limit
--- http_config
    large_client_header_buffers 4 16k;
    shield_ban_zone budget:1m;
--- config
    location /m {
        shield_ban_status budget;
        shield_ban_status_format prometheus;
    }
--- more_headers eval
"Accept: application/openmetrics-text;q=1;x=" . ("a" x 8157)
--- request
GET /m
--- response_body_like: \A# HELP shield_hits .*# EOF\n\z
--- response_headers
Content-Type: application/openmetrics-text; version=1.0.0; charset=utf-8
Vary: Accept
--- error_code: 200

=== TEST 57: Accept over bytes limit
--- http_config
    large_client_header_buffers 4 16k;
    shield_ban_zone budget:1m;
--- config
    location /m {
        shield_ban_status budget;
        shield_ban_status_format prometheus;
    }
--- more_headers eval
"Accept: application/openmetrics-text;q=1;x=" . ("a" x 8158)
--- request
GET /m
--- response_body_like: \A# HELP shield_hits_total .*reason="error"\} 0\n\z
--- response_headers
Content-Type: text/plain; version=0.0.4; charset=utf-8
Vary: Accept
--- error_code: 200

=== TEST 58: Accept after a full nginx header list part
--- http_config
    shield_ban_zone listpart:1m;
--- config
    location /m {
        shield_ban_status listpart;
        shield_ban_status_format prometheus;
    }
--- more_headers eval
CORE::join("\n", (map { "X-Padding-$_: x" } 1..25),
           "Accept: application/openmetrics-text")
--- request
GET /m
--- response_body_like: \A# HELP shield_hits .*# EOF\n\z
--- response_headers
Content-Type: application/openmetrics-text; version=1.0.0; charset=utf-8
Vary: Accept
--- error_code: 200

=== TEST 59: query budget 8192 bytes
--- http_config
    large_client_header_buffers 4 16k;
    shield_ban_zone querybudget:1m;
--- config
    location /m { shield_ban_status querybudget; }
--- request eval
"GET /m?format=prometheus&x=" . ("a" x 8172)
--- response_body_like: \A# HELP shield_hits_total .*reason="error"\} 0\n\z
--- response_headers
Content-Type: text/plain; version=0.0.4; charset=utf-8
Vary: Accept
--- error_code: 200

=== TEST 60: query budget 8193 bytes
--- http_config
    large_client_header_buffers 4 16k;
    shield_ban_zone querybudget:1m;
--- config
    location /m { shield_ban_status querybudget; }
--- request eval
"GET /m?format=prometheus&x=" . ("a" x 8173)
--- error_code: 400

=== TEST 61: HTAB in quoted Accept extension
--- http_config
    shield_ban_zone quotedtab:1m;
--- config
    location /m {
        shield_ban_status quotedtab;
        shield_ban_status_format prometheus;
    }
--- more_headers eval
"Accept: application/openmetrics-text;q=1;x=\"a\tb\""
--- request
GET /m
--- response_body_like: \A# HELP shield_hits .*# EOF\n\z
--- response_headers
Content-Type: application/openmetrics-text; version=1.0.0; charset=utf-8
Vary: Accept
--- error_code: 200

=== TEST 62: escaped HTAB in quoted Accept extension
--- http_config
    shield_ban_zone quotedtab:1m;
--- config
    location /m {
        shield_ban_status quotedtab;
        shield_ban_status_format prometheus;
    }
--- more_headers eval
"Accept: application/openmetrics-text;q=1;x=\"a\\\tb\""
--- request
GET /m
--- response_body_like: \A# HELP shield_hits .*# EOF\n\z
--- response_headers
Content-Type: application/openmetrics-text; version=1.0.0; charset=utf-8
Vary: Accept
--- error_code: 200

=== TEST 63: counters-only zone supports the unchanged JSON schema
--- http_config
    shield_stats_zone stats30 32k;
--- config
    location /status { shield_ban_status stats30; }
--- request
GET /status
--- response_body_like: ^\{"zone":"stats30","nodes":0,"blocked":0,"bans":0,"inspected":0,"ban_refused":0,"evictions":0,"alloc_failures":0,"used":\d+,"size":32768,.*"banned":\[\]\}$
--- response_headers
Content-Type: application/json
--- error_code: 200

=== TEST 64: counters-only zone supports negotiated OpenMetrics
--- http_config
    shield_stats_zone stats31 32k;
--- config
    location /metrics {
        shield_ban_status stats31;
        shield_ban_status_format prometheus;
    }
--- request
GET /metrics
--- more_headers
Accept: application/openmetrics-text
--- response_body_like: (?s)^# HELP shield_hits .*shield_requests_total\{zone="stats31"\} 0\n.*# EOF\n$
--- response_headers
Content-Type: application/openmetrics-text; version=1.0.0; charset=utf-8
--- error_code: 200
