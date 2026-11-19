# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
# Ambiguous body content is observed, with strict enforcement explicitly opted in.
use Test::Nginx::Socket 'no_plan';
use IO::Socket::INET;
use IO::Select;

my $syslog_socket;
add_block_preprocessor(sub {
    my ($block) = @_;
    return unless $block->observe_syslog;
    $syslog_socket = IO::Socket::INET->new(
        LocalAddr => '127.0.0.1', LocalPort => 0, Proto => 'udp',
    ) or die "open local syslog recorder: $!";
    my $port = $syslog_socket->sockport();
    $block->set_value('config', $block->config()
        . "\nerror_log syslog:server=127.0.0.1:$port notice;\n");
});

repeat_each(1);
no_long_string();
add_test_cleanup_handler(sub {
    my ($block) = @_;
    if ($block->observe_syslog) {
        my $select = IO::Select->new($syslog_socket);
        my $events = '';
        while ($select->can_read(0)) {
            my $event = '';
            $syslog_socket->recv($event, 65535) or die "receive syslog: $!";
            $events .= $event;
        }
        close $syslog_socket or die "close local syslog recorder: $!";
        Test::More::like($events, qr/shield: blocked request/,
                         'syslog recorder receives the enforced control');
        Test::More::unlike($events, qr/shield: observed body marker/,
                           'observation never enters syslog writer');
    }
    if ($block->observe_count) {
        open my $errors, '<', server_root() . '/logs/error.log' or die $!;
        my @notices = grep { /shield: observed body marker/ } <$errors>;
        close $errors or die $!;
        Test::More::is(scalar @notices, $block->observe_count,
                      'only the eligible request is observed');
        Test::More::unlike(join('', @notices), qr/request:|ht05_secret_canary/,
                          'observation contains no request context or secret');
    }
    return unless $block->observe_no_report;
    my $path = server_root() . '/logs/precision-hit.log';
    open my $fh, '<', $path or die "open precision hit log: $!";
    local $/;
    my $content = <$fh>;
    close $fh or die "close precision hit log: $!";
    Test::More::is($content // '', '', 'observation never enters reporter hit log');
});
run_tests();

__DATA__

=== TEST 1: sqli exact body marker observed by compiled default
--- config
location /t { shield block; empty_gif; }
--- request
POST /t
union select
--- more_headers
Content-Type: text/plain
--- error_code: 405
--- error_log
category=sqli source=body verdict=suspicious action=observe
--- no_error_log
shield: blocked request

=== TEST 2: sqli strict body marker enforced
--- config
location /t { shield block; shield_body_strict on; empty_gif; }
--- request
POST /t
union select
--- more_headers
Content-Type: text/plain
--- error_code: 403
--- error_log
category=sqli source=body

=== TEST 3: sqli URI policy retained
--- config
location /t { shield block; empty_gif; }
--- request
GET /t?x=union%20select
--- error_code: 403
--- error_log
category=sqli source=uri

=== TEST 4: sqli header policy retained
--- config
location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
User-Agent: union select
--- error_code: 403
--- error_log
category=sqli source=user-agent

=== TEST 5: overlong exact body marker observed by compiled default
--- config
location /t { shield block; empty_gif; }
--- request
POST /t
%c0%af
--- more_headers
Content-Type: text/plain
--- error_code: 405
--- error_log
category=overlong source=body verdict=suspicious action=observe
--- no_error_log
shield: blocked request

=== TEST 6: overlong strict body marker enforced
--- config
location /t { shield block; shield_body_strict on; empty_gif; }
--- request
POST /t
%c0%af
--- more_headers
Content-Type: text/plain
--- error_code: 403
--- error_log
category=overlong source=body

=== TEST 7: overlong URI policy retained
--- config
location /t { shield block; empty_gif; }
--- request
GET /t?x=%c0%af
--- error_code: 403
--- error_log
category=overlong source=uri

=== TEST 8: overlong header policy retained
--- config
location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
User-Agent: %c0%af
--- error_code: 403
--- error_log
category=overlong source=user-agent

=== TEST 9: rails_yaml exact body marker observed by compiled default
--- config
location /t { shield block; empty_gif; }
--- request
POST /t
!ruby/object:
--- more_headers
Content-Type: text/plain
--- error_code: 405
--- error_log
category=rails_yaml source=body verdict=suspicious action=observe
--- no_error_log
shield: blocked request

=== TEST 10: rails_yaml strict body marker enforced
--- config
location /t { shield block; shield_body_strict on; empty_gif; }
--- request
POST /t
!ruby/object:
--- more_headers
Content-Type: text/plain
--- error_code: 403
--- error_log
category=rails_yaml source=body

=== TEST 11: rails_yaml URI policy retained
--- config
location /t { shield block; empty_gif; }
--- request
GET /t?x=%21ruby/object%3A
--- error_code: 403
--- error_log
category=rails_yaml source=uri

=== TEST 12: rails_yaml header policy retained
--- config
location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
User-Agent: !ruby/object:
--- error_code: 403
--- error_log
category=rails_yaml source=user-agent

=== TEST 13: ssi exact body marker observed by compiled default
--- config
location /t { shield block; empty_gif; }
--- request
POST /t
<!--#include virtual
--- more_headers
Content-Type: text/plain
--- error_code: 405
--- error_log
category=ssi source=body verdict=suspicious action=observe
--- no_error_log
shield: blocked request

=== TEST 14: ssi strict body marker enforced
--- config
location /t { shield block; shield_body_strict on; empty_gif; }
--- request
POST /t
<!--#include virtual
--- more_headers
Content-Type: text/plain
--- error_code: 403
--- error_log
category=ssi source=body

=== TEST 15: ssi URI policy retained
--- config
location /t { shield block; empty_gif; }
--- request
GET /t?x=%3C%21--%23include%20virtual
--- error_code: 403
--- error_log
category=ssi source=uri

=== TEST 16: ssi header policy retained
--- config
location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
User-Agent: <!--#include virtual
--- error_code: 403
--- error_log
category=ssi source=user-agent

=== TEST 17: ssrf_meta exact body marker observed by compiled default
--- config
location /t { shield block; empty_gif; }
--- request
POST /t
169.254.169.254
--- more_headers
Content-Type: text/plain
--- error_code: 405
--- error_log
category=ssrf_meta source=body verdict=suspicious action=observe
--- no_error_log
shield: blocked request

=== TEST 18: ssrf_meta strict body marker enforced
--- config
location /t { shield block; shield_body_strict on; empty_gif; }
--- request
POST /t
169.254.169.254
--- more_headers
Content-Type: text/plain
--- error_code: 403
--- error_log
category=ssrf_meta source=body

=== TEST 19: ssrf_meta URI policy retained
--- config
location /t { shield block; empty_gif; }
--- request
GET /t?x=169.254.169.254
--- error_code: 403
--- error_log
category=ssrf_meta source=uri

=== TEST 20: ssrf_meta header policy retained
--- config
location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
User-Agent: 169.254.169.254
--- error_code: 403
--- error_log
category=ssrf_meta source=user-agent

=== TEST 21: ssrf_meta exact body marker observed by compiled default
--- config
location /t { shield block; empty_gif; }
--- request
POST /t
/latest/meta-data/
--- more_headers
Content-Type: text/plain
--- error_code: 405
--- error_log
category=ssrf_meta source=body verdict=suspicious action=observe
--- no_error_log
shield: blocked request

=== TEST 22: ssrf_meta strict body marker enforced
--- config
location /t { shield block; shield_body_strict on; empty_gif; }
--- request
POST /t
/latest/meta-data/
--- more_headers
Content-Type: text/plain
--- error_code: 403
--- error_log
category=ssrf_meta source=body

=== TEST 23: ssrf_meta URI policy retained
--- config
location /t { shield block; empty_gif; }
--- request
GET /t?x=/latest/meta-data/
--- error_code: 403
--- error_log
category=ssrf_meta source=uri

=== TEST 24: ssrf_meta header policy retained
--- config
location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
User-Agent: /latest/meta-data/
--- error_code: 403
--- error_log
category=ssrf_meta source=user-agent

=== TEST 25: nosql exact body marker observed by compiled default
--- config
location /t { shield block; empty_gif; }
--- request
POST /t
{"$where":
--- more_headers
Content-Type: text/plain
--- error_code: 405
--- error_log
category=nosql source=body verdict=suspicious action=observe
--- no_error_log
shield: blocked request

=== TEST 26: nosql strict body marker enforced
--- config
location /t { shield block; shield_body_strict on; empty_gif; }
--- request
POST /t
{"$where":
--- more_headers
Content-Type: text/plain
--- error_code: 403
--- error_log
category=nosql source=body

=== TEST 27: nosql URI policy retained
--- config
location /t { shield block; empty_gif; }
--- request
GET /t?x=%7B%22%24where%22%3A
--- error_code: 403
--- error_log
category=nosql source=uri

=== TEST 28: nosql header policy retained
--- config
location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
User-Agent: {"$where":
--- error_code: 403
--- error_log
category=nosql source=user-agent

=== TEST 29: ssti exact body marker observed by compiled default
--- config
location /t { shield block; empty_gif; }
--- request
POST /t
{{7*7}}
--- more_headers
Content-Type: text/plain
--- error_code: 405
--- error_log
category=ssti source=body verdict=suspicious action=observe
--- no_error_log
shield: blocked request

=== TEST 30: ssti strict body marker enforced
--- config
location /t { shield block; shield_body_strict on; empty_gif; }
--- request
POST /t
{{7*7}}
--- more_headers
Content-Type: text/plain
--- error_code: 403
--- error_log
category=ssti source=body

=== TEST 31: ssti URI policy retained
--- config
location /t { shield block; empty_gif; }
--- request
GET /t?x=%7B%7B7%2A7%7D%7D
--- error_code: 403
--- error_log
category=ssti source=uri

=== TEST 32: ssti header policy retained
--- config
location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
User-Agent: {{7*7}}
--- error_code: 403
--- error_log
category=ssti source=user-agent

=== TEST 33: repeated block observations never accumulate bans or reports
--- http_config
shield_ban_zone observed:1m;
--- config
shield block;
shield_log logs/precision-hit.log;
location /t { shield_ban zone=observed count=1 window=60s bantime=30s; empty_gif; }
location /status { shield_ban_status observed; }
--- request eval
[
    "POST /t\nunion select",
    "POST /t\nunion select",
    "POST /t\n%c0%af",
    "POST /t\n%c0%af",
    "POST /t\n!ruby/object:",
    "POST /t\n!ruby/object:",
    "POST /t\n<!--#include virtual",
    "POST /t\n<!--#include virtual",
    "POST /t\n169.254.169.254",
    "POST /t\n169.254.169.254",
    "POST /t\n/latest/meta-data/",
    "POST /t\n/latest/meta-data/",
    "POST /t\n{\"\$where\":",
    "POST /t\n{\"\$where\":",
    "POST /t\n{{7*7}}",
    "POST /t\n{{7*7}}",
    "GET /t",
    "GET /status"
]
--- more_headers
Content-Type: text/plain
--- error_code eval
[405, 405, 405, 405, 405, 405, 405, 405, 405, 405, 405, 405, 405, 405, 405, 405, 200, 200]
--- no_error_log
shield: banned request
--- observe_no_report: 1
--- response_body_like eval
[(qr/./) x 17, qr/"nodes":0,"blocked":0,"bans":0.*"sqli":0.*"banned":\[\]/s]

=== TEST 34: repeated detect observations never accumulate bans or reports
--- http_config
shield_ban_zone observed:1m;
--- config
shield detect;
shield_log logs/precision-hit.log;
location /t { shield_ban zone=observed count=1 window=60s bantime=30s; empty_gif; }
location /status { shield_ban_status observed; }
--- request eval
[
    "POST /t\nunion select",
    "POST /t\nunion select",
    "POST /t\n%c0%af",
    "POST /t\n%c0%af",
    "POST /t\n!ruby/object:",
    "POST /t\n!ruby/object:",
    "POST /t\n<!--#include virtual",
    "POST /t\n<!--#include virtual",
    "POST /t\n169.254.169.254",
    "POST /t\n169.254.169.254",
    "POST /t\n/latest/meta-data/",
    "POST /t\n/latest/meta-data/",
    "POST /t\n{\"\$where\":",
    "POST /t\n{\"\$where\":",
    "POST /t\n{{7*7}}",
    "POST /t\n{{7*7}}",
    "GET /t",
    "GET /status"
]
--- more_headers
Content-Type: text/plain
--- error_code eval
[405, 405, 405, 405, 405, 405, 405, 405, 405, 405, 405, 405, 405, 405, 405, 405, 200, 200]
--- no_error_log
shield: banned request
--- observe_no_report: 1
--- response_body_like eval
[(qr/./) x 17, qr/"nodes":0,"blocked":0,"bans":0.*"sqli":0.*"banned":\[\]/s]

=== TEST 35: strict inherited and explicitly withdrawn in child
--- config
shield_body_strict on;
location /strict { shield block; empty_gif; }
location /observe { shield block; shield_body_strict off; empty_gif; }
--- request eval
[
    "POST /strict\nunion select",
    "POST /observe?token=x\nunion select"
]
--- more_headers
Content-Type: text/plain
--- error_code eval
[403, 405]
--- observe_count: 1

=== TEST 36: observation cannot hide raw sibling or decoded sibling
--- config
location /t { shield block; empty_gif; }
--- request eval
[
    "POST /t\n%c0%af %e0%80%af",
    "POST /t\n%c0%af union/**/select",
    "POST /t\nunion select union/**/select"
]
--- more_headers
Content-Type: text/plain
--- error_code eval
[403, 403, 403]

=== TEST 37: observation cannot hide same-buffer SSRF AND rule
--- config
location /t { shield block; empty_gif; }
--- request
POST /t
169.254.169.254 169-254-169-254 .nip.io
--- more_headers
Content-Type: text/plain
--- error_code: 403
--- error_log
category=ssrf_meta source=body

=== TEST 38: category skip still suppresses observation
--- config
location /t { shield block; shield_skip sqli; empty_gif; }
--- request
POST /t
union select
--- more_headers
Content-Type: text/plain
--- error_code: 405
--- no_error_log
observed body marker

=== TEST 39: body off still suppresses inspection
--- config
location /t { shield block; shield_body off; empty_gif; }
--- request
POST /t
union select
--- more_headers
Content-Type: text/plain
--- error_code: 405
--- no_error_log
observed body marker

=== TEST 40: binary type does not gain body inspection
--- config
location /t { shield block; empty_gif; }
--- request
POST /t
union select
--- more_headers
Content-Type: application/octet-stream
--- error_code: 405
--- no_error_log
observed body marker

=== TEST 41: body cap is exact and never extended for a marker
--- config
location /t { shield block; shield_max_body 12; empty_gif; }
--- request eval
[
    "POST /t\nunion select",
    "POST /t\naunion select"
]
--- more_headers
Content-Type: text/plain
--- error_code eval
[405, 405]
--- observe_count: 1

=== TEST 42: temp-file observation preserves policy
--- config
location /t { shield block; client_body_buffer_size 512; shield_max_body 32k; empty_gif; }
--- request eval
[
    "POST /t\n" . ("a" x 12000) . "union select"
]
--- more_headers
Content-Type: text/plain
--- error_code eval
[405]
--- error_log
verdict=suspicious action=observe

=== TEST 43: malformed percent tail stays unclassified
--- config
location /t { shield block; empty_gif; }
--- request eval
[
    "POST /t\n%",
    "POST /t\n%0",
    "POST /t\n%GG"
]
--- more_headers
Content-Type: text/plain
--- error_code eval
[405, 405, 405]
--- no_error_log
observed body marker

=== TEST 44: invalid strict value
--- config
location /t { shield_body_strict perhaps; shield block; empty_gif; }
--- must_die
--- error_log
invalid value "perhaps"

=== TEST 45: duplicate strict value
--- config
location /t { shield_body_strict on; shield_body_strict off; shield block; empty_gif; }
--- must_die
--- error_log
is duplicate

=== TEST 46: strict still arms existing bans
--- http_config
shield_ban_zone strict:1m;
--- config
location /t { shield block; shield_body_strict on; shield_ban zone=strict count=1 window=60s bantime=30s; empty_gif; }
--- request eval
[
    "POST /t\nunion select",
    "GET /t"
]
--- more_headers
Content-Type: text/plain
--- error_code eval
[403, 403]

=== TEST 47: opted-in CVE profile outranks an observed generic marker
--- config
location /t { shield block; shield_cve craft_cms; empty_gif; }
--- request
POST /t
class=yii%5Crbac%5CPhpManager&itemFile=/shield-fixture-does-not-exist&note=union+select
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- error_code: 403
--- error_log
category=deserial source=body
--- no_error_log
observed body marker

=== TEST 48: disabled CVE profile does not promote observed generic marker
--- config
location /t { shield block; empty_gif; }
--- request
POST /t
class=yii%5Crbac%5CPhpManager&itemFile=/shield-fixture-does-not-exist&note=union+select
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- error_code: 405
--- error_log
category=sqli source=body verdict=suspicious action=observe

=== TEST 49: gzip applies observation after decoding
--- config
location /t { shield block; shield_gzip on; empty_gif; }
--- request eval
"POST /t\n" . pack("H*", "1f8b08000000000002ff2bcdcbcccf53284ecd494d2e01000c2c5a9b0c000000")
--- more_headers
Content-Type: text/plain
Content-Encoding: gzip
--- error_code: 405
--- error_log
category=sqli source=body verdict=suspicious action=observe

=== TEST 50: gzip applies strict enforcement after decoding
--- config
location /t { shield block; shield_gzip on; shield_body_strict on; empty_gif; }
--- request eval
"POST /t\n" . pack("H*", "1f8b08000000000002ff2bcdcbcccf53284ecd494d2e01000c2c5a9b0c000000")
--- more_headers
Content-Type: text/plain
Content-Encoding: gzip
--- error_code: 403
--- error_log
category=sqli source=body

=== TEST 51: observation excludes remote writers while enforcement still logs
--- observe_syslog: 1
--- config
location /t { shield block; empty_gif; }
--- request eval
["POST /t\nunion select", "GET /t?x=union%20select"]
--- more_headers
Content-Type: text/plain
--- error_code eval
[405, 403]
