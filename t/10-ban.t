# shield_ban: repeat-offender banning via a shared-memory zone.
#
# The ban is keyed on the client address; every request in a single test block
# comes from 127.0.0.1, so hits accumulate across the block's requests. Each
# request is a SEPARATE connection (a request list, not pipelined) -- the ban
# state lives in shared memory, so it persists across connections; and the
# static ASan build drops pipelined keep-alive requests, which a request list
# avoids. Test::Nginx restarts nginx per block, so each block starts empty.
#
# NB: shield runs in PRECONTENT; a tested location needs a real content handler
# (empty_gif) for the handler to run, as in the other suites.
use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_long_string();
run_tests();

__DATA__

=== TEST 1: a single hit does not ban (below threshold)
--- http_config
    shield_ban_zone shield1:1m;
--- config
    location /t {
        shield block;
        shield_ban zone=shield1 count=3 window=60s bantime=10s;
        empty_gif;
    }
--- request eval
[
    # one attack (count=1, below the threshold of 3) ...
    "GET /t?id=1%20union%20select%20pw",
    # ... so a following benign request still passes: not banned
    "GET /t?sort=order",
]
--- error_code eval
[403, 200]

=== TEST 2: hits reaching the threshold ban the client on the next request
--- http_config
    shield_ban_zone shield2:1m;
--- config
    location /t {
        shield block;
        shield_status 429;
        shield_ban zone=shield2 count=2 window=60s bantime=30s;
        empty_gif;
    }
--- request eval
[
    # hit 1 (blocked as attack, count=1)
    "GET /t?id=1%20union%20select%20pw",
    # hit 2 (blocked as attack, count=2 -> ban armed)
    "GET /t?id=1%20union%20select%20pw",
    # now banned: a benign request is refused with shield_status before scanning
    "GET /t?sort=order",
]
--- error_code eval
[429, 429, 429]

=== TEST 3: the ban holds while active (benign traffic still refused)
--- http_config
    shield_ban_zone shield3:1m;
--- config
    location /t {
        shield block;
        shield_ban zone=shield3 count=2 window=60s bantime=30s;
        empty_gif;
    }
--- request eval
[
    "GET /t?id=1%20union%20select%20pw",
    "GET /t?id=1%20union%20select%20pw",
    "GET /t?sort=order",
    "GET /t?page=2",
]
--- error_code eval
[403, 403, 403, 403]

=== TEST 4: detect mode also counts toward a ban
--- http_config
    shield_ban_zone shield4:1m;
--- config
    location /t {
        shield detect;
        shield_status 403;
        shield_ban zone=shield4 count=2 window=60s bantime=30s;
        empty_gif;
    }
--- request eval
[
    # detect mode: attacks are NOT blocked (200), but each counts as a hit
    "GET /t?id=1%20union%20select%20pw",
    "GET /t?id=1%20union%20select%20pw",
    # ban armed by the two detect hits: this benign request is now refused
    "GET /t?sort=order",
]
--- error_code eval
[200, 200, 403]

=== TEST 5: a client on a different location's zone is unaffected
--- http_config
    shield_ban_zone shieldA:1m;
    shield_ban_zone shieldB:1m;
--- config
    location /a {
        shield block;
        shield_ban zone=shieldA count=2 window=60s bantime=30s;
        empty_gif;
    }
    location /b {
        shield block;
        shield_ban zone=shieldB count=2 window=60s bantime=30s;
        empty_gif;
    }
--- request eval
[
    # ban the client under zone A
    "GET /a?id=1%20union%20select%20pw",
    "GET /a?id=1%20union%20select%20pw",
    "GET /a?sort=order",
    # zone B has seen no hits: the same client is still free there
    "GET /b?sort=order",
]
--- error_code eval
[403, 403, 403, 200]

=== TEST 6: shield_ban rejects an unknown parameter
--- http_config
    shield_ban_zone shield6:1m;
--- config
    location /t {
        shield block;
        shield_ban zone=shield6 count=2 window=60s frobnicate=1;
        empty_gif;
    }
--- must_die
--- error_log
invalid shield_ban parameter "frobnicate=1"

=== TEST 7: shield_ban rejects a zero count
--- http_config
    shield_ban_zone shield7:1m;
--- config
    location /t {
        shield block;
        shield_ban zone=shield7 count=0 window=60s bantime=30s;
        empty_gif;
    }
--- must_die
--- error_log
invalid shield_ban count "count=0"

=== TEST 8: shield_ban rejects a bad window time
--- http_config
    shield_ban_zone shield8:1m;
--- config
    location /t {
        shield block;
        shield_ban zone=shield8 count=2 window=abc bantime=30s;
        empty_gif;
    }
--- must_die
--- error_log
invalid shield_ban window "window=abc"

=== TEST 9: shield_ban_zone rejects a malformed spec (no size)
--- http_config
    shield_ban_zone shield9;
--- config
    location /t { shield block; empty_gif; }
--- must_die
--- error_log
expected name:size

=== TEST 10: shield_ban referencing an undefined zone fails at load
--- config
    location /t {
        shield block;
        shield_ban zone=nonexistent count=2 window=60s bantime=30s;
        empty_gif;
    }
--- must_die
--- error_log
zero size shared memory zone "nonexistent"

=== TEST 11: key=forwarded without trusted= is refused at config time
--- http_config
    shield_ban_zone shield11:1m;
--- config
    location /t {
        shield block;
        shield_ban zone=shield11 count=2 window=60s bantime=30s key=forwarded;
        empty_gif;
    }
--- must_die
--- error_log
key=forwarded requires at least one trusted=

=== TEST 12: trusted= without key=forwarded is refused (it would do nothing)
--- http_config
    shield_ban_zone shield12:1m;
--- config
    location /t {
        shield block;
        shield_ban zone=shield12 count=2 window=60s bantime=30s
                   trusted=127.0.0.1;
        empty_gif;
    }
--- must_die
--- error_log
trusted= is meaningless without key=forwarded

=== TEST 13: shield_ban rejects an unknown key
--- http_config
    shield_ban_zone shield13:1m;
--- config
    location /t {
        shield block;
        shield_ban zone=shield13 count=2 window=60s bantime=30s key=bogus;
        empty_gif;
    }
--- must_die
--- error_log
expected peer or forwarded

=== TEST 14: shield_ban rejects a malformed trusted CIDR
--- http_config
    shield_ban_zone shield14:1m;
--- config
    location /t {
        shield block;
        shield_ban zone=shield14 count=2 window=60s bantime=30s
                   key=forwarded trusted=999.1.1.1/8;
        empty_gif;
    }
--- must_die
--- error_log
invalid shield_ban trusted address

=== TEST 15: key=forwarded bans the XFF client, not the shared proxy address
# The peer (127.0.0.1) IS trusted here, so XFF is honoured. Two attacks from
# forwarded client .10 arm a ban for .10 only; client .20 -- same TCP peer,
# different XFF -- must still be served. If the key had fallen back to the peer,
# .20 would be banned too and this returns 403 instead of 200.
--- http_config
    shield_ban_zone shield15:1m;
--- config
    location /t {
        shield block;
        shield_ban zone=shield15 count=2 window=60s bantime=30s
                   key=forwarded trusted=127.0.0.1;
        empty_gif;
    }
--- request eval
[
    "GET /t?id=1%20union%20select%20pw",
    "GET /t?id=1%20union%20select%20pw",
    "GET /t?sort=order",
    "GET /t?sort=order",
]
--- more_headers eval
[
    "X-Forwarded-For: 203.0.113.10\n",
    "X-Forwarded-For: 203.0.113.10\n",
    # .10 is now banned -> refused before scanning
    "X-Forwarded-For: 203.0.113.10\n",
    # .20 shares the TCP peer but is a different key -> unaffected
    "X-Forwarded-For: 203.0.113.20\n",
]
--- error_code eval
[403, 403, 403, 200]

=== TEST 16: an UNTRUSTED peer cannot spoof the ban key via XFF
# The trusted list names 10.0.0.1, which is NOT the test client, so the header
# must be ignored entirely and the key falls back to the TCP peer. The attacker
# rotates a fresh XFF value on every request: if the header were honoured from
# an untrusted peer, each request would be a distinct key, no key would ever
# reach count=2, and the 3rd request would be served (200). Being banned (403)
# is what proves the header was NOT trusted.
--- http_config
    shield_ban_zone shield16:1m;
--- config
    location /t {
        shield block;
        shield_ban zone=shield16 count=2 window=60s bantime=30s
                   key=forwarded trusted=10.0.0.1;
        empty_gif;
    }
--- request eval
[
    "GET /t?id=1%20union%20select%20pw",
    "GET /t?id=1%20union%20select%20pw",
    "GET /t?sort=order",
]
--- more_headers eval
[
    "X-Forwarded-For: 198.51.100.1\n",
    "X-Forwarded-For: 198.51.100.2\n",
    "X-Forwarded-For: 198.51.100.3\n",
]
--- error_code eval
[403, 403, 403]

=== TEST 17: the RIGHTMOST XFF entry is the key, not the client-supplied left
# Behind a trusted proxy the attacker still controls the LEFT of the chain: the
# proxy appends what it saw and never rewrites what came before. Both requests
# carry a different forged leftmost value but the same real rightmost one, so
# they must count toward ONE key and reach the threshold. Keying on the leftmost
# would make them two keys, neither banned, and the 3rd request would be 200.
--- http_config
    shield_ban_zone shield17:1m;
--- config
    location /t {
        shield block;
        shield_ban zone=shield17 count=2 window=60s bantime=30s
                   key=forwarded trusted=127.0.0.1;
        empty_gif;
    }
--- request eval
[
    "GET /t?id=1%20union%20select%20pw",
    "GET /t?id=1%20union%20select%20pw",
    "GET /t?sort=order",
]
--- more_headers eval
[
    "X-Forwarded-For: 192.0.2.111, 203.0.113.77\n",
    "X-Forwarded-For: 192.0.2.222, 203.0.113.77\n",
    "X-Forwarded-For: 192.0.2.333, 203.0.113.77\n",
]
--- error_code eval
[403, 403, 403]

=== TEST 18: a trusted peer sending no XFF falls back to the peer address
--- http_config
    shield_ban_zone shield18:1m;
--- config
    location /t {
        shield block;
        shield_ban zone=shield18 count=2 window=60s bantime=30s
                   key=forwarded trusted=127.0.0.1;
        empty_gif;
    }
--- request eval
[
    "GET /t?id=1%20union%20select%20pw",
    "GET /t?id=1%20union%20select%20pw",
    "GET /t?sort=order",
]
--- error_code eval
[403, 403, 403]

=== TEST 19: an unparsable XFF value falls back to the peer, not to a wild key
--- http_config
    shield_ban_zone shield19:1m;
--- config
    location /t {
        shield block;
        shield_ban zone=shield19 count=2 window=60s bantime=30s
                   key=forwarded trusted=127.0.0.1;
        empty_gif;
    }
--- request eval
[
    "GET /t?id=1%20union%20select%20pw",
    "GET /t?id=1%20union%20select%20pw",
    "GET /t?sort=order",
]
--- more_headers eval
[
    "X-Forwarded-For: not-an-address\n",
    "X-Forwarded-For: also!garbage\n",
    "X-Forwarded-For: %%%\n",
]
--- error_code eval
[403, 403, 403]

=== TEST 20: shield_ban_status reports counters and the ban list
--- http_config
    shield_ban_zone shield20:1m;
--- config
    location /t {
        shield block;
        shield_ban zone=shield20 count=2 window=60s bantime=30s;
        empty_gif;
    }
    location /status {
        shield_ban_status shield20;
    }
--- request eval
[
    "GET /t?id=1%20union%20select%20pw",
    "GET /t?id=1%20union%20select%20pw",
    "GET /status",
]
--- response_body_like eval
[
    qr/./,
    qr/./,
    # sqli fired twice, both blocked, one ban armed, and the banned client is
    # listed with its remaining lifetime.
    qr/"blocked":2.*"bans":1.*"sqli":2.*"banned":\[\{"addr":"127\.0\.0\.1","hits":\d+,"expires":\d+\}\]/s,
]
--- error_code eval
[403, 403, 200]

=== TEST 21: shield_ban_status reports every category, including zeroes
--- http_config
    shield_ban_zone shield21:1m;
--- config
    location /t {
        shield block;
        shield_ban zone=shield21 count=5 window=60s bantime=30s;
        empty_gif;
    }
    location /status {
        shield_ban_status shield21;
    }
--- request
    GET /status
--- response_body_like chomp
"xss":0
--- error_code: 200

=== TEST 22: an empty zone reports zeroes and an empty ban list
--- http_config
    shield_ban_zone shield22:1m;
--- config
    location /status {
        shield_ban_status shield22;
    }
--- request
    GET /status
--- response_body_like chomp
"nodes":0,"blocked":0,"bans":0
--- error_code: 200

=== TEST 23: shield_ban_status rejects a non-GET method
--- http_config
    shield_ban_zone shield23:1m;
--- config
    location /status {
        shield_ban_status shield23;
    }
--- request
    POST /status
--- error_code: 405

=== TEST 24: detect mode counts the hit but does not count it as blocked
--- http_config
    shield_ban_zone shield24:1m;
--- config
    location /t {
        shield detect;
        shield_ban zone=shield24 count=9 window=60s bantime=30s;
        empty_gif;
    }
    location /status {
        shield_ban_status shield24;
    }
--- request eval
[
    "GET /t?id=1%20union%20select%20pw",
    "GET /status",
]
--- response_body_like eval
[
    qr/./,
    qr/"blocked":0.*"sqli":1/s,
]
--- error_code eval
[200, 200]

=== TEST 25: shield_ban_status is duplicate in one location
--- http_config
    shield_ban_zone shield25:1m;
--- config
    location /status {
        shield_ban_status shield25;
        shield_ban_status shield25;
    }
--- must_die
--- error_log
"shield_ban_status" directive is duplicate

=== TEST 26: a forged EXTRA XFF header line cannot steal the ban key
# Since nginx 1.23 repeated headers are a ->next chain, NOT one merged value,
# and headers_in.x_forwarded_for is only the FIRST line. A proxy that appends
# its own line leaves the client's forged line at the head. Reading the head
# would let the attacker rotate a fresh value per request so no key ever reaches
# the threshold. Here the real client (last line) is constant and must be banned
# by the 3rd request despite the rotating forged first line.
--- http_config
    shield_ban_zone shield26:1m;
--- config
    location /t {
        shield block;
        shield_ban zone=shield26 count=2 window=60s bantime=30s
                   key=forwarded trusted=127.0.0.1;
        empty_gif;
    }
--- request eval
[
    "GET /t?id=1%20union%20select%20pw",
    "GET /t?id=1%20union%20select%20pw",
    "GET /t?sort=order",
]
--- more_headers eval
[
    "X-Forwarded-For: 198.51.100.1\nX-Forwarded-For: 203.0.113.99\n",
    "X-Forwarded-For: 198.51.100.2\nX-Forwarded-For: 203.0.113.99\n",
    "X-Forwarded-For: 198.51.100.3\nX-Forwarded-For: 203.0.113.99\n",
]
--- error_code eval
[403, 403, 403]

=== TEST 27: an IPv6 forwarded client is keyed on its full 16-byte address
# Exercises the v6 branch of the key extraction, which the loopback peer path
# never reaches (the suite connects over IPv4). The forged first line rotates;
# the real v6 client on the last line must still accumulate to a ban.
--- http_config
    shield_ban_zone shield27:1m;
--- config
    location /t {
        shield block;
        shield_ban zone=shield27 count=2 window=60s bantime=30s
                   key=forwarded trusted=127.0.0.1;
        empty_gif;
    }
--- request eval
[
    "GET /t?id=1%20union%20select%20pw",
    "GET /t?id=1%20union%20select%20pw",
    "GET /t?sort=order",
    "GET /t?sort=order",
]
--- more_headers eval
[
    "X-Forwarded-For: 198.51.100.1\nX-Forwarded-For: 2001:db8::1234\n",
    "X-Forwarded-For: 198.51.100.2\nX-Forwarded-For: 2001:db8::1234\n",
    # same v6 client -> banned
    "X-Forwarded-For: 198.51.100.3\nX-Forwarded-For: 2001:db8::1234\n",
    # a DIFFERENT v6 client -> unaffected (keys are distinct, not truncated)
    "X-Forwarded-For: 198.51.100.4\nX-Forwarded-For: 2001:db8::5678\n",
]
--- error_code eval
[403, 403, 403, 200]

=== TEST 28: degenerate XFF values fall back to the peer without crashing
# The rightmost-entry scan does pointer arithmetic over attacker-controlled
# bytes, so the empty / comma-only / whitespace-only forms must terminate
# safely rather than underflow or parse garbage. Each request is benign, so a
# 200 means "handled, keyed on the peer"; a crash or 5xx would be the failure.
# Verified clean under ASan+UBSan with these same values.
--- http_config
    shield_ban_zone shield28:1m;
--- config
    location /t {
        shield block;
        shield_ban zone=shield28 count=99 window=60s bantime=30s
                   key=forwarded trusted=127.0.0.1;
        empty_gif;
    }
--- request eval
[
    "GET /t?sort=order",
    "GET /t?sort=order",
    "GET /t?sort=order",
    "GET /t?sort=order",
    "GET /t?sort=order",
    "GET /t?sort=order",
]
--- more_headers eval
[
    "X-Forwarded-For: ,\n",
    "X-Forwarded-For: ,,\n",
    "X-Forwarded-For:    \n",
    "X-Forwarded-For:   ,  \n",
    "X-Forwarded-For: , 203.0.113.7\n",
    "X-Forwarded-For: 203.0.113.7 ,\n",
]
--- error_code eval
[200, 200, 200, 200, 200, 200]

=== TEST 29: a port-form XFF entry is parsed, and the PORT is not part of the key
# RFC 7239-era proxies emit v4:port and [v6]:port. ngx_parse_addr_port handles
# both; the address keys the ban and the port is ignored.
#
# The discriminating arm is the 4th: a DIFFERENT address in port form must be
# unaffected (200). Without port parsing every port-form value fails to parse
# and falls back to the peer -- all four requests then share the peer key, and
# the 4th would be 403. That is what makes this test falsifiable; asserting only
# the first three would pass either way.
--- http_config
    shield_ban_zone shield29:1m;
--- config
    location /t {
        shield block;
        shield_ban zone=shield29 count=2 window=60s bantime=30s
                   key=forwarded trusted=127.0.0.1;
        empty_gif;
    }
--- request eval
[
    "GET /t?id=1%20union%20select%20pw",
    "GET /t?id=1%20union%20select%20pw",
    "GET /t?sort=order",
    "GET /t?sort=order",
]
--- more_headers eval
[
    "X-Forwarded-For: 203.0.113.90:1111\n",
    "X-Forwarded-For: 203.0.113.90:2222\n",
    # same address, third port -> banned (port is not part of the key)
    "X-Forwarded-For: 203.0.113.90:3333\n",
    # DIFFERENT address -> unaffected; 403 here means the port form failed to
    # parse and everything collapsed onto the peer key
    "X-Forwarded-For: 203.0.113.91:4444\n",
]
--- error_code eval
[403, 403, 403, 200]
