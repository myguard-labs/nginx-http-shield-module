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
