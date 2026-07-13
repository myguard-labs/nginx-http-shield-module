# Modes, status codes, and per-category skip.
#
# NB: shield runs in the PRECONTENT phase. The `return` directive finalizes in
# the REWRITE phase, before PRECONTENT, so a tested location must use a real
# content handler (empty_gif) for the shield handler to run at all.
use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_long_string();
run_tests();

__DATA__

=== TEST 1: block mode returns 403 on an attack
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?id=1%20union%20select%20pw
--- error_code: 403

=== TEST 2: block mode passes a benign request
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?sort=order&page=2
--- error_code: 200

=== TEST 3: detect mode never blocks
--- config
    location /t { shield detect; empty_gif; }
--- request
GET /t?id=1%20union%20select%20pw
--- error_code: 200

=== TEST 4: off mode never blocks
--- config
    location /t { shield off; empty_gif; }
--- request
GET /t?id=1%20union%20select%20pw
--- error_code: 200

=== TEST 5: shield_status 404
--- config
    location /t { shield block; shield_status 404; empty_gif; }
--- request
GET /t?id=1%20union%20select%20pw
--- error_code: 404

=== TEST 6: shield_status 429
--- config
    location /t { shield block; shield_status 429; empty_gif; }
--- request
GET /t?id=1%20union%20select%20pw
--- error_code: 429

=== TEST 7: shield_skip disables its category only
--- config
    location /t { shield block; shield_skip sqli; empty_gif; }
--- request
GET /t?id=1%20union%20select%20pw
--- error_code: 200

=== TEST 8: shield_skip is category-scoped (other categories still fire)
--- config
    location /t { shield block; shield_skip sqli; empty_gif; }
--- request
GET /t?f=../../etc/passwd
--- error_code: 403

=== TEST 9: mode inherits from server into location
--- config
    shield block;
    location /t { empty_gif; }
--- request
GET /t?id=1%20union%20select%20pw
--- error_code: 403
