# Configuration-time validation: every directive must reject bad input at load
# with a clear message, not silently accept it. These exercise the NGX_CONF_ERROR
# branches of the directive handlers.
use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_long_string();
run_tests();

__DATA__

=== TEST 1: shield rejects an unknown mode
--- config
    location /t { shield banana; empty_gif; }
--- must_die
--- error_log
invalid shield mode "banana"

=== TEST 2: shield rejects a duplicate directive
--- config
    location /t {
        shield block;
        shield detect;
        empty_gif;
    }
--- must_die
--- error_log
"shield" directive is duplicate

=== TEST 3: shield_status rejects an out-of-range code
--- config
    location /t { shield block; shield_status 200; empty_gif; }
--- must_die
--- error_log
invalid shield_status "200"

=== TEST 4: shield_status rejects a non-numeric code
--- config
    location /t { shield block; shield_status abc; empty_gif; }
--- must_die
--- error_log
invalid shield_status "abc"

=== TEST 5: shield_status rejects a duplicate directive
--- config
    location /t {
        shield block;
        shield_status 403;
        shield_status 404;
        empty_gif;
    }
--- must_die
--- error_log
"shield_status" directive is duplicate

=== TEST 6: shield_status accepts each allowed code
--- config
    location /a { shield block; shield_status 403; empty_gif; }
    location /b { shield block; shield_status 404; empty_gif; }
    location /c { shield block; shield_status 419; empty_gif; }
    location /d { shield block; shield_status 429; empty_gif; }
    location /e { shield block; shield_status 444; empty_gif; }
--- request
GET /a?sort=order
--- error_code: 200

=== TEST 7: shield_skip rejects an unknown category
--- config
    location /t { shield block; shield_skip not_a_category; empty_gif; }
--- must_die
--- error_log
unknown shield category "not_a_category"

=== TEST 8: shield_skip accepts a known category and disables it
--- config
    location /t {
        shield block;
        shield_skip range_dos;
        empty_gif;
    }
--- request
GET /t?sort=order
--- error_code: 200

=== TEST 9: shield_log rejects a duplicate directive
--- config
    location /t {
        shield block;
        shield_log /tmp/shield-dup-a.log;
        shield_log /tmp/shield-dup-b.log;
        empty_gif;
    }
--- must_die
--- error_log
"shield_log" directive is duplicate
