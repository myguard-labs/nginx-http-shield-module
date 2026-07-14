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

=== TEST 10: a skipped category does not mask a live one later in the buffer
--- config
    location /t { shield block; shield_skip sqli; empty_gif; }
--- request
GET /t?a=union%20select%201&b=../../etc/passwd
--- error_code: 403

=== TEST 11: skipped-first ordering holds in the other direction too
--- config
    location /t { shield block; shield_skip traversal; empty_gif; }
--- request
GET /t?a=../../etc/passwd&b=union%20select%201
--- error_code: 403

=== TEST 12: skipping every category that matches still passes the request
# The payload matches three categories: sqli ("union select"), traversal (the
# "../" gadget) and sensitive_file (the "/etc/passwd" target). The filename is
# reported as sensitive_file rather than traversal -- traversal owns the GADGET,
# sensitive_file owns the TARGET -- so an operator skipping the traversal
# category alone no longer silently also skips the filename.
--- config
    location /t { shield block; shield_skip sqli traversal sensitive_file; empty_gif; }
--- request
GET /t?a=union%20select%201&b=../../etc/passwd
--- error_code: 200

=== TEST 13: a multi-category state blocks and reports the lowest table row
# Co-located-category bypass (TESTS 13-15). The Ivanti exploit_path signature
# "/api/v1/totp/user-backup-code/../" ENDS with the traversal signature "../",
# so both categories accept at the same automaton state. An out[] holding one
# category per state reported only the first and silently dropped the other --
# with nothing skipped, this request returned 200.
# Distinct from TESTS 10-12, which pin two matches at DIFFERENT offsets.
# When several live categories share a state the lowest category-table row
# wins (traversal, row 2, over exploit_path, row 27) -- the category the old
# per-signature engine reported, since it scanned the table in order.
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?f=y/api/v1/totp/user-backup-code/../
--- error_log
category=traversal
--- error_code: 403

=== TEST 14: skipping the longer category leaves the co-located shorter one live
--- config
    location /t { shield block; shield_skip exploit_path; empty_gif; }
--- request
GET /t?f=y/api/v1/totp/user-backup-code/../
--- error_log
category=traversal
--- error_code: 403

=== TEST 15: skipping the shorter category leaves the co-located longer one live
--- config
    location /t { shield block; shield_skip traversal; empty_gif; }
--- request
GET /t?f=y/api/v1/totp/user-backup-code/../
--- error_log
category=exploit_path
--- error_code: 403
