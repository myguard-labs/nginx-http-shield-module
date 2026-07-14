# AND-rules: a category that fires only when a SET of terms co-occurs in one
# buffer. Every term here is, on its own, ordinary traffic -- t/05 TESTS 30-34
# pin that each one alone must NOT block. These tests pin the other half: the
# full term set together IS the attack and must block.
#
# The pair is the whole point of the primitive. A signature engine that can
# only match one token at a time has to choose between blocking the product
# (term alone = 403) and missing the exploit (never listed at all).
use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_long_string();
run_tests();

__DATA__

=== TEST 1: Grafana plugin path + traversal gadget (CVE-2021-43798)
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?url=/public/plugins/graph/../../../../etc/passwd
--- error_code: 403

=== TEST 2: the Grafana rule reports the traversal category
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?url=/public/plugins/graph/../../../../etc/passwd
--- error_log
category=traversal
--- error_code: 403

=== TEST 3: OFBiz auth bypass -- bypass param steering the control endpoint
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?p=/webtools/control/main&requirePasswordChange=Y
--- error_code: 403

=== TEST 4: Metabase setup-validate carrying an H2 JDBC INIT gadget
--- config
    location /t { shield block; shield_body on; empty_gif; }
--- request eval
"POST /t
{\"token\":\"x\",\"details\":{\"details\":{\"db\":\"zip:/app/metabase.jar\"},\"engine\":\"h2\"},\"url\":\"/api/setup/validate\",\"conn\":\"jdbc:h2:mem:test\"}"
--- more_headers
Content-Type: application/json
--- error_log
category=deserial
--- error_code: 403

=== TEST 5: time-based SQLi -- sleep( paired with a SELECT
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?id=1%20and%20(select%20sleep(5))
--- error_code: 403

=== TEST 6: shield_skip on a rule's category disables the rule too
--- config
    location /t { shield block; shield_skip traversal; empty_gif; }
--- request
GET /t?url=/public/plugins/graph/x/y/z/module.js
--- error_code: 200

=== TEST 7: terms split across different requests never accumulate
# `seen` is per-buffer state, not per-connection: one term now and the other
# term in a later request must never combine into a hit.
--- config
    location /t { shield block; empty_gif; }
--- pipelined_requests eval
["GET /t?url=/public/plugins/graph/module.js",
 "GET /t?q=jdbc:h2:mem"]
--- error_code eval
[200, 200]

=== TEST 8: a rule term is not a signature -- detect mode stays quiet on one term
--- config
    location /t { shield detect; empty_gif; }
--- request
GET /t?url=/public/plugins/graph/module.js
--- error_code: 200

=== TEST 9: Jenkins CLI file read -- /cli AND remoting=true (CVE-2024-23897)
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/cli?remoting=true
--- error_code: 403

=== TEST 10: /cli alone is a legitimate Jenkins endpoint, not blocked
# The browser CLI uses the websocket transport; only the remoting channel
# carries remoting=true. The endpoint on its own must pass.
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/cli
--- error_code: 200

=== TEST 11: VMware Workspace ONE SSTI -- catalog-portal verify AND freemarker (CVE-2022-22954)
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?x=/catalog-portal/ui/oauth/verify+freemarker
--- error_code: 403

=== TEST 12: the catalog-portal verify endpoint alone is a real route, not blocked
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?x=/catalog-portal/ui/oauth/verify
--- error_code: 200
