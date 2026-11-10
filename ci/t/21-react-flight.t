# React2Shell Flight gadgets (CVE-2025-55182). Payloads are inert markers:
# no command execution, vulnerable upstream, or application is needed.
use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_long_string();
run_tests();

__DATA__

=== TEST 1: prototype then gadget in multipart body
--- config
    location /t { shield block; empty_gif; }
--- request
POST /t
--flight
Content-Disposition: form-data; name="0"

{"then":"$1:__proto__:then","status":"resolved_model"}
--flight--
--- more_headers
Content-Type: multipart/form-data; boundary=flight
--- error_code: 403
--- error_log
category=deserial

=== TEST 2: constructor chain alone in JSON is blocked
--- config
    location /t { shield block; empty_gif; }
--- request
POST /t
{"_response":{"_formData":{"get":"$ab:constructor:constructor"}}}
--- more_headers
Content-Type: application/json
--- error_code: 403

=== TEST 3: percent encoded Flight gadget in form body
--- config
    location /t { shield block; empty_gif; }
--- request
POST /t
0=%7B%22then%22%3A%22%242%3A__proto__%3Athen%22%7D
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- error_code: 403

=== TEST 4: ordinary Flight references stay clean
--- config
    location /t { shield block; empty_gif; }
--- request
POST /t
{"then":"$@1","value":"$2:profile:name","constructor":"Widget","__proto__":null}
--- more_headers
Content-Type: application/json
--- error_code: 405

=== TEST 5: similar property paths stay clean
--- config
    location /t { shield block; empty_gif; }
--- request
POST /t
{"a":"$1:__proto__:theme","b":"$1:constructor:construct"}
--- more_headers
Content-Type: application/json
--- error_code: 405

=== TEST 6: skipped deserial category allows marker through
--- config
    location /t { shield block; shield_skip deserial; empty_gif; }
--- request
POST /t
{"then":"$1:__proto__:then"}
--- more_headers
Content-Type: application/json
--- error_code: 405

=== TEST 7: URI query markers are blocked after decoding
--- config
    location /t { shield block; empty_gif; }
--- request
GET /t?q=%243%3Aconstructor%3Aconstructor
--- error_code: 403

=== TEST 8: text body is folded before matching
--- config
    location /t { shield block; empty_gif; }
--- request
POST /t
$2:__PROTO__:THEN
--- more_headers
Content-Type: text/plain
--- error_code: 403
