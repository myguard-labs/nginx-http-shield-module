# Request-body inspection.
#
# The content handler here is empty_gif, which answers GET/HEAD only. A POST
# that shield lets through therefore reaches empty_gif and comes back 405 --
# so in these tests 403 means "shield blocked" and 405 means "shield passed
# it through". That distinction is exactly what we want to assert.
use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_long_string();
run_tests();

__DATA__

=== TEST 1: SQLi in a urlencoded body is blocked
--- config
    location /t { shield block; empty_gif; }
--- request
POST /t
q=1 union select password from users
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- error_code: 403

=== TEST 2: xmlrpc system.multicall abuse in body
--- config
    location /t { shield block; empty_gif; }
--- request
POST /t
<methodCall><methodName>system.multicall</methodName></methodCall>
--- more_headers
Content-Type: text/xml
--- error_code: 403

=== TEST 3: ImageTragick payload in body
--- config
    location /t { shield block; empty_gif; }
--- request
POST /t
push graphic-context viewbox 0 0 640 480
--- more_headers
Content-Type: text/plain
--- error_code: 403

=== TEST 4: a benign body is passed through (405 from empty_gif, not 403)
--- config
    location /t { shield block; empty_gif; }
--- request
POST /t
name=john&city=paris&comment=hello world
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- error_code: 405

=== TEST 5: a non-text body type is never scanned
--- config
    location /t { shield block; empty_gif; }
--- request
POST /t
union select 1
--- more_headers
Content-Type: application/octet-stream
--- error_code: 405

=== TEST 6: body inspection can be turned off
--- config
    location /t { shield block; shield_body off; empty_gif; }
--- request
POST /t
q=1 union select 1
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- error_code: 405

=== TEST 7: an attack past shield_max_body is not seen
--- config
    location /t { shield block; shield_max_body 4k; empty_gif; }
--- request eval
"POST /t\n" . ("x=" . ("a" x 8000) . "&q=union select 1")
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- error_code: 405

=== TEST 8: an attack within shield_max_body is caught
--- config
    location /t { shield block; shield_max_body 4k; empty_gif; }
--- request eval
"POST /t\n" . ("q=union select 1&x=" . ("a" x 8000))
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- error_code: 403

=== TEST 9: default shield_max_body is 8k -- attack inside it is caught
--- config
    location /t { shield block; empty_gif; }
--- request eval
"POST /t\n" . ("x=" . ("a" x 6000) . "&q=union select 1")
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- error_code: 403

=== TEST 10: default shield_max_body is 8k -- attack past it is not scanned
--- config
    location /t { shield block; empty_gif; }
--- request eval
"POST /t\n" . ("x=" . ("a" x 12000) . "&q=union select 1")
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- error_code: 405

=== TEST 11: an attack in a temp-file-buffered body is caught
--- config
    location /t {
        client_body_buffer_size 512;
        shield block;
        empty_gif;
    }
--- request eval
"POST /t\n" . ("x=" . ("a" x 3000) . "&q=union select 1")
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- error_code: 403

=== TEST 12: a benign temp-file-buffered body is passed through
--- config
    location /t {
        client_body_buffer_size 512;
        shield block;
        empty_gif;
    }
--- request eval
"POST /t\n" . ("x=" . ("a" x 3000) . "&q=hello+world")
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- error_code: 405

=== TEST 13: an attack at the very end of a temp-file-buffered body is caught
--- config
    location /t {
        client_body_buffer_size 512;
        shield block;
        shield_max_body 64k;
        empty_gif;
    }
--- request eval
"POST /t\n" . ("x=" . ("a" x 20000) . "&q=<!--#exec cmd=\"id\"-->")
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- error_code: 403

=== TEST 14: vendor JSON media type is scanned
--- config
    location /t { shield block; empty_gif; }
--- request
POST /t
{"filter":"1 union select password from users"}
--- more_headers
Content-Type: application/vnd.api+json; charset=utf-8
--- error_code: 403

=== TEST 15: SOAP structured XML media type is scanned
--- config
    location /t { shield block; empty_gif; }
--- request eval
"POST /t\n<!ENTITY x SYSTEM \"file:///etc/passwd\">"
--- more_headers
Content-Type: application/soap+xml; charset=utf-8
--- error_code: 403

=== TEST 16: GraphQL media type is scanned
--- config
    location /t { shield block; empty_gif; }
--- request
POST /t
query { user(id: "1 union select password from users") { name } }
--- more_headers
Content-Type: application/graphql
--- error_code: 403

=== TEST 17: newline-delimited JSON media type is scanned
--- config
    location /t { shield block; empty_gif; }
--- request
POST /t
{"$where":"return true"}
--- more_headers
Content-Type: application/x-ndjson
--- error_code: 403

=== TEST 18: YAML media type is scanned
--- config
    location /t { shield block; empty_gif; }
--- request eval
"POST /t\n--- !ruby/object:Gem::Requirement"
--- more_headers
Content-Type: application/yaml
--- error_code: 403

=== TEST 19: JSON text-sequence media type remains scanned
--- config
    location /t { shield block; empty_gif; }
--- request
POST /t
{"filter":"1 union select password from users"}
--- more_headers
Content-Type: application/json-seq
--- error_code: 403
