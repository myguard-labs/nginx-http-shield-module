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
