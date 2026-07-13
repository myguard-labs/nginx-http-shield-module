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
