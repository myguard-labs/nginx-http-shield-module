# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
# HTTP policy observations; offline SQLite pair proves only toy sink semantics.
# 405 from empty_gif on POST means Shield allowed dispatch, not a stored result.
use Test::Nginx::Socket 'no_plan';

repeat_each(1);
no_long_string();
run_tests();

__DATA__

=== TEST 1: complete H2 AND gadget is detected in one body buffer
--- config
    location /sink { shield block; empty_gif; }
--- request
POST /sink
jdbc:h2:mem:test;init=fixture
--- more_headers
Content-Type: text/plain
--- error_code: 403
--- error_log
category=deserial source=body

=== TEST 2: first AND term alone does not fire
--- config
    location /sink { shield block; empty_gif; }
--- request
POST /sink
jdbc:h2:mem:test
--- more_headers
Content-Type: text/plain
--- error_code: 405
--- no_error_log
shield: blocked request

=== TEST 3: second AND term alone does not fire
--- config
    location /sink { shield block; empty_gif; }
--- request
POST /sink
init=fixture
--- more_headers
Content-Type: text/plain
--- error_code: 405
--- no_error_log
shield: blocked request

=== TEST 4: AND terms in separate URI and body buffers do not combine
--- config
    location /sink { shield block; empty_gif; }
--- request
POST /sink?dsn=jdbc:h2:mem:test
init=fixture
--- more_headers
Content-Type: text/plain
--- error_code: 405
--- no_error_log
shield: blocked request

=== TEST 5: same toy SQL bytes allowed by explicit content route skip
--- config
    location /content { shield block; shield_skip sqli; empty_gif; }
--- request
POST /content
id=-1+union+select+value+from+private_data
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- error_code: 405
--- no_error_log
shield: blocked request

=== TEST 6: toy SQL bytes detected on sink policy route
--- config
    location /sink { shield block; empty_gif; }
--- request
POST /sink
id=-1+union+select+value+from+private_data
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- error_code: 403
--- error_log
category=sqli source=body

=== TEST 7: percent-encoded toy attack variant detected
--- config
    location /sink { shield block; empty_gif; }
--- request
POST /sink
id=%2D%31%20%75%6E%69%6F%6E%20%73%65%6C%65%63%74%20%76%61%6C%75%65%20%66%72%6F%6D%20%70%72%69%76%61%74%65%5F%64%61%74%61
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- error_code: 403
--- error_log
category=sqli source=body

=== TEST 8: keyword case toy attack variant detected
--- config
    location /sink { shield block; empty_gif; }
--- request
POST /sink
id=-1%20UNION%20SELECT%20VALUE%20FROM%20PRIVATE_DATA
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- error_code: 403
--- error_log
category=sqli source=body

=== TEST 9: benign toy variant accepted on sink policy route
--- config
    location /sink { shield block; empty_gif; }
--- request
POST /sink
id=%31
--- more_headers
Content-Type: application/x-www-form-urlencoded
--- error_code: 405
--- no_error_log
shield: blocked request
