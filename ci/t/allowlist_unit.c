/* Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 * Real-pool allowlist parsing, lifetime and allocation-failure controls. */
#undef NDEBUG
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <assert.h>

static int fail_create, fail_push;
static ngx_uint_t create_calls, push_calls;

static ngx_array_t *
allow_array_create(ngx_pool_t *pool, ngx_uint_t n, size_t size)
{
    create_calls++;
    return fail_create ? NULL : ngx_array_create(pool, n, size);
}

static void *
allow_array_push(ngx_array_t *array)
{
    push_calls++;
    return fail_push ? NULL : ngx_array_push(array);
}

/* Inject at the two allocation APIs, retaining nginx's actual array storage,
 * CIDR parser and matcher on the successful paths. */
#define ngx_array_create allow_array_create
#define ngx_array_push allow_array_push
#include "../../src/ngx_http_shield_module.c"
#undef ngx_array_create
#undef ngx_array_push

void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log,
#ifdef ngx_src_file
    const char *filename,
#endif
    ngx_err_t err, const char *format, ...)
{
#ifdef ngx_src_file
    (void) filename;
#endif
    (void) level; (void) log; (void) err; (void) format;
}

void
ngx_conf_log_error(ngx_uint_t level, ngx_conf_t *cf, ngx_err_t err,
    const char *format, ...)
{
    (void) level; (void) cf; (void) err; (void) format;
}

/* Each configuration scenario owns and tears down a real nginx pool, including
 * rejected partial lists and array growth into pool-managed large allocations. */
static char *
parse_allow(ngx_pool_t *pool, ngx_http_shield_loc_conf_t *conf,
    const char **tokens, ngx_uint_t count)
{
    ngx_conf_t cf;
    ngx_array_t args;
    ngx_str_t values[8];
    ngx_uint_t i;

    assert(count < 8);
    ngx_memzero(&cf, sizeof(cf));
    ngx_memzero(&args, sizeof(args));
    ngx_str_set(&values[0], "shield_allow");
    for (i = 0; i < count; i++) {
        values[i + 1].data = (u_char *) tokens[i];
        values[i + 1].len = strlen(tokens[i]);
    }
    args.elts = values;
    args.nelts = count + 1;
    cf.args = &args;
    cf.pool = pool;
    return ngx_http_shield_allow(&cf, NULL, conf);
}

static void
assert_match(ngx_array_t *cidrs, const char *text, int family, ngx_int_t expected)
{
    ngx_http_request_t request;
    ngx_connection_t connection;
    struct sockaddr_storage address;
    void *binary;

    ngx_memzero(&request, sizeof(request));
    ngx_memzero(&connection, sizeof(connection));
    ngx_memzero(&address, sizeof(address));
    request.connection = &connection;
    connection.sockaddr = (struct sockaddr *) &address;
    address.ss_family = (sa_family_t) family;
    if (family == AF_INET) {
        binary = &((struct sockaddr_in *) &address)->sin_addr;
    } else {
        binary = &((struct sockaddr_in6 *) &address)->sin6_addr;
    }
    assert(inet_pton(family, text, binary) == 1);
    assert(ngx_http_shield_allowlisted(&request, cidrs) == expected);
}

static void
parser_cases(ngx_log_t *log)
{
    static const struct {
        const char *cidr, *match, *miss;
        int family;
    } valid[] = {
        { "255.0.0.255/32", "255.0.0.255", "255.0.0.254", AF_INET },
        { "192.0.2.7", "192.0.2.7", "192.0.2.8", AF_INET },
        { "192.0.2.0/24", "192.0.2.255", "192.0.3.0", AF_INET },
        { "192.0.2.129/24", "192.0.2.0", "192.0.1.255", AF_INET },
        { "0.0.0.0/0", "255.255.255.255", NULL, AF_INET },
        { "192.0.2.255/32", "192.0.2.255", "192.0.2.254", AF_INET },
#if (NGX_HAVE_INET6)
        { "2001:db8::1", "2001:db8::1", "2001:db8::2", AF_INET6 },
        { "2001:db8::ff/64", "2001:db8::", "2001:db8:0:1::", AF_INET6 },
        { "::/0", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", NULL, AF_INET6 },
        { "::1/128", "::1", "::2", AF_INET6 },
        { "0:0:1::/48", "0:0:1::ffff", "0:0:2::", AF_INET6 },
        { "::ffff:0.0.0.0/96", "255.255.255.255", NULL, AF_INET },
        { "::ffff:192.0.2.129/120", "192.0.2.255", "192.0.3.0", AF_INET },
        { "::ffff:192.0.2.7/128", "::ffff:192.0.2.7", "::ffff:192.0.2.8", AF_INET6 },
        { "::ffff:192.0.2.7/80", "::1", "0:1::", AF_INET6 },
#endif
    };
    static const char *invalid[] = {
        "...", ".../24", ".0.2.1",
        ".0.2.1/24", "192..2.1", "192..2.1/24",
        "192.0..1", "192.0..1/24", "192.0.2.",
        "192.0.2./24", "192..2.0", "192..2.0/24",
        ".../0", "::ffff:...", "::ffff:.../120",
        "::ffff:.0.2.1", "::ffff:.0.2.1/120", "::ffff:192..2.1",
        "::ffff:192..2.1/120", "::ffff:192.0..1", "::ffff:192.0..1/120",
        "::ffff:192.0.2.", "::ffff:192.0.2./120", "::ffff:192..2.0",
        "::ffff:192..2.0/120", "2001:db8::...", "2001:db8::.../120",
        "2001:db8::.0.2.1", "2001:db8::.0.2.1/120", "2001:db8::192..2.1",
        "2001:db8::192..2.1/120", "2001:db8::192.0..1", "2001:db8::192.0..1/120",
        "2001:db8::192.0.2.", "2001:db8::192.0.2./120", "2001:db8::192..2.0",
        "2001:db8::192..2.0/120",
        "192+.0.2.1", "192.a.2.1",
        "", "invalid", "192.0.2.256", "192.0.2.1/33", "192.0.2.1/-1",
        "192.0.2.1/", "192.0.2.1/24garbage", "192.0.2.1:80", "localhost",
        "unix:/tmp/shield.sock", "255.255.255.255/32", "::1/129", "2001:db8::gg", "[::1]", "OFF"
    };
    ngx_pool_t *pool;
    ngx_http_shield_loc_conf_t conf;
    ngx_array_t *saved;
    const char *tokens[3];
    ngx_uint_t i;

    fail_create = fail_push = 0;
    for (i = 0; i < sizeof(valid) / sizeof(valid[0]); i++) {
        pool = ngx_create_pool(4096, log);
        assert(pool != NULL);
        ngx_memzero(&conf, sizeof(conf));
        conf.allow_cidrs = NGX_CONF_UNSET_PTR;
        tokens[0] = valid[i].cidr;
        (void) fprintf(stderr, "allowlist_unit: valid %s\n", tokens[0]);
        assert(parse_allow(pool, &conf, tokens, 1) == NGX_CONF_OK);
        assert(conf.allow_cidrs->nelts == 1);
        assert_match(conf.allow_cidrs, valid[i].match, valid[i].family, 1);
        if (valid[i].miss != NULL) {
            assert_match(conf.allow_cidrs, valid[i].miss, valid[i].family, 0);
        }
        ngx_destroy_pool(pool);
    }
    for (i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        pool = ngx_create_pool(4096, log);
        assert(pool != NULL);
        ngx_memzero(&conf, sizeof(conf));
        conf.allow_cidrs = NGX_CONF_UNSET_PTR;
        /* A valid prefix before the malformed token exercises partial state. */
        tokens[0] = "198.51.100.0/24";
        tokens[1] = invalid[i];
        (void) fprintf(stderr, "allowlist_unit: invalid %s\n", tokens[1]);
        assert(parse_allow(pool, &conf, tokens, 2) == NGX_CONF_ERROR);
        assert(conf.allow_cidrs != NGX_CONF_UNSET_PTR);
        assert(conf.allow_cidrs->nelts == 2);
        ngx_destroy_pool(pool);
    }

    pool = ngx_create_pool(4096, log);
    assert(pool != NULL);
    ngx_memzero(&conf, sizeof(conf));
    conf.allow_cidrs = NGX_CONF_UNSET_PTR;
    tokens[0] = "off";
    assert(parse_allow(pool, &conf, tokens, 1) == NGX_CONF_OK);
    assert(conf.allow_cidrs == NULL);
    assert(parse_allow(pool, &conf, tokens, 1) == NGX_CONF_ERROR);
    tokens[0] = "192.0.2.1";
    assert(parse_allow(pool, &conf, tokens, 1) == NGX_CONF_ERROR);
    assert(conf.allow_cidrs == NULL);
    ngx_destroy_pool(pool);

    for (i = 0; i < 2; i++) {
        pool = ngx_create_pool(4096, log);
        assert(pool != NULL);
        ngx_memzero(&conf, sizeof(conf));
        conf.allow_cidrs = NGX_CONF_UNSET_PTR;
        tokens[i] = "off";
        tokens[1 - i] = "192.0.2.1";
        assert(parse_allow(pool, &conf, tokens, 2) == NGX_CONF_ERROR);
        assert(conf.allow_cidrs == NGX_CONF_UNSET_PTR);
        ngx_destroy_pool(pool);
    }

    pool = ngx_create_pool(4096, log);
    assert(pool != NULL);
    ngx_memzero(&conf, sizeof(conf));
    conf.allow_cidrs = NGX_CONF_UNSET_PTR;
    tokens[0] = "192.0.2.0/24";
    assert(parse_allow(pool, &conf, tokens, 1) == NGX_CONF_OK);
    saved = conf.allow_cidrs;
    tokens[0] = "off";
    assert(parse_allow(pool, &conf, tokens, 1) == NGX_CONF_ERROR);
    assert(conf.allow_cidrs == saved && saved->nelts == 1);
    tokens[0] = "198.51.100.0/24";
    tokens[1] = "203.0.113.0/24";
    assert(parse_allow(pool, &conf, tokens, 2) == NGX_CONF_OK);
    assert(saved->nelts == 3);
    assert_match(saved, "192.0.2.255", AF_INET, 1);
    assert_match(saved, "198.51.100.255", AF_INET, 1);
    assert_match(saved, "203.0.113.255", AF_INET, 1);
    assert_match(saved, "198.51.101.0", AF_INET, 0);
    for (i = 0; i < 128; i++) {
        assert(parse_allow(pool, &conf, tokens, 2) == NGX_CONF_OK);
        assert(conf.allow_cidrs == saved && saved->nelts == 5 + 2 * i);
    }
    assert(saved->nalloc >= 259);
    assert(pool->large != NULL);
    assert_match(saved, "203.0.113.1", AF_INET, 1);
    ngx_destroy_pool(pool);
    puts("allowlist_unit: valid, malformed partial lists, normalized, off, repeated/append and large-array pool teardown passed");
}

int
main(void)
{
    ngx_log_t log;
    ngx_pool_t *pool;
    ngx_conf_t cf;
    ngx_array_t args;
    ngx_str_t values[] = {
        ngx_string("shield_allow"), ngx_string("192.0.2.0/24")
    };
    ngx_http_shield_loc_conf_t conf;
    ngx_http_request_t request;
    ngx_connection_t connection;
    struct sockaddr_in address;
    struct sockaddr unsupported;
    ngx_array_t *saved;

    ngx_memzero(&log, sizeof(log));
    ngx_pagesize = (ngx_uint_t) getpagesize();
    ngx_cacheline_size = 64;
    pool = ngx_create_pool(4096, &log);
    assert(pool != NULL);
    ngx_memzero(&cf, sizeof(cf));
    ngx_memzero(&args, sizeof(args));
    ngx_memzero(&conf, sizeof(conf));
    args.elts = values;
    args.nelts = 2;
    cf.args = &args;
    cf.pool = pool;

    conf.allow_cidrs = NGX_CONF_UNSET_PTR;
    fail_create = 1;
    assert(ngx_http_shield_allow(&cf, NULL, &conf) == NGX_CONF_ERROR);
    assert(create_calls == 1 && push_calls == 0);
    assert(conf.allow_cidrs == NULL);

    conf.allow_cidrs = NGX_CONF_UNSET_PTR;
    fail_create = 0;
    fail_push = 1;
    assert(ngx_http_shield_allow(&cf, NULL, &conf) == NGX_CONF_ERROR);
    assert(create_calls == 2 && push_calls == 1);
    assert(conf.allow_cidrs != NULL && conf.allow_cidrs->nelts == 0);

    fail_push = 0;
    assert(ngx_http_shield_allow(&cf, NULL, &conf) == NGX_CONF_OK);
    assert(conf.allow_cidrs->nelts == 1);
    saved = conf.allow_cidrs;
    fail_push = 1;
    assert(ngx_http_shield_allow(&cf, NULL, &conf) == NGX_CONF_ERROR);
    assert(conf.allow_cidrs == saved && saved->nelts == 1);
    assert(create_calls == 2 && push_calls == 3);

    ngx_memzero(&request, sizeof(request));
    ngx_memzero(&connection, sizeof(connection));
    request.connection = &connection;
    assert(ngx_http_shield_allowlisted(&request, NULL) == 0);
    assert(ngx_http_shield_allowlisted(&request, saved) == 0);
    ngx_memzero(&unsupported, sizeof(unsupported));
    unsupported.sa_family = AF_UNSPEC;
    connection.sockaddr = &unsupported;
    assert(ngx_http_shield_allowlisted(&request, saved) == 0);

    ngx_memzero(&address, sizeof(address));
    address.sin_family = AF_INET;
    connection.sockaddr = (struct sockaddr *) &address;
    assert(inet_pton(AF_INET, "192.0.2.255", &address.sin_addr) == 1);
    assert(ngx_http_shield_allowlisted(&request, saved) == 1);
    assert(inet_pton(AF_INET, "192.0.3.0", &address.sin_addr) == 1);
    assert(ngx_http_shield_allowlisted(&request, saved) == 0);

    ngx_destroy_pool(pool);
    parser_cases(&log);
    puts("allowlist_unit: create failure, initial/append push failure, null list/socket, unsupported family, IPv4 boundary match/nonmatch passed");
    return 0;
}
