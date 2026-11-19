/* Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 * Direct body collection failure and per-zone accounting checks. */
#undef NDEBUG
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <assert.h>

static size_t cve_compares;
static int cve_memcmp(const void *a, const void *b, size_t size)
{
    cve_compares++;
    return memcmp(a, b, size);
}
#undef ngx_memcmp
#define ngx_memcmp(a, b, n) cve_memcmp(a, b, n)

static void *test_main_conf;
#undef ngx_http_get_module_main_conf
#define ngx_http_get_module_main_conf(r, module) test_main_conf
#undef ngx_http_get_module_loc_conf
#define ngx_http_get_module_loc_conf(r, module) ((r)->loc_conf[0])
#include "../../src/ngx_http_shield_module.c"

static int fail_alloc = 1;
static int fail_read;
static int prefix_attack;
static size_t inspected_len;
static ngx_uint_t inspected_strict;
static size_t policy_calls;
static int policy_observation;
static int policy_fail_cve_alloc;
static const char *last_identity_policy;
static const ngx_http_shield_hit_t observation_hit = {
    "observation-sentinel", NGX_HTTP_SHIELD_SOURCE_BODY, UINT64_C(0x55),
    "observation-sentinel", NGX_HTTP_SHIELD_CAT_SQLI
};
/* Synthetic non-production scanner seam: record prebody routing arguments and
 * inject a decision at one call. This does not classify production signatures. */
static int prebody_record;
static size_t prebody_calls;
static size_t prebody_decision_call;
static ngx_int_t prebody_decision;
static struct {
    const u_char *data;
    size_t len;
    const char *source;
    size_t form_offset;
    uint64_t skip;
} prebody_scans[4];
static int fail_nth;
static int alloc_calls;
static size_t alloc_sizes[8];
static int fail_arena = 1;
static int arena_calls;
static union {
    ngx_shield_gzip_align_t align;
    u_char bytes[NGX_SHIELD_GZIP_ARENA];
} arena_storage;
static u_char storage[8][NGX_SHIELD_GZIP_INITIAL_OUTPUT + 1];

void *ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    (void) pool;
    assert(size <= sizeof(storage[0]));
    alloc_calls++;
    if ((size_t) alloc_calls <= sizeof(alloc_sizes) / sizeof(alloc_sizes[0])) {
        alloc_sizes[alloc_calls - 1] = size;
    }
    return fail_alloc || alloc_calls == fail_nth
           ? NULL : storage[(alloc_calls - 1) % 8];
}

void *ngx_palloc(ngx_pool_t *pool, size_t size)
{
    (void) pool;
    assert(size == sizeof(arena_storage.bytes));
    arena_calls++;
    return fail_arena ? NULL : arena_storage.bytes;
}

ngx_int_t ngx_pfree(ngx_pool_t *pool, void *data)
{
    (void) pool; (void) data;
    return NGX_OK;
}

ssize_t ngx_read_file(ngx_file_t *file, u_char *buf, size_t size, off_t offset)
{
    (void) file; (void) offset;
    if (fail_read) {
        return NGX_ERROR;
    }
    ngx_memset(buf, 'a', size);
    if (prefix_attack && size >= 4) {
        ngx_memcpy(buf, "evil", 4);
    }
    return (ssize_t) size;
}

ngx_int_t ngx_http_shield_scan_input(const ngx_http_shield_automata_t *automata,
    u_char *data, size_t len, u_char *lc, u_char *dec, const char *source,
    size_t form_offset, uint64_t skip, ngx_http_shield_hit_t *hit)
{
    (void) automata; (void) data; (void) len; (void) lc; (void) dec;
    (void) source; (void) form_offset; (void) skip; (void) hit;
    inspected_len = len;
    if (prebody_record) {
        size_t n = prebody_calls++;
        assert(n < sizeof(prebody_scans) / sizeof(prebody_scans[0]));
        prebody_scans[n].data = data;
        prebody_scans[n].len = len;
        prebody_scans[n].source = source;
        prebody_scans[n].form_offset = form_offset;
        prebody_scans[n].skip = skip;
        if (prebody_calls == prebody_decision_call) {
            if (prebody_decision == NGX_OK) {
                *hit = observation_hit;
                hit->rule = UINT64_C(0x66);
                hit->view = "synthetic-prebody-hit";
            }
            return prebody_decision;
        }
        return NGX_DECLINED;
    }
    return prefix_attack && len >= 4 && ngx_memcmp(data, "evil", 4) == 0
           ? NGX_OK : NGX_DECLINED;
}


/* Keep the body collection oracle deterministic while exercising scan_r's
 * current policy entry point and the request's actual location configuration. */
ngx_int_t ngx_http_shield_scan_policy(const ngx_http_shield_automata_t *automata,
    u_char *data, size_t len, u_char *lc, u_char *dec, const char *source,
    size_t form_offset, uint64_t skip, ngx_uint_t strict,
    ngx_http_shield_hit_t *hit)
{
    assert(ngx_strcmp(source, NGX_HTTP_SHIELD_SOURCE_BODY) == 0);
    policy_calls++;
    inspected_strict = strict;
    if (policy_observation) {
        inspected_len = len;
        *hit = observation_hit;
        if (policy_fail_cve_alloc) {
            /* Scanner scratch succeeded; fail only the next CVE allocation. */
            fail_nth = alloc_calls + 1;
        }
        return NGX_DONE;
    }
    return ngx_http_shield_scan_input(automata, data, len, lc, dec, source,
                                     form_offset, skip, hit);
}

/* Public-definition hashing is covered by the scanner units. This harness
 * checks plumbing, so a distinct fixed identity is sufficient here. */
uint64_t ngx_http_shield_rule_identity(const char *kind, const char *name,
    const ngx_http_shield_sig_t *terms, ngx_uint_t nterms, ngx_uint_t flags)
{
    assert(kind != NULL && name != NULL);
    last_identity_policy = name;
    (void) terms; (void) nterms; (void) flags;
    return UINT64_C(0x123456789abcdef0);
}

/* These cases exercise real body/CVE precedence with a scanner observation.
 * The fixed rule identity checks publication, not the scanner's hash function. */
enum {
    BODY_OBSERVATION_PROMOTED,
    BODY_OBSERVATION_DECLINED,
    BODY_OBSERVATION_CVE_ERROR
};

static void test_body_cve_precedence(int which)
{
    ngx_http_request_t r;
    ngx_http_request_body_t request_body;
    ngx_http_shield_loc_conf_t conf;
    ngx_http_shield_main_conf_t main_conf;
    ngx_http_shield_ban_ctx_t ban_ctx, stats_ctx;
    ngx_http_shield_ban_shctx_t ban;
    ngx_http_shield_stats_shctx_t stats;
    ngx_shm_zone_t ban_zone, stats_zone;
    ngx_http_variable_value_t marks[2];
    ngx_http_shield_hit_t hit;
    ngx_buf_t buf;
    ngx_chain_t chain;
    void *loc_conf[1];
    u_char craft[] = "__class guzzlehttp\\psr7\\fnstream _fn_close";
    u_char clean[] = "abcd";
    u_char *payload = which == BODY_OBSERVATION_PROMOTED ? craft : clean;
    size_t len = which == BODY_OBSERVATION_PROMOTED
                 ? sizeof(craft) - 1 : sizeof(clean) - 1;
    size_t before = policy_calls;
    ngx_int_t rc;
    ngx_uint_t reason;
    ngx_atomic_uint_t expected;

    ngx_memzero(&r, sizeof(r));
    ngx_memzero(&request_body, sizeof(request_body));
    ngx_memzero(&conf, sizeof(conf));
    ngx_memzero(&main_conf, sizeof(main_conf));
    ngx_memzero(&ban_ctx, sizeof(ban_ctx));
    ngx_memzero(&stats_ctx, sizeof(stats_ctx));
    ngx_memzero(&ban, sizeof(ban));
    ngx_memzero(&stats, sizeof(stats));
    ngx_memzero(&ban_zone, sizeof(ban_zone));
    ngx_memzero(&stats_zone, sizeof(stats_zone));
    ngx_memzero(marks, sizeof(marks));
    ngx_memzero(&hit, sizeof(hit));
    ngx_memzero(&buf, sizeof(buf));
    test_main_conf = &main_conf;
    loc_conf[0] = &conf;
    r.loc_conf = loc_conf;
    r.main = &r;
    r.variables = marks;
    r.request_body = &request_body;
    r.headers_in.content_length_n = (off_t) len;
    buf.memory = 1;
    buf.pos = payload;
    buf.last = payload + len;
    chain.buf = &buf;
    chain.next = NULL;
    request_body.bufs = &chain;
    ban_ctx.sh = &ban;
    ban_zone.data = &ban_ctx;
    conf.ban_zone = &ban_zone;
    stats_ctx.stats_only = 1;
    stats_ctx.stats = &stats;
    stats_ctx.request_index = 1;
    stats_zone.data = &stats_ctx;
    main_conf.stats_zone = &stats_zone;
    conf.max_body = len;
    conf.cve = NGX_SHIELD_CVE_CRAFT;
    fail_alloc = 0;
    fail_arena = 0;
    fail_read = 0;
    prefix_attack = 0;
    fail_nth = 0;
    alloc_calls = 0;
    arena_calls = 0;
    policy_observation = 1;
    policy_fail_cve_alloc = which == BODY_OBSERVATION_CVE_ERROR;

    rc = ngx_http_shield_inspect_body(&r, &conf, &hit);
    if (which == BODY_OBSERVATION_PROMOTED) {
        assert(rc == NGX_OK && "observation promoted by decoded Craft");
        assert(hit.rule == UINT64_C(0x123456789abcdef0));
        assert(hit.cat == NGX_HTTP_SHIELD_CAT_DESERIAL);
        assert(ngx_strcmp(hit.category, "deserial") == 0);
        assert(ngx_strcmp(hit.source, NGX_HTTP_SHIELD_SOURCE_BODY) == 0);
        assert(ngx_strcmp(hit.view, "policy-decoded") == 0);
    } else {
        if (which == BODY_OBSERVATION_DECLINED) {
            assert(rc == NGX_DONE && "observation preserved on CVE decline");
        } else {
            assert(rc == NGX_ERROR && "observation CVE scratch error propagates");
        }
        assert(hit.rule == UINT64_C(0x55));
        assert(hit.cat == NGX_HTTP_SHIELD_CAT_SQLI);
        assert(ngx_strcmp(hit.category, "observation-sentinel") == 0);
        assert(ngx_strcmp(hit.source, NGX_HTTP_SHIELD_SOURCE_BODY) == 0);
        assert(ngx_strcmp(hit.view, "observation-sentinel") == 0);
    }
    assert(policy_calls == before + 1 && inspected_len == len);
    assert(alloc_calls == 4 && arena_calls == 0);
    assert(alloc_sizes[0] == len && alloc_sizes[1] == len
           && alloc_sizes[2] == len && alloc_sizes[3] == len);
    for (reason = 0; reason < NGX_HTTP_SHIELD_BODY_REASONS; reason++) {
        expected = which == BODY_OBSERVATION_CVE_ERROR
                   && reason == NGX_HTTP_SHIELD_BODY_ERROR ? 1 : 0;
        assert(stats.body_uninspected[reason] == expected);
        assert(ban.body_uninspected[reason] == expected);
    }
    policy_observation = 0;
    policy_fail_cve_alloc = 0;
    fail_nth = 0;
    fail_alloc = 1;
    fail_arena = 1;
    test_main_conf = NULL;
}

/* The JSON policy is excluded from the decoded pass. Its publication must
 * replace every observation field; a disabled policy must preserve them all. */
static void test_body_json_publication(ngx_uint_t enabled)
{
    ngx_http_request_t r;
    ngx_http_request_body_t request_body;
    ngx_http_shield_loc_conf_t conf;
    ngx_http_shield_main_conf_t main_conf;
    ngx_http_shield_ban_ctx_t ban_ctx, stats_ctx;
    ngx_http_shield_ban_shctx_t ban;
    ngx_http_shield_stats_shctx_t stats;
    ngx_shm_zone_t ban_zone, stats_zone;
    ngx_http_variable_value_t marks[2];
    ngx_http_shield_hit_t hit;
    ngx_buf_t buf;
    ngx_table_elt_t content_type;
    ngx_chain_t chain;
    void *loc_conf[1];
    u_char payload[] = "{\"v\":\":__proto__:then\"}";
    size_t len = sizeof(payload) - 1;
    size_t before = policy_calls;
    ngx_int_t rc;
    ngx_uint_t reason;

    ngx_memzero(&r, sizeof(r));
    ngx_memzero(&request_body, sizeof(request_body));
    ngx_memzero(&conf, sizeof(conf));
    ngx_memzero(&main_conf, sizeof(main_conf));
    ngx_memzero(&ban_ctx, sizeof(ban_ctx));
    ngx_memzero(&stats_ctx, sizeof(stats_ctx));
    ngx_memzero(&ban, sizeof(ban));
    ngx_memzero(&stats, sizeof(stats));
    ngx_memzero(&ban_zone, sizeof(ban_zone));
    ngx_memzero(&stats_zone, sizeof(stats_zone));
    ngx_memzero(marks, sizeof(marks));
    ngx_memzero(&hit, sizeof(hit));
    ngx_memzero(&buf, sizeof(buf));
    ngx_memzero(&content_type, sizeof(content_type));
    content_type.hash = 1;
    ngx_str_set(&content_type.key, "Content-Type");
    ngx_str_set(&content_type.value, "application/json");
    r.headers_in.headers.part.elts = &content_type;
    r.headers_in.headers.part.nelts = 1;
    test_main_conf = &main_conf;
    loc_conf[0] = &conf;
    r.loc_conf = loc_conf;
    r.main = &r;
    r.variables = marks;
    r.request_body = &request_body;
    r.headers_in.content_length_n = (off_t) len;
    buf.memory = 1;
    buf.pos = payload;
    buf.last = payload + len;
    chain.buf = &buf;
    chain.next = NULL;
    request_body.bufs = &chain;
    ban_ctx.sh = &ban;
    ban_zone.data = &ban_ctx;
    conf.ban_zone = &ban_zone;
    stats_ctx.stats_only = 1;
    stats_ctx.stats = &stats;
    stats_ctx.request_index = 1;
    stats_zone.data = &stats_ctx;
    main_conf.stats_zone = &stats_zone;
    conf.max_body = len;
    conf.cve = enabled ? NGX_SHIELD_CVE_JSON : 0;
    fail_alloc = 0;
    fail_arena = 0;
    fail_read = 0;
    prefix_attack = 0;
    fail_nth = 0;
    alloc_calls = 0;
    arena_calls = 0;
    policy_observation = 1;
    policy_fail_cve_alloc = 0;

    rc = ngx_http_shield_inspect_body(&r, &conf, &hit);
    if (enabled) {
        assert(rc == NGX_OK && "observation promoted by JSON publication");
        assert(hit.rule == UINT64_C(0x123456789abcdef0));
        assert(hit.cat == NGX_HTTP_SHIELD_CAT_DESERIAL);
        assert(ngx_strcmp(hit.category, "deserial") == 0);
        assert(ngx_strcmp(hit.source, NGX_HTTP_SHIELD_SOURCE_BODY) == 0);
        assert(ngx_strcmp(hit.view, "policy-json") == 0);
    } else {
        assert(rc == NGX_DONE && "disabled JSON preserves observation");
        assert(hit.rule == UINT64_C(0x55));
        assert(hit.cat == NGX_HTTP_SHIELD_CAT_SQLI);
        assert(ngx_strcmp(hit.category, "observation-sentinel") == 0);
        assert(ngx_strcmp(hit.source, NGX_HTTP_SHIELD_SOURCE_BODY) == 0);
        assert(ngx_strcmp(hit.view, "observation-sentinel") == 0);
    }
    assert(policy_calls == before + 1 && inspected_len == len);
    assert(alloc_calls == (enabled ? 4 : 3) && arena_calls == 0);
    assert(alloc_sizes[0] == len && alloc_sizes[1] == len
           && alloc_sizes[2] == len);
    if (enabled) {
        assert(alloc_sizes[3] == len);
    }
    for (reason = 0; reason < NGX_HTTP_SHIELD_BODY_REASONS; reason++) {
        assert(stats.body_uninspected[reason] == 0);
        assert(ban.body_uninspected[reason] == 0);
    }
    policy_observation = 0;
    policy_fail_cve_alloc = 0;
    fail_nth = 0;
    fail_alloc = 1;
    fail_arena = 1;
    test_main_conf = NULL;
}

/* A complete multipart field carries a JSON string token. Only the multipart
 * view can publish it; disabling CVEs must preserve every observation field. */
static void test_body_multipart_publication(ngx_uint_t enabled)
{
    ngx_http_request_t r;
    ngx_http_request_body_t request_body;
    ngx_http_shield_loc_conf_t conf;
    ngx_http_shield_main_conf_t main_conf;
    ngx_http_shield_ban_ctx_t ban_ctx, stats_ctx;
    ngx_http_shield_ban_shctx_t ban;
    ngx_http_shield_stats_shctx_t stats;
    ngx_shm_zone_t ban_zone, stats_zone;
    ngx_http_variable_value_t marks[2];
    ngx_http_shield_hit_t hit;
    ngx_buf_t buf;
    ngx_table_elt_t content_type;
    ngx_chain_t chain;
    void *loc_conf[1];
    u_char payload[] =
        "--shield-boundary\r\n"
        "Content-Disposition: form-data; name=\"payload\"\r\n"
        "\r\n"
        "\":__proto__:then\"\r\n"
        "--shield-boundary--\r\n";
    size_t len = sizeof(payload) - 1;
    size_t before = policy_calls;
    ngx_int_t rc;
    ngx_uint_t reason;

    ngx_memzero(&r, sizeof(r));
    ngx_memzero(&request_body, sizeof(request_body));
    ngx_memzero(&conf, sizeof(conf));
    ngx_memzero(&main_conf, sizeof(main_conf));
    ngx_memzero(&ban_ctx, sizeof(ban_ctx));
    ngx_memzero(&stats_ctx, sizeof(stats_ctx));
    ngx_memzero(&ban, sizeof(ban));
    ngx_memzero(&stats, sizeof(stats));
    ngx_memzero(&ban_zone, sizeof(ban_zone));
    ngx_memzero(&stats_zone, sizeof(stats_zone));
    ngx_memzero(marks, sizeof(marks));
    ngx_memzero(&hit, sizeof(hit));
    ngx_memzero(&buf, sizeof(buf));
    ngx_memzero(&content_type, sizeof(content_type));
    content_type.hash = 1;
    ngx_str_set(&content_type.key, "Content-Type");
    ngx_str_set(&content_type.value,
                "multipart/form-data; boundary=shield-boundary");
    r.headers_in.headers.part.elts = &content_type;
    r.headers_in.headers.part.nelts = 1;
    test_main_conf = &main_conf;
    loc_conf[0] = &conf;
    r.loc_conf = loc_conf;
    r.main = &r;
    r.variables = marks;
    r.request_body = &request_body;
    r.headers_in.content_length_n = (off_t) len;
    buf.memory = 1;
    buf.pos = payload;
    buf.last = payload + len;
    chain.buf = &buf;
    chain.next = NULL;
    request_body.bufs = &chain;
    ban_ctx.sh = &ban;
    ban_zone.data = &ban_ctx;
    conf.ban_zone = &ban_zone;
    stats_ctx.stats_only = 1;
    stats_ctx.stats = &stats;
    stats_ctx.request_index = 1;
    stats_zone.data = &stats_ctx;
    main_conf.stats_zone = &stats_zone;
    conf.max_body = len;
    conf.cve = enabled ? NGX_SHIELD_CVE_JSON : 0;
    fail_alloc = 0;
    fail_arena = 0;
    fail_read = 0;
    prefix_attack = 0;
    fail_nth = 0;
    alloc_calls = 0;
    arena_calls = 0;
    policy_observation = 1;
    policy_fail_cve_alloc = 0;

    rc = ngx_http_shield_inspect_body(&r, &conf, &hit);
    if (enabled) {
        assert(rc == NGX_OK && "observation promoted by multipart publication");
        assert(hit.rule == UINT64_C(0x123456789abcdef0));
        assert(hit.cat == NGX_HTTP_SHIELD_CAT_DESERIAL);
        assert(ngx_strcmp(hit.category, "deserial") == 0);
        assert(ngx_strcmp(hit.source, NGX_HTTP_SHIELD_SOURCE_BODY) == 0);
        assert(ngx_strcmp(hit.view, "policy-multipart") == 0);
    } else {
        assert(rc == NGX_DONE && "disabled multipart CVE preserves observation");
        assert(hit.rule == UINT64_C(0x55));
        assert(hit.cat == NGX_HTTP_SHIELD_CAT_SQLI);
        assert(ngx_strcmp(hit.category, "observation-sentinel") == 0);
        assert(ngx_strcmp(hit.source, NGX_HTTP_SHIELD_SOURCE_BODY) == 0);
        assert(ngx_strcmp(hit.view, "observation-sentinel") == 0);
    }
    assert(policy_calls == before + 1 && inspected_len == len);
    assert(alloc_calls == (enabled ? 4 : 3) && arena_calls == 0);
    assert(alloc_sizes[0] == len && alloc_sizes[1] == len
           && alloc_sizes[2] == len);
    if (enabled) {
        assert(alloc_sizes[3] == len);
    }
    for (reason = 0; reason < NGX_HTTP_SHIELD_BODY_REASONS; reason++) {
        assert(stats.body_uninspected[reason] == 0);
        assert(ban.body_uninspected[reason] == 0);
    }
    policy_observation = 0;
    policy_fail_cve_alloc = 0;
    fail_nth = 0;
    fail_alloc = 1;
    fail_arena = 1;
    test_main_conf = NULL;
}

/* Query policies publish from their query-specific views. Disabled, skipped,
 * clean, allocation-error and empty inputs must leave every sentinel intact. */
static void test_query_publication(ngx_uint_t policy, ngx_uint_t control)
{
    ngx_http_request_t r;
    ngx_http_shield_loc_conf_t conf;
    ngx_http_shield_hit_t hit = observation_hit;
    ngx_str_t input;
    ngx_int_t rc;
    ngx_uint_t cat;
    size_t before = policy_calls;

    ngx_memzero(&r, sizeof(r));
    ngx_memzero(&conf, sizeof(conf));
    if (policy == NGX_SHIELD_CVE_PHP) {
        ngx_str_set(&input, "%adD+allow_url_include=1");
        cat = NGX_HTTP_SHIELD_CAT_PHP_RCE;
    } else {
        ngx_str_set(&input, "JAVA%2eLANG%2eRUNTIME");
        cat = NGX_HTTP_SHIELD_CAT_JAVA_EVAL;
    }
    conf.cve = control == 1 ? 0 : policy;
    conf.skip = control == 2 ? (uint64_t) 1 << cat : 0;
    if (control == 3) {
        ngx_str_set(&input, "benign");
    } else if (control == 5) {
        input.len = 0;
    }
    fail_alloc = control == 4;
    fail_nth = 0;
    alloc_calls = 0;
    last_identity_policy = "identity-sentinel";
    /* Exercise query publication through the actual prebody early return. */
    r.args = input;
    rc = ngx_http_shield_inspect_prebody(&r, &conf, &hit);
    if (control == 0) {
        assert(rc == NGX_OK && "query policy publishes hit");
        assert(hit.rule == UINT64_C(0x123456789abcdef0));
        assert(hit.cat == cat);
        assert(ngx_strcmp(hit.category, (policy == NGX_SHIELD_CVE_PHP
                         ? "php_rce" : "java_eval")) == 0);
        assert(ngx_strcmp(hit.source, NGX_HTTP_SHIELD_SOURCE_URI) == 0);
        assert(ngx_strcmp(hit.view, (policy == NGX_SHIELD_CVE_PHP
                         ? "policy-query" : "policy-decoded")) == 0);
        assert(ngx_strcmp(last_identity_policy,
                         (policy == NGX_SHIELD_CVE_PHP
                         ? "php_cgi" : "geoserver_eval")) == 0);
    } else {
        assert(rc == (control == 4 ? NGX_ERROR : NGX_DECLINED)
               && "query control preserves sentinel");
        assert(hit.rule == observation_hit.rule && hit.cat == observation_hit.cat);
        assert(hit.category == observation_hit.category);
        assert(hit.source == observation_hit.source);
        assert(hit.view == observation_hit.view);
        assert(ngx_strcmp(last_identity_policy, "identity-sentinel") == 0);
    }
    assert(alloc_calls == (control == 1 || control == 5
                          || (control == 2 && policy == NGX_SHIELD_CVE_GEO)
                          ? 0 : 1));
    assert(policy_calls == before);
    fail_alloc = 1;
}

/* Empty header values isolate the real policy-name and method predicates from
 * generic value scanning, whose classifier is stubbed for this body harness. */
static void test_header_publication(ngx_uint_t policy, ngx_uint_t control)
{
    ngx_http_request_t r;
    ngx_http_shield_loc_conf_t conf;
    ngx_http_shield_hit_t hit = observation_hit;
    ngx_table_elt_t header;
    ngx_int_t rc;
    size_t before = policy_calls;

    ngx_memzero(&r, sizeof(r));
    ngx_memzero(&conf, sizeof(conf));
    ngx_memzero(&header, sizeof(header));
    conf.cve = control == 1 ? 0 : policy;
    conf.skip = ((uint64_t) 1 << NGX_HTTP_SHIELD_CAT_HTTPOXY)
                | ((uint64_t) 1 << NGX_HTTP_SHIELD_CAT_RANGE_DOS)
                | ((uint64_t) 1 << NGX_HTTP_SHIELD_CAT_CTRL_CHAR)
                | ((uint64_t) 1 << NGX_HTTP_SHIELD_CAT_DOTFILE);
    if (control == 2) {
        conf.skip |= (uint64_t) 1 << NGX_HTTP_SHIELD_CAT_EXPLOIT_PATH;
    }
    if (policy == NGX_SHIELD_CVE_NEXT) {
        ngx_str_set(&header.key, "X-Middleware-Subrequest");
    } else {
        ngx_str_set(&header.key, "content-range");
    }
    if (control == 3) {
        ngx_str_set(&header.key, "X-Unrelated");
    }
    header.hash = control == 4 ? 0 : 1;
    r.method = control == 5 ? NGX_HTTP_GET : NGX_HTTP_PUT;
    r.headers_in.headers.part.elts = &header;
    r.headers_in.headers.part.nelts = 1;
    alloc_calls = 0;
    last_identity_policy = "identity-sentinel";
    rc = ngx_http_shield_inspect_prebody(&r, &conf, &hit);
    if (control == 0) {
        assert(rc == NGX_OK && "header policy publishes hit");
        assert(hit.rule == UINT64_C(0x123456789abcdef0));
        assert(hit.cat == NGX_HTTP_SHIELD_CAT_EXPLOIT_PATH);
        assert(ngx_strcmp(hit.category, "exploit_path") == 0);
        assert(ngx_strcmp(hit.source, NGX_HTTP_SHIELD_SOURCE_HEADER) == 0);
        assert(ngx_strcmp(hit.view, "policy-header") == 0);
        assert(ngx_strcmp(last_identity_policy,
                         (policy == NGX_SHIELD_CVE_NEXT
                         ? "nextjs_middleware" : "tomcat_put")) == 0);
    } else {
        assert(rc == NGX_DECLINED && "header control preserves sentinel");
        assert(hit.rule == observation_hit.rule && hit.cat == observation_hit.cat);
        assert(hit.category == observation_hit.category);
        assert(hit.source == observation_hit.source);
        assert(hit.view == observation_hit.view);
        assert(ngx_strcmp(last_identity_policy, "identity-sentinel") == 0);
    }
    assert(policy_calls == before && alloc_calls == 0);
}

/* Metadata in a second list part must be inspected before body publication.
 * Conflicting or malformed boundaries propagate errors without replacing the
 * scanner observation; disabled, skipped and ignored fields preserve it too. */
enum {
    BODY_METADATA_JSON_CONTINUATION,
    BODY_METADATA_SAME_BOUNDARY,
    BODY_METADATA_CONFLICT_LENGTH,
    BODY_METADATA_CONFLICT_BYTES,
    BODY_METADATA_MISSING,
    BODY_METADATA_EMPTY,
    BODY_METADATA_UNTERMINATED,
    BODY_METADATA_DUPLICATE,
    BODY_METADATA_MAX_BOUNDARY,
    BODY_METADATA_LONG_BOUNDARY,
    BODY_METADATA_DISABLED,
    BODY_METADATA_SKIPPED,
    BODY_METADATA_ZERO_HASH,
    BODY_METADATA_OTHER_HEADER,
    BODY_METADATA_CASES
};
static void test_body_metadata(ngx_uint_t control)
{
    ngx_http_request_t r;
    ngx_http_request_body_t request_body;
    ngx_http_shield_loc_conf_t conf;
    ngx_http_shield_main_conf_t main_conf;
    ngx_http_shield_ban_ctx_t ban_ctx, stats_ctx;
    ngx_http_shield_ban_shctx_t ban;
    ngx_http_shield_stats_shctx_t stats;
    ngx_shm_zone_t ban_zone, stats_zone;
    ngx_http_variable_value_t marks[2];
    ngx_http_shield_hit_t hit;
    ngx_buf_t buf;
    ngx_table_elt_t first[2], content_type;
    ngx_list_part_t next;
    ngx_chain_t chain;
    void *loc_conf[1];
    u_char payload[512];
    const char *boundary = "shield-boundary";
    const char *long_boundary =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    size_t len;
    size_t before = policy_calls;
    ngx_int_t rc;
    ngx_uint_t reason;
    ngx_uint_t invalid = (control >= BODY_METADATA_CONFLICT_LENGTH
                         && control <= BODY_METADATA_DUPLICATE)
                        || control == BODY_METADATA_LONG_BOUNDARY;
    ngx_uint_t publish = control == BODY_METADATA_JSON_CONTINUATION
                        || control == BODY_METADATA_SAME_BOUNDARY
                        || control == BODY_METADATA_MAX_BOUNDARY;
    ngx_atomic_uint_t expected;

    if (control == BODY_METADATA_MAX_BOUNDARY) {
        boundary = long_boundary;
    }
    len = (size_t) snprintf((char *) payload, sizeof(payload),
              "--%s\r\nContent-Disposition: form-data; name=\"payload\"\r\n"
              "\r\n\":__proto__:then\"\r\n--%s--\r\n", boundary, boundary);
    assert(len < sizeof(payload));
    if (control == BODY_METADATA_JSON_CONTINUATION) {
        ngx_memcpy(payload, "{\"v\":\":__proto__:then\"}",
                   sizeof("{\"v\":\":__proto__:then\"}") - 1);
        len = sizeof("{\"v\":\":__proto__:then\"}") - 1;
    }

    ngx_memzero(&r, sizeof(r));
    ngx_memzero(&request_body, sizeof(request_body));
    ngx_memzero(&conf, sizeof(conf));
    ngx_memzero(&main_conf, sizeof(main_conf));
    ngx_memzero(&ban_ctx, sizeof(ban_ctx));
    ngx_memzero(&stats_ctx, sizeof(stats_ctx));
    ngx_memzero(&ban, sizeof(ban));
    ngx_memzero(&stats, sizeof(stats));
    ngx_memzero(&ban_zone, sizeof(ban_zone));
    ngx_memzero(&stats_zone, sizeof(stats_zone));
    ngx_memzero(marks, sizeof(marks));
    ngx_memzero(&hit, sizeof(hit));
    ngx_memzero(&buf, sizeof(buf));
    ngx_memzero(first, sizeof(first));
    ngx_memzero(&next, sizeof(next));
    ngx_memzero(&content_type, sizeof(content_type));
    /* An inactive malformed Content-Type and an unrelated active header must
     * neither fail the scan nor hide the field in the following list part. */
    ngx_str_set(&first[0].key, "Content-Type");
    ngx_str_set(&first[0].value, "multipart/form-data; boundary=");
    first[1].hash = 1;
    ngx_str_set(&first[1].key, "X-Unrelated");
    ngx_str_set(&first[1].value, "multipart/form-data; boundary=");
    if (control == BODY_METADATA_SAME_BOUNDARY
        || control == BODY_METADATA_CONFLICT_LENGTH
        || control == BODY_METADATA_CONFLICT_BYTES)
    {
        first[0].hash = 1;
        ngx_str_set(&first[0].value,
                    "multipart/form-data; boundary=shield-boundary");
    }
    content_type.hash = 1;
    ngx_str_set(&content_type.key, "Content-Type");
    ngx_str_set(&content_type.value,
                "multipart/form-data; boundary=shield-boundary");
    switch (control) {
    case BODY_METADATA_JSON_CONTINUATION:
        ngx_str_set(&content_type.value, "application/problem+json");
        break;
    case BODY_METADATA_CONFLICT_LENGTH:
        ngx_str_set(&content_type.value, "multipart/form-data; boundary=x");
        break;
    case BODY_METADATA_CONFLICT_BYTES:
        ngx_str_set(&content_type.value,
                    "multipart/form-data; boundary=shield-boundarz");
        break;
    case BODY_METADATA_MISSING:
    case BODY_METADATA_DISABLED:
    case BODY_METADATA_SKIPPED:
    case BODY_METADATA_ZERO_HASH:
    case BODY_METADATA_OTHER_HEADER:
        ngx_str_set(&content_type.value, "multipart/form-data");
        break;
    case BODY_METADATA_EMPTY:
        ngx_str_set(&content_type.value, "multipart/form-data; boundary=");
        break;
    case BODY_METADATA_UNTERMINATED:
        ngx_str_set(&content_type.value, "multipart/form-data; boundary=\"open");
        break;
    case BODY_METADATA_DUPLICATE:
        ngx_str_set(&content_type.value,
                    "multipart/form-data; boundary=x; boundary=x");
        break;
    case BODY_METADATA_MAX_BOUNDARY:
    case BODY_METADATA_LONG_BOUNDARY:
        ngx_str_set(&content_type.value,
                    "multipart/form-data; boundary="
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" "a");
        if (control == BODY_METADATA_MAX_BOUNDARY) {
            content_type.value.len--;
        }
        break;
    default:
        break;
    }
    if (control == BODY_METADATA_ZERO_HASH) {
        content_type.hash = 0;
    } else if (control == BODY_METADATA_OTHER_HEADER) {
        ngx_str_set(&content_type.key, "X-Unrelated");
    }
    r.headers_in.headers.part.elts = first;
    r.headers_in.headers.part.nelts = 2;
    r.headers_in.headers.part.next = &next;
    next.elts = &content_type;
    next.nelts = 1;
    test_main_conf = &main_conf;
    loc_conf[0] = &conf;
    r.loc_conf = loc_conf;
    r.main = &r;
    r.variables = marks;
    r.request_body = &request_body;
    r.headers_in.content_length_n = (off_t) len;
    buf.memory = 1;
    buf.pos = payload;
    buf.last = payload + len;
    chain.buf = &buf;
    chain.next = NULL;
    request_body.bufs = &chain;
    ban_ctx.sh = &ban;
    ban_zone.data = &ban_ctx;
    conf.ban_zone = &ban_zone;
    stats_ctx.stats_only = 1;
    stats_ctx.stats = &stats;
    stats_ctx.request_index = 1;
    stats_zone.data = &stats_ctx;
    main_conf.stats_zone = &stats_zone;
    conf.max_body = len;
    conf.cve = control == BODY_METADATA_DISABLED ? 0 : NGX_SHIELD_CVE_JSON;
    if (control == BODY_METADATA_SKIPPED) {
        conf.skip = (uint64_t) 1 << NGX_HTTP_SHIELD_CAT_DESERIAL;
    }
    fail_alloc = 0;
    fail_arena = 0;
    fail_read = 0;
    prefix_attack = 0;
    fail_nth = 0;
    alloc_calls = 0;
    arena_calls = 0;
    policy_observation = 1;
    policy_fail_cve_alloc = 0;

    last_identity_policy = "identity-sentinel";
    rc = ngx_http_shield_inspect_body(&r, &conf, &hit);
    if (publish) {
        assert(rc == NGX_OK && "continued metadata publishes body policy");
        assert(hit.rule == UINT64_C(0x123456789abcdef0));
        assert(hit.cat == NGX_HTTP_SHIELD_CAT_DESERIAL);
        assert(ngx_strcmp(hit.category, "deserial") == 0);
        assert(ngx_strcmp(hit.source, NGX_HTTP_SHIELD_SOURCE_BODY) == 0);
        assert(ngx_strcmp(hit.view,
                         (control == BODY_METADATA_JSON_CONTINUATION
                          ? "policy-json" : "policy-multipart")) == 0);
        assert(ngx_strcmp(last_identity_policy, "react_flight") == 0);
    } else {
        if (invalid) {
            assert(rc == NGX_ERROR && "invalid multipart metadata fails closed");
        } else {
            assert(rc == NGX_DONE && "ignored metadata preserves observation");
        }
        assert(hit.rule == UINT64_C(0x55));
        assert(hit.cat == NGX_HTTP_SHIELD_CAT_SQLI);
        assert(ngx_strcmp(hit.category, "observation-sentinel") == 0);
        assert(ngx_strcmp(hit.source, NGX_HTTP_SHIELD_SOURCE_BODY) == 0);
        assert(ngx_strcmp(hit.view, "observation-sentinel") == 0);
        assert(ngx_strcmp(last_identity_policy, "identity-sentinel") == 0);
    }
    assert(policy_calls == before + 1 && inspected_len == len);
    assert(alloc_calls == (control == BODY_METADATA_DISABLED
                          || control == BODY_METADATA_SKIPPED ? 3 : 4)
           && arena_calls == 0);
    assert(alloc_sizes[0] == len && alloc_sizes[1] == len
           && alloc_sizes[2] == len);
    if (control != BODY_METADATA_DISABLED && control != BODY_METADATA_SKIPPED) {
        assert(alloc_sizes[3] == len);
    }
    for (reason = 0; reason < NGX_HTTP_SHIELD_BODY_REASONS; reason++) {
        expected = invalid && reason == NGX_HTTP_SHIELD_BODY_ERROR ? 1 : 0;
        assert(stats.body_uninspected[reason] == expected);
        assert(ban.body_uninspected[reason] == expected);
    }
    policy_observation = 0;
    policy_fail_cve_alloc = 0;
    fail_nth = 0;
    fail_alloc = 1;
    fail_arena = 1;
    test_main_conf = NULL;
}


/* Each structural guard must stop the prebody pipeline and publish its exact
 * metadata. The skip and adjacent clean boundary must preserve the sentinel. */
static void test_prebody_structural(ngx_uint_t which, ngx_uint_t control)
{
    ngx_http_request_t r;
    ngx_http_shield_loc_conf_t conf;
    ngx_http_shield_hit_t hit = observation_hit;
    ngx_table_elt_t header;
    ngx_uint_t cat;
    const char *name, *source;
    u_char ranges[NGX_HTTP_SHIELD_MAX_RANGES + 1];
    ngx_int_t rc;

    ngx_memzero(&r, sizeof(r));
    ngx_memzero(&conf, sizeof(conf));
    ngx_memzero(&header, sizeof(header));
    header.hash = 1;
    ngx_str_set(&header.key, "X-Unrelated");
    r.headers_in.headers.part.elts = &header;
    r.headers_in.headers.part.nelts = 1;
    switch (which) {
    case 0:
        cat = NGX_HTTP_SHIELD_CAT_HTTPOXY;
        name = NGX_HTTP_SHIELD_NAME_HTTPOXY;
        source = NGX_HTTP_SHIELD_SOURCE_HEADER;
        ngx_str_set(&header.key, "pRoXy");
        if (control == 2) {
            ngx_str_set(&header.key, "Proxy-Extra");
        }
        break;
    case 1:
        cat = NGX_HTTP_SHIELD_CAT_RANGE_DOS;
        name = NGX_HTTP_SHIELD_NAME_RANGE_DOS;
        source = NGX_HTTP_SHIELD_SOURCE_RANGE;
        ngx_memset(ranges, ',', sizeof(ranges));
        header.value.data = ranges;
        header.value.len = NGX_HTTP_SHIELD_MAX_RANGES - (control == 2);
        r.headers_in.range = &header;
        break;
    case 2:
        cat = NGX_HTTP_SHIELD_CAT_CTRL_CHAR;
        name = NGX_HTTP_SHIELD_NAME_CTRL_CHAR;
        source = NGX_HTTP_SHIELD_SOURCE_URI;
        ngx_str_set(&r.uri, "/\x01");
        if (control == 2) {
            ngx_str_set(&r.uri, "/\0\r\n\x20\x7f");
        }
        break;
    default:
        cat = NGX_HTTP_SHIELD_CAT_DOTFILE;
        name = NGX_HTTP_SHIELD_NAME_DOTFILE;
        source = NGX_HTTP_SHIELD_SOURCE_URI;
        ngx_str_set(&r.uri, "/.well-known/.env");
        if (control == 2) {
            ngx_str_set(&r.uri, "/.well-known/acme-challenge/token");
        }
        break;
    }
    conf.skip = UINT64_MAX & ~((uint64_t) 1 << cat);
    if (control == 1) {
        conf.skip = UINT64_MAX;
    }
    /* Range uses its parsed field; no generic header scan is needed here. */
    header.value.len = which == 1 ? header.value.len : 0;
    if (which == 1) {
        header.hash = 0;
    }
    prebody_record = 1;
    prebody_calls = 0;
    last_identity_policy = "identity-sentinel";
    alloc_calls = 0;
    rc = ngx_http_shield_inspect_prebody(&r, &conf, &hit);
    if (control == 0) {
        assert(rc == NGX_OK && "prebody structural guard publishes hit");
        assert(hit.rule == UINT64_C(0x123456789abcdef0));
        assert(hit.cat == cat && ngx_strcmp(hit.category, name) == 0);
        assert(ngx_strcmp(hit.source, source) == 0);
        assert(ngx_strcmp(hit.view, "structural") == 0);
        assert(ngx_strcmp(last_identity_policy, name) == 0);
    } else {
        assert(rc == NGX_DECLINED && "prebody structural boundary is clean");
        assert(hit.rule == observation_hit.rule && hit.cat == observation_hit.cat);
        assert(hit.category == observation_hit.category);
        assert(hit.source == observation_hit.source && hit.view == observation_hit.view);
        assert(ngx_strcmp(last_identity_policy, "identity-sentinel") == 0);
    }
    assert(prebody_calls == 0 && alloc_calls == 0);
    prebody_record = 0;
}

/* Record every real prebody scan_r invocation. Test the URI two-pass contract,
 * all header policies, list continuation, inactive/empty fields and decisions.
 * Expected masks below are independent enumerations of the public categories. */
static void test_prebody_routes(ngx_uint_t which)
{
    ngx_http_request_t r;
    ngx_http_shield_loc_conf_t conf;
    ngx_http_shield_main_conf_t main_conf;
    ngx_http_shield_hit_t hit = observation_hit;
    ngx_table_elt_t headers[3], tail;
    ngx_list_part_t next;
    void *loc_conf[1];
    ngx_int_t rc, expected_rc = NGX_DECLINED;
    const char *source = NGX_HTTP_SHIELD_SOURCE_HEADER;
    uint64_t base = (uint64_t) 1 << NGX_HTTP_SHIELD_CAT_WEBSHELL;
    uint64_t generic = ((uint64_t) 1 << NGX_HTTP_SHIELD_CAT_TEMPLATE)
                       | ((uint64_t) 1 << NGX_HTTP_SHIELD_CAT_SHELLSHOCK);
    uint64_t no_query = ((uint64_t) 1 << NGX_HTTP_SHIELD_CAT_XSS)
                        | ((uint64_t) 1 << NGX_HTTP_SHIELD_CAT_SENSITIVE_FILE);
    uint64_t expected_skip = base | ~generic;
    size_t expected_calls = 1, expected_len = 4, expected_offset = 4;
    size_t before = policy_calls;

    ngx_memzero(&r, sizeof(r));
    ngx_memzero(&conf, sizeof(conf));
    ngx_memzero(&main_conf, sizeof(main_conf));
    ngx_memzero(headers, sizeof(headers));
    ngx_memzero(&tail, sizeof(tail));
    ngx_memzero(&next, sizeof(next));
    loc_conf[0] = &conf;
    r.loc_conf = loc_conf;
    test_main_conf = &main_conf;
    conf.skip = base;
    headers[0].hash = 1;
    ngx_str_set(&headers[0].key, "Authorization");
    ngx_str_set(&headers[0].value, "abcd");
    r.headers_in.headers.part.elts = headers;
    r.headers_in.headers.part.nelts = 1;
    prebody_decision_call = 0;
    prebody_decision = NGX_DECLINED;
    fail_alloc = 0;
    fail_nth = 0;
    alloc_calls = 0;
    if (which < 9) {
        headers[0].value.len = 0;
        ngx_str_set(&r.unparsed_uri, "/ab?q=1");
        source = NGX_HTTP_SHIELD_SOURCE_URI;
        expected_len = 7;
        expected_offset = 4;
        expected_skip = base | no_query;
        expected_calls = 2;
        if (which == 1) {
            ngx_str_set(&r.unparsed_uri, "/abc");
            expected_len = expected_offset = 4;
        } else if (which == 2) {
            ngx_str_set(&r.unparsed_uri, "?q=1");
            expected_len = 4;
            expected_offset = 1;
            expected_calls = 1;
        } else if (which == 3) {
            conf.skip |= no_query;
            expected_calls = 1;
        } else if (which == 4 || which == 5) {
            prebody_decision_call = which - 3;
            prebody_decision = NGX_OK;
            expected_rc = NGX_OK;
            expected_calls = prebody_decision_call;
        } else if (which == 6 || which == 7) {
            fail_nth = which == 6 ? 1 : 3;
            expected_calls = which == 6 ? 0 : 1;
            expected_rc = NGX_ERROR;
        } else if (which == 8) {
            test_main_conf = NULL;
            expected_calls = 0;
            expected_rc = NGX_ERROR;
        }
    } else {
        switch (which) {
        case 9:
            break;
        case 10:
            ngx_str_set(&headers[0].key, "uSeR-aGeNt");
            source = NGX_HTTP_SHIELD_SOURCE_USER_AGENT;
            expected_skip = base;
            break;
        case 11:
            ngx_str_set(&headers[0].key, "Referer");
            source = NGX_HTTP_SHIELD_SOURCE_REFERER;
            expected_skip = base | ((uint64_t) 1 << NGX_HTTP_SHIELD_CAT_SENSITIVE_FILE);
            break;
        case 12:
            ngx_str_set(&headers[0].key, "Content-Type");
            source = NGX_HTTP_SHIELD_SOURCE_CONTENT_TYPE;
            expected_skip = base | ~(generic
                | ((uint64_t) 1 << NGX_HTTP_SHIELD_CAT_JAVA_RCE)
                | ((uint64_t) 1 << NGX_HTTP_SHIELD_CAT_CRLF)
                | ((uint64_t) 1 << NGX_HTTP_SHIELD_CAT_NULLBYTE)
                | ((uint64_t) 1 << NGX_HTTP_SHIELD_CAT_OVERLONG));
            break;
        case 13:
        case 14:
        case 15:
            if (which == 13) {
                ngx_str_set(&headers[0].key, "Destination");
            } else if (which == 14) {
                ngx_str_set(&headers[0].key, "X-Original-URL");
            } else {
                ngx_str_set(&headers[0].key, "X-Rewrite-URL");
            }
            ngx_str_set(&headers[0].value, "/a?q");
            expected_offset = 3;
            expected_skip = base;
            break;
        case 16:
            ngx_str_set(&headers[0].key, "Destination");
            expected_skip = base;
            break;
        case 17:
            ngx_str_set(&headers[0].key, "Cookie");
            expected_skip = base | ~(generic
                | ((uint64_t) 1 << NGX_HTTP_SHIELD_CAT_SQLI)
                | ((uint64_t) 1 << NGX_HTTP_SHIELD_CAT_XSS)
                | ((uint64_t) 1 << NGX_HTTP_SHIELD_CAT_CMDI)
                | ((uint64_t) 1 << NGX_HTTP_SHIELD_CAT_LFI_RFI)
                | ((uint64_t) 1 << NGX_HTTP_SHIELD_CAT_CRLF)
                | ((uint64_t) 1 << NGX_HTTP_SHIELD_CAT_NULLBYTE)
                | ((uint64_t) 1 << NGX_HTTP_SHIELD_CAT_OVERLONG)
                | ((uint64_t) 1 << NGX_HTTP_SHIELD_CAT_PHP_RCE)
                | ((uint64_t) 1 << NGX_HTTP_SHIELD_CAT_JAVA_RCE)
                | ((uint64_t) 1 << NGX_HTTP_SHIELD_CAT_JAVA_EVAL)
                | ((uint64_t) 1 << NGX_HTTP_SHIELD_CAT_NOSQL)
                | ((uint64_t) 1 << NGX_HTTP_SHIELD_CAT_SSTI));
            break;
        case 18:
            /* Inactive and empty fields precede a duplicate named field in
             * the second list part, independent of parsed field pointers. */
            tail = headers[0];
            ngx_str_set(&tail.key, "User-Agent");
            headers[0].hash = 0;
            headers[1] = tail;
            headers[1].value.len = 0;
            next.elts = &tail;
            next.nelts = 1;
            r.headers_in.headers.part.nelts = 2;
            r.headers_in.headers.part.next = &next;
            source = NGX_HTTP_SHIELD_SOURCE_USER_AGENT;
            expected_skip = base;
            break;
        case 19:
            prebody_decision_call = 1;
            prebody_decision = expected_rc = NGX_OK;
            break;
        case 20:
            fail_nth = 2;
            expected_calls = 0;
            expected_rc = NGX_ERROR;
            break;
        }
    }
    prebody_record = 1;
    prebody_calls = 0;
    rc = ngx_http_shield_inspect_prebody(&r, &conf, &hit);
    assert(rc == expected_rc && "prebody scan decision propagates");
    assert(prebody_calls == expected_calls && "prebody scan call count");
    if (expected_calls) {
        assert(prebody_scans[0].len == expected_len);
        assert(prebody_scans[0].form_offset == expected_offset && "prebody form offset");
        assert(prebody_scans[0].skip == expected_skip && "prebody category mask");
        assert(ngx_strcmp(prebody_scans[0].source, source) == 0);
        assert(prebody_scans[0].data == (which < 9 ? r.unparsed_uri.data
                         : (which == 18 ? tail.value.data : headers[0].value.data)));
    }
    if (expected_calls == 2) {
        size_t path_len = which == 1 ? 4 : 3;
        assert(prebody_scans[1].data == r.unparsed_uri.data);
        assert(prebody_scans[1].len == path_len && "prebody path-only length");
        assert(prebody_scans[1].form_offset == path_len);
        assert(prebody_scans[1].skip == (base | ~no_query));
        assert(ngx_strcmp(prebody_scans[1].source, NGX_HTTP_SHIELD_SOURCE_URI) == 0);
    }
    assert(hit.rule == (expected_rc == NGX_OK ? UINT64_C(0x66)
                                             : observation_hit.rule));
    assert(hit.cat == observation_hit.cat && hit.category == observation_hit.category);
    assert(hit.source == observation_hit.source);
    assert(ngx_strcmp(hit.view, (expected_rc == NGX_OK
                    ? "synthetic-prebody-hit" : observation_hit.view)) == 0);
    assert(policy_calls == before && "prebody never calls body policy stub");
    if (expected_rc == NGX_ERROR) {
        assert(alloc_calls == (which == 7 ? 4 : 2));
    } else {
        assert(alloc_calls == (int) (2 * expected_calls));
    }
    prebody_record = 0;
    fail_alloc = 1;
    fail_nth = 0;
    test_main_conf = NULL;
}

/* Zero-length scan_r calls need no data, main configuration or allocations. */
static void test_prebody_empty_scan(void)
{
    ngx_http_request_t r;
    ngx_http_shield_hit_t hit = observation_hit;
    size_t before = policy_calls;

    ngx_memzero(&r, sizeof(r));
    test_main_conf = NULL;
    prebody_calls = 0;
    alloc_calls = 0;
    fail_alloc = 1;
    assert(ngx_http_shield_scan_r(&r, NULL, 0, NGX_HTTP_SHIELD_SOURCE_URI,
                                 0, 0, &hit) == NGX_DECLINED
           && "empty prebody scan declines without scratch");
    assert(alloc_calls == 0 && policy_calls == before && prebody_calls == 0);
    assert(hit.rule == observation_hit.rule && hit.cat == observation_hit.cat);
    assert(hit.category == observation_hit.category);
    assert(hit.source == observation_hit.source && hit.view == observation_hit.view);
}

int main(void)
{
    ngx_http_request_t r;
    void *loc_conf[1];
    ngx_http_request_body_t request_body;
    ngx_http_shield_loc_conf_t conf;
    ngx_http_shield_ban_ctx_t ctx;
    ngx_http_shield_ban_shctx_t shared;
    ngx_http_variable_value_t mark;
    ngx_http_shield_hit_t hit;
    ngx_shm_zone_t zone;
    ngx_buf_t buf;
    ngx_chain_t chain;
    ngx_file_t file;
    ngx_http_shield_main_conf_t main_conf;
    ngx_table_elt_t encoding;
    u_char data[] = "abcd";
    u_char tiny_gzip[] = {
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff,
        0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00, 0x86, 0xa6, 0x10,
        0x36, 0x05, 0x00, 0x00, 0x00
    };

    {
        ngx_uint_t which, control;
        for (which = 0; which < 4; which++) {
            for (control = 0; control < 3; control++) {
                test_prebody_structural(which, control);
            }
        }
        for (which = 0; which < 21; which++) {
            test_prebody_routes(which);
        }
    }
    test_prebody_empty_scan();
    test_body_cve_precedence(BODY_OBSERVATION_PROMOTED);
    test_body_cve_precedence(BODY_OBSERVATION_DECLINED);
    test_body_cve_precedence(BODY_OBSERVATION_CVE_ERROR);
    test_body_json_publication(1);
    test_body_json_publication(0);
    test_body_multipart_publication(1);
    test_body_multipart_publication(0);
    {
        ngx_uint_t control;
        for (control = 0; control < BODY_METADATA_CASES; control++) {
            test_body_metadata(control);
        }
    }
    test_query_publication(NGX_SHIELD_CVE_PHP, 0);
    test_query_publication(NGX_SHIELD_CVE_PHP, 1);
    test_query_publication(NGX_SHIELD_CVE_PHP, 2);
    test_query_publication(NGX_SHIELD_CVE_PHP, 3);
    test_query_publication(NGX_SHIELD_CVE_PHP, 4);
    test_query_publication(NGX_SHIELD_CVE_PHP, 5);
    test_query_publication(NGX_SHIELD_CVE_GEO, 0);
    test_query_publication(NGX_SHIELD_CVE_GEO, 1);
    test_query_publication(NGX_SHIELD_CVE_GEO, 2);
    test_query_publication(NGX_SHIELD_CVE_GEO, 3);
    test_query_publication(NGX_SHIELD_CVE_GEO, 4);
    test_query_publication(NGX_SHIELD_CVE_GEO, 5);
    test_header_publication(NGX_SHIELD_CVE_NEXT, 0);
    test_header_publication(NGX_SHIELD_CVE_NEXT, 1);
    test_header_publication(NGX_SHIELD_CVE_NEXT, 2);
    test_header_publication(NGX_SHIELD_CVE_NEXT, 3);
    test_header_publication(NGX_SHIELD_CVE_NEXT, 4);
    test_header_publication(NGX_SHIELD_CVE_TOMCAT, 0);
    test_header_publication(NGX_SHIELD_CVE_TOMCAT, 1);
    test_header_publication(NGX_SHIELD_CVE_TOMCAT, 2);
    test_header_publication(NGX_SHIELD_CVE_TOMCAT, 3);
    test_header_publication(NGX_SHIELD_CVE_TOMCAT, 4);
    test_header_publication(NGX_SHIELD_CVE_TOMCAT, 5);

    ngx_memzero(&r, sizeof(r));
    ngx_memzero(&request_body, sizeof(request_body));
    ngx_memzero(&conf, sizeof(conf));
    ngx_memzero(&ctx, sizeof(ctx));
    ngx_memzero(&shared, sizeof(shared));
    ngx_memzero(&mark, sizeof(mark));
    ngx_memzero(&zone, sizeof(zone));
    ngx_memzero(&buf, sizeof(buf));
    ngx_memzero(&file, sizeof(file));
    ngx_memzero(&main_conf, sizeof(main_conf));
    ngx_memzero(&encoding, sizeof(encoding));
    test_main_conf = &main_conf;
    loc_conf[0] = &conf;
    r.loc_conf = loc_conf;
    r.main = &r;
    r.variables = &mark;
    r.request_body = &request_body;
    r.headers_in.content_length_n = 4;
    r.headers_in.headers.part.elts = &encoding;
    r.headers_in.headers.part.nelts = 1;
    ngx_str_set(&encoding.key, "Content-Encoding");
    ngx_str_set(&encoding.value, "gzip");
    encoding.hash = 1;
    buf.memory = 1;
    buf.pos = data;
    buf.last = data + 4;
    chain.buf = &buf;
    chain.next = NULL;
    request_body.bufs = &chain;
    ctx.sh = &shared;
    zone.data = &ctx;
    conf.ban_zone = &zone;
    conf.max_body = 3;
    assert(ngx_http_shield_inspect_body(&r, &conf, &hit) == NGX_ERROR);
    assert(shared.body_uninspected[NGX_HTTP_SHIELD_BODY_ERROR] == 1);
    assert(shared.body_uninspected[NGX_HTTP_SHIELD_BODY_TOO_LARGE] == 0);
    assert(shared.body_uninspected[NGX_HTTP_SHIELD_BODY_ENCODING] == 0);
    assert(ngx_http_shield_inspect_body(&r, &conf, &hit) == NGX_ERROR);
    assert(shared.body_uninspected[NGX_HTTP_SHIELD_BODY_ERROR] == 1);

    /* File-read failure dominates both encoded and over-cap causes. */
    ngx_memzero(&mark, sizeof(mark));
    fail_alloc = 0;
    fail_read = 1;
    buf.memory = 0;
    buf.in_file = 1;
    buf.file = &file;
    buf.file_pos = 0;
    buf.file_last = 4;
    assert(ngx_http_shield_inspect_body(&r, &conf, &hit) == NGX_ERROR);
    assert(shared.body_uninspected[NGX_HTTP_SHIELD_BODY_ERROR] == 2);
    assert(shared.body_uninspected[NGX_HTTP_SHIELD_BODY_ENCODING] == 0);
    assert(shared.body_uninspected[NGX_HTTP_SHIELD_BODY_TOO_LARGE] == 0);

    /* Collection succeeds, then scanner scratch allocation fails. */
    ngx_memzero(&mark, sizeof(mark));
    fail_read = 0;
    alloc_calls = 0;
    fail_nth = 2;
    assert(ngx_http_shield_inspect_body(&r, &conf, &hit) == NGX_ERROR);
    assert(shared.body_uninspected[NGX_HTTP_SHIELD_BODY_ERROR] == 3);
    assert(shared.body_uninspected[NGX_HTTP_SHIELD_BODY_ENCODING] == 0);
    assert(shared.body_uninspected[NGX_HTTP_SHIELD_BODY_TOO_LARGE] == 0);
    alloc_calls = 0;
    assert(ngx_http_shield_inspect_body(&r, &conf, &hit) == NGX_ERROR);
    assert(shared.body_uninspected[NGX_HTTP_SHIELD_BODY_ERROR] == 3);
    fail_nth = 0;

    /* An empty cap is incomplete for a nonempty body, but not an empty one. */
    ngx_memzero(&mark, sizeof(mark));
    encoding.hash = 0;
    conf.max_body = 0;
    assert(ngx_http_shield_inspect_body(&r, &conf, &hit) == NGX_DECLINED);
    assert(shared.body_uninspected[NGX_HTTP_SHIELD_BODY_TOO_LARGE] == 1);
    ngx_memzero(&mark, sizeof(mark));
    buf.file_last = 0;
    assert(ngx_http_shield_inspect_body(&r, &conf, &hit) == NGX_DECLINED);
    assert(shared.body_uninspected[NGX_HTTP_SHIELD_BODY_TOO_LARGE] == 1);

    /* File-backed and unknown-length (chunked) bodies use actual buffer size. */
    conf.max_body = 4;
    fail_read = 0;
    r.headers_in.content_length_n = -1;
    buf.file_last = 4;
    assert(ngx_http_shield_inspect_body(&r, &conf, &hit) == NGX_DECLINED);
    assert(shared.body_uninspected[NGX_HTTP_SHIELD_BODY_TOO_LARGE] == 1);
    buf.file_last = 5;
    assert(ngx_http_shield_inspect_body(&r, &conf, &hit) == NGX_DECLINED);
    assert(shared.body_uninspected[NGX_HTTP_SHIELD_BODY_TOO_LARGE] == 2);

    /* Cap large-file spans before narrowing. Test SIZE_MAX/+1/+N where
     * off_t is wider, and 4-GiB boundaries on native 64-bit builds. */
    {
        off_t spans[3];
        ngx_str_t collected;
        size_t i;
        ngx_atomic_uint_t before;
        uint64_t boundary = sizeof(size_t) < sizeof(off_t)
                            ? (uint64_t) SIZE_MAX : UINT32_MAX;

        spans[0] = (off_t) boundary;
        spans[1] = (off_t) (boundary + 1);
        spans[2] = (off_t) (boundary + 7);
        conf.max_body = 8;
        for (i = 0; i < 3; i++) {
            ngx_memzero(&mark, sizeof(mark));
            buf.file_pos = 17;
            buf.file_last = buf.file_pos + spans[i];
            inspected_len = 0;
            before = shared.body_uninspected[NGX_HTTP_SHIELD_BODY_TOO_LARGE];
            assert(ngx_http_shield_inspect_body(&r, &conf, &hit)
                   == NGX_DECLINED);
            assert(inspected_len == conf.max_body);
            assert(shared.body_uninspected[NGX_HTTP_SHIELD_BODY_TOO_LARGE]
                   == before + 1);
            ngx_memzero(&mark, sizeof(mark));
            prefix_attack = 1;
            assert(ngx_http_shield_inspect_body(&r, &conf, &hit) == NGX_OK);
            assert(inspected_len == conf.max_body);
            prefix_attack = 0;
        }
        buf.file_pos = 17;
        buf.file_last = 16;
        assert(ngx_http_shield_collect_body(&r, 8, &collected) == NGX_ERROR);
        buf.file_pos = 0;
        buf.file_last = 5;
        conf.max_body = 4;
    }

    /* A missing zone or detached shared state must never count or crash. */
    ngx_memzero(&mark, sizeof(mark));
    fail_alloc = 1;
    conf.ban_zone = NULL;
    assert(ngx_http_shield_inspect_body(&r, &conf, &hit) == NGX_ERROR);
    conf.ban_zone = &zone;
    ctx.sh = NULL;
    assert(ngx_http_shield_inspect_body(&r, &conf, &hit) == NGX_ERROR);
    assert(shared.body_uninspected[NGX_HTTP_SHIELD_BODY_ERROR] == 3);
    /* Counters-only storage uses atomics and a separate redirect marker. */
    {
        ngx_http_shield_stats_shctx_t stats;
        ngx_http_shield_ban_ctx_t stats_ctx;
        ngx_shm_zone_t stats_zone;
        ngx_http_variable_value_t marks[2];
        ngx_atomic_uint_t maximum = (ngx_atomic_uint_t) -1;

        ngx_memzero(&stats, sizeof(stats));
        ngx_memzero(&stats_ctx, sizeof(stats_ctx));
        ngx_memzero(&stats_zone, sizeof(stats_zone));
        ngx_memzero(marks, sizeof(marks));
        stats_ctx.stats_only = 1;
        stats_ctx.stats = &stats;
        stats_ctx.request_index = 1;
        stats_zone.data = &stats_ctx;
        main_conf.stats_zone = &stats_zone;
        r.variables = marks;
        ctx.sh = &shared;
        conf.ban_zone = &zone;
        conf.max_body = 4;
        buf.in_file = 0;
        buf.memory = 1;
        buf.last = data + 4;
        fail_alloc = 1;
        assert(ngx_http_shield_inspect_body(&r, &conf, &hit) == NGX_ERROR);
        assert(stats.body_uninspected[NGX_HTTP_SHIELD_BODY_ERROR] == 1);
        assert(shared.body_uninspected[NGX_HTTP_SHIELD_BODY_ERROR] == 4);
        assert(ngx_http_shield_inspect_body(&r, &conf, &hit) == NGX_ERROR);
        assert(stats.body_uninspected[NGX_HTTP_SHIELD_BODY_ERROR] == 1);
        assert(shared.body_uninspected[NGX_HTTP_SHIELD_BODY_ERROR] == 4);
        fail_alloc = 0;
        conf.ban_zone = NULL;
        encoding.hash = 1;
        ngx_memzero(marks, sizeof(marks));
        assert(ngx_http_shield_inspect_body(&r, &conf, &hit) == NGX_DECLINED);
        assert(stats.body_uninspected[NGX_HTTP_SHIELD_BODY_ENCODING] == 1);
        encoding.hash = 0;
        conf.max_body = 3;
        ngx_memzero(marks, sizeof(marks));
        assert(ngx_http_shield_inspect_body(&r, &conf, &hit) == NGX_DECLINED);
        assert(stats.body_uninspected[NGX_HTTP_SHIELD_BODY_TOO_LARGE] == 1);
        ngx_memzero(marks, sizeof(marks));
        ngx_http_shield_count_request(&r, &stats_ctx, 0);
        ngx_http_shield_count_request(&r, &stats_ctx, 0);
        ngx_http_shield_count_request(&r, &stats_ctx, 1);
        ngx_http_shield_count_request(&r, &stats_ctx, 1);
        assert(stats.inspected == 1 && stats.ban_refused == 1);
        hit.cat = 0;
        hit.source = NGX_HTTP_SHIELD_SOURCE_BODY;
        ngx_http_shield_stats_hit(&stats_ctx, &hit, 0);
        ngx_http_shield_stats_hit(&stats_ctx, &hit, 1);
        assert(stats.cat_hits[0] == 2);
        assert(stats.cat_detect[0] == 1 && stats.cat_block[0] == 1);
        assert(stats.source_hits[0][6] == 2 && stats.blocked == 1);
        stats.cat_hits[0] = maximum;
        assert(ngx_http_shield_ban_counter_value(&stats.cat_hits[0])
               == (uint64_t) maximum);
        ngx_http_shield_stats_hit(&stats_ctx, &hit, 0);
        assert(stats.cat_hits[0] == 0); /* native width wrap */
        hit.cat = NGX_HTTP_SHIELD_BAN_NCOUNTERS;
        hit.source = NULL;
        ngx_http_shield_stats_hit(&stats_ctx, &hit, 1);
        assert(stats.blocked == 2 && stats.cat_hits[0] == 0);
        hit.cat = 0;
        hit.source = "unknown";
        ngx_http_shield_stats_hit(&stats_ctx, &hit, 0);
        assert(stats.source_hits[0][6] == 3);
    }
    /* Optional CVE scratch failure must stay an error, never a clean scan. */
    {
        ngx_str_t input = ngx_string("abcd");
        ngx_int_t result;

        conf.cve = NGX_SHIELD_CVE_CRAFT;
        conf.skip = 0;
        fail_alloc = 1;
        assert(ngx_http_shield_cve_scan(&r, &conf, &input, 1, &hit)
               == NGX_ERROR);
        fail_alloc = 0;
        assert(ngx_http_shield_cve_scan(&r, &conf, &input, 1, &hit)
               == NGX_DECLINED);
        conf.skip = (uint64_t) 1 << NGX_HTTP_SHIELD_CAT_DESERIAL;
        alloc_calls = 0;
        assert(ngx_http_shield_cve_scan(&r, &conf, &input, 1, &hit)
               == NGX_DECLINED);
        assert(alloc_calls == 0);
        result = ngx_http_shield_cve_hit(NGX_HTTP_SHIELD_CAT_DESERIAL,
                     conf.skip, NGX_HTTP_SHIELD_SOURCE_BODY,
                     "craft", "policy-body", &hit);
        assert(result == NGX_DECLINED);
        result = ngx_http_shield_cve_hit(NGX_HTTP_SHIELD_CAT_DESERIAL,
                     0, NGX_HTTP_SHIELD_SOURCE_BODY,
                     "craft", "policy-body", &hit);
        assert(result == NGX_OK);
        assert(hit.rule == UINT64_C(0x123456789abcdef0));
        assert(hit.cat == NGX_HTTP_SHIELD_CAT_DESERIAL);
        assert(ngx_strcmp(hit.view, "policy-body") == 0);
        assert(ngx_strcmp(hit.source, NGX_HTTP_SHIELD_SOURCE_BODY) == 0);
        assert(ngx_http_shield_cve_hit(NGX_HTTP_SHIELD_CAT_N, 0,
                   NGX_HTTP_SHIELD_SOURCE_BODY, "craft", "policy-body", &hit)
               == NGX_DECLINED);
    }
    /* Duplicate metadata must not multiply whole-body decoding/matching. */
    {
        ngx_table_elt_t types[64];
        ngx_str_t input = ngx_string("\"abcdefghijklmnopqrstuvwxyz\"");
        size_t once;
        ngx_uint_t n;

        ngx_memzero(types, sizeof(types));
        for (n = 0; n < 64; n++) {
            ngx_str_set(&types[n].key, "Content-Type");
            ngx_str_set(&types[n].value, "application/json");
            types[n].hash = 1;
        }
        r.headers_in.headers.part.elts = types;
        r.headers_in.headers.part.nelts = 1;
        r.headers_in.headers.part.next = NULL;
        conf.cve = NGX_SHIELD_CVE_JSON;
        conf.skip = 0;
        fail_alloc = 0;
        cve_compares = 0;
        assert(ngx_http_shield_cve_scan(&r, &conf, &input, 1, &hit)
               == NGX_DECLINED);
        once = cve_compares;
        assert(once > 0);
        r.headers_in.headers.part.nelts = 64;
        cve_compares = 0;
        assert(ngx_http_shield_cve_scan(&r, &conf, &input, 1, &hit)
               == NGX_DECLINED);
        assert(cve_compares == once);
    }
    /* Decoder allocation failures preserve the existing inspection error path. */
    r.variables = &mark;
    main_conf.stats_zone = NULL;
    conf.ban_zone = NULL;
    conf.gzip = 1;
    conf.max_encoded_body = 4;
    conf.max_body = 4;
    r.headers_in.headers.part.elts = &encoding;
    r.headers_in.headers.part.nelts = 1;
    encoding.hash = 1;
    ngx_str_set(&encoding.value, "gzip");
    request_body.bufs = &chain;
    r.request_body = &request_body;
    buf.memory = 1;
    buf.pos = data;
    buf.last = data + sizeof(data) - 1;
    fail_alloc = 0;
    alloc_calls = 0;
    fail_nth = 2;
    fail_arena = 0;
    arena_calls = 0;
    assert(ngx_http_shield_inspect_body(&r, &conf, &hit) == NGX_ERROR);
    assert(alloc_calls == 2 && arena_calls == 1); /* decoded buffer alone */
    fail_nth = 0;
    fail_arena = 1;
    alloc_calls = 0;
    arena_calls = 0;
    assert(ngx_http_shield_inspect_body(&r, &conf, &hit) == NGX_ERROR);
    assert(alloc_calls == 2 && arena_calls == 1); /* arena alone */

    /* A large configured output budget allocates only the bounded prefix for
     * a tiny complete member. Reaching that prefix is what triggers a full
     * retry, so this request must not reserve the 16 MiB operator ceiling. */
    fail_arena = 0;
    alloc_calls = 0;
    arena_calls = 0;
    ngx_memzero(alloc_sizes, sizeof(alloc_sizes));
    conf.cve = 0;
    conf.skip = 0;
    conf.max_encoded_body = sizeof(tiny_gzip);
    conf.max_body = NGX_SHIELD_GZIP_MAX;
    r.headers_in.content_length_n = sizeof(tiny_gzip);
    buf.pos = tiny_gzip;
    buf.last = tiny_gzip + sizeof(tiny_gzip);
    assert(ngx_http_shield_inspect_body(&r, &conf, &hit) == NGX_DECLINED);
    assert(alloc_calls == 4 && arena_calls == 1);
    assert(alloc_sizes[0] == sizeof(tiny_gzip));
    assert(alloc_sizes[1] == NGX_SHIELD_GZIP_INITIAL_OUTPUT + 1);
    assert(alloc_sizes[2] == 5 && alloc_sizes[3] == 5);
    /* Both policy settings must come from this request's location. */
    {
        size_t before = policy_calls;

        conf.body_strict = 0;
        assert(ngx_http_shield_scan_r(&r, data, 4,
                   NGX_HTTP_SHIELD_SOURCE_BODY, 4, 0, &hit) == NGX_DECLINED);
        assert(policy_calls == before + 1 && inspected_strict == 0);
        conf.body_strict = 1;
        assert(ngx_http_shield_scan_r(&r, data, 4,
                   NGX_HTTP_SHIELD_SOURCE_BODY, 4, 0, &hit) == NGX_DECLINED);
        assert(policy_calls == before + 2 && inspected_strict == 1);
    }
    puts("body_unit: errors, boundaries, policy plumbing and accounting passed");
    return 0;
}
