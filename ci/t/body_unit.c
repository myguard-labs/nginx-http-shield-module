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
#include "../../src/ngx_http_shield_module.c"

static int fail_alloc = 1;
static int fail_read;
static int fail_nth;
static int alloc_calls;
static int fail_arena = 1;
static int arena_calls;
static union {
    ngx_shield_gzip_align_t align;
    u_char bytes[NGX_SHIELD_GZIP_ARENA];
} arena_storage;
static u_char storage[32];

void *ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    (void) pool;
    assert(size <= sizeof(storage));
    alloc_calls++;
    return fail_alloc || alloc_calls == fail_nth ? NULL : storage;
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
    return (ssize_t) size;
}

ngx_int_t ngx_http_shield_scan_input(const ngx_http_shield_automata_t *automata,
    u_char *data, size_t len, u_char *lc, u_char *dec, const char *source,
    uint64_t skip, ngx_http_shield_hit_t *hit)
{
    (void) automata; (void) data; (void) len; (void) lc; (void) dec;
    (void) source; (void) skip; (void) hit;
    return NGX_DECLINED;
}

int main(void)
{
    ngx_http_request_t r;
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
                     conf.skip, NGX_HTTP_SHIELD_SOURCE_BODY, &hit);
        assert(result == NGX_DECLINED);
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
    puts("body_unit: errors, boundaries and once-per-zone accounting passed");
    return 0;
}
