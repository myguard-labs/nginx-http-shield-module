/* Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 * Direct body collection failure and per-zone accounting checks. */
#undef NDEBUG
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <assert.h>

static void *test_main_conf;
#undef ngx_http_get_module_main_conf
#define ngx_http_get_module_main_conf(r, module) test_main_conf
#include "../../src/ngx_http_shield_module.c"

static int fail_alloc = 1;
static int fail_read;
static int fail_nth;
static int alloc_calls;
static u_char storage[32];

void *ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    (void) pool;
    assert(size <= sizeof(storage));
    alloc_calls++;
    return fail_alloc || alloc_calls == fail_nth ? NULL : storage;
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
    puts("body_unit: errors, boundaries and once-per-zone accounting passed");
    return 0;
}
