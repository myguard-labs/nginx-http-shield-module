/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Direct-call renderer checks using nginx's real formatter. The request pool
 * allocator is replaced so allocation failure and size guards are deterministic.
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <assert.h>

static void *status_alloc(ngx_pool_t *pool, size_t size);
static size_t status_strlen(const void *s);

#undef ngx_strlen
#define ngx_strlen(s) status_strlen(s)
#define ngx_pnalloc status_alloc
#include "../../src/ngx_http_shield_status.h"
#undef ngx_pnalloc

static int fail_alloc;
static int huge_category;
static unsigned allocations;
static void *allocation;

static size_t
status_strlen(const void *s)
{
    return huge_category ? NGX_MAX_SIZE_T_VALUE : strlen(s);
}

static void *
status_alloc(ngx_pool_t *pool, size_t size)
{
    (void) pool;
    allocations++;
    if (fail_alloc) {
        return NULL;
    }
    allocation = malloc(size);
    return allocation;
}

int
main(void)
{
    ngx_str_t zone = ngx_string("quote\"slash\\line\n");
    ngx_str_t body;
    uint64_t hits[NGX_HTTP_SHIELD_CAT_N] = { 0 };
    char *text;
    size_t limit;

    assert(strcmp(ngx_http_shield_cat_name(NGX_HTTP_SHIELD_CAT_N),
                  "unknown") == 0);
    hits[0] = UINT64_MAX;
    assert(ngx_http_shield_status_prometheus(NULL, &zone, hits,
               UINT64_MAX, UINT64_MAX, 1, 1, &body) == NGX_OK);
    assert(allocations == 1);
    text = malloc(body.len + 1);
    assert(text != NULL);
    memcpy(text, body.data, body.len);
    text[body.len] = '\0';
    assert(strstr(text, "zone=\"quote\\\"slash\\\\line\\n\"") != NULL);
    assert(strstr(text, "category=\"sqli\"} 18446744073709551615\n") != NULL);
    assert(strstr(text, "category=\"dotfile\"} 0\n") != NULL);
    assert(strstr(text, "\"} 18446744073709551615\n# HELP shield_bans") != NULL);
    assert(strstr(text, "\"} 18446744073709551615\n# HELP shield_zone_nodes") != NULL);
    assert(body.len >= 6 && memcmp(text + body.len - 6, "# EOF\n", 6) == 0);
    free(text);
    free(allocation);

    fail_alloc = 1;
    assert(ngx_http_shield_status_prometheus(NULL, &zone, hits,
               0, 0, 0, 0, &body) == NGX_ERROR);
    assert(allocations == 2);
    fail_alloc = 0;

    /* A large admissible size reaches the allocator; overflow is rejected. */
    limit = ((NGX_MAX_SIZE_T_VALUE - 2048)
                / (NGX_HTTP_SHIELD_CAT_N + 5) - 128) / 2;
    zone.len = limit - 1024;
    fail_alloc = 1;
    assert(ngx_http_shield_status_prometheus(NULL, &zone, hits,
               0, 0, 0, 0, &body) == NGX_ERROR);
    assert(allocations == 3);
    fail_alloc = 0;
    zone.len = limit + 1;
    assert(ngx_http_shield_status_prometheus(NULL, &zone, hits,
               0, 0, 0, 0, &body) == NGX_ERROR);
    assert(allocations == 3); /* size rejected before reading/allocating */

    zone.len = 0;
    huge_category = 1;
    assert(ngx_http_shield_status_prometheus(NULL, &zone, hits,
               0, 0, 0, 0, &body) == NGX_ERROR);
    assert(allocations == 3);
    huge_category = 0;

    assert(ngx_http_shield_status_prometheus(NULL, &zone, hits,
               0, 0, 0, 0, &body) == NGX_OK);
    assert(allocations == 4);
    assert(memcmp(body.data, "# HELP shield_hits ", 19) == 0);
    free(allocation);
    puts("status_unit: maximum counters, escaping, empty label and error paths passed");
    return 0;
}
