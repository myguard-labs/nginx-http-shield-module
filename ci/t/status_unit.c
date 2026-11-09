/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Direct-call renderer checks using nginx's real formatter. The request pool
 * allocator is replaced so allocation failure and size guards are deterministic.
 */
#undef NDEBUG
#include <ngx_config.h>
#include <ngx_core.h>
#include <assert.h>

static void *status_alloc(ngx_pool_t *pool, size_t size);
static void *status_aligned_alloc(ngx_pool_t *pool, size_t size);
static size_t status_strlen(const void *s);
static size_t status_inet_ntop(int family, u_char *addr, u_char *text,
    size_t len);

#undef ngx_strlen
#define ngx_strlen(s) status_strlen(s)
#define ngx_palloc status_aligned_alloc
#define ngx_pnalloc status_alloc
#define ngx_inet_ntop status_inet_ntop
#include "../../src/ngx_http_shield_status.h"
#undef ngx_inet_ntop
#undef ngx_pnalloc
#undef ngx_palloc

static int fail_alloc;
static int huge_category;
static unsigned allocations;
static unsigned aligned_allocations;
static void *allocation;
static size_t allocation_size;

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
    allocation_size = size;
    return allocation;
}

static void *
status_aligned_alloc(ngx_pool_t *pool, size_t size)
{
    aligned_allocations++;
    return status_alloc(pool, size);
}

static size_t
status_inet_ntop(int family, u_char *addr, u_char *text, size_t len)
{
    const char  *value;
    size_t       size;

    if (family == AF_INET && addr[0] == 127) {
        value = "127.0.0.1";
    } else if (family == AF_INET) {
        value = "203.0.113.9";
    } else {
        value = "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255";
    }

    size = strlen(value);
    if (len < size) {
        return 0;
    }
    memcpy(text, value, size);
    return size;
}

int
main(void)
{
    ngx_str_t zone = ngx_string("quote\"slash\\line\n");
    ngx_str_t body;
    uint64_t hits[NGX_HTTP_SHIELD_CAT_N] = { 0 };
    ngx_http_shield_ban_node_t source, source6;
    ngx_http_shield_status_ban_t copied;
    ngx_http_shield_status_snapshot_t snapshot;
    char *text;
    void *entries_allocation;
    size_t limit;
    unsigned aligned_before;
    ngx_uint_t i, physical, retry;

    assert(strcmp(ngx_http_shield_cat_name(NGX_HTTP_SHIELD_CAT_N),
                  "unknown") == 0);
    hits[0] = UINT64_MAX;
    assert(ngx_http_shield_status_prometheus(NULL, &zone, hits,
               UINT64_MAX, UINT64_MAX, 1, 1, &body) == NGX_OK);
    assert(allocations == 1);
    assert(aligned_allocations == 0); /* byte output remains unaligned */
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

    /* The JSON renderer consumes an owned copy, not the shared source node. */
    ngx_memzero(&source, sizeof(source));
    ngx_memzero(&snapshot, sizeof(snapshot));
    zone.data = (u_char *) "quote\"slash\\line\n";
    zone.len = strlen((char *) zone.data);
    source.len = 4;
    source.addr[0] = 127;
    source.hits = (ngx_uint_t) -1;
    source.banned_until = 20;

    aligned_before = aligned_allocations;
    assert(ngx_http_shield_status_snapshot_alloc(NULL, 1, &snapshot)
           == NGX_OK);
    assert(aligned_allocations == aligned_before + 1);
    entries_allocation = allocation;
    ngx_memzero(snapshot.entries, sizeof(ngx_http_shield_status_ban_t));
    assert(ngx_http_shield_status_snapshot_ban(snapshot.entries, &source, 10)
           == NGX_OK);
    snapshot.nodes = 1;
    snapshot.banned = 1;
    snapshot.blocked = UINT64_MAX;
    snapshot.bans = UINT64_MAX;
    snapshot.cat_hits[0] = UINT64_MAX;

    memset(source.addr, 0, sizeof(source.addr));
    source.hits = 0;
    source.banned_until = 0;

    assert(ngx_http_shield_status_json(NULL, &zone, &snapshot, &body)
           == NGX_OK);
    assert(aligned_allocations == aligned_before + 1);
    assert(body.len < allocation_size); /* spare byte proves no truncation */
    text = malloc(body.len + 1);
    assert(text != NULL);
    memcpy(text, body.data, body.len);
    text[body.len] = '\0';
    assert(strstr(text, "\"zone\":\"quote\\\"slash\\\\line\\n\"")
           != NULL);
    assert(strstr(text, "\"blocked\":18446744073709551615") != NULL);
    assert(strstr(text, "\"sqli\":18446744073709551615") != NULL);
    assert(strstr(text, "\"addr\":\"127.0.0.1\"") != NULL);
    assert(strstr(text, "\"hits\":18446744073709551615") != NULL);
    assert(strstr(text, "\"expires\":10") != NULL);
    assert(body.len >= 2 && memcmp(text + body.len - 2, "]}", 2) == 0);
    free(text);
    free(allocation);
    free(entries_allocation);

    /* Saturate every formatter width so an undersized entry reservation has
     * no unrelated numeric slack in which to hide. */
    ngx_memzero(&source6, sizeof(source6));
    ngx_memzero(&snapshot, sizeof(snapshot));
    source6.len = 16;
    memset(source6.addr, 0xff, sizeof(source6.addr));
    source6.hits = (ngx_uint_t) -1;
    source6.banned_until = NGX_MAX_TIME_T_VALUE;
    assert(ngx_http_shield_status_snapshot_alloc(NULL, 1, &snapshot)
           == NGX_OK);
    entries_allocation = allocation;
    assert(ngx_http_shield_status_snapshot_ban(snapshot.entries,
                                               &source6, 0)
           == NGX_OK);
    snapshot.nodes = (ngx_uint_t) -1;
    snapshot.banned = 1;
    snapshot.blocked = UINT64_MAX;
    snapshot.bans = UINT64_MAX;
    for (i = 0; i < NGX_HTTP_SHIELD_CAT_N; i++) {
        snapshot.cat_hits[i] = UINT64_MAX;
    }
    zone.len = 0;
    assert(ngx_http_shield_status_json(NULL, &zone, &snapshot, &body)
           == NGX_OK);
    assert(body.len < allocation_size);
    text = malloc(body.len + 1);
    assert(text != NULL);
    memcpy(text, body.data, body.len);
    text[body.len] = '\0';
    assert(strstr(text,
                  "\"addr\":\"ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255\"")
           != NULL);
    assert(strstr(text, "\"expires\":") != NULL);
    assert(body.len >= 2 && memcmp(text + body.len - 2, "]}", 2) == 0);
    free(text);
    free(allocation);
    free(entries_allocation);

    source.len = 4;
    source.banned_until = 10;
    assert(ngx_http_shield_status_snapshot_ban(&copied, &source, 10)
           == NGX_DECLINED);
    source.len = 5;
    source.banned_until = 11;
    assert(ngx_http_shield_status_snapshot_ban(&copied, &source, 10)
           == NGX_ERROR);

    fail_alloc = 1;
    assert(ngx_http_shield_status_snapshot_alloc(NULL, 1, &snapshot)
           == NGX_ERROR);
    fail_alloc = 0;
    assert(ngx_http_shield_status_snapshot_alloc(NULL,
               (ngx_uint_t) (NGX_MAX_SIZE_T_VALUE
                   / sizeof(ngx_http_shield_status_ban_t)) + 1,
               &snapshot) == NGX_ERROR);

    /* Retry capacity follows the observed active set, not the whole zone. */
    physical = (ngx_uint_t) -1;
    assert(ngx_http_shield_status_retry_capacity(1, 4096, &retry) == NGX_OK);
    assert(retry == 2);
    assert(ngx_http_shield_status_retry_capacity(256, physical, &retry)
           == NGX_OK);
    assert(retry == 320); /* proportional headroom is bounded at 64 */
    assert(ngx_http_shield_status_retry_capacity(physical - 1, physical,
                                                 &retry) == NGX_OK);
    assert(retry == physical);
    assert(ngx_http_shield_status_retry_capacity(physical, physical, &retry)
           == NGX_OK);
    assert(retry == physical);
    assert(ngx_http_shield_status_retry_capacity(1, 1, &retry) == NGX_OK);
    assert(retry == 1);
    assert(ngx_http_shield_status_retry_capacity(0, physical, &retry)
           == NGX_ERROR);
    assert(ngx_http_shield_status_retry_capacity(2, 1, &retry) == NGX_ERROR);

    ngx_memzero(&snapshot, sizeof(snapshot));
    fail_alloc = 1;
    assert(ngx_http_shield_status_json(NULL, &zone, &snapshot, &body)
           == NGX_ERROR);
    fail_alloc = 0;

    zone.len = NGX_MAX_SIZE_T_VALUE;
    assert(ngx_http_shield_status_json(NULL, &zone, &snapshot, &body)
           == NGX_ERROR);
    zone.len = 0;
    snapshot.banned = 1;
    assert(ngx_http_shield_status_json(NULL, &zone, &snapshot, &body)
           == NGX_ERROR);
    snapshot.capacity = (ngx_uint_t) -1;
    snapshot.banned = (ngx_uint_t) -1;
    snapshot.entries = (ngx_http_shield_status_ban_t *) &source;
    assert(ngx_http_shield_status_json(NULL, &zone, &snapshot, &body)
           == NGX_ERROR);

    puts("status_unit: JSON/OpenMetrics bounds, ownership, escaping and error paths passed");
    return 0;
}
