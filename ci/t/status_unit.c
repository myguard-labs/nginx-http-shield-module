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
#include <inttypes.h>

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

ngx_uint_t ngx_pagesize = 4096;

static uint64_t extra_value;

static ngx_int_t
render_metrics(ngx_pool_t *pool, ngx_str_t *zone, uint64_t *hits,
    uint64_t blocked, uint64_t bans, ngx_uint_t nodes, ngx_uint_t banned,
    ngx_str_t *body)
{
    ngx_http_shield_status_snapshot_t snapshot;

    ngx_memzero(&snapshot, sizeof(snapshot));
    ngx_memcpy(snapshot.cat_hits, hits,
               NGX_HTTP_SHIELD_CAT_N * sizeof(uint64_t));
    ngx_memcpy(snapshot.cat_detect, hits,
               NGX_HTTP_SHIELD_CAT_N * sizeof(uint64_t));
    ngx_memcpy(snapshot.cat_block, hits,
               NGX_HTTP_SHIELD_CAT_N * sizeof(uint64_t));
    for (ngx_uint_t i = 0; i < NGX_HTTP_SHIELD_CAT_N; i++) {
        for (ngx_uint_t j = 0; j < NGX_HTTP_SHIELD_SOURCE_COUNT; j++) {
            snapshot.source_hits[i][j] = hits[i];
        }
    }
    snapshot.blocked = blocked;
    snapshot.bans = bans;
    snapshot.nodes = nodes;
    snapshot.banned = banned;
    snapshot.inspected = snapshot.ban_refused = extra_value;
    snapshot.evictions = snapshot.alloc_failures = extra_value;
    snapshot.used = snapshot.size = extra_value;
    for (ngx_uint_t i = 0; i < NGX_HTTP_SHIELD_BODY_REASONS; i++) {
        snapshot.body_uninspected[i] = extra_value;
    }
    return ngx_http_shield_status_prometheus(pool, zone, &snapshot, body, 1);
}

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

/* Independent ordered wire oracle: catches missing, reordered or renamed families. */
static void
check_golden(ngx_str_t *body, int prometheus, int maximum)
{
    static const char *cats[] = {
        "sqli", "xss", "traversal", "overlong", "cmdi", "lfi", "crlf",
        "nullbyte", "template", "deserial", "shellshock", "php_rce",
        "java_rce", "java_eval", "rails_yaml", "drupal", "vbulletin",
        "xmlrpc", "ssi", "imagetragick", "httpoxy", "range_dos",
        "sensitive_file", "webshell", "ssrf_meta", "nosql", "ssti",
        "exploit_path", "ctrl_char", "dotfile"
    };
    char expected[65536];
    size_t used = 0, i;
    int n;
#define APPEND(...) do { \
    n = snprintf(expected + used, sizeof(expected) - used, __VA_ARGS__); \
    assert(n >= 0 && (size_t) n < sizeof(expected) - used); \
    used += (size_t) n; \
} while (0)
    if (prometheus) {
        APPEND("# HELP shield_hits Shield signature hits by category.\n"
               "# TYPE shield_hits counter\n");
        for (i = 0; i < sizeof(cats) / sizeof(cats[0]); i++) {
            APPEND("shield_hits_total{zone=\"quote\\\"slash\\\\line\\n\",category=\"%s\"} %s\n",
                   cats[i], maximum ? "18446744073709551615" : "0");
        }
        APPEND("# HELP shield_blocked Shield requests blocked.\n"
               "# TYPE shield_blocked counter\n"
               "shield_blocked_total{zone=\"quote\\\"slash\\\\line\\n\"} %s\n"
               "# HELP shield_bans Shield bans armed.\n"
               "# TYPE shield_bans counter\n"
               "shield_bans_total{zone=\"quote\\\"slash\\\\line\\n\"} %s\n"
               "# HELP shield_zone_nodes Shield zone nodes in use.\n"
               "# TYPE shield_zone_nodes gauge\n"
               "shield_zone_nodes{zone=\"quote\\\"slash\\\\line\\n\"} %" PRIuPTR "\n"
               "# HELP shield_banned_clients Shield clients currently banned.\n"
               "# TYPE shield_banned_clients gauge\n"
               "shield_banned_clients{zone=\"quote\\\"slash\\\\line\\n\"} %" PRIuPTR "\n",
               maximum ? "18446744073709551615" : "0",
               maximum ? "18446744073709551615" : "0",
               maximum ? UINTPTR_MAX : (uintptr_t) 0,
               maximum ? UINTPTR_MAX : (uintptr_t) 0);
        {
            static const char *families[] = {
                "shield_requests", "shield_ban_refusals", "shield_zone_evictions",
                "shield_zone_alloc_failures", "shield_zone_used_bytes",
                "shield_zone_size_bytes"
            };
            static const char *help[] = {
                "Shield requests inspected.",
                "Shield requests refused by an active ban.",
                "Shield zone nodes evicted.",
                "Shield zone node allocation failures.",
                "Shield zone bytes reserved including slab overhead.",
                "Shield zone size in bytes."
            };
            for (i = 0; i < 6; i++) {
                APPEND("# HELP %s %s\n# TYPE %s %s\n"
                       "%s%s{zone=\"quote\\\"slash\\\\line\\n\"} %s\n",
                       families[i], help[i], families[i],
                       i < 4 ? "counter" : "gauge", families[i],
                       i < 4 ? "_total" : "",
                       maximum ? "18446744073709551615" : "0");
            }
        APPEND("# HELP shield_detections Shield detections by category and mode.\n"
               "# TYPE shield_detections counter\n");
        for (i = 0; i < sizeof(cats) / sizeof(cats[0]); i++) {
            APPEND("shield_detections_total{zone=\"quote\\\"slash\\\\line\\n\",category=\"%s\",mode=\"detect\"} %s\n",
                   cats[i], maximum ? "18446744073709551615" : "0");
            APPEND("shield_detections_total{zone=\"quote\\\"slash\\\\line\\n\",category=\"%s\",mode=\"block\"} %s\n",
                   cats[i], maximum ? "18446744073709551615" : "0");
        }
            APPEND("# HELP shield_source_hits Shield signature hits by category and source.\n"
                   "# TYPE shield_source_hits counter\n");
            {
                static const char *sources[] = {
                    "uri", "header", "range", "user-agent", "referer",
                    "content-type", "body"
                };
                size_t j;
                for (i = 0; i < sizeof(cats) / sizeof(cats[0]); i++) {
                    for (j = 0; j < sizeof(sources) / sizeof(sources[0]); j++) {
                        APPEND("shield_source_hits_total{zone=\"quote\\\"slash\\\\line\\n\",category=\"%s\",source=\"%s\"} %s\n",
                               cats[i], sources[j],
                               maximum ? "18446744073709551615" : "0");
                    }
                }
            }
            APPEND("# HELP shield_body_uninspected Shield bodies with incomplete inspection by reason.\n"
                   "# TYPE shield_body_uninspected counter\n");
            {
                static const char *reasons[] = { "too_large", "encoding", "error" };
                for (i = 0; i < 3; i++) {
                    APPEND("shield_body_uninspected_total{zone=\"quote\\\"slash\\\\line\\n\",reason=\"%s\"} %s\n",
                           reasons[i], maximum ? "18446744073709551615" : "0");
                }
            }
            APPEND("# EOF\n");
        }
    } else {
        APPEND("{\"zone\":\"quote\\\"slash\\\\line\\n\",\"nodes\":%" PRIuPTR
               ",\"blocked\":%s,\"bans\":%s" ,
               maximum ? UINTPTR_MAX : (uintptr_t) 0,
               maximum ? "18446744073709551615" : "0",
               maximum ? "18446744073709551615" : "0");
        {
            static const char *keys[] = {
                "inspected", "ban_refused", "evictions", "alloc_failures", "used", "size"
            };
            for (i = 0; i < 6; i++) {
                APPEND(",\"%s\":%s", keys[i],
                       maximum ? "18446744073709551615" : "0");
            }
            APPEND(",\"body_uninspected\":{\"too_large\":%s,\"encoding\":%s,\"error\":%s}",
                   maximum ? "18446744073709551615" : "0",
                   maximum ? "18446744073709551615" : "0",
                   maximum ? "18446744073709551615" : "0");
            APPEND(",\"categories\":{");
        }
        for (i = 0; i < sizeof(cats) / sizeof(cats[0]); i++) {
            APPEND("%s\"%s\":%s", i ? "," : "", cats[i],
                   maximum ? "18446744073709551615" : "0");
        }
        APPEND("},\"detections\":{");
        for (i = 0; i < sizeof(cats) / sizeof(cats[0]); i++) {
            APPEND("%s\"%s\":{\"detect\":%s,\"block\":%s}",
                   i ? "," : "", cats[i],
                   maximum ? "18446744073709551615" : "0",
                   maximum ? "18446744073709551615" : "0");
        }
        APPEND("},\"banned\":[]}");
    }
#undef APPEND
    if (prometheus == 2) {
        static const char *counters[] = {
            "shield_hits", "shield_blocked", "shield_bans", "shield_requests",
            "shield_ban_refusals", "shield_zone_evictions",
            "shield_zone_alloc_failures", "shield_detections",
            "shield_source_hits", "shield_body_uninspected"
        };
        char projected[65536], *line, *next, *name_end;
        size_t offset, length, prefix, j;

        /* Project the independent literal OM golden, never the production
         * descriptor table, to 0.0.4 metadata and framing. */
        offset = 0;
        for (line = expected; *line; line = next + 1) {
            next = strchr(line, '\n');
            assert(next != NULL);
            if (strncmp(line, "# EOF\n", 6) == 0) { break; }
            length = (size_t) (next + 1 - line);
            prefix = strncmp(line, "# HELP ", 7) == 0 ? 7
                     : strncmp(line, "# TYPE ", 7) == 0 ? 7 : 0;
            name_end = prefix ? strchr(line + prefix, ' ') : NULL;
            for (j = 0; name_end != NULL
                        && j < sizeof(counters) / sizeof(counters[0]); j++)
            {
                if ((size_t) (name_end - line) == prefix + strlen(counters[j])
                    && memcmp(line + prefix, counters[j],
                              strlen(counters[j])) == 0)
                {
                    size_t before = (size_t) (name_end - line);
                    assert(offset + length + 6 < sizeof(projected));
                    memcpy(projected + offset, line, before);
                    memcpy(projected + offset + before, "_total", 6);
                    offset += before + 6;
                    line = name_end;
                    length -= before;
                    break;
                }
            }
            assert(offset + length < sizeof(projected));
            memcpy(projected + offset, line, length);
            offset += length;
        }
        memcpy(expected, projected, offset);
        used = offset;
    }
    assert(body->len == used);
    assert(memcmp(body->data, expected, used) == 0);
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
    char expected_hits[64];
    char *text;
    int expected_len;
    void *entries_allocation;
    size_t limit;
    unsigned aligned_before;
    ngx_uint_t i, physical, retry;

    /* Synthetic owned slab: whole-free pages only; partial pages and metadata
     * remain reserved, and impossible free-page arithmetic is rejected. */
    {
        union {
            ngx_slab_pool_t pool;
            u_char bytes[16384];
        } slab;
        ngx_memzero(&slab, sizeof(slab));
        slab.pool.end = slab.bytes + sizeof(slab.bytes);
        slab.pool.pfree = 2;
        assert(ngx_http_shield_status_slab_usage(&slab.pool, &snapshot) == NGX_OK);
        assert(snapshot.size == 16384 && snapshot.used == 8192);
        slab.pool.pfree = 0;
        assert(ngx_http_shield_status_slab_usage(&slab.pool, &snapshot) == NGX_OK);
        assert(snapshot.used == snapshot.size);
        slab.pool.pfree = 5;
        assert(ngx_http_shield_status_slab_usage(&slab.pool, &snapshot) == NGX_ERROR);
    }

    /* Distinct values make swapped descriptor offsets observable. */
    ngx_memzero(&snapshot, sizeof(snapshot));
    snapshot.inspected = 11;
    snapshot.ban_refused = 22;
    snapshot.evictions = 33;
    snapshot.alloc_failures = 44;
    snapshot.used = 55;
    snapshot.size = 66;
    snapshot.body_uninspected[0] = 77;
    snapshot.body_uninspected[1] = 88;
    snapshot.body_uninspected[2] = 99;
    assert(ngx_http_shield_status_json(NULL, &zone, &snapshot, &body) == NGX_OK);
    text = malloc(body.len + 1);
    assert(text != NULL);
    memcpy(text, body.data, body.len);
    text[body.len] = '\0';
    assert(strstr(text, "\"inspected\":11,\"ban_refused\":22,"
                        "\"evictions\":33,\"alloc_failures\":44,"
                        "\"used\":55,\"size\":66") != NULL);
    assert(strstr(text, "\"body_uninspected\":{\"too_large\":77,"
                        "\"encoding\":88,\"error\":99}") != NULL);
    free(text);
    free(allocation);
    assert(ngx_http_shield_status_prometheus(NULL, &zone, &snapshot, &body, 1) == NGX_OK);
    text = malloc(body.len + 1);
    assert(text != NULL);
    memcpy(text, body.data, body.len);
    text[body.len] = '\0';
    assert(strstr(text, "shield_requests_total{zone=\"quote\\\"slash\\\\line\\n\"} 11\n") != NULL);
    assert(strstr(text, "shield_ban_refusals_total{zone=\"quote\\\"slash\\\\line\\n\"} 22\n") != NULL);
    assert(strstr(text, "shield_zone_evictions_total{zone=\"quote\\\"slash\\\\line\\n\"} 33\n") != NULL);
    assert(strstr(text, "shield_zone_alloc_failures_total{zone=\"quote\\\"slash\\\\line\\n\"} 44\n") != NULL);
    assert(strstr(text, "shield_zone_used_bytes{zone=\"quote\\\"slash\\\\line\\n\"} 55\n") != NULL);
    assert(strstr(text, "shield_zone_size_bytes{zone=\"quote\\\"slash\\\\line\\n\"} 66\n") != NULL);
    assert(strstr(text, "reason=\"too_large\"} 77\n") != NULL);
    assert(strstr(text, "reason=\"encoding\"} 88\n") != NULL);
    assert(strstr(text, "reason=\"error\"} 99\n") != NULL);
    free(text);
    free(allocation);
    allocations = 0;

    /* Prometheus metadata uses sample names; OpenMetrics keeps family names
     * and EOF. These assertions do not read the production descriptor table. */
    assert(ngx_http_shield_status_prometheus(NULL, &zone, &snapshot, &body, 0)
           == NGX_OK);
    text = malloc(body.len + 1);
    assert(text != NULL);
    memcpy(text, body.data, body.len);
    text[body.len] = '\0';
    assert(strstr(text, "# HELP shield_hits_total ") != NULL);
    assert(strstr(text, "# TYPE shield_hits_total counter\n") != NULL);
    assert(strstr(text, "# TYPE shield_zone_nodes gauge\n") != NULL);
    assert(strstr(text, "# EOF") == NULL);
    free(text);
    free(allocation);

    /* Exact bytes for zero and maximum values, with escaping in both formats. */
    ngx_memzero(&snapshot, sizeof(snapshot));
    assert(ngx_http_shield_status_json(NULL, &zone, &snapshot, &body) == NGX_OK);
    check_golden(&body, 0, 0);
    free(allocation);
    assert(render_metrics(NULL, &zone, hits, 0, 0, 0, 0,
                                            &body) == NGX_OK);
    check_golden(&body, 1, 0);
    free(allocation);
    snapshot.nodes = (ngx_uint_t) -1;
    snapshot.blocked = snapshot.bans = UINT64_MAX;
    snapshot.inspected = snapshot.ban_refused = UINT64_MAX;
    snapshot.evictions = snapshot.alloc_failures = UINT64_MAX;
    snapshot.used = snapshot.size = UINT64_MAX;
    for (i = 0; i < NGX_HTTP_SHIELD_BODY_REASONS; i++) {
        snapshot.body_uninspected[i] = UINT64_MAX;
    }
    extra_value = UINT64_MAX;
    for (i = 0; i < NGX_HTTP_SHIELD_CAT_N; i++) {
        snapshot.cat_hits[i] = hits[i] = UINT64_MAX;
        snapshot.cat_detect[i] = snapshot.cat_block[i] = UINT64_MAX;
    }
    assert(ngx_http_shield_status_json(NULL, &zone, &snapshot, &body) == NGX_OK);
    check_golden(&body, 0, 1);
    free(allocation);
    assert(render_metrics(NULL, &zone, hits, UINT64_MAX,
               UINT64_MAX, (ngx_uint_t) -1, (ngx_uint_t) -1, &body) == NGX_OK);
    check_golden(&body, 1, 1);
    free(allocation);
    /* The same maximum snapshot must fit the larger 0.0.4 metadata too. */
    for (i = 0; i < NGX_HTTP_SHIELD_CAT_N; i++) {
        for (ngx_uint_t j = 0; j < NGX_HTTP_SHIELD_SOURCE_COUNT; j++) {
            snapshot.source_hits[i][j] = UINT64_MAX;
        }
    }
    snapshot.banned = (ngx_uint_t) -1;
    assert(ngx_http_shield_status_prometheus(NULL, &zone, &snapshot, &body, 0)
           == NGX_OK);
    check_golden(&body, 2, 1);
    free(allocation);
    {
        u_char long_label[4096];
        ngx_str_t long_zone;
        const char tail[] = "reason=\"error\"} 18446744073709551615\n";

        /* Every label byte expands; numeric widths and the final sample are
         * maximal, so neither escaping nor counters leave hidden slack. */
        memset(long_label, '\\', sizeof(long_label));
        long_zone.data = long_label;
        long_zone.len = sizeof(long_label);
        assert(ngx_http_shield_status_prometheus(NULL, &long_zone, &snapshot,
                                                &body, 0) == NGX_OK);
        assert(body.data + body.len < (u_char *) allocation + allocation_size);
        assert(body.len >= sizeof(tail) - 1);
        assert(memcmp(body.data + body.len - (sizeof(tail) - 1), tail,
                      sizeof(tail) - 1) == 0);
        free(allocation);
    }
    extra_value = 0;
    ngx_memzero(hits, sizeof(hits));
    allocations = 0;
    aligned_allocations = 0;

    assert(strcmp(ngx_http_shield_cat_name(NGX_HTTP_SHIELD_CAT_N),
                  "unknown") == 0);
    hits[0] = UINT64_MAX;
    assert(render_metrics(NULL, &zone, hits,
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
    assert(render_metrics(NULL, &zone, hits,
               0, 0, 0, 0, &body) == NGX_ERROR);
    assert(allocations == 2);
    fail_alloc = 0;

    /* A large admissible size reaches the allocator; overflow is rejected. */
    limit = ((NGX_MAX_SIZE_T_VALUE - 2048)
                / ((3 + NGX_HTTP_SHIELD_SOURCE_COUNT) * NGX_HTTP_SHIELD_CAT_N
                   + NGX_SHIELD_STATUS_METRICS + 2)
                - 128) / 2;
    zone.len = limit - 1024;
    fail_alloc = 1;
    assert(render_metrics(NULL, &zone, hits,
               0, 0, 0, 0, &body) == NGX_ERROR);
    assert(allocations == 3);
    fail_alloc = 0;
    zone.len = limit + 1;
    assert(render_metrics(NULL, &zone, hits,
               0, 0, 0, 0, &body) == NGX_ERROR);
    assert(allocations == 3); /* size rejected before reading/allocating */

    zone.len = 0;
    huge_category = 1;
    assert(render_metrics(NULL, &zone, hits,
               0, 0, 0, 0, &body) == NGX_ERROR);
    assert(allocations == 3);
    huge_category = 0;

    assert(render_metrics(NULL, &zone, hits,
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
    expected_len = snprintf(expected_hits, sizeof(expected_hits),
                            "\"hits\":%" PRIuPTR,
                            (uintptr_t) snapshot.entries[0].hits);
    assert(expected_len > 0 && (size_t) expected_len < sizeof(expected_hits));
    assert(strstr(text, expected_hits) != NULL);
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

    snapshot.capacity = 1;
    snapshot.entries = &copied;
    assert(ngx_http_shield_status_snapshot_alloc(NULL, 0, &snapshot)
           == NGX_OK);
    assert(snapshot.capacity == 0);
    assert(snapshot.entries == NULL);

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
