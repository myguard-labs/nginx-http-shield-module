/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Private status renderers; shared with the direct-call unit harness.
 */
#ifndef NGX_HTTP_SHIELD_STATUS_H_INCLUDED_
#define NGX_HTTP_SHIELD_STATUS_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include "ngx_http_shield_patterns.h"
#include "ngx_http_shield_ban.h"


typedef struct {
    u_char      len;
    u_char      addr[16];
    time_t      expires;
    ngx_uint_t  hits;
} ngx_http_shield_status_ban_t;


typedef struct {
    uint64_t                       cat_hits[NGX_HTTP_SHIELD_BAN_NCOUNTERS];
    uint64_t                       cat_detect[NGX_HTTP_SHIELD_BAN_NCOUNTERS];
    uint64_t                       cat_block[NGX_HTTP_SHIELD_BAN_NCOUNTERS];
    uint64_t                       source_hits[NGX_HTTP_SHIELD_BAN_NCOUNTERS]
                                              [NGX_HTTP_SHIELD_SOURCE_COUNT];
    uint64_t                       blocked;
    uint64_t                       bans;
    uint64_t                       inspected;
    uint64_t                       ban_refused;
    uint64_t                       body_uninspected
                                       [NGX_HTTP_SHIELD_BODY_REASONS];
    uint64_t                       evictions;
    uint64_t                       alloc_failures;
    uint64_t                       used;
    uint64_t                       size;
    ngx_uint_t                     nodes;
    ngx_uint_t                     banned;
    ngx_uint_t                     capacity;
    ngx_http_shield_status_ban_t  *entries;
} ngx_http_shield_status_snapshot_t;


/* Order is part of the status wire format. A NULL JSON key denotes a
 * metric-only family; hits are emitted separately for each category. */
typedef struct {
    const char  *json_key;
    const char  *family;
    const char  *help;
    ngx_uint_t   counter;
    size_t       offset;
} ngx_http_shield_status_metric_t;

static const ngx_http_shield_status_metric_t
ngx_http_shield_status_metrics[] = {
    { NULL, "shield_hits", "Shield signature hits by category.", 1, 0 },
#define NGX_SHIELD_METRIC(key, family, help, counter, field) \
    { key, family, help, counter, \
      offsetof(ngx_http_shield_status_snapshot_t, field) }
    NGX_SHIELD_METRIC("blocked", "shield_blocked", "Shield requests blocked.",
                      1, blocked),
    NGX_SHIELD_METRIC("bans", "shield_bans", "Shield bans armed.", 1, bans),
    NGX_SHIELD_METRIC("nodes", "shield_zone_nodes", "Shield zone nodes in use.",
                      0, nodes),
    NGX_SHIELD_METRIC(NULL, "shield_banned_clients",
                      "Shield clients currently banned.", 0, banned),
    NGX_SHIELD_METRIC("inspected", "shield_requests",
                      "Shield requests inspected.", 1, inspected),
    NGX_SHIELD_METRIC("ban_refused", "shield_ban_refusals",
                      "Shield requests refused by an active ban.",
                      1, ban_refused),
    NGX_SHIELD_METRIC("evictions", "shield_zone_evictions",
                      "Shield zone nodes evicted.", 1, evictions),
    NGX_SHIELD_METRIC("alloc_failures", "shield_zone_alloc_failures",
                      "Shield zone node allocation failures.",
                      1, alloc_failures),
    NGX_SHIELD_METRIC("used", "shield_zone_used_bytes",
                      "Shield zone bytes reserved including slab overhead.",
                      0, used),
    NGX_SHIELD_METRIC("size", "shield_zone_size_bytes",
                      "Shield zone size in bytes.", 0, size),
    { NULL, "shield_detections",
      "Shield detections by category and mode.", 1, 0 },
    { NULL, "shield_source_hits",
      "Shield signature hits by category and source.", 1, 0 },
    { NULL, "shield_body_uninspected",
      "Shield bodies with incomplete inspection by reason.", 1, 0 }
#undef NGX_SHIELD_METRIC
};

#define NGX_SHIELD_STATUS_METRICS \
    (sizeof(ngx_http_shield_status_metrics) \
     / sizeof(ngx_http_shield_status_metrics[0]))


/* Caller holds the slab mutex. Include metadata and reserved partial pages;
 * only wholly free slab pages are subtracted from the mapped zone size. */
static ngx_int_t
ngx_http_shield_status_slab_usage(ngx_slab_pool_t *shpool,
    ngx_http_shield_status_snapshot_t *snapshot)
{
    snapshot->size = (u_char *) shpool->end - (u_char *) shpool;
    if (shpool->pfree > snapshot->size / ngx_pagesize) {
        return NGX_ERROR;
    }
    snapshot->used = snapshot->size - shpool->pfree * ngx_pagesize;
    return NGX_OK;
}


static uint64_t
ngx_http_shield_status_value(ngx_http_shield_status_snapshot_t *snapshot,
    ngx_uint_t index)
{
    uint64_t value;

    if (index == 3) {
        return snapshot->nodes;
    }
    if (index == 4) {
        return snapshot->banned;
    }
    ngx_memcpy(&value, (u_char *) snapshot
                      + ngx_http_shield_status_metrics[index].offset,
               sizeof(value));
    return value;
}


static ngx_int_t
ngx_http_shield_status_size_add(size_t *size, size_t add)
{
    if (add > NGX_MAX_SIZE_T_VALUE - *size) {
        return NGX_ERROR;
    }

    *size += add;
    return NGX_OK;
}


/* Add modest retry slack without turning a small observed active set into a
 * whole-zone request-pool allocation. Subtract before adding so both the zone
 * cap and ngx_uint_t overflow are handled by the same bound. */
static ngx_int_t
ngx_http_shield_status_retry_capacity(ngx_uint_t observed,
    ngx_uint_t physical, ngx_uint_t *capacity)
{
    ngx_uint_t  headroom, remaining;

    if (observed == 0 || observed > physical) {
        return NGX_ERROR;
    }

    headroom = observed / 4;
    if (headroom == 0) {
        headroom = 1;
    } else if (headroom > 64) {
        headroom = 64;
    }

    remaining = physical - observed;
    if (headroom > remaining) {
        headroom = remaining;
    }

    *capacity = observed + headroom;
    return NGX_OK;
}


static ngx_int_t
ngx_http_shield_status_snapshot_alloc(ngx_pool_t *pool, ngx_uint_t capacity,
    ngx_http_shield_status_snapshot_t *snapshot)
{
    size_t  size;

    if (capacity == 0) {
        snapshot->capacity = 0;
        snapshot->entries = NULL;
        return NGX_OK;
    }

    if (capacity > NGX_MAX_SIZE_T_VALUE
                   / sizeof(ngx_http_shield_status_ban_t))
    {
        return NGX_ERROR;
    }

    size = capacity * sizeof(ngx_http_shield_status_ban_t);
    snapshot->entries = ngx_palloc(pool, size);
    if (snapshot->entries == NULL) {
        return NGX_ERROR;
    }

    snapshot->capacity = capacity;
    return NGX_OK;
}


/* Copy every field the renderer needs while the caller holds the slab mutex.
 * The returned entry has request-pool ownership and no shared pointer. */
static ngx_int_t
ngx_http_shield_status_snapshot_ban(ngx_http_shield_status_ban_t *dst,
    ngx_http_shield_ban_node_t *src, time_t now)
{
    if (src->banned_until <= now) {
        return NGX_DECLINED;
    }

    if (src->len != 4 && src->len != 16) {
        return NGX_ERROR;
    }

    dst->len = src->len;
    ngx_memcpy(dst->addr, src->addr, src->len);
    dst->hits = src->hits;
    dst->expires = src->banned_until - now;

    return NGX_OK;
}

/*
 * Name of a category by enum value, for the status report.
 *
 * Derived from ngx_http_shield_categories[] rather than from a second hand-kept
 * list, so adding a signature category cannot make the two disagree. The four
 * STRUCTURAL categories have no table row (nothing to match with signatures),
 * so they are named from the same NGX_HTTP_SHIELD_NAME_* macros the detection
 * sites use -- again, no new copy of the string.
 *
 * Returns "unknown" rather than NULL for an unnamed value: a category added to
 * the enum but to neither the table nor the switch below should show up as a
 * visibly wrong key in monitoring, not crash the endpoint.
 */
static const char *
ngx_http_shield_cat_name(ngx_uint_t cat)
{
    ngx_uint_t  i;

    for (i = 0; i < NGX_HTTP_SHIELD_NCATEGORIES; i++) {
        if (ngx_http_shield_categories[i].cat == cat) {
            return ngx_http_shield_categories[i].name;
        }
    }

    switch (cat) {
    case NGX_HTTP_SHIELD_CAT_HTTPOXY:
        return NGX_HTTP_SHIELD_NAME_HTTPOXY;
    case NGX_HTTP_SHIELD_CAT_RANGE_DOS:
        return NGX_HTTP_SHIELD_NAME_RANGE_DOS;
    case NGX_HTTP_SHIELD_CAT_CTRL_CHAR:
        return NGX_HTTP_SHIELD_NAME_CTRL_CHAR;
    case NGX_HTTP_SHIELD_CAT_DOTFILE:
        return NGX_HTTP_SHIELD_NAME_DOTFILE;
    default:
        return "unknown";   /* LCOV_EXCL_LINE -- unreachable while the enum, */
                            /* the table, and this switch stay in sync       */
    }
}


/* Render an owned snapshot as JSON. Size arithmetic is checked before the
 * request-pool allocation, and one spare byte makes a formatter reaching
 * `last` an explicit error rather than a silently truncated document. */
static ngx_int_t
ngx_http_shield_status_json(ngx_pool_t *pool, ngx_str_t *zone,
    ngx_http_shield_status_snapshot_t *snapshot, ngx_str_t *body)
{
    size_t       entry_size, escape, len, size;
    u_char      *buf, *p, *last;
    ngx_uint_t   i;

    if (snapshot->banned > snapshot->capacity
        || (snapshot->banned != 0 && snapshot->entries == NULL))
    {
        return NGX_ERROR;
    }

    /* One spare byte is retained through rendering as the truncation oracle. */
    size = 1;

#define NGX_SHIELD_STATUS_ADD_LITERAL(s)                                    \
    if (ngx_http_shield_status_size_add(&size, sizeof(s) - 1) != NGX_OK) {  \
        return NGX_ERROR;                                                    \
    }

    NGX_SHIELD_STATUS_ADD_LITERAL("{\"zone\":\"");

    /* Reject a synthetic impossible length before ngx_escape_json reads it. */
    if (zone->len > NGX_MAX_SIZE_T_VALUE - size) {
        return NGX_ERROR;
    }
    escape = ngx_escape_json(NULL, zone->data, zone->len);
    if (ngx_http_shield_status_size_add(&size, zone->len) != NGX_OK
        || ngx_http_shield_status_size_add(&size, escape) != NGX_OK)
    {
        return NGX_ERROR;
    }

    NGX_SHIELD_STATUS_ADD_LITERAL("\"");
    /* JSON order is nodes, blocked, bans; metrics use exposition order. */
    for (i = 0; i < NGX_SHIELD_STATUS_METRICS; i++) {
        ngx_uint_t index = i == 0 ? 3 : (i == 3 ? 0 : i);
        if (ngx_http_shield_status_metrics[index].json_key == NULL) {
            continue;
        }
        len = ngx_strlen(ngx_http_shield_status_metrics[index].json_key);
        if (ngx_http_shield_status_size_add(&size, len) != NGX_OK
            || ngx_http_shield_status_size_add(&size,
                   sizeof(",\"\":") - 1 + NGX_INT64_LEN) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }
    NGX_SHIELD_STATUS_ADD_LITERAL(
        ",\"body_uninspected\":{\"too_large\":,\"encoding\":,\"error\":}");
    if (ngx_http_shield_status_size_add(&size, 3 * NGX_INT64_LEN) != NGX_OK) {
        return NGX_ERROR;
    }
    NGX_SHIELD_STATUS_ADD_LITERAL(",\"categories\":{");

    for (i = 0; i < NGX_HTTP_SHIELD_CAT_N; i++) {
        len = ngx_strlen(ngx_http_shield_cat_name(i));
        if (ngx_http_shield_status_size_add(&size,
                1 + sizeof("\"\":") - 1 + NGX_INT64_LEN) != NGX_OK
            || ngx_http_shield_status_size_add(&size, len) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    NGX_SHIELD_STATUS_ADD_LITERAL("},\"detections\":{");
    for (i = 0; i < NGX_HTTP_SHIELD_CAT_N; i++) {
        len = ngx_strlen(ngx_http_shield_cat_name(i));
        if (ngx_http_shield_status_size_add(&size, len) != NGX_OK
            || ngx_http_shield_status_size_add(&size,
                   1 + sizeof("\"\":{\"detect\":,\"block\":}") - 1
                   + 2 * NGX_INT64_LEN) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }
    NGX_SHIELD_STATUS_ADD_LITERAL("},\"banned\":[");

    entry_size = 1 + sizeof("{\"addr\":\"") - 1 + NGX_INET6_ADDRSTRLEN
                 + sizeof("\",\"hits\":") - 1 + NGX_INT_T_LEN
                 + sizeof(",\"expires\":") - 1 + NGX_TIME_T_LEN
                 + sizeof("}") - 1;

    if (snapshot->banned > (NGX_MAX_SIZE_T_VALUE - size) / entry_size) {
        return NGX_ERROR;
    }
    size += snapshot->banned * entry_size;
    NGX_SHIELD_STATUS_ADD_LITERAL("]}");

#undef NGX_SHIELD_STATUS_ADD_LITERAL

    buf = ngx_pnalloc(pool, size);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    last = buf + size;
    p = ngx_slprintf(buf, last, "{\"zone\":\"");
    p = (u_char *) ngx_escape_json(p, zone->data, zone->len);
    p = ngx_slprintf(p, last, "\"");
    for (i = 0; i < NGX_SHIELD_STATUS_METRICS; i++) {
        ngx_uint_t index = i == 0 ? 3 : (i == 3 ? 0 : i);
        if (ngx_http_shield_status_metrics[index].json_key == NULL) {
            continue;
        }
        uint64_t value = ngx_http_shield_status_value(snapshot, index);
        p = ngx_slprintf(p, last, ",\"%s\":%uL",
                         ngx_http_shield_status_metrics[index].json_key, value);
    }
    p = ngx_slprintf(p, last,
                     ",\"body_uninspected\":{\"too_large\":%uL,"
                     "\"encoding\":%uL,\"error\":%uL}",
                     snapshot->body_uninspected[0],
                     snapshot->body_uninspected[1],
                     snapshot->body_uninspected[2]);
    p = ngx_slprintf(p, last, ",\"categories\":{");

    for (i = 0; i < NGX_HTTP_SHIELD_CAT_N; i++) {
        p = ngx_slprintf(p, last, "%s\"%s\":%uL",
                         i == 0 ? "" : ",",
                         ngx_http_shield_cat_name(i),
                         snapshot->cat_hits[i]);
    }

    p = ngx_slprintf(p, last, "},\"detections\":{");
    for (i = 0; i < NGX_HTTP_SHIELD_CAT_N; i++) {
        p = ngx_slprintf(p, last, "%s\"%s\":{\"detect\":%uL,\"block\":%uL}",
                         i == 0 ? "" : ",", ngx_http_shield_cat_name(i),
                         snapshot->cat_detect[i], snapshot->cat_block[i]);
    }
    p = ngx_slprintf(p, last, "},\"banned\":[");

    for (i = 0; i < snapshot->banned; i++) {
        if (snapshot->entries[i].len != 4
            && snapshot->entries[i].len != 16)
        {
            return NGX_ERROR;
        }

        p = ngx_slprintf(p, last, "%s{\"addr\":\"", i == 0 ? "" : ",");
        len = ngx_inet_ntop(snapshot->entries[i].len == 4 ? AF_INET : AF_INET6,
                            snapshot->entries[i].addr, p, last - p);
        if (len == 0) {
            return NGX_ERROR;
        }
        p += len;
        p = ngx_slprintf(p, last, "\",\"hits\":%ui,\"expires\":%T}",
                         snapshot->entries[i].hits,
                         snapshot->entries[i].expires);
    }

    p = ngx_slprintf(p, last, "]}");
    if (p >= last) {
        return NGX_ERROR;
    }

    body->data = buf;
    body->len = p - buf;
    return NGX_OK;
}


/* Render metrics outside the slab lock. Only aggregate gauges are exposed:
 * per-client labels would create unbounded time-series cardinality. The zone
 * label is escaped once into the same allocation as the response body. */
static ngx_int_t
ngx_http_shield_status_prometheus(ngx_pool_t *pool, ngx_str_t *zone,
    ngx_http_shield_status_snapshot_t *snapshot, ngx_str_t *body,
    ngx_flag_t openmetrics)
{
    size_t       size, len;
    u_char      *buf, *p, *last;
    ngx_uint_t   i;
    ngx_str_t    label;

    /* 2048 covers metadata, 128 covers each sample's fixed text and value;
     * category names are measured separately. One extra row reserves the
     * scratch label. Quotes, backslashes and line feeds each expand to 2 bytes.
     * Guard multiplication before allocating, even for huge config tokens. */
    if (zone->len > ((NGX_MAX_SIZE_T_VALUE - 2048)
                    / ((3 + NGX_HTTP_SHIELD_SOURCE_COUNT)
                       * NGX_HTTP_SHIELD_CAT_N + NGX_SHIELD_STATUS_METRICS + 2)
                    - 128) / 2)
    {
        return NGX_ERROR;
    }

    size = 2048 + ((3 + NGX_HTTP_SHIELD_SOURCE_COUNT) * NGX_HTTP_SHIELD_CAT_N
                       + NGX_SHIELD_STATUS_METRICS + 2)
                  * (128 + 2 * zone->len);
    for (i = 0; i < NGX_HTTP_SHIELD_CAT_N; i++) {
        len = ngx_strlen(ngx_http_shield_cat_name(i));
        if (len > NGX_MAX_SIZE_T_VALUE - size) {
            return NGX_ERROR;
        }
        if (len > (NGX_MAX_SIZE_T_VALUE - size)
                  / (3 + NGX_HTTP_SHIELD_SOURCE_COUNT))
        {
            return NGX_ERROR;
        }
        size += (3 + NGX_HTTP_SHIELD_SOURCE_COUNT) * len;
    }

    buf = ngx_pnalloc(pool, size);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    p = buf;
    for (i = 0; i < zone->len; i++) {
        switch (zone->data[i]) {
        case '\\':
        case '"':
            *p++ = '\\';
            *p++ = zone->data[i];
            break;
        case '\n':
            *p++ = '\\';
            *p++ = 'n';
            break;
        default:
            *p++ = zone->data[i];
            break;
        }
    }
    label.data = buf;
    label.len = p - buf;
    body->data = p;
    last = buf + size;

    /* OpenMetrics counter metadata omits _total; 0.0.4 uses sample names. */
    for (i = 0; i < NGX_SHIELD_STATUS_METRICS; i++) {
        const ngx_http_shield_status_metric_t *metric;
        uint64_t value;
        ngx_uint_t j;

        metric = &ngx_http_shield_status_metrics[i];
        p = ngx_slprintf(p, last, "# HELP %s%s %s\n# TYPE %s%s %s\n",
                         metric->family,
                         metric->counter && !openmetrics ? "_total" : "",
                         metric->help, metric->family,
                         metric->counter && !openmetrics ? "_total" : "",
                         metric->counter ? "counter" : "gauge");
        if (i == 0) {
            for (j = 0; j < NGX_HTTP_SHIELD_CAT_N; j++) {
                p = ngx_slprintf(p, last,
                    "%s_total{zone=\"%V\",category=\"%s\"} %uL\n",
                    metric->family, &label, ngx_http_shield_cat_name(j),
                    snapshot->cat_hits[j]);
            }
            continue;
        }
        if (i == NGX_SHIELD_STATUS_METRICS - 3) {
            for (j = 0; j < NGX_HTTP_SHIELD_CAT_N; j++) {
                p = ngx_slprintf(p, last,
                    "%s_total{zone=\"%V\",category=\"%s\","
                    "mode=\"detect\"} %uL\n"
                    "%s_total{zone=\"%V\",category=\"%s\","
                    "mode=\"block\"} %uL\n",
                    metric->family, &label, ngx_http_shield_cat_name(j),
                    snapshot->cat_detect[j], metric->family, &label,
                    ngx_http_shield_cat_name(j), snapshot->cat_block[j]);
            }
            continue;
        }
        if (i == NGX_SHIELD_STATUS_METRICS - 2) {
            ngx_uint_t source;

            for (j = 0; j < NGX_HTTP_SHIELD_CAT_N; j++) {
                for (source = 0; source < NGX_HTTP_SHIELD_SOURCE_COUNT;
                     source++)
                {
                    p = ngx_slprintf(p, last,
                        "%s_total{zone=\"%V\",category=\"%s\","
                        "source=\"%s\"} %uL\n",
                        metric->family, &label, ngx_http_shield_cat_name(j),
                        ngx_http_shield_source_name(source),
                        snapshot->source_hits[j][source]);
                }
            }
            continue;
        }
        if (i == NGX_SHIELD_STATUS_METRICS - 1) {
            static const char *reasons[] = { "too_large", "encoding", "error" };

            for (j = 0; j < NGX_HTTP_SHIELD_BODY_REASONS; j++) {
                p = ngx_slprintf(p, last,
                    "%s_total{zone=\"%V\",reason=\"%s\"} %uL\n",
                    metric->family, &label, reasons[j],
                    snapshot->body_uninspected[j]);
            }
            continue;
        }
        value = ngx_http_shield_status_value(snapshot, i);
        p = ngx_slprintf(p, last, "%s%s{zone=\"%V\"} %uL\n",
                         metric->family, metric->counter ? "_total" : "",
                         &label, value);
    }
    if (openmetrics) {
        p = ngx_slprintf(p, last, "# EOF\n");
    }

    body->len = p - body->data;
    return NGX_OK;
}


#endif /* NGX_HTTP_SHIELD_STATUS_H_INCLUDED_ */
