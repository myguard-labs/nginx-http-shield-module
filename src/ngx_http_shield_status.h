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


/* Render OpenMetrics outside the slab lock. Only aggregate gauges are exposed:
 * per-client labels would create unbounded time-series cardinality. The zone
 * label is escaped once into the same allocation as the response body. */
static ngx_int_t
ngx_http_shield_status_prometheus(ngx_pool_t *pool, ngx_str_t *zone,
    uint64_t *cat_hits, uint64_t blocked, uint64_t bans, ngx_uint_t nodes,
    ngx_uint_t banned, ngx_str_t *body)
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
                    / (NGX_HTTP_SHIELD_CAT_N + 5) - 128) / 2)
    {
        return NGX_ERROR;
    }

    size = 2048 + (NGX_HTTP_SHIELD_CAT_N + 5) * (128 + 2 * zone->len);
    for (i = 0; i < NGX_HTTP_SHIELD_CAT_N; i++) {
        len = ngx_strlen(ngx_http_shield_cat_name(i));
        if (len > NGX_MAX_SIZE_T_VALUE - size) {
            return NGX_ERROR;
        }
        size += len;
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

    /* OpenMetrics counter family names omit the _total sample suffix. */
    p = ngx_slprintf(p, last,
                     "# HELP shield_hits Shield signature hits by category.\n"
                     "# TYPE shield_hits counter\n");
    for (i = 0; i < NGX_HTTP_SHIELD_CAT_N; i++) {
        p = ngx_slprintf(p, last,
                         "shield_hits_total{zone=\"%V\",category=\"%s\"} %uL\n",
                         &label, ngx_http_shield_cat_name(i), cat_hits[i]);
    }

    p = ngx_slprintf(p, last,
                     "# HELP shield_blocked Shield requests blocked.\n"
                     "# TYPE shield_blocked counter\n"
                     "shield_blocked_total{zone=\"%V\"} %uL\n"
                     "# HELP shield_bans Shield bans armed.\n"
                     "# TYPE shield_bans counter\n"
                     "shield_bans_total{zone=\"%V\"} %uL\n"
                     "# HELP shield_zone_nodes Shield zone nodes in use.\n"
                     "# TYPE shield_zone_nodes gauge\n"
                     "shield_zone_nodes{zone=\"%V\"} %ui\n"
                     "# HELP shield_banned_clients "
                     "Shield clients currently banned.\n"
                     "# TYPE shield_banned_clients gauge\n"
                     "shield_banned_clients{zone=\"%V\"} %ui\n"
                     "# EOF\n",
                     &label, blocked, &label, bans, &label, nodes,
                     &label, banned);

    body->len = p - body->data;
    return NGX_OK;
}


#endif /* NGX_HTTP_SHIELD_STATUS_H_INCLUDED_ */
