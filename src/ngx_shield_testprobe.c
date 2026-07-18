/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * ngx_shield_testprobe.c -- in-worker test probe renderer (CI only).
 *
 * See ngx_shield_testprobe.h for why this is split from the HTTP module.
 */

#include "ngx_shield_testprobe.h"

#ifdef NGX_TEST_HARNESS

#include "ngx_http_shield_ban.h"


u_char *
ngx_shield_probe_json(u_char *buf, u_char *last, ngx_shm_zone_t *zone)
{
    time_t                       now;
    u_char                      *p;
    ngx_queue_t                 *q;
    ngx_uint_t                   nodes, banned, pages_free, present;
    ngx_http_shield_ban_node_t  *node;
    ngx_http_shield_ban_ctx_t   *ctx;

    nodes = 0;
    banned = 0;
    pages_free = 0;
    present = 0;

    /*
     * Worker identity and connection accounting.
     *
     * connection_n / free_connection_n are plain ngx_cycle fields present in
     * both nginx and angie. Deliberately NOT ngx_stat_active and friends: those
     * exist only under NGX_STAT_STUB, so reading them would silently couple the
     * harness to whether stub_status was configured into the build.
     */
    p = ngx_slprintf(buf, last,
                     "{\"flavor\":\"%s\","
                     "\"flavor_version\":\"%s\","
                     "\"pid\":%P,"
                     "\"page_size\":%uz,"
                     "\"connections\":{\"total\":%ui,\"free\":%ui}",
                     (u_char *) NGX_SHIELD_PROBE_FLAVOR,
                     (u_char *) NGX_SHIELD_PROBE_FLAVOR_VER,
                     ngx_pid,
                     (size_t) ngx_pagesize,
                     (ngx_uint_t) ngx_cycle->connection_n,
                     (ngx_uint_t) ngx_cycle->free_connection_n);

    if (zone == NULL) {
        return ngx_slprintf(p, last, ",\"zone\":{\"present\":false}}");
    }

    ctx = zone->data;

    /*
     * zone->data is set by the shield_ban_zone directive at config time, but
     * ctx->sh / ctx->shpool are only filled by the zone init callback, which
     * runs per worker. A probe that races a reload can legitimately see the
     * former without the latter -- report it instead of dereferencing it.
     */
    if (ctx != NULL && ctx->sh != NULL && ctx->shpool != NULL) {
        present = 1;
        now = ngx_time();

        ngx_shmtx_lock(&ctx->shpool->mutex);

        for (q = ngx_queue_head(&ctx->sh->queue);
             q != ngx_queue_sentinel(&ctx->sh->queue);
             q = ngx_queue_next(q))
        {
            node = ngx_queue_data(q, ngx_http_shield_ban_node_t, queue);

            nodes++;

            if (node->banned_until > now) {
                banned++;
            }
        }

        /* pfree is the free-page count the slab allocator maintains
         * unconditionally. pool->stats[] is the richer source but is only
         * populated under NGX_DEBUG_MALLOC-style builds, so it is not a
         * portable signal for a harness that must run on release-ish CI
         * builds of both nginx and angie. */
        pages_free = ctx->shpool->pfree;

        ngx_shmtx_unlock(&ctx->shpool->mutex);
    }

    return ngx_slprintf(p, last,
                        ",\"zone\":{"
                        "\"present\":%s,"
                        "\"name\":\"%V\","
                        "\"size\":%uz,"
                        "\"slab_pages_free\":%ui,"
                        "\"nodes\":%ui,"
                        "\"banned\":%ui"
                        "}}",
                        (u_char *) (present ? "true" : "false"),
                        &zone->shm.name,
                        (size_t) zone->shm.size,
                        pages_free,
                        nodes,
                        banned);
}

#else

/* ISO C forbids an empty translation unit, and angie's configure adds -Werror,
 * so the disabled build needs a declaration to stand on. */
typedef int ngx_shield_probe_not_built_t;

#endif /* NGX_TEST_HARNESS */
