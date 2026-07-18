/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * ngx_http_shield_ban.c -- shared-memory state engine for shield_ban.
 *
 * Split out of the HTTP module (see ngx_http_shield_ban.h) so it depends only on
 * <ngx_core.h> and can be unit-tested directly with synthetic addresses and a
 * synthetic clock. Every function here runs under a lock the caller holds.
 */

#include "ngx_http_shield_ban.h"


time_t
ngx_http_shield_time_add_clamp(time_t now, time_t delta)
{
    time_t  time_t_max = (time_t) (((uint64_t) 1
                                    << (sizeof(time_t) * 8 - 1)) - 1);

    if (delta > time_t_max - now) {
        return time_t_max;
    }
    return now + delta;
}


void
ngx_http_shield_ban_rbtree_insert(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t           **p;
    ngx_http_shield_ban_node_t   *bn, *bnt;

    for ( ;; ) {
        if (node->key < temp->key) {
            p = &temp->left;

        } else if (node->key > temp->key) {
            p = &temp->right;

        } else { /* hash collision: order by the stored address bytes */
            bn  = (ngx_http_shield_ban_node_t *) &node->color;
            bnt = (ngx_http_shield_ban_node_t *) &temp->color;

            p = (bn->len < bnt->len
                 || (bn->len == bnt->len
                     && ngx_memcmp(bn->addr, bnt->addr, bn->len) < 0))
                ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


ngx_http_shield_ban_node_t *
ngx_http_shield_ban_lookup(ngx_http_shield_ban_ctx_t *ctx, ngx_uint_t hash,
    u_char *addr, u_char len)
{
    ngx_int_t                    rc;
    ngx_rbtree_node_t           *node, *sentinel;
    ngx_http_shield_ban_node_t  *bn;

    node = ctx->sh->rbtree.root;
    sentinel = ctx->sh->rbtree.sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key: resolve exactly on the stored address */
        bn = (ngx_http_shield_ban_node_t *) &node->color;

        rc = (ngx_int_t) len - (ngx_int_t) bn->len;
        if (rc == 0) {
            rc = ngx_memcmp(addr, bn->addr, len);
        }

        if (rc == 0) {
            ngx_queue_remove(&bn->queue);
            ngx_queue_insert_head(&ctx->sh->queue, &bn->queue);
            return bn;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}


void
ngx_http_shield_ban_expire(ngx_http_shield_ban_ctx_t *ctx, time_t now,
    time_t window)
{
    ngx_uint_t                   scanned, evicted;
    ngx_queue_t                 *q, *prev;
    ngx_rbtree_node_t           *node;
    ngx_http_shield_ban_node_t  *bn;

    /* Walk from the LRU tail toward the head, evicting only nodes that are
     * genuinely stale -- neither actively banned nor inside a live counting
     * window. A node is skipped (not evicted) when either deadline is still in
     * the future.
     *
     * We must NOT stop at the first live node. The tail is LRU-oldest by *touch*
     * time, but "oldest touched" is not "soonest to expire": a below-threshold
     * node under a long window can be touched-older yet expire later than a
     * banned node under a short bantime. Evicting a below-threshold node that
     * still has a live window would let an attacker defeat the ban by rotating
     * source addresses to keep the zone at the eviction margin -- no single IP
     * ever accumulates enough hits to arm (S27-1). So we scan past live nodes
     * looking for a stale one.
     *
     * Two separate budgets, not one shared iteration cap. If a single "scan up
     * to N" cap counted skips and evictions together, a cluster of >=N live
     * nodes at the tail would consume the whole cap on skips and the call would
     * reclaim nothing even though stale nodes sit just past them -- and since
     * every call restarts at the same tail, the zone could never reclaim (the
     * allocation keeps failing despite reclaimable space). So SCAN bounds how
     * far we look (generous, to see past a live-tail cluster) and EVICT bounds
     * how many we actually free (the real per-request work cost). */
    scanned = 0;
    evicted = 0;
    q = ngx_queue_last(&ctx->sh->queue);

    while (q != ngx_queue_sentinel(&ctx->sh->queue)
           && scanned < NGX_HTTP_SHIELD_BAN_EXPIRE_SCAN
           && evicted < NGX_HTTP_SHIELD_BAN_EXPIRE_EVICT)
    {
        scanned++;
        prev = ngx_queue_prev(q);
        bn = ngx_queue_data(q, ngx_http_shield_ban_node_t, queue);

        /* The window deadline is DERIVED from the caller's current `window`,
         * not read from the node. A reload that shortens ban_window would
         * otherwise leave already-touched nodes protected by a deadline
         * stamped under the old, longer policy -- they would read as live
         * past the point the running config says they lapse, and hold slab
         * space the current policy considers reclaimable. Deriving means the
         * live config always governs, and a reload takes effect at once. */
        if (bn->banned_until > now
            || ngx_http_shield_time_add_clamp(bn->window_start, window) > now)
        {
            /* Live: keep it, look at the next-older node. */
            q = prev;
            continue;
        }

        node = (ngx_rbtree_node_t *)
                   ((u_char *) bn - offsetof(ngx_rbtree_node_t, color));

        ngx_queue_remove(q);
        ngx_rbtree_delete(&ctx->sh->rbtree, node);
        ngx_slab_free_locked(ctx->shpool, node);
        evicted++;
        q = prev;
    }
}


ngx_int_t
ngx_http_shield_ban_is_banned_locked(ngx_http_shield_ban_ctx_t *ctx,
    ngx_uint_t hash, u_char *addr, u_char len, time_t now)
{
    ngx_http_shield_ban_node_t  *bn;

    bn = ngx_http_shield_ban_lookup(ctx, hash, addr, len);
    return (bn != NULL && bn->banned_until > now);
}


ngx_int_t
ngx_http_shield_ban_record_locked(ngx_http_shield_ban_ctx_t *ctx,
    ngx_uint_t hash, u_char *addr, u_char len, time_t now,
    ngx_uint_t count, time_t window, time_t ban_time)
{
    size_t                       size;
    ngx_rbtree_node_t           *node;
    ngx_http_shield_ban_node_t  *bn;

    /* Lookup-before-insert: we only ever ngx_rbtree_insert() a key that lookup
     * just proved absent, so the rbtree never holds two nodes for one address.
     * That invariant is why the insert helper's collision branch (which orders
     * equal-hash nodes and would otherwise duplicate an existing address) is
     * never reached for an already-present key. */
    bn = ngx_http_shield_ban_lookup(ctx, hash, addr, len);

    if (bn == NULL) {
        size = offsetof(ngx_rbtree_node_t, color)
             + sizeof(ngx_http_shield_ban_node_t);

        ngx_http_shield_ban_expire(ctx, now, window);

        node = ngx_slab_alloc_locked(ctx->shpool, size);
        if (node == NULL) {
            /* Out of slab space and nothing reclaimable: drop this hit. */
            return NGX_ERROR;
        }

        node->key = hash;
        bn = (ngx_http_shield_ban_node_t *) &node->color;
        bn->len = len;
        ngx_memcpy(bn->addr, addr, len);
        bn->hits = 0;
        bn->banned_until = 0;
        bn->window_start = now;

        ngx_rbtree_insert(&ctx->sh->rbtree, node);
        ngx_queue_insert_head(&ctx->sh->queue, &bn->queue);
    }

    /* Roll the window: if the current window has elapsed, start a fresh one.
     * This is a FIXED (tumbling) window, not a sliding one -- the count resets
     * wholesale rather than ageing out individual hits, so an attacker pacing
     * hits across a window boundary can stay under `count`. That is the
     * documented trade-off (README "Repeat-offender banning"): a true sliding
     * window needs per-hit timestamps, which this fixed-size node cannot hold.
     *
     * A still-active ban does not reset the window -- it just keeps extending
     * while the attacker keeps hitting, which is the intended behavior.
     *
     * `now < window_start` can only happen if the wall clock was stepped
     * backward (ngx_time() is wall-clock based). Treat that as a window reset
     * too, so a backward clock jump can never leave a stale window_start in the
     * future and quietly widen the hit-count leniency window. */
    if (now < bn->window_start
        || now - bn->window_start >= window)
    {
        bn->window_start = now;
        bn->hits = 0;
    }

    bn->hits++;

    if (bn->hits >= count) {
        bn->banned_until = ngx_http_shield_time_add_clamp(now, ban_time);
        /* Reset the counter so the ban is re-armed cleanly if it is ever
         * extended after expiry, rather than tripping again on the next hit. */
        bn->hits = 0;
        bn->window_start = now;
    }

    return NGX_OK;
}
