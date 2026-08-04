/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * ngx_http_shield_ban.c -- shared-memory state engine for shield_ban.
 *
 * Split out of the HTTP module (see ngx_http_shield_ban.h) so it depends only
 * on <ngx_core.h> and can be unit-tested directly with synthetic addresses and
 * a synthetic clock. Every function here runs under a lock the caller holds.
 */

#include "ngx_http_shield_ban.h"


void
ngx_http_shield_xff_last_token(u_char *value, size_t len, ngx_str_t *out)
{
    u_char  *p, *start, *end;

    start = value;
    end = value + len;

    /* The LAST comma-separated element: a proxy appending to an existing line
     * puts what it saw at the end. Scanning backwards means a line with no
     * comma at all leaves `start` at the beginning, which is the whole value
     * and the correct single-element answer. */
    for (p = end; p > start; p--) {
        if (*(p - 1) == ',') {
            start = p;
            break;
        }
    }

    /* "a.b.c.d, e.f.g.h" leaves a leading space on every element but the
     * first. Both trims are bounded by `end`/`start`, so an all-whitespace or
     * empty token collapses to length 0 rather than walking off either side. */
    while (start < end && (*start == ' ' || *start == '\t')) {
        start++;
    }

    out->data = start;
    out->len = (size_t) (end - start);

    while (out->len > 0
           && (start[out->len - 1] == ' ' || start[out->len - 1] == '\t'))
    {
        out->len--;
    }
}


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
ngx_http_shield_ban_shctx_init(ngx_http_shield_ban_shctx_t *sh)
{
    ngx_queue_init(&sh->queue);

    /* Start at the sentinel = "begin at the LRU tail". Must be set explicitly:
     * the slab does not zero, and even zeroed memory would be a NULL cursor
     * rather than a valid sentinel pointer. */
    sh->cursor = &sh->queue;

    /* ngx_slab_alloc() does not zero either, so the counters would otherwise
     * start at whatever the segment last held and shield_status would report
     * garbage totals on a fresh zone. */
    ngx_memzero(sh->cat_hits, sizeof(sh->cat_hits));
    sh->blocked = 0;
    sh->bans = 0;
}


void
ngx_http_shield_ban_count_hit(ngx_http_shield_ban_ctx_t *ctx, ngx_uint_t cat,
    ngx_uint_t blocked)
{
    /* Bound-check rather than trust: `cat` comes from the scanner's category
     * enum, and a category added to patterns.h beyond the 64 the bitmask allows
     * would otherwise write past cat_hits[] into neighbouring shm. The module
     * static-asserts the two bounds agree, so this is belt-and-braces at the
     * one place that indexes the array -- cheap, and out of the hot path's way
     * (this runs only on a hit, not on every request). */
    if (cat < NGX_HTTP_SHIELD_BAN_NCOUNTERS) {
        ctx->sh->cat_hits[cat]++;
    }

    if (blocked) {
        ctx->sh->blocked++;
    }
}


void
ngx_http_shield_ban_expire(ngx_http_shield_ban_ctx_t *ctx, time_t now,
    time_t window)
{
    ngx_uint_t                   scanned, evicted, wrapped;
    ngx_queue_t                 *q, *prev;
    ngx_rbtree_node_t           *node;
    ngx_http_shield_ban_node_t  *bn;

    /* Walk from the LRU tail toward the head, evicting only nodes that are
     * genuinely stale -- neither actively banned nor inside a live counting
     * window. A node is skipped (not evicted) when either deadline is still in
     * the future.
     *
     * We must NOT stop at the first live node. The tail is LRU-oldest by
     * *touch* time, but "oldest touched" is not "soonest to expire": a
     * below-threshold node under a long window can be touched-older yet expire
     * later than a banned node under a short bantime. Evicting a
     * below-threshold node that still has a live window would let an attacker
     * defeat the ban by rotating source addresses to keep the zone at the
     * eviction margin -- no single IP ever accumulates enough hits to arm
     * (S27-1). So we scan past live nodes looking for a stale one.
     *
     * Two separate budgets, not one shared iteration cap. If a single "scan up
     * to N" cap counted skips and evictions together, a cluster of >=N live
     * nodes at the tail would consume the whole cap on skips and the call would
     * reclaim nothing even though stale nodes sit just past them. So SCAN
     * bounds how far we look and EVICT bounds how many we actually free.
     *
     * That split is still not sufficient on its own: a live cluster LARGER than
     * SCAN parked at the tail exhausts the scan budget on skips, and because
     * the walk restarts at the same tail every call, the zone can never reclaim
     * -- new attackers stop being recorded and the ban fails OPEN (S30-1).
     * Banned nodes form exactly such a cluster: they are only touched while
     * they keep sending, and under the documented count=5 window=1m bantime=1h
     * they stay live 60x longer than a counting node.
     *
     * The previous fix ROTATED every skipped live node to the LRU head, so the
     * next call would start on unexamined nodes. That works only while nothing
     * else reorders the queue -- and something does: ngx_http_shield_ban_lookup
     * re-heads a node on every hit, and is_banned() runs on EVERY request to a
     * shield_ban location. Ordinary traffic therefore continuously reshuffles
     * the very order the rotation relied on. With a live cluster larger than
     * SCAN at the tail and one stale node re-touched every round, the walk
     * never reaches the stale node: 200 expire calls, zero reclaim (S32-4).
     *
     * So progress no longer depends on queue order at all. A CURSOR in shctx
     * records where the last call stopped, and the next call RESUMES there
     * instead of restarting at the tail. Nodes the cursor has already passed
     * are not re-examined until it wraps, whatever traffic does to the ordering
     * in the meantime. Rotation is gone with it: skipping is a read again,
     * which also retires the S32-5 note about rotation dirtying shm under the
     * mutex.
     *
     * The cursor is a pointer INTO the queue, so it must never be left pointing
     * at freed memory. ONE rule keeps that true, and it is the store at the end
     * of this function: the loop advances q to `prev` BEFORE freeing a node, so
     * whatever q holds on exit is either a node this call did not free or the
     * queue sentinel (embedded in shctx, never freed). No separate fix-up on
     * the eviction path is needed, and none exists -- a guard there could never
     * be observed to fire, so it would be untestable dead weight.
     *
     * The other removal site, ngx_http_shield_ban_lookup(), re-inserts the node
     * it removes, so it cannot invalidate the cursor either. Any FUTURE path
     * that unlinks and frees a node outside this loop MUST re-park the cursor.
     *
     * Wrapping past the head stores the sentinel, i.e. "start at the tail
     * again", so the walk is cyclic and every node is eventually examined. */
    scanned = 0;
    evicted = 0;
    wrapped = 0;

    /* Resume where the last call stopped. The sentinel means "start at the
     * tail"; ngx_queue_last() of an empty queue is the sentinel too, so the
     * loop below simply does not run. */
    q = ctx->sh->cursor;

    if (q == ngx_queue_sentinel(&ctx->sh->queue)) {
        q = ngx_queue_last(&ctx->sh->queue);
        wrapped = 1;   /* already starting from the tail; nothing left
                        to wrap */
    }

    while (scanned < NGX_HTTP_SHIELD_BAN_EXPIRE_SCAN
           && evicted < NGX_HTTP_SHIELD_BAN_EXPIRE_EVICT)
    {
        if (q == ngx_queue_sentinel(&ctx->sh->queue)) {
            /* Ran off the head. The cursor removed the DEPENDENCE on queue
             * order, but without this it would still be SENSITIVE to it:
             * ban_lookup() re-heads any node on a hit, including the one the
             * cursor is parked on, so a call can resume near the head, run out
             * of queue, and return with most of its SCAN budget unspent. Wrap
             * to the tail and spend the remainder here instead of deferring it
             * to the next call.
             *
             * EFFICIENCY, not correctness: reclaim already completed without
             * this, because a call that ends at the sentinel still parks there
             * and the following call restarts from the tail. Measured on the
             * unit suite, calls ending at the sentinel with budget left over a
             * non-empty queue drop from 187/293 to 150/291. No test can fail on
             * its absence -- which is exactly why it is documented as a
             * throughput tweak rather than a guarantee.
             *
             * `wrapped` bounds it to ONE lap, so a queue with no evictable node
             * cannot spin: the second time we reach the sentinel we stop. */
            if (wrapped) {
                break;
            }

            wrapped = 1;
            q = ngx_queue_last(&ctx->sh->queue);
            continue;
        }

        scanned++;
        prev = ngx_queue_prev(q);
        bn = ngx_queue_data(q, ngx_http_shield_ban_node_t, queue);

        /* The window deadline is DERIVED from the caller's current `window`,
         * not read from the node. A reload that shortens ban_window would
         * otherwise leave already-touched nodes protected by a deadline
         * stamped under the old, longer policy -- they would read as live
         * past the point the running config says they lapse, and hold slab
         * space the current policy considers reclaimable. Deriving means the
         * live config always governs, and a reload takes effect at once.
         *
         * The two clocks are EXCLUSIVE, not OR-ed. An armed node is governed by
         * banned_until alone; only an unarmed (counting) node is governed by
         * its window. Deriving the deadline made window_start load-bearing for
         * eviction, but ban_record_locked still stamps `window_start = now`
         * when it arms -- there purely to reset the counter cleanly. OR-ing the
         * two therefore let that counter-hygiene write silently re-arm a SECOND
         * liveness clock, and the node's real lifetime became max(bantime,
         * window) instead of bantime: with count=1 window=1000 bantime=100 the
         * ban lapsed at t=100 but the node stayed unevictable until t=1100, 11x
         * bantime, on any config where window > bantime (nothing validates
         * against one). Checking banned_until FIRST and falling through to the
         * window only when the node is unarmed keeps each node under exactly
         * one deadline (S32-1).
         *
         * `now < bn->window_start` mirrors the same guard in record(): a
         * backward wall-clock step would otherwise leave a window_start in the
         * future, whose derived deadline reads live for the whole interval and
         * freezes reclaim until real time catches up. Treat it as stale, which
         * is what record() does with the counting window (S32-3). */
        if (bn->banned_until > now
            || (bn->banned_until == 0
                && now >= bn->window_start
                && ngx_http_shield_time_add_clamp(bn->window_start, window)
                       > now))
        {
            /* Live: skip it. A plain read -- the cursor, not the queue order,
             * is what carries progress to the next call now. */
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

    /* Park the cursor for the next call.
     *
     * `q` is where the walk stopped: a live node it has not yet judged, or the
     * sentinel if it ran off the head. Storing the sentinel makes the next call
     * wrap around to the tail, which is what keeps the walk cyclic -- without
     * the wrap the cursor would stick at the head and reclaim would stop after
     * one lap.
     *
     * Storing `q` unconditionally is safe: the loop only ever leaves q pointing
     * at a node it did NOT free (it advances to `prev` before freeing), or at
     * the sentinel. */
    ctx->sh->cursor = q;
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

        node = ngx_shield_slab_alloc(ctx, size);
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
     * A still-active ban is never re-recorded in practice: the request handler
     * short-circuits banned clients (is_banned -> 403) BEFORE it ever calls
     * record, so this window bookkeeping only runs for a not-currently-banned
     * client. Were record reached with a live ban, it would extend rather than
     * reset the window; that path is defensive, not the hot path.
     *
     * `now < window_start` can only happen if the wall clock was stepped
     * backward (ngx_time() is wall-clock based). Treat that as a window reset
     * too, so a backward clock jump can never leave a stale window_start in the
     * future and quietly widen the hit-count leniency window. */
    /* Retire a LAPSED ban as soon as we see one, INDEPENDENT of the window roll
     * below. banned_until is what marks a node "armed" for eviction purposes
     * (see ban_expire), so a stale past value keeps the node off the window
     * arm: an address that was banned once and came back would be counting
     * under a window that ban_expire no longer honours, and could be evicted
     * mid-count -- the eviction-bypass shape from S27-1, reachable a second
     * way.
     *
     * This must NOT be folded into the window-roll branch below. When ban_time
     * < window the ban lapses INSIDE the current window, so a return between
     * banned_until and window_start + window rolls nothing and would leave the
     * stale armed state in place for the rest of the window -- exactly the
     * interval in which the node is rebuilding its hit count and most needs the
     * window arm. A still-live ban is left alone: ban_expire keeps that node on
     * banned_until, which is the whole point of the S32-1 split. */
    if (bn->banned_until != 0 && bn->banned_until <= now) {
        bn->banned_until = 0;
    }

    if (now < bn->window_start
        || now - bn->window_start >= window)
    {
        bn->window_start = now;
        bn->hits = 0;
    }

    bn->hits++;

    if (bn->hits >= count) {
        /* Count the ARM, not the banned state: this branch is reached once per
         * ban (the handler short-circuits an already-banned client before
         * record() is ever called), so the total is "bans issued" rather than
         * "requests while banned". */
        ctx->sh->bans++;

        bn->banned_until = ngx_http_shield_time_add_clamp(now, ban_time);
        /* Reset the counter so the ban is re-armed cleanly if it is ever
         * extended after expiry, rather than tripping again on the next hit. */
        bn->hits = 0;
        bn->window_start = now;
    }

    return NGX_OK;
}


#ifdef NGX_TEST_HARNESS

/*
 * CI-only slab allocator wrapper. See the declaration in ngx_http_shield_ban.h.
 *
 * Counting happens only while a fault is armed, so an armed nth is relative to
 * the arming request and not to whatever traffic the server saw beforehand --
 * otherwise a rule's "fail the first allocation" would depend on how many
 * cases ran before it.
 *
 * Runs under the slab mutex, which the caller already holds.
 */
void *
ngx_http_shield_ban_slab_alloc(ngx_http_shield_ban_ctx_t *ctx, size_t size)
{
    if (ctx->sh->fault_slab_nth >= 0) {
        ctx->sh->fault_slab_seen++;

        if ((ngx_int_t) ctx->sh->fault_slab_seen == ctx->sh->fault_slab_nth) {
            return NULL;
        }
    }

    return ngx_slab_alloc_locked(ctx->shpool, size);
}

#endif /* NGX_TEST_HARNESS */
