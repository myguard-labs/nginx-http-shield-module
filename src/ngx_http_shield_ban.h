/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * ngx_http_shield_ban.h -- repeat-offender ban list in shared memory.
 *
 * The shared-memory state engine for shield_ban lives here, split out of the
 * HTTP module so it depends only on <ngx_core.h> (rbtree + slab + queue + time)
 * and never on <ngx_http.h>. That lets the eviction / fixed-window / ban-arm
 * logic be exercised by a direct-call unit harness (t/ban_unit.c) with synthetic
 * addresses and a synthetic clock -- the path Test::Nginx cannot reach because
 * it drives a single loopback client with no clock control.
 *
 * The HTTP module owns everything request-shaped: extracting the peer address,
 * taking the shm lock, plumbing the location's count/window/bantime, and logging
 * a full zone. The functions here run under a lock the caller already holds and
 * take every input explicitly.
 */

#ifndef NGX_HTTP_SHIELD_BAN_H_INCLUDED_
#define NGX_HTTP_SHIELD_BAN_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>


/*
 * One per banned/tracked client address. Embedded in an rbtree node right after
 * the node's `color` byte (the ngx_rbtree/limit_req idiom), and threaded onto an
 * LRU queue so ngx_http_shield_ban_expire() can evict the oldest entries when
 * the slab is full. The rbtree is keyed on a CRC32 of the address bytes; the
 * full address is stored so hash collisions are resolved exactly.
 */
typedef struct {
    u_char        color;          /* aliases ngx_rbtree_node_t.color; the tree */
                                  /* rebalances by writing node->color, so the */
                                  /* embedded struct MUST expose that byte      */
                                  /* first (the ngx_http_limit_req idiom) --    */
                                  /* otherwise color writes clobber `queue`.    */
    u_char        len;            /* address length in bytes (4 v4, 16 v6)      */
    u_char        addr[16];       /* raw address bytes, for exact collision cmp */
    ngx_queue_t   queue;          /* LRU: most-recently-touched at head        */
    time_t        window_start;   /* start of the current hit-counting window.   */
                                  /* The window END is DERIVED (window_start +   */
                                  /* the caller's current ban_window), never     */
                                  /* stored: a reload that shortens `window`     */
                                  /* must not leave nodes carrying a longer      */
                                  /* deadline stamped under the old policy.      */
    time_t        banned_until;   /* 0 = not banned; else ban expiry (seconds) */
    ngx_uint_t    hits;           /* shield hits seen in the current window     */
} ngx_http_shield_ban_node_t;

typedef struct {
    ngx_rbtree_t       rbtree;
    ngx_rbtree_node_t  sentinel;
    ngx_queue_t        queue;     /* LRU list head over all ban nodes           */
} ngx_http_shield_ban_shctx_t;

typedef struct {
    ngx_http_shield_ban_shctx_t *sh;
    ngx_slab_pool_t             *shpool;
} ngx_http_shield_ban_ctx_t;


/* Eviction budgets for ngx_http_shield_ban_expire(): SCAN bounds how far the
 * LRU-tail walk looks in ONE call; EVICT bounds how many nodes that call frees
 * (the real per-request work cost).
 *
 * SCAN alone cannot guarantee reclaim, and raising it does not fix that. The
 * walk always restarts at the tail, so a cluster of live nodes LARGER than SCAN
 * parked there consumes the whole budget on skips forever and the zone never
 * reclaims, even with free-able nodes just head-ward -- new attackers then
 * cannot be recorded and the ban fails OPEN (S30-1, the third instance of this
 * class after S27-1 and the PR#50 shared-cap bug). Any constant bound is
 * defeated by a cluster that outgrows it, and banned nodes cluster by
 * construction: with the documented count=5 window=1m bantime=1h they stay live
 * 60x longer than counting nodes.
 *
 * The fix is not a bigger number but a moving start point: every live node the
 * walk skips is ROTATED to the LRU head (see ngx_http_shield_ban_expire), so the
 * next call begins on nodes it has not examined yet. Reclaim therefore makes
 * progress across calls regardless of cluster size, while per-call work stays
 * bounded by SCAN. */
#define NGX_HTTP_SHIELD_BAN_EXPIRE_SCAN   32
#define NGX_HTTP_SHIELD_BAN_EXPIRE_EVICT  4


/*
 * `now + delta`, clamped to the maximum signed time_t. A 32-bit time_t build
 * with a large ban_time/ban_window would otherwise overflow into a negative
 * (already-expired) or undefined value; on overflow we saturate at "effectively
 * forever". time_t is signed; derive its max without <limits.h>.
 */
time_t ngx_http_shield_time_add_clamp(time_t now, time_t delta);

/* rbtree comparator for equal-hash (collision) ordering. */
void ngx_http_shield_ban_rbtree_insert(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);

/* Find the ban node for this address, moving it to the LRU head on a hit.
 * Returns NULL if absent. Caller holds the shm lock. */
ngx_http_shield_ban_node_t *ngx_http_shield_ban_lookup(
    ngx_http_shield_ban_ctx_t *ctx, ngx_uint_t hash, u_char *addr, u_char len);

/* Reclaim slab space by evicting genuinely-stale LRU nodes (neither banned nor
 * inside a live counting window). Bounded. Caller holds the shm lock. */
void ngx_http_shield_ban_expire(ngx_http_shield_ban_ctx_t *ctx, time_t now,
    time_t window);

/* Is this address currently banned (banned_until > now)? Also refreshes LRU.
 * Caller holds the shm lock. */
ngx_int_t ngx_http_shield_ban_is_banned_locked(ngx_http_shield_ban_ctx_t *ctx,
    ngx_uint_t hash, u_char *addr, u_char len, time_t now);

/*
 * Record one hit: find-or-create the node, slide/reset the window, bump the
 * count, and arm the ban once hits reach `count`. Caller holds the shm lock.
 * Returns NGX_OK, or NGX_ERROR when the slab is full and nothing was
 * reclaimable (the caller logs; the ban is best-effort, never a correctness
 * gate). `now`, `count`, `window`, `ban_time` are the policy in effect.
 */
ngx_int_t ngx_http_shield_ban_record_locked(ngx_http_shield_ban_ctx_t *ctx,
    ngx_uint_t hash, u_char *addr, u_char len, time_t now,
    ngx_uint_t count, time_t window, time_t ban_time);


#endif /* NGX_HTTP_SHIELD_BAN_H_INCLUDED_ */
