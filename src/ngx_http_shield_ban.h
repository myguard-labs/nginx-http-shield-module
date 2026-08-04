/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * ngx_http_shield_ban.h -- repeat-offender ban list in shared memory.
 *
 * The shared-memory state engine for shield_ban lives here, split out of the
 * HTTP module so it depends only on <ngx_core.h> (rbtree + slab + queue + time)
 * and never on <ngx_http.h>. That lets the eviction / fixed-window / ban-arm
 * logic be exercised by a direct-call unit harness (ci/t/ban_unit.c) with
 * synthetic addresses and a synthetic clock -- the path Test::Nginx cannot
 * reach because it drives a single loopback client with no clock control.
 *
 * The HTTP module owns everything request-shaped: extracting the peer address,
 * taking the shm lock, plumbing the location's count/window/bantime, and
 * logging a full zone. The functions here run under a lock the caller already
 * holds and take every input explicitly.
 */

#ifndef NGX_HTTP_SHIELD_BAN_H_INCLUDED_
#define NGX_HTTP_SHIELD_BAN_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>


/*
 * One per banned/tracked client address. Embedded in an rbtree node right after
 * the node's `color` byte (the ngx_rbtree/limit_req idiom), and threaded onto
 * an LRU queue so ngx_http_shield_ban_expire() can evict the oldest entries
 * when the slab is full. The rbtree is keyed on a CRC32 of the address bytes;
 * the full address is stored so hash collisions are resolved exactly.
 */
typedef struct {
    u_char        color;          /* aliases ngx_rbtree_node_t.color; the */
                                  /* tree rebalances by writing node->color, */
                                  /* so the embedded struct MUST expose that */
                                  /* byte first (the ngx_http_limit_req */
                                  /* idiom) -- otherwise color writes */
                                  /* clobber `queue`. */
    u_char        len;            /* address length (4 v4, 16 v6) */
    u_char        addr[16];       /* raw addr bytes, exact collision cmp */
    ngx_queue_t   queue;          /* LRU: most-recently-touched at head */
    time_t        window_start;   /* start of current hit-counting window. */
                                  /* The window END is DERIVED (window_start */
                                  /* + the caller's current ban_window), */
                                  /* never stored: a reload that shortens */
                                  /* `window` must not leave nodes carrying */
                                  /* a longer deadline stamped under the */
                                  /* old policy. */
    time_t        banned_until;   /* 0=not banned; else ban expiry, sec */
    ngx_uint_t    hits;           /* shield hits seen in current window */
} ngx_http_shield_ban_node_t;

/* Number of hit counters kept in shared memory, one per shield category.
 *
 * Deliberately NOT NGX_HTTP_SHIELD_CAT_N: that lives in
 * ngx_http_shield_patterns.h, which pulls in the whole signature corpus, and
 * this header must keep depending on <ngx_core.h> alone so the ban engine stays
 * unit-testable. 64 is the same bound the scanner's category bitmask already
 * enforces at compile time (the `NGX_HTTP_SHIELD_CAT_N <= 64` assert in
 * patterns.h), so a category that fits the scanner fits here. The module
 * static-asserts the two agree.
 */
#define NGX_HTTP_SHIELD_BAN_NCOUNTERS  64

typedef struct {
    ngx_rbtree_t       rbtree;
    ngx_rbtree_node_t  sentinel;
    ngx_queue_t        queue;     /* LRU list head over all ban nodes */

    /* Per-category hit totals since worker start, reported by
     * shield_ban_status. Monotonic; never reset except by a full restart (a
     * reload reuses the segment, so counts survive it -- which is what an
     * operator graphing them expects). Written under the slab mutex like
     * everything else here. */
    uint64_t           cat_hits[NGX_HTTP_SHIELD_BAN_NCOUNTERS];

    /* Totals that are not per-category: requests blocked, and bans armed. */
    uint64_t           blocked;   /* requests denied by shield (any cat) */
    uint64_t           bans;      /* ban arms, i.e. hits reaching threshold */

    /* Resumable eviction cursor: where the NEXT ngx_http_shield_ban_expire()
     * call starts its walk, instead of always restarting at the LRU tail.
     *
     * Rotating skipped live nodes to the head (the S30-1 fix) guarantees
     * progress only while nothing else reorders the queue. But ban_lookup()
     * re-heads a node on EVERY request, and is_banned() runs per request, so
     * ordinary traffic continuously undoes the rotation. With a live cluster
     * larger than SCAN at the tail and one stale node touched every round, the
     * walk never reaches that stale node -- 200 expire calls, zero reclaim
     * (S32-4). A cursor decouples reclaim progress from queue order entirely.
     *
     * INVARIANT: `cursor` is either &queue (the sentinel, meaning "start at the
     * tail") or points at the `queue` member of a LIVE node -- never at freed
     * slab memory. ngx_http_shield_ban_expire() maintains this by advancing off
     * a node before freeing it; ngx_http_shield_ban_lookup() re-inserts every
     * node it unlinks, so it cannot invalidate the cursor. A future path that
     * unlinks AND frees outside expire() would have to re-park the cursor.
     *
     * A queue pointer rather than a stored address on purpose: an address would
     * need an O(log n) re-lookup each call and is ambiguous once its node is
     * evicted, whereas a pointer is free to follow and merely has to be
     * maintained at the single site that frees.
     */
    ngx_queue_t       *cursor;

#ifdef NGX_TEST_HARNESS
    /* CI-only slab fault injection (see ngx_shield_probe_hooks.c).
     *
     * These live in SHARED memory rather than in a process global on purpose:
     * the request that arms the fault and the request that trips it may be
     * served by different workers, and a global would make the harness pass or
     * fail on which worker happened to answer. Tests currently pin
     * worker_processes 1, which would hide exactly that bug.
     *
     * nth: -1 = never fail (the ngx_label_autoconf convention), else fail the
     * nth slab allocation after arming. seen: allocations counted since.
     */
    ngx_int_t          fault_slab_nth;
    ngx_uint_t         fault_slab_seen;
#endif
} ngx_http_shield_ban_shctx_t;

typedef struct {
    ngx_http_shield_ban_shctx_t *sh;
    ngx_slab_pool_t             *shpool;
} ngx_http_shield_ban_ctx_t;


/*
 * Slab allocation for ban nodes.
 *
 * In a normal build this is ngx_slab_alloc_locked() and nothing else. Under
 * NGX_TEST_HARNESS it routes through a counter so a test can force the Nth
 * allocation to fail, which is the only way to reach the zone-full path in
 * ngx_http_shield_ban_record_locked() -- filling a real 1m zone would take
 * thousands of distinct source addresses the loopback harness cannot produce.
 */
#ifdef NGX_TEST_HARNESS
void *ngx_http_shield_ban_slab_alloc(ngx_http_shield_ban_ctx_t *ctx,
    size_t size);
#define ngx_shield_slab_alloc(ctx, size)                                      \
    ngx_http_shield_ban_slab_alloc(ctx, size)
#else
#define ngx_shield_slab_alloc(ctx, size)                                      \
    ngx_slab_alloc_locked((ctx)->shpool, size)
#endif


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
 * walk skips is ROTATED to the LRU head (see ngx_http_shield_ban_expire), so
 * the next call begins on nodes it has not examined yet. Reclaim therefore
 * makes progress across calls regardless of cluster size, while per-call work
 * stays bounded by SCAN. */
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
 * inside a live counting window). Bounded. Resumes from ctx->sh->cursor rather
 * than restarting at the tail, so reclaim progress does not depend on queue
 * order. Caller holds the shm lock. */
void ngx_http_shield_ban_expire(ngx_http_shield_ban_ctx_t *ctx, time_t now,
    time_t window);

/* Initialise the LRU + eviction cursor for a fresh shared segment. Zeroed
 * memory is NOT sufficient: the cursor must start at the queue sentinel, whose
 * address is only known once the queue head is placed. */
void ngx_http_shield_ban_shctx_init(ngx_http_shield_ban_shctx_t *sh);

/* Count one shield hit in category `cat` (and, if `blocked`, one denied
 * request) for the shield_ban_status report. Out-of-range `cat` is ignored
 * rather than trusted -- the counters are indexed by a value that ultimately
 * derives from scanner output, so the bound is enforced here at the single
 * write site. Caller holds the shm lock. */
void ngx_http_shield_ban_count_hit(ngx_http_shield_ban_ctx_t *ctx,
    ngx_uint_t cat, ngx_uint_t blocked);

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


/*
 * Select the RIGHTMOST comma-separated element of one X-Forwarded-For header
 * LINE and trim surrounding spaces/tabs, writing the result into *out as a
 * pointer into `value` (no copy, no allocation).
 *
 * Split out of ngx_http_shield_ban_addr() so this parse can be driven directly
 * by a fuzz target: it is the only part of ban keying that consumes
 * attacker-supplied bytes, and it took an ngx_http_request_t purely by
 * accident of where it was written. Walking the ->next header chain and
 * converting the token to an address stay on the request side, where a pool
 * and r->connection exist.
 *
 * Rightmost, not leftmost: XFF is append-only, so the leftmost entry is
 * whatever the client claimed. See ngx_http_shield_ban_addr() for the full
 * trust argument.
 *
 * `value` may be any byte string including empty; `len` 0 yields an empty
 * token. The result always satisfies out->data >= value and
 * out->data + out->len <= value + len.
 */
void ngx_http_shield_xff_last_token(u_char *value, size_t len, ngx_str_t *out);


#endif /* NGX_HTTP_SHIELD_BAN_H_INCLUDED_ */
