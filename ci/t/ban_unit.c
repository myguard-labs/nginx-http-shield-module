/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * ban_unit.c -- direct-call unit harness for the shield_ban state engine.
 *
 * Test::Nginx cannot reach the interesting ban paths: it drives a single
 * loopback client (one node per zone -> the rbtree never grows past its root,
 * so the comparator and multi-node lookup never run) with no clock control (so
 * window elapse, ban expiry, and LRU eviction never fire). This harness calls
 * ngx_http_shield_ban_{lookup,record_locked,expire,is_banned_locked} directly
 * with SYNTHETIC addresses and a SYNTHETIC clock, exercising exactly those
 * paths -- most importantly the S27-1 invariant that a below-threshold node
 * with a LIVE counting window is never evicted to make room for another.
 *
 * The state engine lives in src/ngx_http_shield_ban.c (only <ngx_core.h>), so
 * we link it against nginx's real ngx_rbtree.c plus a malloc-backed fake slab
 * pool. No network, no nginx runtime, deterministic clock passed in per call.
 *
 * Build/run: bash t/run-ban-unit.sh   (needs a configured nginx tree in .build)
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "../../src/ngx_http_shield_ban.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ *
 * nginx runtime stubs. rbtree.c needs none of these at link time for
 * the symbols we call, but <ngx_core.h> declares ngx_cycle; provide it
 * so a future refactor that reaches for it is caught, not silently
 * mislinked.
 * ------------------------------------------------------------------ */
volatile ngx_cycle_t  *ngx_cycle;

/* ------------------------------------------------------------------ *
 * Fake slab pool. ngx_http_shield_ban_record_locked/expire call only
 * ngx_slab_alloc_locked and ngx_slab_free_locked; back them with plain
 * malloc/free. `fail_alloc` lets a test force the slab-full path.
 * ------------------------------------------------------------------ */
static int      fail_alloc = 0;
static size_t   live_allocs = 0;

void *
ngx_slab_alloc_locked(ngx_slab_pool_t *pool, size_t size)
{
    (void) pool;
    if (fail_alloc) {
        return NULL;
    }
    live_allocs++;
    return malloc(size);
}

/* Size of a ban allocation, so free() can poison the whole block. Mirrors what
 * ngx_http_shield_ban_record_locked() asks for. */
#define BAN_ALLOC_SIZE                                                       \
    (offsetof(ngx_rbtree_node_t, color) + sizeof(ngx_http_shield_ban_node_t))

void
ngx_slab_free_locked(ngx_slab_pool_t *pool, void *p)
{
    (void) pool;
    if (p) {
        live_allocs--;
        /* POISON before releasing. A real slab hands the block to another
         * allocation and its queue links stop being followable; plain free()
         * leaves them intact, so a dangling pointer into a freed node keeps
         * "working" and a use-after-free reads as a pass. Poisoning makes any
         * such deref land on 0xdb... instead -- which segfaults, or trips ASan,
         * deterministically rather than by luck. */
        memset(p, 0xdb, BAN_ALLOC_SIZE);
        free(p);
    }
}

/* ------------------------------------------------------------------ *
 * Test scaffolding.
 * ------------------------------------------------------------------ */
static int tests_run = 0;
static int tests_failed = 0;

#define OK(cond, msg)                                                        \
    do {                                                                     \
        tests_run++;                                                         \
        if (cond) {                                                         \
            printf("ok %d - %s\n", tests_run, msg);                          \
        } else {                                                            \
            tests_failed++;                                                  \
            printf("not ok %d - %s\n", tests_run, msg);                      \
        }                                                                    \
    } while (0)

static ngx_http_shield_ban_shctx_t  g_sh;
static ngx_http_shield_ban_ctx_t    g_ctx;

static void
ctx_reset(void)
{
    ngx_rbtree_init(&g_sh.rbtree, &g_sh.sentinel,
                    ngx_http_shield_ban_rbtree_insert);
    ngx_http_shield_ban_shctx_init(&g_sh);   /* queue + eviction cursor */
    g_ctx.sh = &g_sh;
    g_ctx.shpool = NULL;     /* fake slab ignores the pool arg */
    fail_alloc = 0;
    live_allocs = 0;
}

/* Free every node still in the tree (via the LRU queue) so a test does not
 * leak into the next. Uses the same offset trick the engine does. */
static void
ctx_free_all(void)
{
    ngx_queue_t                 *q;
    ngx_http_shield_ban_node_t  *bn;
    ngx_rbtree_node_t           *node;

    while (!ngx_queue_empty(&g_sh.queue)) {
        q = ngx_queue_head(&g_sh.queue);
        bn = ngx_queue_data(q, ngx_http_shield_ban_node_t, queue);
        node = (ngx_rbtree_node_t *)
                   ((u_char *) bn - offsetof(ngx_rbtree_node_t, color));
        ngx_queue_remove(q);
        ngx_rbtree_delete(&g_sh.rbtree, node);
        ngx_slab_free_locked(NULL, node);
    }

    /* Every node is gone, so any cursor still parked on one now dangles. Park
     * it back on the sentinel. ctx_reset() would do this at the start of the
     * next test, but not every test calls free_all then reset in that order. */
    g_sh.cursor = &g_sh.queue;
}

/* Convenience: record one hit for a synthetic (hash, addr) with a policy. */
static ngx_int_t
hit(ngx_uint_t hash, u_char *addr, u_char len, time_t now,
    ngx_uint_t count, time_t window, time_t ban_time)
{
    return ngx_http_shield_ban_record_locked(&g_ctx, hash, addr, len, now,
                                             count, window, ban_time);
}

static ngx_int_t
banned(ngx_uint_t hash, u_char *addr, u_char len, time_t now)
{
    return ngx_http_shield_ban_is_banned_locked(&g_ctx, hash, addr, len, now);
}


/* ================================================================== *
 * Tests
 * ================================================================== */

/* A single address reaches the threshold and is banned; the ban holds until
 * banned_until and lapses after. */
static void
test_ban_arms_and_expires(void)
{
    u_char a4[4] = { 10, 0, 0, 1 };

    ctx_reset();

    OK(hit(0x1111, a4, 4, 100, 3, 60, 600) == NGX_OK, "hit1 ok");
    OK(!banned(0x1111, a4, 4, 100), "not banned after 1 hit");
    hit(0x1111, a4, 4, 101, 3, 60, 600);
    OK(!banned(0x1111, a4, 4, 101), "not banned after 2 hits");
    hit(0x1111, a4, 4, 102, 3, 60, 600);
    OK(banned(0x1111, a4, 4, 102), "banned after 3rd hit");
    OK(banned(0x1111, a4, 4, 700), "ban still holds just before expiry");
    OK(!banned(0x1111, a4, 4, 703), "ban lapses after banned_until");

    ctx_free_all();
}

/* Hits spread past the window never accumulate to a ban (window slides). */
static void
test_window_slides(void)
{
    u_char a4[4] = { 10, 0, 0, 2 };

    ctx_reset();

    hit(0x2222, a4, 4, 100, 3, 60, 600);   /* hits=1 */
    hit(0x2222, a4, 4, 130, 3, 60, 600);   /* hits=2 */
    /* 70s after window_start -> window resets, hits back to 1 */
    hit(0x2222, a4, 4, 170, 3, 60, 600);   /* hits=1 */
    hit(0x2222, a4, 4, 175, 3, 60, 600);   /* hits=2 */
    OK(!banned(0x2222, a4, 4, 175), "no ban when hits straddle a window reset");

    ctx_free_all();
}

/* Backward clock step resets the window rather than widening leniency. */
static void
test_backward_clock_resets_window(void)
{
    u_char a4[4] = { 10, 0, 0, 3 };

    ctx_reset();

    hit(0x3333, a4, 4, 1000, 3, 60, 600);      /* window_start=1000 hits=1 */
    hit(0x3333, a4, 4,  500, 3, 60, 600);      /* now<window_start -> reset, hits=1 */
    hit(0x3333, a4, 4,  501, 3, 60, 600);      /* hits=2 */
    OK(!banned(0x3333, a4, 4, 501), "backward clock reset kept count low");

    ctx_free_all();
}

/*
 * S27-1 core: two DISTINCT addresses in a zone under eviction pressure. The
 * expire walk must not drop addr A's live below-threshold window to make room
 * for addr B -- otherwise alternating sources defeat the ban.
 *
 * We force eviction by failing the slab alloc only when we WANT to prove a node
 * survived: instead, we call expire() directly with a `now` inside both windows
 * and assert both nodes remain. A stale node (window+ban both elapsed) IS
 * evicted.
 */
static void
test_expire_preserves_live_window(void)
{
    u_char a[4] = { 10, 0, 0, 10 };
    u_char b[4] = { 10, 0, 0, 11 };

    ctx_reset();

    /* Two below-threshold nodes, distinct hashes so both live in the tree. */
    hit(0xAAAA, a, 4, 100, 5, 60, 600);   /* A: window [100,160) */
    hit(0xBBBB, b, 4, 105, 5, 60, 600);   /* B: window [105,165) */

    /* Expire at t=150: both windows still live -> nothing evicted. */
    ngx_http_shield_ban_expire(&g_ctx, 150, 60);
    OK(ngx_http_shield_ban_lookup(&g_ctx, 0xAAAA, a, 4) != NULL,
       "A survives expire while its window is live");
    OK(ngx_http_shield_ban_lookup(&g_ctx, 0xBBBB, b, 4) != NULL,
       "B survives expire while its window is live");
    OK(live_allocs == 2, "both nodes still allocated");

    ctx_free_all();
}

/*
 * S30-5: a reload that SHORTENS ban_window must take effect immediately.
 * The window deadline is derived from window_start + the caller's current
 * window, never stamped into the node, so a node recorded under a long window
 * becomes reclaimable as soon as the shorter policy says its window lapsed.
 * Stamping the deadline at write time left such nodes reading "live" -- and
 * holding slab space -- long past what the running config allowed.
 */
static void
test_expire_honours_shortened_window_after_reload(void)
{
    u_char a[4] = { 10, 0, 0, 30 };

    ctx_reset();

    /* Recorded under a 600s window: under the OLD policy live until t=700. */
    hit(0xD001, a, 4, 100, 5, 600, 600);

    /* Reload shrinks ban_window to 60s. At t=200 the node's window
     * (100 + 60 = 160) has lapsed under the NEW policy -> reclaimable. */
    ngx_http_shield_ban_expire(&g_ctx, 200, 60);
    OK(ngx_http_shield_ban_lookup(&g_ctx, 0xD001, a, 4) == NULL,
       "shortened window after reload makes the node reclaimable at once");
    OK(live_allocs == 0, "slab freed under the new policy");

    ctx_free_all();
}

/*
 * The mirror case: a reload that LENGTHENS ban_window protects a node that the
 * old, shorter policy would have reclaimed. Same derivation, opposite sign.
 */
static void
test_expire_honours_lengthened_window_after_reload(void)
{
    u_char a[4] = { 10, 0, 0, 31 };

    ctx_reset();

    /* Recorded under a 60s window: under the OLD policy stale from t=160. */
    hit(0xD002, a, 4, 100, 5, 60, 600);

    /* Reload grows ban_window to 600s -> at t=200 the node is live again. */
    ngx_http_shield_ban_expire(&g_ctx, 200, 600);
    OK(ngx_http_shield_ban_lookup(&g_ctx, 0xD002, a, 4) != NULL,
       "lengthened window after reload keeps the node live");
    OK(live_allocs == 1, "node retained under the new policy");

    ctx_free_all();
}

/*
 * S32-1: an ARMED node is governed by banned_until ALONE, never by the derived
 * window. ban_record_locked stamps `window_start = now` when it arms (counter
 * hygiene), so while the two clocks were OR-ed that write re-armed a second
 * liveness deadline and the node's real lifetime became max(bantime, window).
 * The repro config is the one from the audit: count=1 window=1000 bantime=100.
 * The ban lapses at t=200; before the fix the node stayed unevictable until
 * t=1101, 11x bantime.
 */
static void
test_expire_armed_node_ignores_window(void)
{
    u_char a[4] = { 10, 0, 0, 40 };

    ctx_reset();

    /* count=1 -> this single hit arms immediately. window (1000) >> bantime. */
    hit(0xD100, a, 4, 100, 1, 1000, 100);

    /* Still banned at t=150: banned_until (200) governs, node must be kept. */
    ngx_http_shield_ban_expire(&g_ctx, 150, 1000);
    OK(ngx_http_shield_ban_lookup(&g_ctx, 0xD100, a, 4) != NULL,
       "armed node kept while banned_until is live");

    /* Ban lapsed at t=200. The derived window would say live until t=1100,
     * but an armed node is not governed by it -> reclaim at bantime. */
    ngx_http_shield_ban_expire(&g_ctx, 250, 1000);
    OK(ngx_http_shield_ban_lookup(&g_ctx, 0xD100, a, 4) == NULL,
       "lapsed ban reclaimed at banned_until, not at window_start+window");
    OK(live_allocs == 0, "slab freed at bantime, not at max(bantime, window)");

    ctx_free_all();
}

/*
 * S32-1 companion: retiring a lapsed ban must not cost the node its window
 * protection. Once an address has been banned, banned_until stays non-zero
 * until the window rolls; if it were left stale forever the node would never
 * again qualify for the window arm and could be evicted mid-count -- the S27-1
 * eviction bypass, reachable a second way.
 */
static void
test_reban_after_lapse_keeps_window_protection(void)
{
    u_char a[4] = { 10, 0, 0, 41 };

    ctx_reset();

    /* Banned at t=100, ban lapses at t=200. */
    hit(0xD101, a, 4, 100, 1, 60, 100);

    /* At t=300 the attacker returns: window rolls, the lapsed ban is retired
     * and this hit counts under a fresh window [300,360). count=5 -> unarmed. */
    hit(0xD101, a, 4, 300, 5, 60, 100);

    /* Mid-window: the node is counting and must be protected by the window
     * arm again, exactly as a never-banned node would be. */
    ngx_http_shield_ban_expire(&g_ctx, 330, 60);
    OK(ngx_http_shield_ban_lookup(&g_ctx, 0xD101, a, 4) != NULL,
       "re-counting node after a lapsed ban is protected by its window");

    /* And once THAT window lapses it is stale like any other. */
    ngx_http_shield_ban_expire(&g_ctx, 400, 60);
    OK(live_allocs == 0, "reclaimed once the fresh window lapses");

    ctx_free_all();
}

/*
 * S32-3: expire() mirrors record()'s backward-clock guard. A wall clock stepped
 * backward leaves window_start in the future; deriving a deadline from it reads
 * live for the whole interval and freezes reclaim until real time catches up.
 */
static void
test_expire_backward_clock_does_not_freeze_reclaim(void)
{
    u_char a[4] = { 10, 0, 0, 42 };

    ctx_reset();

    /* Recorded at t=1000, unarmed (count=5, one hit). */
    hit(0xD102, a, 4, 1000, 5, 60, 600);

    /* Clock steps back to t=100: window_start (1000) is now in the future.
     * Treat as stale rather than deriving a deadline of 1060 > 100. */
    ngx_http_shield_ban_expire(&g_ctx, 100, 60);
    OK(ngx_http_shield_ban_lookup(&g_ctx, 0xD102, a, 4) == NULL,
       "future window_start treated as stale, reclaim not frozen");
    OK(live_allocs == 0, "slab freed after backward clock step");

    ctx_free_all();
}


/*
 * S32-1 follow-up (CodeRabbit, PR #62): the lapse-retirement must not be gated
 * on the window roll. When ban_time < window the ban lapses INSIDE the current
 * window, so a returning address between banned_until and window_start + window
 * rolls nothing -- and if the stale armed state survived, ban_expire would deny
 * that node the window arm for the rest of the window, exactly while it is
 * rebuilding its hit count. That is the S27-1 eviction bypass a second way.
 */
static void
test_lapsed_ban_retired_before_window_rollover(void)
{
    u_char a[4] = { 10, 0, 0, 99 };

    ctx_reset();

    /* window=1000 >> ban_time=100. count=1 -> armed at once, lapses at t=200. */
    hit(0xD999, a, 4, 100, 1, 1000, 100);

    /* Return at t=300: the ban has lapsed but the window [100,1100) has NOT
     * rolled, so this hit counts under the ORIGINAL window. */
    hit(0xD999, a, 4, 300, 5, 1000, 100);

    /* Counting under a live window -> must be protected by the window arm. */
    ngx_http_shield_ban_expire(&g_ctx, 350, 1000);
    OK(ngx_http_shield_ban_lookup(&g_ctx, 0xD999, a, 4) != NULL,
       "counting node protected after a ban lapse, before window rollover");

    /* And still stale once that window finally lapses. */
    ngx_http_shield_ban_expire(&g_ctx, 1200, 1000);
    OK(live_allocs == 0, "reclaimed once the original window lapses");

    ctx_free_all();
}

/* A genuinely stale node (window + ban both elapsed) IS reclaimed by expire. */
static void
test_expire_reclaims_stale(void)
{
    u_char a[4] = { 10, 0, 0, 20 };

    ctx_reset();

    hit(0xCCCC, a, 4, 100, 5, 60, 600);   /* window [100,160), not banned */

    /* At t=200 the window has lapsed and it was never banned -> stale. */
    ngx_http_shield_ban_expire(&g_ctx, 200, 60);
    OK(ngx_http_shield_ban_lookup(&g_ctx, 0xCCCC, a, 4) == NULL,
       "stale node reclaimed by expire");
    OK(live_allocs == 0, "slab freed");

    ctx_free_all();
}

/*
 * S27-1 end to end: an attacker rotates source addresses to keep the zone at
 * the eviction margin. Each new address triggers ban_expire (via the create
 * path) but must NOT evict a previously-seen address whose window is still
 * live, so a repeat visitor still accumulates hits toward a ban.
 */
static void
test_rotation_does_not_defeat_ban(void)
{
    u_char victim[4] = { 10, 0, 0, 30 };
    u_char rot[4]    = { 10, 0, 0, 0 };
    int    i;

    ctx_reset();

    /* Victim hits twice (threshold 3) within its window. */
    hit(0xD000, victim, 4, 100, 3, 300, 600);
    hit(0xD000, victim, 4, 101, 3, 300, 600);

    /* Attacker rotates 8 fresh addresses; each create runs expire(). If expire
     * dropped the victim's live below-threshold node, the 3rd victim hit would
     * start a fresh node at hits=1 and never ban. */
    for (i = 0; i < 8; i++) {
        rot[3] = (u_char) (100 + i);
        hit((ngx_uint_t) (0xE000 + i), rot, 4, 102 + i, 3, 300, 600);
    }

    /* Victim's 3rd hit inside the same window -> must arm the ban. */
    hit(0xD000, victim, 4, 150, 3, 300, 600);
    OK(banned(0xD000, victim, 4, 150),
       "victim still bans despite address rotation (S27-1)");

    ctx_free_all();
}

/*
 * Progress past a cluster of live nodes at the LRU TAIL. If the eviction walk
 * bounded skips and evictions with one shared cap, N (> that cap) live nodes at
 * the tail would starve the cap before reaching a stale node just head-ward --
 * and since each call restarts at the tail, the zone could never reclaim despite
 * free-able space (CodeRabbit PR#50). Separate SCAN (how far we look) from EVICT
 * (how many we free) fixes it.
 *
 * Setup so the LIVE cluster is tail-ward of the stale node: insert the live
 * nodes FIRST (each new head-insert pushes earlier ones toward the tail), so the
 * first-inserted live node is the LRU tail; insert the stale node LAST so it is
 * at the head. The tail-to-head walk must skip the whole live cluster (more than
 * EVICT nodes) to reach and free the stale node.
 */
/*
 * S30-7 / S30-1: the same shape, but with a live tail cluster LARGER than SCAN.
 *
 * The existing test above uses n_live = EVICT + 2, deliberately "< SCAN", so it
 * can never observe the case where the cluster itself exhausts the scan budget.
 * A constant scan bound is defeated as soon as the cluster outgrows it: the walk
 * restarts at the same tail every call, burns all SCAN steps on live nodes, and
 * reclaims nothing even though stale nodes sit just head-ward. New addresses can
 * then never be recorded -- the ban fails OPEN, which is the S27-1 outcome by a
 * different route.
 *
 * Under the README's own example (count=5 window=1m bantime=1h) banned nodes
 * stay live 60x longer than counting ones, so a >SCAN live cluster is routine
 * rather than adversarial.
 */
static void
test_expire_progresses_past_oversized_live_cluster(void)
{
    u_char stale[4] = { 10, 0, 1, 80 };
    u_char live[4]  = { 10, 1, 0, 0 };
    int    i;
    int    n_live = NGX_HTTP_SHIELD_BAN_EXPIRE_SCAN + 8;   /* > SCAN */

    ctx_reset();

    /* Live cluster first -> occupies the LRU tail. Banned for a long time, so
     * every one of them is genuinely live and must not be evicted. */
    for (i = 0; i < n_live; i++) {
        live[2] = (u_char) (i >> 8);
        live[3] = (u_char) (i & 0xff);
        /* count=1 -> armed immediately, banned_until = 500 + 36000. */
        hit((ngx_uint_t) (0xE000 + i), live, 4, 500, 1, 60, 36000);
    }

    /* One genuinely stale node at the head (window lapsed, never banned). */
    hit(0xEFFF, stale, 4, 100, 5, 10, 600);

    /* At t=600 the stale node is reclaimable but sits n_live (> SCAN) nodes
     * head-ward of the tail, so ONE call cannot reach it. The real caller runs
     * expire() once per recorded hit, and each call RESUMES from the cursor
     * where the last one stopped, so a bounded number of calls must reach the
     * stale node. Without the cursor every call rescans the same tail and this
     * loop never reclaims (S30-1, later S32-4). Generous headroom, then assert
     * progress. */
    for (i = 0; i < 16 && live_allocs > (size_t) n_live; i++) {
        ngx_http_shield_ban_expire(&g_ctx, 600, 10);
    }
    OK(ngx_http_shield_ban_lookup(&g_ctx, 0xEFFF, stale, 4) == NULL,
       "reclaim progresses past a live cluster LARGER than SCAN");
    OK(live_allocs == (size_t) n_live, "oversized live cluster fully retained");

    ctx_free_all();
}

/*
 * S32-4: reclaim must not depend on LRU order, because ordinary traffic
 * rewrites that order continuously.
 *
 * This is the exact shape that defeated the S30-1 rotation fix. Rotation moved
 * every skipped live node to the LRU head so the next call would start on fresh
 * ground -- but ngx_http_shield_ban_lookup() ALSO moves a node to the head, and
 * is_banned() calls it on every request to a shield_ban location. So a client
 * that keeps touching one node re-heads it between expire() calls and undoes
 * the rotation's progress.
 *
 * Here: a live cluster larger than SCAN sits at the tail, one stale node is
 * reclaimable, and that stale node is TOUCHED ONCE PER ROUND (via lookup, which
 * is what a real request does). Under rotation the walk restarted at the tail
 * every call, spent its whole scan budget on the live cluster, and never
 * reached the stale node: measured 200 calls, zero reclaim. With a resumable
 * cursor the walk picks up where it stopped regardless of the reshuffling, so
 * the stale node is reached in a bounded number of rounds.
 *
 * Negative control for this test: revert expire() to start at
 * ngx_queue_last() every call and it fails -- live_allocs never drops.
 */
static void
test_expire_progresses_despite_per_round_touch(void)
{
    u_char stale[4] = { 10, 0, 2, 90 };
    u_char live[4]  = { 10, 2, 0, 0 };
    int    i;
    int    n_live = NGX_HTTP_SHIELD_BAN_EXPIRE_SCAN + 8;   /* > SCAN */

    ctx_reset();

    /* Live cluster first -> occupies the LRU tail; banned long past t=600. */
    for (i = 0; i < n_live; i++) {
        live[2] = (u_char) (i >> 8);
        live[3] = (u_char) (i & 0xff);
        hit((ngx_uint_t) (0xF000 + i), live, 4, 500, 1, 60, 36000);
    }

    /* One stale node: window lapsed at t=110, never banned, so at t=600 it is
     * genuinely evictable no matter how recently it was TOUCHED. Touching
     * changes LRU position only -- not liveness. */
    hit(0xFFFE, stale, 4, 100, 5, 10, 600);

    for (i = 0; i < 64 && live_allocs > (size_t) n_live; i++) {
        /* The per-round touch: re-heads the stale node exactly the way a real
         * request's is_banned() would, right before the eviction pass. */
        ngx_http_shield_ban_lookup(&g_ctx, 0xFFFE, stale, 4);
        ngx_http_shield_ban_expire(&g_ctx, 600, 10);
    }

    OK(ngx_http_shield_ban_lookup(&g_ctx, 0xFFFE, stale, 4) == NULL,
       "reclaim progresses although the stale node is touched every round"
       " (S32-4)");
    OK(live_allocs == (size_t) n_live,
       "per-round-touch case retains the whole live cluster");

    ctx_free_all();
}


/*
 * The cursor is a raw pointer into the LRU, so the node it points at must never
 * be freed underneath it. Eviction is the only path that unlinks-and-frees, and
 * it keeps the invariant by advancing `q` to `prev` BEFORE ngx_slab_free_locked(),
 * so the value parked in ctx->sh->cursor on exit is always a node this call did
 * not free (or the sentinel). There is no separate fix-up helper -- one was
 * prototyped and dropped precisely because that store already masks it, which
 * made it impossible to observe firing.
 *
 * Drive many rounds over a population that is entirely evictable, so the cursor
 * repeatedly lands on nodes that the very next call frees. A dangling cursor
 * would be dereferenced as a node on the following call -- caught here by ASan
 * in the sanitizer CI leg, and by the final "everything reclaimed" assertion in
 * a plain build (the fake slab poisons freed blocks to 0xdb, so a walk into
 * freed memory cannot quietly keep working).
 */
static void
test_cursor_survives_eviction_of_its_node(void)
{
    u_char a[4] = { 10, 3, 0, 0 };
    int    i;
    int    n = NGX_HTTP_SHIELD_BAN_EXPIRE_SCAN * 3;

    ctx_reset();

    for (i = 0; i < n; i++) {
        a[2] = (u_char) (i >> 8);
        a[3] = (u_char) (i & 0xff);
        /* Short window, never banned -> all stale well before t=5000. */
        hit((ngx_uint_t) (0x11000 + i), a, 4, 1000, 5, 10, 600);
    }

    /* EVICT caps each call, so this needs several rounds; every round parks the
     * cursor on a node a later round frees. */
    for (i = 0; i < n + 16 && live_allocs > 0; i++) {
        ngx_http_shield_ban_expire(&g_ctx, 5000, 10);
    }

    OK(live_allocs == 0,
       "cursor stays valid across eviction of the node it points at");

    ctx_free_all();
}



/*
 * S32-4 under the harshest reordering: EVERY live node re-headed every round.
 *
 * ban_lookup() re-heads a node on each hit, including whichever node the cursor
 * parked on, so a busy proxy continuously reshuffles the queue under the walk.
 * Reclaim must still finish. This is the property the cursor buys and the
 * rotation approach did not (S32-4).
 *
 * NB this does NOT isolate the wrap-within-one-call branch in expire(): reclaim
 * completes with or without it, because a call that ends at the sentinel parks
 * there and the next call restarts from the tail. The wrap is a measured
 * throughput tweak (fewer calls returning with unspent budget), not a
 * correctness guarantee -- see the comment at that branch. Do not add an
 * assertion here claiming otherwise.
 */
static void
test_expire_wraps_within_one_call(void)
{
    u_char live[4]  = { 10, 4, 0, 0 };
    u_char stale[4] = { 10, 5, 0, 0 };
    int    i;
    /* Enough live nodes that ONE call cannot walk past them: the walk burns its
     * whole SCAN budget and parks the cursor mid-cluster. */
    int    n_live = NGX_HTTP_SHIELD_BAN_EXPIRE_SCAN + 4;
    int    n_stale = 4;

    ctx_reset();

    /* Stale nodes first -> they end up nearest the TAIL. */
    for (i = 0; i < n_stale; i++) {
        stale[3] = (u_char) i;
        hit((ngx_uint_t) (0x31000 + i), stale, 4, 100, 5, 10, 600);
    }
    /* Then the live cluster -> nearer the head than the stale ones. */
    for (i = 0; i < n_live; i++) {
        live[2] = (u_char) (i >> 8);
        live[3] = (u_char) (i & 0xff);
        hit((ngx_uint_t) (0x32000 + i), live, 4, 500, 1, 60, 36000);
    }

    /* First call: starts at the tail, frees up to EVICT stale nodes, parks. */
    ngx_http_shield_ban_expire(&g_ctx, 5000, 10);

    /* Now drive rounds where EVERY live node is touched each round, which is
     * what a busy proxy does. That keeps re-heading nodes -- including whichever
     * one the cursor parked on -- so a cursor that cannot wrap within a call
     * repeatedly resumes near the head and reclaims nothing. */
    for (i = 0; i < 64 && live_allocs > (size_t) n_live; i++) {
        int j;
        for (j = 0; j < n_live; j++) {
            live[2] = (u_char) (j >> 8);
            live[3] = (u_char) (j & 0xff);
            ngx_http_shield_ban_lookup(&g_ctx, (ngx_uint_t) (0x32000 + j),
                                       live, 4);
        }
        ngx_http_shield_ban_expire(&g_ctx, 5000, 10);
    }

    OK(live_allocs == (size_t) n_live,
       "all stale nodes reclaimed despite every live node being re-headed");

    ctx_free_all();
}


static void
test_expire_progresses_past_live_cluster(void)
{
    u_char stale[4] = { 10, 0, 0, 80 };
    u_char live[4]  = { 10, 0, 0, 0 };
    int    i;
    int    n_live = NGX_HTTP_SHIELD_BAN_EXPIRE_EVICT + 2;   /* > EVICT, < SCAN */

    ctx_reset();

    /* Live cluster first -> occupies the LRU tail (long window, all live @600).
     *
     * Inserted at t=100, BEFORE the stale node, so the clock only moves forward
     * across this setup. Ordering matters: creating a node runs ban_expire()
     * with the creating call's `now`, and expire() treats a window_start in the
     * FUTURE as stale (the S32-3 backward-clock guard). Stamping the cluster at
     * t=500 and then inserting the stale node at t=100 would step the clock
     * backward and let that insert reclaim cluster nodes before the assertion
     * below ever runs. */
    for (i = 0; i < n_live; i++) {
        live[3] = (u_char) (1 + i);
        /* count=1 -> armed immediately, banned_until = 100 + 36000. */
        hit((ngx_uint_t) (0xF100 + i), live, 4, 100, 1, 60, 36000);
    }
    /* Stale node last -> at the head, and never banned (count=5, one hit) so it
     * is governed by its window alone. */
    hit(0xF000, stale, 4, 400, 5, 10, 600);

    /* The walk starts at the tail (first live node), must skip all n_live live
     * nodes (> EVICT) and still reach the stale head node and free it.
     *
     * The cluster is LRU-OLDER (touched t=100) than the stale node (t=400) yet
     * expires much later -- that inversion is the point: "oldest touched" is not
     * "soonest to expire", so the walk cannot stop at the first live node it
     * meets. At t=2400 the cluster is held by its ban (until 36100) while the
     * stale node's derived window [400,2400) has just lapsed. */
    ngx_http_shield_ban_expire(&g_ctx, 2400, 2000);
    OK(ngx_http_shield_ban_lookup(&g_ctx, 0xF000, stale, 4) == NULL,
       "eviction makes progress: stale node freed past a live tail cluster");
    OK(live_allocs == (size_t) n_live, "all live cluster nodes retained");

    ctx_free_all();
}

/* Hash collision: two different addresses sharing one hash must stay distinct
 * (exercises the comparator + exact-address resolution in lookup). */
static void
test_hash_collision_distinct(void)
{
    u_char a[4] = { 10, 0, 0, 40 };
    u_char b[4] = { 10, 0, 0, 41 };

    ctx_reset();

    hit(0x5555, a, 4, 100, 3, 60, 600);
    hit(0x5555, b, 4, 100, 3, 60, 600);   /* same hash, different addr */

    OK(ngx_http_shield_ban_lookup(&g_ctx, 0x5555, a, 4) != NULL, "collision A present");
    OK(ngx_http_shield_ban_lookup(&g_ctx, 0x5555, b, 4) != NULL, "collision B present");
    OK(live_allocs == 2, "two distinct nodes for one hash");

    /* Ban A only; B must stay unbanned. */
    hit(0x5555, a, 4, 101, 3, 60, 600);
    hit(0x5555, a, 4, 102, 3, 60, 600);
    OK(banned(0x5555, a, 4, 102), "collision A banned");
    OK(!banned(0x5555, b, 4, 102), "collision B not banned (distinct state)");

    ctx_free_all();
}

/* IPv4 (4-byte) and IPv6 (16-byte) keys coexist and stay distinct. */
static void
test_ipv4_ipv6_distinct(void)
{
    u_char v4[4]  = { 10, 0, 0, 50 };
    u_char v6[16] = { 0x20, 0x01, 0xd, 0xb8, 0,0,0,0, 0,0,0,0, 0,0,0, 0x50 };

    ctx_reset();

    hit(0x6060, v4, 4, 100, 3, 60, 600);
    hit(0x6060, v6, 16, 100, 3, 60, 600);   /* same hash, different length */

    OK(ngx_http_shield_ban_lookup(&g_ctx, 0x6060, v4, 4) != NULL, "v4 present");
    OK(ngx_http_shield_ban_lookup(&g_ctx, 0x6060, v6, 16) != NULL, "v6 present");
    OK(live_allocs == 2, "v4 and v6 are distinct nodes");

    ctx_free_all();
}

/* Slab full and nothing reclaimable -> record returns NGX_ERROR, no crash. */
static void
test_slab_full(void)
{
    u_char a[4] = { 10, 0, 0, 60 };

    ctx_reset();
    fail_alloc = 1;

    OK(hit(0x7070, a, 4, 100, 3, 60, 600) == NGX_ERROR,
       "record reports NGX_ERROR when slab is full");
    OK(ngx_http_shield_ban_lookup(&g_ctx, 0x7070, a, 4) == NULL,
       "no node created on slab-full");

    fail_alloc = 0;
    ctx_free_all();
}

/* time_add_clamp saturates instead of overflowing. */
static void
test_time_clamp(void)
{
    time_t tmax = (time_t) (((uint64_t) 1 << (sizeof(time_t) * 8 - 1)) - 1);

    OK(ngx_http_shield_time_add_clamp(100, 50) == 150, "clamp: normal add");
    OK(ngx_http_shield_time_add_clamp(tmax - 10, 5) == tmax - 5,
       "clamp: near-max add still exact");
    OK(ngx_http_shield_time_add_clamp(tmax - 10, 100) == tmax,
       "clamp: overflow saturates at time_t max");

    /* A ban armed with a huge ban_time saturates rather than wrapping. */
    {
        u_char a[4] = { 10, 0, 0, 70 };
        ctx_reset();
        hit(0x8080, a, 4, tmax - 5, 1, 60, 1000000);   /* count=1 -> arms now */
        OK(banned(0x8080, a, 4, tmax - 1),
           "ban with overflowing bantime is effectively forever");
        ctx_free_all();
    }
}


int
main(void)
{
    printf("TAP version 13\n");

    test_ban_arms_and_expires();
    test_window_slides();
    test_backward_clock_resets_window();
    test_expire_preserves_live_window();
    test_expire_honours_shortened_window_after_reload();
    test_expire_honours_lengthened_window_after_reload();
    test_expire_armed_node_ignores_window();
    test_reban_after_lapse_keeps_window_protection();
    test_expire_backward_clock_does_not_freeze_reclaim();
    test_lapsed_ban_retired_before_window_rollover();
    test_expire_reclaims_stale();
    test_expire_progresses_past_live_cluster();
    test_expire_progresses_past_oversized_live_cluster();
    test_expire_progresses_despite_per_round_touch();
    test_cursor_survives_eviction_of_its_node();
    test_expire_wraps_within_one_call();
    test_rotation_does_not_defeat_ban();
    test_hash_collision_distinct();
    test_ipv4_ipv6_distinct();
    test_slab_full();
    test_time_clamp();

    printf("1..%d\n", tests_run);
    if (tests_failed) {
        printf("# FAILED %d of %d\n", tests_failed, tests_run);
        return 1;
    }
    printf("# all %d passed\n", tests_run);
    return 0;
}
