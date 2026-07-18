/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * ngx_shield_probe_hooks.c -- shield's module-specific half of the test probe.
 *
 * Everything generic -- flavor, pid, connections, fds, cycle-pool stats, the
 * zone's name/size/slab page accounting, and the whole fault_slab= query parser
 * -- now comes from t/harness (nginx-test-harness). What remains here is only
 * what a generic probe cannot know: the SEMANTICS of shield's shared memory.
 *
 * Two hooks, matching ngx_test_probe_hooks_t:
 *
 *   zone_render  walks the ban LRU queue to report node and ban counts, plus
 *                the fault-injection counters, as extra members of the "zone"
 *                object. O(nodes) under the slab mutex, which is why the whole
 *                feature is test-only.
 *   fault_set    stores an already-parsed and validated nth into the zone.
 *
 * The rendered field names are unchanged from the pre-harness probe
 * (zone.nodes, zone.banned, zone.fault.slab_nth, zone.fault.slab_seen), so
 * the rule files under t/prober/rules assert on exactly the paths they
 * always did.
 *
 * Like ngx_http_shield_ban.{c,h}, this depends only on <ngx_core.h> and never
 * on <ngx_http.h>: everything request-shaped stays in the HTTP module.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#ifdef NGX_TEST_HARNESS

#include "ngx_test_probe.h"
#include "ngx_http_shield_ban.h"


/*
 * Append shield's own members to the probe's "zone" object.
 *
 * Contract (see ngx_test_probe_hooks_t): the generic members are already
 * rendered and the object is still open, so this must lead with a comma and
 * must NOT close the brace. Rendering is ngx_slprintf-based against `last`,
 * which truncates rather than overflowing.
 *
 * The probe calls this WITHOUT holding the slab mutex -- locking is the hook's
 * own responsibility -- so the queue walk takes it here.
 *
 * The harness decides "present" from zone->shm.addr (the master mapped the
 * segment) while shield's state needs ctx->sh and ctx->shpool, which the
 * per-worker init callback fills in later. A probe racing a reload can see the
 * former without the latter, so this re-checks rather than assuming the
 * harness's present implies shield's. In that window the shield-specific
 * members are reported at their zero values, which is honest: no nodes are
 * reachable through a zone this worker has not initialised.
 */
static u_char *
ngx_shield_probe_zone_render(u_char *buf, u_char *last, ngx_shm_zone_t *zone)
{
    time_t                       now;
    ngx_queue_t                 *q;
    ngx_int_t                    fault_nth;
    ngx_uint_t                   nodes, banned, fault_seen;
    ngx_http_shield_ban_node_t  *node;
    ngx_http_shield_ban_ctx_t   *ctx;

    nodes = 0;
    banned = 0;
    fault_nth = -1;
    fault_seen = 0;

    ctx = zone->data;

    if (ctx != NULL && ctx->sh != NULL && ctx->shpool != NULL) {
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

        fault_nth = ctx->sh->fault_slab_nth;
        fault_seen = ctx->sh->fault_slab_seen;

        ngx_shmtx_unlock(&ctx->shpool->mutex);
    }

    return ngx_slprintf(buf, last,
                        ",\"nodes\":%ui,"
                        "\"banned\":%ui,"
                        "\"fault\":{\"slab_nth\":%i,\"slab_seen\":%ui}",
                        nodes,
                        banned,
                        fault_nth,
                        fault_seen);
}


/*
 * Arm or clear slab fault injection at `nth` (negative disarms).
 *
 * The harness has already matched the query argument, rejected malformed and
 * over-long values, and applied the sign; this only has to store the result.
 *
 * The counters live in SHARED memory, not in a process global, because the
 * worker that arms the fault need not be the worker that trips it -- a global
 * would make the harness pass or fail on which worker answered. Tests pin
 * worker_processes 1 (the harness requires it for the pid oracle), which would
 * hide exactly that bug, so the storage decision cannot be left to the test
 * configuration. See ngx_http_shield_ban.h.
 *
 * Arming resets `seen`, so an armed nth counts from this request rather than
 * from whatever traffic the zone saw before it.
 */
static ngx_int_t
ngx_shield_probe_fault_set(ngx_shm_zone_t *zone, ngx_int_t nth)
{
    ngx_http_shield_ban_ctx_t  *ctx;

    if (zone == NULL) {
        return NGX_DECLINED;
    }

    ctx = zone->data;

    if (ctx == NULL || ctx->sh == NULL || ctx->shpool == NULL) {
        return NGX_DECLINED;
    }

    ngx_shmtx_lock(&ctx->shpool->mutex);
    ctx->sh->fault_slab_nth = nth;
    ctx->sh->fault_slab_seen = 0;
    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return NGX_OK;
}


static const ngx_test_probe_hooks_t  ngx_shield_probe_hooks = {
    ngx_shield_probe_zone_render,
    ngx_shield_probe_fault_set
};


void
ngx_shield_probe_hooks_register(void)
{
    ngx_test_probe_register(&ngx_shield_probe_hooks);
}

#else

/* ISO C forbids an empty translation unit, and angie's configure adds -Werror,
 * so the disabled build needs a declaration to stand on. */
typedef int ngx_shield_probe_hooks_not_built_t;

#endif /* NGX_TEST_HARNESS */
