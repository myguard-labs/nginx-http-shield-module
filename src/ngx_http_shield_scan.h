/*
 * Copyright (C) 2026 Thijs Eilander
 *
 * The decision seam: everything that decides whether a buffer is an attack,
 * separated from everything that knows about an nginx request.
 *
 * Nothing here takes an ngx_http_request_t. The scanner sees bytes, a skip
 * mask and two caller-supplied scratch buffers, and returns a verdict. That
 * is what makes it linkable outside nginx -- ci/tests/unit and ci/fuzz/
 * compile THIS source, not a copy of it, so a divergence between what is
 * fuzzed and what ships cannot happen silently.
 *
 * Request plumbing (pool allocation, header walking, body buffering, logging
 * through r->connection->log) stays in ngx_http_shield_module.c and calls in
 * here.
 */

#ifndef NGX_HTTP_SHIELD_SCAN_H_INCLUDED_
#define NGX_HTTP_SHIELD_SCAN_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_http_shield_patterns.h"


/* A single detection result, for logging and for shield_status. */
typedef struct {
    const char  *category;
    const char  *source;      /* "uri" / "user-agent" / "body" / ...        */
    ngx_uint_t   cat;         /* NGX_HTTP_SHIELD_CAT_*, for shield_status   */
} ngx_http_shield_hit_t;


/* The two automata, built once at postconfiguration and read-only for the life
 * of the cycle: no per-request allocation, no locking, safe to share. One per
 * buffer flavour, because categories disagree about which buffer they scan. */
extern ngx_http_shield_ac_t  ngx_http_shield_ac_raw;
extern ngx_http_shield_ac_t  ngx_http_shield_ac_decoded;


/*
 * Build one automaton over the signature tables selected by `match`.
 *
 * Takes an explicit pool and log rather than an ngx_conf_t so it can be driven
 * from a unit test or a fuzz harness, neither of which has one. The permanent
 * tables come from `pool` (cf->pool in production, so they live as long as the
 * cycle); build scratch goes in a temporary pool destroyed before return.
 *
 * Returns NGX_OK, or NGX_ERROR after logging the reason.
 */
ngx_int_t ngx_http_shield_ac_build(ngx_pool_t *pool, ngx_log_t *log,
    ngx_http_shield_ac_t *ac, ngx_uint_t match);


/*
 * Scan one input buffer against every enabled signature category.
 *
 * `scratch_lc` and `scratch_dec` must each be at least `len` bytes. They are
 * caller-owned on purpose: in production they come from r->pool, in a fuzz
 * harness from the stack or malloc. Passing them in is what keeps this
 * function free of any allocator policy -- and ngx_unescape_uri never grows
 * the buffer, so `len` bytes is always enough for the decoded copy.
 *
 * `skip` is the shield_skip mask; a set bit disables that category.
 * `source` is a static string recorded on the hit for logging.
 *
 * Returns NGX_OK and fills *hit on a match, or NGX_DECLINED when clean.
 * Never returns NGX_ERROR: with the scratch supplied there is nothing left
 * that can fail, so the caller's fail-closed path lives at the allocation.
 */
ngx_int_t ngx_http_shield_scan_input(u_char *data, size_t len,
    u_char *scratch_lc, u_char *scratch_dec, const char *source,
    uint64_t skip, ngx_http_shield_hit_t *hit);


#endif /* NGX_HTTP_SHIELD_SCAN_H_INCLUDED_ */
