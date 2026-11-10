/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Exercise the real capability-admission and block-only config callbacks.
 * Linker sections discard unrelated nginx callbacks; no request runtime needed.
 */
#undef NDEBUG
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <assert.h>

#include "../../src/ngx_http_shield_module.c"

static const char *last_error;

void
ngx_conf_log_error(ngx_uint_t level, ngx_conf_t *cf, ngx_err_t error,
    const char *format, ...)
{
    (void) level;
    (void) cf;
    (void) error;
    last_error = format;
}

int
main(void)
{
    ngx_conf_t cf;
    ngx_array_t args;
    ngx_str_t values[] = { ngx_string("shield"), ngx_string("block") };
    ngx_http_shield_loc_conf_t slcf;

    ngx_memzero(&cf, sizeof(cf));
    ngx_memzero(&args, sizeof(args));
    ngx_memzero(&slcf, sizeof(slcf));
    args.elts = values;
    args.nelts = 2;
    cf.args = &args;
    slcf.mode = NGX_CONF_UNSET_UINT;
    assert(NGX_HAVE_ATOMIC_OPS == EXPECT_ATOMICS);
#if NGX_HAVE_ATOMIC_OPS
    assert(ngx_http_shield_ban_atomic_required(&cf) == NGX_OK);
    assert(last_error == NULL);
#else
    assert(ngx_http_shield_ban_atomic_required(&cf) == NGX_ERROR);
    assert(last_error != NULL);
    assert(strcmp(last_error,
                  "shield_ban_zone requires native atomic operations") == 0);
#if !defined(ATOMIC_GUARD_CONTROL)
    /* A syntactically valid zone is rejected before pool/zone setup. The
     * control mode separately isolates the same guard for causal mutation. */
    {
        ngx_str_t zone_values[] = {
            ngx_string("shield_ban_zone"), ngx_string("atomic:1m")
        };
        args.elts = zone_values;
        last_error = NULL;
        assert(ngx_http_shield_ban_zone(&cf, NULL, NULL) == NGX_CONF_ERROR);
        assert(last_error != NULL);
        assert(strcmp(last_error,
                      "shield_ban_zone requires native atomic operations") == 0);
        args.elts = values;
    }
#endif
#endif
    /* Block-only configuration never calls the zone capability gate. */
    last_error = NULL;
    assert(ngx_http_shield_mode(&cf, NULL, &slcf) == NGX_CONF_OK);
    assert(slcf.mode == NGX_HTTP_SHIELD_BLOCK);
    assert(last_error == NULL);
    printf("atomic_config_unit: capability=%d admission and block-only config passed\n",
           NGX_HAVE_ATOMIC_OPS);
    return 0;
}
