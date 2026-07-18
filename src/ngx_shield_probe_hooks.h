/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * ngx_shield_probe_hooks.h -- register shield's probe hooks (CI only).
 *
 * The probe itself lives in t/harness (nginx-test-harness); this declares the
 * one call the HTTP module makes to hand it shield's zone semantics. See
 * ngx_shield_probe_hooks.c for what the two hooks do, and t/harness/README.md
 * for the consumer contract.
 */

#ifndef NGX_SHIELD_PROBE_HOOKS_H_INCLUDED_
#define NGX_SHIELD_PROBE_HOOKS_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>

#ifdef NGX_TEST_HARNESS

/*
 * Upper bound on what ngx_shield_probe_zone_render() appends to the probe's
 * "zone" object, on top of the harness's NGX_TEST_PROBE_JSON_MAX.
 *
 * The hook renders four fixed keys and four integers; the literal text is ~60
 * bytes, and 128 leaves room for every value to widen to a full 64-bit decimal
 * at once. The caller adds this to the harness bound when sizing the response
 * buffer -- see ngx_http_shield_probe_handler().
 */
#define NGX_HTTP_SHIELD_PROBE_ZONE_MAX  128


/*
 * Register shield's zone_render and fault_set hooks with the harness probe.
 *
 * Call once, from module init or postconfiguration. Registering is what makes
 * the probe report zone.nodes / zone.banned and accept fault_slab=; without it
 * the generic document still renders, so a missed call degrades to "the
 * shield-specific assertions all fail" rather than to a crash.
 */
void ngx_shield_probe_hooks_register(void);

#endif /* NGX_TEST_HARNESS */

#endif /* NGX_SHIELD_PROBE_HOOKS_H_INCLUDED_ */
