/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * ngx_shield_testprobe.h -- in-worker test probe (CI only, never shipped).
 *
 * P1 of the harness scoped in memory/labs/nginx-http-shield-module/
 * testprobe-scope.md: a read-only introspection endpoint that reports worker
 * and shm-zone state as JSON, so an external prober can assert on state the
 * HTTP response alone does not reveal (slab occupancy, node counts, connection
 * accounting) and diff it across requests.
 *
 * The whole feature is compiled out unless NGX_TEST_HARNESS is defined. It is
 * NOT built into the packaged .deb -- tools/ci-build.sh sets the define only
 * when TEST_HARNESS=1.
 *
 * Like ngx_http_shield_ban.{c,h}, this renderer depends only on <ngx_core.h>
 * and never on <ngx_http.h>: everything request-shaped (the directive, the
 * content handler, the response) stays in the HTTP module. That keeps the
 * renderer reachable from a direct-call unit harness, the same way ban.c is.
 */

#ifndef NGX_SHIELD_TESTPROBE_H_INCLUDED_
#define NGX_SHIELD_TESTPROBE_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>

#ifdef NGX_TEST_HARNESS

/*
 * nginx-vs-angie detection.
 *
 * Angie reaches module code as ANGIE_VERSION via ngx_core.h -> ngx_module.h ->
 * <angie.h>, so plain <ngx_core.h> is enough and no __has_include is needed.
 *
 * Do NOT test NGINX_VERSION to tell them apart: angie defines that too
 * (its src/core/nginx.h carries the nginx version it tracks), so the test is
 * true on both. Verified against angie 1.12.1 / nginx 1.30.3, 2026-07-18.
 * See memory/lessons/reference-angie-vs-nginx-detect.md.
 */
#ifdef ANGIE_VERSION
#define NGX_SHIELD_PROBE_FLAVOR      "angie"
#define NGX_SHIELD_PROBE_FLAVOR_VER  ANGIE_VERSION
#else
#define NGX_SHIELD_PROBE_FLAVOR      "nginx"
#define NGX_SHIELD_PROBE_FLAVOR_VER  NGINX_VERSION
#endif


/* Upper bound on the fixed part of the JSON document. The caller adds the
 * zone name length on top. Rendering is ngx_slprintf-based and truncates at
 * `last` rather than overflowing, so this bound is a quality-of-output
 * concern, not a safety boundary. */
#define NGX_SHIELD_PROBE_JSON_MAX  512


/*
 * Render the probe document into [buf, last) and return the end pointer.
 *
 * `zone` may be NULL, or may name a zone whose init has not run (no worker has
 * touched it yet); both are reported as "present": false rather than treated as
 * errors, so the prober can distinguish "no zone configured" from "zone empty".
 *
 * Walks the ban LRU queue under the slab mutex. That is O(nodes) and is why
 * this is a test-only endpoint.
 */
u_char *ngx_shield_probe_json(u_char *buf, u_char *last, ngx_shm_zone_t *zone);

#endif /* NGX_TEST_HARNESS */

#endif /* NGX_SHIELD_TESTPROBE_H_INCLUDED_ */
