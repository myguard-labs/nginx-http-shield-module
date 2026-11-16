/* Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 * Offline body adapter: production automata, masks and nginx decoder.
 * Input: one bounded hexadecimal body per line, preceded by form flag.
 */
#include "ngx_http_shield_scan.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

volatile ngx_cycle_t *ngx_cycle;

void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
    (void) level; (void) log; (void) err; (void) fmt;
}

static int
hex(unsigned char c)
{
    if (c >= '0' && c <= '9') { return c - '0'; }
    if (c >= 'a' && c <= 'f') { return c - 'a' + 10; }
    return -1;
}

int
main(void)
{
    ngx_log_t log;
    ngx_pool_t *pool;
    ngx_http_shield_automata_t automata;
    ngx_http_shield_hit_t hit;
    ngx_int_t rc;
    char line[8196];
    u_char data[4096], lc[4096], dec[4096];
    size_t n, i, form_offset;
    int hi, lo;

    memset(&log, 0, sizeof(log));
    pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, &log);
    if (pool == NULL) { return 2; }
    if (ngx_http_shield_ac_build(pool, &log, &automata.decoded,
            NGX_HTTP_SHIELD_MATCH_DECODED) != NGX_OK
        || ngx_http_shield_ac_build(pool, &log, &automata.raw,
            NGX_HTTP_SHIELD_MATCH_RAW) != NGX_OK)
    {
        ngx_destroy_pool(pool);
        return 2;
    }
    while (fgets(line, sizeof(line), stdin) != NULL) {
        n = strlen(line);
        if (n < 3 || line[n - 1] != '\n' || line[1] != ':'
            || (line[0] != '0' && line[0] != '1') || (n - 3) % 2 != 0)
        {
            ngx_destroy_pool(pool);
            return 2;
        }
        n = (n - 3) / 2;
        if (n > sizeof(data)) { ngx_destroy_pool(pool); return 2; }
        for (i = 0; i < n; i++) {
            hi = hex((unsigned char) line[2 + i * 2]);
            lo = hex((unsigned char) line[3 + i * 2]);
            if (hi < 0 || lo < 0) { ngx_destroy_pool(pool); return 2; }
            data[i] = (u_char) ((hi << 4) | lo);
        }
        form_offset = line[0] == '1' ? 0 : n;
        rc = ngx_http_shield_scan_input(&automata, data, n, lc, dec,
            "body", form_offset, ngx_http_shield_no_body_mask(), &hit);
        if (rc != NGX_OK && rc != NGX_DECLINED) {
            ngx_destroy_pool(pool);
            return 2;
        }
        puts(rc == NGX_OK ? hit.category : "clean");
    }
    ngx_destroy_pool(pool);
    return ferror(stdin) || ferror(stdout) ? 2 : 0;
}
