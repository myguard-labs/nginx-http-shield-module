/* Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 * Test-only amalgamation. Only the COPIED category/rule descriptors are mutable;
 * scanner implementation, signature bytes, flags and nginx decoder are real.
 */
#include "ngx_http_shield_scan.c"
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

static void
print_terms(const ngx_http_shield_sig_t *terms, ngx_uint_t count)
{
    ngx_uint_t i;
    size_t j;

    for (i = 0; i < count; i++) {
        if (i) { (void) putchar(','); }
        for (j = 0; j < terms[i].len; j++) {
            printf("%02x", (unsigned char) terms[i].s[j]);
        }
    }
}

static int
inventory(void)
{
    ngx_uint_t row, item;
    const ngx_http_shield_catdef_t *cat;
    const ngx_http_shield_ruledef_t *rule;

    for (row = 0; row < NGX_HTTP_SHIELD_NCATEGORIES; row++) {
        cat = &ngx_http_shield_categories[row];
        for (item = 0; item < cat->nsigs; item++) {
            printf("signature\t%u\t%u\t%s\t%s\t", (unsigned) row,
                   (unsigned) item, cat->name, cat->name);
            print_terms(&cat->sigs[item], 1);
            (void) putchar('\n');
        }
    }
    for (row = 0; row < NGX_HTTP_SHIELD_NRULES; row++) {
        rule = &ngx_http_shield_rules[row];
        for (item = 0; item < NGX_HTTP_SHIELD_NCATEGORIES; item++) {
            if (ngx_http_shield_categories[item].cat == rule->cat) { break; }
        }
        if (item == NGX_HTTP_SHIELD_NCATEGORIES) { return 2; }
        printf("and-rule\t%u\t0\t%s\t%s\t", (unsigned) row,
               rule->name, ngx_http_shield_categories[item].name);
        print_terms(rule->terms, rule->nterms);
        (void) putchar('\n');
    }
    return ferror(stdout) ? 2 : 0;
}

static int
number(const char *arg, unsigned long *value)
{
    char *end;

    if (*arg < '0' || *arg > '9') { return 0; }
    *value = strtoul(arg, &end, 10);
    return *end == '\0' && *value < 65536;
}

static int
isolate(int argc, char **argv)
{
    ngx_uint_t i;
    unsigned long row, item;
    int signature;

    if (argc != 5 || !number(argv[2], &row) || !number(argv[3], &item)
        || (strcmp(argv[4], "on") && strcmp(argv[4], "off")))
    {
        return 0;
    }
    signature = strcmp(argv[1], "signature") == 0;
    if (!signature && strcmp(argv[1], "and-rule")) { return 0; }
    if ((signature && (row >= NGX_HTTP_SHIELD_NCATEGORIES
                      || item >= ngx_http_shield_categories[row].nsigs))
        || (!signature && (row >= NGX_HTTP_SHIELD_NRULES || item != 0)))
    {
        return 0;
    }
    for (i = 0; i < NGX_HTTP_SHIELD_NCATEGORIES; i++) {
        if (signature && i == row && strcmp(argv[4], "on") == 0) {
            ngx_http_shield_categories[i].sigs += item;
            ngx_http_shield_categories[i].nsigs = 1;
        } else {
            ngx_http_shield_categories[i].nsigs = 0;
        }
    }
    for (i = 0; i < NGX_HTTP_SHIELD_NRULES; i++) {
        if (signature || i != row || strcmp(argv[4], "off") == 0) {
            ngx_http_shield_rules[i].nterms = 0;
        }
    }
    return 1;
}

static int
hex(unsigned char c)
{
    if (c >= '0' && c <= '9') { return c - '0'; }
    if (c >= 'a' && c <= 'f') { return c - 'a' + 10; }
    return -1;
}

int
main(int argc, char **argv)
{
    ngx_log_t log;
    ngx_pool_t *pool;
    ngx_http_shield_automata_t automata;
    ngx_http_shield_hit_t hit;
    ngx_int_t rc;
    char line[8196];
    u_char data[4096], lc[4096], dec[4096];
    size_t n, i;
    int hi, lo;

    if (argc == 2 && strcmp(argv[1], "--list") == 0) { return inventory(); }
    if (!(argc == 2 && strcmp(argv[1], "--full") == 0)
        && !isolate(argc, argv))
    {
        return 2;
    }
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
        rc = ngx_http_shield_scan_input(&automata, data, n, lc, dec,
            "causal-buffer", line[0] == '1' ? 0 : n, 0, &hit);
        if (rc != NGX_OK && rc != NGX_DECLINED) {
            ngx_destroy_pool(pool);
            return 2;
        }
        puts(rc == NGX_OK ? hit.category : "clean");
    }
    ngx_destroy_pool(pool);
    return ferror(stdin) || ferror(stdout) ? 2 : 0;
}
