/* Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause */
#undef NDEBUG
#include <ngx_config.h>
#include <ngx_core.h>
#include <assert.h>
#include "../../src/ngx_http_shield_negotiate.h"

static void
check_accept(const char *input, ngx_int_t expected, ngx_int_t om,
    ngx_int_t plain)
{
    ngx_str_t   value;
    ngx_int_t   oq, pq;
    ngx_uint_t  items;

    value.data = (u_char *) input;
    value.len = strlen(input);
    items = 0;
    oq = pq = 0;
    assert(ngx_http_shield_accept(&value, &items, &oq, &pq) == expected);
    if (expected == NGX_OK) {
        assert(oq == om && pq == plain);
    }
}

int
main(void)
{
    static const struct {
        const char *input;
        ngx_int_t rc;
        ngx_uint_t format;
    } queries[] = {
        { "", NGX_OK, 0 }, { "x=1", NGX_OK, 0 },
        { "format=json", NGX_OK, 0 },
        { "format=prometheus", NGX_OK, 1 },
        { "x=1&format=prometheus&y=2", NGX_OK, 1 },
        { "&format=json&&", NGX_OK, 0 },
        { "FORMAT=prometheus", NGX_OK, 0 },
        { "xformat=prometheus", NGX_OK, 0 },
        { "format=", NGX_ERROR, 0 }, { "format", NGX_ERROR, 0 },
        { "format=xml", NGX_ERROR, 0 },
        { "format=JSON", NGX_ERROR, 0 },
        { "format=%6ason", NGX_ERROR, 0 },
        { "format=json&format=json", NGX_ERROR, 0 },
        { "format=json&format=prometheus", NGX_ERROR, 0 }
    };
    static const char *invalid[] = {
        "broken", "/", "application/", "application/openmetrics-text,",
        "application/openmetrics-text;q=", "application/openmetrics-text;q=-1",
        "application/openmetrics-text;q=2", "application/openmetrics-text;q=.5",
        "application/openmetrics-text;q=0.0001",
        "application/openmetrics-text;q=1.001",
        "application/openmetrics-text;q=00",
        "application/openmetrics-text;q=0.x",
        "application/openmetrics-text;q=\"1\"",
        "application/openmetrics-text;q=1;q=1",
        "application/openmetrics-text;", "application/openmetrics-text;=x",
        "application/openmetrics-text;foo",
        "application/openmetrics-text;foo=\"x",
        "application/openmetrics-text;foo=\"x\\",
        "application/openmetrics-text;foo=\"\001\"",
        "application/openmetrics-text;foo=\177",
        "application/openmetrics-text;foo=x broken"
    };
    char        budget[9000];
    ngx_str_t   value;
    ngx_int_t   oq, pq;
    ngx_uint_t  i, items, format;

    for (i = 0; i < sizeof(queries) / sizeof(queries[0]); i++) {
        value.data = (u_char *) queries[i].input;
        value.len = strlen(queries[i].input);
        format = 0;
        assert(ngx_http_shield_query_format(&value, &format) == queries[i].rc);
        if (queries[i].rc == NGX_OK) { assert(format == queries[i].format); }
    }
    value.data = (u_char *) "";
    value.len = 0;
    format = 1;
    assert(ngx_http_shield_query_format(&value, &format) == NGX_OK);
    assert(format == 1);
    memset(budget, 'x', sizeof(budget));
    value.data = (u_char *) budget;
    value.len = NGX_SHIELD_NEGOTIATE_BYTES;
    assert(ngx_http_shield_query_format(&value, &format) == NGX_OK);
    value.len++;
    assert(ngx_http_shield_query_format(&value, &format) == NGX_ERROR);

    check_accept("", NGX_OK, 0, 0);
    check_accept("*/*", NGX_OK, 0, 0);
    check_accept("application/*", NGX_OK, 0, 0);
    check_accept("application/openmetrics-text", NGX_OK, 1000, 0);
    check_accept(" APPLICATION/OPENMETRICS-TEXT \t", NGX_OK, 1000, 0);
    check_accept("application/openmetrics-text;q=0", NGX_OK, 0, 0);
    check_accept("application/openmetrics-text;q=0.001", NGX_OK, 1, 0);
    check_accept("application/openmetrics-text;q=0.12", NGX_OK, 120, 0);
    check_accept("application/openmetrics-text;q=1.000", NGX_OK, 1000, 0);
    check_accept("application/openmetrics-text;q=0.", NGX_OK, 0, 0);
    check_accept("application/openmetrics-text;q=1.", NGX_OK, 1000, 0);
    check_accept("application/openmetrics-text;version=1.0.0;charset=utf-8",
                 NGX_OK, 1000, 0);
    check_accept("application/openmetrics-text; version = \"1.0.0\"; q = 0.5",
                 NGX_OK, 500, 0);
    check_accept("application/openmetrics-text;q=1;x=\"a,b\\\"c\"",
                 NGX_OK, 1000, 0);
    check_accept("application/openmetrics-text;q=1;x=\"a\tb\"",
                 NGX_OK, 1000, 0);
    check_accept("application/openmetrics-text;q=1;x=\"a\\\tb\"",
                 NGX_OK, 1000, 0);
    check_accept("application/openmetrics-text;x=\"a\tb\"",
                 NGX_OK, 0, 0);
    check_accept("application/openmetrics-text;q=1;x=\"a\177b\"",
                 NGX_ERROR, 0, 0);
    check_accept("application/openmetrics-text;version=2.0.0", NGX_OK, 0, 0);
    check_accept("application/openmetrics-text;charset=latin1", NGX_OK, 0, 0);
    check_accept("application/openmetrics-text;unknown=x", NGX_OK, 0, 0);
    check_accept("text/plain;version=0.0.4;q=0.9, "
                 "application/openmetrics-text;q=0.5", NGX_OK, 500, 900);
    check_accept("application/openmetrics-text;q=0.5, "
                 "application/openmetrics-text;q=0.8", NGX_OK, 800, 0);
    for (i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        check_accept(invalid[i], NGX_ERROR, 0, 0);
    }
    budget[0] = '\0';
    for (i = 0; i < NGX_SHIELD_NEGOTIATE_ITEMS; i++) {
        snprintf(budget + strlen(budget), sizeof(budget) - strlen(budget),
                 "%s", i ? ",text/plain" : "text/plain");
    }
    check_accept(budget, NGX_OK, 0, 1000);
    snprintf(budget + strlen(budget), sizeof(budget) - strlen(budget),
             ",text/plain");
    check_accept(budget, NGX_ERROR, 0, 0);
    snprintf(budget, sizeof(budget), "application/openmetrics-text;q=1");
    for (i = 1; i < NGX_SHIELD_NEGOTIATE_PARAMS; i++) {
        snprintf(budget + strlen(budget), sizeof(budget) - strlen(budget),
                 ";ext=value");
    }
    check_accept(budget, NGX_OK, 1000, 0);
    snprintf(budget + strlen(budget), sizeof(budget) - strlen(budget),
             ";ext=value");
    check_accept(budget, NGX_ERROR, 0, 0);
    /* Repeated fields share the list budget and retain maximum scores. */
    value.data = (u_char *) "application/openmetrics-text";
    value.len = strlen((char *) value.data);
    items = NGX_SHIELD_NEGOTIATE_ITEMS - 1;
    oq = pq = 0;
    assert(ngx_http_shield_accept(&value, &items, &oq, &pq) == NGX_OK);
    assert(oq == 1000);
    assert(ngx_http_shield_accept(&value, &items, &oq, &pq) == NGX_ERROR);
    puts("negotiate_unit: query, Accept, quality and budget controls passed");
    return 0;
}
