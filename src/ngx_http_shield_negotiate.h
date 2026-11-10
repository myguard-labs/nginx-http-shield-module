/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef NGX_HTTP_SHIELD_NEGOTIATE_H
#define NGX_HTTP_SHIELD_NEGOTIATE_H

#include <ngx_config.h>
#include <ngx_core.h>

#define NGX_HTTP_SHIELD_STATUS_JSON        0
#define NGX_HTTP_SHIELD_STATUS_PROMETHEUS  1

#define NGX_SHIELD_NEGOTIATE_BYTES   8192
#define NGX_SHIELD_NEGOTIATE_ITEMS   32
#define NGX_SHIELD_NEGOTIATE_PARAMS  16

/* Raw query names/values are case-sensitive and are not percent-decoded. */
static ngx_int_t
ngx_http_shield_query_format(ngx_str_t *args, ngx_uint_t *format)
{
    size_t       pos, start, end;
    ngx_uint_t   found;

    if (args->len > NGX_SHIELD_NEGOTIATE_BYTES) {
        return NGX_ERROR;
    }
    found = 0;
    for (pos = 0; pos < args->len; pos = end + 1) {
        start = pos;
        for (end = pos; end < args->len && args->data[end] != '&'; end++) {
            /* Find one query argument. */
        }
        for (; pos < end && args->data[pos] != '='; pos++) {
            /* Find its raw name. */
        }
        if (pos - start != 6
            || ngx_strncmp(args->data + start, "format", 6) != 0)
        {
            continue;
        }
        if (found++ || pos == end) {
            return NGX_ERROR;
        }
        start = pos + 1;
        if (end - start == 4
            && ngx_strncmp(args->data + start, "json", 4) == 0)
        {
            *format = NGX_HTTP_SHIELD_STATUS_JSON;
        } else if (end - start == 10
                   && ngx_strncmp(args->data + start, "prometheus", 10) == 0)
        {
            *format = NGX_HTTP_SHIELD_STATUS_PROMETHEUS;
        } else {
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}

static ngx_uint_t
ngx_http_shield_accept_token(u_char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
           || (c >= '0' && c <= '9') || c == '!' || c == '#'
           || c == '$' || c == '%' || c == '&' || c == '\''
           || c == '*' || c == '+' || c == '-' || c == '.'
           || c == '^' || c == '_' || c == '`' || c == '|' || c == '~';
}

/* q is an integer in thousandths; no floats, signs or excess precision. */
static ngx_int_t
ngx_http_shield_accept_quality(ngx_str_t *v)
{
    size_t      i;
    ngx_int_t   q, scale;

    if (v->len == 0 || v->len > 5
        || (v->data[0] != '0' && v->data[0] != '1'))
    {
        return NGX_ERROR;
    }
    q = (v->data[0] - '0') * 1000;
    if (v->len == 1) {
        return q;
    }
    if (v->data[1] != '.') {
        return NGX_ERROR;
    }
    scale = 100;
    for (i = 2; i < v->len; i++, scale /= 10) {
        if (v->data[i] < '0' || v->data[i] > '9'
            || (q >= 1000 && v->data[i] != '0'))
        {
            return NGX_ERROR;
        }
        q += (v->data[i] - '0') * scale;
    }
    return q;
}

static void
ngx_http_shield_accept_space(u_char **p, u_char *end)
{
    while (*p < end && (**p == ' ' || **p == '\t')) {
        (*p)++;
    }
}

/* Parse one header, sharing an item budget and scores across repeated fields.
 * Any malformed or over-budget field makes the caller fall back to 0.0.4.
 * Wildcards never opt into OpenMetrics. Unknown media parameters do not match
 * our representations; syntactically valid accept extensions follow q. */
static ngx_int_t
ngx_http_shield_accept(ngx_str_t *v, ngx_uint_t *items,
    ngx_int_t *openmetrics, ngx_int_t *plain)
{
    u_char      *p, *end, *start;
    ngx_str_t    type, name, value;
    ngx_int_t    q;
    ngx_uint_t   params, seen_q, supported, quoted, om, text;

    if (v->len == 0) {
        return NGX_OK;
    }
    p = v->data;
    end = p + v->len;
    for ( ;; ) {
        if (++*items > NGX_SHIELD_NEGOTIATE_ITEMS) {
            return NGX_ERROR;
        }
        ngx_http_shield_accept_space(&p, end);
        start = p;
        while (p < end && ngx_http_shield_accept_token(*p)) {
            p++;
        }
        if (p == start || p == end || *p++ != '/') {
            return NGX_ERROR;
        }
        value.data = p;
        while (p < end && ngx_http_shield_accept_token(*p)) {
            p++;
        }
        if (p == value.data) {
            return NGX_ERROR;
        }
        type.data = start;
        type.len = p - start;
        om = type.len == sizeof("application/openmetrics-text") - 1
             && ngx_strncasecmp(type.data,
                        (u_char *) "application/openmetrics-text",
                        type.len) == 0;
        text = type.len == sizeof("text/plain") - 1
               && ngx_strncasecmp(type.data, (u_char *) "text/plain",
                                  type.len) == 0;
        q = 1000;
        seen_q = params = 0;
        supported = 1;
        ngx_http_shield_accept_space(&p, end);
        while (p < end && *p == ';') {
            if (++params > NGX_SHIELD_NEGOTIATE_PARAMS) {
                return NGX_ERROR;
            }
            p++;
            ngx_http_shield_accept_space(&p, end);
            name.data = p;
            while (p < end && ngx_http_shield_accept_token(*p)) {
                p++;
            }
            name.len = p - name.data;
            ngx_http_shield_accept_space(&p, end);
            if (name.len == 0 || p == end || *p++ != '=') {
                return NGX_ERROR;
            }
            ngx_http_shield_accept_space(&p, end);
            quoted = p < end && *p == '"';
            if (quoted) {
                p++;
            }
            value.data = p;
            if (quoted) {
                while (p < end && *p != '"') {
                    if (*p == '\\') {
                        p++;
                        if (p == end) {
                            return NGX_ERROR;
                        }
                    }
                    if ((*p < 0x20 && *p != '\t') || *p == 0x7f) {
                        return NGX_ERROR;
                    }
                    p++;
                }
                if (p == end) {
                    return NGX_ERROR;
                }
                value.len = p++ - value.data;
            } else {
                while (p < end && ngx_http_shield_accept_token(*p)) {
                    p++;
                }
                value.len = p - value.data;
                if (value.len == 0) {
                    return NGX_ERROR;
                }
            }
            if (name.len == 1 && ngx_tolower(name.data[0]) == 'q') {
                if (seen_q++ || quoted
                    || (q = ngx_http_shield_accept_quality(&value)) < 0)
                {
                    return NGX_ERROR;
                }
            } else if (!seen_q) {
                if (name.len == 7
                    && ngx_strncasecmp(name.data, (u_char *) "version", 7)
                       == 0)
                {
                    supported &= (om && value.len == 5
                                  && ngx_strncmp(value.data, "1.0.0", 5) == 0)
                                 || (text && value.len == 5
                                     && ngx_strncmp(value.data, "0.0.4", 5)
                                        == 0);
                } else if (name.len == 7
                           && ngx_strncasecmp(name.data,
                                             (u_char *) "charset", 7) == 0)
                {
                    supported &= value.len == 5
                                 && ngx_strncasecmp(value.data,
                                             (u_char *) "utf-8", 5) == 0;
                } else {
                    supported = 0;
                }
            }
            ngx_http_shield_accept_space(&p, end);
        }
        if (supported && om && q > *openmetrics) {
            *openmetrics = q;
        }
        if (supported && text && q > *plain) {
            *plain = q;
        }
        if (p == end) {
            return NGX_OK;
        }
        if (*p++ != ',') {
            return NGX_ERROR;
        }
    }
}

#endif /* NGX_HTTP_SHIELD_NEGOTIATE_H */
