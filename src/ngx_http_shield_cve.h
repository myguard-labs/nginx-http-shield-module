/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Explicit application policies. These are not universal attack signatures.
 * Helpers borrow bounded buffers; no request state, allocation or mutation of
 * forwarded bytes. JSON scratch never grows beyond the input length.
 */

#ifndef NGX_HTTP_SHIELD_CVE_H_INCLUDED_
#define NGX_HTTP_SHIELD_CVE_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_http_shield_patterns.h"

#define NGX_SHIELD_CVE_PHP       0x01
#define NGX_SHIELD_CVE_CRAFT     0x02
#define NGX_SHIELD_CVE_GEO       0x04
#define NGX_SHIELD_CVE_NEXT      0x08
#define NGX_SHIELD_CVE_TOMCAT    0x10
#define NGX_SHIELD_CVE_JSON      0x20
#define NGX_SHIELD_CVE_BODY      (NGX_SHIELD_CVE_CRAFT|NGX_SHIELD_CVE_GEO \
                                 |NGX_SHIELD_CVE_JSON)

/* Fixed small vocabulary: each comparison is bounded by its literal length. */
static ngx_inline ngx_uint_t
ngx_http_shield_cve_has(ngx_str_t *s, const char *literal, size_t len)
{
    size_t  i;

    for (i = 0; i <= s->len && len <= s->len - i; i++) {
        if (ngx_memcmp(s->data + i, literal, len) == 0) {
            return 1;
        }
    }
    return 0;
}

#define ngx_shield_cve_has(s, text) \
    ngx_http_shield_cve_has(s, text, sizeof(text) - 1)


static ngx_inline ngx_int_t
ngx_http_shield_cve_hex(u_char *p)
{
    ngx_int_t   value, digit;
    ngx_uint_t  i;

    value = 0;
    for (i = 0; i < 4; i++) {
        digit = ngx_tolower(p[i]);
        if (digit >= '0' && digit <= '9') {
            digit -= '0';
        } else if (digit >= 'a' && digit <= 'f') {
            digit = digit - 'a' + 10;
        } else {
            return NGX_ERROR;
        }
        value = value * 16 + digit;
    }
    return value;
}


/* Extract complete JSON string tokens as an ASCII inspection view, separated
 * by NUL. Decode exactly once; a literal escaped backslash stays a backslash.
 * Non-ASCII code points become a nonmatching byte, never disappear. Validate
 * surrogate pairs before consuming them. Malformed/incomplete tokens are not
 * decoded; earlier complete tokens remain inspectable. This is not a JSON
 * document validator and never repairs input forwarded to the application. */
static ngx_inline size_t
ngx_http_shield_cve_json(u_char *dst, const u_char *src, size_t len)
{
    size_t      i, out, start;
    ngx_int_t   value, low;
    u_char      c;

    i = 0;
    out = 0;
    while (i < len) {
        if (src[i++] != '"') {
            continue;
        }
        start = out;
        for ( ;; ) {
            if (i == len) {
                return start;
            }
            c = src[i++];
            if (c == '"') {
                dst[out++] = 0;
                break;
            }
            if (c < 0x20) {
                return start;
            }
            if (c == '\\') {
                if (i == len) {
                    return start;
                }
                c = src[i++];
                switch (c) {
                case '"': case '\\': case '/':
                    break;
                case 'b': c = '\b'; break;
                case 'f': c = '\f'; break;
                case 'n': c = '\n'; break;
                case 'r': c = '\r'; break;
                case 't': c = '\t'; break;
                case 'u':
                    if (len - i < 4) {
                        return start;
                    }
                    value = ngx_http_shield_cve_hex((u_char *) src + i);
                    if (value == NGX_ERROR) {
                        return start;
                    }
                    i += 4;
                    if (value >= 0xd800 && value <= 0xdbff) {
                        if (len - i < 6 || src[i] != '\\'
                            || src[i + 1] != 'u')
                        {
                            return start;
                        }
                        low = ngx_http_shield_cve_hex((u_char *) src + i + 2);
                        if (low < 0xdc00 || low > 0xdfff) {
                            return start;
                        }
                        i += 6;
                    } else if (value >= 0xdc00 && value <= 0xdfff) {
                        return start;
                    }
                    c = value < 0x80 ? (u_char) value : 0x80;
                    break;
                default:
                    return start;
                }
            }
            dst[out++] = ngx_tolower(c);
        }
    }
    return out;
}


/* Return a category index, or CAT_N for no hit. Callers mask disabled
 * profiles/categories before calling. One hit preserves accounting. */
static ngx_inline ngx_uint_t
ngx_http_shield_cve_body_match(ngx_str_t *s, ngx_uint_t flags)
{
    if ((flags & NGX_SHIELD_CVE_CRAFT)
        && ((ngx_shield_cve_has(s, "__class")
             && ngx_shield_cve_has(s, "guzzlehttp\\psr7\\fnstream")
             && ngx_shield_cve_has(s, "_fn_close"))
            || (ngx_shield_cve_has(s, "class")
                && ngx_shield_cve_has(s, "yii\\rbac\\phpmanager")
                && ngx_shield_cve_has(s, "itemfile"))))
    {
        return NGX_HTTP_SHIELD_CAT_DESERIAL;
    }

    if ((flags & NGX_SHIELD_CVE_GEO)
        && (ngx_shield_cve_has(s, "java.lang.runtime")
            || ngx_shield_cve_has(s, "java.lang.processbuilder")
            || ngx_shield_cve_has(s, "java.lang.thread.sleep(")
            || ngx_shield_cve_has(s, "javax.script.scriptenginemanager")))
    {
        return NGX_HTTP_SHIELD_CAT_JAVA_EVAL;
    }

    if ((flags & NGX_SHIELD_CVE_JSON)
        && (ngx_shield_cve_has(s, ":__proto__:then")
            || ngx_shield_cve_has(s, ":constructor:constructor")))
    {
        return NGX_HTTP_SHIELD_CAT_DESERIAL;
    }
    return NGX_HTTP_SHIELD_CAT_N;
}


/* A leading Windows best-fit option prefix in a CGI query. This is scoped
 * to CGI locations by configuration; do not fold soft hyphens globally. */
static ngx_inline ngx_uint_t
ngx_http_shield_cve_php(ngx_str_t *s)
{
    size_t  i;

    i = 0;
    if (s->len > 1 && s->data[0] == 0xc2) {
        i = 1;
    }
    return s->len > i + 1 && s->data[i] == 0xad
           && (s->data[i + 1] == 'd' || s->data[i + 1] == 'n'
               || s->data[i + 1] == 'c');
}

/* Parse the MIME boundary parameter into caller-owned bounded storage. Other
 * parameters may be quoted; duplicate boundaries and invalid syntax are errors.
 * RFC 2046 limits a boundary to 70 characters. */
static ngx_inline ngx_int_t
ngx_http_shield_cve_boundary(ngx_str_t *type, ngx_str_t *boundary)
{
    size_t      i, start, end, n;
    ngx_uint_t  found, selected, quoted;
    u_char      c;

    i = 0;
    found = 0;
    while (i < type->len && type->data[i] != ';') {
        i++;
    }
    while (i < type->len) {
        i++;
        while (i < type->len
               && (type->data[i] == ' ' || type->data[i] == '\t'))
        {
            i++;
        }
        if (i == type->len) {
            break;
        }
        start = i;
        while (i < type->len && type->data[i] != '='
               && type->data[i] != ';')
        {
            i++;
        }
        end = i;
        while (end > start
               && (type->data[end - 1] == ' ' || type->data[end - 1] == '\t'))
        {
            end--;
        }
        if (i == type->len || type->data[i] != '=') {
            return NGX_ERROR;
        }
        selected = end - start == 8;
        for (n = 0; selected && n < 8; n++) {
            if (ngx_tolower(type->data[start + n]) != "boundary"[n]) {
                selected = 0;
            }
        }
        if (selected && found) {
            return NGX_ERROR;
        }
        i++;
        while (i < type->len
               && (type->data[i] == ' ' || type->data[i] == '\t'))
        {
            i++;
        }
        quoted = i < type->len && type->data[i] == '"';
        if (quoted) {
            i++;
        }
        n = 0;
        for ( ;; ) {
            if (i == type->len) {
                if (quoted) {
                    return NGX_ERROR;
                }
                break;
            }
            c = type->data[i];
            if ((quoted && c == '"')
                || (!quoted && (c == ';' || c == ' ' || c == '\t')))
            {
                if (quoted) {
                    i++;
                }
                break;
            }
            i++;
            if (quoted && c == '\\') {
                if (i == type->len) {
                    return NGX_ERROR;
                }
                c = type->data[i++];
            }
            if (selected) {
                if (n == 70 || c < 0x20 || c > 0x7e) {
                    return NGX_ERROR;
                }
                boundary->data[n++] = c;
            }
        }
        if (selected) {
            while (n && boundary->data[n - 1] == ' ' && !quoted) {
                n--;
            }
            if (!n || boundary->data[n - 1] == ' ') {
                return NGX_ERROR;
            }
            boundary->len = n;
            found = 1;
        }
        while (i < type->len
               && (type->data[i] == ' ' || type->data[i] == '\t'))
        {
            i++;
        }
        if (i < type->len && type->data[i] != ';') {
            return NGX_ERROR;
        }
    }
    return found ? NGX_OK : NGX_ERROR;
}


/* Find only complete delimiter lines, including an optional closing marker.
 * A boundary-like substring in field data must not split the field. */
static ngx_inline size_t
ngx_http_shield_cve_delimiter(const u_char *src, size_t len, size_t offset,
    ngx_str_t *boundary)
{
    size_t  i, end;

    for (i = offset; i < len; i++) {
        if (i != 0 && (i < 2 || src[i - 2] != '\r' || src[i - 1] != '\n')) {
            continue;
        }
        if (len - i < boundary->len + 2 || src[i] != '-'
            || src[i + 1] != '-'
            || ngx_memcmp(src + i + 2, boundary->data, boundary->len) != 0)
        {
            continue;
        }
        end = i + 2 + boundary->len;
        if (len - end >= 2 && src[end] == '-' && src[end + 1] == '-') {
            end += 2;
        }
        while (end < len && (src[end] == ' ' || src[end] == '\t')) {
            end++;
        }
        if (end == len
            || (len - end >= 2 && src[end] == '\r' && src[end + 1] == '\n'))
        {
            return i;
        }
    }
    return len;
}


/* Inspect each complete field independently. A malformed JSON string in one
 * part cannot suppress later fields. Header contents are never JSON input.
 * The last truncated part remains prefix-limited, as is all body inspection. */
static ngx_inline size_t
ngx_http_shield_cve_multipart(u_char *dst, const u_char *src, size_t len,
    ngx_str_t *boundary)
{
    size_t  pos, end, start, out;

    out = 0;
    pos = ngx_http_shield_cve_delimiter(src, len, 0, boundary);
    while (pos < len) {
        pos += boundary->len + 2;
        while (pos < len && (src[pos] == ' ' || src[pos] == '\t')) {
            pos++;
        }
        if (len - pos < 2 || src[pos] != '\r' || src[pos + 1] != '\n') {
            break;
        }
        pos += 2;
        end = ngx_http_shield_cve_delimiter(src, len, pos, boundary);
        start = pos;
        while (end - start >= 4) {
            if (src[start] == '\r' && src[start + 1] == '\n'
                && src[start + 2] == '\r' && src[start + 3] == '\n')
            {
                start += 4;
                out += ngx_http_shield_cve_json(dst + out, src + start,
                                               end - start);
                break;
            }
            start++;
        }
        pos = end;
    }
    return out;
}

#endif /* NGX_HTTP_SHIELD_CVE_H_INCLUDED_ */
