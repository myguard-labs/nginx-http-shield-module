/* Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause */
#undef NDEBUG
#include <ngx_config.h>
#include <ngx_core.h>
#include "../../src/ngx_http_shield_cve.h"
#include <assert.h>

static ngx_uint_t checks;

static void
json_case(const char *input, const char *expected, size_t len)
{
    u_char  *out;
    size_t   n, size;

    size = ngx_strlen(input);
    out = malloc(size + 2);
    assert(out != NULL);
    ngx_memset(out, 0xa5, size + 2);
    n = ngx_http_shield_cve_json(out, (const u_char *) input, size);
    assert(n == len);
    assert(ngx_memcmp(out, expected, len) == 0);
    assert(out[size] == 0xa5 && out[size + 1] == 0xa5);
    free(out);
    checks++;
}

static void
match_case(const char *text, ngx_uint_t flags, ngx_uint_t cat)
{
    ngx_str_t  s;

    s.data = (u_char *) text;
    s.len = ngx_strlen(text);
    assert(ngx_http_shield_cve_body_match(&s, flags) == cat);
    checks++;
}

static void
multipart_case(const char *body, const char *type, ngx_uint_t cat)
{
    u_char     boundary_data[70], output[2048];
    ngx_str_t  boundary, content_type, view;

    boundary.data = boundary_data;
    boundary.len = 0;
    content_type.data = (u_char *) type;
    content_type.len = ngx_strlen(type);
    assert(ngx_http_shield_cve_boundary(&content_type, &boundary) == NGX_OK);
    view.data = output;
    view.len = ngx_http_shield_cve_multipart(output, (const u_char *) body,
                                            ngx_strlen(body), &boundary);
    assert(ngx_http_shield_cve_body_match(&view, NGX_SHIELD_CVE_JSON) == cat);
    checks++;
}

static void
boundary_case(const char *text, ngx_int_t expected)
{
    u_char     output[70];
    ngx_str_t  type, boundary;

    boundary.data = output;
    type.data = (u_char *) text;
    type.len = ngx_strlen(text);
    assert(ngx_http_shield_cve_boundary(&type, &boundary) == expected);
    checks++;
}

static void
multipart_controls(void)
{
    const char *body =
        "--Fixt\r\nContent-Disposition: form-data; name=\"noise\"\r\n\r\n"
        "\"\r\n--Fixt\r\nContent-Disposition: form-data; name=\"0\"\r\n\r\n"
        "{\"v\":\"$1:\\u005f_proto__:\\u0074hen\"}\r\n--Fixt--\r\n";

    multipart_case(body, "multipart/form-data; boundary=Fixt",
                   NGX_HTTP_SHIELD_CAT_DESERIAL);
    multipart_case(body, "multipart/form-data; foo=\"a;b\"; boundary=\"Fixt\"",
                   NGX_HTTP_SHIELD_CAT_DESERIAL);
    multipart_case(body, "multipart/form-data; boundary=\"Fixt\"; charset=utf-8",
                   NGX_HTTP_SHIELD_CAT_DESERIAL);
    multipart_case(body, "multipart/form-data; BOUNDARY = Fixt ",
                   NGX_HTTP_SHIELD_CAT_DESERIAL);
    multipart_case(body, "multipart/form-data; boundary=other",
                   NGX_HTTP_SHIELD_CAT_N);
    multipart_case("--Fixt--\r\n", "multipart/form-data; boundary=Fixt",
                   NGX_HTTP_SHIELD_CAT_N);
    multipart_case("--Fixt\r\nno headers", "multipart/form-data; boundary=Fixt",
                   NGX_HTTP_SHIELD_CAT_N);
    multipart_case("--Fixtx\r\n\r\n\"$1:__proto__:then\"\r\n--Fixt--",
                   "multipart/form-data; boundary=Fixt",
                   NGX_HTTP_SHIELD_CAT_N);
    boundary_case("multipart/form-data; boundary=Fixt;", NGX_OK);
    boundary_case("multipart/form-data; boundary=Fixt\t", NGX_OK);
    boundary_case("multipart/form-data; boundary=Fixt; \t", NGX_OK);
    multipart_case("--Fixt \t\r\nContent-Disposition: form-data; name=0"
                   "\r\n\r\n\"$1:\\u005f_proto__:\\u0074hen\""
                   "\r\n--Fixt-- \t\r\n",
                   "multipart/form-data; boundary=Fixt",
                   NGX_HTTP_SHIELD_CAT_DESERIAL);
    boundary_case("multipart/form-data", NGX_ERROR);
    boundary_case("multipart/form-data; boundary=", NGX_ERROR);
    boundary_case("multipart/form-data; boundary=\"\"", NGX_ERROR);
    boundary_case("multipart/form-data; boundary=\"Fixt", NGX_ERROR);
    boundary_case("multipart/form-data; boundary=\"Fixt\"X", NGX_ERROR);
    boundary_case("multipart/form-data; boundary=\"Fixt\\", NGX_ERROR);
    boundary_case("multipart/form-data; boundary=\"Fixt \"", NGX_ERROR);
    boundary_case("multipart/form-data; boundary=Fixt; boundary=Fixt", NGX_ERROR);
    boundary_case("multipart/form-data; other=Fixt", NGX_ERROR);
    boundary_case("multipart/form-data; other", NGX_ERROR);
    boundary_case("multipart/form-data; boundary=Fixt\n", NGX_ERROR);
    boundary_case("multipart/form-data; boundary="
                  "12345678901234567890123456789012345678901234567890123456789012345678901",
                  NGX_ERROR);
}

int
main(void)
{
    char        text[32];
    u_char      expected[2];
    ngx_uint_t  i;
    ngx_str_t   s;

    for (i = 0; i < 128; i++) {
        snprintf(text, sizeof(text), "\"\\u%04x\"", (unsigned) i);
        expected[0] = ngx_tolower(i);
        expected[1] = 0;
        json_case(text, (const char *) expected, 2);
    }
    json_case("", "", 0);
    json_case("{}", "", 0);
    json_case("\"\"", "\0", 1);
    json_case("\"A\" \"B\"", "a\0b\0", 4);
    json_case("\"\\\"\\\\\\/\\b\\f\\n\\r\\t\"",
              "\"\\/\b\f\n\r\t\0", 9);
    json_case("\"\\uD834\\uDD1E\"", "\200\0", 2);
    json_case("\"\\u00e9\"", "\200\0", 2);
    json_case("\"a\" \"\\uD834x\"", "a\0", 2);
    json_case("\"\\uDC00\"", "", 0);
    json_case("\"\\uD800\\u0000\"", "", 0);
    json_case("\"\\uD800\\uZZZZ\"", "", 0);
    json_case("\"\\uXX00\"", "", 0);
    json_case("\"\\u00\"", "", 0);
    json_case("\"\\x\"", "", 0);
    json_case("\"\\", "", 0);
    json_case("\"unterminated", "", 0);
    json_case("\"raw\ncontrol\"", "", 0);
    json_case("\"\\\\u0041\"", "\\u0041\0", 7);
    match_case("__class guzzlehttp\\psr7\\fnstream _fn_close",
               NGX_SHIELD_CVE_CRAFT, NGX_HTTP_SHIELD_CAT_DESERIAL);
    match_case("class yii\\rbac\\phpmanager itemfile",
               NGX_SHIELD_CVE_CRAFT, NGX_HTTP_SHIELD_CAT_DESERIAL);
    match_case("class yii\\rbac\\phpmanager", NGX_SHIELD_CVE_CRAFT,
               NGX_HTTP_SHIELD_CAT_N);
    match_case("__class guzzlehttp\\psr7\\fnstream", NGX_SHIELD_CVE_CRAFT,
               NGX_HTTP_SHIELD_CAT_N);
    match_case("java.lang.thread.sleep(0)", NGX_SHIELD_CVE_GEO,
               NGX_HTTP_SHIELD_CAT_JAVA_EVAL);
    match_case("java.lang.runtime", NGX_SHIELD_CVE_GEO,
               NGX_HTTP_SHIELD_CAT_JAVA_EVAL);
    match_case("java.lang.processbuilder", NGX_SHIELD_CVE_GEO,
               NGX_HTTP_SHIELD_CAT_JAVA_EVAL);
    match_case("javax.script.scriptenginemanager", NGX_SHIELD_CVE_GEO,
               NGX_HTTP_SHIELD_CAT_JAVA_EVAL);
    match_case(":__proto__:then", NGX_SHIELD_CVE_JSON,
               NGX_HTTP_SHIELD_CAT_DESERIAL);
    match_case(":constructor:constructor", NGX_SHIELD_CVE_JSON,
               NGX_HTTP_SHIELD_CAT_DESERIAL);
    match_case(":__proto__:then", 0, NGX_HTTP_SHIELD_CAT_N);
    s.data = (u_char *) "\255d setting";
    s.len = 10;
    assert(ngx_http_shield_cve_php(&s));
    s.len = 0;
    assert(!ngx_http_shield_cve_php(&s));
    s.len = 1;
    assert(!ngx_http_shield_cve_php(&s));
    s.data = (u_char *) "\302\255c path";
    s.len = 8;
    assert(ngx_http_shield_cve_php(&s));
    multipart_controls();
    puts("CVE helpers: decoder boundaries and profile matches passed");
    return checks > 150 ? 0 : 1;
}
