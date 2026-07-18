/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * prober.c -- rule-driven HTTP prober for the shield module. P2 of the harness
 * scoped in memory/labs/nginx-http-shield-module/testprobe-scope.md.
 *
 * Why this exists alongside the Perl suite in t/ rather than replacing it:
 *
 *   1. It runs against ANGIE. Stock Test::Nginx::Socket probes the server's
 *      version banner and requires "nginx version: x.y" (Util.pm:1365); angie
 *      answers "Angie version: Angie/1.12.0", so the harness bails before the
 *      first test and the angie CI leg has only ever been build-and-load. This
 *      prober reads no banner, so the same rules run on both servers.
 *
 *   2. It asserts on IN-WORKER state, not just the response. A rule can require
 *      that the ban zone gained exactly one node, which no amount of response
 *      matching can establish.
 *
 * Rule file syntax -- one case per stanza, blank line separated:
 *
 *     name    ban arms after the configured count
 *     send    GET /guarded?id=1+union+select+1,2,3-- HTTP/1.1\r\n
 *     send    Host: t\r\nConnection: close\r\n\r\n
 *     expect  status=403
 *     expect  body~Forbidden
 *     expect  header~Content-Type: text/html
 *     probe   zone.nodes == 1
 *     probe   flavor == "angie"
 *
 * `send` is repeatable and concatenates verbatim, so a stanza can spell out a
 * malformed request byte for byte. Escapes: \r \n \t \\ \" \0 \xNN.
 *
 * Every request must ask for Connection: close; see http.h for why.
 *
 * Output is TAP, so `prove` consumes it exactly like the Perl suite.
 */

#define _GNU_SOURCE

#include "http.h"
#include "json.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ASSERTS  32
#define MAX_CASES    256


typedef enum {
    EXPECT_STATUS,
    EXPECT_BODY_CONTAINS,
    EXPECT_HEADER_CONTAINS
} expect_kind;

typedef struct {
    expect_kind  kind;
    long         number;
    char        *text;
} expectation;

typedef struct {
    char  *path;
    char  *op;
    char  *literal;
} probe_assert;

typedef struct {
    char           *name;
    unsigned char  *request;
    size_t          request_len;
    expectation     expects[MAX_ASSERTS];
    size_t          n_expects;
    probe_assert    probes[MAX_ASSERTS];
    size_t          n_probes;
} test_case;


static const char  *opt_host = "127.0.0.1";
static int          opt_port = 18099;
static const char  *opt_probe_uri = "/__probe";
static int          opt_timeout_ms = 5000;
static int          opt_verbose = 0;


static void
die(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    fprintf(stderr, "prober: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);

    exit(2);
}


static char *
xstrdup(const char *s)
{
    char *p = strdup(s);

    if (p == NULL) {
        die("out of memory");
    }

    return p;
}


/* Trim leading and trailing whitespace in place; returns the new start. */
static char *
trim(char *s)
{
    char *end;

    while (*s != '\0' && isspace((unsigned char) *s)) {
        s++;
    }

    end = s + strlen(s);

    while (end > s && isspace((unsigned char) end[-1])) {
        end--;
    }

    *end = '\0';

    return s;
}


/*
 * Decode the rule-file escapes into raw bytes appended to *buf.
 *
 * Note this is byte-exact and does no HTTP-level fixups whatsoever: no implied
 * CRLF at end of line, no Content-Length synthesis, no header ordering. The
 * point of the harness is that the request on the wire is the request in the
 * file.
 */
static void
append_escaped(unsigned char **buf, size_t *len, size_t *cap, const char *src)
{
    while (*src != '\0') {
        unsigned char c;

        if (*src == '\\' && src[1] != '\0') {
            src++;

            switch (*src) {
            case 'r':  c = '\r'; src++; break;
            case 'n':  c = '\n'; src++; break;
            case 't':  c = '\t'; src++; break;
            case '0':  c = '\0'; src++; break;
            case '\\': c = '\\'; src++; break;
            case '"':  c = '"';  src++; break;

            case 'x': {
                char  hex[3];
                int   i = 0;

                src++;

                while (i < 2 && isxdigit((unsigned char) src[i])) {
                    hex[i] = src[i];
                    i++;
                }

                if (i == 0) {
                    die("bad \\x escape in send line");
                }

                hex[i] = '\0';
                c = (unsigned char) strtol(hex, NULL, 16);
                src += i;
                break;
            }

            default:
                die("unknown escape \\%c in send line", *src);
            }

        } else {
            c = (unsigned char) *src++;
        }

        if (*len + 1 >= *cap) {
            unsigned char *bigger;

            *cap = (*cap == 0) ? 256 : *cap * 2;
            bigger = realloc(*buf, *cap);
            if (bigger == NULL) {
                die("out of memory");
            }
            *buf = bigger;
        }

        (*buf)[(*len)++] = c;
    }
}


static void
case_free(test_case *tc)
{
    size_t i;

    free(tc->name);
    free(tc->request);

    for (i = 0; i < tc->n_expects; i++) {
        free(tc->expects[i].text);
    }

    for (i = 0; i < tc->n_probes; i++) {
        free(tc->probes[i].path);
        free(tc->probes[i].op);
        free(tc->probes[i].literal);
    }

    memset(tc, 0, sizeof(*tc));
}


static void
parse_expect(test_case *tc, char *arg, const char *file, int lineno)
{
    expectation *e;

    if (tc->n_expects >= MAX_ASSERTS) {
        die("%s:%d: too many expect lines (max %d)",
            file, lineno, MAX_ASSERTS);
    }

    e = &tc->expects[tc->n_expects];

    if (strncmp(arg, "status=", 7) == 0) {
        e->kind = EXPECT_STATUS;
        e->number = strtol(arg + 7, NULL, 10);
        e->text = NULL;

    } else if (strncmp(arg, "body~", 5) == 0) {
        e->kind = EXPECT_BODY_CONTAINS;
        e->text = xstrdup(trim(arg + 5));

    } else if (strncmp(arg, "header~", 7) == 0) {
        e->kind = EXPECT_HEADER_CONTAINS;
        e->text = xstrdup(trim(arg + 7));

    } else {
        die("%s:%d: unknown expect form \"%s\" "
            "(want status=, body~, header~)", file, lineno, arg);
    }

    tc->n_expects++;
}


static void
parse_probe(test_case *tc, char *arg, const char *file, int lineno)
{
    char         *path, *op, *lit;
    probe_assert *pa;

    if (tc->n_probes >= MAX_ASSERTS) {
        die("%s:%d: too many probe lines (max %d)", file, lineno, MAX_ASSERTS);
    }

    path = strtok(arg, " \t");
    op = strtok(NULL, " \t");
    lit = strtok(NULL, "");

    if (path == NULL || op == NULL || lit == NULL) {
        die("%s:%d: probe needs <path> <op> <value>", file, lineno);
    }

    pa = &tc->probes[tc->n_probes];
    pa->path = xstrdup(path);
    pa->op = xstrdup(op);
    pa->literal = xstrdup(trim(lit));

    tc->n_probes++;
}


static size_t
load_rules(const char *file, test_case *cases, size_t max)
{
    FILE    *fp;
    char     line[4096];
    size_t   n = 0, cap = 0;
    int      lineno = 0;
    int      open_case = 0;

    fp = fopen(file, "r");
    if (fp == NULL) {
        die("cannot open rule file %s", file);
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        char *p, *directive, *arg;

        lineno++;

        p = line;

        /* Strip the newline only -- trailing spaces can be significant inside
         * a send line, so trimming happens per-directive, not here. */
        p[strcspn(p, "\n")] = '\0';

        {
            char *probe = p;

            while (*probe != '\0' && isspace((unsigned char) *probe)) {
                probe++;
            }

            if (*probe == '\0') {
                open_case = 0;                        /* blank line ends stanza */
                continue;
            }

            if (*probe == '#') {
                continue;
            }

            p = probe;
        }

        directive = p;

        while (*p != '\0' && !isspace((unsigned char) *p)) {
            p++;
        }

        if (*p != '\0') {
            *p++ = '\0';
        }

        while (*p != '\0' && (*p == ' ' || *p == '\t')) {
            p++;
        }

        arg = p;

        if (strcmp(directive, "name") == 0) {
            if (n >= max) {
                die("%s:%d: too many cases (max %zu)", file, lineno, max);
            }

            n++;
            cap = 0;
            open_case = 1;
            cases[n - 1].name = xstrdup(trim(arg));
            continue;
        }

        if (!open_case || n == 0) {
            die("%s:%d: \"%s\" before any name directive",
                file, lineno, directive);
        }

        if (strcmp(directive, "send") == 0) {
            append_escaped(&cases[n - 1].request, &cases[n - 1].request_len,
                           &cap, arg);

        } else if (strcmp(directive, "expect") == 0) {
            parse_expect(&cases[n - 1], trim(arg), file, lineno);

        } else if (strcmp(directive, "probe") == 0) {
            parse_probe(&cases[n - 1], trim(arg), file, lineno);

        } else {
            die("%s:%d: unknown directive \"%s\"", file, lineno, directive);
        }
    }

    fclose(fp);

    return n;
}


/* ---- assertion evaluation --------------------------------------------- */

static int
compare_number(double have, const char *op, double want)
{
    if (strcmp(op, "==") == 0) return have == want;
    if (strcmp(op, "!=") == 0) return have != want;
    if (strcmp(op, "<")  == 0) return have <  want;
    if (strcmp(op, "<=") == 0) return have <= want;
    if (strcmp(op, ">")  == 0) return have >  want;
    if (strcmp(op, ">=") == 0) return have >= want;

    die("unknown numeric operator \"%s\"", op);
    return 0;
}


/* Strip surrounding double quotes from a rule literal, in place. */
static const char *
unquote(const char *lit, char *scratch, size_t scratchlen)
{
    size_t len = strlen(lit);

    if (len >= 2 && lit[0] == '"' && lit[len - 1] == '"') {
        if (len - 1 >= scratchlen) {
            die("literal too long: %s", lit);
        }

        memcpy(scratch, lit + 1, len - 2);
        scratch[len - 2] = '\0';

        return scratch;
    }

    return lit;
}


static int
eval_probe(const json_value *doc, const probe_assert *pa, char *why,
           size_t whylen)
{
    char              scratch[512];
    const char       *want;
    const json_value *v;

    v = json_get(doc, pa->path);

    if (v == NULL) {
        snprintf(why, whylen, "probe path \"%.128s\" not present in document",
                 pa->path);
        return 0;
    }

    want = unquote(pa->literal, scratch, sizeof(scratch));

    switch (v->type) {

    case JSON_NUMBER: {
        char   *stop;
        double  wanted = strtod(want, &stop);

        if (stop == want || *stop != '\0') {
            snprintf(why, whylen,
                     "%.128s is a number but the rule compares it to \"%.128s\"",
                     pa->path, want);
            return 0;
        }

        if (!compare_number(v->number, pa->op, wanted)) {
            snprintf(why, whylen, "%.128s: have %g, want %.16s %.128s",
                     pa->path, v->number, pa->op, want);
            return 0;
        }

        return 1;
    }

    case JSON_STRING:
        if (strcmp(pa->op, "==") == 0) {
            if (strcmp(v->string, want) != 0) {
                snprintf(why, whylen, "%.128s: have \"%.128s\", want \"%.128s\"",
                         pa->path, v->string, want);
                return 0;
            }
            return 1;
        }

        if (strcmp(pa->op, "!=") == 0) {
            if (strcmp(v->string, want) == 0) {
                snprintf(why, whylen, "%.128s: have \"%.128s\", want != \"%.128s\"",
                         pa->path, v->string, want);
                return 0;
            }
            return 1;
        }

        if (strcmp(pa->op, "~") == 0) {
            if (strstr(v->string, want) == NULL) {
                snprintf(why, whylen, "%.128s: \"%.128s\" does not contain \"%.128s\"",
                         pa->path, v->string, want);
                return 0;
            }
            return 1;
        }

        snprintf(why, whylen, "operator \"%.32s\" is not valid on a string",
                 pa->op);
        return 0;

    case JSON_BOOL: {
        int wanted = (strcmp(want, "true") == 0);

        if (strcmp(want, "true") != 0 && strcmp(want, "false") != 0) {
            snprintf(why, whylen,
                     "%.128s is a boolean but the rule compares it to \"%.128s\"",
                     pa->path, want);
            return 0;
        }

        if (strcmp(pa->op, "==") == 0) {
            if (v->boolean != wanted) {
                snprintf(why, whylen, "%.128s: have %s, want %.128s", pa->path,
                         v->boolean ? "true" : "false", want);
                return 0;
            }
            return 1;
        }

        snprintf(why, whylen, "operator \"%.32s\" is not valid on a boolean",
                 pa->op);
        return 0;
    }

    default:
        snprintf(why, whylen, "%.128s is of type %s, which cannot be compared",
                 pa->path, json_type_name(v->type));
        return 0;
    }
}


static json_value *
fetch_probe(char *errbuf, size_t errlen)
{
    char           req[512];
    int            n;
    const char    *jerr = NULL;
    json_value    *doc;
    http_response  resp;

    n = snprintf(req, sizeof(req),
                 "GET %s HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n",
                 opt_probe_uri);

    if (http_request(opt_host, opt_port, (const unsigned char *) req,
                     (size_t) n, opt_timeout_ms, &resp, errbuf, errlen) != 0)
    {
        return NULL;
    }

    if (resp.status != 200) {
        snprintf(errbuf, errlen, "probe endpoint returned status %d "
                 "(is shield_probe configured, and was the module built "
                 "with TEST_HARNESS=1?)", resp.status);
        http_response_free(&resp);
        return NULL;
    }

    if (resp.body == NULL) {
        snprintf(errbuf, errlen, "probe response had no body");
        http_response_free(&resp);
        return NULL;
    }

    doc = json_parse(resp.body, &jerr);

    if (doc == NULL) {
        snprintf(errbuf, errlen, "probe JSON parse failed: %s",
                 jerr ? jerr : "unknown");
    }

    http_response_free(&resp);

    return doc;
}


/* Returns 1 if the case passed. Diagnostics are printed as TAP comments. */
static int
run_case(const test_case *tc)
{
    char           errbuf[512];
    char           why[512];
    int            ok = 1;
    size_t         i;
    http_response  resp;

    if (tc->request_len == 0) {
        printf("# no send line in case \"%s\"\n", tc->name);
        return 0;
    }

    if (http_request(opt_host, opt_port, tc->request, tc->request_len,
                     opt_timeout_ms, &resp, errbuf, sizeof(errbuf)) != 0)
    {
        printf("# request failed: %s\n", errbuf);
        return 0;
    }

    if (opt_verbose) {
        printf("# <- status %d, %zu body bytes\n", resp.status, resp.body_len);
    }

    for (i = 0; i < tc->n_expects; i++) {
        const expectation *e = &tc->expects[i];

        switch (e->kind) {

        case EXPECT_STATUS:
            if (resp.status != (int) e->number) {
                printf("# status: have %d, want %ld\n",
                       resp.status, e->number);
                ok = 0;
            }
            break;

        case EXPECT_BODY_CONTAINS:
            if (resp.body == NULL
                || memmem(resp.body, resp.body_len,
                          e->text, strlen(e->text)) == NULL)
            {
                printf("# body does not contain \"%s\"\n", e->text);
                ok = 0;
            }
            break;

        case EXPECT_HEADER_CONTAINS:
            if (!http_has_header(&resp, e->text)) {
                printf("# no header matching \"%s\"\n", e->text);
                ok = 0;
            }
            break;
        }
    }

    http_response_free(&resp);

    if (tc->n_probes > 0) {
        json_value *doc = fetch_probe(errbuf, sizeof(errbuf));

        if (doc == NULL) {
            printf("# %s\n", errbuf);
            return 0;
        }

        for (i = 0; i < tc->n_probes; i++) {
            if (!eval_probe(doc, &tc->probes[i], why, sizeof(why))) {
                printf("# %s\n", why);
                ok = 0;
            }
        }

        json_free(doc);
    }

    return ok;
}


static void
usage(void)
{
    fprintf(stderr,
            "usage: prober [-H host] [-p port] [-u probe-uri] [-t ms] [-v]\n"
            "              <rulefile> [rulefile ...]\n");
    exit(2);
}


int
main(int argc, char **argv)
{
    int         i, argi, failures = 0, total = 0;
    size_t      n = 0, c;
    test_case  *cases;

    for (argi = 1; argi < argc; argi++) {
        if (argv[argi][0] != '-') {
            break;
        }

        if (strcmp(argv[argi], "-v") == 0) {
            opt_verbose = 1;
            continue;
        }

        if (argi + 1 >= argc) {
            usage();
        }

        if (strcmp(argv[argi], "-H") == 0) {
            opt_host = argv[++argi];

        } else if (strcmp(argv[argi], "-p") == 0) {
            opt_port = atoi(argv[++argi]);

        } else if (strcmp(argv[argi], "-u") == 0) {
            opt_probe_uri = argv[++argi];

        } else if (strcmp(argv[argi], "-t") == 0) {
            opt_timeout_ms = atoi(argv[++argi]);

        } else {
            usage();
        }
    }

    if (argi >= argc) {
        usage();
    }

    cases = calloc(MAX_CASES, sizeof(test_case));
    if (cases == NULL) {
        die("out of memory");
    }

    for (i = argi; i < argc; i++) {
        n += load_rules(argv[i], cases + n, MAX_CASES - n);
    }

    printf("1..%zu\n", n);

    for (c = 0; c < n; c++) {
        int ok = run_case(&cases[c]);

        total++;

        if (!ok) {
            failures++;
        }

        printf("%s %zu - %s\n", ok ? "ok" : "not ok", c + 1, cases[c].name);
        fflush(stdout);
    }

    for (c = 0; c < n; c++) {
        case_free(&cases[c]);
    }

    free(cases);

    if (failures > 0) {
        printf("# %d of %d cases failed\n", failures, total);
    }

    return failures > 0 ? 1 : 0;
}
