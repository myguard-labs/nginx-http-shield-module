/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * fuzz_scan.c -- libFuzzer target for the ngx_http_shield scan core.
 *
 * Fuzz surface: the exact per-input normalize + scan pipeline the module runs
 * on every inspected buffer (URI, query, User-Agent, Referer, Content-Type,
 * body). For an arbitrary attacker-controlled byte string it:
 *
 *   1. builds the lowercased raw copy      (ngx_strlow)
 *   2. builds the percent-decoded copy     (ngx_unescape_uri) + '+'->' ' + lc
 *   3. scans the raw and/or decoded buffer per each category's match flags.
 *
 * DIFFERENTIAL. The module now uses an Aho-Corasick engine (ac_scan), which is
 * fast but non-obvious. This target runs TWO engines on every input:
 *   - the original naive per-signature memmem (shield_scan) -- simple enough to
 *     be correct by inspection, kept as the reference oracle;
 *   - a malloc port of the shipped AC engine (shield_scan_ac).
 * They must agree on hit / no-hit; a divergence aborts and libFuzzer saves the
 * input. This fuzzes the AC build + scan, which are otherwise untested against
 * hostile input, and proves the rewrite matches the reference on every string.
 *
 * Input layout: 8 bytes little-endian skip mask, then 1 position-fold byte
 * (bit 0 folds ngx_http_shield_no_body_mask() -- the fold
 * ngx_http_shield_inspect_body() applies in production; bit 1 folds
 * ngx_http_shield_no_query_mask() -- the fold the URI scan applies to the
 * query-ineligible categories), then the scanned payload.
 *
 * Keeping the decoder path (ngx_unescape_uri) real -- rather than a stub -- is
 * still the point: it is nginx's own hostile-input decoder, and the buffer
 * sizing around it (dec is len bytes; decoding only ever shrinks) is what we
 * prove never over-reads or over-writes under ASan/UBSan.
 *
 * The signature tables are the real ones: we include the module's
 * ngx_http_shield_patterns.h unchanged, so every fuzz run scans the exact set
 * shipped in production.
 *
 * Build: see fuzz/build.sh (needs nginx source headers under .build/).
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* Pull in the real signature tables (types come from ngx_core.h above). */
#include "../src/ngx_http_shield_patterns.h"

/*
 * ngx_string.c is linked whole so ngx_unescape_uri()/ngx_strlow() are the real
 * decoder. That drags in three symbols from functions we never call
 * (ngx_pstrdup -> ngx_pnalloc, ngx_sort -> ngx_alloc + ngx_cycle). Satisfy the
 * linker with stubs that abort if ever reached, so a future refactor that
 * routes the scan through them is caught rather than silently mislinked.
 */
volatile ngx_cycle_t  *ngx_cycle;

void *
ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    (void) pool; (void) size;
    abort();
}

void *
ngx_alloc(size_t size, ngx_log_t *log)
{
    (void) size; (void) log;
    abort();
}

/* Mirror of ngx_http_shield_memmem() in the module. Kept identical: a plain
 * forward substring search that never reads past haystack+hlen. */
static u_char *
shield_memmem(u_char *haystack, size_t hlen, const char *needle, size_t nlen)
{
    u_char  *p, *last;

    if (nlen == 0 || hlen < nlen) {
        return NULL;
    }

    last = haystack + hlen - nlen;

    for (p = haystack; p <= last; p++) {
        if (*p == (u_char) needle[0] && memcmp(p, needle, nlen) == 0) {
            return p;
        }
    }

    return NULL;
}

/*
 * Faithful copy of the scan body of ngx_http_shield_scan_input(), with the
 * two scratch buffers taken from the caller (heap) instead of r->pool. The
 * skip mask is fuzzed too (first eight bytes of the input, little-endian) so
 * both the enabled and skipped paths of the category loop are exercised.
 */
static int
shield_scan(u_char *data, size_t len, uint64_t skip)
{
    size_t                           i, j, dlen;
    u_char                          *raw_lc, *dec, *dst, *src;
    const ngx_http_shield_catdef_t  *cat;
    int                              hit = 0;

    if (len == 0) {
        return 0;
    }

    raw_lc = malloc(len);
    dec = malloc(len);
    if (raw_lc == NULL || dec == NULL) {
        free(raw_lc);
        free(dec);
        return 0;
    }

    ngx_strlow(raw_lc, data, len);

    dst = dec;
    src = data;
    ngx_unescape_uri(&dst, &src, len, 0);
    dlen = dst - dec;

    for (i = 0; i < dlen; i++) {
        if (dec[i] == '+') {
            dec[i] = ' ';
        }
    }
    ngx_strlow(dec, dec, dlen);

    for (i = 0; i < NGX_HTTP_SHIELD_NCATEGORIES; i++) {
        cat = &ngx_http_shield_categories[i];

        if (skip & ((uint64_t) 1 << cat->cat)) {
            continue;
        }

        for (j = 0; j < cat->nsigs; j++) {
            const ngx_http_shield_sig_t  *sig = &cat->sigs[j];

            if ((cat->match & NGX_HTTP_SHIELD_MATCH_RAW)
                && shield_memmem(raw_lc, len, sig->s, sig->len) != NULL)
            {
                hit = 1;
                goto done;
            }

            if ((cat->match & NGX_HTTP_SHIELD_MATCH_DECODED)
                && shield_memmem(dec, dlen, sig->s, sig->len) != NULL)
            {
                hit = 1;
                goto done;
            }
        }
    }

    /* AND-rules, the same way the module evaluates them: a rule fires when
     * EVERY one of its terms is present in the SAME normalized buffer. Kept in
     * lockstep with ngx_http_shield_ac_scan() by construction -- if the module
     * grows a rule and this does not, the differential diverges and aborts,
     * which is the point.
     *
     * Note the per-buffer quantifier: all terms in the raw copy, or all terms
     * in the decoded copy. "One term raw, one term decoded" is NOT a match. */
    for (i = 0; i < NGX_HTTP_SHIELD_NRULES; i++) {
        const ngx_http_shield_ruledef_t  *rule = &ngx_http_shield_rules[i];
        int                               all_raw, all_dec;

        if (skip & ((uint64_t) 1 << rule->cat)) {
            continue;
        }

        all_raw = (rule->match & NGX_HTTP_SHIELD_MATCH_RAW) ? 1 : 0;
        all_dec = (rule->match & NGX_HTTP_SHIELD_MATCH_DECODED) ? 1 : 0;

        for (j = 0; j < rule->nterms; j++) {
            const ngx_http_shield_sig_t  *t = &rule->terms[j];

            if (all_raw
                && shield_memmem(raw_lc, len, t->s, t->len) == NULL)
            {
                all_raw = 0;
            }

            if (all_dec
                && shield_memmem(dec, dlen, t->s, t->len) == NULL)
            {
                all_dec = 0;
            }
        }

        if (all_raw || all_dec) {
            hit = 1;
            goto done;
        }
    }

done:
    free(raw_lc);
    free(dec);
    return hit;
}

/* ---- Aho-Corasick oracle (malloc port of the module's engine) ----------
 *
 * A standalone copy of ngx_http_shield_ac_build()/ac_scan() from the module,
 * ported off ngx_pool_t onto malloc so it links into the fuzz target without a
 * cycle. It reads the SAME ngx_http_shield_categories[] table as the naive
 * scan above, so the two are true differential oracles: every fuzz input is run
 * through both and they must agree on hit / no-hit (see the assert in
 * LLVMFuzzerTestOneInput). The naive engine -- simple enough to be obviously
 * correct -- is the reference; any divergence aborts and libFuzzer saves the
 * input.
 *
 * Keep this port in lockstep with the module. out[] is a MASK of the categories
 * accepting at a state, not a single id: one state can accept several (shared
 * signature string, or a short signature ending inside a longer one from
 * another category, unioned along fail links). Storing one id per state is
 * exactly the detection bypass this harness caught -- the naive oracle checks
 * every signature independently and so never had it.
 *
 * Note: this asserts hit/no-hit parity, NOT same-category. The naive scan is
 * category-major (first matching category in table order) while AC is
 * buffer-major (whole RAW automaton, then whole DECODED); on an input matching
 * two categories they may legitimately name different ones. Both are valid
 * blocks, so category identity is deliberately not part of the invariant.
 */
#define AC_ALPHABET  256

typedef struct {
    uint16_t  *next;   /* [nstates][256] */
    uint64_t  *out;    /* [nstates] accepting-category mask */
    uint64_t  *rout;   /* [nstates] accepting rule-TERM mask */
    uint64_t   need[NGX_HTTP_SHIELD_NRULES];  /* per-rule required term set */
    size_t     nstates;
} ac_t;

static ac_t  ac_decoded, ac_raw;

/* Build one automaton over every category carrying `match`. Aborts on OOM or
 * on a state-count overflow -- the fuzzer wants a loud failure, not a skip. */
static void
ac_build_fuzz(ac_t *ac, ngx_uint_t match)
{
    size_t     i, j, k, cap, nstates, head, tail;
    ngx_uint_t b, term;
    uint16_t  *next, *queue, *fail, s, v, f;
    uint64_t  *out, *rout;

    cap = 1;
    for (i = 0; i < NGX_HTTP_SHIELD_NCATEGORIES; i++) {
        if (!(ngx_http_shield_categories[i].match & match)) {
            continue;
        }
        for (j = 0; j < ngx_http_shield_categories[i].nsigs; j++) {
            cap += ngx_http_shield_categories[i].sigs[j].len;
        }
    }
    for (i = 0; i < NGX_HTTP_SHIELD_NRULES; i++) {
        if (!(ngx_http_shield_rules[i].match & match)) {
            continue;
        }
        for (j = 0; j < ngx_http_shield_rules[i].nterms; j++) {
            cap += ngx_http_shield_rules[i].terms[j].len;
        }
    }

    term = 0;
    for (i = 0; i < NGX_HTTP_SHIELD_NRULES; i++) {
        term += ngx_http_shield_rules[i].nterms;
    }
    if (term > 64) {
        abort();
    }

    if (cap > 65535) {
        abort();
    }

    next = calloc(cap * AC_ALPHABET, sizeof(*next));
    out = calloc(cap, sizeof(*out));
    rout = calloc(cap, sizeof(*rout));
    queue = malloc(cap * sizeof(*queue));
    fail = calloc(cap, sizeof(*fail));
    if (next == NULL || out == NULL || rout == NULL || queue == NULL
        || fail == NULL)
    {
        abort();
    }

    nstates = 1;
    for (i = 0; i < NGX_HTTP_SHIELD_NCATEGORIES; i++) {
        if (!(ngx_http_shield_categories[i].match & match)) {
            continue;
        }
        for (j = 0; j < ngx_http_shield_categories[i].nsigs; j++) {
            const ngx_http_shield_sig_t  *sig =
                &ngx_http_shield_categories[i].sigs[j];
            s = 0;
            for (k = 0; k < sig->len; k++) {
                b = (u_char) sig->s[k];
                if (next[(size_t) s * AC_ALPHABET + b] == 0) {
                    next[(size_t) s * AC_ALPHABET + b] = (uint16_t) nstates++;
                }
                s = next[(size_t) s * AC_ALPHABET + b];
            }
            out[s] |= (uint64_t) 1 << ngx_http_shield_categories[i].cat;
        }
    }

    /* Rule terms into the same trie: rout[] only, never out[]. */
    term = 0;
    for (i = 0; i < NGX_HTTP_SHIELD_NRULES; i++) {
        ac->need[i] = 0;
        for (j = 0; j < ngx_http_shield_rules[i].nterms; j++, term++) {
            const ngx_http_shield_sig_t  *t = &ngx_http_shield_rules[i].terms[j];
            if (!(ngx_http_shield_rules[i].match & match)) {
                continue;
            }
            ac->need[i] |= (uint64_t) 1 << term;
            s = 0;
            for (k = 0; k < t->len; k++) {
                b = (u_char) t->s[k];
                if (next[(size_t) s * AC_ALPHABET + b] == 0) {
                    next[(size_t) s * AC_ALPHABET + b] = (uint16_t) nstates++;
                }
                s = next[(size_t) s * AC_ALPHABET + b];
            }
            rout[s] |= (uint64_t) 1 << term;
        }
    }

    head = tail = 0;
    for (b = 0; b < AC_ALPHABET; b++) {
        v = next[b];
        if (v != 0) {
            queue[tail++] = v;
        }
    }
    while (head < tail) {
        s = queue[head++];
        for (b = 0; b < AC_ALPHABET; b++) {
            v = next[(size_t) s * AC_ALPHABET + b];
            f = next[(size_t) fail[s] * AC_ALPHABET + b];
            if (v == 0) {
                next[(size_t) s * AC_ALPHABET + b] = f;
                continue;
            }
            fail[v] = f;
            out[v] |= out[f];
            rout[v] |= rout[f];
            queue[tail++] = v;
        }
    }

    free(queue);
    free(fail);

    ac->next = next;
    ac->out = out;
    ac->rout = rout;
    ac->nstates = nstates;
}

static int
ac_scan_fuzz(const ac_t *ac, u_char *data, size_t len, uint64_t skip)
{
    size_t    i;
    uint64_t  seen = 0;
    uint16_t  s = 0;

    for (i = 0; i < len; i++) {
        s = ac->next[(size_t) s * AC_ALPHABET + data[i]];

        seen |= ac->rout[s];

        /* out[s] is the SET of categories accepting here; ~skip drops the
         * disabled ones. Hit/no-hit only -- the caller does not care which
         * category, so no table-order tiebreak is needed (unlike the module). */
        if (ac->out[s] & ~skip) {
            return 1;
        }
    }

    /* AND-rules: every term of the rule seen in THIS buffer. */
    for (i = 0; i < NGX_HTTP_SHIELD_NRULES; i++) {
        if (ac->need[i] == 0) {
            continue;
        }
        if ((seen & ac->need[i]) != ac->need[i]) {
            continue;
        }
        if (skip & ((uint64_t) 1 << ngx_http_shield_rules[i].cat)) {
            continue;
        }
        return 1;
    }

    return 0;
}

/* Same normalize + double-automaton scan the module's scan_input() runs. */
static int
shield_scan_ac(u_char *data, size_t len, uint64_t skip)
{
    size_t   i, dlen;
    u_char  *raw_lc, *dec, *dst, *src;
    int      hit;

    if (len == 0) {
        return 0;
    }

    raw_lc = malloc(len);
    dec = malloc(len);
    if (raw_lc == NULL || dec == NULL) {
        free(raw_lc);
        free(dec);
        return 0;
    }

    ngx_strlow(raw_lc, data, len);

    dst = dec;
    src = data;
    ngx_unescape_uri(&dst, &src, len, 0);
    dlen = dst - dec;
    for (i = 0; i < dlen; i++) {
        if (dec[i] == '+') {
            dec[i] = ' ';
        }
    }
    ngx_strlow(dec, dec, dlen);

    hit = ac_scan_fuzz(&ac_raw, raw_lc, len, skip)
          || ac_scan_fuzz(&ac_decoded, dec, dlen, skip);

    free(raw_lc);
    free(dec);
    return hit;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint64_t   skip = 0;
    u_char    *buf;
    static int built;

    if (!built) {
        ac_build_fuzz(&ac_decoded, NGX_HTTP_SHIELD_MATCH_DECODED);
        ac_build_fuzz(&ac_raw, NGX_HTTP_SHIELD_MATCH_RAW);
        built = 1;
    }

    /* Consume the first eight bytes (explicit little-endian decode) as the
     * FULL skip mask. Expanding a single byte across the mask tied together
     * every pair of categories whose enum positions agree modulo 8, so the
     * oracle could never skip one while leaving the other enabled -- the
     * exact cross-category masking class this harness exists to find. */
    if (size >= 8) {
        size_t  i;

        for (i = 0; i < 8; i++) {
            skip |= (uint64_t) data[i] << (i * 8);
        }
        data += 8;
        size -= 8;
    }

    if (size == 0) {
        return 0;
    }

    /* One more byte selects the position-fold mode. The module folds a
     * position mask into the skip mask at specific scan sites only:
     *   bit 0 -> ngx_http_shield_no_body_mask(), on the body scan;
     *   bit 1 -> ngx_http_shield_no_query_mask(), on the whole-target scan of
     *            the URI (the query-ineligible categories).
     * Fuzzing these dimensions independently -- rather than only ever scanning
     * as if this were an unmasked path/header -- exercises the folds themselves:
     * a category wrongly left out of (or wrongly added to) either mask would
     * otherwise never surface as a differential, since both engines below would
     * just agree on the wrong answer. */
    if (data[0] & 1) {
        skip |= ngx_http_shield_no_body_mask();
    }
    if (data[0] & 2) {
        skip |= ngx_http_shield_no_query_mask();
    }
    data += 1;
    size -= 1;

    if (size == 0) {
        return 0;
    }

    /* Copy into a fresh buffer so ngx_strlow/ngx_unescape_uri write in place
     * over a heap allocation ASan can bound-check exactly. */
    buf = malloc(size);
    if (buf == NULL) {
        return 0;
    }
    memcpy(buf, data, size);

    /* Differential: the naive engine (obvious-by-inspection reference) and the
     * shipped Aho-Corasick engine must agree that this input is a hit or not.
     * Both read the same signature table; a divergence is a real bug in the
     * rewrite and aborts so libFuzzer records the input. */
    {
        int naive = shield_scan(buf, size, skip);
        int ac = shield_scan_ac(buf, size, skip);
        if (naive != ac) {
            fprintf(stderr,
                    "SHIELD DIFFERENTIAL: naive=%d ac=%d len=%zu skip=%#llx\n",
                    naive, ac, size, (unsigned long long) skip);
            abort();
        }
    }

    free(buf);
    return 0;
}
