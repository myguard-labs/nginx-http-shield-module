/*
 * Copyright (C) 2026 Thijs Eilander
 *
 * The decision core: normalization, the Aho-Corasick automata, and the scan
 * that turns a buffer into a verdict. See ngx_http_shield_scan.h for why this
 * is a separate translation unit -- in short, so the unit tests and the fuzz
 * targets compile the REAL scanner instead of a copy that drifts.
 *
 * Includes <ngx_core.h> only. Nothing here may reach for ngx_http_request_t:
 * that is the invariant the whole split exists to hold, and ci/linter and the
 * unit build both check it.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_http_shield_scan.h"

/* ---- Aho-Corasick ------------------------------------------------------ */

/* File-local: the scan is reached through ngx_http_shield_scan_input(), which
 * picks the right automaton for each buffer flavour. Defined below its callers,
 * so it needs a prototype here. */
static const ngx_http_shield_catdef_t *ngx_http_shield_ac_scan(
    const ngx_http_shield_ac_t *ac, u_char *data, size_t len, uint64_t skip);


/* Built once at postconfiguration, read-only thereafter. One automaton per
 * buffer flavour, because categories disagree about which buffer they scan. */
ngx_http_shield_ac_t  ngx_http_shield_ac_decoded;
ngx_http_shield_ac_t  ngx_http_shield_ac_raw;


/* Index of the lowest set bit. Only ever called with m != 0. */
static ngx_inline ngx_uint_t
ngx_http_shield_ac_lowest_bit(uint64_t m)
{
#if (__GNUC__ || __clang__)
    return (ngx_uint_t) __builtin_ctzll(m);
#else
    ngx_uint_t  n = 0;

    while (!(m & 1)) {
        m >>= 1;
        n++;
    }

    return n;
#endif
}


/*
 * Build the automaton over every signature of every category carrying `match`.
 *
 * Two passes: a goto-trie, then a BFS that resolves fail links and flattens
 * them into the goto table, so the scan never walks a fail chain -- each input
 * byte is exactly one array lookup.
 *
 * Output sets are UNIONED along fail links (out[v] |= out[fail[v]]), which is
 * what lets a short signature be found while the trie is deep inside a longer
 * one that shares its suffix -- including when the two belong to different
 * categories, which is why out[] is a mask rather than a single category id.
 */
ngx_int_t
ngx_http_shield_ac_build(ngx_pool_t *pool, ngx_log_t *log,
    ngx_http_shield_ac_t *ac, ngx_uint_t match)
{
    size_t                       i, j, k, cap, nstates, head, tail;
    ngx_uint_t                   b, term;
    ngx_pool_t                  *temp;
    uint64_t                    *out, *rout;
    ngx_http_shield_ac_state_t  *next, *queue, *fail, s, v, f;

    /* Upper bound on trie size: one state per signature byte, plus the root.
     * The BFS below never creates a state, so this is never exceeded. */
    cap = 1;
    for (i = 0; i < NGX_HTTP_SHIELD_NCATEGORIES; i++) {
        if (!(ngx_http_shield_categories[i].match & match)) {
            continue;
        }
        for (j = 0; j < ngx_http_shield_categories[i].nsigs; j++) {
            cap += ngx_http_shield_categories[i].sigs[j].len;
        }
    }

    /* Rule terms live in the same trie -- they are matched by the same pass. */
    for (i = 0; i < NGX_HTTP_SHIELD_NRULES; i++) {
        if (!(ngx_http_shield_rules[i].match & match)) {
            continue;
        }
        for (j = 0; j < ngx_http_shield_rules[i].nterms; j++) {
            cap += ngx_http_shield_rules[i].terms[j].len;
        }
    }

    /* The compile-time count is a useful early failure, but it is assembled
     * from sizeof() terms and can be left stale when a rule is appended. Keep
     * the shift itself safe independently of that bookkeeping. */
    term = 0;
    for (i = 0; i < NGX_HTTP_SHIELD_NRULES; i++) {
        term += ngx_http_shield_rules[i].nterms;
    }
    if (term > 64) {
        ngx_log_error(NGX_LOG_EMERG, log, 0,
                           "shield: rule set has %ui terms, max 64", term);
        return NGX_ERROR;
    }

    if (cap > NGX_HTTP_SHIELD_AC_MAX_STATES) {
        ngx_log_error(NGX_LOG_EMERG, log, 0,
                           "shield: signature set too large for the "
                           "automaton (%uz states, max %d)",
                           cap, NGX_HTTP_SHIELD_AC_MAX_STATES);
        return NGX_ERROR;
    }

    /* next[] and out[] outlive the build and are read by every request, so
     * they come from the caller's pool (cf->pool in production). queue[] and
     * fail[] are build scratch: they go in a temporary pool that is destroyed
     * before this function returns. */
    next = ngx_pcalloc(pool,
                       cap * NGX_HTTP_SHIELD_AC_ALPHABET * sizeof(*next));
    out = ngx_pcalloc(pool, cap * sizeof(*out));
    rout = ngx_pcalloc(pool, cap * sizeof(*rout));

    if (next == NULL || out == NULL || rout == NULL) {
        return NGX_ERROR;
    }

    temp = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, log);
    if (temp == NULL) {
        return NGX_ERROR;
    }

    queue = ngx_palloc(temp, cap * sizeof(*queue));
    fail = ngx_pcalloc(temp, cap * sizeof(*fail));

    if (queue == NULL || fail == NULL) {
        ngx_destroy_pool(temp);
        return NGX_ERROR;
    }

    /* Reverse index: accepting-mask bit -> category table row. Only rows in
     * THIS automaton are mapped; bits for the others are never set in out[]. */
    for (i = 0; i < 64; i++) {
        ac->row[i] = NGX_HTTP_SHIELD_NCATEGORIES;
    }

    for (i = 0; i < NGX_HTTP_SHIELD_NCATEGORIES; i++) {
        if (ngx_http_shield_categories[i].match & match) {
            ac->row[ngx_http_shield_categories[i].cat] = (ngx_uint_t) i;
        }
    }

    /* A rule reports a category, and it may be one whose signature TABLE is not
     * in this automaton (a RAW rule naming a DECODED-only category). Map those
     * rows too, or the rule would match and then have nothing to report. */
    for (i = 0; i < NGX_HTTP_SHIELD_NRULES; i++) {
        if (!(ngx_http_shield_rules[i].match & match)) {
            continue;
        }

        for (j = 0; j < NGX_HTTP_SHIELD_NCATEGORIES; j++) {
            if (ngx_http_shield_categories[j].cat
                == ngx_http_shield_rules[i].cat)
            {
                ac->row[ngx_http_shield_rules[i].cat] = (ngx_uint_t) j;
                break;
            }
        }
    }

    /* Pass 1: goto-trie. State 0 is the root; 0 in next[] means "absent" here,
     * which is unambiguous because the root can never be a target. */
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

                if (next[(size_t) s * NGX_HTTP_SHIELD_AC_ALPHABET + b] == 0) {
                    next[(size_t) s * NGX_HTTP_SHIELD_AC_ALPHABET + b] =
                        (ngx_http_shield_ac_state_t) nstates;
                    nstates++;
                }

                s = next[(size_t) s * NGX_HTTP_SHIELD_AC_ALPHABET + b];
            }

            /* Accept for THIS category, without evicting any other category
             * that also accepts here (two categories may share a signature
             * string). ac_scan resolves a multi-category state by table
             * order. */
            out[s] |= (uint64_t) 1 << ngx_http_shield_categories[i].cat;
        }
    }

    /* Pass 1b: rule terms into the SAME trie. A term sets a bit in rout[] and
     * never in out[], so it is matched by the same per-byte lookup but cannot
     * fire a category by itself -- only a rule whose whole term set was seen
     * can. Term ids are assigned across ngx_http_shield_rules[] in declaration
     * order, independently of `match`, so a term's bit means the same thing in
     * both automatons. */
    term = 0;

    for (i = 0; i < NGX_HTTP_SHIELD_NRULES; i++) {
        ac->need[i] = 0;

        for (j = 0; j < ngx_http_shield_rules[i].nterms; j++, term++) {
            const ngx_http_shield_sig_t  *t =
                &ngx_http_shield_rules[i].terms[j];

            if (!(ngx_http_shield_rules[i].match & match)) {
                continue;
            }

            ac->need[i] |= (uint64_t) 1 << term;

            s = 0;

            for (k = 0; k < t->len; k++) {
                b = (u_char) t->s[k];

                if (next[(size_t) s * NGX_HTTP_SHIELD_AC_ALPHABET + b] == 0) {
                    next[(size_t) s * NGX_HTTP_SHIELD_AC_ALPHABET + b] =
                        (ngx_http_shield_ac_state_t) nstates;
                    nstates++;
                }

                s = next[(size_t) s * NGX_HTTP_SHIELD_AC_ALPHABET + b];
            }

            rout[s] |= (uint64_t) 1 << term;
        }
    }

    /* Pass 2: BFS. Resolve fail links and flatten them into next[], so an
     * absent transition already points at the correct fallback state. */
    head = 0;
    tail = 0;

    for (b = 0; b < NGX_HTTP_SHIELD_AC_ALPHABET; b++) {
        v = next[b];
        if (v != 0) {
            queue[tail++] = v;
        }
    }

    while (head < tail) {
        s = queue[head++];

        /* fail(s) is already flattened into next[] by the time s is dequeued,
         * because BFS visits s's parent before s. */
        for (b = 0; b < NGX_HTTP_SHIELD_AC_ALPHABET; b++) {
            v = next[(size_t) s * NGX_HTTP_SHIELD_AC_ALPHABET + b];

            /* fail state of s, reached via this byte */
            f = next[(size_t) fail[s] * NGX_HTTP_SHIELD_AC_ALPHABET + b];

            if (v == 0) {
                next[(size_t) s * NGX_HTTP_SHIELD_AC_ALPHABET + b] = f;
                continue;
            }

            fail[v] = f;

            /* UNION, not copy-if-unset: v may already accept its own category
             * while its fail state f accepts a different one (a shorter
             * signature ending at the same offset). Keeping only the first
             * dropped the other -- the detection bypass this replaces. */
            out[v] |= out[f];

            /* Rule terms union along the fail links for the same reason: a
             * term ending inside a longer signature (or inside another term)
             * must still be recorded, or its rule could never complete. */
            rout[v] |= rout[f];

            queue[tail++] = v;
        }
    }

    ngx_destroy_pool(temp);

    ac->next = next;
    ac->out = out;
    ac->rout = rout;
    ac->nstates = nstates;

    return NGX_OK;
}


/* ---- normalization + scan ---------------------------------------------- */

/*
 * Scan one input buffer against every enabled signature category.
 *
 * Two normalized copies are built from the raw input:
 *   - a lowercased copy of the raw bytes, for categories that must see the
 *     still-encoded form (overlong UTF-8, %00, %0d%0a, double-encoding);
 *   - a percent-decoded, '+'->space, lowercased copy for everything else.
 *
 * Both scratch buffers are supplied by the caller and must each hold at least
 * `len` bytes. ngx_unescape_uri never grows the buffer, so `len` is always
 * enough for the decoded copy. The allocation -- and the fail-closed path when
 * it fails -- lives at the call site, which is what keeps this function free
 * of any allocator policy and linkable outside nginx.
 */
ngx_int_t
ngx_http_shield_scan_input(u_char *data, size_t len, u_char *scratch_lc,
    u_char *scratch_dec, const char *source, uint64_t skip,
    ngx_http_shield_hit_t *hit)
{
    size_t                           i, dlen;
    u_char                          *raw_lc, *dec, *dst, *src;
    const ngx_http_shield_catdef_t  *cat;

    if (len == 0) {
        return NGX_DECLINED;
    }

    raw_lc = scratch_lc;
    dec = scratch_dec;

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

    cat = ngx_http_shield_ac_scan(&ngx_http_shield_ac_raw, raw_lc, len,
                                  skip);
    if (cat != NULL) {
        hit->category = cat->name;
        hit->cat = cat->cat;
        hit->source = source;
        return NGX_OK;
    }

    cat = ngx_http_shield_ac_scan(&ngx_http_shield_ac_decoded, dec, dlen,
                                  skip);
    if (cat != NULL) {
        hit->category = cat->name;
        hit->cat = cat->cat;
        hit->source = source;
        return NGX_OK;
    }

    return NGX_DECLINED;
}


/*
 * One pass over the buffer for every signature in the automaton. out[s] is the
 * set of categories accepting at state s, as a bitmask; masking it with ~skip
 * drops the categories disabled via shield_skip in one operation, so a skipped
 * category can neither be reported nor mask a live one sharing its state.
 *
 * A state may accept several live categories at once. The winner is the one
 * with the lowest CATEGORY TABLE ROW, which is the category the old per-
 * signature engine would have reported (it scanned the table in order). Bit
 * position is deliberately not used as the tiebreak: it tracks the enum, and
 * the enum and the table are free to diverge.
 */
static const ngx_http_shield_catdef_t *
ngx_http_shield_ac_scan(const ngx_http_shield_ac_t *ac, u_char *data,
    size_t len, uint64_t skip)
{
    size_t                      i;
    uint64_t                    live, seen;
    ngx_uint_t                  row, best;
    ngx_http_shield_ac_state_t  s = 0;

    if (ac->nstates == 0) {
        return NULL;
    }

    seen = 0;

    for (i = 0; i < len; i++) {
        s = ac->next[(size_t) s * NGX_HTTP_SHIELD_AC_ALPHABET + data[i]];

        /* Rule terms: accumulate, never decide. This is the only added work in
         * the hot loop -- one OR against a mask that is zero for every state
         * that ends no rule term, which is nearly all of them. */
        seen |= ac->rout[s];

        live = ac->out[s] & ~skip;
        if (live == 0) {
            continue;
        }

        best = NGX_HTTP_SHIELD_NCATEGORIES;

        do {
            row = ac->row[ngx_http_shield_ac_lowest_bit(live)];
            if (row < best) {
                best = row;
            }
            live &= live - 1;   /* clear lowest set bit */
        } while (live);

        if (best < NGX_HTTP_SHIELD_NCATEGORIES) {
            /* A standalone signature already decides the request, so there is
             * nothing an AND-rule could add: return without evaluating them.
             * This keeps the standalone path exactly as fast as it was. */
            return &ngx_http_shield_categories[best];
        }
    }

    /* No standalone signature fired. Evaluate the AND-rules: a rule matches
     * when every one of its terms was seen somewhere in this buffer. */
    if (seen == 0) {
        return NULL;
    }

    for (i = 0; i < NGX_HTTP_SHIELD_NRULES; i++) {

        /* need == 0 means the rule contributes no term to THIS automaton
         * (wrong `match` flavour); it must not match trivially. */
        if (ac->need[i] == 0) {
            continue;
        }

        if ((seen & ac->need[i]) != ac->need[i]) {
            continue;
        }

        if (skip & ((uint64_t) 1 << ngx_http_shield_rules[i].cat)) {
            continue;
        }

        row = ac->row[ngx_http_shield_rules[i].cat];

        if (row < NGX_HTTP_SHIELD_NCATEGORIES) {
            return &ngx_http_shield_categories[row];
        }
    }

    return NULL;
}
