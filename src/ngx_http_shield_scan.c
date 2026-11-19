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
    const ngx_http_shield_ac_t *ac, u_char *data, size_t len, uint64_t skip,
    ngx_uint_t strict, ngx_uint_t *observed_row,
    ngx_http_shield_hit_t *observation, ngx_http_shield_hit_t *hit,
    const char *view);


/* Only these category-qualified byte strings have body-collision evidence.
 * Classify while building the cycle-owned immutable trie, never per request.
 * Separate outputs preserve same-category siblings ending at the same state. */
static ngx_uint_t
ngx_http_shield_body_observe(ngx_uint_t cat, const ngx_http_shield_sig_t *sig)
{
    if (cat == NGX_HTTP_SHIELD_CAT_OVERLONG
        && sig->len == sizeof("%c0%af") - 1
        && ngx_memcmp(sig->s, "%c0%af", sizeof("%c0%af") - 1) == 0)
    {
        return 1;
    }

    if (cat == NGX_HTTP_SHIELD_CAT_SQLI
        && sig->len == sizeof("union select") - 1
        && ngx_memcmp(sig->s, "union select", sizeof("union select") - 1) == 0)
    {
        return 1;
    }

    if (cat == NGX_HTTP_SHIELD_CAT_NOSQL
        && sig->len == sizeof("{\"$where\":") - 1
        && ngx_memcmp(sig->s, "{\"$where\":", sizeof("{\"$where\":") - 1) == 0)
    {
        return 1;
    }

    if (cat == NGX_HTTP_SHIELD_CAT_SSTI
        && sig->len == sizeof("{{7*7}}") - 1
        && ngx_memcmp(sig->s, "{{7*7}}", sizeof("{{7*7}}") - 1) == 0)
    {
        return 1;
    }

    if (cat == NGX_HTTP_SHIELD_CAT_SSRF_META
        && sig->len == sizeof("169.254.169.254") - 1
        && ngx_memcmp(sig->s, "169.254.169.254",
                      sizeof("169.254.169.254") - 1) == 0)
    {
        return 1;
    }

    if (cat == NGX_HTTP_SHIELD_CAT_SSRF_META
        && sig->len == sizeof("/latest/meta-data/") - 1
        && ngx_memcmp(sig->s, "/latest/meta-data/",
                      sizeof("/latest/meta-data/") - 1) == 0)
    {
        return 1;
    }

    if (cat == NGX_HTTP_SHIELD_CAT_SSI
        && sig->len == sizeof("<!--#include virtual") - 1
        && ngx_memcmp(sig->s, "<!--#include virtual",
                      sizeof("<!--#include virtual") - 1) == 0)
    {
        return 1;
    }

    if (cat == NGX_HTTP_SHIELD_CAT_RAILS_YAML
        && sig->len == sizeof("!ruby/object:") - 1
        && ngx_memcmp(sig->s, "!ruby/object:",
                      sizeof("!ruby/object:") - 1) == 0)
    {
        return 1;
    }

    return 0;
}


/* Length-delimited public-definition identity, independent of table position,
 * pointer width, byte order and request content. Unsigned wrap is intentional.
 */
static uint64_t
ngx_http_shield_identity_part(uint64_t hash, const u_char *data, size_t len)
{
    size_t  i;
    uint64_t size = (uint64_t) len;

    for (i = 0; i < 8; i++) {
        hash = (hash ^ (size & 255)) * UINT64_C(1099511628211);
        size >>= 8;
    }
    for (i = 0; i < len; i++) {
        hash = (hash ^ data[i]) * UINT64_C(1099511628211);
    }
    return hash;
}


uint64_t
ngx_http_shield_rule_identity(const char *kind, const char *name,
    const ngx_http_shield_sig_t *terms, ngx_uint_t nterms, ngx_uint_t flags)
{
    ngx_uint_t  i;
    u_char      metadata[2];
    uint64_t    hash = UINT64_C(14695981039346656037);

    hash = ngx_http_shield_identity_part(hash, (const u_char *) kind,
                                         ngx_strlen(kind));
    hash = ngx_http_shield_identity_part(hash, (const u_char *) name,
                                         ngx_strlen(name));
    metadata[0] = (u_char) flags;
    metadata[1] = NGX_HTTP_SHIELD_RULE_REVISION;
    hash = ngx_http_shield_identity_part(hash, metadata, sizeof(metadata));
    for (i = 0; i < nterms; i++) {
        hash = ngx_http_shield_identity_part(hash,
                   (const u_char *) terms[i].s, terms[i].len);
    }
    return hash;
}


uint64_t
ngx_http_shield_ruleset_identity(void)
{
    size_t    i, j, k;
    uint64_t  hash = UINT64_C(14695981039346656037), rule;
    u_char    encoded[8];

    for (i = 0; i < NGX_HTTP_SHIELD_NCATEGORIES + NGX_HTTP_SHIELD_NRULES; i++) {
        size_t count = i < NGX_HTTP_SHIELD_NCATEGORIES
                       ? ngx_http_shield_categories[i].nsigs : 1;
        for (j = 0; j < count; j++) {
            if (i < NGX_HTTP_SHIELD_NCATEGORIES) {
                const ngx_http_shield_catdef_t *cat =
                    &ngx_http_shield_categories[i];
                rule = ngx_http_shield_rule_identity("sig", cat->name,
                                      &cat->sigs[j], 1, cat->match);
            } else {
                const ngx_http_shield_ruledef_t *def =
                    &ngx_http_shield_rules[i - NGX_HTTP_SHIELD_NCATEGORIES];
                rule = ngx_http_shield_rule_identity("and", def->name,
                                    def->terms, def->nterms, def->match);
            }
            for (k = 0; k < sizeof(encoded); k++) {
                encoded[k] = (u_char) (rule & 255);
                rule >>= 8;
            }
            hash = ngx_http_shield_identity_part(hash, encoded,
                                                  sizeof(encoded));
        }
    }
    return hash;
}


/* Attribute only the chosen category at its accepting endpoint. This is a
 * bounded suffix comparison against static definitions, not another input scan
 * or an all-match production collector. Observe/enforce outputs may share an
 * endpoint and category, so apply the same policy partition as the trie. */
static uint64_t
ngx_http_shield_signature_identity(ngx_uint_t row, u_char *data, size_t end,
    ngx_uint_t strict, ngx_uint_t observation)
{
    size_t                          i;
    const ngx_http_shield_catdef_t  *cat = &ngx_http_shield_categories[row];

    for (i = 0; i < cat->nsigs; i++) {
        const ngx_http_shield_sig_t *sig = &cat->sigs[i];
        if (!strict && ngx_http_shield_body_observe(cat->cat, sig)
                       != observation)
        {
            continue;
        }
        if (sig->len <= end
            && ngx_memcmp(data + end - sig->len, sig->s, sig->len) == 0)
        {
            return ngx_http_shield_rule_identity("sig", cat->name, sig, 1,
                                                   cat->match);
        }
    }
    return 0; /* Unknown attribution must never invent a matching rule. */
}


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


ngx_int_t
ngx_http_shield_ac_capacity(ngx_log_t *log, size_t *cap,
    const ngx_http_shield_catdef_t *categories, size_t ncategories,
    const ngx_http_shield_ruledef_t *rules, size_t nrules, ngx_uint_t match)
{
    size_t  i, j;

    *cap = 1;
    for (i = 0; i < ncategories; i++) {
        if (!(categories[i].match & match)) {
            continue;
        }
        for (j = 0; j < categories[i].nsigs; j++) {
            if (ngx_http_shield_ac_capacity_add(cap,
                                                categories[i].sigs[j].len)
                != NGX_OK)
            {
                ngx_log_error(NGX_LOG_EMERG, log, 0,
                              "shield: signature set exceeds automaton "
                              "state limit");
                return NGX_ERROR;
            }
        }
    }

    for (i = 0; i < nrules; i++) {
        if (!(rules[i].match & match)) {
            continue;
        }
        for (j = 0; j < rules[i].nterms; j++) {
            if (ngx_http_shield_ac_capacity_add(cap, rules[i].terms[j].len)
                != NGX_OK)
            {
                ngx_log_error(NGX_LOG_EMERG, log, 0,
                              "shield: rule terms exceed automaton "
                              "state limit");
                return NGX_ERROR;
            }
        }
    }

    return NGX_OK;
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
    size_t                       next_bytes, mask_bytes, state_bytes;
    ngx_uint_t                   b, term;
    ngx_pool_t                  *temp;
    uint64_t                    *out, *rout, *observe;
    ngx_http_shield_ac_state_t  *next, *queue, *fail, s, v, f;

    /* One state per signature byte, plus the root. The BFS never creates a
     * state, so this checked count bounds every subsequent state index. */
    if (ngx_http_shield_ac_capacity(log, &cap, ngx_http_shield_categories,
                                    NGX_HTTP_SHIELD_NCATEGORIES,
                                    ngx_http_shield_rules,
                                    NGX_HTTP_SHIELD_NRULES, match)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* The compile-time count catches oversized tables early. Check the live
     * table again before assigning any bit position, so no shift depends on
     * the compile-time expression alone. */
    term = 0;
    for (i = 0; i < NGX_HTTP_SHIELD_NRULES; i++) {
        if (ngx_http_shield_rules[i].nterms > 64 - term) {
            ngx_log_error(NGX_LOG_EMERG, log, 0,
                          "shield: rule set exceeds 64 terms");
            return NGX_ERROR;
        }
        term += ngx_http_shield_rules[i].nterms;
    }

    /* Keep every allocation product explicit and checked. The state ceiling
     * above is already far below these limits on supported nginx targets, but
     * this makes that prerequisite local to the products it protects. */
    if (cap > NGX_MAX_SIZE_T_VALUE / NGX_HTTP_SHIELD_AC_ALPHABET
                                   / sizeof(*next)
        || cap > NGX_MAX_SIZE_T_VALUE / sizeof(*out)
        || cap > NGX_MAX_SIZE_T_VALUE / sizeof(*queue))
    {
        ngx_log_error(NGX_LOG_EMERG, log, 0,
                      "shield: automaton allocation size overflow");
        return NGX_ERROR;
    }

    next_bytes = cap * NGX_HTTP_SHIELD_AC_ALPHABET * sizeof(*next);
    mask_bytes = cap * sizeof(*out);
    state_bytes = cap * sizeof(*queue);

    /* next[] and out[] outlive the build and are read by every request, so
     * they come from the caller's pool (cf->pool in production). queue[] and
     * fail[] are build scratch: they go in a temporary pool that is destroyed
     * before this function returns. */
    next = ngx_pcalloc(pool, next_bytes);
    out = ngx_pcalloc(pool, mask_bytes);
    rout = ngx_pcalloc(pool, mask_bytes);
    observe = ngx_pcalloc(pool, mask_bytes);

    if (next == NULL || out == NULL || rout == NULL || observe == NULL) {
        return NGX_ERROR;
    }

    temp = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, log);
    if (temp == NULL) {
        return NGX_ERROR;
    }

    queue = ngx_palloc(temp, state_bytes);
    fail = ngx_pcalloc(temp, state_bytes);

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
            if (ngx_http_shield_body_observe(
                    ngx_http_shield_categories[i].cat, sig))
            {
                observe[s] |= (uint64_t) 1
                              << ngx_http_shield_categories[i].cat;
            } else {
                out[s] |= (uint64_t) 1 << ngx_http_shield_categories[i].cat;
            }
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
            observe[v] |= observe[f];

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
    ac->observe = observe;
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
 *   - a lowercased, percent-decoded copy for everything else, with raw '+'
 *     changed to space only in the form/query region given by form_offset.
 *
 * Both scratch buffers are supplied by the caller and must each hold at least
 * `len` bytes. ngx_unescape_uri never grows the buffer, so `len` is always
 * enough for the decoded copy. The allocation -- and the fail-closed path when
 * it fails -- lives at the call site, which is what keeps this function free
 * of any allocator policy and linkable outside nginx.
 */
ngx_int_t
ngx_http_shield_scan_input(const ngx_http_shield_automata_t *automata,
    u_char *data, size_t len, u_char *scratch_lc, u_char *scratch_dec,
    const char *source, size_t form_offset, uint64_t skip,
    ngx_http_shield_hit_t *hit)
{
    /* Preserve the public scanner's historical enforcement semantics. */
    return ngx_http_shield_scan_policy(automata, data, len, scratch_lc,
                                      scratch_dec, source, form_offset, skip,
                                      1, hit);
}


ngx_int_t
ngx_http_shield_scan_policy(const ngx_http_shield_automata_t *automata,
    u_char *data, size_t len, u_char *scratch_lc, u_char *scratch_dec,
    const char *source, size_t form_offset, uint64_t skip, ngx_uint_t strict,
    ngx_http_shield_hit_t *hit)
{
    size_t                           i, dlen;
    ngx_uint_t                       observed_row = NGX_HTTP_SHIELD_NCATEGORIES;
    ngx_http_shield_hit_t             observation;
    u_char                          *raw_lc, *dec, *dst, *src;
    const ngx_http_shield_catdef_t  *cat;

    if (len == 0) {
        return NGX_DECLINED;
    }

    raw_lc = scratch_lc;
    dec = scratch_dec;

    ngx_strlow(raw_lc, data, len);

    /* Raw signatures must see the untouched spelling, including percent
     * escapes and literal plus signs. Reuse this scratch only after that
     * scan. */
    cat = ngx_http_shield_ac_scan(&automata->raw, raw_lc, len, skip,
                                   strict, &observed_row, &observation, hit,
                                   "raw");
    if (cat != NULL) {
        hit->category = cat->name;
        hit->cat = cat->cat;
        hit->source = source;
        return NGX_OK;
    }

    /* Form/query '+' means space before percent decoding. A decoded %2B
     * remains a literal plus; paths and opaque headers preserve both forms. */
    for (i = form_offset; i < len; i++) {
        if (raw_lc[i] == '+') {
            raw_lc[i] = ' ';
        }
    }
    dst = dec;
    src = raw_lc;
    ngx_unescape_uri(&dst, &src, len, 0);
    dlen = dst - dec;
    ngx_strlow(dec, dec, dlen);

    cat = ngx_http_shield_ac_scan(&automata->decoded, dec, dlen, skip,
                                   strict, &observed_row, &observation, hit,
                                   "decoded");
    if (cat != NULL) {
        hit->category = cat->name;
        hit->cat = cat->cat;
        hit->source = source;
        return NGX_OK;
    }

    /* Observation is advisory. Both byte views and all AND rules have had
     * the chance to enforce before an ambiguous result can be returned. */
    if (observed_row < NGX_HTTP_SHIELD_NCATEGORIES) {
        *hit = observation;
        hit->source = source;
        return NGX_DONE;
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
    size_t len, uint64_t skip, ngx_uint_t strict, ngx_uint_t *observed_row,
    ngx_http_shield_hit_t *observation, ngx_http_shield_hit_t *hit,
    const char *view)
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

        live = ac->out[s];
        if (strict) {
            live |= ac->observe[s];
        } else {
            uint64_t pending = ac->observe[s] & ~skip;
            while (pending) {
                row = ac->row[ngx_http_shield_ac_lowest_bit(pending)];
                if (row < *observed_row) {
                    *observed_row = row;
                    observation->cat = ngx_http_shield_categories[row].cat;
                    observation->category =
                        ngx_http_shield_categories[row].name;
                    observation->rule = ngx_http_shield_signature_identity(
                                              row, data, i + 1, 0, 1);
                    observation->view = view;
                }
                pending &= pending - 1;
            }
        }
        live &= ~skip;
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
            hit->rule = ngx_http_shield_signature_identity(best, data,
                                                             i + 1, strict, 0);
            hit->view = view;
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
            hit->rule = ngx_http_shield_rule_identity("and",
                            ngx_http_shield_rules[i].name,
                            ngx_http_shield_rules[i].terms,
                            ngx_http_shield_rules[i].nterms,
                            ngx_http_shield_rules[i].match);
            hit->view = view;
            return &ngx_http_shield_categories[row];
        }
    }

    return NULL;
}
