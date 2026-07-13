/*
 * ngx_http_shield_module.c
 *
 * A small nginx dynamic module that blocks exploitation of web
 * vulnerabilities that were patched years ago -- SQL injection, ancient PHP/
 * Java RCE chains, Log4Shell, Shellshock, path traversal, cloud-metadata
 * SSRF, and so on. It is deliberately NOT a general-purpose WAF: every
 * signature is chosen so that no legitimate client ever sends it, which keeps
 * the false-positive rate near zero and makes it safe to enable in front of a
 * large, mixed, not-fully-patched customer base.
 *
 * Signatures live in ngx_http_shield_patterns.h. The engine here normalizes
 * each input (percent-decode once, lowercase, '+' -> space) and runs a plain
 * substring scan of every enabled category's patterns over it, plus two
 * structural checks (httpoxy Proxy header, Apache-Killer Range).
 *
 * Runs in the PRECONTENT phase so that, when body inspection is enabled, it
 * can read the request body and then resume phase processing -- the same
 * mechanism the stock ngx_http_mirror_module uses.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_shield_patterns.h"


#define NGX_HTTP_SHIELD_OFF     0
#define NGX_HTTP_SHIELD_DETECT  1
#define NGX_HTTP_SHIELD_BLOCK   2

/* Maximum number of comma-separated ranges tolerated in a Range header before
 * it is treated as an Apache-Killer (CVE-2011-3192) attempt. */
#define NGX_HTTP_SHIELD_MAX_RANGES  10


typedef struct {
    ngx_uint_t   mode;        /* OFF / DETECT / BLOCK                        */
    ngx_flag_t   body;        /* inspect request body                       */
    size_t       max_body;    /* bytes of body scanned                      */
    ngx_uint_t   status;      /* status returned in BLOCK mode              */
    uint64_t     skip;        /* bitmask of disabled categories             */
} ngx_http_shield_loc_conf_t;


typedef struct {
    ngx_int_t    status;      /* re-entry value after body read             */
} ngx_http_shield_ctx_t;


/* A single detection result, for logging. */
typedef struct {
    const char  *category;
    const char  *source;      /* "uri" / "user-agent" / "body" / ...        */
} ngx_http_shield_hit_t;


static ngx_int_t ngx_http_shield_handler(ngx_http_request_t *r);
static void ngx_http_shield_body_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_shield_inspect_prebody(ngx_http_request_t *r,
    ngx_http_shield_loc_conf_t *slcf, ngx_http_shield_hit_t *hit);
static ngx_int_t ngx_http_shield_inspect_body(ngx_http_request_t *r,
    ngx_http_shield_loc_conf_t *slcf, ngx_http_shield_hit_t *hit);
static ngx_int_t ngx_http_shield_act(ngx_http_request_t *r,
    ngx_http_shield_loc_conf_t *slcf, ngx_http_shield_hit_t *hit);

static ngx_int_t ngx_http_shield_scan_input(ngx_http_request_t *r,
    ngx_http_shield_loc_conf_t *slcf, u_char *data, size_t len,
    const char *source, ngx_http_shield_hit_t *hit);
static u_char *ngx_http_shield_memmem(u_char *haystack, size_t hlen,
    const char *needle, size_t nlen);
static ngx_int_t ngx_http_shield_scannable_body(ngx_http_request_t *r);

static void *ngx_http_shield_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_shield_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_shield_mode(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_shield_status(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_shield_skip(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_shield_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_shield_commands[] = {

    { ngx_string("shield"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_shield_mode,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("shield_body"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_shield_loc_conf_t, body),
      NULL },

    { ngx_string("shield_max_body"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_shield_loc_conf_t, max_body),
      NULL },

    { ngx_string("shield_status"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_shield_status,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("shield_skip"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_shield_skip,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_shield_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_shield_init,                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_shield_create_loc_conf,       /* create location configuration */
    ngx_http_shield_merge_loc_conf         /* merge location configuration */
};


ngx_module_t  ngx_http_shield_module = {
    NGX_MODULE_V1,
    &ngx_http_shield_module_ctx,           /* module context */
    ngx_http_shield_commands,              /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


/* ---- phase handler ----------------------------------------------------- */

static ngx_int_t
ngx_http_shield_handler(ngx_http_request_t *r)
{
    ngx_int_t                    rc;
    ngx_http_shield_ctx_t       *ctx;
    ngx_http_shield_hit_t        hit;
    ngx_http_shield_loc_conf_t  *slcf;

    if (r != r->main) {
        return NGX_DECLINED;
    }

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_shield_module);

    if (slcf->mode == NGX_HTTP_SHIELD_OFF) {
        return NGX_DECLINED;
    }

    /* Re-entry after the request body has been read: the body handler has
     * already recorded the verdict. */
    ctx = ngx_http_get_module_ctx(r, ngx_http_shield_module);
    if (ctx != NULL) {
        return ctx->status;
    }

    /* First pass: request line + headers (no body). */
    ngx_memzero(&hit, sizeof(ngx_http_shield_hit_t));

    rc = ngx_http_shield_inspect_prebody(r, slcf, &hit);
    if (rc == NGX_OK) {
        rc = ngx_http_shield_act(r, slcf, &hit);
        if (rc != NGX_DECLINED) {
            return rc;
        }
        /* DETECT mode: logged, fall through and keep serving. */
        return NGX_DECLINED;
    }

    /* No pre-body hit. Read and scan the body if enabled and scannable. */
    if (!slcf->body || !ngx_http_shield_scannable_body(r)) {
        return NGX_DECLINED;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_shield_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }
    ctx->status = NGX_DECLINED;
    ngx_http_set_ctx(r, ctx, ngx_http_shield_module);

    rc = ngx_http_read_client_request_body(r, ngx_http_shield_body_handler);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    ngx_http_finalize_request(r, NGX_DONE);
    return NGX_DONE;
}


static void
ngx_http_shield_body_handler(ngx_http_request_t *r)
{
    ngx_int_t                    rc;
    ngx_http_shield_ctx_t       *ctx;
    ngx_http_shield_hit_t        hit;
    ngx_http_shield_loc_conf_t  *slcf;

    ctx = ngx_http_get_module_ctx(r, ngx_http_shield_module);
    slcf = ngx_http_get_module_loc_conf(r, ngx_http_shield_module);

    ngx_memzero(&hit, sizeof(ngx_http_shield_hit_t));

    if (ngx_http_shield_inspect_body(r, slcf, &hit) == NGX_OK) {
        rc = ngx_http_shield_act(r, slcf, &hit);
        ctx->status = (rc == NGX_DECLINED) ? NGX_DECLINED : rc;
    } else {
        ctx->status = NGX_DECLINED;
    }

    /* Keep the buffered body around for the content handler, then resume the
     * phase engine, which re-enters ngx_http_shield_handler and returns
     * ctx->status. */
    r->preserve_body = 1;
    r->write_event_handler = ngx_http_core_run_phases;
    ngx_http_core_run_phases(r);
}


/* ---- decision + logging ------------------------------------------------ */

static ngx_int_t
ngx_http_shield_act(ngx_http_request_t *r, ngx_http_shield_loc_conf_t *slcf,
    ngx_http_shield_hit_t *hit)
{
    /* Only the category and the source are logged, never attacker-supplied
     * bytes: those can contain control characters and would allow log
     * injection. Forensic detail belongs in the access log. */
    if (slcf->mode == NGX_HTTP_SHIELD_BLOCK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "shield: blocked request from %V, "
                      "category=%s source=%s status=%ui",
                      &r->connection->addr_text, hit->category, hit->source,
                      slcf->status);
        return (ngx_int_t) slcf->status;
    }

    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                  "shield: detected attack from %V, category=%s source=%s "
                  "(detect mode, not blocked)",
                  &r->connection->addr_text, hit->category, hit->source);
    return NGX_DECLINED;
}


/* ---- structural checks ------------------------------------------------- */

static ngx_int_t
ngx_http_shield_check_httpoxy(ngx_http_request_t *r,
    ngx_http_shield_loc_conf_t *slcf, ngx_http_shield_hit_t *hit)
{
    ngx_uint_t        i;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *header;

    if (slcf->skip & ((uint64_t) 1 << NGX_HTTP_SHIELD_CAT_HTTPOXY)) {
        return NGX_DECLINED;
    }

    part = &r->headers_in.headers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].key.len == sizeof("Proxy") - 1
            && ngx_strncasecmp(header[i].key.data, (u_char *) "Proxy",
                               sizeof("Proxy") - 1) == 0)
        {
            hit->category = NGX_HTTP_SHIELD_NAME_HTTPOXY;
            hit->source = "header";
            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_shield_check_range(ngx_http_request_t *r,
    ngx_http_shield_loc_conf_t *slcf, ngx_http_shield_hit_t *hit)
{
    size_t            n;
    ngx_uint_t        ranges;
    ngx_table_elt_t  *range;

    if (slcf->skip & ((uint64_t) 1 << NGX_HTTP_SHIELD_CAT_RANGE_DOS)) {
        return NGX_DECLINED;
    }

    range = r->headers_in.range;
    if (range == NULL) {
        return NGX_DECLINED;
    }

    ranges = 1;
    for (n = 0; n < range->value.len; n++) {
        if (range->value.data[n] == ',') {
            ranges++;
        }
    }

    if (ranges > NGX_HTTP_SHIELD_MAX_RANGES) {
        hit->category = NGX_HTTP_SHIELD_NAME_RANGE_DOS;
        hit->source = "range";
        return NGX_OK;
    }

    return NGX_DECLINED;
}


/* ---- pre-body inspection (request target + headers) -------------------- */

static ngx_int_t
ngx_http_shield_inspect_prebody(ngx_http_request_t *r,
    ngx_http_shield_loc_conf_t *slcf, ngx_http_shield_hit_t *hit)
{
    ngx_table_elt_t  *h;

    if (ngx_http_shield_check_httpoxy(r, slcf, hit) == NGX_OK) {
        return NGX_OK;
    }

    if (ngx_http_shield_check_range(r, slcf, hit) == NGX_OK) {
        return NGX_OK;
    }

    /* Request target as sent by the client (path + query, still encoded). */
    if (r->unparsed_uri.len
        && ngx_http_shield_scan_input(r, slcf, r->unparsed_uri.data,
                                      r->unparsed_uri.len, "uri", hit) == NGX_OK)
    {
        return NGX_OK;
    }

    h = r->headers_in.user_agent;
    if (h != NULL
        && ngx_http_shield_scan_input(r, slcf, h->value.data, h->value.len,
                                      "user-agent", hit) == NGX_OK)
    {
        return NGX_OK;
    }

    h = r->headers_in.referer;
    if (h != NULL
        && ngx_http_shield_scan_input(r, slcf, h->value.data, h->value.len,
                                      "referer", hit) == NGX_OK)
    {
        return NGX_OK;
    }

    h = r->headers_in.content_type;
    if (h != NULL
        && ngx_http_shield_scan_input(r, slcf, h->value.data, h->value.len,
                                      "content-type", hit) == NGX_OK)
    {
        return NGX_OK;
    }

    return NGX_DECLINED;
}


/* ---- body inspection --------------------------------------------------- */

static ngx_int_t
ngx_http_shield_scannable_body(ngx_http_request_t *r)
{
    ngx_table_elt_t  *ct;
    ngx_str_t         v;

    if (r->headers_in.content_length_n <= 0 && !r->headers_in.chunked) {
        return 0;
    }

    ct = r->headers_in.content_type;
    if (ct == NULL) {
        return 0;
    }

    v = ct->value;

    /* Only text-shaped bodies can carry the payloads we look for. Binary
     * uploads (images, archives, octet-stream) are never scanned. */
    if (v.len >= sizeof("application/x-www-form-urlencoded") - 1
        && ngx_strncasecmp(v.data,
                           (u_char *) "application/x-www-form-urlencoded",
                           sizeof("application/x-www-form-urlencoded") - 1)
           == 0)
    {
        return 1;
    }

    if (v.len >= sizeof("multipart/form-data") - 1
        && ngx_strncasecmp(v.data, (u_char *) "multipart/form-data",
                           sizeof("multipart/form-data") - 1) == 0)
    {
        return 1;
    }

    if (v.len >= sizeof("application/json") - 1
        && ngx_strncasecmp(v.data, (u_char *) "application/json",
                           sizeof("application/json") - 1) == 0)
    {
        return 1;
    }

    if (v.len >= sizeof("text/") - 1
        && ngx_strncasecmp(v.data, (u_char *) "text/", sizeof("text/") - 1)
           == 0)
    {
        return 1;
    }

    if (v.len >= sizeof("application/xml") - 1
        && ngx_strncasecmp(v.data, (u_char *) "application/xml",
                           sizeof("application/xml") - 1) == 0)
    {
        return 1;
    }

    return 0;
}


static ngx_int_t
ngx_http_shield_collect_body(ngx_http_request_t *r, size_t max, ngx_str_t *out)
{
    size_t        len, total;
    ssize_t       rn;
    u_char       *p;
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

    out->len = 0;
    out->data = NULL;

    if (r->request_body == NULL || r->request_body->bufs == NULL || max == 0) {
        return NGX_OK;
    }

    p = ngx_pnalloc(r->pool, max);
    if (p == NULL) {
        return NGX_ERROR;
    }

    out->data = p;
    total = 0;

    for (cl = r->request_body->bufs; cl != NULL && total < max; cl = cl->next) {
        b = cl->buf;

        if (ngx_buf_in_memory(b)) {
            len = b->last - b->pos;
            if (len > max - total) {
                len = max - total;
            }
            ngx_memcpy(p + total, b->pos, len);
            total += len;

        } else if (b->in_file && b->file != NULL) {
            len = (size_t) (b->file_last - b->file_pos);
            if (len > max - total) {
                len = max - total;
            }
            rn = ngx_read_file(b->file, p + total, len, b->file_pos);
            if (rn == NGX_ERROR) {
                /* Scan whatever was collected so far rather than fail open. */
                break;
            }
            total += (size_t) rn;
        }
    }

    out->len = total;
    return NGX_OK;
}


static ngx_int_t
ngx_http_shield_inspect_body(ngx_http_request_t *r,
    ngx_http_shield_loc_conf_t *slcf, ngx_http_shield_hit_t *hit)
{
    ngx_str_t  body;

    if (ngx_http_shield_collect_body(r, slcf->max_body, &body) != NGX_OK) {
        return NGX_DECLINED;
    }

    if (body.len == 0) {
        return NGX_DECLINED;
    }

    return ngx_http_shield_scan_input(r, slcf, body.data, body.len, "body",
                                      hit);
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
 * ngx_unescape_uri never grows the buffer, so a single allocation of `len`
 * bytes is always large enough for the decoded copy.
 */
static ngx_int_t
ngx_http_shield_scan_input(ngx_http_request_t *r,
    ngx_http_shield_loc_conf_t *slcf, u_char *data, size_t len,
    const char *source, ngx_http_shield_hit_t *hit)
{
    size_t                           i, j, dlen;
    u_char                          *raw_lc, *dec, *dst, *src;
    const ngx_http_shield_catdef_t  *cat;

    if (len == 0) {
        return NGX_DECLINED;
    }

    raw_lc = ngx_pnalloc(r->pool, len);
    dec = ngx_pnalloc(r->pool, len);
    if (raw_lc == NULL || dec == NULL) {
        return NGX_DECLINED;
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

        if (slcf->skip & ((uint64_t) 1 << cat->cat)) {
            continue;
        }

        for (j = 0; j < cat->nsigs; j++) {
            const ngx_http_shield_sig_t  *sig = &cat->sigs[j];

            if ((cat->match & NGX_HTTP_SHIELD_MATCH_RAW)
                && ngx_http_shield_memmem(raw_lc, len, sig->s, sig->len)
                   != NULL)
            {
                hit->category = cat->name;
                hit->source = source;
                return NGX_OK;
            }

            if ((cat->match & NGX_HTTP_SHIELD_MATCH_DECODED)
                && ngx_http_shield_memmem(dec, dlen, sig->s, sig->len) != NULL)
            {
                hit->category = cat->name;
                hit->source = source;
                return NGX_OK;
            }
        }
    }

    return NGX_DECLINED;
}


static u_char *
ngx_http_shield_memmem(u_char *haystack, size_t hlen, const char *needle,
    size_t nlen)
{
    u_char  *p, *last;

    if (nlen == 0 || hlen < nlen) {
        return NULL;
    }

    last = haystack + hlen - nlen;

    for (p = haystack; p <= last; p++) {
        if (*p == (u_char) needle[0]
            && ngx_memcmp(p, needle, nlen) == 0)
        {
            return p;
        }
    }

    return NULL;
}


/* ---- configuration ----------------------------------------------------- */

static void *
ngx_http_shield_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_shield_loc_conf_t  *slcf;

    slcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_shield_loc_conf_t));
    if (slcf == NULL) {
        return NULL;
    }

    slcf->mode = NGX_CONF_UNSET_UINT;
    slcf->body = NGX_CONF_UNSET;
    slcf->max_body = NGX_CONF_UNSET_SIZE;
    slcf->status = NGX_CONF_UNSET_UINT;
    slcf->skip = 0;

    return slcf;
}


static char *
ngx_http_shield_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_shield_loc_conf_t  *prev = parent;
    ngx_http_shield_loc_conf_t  *conf = child;

    ngx_conf_merge_uint_value(conf->mode, prev->mode, NGX_HTTP_SHIELD_OFF);
    ngx_conf_merge_value(conf->body, prev->body, 1);
    /* 8k, not 64k. Scan cost is linear in the buffer: the engine sweeps every
     * signature over it, so a 64k body costs ~10.9ms of blocking CPU in a
     * single-threaded worker. Body size and Content-Type are both
     * attacker-controlled, which made the old default a cheap DoS amplifier
     * (~90 req/s to pin a worker). 8k keeps real form/JSON payloads covered. */
    ngx_conf_merge_size_value(conf->max_body, prev->max_body, 8 * 1024);
    ngx_conf_merge_uint_value(conf->status, prev->status, NGX_HTTP_FORBIDDEN);

    /* skip: inherit the parent mask only when this location set none. */
    if (conf->skip == 0) {
        conf->skip = prev->skip;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_shield_mode(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_shield_loc_conf_t  *slcf = conf;
    ngx_str_t                   *value = cf->args->elts;

    if (slcf->mode != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    if (ngx_strcmp(value[1].data, "off") == 0) {
        slcf->mode = NGX_HTTP_SHIELD_OFF;
    } else if (ngx_strcmp(value[1].data, "detect") == 0) {
        slcf->mode = NGX_HTTP_SHIELD_DETECT;
    } else if (ngx_strcmp(value[1].data, "block") == 0) {
        slcf->mode = NGX_HTTP_SHIELD_BLOCK;
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid shield mode \"%V\", "
                           "expected off, detect or block", &value[1]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_shield_status(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_shield_loc_conf_t  *slcf = conf;
    ngx_str_t                   *value = cf->args->elts;
    ngx_int_t                    code;

    if (slcf->status != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    code = ngx_atoi(value[1].data, value[1].len);

    if (code != 403 && code != 404 && code != 419 && code != 429
        && code != 444)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid shield_status \"%V\", "
                           "allowed: 403, 404, 419, 429, 444", &value[1]);
        return NGX_CONF_ERROR;
    }

    slcf->status = (ngx_uint_t) code;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_shield_cat_by_name(ngx_str_t *name)
{
    ngx_uint_t  i;

    for (i = 0; i < NGX_HTTP_SHIELD_NCATEGORIES; i++) {
        if (name->len == ngx_strlen(ngx_http_shield_categories[i].name)
            && ngx_strncmp(name->data, ngx_http_shield_categories[i].name,
                           name->len) == 0)
        {
            return (ngx_int_t) ngx_http_shield_categories[i].cat;
        }
    }

    if (name->len == sizeof(NGX_HTTP_SHIELD_NAME_HTTPOXY) - 1
        && ngx_strncmp(name->data, NGX_HTTP_SHIELD_NAME_HTTPOXY, name->len)
           == 0)
    {
        return NGX_HTTP_SHIELD_CAT_HTTPOXY;
    }

    if (name->len == sizeof(NGX_HTTP_SHIELD_NAME_RANGE_DOS) - 1
        && ngx_strncmp(name->data, NGX_HTTP_SHIELD_NAME_RANGE_DOS, name->len)
           == 0)
    {
        return NGX_HTTP_SHIELD_CAT_RANGE_DOS;
    }

    return -1;
}


static char *
ngx_http_shield_skip(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_shield_loc_conf_t  *slcf = conf;
    ngx_str_t                   *value = cf->args->elts;
    ngx_uint_t                   i;
    ngx_int_t                    cat;

    for (i = 1; i < cf->args->nelts; i++) {
        cat = ngx_http_shield_cat_by_name(&value[i]);
        if (cat < 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "unknown shield category \"%V\"", &value[i]);
            return NGX_CONF_ERROR;
        }
        slcf->skip |= ((uint64_t) 1 << cat);
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_shield_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_shield_handler;

    return NGX_OK;
}
