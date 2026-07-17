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
 * each input (percent-decode once, lowercase, '+' -> space) and matches every
 * signature against it in a single Aho-Corasick pass, plus three structural
 * checks (httpoxy Proxy header, Apache-Killer Range, encoded C0 controls).
 * Scan cost is O(bytes)
 * and independent of the size of the signature set.
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
static ngx_int_t ngx_http_shield_fail(ngx_http_request_t *r,
    ngx_http_shield_loc_conf_t *slcf, const char *what);

static ngx_int_t ngx_http_shield_scan_input(ngx_http_request_t *r,
    ngx_http_shield_loc_conf_t *slcf, u_char *data, size_t len,
    const char *source, uint64_t skip, ngx_http_shield_hit_t *hit);
static ngx_int_t ngx_http_shield_ac_build(ngx_conf_t *cf,
    ngx_http_shield_ac_t *ac, ngx_uint_t match);
static const ngx_http_shield_catdef_t *ngx_http_shield_ac_scan(
    const ngx_http_shield_ac_t *ac, u_char *data, size_t len, uint64_t skip);
static ngx_int_t ngx_http_shield_scannable_body(ngx_http_request_t *r);
static ngx_int_t ngx_http_shield_header_name_is(ngx_table_elt_t *h,
    const char *name, size_t len);
static ngx_int_t ngx_http_shield_content_type_is(ngx_str_t *v,
    const char *type, size_t len);
static ngx_int_t ngx_http_shield_content_type_suffix(ngx_str_t *v,
    const char *suffix, size_t len);

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

    if (rc == NGX_ERROR) {
        return ngx_http_shield_fail(r, slcf, "request target or headers");
    }

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

    rc = ngx_http_shield_inspect_body(r, slcf, &hit);

    if (rc == NGX_OK) {
        rc = ngx_http_shield_act(r, slcf, &hit);
        ctx->status = (rc == NGX_DECLINED) ? NGX_DECLINED : rc;

    } else if (rc == NGX_ERROR) {
        ctx->status = ngx_http_shield_fail(r, slcf, "request body");

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


/*
 * Inspection itself failed -- a pool allocation or a request-body temp-file
 * read did not succeed, so a buffer went unscanned. An unscanned buffer is not
 * a clean one, so `shield block` fails CLOSED with 500 rather than authorizing
 * a request it never actually inspected. `shield detect` is an observation
 * mode by definition and must not change the response, so it only logs.
 */
static ngx_int_t
ngx_http_shield_fail(ngx_http_request_t *r, ngx_http_shield_loc_conf_t *slcf,
    const char *what)
{
    if (slcf->mode == NGX_HTTP_SHIELD_BLOCK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "shield: could not inspect %s, failing closed "
                      "(block mode)", what);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "shield: could not inspect %s, request left unscanned "
                  "(detect mode)", what);
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


/*
 * Control characters in the request target.
 *
 * A structural check, not a signature: it is the SHAPE of the byte that is
 * wrong, so no signature list can go stale and no encoding trick evades it.
 *
 * nginx already rejects a RAW control byte in the request line with 400, so
 * only the percent-encoded form ever reaches a phase handler -- and it arrives
 * decoded, as a real control byte, in r->uri. No legitimate client sends one:
 * they are used to smuggle terminators past filters and log parsers, and to
 * split records in downstream systems that treat the URI as text.
 *
 * NUL and CR/LF are deliberately NOT flagged here. They already have their own
 * categories (nullbyte, crlf), which name the attack more precisely and which
 * an operator may have skipped on purpose; taking them over would silently
 * change the reported category and override that choice. DEL (0x7f) is left
 * out too -- it is not a C0 control and shows up in enough legacy junk to be a
 * false-positive risk without a real attack behind it.
 */
static ngx_int_t
ngx_http_shield_check_ctrl_char(ngx_http_request_t *r,
    ngx_http_shield_loc_conf_t *slcf, ngx_http_shield_hit_t *hit)
{
    size_t   i;
    u_char   c;

    if (slcf->skip & ((uint64_t) 1 << NGX_HTTP_SHIELD_CAT_CTRL_CHAR)) {
        return NGX_DECLINED;
    }

    /* r->uri is the decoded path: nginx has already percent-decoded it, so a
     * "%01" in the request line is a 0x01 byte here. The query string is not
     * decoded by nginx and is covered by the signature scan instead. */
    for (i = 0; i < r->uri.len; i++) {
        c = r->uri.data[i];

        if (c >= 0x20) {
            continue;
        }

        if (c == '\0' || c == CR || c == LF) {
            continue;   /* owned by nullbyte / crlf */
        }

        hit->category = NGX_HTTP_SHIELD_NAME_CTRL_CHAR;
        hit->source = "uri";
        return NGX_OK;
    }

    return NGX_DECLINED;
}


/* ---- pre-body inspection (request target + headers) -------------------- */

static ngx_int_t
ngx_http_shield_inspect_prebody(ngx_http_request_t *r,
    ngx_http_shield_loc_conf_t *slcf, ngx_http_shield_hit_t *hit)
{
    ngx_int_t         rc;
    ngx_uint_t        i;
    uint64_t          allowed, generic_allowed, header_skip;
    const char       *source;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *header;

    /* Every scan is three-valued: NGX_OK (hit), NGX_DECLINED (clean),
     * NGX_ERROR (the buffer could not be scanned). NGX_ERROR must never be
     * flattened into NGX_DECLINED -- an unscanned buffer is not a clean one. */

    if (ngx_http_shield_check_httpoxy(r, slcf, hit) == NGX_OK) {
        return NGX_OK;
    }

    if (ngx_http_shield_check_range(r, slcf, hit) == NGX_OK) {
        return NGX_OK;
    }

    if (ngx_http_shield_check_ctrl_char(r, slcf, hit) == NGX_OK) {
        return NGX_OK;
    }

    /* Request target as sent by the client (path + query, still encoded). */
    if (r->unparsed_uri.len) {
        rc = ngx_http_shield_scan_input(r, slcf, r->unparsed_uri.data,
                                        r->unparsed_uri.len, "uri",
                                        slcf->skip, hit);
        if (rc != NGX_DECLINED) {
            return rc;
        }
    }

    /* Log4Shell and Shellshock are valuable in EVERY request-header value:
     * applications and middleware routinely copy arbitrary headers into logs
     * or CGI environment variables. Their signatures are punctuation-rich,
     * so scanning opaque Authorization/API-key values for these two categories
     * does not create the random short-token collisions that a full-table scan
     * would ("ro0ab", "p0wny", and similar five-byte signatures are real
     * examples). URI-bearing headers get the full table; Cookie gets the
     * injection-shaped categories, but not opaque-token categories. */
    generic_allowed = ((uint64_t) 1 << NGX_HTTP_SHIELD_CAT_TEMPLATE)
                      | ((uint64_t) 1 << NGX_HTTP_SHIELD_CAT_SHELLSHOCK);

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

        if (header[i].hash == 0 || header[i].value.len == 0) {
            continue;
        }

        source = "header";
        allowed = generic_allowed;
        header_skip = slcf->skip | ~allowed;

        /* Preserve the existing named scans and their stable log labels. */
        if (&header[i] == r->headers_in.user_agent) {
            source = "user-agent";
            header_skip = slcf->skip;

        } else if (&header[i] == r->headers_in.referer) {
            source = "referer";
            header_skip = slcf->skip;

        } else if (&header[i] == r->headers_in.content_type) {
            source = "content-type";
            /* Multipart boundaries are opaque random strings. Keep the
             * header-borne exploit categories (especially Struts OGNL) but do
             * not run five-byte gadget/webshell names over boundary entropy. */
            allowed |= ((uint64_t) 1 << NGX_HTTP_SHIELD_CAT_JAVA_RCE)
                       | ((uint64_t) 1 << NGX_HTTP_SHIELD_CAT_CRLF)
                       | ((uint64_t) 1 << NGX_HTTP_SHIELD_CAT_NULLBYTE)
                       | ((uint64_t) 1 << NGX_HTTP_SHIELD_CAT_OVERLONG);
            header_skip = slcf->skip | ~allowed;

        /* Reverse proxies commonly put the effective request target in one of
         * these headers. Treat it exactly like the request target, which also
         * makes WebDAV Destination traversal visible at PRECONTENT. */
        } else if (ngx_http_shield_header_name_is(&header[i], "Destination",
                                                   sizeof("Destination") - 1)
                   || ngx_http_shield_header_name_is(&header[i],
                                                      "X-Original-URL",
                                                      sizeof("X-Original-URL")
                                                          - 1)
                   || ngx_http_shield_header_name_is(&header[i],
                                                      "X-Rewrite-URL",
                                                      sizeof("X-Rewrite-URL")
                                                          - 1))
        {
            header_skip = slcf->skip;

        } else if (ngx_http_shield_header_name_is(&header[i], "Cookie",
                                                   sizeof("Cookie") - 1))
        {
            allowed |= ((uint64_t) 1 << NGX_HTTP_SHIELD_CAT_SQLI)
                       | ((uint64_t) 1 << NGX_HTTP_SHIELD_CAT_XSS)
                       | ((uint64_t) 1 << NGX_HTTP_SHIELD_CAT_CMDI)
                       | ((uint64_t) 1 << NGX_HTTP_SHIELD_CAT_LFI_RFI)
                       | ((uint64_t) 1 << NGX_HTTP_SHIELD_CAT_CRLF)
                       | ((uint64_t) 1 << NGX_HTTP_SHIELD_CAT_NULLBYTE)
                       | ((uint64_t) 1 << NGX_HTTP_SHIELD_CAT_OVERLONG)
                       | ((uint64_t) 1 << NGX_HTTP_SHIELD_CAT_PHP_RCE)
                       | ((uint64_t) 1 << NGX_HTTP_SHIELD_CAT_JAVA_RCE)
                       | ((uint64_t) 1 << NGX_HTTP_SHIELD_CAT_JAVA_EVAL)
                       | ((uint64_t) 1 << NGX_HTTP_SHIELD_CAT_NOSQL)
                       | ((uint64_t) 1 << NGX_HTTP_SHIELD_CAT_SSTI);
            header_skip = slcf->skip | ~allowed;
        }

        rc = ngx_http_shield_scan_input(r, slcf, header[i].value.data,
                                        header[i].value.len, source,
                                        header_skip, hit);
        if (rc != NGX_DECLINED) {
            return rc;
        }
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
    if (ngx_http_shield_content_type_is(
            &v, "application/x-www-form-urlencoded",
            sizeof("application/x-www-form-urlencoded") - 1))
    {
        return 1;
    }

    if (ngx_http_shield_content_type_is(&v, "multipart/form-data",
                                        sizeof("multipart/form-data") - 1))
    {
        return 1;
    }

    if (ngx_http_shield_content_type_is(&v, "application/json",
                                        sizeof("application/json") - 1))
    {
        return 1;
    }

    if (v.len >= sizeof("text/") - 1
        && ngx_strncasecmp(v.data, (u_char *) "text/", sizeof("text/") - 1)
           == 0)
    {
        return 1;
    }

    if (ngx_http_shield_content_type_is(&v, "application/xml",
                                        sizeof("application/xml") - 1))
    {
        return 1;
    }

    /* Structured syntax suffixes cover vendor APIs and SOAP without treating
     * every application media type as text. The remaining exact types are
     * common textual request formats that carry the same injection payloads. */
    if (ngx_http_shield_content_type_suffix(&v, "+json",
                                            sizeof("+json") - 1)
        || ngx_http_shield_content_type_suffix(&v, "+xml",
                                                sizeof("+xml") - 1)
        || ngx_http_shield_content_type_is(&v, "application/graphql",
                                            sizeof("application/graphql") - 1)
        || ngx_http_shield_content_type_is(&v, "application/x-ndjson",
                                            sizeof("application/x-ndjson") - 1)
        || ngx_http_shield_content_type_is(&v, "application/json-seq",
                                            sizeof("application/json-seq") - 1)
        || ngx_http_shield_content_type_is(&v, "application/yaml",
                                            sizeof("application/yaml") - 1)
        || ngx_http_shield_content_type_is(&v, "application/x-yaml",
                                            sizeof("application/x-yaml") - 1))
    {
        return 1;
    }

    return 0;
}


static ngx_int_t
ngx_http_shield_header_name_is(ngx_table_elt_t *h, const char *name,
    size_t len)
{
    return h->key.len == len
           && ngx_strncasecmp(h->key.data, (u_char *) name, len) == 0;
}


static ngx_int_t
ngx_http_shield_content_type_is(ngx_str_t *v, const char *type, size_t len)
{
    if (v->len < len
        || ngx_strncasecmp(v->data, (u_char *) type, len) != 0)
    {
        return 0;
    }

    return v->len == len || v->data[len] == ';' || v->data[len] == ' '
           || v->data[len] == '\t';
}


static ngx_int_t
ngx_http_shield_content_type_suffix(ngx_str_t *v, const char *suffix,
    size_t len)
{
    size_t  end;

    if (v->len < sizeof("application/") - 1 + len
        || ngx_strncasecmp(v->data, (u_char *) "application/",
                           sizeof("application/") - 1) != 0)
    {
        return 0;
    }

    for (end = 0; end < v->len && v->data[end] != ';'; end++) {
        /* void */
    }

    while (end > 0 && (v->data[end - 1] == ' ' || v->data[end - 1] == '\t')) {
        end--;
    }

    return end >= len
           && ngx_strncasecmp(v->data + end - len, (u_char *) suffix, len)
              == 0;
}


static ngx_int_t
ngx_http_shield_collect_body(ngx_http_request_t *r, size_t max, ngx_str_t *out)
{
    off_t         off;
    size_t        len, total, done;
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

            /* A partial scan is not a clean scan: an attack could sit in the
             * bytes we failed to read. Loop short reads, and treat a read
             * error or a truncated buffer as an inspection failure so the
             * caller can fail closed. */
            off = b->file_pos;
            done = 0;

            while (done < len) {
                rn = ngx_read_file(b->file, p + total + done, len - done, off);
                if (rn <= 0) {
                    return NGX_ERROR;
                }
                done += (size_t) rn;
                off += rn;
            }

            total += done;
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
        /* Allocation or temp-file read failure: the body was not scanned. */
        return NGX_ERROR;
    }

    if (body.len == 0) {
        return NGX_DECLINED;
    }

    /* Fold the body-unsafe categories into the skip mask for this scan only.
     * They still match at full strength in the request target and headers. */
    return ngx_http_shield_scan_input(r, slcf, body.data, body.len, "body",
                                      slcf->skip
                                          | ngx_http_shield_no_body_mask(),
                                      hit);
}


/* ---- Aho-Corasick ------------------------------------------------------ */

/* Built once at postconfiguration, read-only thereafter. One automaton per
 * buffer flavour, because categories disagree about which buffer they scan. */
static ngx_http_shield_ac_t  ngx_http_shield_ac_decoded;
static ngx_http_shield_ac_t  ngx_http_shield_ac_raw;


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
static ngx_int_t
ngx_http_shield_ac_build(ngx_conf_t *cf, ngx_http_shield_ac_t *ac,
    ngx_uint_t match)
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
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "shield: rule set has %ui terms, max 64", term);
        return NGX_ERROR;
    }

    if (cap > NGX_HTTP_SHIELD_AC_MAX_STATES) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "shield: signature set too large for the "
                           "automaton (%uz states, max %d)",
                           cap, NGX_HTTP_SHIELD_AC_MAX_STATES);
        return NGX_ERROR;
    }

    /* next[] and out[] outlive the build and are read by every request, so
     * they come from cf->pool. queue[] and fail[] are build scratch: they go
     * in a temporary pool that is destroyed before this function returns. */
    next = ngx_pcalloc(cf->pool,
                       cap * NGX_HTTP_SHIELD_AC_ALPHABET * sizeof(*next));
    out = ngx_pcalloc(cf->pool, cap * sizeof(*out));
    rout = ngx_pcalloc(cf->pool, cap * sizeof(*rout));

    if (next == NULL || out == NULL || rout == NULL) {
        return NGX_ERROR;
    }

    temp = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, cf->log);
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
            if (ngx_http_shield_categories[j].cat == ngx_http_shield_rules[i].cat)
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
             * string). ac_scan resolves a multi-category state by table order. */
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
            const ngx_http_shield_sig_t  *t = &ngx_http_shield_rules[i].terms[j];

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
 * ngx_unescape_uri never grows the buffer, so a single allocation of `len`
 * bytes is always large enough for the decoded copy.
 */
static ngx_int_t
ngx_http_shield_scan_input(ngx_http_request_t *r,
    ngx_http_shield_loc_conf_t *slcf, u_char *data, size_t len,
    const char *source, uint64_t skip, ngx_http_shield_hit_t *hit)
{
    size_t                           i, dlen;
    u_char                          *raw_lc, *dec, *dst, *src;
    const ngx_http_shield_catdef_t  *cat;

    if (len == 0) {
        return NGX_DECLINED;
    }

    raw_lc = ngx_pnalloc(r->pool, len);
    dec = ngx_pnalloc(r->pool, len);
    if (raw_lc == NULL || dec == NULL) {
        /* Never report an unscanned buffer as clean: the caller fails closed. */
        return NGX_ERROR;
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

    cat = ngx_http_shield_ac_scan(&ngx_http_shield_ac_raw, raw_lc, len,
                                  skip);
    if (cat != NULL) {
        hit->category = cat->name;
        hit->source = source;
        return NGX_OK;
    }

    cat = ngx_http_shield_ac_scan(&ngx_http_shield_ac_decoded, dec, dlen,
                                  skip);
    if (cat != NULL) {
        hit->category = cat->name;
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
    /* 8k, not 64k. Scan cost is linear in the buffer -- the Aho-Corasick pass
     * is O(bytes), independent of the signature count -- so a body is still a
     * blocking-CPU budget in a single-threaded worker, and both its length and
     * the Content-Type that opts it into scanning are attacker-controlled. The
     * old 64k default was a cheap DoS amplifier under the pre-AC O(n*m) engine
     * (~10.9 ms/req, ~90 req/s to pin a worker); the cap stays at 8k because
     * the budget is still attacker-driven, and 8k covers real form/JSON. */
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

    if (name->len == sizeof(NGX_HTTP_SHIELD_NAME_CTRL_CHAR) - 1
        && ngx_strncmp(name->data, NGX_HTTP_SHIELD_NAME_CTRL_CHAR, name->len)
           == 0)
    {
        return NGX_HTTP_SHIELD_CAT_CTRL_CHAR;
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

    /* Build both automatons once, here, from the compiled-in tables. Failure
     * is fatal: running with a half-built automaton would silently stop
     * matching signatures. */
    if (ngx_http_shield_ac_build(cf, &ngx_http_shield_ac_decoded,
                                 NGX_HTTP_SHIELD_MATCH_DECODED)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (ngx_http_shield_ac_build(cf, &ngx_http_shield_ac_raw,
                                 NGX_HTTP_SHIELD_MATCH_RAW)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PRECONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_shield_handler;

    return NGX_OK;
}
