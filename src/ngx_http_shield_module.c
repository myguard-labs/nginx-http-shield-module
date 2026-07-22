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
#include "ngx_http_shield_ban.h"
#include "ngx_shield_probe_hooks.h"

#ifdef NGX_TEST_HARNESS
#include "ngx_test_probe.h"
#endif


#define NGX_HTTP_SHIELD_OFF     0
#define NGX_HTTP_SHIELD_DETECT  1
#define NGX_HTTP_SHIELD_BLOCK   2

/* Maximum number of comma-separated ranges tolerated in a Range header before
 * it is treated as an Apache-Killer (CVE-2011-3192) attempt. */
#define NGX_HTTP_SHIELD_MAX_RANGES  10


/* ---- shield_ban: repeat-offender ban list in shared memory ------------- */

/* The ban shared-memory state engine (node/shctx/ctx types + lookup/expire/
 * record/is_banned) lives in ngx_http_shield_ban.{c,h} so it can be unit-tested
 * without <ngx_http.h>. This TU keeps the request-shaped glue below. */

/* The ban node struct is overlaid on an ngx_rbtree_node_t via `&node->color`,
 * so its first byte MUST land on the node's color byte (which the rbtree
 * rewrites on every rebalance). If a future edit reorders the fields, break the
 * build here rather than silently corrupting the LRU queue in production. */
typedef char ngx_http_shield_ban_color_first[
    (offsetof(ngx_http_shield_ban_node_t, color) == 0) ? 1 : -1];


typedef struct {
    ngx_uint_t   mode;        /* OFF / DETECT / BLOCK                        */
    ngx_flag_t   body;        /* inspect request body                       */
    size_t       max_body;    /* bytes of body scanned                      */
    ngx_uint_t   status;      /* status returned in BLOCK mode              */
    uint64_t     skip;        /* bitmask of disabled categories             */
    ngx_open_file_t *log;     /* JSON hit log file; NULL = disabled         */
    time_t       log_error_time;    /* last file-sink write-fail alert (rate-limit) */
    time_t       log_disk_full_time;/* last second ENOSPC seen on the file sink     */
    ngx_syslog_peer_t *syslog_peer; /* JSON hit log to a syslog server; NULL off */

    ngx_shm_zone_t *ban_zone; /* shield_ban shm zone; NULL/UNSET = no banning */
    ngx_uint_t   ban_count;   /* hits within ban_window that trigger a ban    */
    time_t       ban_window;  /* fixed hit-count window, seconds              */
    time_t       ban_time;    /* how long a triggered ban lasts, seconds      */

#ifdef NGX_TEST_HARNESS
    ngx_shm_zone_t *probe_zone; /* zone the shield_probe endpoint reports on  */
#endif
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

static ngx_int_t ngx_http_shield_check_dotfile(ngx_http_request_t *r,
    ngx_http_shield_loc_conf_t *slcf, ngx_http_shield_hit_t *hit);
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
static char *ngx_http_shield_log(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static void ngx_http_shield_write_log(ngx_http_request_t *r,
    ngx_http_shield_loc_conf_t *slcf, ngx_http_shield_hit_t *hit);
static ngx_int_t ngx_http_shield_init(ngx_conf_t *cf);

/* shield_ban */
static ngx_int_t ngx_http_shield_ban_addr(ngx_http_request_t *r,
    u_char *addr, u_char *len);
static ngx_int_t ngx_http_shield_ban_is_banned(ngx_http_request_t *r,
    ngx_http_shield_loc_conf_t *slcf);
static void ngx_http_shield_ban_record(ngx_http_request_t *r,
    ngx_http_shield_loc_conf_t *slcf);
static ngx_int_t ngx_http_shield_ban_init_zone(ngx_shm_zone_t *shm_zone,
    void *data);
static char *ngx_http_shield_ban_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
#ifdef NGX_TEST_HARNESS
static char *ngx_http_shield_probe(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_shield_probe_handler(ngx_http_request_t *r);
#endif
static char *ngx_http_shield_ban(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


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

    { ngx_string("shield_log"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_shield_log,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("shield_ban_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_shield_ban_zone,
      0,
      0,
      NULL },

    { ngx_string("shield_ban"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE4,
      ngx_http_shield_ban,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

#ifdef NGX_TEST_HARNESS

    /* CI-only introspection endpoint; absent from any build that does not
     * define NGX_TEST_HARNESS, so a config using it fails to load there
     * rather than silently exposing zone internals. */
    { ngx_string("shield_probe"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_shield_probe,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

#endif

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

    /* Repeat-offender short-circuit: an IP with an active ban is cut off with
     * the configured status BEFORE any signature scanning, so known-bad clients
     * cost only a shm rbtree lookup. Checked before the first pass so a banned
     * IP never reaches the (more expensive) inspection or body read. */
    if (slcf->ban_zone != NULL && ngx_http_shield_ban_is_banned(r, slcf)) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "shield: banned request from %V, status=%ui",
                      &r->connection->addr_text, slcf->status);
        return (ngx_int_t) slcf->status;
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
    /* Count this hit toward a ban. Done for BOTH block and detect modes: a
     * detect-mode deployment still wants to escalate a persistent attacker to a
     * hard ban. Records under the shm lock; a triggered ban takes effect on the
     * attacker's NEXT request (this one is still handled on its own merits). */
    if (slcf->ban_zone != NULL) {
        ngx_http_shield_ban_record(r, slcf);
    }

    /* Only the category and the source are logged, never attacker-supplied
     * bytes: those can contain control characters and would allow log
     * injection. Forensic detail belongs in the access log. */
    if (slcf->mode == NGX_HTTP_SHIELD_BLOCK) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "shield: blocked request from %V, "
                      "category=%s source=%s status=%ui",
                      &r->connection->addr_text, hit->category, hit->source,
                      slcf->status);
        ngx_http_shield_write_log(r, slcf, hit);
        return (ngx_int_t) slcf->status;
    }

    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                  "shield: detected attack from %V, category=%s source=%s "
                  "(detect mode, not blocked)",
                  &r->connection->addr_text, hit->category, hit->source);
    ngx_http_shield_write_log(r, slcf, hit);
    return NGX_DECLINED;
}


/*
 * Emit one JSON object per hit to shield_log, for an out-of-band reporter
 * (e.g. AbuseIPDB). The request line is the ONLY attacker-controlled field, so
 * it is JSON-string-escaped: '"' and '\' are backslash-escaped and every byte
 * below 0x20 or >= 0x80 becomes \uXXXX. That single pass both defeats log
 * injection (no raw CR/LF can reach the sink) and keeps the record valid JSON
 * even when the request line is not valid UTF-8. All other fields are trusted C
 * constants or numbers. The record goes to a file (newline-terminated) and/or a
 * syslog server. Best-effort: a short write is ignored -- logging must never
 * change the request outcome.
 */
static void
ngx_http_shield_write_log(ngx_http_request_t *r,
    ngx_http_shield_loc_conf_t *slcf, ngx_http_shield_hit_t *hit)
{
    u_char      *p, *last;
    ngx_str_t    line;
    ngx_str_t    req;
    ngx_str_t   *ts;
    ngx_uint_t   i;
    ngx_uint_t   block;
    size_t       cap;
    u_char       c;

    if (slcf->log == NULL && slcf->syslog_peer == NULL) {
        return;
    }

    block = (slcf->mode == NGX_HTTP_SHIELD_BLOCK);
    ts = (ngx_str_t *) &ngx_cached_http_log_iso8601;
    req = r->request_line;

    /* Bound the request line BEFORE escaping so the finished record always fits
     * a syslog datagram (4096) whole -- truncating the serialized JSON after the
     * fact could split a \uXXXX escape and emit invalid JSON. Worst-case blowup
     * is 6x (every byte -> \uXXXX); leave generous room for the syslog header
     * and the fixed scaffolding. The escape loop's own `p < last - 6` guard then
     * guarantees it never stops mid-escape. Bounding on an input byte boundary
     * (not a UTF-8 char boundary) is safe: each source byte escapes independently.
     */
    if (req.len > 600) {
        req.len = 600;
    }

    /* Worst case: every request byte expands to a 6-char \uXXXX escape, plus
     * the fixed scaffolding, timestamp, IP, category, source and status. */
    cap = ts->len + r->connection->addr_text.len
        + ngx_strlen(hit->category) + ngx_strlen(hit->source)
        + req.len * 6 + 160;

    line.data = ngx_pnalloc(r->pool, cap);
    if (line.data == NULL) {
        return;
    }

    p = line.data;
    last = line.data + cap;

    p = ngx_slprintf(p, last,
        "{\"ts\":\"%V\",\"ip\":\"%V\",\"cat\":\"%s\",\"src\":\"%s\","
        "\"mode\":\"%s\",\"status\":%ui,\"req\":\"",
        ts, &r->connection->addr_text, hit->category, hit->source,
        block ? "block" : "detect",
        block ? slcf->status : (ngx_uint_t) 0);

    for (i = 0; i < req.len && p < last - 6; i++) {
        c = req.data[i];

        if (c == '"' || c == '\\') {
            *p++ = '\\';
            *p++ = c;
        } else if (c == '\n') {
            *p++ = '\\'; *p++ = 'n';
        } else if (c == '\r') {
            *p++ = '\\'; *p++ = 'r';
        } else if (c == '\t') {
            *p++ = '\\'; *p++ = 't';
        } else if (c < 0x20 || c >= 0x80) {
            /* Control bytes and any non-ASCII byte become \uXXXX: the request
             * line is not guaranteed valid UTF-8, and a raw high byte would
             * otherwise emit malformed JSON. */
            p = ngx_slprintf(p, last, "\\u%04xd", (ngx_uint_t) c);
        } else {
            *p++ = c;
        }
    }

    *p++ = '"';
    *p++ = '}';

    line.len = p - line.data;

    /* File sink: append a newline terminator and write the record. Best-effort
     * for the REQUEST (a failed write never changes the response), but not
     * silent: mirror nginx's access-log writer so a full disk or broken sink
     * surfaces a rate-limited ALERT instead of records vanishing unnoticed. */
    if (slcf->log != NULL && ngx_time() != slcf->log_disk_full_time) {
        ssize_t  n;
        time_t   now;

        /* Skip the write for the rest of the second after an ENOSPC: on some
         * filesystems writing to a full disk blocks far longer than a normal
         * write, so back off exactly as nginx's access-log writer does. */

        *p = '\n';
        n = ngx_write_fd(slcf->log->fd, line.data, line.len + 1);

        if (n != (ssize_t) (line.len + 1)) {
            now = ngx_time();

            if (n == -1) {
                ngx_err_t  err = ngx_errno;

                if (err == NGX_ENOSPC) {
                    slcf->log_disk_full_time = now;
                }

                if (now - slcf->log_error_time > 59) {
                    ngx_log_error(NGX_LOG_ALERT, r->connection->log, err,
                                  ngx_write_fd_n " to shield_log \"%s\" failed",
                                  slcf->log->name.data);
                    slcf->log_error_time = now;
                }

            } else if (now - slcf->log_error_time > 59) {
                ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                              ngx_write_fd_n " to shield_log \"%s\" was "
                              "incomplete: %z of %uz",
                              slcf->log->name.data, n, line.len + 1);
                slcf->log_error_time = now;
            }
        }
    }

    /* Syslog sink: prepend the RFC 3164 header into its own buffer, then the
     * JSON body (no newline -- syslog frames datagrams itself). */
    if (slcf->syslog_peer != NULL) {
        u_char  *sb, *sp;
        size_t   scap;

        /* nginx caps a syslog datagram at NGX_SYSLOG_MAX_STR (4096), but that
         * macro is private to ngx_syslog.c; mirror it here. */
        scap = 4096;
        sb = ngx_pnalloc(r->pool, scap);
        if (sb == NULL) {
            return;
        }
        sp = ngx_syslog_add_header(slcf->syslog_peer, sb);
        /* The record is already bounded (req capped above) to fit the frame
         * whole. If a pathologically long header ever left too little room,
         * skip the send rather than truncate -- a partial record is invalid
         * JSON, and dropping one datagram is the safer failure. */
        if (line.len <= (size_t) (sb + scap - sp)) {
            sp = ngx_cpymem(sp, line.data, line.len);
            (void) ngx_syslog_send(slcf->syslog_peer, sb, sp - sb);
        }
    }
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


/*
 * Any path segment starting with '.' -- dotfiles and dotdirs (.git, .env,
 * .htaccess, .ssh, .well-known included: no exception carved out, per the
 * directive this is scanned against).
 *
 * A structural check like ctrl_char: the SHAPE of the segment is wrong, not
 * its content, so it needs no signature list and cannot be evaded by a name
 * the list doesn't happen to carry yet.
 *
 * "." and ".." themselves are excluded -- they are relative-path tokens, not
 * named dotfiles, and ".." is already the traversal category's job.
 */
static ngx_int_t
ngx_http_shield_check_dotfile(ngx_http_request_t *r,
    ngx_http_shield_loc_conf_t *slcf, ngx_http_shield_hit_t *hit)
{
    size_t   i;
    u_char   c;
    ngx_int_t  at_segment_start;

    if (slcf->skip & ((uint64_t) 1 << NGX_HTTP_SHIELD_CAT_DOTFILE)) {
        return NGX_DECLINED;
    }

    at_segment_start = 1;

    for (i = 0; i < r->uri.len; i++) {
        c = r->uri.data[i];

        if (c == '/') {
            at_segment_start = 1;
            continue;
        }

        if (at_segment_start && c == '.') {
            size_t  rest = r->uri.len - i;

            if ((rest == 1)
                || (rest >= 2 && r->uri.data[i + 1] == '/'))
            {
                at_segment_start = 0;
                continue;   /* lone "." segment */
            }

            if ((rest == 2 && r->uri.data[i + 1] == '.')
                || (rest >= 3 && r->uri.data[i + 1] == '.'
                    && r->uri.data[i + 2] == '/'))
            {
                at_segment_start = 0;
                continue;   /* ".." segment -- owned by traversal */
            }

            hit->category = NGX_HTTP_SHIELD_NAME_DOTFILE;
            hit->source = "uri";
            return NGX_OK;
        }

        at_segment_start = 0;
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

    if (ngx_http_shield_check_dotfile(r, slcf, hit) == NGX_OK) {
        return NGX_OK;
    }

    /* Request target as sent by the client (path + query, still encoded).
     *
     * Path and query mean different things: the path is a resource locator, the
     * query is an arbitrary user-controlled VALUE (a search term, a URL echoed
     * back). A few categories -- xss, sensitive_file (ngx_http_shield_no_query_mask())
     * -- have no benign reading in a path but are ordinary content as a query
     * value, so they must not fire on the query.
     *
     * Done as TWO passes over the same buffer rather than by splitting it, so
     * that AND-rules keep working: a rule like jenkins_cli_read pairs the term
     * "/cli?" (which straddles the path/query boundary) with "remoting=true"
     * (a query param). Splitting the buffer on '?' would put those two terms in
     * different scans and the rule could never fire. AND-rule terms live in a
     * separate id space (rout[]) that the category skip mask does not touch, so:
     *
     *  1. scan the WHOLE target with the query categories masked out -- every
     *     standalone category except xss/sensitive_file, plus ALL AND-rules
     *     (whose terms may span the boundary), match here;
     *  2. scan the PATH component only, at full strength, to recover xss and
     *     sensitive_file where they DO have attack meaning (in the path).
     *
     * xss/sensitive_file in the query are masked out of pass 1 and outside the
     * buffer of pass 2, so they are deliberately not detected there. */
    if (r->unparsed_uri.len) {
        u_char  *q;
        size_t   path_len;

        rc = ngx_http_shield_scan_input(
                 r, slcf, r->unparsed_uri.data, r->unparsed_uri.len, "uri",
                 slcf->skip | ngx_http_shield_no_query_mask(), hit);
        if (rc != NGX_DECLINED) {
            return rc;
        }

        q = ngx_strlchr(r->unparsed_uri.data,
                        r->unparsed_uri.data + r->unparsed_uri.len, '?');
        path_len = (q == NULL) ? r->unparsed_uri.len
                               : (size_t) (q - r->unparsed_uri.data);

        /* Recover the query-ineligible categories in the path only. Skip the
         * second pass entirely when they are not part of the effective mask
         * (shield_skip already drops them, or there is no path). */
        if (path_len
            && (~slcf->skip & ngx_http_shield_no_query_mask()) != 0)
        {
            rc = ngx_http_shield_scan_input(
                     r, slcf, r->unparsed_uri.data, path_len, "uri",
                     slcf->skip | ~ngx_http_shield_no_query_mask(), hit);
            if (rc != NGX_DECLINED) {
                return rc;
            }
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

        /* Preserve the existing named scans and their stable log labels.
         *
         * These match on the NAME, never on the r->headers_in.<field> pointer.
         * That pointer addresses only the FIRST instance nginx parsed, and all
         * three of these fields are chained (ngx_http_process_header_line
         * appends duplicates rather than rejecting them). A pointer compare
         * therefore misses every duplicate, which fell through to the generic
         * mask -- for Content-Type that dropped java_rce, so Struts OGNL in a
         * second Content-Type went entirely unscanned (S30-2). Per-field policy
         * has to reach EVERY instance of the field. */
        if (ngx_http_shield_header_name_is(&header[i], "User-Agent",
                                           sizeof("User-Agent") - 1))
        {
            source = "user-agent";
            header_skip = slcf->skip;

        } else if (ngx_http_shield_header_name_is(&header[i], "Referer",
                                                  sizeof("Referer") - 1))
        {
            source = "referer";
            header_skip = slcf->skip;

        } else if (ngx_http_shield_header_name_is(&header[i], "Content-Type",
                                                  sizeof("Content-Type") - 1))
        {
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
ngx_http_shield_content_type_value_scannable(ngx_str_t v)
{
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
ngx_http_shield_scannable_body(ngx_http_request_t *r)
{
    ngx_table_elt_t  *ct;

    if (r->headers_in.content_length_n <= 0 && !r->headers_in.chunked) {
        return 0;
    }

    /* Walk the whole Content-Type header chain (nginx links duplicates via
     * ->next). A request-smuggling attempt may send a benign first value
     * (octet-stream) followed by a text one; scan if ANY instance is
     * text-shaped so the body is never left unscanned by a decoy header. */
    for (ct = r->headers_in.content_type; ct != NULL; ct = ct->next) {
        if (ngx_http_shield_content_type_value_scannable(ct->value)) {
            return 1;
        }
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


/* True when the value's media type is exactly `type`. Per RFC 9110 the type
 * token ends at the value's end or at the ";" that starts the parameters,
 * with optional whitespace between. Trailing junk after the token but before
 * either terminator ("application/json garbage") is not this media type: the
 * whitespace is only allowed to precede a real terminator, so it is skipped
 * and then the terminator is required. */
static ngx_int_t
ngx_http_shield_content_type_is(ngx_str_t *v, const char *type, size_t len)
{
    size_t  i;

    if (v->len < len
        || ngx_strncasecmp(v->data, (u_char *) type, len) != 0)
    {
        return 0;
    }

    for (i = len; i < v->len && (v->data[i] == ' ' || v->data[i] == '\t'); i++) {
        /* void */
    }

    return i == v->len || v->data[i] == ';';
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

    /* Size the scan buffer to the known body length, not always the cap: a
     * 1-byte body must not reserve the whole shield_max_body. Chunked bodies
     * report content_length_n < 0 (length unknown) -> fall back to the cap. */
    if (r->headers_in.content_length_n > 0
        && (off_t) max > r->headers_in.content_length_n)
    {
        max = (size_t) r->headers_in.content_length_n;
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
    slcf->log = NGX_CONF_UNSET_PTR;   /* NULL means explicit `off`, not unset */
    slcf->syslog_peer = NGX_CONF_UNSET_PTR;

    slcf->ban_zone = NGX_CONF_UNSET_PTR;
    slcf->ban_count = NGX_CONF_UNSET_UINT;
    slcf->ban_window = NGX_CONF_UNSET;
    slcf->ban_time = NGX_CONF_UNSET;

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

    /* skip: a child that names ANY shield_skip token replaces the parent mask
     * wholesale (masks do not union). A child that names none (conf->skip == 0)
     * inherits the parent's mask. Consequence: an empty child CANNOT explicitly
     * clear an inherited mask -- zero means "unset, inherit", not "skip nothing"
     * -- so to disable inherited skips a child must re-state the categories it
     * DOES want skipped, or none survives only if the parent had none. */
    if (conf->skip == 0) {
        conf->skip = prev->skip;
    }

    /* Inherit only when this location never mentioned shield_log. An explicit
     * `shield_log off` sets NULL and must survive inheritance. Both sink fields
     * move together (a single directive sets both). */
    if (conf->log == NGX_CONF_UNSET_PTR) {
        conf->log = (prev->log == NGX_CONF_UNSET_PTR) ? NULL : prev->log;
        conf->syslog_peer = (prev->syslog_peer == NGX_CONF_UNSET_PTR) ? NULL : prev->syslog_peer;
    }

    /* shield_ban: inherit the whole policy as a unit. A location either sets its
     * own shield_ban (all four fields together, enforced by the directive) or
     * inherits the parent's. NGX_CONF_UNSET_PTR ban_zone => never set here. */
    if (conf->ban_zone == NGX_CONF_UNSET_PTR) {
        if (prev->ban_zone == NGX_CONF_UNSET_PTR) {
            /* Nobody up the chain set shield_ban. Leave banning off and give
             * the policy fields defined values -- copying the parent's here
             * would propagate NGX_CONF_UNSET* sentinels into a live conf. */
            conf->ban_zone = NULL;
            conf->ban_count = 0;
            conf->ban_window = 0;
            conf->ban_time = 0;

        } else {
            conf->ban_zone = prev->ban_zone;
            conf->ban_count = prev->ban_count;
            conf->ban_window = prev->ban_window;
            conf->ban_time = prev->ban_time;
        }
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

    if (name->len == sizeof(NGX_HTTP_SHIELD_NAME_DOTFILE) - 1
        && ngx_strncmp(name->data, NGX_HTTP_SHIELD_NAME_DOTFILE, name->len)
           == 0)
    {
        return NGX_HTTP_SHIELD_CAT_DOTFILE;
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


/* ---- shield_ban: shared-memory repeat-offender ban list ---------------- */

/*
 * Extract the client address as raw bytes (4 for IPv4, 16 for IPv6). The ban
 * key is the binary address, not its text form, so v4/v6 both hash and compare
 * exactly and cheaply. Returns NGX_DECLINED for any other address family (e.g.
 * a unix socket): such a client is simply not ban-tracked.
 */
static ngx_int_t
ngx_http_shield_ban_addr(ngx_http_request_t *r, u_char *addr, u_char *len)
{
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    switch (r->connection->sockaddr->sa_family) {

    case AF_INET:
        sin = (struct sockaddr_in *) r->connection->sockaddr;
        ngx_memcpy(addr, &sin->sin_addr, 4);
        *len = 4;
        return NGX_OK;

#if (NGX_HAVE_INET6)
    /* LCOV_EXCL_START -- suite clients connect over IPv4 loopback only. */
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) r->connection->sockaddr;
        ngx_memcpy(addr, &sin6->sin6_addr, 16);
        *len = 16;
        return NGX_OK;
    /* LCOV_EXCL_STOP */
#endif

    default:
        return NGX_DECLINED;  /* LCOV_EXCL_LINE -- non-inet family (unix sock) */
    }
}


/*
 * Is this client currently banned? Read-mostly fast path: takes the shm mutex
 * (ngx_shmtx_lock is exclusive -- there is no shared/reader mode), one
 * rbtree lookup, compare banned_until against now. An expired ban is treated as
 * not-banned (and the node is left for ngx_http_shield_ban_expire/record to
 * reclaim or reset). Never allocates. The state lookup itself lives in
 * ngx_http_shield_ban.c; this wrapper owns the request-address extraction, the
 * clock, and the shm lock.
 */
static ngx_int_t
ngx_http_shield_ban_is_banned(ngx_http_request_t *r,
    ngx_http_shield_loc_conf_t *slcf)
{
    u_char                       addr[16];
    u_char                       len;
    time_t                       now;
    ngx_uint_t                   hash;
    ngx_int_t                    banned;
    ngx_http_shield_ban_ctx_t   *ctx;

    if (ngx_http_shield_ban_addr(r, addr, &len) != NGX_OK) {
        return 0;  /* LCOV_EXCL_LINE -- non-inet family, untestable over TCP */
    }

    ctx = slcf->ban_zone->data;
    hash = ngx_crc32_short(addr, len);
    now = ngx_time();

    ngx_shmtx_lock(&ctx->shpool->mutex);
    banned = ngx_http_shield_ban_is_banned_locked(ctx, hash, addr, len, now);
    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return banned;
}


/*
 * Record one shield hit for this client. Extracts the peer address, takes the
 * shm lock, and delegates the find-or-create / window-slide / ban-arm state
 * transition to ngx_http_shield_ban_record_locked() (in ngx_http_shield_ban.c,
 * unit-tested there). A full zone is non-fatal -- the ban is a best-effort
 * escalation, never a correctness gate -- so we only log and drop the hit.
 */
static void
ngx_http_shield_ban_record(ngx_http_request_t *r,
    ngx_http_shield_loc_conf_t *slcf)
{
    u_char                       addr[16];
    u_char                       len;
    time_t                       now;
    ngx_uint_t                   hash;
    ngx_int_t                    rc;
    ngx_http_shield_ban_ctx_t   *ctx;

    if (ngx_http_shield_ban_addr(r, addr, &len) != NGX_OK) {
        return;   /* LCOV_EXCL_LINE -- non-inet family, untestable over TCP */
    }

    ctx = slcf->ban_zone->data;
    hash = ngx_crc32_short(addr, len);
    now = ngx_time();

    ngx_shmtx_lock(&ctx->shpool->mutex);
    rc = ngx_http_shield_ban_record_locked(ctx, hash, addr, len, now,
                                           slcf->ban_count, slcf->ban_window,
                                           slcf->ban_time);
    ngx_shmtx_unlock(&ctx->shpool->mutex);

    if (rc == NGX_ERROR) {
        /* Reachable under test: t/prober/rules/04-fault.rule arms a slab fault
         * via the probe endpoint and drives this path. It used to carry an
         * LCOV_EXCL because filling a real zone would need thousands of
         * distinct source addresses the loopback harness cannot produce. */
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "shield_ban zone \"%V\" is full; hit not counted",
                      &slcf->ban_zone->shm.name);
    }
}


/*
 * shm zone init: on a fresh segment, lay down the rbtree + LRU queue in the
 * slab pool. On reload (existing data passed in), just re-point at it.
 */
static ngx_int_t
ngx_http_shield_ban_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_shield_ban_ctx_t  *octx = data;
    ngx_http_shield_ban_ctx_t  *ctx;
    size_t                      len;

    ctx = shm_zone->data;

    if (octx) {
        /* LCOV_EXCL_START -- reload/existing-segment inherit: needs a config
         * reload or a pre-existing shm segment, neither of which a single
         * Test::Nginx start produces. */
        /* Reload: inherit the existing shared segment. */
        ctx->sh = octx->sh;
        ctx->shpool = octx->shpool;
        return NGX_OK;
        /* LCOV_EXCL_STOP */
    }

    ctx->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        ctx->sh = ctx->shpool->data;   /* LCOV_EXCL_LINE -- pre-existing segment */
        return NGX_OK;                 /* LCOV_EXCL_LINE */
    }

    ctx->sh = ngx_slab_alloc(ctx->shpool,
                             sizeof(ngx_http_shield_ban_shctx_t));
    if (ctx->sh == NULL) {
        return NGX_ERROR;   /* LCOV_EXCL_LINE -- fresh-zone slab OOM */
    }

    ctx->shpool->data = ctx->sh;

    ngx_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
                    ngx_http_shield_ban_rbtree_insert);
    ngx_queue_init(&ctx->sh->queue);

#ifdef NGX_TEST_HARNESS
    /* -1 = no fault armed. ngx_slab_alloc() does not zero, so this must be set
     * explicitly: a stray 0 here would mean "fail allocation number zero",
     * which never trips, and would hide a genuinely broken arming path. */
    ctx->sh->fault_slab_nth = -1;
    ctx->sh->fault_slab_seen = 0;
#endif

    len = sizeof(" in shield_ban_zone \"\"") + shm_zone->shm.name.len;
    ctx->shpool->log_ctx = ngx_slab_alloc(ctx->shpool, len);
    if (ctx->shpool->log_ctx == NULL) {
        return NGX_ERROR;   /* LCOV_EXCL_LINE -- log-ctx slab OOM */
    }

    ngx_sprintf(ctx->shpool->log_ctx, " in shield_ban_zone \"%V\"%Z",
                &shm_zone->shm.name);

    return NGX_OK;
}


/*
 * shield_ban_zone <name>:<size>  (http{} only) -- define the shared segment.
 * Mirrors the limit_req_zone "name:size" spelling. The zone is referenced by
 * name from a per-location `shield_ban zone=<name> ...`.
 */
static char *
ngx_http_shield_ban_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    u_char                     *p;
    ssize_t                     size;
    ngx_str_t                  *value, name, s;
    ngx_shm_zone_t             *shm_zone;
    ngx_http_shield_ban_ctx_t  *ctx;

    value = cf->args->elts;

    p = (u_char *) ngx_strchr(value[1].data, ':');
    if (p == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid shield_ban_zone \"%V\", "
                           "expected name:size (e.g. shield:10m)", &value[1]);
        return NGX_CONF_ERROR;
    }

    name.data = value[1].data;
    name.len = p - value[1].data;

    s.data = p + 1;
    s.len = value[1].data + value[1].len - s.data;

    size = ngx_parse_size(&s);
    if (size == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid shield_ban_zone size \"%V\"", &s);
        return NGX_CONF_ERROR;
    }

    if (size < (ssize_t) (8 * ngx_pagesize)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "shield_ban_zone \"%V\" is too small "
                           "(minimum 8 pages)", &name);
        return NGX_CONF_ERROR;
    }

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_shield_ban_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    shm_zone = ngx_shared_memory_add(cf, &name, size, &ngx_http_shield_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (shm_zone->data) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "shield_ban_zone \"%V\" is already defined", &name);
        return NGX_CONF_ERROR;
    }

    shm_zone->init = ngx_http_shield_ban_init_zone;
    shm_zone->data = ctx;

    return NGX_CONF_OK;
}


#ifdef NGX_TEST_HARNESS

/* ---- shield_probe: CI-only introspection endpoint ---------------------- */

/*
 * shield_probe <zone>;
 *
 * Installs a content handler in this location that renders worker + shm state
 * as JSON. The renderer itself lives in t/harness (nginx-test-harness); this
 * module supplies only the HTTP surface and, via ngx_shield_probe_hooks.c, the
 * shield-specific zone semantics. Compiled out entirely unless
 * NGX_TEST_HARNESS is defined.
 *
 * The zone is resolved with a size of 0, which is nginx's documented "attach to
 * an already-declared zone" form (the same call ngx_http_limit_req uses to bind
 * a location to a zone declared elsewhere). Declaring the zone remains
 * shield_ban_zone's job -- a probe must observe state, never create it.
 */
static char *
ngx_http_shield_probe(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_shield_loc_conf_t  *slcf = conf;

    ngx_str_t                 *value;
    ngx_http_core_loc_conf_t  *clcf;

    value = cf->args->elts;

    if (slcf->probe_zone != NULL) {
        return "is duplicate";
    }

    slcf->probe_zone = ngx_shared_memory_add(cf, &value[1], 0,
                                             &ngx_http_shield_module);
    if (slcf->probe_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_shield_probe_handler;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_shield_probe_handler(ngx_http_request_t *r)
{
    size_t                       size;
    u_char                      *buf, *last;
    ngx_int_t                    rc;
    ngx_buf_t                   *b;
    ngx_chain_t                  out;
    ngx_http_shield_loc_conf_t  *slcf;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    slcf = ngx_http_get_module_loc_conf(r, ngx_http_shield_module);

    /* Applied before rendering, so the response reports the state the caller
     * just asked for rather than the state from before the request. */
    (void) ngx_test_probe_arm(slcf->probe_zone, &r->args);

    /*
     * NGX_TEST_PROBE_JSON_MAX bounds the harness's GENERIC document only; the
     * zone name and whatever the module hook appends are the caller's to add.
     * Shield's hook renders four fixed keys and four integers
     * (",\"nodes\":N,\"banned\":N,\"fault\":{\"slab_nth\":N,\"slab_seen\":N}"),
     * which is ~60 bytes of literal plus the digits -- 128 covers it with room
     * for every value widening to a full 64-bit decimal at once.
     *
     * Undersizing here does not overflow (rendering is ngx_slprintf-based and
     * truncates at `last`), but a truncated document fails to parse in the
     * prober, which surfaces as "broken probe" on every case rather than as a
     * wrong answer on one.
     */
    size = NGX_TEST_PROBE_JSON_MAX + NGX_HTTP_SHIELD_PROBE_ZONE_MAX;
    if (slcf->probe_zone != NULL) {
        size += slcf->probe_zone->shm.name.len;
    }

    buf = ngx_pnalloc(r->pool, size);
    if (buf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    last = ngx_test_probe_json(buf, buf + size, slcf->probe_zone);

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = last - buf;
    ngx_str_set(&r->headers_out.content_type, "application/json");
    r->headers_out.content_type_len = r->headers_out.content_type.len;
    r->headers_out.content_type_lowcase = NULL;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->pos = buf;
    b->last = last;
    b->memory = 1;
    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}

#endif /* NGX_TEST_HARNESS */


/*
 * shield_ban zone=<name> count=<n> window=<time> bantime=<time>  -- policy.
 * Binds a location to a zone defined by shield_ban_zone and sets the trigger:
 * ban the client for <bantime> once it produces <count> shield hits inside a
 * fixed <window>. The zone must already be defined at http level.
 */
static char *
ngx_http_shield_ban(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_shield_loc_conf_t  *slcf = conf;
    ngx_str_t                   *value, name, s;
    ngx_uint_t                   i;
    ngx_int_t                    n;
    time_t                       window, bantime;
    ngx_shm_zone_t              *shm_zone;

    if (slcf->ban_zone != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    ngx_str_null(&name);
    n = NGX_CONF_UNSET;
    window = NGX_CONF_UNSET;
    bantime = NGX_CONF_UNSET;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "zone=", 5) == 0) {
            name.data = value[i].data + 5;
            name.len = value[i].len - 5;
            continue;
        }

        if (ngx_strncmp(value[i].data, "count=", 6) == 0) {
            n = ngx_atoi(value[i].data + 6, value[i].len - 6);
            if (n == NGX_ERROR || n <= 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid shield_ban count \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }
            continue;
        }

        if (ngx_strncmp(value[i].data, "window=", 7) == 0) {
            s.data = value[i].data + 7;
            s.len = value[i].len - 7;
            window = ngx_parse_time(&s, 1);
            if (window == (time_t) NGX_ERROR || window <= 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid shield_ban window \"%V\"",
                                   &value[i]);
                return NGX_CONF_ERROR;
            }
            continue;
        }

        if (ngx_strncmp(value[i].data, "bantime=", 8) == 0) {
            s.data = value[i].data + 8;
            s.len = value[i].len - 8;
            bantime = ngx_parse_time(&s, 1);
            if (bantime == (time_t) NGX_ERROR || bantime <= 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid shield_ban bantime \"%V\"",
                                   &value[i]);
                return NGX_CONF_ERROR;
            }
            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid shield_ban parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    if (name.len == 0 || n == NGX_CONF_UNSET
        || window == NGX_CONF_UNSET || bantime == NGX_CONF_UNSET)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "shield_ban requires zone=, count=, window= "
                           "and bantime=");
        return NGX_CONF_ERROR;
    }

    shm_zone = ngx_shared_memory_add(cf, &name, 0, &ngx_http_shield_module);
    if (shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    slcf->ban_zone = shm_zone;
    slcf->ban_count = (ngx_uint_t) n;
    slcf->ban_window = window;
    slcf->ban_time = bantime;

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

#ifdef NGX_TEST_HARNESS
    /* Hand the harness probe shield's zone semantics. Done here rather than in
     * init_process so it is in place before any worker can serve a probe
     * request; the hooks are plain function pointers in the module's own image,
     * so they survive the fork with no per-worker work. */
    ngx_shield_probe_hooks_register();
#endif

    return NGX_OK;
}


/*
 * shield_log <file> | syslog:<opts> | off -- one JSON hit record per request,
 * to a file (opened via ngx_conf_open_file so nginx reopens it on SIGUSR1,
 * logrotate-safe) or to a syslog server (ngx_syslog, e.g.
 * `syslog:server=10.0.0.1,tag=shield`). No "|command" form: shield runs in
 * PRECONTENT on every request in root-started workers, so piping attacker-
 * influenced bytes into a forked shell would reintroduce exactly the command-
 * injection/DoS class this module blocks. Ship to a file/syslog and report out
 * of band.
 *
 * UNSET_PTR means "never configured" (inherit); NULL means explicit `off`
 * (disable, survives inheritance). `log` carries the unset/off sentinel for
 * both sinks; a syslog config leaves `log` NULL and sets `syslog`.
 */
static char *
ngx_http_shield_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_shield_loc_conf_t  *slcf = conf;
    ngx_str_t                   *value = cf->args->elts;
    ngx_syslog_peer_t           *peer;

    if (slcf->log != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    if (value[1].len == 3 && ngx_strncmp(value[1].data, "off", 3) == 0) {
        slcf->log = NULL;      /* explicitly disabled; survives inheritance */
        slcf->syslog_peer = NULL;
        return NGX_CONF_OK;
    }

    if (value[1].data[0] == '|') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "shield_log does not support piping to a command; "
                           "log to a file and report out of band");
        return NGX_CONF_ERROR;
    }

    if (ngx_strncmp(value[1].data, "syslog:", 7) == 0) {
        peer = ngx_pcalloc(cf->pool, sizeof(ngx_syslog_peer_t));
        if (peer == NULL) {
            return NGX_CONF_ERROR;
        }
        if (ngx_syslog_process_conf(cf, peer) != NGX_CONF_OK) {
            return NGX_CONF_ERROR;
        }
        slcf->syslog_peer = peer;
        slcf->log = NULL;      /* set, but no file sink */
        return NGX_CONF_OK;
    }

    slcf->log = ngx_conf_open_file(cf->cycle, &value[1]);
    if (slcf->log == NULL) {
        return NGX_CONF_ERROR;
    }
    slcf->syslog_peer = NULL;

    return NGX_CONF_OK;
}
