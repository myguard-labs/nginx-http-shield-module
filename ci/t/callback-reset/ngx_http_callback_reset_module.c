/* Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

static ngx_int_t ngx_http_callback_reset_handler(ngx_http_request_t *r);
static char *ngx_http_callback_reset(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static void ngx_http_callback_reset_complete(ngx_event_t *ev);
static void ngx_http_callback_reset_cleanup(void *data);

typedef struct {
    ngx_event_t          event;
    ngx_http_request_t  *request;
} ngx_http_callback_reset_ctx_t;

static ngx_command_t ngx_http_callback_reset_commands[] = {
    { ngx_string("callback_reset_suspend"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_callback_reset, 0, 0, NULL },
    ngx_null_command
};

static ngx_http_module_t ngx_http_callback_reset_module_ctx = {
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

ngx_module_t ngx_http_callback_reset_module = {
    NGX_MODULE_V1,
    &ngx_http_callback_reset_module_ctx,
    ngx_http_callback_reset_commands,
    NGX_HTTP_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};

/* The fixture is loaded against the exact configured core headers. */
ngx_module_t *ngx_modules[] = { &ngx_http_callback_reset_module, NULL };
char *ngx_module_names[] = { "ngx_http_callback_reset_module", NULL };
char *ngx_module_order[] = { NULL };

static char *
ngx_http_callback_reset(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;

    (void) cmd;
    (void) conf;
    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_callback_reset_handler;
    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_callback_reset_handler(ngx_http_request_t *r)
{
    ngx_http_callback_reset_ctx_t *ctx;
    ngx_pool_cleanup_t           *cleanup;

    ctx = ngx_http_get_module_ctx(r, ngx_http_callback_reset_module);
    if (ctx != NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "callback-reset unexpected content reentry");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ctx = ngx_pcalloc(r->pool, sizeof(*ctx));
    cleanup = ngx_pool_cleanup_add(r->pool, 0);
    if (ctx == NULL || cleanup == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ctx->request = r;
    ctx->event.data = ctx;
    ctx->event.handler = ngx_http_callback_reset_complete;
    ctx->event.log = r->connection->log;
    cleanup->handler = ngx_http_callback_reset_cleanup;
    cleanup->data = ctx;
    ngx_http_set_ctx(r, ctx, ngx_http_callback_reset_module);

    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                  "callback-reset suspend method=%ui", r->method);
    /* Own a normal asynchronous content reference. Leave the old read event
     * and post_handler untouched: only real nginx invokes the stale callback.
     * Our independent event completes only after the core finishes the body. */
    r->main->count++;
    ngx_add_timer(&ctx->event, 10);
    return NGX_DONE;
}

static void
ngx_http_callback_reset_complete(ngx_event_t *ev)
{
    ngx_http_callback_reset_ctx_t *ctx = ev->data;
    ngx_http_request_t            *r = ctx->request;
    ngx_http_complex_value_t       value;
    ngx_str_t                     type = ngx_string("text/plain");
    ngx_int_t                     rc;

    if (r->request_body == NULL || r->request_body->rest != 0
        || !r->request_body->last_saved)
    {
        ngx_add_timer(ev, 10);
        return;
    }
    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                  "callback-reset complete count=%ui", r->main->count);
    ngx_memzero(&value, sizeof(value));
    ngx_str_set(&value.value, "destination-complete\n");
    rc = ngx_http_send_response(r, NGX_HTTP_OK, &type, &value);
    ngx_http_finalize_request(r, rc);
}

static void
ngx_http_callback_reset_cleanup(void *data)
{
    ngx_http_callback_reset_ctx_t *ctx = data;

    if (ctx->event.timer_set) {
        ngx_del_timer(&ctx->event);
    }
    ngx_log_error(NGX_LOG_NOTICE, ctx->request->connection->log, 0,
                  "callback-reset cleanup");
}
