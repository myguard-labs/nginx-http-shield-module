/* Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 * Exercise shield's private log copies through nginx's real log core.
 * Only write(2) is replaced: no full filesystem or live nginx is needed. */
#undef NDEBUG
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <assert.h>

static void *test_main_conf;
#undef ngx_http_get_module_main_conf
#define ngx_http_get_module_main_conf(r, module) test_main_conf
#include "../../src/ngx_http_shield_module.c"

static ngx_time_t test_time = { 100, 0, 0 };
volatile ngx_time_t *ngx_cached_time = &test_time;
volatile ngx_str_t ngx_cached_err_log_time = ngx_string("2026/01/01 00:00:00");
ngx_pid_t ngx_pid = 1;

static size_t writes[4];
static char messages[4][NGX_MAX_ERROR_STR + 1];
static int write_error;
static size_t handler_calls;

/* GNU ld requires this symbol for --wrap=write; keep it out of C names. */
ssize_t shield_test_write(int fd, const void *buf, size_t size)
    __asm__("__wrap_write");
ssize_t shield_test_write(int fd, const void *buf, size_t size)
{
    size_t slot;

    assert(fd >= 100 && fd <= 103);
    slot = (size_t) (fd - 100);
    assert(size < sizeof(messages[slot]));
    writes[slot]++;
    ngx_memcpy(messages[slot], buf, size);
    messages[slot][size] = '\0';
    if (slot == 1 && write_error != 0) {
        errno = write_error;
        return -1;
    }
    return (ssize_t) size;
}

static u_char *private_handler(ngx_log_t *log, u_char *buf, size_t len)
{
    (void) log; (void) len;
    handler_calls++;
    return ngx_cpymem(buf, " PRIVATE-URI", sizeof(" PRIVATE-URI") - 1);
}

typedef struct {
    ngx_http_request_t *request;
    ngx_http_shield_loc_conf_t *conf;
    ngx_http_shield_hit_t *hit;
    ngx_log_t *sink;
    size_t calls;
    size_t nested;
    int busy;
    int reenter;
} writer_state_t;

static void test_writer(ngx_log_t *log, ngx_uint_t level, u_char *buf, size_t len)
{
    writer_state_t *state = log->wdata;

    assert(log->handler == NULL && log->next == NULL);
    assert(level == NGX_LOG_WARN);
    assert(len != 0 && buf[len - 1] == '\n');
    if (state->busy) {
        state->nested++;
        return;
    }
    state->calls++;
    if (state->reenter) {
        state->busy = 1;
        /* A writer owns its mutable state, even when called via a copy. */
        state->sink->disk_full_time = 999;
        ngx_http_shield_log_hit(state->request, state->conf, state->hit, 0);
        state->busy = 0;
    }
}

static void reset(ngx_log_t logs[4], ngx_open_file_t files[4])
{
    size_t i;

    ngx_memzero(logs, 4 * sizeof(*logs));
    ngx_memzero(files, 4 * sizeof(*files));
    ngx_memzero(writes, sizeof(writes));
    ngx_memzero(messages, sizeof(messages));
    handler_calls = 0;
    write_error = NGX_ENOSPC;
    test_time.sec = 100;
    for (i = 0; i < 4; i++) {
        files[i].fd = (ngx_fd_t) (100 + i);
        logs[i].log_level = NGX_LOG_NOTICE;
        logs[i].file = &files[i];
        logs[i].handler = private_handler;
        logs[i].data = &files[i];
        logs[i].action = "reading client request";
        logs[i].connection = 42;
        logs[i].next = i < 3 ? &logs[i + 1] : NULL;
    }
    logs[3].log_level = NGX_LOG_ERR;
}

static void check_message(const char *message, const char *action,
    const char *body_policy, const char *ban)
{
    assert(strstr(message, action) != NULL);
    assert(strstr(message, "category=deserial source=body") != NULL);
    assert(strstr(message, "rule=123456789abcdef0 rev=1") != NULL);
    assert(strstr(message, "ruleset=1122334455667788 view=raw") != NULL);
    assert(strstr(message, body_policy) != NULL && "log body_policy label");
    assert(strstr(message, ban) != NULL && "log ban label");
    assert(strstr(message, "PRIVATE-URI") == NULL);
}

static void test_strict_ban_metadata(ngx_http_request_t *request,
    ngx_http_shield_loc_conf_t *conf, ngx_http_shield_hit_t *hit,
    ngx_log_t logs[4], ngx_open_file_t files[4])
{
    ngx_shm_zone_t ban_zone;

    ngx_memzero(&ban_zone, sizeof(ban_zone));
    reset(logs, files);
    conf->body_strict = 1;
    conf->ban_zone = &ban_zone;
    ngx_http_shield_log_hit(request, conf, hit, 0);
    check_message(messages[0], "action=block", "body_policy=strict ",
                  " ban=on\n");
    conf->body_strict = 0;
    conf->ban_zone = NULL;
}

int main(void)
{
    ngx_http_request_t request;
    ngx_connection_t connection;
    ngx_http_shield_loc_conf_t conf;
    ngx_http_shield_main_conf_t main_conf;
    ngx_http_shield_hit_t hit;
    ngx_log_t logs[4], saved[4];
    ngx_open_file_t files[4];
    writer_state_t writer;
    ngx_uint_t observation, mode;
    size_t i;

    ngx_memzero(&request, sizeof(request));
    ngx_memzero(&connection, sizeof(connection));
    ngx_memzero(&conf, sizeof(conf));
    ngx_memzero(&main_conf, sizeof(main_conf));
    ngx_memzero(&hit, sizeof(hit));
    ngx_memzero(&writer, sizeof(writer));
    request.connection = &connection;
    connection.log = logs;
    ngx_str_set(&connection.addr_text, "192.0.2.1");
    main_conf.ruleset = UINT64_C(0x1122334455667788);
    test_main_conf = &main_conf;
    conf.status = 403;
    hit.rule = UINT64_C(0x123456789abcdef0);
    hit.category = "deserial";
    hit.source = NGX_HTTP_SHIELD_SOURCE_BODY;
    hit.view = "raw";
    ngx_use_stderr = 0;

    /* Verify the injected errno/clock exercise nginx's own chain backoff. */
    reset(logs, files);
    logs[0].handler = NULL;
    ngx_log_error(NGX_LOG_WARN, logs, 0, "core baseline");
    ngx_log_error(NGX_LOG_WARN, logs, 0, "core baseline");
    assert(writes[0] == 2 && writes[1] == 1);
    assert(logs[1].disk_full_time == test_time.sec);

    for (observation = 0; observation <= 1; observation++) {
        for (mode = NGX_HTTP_SHIELD_DETECT; mode <= NGX_HTTP_SHIELD_BLOCK;
             mode++)
        {
            reset(logs, files);
            conf.mode = mode;
            writer.calls = 0;
            logs[2].writer = test_writer;
            logs[2].wdata = &writer;
            ngx_memcpy(saved, logs, sizeof(saved));
            ngx_http_shield_log_hit(&request, &conf, &hit, observation);
            ngx_http_shield_log_hit(&request, &conf, &hit, observation);
            assert(writes[0] == 2);
            /* The second shield event must suppress the full secondary sink. */
            assert(writes[1] == 1);
            assert(logs[1].disk_full_time == test_time.sec);
            assert(writes[2] == 0 && writes[3] == 0);
            assert(writer.calls == (observation ? 0 : 2));
            assert(handler_calls == 0);
            check_message(messages[0], observation ? "action=observe"
                          : mode == NGX_HTTP_SHIELD_BLOCK ? "action=block"
                          : "action=detect", "body_policy=observe ",
                          " ban=off\n");
            assert((strstr(messages[0], "192.0.2.1") != NULL) == !observation);
            test_time.sec++;
            ngx_http_shield_log_hit(&request, &conf, &hit, observation);
            assert(writes[0] == 3 && writes[1] == 2);
            assert(logs[1].disk_full_time == test_time.sec);
            /* Every original chain/callback/level field stays intact. */
            saved[1].disk_full_time = logs[1].disk_full_time;
            for (i = 0; i < 4; i++) {
                assert(memcmp(&saved[i], &logs[i], sizeof(logs[i])) == 0);
            }
        }
    }

    test_strict_ban_metadata(&request, &conf, &hit, logs, files);

    /* Healthy and non-ENOSPC sinks are attempted for each message. */
    for (i = 0; i < 2; i++) {
        int error = i ? NGX_EIO : 0;

        reset(logs, files);
        write_error = error;
        ngx_http_shield_log_hit(&request, &conf, &hit, 0);
        ngx_http_shield_log_hit(&request, &conf, &hit, 0);
        assert(writes[0] == 2 && writes[1] == 2 && writes[2] == 2);
        assert(logs[1].disk_full_time == 0);
    }

    /* A reentrant writer keeps its shared guard and sink state. */
    reset(logs, files);
    writer.request = &request;
    writer.conf = &conf;
    writer.hit = &hit;
    writer.sink = &logs[2];
    writer.calls = 0;
    writer.nested = 0;
    writer.reenter = 1;
    logs[2].writer = test_writer;
    logs[2].wdata = &writer;
    ngx_http_shield_log_hit(&request, &conf, &hit, 0);
    assert(writer.calls == 1 && writer.nested == 1 && writer.busy == 0);
    assert(logs[2].disk_full_time == 999);
    assert(logs[2].writer == test_writer && logs[2].wdata == &writer);
    assert(logs[2].next == &logs[3] && logs[2].handler == private_handler);
    assert(writes[0] == 2 && writes[1] == 1 && writes[3] == 0);
    puts("log_unit: core backoff, four shield modes, strict/ban metadata, two write outcomes and reentrancy passed");
    return 0;
}
