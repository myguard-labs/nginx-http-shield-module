/* Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 * Run the complete upstream -t path, then finish its explicit ownership tree.
 * See config-lifetime.md for the upstream success/failure cleanup contract.
 */
#undef NDEBUG
#include <ngx_config.h>
#include <ngx_core.h>
#include <assert.h>
#include <dirent.h>
#include <sys/mman.h>

static ngx_cycle_t *test_init_cycle(ngx_cycle_t *old);
static ngx_cycle_t *test_cycle;
static ngx_pool_t *test_bootstrap_pool;
static ngx_fd_t test_bootstrap_fd;
static unsigned test_calls;
static void *test_crc_allocation;
static void *test_title_allocation;
static char *test_retired_environment[] = { NULL };

/* Headers above keep the actual external function declaration intact. Only
 * the call inside main is intercepted; no allocator or destructor is replaced.
 */
#define main test_nginx_main
#define ngx_init_cycle test_init_cycle
#include <nginx.c>
#undef ngx_init_cycle
#undef main

/* CRC initialization returns an aligned interior pointer, losing its raw base.
 * Capture only that upstream function's one allocation, forwarding unchanged;
 * module allocation calls are neither wrapped nor recorded.
 */
static void *
test_crc_alloc(size_t size, ngx_log_t *log)
{
    assert(test_crc_allocation == NULL);
    test_crc_allocation = ngx_alloc(size, log);
    return test_crc_allocation;
}
#define ngx_alloc test_crc_alloc
#include <ngx_crc32.c>
#undef ngx_alloc

static void *
test_title_alloc(size_t size, ngx_log_t *log)
{
    assert(test_title_allocation == NULL);
    test_title_allocation = ngx_alloc(size, log);
    return test_title_allocation;
}
#define ngx_alloc test_title_alloc
#include <ngx_setproctitle.c>
#undef ngx_alloc

#if !(NGX_LINUX && NGX_HAVE_STRERRORDESC_NP)
#error This lifecycle driver requires Linux with allocation-free strerror init
#endif

static ngx_cycle_t *
test_init_cycle(ngx_cycle_t *old)
{
    assert(++test_calls == 1);
    test_bootstrap_pool = old->pool;
    test_bootstrap_fd = old->log->file->fd;
    test_cycle = ngx_init_cycle(old);
    /* ngx_init_cycle destroys the initial pool on success and both new pools
     * on failure. The bootstrap pool survives only the failed parse.
     */
    if (test_cycle != NULL) {
        test_bootstrap_pool = NULL;
    }
    return test_cycle;
}

static unsigned
test_fd_count(void)
{
    DIR *dir;
    struct dirent *entry;
    unsigned count = 0;

    dir = opendir("/proc/self/fd");
    assert(dir != NULL);
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] != '.') {
            count++;
        }
    }
    assert(closedir(dir) == 0);
    return count;
}

static void
test_destroy_cycle(ngx_cycle_t *cycle)
{
    ngx_uint_t i;
    ngx_list_part_t *part;
    ngx_open_file_t *file;
    ngx_shm_zone_t *zone;
    ngx_listening_t *ls;
    unsigned files = 0, zones = 0, listeners = 0;
    size_t offset;
    unsigned char residency;

    assert(cycle->old_cycle == NULL);
    ngx_cycle = cycle;
    /* Match master exit callbacks before destroying resources they can use. */
    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->exit_master) {
            cycle->modules[i]->exit_master(cycle);
        }
    }

    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {
        assert(!ls[i].inherited && ls[i].connection == NULL);
        assert(ls[i].sockaddr->sa_family == AF_INET);
        if (ls[i].fd != (ngx_socket_t) -1) {
            listeners++;
        }
    }
    ngx_close_listening_sockets(cycle);

    /* Every zone is new: this driver admits no old cycle/inherited resources.
     * The upstream failed-cycle/reload path owns the same shm_free operation.
     * Pool cleanup is intentionally left to nginx; no module allocations are
     * individually freed or discovered by an allocation sweep.
     */
    for (part = &cycle->shared_memory.part; part; part = part->next) {
        zone = part->elts;
        for (i = 0; i < part->nelts; i++) {
            assert(zone[i].shm.addr != NULL && !zone[i].shm.exists);
            ngx_shm_free(&zone[i].shm);
            for (offset = 0; offset < zone[i].shm.size;
                 offset += ngx_pagesize)
            {
                assert(mincore(zone[i].shm.addr + offset, ngx_pagesize,
                               &residency) == -1 && errno == ENOMEM);
            }
            zones++;
        }
    }

    /* Preserve the log until pool cleanup (including dlclose) is complete.
     * Logs are opened in an earlier pass and their descriptor values are
     * copied before releasing the pool; no pool data is read after destruction.
     */
    {
        ngx_fd_t fds[32];
        unsigned n = 0;
        for (part = &cycle->open_files.part; part; part = part->next) {
            file = part->elts;
            for (i = 0; i < part->nelts; i++) {
                if (file[i].fd != NGX_INVALID_FILE
                    && file[i].fd != ngx_stderr)
                {
                    assert(n < sizeof(fds) / sizeof(fds[0]));
                    fds[n++] = file[i].fd;
                }
            }
        }
        /* Exit callbacks above still see the active environment. Only pool
         * cleanup follows retirement; nginx's registered environment cleanup
         * must see that its entries are no longer process-owned.
         */
        environ = test_retired_environment;
        ngx_destroy_pool(cycle->pool);
        for (i = 0; i < n; i++) {
            assert(ngx_close_file(fds[i]) != NGX_FILE_ERROR);
            files++;
        }
    }
    ngx_cycle = NULL;
    (void) fprintf(stderr, "lifecycle: cycle=1 shm=%u listeners=%u files=%u\n",
            zones, listeners, files);
}

int
main(int argc, char **argv)
{
    uint32_t *saved_crc = ngx_crc32_table_short;
    unsigned fds = test_fd_count();
    int i, rc;

    /* Refuse daemon/service modes. Runner supplies exactly these options. */
    assert(argc == 8 && strcmp(argv[1], "-t") == 0);
    assert(strcmp(argv[2], "-e") == 0 && strcmp(argv[3], "stderr") == 0);
    assert(strcmp(argv[4], "-p") == 0 && strcmp(argv[6], "-c") == 0);
    assert(getenv("NGINX") == NULL);
    rc = test_nginx_main(argc, argv);
    assert(test_calls == 1);
    /* Retire this process's environment at its final exit, before registered
     * cleanups and before freeing the process-title environment copy. nginx's
     * environment cleanups intentionally retain entries that are still active.
     * No further parsing/worker start is permitted after this point.
     */
    if (test_cycle != NULL) {
        assert(rc == 0);
        test_destroy_cycle(test_cycle);
        test_cycle = NULL;
    } else {
        assert(rc == 1 && test_bootstrap_pool != NULL);
        environ = test_retired_environment;
        ngx_destroy_pool(test_bootstrap_pool);
        ngx_cycle = NULL;
        (void) fprintf(stderr, "lifecycle: rejected=1 bootstrap=1\n");
    }
    test_bootstrap_pool = NULL;
    if (test_bootstrap_fd != NGX_INVALID_FILE
        && test_bootstrap_fd != ngx_stderr)
    {
        assert(ngx_close_file(test_bootstrap_fd) != NGX_FILE_ERROR);
    }
    /* These allocations are made by ngx_save_argv, not by a module. */
    assert(ngx_argv != NULL);
    for (i = 0; i < ngx_argc; i++) {
        ngx_free(ngx_argv[i]);
    }
    ngx_free(ngx_argv);
    ngx_argv = NULL;
    ngx_free(test_title_allocation);
    test_title_allocation = NULL;
    ngx_os_environ = NULL;
    /* ngx_crc32_table_init allocates only if the static table is unaligned. */
    if (test_crc_allocation != NULL) {
        assert(ngx_crc32_table_short != saved_crc);
        ngx_free(test_crc_allocation);
        test_crc_allocation = NULL;
        ngx_crc32_table_short = saved_crc;
    }
    assert(test_fd_count() == fds);
    (void) fprintf(stderr, "lifecycle: descriptors restored; parser_exit=%d\n", rc);
    return rc;
}
