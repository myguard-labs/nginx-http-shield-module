/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Windows uses signed LONG32 fetch returns with unsigned 32-bit storage.
 * Emulate that API independently of this host's native atomic width.
 */
#undef NDEBUG
#include <ngx_config.h>
#include <ngx_core.h>
#include <assert.h>

/* Use nginx's real Windows macro, including its pointer-argument cast. The
 * API stub copies 32 bits even on Unix hosts where long is 64 bits. */
static long
InterlockedExchangeAdd(long *address, long add)
{
    uint32_t previous, next;
    int32_t result;

    ngx_memcpy(&previous, (u_char *) address, sizeof(previous));
    next = previous + (uint32_t) add;
    ngx_memcpy((u_char *) address, &next, sizeof(next));
    ngx_memcpy(&result, &previous, sizeof(result));
    return result;
}

#undef ngx_atomic_fetch_add
#undef ngx_atomic_cmp_set
#undef ngx_memory_barrier
#undef ngx_cpu_pause
#undef ngx_trylock
#undef ngx_unlock
#undef NGX_ATOMIC_T_LEN
#undef _NGX_ATOMIC_H_INCLUDED_
#define ngx_atomic_int_t windows_atomic_int_t
#define ngx_atomic_uint_t windows_atomic_uint_t
#define ngx_atomic_t windows_atomic_t
#define ngx_spinlock windows_spinlock
#include NGX_WINDOWS_ATOMIC_HEADER
#include "../../src/ngx_http_shield_ban.h"

int
main(void)
{
    volatile uint32_t counter;
    uint32_t values[] = { 0x7fffffff, 0x80000000, 0xffffffff };
    ngx_http_shield_ban_shctx_t sh;
    ngx_http_shield_ban_ctx_t ctx;
    ngx_uint_t i;

    for (i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
        counter = values[i];
        assert(ngx_http_shield_ban_counter_value(&counter)
               == (uint64_t) values[i]);
        assert(counter == values[i]);
    }
    counter = UINT32_MAX;
    (void) ngx_atomic_fetch_add(&counter, 1);
    assert(ngx_http_shield_ban_counter_value(&counter) == 0);
    ngx_memzero(&sh, sizeof(sh));
    ctx.sh = &sh;
    ngx_http_shield_ban_count_request(&ctx, 0);
    assert(sh.inspected == 1 && sh.ban_refused == 0);
    ngx_http_shield_ban_count_request(&ctx, 1);
    assert(sh.inspected == 1 && sh.ban_refused == 1);
    printf("request variable slot: %zu bytes\n", sizeof(ngx_variable_value_t));
    puts("atomic_width_unit: Windows macro, LONG32 boundaries and wrap passed");
    return 0;
}
