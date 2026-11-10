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

static int32_t
signed_fetch_add(volatile uint32_t *counter, int32_t add)
{
    uint32_t previous = *counter;
    int32_t result;

    *counter += (uint32_t) add;
    ngx_memcpy(&result, &previous, sizeof(result));
    return result;
}

#undef ngx_atomic_fetch_add
#define ngx_atomic_fetch_add signed_fetch_add
#define ngx_atomic_t volatile uint32_t
#define ngx_atomic_uint_t uint32_t
#include "../../src/ngx_http_shield_ban.h"

int
main(void)
{
    volatile uint32_t counter;
    uint32_t values[] = { 0x7fffffff, 0x80000000, 0xffffffff };
    ngx_uint_t i;

    for (i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
        counter = values[i];
        assert(ngx_http_shield_ban_counter_value(&counter) == (uint64_t) values[i]);
        assert(counter == values[i]);
    }
    counter = UINT32_MAX;
    (void) signed_fetch_add(&counter, 1);
    assert(ngx_http_shield_ban_counter_value(&counter) == 0);
    printf("request variable slot: %zu bytes\n", sizeof(ngx_variable_value_t));
    puts("atomic_width_unit: signed LONG32 boundaries and wrap passed");
    return 0;
}
