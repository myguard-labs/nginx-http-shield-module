/* Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause */
/* Fuzz the shipped bounded gzip decoder with determinism and bound oracles. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../../src/ngx_http_shield_gzip.h"

static union {
    ngx_shield_gzip_align_t align;
    unsigned char bytes[NGX_SHIELD_GZIP_ARENA];
} arena_a, arena_b;

static int
same_result(ngx_shield_gzip_result_t a, ngx_shield_gzip_result_t b)
{
    return a.state == b.state
           && a.consumed == b.consumed
           && a.produced == b.produced
           && a.allocated == b.allocated
           && a.allocations == b.allocations
           && a.members == b.members
           && a.calls == b.calls
           && a.zstatus == b.zstatus;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ngx_shield_gzip_result_t a, b;
    unsigned char *input, *before, *out_a, *out_b;
    size_t input_len, capacity;

    if (size < 2) {
        return 0;
    }
    capacity = 1 + ((((size_t) data[0] << 8) | data[1]) % 65536);
    input_len = size - 2;
    input = malloc(input_len == 0 ? 1 : input_len);
    before = malloc(input_len == 0 ? 1 : input_len);
    out_a = malloc(capacity);
    out_b = malloc(capacity);
    if (input == NULL || before == NULL || out_a == NULL || out_b == NULL) {
        abort();
    }
    memcpy(input, data + 2, input_len);
    memcpy(before, input, input_len);
    memset(out_a, 0xa5, capacity);
    memset(out_b, 0xa5, capacity);

    a = ngx_shield_gzip_decode(input, input_len, out_a, capacity,
                               arena_a.bytes, sizeof(arena_a.bytes));
    b = ngx_shield_gzip_decode(input, input_len, out_b, capacity,
                               arena_b.bytes, sizeof(arena_b.bytes));
    if (memcmp(input, before, input_len) != 0
        || !same_result(a, b)
        || a.consumed > input_len || a.produced > capacity
        || a.allocated > NGX_SHIELD_GZIP_ARENA || a.allocations > 2
        || a.members > NGX_SHIELD_GZIP_MAX_MEMBERS
        || a.calls > 3 * NGX_SHIELD_GZIP_MAX_MEMBERS
        || memcmp(out_a, out_b, a.produced) != 0)
    {
        abort();
    }
    free(out_b);
    free(out_a);
    free(before);
    free(input);
    return 0;
}
