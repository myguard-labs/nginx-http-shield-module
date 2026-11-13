/* Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause */
#ifndef NGX_HTTP_SHIELD_GZIP_H
#define NGX_HTTP_SHIELD_GZIP_H

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <zlib.h>

/* One reused zlib stream, caller-owned immutable input and output.
 * No allocation escapes this aligned, bounded arena or survives the call. */
#define NGX_SHIELD_GZIP_ARENA 65536
#define NGX_SHIELD_GZIP_MAX (16 * 1024 * 1024)
#define NGX_SHIELD_GZIP_INITIAL_OUTPUT (64 * 1024)
#define NGX_SHIELD_GZIP_MAX_MEMBERS 64

typedef union {
    long double number;
    void *pointer;
    uint64_t integer;
} ngx_shield_gzip_align_t;

typedef struct {
    unsigned char *data;
    size_t size, used, allocations;
} ngx_shield_gzip_arena_t;

typedef enum {
    NGX_SHIELD_GZIP_COMPLETE,
    NGX_SHIELD_GZIP_LIMIT,
    NGX_SHIELD_GZIP_TRUNCATED,
    NGX_SHIELD_GZIP_INVALID,
    NGX_SHIELD_GZIP_TRAILING,
    NGX_SHIELD_GZIP_MEMBER_LIMIT,
    NGX_SHIELD_GZIP_ERROR
} ngx_shield_gzip_state_t;

typedef struct {
    ngx_shield_gzip_state_t state;
    size_t consumed, produced, allocated, allocations, members, calls;
    int zstatus;
} ngx_shield_gzip_result_t;

static voidpf
ngx_shield_gzip_alloc(voidpf opaque, uInt items, uInt size)
{
    ngx_shield_gzip_arena_t *arena = opaque;
    size_t bytes, padding, alignment = sizeof(ngx_shield_gzip_align_t);
    unsigned char *result;

    if (size != 0 && (size_t) items > SIZE_MAX / size) {
        return Z_NULL;
    }
    bytes = (size_t) items * size;
    padding = (alignment - arena->used % alignment) % alignment;
    if (padding > arena->size - arena->used
        || bytes > arena->size - arena->used - padding)
    {
        return Z_NULL;
    }
    result = arena->data + arena->used + padding;
    arena->used += padding + bytes;
    arena->allocations++;
    memset(result, 0, bytes);
    return result;
}

static void
ngx_shield_gzip_free(voidpf opaque, voidpf address)
{
    /* The caller owns the arena; inflateEnd releases all zlib references. */
    (void) opaque;
    (void) address;
}

static ngx_shield_gzip_result_t
ngx_shield_gzip_decode(const unsigned char *input, size_t length,
    unsigned char *output, size_t capacity, void *memory, size_t memory_size)
{
    ngx_shield_gzip_result_t result;
    ngx_shield_gzip_arena_t arena;
    z_stream stream;
    gz_header header;
    unsigned char prefix[4] = {0};
    size_t member_start, prefix_size;
    int status, header_crc;

    memset(&result, 0, sizeof(result));
    result.state = NGX_SHIELD_GZIP_ERROR;
    result.zstatus = Z_STREAM_ERROR;
    if (length > UINT_MAX || capacity == 0 || capacity > UINT_MAX
        || input == NULL || output == NULL || memory == NULL)
    {
        return result;
    }
    memset(&stream, 0, sizeof(stream));
    arena.data = memory;
    arena.size = memory_size;
    arena.used = 0;
    arena.allocations = 0;
    stream.zalloc = ngx_shield_gzip_alloc;
    stream.zfree = ngx_shield_gzip_free;
    stream.opaque = &arena;
    status = inflateInit2(&stream, 15 + 16); /* gzip only, never raw/auto */
    if (status == Z_OK) {
        stream.next_out = output;
        stream.avail_out = (uInt) capacity;
        for ( ;; ) {
            member_start = result.consumed;
            prefix_size = length - member_start;
            if (prefix_size > sizeof(prefix)) {
                prefix_size = sizeof(prefix);
            }
            memcpy(prefix, input + member_start, prefix_size);
            header_crc = prefix_size == 4 && (prefix[3] & 2);
            if (prefix_size == 4) {
                /* Match Python gzip's accepted reserved flags and unchecked
                 * FHCRC. Only this fixed-size inspection prefix is changed. */
                prefix[3] &= 0x1d;
            }
            memset(&header, 0, sizeof(header));
            status = inflateGetHeader(&stream, &header);
            if (status != Z_OK) {
                break;
            }
            stream.next_in = prefix;
            stream.avail_in = (uInt) prefix_size;
            result.calls++;
            status = inflate(&stream, Z_BLOCK);
            result.consumed = member_start + prefix_size - stream.avail_in;
            if (status != Z_OK && status != Z_BUF_ERROR) {
                goto failed;
            }
            /* zlib parses every optional field. Z_BLOCK returns at the header
             * boundary before consuming any deflate bytes or trailer. */
            stream.next_in = (Bytef *) input + result.consumed;
            stream.avail_in = (uInt) (length - result.consumed);
            result.calls++;
            status = inflate(&stream, Z_BLOCK);
            result.consumed = length - stream.avail_in;
            if (status != Z_OK || !header.done) {
                goto failed;
            }
            if (header_crc) {
                if (stream.avail_in < 2) {
                    result.consumed = length;
                    result.state = NGX_SHIELD_GZIP_TRUNCATED;
                    break;
                }
                stream.next_in += 2;
                stream.avail_in -= 2;
                result.consumed += 2;
            }
            result.calls++;
            status = inflate(&stream, Z_FINISH);
            result.consumed = length - stream.avail_in;
            result.produced = capacity - stream.avail_out;
            if (status == Z_STREAM_END) {
                result.members++;
                if (result.consumed == member_start) {
                    result.state = NGX_SHIELD_GZIP_ERROR;
                    break;
                }
                /* Padding costs at most the input byte budget. */
                while (stream.avail_in != 0 && *stream.next_in == 0) {
                    stream.next_in++;
                    stream.avail_in--;
                }
                result.consumed = length - stream.avail_in;
                if (stream.avail_in == 0) {
                    result.state = NGX_SHIELD_GZIP_COMPLETE;
                    break;
                }
                /* Known non-member data is invalid even at a byte/member cap.
                 * A lone next magic byte is an incomplete member instead. */
                if (*stream.next_in != 0x1f
                    || (stream.avail_in > 1 && stream.next_in[1] != 0x8b))
                {
                    result.state = NGX_SHIELD_GZIP_TRAILING;
                    break;
                }
                if (stream.avail_in == 1) {
                    result.state = NGX_SHIELD_GZIP_TRUNCATED;
                    break;
                }
                if (stream.avail_out == 0) {
                    result.state = NGX_SHIELD_GZIP_LIMIT;
                    break;
                }
                if (result.members == NGX_SHIELD_GZIP_MAX_MEMBERS) {
                    result.state = NGX_SHIELD_GZIP_MEMBER_LIMIT;
                    break;
                }
                status = inflateReset2(&stream, 15 + 16);
                if (status != Z_OK) {
                    result.state = NGX_SHIELD_GZIP_ERROR;
                    break;
                }
                continue;
            }
failed:
            if (status == Z_DATA_ERROR || status == Z_NEED_DICT) {
                result.state = NGX_SHIELD_GZIP_INVALID;
            } else if (status == Z_BUF_ERROR || status == Z_OK) {
                result.state = stream.avail_out == 0 ? NGX_SHIELD_GZIP_LIMIT
                                                    : NGX_SHIELD_GZIP_TRUNCATED;
            }
            break;
        }
        (void) inflateEnd(&stream);
    }
    result.zstatus = status;
    result.allocated = arena.used;
    result.allocations = arena.allocations;
    return result;
}

#endif
