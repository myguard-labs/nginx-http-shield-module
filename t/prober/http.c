/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * http.c -- see http.h.
 */

/* _GNU_SOURCE for memmem(): the response body is binary, so the header
 * terminator must be located by length-bounded search, never by strstr(). */
#define _GNU_SOURCE

#include "http.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <strings.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>


void
http_response_free(http_response *resp)
{
    if (resp == NULL) {
        return;
    }

    free(resp->raw);
    free(resp->headers);

    resp->raw = NULL;
    resp->headers = NULL;
    resp->body = NULL;
    resp->raw_len = 0;
    resp->body_len = 0;
}


/*
 * send(MSG_NOSIGNAL) rather than write(): several rule files deliberately
 * provoke the server into closing mid-request (malformed framing, oversized
 * headers), and a plain write() to a closed peer raises SIGPIPE, whose default
 * action would kill the whole prober. A harness that dies on the case it was
 * written to exercise reports a crash as a missing test, so the failure has to
 * arrive as EPIPE on this one request instead.
 */
static int
write_all(int fd, const unsigned char *buf, size_t len)
{
    size_t off = 0;

    while (off < len) {
        ssize_t n = send(fd, buf + off, len - off, MSG_NOSIGNAL);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }

        if (n == 0) {
            return -1;
        }

        off += (size_t) n;
    }

    return 0;
}


static void
parse_response(http_response *resp)
{
    char   *sep;
    size_t  header_len;

    resp->status = -1;
    resp->body = NULL;
    resp->body_len = 0;
    resp->headers = NULL;

    if (resp->raw == NULL || resp->raw_len == 0) {
        return;
    }

    if (resp->raw_len > 12 && memcmp(resp->raw, "HTTP/", 5) == 0) {
        const char *sp = memchr(resp->raw, ' ', resp->raw_len);

        if (sp != NULL) {
            resp->status = (int) strtol(sp + 1, NULL, 10);
        }
    }

    /*
     * Split on the header terminator. A response with no CRLFCRLF is left with
     * headers == NULL and no body rather than being guessed at -- silently
     * treating a truncated response as "all headers" would make a connection
     * reset look like a successful empty reply.
     */
    sep = memmem(resp->raw, resp->raw_len, "\r\n\r\n", 4);
    if (sep == NULL) {
        return;
    }

    header_len = (size_t) (sep - resp->raw);

    resp->headers = malloc(header_len + 1);
    if (resp->headers != NULL) {
        memcpy(resp->headers, resp->raw, header_len);
        resp->headers[header_len] = '\0';
    }

    resp->body = sep + 4;
    resp->body_len = resp->raw_len - header_len - 4;
}


int
http_request(const char *host, int port,
             const unsigned char *req, size_t req_len,
             int timeout_ms, const char *source,
             http_response *resp,
             char *errbuf, size_t errlen)
{
    int                 fd, one = 1;
    char               *buf = NULL;
    size_t              cap = 8192, len = 0;
    struct sockaddr_in  sin;
    struct timeval      tv;

    memset(resp, 0, sizeof(*resp));
    resp->status = -1;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons((uint16_t) port);

    if (inet_pton(AF_INET, host, &sin.sin_addr) != 1) {
        snprintf(errbuf, errlen, "bad host address \"%s\"", host);
        return -1;
    }

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        snprintf(errbuf, errlen, "socket: %s", strerror(errno));
        return -1;
    }

    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    /* Nagle would coalesce the deliberately-split writes some rules depend on
     * to exercise request smuggling and partial-header handling. */
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    if (source != NULL) {
        struct sockaddr_in  local;

        memset(&local, 0, sizeof(local));
        local.sin_family = AF_INET;
        local.sin_port = 0;

        if (inet_pton(AF_INET, source, &local.sin_addr) != 1) {
            snprintf(errbuf, errlen, "bad source address \"%s\"", source);
            close(fd);
            return -1;
        }

        /* SO_REUSEADDR so a rule can reuse a source address while an earlier
         * connection from it is still in TIME_WAIT. */
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

        if (bind(fd, (struct sockaddr *) &local, sizeof(local)) != 0) {
            snprintf(errbuf, errlen, "bind %s: %s", source, strerror(errno));
            close(fd);
            return -1;
        }
    }

    if (connect(fd, (struct sockaddr *) &sin, sizeof(sin)) != 0) {
        snprintf(errbuf, errlen, "connect %s:%d: %s",
                 host, port, strerror(errno));
        close(fd);
        return -1;
    }

    if (write_all(fd, req, req_len) != 0) {
        snprintf(errbuf, errlen, "write: %s", strerror(errno));
        close(fd);
        return -1;
    }

    buf = malloc(cap);
    if (buf == NULL) {
        snprintf(errbuf, errlen, "out of memory");
        close(fd);
        return -1;
    }

    for ( ;; ) {
        ssize_t n;

        if (len + 4096 > cap) {
            char *bigger;

            cap *= 2;
            bigger = realloc(buf, cap);
            if (bigger == NULL) {
                snprintf(errbuf, errlen, "out of memory");
                free(buf);
                close(fd);
                return -1;
            }
            buf = bigger;
        }

        n = read(fd, buf + len, cap - len - 1);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }

            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                snprintf(errbuf, errlen,
                         "read timed out after %d ms (%zu bytes so far); "
                         "does the request ask for Connection: close?",
                         timeout_ms, len);
                free(buf);
                close(fd);
                return -1;
            }

            /* A reset after a complete response is a legitimate outcome for
             * malformed-input cases; keep what we have and let the rule judge. */
            break;
        }

        if (n == 0) {
            break;
        }

        len += (size_t) n;
    }

    close(fd);

    buf[len] = '\0';
    resp->raw = buf;
    resp->raw_len = len;

    parse_response(resp);

    return 0;
}


int
http_has_header(const http_response *resp, const char *needle)
{
    const char *line;
    size_t      nlen;

    if (resp->headers == NULL) {
        return 0;
    }

    nlen = strlen(needle);
    line = resp->headers;

    while (line != NULL && *line != '\0') {
        const char *eol = strstr(line, "\r\n");
        size_t      llen = (eol != NULL) ? (size_t) (eol - line) : strlen(line);

        if (llen >= nlen) {
            size_t i;

            for (i = 0; i + nlen <= llen; i++) {
                if (strncasecmp(line + i, needle, nlen) == 0) {
                    return 1;
                }
            }
        }

        line = (eol != NULL) ? eol + 2 : NULL;
    }

    return 0;
}
