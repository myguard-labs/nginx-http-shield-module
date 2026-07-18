/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * json.h -- minimal JSON reader for the probe document.
 *
 * Deliberately a real tokenizer rather than substring matching on the response
 * body. A grep for "\"nodes\":1" would pass on a document where nodes lives in
 * a different object, and would silently keep passing if the probe's shape ever
 * changed -- exactly the failure mode a harness must not have, since a test
 * that cannot fail is worse than no test.
 *
 * Scope is the probe document and nothing more: no \u escapes, no exponent
 * notation, no duplicate-key policy. Inputs come from ngx_shield_probe_json(),
 * not from the network, so the parser is strict and small rather than lenient.
 */

#ifndef PROBER_JSON_H
#define PROBER_JSON_H

#include <stddef.h>

typedef enum {
    JSON_NULL,
    JSON_BOOL,
    JSON_NUMBER,
    JSON_STRING,
    JSON_OBJECT,
    JSON_ARRAY
} json_type;

typedef struct json_value json_value;

struct json_value {
    json_type    type;
    double       number;
    int          boolean;
    char        *string;    /* JSON_STRING only, NUL-terminated */
    char       **keys;      /* JSON_OBJECT only, parallel to items */
    json_value **items;     /* JSON_OBJECT / JSON_ARRAY members */
    size_t       count;
};

/*
 * Parse a complete document. Returns NULL on malformed input or trailing
 * garbage; on failure, and if err is non-NULL, *err points at a static
 * description. The result is owned by the caller: free with json_free().
 */
json_value *json_parse(const char *text, const char **err);

void json_free(json_value *v);

/*
 * Look up a dotted path, e.g. "zone.nodes". Returns NULL if any component is
 * missing or if a non-object is traversed. Array indexing is not supported --
 * the probe document has no arrays, and inventing the syntax before there is a
 * caller for it would be speculative.
 */
const json_value *json_get(const json_value *root, const char *path);

/* Human-readable type name, for assertion failure diagnostics. */
const char *json_type_name(json_type t);

#endif /* PROBER_JSON_H */
