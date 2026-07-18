/*
 * Copyright (C) 2026 Thijs Eilander
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * json_test.c -- TAP self-test for the prober's JSON reader.
 *
 * The reader is the harness ORACLE: every `probe` and `delta` assertion is
 * evaluated against the document it produces. A parser that quietly accepts a
 * malformed document, or that reads a number wrong, turns every rule that
 * depends on it into a test that cannot fail -- which is worse than having no
 * rule at all, because the run still reports green.
 *
 * So the accept cases pin the shapes the probe renderer actually emits, and the
 * reject cases pin the shapes that would mean the renderer is broken (raw
 * control bytes in a string, leading-zero or leading-plus numbers, truncated
 * documents). Run by t/prober/run.sh before any server is booted.
 */

#define _GNU_SOURCE

#include "json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int  tests_run = 0;
static int  failures = 0;


static void
ok(int cond, const char *name)
{
    tests_run++;

    printf("%sok %d - %s\n", cond ? "" : "not ", tests_run, name);

    if (!cond) {
        failures++;
    }
}


static void
accepts(const char *text, const char *name)
{
    const char *err = NULL;
    json_value *v = json_parse(text, &err);

    if (v == NULL) {
        printf("# %s: rejected with \"%s\"\n", name, err ? err : "?");
    }

    ok(v != NULL, name);
    json_free(v);
}


static void
rejects(const char *text, const char *name)
{
    const char *err = NULL;
    json_value *v = json_parse(text, &err);

    if (v != NULL) {
        printf("# %s: accepted, but must not be\n", name);
    }

    ok(v == NULL, name);
    json_free(v);
}


static void
number_is(const char *text, const char *path, double want, const char *name)
{
    const char       *err = NULL;
    const json_value *field;
    json_value       *doc = json_parse(text, &err);
    int               good;

    if (doc == NULL) {
        printf("# %s: parse failed: %s\n", name, err ? err : "?");
        ok(0, name);
        return;
    }

    field = json_get(doc, path);
    good = (field != NULL && field->type == JSON_NUMBER && field->number == want);

    if (!good) {
        printf("# %s: %s is %s\n", name, path,
               field == NULL ? "absent" : json_type_name(field->type));
    }

    ok(good, name);
    json_free(doc);
}


int
main(void)
{
    /* The document the probe renderer actually emits, in the shape the rule
     * files assert against. If this ever stops parsing, every rule breaks at
     * once, so it is the first thing checked. */
    static const char probe_doc[] =
        "{\"flavor\":\"nginx\",\"flavor_version\":\"1.31.3\",\"pid\":1234,"
        "\"page_size\":4096,\"connections\":{\"total\":512,\"free\":511},"
        "\"zone\":{\"present\":true,\"name\":\"shield\",\"size\":1048576,"
        "\"slab_pages_free\":248,\"nodes\":2,\"banned\":1,"
        "\"fault\":{\"slab_nth\":-1,\"slab_seen\":0}}}";

    printf("1..24\n");

    accepts(probe_doc, "the probe document parses");
    number_is(probe_doc, "zone.nodes", 2, "a nested number reads back");
    number_is(probe_doc, "zone.fault.slab_nth", -1,
              "a negative number keeps its sign");
    number_is(probe_doc, "connections.free", 511, "a two-level path resolves");

    {
        json_value *doc = json_parse(probe_doc, NULL);

        ok(doc != NULL && json_get(doc, "zone.absent") == NULL,
           "an absent path is NULL, not a zero");
        json_free(doc);
    }

    /* Numbers: the JSON grammar, not what strtod() happens to swallow. */
    accepts("{\"n\":0}", "zero");
    accepts("{\"n\":-0}", "negative zero");
    accepts("{\"n\":1234567890}", "a plain integer");
    accepts("{\"n\":1.5}", "a fraction");
    accepts("{\"n\":1e3}", "an exponent");
    rejects("{\"n\":+1}", "a leading plus is not JSON");
    rejects("{\"n\":.5}", "a bare fraction is not JSON");
    rejects("{\"n\":01}", "a leading zero is not JSON");
    rejects("{\"n\":1.}", "a trailing decimal point is not JSON");
    rejects("{\"n\":1e}", "an empty exponent is not JSON");
    rejects("{\"n\":0x10}", "hex is not JSON");
    rejects("{\"n\":"
            "111111111111111111111111111111111111111111111111111111111111"
            "111111111111111111111111}",
            "an over-long number is an error, not a truncation");

    /* Strings. */
    accepts("{\"s\":\"a\\nb\"}", "an escaped newline");
    rejects("{\"s\":\"a\nb\"}", "a raw newline in a string");
    rejects("{\"s\":\"a\tb\"}", "a raw tab in a string");
    rejects("{\"s\":\"unterminated}", "an unterminated string");

    /* Document framing. */
    rejects("{\"a\":1", "a truncated object");
    rejects("{\"a\":1}}", "trailing garbage after the document");
    rejects("", "an empty document");

    if (failures > 0) {
        printf("# %d of %d self-tests failed\n", failures, tests_run);
    }

    return failures > 0 ? 1 : 0;
}
