#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
#
# ci/tools/gen-fuzz-dict.py -- derive ci/fuzz/fuzz.dict from the signature
# tables in src/ngx_http_shield_patterns.h.
#
#   ci/tools/gen-fuzz-dict.py            write ci/fuzz/fuzz.dict
#   ci/tools/gen-fuzz-dict.py --check    exit 1 if the file on disk differs
#   ci/tools/gen-fuzz-dict.py --stdout   print, write nothing
#
# WHY THIS EXISTS. The dictionary was hand-written: 31 tokens chosen by eye
# against a table that carries 650+ signatures. A libFuzzer dictionary lets the
# mutator synthesize a multi-byte literal it would otherwise need a blind
# byte-by-byte walk to discover. The hand-written set had no mechanism keeping
# it in step with the tables either: adding a signature to the header -- the
# routine change in this repo -- never touched the dict, and nothing went red.
#
# WHAT IT BUYS, MEASURED (2026-08-04, empty corpus, 60s each, one run per arm):
#
#   arm                     cov    ft    distinct signatures reached
#   old dict (31 tokens)    199   788    23 / 645
#   new dict (652 tokens)   199   782    35 / 645
#
# EDGE COVERAGE DOES NOT MOVE, and expecting it to was the wrong model: the
# scan engine is an Aho-Corasick trie walk, so the same edges execute whichever
# literal is fed in. `ft` differing by 6 across single runs is noise.
#
# What moves is SIGNATURE REACH -- 23 -> 35 distinct table literals actually
# driven through the scanner. That is the number that matters here because
# fuzz_scan is DIFFERENTIAL: it compares a naive per-signature memmem oracle
# against the shipped engine, so each additional signature exercised is an
# additional chance to catch a divergence between them. A coverage-guided
# fuzzer cannot find that on edge feedback alone -- the divergence lives in
# WHICH signature matched, not in which branch ran.
#
# So this is a reach improvement, not a coverage improvement. Do not "restore"
# the hand-written dict on the grounds that cov is unchanged.
#
# Deriving it from NGX_HTTP_SHIELD_SIG(...) makes the coupling mechanical. The
# --check mode is wired into ci/linter/lint-fuzz-dict.sh so a new signature
# without a regenerated dict fails the gate instead of silently narrowing the
# fuzzer's reach.
#
# WHY A STRAIGHT EXTRACTION IS THE RIGHT DERIVATION. The header's own rules
# (see its top comment) require every signature to be stored LOWERCASE and, for
# the decoded categories, in DECODED form -- because the engine lowercases and
# percent-decodes each buffer before scanning. The categories that match raw
# input (overlong, nullbyte, crlf) store their literals already encoded, for
# the same reason. So each literal is by construction the byte string the
# scanner actually compares against, and needs no re-encoding here. The one
# thing this script must not do is "helpfully" percent-encode the decoded
# entries: those bytes would then match neither buffer.
#
# The AND-rule term arrays (ngx_http_shield_rule_*) use the same SIG macro and
# are picked up by the same scan. That is intended -- a rule only fires when
# ALL its terms are present, which is precisely the case where the mutator
# needs both literals handed to it rather than discovered independently.
#
# Extend: if a token that is NOT a table signature ever earns a place (a
# structural byte the mutator needs, not a detection string), add it to
# EXTRA_TOKENS below with a comment saying why, so the next regeneration keeps
# it. Do not hand-edit ci/fuzz/fuzz.dict -- the linter will fail it.

import argparse
import os
import re
import subprocess
import sys

HEADER = "src/ngx_http_shield_patterns.h"
DICT = "ci/fuzz/fuzz.dict"

# Structural tokens that are not signatures. The scan pipeline decodes
# percent-escapes and folds '+' to ' ' before matching, so these three steer
# the mutator into the DECODER rather than into a signature -- the code path
# that the signature literals, being post-decode, can never exercise.
EXTRA_TOKENS = [
    "%",
    "+",
    "%25",  # encoded '%': the double-decode / re-entry case
]

# NGX_HTTP_SHIELD_SIG("...") -- capture the C string literal body, allowing
# escapes. The tables are one literal per macro call.
SIG_RE = re.compile(r'NGX_HTTP_SHIELD_SIG\(\s*"((?:[^"\\]|\\.)*)"\s*\)')

# C escapes that appear in the tables. Deliberately explicit rather than a
# codecs unicode_escape round-trip: that would also decode sequences C does not
# have, and would mangle any high byte written as \xNN by re-interpreting it as
# a code point.
C_ESCAPES = {
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "v": "\v",
    "f": "\f",
    "b": "\b",
    "a": "\a",
    "0": "\0",
    "\\": "\\",
    '"': '"',
    "'": "'",
    "?": "?",
}


def repo_root():
    return subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def unescape_c(lit):
    """Turn a C string-literal body into the bytes the compiler would emit."""
    out = []
    i = 0
    while i < len(lit):
        c = lit[i]
        if c != "\\":
            out.append(c)
            i += 1
            continue
        i += 1
        if i >= len(lit):
            raise ValueError(f"trailing backslash in literal: {lit!r}")
        e = lit[i]
        if e == "x":
            j = i + 1
            while j < len(lit) and lit[j] in "0123456789abcdefABCDEF":
                j += 1
            if j == i + 1:
                raise ValueError(f"\\x with no digits in literal: {lit!r}")
            out.append(chr(int(lit[i + 1 : j], 16)))
            i = j
            continue
        if e in C_ESCAPES:
            out.append(C_ESCAPES[e])
            i += 1
            continue
        raise ValueError(f"unhandled C escape \\{e} in literal: {lit!r}")
    return "".join(out)


def dict_quote(s):
    """Encode a signature as a libFuzzer dictionary entry body.

    libFuzzer's parser (FuzzerDictionary / ParseOneDictionaryEntry) accepts
    printable bytes, \\" and \\\\ escapes, and \\xNN. Anything outside
    printable ASCII goes out as \\xNN so the file stays diffable text.

    Encoding to UTF-8 first is what makes the non-ASCII signatures correct.
    ngx_http_shield_ssrf_meta carries "169。254。169。254" and the halfwidth
    "169｡254｡169｡254" -- IP separators some clients normalize to '.', which is
    the evasion those entries exist to catch. The header is a UTF-8 file, so
    the compiler stores each of those separators as THREE bytes, and the
    scanner compares bytes. Emitting one \\xNN per code point would put a
    string in the dictionary that matches nothing.
    """
    out = []
    for b in s.encode("utf-8"):
        ch = chr(b)
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif 0x20 <= b <= 0x7E:
            out.append(ch)
        else:
            out.append(f"\\x{b:02x}")
    return "".join(out)


def build(root):
    with open(os.path.join(root, HEADER), encoding="utf-8") as fh:
        src = fh.read()

    sigs = [unescape_c(m.group(1)) for m in SIG_RE.finditer(src)]
    if not sigs:
        # A rename of the macro must fail loudly. Emitting an empty dictionary
        # would leave the fuzzer running with no dictionary at all and every
        # gate green.
        raise SystemExit(
            f"gen-fuzz-dict: no NGX_HTTP_SHIELD_SIG(...) found in {HEADER} -- "
            "macro renamed? refusing to write an empty dictionary"
        )

    # Deduplicate, keep a stable order. The same literal legitimately appears
    # in more than one table ("../" in traversal and in an exploit path); a
    # dictionary entry repeated is harmless to libFuzzer but makes the file
    # churn under reordering, so sort and unique.
    tokens = sorted(set(sigs) | set(EXTRA_TOKENS))

    lines = [
        "# libFuzzer dictionary for fuzz_scan.",
        "#",
        "# GENERATED -- do not edit. Regenerate with:",
        "#     ci/tools/gen-fuzz-dict.py",
        "# Source of truth: src/ngx_http_shield_patterns.h (NGX_HTTP_SHIELD_SIG).",
        "# Drift is a hard failure in ci/linter/lint-fuzz-dict.sh.",
        "#",
        (
            f"# {len(sigs)} signature literals -> {len(tokens)} unique"
            f" entries (incl. {len(EXTRA_TOKENS)} decoder tokens)."
        ),
        "",
    ]
    lines += [f'"{dict_quote(t)}"' for t in tokens]
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser(description="derive ci/fuzz/fuzz.dict")
    g = ap.add_mutually_exclusive_group()
    g.add_argument(
        "--check",
        action="store_true",
        help="exit 1 if the file on disk is not what we generate",
    )
    g.add_argument(
        "--stdout", action="store_true", help="print the dictionary, write nothing"
    )
    args = ap.parse_args()

    root = repo_root()
    want = build(root)
    path = os.path.join(root, DICT)

    if args.stdout:
        sys.stdout.write(want)
        return 0

    if args.check:
        try:
            with open(path, encoding="utf-8") as fh:
                have = fh.read()
        except FileNotFoundError:
            print(f"gen-fuzz-dict: {DICT} is missing", file=sys.stderr)
            return 1
        if have != want:
            print(
                f"gen-fuzz-dict: {DICT} is out of date with {HEADER}.\n"
                "  Regenerate: ci/tools/gen-fuzz-dict.py",
                file=sys.stderr,
            )
            return 1
        return 0

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(want)
    print(f"gen-fuzz-dict: wrote {DICT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
