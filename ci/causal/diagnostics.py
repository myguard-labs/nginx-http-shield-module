# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Offline public-rule identities and overlap; no application-sink verdicts."""

import struct


def nginx_unescape(data):
    """Match ngx_unescape_uri(..., type=0), including malformed escapes."""
    decoded = bytearray()
    state = "usual"
    first = 0
    for byte in data:
        if state == "usual":
            if byte == ord("%"):
                state = "first"
            else:
                decoded.append(byte)
        elif state == "first":
            if ord("0") <= byte <= ord("9"):
                first = byte - ord("0")
                state = "second"
            elif ord("a") <= (byte | 0x20) <= ord("f"):
                first = (byte | 0x20) - ord("a") + 10
                state = "second"
            else:
                decoded.append(byte)
                state = "usual"
        else:
            if ord("0") <= byte <= ord("9"):
                decoded.append((first << 4) + byte - ord("0"))
            elif ord("a") <= (byte | 0x20) <= ord("f"):
                decoded.append((first << 4) + (byte | 0x20) - ord("a") + 10)
            state = "usual"
    return bytes(decoded)


def identity(kind, name, terms, flags):
    """Independent, endian-explicit implementation of the public format v1."""
    value = 14695981039346656037
    for part in [kind.encode(), name.encode(), bytes([flags, 1]), *terms]:
        for byte in struct.pack("<Q", len(part)) + part:
            value = ((value ^ byte) * 1099511628211) & ((1 << 64) - 1)
    return f"{value:016x}"


def inventory(text):
    entries = []
    seen = set()
    for line in text.splitlines():
        kind, row, item, name, category, encoded, flags, rule = line.split("\t")
        terms = [bytes.fromhex(term) for term in encoded.split(",")]
        expected = identity(
            "sig" if kind == "signature" else "and", name, terms, int(flags)
        )
        if kind not in {"signature", "and-rule"} or rule != expected:
            raise ValueError("diagnostic public-rule identity drift")
        if rule in seen:
            raise ValueError("diagnostic duplicate/colliding public-rule identity")
        seen.add(rule)
        entries.append(
            {
                "kind": kind,
                "row": int(row),
                "item": int(item),
                "name": name,
                "category": category,
                "terms": terms,
                "flags": int(flags),
                "rule": rule,
            }
        )
    if not entries:
        raise ValueError("empty diagnostic inventory")
    return entries


def overlap(entries, data, form=False):
    """All matching public definitions for a bounded sanitized local fixture.

    This offline oracle deliberately keeps overlaps; the production scanner
    still returns its first winning category/endpoint, then definition order.
    """
    if len(data) > 4096:
        raise ValueError("diagnostic fixture exceeds 4096 bytes")
    raw = data.lower()
    decoded = nginx_unescape(raw.replace(b"+", b" ") if form else raw).lower()
    found = []
    for view, flag, value in (("raw", 2, raw), ("decoded", 1, decoded)):
        for entry in entries:
            if not entry["flags"] & flag:
                continue
            ends = [value.find(term) + len(term) for term in entry["terms"]]
            if all(term in value for term in entry["terms"]):
                found.append(dict(entry, view=view, end=max(ends)))
    return found


def check(binary, run):
    entries = inventory(run([str(binary), "--list", "--diagnostics"]).decode())
    samples = [
        b"<java.lang.processbuilder",  # shared endpoint, different categories
        b"union select union/**/select",  # same category, distinct predicates
        b"%c0%af union select",  # raw precedence
        b"union%20select",  # decoded spelling, same stable identity
        b"jdbc:h2: x init=",  # AND predicate
        b"ordinary local fixture",
        b"",
        b"union selec",
        b"%GG",
        b"union%2G select",  # malformed escape removed by nginx's decoder
    ]
    wire = "".join(f"0:{data.hex()}\n" for data in samples).encode()
    actual = (
        run([str(binary), "--full", "--diagnostics"], input=wire).decode().splitlines()
    )
    if len(actual) != len(samples):
        raise ValueError("incomplete diagnostic scanner results")
    results = []
    for data, line in zip(samples, actual, strict=True):
        matches = overlap(entries, data)
        if not matches:
            expected = "clean"
        else:
            # Production precedence: raw before decoded; any standalone beats
            # AND within a view; first accepting endpoint, then table order.
            view = "raw" if any(row["view"] == "raw" for row in matches) else "decoded"
            in_view = [row for row in matches if row["view"] == view]
            standalone = [row for row in in_view if row["kind"] == "signature"]
            selected = (
                min(standalone, key=lambda row: (row["end"], row["row"], row["item"]))
                if standalone
                else min(in_view, key=lambda row: row["row"])
            )
            expected = "\t".join([selected["category"], selected["rule"], view])
        if line != expected:
            raise ValueError(
                f"diagnostic overlap attribution: expected {expected!r}, got {line!r}"
            )
        results.append(
            {
                "fixture_hex": data.hex(),
                "selected": line,
                "matches": [row["rule"] for row in matches],
            }
        )
    if len(results[0]["matches"]) < 2 or len(results[1]["matches"]) < 2:
        raise ValueError("diagnostic overlap fixtures are vacuous")
    return {"public_identities": len(entries), "fixtures": results}
