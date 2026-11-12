#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Require private headers to invalidate nginx's compiled module objects."""

from __future__ import annotations

import hashlib
import pathlib
import shlex
import sys


def archive_has_pic(lines: list[str], archive: str) -> bool:
    """Check CFLAGS in the linked archive's own generated rule recipes."""
    recipes = []
    for rule_index, rule in enumerate(lines):
        if rule.startswith("\t") or ":" not in rule:
            continue
        targets = shlex.split(rule.split(":", 1)[0])
        if archive not in targets:
            continue
        for recipe_line in lines[rule_index + 1 :]:
            if not recipe_line.startswith("\t"):
                break
            recipes.append(recipe_line)
    flags = [
        token.split("=", 1)[1]
        for recipe_line in recipes
        for token in shlex.split(recipe_line)
        if token.startswith("CFLAGS=")
    ]
    return any("-fPIC" in shlex.split(value) for value in flags)


def main() -> None:
    """Check the generated build dependency contract, including new headers."""
    makefile = pathlib.Path(sys.argv[1])
    source = pathlib.Path(__file__).resolve().parents[2] / "src"
    stamp = makefile.parent / ".conf-stamp"
    if stamp.is_file():
        digest = hashlib.sha256((source.parent / "config").read_bytes()).hexdigest()
        if f"module_config_sha={digest} " not in stamp.read_text(encoding="utf-8"):
            raise RuntimeError("configure stamp does not bind current module config")
    text = makefile.read_text(encoding="utf-8").replace("\\\n", " ")
    declarations = [
        line for line in text.splitlines() if line.startswith("ADDON_DEPS =")
    ]
    if len(declarations) != 1:
        raise RuntimeError("expected one generated ADDON_DEPS declaration")
    dependencies = set(shlex.split(declarations[0].split("=", 1)[1]))
    missing = [
        str(header)
        for header in sorted(source.glob("*.h"))
        if str(header) not in dependencies
    ]
    if missing:
        raise RuntimeError(
            "module headers missing from ADDON_DEPS: " + ", ".join(missing)
        )
    # A dynamic module cannot borrow zlib references from whichever core loads
    # it. Check the generated linker recipe, not only the addon config text.
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if not line.startswith("objs/ngx_http_shield_module.so:"):
            continue
        recipe = next(line for line in lines[index + 1 :] if line.strip())
        link = shlex.split(recipe)
        archives = [token for token in link if token.endswith("/libz.a")]
        if "-lz" not in link and not archives:
            raise RuntimeError("dynamic module lacks its own zlib link dependency")
        for archive in archives:
            if archive not in shlex.split(line.split(":", 1)[1]):
                raise RuntimeError("bundled zlib missing from module dependencies")
            if not archive_has_pic(lines, archive):
                raise RuntimeError("bundled dynamic zlib must be built as PIC")
    print("module dependencies: every private header invalidates compiled objects")


if __name__ == "__main__":
    main()
