#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Require private headers to invalidate nginx's compiled module objects."""

from __future__ import annotations

import pathlib
import shlex
import sys


def main() -> None:
    """Check the generated build dependency contract, including new headers."""
    makefile = pathlib.Path(sys.argv[1])
    source = pathlib.Path(__file__).resolve().parents[2] / "src"
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
    print("module dependencies: every private header invalidates compiled objects")


if __name__ == "__main__":
    main()
