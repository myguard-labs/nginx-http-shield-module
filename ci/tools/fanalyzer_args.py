#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Write a NUL-delimited directory and argv for one compile-database entry.

Called by ci/tools/fanalyzer.sh, which needs the exact flags gcc got for a
translation unit so the analyser parses the same preprocessor branches the
build compiled. Kept as a file rather than an inline heredoc because a heredoc
body cannot be indented inside a YAML block scalar without ending the scalar --
the workflow that first carried this logic failed to parse as YAML at all.

Env: DB    path to compile_commands.json
     SRC   the .c file to look up

Prints nothing and exits 0 when the file has no entry; the caller treats that
as a finding, since an unanalysed TU is a coverage gap and not a clean result.
"""

import json
import os
import shlex
import sys


def main() -> int:
    db_path = os.environ["DB"]
    src = os.path.realpath(os.environ["SRC"])

    with open(db_path, encoding="utf-8") as fh:
        db = json.load(fh)

    for entry in db:
        if os.path.realpath(os.path.join(entry["directory"], entry["file"])) != src:
            continue

        cmd = entry.get("arguments") or shlex.split(entry["command"])

        # Drop argv[0] (the compiler) and any recorded -o <path> / -c; the
        # caller supplies its own. -o takes an argument, -c does not.
        args, skip_next = [], False
        for arg in cmd[1:]:
            if skip_next:
                skip_next = False
                continue
            if arg == "-o":
                skip_next = True
                continue
            if arg == "-c":
                continue
            args.append(arg)

        values = [entry["directory"], *args]
        for value in values:
            sys.stdout.buffer.write(os.fsencode(value) + b"\0")
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
