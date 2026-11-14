#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Qualify full -t parsing and explicit ownership teardown using retained objects.

Usage: python3 ci/t/run-config-lifetime.py CONFIGURED_TREE --output FRESH_DIR
Add --valgrind for all leak kinds, without suppressions. Instrumented objects
retain their configured sanitizer flags. No configured build inputs are written.
"""

import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def variable(makefile, name):
    matches = re.findall(rf"^{name}\s*=\s*(.*)$", makefile, re.MULTILINE)
    if len(matches) != 1:
        raise ValueError(f"expected one {name} assignment")
    return shlex.split(matches[0])


def compiler_command(makefile):
    """Use an explicit CC override, otherwise the configured compiler."""
    compiler = (
        shlex.split(os.environ["CC"])
        if "CC" in os.environ
        else variable(makefile, "CC")
    )
    if not compiler:
        raise ValueError("empty compiler command")
    return compiler


def link_command(makefile, target):
    matches = re.findall(
        rf"^\t\$\(LINK\) -o {re.escape(target)} ([^\n]*)$",
        makefile,
        re.MULTILINE,
    )
    if len(matches) != 1:
        raise ValueError(f"expected one link command for {target}")
    return shlex.split(matches[0])


def run(command, output, label, cwd):
    (output / f"{label}.command").write_text(shlex.join(command) + "\n")
    with (output / f"{label}.log").open("wb") as log:
        result = subprocess.run(command, cwd=cwd, stdout=log, stderr=log, check=False)
    (output / f"{label}.exit").write_text(f"{result.returncode}\n")
    return result.returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tree", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--valgrind", action="store_true")
    args = parser.parse_args()
    tree = args.tree.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    # Expand only continuation lines. Commands and flags come from this exact
    # configured Makefile, never from a guessed daemon/link dependency list.
    makefile = (tree / "objs/Makefile").read_text().replace("\\\n", " ")
    flags = variable(makefile, "CFLAGS")
    includes = variable(makefile, "ALL_INCS")
    if any(
        token.startswith("-I") and not (tree / token[2:]).is_dir() for token in includes
    ):
        raise ValueError("configured include directory missing")
    compiler = compiler_command(makefile)
    driver = output / "config_lifetime.o"
    module = output / "ngx_http_shield_module.o"
    binary = output / "config_lifetime"
    commands = [
        (
            "compile-driver",
            [
                *compiler,
                *flags,
                *includes,
                "-c",
                str(ROOT / "ci/t/config_lifetime.c"),
                "-o",
                str(driver),
            ],
        ),
        (
            "compile-module",
            [
                *compiler,
                *flags,
                *includes,
                "-fPIC",
                "-c",
                str(ROOT / "src/ngx_http_shield_module.c"),
                "-o",
                str(module),
            ],
        ),
    ]
    server_targets = re.findall(
        r"^\t\$\(LINK\) -o (objs/(?:nginx|angie)) ", makefile, re.MULTILINE
    )
    if len(server_targets) != 1:
        raise ValueError("expected one nginx/Angie executable link command")
    original = link_command(makefile, server_targets[0])
    dynamic = "objs/addon/src/ngx_http_shield_module.o" not in original
    inputs = {"Makefile": digest(tree / "objs/Makefile")}

    def replace_objects(tokens):
        replaced = []
        for token in tokens:
            if token == "objs/src/core/nginx.o":
                replaced.append(str(driver))
            elif token in (
                "objs/src/core/ngx_crc32.o",
                "objs/src/os/unix/ngx_setproctitle.o",
            ):
                continue  # exact upstream sources are included by the driver
            elif token == "objs/addon/src/ngx_http_shield_module.o":
                replaced.append(str(module))
            else:
                if token.endswith(".o"):
                    inputs[token] = digest(tree / token)
                replaced.append(token)
        return replaced

    commands.append(
        ("link-driver", [*compiler, "-o", str(binary), *replace_objects(original)])
    )
    if dynamic:
        so = output / "ngx_http_shield_module.so"
        commands.append(
            (
                "link-module",
                [
                    *compiler,
                    "-o",
                    str(so),
                    *replace_objects(
                        link_command(makefile, "objs/ngx_http_shield_module.so")
                    ),
                ],
            )
        )
        load = f'load_module "{so}";\n'
    else:
        load = ""
    for directory in (tree / "src", tree / "objs"):
        for path in sorted(directory.rglob("*.h")):
            inputs[str(path.relative_to(tree))] = digest(path)
    for name in (
        "src/core/nginx.c",
        "src/core/ngx_crc32.c",
        "src/os/unix/ngx_setproctitle.c",
        "objs/ngx_modules.c",
    ):
        inputs[name] = digest(tree / name)
    candidate = {
        str(path.relative_to(ROOT)): digest(path)
        for path in [
            ROOT / "ci/t/config_lifetime.c",
            Path(__file__).resolve(),
            *sorted((ROOT / "src").rglob("*")),
        ]
        if path.is_file()
    }
    (output / "inputs.json").write_text(json.dumps(inputs, indent=2) + "\n")
    (output / "candidate.json").write_text(json.dumps(candidate, indent=2) + "\n")
    for label, command in commands:
        if run(command, output, label, tree) != 0:
            raise RuntimeError(f"{label} failed; see {output}")
    binaries = {
        path.name: {
            "sha256": digest(path),
            "size": path.stat().st_size,
            "mtime_ns": path.stat().st_mtime_ns,
        }
        for path in (binary, module, *output.glob("*.so"))
    }
    (output / "binaries.json").write_text(json.dumps(binaries, indent=2) + "\n")
    # Configurations include successful complete init, partial-parse rejection,
    # normalized networks, hierarchical merge and explicit off. Shared-memory
    # and log descriptors are real resources; no worker is launched.
    cases = {
        "valid": ("shield_allow 192.0.2.1 2001:db8::/32;", "", 0),
        "normalized": ("shield_allow 192.0.2.129/24 ::ffff:192.0.2.129/120;", "", 0),
        "inherited": (
            "shield_allow 192.0.2.0/24;",
            "location /child { empty_gif; }",
            0,
        ),
        "off": (
            "shield_allow 192.0.2.0/24;",
            "location /child { shield_allow off; empty_gif; }",
            0,
        ),
        "invalid-partial": ("shield_allow 192.0.2.1 invalid-address;", "", 1),
        "invalid-empty-all": ("shield_allow 192.0.2.1 .../0;", "", 1),
        "invalid-empty-middle": ("shield_allow 192.0.2.1 192..2.0/24;", "", 1),
        "invalid-empty-final": ("shield_allow 192.0.2.1 192.0.2./24;", "", 1),
        "invalid-empty-mapped": ("shield_allow 192.0.2.1 ::ffff:192.0.2./120;", "", 1),
        "invalid-mixed-off": ("shield_allow 192.0.2.1 off;", "", 1),
        "invalid-log": ("shield_allow 192.0.2.1;", "", 1),
    }
    rows = []
    for label, (directive, child, expected) in cases.items():
        prefix = output / label
        (prefix / "logs").mkdir(parents=True)
        config = prefix / "nginx.conf"
        late_error = (
            "error_log logs/missing/error.log notice;\n"
            if label == "invalid-log"
            else ""
        )
        config.write_text(
            load
            + "pid logs/nginx.pid; error_log logs/error.log notice;\n"
            + late_error
            + "events { worker_connections 32; }\nhttp { access_log off;\n"
            "shield_stats_zone stats 32k;\n"
            "server { listen 127.0.0.1:29347; shield block;\n"
            f"{directive}\nlocation / {{ empty_gif; }}\n{child}\n}}\n}}\n"
        )
        command = [
            str(binary),
            "-t",
            "-e",
            "stderr",
            "-p",
            str(prefix) + "/",
            "-c",
            str(config),
        ]
        if args.valgrind:
            command = [
                "valgrind",
                "--tool=memcheck",
                "--leak-check=full",
                "--show-leak-kinds=all",
                "--errors-for-leak-kinds=all",
                "--error-exitcode=97",
                "--track-fds=yes",
                *command,
            ]
        status = run(command, output, label, tree)
        log = (output / f"{label}.log").read_text(errors="replace")
        marker = f"lifecycle: descriptors restored; parser_exit={expected}"
        passed = status == expected and marker in log
        if args.valgrind:
            passed = passed and "ERROR SUMMARY: 0 errors" in log
            passed = passed and "in use at exit: 0 bytes in 0 blocks" in log
        if label == "normalized":
            passed = passed and "low address bits" in log
        if label == "invalid-partial":
            passed = passed and 'invalid shield_allow address "invalid-address"' in log
        if label.startswith("invalid-empty-"):
            passed = passed and "invalid shield_allow address" in log
        if label == "invalid-mixed-off":
            passed = passed and "shield_allow off must be used alone" in log
        if label == "invalid-log":
            passed = passed and "syntax is ok" in log and "missing/error.log" in log
        rows.append(
            {
                "case": label,
                "expected": expected,
                "status": status,
                "passed": passed,
                "config_sha256": digest(config),
            }
        )
    (output / "results.json").write_text(json.dumps(rows, indent=2) + "\n")
    print(json.dumps(rows))
    return 0 if all(row["passed"] for row in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
