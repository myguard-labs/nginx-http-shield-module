#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Check signal exits and binary cleanup with an isolated fake compiler."""

from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

COMPILER = """#!/usr/bin/env python3
import os
import pathlib
import signal
import sys
out = pathlib.Path(sys.argv[sys.argv.index('-o') + 1])
out.write_text('#!/bin/sh\\nexit 0\\n')
out.chmod(0o700)
if out.name == 'status_unit':
    # This compiler's direct parent is the runner spawned by this test.
    os.kill(os.getppid(), getattr(signal, os.environ['STATUS_TEST_SIGNAL']))
"""


def main() -> None:
    """Send each trapped signal during compilation, using only owned processes."""
    runner = (
        pathlib.Path(sys.argv[1])
        if len(sys.argv) == 2
        else pathlib.Path(__file__).resolve().parents[1] / "t/run-ban-unit.sh"
    )
    with tempfile.TemporaryDirectory(prefix="shield-status-signal-") as temp:
        root = pathlib.Path(temp)
        scripts = root / "ci/t"
        scripts.mkdir(parents=True)
        (root / ".build/nginx-1.0-debug/objs").mkdir(parents=True)
        target = scripts / "run-ban-unit.sh"
        shutil.copyfile(runner, target)
        compiler = root / "compiler"
        compiler.write_text(COMPILER)
        compiler.chmod(0o700)
        bystander = subprocess.Popen(["sleep", "30"])
        try:
            for name, expected in (("SIGHUP", 129), ("SIGINT", 130), ("SIGTERM", 143)):
                env = dict(os.environ, CC=str(compiler), STATUS_TEST_SIGNAL=name)
                env.pop("NGINX_VERSION", None)
                env.pop("NGX_BUILD_MODE", None)
                result = subprocess.run(
                    ["bash", str(target)],
                    env=env,
                    capture_output=True,
                    timeout=10,
                    check=False,
                )
                if result.returncode != expected:
                    raise RuntimeError(
                        f"{name}: exit {result.returncode}, expected {expected}; "
                        f"stderr={result.stderr.decode(errors='replace')}"
                    )
                if (scripts / "status_unit").exists():
                    raise RuntimeError(f"{name}: status binary was not removed")
                if bystander.poll() is not None:
                    raise RuntimeError(f"{name}: unrelated child was signalled")
        finally:
            bystander.terminate()
            bystander.wait(timeout=10)
    print("status runner: HUP/INT/TERM exit status and cleanup passed")


if __name__ == "__main__":
    main()
