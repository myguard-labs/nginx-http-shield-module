"""Exercise lossless compile-database argv extraction for fanalyzer."""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


class FanalyzerArgsTest(unittest.TestCase):
    def run_helper(self, database: list[dict[str, object]], source: Path) -> bytes:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "compile_commands.json"
            db.write_text(json.dumps(database), encoding="utf-8")
            env = {**os.environ, "DB": str(db), "SRC": str(source)}
            return subprocess.check_output(
                ["python3", "ci/tools/fanalyzer_args.py"], env=env
            )

    def test_arguments_round_trip_spaces_and_quotes(self) -> None:
        source = Path.cwd() / "src/ngx_http_shield_scan.c"
        directory = str(Path.cwd())
        arguments = [
            "cc",
            "-DNAME=hello world",
            "-I/tmp/path with space",
            "-c",
            str(source),
            "-o",
            "scan object.o",
        ]
        output = self.run_helper(
            [{"directory": directory, "file": str(source), "arguments": arguments}],
            source,
        )
        self.assertEqual(
            output.split(b"\0")[:-1],
            [
                os.fsencode(directory),
                b"-DNAME=hello world",
                b"-I/tmp/path with space",
                os.fsencode(source),
            ],
        )

    def test_missing_entry_is_empty(self) -> None:
        source = Path.cwd() / "src/ngx_http_shield_scan.c"
        self.assertEqual(self.run_helper([], source), b"")


if __name__ == "__main__":
    unittest.main()
