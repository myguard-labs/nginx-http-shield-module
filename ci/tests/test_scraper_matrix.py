"""Focused runner contracts, including the polling and parser failure oracles."""

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess, TimeoutExpired
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
SPEC = importlib.util.spec_from_file_location(
    "scraper_matrix", TOOLS / "scraper_matrix.py"
)
assert SPEC and SPEC.loader
MATRIX = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MATRIX)


class MatrixTests(unittest.TestCase):
    def test_pins_and_scrape_contract(self):
        images = json.loads((TOOLS / "scraper-images.json").read_text())
        self.assertEqual(
            set(images), {"prometheus", "vmagent", "alloy", "otel", "telegraf"}
        )
        for image in images.values():
            self.assertRegex(image, r":[^@]+@sha256:[0-9a-f]{64}$")
        configs = MATRIX.scrape_configs(12345, "sentinel")
        self.assertEqual(
            [item["metrics_path"] for item in configs], ["/metrics", "/invalid-metrics"]
        )
        self.assertEqual(
            [item["job_name"] for item in configs], ["sentinel_good", "sentinel_bad"]
        )
        self.assertEqual(
            configs[0]["static_configs"][0]["targets"], ["127.0.0.1:12345"]
        )

    def test_value_oracle_empty_wrong_and_exact(self):
        with patch.object(MATRIX, "query", return_value=[]):
            self.assertFalse(MATRIX.has_value(1, "metric", 3))
        with patch.object(MATRIX, "query", return_value=[{"value": [0, "2"]}]):
            self.assertFalse(MATRIX.has_value(1, "metric", 3))
        with patch.object(MATRIX, "query", return_value=[{"value": [0, "3"]}]):
            self.assertTrue(MATRIX.has_value(1, "metric", 3))

    def test_poll_transient_success_and_deadline(self):
        with (
            patch.object(MATRIX.time, "sleep"),
            patch.object(MATRIX.time, "monotonic", side_effect=[0, 1, 2]),
        ):
            calls = iter([OSError("not ready"), False, True])

            def ready():
                result = next(calls)
                if isinstance(result, OSError):
                    raise result
                return result

            MATRIX.eventually(ready, "retry")
        with (
            patch.object(MATRIX.time, "monotonic", side_effect=[0, 30]),
            self.assertRaisesRegex(AssertionError, "Timed out: bad fixture"),
        ):
            MATRIX.eventually(lambda: False, "bad fixture")

    def test_query_errors_and_escaping(self):
        with (
            patch.object(MATRIX, "get", return_value=b'{"status":"error"}'),
            self.assertRaises(AssertionError),
        ):
            MATRIX.query(1, "up")
        with patch.object(
            MATRIX, "get", return_value=b'{"status":"success","data":{"result":[]}}'
        ) as get:
            self.assertEqual(MATRIX.query(1, 'up{job="good"}'), [])
            self.assertIn("%7Bjob%3D%22good%22%7D", get.call_args.args[1])

    def test_owned_container_timeout_and_cleanup(self):

        with tempfile.TemporaryDirectory() as directory:
            docker = MATRIX.Docker(Path(directory), {"test": "pinned-image"})
            with (
                patch.object(
                    MATRIX.subprocess, "run", side_effect=TimeoutExpired("docker", 60)
                ),
                self.assertRaises(TimeoutExpired),
            ):
                docker.run("test", [], "timeout")
            self.assertEqual(docker.ids, [("timeout", docker.owner + "-timeout")])
            with (
                patch.object(
                    MATRIX.subprocess,
                    "run",
                    side_effect=[
                        CompletedProcess([], 0, "owned-id\n", ""),
                        CompletedProcess([], 0, "", ""),
                    ],
                ) as run,
                patch.object(MATRIX.subprocess, "check_output", return_value=""),
            ):
                docker.close()
                self.assertEqual(
                    run.call_args_list[0].args[0][-1],
                    "label=myguard.run=" + docker.owner,
                )
                self.assertEqual(
                    run.call_args_list[1].args[0], ["docker", "rm", "-f", "owned-id"]
                )
            self.assertEqual(
                json.loads((Path(directory) / "containers.json").read_text())["ids"],
                ["owned-id"],
            )

    def test_telegraf_oracle_rejects_false_green(self):
        class Docker:
            def __init__(self, bad):
                self.bad = bad

            def run(self, _key, _args, name):

                config = (root / (name + ".conf")).read_text()
                expected = "/invalid-json" if name.endswith("bad") else "/json"
                MATRIX.require(f'http://127.0.0.1:1{expected}"' in config, config)
                if name.endswith("good") or not self.bad:
                    return CompletedProcess(
                        [], 0, "> http,host=test inspected=3 1\n", ""
                    )
                return CompletedProcess(
                    [], 1, "", "Error: parsing metrics failed: malformed payload"
                )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            MATRIX.run_collector("telegraf-json", Docker(True), root, 1, 2)
            with self.assertRaisesRegex(
                AssertionError, "malformed Telegraf payload accepted"
            ):
                MATRIX.run_collector("telegraf-json", Docker(False), root, 1, 2)


if __name__ == "__main__":
    unittest.main()
