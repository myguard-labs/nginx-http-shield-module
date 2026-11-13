#!/usr/bin/env python3
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "ci/tools/sync-source-inventory.py"


class SourceInventoryTest(unittest.TestCase):
    def test_updates_versions_digests_refs_and_peeled_commits(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            versions = tmp / "versions.env"
            inventory = tmp / "inventory.json"
            bindir = tmp / "bin"
            bindir.mkdir()
            versions.write_text(
                "NGINX_VERSION=1.31.9\nNGINX_VERSION_SHA256="
                + "a" * 64
                + "\nNGINX_STABLE=1.30.7\nNGINX_STABLE_SHA256="
                + "b" * 64
                + "\nANGIE_VERSION=1.12.5\nANGIE_VERSION_SHA256="
                + "c" * 64
                + "\n",
                encoding="utf-8",
            )
            dependencies = [
                {"id": name, "upstream": upstream, "osv_query": {"commit": "0" * 40}}
                for name, upstream in (
                    ("nginx-mainline", "https://github.com/nginx/nginx"),
                    ("nginx-stable", "https://github.com/nginx/nginx"),
                    ("angie", "https://github.com/webserver-llc/angie"),
                )
            ]
            pin_checks = []
            for key in (
                "NGINX_VERSION",
                "NGINX_VERSION_SHA256",
                "NGINX_STABLE",
                "NGINX_STABLE_SHA256",
                "ANGIE_VERSION",
                "ANGIE_VERSION_SHA256",
            ):
                pin_checks.append(
                    {
                        "path": ".github/versions.env",
                        "pattern": rf"(?m)^{key}=([^\n]+)$",
                        "expected": "stale",
                    }
                )
            inventory.write_text(
                json.dumps({"dependencies": dependencies, "pin_checks": pin_checks}),
                encoding="utf-8",
            )
            fake_git = bindir / "git"
            fake_git.write_text(
                "#!/bin/sh\nref=$3\nprintf '%s\\t%s\\n' '1'$(printf '1%.0s' $(seq 1 39)) \"$ref\"\n"
                "printf '%s\\t%s^{}\\n' '2'$(printf '2%.0s' $(seq 1 39)) \"$ref\"\n",
                encoding="utf-8",
            )
            fake_git.chmod(0o755)
            env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}")
            subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--versions",
                    str(versions),
                    "--inventory",
                    str(inventory),
                ],
                check=True,
                env=env,
            )
            result = json.loads(inventory.read_text(encoding="utf-8"))
            updated = result["dependencies"]
            self.assertEqual(
                [row["version"] for row in updated], ["1.31.9", "1.30.7", "1.12.5"]
            )
            self.assertTrue(all(row["resolved_commit"] == "2" * 40 for row in updated))
            self.assertTrue(
                all(row["osv_query"]["commit"] == "2" * 40 for row in updated)
            )
            self.assertEqual(
                [row["expected"] for row in result["pin_checks"]],
                ["1.31.9", "a" * 64, "1.30.7", "b" * 64, "1.12.5", "c" * 64],
            )

    def test_missing_inventory_owner_fails_without_rewrite(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            versions = tmp / "versions.env"
            inventory = tmp / "inventory.json"
            versions.write_text(
                "NGINX_VERSION=1\nNGINX_VERSION_SHA256=" + "a" * 64 + "\n",
                encoding="utf-8",
            )
            original = '{"dependencies": [], "pin_checks": []}\n'
            inventory.write_text(original, encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--versions",
                    str(versions),
                    "--inventory",
                    str(inventory),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(inventory.read_text(encoding="utf-8"), original)

    def test_missing_pin_check_owner_fails_without_rewrite(self):
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            versions = tmp / "versions.env"
            inventory = tmp / "inventory.json"
            bindir = tmp / "bin"
            bindir.mkdir()
            versions.write_text(
                "NGINX_VERSION=1.31.9\nNGINX_VERSION_SHA256="
                + "a" * 64
                + "\nNGINX_STABLE=1.30.7\nNGINX_STABLE_SHA256="
                + "b" * 64
                + "\nANGIE_VERSION=1.12.5\nANGIE_VERSION_SHA256="
                + "c" * 64
                + "\n",
                encoding="utf-8",
            )
            dependencies = [
                {"id": name, "upstream": upstream, "osv_query": {"commit": "0" * 40}}
                for name, upstream in (
                    ("nginx-mainline", "https://github.com/nginx/nginx"),
                    ("nginx-stable", "https://github.com/nginx/nginx"),
                    ("angie", "https://github.com/webserver-llc/angie"),
                )
            ]
            original = json.dumps({"dependencies": dependencies, "pin_checks": []})
            inventory.write_text(original, encoding="utf-8")
            fake_git = bindir / "git"
            fake_git.write_text(
                "#!/bin/sh\nref=$3\nprintf '%s\\t%s\\n' '1'$(printf '1%.0s' $(seq 1 39)) \"$ref\"\n",
                encoding="utf-8",
            )
            fake_git.chmod(0o755)
            env = dict(os.environ, PATH=f"{bindir}:{os.environ['PATH']}")
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--versions",
                    str(versions),
                    "--inventory",
                    str(inventory),
                ],
                capture_output=True,
                text=True,
                check=False,
                env=env,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(inventory.read_text(encoding="utf-8"), original)


if __name__ == "__main__":
    unittest.main()
