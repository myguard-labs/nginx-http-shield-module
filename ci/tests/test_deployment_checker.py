#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Focused parser, effective-policy and secret-safe deployment-checker oracles."""

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "deployment_checker", ROOT / "contrib/deployment-checker/check_deployment.py"
)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)
FIXTURES = ROOT / "ci/tests/fixtures/deployment-checker"
FAULTY_EXPECTED = False


class DeploymentCheckerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        shutil.copytree(FIXTURES, self.root, dirs_exist_ok=True)
        self.contract = json.loads((self.root / "site.json").read_text())

    def run_config(self, text=None, contract=None, name="input.conf"):
        if text is not None:
            (self.root / name).write_text(text)
        (self.root / "site.json").write_text(json.dumps(contract or self.contract))
        return CHECKER.inspect(self.root, name, "site.json")

    def codes(self, result, level=None):
        return {
            d["code"]
            for d in result["diagnostics"]
            if level is None or d["level"] == level
        }

    def simple(self, body="", outer="", locations=""):
        return f"http {{ shield block; {outer} server {{ {body} location /ops/ {{ internal; }} {locations} }} }}"

    def php(
        self,
        script="/srv/site/app/index.php",
        endpoint="unix:/run/shield/guard.sock",
        extra="",
    ):
        return f"location = /index.php {{ fastcgi_param SCRIPT_FILENAME {script}; fastcgi_param PHP_ADMIN_VALUE memory_limit=128M; fastcgi_pass {endpoint}; {extra} }}"

    def test_safe_golden(self):
        result = self.run_config(name="safe.conf")
        self.assertEqual(result["status"], "clean", result)
        self.assertIn("SKIP_INHERITED", self.codes(result))
        self.assertIn("PRIVATE_MAPPING", self.codes(result))

    def test_unsafe_golden(self):
        result = self.run_config(name="unsafe.conf")
        expected = {
            "COVERAGE",
            "PUBLIC_INTERNAL",
            "PHP_SCRIPT",
            "HANDOFF",
            "FILE_CACHE",
        }
        if FAULTY_EXPECTED:
            expected.add("deliberately_wrong_diagnostic")
        self.assertTrue(
            expected <= self.codes(result),
            f"missing expected diagnostic: {expected - self.codes(result)}",
        )
        self.assertEqual(result["status"], "nonclean")

    def test_unknown_golden(self):
        result = self.run_config(name="unknown.conf")
        self.assertEqual(result["status"], "nonclean")
        self.assertIn("UNKNOWN", self.codes(result, "unknown"))

    def test_category_skip_replaces(self):
        result = self.run_config(
            self.simple(outer="shield_skip sqli;", body="shield_skip xss;")
        )
        scopes = {
            d["scope"] for d in result["diagnostics"] if d["code"] == "SKIP_REPLACED"
        }
        self.assertTrue(scopes)
        for scope in scopes:
            local = {
                d["category"]
                for d in result["diagnostics"]
                if d.get("scope") == scope and d["code"] == "SKIP_LOCAL"
            }
            self.assertEqual(local, {"xss"})
            self.assertFalse(
                any(
                    d["code"] == "COVERAGE" and d.get("scope") == scope
                    for d in result["diagnostics"]
                )
            )

    def test_multiple_local_skips_union_and_empty_inherits(self):
        result = self.run_config(
            self.simple(outer="shield_skip sqli; shield_skip xss;")
        )
        inherited = {
            d["category"]
            for d in result["diagnostics"]
            if d["code"] == "SKIP_INHERITED"
        }
        self.assertEqual(inherited, {"sqli", "xss"})
        self.assertIn("COVERAGE", self.codes(result))
        self.assertIn(
            "UNKNOWN", self.codes(self.run_config(self.simple(body="shield_skip;")))
        )

    def test_modes_and_body_flags(self):
        for value in ("off", "detect"):
            with self.subTest(value=value):
                self.assertIn(
                    "COVERAGE",
                    self.codes(self.run_config(self.simple(body=f"shield {value};"))),
                )
        self.assertIn(
            "BODY", self.codes(self.run_config(self.simple(body="shield_body off;")))
        )
        self.assertIn(
            "COVERAGE",
            self.codes(
                self.run_config("http { server { location /ops/ { internal; } } }")
            ),
        )

    def test_no_body_categories_and_source_parity(self):
        source = (ROOT / "src/ngx_http_shield_patterns.h").read_text()
        rows = re.findall(
            r'NGX_HTTP_SHIELD_TABLE\(NGX_HTTP_SHIELD_CAT_\w+, "(\w+)",(.*?)\),',
            source,
            re.DOTALL,
        )
        structural = {"httpoxy", "range_dos", "ctrl_char", "dotfile"}
        self.assertEqual(CHECKER.CATEGORIES, {name for name, _ in rows} | structural)
        self.assertEqual(
            CHECKER.NO_BODY,
            {name for name, body in rows if "NGX_HTTP_SHIELD_NO_BODY" in body}
            | structural,
        )
        for category in sorted(CHECKER.NO_BODY):
            with self.subTest(category=category):
                contract = dict(self.contract, required_body_categories=[category])
                self.assertIn(
                    "BODY", self.codes(self.run_config(self.simple(), contract))
                )

    def test_public_internal_overrides_and_server_isolation(self):
        cases = [
            self.simple(locations="location = /ops/public { return 200; }"),
            "http { shield block; server { location = /ops/ { internal; } location / { return 200; } } }",
            self.simple() + " http { server { location /ops/ { return 200; } } }",
            self.simple(locations="location ~ private { return 200; }"),
            "http { shield block; server { location / { return 200; } } }",
        ]
        for text in cases:
            with self.subTest(text=text):
                self.assertEqual(self.run_config(text)["status"], "nonclean")
        self.assertEqual(
            self.run_config(
                self.simple(locations="location @fallback { stub_status; }")
            )["status"],
            "clean",
        )

    def test_status_handler_and_numeric_status(self):
        self.assertIn(
            "PUBLIC_INTERNAL",
            self.codes(
                self.run_config(
                    self.simple(
                        locations="location /metrics { shield_ban_status metrics; }",
                        outer="shield_stats_zone metrics 32k;",
                    )
                )
            ),
        )
        self.assertEqual(
            self.run_config(self.simple(body="shield_status 444;"))["status"], "clean"
        )

    def test_php_safe_and_final_dynamic(self):
        for script in (
            "/srv/site/app/index.php",
            "$document_root$fastcgi_script_name",
            "${document_root}${fastcgi_script_name}",
        ):
            with self.subTest(script=script):
                result = self.run_config(self.simple(locations=self.php(script)))
                self.assertEqual(result["status"], "clean", result)
                if "$" in script:
                    self.assertIn("GUARDED_DYNAMIC", self.codes(result))

    def test_unsafe_script_and_missing_guard(self):
        for script in (
            "/srv/site/uploads/file.php",
            "/srv/site/cache/a.php",
            "/srv/site/app/other.php",
        ):
            self.assertIn(
                "PHP_SCRIPT",
                self.codes(self.run_config(self.simple(locations=self.php(script)))),
            )
        for mode in ("off", "detect"):
            contract = json.loads(json.dumps(self.contract))
            contract["handoffs"][0]["mode"] = mode
            self.assertIn(
                "HANDOFF",
                self.codes(
                    self.run_config(self.simple(locations=self.php()), contract)
                ),
            )
        contract = json.loads(json.dumps(self.contract))
        contract["handoffs"][0]["isolated"] = False
        self.assertIn(
            "HANDOFF",
            self.codes(self.run_config(self.simple(locations=self.php()), contract)),
        )
        self.assertIn(
            "HANDOFF",
            self.codes(
                self.run_config(
                    self.simple(locations=self.php(extra="fastcgi_keep_conn on;"))
                )
            ),
        )
        self.assertIn(
            "PHP_SCRIPT",
            self.codes(
                self.run_config(
                    self.simple(
                        locations=self.php("$request_filename", "unix:/run/php.sock")
                    )
                )
            ),
        )

    def test_parameter_replacement_duplicates_and_conditional(self):
        result = self.run_config(
            self.simple(
                body="fastcgi_param SCRIPT_FILENAME /srv/site/app/index.php;",
                locations="location /php { fastcgi_param HTTP_PROXY ''; fastcgi_pass unix:/run/shield/guard.sock; }",
            )
        )
        self.assertTrue({"PARAMS_REPLACED", "PHP_PARAMS"} <= self.codes(result))
        for extra in ("fastcgi_param SCRIPT_FILENAME /srv/site/app/index.php;",):
            self.assertIn(
                "PHP_PARAMS",
                self.codes(
                    self.run_config(self.simple(locations=self.php(extra=extra)))
                ),
            )
        text = self.simple(locations=self.php()).replace(
            "SCRIPT_FILENAME /srv/site/app/index.php;",
            "SCRIPT_FILENAME /srv/site/app/index.php if_not_empty;",
        )
        self.assertIn("PHP_PARAMS", self.codes(self.run_config(text)))

    def test_guard_vectors_and_policy(self):
        for value in ("different", "$args", '"" if_not_empty'):
            text = self.simple(locations=self.php()).replace("memory_limit=128M", value)
            self.assertIn("GUARD_VECTOR", self.codes(self.run_config(text)))
        policy = {
            "scripts": {
                "/srv/site/uploads/evil.php": {"PHP_VALUE": [], "PHP_ADMIN_VALUE": []}
            }
        }
        (self.root / "handoff.json").write_text(json.dumps(policy))
        self.assertIn(
            "GUARD_POLICY",
            self.codes(self.run_config(self.simple(locations=self.php()))),
        )

    def test_duplicate_privileged_vectors_legitimate(self):
        policy = {
            "scripts": {
                "/srv/site/app/index.php": {
                    "PHP_VALUE": ["a", "b"],
                    "PHP_ADMIN_VALUE": ["memory_limit=128M"],
                }
            }
        }
        (self.root / "handoff.json").write_text(json.dumps(policy))
        text = self.simple(
            locations=self.php(
                extra="fastcgi_param PHP_VALUE a; fastcgi_param PHP_VALUE b; fastcgi_param HTTP_PHP_VALUE ordinary;"
            )
        )
        self.assertEqual(self.run_config(text)["status"], "clean")
        self.assertIn(
            "GUARD_VECTOR",
            self.codes(
                self.run_config(
                    text.replace(
                        "PHP_VALUE a; fastcgi_param PHP_VALUE b;",
                        "PHP_VALUE b; fastcgi_param PHP_VALUE a;",
                    )
                )
            ),
        )

    def test_private_contract_and_legitimate_symlinks(self):
        self.assertIn(
            "PRIVATE_DAC",
            self.codes(
                self.run_config(
                    self.simple(), dict(self.contract, private_dac_verified=False)
                )
            ),
        )
        for directive, code in (
            ("open_file_cache max=8;", "FILE_CACHE"),
            ("disable_symlinks if_not_owner;", "SYMLINK_POLICY"),
        ):
            self.assertIn(
                code, self.codes(self.run_config(self.simple(body=directive)))
            )
        self.assertEqual(
            self.run_config(
                self.simple(body="root /srv/site/public; disable_symlinks off;")
            )["status"],
            "clean",
        )
        self.assertIn(
            "UNKNOWN",
            self.codes(self.run_config(self.simple(body="root $document_root;"))),
        )

    def test_include_relative_prefix_and_numbered_origin(self):
        (self.root / "parts").mkdir()
        (self.root / "parts/outer.conf").write_text("include policy.conf;")
        (self.root / "policy.conf").write_text("shield_skip sqli;")
        result = self.run_config(self.simple(outer="include parts/outer.conf;"))
        self.assertIn("COVERAGE", self.codes(result))
        included = [d for d in result["diagnostics"] if d["code"] == "INCLUDED"]
        self.assertEqual([d["related_file"] for d in included], [2, 3])
        self.assertEqual(included[1]["file"], 2)

    def test_include_cycles_depth_and_unsupported_paths(self):
        (self.root / "cycle.conf").write_text("include input.conf;")
        self.assertIn("CYCLE", self.codes(self.run_config("include cycle.conf;")))
        for path in (
            "*.conf",
            "$file",
            "../outside.conf",
            "/etc/nginx/nginx.conf",
            "//etc/nginx/nginx.conf",
            "missing.conf",
        ):
            with self.subTest(path=path):
                self.assertEqual(
                    self.run_config(f"include {path};")["status"], "nonclean"
                )
        for index in range(CHECKER.MAX_INCLUDES + 2):
            (self.root / f"depth{index}.conf").write_text(
                f"include depth{index + 1}.conf;"
            )
        self.assertIn("LIMIT", self.codes(self.run_config("include depth0.conf;")))

    def test_no_symlinks_directories_fifo_or_execution(self):
        (self.root / "link.conf").symlink_to(self.root / "safe.conf")
        (self.root / "linked-dir").symlink_to(self.root, target_is_directory=True)
        (self.root / "dir.conf").mkdir()
        os.mkfifo(self.root / "fifo.conf")
        for name in ("link.conf", "linked-dir/safe.conf", "dir.conf", "fifo.conf"):
            with self.subTest(name=name):
                self.assertIn("INPUT", self.codes(self.run_config(f"include {name};")))
        marker = self.root / "executed"
        text = self.simple(body=f"root '$(touch {marker})';")
        self.assertEqual(self.run_config(text)["status"], "nonclean")
        self.assertFalse(marker.exists())

    def test_quoting_comments_escaping_and_variable_bounds(self):
        text = self.simple(
            body='root "/srv/site/public space"; # unmatched " {\n return 200 "safe; # {}";'
        )
        self.assertEqual(self.run_config(text)["status"], "clean")
        parsed = CHECKER.tokens(
            r"""a "escaped\"quote" 'single\'quote' regex\z \$args;""", 1
        )
        self.assertEqual(parsed[1][0], 'escaped"quote')
        self.assertEqual(parsed[2][0], "single'quote")
        self.assertEqual(parsed[3][0], r"regex\z")
        for value in ("$unknown", "${unknown}", "$", "${uri"):
            self.assertEqual(
                self.run_config(self.simple(body=f"root {value};"))["status"],
                "nonclean",
            )

    def test_malformed_syntax(self):
        for text in (
            "}",
            "http {",
            "http",
            "http }",
            "http {} ;",
            'http { root "a; }',
            "http { root a\\",
            'http { root "a"suffix; }',
            'http { root a"b; }',
            "http { root '\0'; }",
        ):
            with self.subTest(text=text):
                self.assertEqual(self.run_config(text)["status"], "nonclean")
        (self.root / "invalid.conf").write_bytes(b"\xff")
        self.assertIn("INPUT", self.codes(self.run_config(name="invalid.conf")))

    def test_size_token_node_depth_and_diagnostic_limits(self):
        for text in (
            "#" * (CHECKER.MAX_FILE + 1),
            "a" * (CHECKER.MAX_TOKEN + 1),
            "http {" * (CHECKER.MAX_DEPTH + 1) + "}" * (CHECKER.MAX_DEPTH + 1),
        ):
            self.assertIn("LIMIT", self.codes(self.run_config(text)))
        for limit, text in (
            ("MAX_TOKENS", self.simple()),
            ("MAX_NODES", self.simple()),
        ):
            with patch.object(CHECKER, limit, 2):
                self.assertIn("LIMIT", self.codes(self.run_config(text)))
        with patch.object(CHECKER, "MAX_DIAGNOSTICS", 2):
            result = self.run_config(name="unsafe.conf")
            self.assertEqual(len(result["diagnostics"]), 2)
            self.assertEqual(result["status"], "nonclean")
            self.assertIn("LIMIT", self.codes(result))

        class FailingParser:
            def __init__(self, _reader, emit):
                self.emit = emit

            def parse(self, _config):
                self.emit("info", "SKIP_INHERITED")
                self.emit("info", "SKIP_INHERITED")
                raise OSError("late read failure")

        with (
            patch.object(CHECKER, "MAX_DIAGNOSTICS", 2),
            patch.object(CHECKER, "Parser", FailingParser),
        ):
            result = self.run_config(name="safe.conf")
            self.assertEqual(len(result["diagnostics"]), 2)
            self.assertIn("LIMIT", self.codes(result))
        self.assertEqual(
            self.run_config(
                self.simple() + " " * (CHECKER.MAX_FILE - len(self.simple()))
            )["status"],
            "clean",
        )

    def test_file_count_and_total_byte_limits(self):
        (self.root / "small.conf").write_text("# comment\n")
        for field, value in (("MAX_FILES", 3), ("MAX_TOTAL", 1500)):
            with patch.object(CHECKER, field, value):
                result = self.run_config("include small.conf;" * 64)
                self.assertIn("LIMIT", self.codes(result))

    def test_unknown_constructs_duplicates_context_and_arity(self):
        cases = (
            "set $script /x;",
            "proxy_pass http://backend;",
            "root /a; root /b;",
            "shield invalid;",
            "shield_body;",
            "shield_skip imaginary;",
            "if ($args) { return 200; }",
            "fastcgi_param A;",
            "fastcgi_param A b unless_empty;",
            "internal on;",
            "location bogus extra args { }",
        )
        for body in cases:
            with self.subTest(body=body):
                self.assertEqual(
                    self.run_config(self.simple(body=body))["status"], "nonclean"
                )
        self.assertEqual(
            self.run_config("shield block; http { server {} }")["status"], "nonclean"
        )
        self.assertEqual(self.run_config("events {}")["status"], "nonclean")

    def test_contract_schema_and_policy_errors(self):
        cases = [
            dict(self.contract, extra=True),
            dict(self.contract, version=True),
            dict(self.contract, required_categories=["unknown"]),
            dict(self.contract, approved_scripts=[1]),
            dict(self.contract, approved_scripts=["/srv/site/uploads/a.php"]),
            dict(self.contract, private_dac_verified="yes"),
            dict(self.contract, internal_routes="/ops/"),
            dict(self.contract, handoffs=[{}]),
            dict(self.contract, internal_routes=["/a/../b"]),
            dict(self.contract, internal_routes=["/a"] * (CHECKER.MAX_ITEMS + 1)),
        ]
        for contract in cases:
            with self.subTest(contract=contract):
                self.assertIn(
                    "CONTRACT", self.codes(self.run_config(self.simple(), contract))
                )
        for policy in (
            '{"scripts":{},"scripts":{}}',
            '{"scripts":[]}',
            '{"scripts":{"relative":{}}}',
            '{"scripts":{"/x":{"PHP_VALUE":[null],"PHP_ADMIN_VALUE":[]}}}',
            "[]",
            "{",
        ):
            (self.root / "handoff.json").write_text(policy)
            self.assertEqual(self.run_config(self.simple())["status"], "nonclean")

    def test_unmodeled_location_forms_cannot_be_clean(self):
        for location in ("=/ops/public", "^~/ops/public", "~ops", "~*ops", "$arg_flag"):
            with self.subTest(location=location):
                result = self.run_config(
                    self.simple(locations=f"location {location} {{ return 200; }}")
                )
                self.assertEqual(
                    result["status"], "nonclean", "unsupported location returned clean"
                )
                self.assertIn("UNKNOWN", self.codes(result))
        for modifier in ("~", "~*"):
            result = self.run_config(
                self.simple(
                    locations=f"location {modifier} @metrics {{ stub_status; }}"
                )
            )
            self.assertIn(
                "PUBLIC_INTERNAL",
                self.codes(result),
                "regex pattern treated as named location",
            )
            self.assertIn("UNKNOWN", self.codes(result))
        self.assertEqual(
            self.run_config(
                self.simple(locations="location @fallback { stub_status; }")
            )["status"],
            "clean",
        )

    def test_dynamic_script_privileged_vectors(self):
        for vector in ("memory_limit=256M", "$args", "memory_limit=128M if_not_empty"):
            text = self.simple(
                locations=self.php("$document_root$fastcgi_script_name")
            ).replace("memory_limit=128M", vector)
            result = self.run_config(text)
            self.assertEqual(
                result["status"],
                "nonclean",
                "dynamic script bypassed privileged vector analysis",
            )
            self.assertIn("GUARD_VECTOR", self.codes(result))
        policy = {
            "scripts": {
                "/srv/site/app/index.php": {
                    "PHP_VALUE": [],
                    "PHP_ADMIN_VALUE": ["memory_limit=128M"],
                },
                "/srv/site/app/health.php": {
                    "PHP_VALUE": [],
                    "PHP_ADMIN_VALUE": ["memory_limit=256M"],
                },
            }
        }
        (self.root / "handoff.json").write_text(json.dumps(policy))
        contract = dict(self.contract, approved_scripts=list(policy["scripts"]))
        result = self.run_config(
            self.simple(locations=self.php("$document_root$fastcgi_script_name")),
            contract,
        )
        self.assertIn("GUARD_VECTOR", self.codes(result, "unknown"))
        result = self.run_config(self.simple(locations=self.php()), contract)
        self.assertEqual(result["status"], "clean")

    def test_privileged_vector_entry_limit(self):
        for count in (CHECKER.MAX_ITEMS, CHECKER.MAX_ITEMS + 1):
            policy = {
                "scripts": {
                    "/srv/site/app/index.php": {
                        "PHP_VALUE": ["a"] * count,
                        "PHP_ADMIN_VALUE": ["memory_limit=128M"],
                    }
                }
            }
            (self.root / "handoff.json").write_text(json.dumps(policy))
            result = self.run_config(
                self.simple(
                    locations=self.php(extra="fastcgi_param PHP_VALUE a;" * count)
                )
            )
            self.assertEqual(
                result["status"],
                "clean" if count == CHECKER.MAX_ITEMS else "nonclean",
                "guard vector entry limit not enforced",
            )
            if count > CHECKER.MAX_ITEMS:
                self.assertIn("CONTRACT", self.codes(result))

    def test_literal_filesystem_root_is_supported(self):
        for directive in ("root /;", "alias /;"):
            text = (
                self.simple(body=directive)
                if directive.startswith("root")
                else self.simple(locations="location /files/ { " + directive + " }")
            )
            self.assertEqual(
                self.run_config(text)["status"],
                "clean",
                "literal filesystem root rejected",
            )
        self.assertEqual(
            self.run_config(self.simple(body="root //double/root;"))["status"],
            "nonclean",
        )

    def test_malformed_variable_cannot_hide_handlers(self):
        # ngx_conf_read_token accepts the malformed reference as an ordinary
        # FastCGI name; its whitespace and semicolon still delimit directives.
        # Confirmed with pinned nginx -t; do not swallow the following block.
        for handler in ("stub_status;", "fastcgi_pass unix:/tmp/unprotected.sock;"):
            text = (
                "http { shield block; server { location /ops/ { internal; } fastcgi_param ${X 1; location /secret/ { "
                + handler
                + " }index x; } }"
            )
            result = self.run_config(text)
            self.assertEqual(
                result["status"], "nonclean", "malformed variable hid a handler"
            )
            self.assertIn("SYNTAX", self.codes(result))
        for reference in ("${a b}", "${a;}", "${a{b}", "${a\n}", "${a'quoted'}"):
            self.assertEqual(
                self.run_config(self.simple(body=f"index '{reference}';"))["status"],
                "nonclean",
            )
        self.assertEqual(
            self.run_config(
                self.simple(
                    locations=self.php("${document_root}${fastcgi_script_name}")
                )
            )["status"],
            "clean",
        )

    def test_native_escape_and_nested_internal_semantics(self):
        # nginx preserves backslash-space; } only closes a block at token start.
        parsed = CHECKER.tokens(r"index a\ b x}y;", 1)
        self.assertEqual(parsed[1][0], r"a\ b")
        self.assertEqual(parsed[2][0], "x}y")
        parsed = CHECKER.tokens("index a\u00a0b;", 1)
        self.assertEqual(parsed[1][0], "a\u00a0b")
        text = "http { shield block; server { location /ops/ { internal; location /ops/metrics { stub_status; } } } }"
        # ngx_http_core_merge_loc_conf explicitly merges conf->internal.
        self.assertEqual(self.run_config(text)["status"], "clean")

    def test_nested_static_handler_does_not_inherit_fastcgi_pass(self):
        handler = self.php().replace("location = /index.php", "location /php/")
        handler = (
            handler[:-1]
            + " location /php/static/ { fastcgi_param HTTP_PROXY ''; return 200; } }"
        )
        self.assertEqual(
            self.run_config(self.simple(locations=handler))["status"],
            "clean",
            "static nested location inherited FastCGI handler",
        )

    def test_remaining_parser_and_contract_boundaries(self):
        # A hash inside an unquoted token is literal nginx data, not a comment.
        result = self.run_config(
            self.simple(locations=self.php("/srv/site/app/index.php#suffix"))
        )
        self.assertIn("PHP_SCRIPT", self.codes(result))
        with self.assertRaises(CHECKER.Problem):
            CHECKER.tokens("value ${unterminated", 1)
        (self.root / "small.conf").write_text("return 200;")
        with patch.object(CHECKER, "MAX_TOKENS", 6):
            self.assertIn(
                "LIMIT",
                self.codes(
                    self.run_config(
                        "include small.conf; include small.conf; include small.conf;"
                    )
                ),
            )
        for key, value in (
            ("endpoint", "tcp:backend"),
            ("mode", "invalid"),
            ("isolated", "yes"),
            ("policy", 1),
        ):
            contract = json.loads(json.dumps(self.contract))
            contract["handoffs"][0][key] = value
            self.assertIn(
                "CONTRACT", self.codes(self.run_config(self.simple(), contract))
            )
        contract = dict(self.contract, private_roots=[], internal_routes=[])
        self.assertEqual(
            self.run_config("http { shield block; server {} }", contract)["status"],
            "clean",
        )
        self.assertIn(
            "UNKNOWN",
            self.codes(self.run_config(self.simple(body="worker_connections 32;"))),
        )
        text = self.simple(
            body="fastcgi_param SCRIPT_FILENAME /srv/site/app/index.php; fastcgi_param PHP_ADMIN_VALUE memory_limit=128M;",
            locations="location /php { fastcgi_pass unix:/run/shield/guard.sock; }",
        )
        self.assertEqual(self.run_config(text)["status"], "clean")
        text = self.simple(locations="location ~ protected { internal; }")
        self.assertEqual(self.run_config(text)["status"], "clean")
        self.assertFalse(CHECKER.utf8("\ud800"))
        self.assertFalse(CHECKER.absolute("//double/root"))
        with (
            patch.object(
                sys,
                "argv",
                [
                    "checker",
                    "--root",
                    str(self.root),
                    "--config",
                    "safe.conf",
                    "--contract",
                    "site.json",
                ],
            ),
            patch("builtins.print") as output,
        ):
            self.run_config(name="safe.conf")
            self.assertEqual(CHECKER.main(), 0)
            self.assertEqual(json.loads(output.call_args.args[0])["status"], "clean")
        with patch.object(sys, "argv", ["checker"]), patch("sys.stderr"):
            with self.assertRaises(SystemExit) as error:
                CHECKER.main()
            self.assertEqual(error.exception.code, 2)

    def test_public_internal_redirects(self):
        directives = (
            "rewrite ^ /ops/ last;",
            "rewrite ^ /ops/;",
            "try_files $uri /ops/;",
            "error_page 404 /ops/;",
            "error_page 404 =200 /ops/;",
            "error_page 404 = /ops/;",
            "index /ops/;",
        )
        for directive in directives:
            with self.subTest(directive=directive):
                result = self.run_config(
                    self.simple(locations="location /status/ { " + directive + " }")
                )
                self.assertIn(
                    "PUBLIC_INTERNAL",
                    self.codes(result),
                    "public redirect into declared internal route was not diagnosed",
                )
                self.assertEqual(result["status"], "nonclean")

    def test_break_directory_index_composition(self):
        contract = dict(self.contract)
        contract["internal_routes"] = ["/ops/private.html"]
        for index in ("private.html", "private.html.backup"):
            with self.subTest(index=index):
                result = self.run_config(
                    self.simple(
                        locations="location /ops/private.html { internal; } "
                        "location /status/ { rewrite ^ /ops/ break; index "
                        + index
                        + "; }"
                    ),
                    contract=contract,
                )
                self.assertIn(
                    "ROUTE_UNKNOWN",
                    self.codes(result),
                    "directory break plus relative index was falsely clean",
                )
        for directive in (
            "rewrite ^ /ops/ break; index public.html;",
            "rewrite ^ /ops-other/ break; index private.html;",
            "rewrite ^ /ops/private.html break; index private.html;",
        ):
            with self.subTest(legitimate=directive):
                result = self.run_config(
                    self.simple(
                        locations="location /ops/private.html { internal; } "
                        "location /status/ { " + directive + " }"
                    ),
                    contract=contract,
                )
                self.assertEqual(result["status"], "clean", result)

    def test_legitimate_redirect_controls(self):
        directives = (
            "rewrite ^ /ops/ redirect;",
            "rewrite ^ /ops/ permanent;",
            "rewrite ^ https://example.test/ops/;",
            "rewrite ^ http://example.test/ops/ last;",
            "rewrite ^ /ops/file break;",
            "rewrite ^ /ops last;",
            "rewrite ^ /ops-other/ last;",
            "error_page 404 https://example.test/ops/;",
            "try_files $uri $uri/ =404;",
            "try_files $uri =000404;",
            "try_files /ops/file =404;",
            "try_files $uri $uri/ /index.php$is_args$args;",
            "try_files $uri /index.php?$args;",
            "index index.html;",
            "index /ops/; return 200;",
        )
        for directive in directives:
            with self.subTest(directive=directive):
                result = self.run_config(
                    self.simple(locations="location /status/ { " + directive + " }")
                )
                self.assertEqual(result["status"], "clean", result)
        for directive in (
            "rewrite ^ /ops/target last;",
            "try_files $uri /ops/target;",
            "error_page 404 /ops/target;",
            "index /ops/target;",
        ):
            with self.subTest(internal=directive):
                result = self.run_config(
                    self.simple(
                        locations="location /ops/source/ { "
                        + directive
                        + " internal; }"
                    )
                )
                self.assertEqual(result["status"], "clean", result)

    def test_unresolved_redirects_are_unknown(self):
        directives = (
            "rewrite ^ $uri last;",
            "rewrite ^ /ops/$args last;",
            "rewrite ^ /ops/ break;",
            "rewrite ^ $uri break;",
            "rewrite nomatch /ops/ last;",
            "rewrite ^ /ops%2ftarget last;",
            "rewrite ^ /ops/../public last;",
            "rewrite ^ //ops/ last;",
            "try_files $uri $args;",
            "try_files $args/ =404;",
            "try_files /ops// =404;",
            "try_files $uri @fallback;",
            "error_page 404 $uri;",
            "error_page 404 @fallback;",
            "index $args;",
            "index ops/index.html;",
            "index ../ops/index.html;",
            "index .;",
            "index ..;",
        )
        for directive in directives:
            with self.subTest(directive=directive):
                result = self.run_config(
                    self.simple(locations="location /status/ { " + directive + " }")
                )
                self.assertIn("ROUTE_UNKNOWN", self.codes(result, "unknown"), result)
                self.assertEqual(result["status"], "nonclean")

    def test_redirect_syntax_and_query_boundaries(self):
        for directive in (
            "rewrite ^ /ops/ invalid;",
            "rewrite ^;",
            "try_files $uri =oops;",
            "try_files $uri =0;",
            "try_files $uri =1000;",
            "try_files $uri;",
            "error_page invalid /ops/;",
            "error_page 499 /ops/;",
            "error_page =200 /ops/;",
            "error_page 404 =oops /ops/;",
            "index;",
        ):
            with self.subTest(directive=directive):
                self.assertEqual(
                    self.run_config(
                        self.simple(locations="location /status/ { " + directive + " }")
                    )["status"],
                    "nonclean",
                )
        for target, clean in (
            ("/ops?$args", True),
            ("/ops/?$args", False),
            ("/ops/$is_args$args", False),
            ("/index.php$is_args$args", True),
        ):
            result = self.run_config(
                self.simple(
                    locations=f"location /status {{ rewrite ^ {target} last; }}"
                )
            )
            self.assertEqual(result["status"], "clean" if clean else "nonclean")

    def test_redirect_inheritance_and_indirect_helpers(self):
        for directive in ("index /ops/;", "error_page 404 /ops/;"):
            result = self.run_config(
                self.simple(outer=directive, locations="location /public/ { }")
            )
            self.assertIn(
                "PUBLIC_INTERNAL",
                self.codes(result),
                "inherited routing policy was not checked",
            )
        for helper in (
            "location /helper/ { internal; rewrite ^ /ops/ last; }",
            "location @fallback { rewrite ^ /ops/ last; }",
        ):
            result = self.run_config(self.simple(locations=helper))
            self.assertIn("ROUTE_UNKNOWN", self.codes(result, "unknown"))
        contract = dict(self.contract, internal_routes=["/index"])
        result = self.run_config(
            "http { shield block; server { location /index { internal; } location / { index index.html; } } }",
            contract,
        )
        self.assertIn(
            "ROUTE_UNKNOWN",
            self.codes(result, "unknown"),
            "relative index prefix boundary was assumed safe",
        )

    def test_routing_scope_and_duplicate_boundaries(self):
        contract = dict(self.contract, internal_routes=[])
        for directive in (
            "rewrite ^ $uri last;",
            "try_files $uri /fallback;",
            "index subdir/index.html;",
            "error_page 404 /fallback;",
        ):
            result = self.run_config(
                self.simple(locations="location /status/ { " + directive + " }"),
                contract,
            )
            self.assertEqual(result["status"], "clean", result)
        result = self.run_config(
            self.simple(
                locations="location /status/ { try_files $uri /fallback; try_files $uri /other; }"
            )
        )
        self.assertIn("DUPLICATE", self.codes(result, "unknown"))
        result = self.run_config(
            self.simple(
                locations="location /status/ { rewrite ^ /ops/?sensitive-query-placeholder last; }"
            )
        )
        self.assertNotIn("sensitive-query-placeholder", json.dumps(result))
        self.assertIn("PUBLIC_INTERNAL", self.codes(result))

    def test_cli_safe_identifiers_redaction_and_exit_status(self):
        sentinel = "sensitive-value-for-redaction-control"
        config = f"credential_{sentinel}.conf"
        (self.root / config).write_text(
            self.simple(body=f"arbitrary_directive '{sentinel}';")
        )
        command = [
            str(ROOT / "contrib/check-deployment"),
            "--root",
            str(self.root),
            "--config",
            config,
            "--contract",
            "site.json",
        ]
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(sentinel, result.stdout + result.stderr)
        self.assertNotIn(str(self.root), result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "nonclean")
        command[command.index(config)] = "safe.conf"
        self.assertEqual(
            subprocess.run(command, capture_output=True, check=False).returncode, 0
        )
        invalid = subprocess.run(
            [str(ROOT / "contrib/check-deployment"), "--unexpected", sentinel],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(invalid.returncode, 2)
        self.assertNotIn(sentinel, invalid.stderr)
        for contract in ('{"version":1,"version":1}', sentinel):
            (self.root / "site.json").write_text(contract)
            result = CHECKER.inspect(self.root, config, "site.json")
            self.assertNotIn(sentinel, json.dumps(result))
            self.assertEqual(result["status"], "nonclean")
        self.assertEqual(
            CHECKER.inspect(self.root / "absent", config, "site.json")["status"],
            "nonclean",
        )


if __name__ == "__main__":
    if "--faulty-expected" in sys.argv:
        FAULTY_EXPECTED = True
        sys.argv.remove("--faulty-expected")
    unittest.main()
