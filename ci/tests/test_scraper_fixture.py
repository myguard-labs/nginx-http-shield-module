"""Tests for the live scraper fixture's distinct valid and invalid endpoints."""

import http.client
import importlib.util
import json
import threading
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "scraper_fixture",
    Path(__file__).resolve().parents[1] / "tools" / "scraper_fixture.py",
)
assert SPEC is not None and SPEC.loader is not None
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)


class FixtureTests(unittest.TestCase):
    def setUp(self):
        self.server = FIXTURE.FixtureServer(
            ("127.0.0.1", 0),
            b"shield_requests_total 1\n",
            b"shield_requests_total 1\n# EOF\n",
            b'{"inspected":1}',
        )
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()

    def get(self, path, accept=""):
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.server.server_port, timeout=2
        )
        try:
            connection.request("GET", path, headers={"Accept": accept})
            response = connection.getresponse()
            return response.status, response.getheader("Content-Type"), response.read()
        finally:
            connection.close()

    def test_metrics_negotiation_and_invalid_control(self):
        _, content_type, body = self.get("/metrics")
        self.assertIn("version=0.0.4", content_type)
        self.assertEqual(body, b"shield_requests_total 1\n")
        _, content_type, body = self.get("/metrics", "application/openmetrics-text")
        self.assertIn("application/openmetrics-text", content_type)
        self.assertTrue(body.endswith(b"# EOF\n"))
        _, _, invalid = self.get("/invalid-metrics")
        self.assertTrue(invalid.startswith(b"shield_requests_total 1\n"))
        self.assertIn(b'"unterminated', invalid)

    def test_openmetrics_error_precedes_eof_and_causal_control(self):
        _, _, invalid = self.get("/invalid-metrics", "application/openmetrics-text")
        self.assertTrue(invalid.endswith(b"# EOF\n"))
        self.assertEqual(invalid.count(b"# EOF"), 1)
        self.assertIn(b'"unterminated', invalid)
        self.server.valid_as_invalid = True
        for valid, bad in (
            ("/metrics", "/invalid-metrics"),
            ("/json", "/invalid-json"),
        ):
            self.assertEqual(self.get(valid)[2], self.get(bad)[2])
        self.assertIn(("/invalid-json", ""), self.server.requests)

    def test_empty_payload_and_repeated_requests_are_byte_preserving(self):
        self.server.prometheus_fixture = b""
        for _ in range(2):
            status, _, body = self.get("/metrics")
            self.assertEqual(status, 200)
            self.assertEqual(body, b"")
        self.server.json_fixture = b"[]"
        self.assertEqual(self.get("/json")[2], b"[]")

    def test_json_invalid_control_and_unknown_path(self):
        _, _, body = self.get("/json")
        self.assertEqual(json.loads(body)["inspected"], 1)
        _, _, invalid = self.get("/invalid-json")
        with self.assertRaises(json.JSONDecodeError):
            json.loads(invalid)
        status, _, _ = self.get("/missing")
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
