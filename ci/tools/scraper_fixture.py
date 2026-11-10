#!/usr/bin/env python3
"""Serve captured Shield status responses to scraper compatibility tests."""

import argparse
import http.server
from pathlib import Path


class FixtureHandler(http.server.BaseHTTPRequestHandler):
    """Serve valid captures and corresponding deliberately malformed bodies."""

    def do_GET(self):
        self.server.requests.append((self.path, self.headers.get("Accept", "")))
        if self.path not in ("/metrics", "/invalid-metrics", "/json", "/invalid-json"):
            self.send_error(404)
            return
        if self.path.endswith("json"):
            body = self.server.json_fixture  # type: ignore[attr-defined]
            content_type = "application/json"
            if self.path.startswith("/invalid") and not self.server.valid_as_invalid:
                body += b"!"
        else:
            openmetrics = "application/openmetrics-text" in self.headers.get(
                "Accept", ""
            )
            body = (
                self.server.openmetrics_fixture
                if openmetrics  # type: ignore[attr-defined]
                else self.server.prometheus_fixture
            )  # type: ignore[attr-defined]
            content_type = (
                "application/openmetrics-text; version=1.0.0; charset=utf-8"
                if openmetrics
                else "text/plain; version=0.0.4; charset=utf-8"
            )
            if self.path.startswith("/invalid") and not self.server.valid_as_invalid:
                broken = b'broken_metric{label="unterminated} 1\n'
                if openmetrics:
                    body = body.replace(b"# EOF\n", broken + b"# EOF\n")
                else:
                    body += broken
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class FixtureServer(http.server.ThreadingHTTPServer):
    def __init__(self, address, prometheus, openmetrics, json_fixture):
        super().__init__(address, FixtureHandler)
        self.prometheus_fixture = prometheus
        self.openmetrics_fixture = openmetrics
        self.json_fixture = json_fixture
        self.valid_as_invalid = False
        self.requests = []


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prometheus", type=Path, required=True)
    parser.add_argument("--openmetrics", type=Path, required=True)
    parser.add_argument("--json", type=Path, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()
    with FixtureServer(
        (args.host, args.port),
        args.prometheus.read_bytes(),
        args.openmetrics.read_bytes(),
        args.json.read_bytes(),
    ) as server:
        print(server.server_port, flush=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
