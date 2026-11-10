#!/usr/bin/env python3
"""Run pinned Linux collectors against live Shield status captures (Docker required)."""

import argparse
import http.client
import json
import re
import signal
import socket
import subprocess
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import quote

from scraper_fixture import FixtureServer

COLLECTORS = (
    "prometheus",
    "vmagent",
    "alloy",
    "otel",
    "telegraf-prometheus",
    "telegraf-json",
)
METRIC = "shield_requests_total"


def require(condition, message):
    """Keep integration assertions active even when Python optimization is enabled."""
    if not condition:
        raise AssertionError(message)


def port():
    """Reserve a candidate port; listeners still fail explicitly on bind races."""
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def get(address, path, accept=""):
    connection = http.client.HTTPConnection("127.0.0.1", address, timeout=3)
    try:
        connection.request("GET", path, headers={"Accept": accept})
        response = connection.getresponse()
        body = response.read()
        if response.status != 200:
            raise RuntimeError(f"HTTP {response.status}: {body!r}")
        return body
    finally:
        connection.close()


def eventually(predicate, description, seconds=30):
    deadline = time.monotonic() + seconds
    last_error = None
    while True:
        try:
            if predicate():
                return
        except (OSError, RuntimeError) as error:
            last_error = error
        if time.monotonic() >= deadline:
            raise AssertionError(f"Timed out: {description}") from last_error
        time.sleep(0.2)


@contextmanager
def capture(binary, module, output):
    """Capture actual responses from a fresh, nonzero counters-only test workload."""
    address = port()
    root = output / "nginx"
    root.mkdir()
    (root / "logs").mkdir()
    (root / "nginx.conf").write_text(f'''load_module "{module}";
daemon off;
worker_processes 1;
pid {root}/nginx.pid;
error_log {root}/error.log info;
events {{ worker_connections 64; }}
http {{
    access_log off;
    shield_ban_zone matrix:1m;
    server {{
        listen 127.0.0.1:{address};
        shield detect;
        shield_ban zone=matrix count=999 window=60s bantime=30s;
        location /probe {{ empty_gif; }}
        location /json {{ shield off; shield_ban_status matrix; }}
        location /metrics {{
            shield off;
            shield_ban_status matrix;
            shield_ban_status_format prometheus;
        }}
    }}
}}
''')
    with (root / "process.log").open("w", encoding="utf-8") as log:
        process = subprocess.Popen(
            [str(binary), "-p", str(root), "-c", str(root / "nginx.conf")],
            stdout=log,
            stderr=log,
        )
        try:
            eventually(lambda: get(address, "/json"), "Shield startup")
            for _ in range(3):
                get(address, "/probe")
            captures = (
                get(address, "/metrics"),
                get(address, "/metrics", "application/openmetrics-text; version=1.0.0"),
                get(address, "/json"),
            )
            require(METRIC.encode() in captures[0], "live Shield metric missing")
            require(json.loads(captures[2])["inspected"] == 3, captures[2])
            for name, body in zip(
                ("prometheus.txt", "openmetrics.txt", "status.json"),
                captures,
                strict=True,
            ):
                (output / name).write_bytes(body)
            yield captures
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGQUIT)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise
            if process.returncode:
                raise RuntimeError(f"nginx exited {process.returncode}; see {root}")


class Docker:
    """Own and reconcile only containers named and labeled by this invocation."""

    def __init__(self, output, images):
        self.output = output
        self.images = images
        self.owner = "shield-scrapers-" + uuid.uuid4().hex[:12]
        self.ids = []
        self.prepared = set()

    def prepare(self, key):
        if key in self.prepared:
            return
        image = self.images[key]
        result = subprocess.run(
            ["docker", "image", "inspect", image],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=60,
            check=False,
        )
        if result.returncode:
            subprocess.run(
                ["docker", "pull", image],
                capture_output=True,
                text=True,
                timeout=600,
                check=True,
            )
        self.prepared.add(key)

    def run(self, key, args, name, detached=False, entrypoint=None):
        self.prepare(key)
        command = [
            "docker",
            "run",
            "--name",
            f"{self.owner}-{name}",
            "--label",
            f"myguard.run={self.owner}",
            "--network",
            "host",
            "--mount",
            f"type=bind,src={self.output},dst=/matrix",
            "--user",
            "0:0",
        ]
        if detached:
            command += ["-d"]
        if entrypoint:
            command += ["--entrypoint", entrypoint]
        command += [self.images[key], *args]
        self.ids.append((name, f"{self.owner}-{name}"))
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=60, check=False
        )
        # Timeout cleanup also discovers containers using the ownership label.
        (self.output / f"{name}.run.log").write_text(result.stdout + result.stderr)
        if detached and result.returncode:
            raise RuntimeError(f"{name} failed: {result.stderr}")
        return result

    def logs(self, name):
        result = subprocess.run(
            ["docker", "logs", f"{self.owner}-{name}"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        body = result.stdout + result.stderr
        (self.output / f"{name}.log").write_text(body)
        return body

    def close(self):
        result = subprocess.run(
            ["docker", "ps", "-aq", "--filter", f"label=myguard.run={self.owner}"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        ids = result.stdout.split()
        (self.output / "containers.json").write_text(
            json.dumps({"owner": self.owner, "ids": ids})
        )
        for container in ids:
            subprocess.run(
                ["docker", "rm", "-f", container],
                capture_output=True,
                text=True,
                timeout=20,
                check=True,
            )
        remaining = subprocess.check_output(
            ["docker", "ps", "-aq", "--filter", f"label=myguard.run={self.owner}"],
            text=True,
        )
        require(not remaining.strip(), "owned containers remain")


def scrape_configs(address, collector):
    return [
        {
            "job_name": f"{collector}_{kind}",
            "scrape_interval": "1s",
            "metrics_path": path,
            "static_configs": [{"targets": [f"127.0.0.1:{address}"]}],
        }
        for kind, path in (("good", "/metrics"), ("bad", "/invalid-metrics"))
    ]


def query(address, expression):
    body = json.loads(get(address, "/api/v1/query?query=" + quote(expression, safe="")))
    require(body["status"] == "success", body)
    return body["data"]["result"]


def has_value(address, expression, value):
    return any(float(item["value"][1]) == value for item in query(address, expression))


def prometheus(docker, output, address, scrapes):
    (output / "prometheus.json").write_text(json.dumps({"scrape_configs": scrapes}))
    result = docker.run(
        "prometheus",
        ["check", "config", "/matrix/prometheus.json"],
        "promtool-config",
        entrypoint="/bin/promtool",
    )
    require(result.returncode == 0, result.stdout + result.stderr)
    docker.run(
        "prometheus",
        [
            "--config.file=/matrix/prometheus.json",
            f"--web.listen-address=127.0.0.1:{address}",
            "--storage.tsdb.path=/tmp/data",
            "--web.enable-remote-write-receiver",
        ],
        "prometheus",
        detached=True,
    )
    eventually(lambda: get(address, "/-/ready"), "Prometheus receiver ready")


def run_prometheus(docker, receiver):
    eventually(
        lambda: has_value(receiver, f'{METRIC}{{job="prometheus_good"}}', 3),
        "Prometheus ingests live Shield counter",
    )
    eventually(
        lambda: has_value(receiver, 'up{job="prometheus_bad"}', 0),
        "Prometheus rejects malformed scrape",
    )
    # promtool reads stdin, so use a shell only inside its pinned image.
    for kind in ("prometheus", "invalid-prometheus"):
        result = docker.run(
            "prometheus",
            ["-c", f"/bin/promtool check metrics < /matrix/{kind}.txt"],
            "promtool-" + kind,
            entrypoint="/bin/sh",
        )
        require(
            (result.returncode == 0) == (kind == "prometheus"),
            result.stdout + result.stderr,
        )


def run_vmagent(docker, output, fixture_port, receiver):
    name = "vmagent"
    configs = scrape_configs(fixture_port, "vmagent")
    (output / "vmagent.json").write_text(json.dumps({"scrape_configs": configs}))
    docker.run(
        "vmagent",
        [
            "-promscrape.config=/matrix/vmagent.json",
            f"-remoteWrite.url=http://127.0.0.1:{receiver}/api/v1/write",
            "-remoteWrite.flushInterval=1s",
            "-remoteWrite.tmpDataPath=/tmp/write",
            f"-httpListenAddr=127.0.0.1:{port()}",
        ],
        name,
        detached=True,
    )
    eventually(
        lambda: has_value(receiver, f'{METRIC}{{job="vmagent_good"}}', 3),
        "vmagent remote writes Shield counter",
    )
    eventually(
        lambda: (
            "cannot unmarshal Prometheus line" in docker.logs(name)
            and "/invalid-metrics" in docker.logs(name)
        ),
        "vmagent reports malformed sample",
    )


def run_alloy(docker, output, fixture_port, receiver):
    name = "alloy"
    targets = []
    for kind, path in (("good", "/metrics"), ("bad", "/invalid-metrics")):
        targets.append(f'''prometheus.scrape "{kind}" {{
  targets = [{{"__address__" = "127.0.0.1:{fixture_port}"}}]
  job_name = "alloy_{kind}"
  metrics_path = "{path}"
  scrape_interval = "1s"
  scrape_timeout = "1s"
  forward_to = [prometheus.remote_write.sink.receiver]
}}''')
    (output / "alloy.alloy").write_text(
        "\n".join(targets)
        + f"""
prometheus.remote_write "sink" {{
  endpoint {{ url = "http://127.0.0.1:{receiver}/api/v1/write" }}
}}
"""
    )
    result = docker.run("alloy", ["validate", "/matrix/alloy.alloy"], "alloy-config")
    require(result.returncode == 0, result.stderr)
    docker.run(
        "alloy",
        [
            "run",
            f"--server.http.listen-addr=127.0.0.1:{port()}",
            "--storage.path=/tmp/alloy",
            "/matrix/alloy.alloy",
        ],
        name,
        detached=True,
    )
    eventually(
        lambda: has_value(receiver, f'{METRIC}{{job="alloy_good"}}', 3),
        "Alloy remote writes Shield counter",
    )
    eventually(
        lambda: has_value(receiver, 'up{job="alloy_bad"}', 0),
        "Alloy rejects malformed scrape",
    )


def run_otel(docker, output, fixture_port):
    name = "otel"
    configs = scrape_configs(fixture_port, "otel")
    exporter = port()
    config = {
        "receivers": {"prometheus": {"config": {"scrape_configs": configs}}},
        "exporters": {"prometheus": {"endpoint": f"127.0.0.1:{exporter}"}},
        "service": {
            "telemetry": {"metrics": {"level": "none"}},
            "pipelines": {
                "metrics": {
                    "receivers": ["prometheus"],
                    "exporters": ["prometheus"],
                }
            },
        },
    }
    (output / "otel.json").write_text(json.dumps(config))
    result = docker.run(
        "otel", ["validate", "--config=/matrix/otel.json"], "otel-config"
    )
    require(result.returncode == 0, result.stderr)
    docker.run("otel", ["--config=/matrix/otel.json"], name, detached=True)

    def exported():
        text = get(exporter, "/metrics").decode()
        (output / "otel-export.txt").write_text(text)
        return re.search(
            r'shield_requests_total\{[^\n]*job="otel_good"[^\n]*\} 3\b',
            text,
        ) and re.search(r'up\{[^\n]*job="otel_bad"[^\n]*\} 0\b', text)

    eventually(exported, "OTel exports Shield counter and failed scrape")


def run_telegraf(name, docker, output, fixture_port):
    data_format = "json" if name.endswith("json") else "prometheus"
    path = "/json" if data_format == "json" else "/metrics"
    for kind in ("good", "bad"):
        url = f"http://127.0.0.1:{fixture_port}" + (
            "/invalid-" + path.lstrip("/") if kind == "bad" else path
        )
        config = (
            f'[[inputs.http]]\n  urls = ["{url}"]\n  data_format = "json"\n'
            if data_format == "json"
            else f'[[inputs.prometheus]]\n  urls = ["{url}"]\n'
        )
        filename = name + "-" + kind
        (output / (filename + ".conf")).write_text(config)
        result = docker.run(
            "telegraf", ["--config", f"/matrix/{filename}.conf", "--test"], filename
        )
        text = result.stdout + result.stderr
        if kind == "good":
            require(result.returncode == 0, text)
            expected = (
                r"^> http,[^\n]*[ ,]inspected=3(?:i|u)?[,\s]"
                if data_format == "json"
                else r"^> shield_requests_total,[^\n]* counter=3(?:i|u)?[,\s]"
            )
            require(re.search(expected, text, re.MULTILINE), text)
        else:
            error = (
                "parsing metrics failed"
                if data_format == "json"
                else "text format parsing error"
            )
            require(
                result.returncode != 0 and error in text,
                "malformed Telegraf payload accepted: " + text,
            )


def run_collector(name, docker, output, fixture_port, receiver):
    if name == "prometheus":
        run_prometheus(docker, receiver)
    elif name == "vmagent":
        run_vmagent(docker, output, fixture_port, receiver)
    elif name == "alloy":
        run_alloy(docker, output, fixture_port, receiver)
    elif name == "otel":
        run_otel(docker, output, fixture_port)
    else:
        run_telegraf(name, docker, output, fixture_port)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nginx", type=Path, required=True)
    parser.add_argument("--module", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--collector", choices=COLLECTORS, action="append")
    parser.add_argument(
        "--negative-control-valid-as-invalid",
        action="store_true",
        help="causal control: rejection assertions must fail",
    )
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    images = json.loads(Path(__file__).with_name("scraper-images.json").read_text())
    selected = args.collector or COLLECTORS
    docker = Docker(output, images)
    results = []
    try:
        with (
            capture(args.nginx.resolve(), args.module.resolve(), output) as bodies,
            FixtureServer(("127.0.0.1", 0), *bodies) as fixture,
        ):
            fixture.valid_as_invalid = args.negative_control_valid_as_invalid
            thread = threading.Thread(target=fixture.serve_forever)
            thread.start()
            try:
                (output / "invalid-prometheus.txt").write_bytes(
                    get(fixture.server_port, "/invalid-metrics")
                )
                receiver = port()
                prometheus(
                    docker,
                    output,
                    receiver,
                    scrape_configs(fixture.server_port, "prometheus")
                    if "prometheus" in selected
                    else [],
                )
                for name in selected:
                    run_collector(name, docker, output, fixture.server_port, receiver)
                    results.append(name)
                    print(
                        f"PASS {name}: live ingestion and malformed payload control",
                        flush=True,
                    )
                (output / "received-values.json").write_text(
                    json.dumps(
                        {
                            "requests": query(receiver, METRIC),
                            "up": query(receiver, "up"),
                        },
                        indent=2,
                    )
                )
                (output / "prometheus-targets.json").write_bytes(
                    get(receiver, "/api/v1/targets")
                )
            finally:
                (output / "fixture-requests.json").write_text(
                    json.dumps(fixture.requests)
                )
                fixture.shutdown()
                thread.join()
    finally:
        try:
            for name, _ in docker.ids:
                docker.logs(name)
        finally:
            docker.close()
        (output / "result.json").write_text(
            json.dumps(
                {
                    "passed": results,
                    "requested": list(selected),
                    "images": images,
                    "negative_control": args.negative_control_valid_as_invalid,
                },
                indent=2,
            )
            + "\n"
        )


if __name__ == "__main__":
    main()
