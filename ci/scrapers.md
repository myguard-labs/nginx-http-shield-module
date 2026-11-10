# Scraper compatibility matrix

Run the focused collector matrix on Linux with Python 3 and Docker. Build Shield
first with the same command used by CI, then supply the resulting binary and
module. The output directory must be new; captures, generated configurations,
collector logs, values received by Prometheus, and container IDs remain there.

```sh
bash ci/tools/ci-build.sh nginx 1.31.8
python3 -m unittest discover -s ci/tests -p 'test_scraper*.py'
python3 ci/tools/scraper_matrix.py \
  --nginx .build/nginx-1.31.8-debug/objs/nginx \
  --module .build/nginx-1.31.8-debug/objs/ngx_http_shield_module.so \
  --output /tmp/shield-scrapers
```

The runner starts its own foreground nginx master and captures Prometheus,
OpenMetrics and JSON responses after three inspected requests. A loopback HTTP
fixture replays those exact bytes with the corresponding content type. It also
serves an unterminated Prometheus label and trailing garbage after a JSON
object. The malformed metric is inserted before the OpenMetrics `# EOF` marker.
This keeps the negative path distinct from a network or configuration failure.
Captures contain a bounded zone label and no client identifiers.

Images are version and digest pinned in [scraper-images.json](tools/scraper-images.json).
Docker fetches a missing image using its pinned reference. Containers run with
host networking to reach the loopback fixture; use a disposable CI host for
untrusted images. Each container has a unique name and `myguard.run` ownership
label. The runner records and removes its containers on success or failure.
The test uses no persistent Docker volumes or networks. Images remain cached.

| Collector | Valid payload | Malformed payload |
| --- | --- | --- |
| Prometheus / promtool | Counter 3; config/text pass | `up=0`; parser fails |
| vmagent | Remote write counter 3 | Parser error for bad endpoint |
| Alloy | Remote write counter 3 | Remote write `up=0` |
| OTel | Exporter counter 3 | Exporter `up=0` |
| Telegraf Prometheus | `--test` counter 3 | Parser error; nonzero exit |
| Telegraf JSON | `--test` inspected 3 | Parser error; nonzero exit |

vmagent may preserve valid samples from a partially malformed response. Its
oracle requires the parser error, rather than assuming whole-scrape rejection.
The other streaming collectors use distinct good/bad job names, so the good
sample cannot satisfy the bad scrape assertion. The fixture logs requested
paths and negotiated formats in `fixture-requests.json`. Config parsers run in
the same pinned collector images used for ingestion. This matrix exercises
collector parsing and transport; native module tests and sanitizer CI remain
separate required checks.

Use `--collector NAME` (repeatable) to replay a selected integration. For a
causal negative control, add `--negative-control-valid-as-invalid`: the fixture
then serves valid bytes on the malformed endpoints. The selected collector's
rejection assertion must fail. Use a fresh output directory for each invocation.
For example:

```sh
python3 ci/tools/scraper_matrix.py \
  --nginx .build/nginx-1.31.8-debug/objs/nginx \
  --module .build/nginx-1.31.8-debug/objs/ngx_http_shield_module.so \
  --collector telegraf-json --negative-control-valid-as-invalid \
  --output /tmp/shield-scrapers-control
```

Netdata and Zabbix are best effort integrations, outside the required executable
matrix. Netdata can use its generic Prometheus collector against Shield's
Prometheus endpoint; Zabbix can use an HTTP agent item with dependent JSONPath
items against the JSON endpoint. No dedicated Shield plugin or vendor template
is shipped or tested here. Template discovery, preprocessing, authentication,
network policy, dashboard setup and version compatibility need validation in
the operator's deployment. Neither integration is claimed supported by this
matrix. Use the [operator mapping](../README.md#monitoring) when configuring
fields and bounded labels.
