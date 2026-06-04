# waf-efficacy-tool

A dataset-driven WAF tester that replays captured HTTP traffic and measures how the WAF responds. Supports three modes: True Positive (malicious traffic), False Positive (legitimate traffic), and Mixed.

**Primary use in this repo: False Positive testing** — measuring how often the WAF incorrectly blocks real user traffic. See [Dataset setup](#dataset-setup).

## Build

```bash
cd cmd/waf-efficacy
go build -o waf-efficacy.exe
```

Requires Go 1.24+.

## Dataset setup

See [`Data/README.md`](Data/README.md) for download instructions and JSON schema.

Quick start:
```bash
wget https://downloads.openappsec.io/waf-comparison-project/legitimate.zip
unzip legitimate.zip -d Data/
```

## Modes

| Flag | Mode | Dataset used | Metric |
|------|------|-------------|--------|
| `-fp-only` | False Positive | `Data/Legitimate/` | FP rate — how often legitimate traffic is blocked |
| `-tp-only` | True Positive | `Data/Malicious/` | Bypass rate — how often attacks get through |
| _(default)_ | Mixed | Both | Both metrics |

## Usage

### False Positive (primary use)

```bash
.\waf-efficacy.exe \
  -u https://your-waf.site \
  -legitimate Data\Legitimate \
  -o out \
  -fp-only \
  -blocked-status 4** \
  -exclude-blocked-status 400,416 \
  -workers 20 \
  -timeout 10
```

Output written to `out\fp_results.csv`. FP rate printed to console.

### Dump non-403 4xx (investigate unexpected blocks)

```bash
.\waf-efficacy.exe \
  -u https://your-waf.site \
  -legitimate Data\Legitimate \
  -fp-only \
  -blocked-status 4** \
  -exclude-blocked-status 400,416 \
  -dump-status 4** \
  -exclude-dump-status 403 \
  -dump-file stats\fp_4xx.log
```

## Detection

At least one of `-blocked-status` or `-trace-headers` is required.

### Layer 1 — Status code (`-blocked-status`)

```
-blocked-status 403
-blocked-status 4**                  # any 4xx
-blocked-status 4** -exclude-blocked-status 400,416
```

Pattern syntax: exact code (`403`), prefix wildcard (`4**`, `40*`, `4xx`), comma-separated.

### Layer 2 — Trace header (`-trace-headers`)

If a response carries the specified header, the request is treated as **passed through** (not blocked).

```
-trace-headers X-Trace-Proxy:apache
-trace-headers X-Trace-Proxy:*      # any value
```

### Combined

When both layers are active: **blocked = status matches Layer 1 AND trace header absent.**

## All flags

| Flag | Default | Description |
|------|---------|-------------|
| `-u` | — | WAF base URL (required) |
| `-legitimate` | `Data/Legitimate` | Path to legitimate dataset directory |
| `-malicious` | `Data/Malicious` | Path to malicious dataset directory |
| `-o` | `.` | Output directory for CSV results |
| `-fp-only` | `false` | Run False Positive test only |
| `-tp-only` | `false` | Run True Positive test only |
| `-blocked-status` | — | Status patterns treated as blocked (required unless `-trace-headers` set) |
| `-exclude-blocked-status` | — | Subtract from `-blocked-status` set |
| `-trace-headers` | — | `header:value` pairs indicating pass-through (layer 2) |
| `-workers` | `10` | Number of concurrent HTTP workers |
| `-timeout` | `5` | Per-request timeout in seconds |
| `-strip-headers` | — | Headers to remove before sending (e.g. `host,content-length,sec-*`). Supports `*` suffix wildcard. |
| `-sanitize-url` | `true` | Percent-encode bare absolute URLs after `?` in query strings |
| `-dump-status` | — | Status patterns whose raw requests are saved to file |
| `-exclude-dump-status` | — | Subtract from `-dump-status` set |
| `-dump-file` | `dumped_requests.log` | Destination for dumped requests |
| `-log-level` | `silent` | `silent \| error \| info \| debug` |

## Output (CSV)

Written to the `-o` directory as `fp_results.csv`, `tp_results.csv`, or `mixed_results.csv`.

```
test_file, requests_fired, prevented, bypassed, errored, status_codes
```

- `test_file`: source JSON filename (dataset name).
- `prevented`: requests where the WAF was judged to have blocked (FP in FP mode, TP in TP mode).
- `bypassed`: requests not blocked.
- `status_codes`: aggregated `status_code:count` map.

Console summary prints False Positive Rate (FP mode), Bypass Rate (TP mode), or both (Mixed).

## Notes on `-strip-headers`

Legitimate traffic datasets are captured from real browsers and often contain headers that conflict with the HTTP client (e.g. `Host`, `Content-Length`, `Transfer-Encoding`, `Connection`, `Sec-Fetch-*`). Use `-strip-headers` to remove these before replay:

```bash
-strip-headers host,content-length,transfer-encoding,connection,sec-*
```

The `*` suffix strips all headers whose name starts with the given prefix (case-insensitive).
