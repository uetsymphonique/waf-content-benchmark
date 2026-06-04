# customizednuclei

A heavily modified [Nuclei](https://github.com/projectdiscovery/nuclei) SDK runner purpose-built for WAF efficacy measurement. Unlike the standard Nuclei tool (which stops at the first vulnerability match), this runner fires **every HTTP request in every template** and measures how many the WAF blocked vs. let through.

## Build

```bash
go build -o nuclei-waf.exe ./cmd
```

Requires Go 1.24+.

## Modes

Two modes serve two different template sources:

| Mode | Flag | Template source | Blocked = |
|------|------|-----------------|-----------|
| CVE | `-mode cve` | `nuclei-templates/http/cves/` | WAF blocks any request in the template |
| Fuzz | `-mode fuzz` | `fuzz-owasp-top10/templates/` | WAF blocks the individual payload request |

### CVE mode
Template-centric. One CSV row per template. A template is "Prevented" if the WAF blocked at least one of its requests.

```bash
.\nuclei-waf.exe \
  -template ..\nuclei-templates\http\cves \
  -target http://your-waf.site \
  -mode cve \
  -blocked-status 403 \
  -output cve_results.csv \
  -c 10
```

Filter by year or range:
```bash
.\nuclei-waf.exe -template ..\nuclei-templates\http\cves -cve 2021-2023 -target http://your-waf.site -mode cve -blocked-status 403 -output cve_results.csv
```

### Fuzz mode
Request-centric. One CSV row per template, but `prevented_count` and `bypassed_count` reflect individual payload outcomes. All concurrency is allocated to payload threads (1 template worker) to prevent starvation across templates with unequal payload counts.

```bash
.\nuclei-waf.exe \
  -template ..\fuzz-owasp-top10\templates \
  -target http://your-waf.site \
  -mode fuzz \
  -blocked-status 403 \
  -output fuzz_results.csv \
  -c 25
```

Filter by vulnerability category (filename prefix):
```bash
.\nuclei-waf.exe -template ..\fuzz-owasp-top10\templates -vuln sqli,xss -target http://your-waf.site -mode fuzz -blocked-status 403 -output fuzz_results.csv
```

## Detection

At least one of `-blocked-status` or `-trace-headers` is required.

### Layer 1 — Status code (`-blocked-status`)

```
-blocked-status 403
-blocked-status 4**                  # any 4xx
-blocked-status 403,40*              # 403 plus any 40x
-exclude-blocked-status 400,416      # subtract from the blocked set
```

Pattern syntax: exact code (`403`), prefix wildcard (`4**`, `40*`, `4xx`), comma-separated.

### Layer 2 — Trace header (`-trace-headers`)

For setups where the WAF forwards blocked requests to a backend that adds a marker header. If a response carries the trace header, the request is treated as **passed through** (not blocked), regardless of status code.

```
-trace-headers X-Trace-Proxy:apache
-trace-headers X-Trace-Proxy:*          # any value
-trace-headers X-Waf:bypass,X-Cdn:hit  # multiple
```

### Combined

When both layers are active: **blocked = status matches Layer 1 AND trace header absent.**

## All flags

| Flag | Default | Description |
|------|---------|-------------|
| `-template` | — | Template file or directory (required) |
| `-target` | — | Target URL (required) |
| `-mode` | `cve` | `cve` or `fuzz` |
| `-blocked-status` | — | Status patterns treated as blocked (required unless `-trace-headers` set) |
| `-exclude-blocked-status` | — | Subtract from `-blocked-status` set |
| `-trace-headers` | — | `header:value` pairs indicating pass-through (layer 2) |
| `-c` | `5` | Concurrency — template workers (cve) or payload threads (fuzz) |
| `-output` | `results.csv` | CSV output path |
| `-cve` | — | Filter `nuclei-templates/` by year/range (e.g. `2021-2023`) |
| `-vuln` | — | Filter templates by filename prefix (e.g. `sqli,xss`) |
| `-inject-id` | `false` | Prepend template ID to request paths for WAF log grepping |
| `-no-preprocess` | `false` | Skip preprocessing; pass raw templates to Nuclei |
| `-dump-status` | — | Status patterns whose raw requests are saved to file |
| `-exclude-dump-status` | — | Subtract from `-dump-status` set |
| `-dump-file` | `dumped_requests.log` | Destination for dumped requests |
| `-log-level` | `info` | `fatal \| silent \| error \| info \| warning \| debug \| verbose` |

## Output (CSV)

```
template_id, template_file, severity, requests_defined, requests_fired, prevented_count, bypassed_count, errored_count, status_codes
```

When `-trace-headers` is active, three extra columns are appended:

```
..., trace_header_spec, trace_matched_count, trace_unmatched_count
```

- `requests_defined`: number of HTTP request blocks declared in the template.
- `requests_fired`: actual requests sent (may be lower if WAF blocks a multi-step chain early).
- `prevented_count` / `bypassed_count`: tallied per the active detection layer(s).
- `status_codes`: aggregated map of `status_code:count` pairs seen during the run.

## Preprocessors block (fuzz templates)

Fuzz templates in `fuzz-owasp-top10/` use a non-standard `preprocessors:` YAML block to generate derived wordlists at runtime. This block is consumed and stripped before Nuclei parses the template.

```yaml
preprocessors:
  - type: template
    generator:
      - replace("{{payload}}", "<script>", "<ScRiPt>")
      - replace("{{payload}}", "'", "%27")
```

Each `replace(...)` rule scans the source payload file and emits transformed lines. See [`docs/applied_preprocess.md`](docs/applied_preprocess.md) for the full pipeline.

## Further reading

- [`docs/applied_preprocess.md`](docs/applied_preprocess.md) — Full preprocessing pipeline (10+ steps, why each exists).
- [`docs/concurrency_and_oom_prevention.md`](docs/concurrency_and_oom_prevention.md) — Worker pool architecture and OOM prevention design.
