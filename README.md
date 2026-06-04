# WAF Content Benchmark (WCB)

WCB measures Web Application Firewall efficacy using two independent tools, each serving a distinct role:

| Tool | Purpose | Template/Data source |
|------|---------|----------------------|
| `customizednuclei` | Attack coverage — bypass/prevent ratio | `nuclei-templates/` (CVE mode) · `fuzz-owasp-top10/` (Fuzz mode) |
| `waf-efficacy-tool` | False Positive rate — legitimate traffic | `waf-efficacy-tool/Data/Legitimate/` (see setup below) |

---

## Tool 1 — Customized Nuclei (Attack Coverage)

A heavily modified Nuclei SDK runner designed for WAF testing rather than vulnerability detection. It fires HTTP requests and measures how many were blocked (Prevented) vs. passed through (Bypassed) by the WAF.

Two modes correspond to two different template sources:

| Mode | Flag | Template source | Measurement unit |
|------|------|-----------------|-----------------|
| CVE | `-mode cve` | `nuclei-templates/http/cves/` | Per-template (1 block = prevented) |
| Fuzz | `-mode fuzz` | `fuzz-owasp-top10/templates/` | Per-request/payload |

### Key features
- Preprocessing pipeline: rewrites templates before execution so every request fires regardless of WAF response (no Interactsh required, no OOM on large payload sets).
- Custom `preprocessors` block in fuzz templates to derive transformed wordlists (replace, encode, obfuscate).
- Two detection layers: status-code patterns (`-blocked-status`) and trace-header pass-through (`-trace-headers`).
- `-inject-id`: prepends template ID to request paths for WAF log grepping.
- `-dump-status` / `-dump-file`: save raw requests matching a status filter.

### Build
```bash
cd customizednuclei
go build -o nuclei-waf.exe ./cmd
```

### CVE Coverage Mode
Tests how many published CVE exploits the WAF blocks. Templates come from the `nuclei-templates/` submodule.

```bash
# All CVEs
.\nuclei-waf.exe -template ..\nuclei-templates\http\cves -target http://your-waf.site -mode cve -blocked-status 403 -output cve_results.csv -c 10

# Specific year range
.\nuclei-waf.exe -template ..\nuclei-templates\http\cves -cve 2021-2023 -target http://your-waf.site -mode cve -blocked-status 403,40* -output cve_results.csv
```

### OWASP Fuzz Mode
Tests payload-level coverage using the curated `fuzz-owasp-top10/` templates. Each template drives thousands of payloads; concurrency (`-c`) is allocated to payload threads.

```bash
# All OWASP categories
.\nuclei-waf.exe -template ..\fuzz-owasp-top10\templates -target http://your-waf.site -mode fuzz -blocked-status 403 -output fuzz_results.csv -c 25

# Specific vulnerability categories
.\nuclei-waf.exe -template ..\fuzz-owasp-top10\templates -vuln sqli,xss -target http://your-waf.site -mode fuzz -blocked-status 403 -output fuzz_results.csv -c 25
```

### Detection flags
At least one of `-blocked-status` or `-trace-headers` is required:

- `-blocked-status <patterns>`: status codes treated as "blocked" (e.g. `403`, `4**`, `40*`).
- `-exclude-blocked-status <patterns>`: subtract codes from the blocked set (e.g. `400,416`).
- `-trace-headers <header:value,...>`: if a response carries this header, the request reached the backend (not blocked). Use `*` for any value (e.g. `X-Trace-Proxy:*`).
- Combined: blocked = matches `-blocked-status` AND trace header absent.

### Additional flags
- `-c <int>`: concurrency (default: `5`). Behaviour differs by mode:
  - `fuzz` — all threads are allocated to **payload concurrency** (1 template worker); prevents starvation when templates have unequal payload counts.
  - `cve` — threads are allocated to **template workers** (parallel template execution); each worker gets `c/N` payload threads.
- `-cve <years>`: filter `nuclei-templates/` subfolders by year or range (e.g. `2023`, `2021-2023`).
- `-vuln <prefixes>`: filter fuzz templates by filename prefix (e.g. `sqli,xss,rce`).
- `-no-preprocess`: skip preprocessing — passes templates raw to Nuclei (backend simulation).
- `-inject-id`: prepend template ID to request paths for WAF log grepping (default: off).
- `-log-level <level>`: logging verbosity — `fatal | silent | error | info | warning | debug | verbose` (default: `info`). Use `debug` or `verbose` to dump raw HTTP traffic to console.
- `-output <path>`: CSV output file (default: `results.csv`).
- `-dump-status <patterns>` / `-exclude-dump-status <patterns>` / `-dump-file <path>`: capture raw requests by status code pattern; exclude patterns subtract from the dump set.

### Output (CSV)
```
template_id, template_file, severity, requests_defined, requests_fired, prevented_count, bypassed_count, errored_count, status_codes
```

---

## Tool 2 — WAF Efficacy Tool (False Positive Rate)

A standalone dataset-driven HTTP client pulled from an external repo. It replays captured web traffic against the WAF and measures the False Positive rate — how often the WAF incorrectly blocks legitimate requests.

> **Scope in this repo:** The tool supports both TP (Malicious) and FP (Legitimate) datasets, but the Malicious dataset bundled here is incomplete. **Only the FP mode is used** in this benchmark, with the Legitimate dataset described below.

### Dataset setup
Download the Legitimate traffic dataset as described in [`waf-efficacy-tool/Data/README.md`](waf-efficacy-tool/Data/README.md):

```bash
cd waf-efficacy-tool
wget https://downloads.openappsec.io/waf-comparison-project/legitimate.zip
unzip legitimate.zip -d Data/
```

### Build
```bash
cd waf-efficacy-tool\cmd\waf-efficacy
go build -o waf-efficacy.exe
```

### Run (FP testing)
```bash
.\waf-efficacy.exe -u https://your-waf.site -legitimate Data\Legitimate -o out -fp-only -blocked-status 4** -exclude-blocked-status 400,416 -workers 20 -timeout 10
```

Dump requests that received a non-403 4xx response:
```bash
.\waf-efficacy.exe -u https://your-waf.site -legitimate Data\Legitimate -fp-only -blocked-status 4** -exclude-blocked-status 400,416 -dump-status 4** -exclude-dump-status 403 -dump-file stats\fp_4xx.log
```

### Detection flags
Same logic as Tool 1: `-blocked-status`, `-exclude-blocked-status`, `-trace-headers`. At least one is required.

### Additional flags
- `-workers <int>`: number of concurrent HTTP workers (default: `10`).
- `-timeout <int>`: per-request timeout in seconds (default: `5`).
- `-log-level <level>`: logging verbosity — `silent | error | info | debug` (default: `silent`).
- `-strip-headers <names>`: remove headers before sending (e.g. `host,content-length,sec-*`). Useful when replaying captured traffic that includes reserved headers.
- `-sanitize-url`: percent-encode bare absolute URLs appearing after `?` in query strings (default: `true`).
- `-dump-status` / `-exclude-dump-status` / `-dump-file`: save raw requests by status pattern.

### Output (CSV)
```
test_file, requests_fired, prevented, bypassed, errored, status_codes
```
File written to output dir as `fp_results.csv`. Summary (False Positive Rate) printed to console.

---

## Troubleshooting

- **Memory spikes on large payload sets** — Use `-mode fuzz` (not `-mode cve`); the fuzz runner allocates all concurrency to payload threads and streams results to avoid accumulation.
- **Requests not firing for Interactsh templates** — The preprocessor replaces `{{interactsh-url}}` with a static placeholder; no Interactsh server needed.
- **Payload files not found after preprocessing** — Relative payload paths are resolved to absolute during preprocessing; verify templates and wordlists exist on disk relative to the template file.
- **Raw traffic tracing** — Use `-dump-status` + `-dump-file` in either tool to capture requests matching a status pattern.
