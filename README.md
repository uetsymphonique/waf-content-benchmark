# WAF Content Benchmark (WCB)

WCB is a high-performance evaluation system for Web Application Firewall (WAF) content filtering based on the Nuclei SDK. It is specifically optimized for large-scale payload fuzzing and security coverage benchmarking.

## Key Features (by tool)

- **Customized Nuclei (attack/bypass testing)**
  - Specialized fuzzing to measure per-request Bypass/Prevented ratios.
  - Payload Preprocessor with custom `preprocessors` block (Replace, Encode, Obfuscate) to probe normalization and decoding.
  - OOM prevention via streaming `OnResult` callback (handles millions of payloads safely).
  - Dual modes:
    - `-mode cve`: Template-centric (vulnerability-level coverage).
    - `-mode fuzz`: Request-centric (payload-level efficacy).
  - Filtering & exporting:
    - `-cve` filter by CVE year/range.
    - `-vuln` filter by vuln prefixes (e.g., `sqli,xss`).
    - `-dump-status` to export raw HTTP requests matching status patterns.

- **WAF Efficacy Tool (false-positive testing with legitimate traffic)**
  - Consumes a Legitimate traffic dataset (JSON) to measure False Positive rate.
  - Also supports Malicious datasets for TP, and a Mixed mode; in this repo it is primarily used for FP assessment.
  - High-throughput worker pool with streaming JSON loader (low memory usage).
  - CSV outputs and console summaries for FP/TP metrics; optional raw request dumping by status with include/exclude patterns.

## Project Structure

- `customizednuclei/`: Nuclei-based WAF fuzzer/benchmark (core runner + preprocessing pipeline).
- `customizednuclei/docs/`: Concurrency & OOM prevention, preprocessing pipeline details.
- `fuzz-owasp-top10/`: Curated fuzz templates and large payload wordlists (request-centric testing).
- `nuclei-templates/`: Standard CVE exploitation templates (vulnerability-centric testing).
- `waf-efficacy-tool/`: Dataset-driven WAF tester (direct HTTP client) using JSON payload sets — in this repo primarily used for FP testing with a Legitimate traffic dataset.
- `Data/Malicious`, `Data/Legitimate` (example paths): JSON datasets for `waf-efficacy-tool`.

## Quick Start

### 1. Build the Nuclei-based tool (customizednuclei)
```bash
cd customizednuclei
go build -o nuclei-waf.exe ./cmd
```

### 2. Run Benchmark (Fuzzing Mode)
```bash
.\nuclei-waf.exe -template ..\fuzz-owasp-top10\templates -target http://your-waf.site -mode fuzz -output result.csv -c 25
```

### 3. Check CVE Coverage (CVE Mode)
```bash
.\nuclei-waf.exe -template ..\nuclei-templates\http\cves -cve 2021-2022 -target http://your-waf.site -mode cve -output cve_test.csv
```

### 4. Specialized Filtering
```bash
.\nuclei-waf.exe -template ..\fuzz-owasp-top10\templates -vuln sqli,xss -target http://your-waf.site -mode fuzz
```

---

## Alternative: Dataset-Driven Tester (waf-efficacy-tool)

Primarily for False-Positive testing in this repo, leveraging a Legitimate web traffic dataset. Also supports Malicious datasets and Mixed mode when needed.

### Build
```bash
cd waf-efficacy-tool\cmd\waf-efficacy
go build -o waf-efficacy.exe
```

### Run (Mixed mode – default)
```bash
.\waf-efficacy.exe -u https://your-waf.site -malicious Data\Malicious -legitimate Data\Legitimate -o out -workers 20 -timeout 10
```

### True Positive only
```bash
.\waf-efficacy.exe -u https://your-waf.site -malicious Data\Malicious -o out -tp-only -workers 20
```

### False Positive only
```bash
.\waf-efficacy.exe -u https://your-waf.site -legitimate Data\Legitimate -o out -fp-only -workers 20
```

### Dump raw requests for certain statuses
```bash
.\waf-efficacy.exe -u https://your-waf.site -malicious Data\Malicious -dump-status 200,20*,403 -dump-file dumped_requests.log
```

Exclude specific codes from the dump (e.g., dump all 4xx except 403):
```bash
.\waf-efficacy.exe -u https://your-waf.site -legitimate Data\Legitimate -dump-status 4** -exclude-dump-status 403 -dump-file stats\cdn\cdn_fp_4xx.log
```

### Advanced flags (waf-efficacy-tool)
- `-blocked-status` / `-exclude-blocked-status`: control which status codes are treated as WAF "blocked" for TP/FP stats (e.g., `-blocked-status 4** -exclude-blocked-status 400,416`).
- `-exclude-dump-status`: exclude codes/patterns from `-dump-status` output (e.g., `-dump-status 4** -exclude-dump-status 403`).
- `-strip-headers`: remove reserved/sensitive headers before send (e.g., `-strip-headers host,content-length,transfer-encoding,connection,sec-*`).
- `-sanitize-url`: percent-encode bare absolute URL after `?` in query (default: true).

### Dataset JSON schema
Each dataset file is a JSON array of payload objects:
```json
[
  {
    "method": "GET",
    "url": "/path?param=...",
    "headers": {"Header-Name": "Value"},
    "data": "optional-body"
  }
]
```
Notes:
- `url` is relative; the runner automatically prefixes a per-file identifier for log grepping.
- `headers` optional; `data` optional (used for POST/PUT, etc.).

## Outputs

- Customized Nuclei runner (CSV):
  - Columns: `template_id, template_file, severity, requests_defined, requests_fired, prevented_count, bypassed_count, errored_count, status_codes`
  - Supports `-dump-status` to save raw requests matching code filters (e.g., `200,20*,4**`).

- WAF Efficacy Tool (CSV):
  - Files: `tp_results.csv`, `fp_results.csv`, or `mixed_results.csv` in output dir.
  - Columns: `test_file, requests_fired, prevented, bypassed, errored, status_codes`
  - Summary printed to console: Bypass Rate (TP), False Positive Rate (FP), or both (Mixed).

## Modes & Detection Semantics

- `-mode cve` (customizednuclei): Template-centric. A block is considered prevented if WAF blocks any request in the template.
- `-mode fuzz` (customizednuclei): Request-centric. Counts per-payload bypass vs. prevent.
- `waf-efficacy-tool`: Defines blocked as HTTP 4xx by default; computes TP/FP depending on dataset type and selected mode.

## Troubleshooting

- Memory usage spikes when fuzzing large payload sets
  - Use `-mode fuzz` with appropriate `-c` to shift concurrency to payload threads; the runner streams results to avoid OOM.
- Requests not firing for templates requiring Interactsh
  - The preprocessor replaces `{{interactsh-url}}` with a static placeholder to force request emission; ensure your target accepts such requests or exclude those templates.
- Payload files not found after preprocessing
  - Relative paths are resolved to absolute during preprocessing; verify templates and wordlists exist on disk.
- Need to trace per-request raw traffic
  - Use `-dump-status` and `-dump-file` in either tool to capture raw requests matching status filters.

---
WCB is a highly customized implementation of the Nuclei SDK designed for rigorous security gateway and WAF efficacy measurement.
