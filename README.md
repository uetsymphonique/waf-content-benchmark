# WAF Content Benchmark (WCB)

WCB is a high-performance evaluation system for Web Application Firewall (WAF) content filtering based on the Nuclei SDK. It is specifically optimized for large-scale payload fuzzing and security coverage benchmarking.

## Key Features

- **Specialized Fuzzing Mode**: Unlike standard Nuclei (focused on vulnerability identification), WCB measures independent "Bypass/Prevented" ratios for each request.
- **Payload Preprocessor**: Supports a custom `preprocessors` block for automated attack variants (Replace, Encode, Obfuscate) to evaluate WAF normalization capabilities.
- **OOM Prevention (Streaming)**: Utilizes a result streaming mechanism via Nuclei's `OnResult` callback instead of batching results in memory. This allows for millions of payloads without taxing system RAM.
- **Dual-Mode Evaluation**:
    - `-mode cve`: Template-centric metrics (Vulnerability-level coverage).
    - `-mode fuzz`: Request-centric metrics (Payload-level efficacy).
- **Filtering & Exporting**:
    - `-cve`: Filter top-level folders by CVE year/range (e.g., `2023,2024-2025`).
    - `-vuln`: Filter templates by filename prefix (e.g., `sqli,xss`).
    - `-dump-status`: Export raw HTTP requests matching specific status codes or wildcards (e.g., `200,20*,4**`) to a file for bypass analysis.

## Project Structure

- `customizednuclei/`: Core runner implementation in Go.
- `fuzz-owasp-top10/`: Curated collection of benchmarking templates and large-scale payloads.
- `nuclei-templates/`: Standard CVE exploitation templates.
- `customizednuclei/docs/`: Technical documentation regarding concurrency architecture and preprocessing logic.

## Quick Start

### 1. Build the tool
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

## Output Schema
The CSV output is compatible with both execution modes using a unified schema:
`template_id, template_file, severity, requests_defined, requests_fired, prevented_count, bypassed_count, errored_count, status_codes`

---
WCB is a highly customized implementation of the Nuclei SDK designed for rigorous security gateway and WAF efficacy measurement.
