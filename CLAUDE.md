# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Two independent Go modules — see README.md for usage, flags, and examples.

## Build

```bash
cd customizednuclei && go build -o nuclei-waf.exe ./cmd
cd waf-efficacy-tool/cmd/waf-efficacy && go build -o waf-efficacy.exe
```

No tests in either module. Use `go vet ./...` inside each module directory.

## Architecture — customizednuclei

**Entry point:** `cmd/main.go` → `internal/template/collect.go` → `internal/runner/runner.go` → `internal/preprocess/preprocess.go`

**Execution flow:**
1. `template.Collect()` walks the template directory, applying `-cve` (top-level folder name filter) and `-vuln` (filename prefix filter).
2. Template paths are pushed into a buffered channel; N goroutines consume them.
3. Each worker owns its own `runner.Runner` + `nuclei.NucleiEngine` — no shared engine state.
4. Per template: `runner.Execute()` → `preprocess.PreprocessTemplate()` (writes temp file) → `templates.Parse()` → `tmpl.Executer.ExecuteWithResults(scanCtx)`.
5. Results stream through `scanCtx.OnResult` — only the HTTP status code integer is retained (O(c) memory regardless of payload volume).
6. One CSV row per template written under a shared mutex; flushed every 50 rows.

**Concurrency split by mode** (`cmd/main.go`):
- `fuzz`: 1 worker, all `-c` goes to `TemplatePayloadConcurrency`. Prevents starvation when templates have vastly different payload counts.
- `cve`: N workers (up to `-c`), `payloadConcurrency = c/N`. Maximises parallelism for thin single-request templates.

**Detection logic** (`cmd/main.go`, `runner.Execute()`):
- Layer 1 (`-blocked-status`): status code pattern matching.
- Layer 2 (`-trace-headers`): if a response header matches, the request reached the backend (not blocked).
- Combined: blocked = Layer 1 matches AND Layer 2 absent.

**OOM prevention:** Preprocessed templates get `matchers: [{type: dsl, dsl: ["false"]}]`. Nuclei registers zero matches → never appends `ResultEvent` structs to `scan_context`. The `OnResult` hook fires before GC and extracts only the status code.

### Preprocessing Pipeline (`internal/preprocess/preprocess.go`)

Original template files are never modified. Each is rewritten to a temp file, executed, then deleted.

Key transforms in order:
1. Skip templates with no `http:` block.
2. Inject template ID into request paths (`-inject-id`, for WAF log grepping).
3. Delete `flow:` so all HTTP blocks run unconditionally.
4. Set `stop-at-first-match: false`; replace all matchers with `dsl: ["false"]` catch-all; delete `extractors`.
5. Inject static placeholder values for extractor output variables so downstream requests stay well-formed when the WAF blocks an earlier step.
6. Variable resolution hardening (5.5a–5.5e): flatten inter-variable refs, resolve `{{randstr}}`, statically evaluate simple DSL calls (`base64`, `md5`, etc.), fix `hex_decode`/`base64_decode` argument contexts.
7. Replace `{{interactsh-url}}` → `oast.placeholder.example.com`.
8. Inject string placeholders for any still-undefined `{{var}}` in `raw:` blocks.
9. Split multi-HTTP `raw:` strings; insert missing CRLF header/body separators.
10. Resolve relative payload paths to absolute; evaluate and strip custom `preprocessors` blocks.

**Custom `preprocessors` block** (`preprocess_payloads.go`): Non-standard YAML extension. `type: template` with `generator` entries using `replace("{{var}}", "search", "replacement")` to produce derived wordlists from existing payload files at runtime. Stripped before Nuclei parses the template.

## Architecture — waf-efficacy-tool

**Entry point:** `cmd/waf-efficacy/main.go` → `pkg/efficacy/`

Components: `ParseFlags` → `NewHTTPClient` + `NewResultAnalyzer` → `NewRunner` → `runner.Run()`.

`runner.Run()` dispatches to `runFPTest` (or `runTPTest`/both for Mixed). Each spawns:
- A streaming loader (`PayloadLoader.StreamFile`) that reads JSON arrays from disk into a `chan Payload` — one file at a time, low memory.
- A worker pool consuming from a `chan job`; workers call `HTTPClient.SendRequest`, apply two-layer block detection, and send `TestResult` to a collector goroutine.
- Workers prefix payload URLs with the dataset filename (`/testName/original-url`) for WAF log traceability.

`ResultAnalyzer` accumulates results and writes `fp_results.csv` / `tp_results.csv` / `mixed_results.csv`.

## Status Code Pattern Syntax (shared by both tools)

`403` exact · `40*` prefix · `4**` / `4xx` broader prefix · comma-separated lists · exclusion flags subtract from the include set.
