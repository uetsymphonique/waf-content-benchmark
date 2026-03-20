# Template Preprocessing Pipeline

Each Nuclei template is preprocessed into a temporary copy before execution.
The original file is never modified. After execution the temp file is deleted.

The goal is to maximise the number of HTTP requests actually fired regardless
of whether the target is vulnerable, so every request reaches the WAF for
inspection, while simultaneously ensuring memory efficiency and SDK stability.

---

## Pipeline Steps

### Step 1 — Skip Non-HTTP Templates

Templates that have no `http:` block (e.g. `javascript:`, `dns:`, `network:`)
are skipped. They are counted in the *skipped* stat and do not produce a CSV row.

---

### Step 2 — Remove `flow:`

The top-level `flow:` key is deleted. In the original template, `flow:` controls conditional or looped execution of request blocks. Removing it makes Nuclei execute
every request block unconditionally in sequence.

---

### Step 3 — Force Exhaustive Request Execution

Applied to every HTTP block:
- Set `stop-at-first-match: false` to prevent Nuclei from stopping after the first match.
- Set `skip-variables-check: true` to bypass strict validation.
- `matchers-condition` keys are removed.

---

### Step 4 — Replace Matchers with `false` Catch-All

All matchers are replaced with a single catch-all matcher that always returns `false`:

```yaml
matchers:
  - type: dsl
    dsl:
      - "false"
```

**Why `false`?**
If a matcher returns `true`, Nuclei wraps the HTTP response inside a `ResultEvent` and appends it to an internal array in `ScanContext`. During aggressive fuzzing (e.g. 100,000 requests per template), this behaviour causes a massive Out-Of-Memory (OOM) leak. By forcing the matcher to return `false`, Nuclei actively clears memory after firing the request. Our custom Runner tracks the HTTP status regardless, ensuring accurate execution tracking without memory explosions.

---

### Step 5 — Inject Extractor Placeholders

Scans all HTTP blocks for extractors with `internal: true`. For each such
extractor, a placeholder static string is injected into the top-level `variables:` block (e.g., `token`, `session`, `cookie` -> `a1b2c3...`).

When a WAF blocks an earlier request and extraction fails, Nuclei falls back
to the static placeholder, keeping downstream request URLs and bodies well-formed.

---

### Step 5.1 — Violently Remove Extractors

All `extractors` are strictly deleted from every HTTP block. If left intact, an overly broad regex might accidentally extract HTML tags from a WAF 403 page and inject garbage into downstream raw requests, crashing the Go HTML/HTTP parser.

---

### Step 5.5a to 5.5e — Variable Resolution Hardening

These are distinct sub-steps applied to the `variables:` block to stabilise Nuclei's Single-Pass Evaluator:
- **5.5a (Self-referential)**: Variables whose value equals `{{self}}` (e.g. `path: "{{path}}"`) are deleted, avoiding circular evaluation limits.
- **5.5b (Flatten References)**: Inline `{{otherVar}}` dependencies linearly so that alphabetically loaded YAML variables don't fail cross-resolution.
- **5.5c (Resolve RandVars)**: Resolve `{{randstr}}` and `{{rand_base(N)}}` directly into static strings upfront so downstream DSL function calls have a reliable argument.
- **5.5d (Evaluate Simple DSL)**: Statically evaluate single-argument DSL wrappers (e.g. `base64(marker)`) because the argument is now a known string. 
- **5.5e (Hex Decode Context)**: Provide valid hex fallbacks for unresolved variables heavily used inside `hex_decode()` calls to prevent crash-outs.

---

### Step 6 — Fix `base64_decode()` Placeholder Context

Scans every `raw:` string for `base64_decode` / `base64` functions and injects base64-safe placeholders for unresolved variables. This stops the DSL evaluator from outputting stray binary characters inside URLs.

---

### Step 7 — Replace `{{interactsh-url}}`

All occurrences of `{{interactsh-url}}` are hardcoded to the static domain `oast.placeholder.example.com`.
Without an active Interactsh client, Nuclei refuses to fire any request containing this variable.

---

### Step 8 — Inject Undefined Variable Placeholders

Scans every `raw:` request block (Headers, Paths, Bodies) for `{{var}}` injections that are still completely undefined. It injects a sensible string literal so the request can actually formulate and fire over the wire.

---

### Step 9 — Split Multi-HTTP Raws

Splits any `raw:` entry that improperly packs multiple distinct bare-metal HTTP requests into a single string (using `\n\n\n` dividers). This avoids catastrophic net/http pipeline crashes.

---

### Step 9.5 — Fix Missing Body Separators

Inserts a blank line (CRLF) between HTTP headers and the body if the template author forgot it, preventing Go's builtin `net/http` stack from failing the request entirely before reaching the WAF.

---

### Step 10 — Resolve Payload Paths

Resolves relative payload paths (typically used in fuzzing) to their absolute paths matching the original template's directory. This ensures the temporary executing YAML file can still locate local resources.
