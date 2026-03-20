# Template Preprocessing Pipeline

Each Nuclei template is preprocessed into a temporary copy before execution.
The original file is never modified. After execution the temp file is deleted.

The goal is to maximise the number of HTTP requests actually fired regardless
of whether the target is vulnerable, so every request reaches the WAF for
inspection.

---

## Pipeline Steps

### Step 1 — Skip Non-HTTP Templates

Templates that have no `http:` block (e.g. `javascript:`, `dns:`, `network:`)
are skipped. They are counted in the *skipped* stat and do not produce a CSV
row.

---

### Step 2 — Remove `flow:`

The top-level `flow:` key is deleted. In the original template, `flow:`
controls conditional or looped execution of request blocks (e.g.
`if (template.path != null) { http(1) }`). Removing it makes Nuclei execute
every request block unconditionally in sequence.

---

### Step 3 — Set `stop-at-first-match: false`

Applied to every HTTP block. Prevents Nuclei from stopping after the first
matching response — all requests in a block are always sent.

---

### Step 4 — Replace Matchers with Catch-All

All `matchers` and `matchers-condition` keys are replaced with a single
catch-all matcher:

```yaml
matchers:
  - type: dsl
    name: catch-all
    dsl:
      - "true"
```

This ensures every request produces a `ResultEvent` (and therefore increments
`requests_fired`) regardless of HTTP status or response body content.
The tool is measuring *coverage*, not vulnerability detection.

---

### Step 5 — Inject Extractor Placeholders

Scans all HTTP blocks for extractors with `internal: true`.  For each such
extractor a placeholder value is injected into the top-level `variables:`
block using rule-based generation (`placeholder.go`):

| Extractor hint | Generated value |
|----------------|-----------------|
| name contains `token`, `session`, `cookie` | `a1b2c3d4e5f67890abcdef1234567890` |
| name contains `nonce`, `csrf` | `abcdefghij1234567890abcdef123456` |
| name contains `access_token`, `jwt` | fake JWT string |
| name contains `uuid`, `guid` | `550e8400-e29b-41d4-a716-446655440000` |
| name contains `username`, `user` | `admin` |
| name contains `password`, `pass` | `Password123!` |
| name contains `email`, `mail` | `test@example.com` |
| fallback | `placeholder-<name>` |

When a WAF blocks an earlier request and extraction fails, Nuclei falls back
to the static placeholder, keeping downstream request URLs and bodies
well-formed.

---

### Step 5.5a — Remove Self-Referential Variables

Variables whose value equals `{{self}}` (e.g. `path: "{{path}}"`) are deleted
from the `variables:` block.  Such entries are typically CLI input placeholders
whose author expected users to supply a value via `-var`.  Leaving them causes
a circular evaluation error.  After deletion, Nuclei falls back to the
matching DSL built-in (e.g. the built-in `path` variable returns the URL path
component of the target).

---

### Step 5.5b — Flatten Inter-Variable References

`yaml.v3` marshals map keys in alphabetical order.  Nuclei's single-pass
variable evaluator processes keys in file order, so a variable that appears
earlier alphabetically (e.g. `cmd`) may be evaluated before the variable it
references (e.g. `useragent`), leaving `{{useragent}}` unresolved in the final
request.

This step iterates over the `variables:` block up to four times, inlining
every `{{otherVar}}` reference that is a pure identifier (no function calls,
no operators) and whose target key also exists in the same `variables:` block.
Only identifiers are substituted; DSL function calls such as `{{rand_base(6)}}`
are left untouched.

**Example** (`CVE-2021-1497`):

```
# Before
useragent: '{{rand_base(6)}}'
cmd:       'curl http://... -H "User-Agent: {{useragent}}"'

# After flatten (cmd resolved, useragent removed from cmd's dependency)
cmd:       'curl http://... -H "User-Agent: {{rand_base(6)}}"'
```

---

### Step 6 — Fix `base64_decode()` Placeholder Context

Scans every `raw:` string for `base64_decode(varname)` and `base64(varname)`
patterns.  For each referenced variable:

1. If the variable has no value yet — inject a base64-safe placeholder.
2. If the current value is valid Base64 Standard Encoding but decodes to
   non-printable bytes (e.g. a hex token like `a1b2c3d4...` decodes to binary)
   — replace it with `base64(printable_placeholder)`.
3. If the current value is not valid Base64 at all — same replacement.

This prevents Nuclei's DSL evaluator from producing binary data inside URLs or
HTTP bodies, which causes `net/http: can't write control character in
Request.URL`.

---

### Step 7 — Replace `{{interactsh-url}}`

All occurrences of `{{interactsh-url}}` in `raw:` strings and `variables:`
values are replaced with the static domain `oast.placeholder.example.com`.

Without an active Interactsh client the Nuclei SDK leaves `{{interactsh-url}}`
unresolved and refuses to fire the request.

---

### Step 8 — Inject Undefined Variable Placeholders

Scans every `raw:` string and every `path:` list entry for `{{...}}`
expressions.  For each expression:

1. String literals inside the expression (single- or double-quoted) are
   stripped first to avoid treating URL components inside DSL arguments as
   variable names (e.g. `base64('http://example.com')` should not yield `http`
   or `example` as variable names).
2. Remaining lowercase identifiers are checked against the Nuclei built-in
   set (DSL functions, runtime variables) and against already-defined variables
   and extractor names.
3. Any identifier that is not a built-in and not already defined is injected
   into `variables:` with a rule-based placeholder value.

This covers cases such as `{{username}}` / `{{password}}` that templates
expect to be supplied on the CLI via `-var`.

---

### Step 9 — Split Multi-Request `raw:` Entries

Some templates concatenate multiple complete HTTP requests into a single
`raw:` list entry (e.g. three `GET … HTTP/1.1` lines in one YAML block scalar).
Nuclei parses such an entry as a single malformed request and fires nothing.

This step detects the pattern and splits the entry into separate `raw:` list
items, each containing exactly one HTTP request.

**Split condition**: a new HTTP method line (`GET`, `POST`, etc.) is only
treated as a split point when the text that precedes it in the same entry
already contains at least one ` HTTP/1` or ` HTTP/2` version token.  This
prevents Nuclei per-request annotations (`@timeout: Xs`) from being split away
from their actual request line.

---

### Step 9.5 — Insert Missing Header/Body Separator

Some templates omit the mandatory blank line between the HTTP header section
and the body in a `raw:` entry.  Go's `net/http` then treats the body line as
a header field name and rejects the request with `invalid header field name`.

For each `raw:` entry this step walks the lines after the request line.  When
it encounters the first line that is neither a valid header (`Field-Name: …`)
nor a Nuclei annotation (`@timeout`, `@once`, …), and no blank line has yet
appeared, it inserts one blank line immediately before that body line.

---

### Step 10 — Resolve Payload Paths

Relative file paths referenced in `variables:` values (strings ending in
`.txt` or containing `payloads`) and in `http[].payloads:` blocks are
converted to absolute paths based on the original template's directory.

This is necessary because the modified template is written to a system temp
directory; relative paths would no longer resolve correctly from that location.

---

## Output

After all steps the modified document is marshalled back to YAML and written
to a unique temp file (e.g. `nuclei-waf-12345.yaml` in the OS temp dir).
The original template file is untouched. The temp file is deleted by a
deferred cleanup call after the template has been executed.
