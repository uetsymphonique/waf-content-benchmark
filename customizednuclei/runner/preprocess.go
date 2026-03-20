package runner

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// ── Regexes used by the new preprocessing passes ────────────────────────────

// reAllTemplateExpr captures the content of every {{ … }} block.
var reAllTemplateExpr = regexp.MustCompile(`\{\{([^}]+)\}\}`)

// reLowercaseIdent matches bare lowercase identifiers inside a DSL expression.
// Uppercase identifiers (Hostname, BaseURL …) are Nuclei built-ins and are
// naturally excluded because they start with a capital letter.
var reLowercaseIdent = regexp.MustCompile(`\b([a-z_][a-z0-9_]*)\b`)

// reStringLiteral matches single- or double-quoted string literals inside a
// DSL expression so they can be stripped before identifier extraction.
var reStringLiteral = regexp.MustCompile(`'[^']*'|"[^"]*"`)

// reSimpleVarName matches a template expression that is PURELY a lowercase
// identifier (no function calls, no operators).
var reSimpleVarName = regexp.MustCompile(`^\s*[a-z_][a-z0-9_]*\s*$`)

// reBase64VarCtx detects a variable name used as the first argument of
// base64() or base64_decode(), e.g. base64_decode(httoken).
var reBase64VarCtx = regexp.MustCompile(`base64(?:_decode)?\(([a-zA-Z_][a-zA-Z0-9_]*)\)`)

// reHTTPRequestBoundary finds the start of a second (or later) HTTP request
// embedded inside a single raw: string entry.
var reHTTPRequestBoundary = regexp.MustCompile(
	`\n(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE) \S+ HTTP/[12]`,
)

// nucleiBuiltinSet lists lowercase DSL function names and the few lowercase
// built-in variable names that Nuclei resolves at runtime. They must never be
// injected as static placeholder values.
var nucleiBuiltinSet = map[string]bool{
	// Lowercase Nuclei runtime variables
	"ip": true, "useragent": true,
	// DSL functions
	"rand_base": true, "rand_text_alpha": true, "rand_text_alphanumeric": true,
	"rand_int": true, "rand_ip": true, "rand_char": true, "rand_text_numeric": true,
	"url_encode": true, "url_decode": true,
	"base64": true, "base64_decode": true, "base64_py": true,
	"hex_encode": true, "hex_decode": true,
	"to_lower": true, "to_upper": true, "tolower": true, "toupper": true,
	"trim": true, "trim_left": true, "trim_right": true, "trim_prefix": true,
	"trim_space": true, "trim_suffix": true, "trimprefix": true,
	"len": true, "md5": true, "sha1": true, "sha256": true, "mmh3": true,
	"html_escape": true, "html_unescape": true,
	"regex": true, "replace": true, "replace_regex": true, "reverse": true,
	"contains": true, "contains_all": true, "starts_with": true, "ends_with": true,
	"split": true, "join": true, "concat": true,
	"unix_time": true, "date_time": true,
	"zlib": true, "zlib_decode": true,
	"print_debug": true, "wait_for": true,
	// DSL literals / keywords
	"true": true, "false": true,
	// HTTP response accessor base names
	"body": true, "header": true, "all_headers": true,
	"status_code": true, "content_type": true, "content_length": true,
	"duration": true, "response_time": true,
}

// preprocessResult is returned by preprocessTemplate.
type preprocessResult struct {
	path    string // temp file path to pass to templates.Parse
	skip    bool   // true when the template has no HTTP block (e.g. javascript:/dns-only)
	cleanup func() // removes the temp file; always safe to call even when skip==true
}

// nopCleanup is a no-op cleanup used for skipped templates.
func nopCleanup() {}

// preprocessTemplate applies the WAF-testing pipeline to a single template
// file without touching the original:
//
//  1. Skip templates with no `http:` block (javascript:, dns-only, etc.)
//  2. Remove the `flow:` key so all request steps run unconditionally.
//  3. Set `stop-at-first-match: false` on every HTTP request block.
//  4. Replace all `matchers` / `matchers-condition` with a single
//     catch-all `dsl: ["true"]` — ensures every request generates a
//     ResultEvent regardless of the actual response.
//  5. Resolve relative payload file paths (in `variables:` and
//     `http[].payloads:` blocks) to absolute so the temp file location
//     does not break wordlist loading.
//
// The modified template is written to a unique temp file; caller must invoke
// result.cleanup() after execution to remove it.
func preprocessTemplate(templatePath string) (*preprocessResult, error) {
	raw, err := os.ReadFile(templatePath)
	if err != nil {
		return nil, fmt.Errorf("read template: %w", err)
	}

	var doc map[string]interface{}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse YAML %q: %w", templatePath, err)
	}

	// Step 1 — skip if there is no HTTP block.
	httpRaw, hasHTTP := doc["http"]
	if !hasHTTP {
		return &preprocessResult{skip: true, cleanup: nopCleanup}, nil
	}
	httpBlocks, ok := httpRaw.([]interface{})
	if !ok || len(httpBlocks) == 0 {
		return &preprocessResult{skip: true, cleanup: nopCleanup}, nil
	}

	// Step 2 — remove flow directive.
	delete(doc, "flow")

	// Steps 3 & 4 — process each HTTP request block.
	for _, block := range httpBlocks {
		m, ok := block.(map[string]interface{})
		if !ok {
			continue
		}
		m["stop-at-first-match"] = false
		delete(m, "matchers-condition")
		m["matchers"] = catchAllMatcher()
	}

	// Step 5 — inject placeholder values for all internal extractor variables
	// so downstream requests stay well-formed when WAF blocks an earlier step.
	injectExtractorPlaceholders(doc)

	// Step 5.5a — remove self-referential variables (e.g. path: "{{path}}")
	// that create circular evaluation and mask the matching Nuclei DSL built-in.
	removeSelfRefVariables(doc)

	// Step 5.5b — flatten inter-variable references in the variables: block.
	// yaml.v3 marshals keys alphabetically, so Nuclei's single-pass evaluator
	// may process a key before the key it references, leaving {{varName}}
	// tokens unresolved. Inlining the referenced value avoids this ordering
	// dependency.
	flattenVariableRefs(doc)

	// Step 6 — upgrade any existing placeholder that is used inside a
	// base64_decode() DSL call to a base64-valid string; otherwise Nuclei's
	// DSL evaluator errors and skips the request.
	fixBase64PlaceholderContext(doc)

	// Step 7 — replace {{interactsh-url}} with a static domain in raw strings
	// and variable values. Without an interactsh client the built-in stays
	// unresolved and Nuclei refuses to fire the request.
	replaceInteractshURL(doc)

	// Step 8 — scan every raw: string for {{varname}} references that are
	// still undefined (not a Nuclei built-in, not already in variables, not
	// an extractor output) and inject sensible defaults so all requests fire.
	injectRawVariablePlaceholders(doc)

	// Step 9 — split any raw: entry that contains multiple HTTP requests
	// packed into a single string (e.g. three GET lines in one raw: block).
	splitMultiHTTPRaws(doc)

	// Step 9.5 — insert blank line between HTTP headers and body when missing.
	// Go's net/http rejects requests where the body is concatenated directly
	// after the last header line without the required CRLF separator.
	fixMissingBodySeparators(doc)

	// Step 10 — resolve relative payload paths so temp file location is
	// transparent to Nuclei's file loader.
	templateDir := filepath.Dir(templatePath)
	resolvePayloadPaths(doc, templateDir)

	// Marshal back to YAML and write to a temp file.
	modified, err := yaml.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("marshal modified template: %w", err)
	}

	tmp, err := os.CreateTemp("", "nuclei-waf-*.yaml")
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	if _, err := tmp.Write(modified); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return nil, fmt.Errorf("write temp file: %w", err)
	}
	tmp.Close()

	name := tmp.Name()
	return &preprocessResult{
		path:    name,
		cleanup: func() { os.Remove(name) },
	}, nil
}

// catchAllMatcher returns the YAML structure for a single dsl:["true"] matcher.
func catchAllMatcher() []interface{} {
	return []interface{}{
		map[string]interface{}{
			"type": "dsl",
			"name": "catch-all",
			"dsl":  []interface{}{"true"},
		},
	}
}

// resolvePayloadPaths converts relative .txt paths to absolute paths so the
// generated temp file can resolve wordlists from anywhere.
//
// Locations checked:
//   - top-level `variables:` block
//   - each `http[].payloads:` block
func resolvePayloadPaths(doc map[string]interface{}, templateDir string) {
	if vars, ok := doc["variables"].(map[string]interface{}); ok {
		resolveStringPaths(vars, templateDir)
	}

	httpBlocks, ok := doc["http"].([]interface{})
	if !ok {
		return
	}
	for _, block := range httpBlocks {
		m, ok := block.(map[string]interface{})
		if !ok {
			continue
		}
		if payloads, ok := m["payloads"].(map[string]interface{}); ok {
			resolveStringPaths(payloads, templateDir)
		}
	}
}

// resolveStringPaths updates any string value in m that looks like a relative
// payload file path to its absolute equivalent.
func resolveStringPaths(m map[string]interface{}, baseDir string) {
	for k, v := range m {
		s, ok := v.(string)
		if !ok {
			continue
		}
		if (strings.HasSuffix(s, ".txt") || strings.Contains(s, "payloads")) && !filepath.IsAbs(s) {
			m[k] = filepath.Join(baseDir, s)
		}
	}
}

// removeSelfRefVariables deletes any variable in the variables: block whose
// value is {{self}} (a self-referential template expression).  Such variables
// are typically placeholders for CLI inputs (e.g. path: "{{path}}") that
// expect the user to supply a value.  By removing them we let Nuclei fall back
// to the matching DSL built-in variable (e.g. path → URL path component).
func removeSelfRefVariables(doc map[string]interface{}) {
	vars, ok := doc["variables"].(map[string]interface{})
	if !ok {
		return
	}
	for k, v := range vars {
		s, ok := v.(string)
		if !ok {
			continue
		}
		if strings.TrimSpace(s) == "{{"+k+"}}" {
			delete(vars, k)
		}
	}
}

// fixMissingBodySeparators ensures every raw: HTTP entry has a blank line
// between its header section and its body.  Some templates omit this required
// separator; Go's net/http then rejects the request with "invalid header field
// name" because it treats the body line as a continuation of the headers.
func fixMissingBodySeparators(doc map[string]interface{}) {
	httpBlocks, ok := doc["http"].([]interface{})
	if !ok {
		return
	}
	for _, block := range httpBlocks {
		m, ok := block.(map[string]interface{})
		if !ok {
			continue
		}
		raws := toSlice(m["raw"])
		changed := false
		newRaws := make([]interface{}, len(raws))
		for i, rawEntry := range raws {
			s, ok := rawEntry.(string)
			if !ok {
				newRaws[i] = rawEntry
				continue
			}
			fixed := insertBodySeparator(s)
			newRaws[i] = fixed
			if fixed != s {
				changed = true
			}
		}
		if changed {
			m["raw"] = newRaws
		}
	}
}

// reHeaderLine matches a valid HTTP header line (Field-Name: value).
var reHeaderLine = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9\-]*:\s`)

// insertBodySeparator inserts a blank line between the HTTP header section and
// body if one is missing. Returns the input unchanged when no fix is needed.
func insertBodySeparator(raw string) string {
	// If a blank line already exists, the separator is present.
	if strings.Contains(raw, "\n\n") || strings.Contains(raw, "\r\n\r\n") {
		return raw
	}
	lines := strings.Split(raw, "\n")
	if len(lines) < 2 {
		return raw
	}
	// First line must look like an HTTP request line.
	first := strings.TrimRight(lines[0], "\r")
	if !strings.Contains(first, " HTTP/") {
		return raw
	}
	// Walk past the header lines; when we find a non-header, non-empty line
	// insert the blank line separator just before it.
	for i := 1; i < len(lines); i++ {
		trimmed := strings.TrimRight(lines[i], "\r")
		if trimmed == "" {
			return raw // already has a blank line somewhere — nothing to fix
		}
		if reHeaderLine.MatchString(trimmed) {
			continue // normal header line
		}
		// Nuclei per-request annotations start with '@' — not a body line.
		if strings.HasPrefix(trimmed, "@") {
			continue
		}
		// This line is neither a header nor an annotation; it must be the body.
		var out []string
		out = append(out, lines[:i]...)
		out = append(out, "") // blank separator
		out = append(out, lines[i:]...)
		return strings.Join(out, "\n")
	}
	return raw
}

// flattenVariableRefs resolves {{varName}} inter-variable references within
// the variables: block by substituting the referenced variable's raw value
// inline. This is necessary because yaml.v3 marshals map keys in alphabetical
// order, so Nuclei's single-pass evaluator may process a variable before the
// variable it references, leaving {{varName}} unresolved in the final request.
//
// Only pure identifier references (no parentheses, operators, spaces) that
// resolve to another key in the same variables block are substituted.
// DSL function calls like {{rand_base(6)}} are left untouched.
// Up to 4 passes handle chains up to depth 4.
func flattenVariableRefs(doc map[string]interface{}) {
	vars, ok := doc["variables"].(map[string]interface{})
	if !ok {
		return
	}

	for pass := 0; pass < 4; pass++ {
		changed := false
		for k, v := range vars {
			s, ok := v.(string)
			if !ok {
				continue
			}
			newS := reAllTemplateExpr.ReplaceAllStringFunc(s, func(match string) string {
				inner := match[2 : len(match)-2] // strip {{ and }}
				if !reSimpleVarName.MatchString(inner) {
					return match // function call or complex expression — leave alone
				}
				name := strings.TrimSpace(inner)
				if name == k {
					return match // self-reference guard
				}
				if refVal, ok := vars[name].(string); ok {
					return refVal // inline the referenced variable's value
				}
				return match
			})
			if newS != s {
				vars[k] = newS
				changed = true
			}
		}
		if !changed {
			break
		}
	}
}

// injectExtractorPlaceholders scans all HTTP blocks for extractors with
// internal:true and injects a realistic placeholder into the template's
// variables block for each one. When WAF blocks an earlier step and extraction
// fails, Nuclei falls back to the static placeholder, keeping the downstream
// request body / URL well-formed.
func injectExtractorPlaceholders(doc map[string]interface{}) {
	httpBlocks, ok := doc["http"].([]interface{})
	if !ok {
		return
	}

	type entry struct {
		name     string
		extType  string
		patterns []string
	}
	var entries []entry

	for _, block := range httpBlocks {
		m, ok := block.(map[string]interface{})
		if !ok {
			continue
		}
		for _, raw := range toSlice(m["extractors"]) {
			ext, ok := raw.(map[string]interface{})
			if !ok {
				continue
			}
			internal, _ := ext["internal"].(bool)
			if !internal {
				continue
			}
			name, _ := ext["name"].(string)
			if name == "" {
				continue
			}
			extType, _ := ext["type"].(string)
			var patterns []string
			switch extType {
			case "regex":
				for _, p := range toSlice(ext["regex"]) {
					if s, ok := p.(string); ok {
						patterns = append(patterns, s)
					}
				}
			case "json":
				for _, p := range toSlice(ext["json"]) {
					if s, ok := p.(string); ok {
						patterns = append(patterns, s)
					}
				}
			case "kval":
				for _, p := range toSlice(ext["kval"]) {
					if s, ok := p.(string); ok {
						patterns = append(patterns, s)
					}
				}
			}
			entries = append(entries, entry{name, extType, patterns})
		}
	}

	if len(entries) == 0 {
		return
	}

	// Ensure variables block exists.
	vars, ok := doc["variables"].(map[string]interface{})
	if !ok {
		vars = make(map[string]interface{})
		doc["variables"] = vars
	}

	for _, e := range entries {
		if _, exists := vars[e.name]; exists {
			continue // do not override existing static variables
		}
		vars[e.name] = placeholderFor(e.name, e.extType, e.patterns)
	}
}

// toSlice normalises an interface{} that may be nil, a single item, or a
// []interface{} into a []interface{} for uniform iteration.
func toSlice(v interface{}) []interface{} {
	if v == nil {
		return nil
	}
	if s, ok := v.([]interface{}); ok {
		return s
	}
	return []interface{}{v}
}

// ── Fix C — base64 context upgrade ──────────────────────────────────────────

// fixBase64PlaceholderContext scans raw request strings for variables used
// directly inside base64() or base64_decode(). If the variable's current
// placeholder value is not valid standard-encoding base64, it is replaced with
// base64(fromName(varname)) so Nuclei's DSL does not error on decode.
func fixBase64PlaceholderContext(doc map[string]interface{}) {
	httpBlocks, ok := doc["http"].([]interface{})
	if !ok {
		return
	}

	// Collect variable names that appear in base64_decode(varname) context.
	b64Vars := map[string]bool{}
	for _, block := range httpBlocks {
		m, ok := block.(map[string]interface{})
		if !ok {
			continue
		}
		for _, rawEntry := range toSlice(m["raw"]) {
			s, ok := rawEntry.(string)
			if !ok {
				continue
			}
			for _, match := range reBase64VarCtx.FindAllStringSubmatch(s, -1) {
				b64Vars[match[1]] = true
			}
		}
	}
	if len(b64Vars) == 0 {
		return
	}

	vars, ok := doc["variables"].(map[string]interface{})
	if !ok {
		vars = make(map[string]interface{})
		doc["variables"] = vars
	}

	for name := range b64Vars {
		current, exists := vars[name]
		if !exists {
			// Not yet defined — set a valid base64 placeholder now.
			vars[name] = validBase64Placeholder(name)
			continue
		}
		// Already defined — check whether it is valid base64 AND whether the
		// decoded bytes are all printable ASCII.  A hex-like token (e.g.
		// "a1b2c3d4e5f67890...") is valid base64 but decodes to binary data
		// that cannot safely appear in URLs or HTTP bodies.
		if s, ok := current.(string); ok {
			decoded, err := base64.StdEncoding.DecodeString(s)
			if err != nil || !isPrintableASCII(decoded) {
				vars[name] = validBase64Placeholder(name)
			}
		}
	}
}

// isPrintableASCII returns true when every byte in b is a printable ASCII
// character (0x20–0x7E inclusive).
func isPrintableASCII(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7E {
			return false
		}
	}
	return true
}

// validBase64Placeholder returns a base64-encoded string that is safe to pass
// to base64_decode() in Nuclei's DSL without causing an evaluation error.
func validBase64Placeholder(name string) string {
	plain := fromName(strings.ToLower(name), name)
	return base64.StdEncoding.EncodeToString([]byte(plain))
}

// ── Fix D — interactsh-url replacement ──────────────────────────────────────

// replaceInteractshURL replaces every occurrence of {{interactsh-url}} with a
// static domain in raw request strings and variable values.  The Nuclei
// built-in is only resolved when an interactsh client is configured; without
// one, the template never fires.  For WAF-coverage purposes we just need the
// request to be sent; OOB detection is irrelevant.
func replaceInteractshURL(doc map[string]interface{}) {
	const placeholder = "oast.placeholder.example.com"
	const token = "{{interactsh-url}}"

	// Replace inside variables block values.
	if vars, ok := doc["variables"].(map[string]interface{}); ok {
		for k, v := range vars {
			if s, ok := v.(string); ok && strings.Contains(s, token) {
				vars[k] = strings.ReplaceAll(s, token, placeholder)
			}
		}
	}

	// Replace inside each raw: string.
	httpBlocks, ok := doc["http"].([]interface{})
	if !ok {
		return
	}
	for _, block := range httpBlocks {
		m, ok := block.(map[string]interface{})
		if !ok {
			continue
		}
		raws := toSlice(m["raw"])
		newRaws := make([]interface{}, len(raws))
		changed := false
		for i, rawEntry := range raws {
			s, ok := rawEntry.(string)
			if !ok {
				newRaws[i] = rawEntry
				continue
			}
			replaced := strings.ReplaceAll(s, token, placeholder)
			newRaws[i] = replaced
			if replaced != s {
				changed = true
			}
		}
		if changed {
			m["raw"] = newRaws
		}
	}
}

// ── Fix A — undefined raw variable injection ─────────────────────────────────

// collectDefinedVars returns a set of variable names that are already known at
// preprocessing time: explicit template variables and internal extractor names.
func collectDefinedVars(doc map[string]interface{}) map[string]bool {
	defined := map[string]bool{}
	if vars, ok := doc["variables"].(map[string]interface{}); ok {
		for k := range vars {
			defined[k] = true
		}
	}
	httpBlocks, ok := doc["http"].([]interface{})
	if !ok {
		return defined
	}
	for _, block := range httpBlocks {
		m, ok := block.(map[string]interface{})
		if !ok {
			continue
		}
		for _, rawExt := range toSlice(m["extractors"]) {
			ext, ok := rawExt.(map[string]interface{})
			if !ok {
				continue
			}
			if name, ok := ext["name"].(string); ok && name != "" {
				defined[name] = true
			}
		}
	}
	return defined
}

// injectRawVariablePlaceholders scans every raw: request string for
// {{varname}} references that are neither a Nuclei built-in nor already
// defined in the template's variables / extractor outputs, and injects a
// sensible default value.
//
// This primarily fixes "authenticated" templates that use {{username}} and
// {{password}} and expect the caller to supply -var username=… at runtime.
// Without the injection Nuclei silently skips every request that contains an
// unresolved variable, resulting in 0 fired requests.
func injectRawVariablePlaceholders(doc map[string]interface{}) {
	defined := collectDefinedVars(doc)

	httpBlocks, ok := doc["http"].([]interface{})
	if !ok {
		return
	}

	missing := map[string]bool{}

	// scanExpressions extracts undefined lowercase identifiers from a string
	// that may contain {{...}} template expressions.
	scanExpressions := func(s string) {
		for _, exprMatch := range reAllTemplateExpr.FindAllStringSubmatch(s, -1) {
			// Strip string literals (e.g. base64('http://example.com')) so
			// that words inside quoted arguments are not treated as variable
			// names.
			expr := reStringLiteral.ReplaceAllString(exprMatch[1], "")
			for _, idMatch := range reLowercaseIdent.FindAllStringSubmatch(expr, -1) {
				name := idMatch[1]
				if nucleiBuiltinSet[name] || defined[name] {
					continue
				}
				missing[name] = true
			}
		}
	}

	for _, block := range httpBlocks {
		m, ok := block.(map[string]interface{})
		if !ok {
			continue
		}
		// Scan raw: string entries.
		for _, rawEntry := range toSlice(m["raw"]) {
			if s, ok := rawEntry.(string); ok {
				scanExpressions(s)
			}
		}
		// Scan path: list entries (used by method+path style blocks).
		for _, pathEntry := range toSlice(m["path"]) {
			if s, ok := pathEntry.(string); ok {
				scanExpressions(s)
			}
		}
	}
	if len(missing) == 0 {
		return
	}

	vars, ok := doc["variables"].(map[string]interface{})
	if !ok {
		vars = make(map[string]interface{})
		doc["variables"] = vars
	}
	for name := range missing {
		if _, exists := vars[name]; exists {
			continue
		}
		vars[name] = fromName(strings.ToLower(name), name)
	}
}

// ── Fix E — multi-HTTP raw entry split ──────────────────────────────────────

// splitMultiHTTPRaws detects raw: entries that contain multiple HTTP requests
// crammed into a single string (e.g. three GET lines in one raw block) and
// splits each such entry into individual raw entries.
func splitMultiHTTPRaws(doc map[string]interface{}) {
	httpBlocks, ok := doc["http"].([]interface{})
	if !ok {
		return
	}
	for _, block := range httpBlocks {
		m, ok := block.(map[string]interface{})
		if !ok {
			continue
		}
		raws := toSlice(m["raw"])
		var newRaws []interface{}
		changed := false
		for _, rawEntry := range raws {
			s, ok := rawEntry.(string)
			if !ok {
				newRaws = append(newRaws, rawEntry)
				continue
			}
			parts := splitHTTPRequests(s)
			if len(parts) > 1 {
				changed = true
			}
			for _, p := range parts {
				newRaws = append(newRaws, p)
			}
		}
		if changed {
			m["raw"] = newRaws
		}
	}
}

// splitHTTPRequests splits a raw string that embeds multiple HTTP requests
// into a slice of individual request strings.  Returns a single-element slice
// if only one request is detected.
//
// A split point is only accepted when the preceding portion of the string
// already contains a complete HTTP request (has a " HTTP/1" or " HTTP/2"
// version token). This prevents the function from splitting Nuclei per-request
// annotations like "@timeout: 10s" that appear on the line immediately before
// the actual method line within a single raw: entry.
func splitHTTPRequests(raw string) []string {
	locs := reHTTPRequestBoundary.FindAllStringIndex(raw, -1)
	if len(locs) == 0 {
		return []string{raw}
	}

	// Filter to only split points where the preceding segment already contains
	// a completed HTTP request line (the " HTTP/1.x" or " HTTP/2" marker).
	var validLocs [][]int
	for _, loc := range locs {
		preceding := raw[:loc[0]]
		if strings.Contains(preceding, " HTTP/1") || strings.Contains(preceding, " HTTP/2") {
			validLocs = append(validLocs, loc)
		}
	}
	if len(validLocs) == 0 {
		return []string{raw}
	}

	var parts []string
	prev := 0
	for _, loc := range validLocs {
		if part := strings.TrimSpace(raw[prev:loc[0]]); part != "" {
			parts = append(parts, part)
		}
		prev = loc[0] + 1 // skip the '\n'; the new request starts with the method
	}
	if part := strings.TrimSpace(raw[prev:]); part != "" {
		parts = append(parts, part)
	}

	if len(parts) <= 1 {
		return []string{raw}
	}
	return parts
}
