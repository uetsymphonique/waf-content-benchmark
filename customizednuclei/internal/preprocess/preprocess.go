package preprocess

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Result is returned by PreprocessTemplate.
type Result struct {
	Path    string // temp file path to pass to templates.Parse
	Skip    bool   // true when the template has no HTTP block (e.g. javascript:/dns-only)
	Cleanup func() // removes the temp file; always safe to call even when Skip==true
}

// nopCleanup is a no-op cleanup used for skipped templates.
func nopCleanup() {}

// PreprocessTemplate applies the WAF-testing pipeline to a single template
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
func PreprocessTemplate(templatePath string) (*Result, error) {
	raw, err := os.ReadFile(templatePath)
	if err != nil {
		return nil, fmt.Errorf("read template: %w", err)
	}

	rawStr := string(raw)
	// Nuclei parser bug workaround: OGNL/EL payloads like ${{{num1}}*{{num2}}}
	// confuse the AST parser because it matches the first two '{' as Start,
	// making the variable name '{num1', which then fails to resolve.
	// Separating them avoids the parsing error and allows normal resolution.
	rawStr = strings.ReplaceAll(rawStr, "{{{", "{ {{")
	rawStr = strings.ReplaceAll(rawStr, "}}}", "}} }")

	var doc map[string]interface{}
	if err := yaml.Unmarshal([]byte(rawStr), &doc); err != nil {
		return nil, fmt.Errorf("parse YAML %q: %w", templatePath, err)
	}

	// Step 1 — skip if there is no HTTP block.
	httpRaw, hasHTTP := doc["http"]
	if !hasHTTP {
		return &Result{Skip: true, Cleanup: nopCleanup}, nil
	}
	httpBlocks, ok := httpRaw.([]interface{})
	if !ok || len(httpBlocks) == 0 {
		return &Result{Skip: true, Cleanup: nopCleanup}, nil
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
		m["skip-variables-check"] = true
		delete(m, "matchers-condition")
		m["matchers"] = catchAllMatcher()
	}

	// Step 5 — inject placeholder values for all internal extractor variables
	// so downstream requests stay well-formed when WAF blocks an earlier step.
	injectExtractorPlaceholders(doc)

	// Step 5.1 — violently remove extractors so Nuclei never runs them. If
	// left intact, an overly broad regex might accidentally extract HTML tags
	// from a WAF 403 page and inject garbage into downstream raw requests,
	// crashing the parser (e.g. CVE-2024-1561).
	for _, block := range httpBlocks {
		m, ok := block.(map[string]interface{})
		if !ok {
			continue
		}
		delete(m, "extractors")
	}

	// Step 5.5a — remove self-referential variables (e.g. path: "{{path}}")
	// that create circular evaluation and mask the matching Nuclei DSL built-in.
	removeSelfRefVariables(doc)

	// Step 5.5b — flatten inter-variable references in the variables: block.
	// yaml.v3 marshals keys alphabetically, so Nuclei's single-pass evaluator
	// may process a key before the key it references, leaving {{varName}}
	// tokens unresolved. Inlining the referenced value avoids this ordering
	// dependency.
	flattenVariableRefs(doc)

	// Step 5.5c — resolve {{randstr}} / {{rand_base(N)}} to static strings so
	// they can be used as arguments to downstream DSL function calls.
	resolveRandVars(doc)

	// Step 5.5d — statically evaluate simple single-argument DSL function calls
	// (base64, md5, sha1, sha256, hex_encode, url_encode, to_upper, to_lower,
	// reverse) whose argument is now a known static string. This fixes cases
	// like b64marker: {{base64(marker)}} where the evaluator previously
	// complained "No parameter 'marker' found".
	evaluateSimpleDSLVars(doc)

	// Step 5.5e — upgrade any variable whose value is still an unresolved DSL
	// expression (e.g. {{hmac(...)}}) but is used inside hex_decode() in a raw
	// request. Replace with a valid hex fallback so Nuclei's DSL runtime can
	// decode it without erroring out.
	fixHexDecodeVarContext(doc)

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
	// packed into a single string (e.g. three GET lines in one raw block).
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
	return &Result{
		Path:    name,
		Cleanup: func() { os.Remove(name) },
	}, nil
}
