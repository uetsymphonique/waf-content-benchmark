package runner

import (
	"encoding/base64"
	"regexp"
	"strings"
)

// reBase64VarCtx detects a variable name used as the first argument of
// base64() or base64_decode(), e.g. base64_decode(httoken).
var reBase64VarCtx = regexp.MustCompile(`base64(?:_decode)?\(([a-zA-Z_][a-zA-Z0-9_]*)\)`)

// injectExtractorPlaceholders finds all extractors with internal:true and 
// injects a realistic placeholder into the template's variables block for each one.
// When WAF blocks an earlier step and extraction fails, Nuclei falls back 
// to the static placeholder, keeping the downstream request body / URL well-formed.
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
