package runner

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"math/rand"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

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

// reDSLSingleArgFunc matches a template expression that is a single
// identifier-argument DSL function call, e.g. {{base64(marker)}}.
var reDSLSingleArgFunc = regexp.MustCompile(`^\{\{(\w+)\((\w+)\)\}\}$`)

// reRandBase matches {{rand_base(N)}} with an optional second arg.
var reRandBase = regexp.MustCompile(`^\{\{rand_base\((\d+)(?:,.*)?\)\}\}$`)

// reHexDecodeVarCtx detects a variable name used as the argument of
// hex_decode(), e.g. hex_decode(auth) or hex_decode(rawXor).
var reHexDecodeVarCtx = regexp.MustCompile(`hex_decode\(([a-zA-Z_][a-zA-Z0-9_]*)\)`)

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

// resolveRandVars substitutes {{randstr}} and {{rand_base(N)}} within the
// variables: block with a freshly generated static string. This allows
// subsequent evaluateSimpleDSLVars to use these values as concrete arguments
// to functions like base64(marker) where marker was originally {{randstr}}.
func resolveRandVars(doc map[string]interface{}) {
	vars, ok := doc["variables"].(map[string]interface{})
	if !ok {
		return
	}
	for k, v := range vars {
		s, ok := v.(string)
		if !ok {
			continue
		}
		trimmed := strings.TrimSpace(s)
		if trimmed == "{{randstr}}" {
			vars[k] = randAlpha(8)
			continue
		}
		if m := reRandBase.FindStringSubmatch(trimmed); m != nil {
			n, _ := strconv.Atoi(m[1])
			if n <= 0 {
				n = 8
			}
			vars[k] = randAlpha(n)
		}
	}
}

// fixHexDecodeVarContext scans every raw: request string for variables used as
// the argument to hex_decode(), and replaces any variable whose value is still
// an unresolved DSL expression (contains "{{") with a valid lowercase hex
// string. Without this, calls like {{base64(hex_decode(auth))}} fail with
// "invalid hex string" at Nuclei's DSL runtime when `auth` holds an unresolvable
// expression such as {{hmac('sha1', query, secret)}}.
//
// A generic 16-byte hex string "41424344454647484950515253545556" (printable
// ASCII ABCDEFGHIJKLMNOPQRSTUV) is used as the fallback.
func fixHexDecodeVarContext(doc map[string]interface{}) {
	httpBlocks, ok := doc["http"].([]interface{})
	if !ok {
		return
	}

	// Collect variable names that appear as hex_decode(varname) argument.
	hexVars := map[string]bool{}
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
			for _, match := range reHexDecodeVarCtx.FindAllStringSubmatch(s, -1) {
				hexVars[match[1]] = true
			}
		}
	}
	if len(hexVars) == 0 {
		return
	}

	vars, ok := doc["variables"].(map[string]interface{})
	if !ok {
		vars = make(map[string]interface{})
		doc["variables"] = vars
	}

	for name := range hexVars {
		current, exists := vars[name]
		if !exists {
			vars[name] = "41424344454647484950515253545556"
			continue
		}
		// If the current value still contains {{ (not yet resolved), upgrade to hex.
		if s, ok := current.(string); ok && strings.Contains(s, "{{") {
			vars[name] = "41424344454647484950515253545556"
		}
	}
}

// evaluateSimpleDSLVars statically evaluates template expressions of the form
// {{funcName(argName)}} where argName is a variable already resolved to a
// plain string (no {{}}) in the same variables: block. Runs up to 4 passes to
// handle chains like: a={{randstr}}, b={{base64(a)}}, c={{md5(b)}}.
//
// Supported functions: base64, base64_py, md5, sha1, sha256, hex_encode,
// url_encode, to_upper, toupper, to_lower, tolower, reverse, trim, len.
func evaluateSimpleDSLVars(doc map[string]interface{}) {
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
			m := reDSLSingleArgFunc.FindStringSubmatch(strings.TrimSpace(s))
			if m == nil {
				continue
			}
			funcName := m[1]
			argName := m[2]
			argRaw, exists := vars[argName]
			if !exists {
				continue
			}
			argStr, ok := argRaw.(string)
			if !ok || strings.Contains(argStr, "{{") {
				continue // arg not yet resolved
			}
			if result := applyDSLFunc(funcName, argStr); result != "" {
				vars[k] = result
				changed = true
			}
		}
		if !changed {
			break
		}
	}
}

// applyDSLFunc evaluates a single-argument DSL function against a resolved
// string value. Returns empty string for unknown or unsupported functions.
func applyDSLFunc(funcName, arg string) string {
	switch funcName {
	case "base64", "base64_py":
		return base64.StdEncoding.EncodeToString([]byte(arg))
	case "md5":
		h := md5.Sum([]byte(arg))
		return hex.EncodeToString(h[:])
	case "sha1":
		h := sha1.Sum([]byte(arg))
		return hex.EncodeToString(h[:])
	case "sha256":
		h := sha256.Sum256([]byte(arg))
		return hex.EncodeToString(h[:])
	case "hex_encode":
		return hex.EncodeToString([]byte(arg))
	case "url_encode":
		return url.QueryEscape(arg)
	case "to_upper", "toupper":
		return strings.ToUpper(arg)
	case "to_lower", "tolower":
		return strings.ToLower(arg)
	case "reverse":
		r := []rune(arg)
		for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
			r[i], r[j] = r[j], r[i]
		}
		return string(r)
	case "trim":
		return strings.TrimSpace(arg)
	case "len":
		return strconv.Itoa(len(arg))
	}
	return ""
}

// randAlpha returns a random lowercase-alphanumeric string of length n.
var randAlphaChars = []byte("abcdefghijklmnopqrstuvwxyz0123456789")

func randAlpha(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = randAlphaChars[rand.Intn(len(randAlphaChars))]
	}
	return string(b)
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
		// Extract payloads: any key in payloads block is a defined variable.
		// Ex: `payloads: padding: citrix_paddings.txt` defines `padding`.
		if payloads, ok := m["payloads"].(map[string]interface{}); ok {
			for k := range payloads {
				defined[k] = true
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
				// Hardcoded fallback for Exchange Server SSRF (CVE-2021-28480, 28481)
				// The rawXor variable is generated by a flow block we deleted.
				if strings.Contains(s, "rawXor") && !defined["rawXor"] {
					missing["rawXor"] = true
				}
				scanExpressions(s)
			}
		}
		// Scan path: list entries (used by method+path style blocks).
		for _, pathEntry := range toSlice(m["path"]) {
			if s, ok := pathEntry.(string); ok {
				if strings.Contains(s, "rawXor") && !defined["rawXor"] {
					missing["rawXor"] = true
				}
				scanExpressions(s)
			}
		}
		// Scan payloads: block string values. Some templates put {{varname}}
		// directly inside payload strings (e.g. path payloads like
		// "/bin/view/XWiki/{{username}}?xpage=xml") — these would be missed by
		// the raw:/path: scans above.
		if payloads, ok := m["payloads"].(map[string]interface{}); ok {
			for _, pv := range payloads {
				for _, entry := range toSlice(pv) {
					if s, ok := entry.(string); ok {
						scanExpressions(s)
					}
				}
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
		if name == "rawXor" {
			vars[name] = "41414141" // Valid hex for AAAA
		} else {
			vars[name] = fromName(strings.ToLower(name), name)
		}
	}
}
