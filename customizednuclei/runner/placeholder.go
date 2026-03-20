package runner

import (
	"regexp"
	"strconv"
	"strings"
)

// placeholderFor derives a realistic-looking placeholder value for an internal
// extractor variable. It checks, in priority order:
//
//  1. The extractor's regex pattern(s) — most specific (exact length, charset)
//  2. The variable name — keyword heuristics for common types
//  3. Fallback: "placeholder-<name>"
//
// The goal is a non-empty value that keeps downstream requests well-formed
// when WAF blocks an earlier step and extraction fails.
func placeholderFor(name, extType string, patterns []string) string {
	nameLower := strings.ToLower(name)
	joined := strings.Join(patterns, " ")

	// ── Tier 1: regex-pattern analysis ─────────────────────────────────────
	if extType == "regex" && joined != "" {
		if p := fromRegexPattern(joined, nameLower); p != "" {
			return p
		}
	}

	// ── Tier 2: variable-name heuristics ───────────────────────────────────
	return fromName(nameLower, name)
}

// ── Tier 1 helpers ──────────────────────────────────────────────────────────

// reExactN matches patterns like [A-Z0-9]{26} or [a-f0-9]{32}.
// Group 1 = character class body, Group 2 = exact count N.
var reExactN = regexp.MustCompile(`\[([^\]]+)\]\{(\d+)\}`)

// reRangeN matches {N,M} quantifiers to pick the midpoint.
var reRangeN = regexp.MustCompile(`\{(\d+),(\d+)\}`)

func fromRegexPattern(pattern, name string) string {
	switch {
	// JWT bearer tokens
	case strings.Contains(pattern, "eyJ"):
		return fakeJWT()

	// UUID / GUID  e.g. [0-9a-f]{8}-[0-9a-f]{4}-...
	case reUUIDPattern.MatchString(pattern):
		return "550e8400-e29b-41d4-a716-446655440000"

	// IP address  e.g. \d{1,3}\.\d{1,3}\.\d{1,3}
	case reIPPattern.MatchString(pattern):
		return "203.0.113.42"

	// Pure digit  e.g. \d+ or [0-9]+
	case reDigitOnly.MatchString(pattern):
		return "42"

	// HTTP / redirect URL
	case strings.Contains(pattern, "https?://") ||
		strings.Contains(pattern, "Location:") ||
		strings.Contains(pattern, "href"):
		return "/dashboard"
	}

	// Exact-length character-class: [charset]{N}
	if m := reExactN.FindStringSubmatch(pattern); m != nil {
		n, _ := strconv.Atoi(m[2])
		return generateOfLength(m[1], n)
	}

	// Range quantifier {N,M} — pick midpoint
	if m := reRangeN.FindStringSubmatch(pattern); m != nil {
		lo, _ := strconv.Atoi(m[1])
		hi, _ := strconv.Atoi(m[2])
		n := (lo + hi) / 2
		// Determine charset from context
		cs := inferCharset(pattern)
		return generateOfLength(cs, n)
	}

	return ""
}

var (
	reUUIDPattern = regexp.MustCompile(`\[0-9a-f\]\{8\}[-–]|\[a-f0-9\]\{8\}[-–]`)
	reIPPattern   = regexp.MustCompile(`\\d\{1,3\}\\\.\\d\{1,3\}`)
	reDigitOnly   = regexp.MustCompile(`^[\(\)\^\\d\+\*\[\]0-9\{\},\s]+$`)
)

// generateOfLength builds a placeholder string of exactly n characters using
// the charset hint extracted from a regex character class body.
func generateOfLength(charsetHint string, n int) string {
	var alphabet string
	switch {
	case strings.Contains(charsetHint, "A-Z") && strings.Contains(charsetHint, "0-9"):
		alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	case strings.Contains(charsetHint, "A-Z"):
		alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	case strings.Contains(charsetHint, "a-f") || strings.Contains(charsetHint, "0-9a-f") || strings.Contains(charsetHint, "a-f0-9"):
		alphabet = "a1b2c3d4e5f60789"
	case strings.Contains(charsetHint, "a-z") && strings.Contains(charsetHint, "0-9"):
		alphabet = "abcdefghij0123456789"
	case strings.Contains(charsetHint, "a-zA-Z") || strings.Contains(charsetHint, "A-Za-z"):
		alphabet = "AbCdEfGhIjKlMnOpQrSt"
	case strings.Contains(charsetHint, "a-z"):
		alphabet = "abcdefghijklmnopqrst"
	default:
		alphabet = "abcdefABCDEF0123456789"
	}
	out := make([]byte, n)
	for i := range out {
		out[i] = alphabet[i%len(alphabet)]
	}
	return string(out)
}

// inferCharset guesses the character class for a range quantifier context.
func inferCharset(pattern string) string {
	switch {
	case strings.Contains(pattern, "A-Z") && strings.Contains(pattern, "0-9"):
		return "A-Z0-9"
	case strings.Contains(pattern, "a-f") || strings.Contains(pattern, "a-f0-9"):
		return "a-f0-9"
	case strings.Contains(pattern, "a-zA-Z"):
		return "a-zA-Z0-9"
	default:
		return "a-z0-9"
	}
}

// ── Tier 2 helpers ──────────────────────────────────────────────────────────

func fromName(nameLower, nameOrig string) string {
	contains := func(keywords ...string) bool {
		for _, k := range keywords {
			if strings.Contains(nameLower, k) {
				return true
			}
		}
		return false
	}

	switch {
	// JWT access tokens
	case contains("access_token", "bearer", "jwt"):
		return fakeJWT()

	// UUID-type identifiers
	case contains("uuid", "guid", "realm", "api_token"):
		return "550e8400-e29b-41d4-a716-446655440000"

	// JSESSIONID / uppercase session tokens
	case contains("jsession", "jsessionid"):
		return "ABCDEF1234567890ABCDEF12"

	// WordPress-style nonces (8–12 lowercase hex)
	case contains("nonce", "wpnonce"):
		return "a1b2c3d4e5f6"

	// CSRF / form authenticity tokens
	case contains("csrf", "authenticity_token", "form_key"):
		return "abcdefghij1234567890abcdef123456"

	// Session / cookie IDs
	case contains("session_id", "sessionid"):
		return "a1b2c3d4e5f67890abcdef12345678ab"

	// File / system paths
	case contains("temppath", "filepath", "specfile", "spec"):
		return "/tmp/placeholder-file"

	// Generic paths
	case contains("path") && !contains("xpath"):
		return "/tmp/placeholder"

	// File extensions often concatenated directly to BaseURL without a slash
	case nameLower == "js" || nameLower == "css" || nameLower == "html" || nameLower == "php" || nameLower == "jsp" || nameLower == "aspx":
		return "/placeholder." + nameLower

	// URL / redirect destinations
	case contains("url", "redirect", "endpoint", "node_url"):
		return "/dashboard"

	// IP addresses
	case contains("ip", "ipaddress", "remote_addr"):
		return "203.0.113.42"

	// Version strings
	case contains("version"):
		return "2.0.0"

	// Passwords
	case contains("password", "passwd", "pass", "pwd", "secret_key"):
		return "Password123!"

	// Email addresses
	case contains("email", "mail"):
		return "test@example.com"

	// Usernames
	case contains("username", "user_name", "login", "wordpress_username"):
		return "admin"

	// Slugs (kebab-case identifiers)
	case contains("slug"):
		return "my-repo"

	// Numeric IDs
	case contains("formid", "printerid", "wishlist", "memberfield"):
		return "42"
	case nameLower == "id" || strings.HasSuffix(nameLower, "_id"):
		return "42"

	// Project / repository keys
	case nameLower == "key" || strings.HasSuffix(nameLower, "_key") && !contains("api", "secret", "auth"):
		return "PROJ"

	// Protected / relay state (OAuth / SAML flows)
	case contains("state", "relay"):
		return "AbCdEfGh12345678"

	// Generic auth tokens / secrets / session cookies
	case contains("token", "secret", "apikey", "auth", "session", "cookie", "cid", "hzn"):
		return "a1b2c3d4e5f67890abcdef1234567890"

	default:
		return "placeholder-" + nameOrig
	}
}

// fakeJWT returns a structurally valid but unsigned JWT for use as a placeholder.
// Header: {"alg":"HS256","typ":"JWT"}  Payload: {"sub":"test","iat":1700000000}
func fakeJWT() string {
	return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
		".eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNzAwMDAwMDAwfQ" +
		".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
}
