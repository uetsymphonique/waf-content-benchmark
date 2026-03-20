package runner

import (
	"regexp"
	"strings"
)

// reHTTPRequestBoundary finds the start of a second (or later) HTTP request
// embedded inside a single raw: string entry.
var reHTTPRequestBoundary = regexp.MustCompile(
	`\n(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE) \S+ HTTP/[12]`,
)

// reHeaderLine matches a valid HTTP header line (Field-Name: value).
var reHeaderLine = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9\-]*:\s`)

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
