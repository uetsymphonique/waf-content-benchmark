package runner

import (
	"os"
	"path/filepath"
	"strings"
)

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
//
// Resolution strategy (first match wins):
//  1. Relative to baseDir (template's own directory) — most common case.
//  2. Walk up ancestor directories until the file is found or the filesystem
//     root is reached — handles the nuclei-templates convention where shared
//     wordlists live at the repo root (e.g. helpers/wordlists/numbers.txt).
func resolveStringPaths(m map[string]interface{}, baseDir string) {
	for k, v := range m {
		s, ok := v.(string)
		if !ok {
			continue
		}
		if (strings.HasSuffix(s, ".txt") || strings.Contains(s, "payloads")) && !filepath.IsAbs(s) {
			m[k] = findPayloadFile(s, baseDir)
		}
	}
}

// findPayloadFile resolves a relative payload path by first trying baseDir,
// then walking up the directory tree until the file exists or there is no
// parent left to try.  The original relative path is returned unchanged when
// no existing file is found (Nuclei will surface the error itself).
func findPayloadFile(rel, baseDir string) string {
	dir := baseDir
	for {
		candidate := filepath.Join(dir, rel)
		if _, err := os.Stat(candidate); err == nil {
			return candidate // found
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break // reached filesystem root
		}
		dir = parent
	}
	// Nothing found — return the naïve join so Nuclei can report the error.
	return filepath.Join(baseDir, rel)
}
