package template

import (
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Collect returns a list of .yaml/.yml template paths under basePath.
// If basePath is a file it is returned directly.
// cveFilter: filters top-level subdirectories by name (e.g. "2023").
// vulnFilter: filters files by filename prefix (e.g. "sqli,xss").
func Collect(basePath, cveFilter, vulnFilter string) ([]string, error) {
	fi, err := os.Stat(basePath)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return []string{basePath}, nil
	}

	allowedCVE := ParseCVEFilter(cveFilter)
	
	var allowedVuln []string
	if vulnFilter != "" {
		for _, p := range strings.Split(vulnFilter, ",") {
			if s := strings.TrimSpace(p); s != "" {
				allowedVuln = append(allowedVuln, strings.ToLower(s))
			}
		}
	}

	cleanBase := filepath.Clean(basePath)
	var paths []string

	err = filepath.WalkDir(basePath, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// CVE filter optimizations: only skip top-level directories
			if len(allowedCVE) > 0 && p != cleanBase && filepath.Dir(p) == cleanBase {
				if !allowedCVE[d.Name()] {
					return fs.SkipDir
				}
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(p))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		// Vuln filter: prefix match on filename (case-insensitive)
		if len(allowedVuln) > 0 {
			name := strings.ToLower(strings.TrimSuffix(d.Name(), filepath.Ext(d.Name())))
			match := false
			for _, prefix := range allowedVuln {
				if strings.HasPrefix(name, prefix) {
					match = true
					break
				}
			}
			if !match {
				return nil
			}
		}

		paths = append(paths, p)
		return nil
	})
	return paths, err
}

// ParseCVEFilter parses a filter string like "2023,2024-2026" into a set of
// allowed folder names (as strings).
func ParseCVEFilter(filter string) map[string]bool {
	allowed := make(map[string]bool)
	if filter == "" {
		return allowed
	}
	for _, p := range strings.Split(filter, ",") {
		p = strings.TrimSpace(p)
		if strings.Contains(p, "-") {
			bounds := strings.SplitN(p, "-", 2)
			if len(bounds) == 2 {
				start, err1 := strconv.Atoi(strings.TrimSpace(bounds[0]))
				end, err2 := strconv.Atoi(strings.TrimSpace(bounds[1]))
				if err1 == nil && err2 == nil {
					if start > end {
						start, end = end, start
					}
					for i := start; i <= end; i++ {
						allowed[strconv.Itoa(i)] = true
					}
					continue
				}
			}
		}
		if p != "" {
			allowed[p] = true
		}
	}
	return allowed
}
