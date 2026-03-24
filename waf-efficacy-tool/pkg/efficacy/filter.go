package efficacy

import (
	"strconv"
	"strings"
)

type StatusFilter struct {
	exact    map[int]bool
	prefixes []string
}

func ParseStatusFilter(s string) *StatusFilter {
	if s == "" {
		return nil
	}
	f := &StatusFilter{exact: make(map[int]bool)}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		partLower := strings.ToLower(part)
		if strings.Contains(partLower, "*") || strings.Contains(partLower, "x") {
			prefix := strings.ReplaceAll(strings.ReplaceAll(partLower, "*", ""), "x", "")
			f.prefixes = append(f.prefixes, prefix)
		} else {
			if code, err := strconv.Atoi(part); err == nil {
				f.exact[code] = true
			}
		}
	}
	return f
}

func (f *StatusFilter) Matches(code int) bool {
	if f == nil {
		return false
	}
	if f.exact[code] {
		return true
	}
	codeStr := strconv.Itoa(code)
	for _, p := range f.prefixes {
		if strings.HasPrefix(codeStr, p) {
			return true
		}
	}
	return false
}
