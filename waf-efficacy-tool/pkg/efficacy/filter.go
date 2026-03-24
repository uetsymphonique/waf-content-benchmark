package efficacy

import (
	"net/http"
	"strconv"
	"strings"
)

type StatusFilter struct {
	exact    map[int]bool
	prefixes []string
}

type TraceHeaderMatcher struct {
	header   string
	value    string
	anyValue bool
}

type TraceHeaderFilter struct {
	matchers []TraceHeaderMatcher
}

func ParseTraceHeaderFilter(spec string) *TraceHeaderFilter {
	if spec == "" {
		return nil
	}

	matchers := make([]TraceHeaderMatcher, 0)
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		idx := strings.Index(part, ":")
		if idx <= 0 || idx == len(part)-1 {
			continue
		}

		header := strings.ToLower(strings.TrimSpace(part[:idx]))
		value := strings.TrimSpace(part[idx+1:])
		if header == "" || value == "" {
			continue
		}

		m := TraceHeaderMatcher{
			header:   header,
			value:    value,
			anyValue: value == "*",
		}
		matchers = append(matchers, m)
	}

	if len(matchers) == 0 {
		return nil
	}

	return &TraceHeaderFilter{matchers: matchers}
}

func (f *TraceHeaderFilter) Matches(headers http.Header) bool {
	if f == nil || len(f.matchers) == 0 {
		return false
	}

	for _, m := range f.matchers {
		values := headers.Values(m.header)
		if len(values) == 0 {
			continue
		}

		if m.anyValue {
			return true
		}

		for _, v := range values {
			if strings.EqualFold(strings.TrimSpace(v), m.value) {
				return true
			}
		}
	}

	return false
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
