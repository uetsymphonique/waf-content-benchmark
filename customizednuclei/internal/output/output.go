package output

import (
	"encoding/csv"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Stats holds accumulated benchmark statistics across all templates.
type Stats struct {
	LiveRequestsFired    uint64 // Lock-free atomic counter for streaming progress metrics
	Total                int
	Skipped              int
	Errored              int
	IncompleteTemplate   int
	RequestsDefined      int
	RequestsFired        int
	PreventedComplete    int
	PassedComplete       int
	PreventedIncomplete  int
	UnknownIncomplete    int
	StatusCodesComplete   map[int]int
	StatusCodesIncomplete map[int]int
	RowsWritten          int
}

// NewStats creates a zeroed Stats with initialised maps.
func NewStats(total int) *Stats {
	return &Stats{
		Total:                 total,
		StatusCodesComplete:   make(map[int]int),
		StatusCodesIncomplete: make(map[int]int),
	}
}

// OpenCSV creates (or truncates) a CSV file and writes the header row.
func OpenCSV(path string) (*os.File, *csv.Writer, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}
	w := csv.NewWriter(f)
	w.Write([]string{"template_id", "template_file", "requests_defined", "requests_fired", "prevented_count", "bypassed_count", "errored_count", "status_codes"}) //nolint:errcheck
	return f, w, nil
}

// FormatStatusCodes serialises a status-code→count map as "200:5,403:2".
func FormatStatusCodes(codes map[int]int) string {
	if len(codes) == 0 {
		return ""
	}
	var parts []string
	var sortedKeys []int
	for k := range codes {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Ints(sortedKeys)
	for _, k := range sortedKeys {
		parts = append(parts, fmt.Sprintf("%d:%d", k, codes[k]))
	}
	return strings.Join(parts, ",")
}

// PrintStats prints a summary table to stderr, tailored to the selected evaluation mode.
func PrintStats(s *Stats, mode string) {
	sep := strings.Repeat("─", 60)
	fmt.Fprintf(os.Stderr, "\n%s\n", sep)
	fmt.Fprintf(os.Stderr, "Templates : %d total", s.Total)
	
	totalSkippedErr := s.Skipped + s.Errored
	if totalSkippedErr > 0 || s.IncompleteTemplate > 0 {
		fmt.Fprintf(os.Stderr, "  (%d skipped/err)", totalSkippedErr)
		if s.IncompleteTemplate > 0 {
			fmt.Fprintf(os.Stderr, "  (%d incomplete)", s.IncompleteTemplate)
		}
	}
	fmt.Fprintf(os.Stderr, "\nRequests  : %d defined / %d fired\n\n", s.RequestsDefined, s.RequestsFired)

	if mode == "cve" {
		fmt.Fprintf(os.Stderr, "[ CVE / Template Metrics ]\n")
		completeTotal := s.PreventedComplete + s.PassedComplete
		fmt.Fprintf(os.Stderr, "Templates (Complete)  : %d\n", completeTotal)
		if completeTotal > 0 {
			pctPrev := float64(s.PreventedComplete) / float64(completeTotal) * 100
			pctPass := float64(s.PassedComplete) / float64(completeTotal) * 100
			fmt.Fprintf(os.Stderr, "Coverage  (Complete)  : %d prevented (%.1f%%) / %d bypassed (%.1f%%)\n", s.PreventedComplete, pctPrev, s.PassedComplete, pctPass)
		}

		incompTotal := s.PreventedIncomplete + s.UnknownIncomplete
		fmt.Fprintf(os.Stderr, "Templates (Incomplete): %d\n", incompTotal)
		if incompTotal > 0 {
			pctPrev := float64(s.PreventedIncomplete) / float64(incompTotal) * 100
			pctUnk := float64(s.UnknownIncomplete) / float64(incompTotal) * 100
			fmt.Fprintf(os.Stderr, "Coverage  (Incomplete): %d prevented (%.1f%%) / %d bypassed (%.1f%%)\n", s.PreventedIncomplete, pctPrev, s.UnknownIncomplete, pctUnk)
		}

		if len(s.StatusCodesComplete) > 0 {
			fmt.Fprintf(os.Stderr, "Status Codes (Complt) : %s\n", FormatStatusCodes(s.StatusCodesComplete))
		}
		if len(s.StatusCodesIncomplete) > 0 {
			fmt.Fprintf(os.Stderr, "Status Codes (Incmp)  : %s\n", FormatStatusCodes(s.StatusCodesIncomplete))
		}

	} else if mode == "fuzz" {
		fmt.Fprintf(os.Stderr, "[ Fuzz / Request Metrics ]\n")
		totalCodes := make(map[int]int)
		for c, n := range s.StatusCodesComplete { totalCodes[c] += n }
		for c, n := range s.StatusCodesIncomplete { totalCodes[c] += n }

		reqPrevented := 0
		reqErrored := totalCodes[0]
		for c, n := range totalCodes {
			if c >= 400 && c < 500 {
				reqPrevented += n
			}
		}
		reqPassed := s.RequestsFired - reqPrevented - reqErrored

		fmt.Fprintf(os.Stderr, "Requests  (Fired)     : %d\n", s.RequestsFired)
		if s.RequestsFired > 0 {
			pctPrev := float64(reqPrevented) / float64(s.RequestsFired) * 100
			pctPass := float64(reqPassed) / float64(s.RequestsFired) * 100
			pctErr := float64(reqErrored) / float64(s.RequestsFired) * 100

			fmt.Fprintf(os.Stderr, "Payloads  (Prevented) : %d (%.1f%%)\n", reqPrevented, pctPrev)
			fmt.Fprintf(os.Stderr, "Payloads  (Bypassed)  : %d (%.1f%%)\n", reqPassed, pctPass)
			fmt.Fprintf(os.Stderr, "Payloads  (Errored)   : %d (%.1f%%)\n", reqErrored, pctErr)
		}
		fmt.Fprintf(os.Stderr, "Status Codes          : %s\n", FormatStatusCodes(totalCodes))
	}

	fmt.Fprintf(os.Stderr, "%s\n", sep)
}
