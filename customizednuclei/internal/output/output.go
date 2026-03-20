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
	w.Write([]string{"template_id", "template_file", "requests_defined", "requests_fired", "completed", "bypass_status", "status_codes"}) //nolint:errcheck
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

// PrintStats prints a summary table to stdout.
func PrintStats(s *Stats) {
	sep := strings.Repeat("─", 60)
	fmt.Printf("\n%s\n", sep)
	fmt.Printf("Templates : %d total", s.Total)
	if s.Skipped > 0 {
		fmt.Printf("  (%d skipped)", s.Skipped)
	}
	if s.Errored > 0 {
		fmt.Printf("  (%d errored)", s.Errored)
	}
	if s.IncompleteTemplate > 0 {
		fmt.Printf("  (%d incomplete)", s.IncompleteTemplate)
	}
	fmt.Println()
	fmt.Printf("Requests  : %d defined / %d fired\n", s.RequestsDefined, s.RequestsFired)
	if totalExecComp := s.PreventedComplete + s.PassedComplete; totalExecComp > 0 {
		pctPrev := float64(s.PreventedComplete) / float64(totalExecComp) * 100
		pctPass := float64(s.PassedComplete) / float64(totalExecComp) * 100
		fmt.Printf("Bypass (Complete)   : %d prevented (%.1f%%) / %d passed (%.1f%%)\n", s.PreventedComplete, pctPrev, s.PassedComplete, pctPass)
	}
	if totalExecIncomp := s.PreventedIncomplete + s.UnknownIncomplete; totalExecIncomp > 0 {
		pctPrev := float64(s.PreventedIncomplete) / float64(totalExecIncomp) * 100
		pctUnk := float64(s.UnknownIncomplete) / float64(totalExecIncomp) * 100
		fmt.Printf("Bypass (Incomplete) : %d prevented (%.1f%%) / %d unknown (%.1f%%)\n", s.PreventedIncomplete, pctPrev, s.UnknownIncomplete, pctUnk)
	}
	if len(s.StatusCodesComplete) > 0 {
		fmt.Printf("Stats (Complete)   : %s\n", FormatStatusCodes(s.StatusCodesComplete))
	}
	if len(s.StatusCodesIncomplete) > 0 {
		fmt.Printf("Stats (Incomplete) : %s\n", FormatStatusCodes(s.StatusCodesIncomplete))
	}
	fmt.Printf("%s\n", sep)
}
