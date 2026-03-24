package efficacy

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type FileStats struct {
	RequestsFired int
	Prevented     int
	Bypassed      int
	Errored       int
	StatusCodes   map[int]int
}

type ResultAnalyzer struct {
	summary    TestSummary
	writer     *csv.Writer
	file       *os.File
	isWriting  bool
	hasHeaders bool
	mode       TestMode
	fileStats  map[string]*FileStats
}

func NewResultAnalyzer() *ResultAnalyzer {
	return &ResultAnalyzer{
		fileStats: make(map[string]*FileStats),
	}
}

func (ra *ResultAnalyzer) InitWriter(outputDir string, mode TestMode) error {
	var filename string
	ra.mode = mode
	ra.summary = TestSummary{Mode: mode}

	switch mode {
	case ModeTruePositive:
		filename = "tp_results.csv"
	case ModeFalsePositive:
		filename = "fp_results.csv"
	case ModeMixed:
		filename = "mixed_results.csv"
	}

	path := filepath.Join(outputDir, filename)
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	ra.file = file
	ra.writer = csv.NewWriter(file)
	ra.isWriting = true

	// Write header matching customizednuclei style
	header := []string{"test_file", "requests_fired", "prevented", "bypassed", "errored", "status_codes"}

	if err := ra.writer.Write(header); err != nil {
		return err
	}

	return nil
}

func (ra *ResultAnalyzer) CloseWriter() {
	if ra.isWriting && ra.writer != nil {
		ra.FinalizeCSV()
		ra.writer.Flush()
		if ra.file != nil {
			ra.file.Close()
		}
		ra.isWriting = false
	}
}

func (ra *ResultAnalyzer) FinalizeCSV() {
	for testName, fs := range ra.fileStats {
		var scParts []string
		for code, count := range fs.StatusCodes {
			scParts = append(scParts, fmt.Sprintf("%d:%d", code, count))
		}

		row := []string{
			testName,
			fmt.Sprintf("%d", fs.RequestsFired),
			fmt.Sprintf("%d", fs.Prevented),
			fmt.Sprintf("%d", fs.Bypassed),
			fmt.Sprintf("%d", fs.Errored),
			strings.Join(scParts, " "),
		}

		_ = ra.writer.Write(row)
	}
}

func (ra *ResultAnalyzer) AddResult(r TestResult) {
	// Update file-level metrics
	fs, exists := ra.fileStats[r.TestName]
	if !exists {
		fs = &FileStats{StatusCodes: make(map[int]int)}
		ra.fileStats[r.TestName] = fs
	}

	fs.RequestsFired++

	if r.StatusCode == 0 {
		fs.Errored++
	} else {
		fs.StatusCodes[r.StatusCode]++
		if r.IsBlocked {
			fs.Prevented++
		} else {
			fs.Bypassed++
		}
	}

	if r.StatusCode == 0 {
		return // Skip errors for global summary
	}

	// Update Global Metrics
	ra.summary.TotalRequests++

	if ra.mode == ModeTruePositive || (ra.mode == ModeMixed && r.DatasetType == "Malicious") {
		if r.Bypassed {
			ra.summary.BypassedCount++
		} else {
			ra.summary.BlockedCount++
		}
	} else if ra.mode == ModeFalsePositive || (ra.mode == ModeMixed && r.DatasetType == "Legitimate") {
		if r.FalsePositive {
			ra.summary.FalsePositiveCount++
		} else {
			ra.summary.AllowedCount++
		}
	}
}

func (ra *ResultAnalyzer) GetSummary() TestSummary {
	switch ra.mode {
	case ModeTruePositive:
		if ra.summary.TotalRequests > 0 {
			ra.summary.BypassRate = float64(ra.summary.BypassedCount) / float64(ra.summary.TotalRequests) * 100
		}
	case ModeFalsePositive:
		if ra.summary.TotalRequests > 0 {
			ra.summary.FPRate = float64(ra.summary.FalsePositiveCount) / float64(ra.summary.TotalRequests) * 100
		}
	case ModeMixed:
		tpTotal := ra.summary.BypassedCount + ra.summary.BlockedCount
		fpTotal := ra.summary.FalsePositiveCount + ra.summary.AllowedCount

		if tpTotal > 0 {
			ra.summary.BypassRate = float64(ra.summary.BypassedCount) / float64(tpTotal) * 100
		}
		if fpTotal > 0 {
			ra.summary.FPRate = float64(ra.summary.FalsePositiveCount) / float64(fpTotal) * 100
		}
	}

	return ra.summary
}

func (ra *ResultAnalyzer) PrintSummary() {
	fmt.Println("\n" + strings.Repeat("=", 60))

	switch ra.mode {
	case ModeTruePositive:
		fmt.Println("TRUE POSITIVE TEST RESULTS")
		fmt.Println(strings.Repeat("=", 60))
		fmt.Printf("Total Malicious Requests: %d\n", ra.summary.TotalRequests)
		fmt.Printf("Bypassed (Not 4xx):       %d\n", ra.summary.BypassedCount)
		fmt.Printf("Blocked (4xx):            %d\n", ra.summary.BlockedCount)
		fmt.Printf("Bypass Rate:              %.2f%%\n", ra.summary.BypassRate)

	case ModeFalsePositive:
		fmt.Println("FALSE POSITIVE TEST RESULTS")
		fmt.Println(strings.Repeat("=", 60))
		fmt.Printf("Total Legitimate Requests: %d\n", ra.summary.TotalRequests)
		fmt.Printf("Allowed (Not 4xx):         %d\n", ra.summary.AllowedCount)
		fmt.Printf("False Positives (4xx):     %d\n", ra.summary.FalsePositiveCount)
		fmt.Printf("False Positive Rate:       %.2f%%\n", ra.summary.FPRate)

	case ModeMixed:
		fmt.Println("MIXED TEST RESULTS")
		fmt.Println(strings.Repeat("=", 60))
		fmt.Println("True Positive Metrics:")
		fmt.Printf("  Bypassed:     %d\n", ra.summary.BypassedCount)
		fmt.Printf("  Blocked:      %d\n", ra.summary.BlockedCount)
		fmt.Printf("  Bypass Rate:  %.2f%%\n", ra.summary.BypassRate)
		fmt.Println("\nFalse Positive Metrics:")
		fmt.Printf("  Allowed:      %d\n", ra.summary.AllowedCount)
		fmt.Printf("  FP Count:     %d\n", ra.summary.FalsePositiveCount)
		fmt.Printf("  FP Rate:      %.2f%%\n", ra.summary.FPRate)
	}

	// Aggregate and print status code breakdown across all files
	totalStatus := make(map[int]int)
	for _, fs := range ra.fileStats {
		for code, cnt := range fs.StatusCodes {
			totalStatus[code] += cnt
		}
	}
	if len(totalStatus) > 0 {
		fmt.Println("\nStatus Code Breakdown:")
		// Sort status codes for stable output
		var codes []int
		for c := range totalStatus {
			codes = append(codes, c)
		}
		sort.Ints(codes)
		for _, c := range codes {
			fmt.Printf("  %d: %d\n", c, totalStatus[c])
		}
	}

	fmt.Println(strings.Repeat("=", 60))
}
