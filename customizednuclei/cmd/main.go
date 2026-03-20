package main

import (
	"context"
	"encoding/csv"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"customizednuclei/runner"
)

func main() {
	templatePath := flag.String("template", "", "Path to a nuclei template (.yaml) or a directory of templates")
	target := flag.String("target", "", "Target URL (e.g. https://example.com)")
	logLevel := flag.String("log-level", "info", "Log level: fatal | silent | error | info | warning | debug | verbose")
	output := flag.String("output", "results.csv", "CSV output file path")
	cveFilter := flag.String("cve", "", "Comma-separated list or ranges of CVE folders (e.g. 2023,2024,2025-2027) to filter subfolders")
	concurrency := flag.Int("c", 5, "Number of concurrent workers") // New flag for concurrency
	flag.Parse()

	if *templatePath == "" || *target == "" {
		fmt.Fprintln(os.Stderr, "Usage: nuclei-waf -template <path> -target <url>")
		flag.PrintDefaults()
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	templates, err := collectTemplates(*templatePath, *cveFilter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "template discovery error: %v\n", err)
		os.Exit(1)
	}

	csvFile, csvWriter, err := openCSV(*output)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open output csv: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		csvWriter.Flush()
		csvFile.Close()
	}()

	// Shared stats — protected by mu.
	var mu sync.Mutex
	var stats struct {
		total           int
		skipped         int
		errored            int
		requestsDefined    int
		requestsFired      int
		incompleteTemplate int
		preventedComplete     int
		passedComplete        int
		preventedIncomplete   int
		unknownIncomplete     int
		statusCodesComplete   map[int]int
		statusCodesIncomplete map[int]int
		rowsWritten        int // tracks rows for periodic flush
	}
	stats.total = len(templates)
	stats.statusCodesComplete = make(map[int]int)
	stats.statusCodesIncomplete = make(map[int]int)

	// Clamp concurrency to [1, len(templates)].
	nWorkers := *concurrency
	if nWorkers < 1 {
		nWorkers = 1
	}
	if nWorkers > len(templates) {
		nWorkers = len(templates)
	}

	// Distribute template paths via a buffered job channel.
	jobs := make(chan string, len(templates))
	for _, t := range templates {
		jobs <- t
	}
	close(jobs)

	var wg sync.WaitGroup
	for i := 0; i < nWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Each goroutine owns its own NucleiEngine — no shared engine state.
			r, err := runner.New(ctx, *target, *logLevel)
			if err != nil {
				mu.Lock()
				fmt.Fprintf(os.Stderr, "worker init error: %v\n", err)
				stats.errored++
				mu.Unlock()
				return
			}
			defer r.Close()

			for t := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}

				res, err := r.Execute(ctx, t)

				mu.Lock()
				if err != nil {
					fmt.Fprintf(os.Stderr, "[%s] execute error: %v\n", t, err)
					stats.errored++
					mu.Unlock()
					continue
				}
				if res.Skipped {
					stats.skipped++
					mu.Unlock()
					continue
				}
				stats.requestsDefined += res.RequestsDefined
				stats.requestsFired += res.RequestsFired
				if res.RequestsFired < res.RequestsDefined {
					stats.incompleteTemplate++
					for code, count := range res.StatusCodes {
						stats.statusCodesIncomplete[code] += count
					}
				} else {
					for code, count := range res.StatusCodes {
						stats.statusCodesComplete[code] += count
					}
				}
				isComplete := res.RequestsFired == res.RequestsDefined
				isPrevented := false
				for code := range res.StatusCodes {
					if code >= 400 && code < 500 {
						isPrevented = true
						break
					}
				}

				var bypassStatus string
				if isComplete {
					if isPrevented {
						bypassStatus = "prevented"
						stats.preventedComplete++
					} else {
						bypassStatus = "pass"
						stats.passedComplete++
					}
				} else {
					if isPrevented {
						bypassStatus = "prevented"
						stats.preventedIncomplete++
					} else {
						bypassStatus = "unknown"
						stats.unknownIncomplete++
					}
				}

				csvWriter.Write([]string{ //nolint:errcheck
					res.TemplateID,
					t,
					strconv.Itoa(res.RequestsDefined),
					strconv.Itoa(res.RequestsFired),
					strconv.FormatBool(isComplete),
					bypassStatus,
					formatStatusCodes(res.StatusCodes),
				})
				stats.rowsWritten++
				if stats.rowsWritten%50 == 0 {
					csvWriter.Flush()
				}
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	printStats(stats.total, stats.skipped, stats.errored, stats.incompleteTemplate, stats.requestsDefined, stats.requestsFired,
		stats.preventedComplete, stats.passedComplete, stats.preventedIncomplete, stats.unknownIncomplete,
		stats.statusCodesComplete, stats.statusCodesIncomplete)
}

func printStats(total, skipped, errored, incomplete, defined, fired, prevComp, passComp, prevIncomp, unkIncomp int, statusCodesComplete map[int]int, statusCodesIncomplete map[int]int) {
	sep := strings.Repeat("─", 60)
	fmt.Printf("\n%s\n", sep)
	fmt.Printf("Templates : %d total", total)
	if skipped > 0 {
		fmt.Printf("  (%d skipped)", skipped)
	}
	if errored > 0 {
		fmt.Printf("  (%d errored)", errored)
	}
	if incomplete > 0 {
		fmt.Printf("  (%d incomplete)", incomplete)
	}
	fmt.Println()
	fmt.Printf("Requests  : %d defined / %d fired\n", defined, fired)
	if totalExecComp := prevComp + passComp; totalExecComp > 0 {
		pctPrev := float64(prevComp) / float64(totalExecComp) * 100
		pctPass := float64(passComp) / float64(totalExecComp) * 100
		fmt.Printf("Bypass (Complete)   : %d prevented (%.1f%%) / %d passed (%.1f%%)\n", prevComp, pctPrev, passComp, pctPass)
	}
	if totalExecIncomp := prevIncomp + unkIncomp; totalExecIncomp > 0 {
		pctPrev := float64(prevIncomp) / float64(totalExecIncomp) * 100
		pctUnk := float64(unkIncomp) / float64(totalExecIncomp) * 100
		fmt.Printf("Bypass (Incomplete) : %d prevented (%.1f%%) / %d unknown (%.1f%%)\n", prevIncomp, pctPrev, unkIncomp, pctUnk)
	}
	if len(statusCodesComplete) > 0 {
		fmt.Printf("Stats (Complete)   : %s\n", formatStatusCodes(statusCodesComplete))
	}
	if len(statusCodesIncomplete) > 0 {
		fmt.Printf("Stats (Incomplete) : %s\n", formatStatusCodes(statusCodesIncomplete))
	}
	fmt.Printf("%s\n", sep)
}

func openCSV(path string) (*os.File, *csv.Writer, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}
	w := csv.NewWriter(f)
	w.Write([]string{"template_id", "template_file", "requests_defined", "requests_fired", "completed", "bypass_status", "status_codes"})
	return f, w, nil
}

// collectTemplates returns a list of .yaml template paths.
// If path points to a file it returns that file; if it points to a directory
// it walks the entire tree and collects every .yaml / .yml file.
// If cveFilter is provided, it only descends into direct subdirectories
// that match the allowed years/folders.
func collectTemplates(basePath, cveFilter string) ([]string, error) {
	info, err := os.Stat(basePath)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{basePath}, nil
	}

	allowed := parseCVEFilter(cveFilter)
	cleanBasePath := filepath.Clean(basePath)
	var templates []string

	err = filepath.WalkDir(basePath, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if len(allowed) > 0 && p != cleanBasePath && filepath.Dir(p) == cleanBasePath {
				if !allowed[d.Name()] {
					return fs.SkipDir
				}
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		if ext == ".yaml" || ext == ".yml" {
			templates = append(templates, p)
		}
		return nil
	})
	return templates, err
}

func formatStatusCodes(codes map[int]int) string {
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

func parseCVEFilter(filter string) map[string]bool {
	allowed := make(map[string]bool)
	if filter == "" {
		return allowed
	}
	parts := strings.Split(filter, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if strings.Contains(p, "-") {
			bounds := strings.SplitN(p, "-", 2)
			if len(bounds) == 2 {
				start, err1 := strconv.Atoi(strings.TrimSpace(bounds[0]))
				end, err2 := strconv.Atoi(strings.TrimSpace(bounds[1]))
				if err1 == nil && err2 == nil && start <= end {
					for i := start; i <= end; i++ {
						allowed[strconv.Itoa(i)] = true
					}
					continue
				}
			}
		}
		// If not a range or range failed to parse, add exactly as literal
		if p != "" {
			allowed[p] = true
		}
	}
	return allowed
}
