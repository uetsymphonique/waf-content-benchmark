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
	concurrency := flag.Int("c", 5, "Number of concurrent workers") // New flag for concurrency
	flag.Parse()

	if *templatePath == "" || *target == "" {
		fmt.Fprintln(os.Stderr, "Usage: nuclei-waf -template <path> -target <url>")
		flag.PrintDefaults()
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	templates, err := collectTemplates(*templatePath)
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
		errored         int
		requestsDefined int
		requestsFired   int
		statusCodes     map[int]int
		rowsWritten     int // tracks rows for periodic flush
	}
	stats.total = len(templates)
	stats.statusCodes = make(map[int]int)

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
				for code, count := range res.StatusCodes {
					stats.statusCodes[code] += count
				}
				csvWriter.Write([]string{ //nolint:errcheck
					res.TemplateID,
					t,
					strconv.Itoa(res.RequestsDefined),
					strconv.Itoa(res.RequestsFired),
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

	printStats(stats.total, stats.skipped, stats.errored, stats.requestsDefined, stats.requestsFired, stats.statusCodes)
}

func printStats(total, skipped, errored, defined, fired int, statusCodes map[int]int) {
	sep := strings.Repeat("─", 60)
	fmt.Printf("\n%s\n", sep)
	fmt.Printf("Templates : %d total", total)
	if skipped > 0 {
		fmt.Printf("  (%d skipped)", skipped)
	}
	if errored > 0 {
		fmt.Printf("  (%d errored)", errored)
	}
	fmt.Println()
	fmt.Printf("Requests  : %d defined / %d fired\n", defined, fired)
	if len(statusCodes) > 0 {
		fmt.Print("Status    : ")
		var parts []string
		var sortedKeys []int
		for k := range statusCodes {
			sortedKeys = append(sortedKeys, k)
		}
		sort.Ints(sortedKeys)
		for _, k := range sortedKeys {
			parts = append(parts, fmt.Sprintf("%d:%d", k, statusCodes[k]))
		}
		fmt.Printf("%s\n", strings.Join(parts, ", "))
	}
	fmt.Printf("%s\n", sep)
}

func openCSV(path string) (*os.File, *csv.Writer, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}
	w := csv.NewWriter(f)
	w.Write([]string{"template_id", "template_file", "requests_defined", "requests_fired", "status_codes"})
	return f, w, nil
}

// collectTemplates returns a list of .yaml template paths.
// If path points to a file it returns that file; if it points to a directory
// it walks the entire tree and collects every .yaml / .yml file.
func collectTemplates(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{path}, nil
	}

	var templates []string
	err = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			ext := strings.ToLower(filepath.Ext(p))
			if ext == ".yaml" || ext == ".yml" {
				templates = append(templates, p)
			}
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
