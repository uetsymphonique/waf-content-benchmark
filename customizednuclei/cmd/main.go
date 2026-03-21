package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"customizednuclei/internal/output"
	"customizednuclei/internal/runner"
	tmplcollect "customizednuclei/internal/template"
)

func main() {
	templatePath := flag.String("template", "", "Path to a nuclei template (.yaml) or a directory of templates")
	target := flag.String("target", "", "Target URL (e.g. https://example.com)")
	logLevel := flag.String("log-level", "info", "Log level: fatal | silent | error | info | warning | debug | verbose")
	outputPath := flag.String("output", "results.csv", "CSV output file path")
	cveFilter := flag.String("cve", "", "Comma-separated list or ranges of CVE folders (e.g. 2023,2024,2025-2027) to filter subfolders")
	concurrency := flag.Int("c", 5, "Number of concurrent workers")
	noPreprocess := flag.Bool("no-preprocess", false, "Disable template preprocessing — use raw Nuclei engine behaviour (for backend simulation mode)")
	mode := flag.String("mode", "cve", "Evaluation mode: 'cve' (1 block = full template prevented) or 'fuzz' (counts individual payload bypasses)")
	flag.Parse()

	if *templatePath == "" || *target == "" {
		fmt.Fprintln(os.Stderr, "Usage: nuclei-waf -template <path> -target <url>")
		flag.PrintDefaults()
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	templates, err := tmplcollect.Collect(*templatePath, *cveFilter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "template discovery error: %v\n", err)
		os.Exit(1)
	}

	csvFile, csvWriter, err := output.OpenCSV(*outputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open output csv: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		csvWriter.Flush()
		csvFile.Close()
	}()

	var mu sync.Mutex
	stats := output.NewStats(len(templates))

	// Clamp concurrency to [1, len(templates)].
	nWorkers := *concurrency
	if nWorkers < 1 {
		nWorkers = 1
	}
	if nWorkers > len(templates) {
		nWorkers = len(templates)
	}

	payloadConcurrency := *concurrency / nWorkers
	if payloadConcurrency < 1 {
		payloadConcurrency = 1
	}

	// Distribute template paths via a buffered job channel.
	jobs := make(chan string, len(templates))
	for _, t := range templates {
		jobs <- t
	}
	close(jobs)

	// Start real-time progress bar
	startTime := time.Now()
	var progressWg sync.WaitGroup
	progressWg.Add(1)
	printProgress := func() {
		mu.Lock()
		rowsWritten := stats.RowsWritten
		skippedErr := stats.Skipped + stats.Errored
		completed := rowsWritten + skippedErr
		mu.Unlock()

		reqs := atomic.LoadUint64(&stats.LiveRequestsFired)

		elapsed := time.Since(startTime)
		speed := 0.0
		if elapsed.Seconds() > 0 {
			speed = float64(reqs) / elapsed.Seconds()
		}
		msg := fmt.Sprintf("[Workers: %d, PayloadThreads: %d] Processed: %d/%d (Run: %d, Skip/Err: %d) | Requests Fired: %d | Speed: %.0f req/s | Elapsed: %s",
			nWorkers, payloadConcurrency, completed, stats.Total, rowsWritten, skippedErr, reqs, speed, elapsed.Round(time.Second))
		// Print with padded spaces to clear trailing characters
		fmt.Printf("\r%-110s", msg)
	}

	go func() {
		defer progressWg.Done()
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				printProgress()
				
				mu.Lock()
				completed := stats.RowsWritten + stats.Skipped + stats.Errored
				mu.Unlock()
				if completed >= stats.Total {
					return
				}
			}
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < nWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Each goroutine owns its own NucleiEngine — no shared engine state.
			r, err := runner.New(ctx, *target, *logLevel, payloadConcurrency, func() {
				atomic.AddUint64(&stats.LiveRequestsFired, 1)
			})
			if err != nil {
				mu.Lock()
				fmt.Fprintf(os.Stderr, "worker init error: %v\n", err)
				stats.Errored++
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

				res, err := r.Execute(ctx, t, !*noPreprocess)

				mu.Lock()
				if err != nil {
					fmt.Fprintf(os.Stderr, "[%s] execute error: %v\n", t, err)
					stats.Errored++
					mu.Unlock()
					continue
				}
				if res.Skipped {
					stats.Skipped++
					mu.Unlock()
					continue
				}
				stats.RequestsDefined += res.RequestsDefined
				stats.RequestsFired += res.RequestsFired
				if res.RequestsFired < res.RequestsDefined {
					stats.IncompleteTemplate++
					for code, count := range res.StatusCodes {
						stats.StatusCodesIncomplete[code] += count
					}
				} else {
					for code, count := range res.StatusCodes {
						stats.StatusCodesComplete[code] += count
					}
				}
				isComplete := res.RequestsFired == res.RequestsDefined
				isPreventedTemplate := false
				
				reqPrevented := 0
				reqErrored := 0
				for code, count := range res.StatusCodes {
					if code >= 400 && code < 500 {
						reqPrevented += count
						isPreventedTemplate = true
					}
					if code == 0 {
						reqErrored += count
					}
				}
				reqBypassed := res.RequestsFired - reqPrevented - reqErrored

				if isComplete {
					if isPreventedTemplate {
						stats.PreventedComplete++
					} else {
						stats.PassedComplete++
					}
				} else {
					if isPreventedTemplate {
						stats.PreventedIncomplete++
					} else {
						stats.UnknownIncomplete++
					}
				}

				csvWriter.Write([]string{ //nolint:errcheck
					res.TemplateID,
					t,
					res.Severity,
					strconv.Itoa(res.RequestsDefined),
					strconv.Itoa(res.RequestsFired),
					strconv.Itoa(reqPrevented),
					strconv.Itoa(reqBypassed),
					strconv.Itoa(reqErrored),
					output.FormatStatusCodes(res.StatusCodes),
				})
				stats.RowsWritten++
				if stats.RowsWritten%50 == 0 {
					csvWriter.Flush()
				}
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	printProgress()
	output.PrintStats(stats, *mode)
}
