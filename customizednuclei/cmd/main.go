package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"customizednuclei/internal/output"
	"customizednuclei/internal/runner"
	tmplcollect "customizednuclei/internal/template"
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

		matchers = append(matchers, TraceHeaderMatcher{
			header:   header,
			value:    value,
			anyValue: value == "*",
		})
	}

	if len(matchers) == 0 {
		return nil
	}

	return &TraceHeaderFilter{matchers: matchers}
}

func (f *TraceHeaderFilter) MatchesInternalEvent(event map[string]interface{}) bool {
	if f == nil || len(f.matchers) == 0 {
		return false
	}
	if event == nil {
		return false
	}

	for _, m := range f.matchers {
		key := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(m.header), "-", "_"))
		v, ok := event[key]
		if !ok {
			continue
		}

		if m.anyValue {
			return true
		}
		if strings.EqualFold(strings.TrimSpace(fmt.Sprintf("%v", v)), m.value) {
			return true
		}
	}

	return false
}

func main() {
	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	templatePath := fs.String("template", "", "Path to a nuclei template (.yaml) or a directory of templates")
	target := fs.String("target", "", "Target URL (e.g. https://example.com)")
	logLevel := fs.String("log-level", "info", "Log level: fatal | silent | error | info | warning | debug | verbose")
	outputPath := fs.String("output", "results.csv", "CSV output file path")
	cveFilter := fs.String("cve", "", "Comma-separated list or ranges of CVE folders (e.g. 2023,2024,2025-2027) to filter subfolders")
	vulnFilter := fs.String("vuln", "", "Comma-separated list of filename prefixes to filter templates (e.g. sqli,xss)")
	concurrency := fs.Int("c", 5, "Number of concurrent workers")
	noPreprocess := fs.Bool("no-preprocess", false, "Disable template preprocessing — use raw Nuclei engine behaviour (for backend simulation mode)")
	mode := fs.String("mode", "cve", "Evaluation mode: 'cve' (1 block = full template prevented) or 'fuzz' (counts individual payload bypasses)")
	dumpStatusFilter := fs.String("dump-status", "", "Comma-separated list of status codes to dump raw requests for (e.g. 200,20*,4**)")
	excludeDumpStatusFilter := fs.String("exclude-dump-status", "", "Comma-separated status patterns excluded from dump-status (e.g. 403,416)")
	dumpFilePath := fs.String("dump-file", "dumped_requests.log", "File to write dumped requests to")
	blockedStatus := fs.String("blocked-status", "", "Comma-separated status patterns treated as prevented/blocked (e.g. 403,40*,4**) (layer 1)")
	excludeBlockedStatus := fs.String("exclude-blocked-status", "", "Comma-separated status patterns excluded from blocked-status (e.g. 400,416)")
	traceHeaders := fs.String("trace-headers", "", "Comma-separated header:value pairs indicating request passed through proxy/backend (e.g. X-Trace-Proxy:apache,X-Trace-Layer:backend-flask or X-Trace-Proxy:*) (layer 2)")

	if err := fs.Parse(os.Args[1:]); err != nil {
		if err == flag.ErrHelp {
			os.Exit(0)
		}
		os.Exit(2)
	}

	if *templatePath == "" || *target == "" {
		fmt.Fprintln(os.Stderr, "Usage: nuclei-waf -template <path> -target <url>")
		fs.PrintDefaults()
		os.Exit(1)
	}
	if *blockedStatus == "" && *traceHeaders == "" {
		fmt.Fprintln(os.Stderr, "at least one detection layer is required: define -blocked-status and/or -trace-headers")
		os.Exit(1)
	}
	if *blockedStatus == "" && *excludeBlockedStatus != "" {
		fmt.Fprintln(os.Stderr, "-exclude-blocked-status requires -blocked-status")
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	templates, err := tmplcollect.Collect(*templatePath, *cveFilter, *vulnFilter)
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
	var dumpMu sync.Mutex
	var dumpWriter *os.File
	dumpFilter := ParseStatusFilter(*dumpStatusFilter)
	excludeDumpFilter := ParseStatusFilter(*excludeDumpStatusFilter)
	blockedFilter := ParseStatusFilter(*blockedStatus)
	excludeBlockedFilter := ParseStatusFilter(*excludeBlockedStatus)
	traceHeaderFilter := ParseTraceHeaderFilter(*traceHeaders)

	if dumpFilter != nil {
		f, err := os.OpenFile(*dumpFilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to open dump file: %v\n", err)
			os.Exit(1)
		}
		dumpWriter = f
		defer dumpWriter.Close()
	}

	stats := output.NewStats(len(templates))

	if len(templates) == 0 {
		fmt.Fprintln(os.Stderr, "No templates found matching the criteria")
		os.Exit(1)
	}

	var nWorkers, payloadConcurrency int
	if *mode == "fuzz" {
		// Fuzzing Mode: Templates are 'fat' (contain thousands of payloads).
		// Processing them sequentially (1 worker) with ALL concurrency allocated to payload threads
		// prevents starvation where short templates finish and leave long templates stuck at low concurrency.
		nWorkers = 1
		payloadConcurrency = *concurrency
		if payloadConcurrency < 1 {
			payloadConcurrency = 1
		}
	} else {
		// CVE Mode: Templates are 'thin' (contain 1 payload).
		// Maximise parallel workers to process multiple templates simultaneously.
		nWorkers = *concurrency
		if nWorkers < 1 {
			nWorkers = 1
		}
		if nWorkers > len(templates) {
			nWorkers = len(templates)
		}
		payloadConcurrency = *concurrency / nWorkers
		if payloadConcurrency < 1 {
			payloadConcurrency = 1
		}
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
			r, err := runner.New(ctx, *target, *logLevel, payloadConcurrency, traceHeaderFilter.MatchesInternalEvent, func(statusCode int, rawRequest string) {
				atomic.AddUint64(&stats.LiveRequestsFired, 1)
				if dumpFilter != nil && dumpFilter.Matches(statusCode) && (excludeDumpFilter == nil || !excludeDumpFilter.Matches(statusCode)) && rawRequest != "" {
					dumpMu.Lock()
					fmt.Fprintf(dumpWriter, "========== [Status: %d] ==========\n%s\n\n", statusCode, rawRequest)
					dumpMu.Unlock()
				}
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
				if res != nil {
					stats.RequestsDefined += res.RequestsDefined

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
				}

				if err != nil {
					fmt.Fprintf(os.Stderr, "[%s] execute error: %v\n", t, err)
					stats.Errored++
					mu.Unlock()
					continue
				}
				if res == nil || res.Skipped {
					if res != nil && res.Skipped {
						stats.Skipped++
					}
					mu.Unlock()
					continue
				}
				isComplete := res.RequestsFired == res.RequestsDefined

				reqPrevented := 0
				reqErrored := 0
				for code, count := range res.StatusCodes {
					if code == 0 {
						reqErrored += count
						continue
					}

					tracePassedCount := res.TraceMatchedStatusCodes[code]
					if tracePassedCount < 0 {
						tracePassedCount = 0
					}
					if tracePassedCount > count {
						tracePassedCount = count
					}

					statusLayerEnabled := blockedFilter != nil
					traceLayerEnabled := traceHeaderFilter != nil

					statusBlockedCount := 0
					if statusLayerEnabled && blockedFilter.Matches(code) {
						statusBlockedCount = count
						if excludeBlockedFilter != nil && excludeBlockedFilter.Matches(code) {
							statusBlockedCount = 0
						}
					}

					switch {
					case statusLayerEnabled && traceLayerEnabled:
						blockedCount := statusBlockedCount - tracePassedCount
						if blockedCount > 0 {
							reqPrevented += blockedCount
						}
					case statusLayerEnabled:
						reqPrevented += statusBlockedCount
					case traceLayerEnabled:
						reqPrevented += count - tracePassedCount
					}
				}
				isPreventedTemplate := reqPrevented > 0
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
