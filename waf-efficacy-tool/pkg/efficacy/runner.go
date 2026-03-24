package efficacy

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/schollz/progressbar/v3"
)

type Runner struct {
	cfg             *Config
	client          *HTTPClient
	analyzer        *ResultAnalyzer
	stripHeaderSpec []string
}

func NewRunner(cfg *Config, client *HTTPClient, analyzer *ResultAnalyzer) *Runner {
	return &Runner{
		cfg:             cfg,
		client:          client,
		analyzer:        analyzer,
		stripHeaderSpec: parseHeaderStripSpec(cfg.StripHeaders),
	}
}

func (r *Runner) Run() {
	// Set up dump writer
	var dumpMu *sync.Mutex
	var dumpWriter *os.File
	dumpFilter := ParseStatusFilter(r.cfg.DumpStatus)
	excludeDumpFilter := ParseStatusFilter(r.cfg.ExcludeDumpStatus)

	if dumpFilter != nil {
		f, err := os.OpenFile(r.cfg.DumpFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			log.Fatalf("Failed to open dump file: %v", err)
		}
		dumpWriter = f
		dumpMu = &sync.Mutex{}
		defer dumpWriter.Close()
	}

	// Run tests based on mode
	switch r.cfg.Mode {
	case ModeTruePositive:
		r.runTPTest(dumpFilter, excludeDumpFilter, dumpWriter, dumpMu)
	case ModeFalsePositive:
		r.runFPTest(dumpFilter, excludeDumpFilter, dumpWriter, dumpMu)
	case ModeMixed:
		r.runTPTest(dumpFilter, excludeDumpFilter, dumpWriter, dumpMu)
		r.runFPTest(dumpFilter, excludeDumpFilter, dumpWriter, dumpMu)
	}
}

func (r *Runner) runTPTest(dumpFilter *StatusFilter, excludeDumpFilter *StatusFilter, dumpWriter *os.File, dumpMu *sync.Mutex) {
	fmt.Println("Running True Positive tests...")

	loader := NewPayloadLoader(r.cfg.MaliciousPath)
	files, err := loader.GetFiles()
	if err != nil {
		log.Fatalf("Failed to locate malicious datasets: %v", err)
	}

	r.runTests(files, "Malicious", loader, dumpFilter, excludeDumpFilter, dumpWriter, dumpMu)
}

func (r *Runner) runFPTest(dumpFilter *StatusFilter, excludeDumpFilter *StatusFilter, dumpWriter *os.File, dumpMu *sync.Mutex) {
	fmt.Println("Running False Positive tests...")

	loader := NewPayloadLoader(r.cfg.LegitimPath)
	files, err := loader.GetFiles()
	if err != nil {
		log.Fatalf("Failed to locate legitimate datasets: %v", err)
	}

	r.runTests(files, "Legitimate", loader, dumpFilter, excludeDumpFilter, dumpWriter, dumpMu)
}

func (r *Runner) runTests(files map[string]string, datasetType string, loader *PayloadLoader, dumpFilter *StatusFilter, excludeDumpFilter *StatusFilter, dumpWriter *os.File, dumpMu *sync.Mutex) {
	// Initialize progress bar without a known total at first
	bar := progressbar.Default(-1, "Processing Payloads")

	resultsChan := make(chan TestResult, r.cfg.Workers*2)

	// Create a channel for workers to consume payloads
	type job struct {
		testName string
		payload  Payload
	}
	jobsChan := make(chan job, r.cfg.Workers*2)

	// Start workers
	var wgWorkers sync.WaitGroup
	for i := 0; i < r.cfg.Workers; i++ {
		wgWorkers.Add(1)
		go func() {
			defer wgWorkers.Done()
			for j := range jobsChan {
				ctx, cancel := context.WithTimeout(context.Background(), time.Duration(r.cfg.Timeout)*time.Second)

				// Normalize and inject testName into URL for traceability
				payloadURL := sanitizeBareAbsoluteQueryURL(j.payload.URL, r.cfg.SanitizeURL)
				j.payload.Headers = stripHeadersBySpec(j.payload.Headers, r.stripHeaderSpec)
				if !strings.HasPrefix(payloadURL, "/") {
					payloadURL = "/" + payloadURL
				}
				j.payload.URL = "/" + j.testName + payloadURL

				statusCode, isBlocked, err := r.client.SendRequest(ctx, j.payload)
				cancel()

				if err != nil {
					statusCode = 0
					isBlocked = false
				} else if dumpFilter != nil && dumpFilter.Matches(statusCode) && (excludeDumpFilter == nil || !excludeDumpFilter.Matches(statusCode)) {
					rawReq := r.client.FormatRawRequest(j.payload)
					dumpMu.Lock()
					fmt.Fprintf(dumpWriter, "========== [Status: %d] ==========\n%s\n\n", statusCode, rawReq)
					dumpMu.Unlock()
				}

				result := TestResult{
					TestName:    j.testName,
					Index:       j.payload.Index,
					URL:         j.payload.URL,
					Method:      j.payload.Method,
					StatusCode:  statusCode,
					IsBlocked:   isBlocked,
					DatasetType: datasetType,
					Timestamp:   time.Now(),
				}

				if datasetType == "Malicious" {
					result.Bypassed = !isBlocked
				} else {
					result.FalsePositive = isBlocked
				}

				resultsChan <- result
				bar.Add(1)
			}
		}()
	}

	// Result collector
	var wgCollector sync.WaitGroup
	wgCollector.Add(1)
	go func() {
		defer wgCollector.Done()
		for result := range resultsChan {
			r.analyzer.AddResult(result)
		}
	}()

	// Read files and stream payloads
	for testName, path := range files {
		payloadsChan := make(chan Payload, 100)

		var fileWg sync.WaitGroup
		fileWg.Add(1)
		go func(tn string) {
			defer fileWg.Done()
			for p := range payloadsChan {
				jobsChan <- job{testName: tn, payload: p}
			}
		}(testName)

		_, err := loader.StreamFile(path, payloadsChan)
		if err != nil {
			log.Printf("Warning: failed to fully read %s: %v", path, err)
		}
		close(payloadsChan)
		fileWg.Wait() // wait for current file to finish sending to jobs
	}

	// Signal workers no more jobs
	close(jobsChan)
	// Wait for workers to finish
	wgWorkers.Wait()
	// Signal collector no more results
	close(resultsChan)
	// Wait for collector to finish
	wgCollector.Wait()

	bar.Finish()
	fmt.Println()
}

func sanitizeBareAbsoluteQueryURL(rawURL string, enabled bool) string {
	if !enabled {
		return rawURL
	}
	q := strings.Index(rawURL, "?")
	if q < 0 || q == len(rawURL)-1 {
		return rawURL
	}
	prefix := rawURL[:q+1]
	query := rawURL[q+1:]
	if strings.HasPrefix(query, "http://") || strings.HasPrefix(query, "https://") {
		return prefix + url.QueryEscape(query)
	}
	return rawURL
}

func parseHeaderStripSpec(spec string) []string {
	if spec == "" {
		return nil
	}
	parts := strings.Split(spec, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func stripHeadersBySpec(headers map[string]string, spec []string) map[string]string {
	if len(spec) == 0 || len(headers) == 0 {
		return headers
	}
	filtered := make(map[string]string, len(headers))
	for k, v := range headers {
		if shouldStripHeader(k, spec) {
			continue
		}
		filtered[k] = v
	}
	return filtered
}

func shouldStripHeader(header string, spec []string) bool {
	h := strings.ToLower(strings.TrimSpace(header))
	for _, s := range spec {
		if strings.HasSuffix(s, "*") {
			prefix := strings.TrimSuffix(s, "*")
			if strings.HasPrefix(h, prefix) {
				return true
			}
			continue
		}
		if h == s {
			return true
		}
	}
	return false
}
