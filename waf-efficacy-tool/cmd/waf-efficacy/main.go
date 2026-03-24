package main

import (
	"fmt"
	"log"

	"waf-efficacy-tool/pkg/efficacy"
)

func main() {
	// Parse config
	cfg, err := efficacy.ParseFlags()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("WAF Efficacy Testing Tool\n")
	fmt.Printf("Target: %s\n", cfg.WAFURL)
	fmt.Printf("Mode: %s\n\n", cfg.Mode)

	// Initialize Logger
	efficacy.InitLogger(cfg.LogLevel)

	// Initialize components
	blockedFilter := efficacy.ParseStatusFilter(cfg.BlockedStatus)
	excludeBlockedFilter := efficacy.ParseStatusFilter(cfg.ExcludeBlockedStatus)
	client := efficacy.NewHTTPClient(cfg.WAFURL, cfg.Timeout, blockedFilter, excludeBlockedFilter)
	analyzer := efficacy.NewResultAnalyzer()

	if err := analyzer.InitWriter(cfg.OutputDir, cfg.Mode); err != nil {
		log.Fatalf("Failed to initialize CSV writer: %v", err)
	}
	defer analyzer.CloseWriter()

	// Initialize and run the test runner
	runner := efficacy.NewRunner(cfg, client, analyzer)
	runner.Run()

	// Generate summary and save results
	_ = analyzer.GetSummary()
	analyzer.PrintSummary()
}
