package efficacy

import (
	"flag"
	"fmt"
)

func ParseFlags() (*Config, error) {
	cfg := &Config{}

	flag.StringVar(&cfg.WAFURL, "u", "", "WAF URL to test (required)")
	flag.StringVar(&cfg.MaliciousPath, "malicious", "Data/Malicious", "Path to malicious dataset")
	flag.StringVar(&cfg.LegitimPath, "legitimate", "Data/Legitimate", "Path to legitimate dataset")
	flag.StringVar(&cfg.OutputDir, "o", ".", "Output directory for results")
	flag.IntVar(&cfg.Timeout, "timeout", 5, "Request timeout in seconds")
	flag.IntVar(&cfg.Workers, "workers", 10, "Number of concurrent workers")

	// Mode flags
	tpOnly := flag.Bool("tp-only", false, "Test True Positive only")
	fpOnly := flag.Bool("fp-only", false, "Test False Positive only")
	logLevel := flag.String("log-level", "silent", "Logging level (silent, error, info, debug)")

	// Dump flags
	flag.StringVar(&cfg.DumpStatus, "dump-status", "", "Comma-separated list of status codes to dump raw requests for (e.g. 200,20*,4**)")
	flag.StringVar(&cfg.ExcludeDumpStatus, "exclude-dump-status", "", "Comma-separated status patterns excluded from dump-status (e.g. 403,416)")
	flag.StringVar(&cfg.DumpFile, "dump-file", "dumped_requests.log", "File to write dumped requests to")
	flag.StringVar(&cfg.BlockedStatus, "blocked-status", "4**", "Comma-separated status patterns treated as blocked (e.g. 403,40*,4**)")
	flag.StringVar(&cfg.ExcludeBlockedStatus, "exclude-blocked-status", "", "Comma-separated status patterns excluded from blocked-status (e.g. 400,416)")
	flag.StringVar(&cfg.StripHeaders, "strip-headers", "", "Comma-separated header names/prefixes to strip before send (e.g. Cookie,Origin,Referer,Sec-Fetch-*)")
	flag.BoolVar(&cfg.SanitizeURL, "sanitize-url", true, "Percent-encode bare absolute URL after '?' (e.g. ?https://...)")

	flag.Parse()

	if cfg.WAFURL == "" {
		return nil, fmt.Errorf("WAF URL is required (-u)")
	}

	cfg.LogLevel = LogLevel(*logLevel)

	// Determine mode (default to mixed)
	if *tpOnly {
		cfg.Mode = ModeTruePositive
	} else if *fpOnly {
		cfg.Mode = ModeFalsePositive
	} else {
		cfg.Mode = ModeMixed
	}

	return cfg, nil
}
