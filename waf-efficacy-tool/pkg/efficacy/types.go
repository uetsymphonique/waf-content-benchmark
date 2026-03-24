package efficacy

import "time"

// TestMode defines the testing mode
type TestMode string

const (
	ModeTruePositive  TestMode = "tp"
	ModeFalsePositive TestMode = "fp"
	ModeMixed         TestMode = "mixed"
)

// Payload represents a single test payload
type Payload struct {
	Index   int               `json:"-"` // Track index in JSON array
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Data    string            `json:"data"`
}

// TestResult represents the result of a single test
type TestResult struct {
	TestName      string
	Index         int
	URL           string
	Method        string
	StatusCode    int
	IsBlocked     bool
	Bypassed      bool   // For TP tests
	FalsePositive bool   // For FP tests
	DatasetType   string // "Malicious" or "Legitimate"
	Timestamp     time.Time
}

// TestSummary contains aggregated test results
type TestSummary struct {
	Mode               TestMode
	TotalRequests      int
	BypassedCount      int     // TP mode
	BlockedCount       int     // TP mode
	BypassRate         float64 // TP mode
	FalsePositiveCount int     // FP mode
	AllowedCount       int     // FP mode
	FPRate             float64 // FP mode
}

// LogLevel defines the logging verbosity
type LogLevel string

const (
	LogLevelSilent LogLevel = "silent"
	LogLevelError  LogLevel = "error"
	LogLevelInfo   LogLevel = "info"
	LogLevelDebug  LogLevel = "debug"
)

// Config holds the tool configuration
type Config struct {
	WAFURL               string
	MaliciousPath        string
	LegitimPath          string
	Mode                 TestMode
	OutputDir            string
	Timeout              int
	Workers              int
	LogLevel             LogLevel
	DumpStatus           string
	ExcludeDumpStatus    string
	DumpFile             string
	BlockedStatus        string
	ExcludeBlockedStatus string
	TraceHeaders         string
	StripHeaders         string
	SanitizeURL          bool
}
