package runner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"customizednuclei/internal/preprocess"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/testutils"
)

// Runner wraps the Nuclei engine for WAF testing.
type Runner struct {
	target           string
	engine           *nuclei.NucleiEngine
	OnResultCallback func()
}

// New creates a NucleiEngine (which fully initialises all required internals),
// then wraps it for per-template execution.
//
// logLevel controls gologger output: "silent" | "info" (default) | "debug" | "verbose".
// At "debug" level, Nuclei also dumps raw HTTP request/response via [INF]/[DBG] messages.
func New(ctx context.Context, target, logLevel string, payloadConcurrency int, onProgress func()) (*Runner, error) {
	lvl := parseLogLevel(logLevel)
	gologger.DefaultLogger.SetMaxLevel(lvl)

	ensureIgnoreFile()

	if payloadConcurrency < 1 {
		payloadConcurrency = 1
	}

	progressClient := &LiveProgressClient{}

	// Always enable request/response dumping so Nuclei generates the log
	// messages; gologger's level filter decides what actually gets printed:
	//   info    → [INF] request only
	//   debug   → [INF] request + [DBG] response
	//   verbose → [INF] request + [VER] sent + [DBG] response
	opts := []nuclei.NucleiSDKOptions{
		nuclei.UseOutputWriter(testutils.NewMockOutputWriter(false)),
		nuclei.UseStatsWriter(progressClient),
		nuclei.WithSandboxOptions(true, false),
		nuclei.DisableUpdateCheck(),
		nuclei.WithVerbosity(nuclei.VerbosityOptions{
			Debug:         true,
			DebugRequest:  true,
			DebugResponse: true,
		}),
		nuclei.WithConcurrency(nuclei.Concurrency{
			TemplateConcurrency:           25,
			HostConcurrency:               25,
			HeadlessHostConcurrency:       10,
			HeadlessTemplateConcurrency:   10,
			JavascriptTemplateConcurrency: 25,
			TemplatePayloadConcurrency:    payloadConcurrency,
			ProbeConcurrency:              50,
		}),
	}

	engine, err := nuclei.NewNucleiEngineCtx(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("create nuclei engine: %w", err)
	}

	// Nuclei SDK forces a noisy output writer via init() -> applyRequiredDefaults()
	// that directly calls fmt.Println for every match. We overwrite it here
	// to ensure the engine is completely silent. We track matches ourselves manually.
	engine.GetExecuterOptions().Output = testutils.NewMockOutputWriter(false)

	engine.Options().StoreResponse = true
	engine.Options().Debug = true
	engine.Options().DebugRequests = true
	engine.Options().DebugResponse = true

	return &Runner{
		target:           target,
		engine:           engine,
		OnResultCallback: onProgress,
	}, nil
}

// LiveProgressClient implements progress.Progress
type LiveProgressClient struct{}

func (m *LiveProgressClient) Stop() {}
func (m *LiveProgressClient) Init(hostCount int64, rulesCount int, requestCount int64) {}
func (m *LiveProgressClient) AddToTotal(delta int64) {}
func (m *LiveProgressClient) IncrementRequests() {}
func (m *LiveProgressClient) SetRequests(count uint64) {}
func (m *LiveProgressClient) IncrementMatched() {}
func (m *LiveProgressClient) IncrementErrorsBy(count int64) {}
func (m *LiveProgressClient) IncrementFailedRequestsBy(count int64) {}

// parseLogLevel maps a level name to the corresponding gologger level constant.
// Accepted values (matching gologger's own Level.String() output):
//
//	fatal | silent | error | info | warning | debug | verbose
//
// Unknown strings fall back to LevelInfo.
func parseLogLevel(s string) levels.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "fatal":
		return levels.LevelFatal
	case "silent":
		return levels.LevelSilent
	case "error":
		return levels.LevelError
	case "warning":
		return levels.LevelWarning
	case "debug":
		return levels.LevelDebug
	case "verbose":
		return levels.LevelVerbose
	default:
		return levels.LevelInfo
	}
}

type ExecResult struct {
	TemplateID      string
	Severity        string
	Matched         int         // number of matched ResultEvents
	RequestsDefined int         // request blocks declared in the template (Executer.Requests())
	RequestsFired   int         // actual events received during execution (InternalWrappedEvents)
	Skipped         bool        // template parsed as nil (global matcher — nothing to execute)
	StatusCodes     map[int]int // HTTP status code → count of requests that returned it
}

// Execute preprocesses a template (strips flow/matchers, injects catch-all),
// parses it, fires all HTTP requests against the target, and prints any matches.
// When applyPreprocess is false the original template is passed directly to
// Nuclei without any modification — useful for backend simulation mode.
func (r *Runner) Execute(ctx context.Context, templatePath string, applyPreprocess bool) (*ExecResult, error) {
	var parsePath string
	var cleanupFn func()

	if applyPreprocess {
		pre, err := preprocess.PreprocessTemplate(templatePath)
		if err != nil {
			return nil, fmt.Errorf("preprocess %q: %w", templatePath, err)
		}
		defer pre.Cleanup()
		if pre.Skip {
			gologger.Warning().Msgf("[%s] skipped: non-HTTP content or unsupported template type", templatePath)
			return &ExecResult{TemplateID: templatePath, Skipped: true}, nil
		}
		parsePath = pre.Path
		cleanupFn = pre.Cleanup
	} else {
		parsePath = templatePath
		cleanupFn = func() {}
	}
	defer cleanupFn()

	opts := r.engine.GetExecuterOptions()

	tmpl, err := templates.Parse(parsePath, nil, opts)
	if err != nil {
		return nil, fmt.Errorf("parse template %q: %w", templatePath, err)
	}
	// nil means the template registered as a global matcher — nothing to run.
	if tmpl == nil {
		gologger.Warning().Msgf("[%s] skipped: parsed as nil (global matcher/extractor)", templatePath)
		return &ExecResult{TemplateID: templatePath, Skipped: true}, nil
	}
	// Restore original path so log messages show the real template ID/path.
	tmpl.Path = templatePath

	ctxArgs := contextargs.NewWithInput(ctx, r.target)
	scanCtx := scan.NewScanContext(ctx, ctxArgs)

	// Stream results: calculate stats on-the-fly without keeping massive arrays in memory.
	// This prevents Out-Of-Memory (OOM) when fuzzing with millions of payloads.
	statusCodes := make(map[int]int)
	var requestsFired int
	var mu sync.Mutex

	scanCtx.OnResult = func(e *output.InternalWrappedEvent) {
		if e != nil {
			code := extractStatusCode(e)
			mu.Lock()
			statusCodes[code]++
			requestsFired++
			mu.Unlock()
			if r.OnResultCallback != nil {
				r.OnResultCallback()
			}
		}
	}

	// Use ExecuteWithResults instead of Execute so that our custom OnResult
	severityStr := tmpl.Info.SeverityHolder.Severity.String()

	execRes := &ExecResult{
		TemplateID: tmpl.ID,
		Severity:   severityStr,
	}

	// Use ExecuteWithResults instead of Execute so that our custom OnResult
	// callback doesn't get overwritten. Because our patched templates use a
	// "false" match-all, e.Results will remain empty, thus preventing the OOM
	// accumulation in scanCtx.results naturally.
	resSlice, err := tmpl.Executer.ExecuteWithResults(scanCtx)
	
	// Update counts regardless of success/fail
	execRes.Matched = len(resSlice)
	execRes.RequestsDefined = tmpl.Executer.Requests()
	execRes.RequestsFired = requestsFired
	execRes.StatusCodes = statusCodes

	if err != nil {
		return execRes, fmt.Errorf("execute template %q: %w", tmpl.ID, err)
	}

	return execRes, nil
}

// Close shuts down the underlying Nuclei engine and frees its resources.
func (r *Runner) Close() {
	r.engine.Close()
}

// printResults has been removed as it required massive memory allocation for ResultEvents array.

// extractStatusCode reads the HTTP status code from a Nuclei InternalWrappedEvent.
// Priority:
//  1. internalEvent["status_code"] field (int or float64)
//  2. First line of the raw response string ("HTTP/1.x NNN ...")
//  3. Fallback: 0
func extractStatusCode(e *output.InternalWrappedEvent) int {
	if e == nil {
		return 0
	}
	// Priority 1: structured field.
	if ie := e.InternalEvent; ie != nil {
		if v, ok := ie["status_code"]; ok {
			switch n := v.(type) {
			case int:
				return n
			case float64:
				return int(n)
			}
		}
	}
	// Priority 2: parse the raw response line.
	for _, r := range e.Results {
		if r == nil {
			continue
		}
		line, _, _ := strings.Cut(r.Response, "\n")
		line = strings.TrimRight(line, "\r")
		parts := strings.Fields(line) // ["HTTP/1.1", "200", "OK"]
		if len(parts) >= 2 && strings.HasPrefix(parts[0], "HTTP/") {
			if code, err := strconv.Atoi(parts[1]); err == nil {
				return code
			}
		}
	}
	return 0
}

// ensureIgnoreFile creates an empty .nuclei-ignore file if it does not exist,
// preventing a spurious [ERR] on every run when Nuclei is used as a library
// without going through its official installer.
func ensureIgnoreFile() {
	p := config.DefaultConfig.GetIgnoreFilePath()
	if _, err := os.Stat(p); os.IsNotExist(err) {
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		_ = os.WriteFile(p, []byte("tags: []\nfiles: []\n"), 0o644)
	}
}

