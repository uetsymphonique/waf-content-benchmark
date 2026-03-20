package runner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

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
	target string
	engine *nuclei.NucleiEngine
}

// New creates a NucleiEngine (which fully initialises all required internals),
// then wraps it for per-template execution.
//
// logLevel controls gologger output: "silent" | "info" (default) | "debug" | "verbose".
// At "debug" level, Nuclei also dumps raw HTTP request/response via [INF]/[DBG] messages.
func New(ctx context.Context, target, logLevel string) (*Runner, error) {
	lvl := parseLogLevel(logLevel)
	gologger.DefaultLogger.SetMaxLevel(lvl)

	ensureIgnoreFile()

	// Always enable request/response dumping so Nuclei generates the log
	// messages; gologger's level filter decides what actually gets printed:
	//   info    → [INF] request only
	//   debug   → [INF] request + [DBG] response
	//   verbose → [INF] request + [VER] sent + [DBG] response
	opts := []nuclei.NucleiSDKOptions{
		nuclei.UseOutputWriter(testutils.NewMockOutputWriter(false)),
		nuclei.UseStatsWriter(&testutils.MockProgressClient{}),
		nuclei.WithSandboxOptions(true, false),
		nuclei.DisableUpdateCheck(),
		nuclei.WithVerbosity(nuclei.VerbosityOptions{
			Debug:         true,
			DebugRequest:  true,
			DebugResponse: true,
		}),
	}

	engine, err := nuclei.NewNucleiEngineCtx(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("create nuclei engine: %w", err)
	}

	engine.Options().StoreResponse = true
	engine.Options().Debug = true
	engine.Options().DebugRequests = true
	engine.Options().DebugResponse = true

	return &Runner{
		target: target,
		engine: engine,
	}, nil
}

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

// ExecResult holds per-template execution statistics.
type ExecResult struct {
	TemplateID      string
	Matched         int         // number of matched ResultEvents
	RequestsDefined int         // request blocks declared in the template (Executer.Requests())
	RequestsFired   int         // actual events received during execution (InternalWrappedEvents)
	Skipped         bool        // template parsed as nil (global matcher — nothing to execute)
	StatusCodes     map[int]int // HTTP status code → count of requests that returned it
}

// Execute preprocesses a template (strips flow/matchers, injects catch-all),
// parses it, fires all HTTP requests against the target, and prints any matches.
func (r *Runner) Execute(ctx context.Context, templatePath string) (*ExecResult, error) {
	pre, err := preprocessTemplate(templatePath)
	if err != nil {
		return nil, fmt.Errorf("preprocess %q: %w", templatePath, err)
	}
	defer pre.cleanup()

	if pre.skip {
		gologger.Error().Msgf("[%s] skipped: non-HTTP content or unsupported template type", templatePath)
		return &ExecResult{TemplateID: templatePath, Skipped: true}, nil
	}

	opts := r.engine.GetExecuterOptions()

	tmpl, err := templates.Parse(pre.path, nil, opts)
	if err != nil {
		return nil, fmt.Errorf("parse template %q: %w", templatePath, err)
	}
	// nil means the template registered as a global matcher — nothing to run.
	if tmpl == nil {
		gologger.Error().Msgf("[%s] skipped: parsed as nil (global matcher/extractor)", templatePath)
		return &ExecResult{TemplateID: templatePath, Skipped: true}, nil
	}
	// Restore original path so log messages show the real template ID/path.
	tmpl.Path = templatePath

	ctxArgs := contextargs.NewWithInput(ctx, r.target)
	scanCtx := scan.NewScanContext(ctx, ctxArgs)

	// OnResult fires per event and carries the raw InternalEvent map (status code,
	// response headers before Nuclei post-processes them into ResultEvent fields).
	var internalEvents []*output.InternalWrappedEvent
	scanCtx.OnResult = func(e *output.InternalWrappedEvent) {
		if e != nil {
			internalEvents = append(internalEvents, e)
		}
	}

	results, err := tmpl.Executer.ExecuteWithResults(scanCtx)
	if err != nil {
		return nil, fmt.Errorf("execute template %q: %w", tmpl.ID, err)
	}

	// Tally HTTP status codes across all fired requests.
	statusCodes := make(map[int]int)
	for _, e := range internalEvents {
		code := extractStatusCode(e)
		statusCodes[code]++
	}

	printResults(results)
	return &ExecResult{
		TemplateID:      tmpl.ID,
		Matched:         len(results),
		RequestsDefined: tmpl.Executer.Requests(),
		RequestsFired:   len(internalEvents),
		StatusCodes:     statusCodes,
	}, nil
}

// Close shuts down the underlying Nuclei engine and frees its resources.
func (r *Runner) Close() {
	r.engine.Close()
}

// printResults prints a compact match summary for each ResultEvent.
// Raw request/response are already shown via gologger [INF]/[DBG] dump lines.
func printResults(results []*output.ResultEvent) {
	// NOTE: match logging disabled — catch-all matcher means every request
	// "matches"; we don't distinguish matched vs unmatched at this stage.
	_ = results
	// for i, r := range results {
	// 	fmt.Printf("[%s] match #%d  url:%s  type:%s  time:%s\n",
	// 		r.TemplateID, i+1, r.Matched, r.Type, r.Timestamp.Format("2006-01-02 15:04:05"))
	// }
}

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

