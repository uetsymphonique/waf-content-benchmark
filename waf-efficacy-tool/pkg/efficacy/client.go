package efficacy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type HTTPClient struct {
	client               *http.Client
	baseURL              string
	blockedFilter        *StatusFilter
	excludeBlockedFilter *StatusFilter
}

func NewHTTPClient(baseURL string, timeout int, blockedFilter *StatusFilter, excludeBlockedFilter *StatusFilter) *HTTPClient {
	return &HTTPClient{
		baseURL:              baseURL,
		blockedFilter:        blockedFilter,
		excludeBlockedFilter: excludeBlockedFilter,
		client: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
		},
	}
}

func (hc *HTTPClient) SendRequest(ctx context.Context, payload Payload) (int, bool, error) {
	url := hc.baseURL + payload.URL

	var body io.Reader
	if payload.Data != "" {
		body = strings.NewReader(payload.Data)
	}

	req, err := http.NewRequestWithContext(ctx, payload.Method, url, body)
	if err != nil {
		Errorf("Failed to create request: %v", err)
		return 0, false, err
	}

	// Set headers
	for k, v := range payload.Headers {
		req.Header.Set(k, v)
	}

	// Debug: Print full request
	var fullReq strings.Builder
	fullReq.WriteString("\n" + strings.Repeat("=", 70) + "\n")
	fullReq.WriteString("📤 REQUEST\n")
	fullReq.WriteString(strings.Repeat("-", 70) + "\n")
	fullReq.WriteString(fmt.Sprintf("%s %s\n", payload.Method, url))
	fullReq.WriteString("\nHeaders:\n")
	for k, v := range payload.Headers {
		fullReq.WriteString(fmt.Sprintf("  %s: %s\n", k, v))
	}
	if payload.Data != "" {
		fullReq.WriteString(fmt.Sprintf("\nBody:\n%s\n", payload.Data))
	}
	fullReq.WriteString(strings.Repeat("-", 70) + "\n")

	PrintRaw(fullReq.String())
	Infof("%s %s", payload.Method, url)

	resp, err := hc.client.Do(req)
	if err != nil {
		Errorf("Request failed: %v", err)
		return 0, false, err
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		Errorf("Failed to read response body: %v", err)
	}

	// Detection logic configurable via -blocked-status and -exclude-blocked-status
	isBlocked := hc.blockedFilter != nil && hc.blockedFilter.Matches(resp.StatusCode)
	if isBlocked && hc.excludeBlockedFilter != nil && hc.excludeBlockedFilter.Matches(resp.StatusCode) {
		isBlocked = false
	}

	// Debug: Print full response
	var fullResp strings.Builder
	fullResp.WriteString("📥 RESPONSE\n")
	fullResp.WriteString(strings.Repeat("-", 70) + "\n")
	fullResp.WriteString(fmt.Sprintf("Status: %d %s\n", resp.StatusCode, http.StatusText(resp.StatusCode)))
	fullResp.WriteString("\nHeaders:\n")
	for k, v := range resp.Header {
		fullResp.WriteString(fmt.Sprintf("  %s: %s\n", k, strings.Join(v, ", ")))
	}
	fullResp.WriteString(fmt.Sprintf("\nBody (%d bytes):\n", len(respBody)))
	if len(respBody) > 0 {
		// Limit body output to 500 chars
		bodyStr := string(respBody)
		if len(bodyStr) > 500 {
			fullResp.WriteString(fmt.Sprintf("%s\n... (truncated)\n", bodyStr[:500]))
		} else {
			fullResp.WriteString(bodyStr + "\n")
		}
	}
	fullResp.WriteString(strings.Repeat("-", 70) + "\n")
	fullResp.WriteString(fmt.Sprintf("Result: isBlocked=%t\n", isBlocked))
	fullResp.WriteString(strings.Repeat("=", 70) + "\n")

	PrintRaw(fullResp.String())
	Infof("Response: %d (blocked=%t)", resp.StatusCode, isBlocked)

	return resp.StatusCode, isBlocked, nil
}

func (hc *HTTPClient) FormatRawRequest(p Payload) string {
	var sb strings.Builder
	// URL is already prefixed with testName by runner
	sb.WriteString(fmt.Sprintf("%s %s HTTP/1.1\n", p.Method, p.URL))
	sb.WriteString(fmt.Sprintf("Host: %s\n", strings.TrimPrefix(strings.TrimPrefix(hc.baseURL, "http://"), "https://")))
	// Write headers except Host to avoid duplication
	for k, v := range p.Headers {
		if strings.ToLower(k) != "host" {
			sb.WriteString(fmt.Sprintf("%s: %s\n", k, v))
		}
	}
	sb.WriteString("\n")
	if p.Data != "" {
		sb.WriteString(p.Data)
		sb.WriteString("\n")
	}
	return sb.String()
}
