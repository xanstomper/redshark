// Package pybridge manages the Python sidecar process that wraps deepteam
// and the redteam-ai-benchmark runner. The Go agent starts the sidecar on
// boot, discovers its port, and routes deepteam/benchmark tool calls through
// HTTP to the Python server.
package pybridge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xanstomper/redteam-agent/internal/evidence"
	"github.com/xanstomper/redteam-agent/internal/scope"
)

const (
	defaultStartTimeout = 15 * time.Second
	healthRetryDelay    = 300 * time.Millisecond
)

// ToolDeps is the shared dependency container — mirrors tools.ToolDeps so
// this package doesn't import the tools package (avoids circular deps).
type ToolDeps struct {
	Scope    *scope.Store
	Evidence *evidence.Store
	MaxOut   int
}

// Bridge manages the Python sidecar lifecycle.
type Bridge struct {
	mu      sync.Mutex
	cmd     *exec.Cmd
	baseURL string
	port    int
	started bool
}

// Start launches the Python sidecar and waits until /health returns ok.
func (b *Bridge) Start(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.started {
		return nil
	}

	port := findFreePort()
	python := findPython()
	if python == "" {
		return fmt.Errorf("pybridge: no python binary found (install to pybridge/.venv or system PATH)")
	}

	script := "pybridge/launch.py"
	cmd := exec.CommandContext(ctx, python, script)
	cmd.Env = append(os.Environ(),
		"REDSHARK_PYBRIDGE_PORT="+strconv.Itoa(port),
		"REDSHARK_PYBRIDGE_HOST=127.0.0.1",
	)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("pybridge: start: %w", err)
	}

	b.cmd = cmd
	b.port = port
	b.baseURL = fmt.Sprintf("http://127.0.0.1:%d", port)

	// Wait for health
	deadline := time.Now().Add(defaultStartTimeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(b.baseURL + "/health")
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			b.started = true
			return nil
		}
		if resp != nil {
			resp.Body.Close()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(healthRetryDelay):
		}
	}

	cmd.Process.Kill()
	return fmt.Errorf("pybridge: sidecar did not become healthy within %s", defaultStartTimeout)
}

// Stop terminates the Python sidecar.
func (b *Bridge) Stop() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.cmd != nil && b.cmd.Process != nil {
		return b.cmd.Process.Kill()
	}
	b.started = false
	return nil
}

// URL returns the base URL of the running sidecar.
func (b *Bridge) URL() string { return b.baseURL }

// Started returns whether the sidecar is running.
func (b *Bridge) Started() bool { return b.started }

// PostJSON sends a JSON POST to a sidecar endpoint and returns the body.
func (b *Bridge) PostJSON(ctx context.Context, path string, payload any) ([]byte, error) {
	if !b.started {
		return nil, fmt.Errorf("pybridge: sidecar not started")
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("pybridge: marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("pybridge: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pybridge: post %s: %w", path, err)
	}
	defer resp.Body.Close()

	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("pybridge: read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return out, fmt.Errorf("pybridge: HTTP %d: %s", resp.StatusCode, string(out[:min(200, len(out))]))
	}

	return out, nil
}

// GetJSON sends a GET to a sidecar endpoint and returns the body.
func (b *Bridge) GetJSON(ctx context.Context, path string) ([]byte, error) {
	if !b.started {
		return nil, fmt.Errorf("pybridge: sidecar not started")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.baseURL+path, nil)
	if err != nil {
		return nil, fmt.Errorf("pybridge: new request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pybridge: get %s: %w", path, err)
	}
	defer resp.Body.Close()

	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("pybridge: read response: %w", err)
	}

	return out, nil
}

// Vulnerabilities returns the list of available deepteam vulnerability types.
func (b *Bridge) Vulnerabilities(ctx context.Context) ([]string, error) {
	out, err := b.GetJSON(ctx, "/vulnerabilities")
	if err != nil {
		return nil, err
	}
	var resp struct {
		Vulnerabilities []string `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		return nil, err
	}
	return resp.Vulnerabilities, nil
}

// Attacks returns the list of available deepteam attack types.
func (b *Bridge) Attacks(ctx context.Context) ([]string, error) {
	out, err := b.GetJSON(ctx, "/attacks")
	if err != nil {
		return nil, err
	}
	var resp struct {
		Attacks []string `json:"attacks"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		return nil, err
	}
	return resp.Attacks, nil
}

// --- Tool implementations ---

// DeepteamTool runs a deepteam red-team assessment through the Python bridge.
type DeepteamTool struct {
	Depts   ToolDeps
	Bridge *Bridge
}

func (t *DeepteamTool) Name() string { return "deepteam" }
func (t *DeepteamTool) Desc() string {
	return "LLM red-team assessment via deepteam. Args: {\"target_purpose\":\"chatbot\",\"vulnerabilities\":[\"bias\",\"toxicity\"],\"model_endpoint\":\"...\",\"model_api_key\":\"...\",\"model_name\":\"gpt-4o-mini\",\"attacks_per_vuln\":1,\"dryrun\":true}"
}

func (t *DeepteamTool) Run(ctx context.Context, argsJSON []byte) (string, error) {
	var m map[string]any
	if err := json.Unmarshal(argsJSON, &m); err != nil {
		return "", fmt.Errorf("deepteam: parse args: %w", err)
	}

	// Record intent in evidence trail
	recordEvidence(t.Depts.Evidence, "deepteam", evidence.KindScan, "model", argsJSON, "pre-flight")

	payload := map[string]any{
		"model_endpoint":   strVal(m, "model_endpoint", "https://api.openai.com/v1"),
		"model_api_key":    strVal(m, "model_api_key", ""),
		"model_name":       strVal(m, "model_name", "gpt-4o-mini"),
		"vulnerabilities":  strSlice(m, "vulnerabilities"),
		"attacks_per_vuln": intVal(m, "attacks_per_vuln", 1),
		"async_mode":       boolVal(m, "async_mode", true),
		"max_concurrent":   intVal(m, "max_concurrent", 5),
		"target_purpose":   strVal(m, "target_purpose", ""),
		"dryrun":           boolVal(m, "dryrun", false),
	}

	out, err := t.Bridge.PostJSON(ctx, "/redteam", payload)
	if err != nil {
		if strings.Contains(err.Error(), "sidecar not started") {
			return "[deepteam] Python bridge not running. Start with: pybridge/.venv/bin/python pybridge/server.py", nil
		}
		return "", err
	}

	recordEvidence(t.Depts.Evidence, "deepteam", evidence.KindScan, "model", out, "completed")
	return string(out), nil
}

// BenchmarkTool runs redteam-ai-benchmark questions through the Python bridge.
type BenchmarkTool struct {
	Depts   ToolDeps
	Bridge *Bridge
}

func (t *BenchmarkTool) Name() string { return "benchmark" }
func (t *BenchmarkTool) Desc() string {
	return "AI red-team benchmark runner. Args: {\"model_endpoint\":\"...\",\"model_api_key\":\"...\",\"model_name\":\"gpt-4o-mini\",\"categories\":[\"prompt_injection\"],\"dryrun\":true}"
}

func (t *BenchmarkTool) Run(ctx context.Context, argsJSON []byte) (string, error) {
	var m map[string]any
	if err := json.Unmarshal(argsJSON, &m); err != nil {
		return "", fmt.Errorf("benchmark: parse args: %w", err)
	}

	recordEvidence(t.Depts.Evidence, "benchmark", evidence.KindScan, "model", argsJSON, "pre-flight")

	payload := map[string]any{
		"model_endpoint": strVal(m, "model_endpoint", "https://api.openai.com/v1"),
		"model_api_key":  strVal(m, "model_api_key", ""),
		"model_name":     strVal(m, "model_name", "gpt-4o-mini"),
		"categories":     strSlice(m, "categories"),
		"max_tokens":      intVal(m, "max_tokens", 4096),
		"temperature":     floatVal(m, "temperature", 0.2),
		"dryrun":          boolVal(m, "dryrun", false),
	}

	out, err := t.Bridge.PostJSON(ctx, "/benchmark", payload)
	if err != nil {
		if strings.Contains(err.Error(), "sidecar not started") {
			return "[benchmark] Python bridge not running. Start with: pybridge/.venv/bin/python pybridge/server.py", nil
		}
		return "", err
	}

	recordEvidence(t.Depts.Evidence, "benchmark", evidence.KindScan, "model", out, "completed")
	return string(out), nil
}

// GuardrailsTool checks input text through deepteam guardrails.
type GuardrailsTool struct {
	Depts   ToolDeps
	Bridge *Bridge
}

func (t *GuardrailsTool) Name() string { return "guardrails" }
func (t *GuardrailsTool) Desc() string {
	return "Input guardrails check via deepteam. Args: {\"input\":\"text to check\",\"guards\":[\"toxicity\",\"bias\"]}"
}

func (t *GuardrailsTool) Run(ctx context.Context, argsJSON []byte) (string, error) {
	var m map[string]any
	if err := json.Unmarshal(argsJSON, &m); err != nil {
		return "", fmt.Errorf("guardrails: parse args: %w", err)
	}

	payload := map[string]any{
		"input":  strVal(m, "input", ""),
		"guards": strSlice(m, "guards"),
		"dryrun": boolVal(m, "dryrun", false),
	}

	out, err := t.Bridge.PostJSON(ctx, "/guardrails", payload)
	if err != nil {
		if strings.Contains(err.Error(), "sidecar not started") {
			return "[guardrails] Python bridge not running.", nil
		}
		return "", err
	}

	return string(out), nil
}

// --- helpers ---

func recordEvidence(es *evidence.Store, tool string, kind evidence.Kind, target string, body []byte, note string) {
	if es == nil {
		return
	}
	es.Record(tool, kind, target, nil, body, note)
}

func strVal(m map[string]any, key, fallback string) string {
	v, ok := m[key].(string)
	if !ok || v == "" {
		return fallback
	}
	return v
}

func boolVal(m map[string]any, key string, def bool) bool {
	v, ok := m[key].(bool)
	if !ok {
		return def
	}
	return v
}

func intVal(m map[string]any, key string, def int) int {
	switch v := m[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	}
	return def
}

func floatVal(m map[string]any, key string, def float64) float64 {
	switch v := m[key].(type) {
	case float64:
		return v
	case int:
		return float64(v)
	}
	return def
}

func strSlice(m map[string]any, key string) []string {
	v, ok := m[key].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(v))
	for _, item := range v {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// findFreePort returns an available localhost port.
func findFreePort() int {
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	if err != nil {
		return 9876
	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 9876
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// findPython locates the Python binary — prefers the local venv, then system.
func findPython() string {
	candidates := []string{
		"pybridge/.venv/bin/python",
		"pybridge/.venv/bin/python3",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	// Fall back to PATH
	for _, name := range []string{"python3", "python"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}
