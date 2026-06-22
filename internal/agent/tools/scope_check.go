package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// ScopeCheckTool is a read-only meta-tool: it asks the scope store what the
// gate would do for a given host/port/technique, without actually invoking
// an active tool. The operator uses it as a "would-this-work?" check.
//
// It never makes outbound calls. It always returns.
type ScopeCheckTool struct {
	Deps ToolDeps
}

// Name implements Tool.
func (t *ScopeCheckTool) Name() string { return "scope_check" }

// Desc implements Tool.
func (t *ScopeCheckTool) Desc() string {
	return "Check whether a host/port/technique would be authorized under the loaded scope. Read-only."
}

// scopeCheckArgs models the input.
type scopeCheckArgs struct {
	Host      string `json:"host"`
	Port      string `json:"port,omitempty"`
	Technique string `json:"technique,omitempty"`
}

// Run implements Tool.
func (t *ScopeCheckTool) Run(ctx context.Context, argsJSON []byte) (string, error) {
	var args scopeCheckArgs
	if err := json.Unmarshal(argsJSON, &args); err != nil {
		return "", fmt.Errorf("scope_check: bad args: %w", err)
	}
	if strings.TrimSpace(args.Host) == "" {
		return "", fmt.Errorf("scope_check: host is required")
	}

	// Resolve the address to a target string. We pick the first unwrapped
	// "host"/"address"/"url" key as the gate's target string.
	target := args.Host
	if target == "" {
		var argsAny map[string]any
		_ = json.Unmarshal(argsJSON, &argsAny)
		for _, key := range []string{"host", "address", "url", "target"} {
			if v, ok := argsAny[key].(string); ok && v != "" {
				target = v
				break
			}
		}
	}
	technique := args.Technique
	if technique == "" {
		technique = "scope_check"
	}
	decision := t.Deps.Scope.Authorize(target, technique)

	out := map[string]any{
		"host":    target,
		"port":    args.Port,
		"allowed": decision.Allowed,
		"reason":  decision.Reason,
		"layer":   decision.Layer,
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	return string(b), nil
}
