package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/xanstomper/redteam-agent/internal/evidence"
	"github.com/xanstomper/redteam-agent/internal/scope"
)

// freshStore builds an in-memory evidence store for tests.
func freshStore(t *testing.T) *evidence.Store {
	t.Helper()
	dir := t.TempDir()
	es, err := evidence.Open(dir, "test-engagement")
	if err != nil {
		t.Fatalf("evidence store: %v", err)
	}
	return es
}

// TestNewToolsRegistered verifies all the new red-team tools are registered.
func TestNewToolsRegistered(t *testing.T) {
	deps := ToolDeps{
		Scope:    scope.NewStore(),
		Evidence: freshStore(t),
		MaxOut:   1024,
	}
	reg := Registry(deps)

	want := []string{
		"subfinder", "dnsx", "cname", "amass",
		"gobuster", "nikto", "wafw00f",
		"payloads", "redteam-guide",
	}
	names := reg.Names()

	for _, w := range want {
		found := false
		for _, n := range names {
			if n == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("tool %q not registered (have: %s)", w, strings.Join(names, ", "))
		}
	}
}

// TestPayloadsTool verifies the payloads reference tool.
func TestPayloadsTool(t *testing.T) {
	deps := ToolDeps{
		Scope:    scope.NewStore(),
		Evidence: freshStore(t),
		MaxOut:   1024,
	}
	t1 := &PayloadsTool{Deps: deps}
	out, err := t1.Run(context.Background(), []byte(`{"category":"list"}`))
	if err != nil {
		t.Fatalf("payloads list: %v", err)
	}
	if !strings.Contains(out, "xss") {
		t.Errorf("list output should mention xss, got: %s", out[:min(200, len(out))])
	}

	out, err = t1.Run(context.Background(), []byte(`{"category":"xss"}`))
	if err != nil {
		t.Fatalf("payloads xss: %v", err)
	}
	if !strings.Contains(out, "XSS") {
		t.Errorf("xss output should contain XSS, got: %s", out[:min(200, len(out))])
	}

	// Unknown category falls back to list
	out, _ = t1.Run(context.Background(), []byte(`{"category":"nonsense"}`))
	if !strings.Contains(out, "Available Payload Categories") {
		t.Errorf("unknown category should show list")
	}
}

// TestRedteamGuideTool verifies the guide template tool.
func TestRedteamGuideTool(t *testing.T) {
	deps := ToolDeps{
		Scope:    scope.NewStore(),
		Evidence: freshStore(t),
		MaxOut:   1024,
	}
	t1 := &RedteamGuideTool{Deps: deps}

	out, err := t1.Run(context.Background(), []byte(`{"template":"vulnerability-report"}`))
	if err != nil {
		t.Fatalf("guide: %v", err)
	}
	if !strings.Contains(out, "Severity and Risk") {
		t.Errorf("vulnerability-report should have severity section, got: %s", out[:min(200, len(out))])
	}

	out, _ = t1.Run(context.Background(), []byte(`{"template":"roe"}`))
	if !strings.Contains(out, "Rules of Engagement") {
		t.Errorf("roe should be present, got: %s", out[:min(200, len(out))])
	}
}

// TestCnameToolScopeGate verifies cname tool requires scope authorization.
func TestCnameToolScopeGate(t *testing.T) {
	sc := scope.NewStore()
	es := freshStore(t)
	deps := ToolDeps{Scope: sc, Evidence: es, MaxOut: 1024}

	t.Run("out-of-scope refuses", func(t *testing.T) {
		tool := &CnameTool{Deps: deps}
		args, _ := json.Marshal(map[string]any{"target": "evil.example.com"})
		out, err := tool.Run(context.Background(), args)
		// Either a refusal error or refusal text is acceptable.
		if err == nil && out == "" {
			t.Fatalf("expected refusal (error or text), got empty")
		}
		combined := out + " " + errString(err)
		if !strings.Contains(combined, "refus") &&
			!strings.Contains(combined, "REFUSED") &&
			!strings.Contains(combined, "scope") {
			t.Errorf("expected refusal, got out=%q err=%v", out, err)
		}
	})
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// TestParseFlagsHelper tests the flag parser.
func TestParseFlagsHelper(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"-all -silent", []string{"-all", "-silent"}},
		{`-u "https://example.com" -d`, []string{"-u", "https://example.com", "-d"}},
		{"", nil},
	}
	for _, tt := range tests {
		got := parseFlags(tt.input)
		if len(got) != len(tt.want) {
			t.Errorf("parseFlags(%q): got %v want %v", tt.input, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("parseFlags(%q)[%d]: got %q want %q", tt.input, i, got[i], tt.want[i])
			}
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
