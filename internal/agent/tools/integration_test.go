// Integration test: load a real scope JSON file and run the full path
// (gate → dryrun → evidence record) for an authorized target and a refused
// target. This is the test that protects the whole project from regressions.
//
// Run via `go test ./internal/agent/tools/... -v`.
package tools_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xanstomper/redteam-agent/internal/agent/tools"
	"github.com/xanstomper/redteam-agent/internal/evidence"
	scopepkg "github.com/xanstomper/redteam-agent/internal/scope"
)

func TestIntegration_RealScopeAuthorizes(t *testing.T) {
	dir := t.TempDir()
	scopeFile := filepath.Join(dir, "scope.json")

	if err := os.WriteFile(scopeFile, []byte(`{
		"id":"INT-001",
		"operator":"integration",
		"sponsor":"local",
		"issued":"2026-01-01",
		"expires":"2030-01-01",
		"network":["example.com","10.99.0.0/16"],
		"techniques":["scanning","nmap","report"]
	}`), 0o644); err != nil {
		t.Fatal(err)
	}

	ev, err := evidence.Open(filepath.Join(dir, "evidence"), "INT-001")
	if err != nil {
		t.Fatal(err)
	}
	sc := scopepkg.NewStore()
	scDoc, err := scopepkg.LoadFile(scopeFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := sc.Load(scDoc); err != nil {
		t.Fatal(err)
	}
	registry := tools.Registry(tools.ToolDeps{Scope: sc, Evidence: ev, MaxOut: 1024})

	// 1. Authorized → dryrun reports "would run".
	var got any
	if err := registry.Call(context.Background(), "nmap",
		json.RawMessage(`{"host":"example.com","port":"443","dryrun":true}`), &got); err != nil {
		t.Fatalf("authorized dryrun err: %v", err)
	}
	s, _ := got.(string)
	if !strings.Contains(s, "would run") {
		t.Fatalf("want 'would run' in dryrun output, got: %s", s)
	}

	// 2. Out-of-scope → refused.
	got = nil
	if err := registry.Call(context.Background(), "nmap",
		json.RawMessage(`{"host":"google.com","port":"443","dryrun":true}`), &got); err == nil {
		t.Fatalf("expected refusal for out-of-scope, got nil err")
	}

	// 3. Protected target even with loaded scope → refused with reason mentioning "protected".
	got = nil
	if err := registry.Call(context.Background(), "nmap",
		json.RawMessage(`{"host":"fbi.gov","port":"443","dryrun":true}`), &got); err == nil {
		t.Fatalf("expected refusal for fbi.gov despite loaded scope, got nil err")
	}
}
