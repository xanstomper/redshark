// Package tools_test exercises every safety-critical branch of the
// red-team toolset. It MUST stay green — if it regresses, the agent is
// about to do something it shouldn't.
package tools_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xanstomper/redteam-agent/internal/agent/tools"
	"github.com/xanstomper/redteam-agent/internal/evidence"
	"github.com/xanstomper/redteam-agent/internal/scope"
)

// TestProtectedTargetsAreRefused is the headline safety test. Every line
// must keep working or the agent has become dangerous.
func TestProtectedTargetsAreRefused(t *testing.T) {
	ev, err := evidence.Open(filepath.Join(t.TempDir(), "evidence"), "TEST")
	if err != nil {
		t.Fatalf("evidence store: %v", err)
	}
	sc := scope.NewStore()
	registry := tools.Registry(tools.ToolDeps{Scope: sc, Evidence: ev, MaxOut: 4096})

	cases := []struct {
		tool      string
		host      string
		params    string
		want      []string // any of these substrings counts as success
		whyRefuse string
	}{
		// The protected-target checks: a refusal with the literal "REFUSED" prefix
		// and one of the protected-list reason shapes.
		{"nmap", "fbi.gov", `{"host":"fbi.gov","port":"443","dryrun":true}`,
			[]string{"REFUSED", "protected"}, "FBI .gov must be refused"},
		{"nmap", "army.mil", `{"host":"army.mil","port":"80","dryrun":true}`,
			[]string{"REFUSED", "protected"}, "Army .mil must be refused"},
		{"nmap", "bnd.bund.de", `{"host":"bnd.bund.de","port":"443","dryrun":true}`,
			[]string{"REFUSED", "protected"}, "BND .bund.de must be refused"},
		{"nmap", "nato.int", `{"host":"nato.int","port":"443","dryrun":true}`,
			[]string{"REFUSED", "protected"}, "NATO .int must be refused"},
		{"nmap", "defense.gov.cn", `{"host":"defense.gov.cn","port":"443","dryrun":true}`,
			[]string{"REFUSED", "protected"}, "defense.gov.cn must be refused (.gov)"},
		// The scope_check meta-tool reports structured JSON. Both TLD and
		// keyword refusals are valid — we accept either signal.
		{"scope_check", "fbi.gov", `{"host":"fbi.gov"}`,
			[]string{`"allowed": false`, `"layer": "protected"`}, "scope_check must flag FBI"},
		{"scope_check", "mi6.gov.uk", `{"host":"mi6.gov.uk"}`,
			[]string{`"allowed": false`, `"layer": "protected"`}, "scope_check must flag MI6 via TLD or keyword"},
		{"scope_check", "csis.gc.ca", `{"host":"csis.gc.ca"}`,
			[]string{`"allowed": false`, `"layer": "protected"`}, "scope_check must flag CSIS"},
		{"scope_check", "nato.int", `{"host":"nato.int"}`,
			[]string{`"allowed": false`, `"layer": "protected"`}, "scope_check must flag NATO"},
		// A normal target without a scope should refuse via "no scope".
		{"nmap", "example.com", `{"host":"example.com","port":"443","dryrun":true}`,
			[]string{"no scope"}, "must refuse without scope"},
	}

	for _, tc := range cases {
		t.Run(tc.tool+"-"+tc.host, func(t *testing.T) {
			var got any
			callErr := registry.Call(context.Background(), tc.tool,
				json.RawMessage(tc.params), &got)
			out := combination2string(got, callErr)
			if out == "" {
				t.Fatalf("empty result+err for %s on %s", tc.tool, tc.host)
			}
			for _, want := range tc.want {
				if strings.Contains(strings.ToLower(out), strings.ToLower(want)) {
					return
				}
			}
			t.Errorf("%s on %s\n  want one of: %v\n  got:\n%s\n  (%s)",
				tc.tool, tc.host, tc.want, out, tc.whyRefuse)
		})
	}
}

// combination2string flattens a function result (string OR JSON object OR
// error) into a single string we can grep. Used because scope_check returns
// a JSON object, not a string.
func combination2string(got any, callErr error) string {
	if callErr != nil {
		return callErr.Error()
	}
	switch v := got.(type) {
	case string:
		return v
	case nil:
		return ""
	default:
		b, err := json.MarshalIndent(got, "", "  ")
		if err != nil {
			return ""
		}
		return string(b)
	}
}

// TestScopeMustBeLoadedBeforeActiveTools: no scope loaded → active tool refused.
func TestScopeMustBeLoadedBeforeActiveTools(t *testing.T) {
	ev, err := evidence.Open(filepath.Join(t.TempDir(), "evidence"), "TEST")
	if err != nil {
		t.Fatalf("evidence store: %v", err)
	}
	sc := scope.NewStore()
	registry := tools.Registry(tools.ToolDeps{Scope: sc, Evidence: ev, MaxOut: 4096})

	var got any
	callErr := registry.Call(context.Background(), "nmap",
		json.RawMessage(`{"host":"example.com","port":"443","dryrun":true}`), &got)
	out := ""
	if callErr != nil {
		out = callErr.Error()
	} else {
		out, _ = got.(string)
	}
	if !strings.Contains(out, "no scope") && !strings.Contains(out, "REFUSED") {
		t.Fatalf("expected refusal mentioning scope, got: %s", out)
	}
}

// TestScopeAcceptsLoadedEngagement: a healthy scope authorizes authorized
// hosts and refuses out-of-scope ones.
func TestScopeAcceptsLoadedEngagement(t *testing.T) {
	ev, err := evidence.Open(filepath.Join(t.TempDir(), "evidence"), "TEST")
	if err != nil {
		t.Fatalf("evidence store: %v", err)
	}
	sc := scope.NewStore()
	registry := tools.Registry(tools.ToolDeps{Scope: sc, Evidence: ev, MaxOut: 4096})

	envelope := []byte(`{
		"id":"ENG-001",
		"operator":"tester",
		"sponsor":"acme.example",
		"issues":["#1"],
		"issued":"2026-01-01",
		"expires":"2030-01-01",
		"network":["example.com","10.0.0.0/8"],
		"techniques":["scanning","inspection","nmap","masscan","httpx","ffuf","nuclei","sqlmap","hydra"]
	}`)
	if err := sc.LoadRaw(envelope); err != nil {
		t.Fatalf("sc.LoadRaw: %v", err)
	}

	// Authorized host → dryrun must report "would run".
	var got any
	if err := registry.Call(context.Background(), "nmap",
		json.RawMessage(`{"host":"example.com","port":"443","dryrun":true}`), &got); err != nil {
		t.Fatalf("authorized call err: %v", err)
	}
	out, _ := got.(string)
	if !strings.Contains(strings.ToLower(out), "would run") {
		t.Fatalf("expected dryrun to indicate it would run, got: %s", out)
	}

	// Out-of-scope host → refused.
	got = nil
	if err := registry.Call(context.Background(), "nmap",
		json.RawMessage(`{"host":"unauthorized.example.com","port":"443","dryrun":true}`), &got); err != nil {
		out = err.Error()
		got = nil
	} else {
		out, _ = got.(string)
	}
	if !strings.Contains(strings.ToLower(out), "refused") {
		t.Fatalf("expected REFUSED for out-of-scope host, got: %s", out)
	}
}

// TestIsProtected covers the keyword+TLD refusal directly.
func TestIsProtected(t *testing.T) {
	must := []string{
		"fbi.gov",
		"army.mil",
		"bnd.bund.de",
		"csis-scrs.gc.ca",
		"interpol.int",
		"mi6.gov.uk",
		"myhost.mossad.gov",
		"mycompany.atri.gov",
	}
	mustNot := []string{
		"example.com",
		"docker.REDshark.example",
		"git.golang.org",
		"red-team-internal.lab",
	}
	for _, host := range must {
		if ok, why := scope.IsProtected(host); !ok {
			t.Errorf("expected %q to be protected (got reason=%q)", host, why)
		}
	}
	for _, host := range mustNot {
		if ok, _ := scope.IsProtected(host); ok {
			t.Errorf("expected %q NOT to be protected", host)
		}
	}
}
