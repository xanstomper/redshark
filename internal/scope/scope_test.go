package scope_test

import (
	"testing"

	"github.com/xanstomper/redteam-agent/internal/scope"
)

// TestIsProtected_TLD — every protected TLD must trigger refusal.
func TestIsProtected_TLD(t *testing.T) {
	must := []string{
		"example.fbi.gov",
		"www.army.mil",
		"defense.gov.cn",
		"tor.int",
		"a.b.c.gov.uk",
		"hostline.gc.ca",
		"interpol.int",
		// note: france uses .gouv.fr (not .gov.fr) — covered by TLD entry
	}
	for _, h := range must {
		if ok, why := scope.IsProtected(h); !ok {
			t.Errorf("expected %q protected, got reason %q", h, why)
		}
	}
}

// TestIsProtected_Keyword catches agency names.
func TestIsProtected_Keyword(t *testing.T) {
	must := []string{
		"secureserver.fbi.gov", // would be caught by TLD; included anyway
		"ami6.internal.lan",    // contains the keyword mi6 but no gov TLD
		"hosting-mossad-home.io",
		"mydev-dgse-cluster.lan",
		"regional-asn-bnd-svc.lan",
	}
	mustNot := []string{
		"example.com",
		// Note: "fbi.example.com" would match via the "fbi" keyword, which
		// is intentional defence-in-depth — hostnames containing agency
		// names regardless of TLD are assumed restricted unless the operator
		// loads a scope that explicitly allows them.
		"go.dev",
		"docker.lab",
	}
	for _, h := range must {
		if ok, _ := scope.IsProtected(h); !ok {
			t.Errorf("expected %q protected (keyword)", h)
		}
	}
	for _, h := range mustNot {
		if ok, _ := scope.IsProtected(h); ok {
			t.Errorf("did not expect %q protected", h)
		}
	}
}

// TestAuthoriseGateOrder — protected check fires BEFORE scope-loaded check.
func TestAuthoriseGateOrder(t *testing.T) {
	store := scope.NewStore()
	// No scope loaded. expect rejection with layer="protected" if target
	// is protected, but layer="no-scope" otherwise. We test protected with
	// no scope to confirm the protected gate runs first.
	d := store.Authorize("fbi.gov", "")
	if d.Allowed {
		t.Fatalf("expected refusal against fbi.gov with no scope")
	}
	if d.Layer != "protected" {
		t.Fatalf("expected layer=protected, got %s (reason=%s)", d.Layer, d.Reason)
	}
}

// TestStoresEmptyWhenNilScope rejects when scope is blank.
func TestStoresEmptyWhenNilScope(t *testing.T) {
	store := scope.NewStore()
	d := store.Authorize("example.com", "")
	if d.Allowed {
		t.Fatalf("expected refusal without scope")
	}
	if d.Layer != "no-scope" {
		t.Fatalf("expected layer=no-scope, got %s", d.Layer)
	}
}

// TestScopeExpiry — an expired scope refuses with layer=stale.
func TestScopeExpiry(t *testing.T) {
	// 1990-01-01 — definitely expired.
	envelope := []byte(`{
		"id":"expired",
		"operator":"x",
		"sponsor":"y",
		"issued":"1989-01-01",
		"expires":"1990-01-01",
		"network":["example.com"],
		"techniques":["nmap"]
	}`)
	store := scope.NewStore()
	if err := store.LoadRaw(envelope); err == nil {
		t.Fatalf("expected store to refuse loading an expired scope, got nil error")
	}
}
