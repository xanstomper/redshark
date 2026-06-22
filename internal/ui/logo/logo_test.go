package logo

import (
	"strings"
	"testing"
)

func TestRenderFullMascot(t *testing.T) {
	// Wide terminal — should render full mascot.
	out := RenderFullMascot(80)
	if out == "" {
		t.Fatal("RenderFullMascot returned empty string")
	}
	if !strings.Contains(out, "RedShark") {
		t.Error("mascot missing brand name 'RedShark'")
	}
	if !strings.Contains(out, "REDSHARK") && !strings.Contains(out, "RedShark") {
		t.Error("mascot missing both banner and brand text")
	}
}

func TestRenderCompact(t *testing.T) {
	out := RenderCompact()
	if out == "" {
		t.Fatal("RenderCompact returned empty string")
	}
	if !strings.Contains(out, "RedShark") {
		t.Error("compact banner missing brand name")
	}
}

func TestRenderWidthFallback(t *testing.T) {
	// Narrow terminal should fall back to compact.
	out := Render(40)
	if !strings.Contains(out, "RedShark") {
		t.Error("narrow fallback missing brand name")
	}

	// Wide terminal should render full mascot.
	outWide := Render(100)
	if !strings.Contains(outWide, "RedShark") {
		t.Error("wide render missing brand name")
	}
}

func TestSeparator(t *testing.T) {
	sep := Separator(40)
	if sep == "" {
		t.Error("Separator returned empty string")
	}
	if !strings.Contains(sep, "─") {
		t.Error("Separator missing horizontal bar character")
	}
}

func TestScopeBadge(t *testing.T) {
	active := ScopeBadge("ENG-001", true)
	if !strings.Contains(active, "ENG-001") {
		t.Error("active badge missing scope ID")
	}

	inactive := ScopeBadge("none", false)
	if !strings.Contains(inactive, "none") {
		t.Error("inactive badge missing scope ID")
	}
}
