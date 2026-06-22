package model

import (
	"testing"

	"github.com/xanstomper/redteam-agent/internal/agent"
	"github.com/xanstomper/redteam-agent/internal/msg"
	"github.com/xanstomper/redteam-agent/internal/scope"
)

func TestNew(t *testing.T) {
	coord := &agent.Coordinator{}
	sc := scope.NewStore()
	sess := &msg.Session{ID: "test-session"}

	m := New(coord, sc, sess)
	if m == nil {
		t.Fatal("New returned nil")
	}
	if m.coordinator != coord {
		t.Error("coordinator not set")
	}
	if m.scope != sc {
		t.Error("scope not set")
	}
	if m.session != sess {
		t.Error("session not set")
	}
	if m.showSplash != true {
		t.Error("showSplash should be true by default")
	}
	if m.splashTimer <= 0 {
		t.Error("splashTimer should be positive")
	}
}

func TestCursorX(t *testing.T) {
	sc := scope.NewStore()
	m := &MainModel{input: "hello", scope: sc}
	x := m.cursorX()
	if x <= 0 {
		t.Error("cursorX should be positive for non-empty input")
	}
}

func TestHandleUserInput(t *testing.T) {
	sc := scope.NewStore()
	coord := &agent.Coordinator{}
	sess := &msg.Session{ID: "test"}
	m := New(coord, sc, sess)

	// Before handling: no messages.
	if len(m.messages) != 0 {
		t.Error("expected 0 messages before input")
	}

	// Simulate entering text (we can't easily call handleUserInput directly
	// because it returns a tea.Cmd, but we can verify the model state
	// if we had a synchronous path).
}
