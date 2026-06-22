// Package main is the CLI entry point for RedShark (the user-facing brand).
// Internal module name: github.com/xanstomper/redteam-agent.
//
// Usage:
//
//	redshark                       # start interactive TUI
//	redshark --scope scope.json # start with a preloaded scope
//	redshark --version          # print version
//	redshark --help             # print usage
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"charm.land/bubbletea/v2"

	"github.com/xanstomper/redteam-agent/internal/agent"
	"github.com/xanstomper/redteam-agent/internal/agent/stubprovider"
	"github.com/xanstomper/redteam-agent/internal/agent/tools"
	"github.com/xanstomper/redteam-agent/internal/evidence"
	"github.com/xanstomper/redteam-agent/internal/msg"
	"github.com/xanstomper/redteam-agent/internal/scope"
	"github.com/xanstomper/redteam-agent/internal/ui/logo"
	"github.com/xanstomper/redteam-agent/internal/ui/model"
	"github.com/xanstomper/redteam-agent/internal/version"
)

func main() {
	scopePath := flag.String("scope", "", "path to engagement scope JSON file")
	evidenceDir := flag.String("evidence", "", "directory for evidence chain (default: ./evidence-<scope-id>)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version.String())
		os.Exit(0)
	}

	// Print splash.
	fmt.Fprintln(os.Stderr, logo.Render(80))

	// Initialize scope store.
	scopeStore := scope.NewStore()
	if *scopePath != "" {
		sc, err := scope.LoadFile(*scopePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error loading scope: %v\n", err)
			os.Exit(1)
		}
		if err := scopeStore.Load(sc); err != nil {
			fmt.Fprintf(os.Stderr, "error loading scope: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "scope loaded: %s\n", sc.ID)
	}

	// Initialize evidence store.
	evDir := *evidenceDir
	if evDir == "" {
		if s := scopeStore.Active(); s != nil {
			evDir = "./evidence-" + s.ID
		} else {
			evDir = "./evidence-dryrun"
		}
	}
	engagementID := ""
	if s := scopeStore.Active(); s != nil {
		engagementID = s.ID
	}
	evStore, err := evidence.Open(evDir, engagementID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error opening evidence store: %v\n", err)
		os.Exit(1)
	}
	defer fmt.Fprintf(os.Stderr, "evidence chain: %d records, head %s\n", evStore.Sequence(), evStore.HeadHash())

	// Initialize toolset with shared deps.
	deps := tools.ToolDeps{
		Scope:    scopeStore,
		Evidence: evStore,
		MaxOut:   tools.MaxOutputBytes,
	}
	toolRegistry := tools.Registry(deps)

	// Create session.
	session := &msg.Session{
		ID:        fmt.Sprintf("session-%d", os.Getpid()),
		Messages:  nil,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	// Create provider (stub for skeleton; replace with real LLM provider).
	provider := &stubprovider.StubProvider{}

	// Wire coordinator. Pass the registry's tool list to the coordinator
	// (named-dispatch via .Call is also available on the handle but the
	// coordinator prefers the linear form).
	coord := agent.New(provider, scopeStore, evStore, toolRegistry.Tools(), session)

	// Create and run the TUI.
	_ = context.Background() // placeholder for future cancellation wiring
	tuiModel := model.New(coord, scopeStore, session)
	p := tea.NewProgram(tuiModel, tea.WithContext(context.Background()))

	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "TUI error: %v\n", err)
		os.Exit(1)
	}
}
