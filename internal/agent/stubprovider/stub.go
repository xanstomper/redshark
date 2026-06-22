// Package stubprovider is a skeleton LLM provider that echoes back a canned
// response instead of calling a real API. It exists so you can test the agent
// loop, scope gate, evidence chain, and redaction without needing an API key.
//
// In production, replace with an Anthropic/OpenAI/etc provider that
// implements agent.Provider.
package stubprovider

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/xanstomper/redteam-agent/internal/agent"
	"github.com/xanstomper/redteam-agent/internal/msg"
)

// StubProvider is a no-network LLM provider for development.
type StubProvider struct{}

// Complete returns a mock response. If the user's last message mentions a
// tool name (nmap, nuclei, etc), we simulate a tool call for it.
// Otherwise we return a text-only response describing what the agent would do.
func (p *StubProvider) Complete(_ context.Context, systemPrompt string, history []msg.Message, toolDefs []agent.ToolDef) (*agent.ProviderResponse, error) {
	if len(history) == 0 {
		return &agent.ProviderResponse{
			Content: "RedShark Agent ready. Load a scope to begin.",
		}, nil
	}

	last := history[len(history)-1]
	lower := last.Content

	// Check if the user is asking to run a recognized tool.
	knownTools := map[string]string{
		"nmap":    "nmap",
		"masscan": "masscan",
		"httpx":   "httpx",
		"ffuf":    "ffuf",
		"nuclei":  "nuclei",
		"sqlmap":  "sqlmap",
		"hydra":   "hydra",
	}

	for keyword, toolName := range knownTools {
		if containsWord(lower, keyword) {
			// Try to extract a target from the message.
			target := extractTarget(lower)
			if target == "" {
				target = "example.com"
			}
			args := map[string]any{"target": target}
			argsJSON, _ := json.Marshal(args)
			return &agent.ProviderResponse{
				ToolCalls: []agent.ToolCall{
					{
						ID:   fmt.Sprintf("call-%s-1", toolName),
						Name: toolName,
						Args: string(argsJSON),
					},
				},
			}, nil
		}
	}

	// Default text response.
	return &agent.ProviderResponse{
		Content: fmt.Sprintf("[stub] I would process your request: %q\n\n"+
			"(Install a real provider to get LLM-powered responses. "+
			"This stub only simulates tool calls for: nmap, masscan, httpx, ffuf, nuclei, sqlmap, hydra.)",
			last.Content),
	}, nil
}

func containsWord(s, w string) bool {
	return len(s) > 0 && len(w) > 0 &&
		(s == w || contains(s, " "+w+" ") || contains(s, " "+w+"\n") ||
			hasPrefix(s, w+" ") || hasSuffix(s, " "+w))
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && findSubstring(s, sub)
}

func findSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func hasPrefix(s, pre string) bool {
	return len(s) >= len(pre) && s[:len(pre)] == pre
}

func hasSuffix(s, suf string) bool {
	return len(s) >= len(suf) && s[len(s)-len(suf):] == suf
}

// extractTarget does a poor-man's target extraction: looks for things that
// look like hostnames or IPs after common prepositions.
func extractTarget(s string) string {
	// Very naive: just look for something after "on", "against", "target", "at"
	for _, prefix := range []string{"on ", "against ", "target ", "at ", "scan ", "run "} {
		if idx := findSubstring(s, prefix); idx {
			start := indexOf(s, prefix) + len(prefix)
			rest := s[start:]
			// Take first word-like token.
			for i, c := range rest {
				if c == ' ' || c == '\n' || c == ',' || c == '.' || c == ')' {
					if i > 0 {
						return rest[:i]
					}
					break
				}
				if i == len(rest)-1 {
					return rest
				}
			}
		}
	}
	return ""
}

func indexOf(s, sub string) int {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
