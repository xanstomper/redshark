// Package agent implements the coordinator that wires the scope gate,
// the evidence store, the tool registry, and the model provider into a
// single conversation loop.
//
// The coordinator is what the TUI calls when the operator types a message.
// It:
//  1. Appends the user message to the session.
//  2. Sends the conversation + tool list to the model provider.
//  3. If the model requests a tool, the coordinator runs it through the
//     scope gate, executes the binary, records evidence, and feeds the
//     result back to the model.
//  4. Returns the assistant's final text + tool interactions to the TUI.
//
// In the skeleton the model provider is a stub that echoes back a plan
// instead of calling an LLM API. This lets you verify the scope gate,
// evidence chain, and tool invocation path without a live model key.
package agent

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/xanstomper/redteam-agent/internal/agent/prompts"
	"github.com/xanstomper/redteam-agent/internal/agent/tools"
	"github.com/xanstomper/redteam-agent/internal/evidence"
	"github.com/xanstomper/redteam-agent/internal/msg"
	"github.com/xanstomper/redteam-agent/internal/redact"
	"github.com/xanstomper/redteam-agent/internal/scope"
)

// Provider is the interface for any LLM backend. In the skeleton we use
// a stub; in production this wraps Anthropic/OpenAI/etc.
type Provider interface {
	// Complete sends the conversation history + tool definitions and returns
	// the model's response. The response may include tool-call requests.
	Complete(ctx context.Context, systemPrompt string, history []msg.Message, toolDefs []ToolDef) (*ProviderResponse, error)
}

// ToolDef is the JSON-serialisable description of a tool sent to the model.
type ToolDef struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// Parameters is a JSON Schema object for the tool's input. In the
	// skeleton we keep it simple: every tool takes {target, ...flags}.
	Parameters any `json:"parameters"`
}

// ProviderResponse is what the model returns.
type ProviderResponse struct {
	// Content is the text portion of the response (may be empty if the
	// model only issued tool calls).
	Content string `json:"content"`

	// ToolCalls are the tool invocations the model requested.
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`
}

// ToolCall is one invocation the model requested.
type ToolCall struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Args string `json:"args"` // JSON blob
}

// Coordinator ties everything together.
type Coordinator struct {
	provider Provider
	scope    *scope.Store
	evidence *evidence.Store
	registry map[string]tools.Tool
	session  *msg.Session
}

// New creates a coordinator wired to the given dependencies.
func New(p Provider, s *scope.Store, e *evidence.Store, tl []tools.Tool, session *msg.Session) *Coordinator {
	reg := make(map[string]tools.Tool, len(tl))
	for _, t := range tl {
		reg[t.Name()] = t
	}
	return &Coordinator{
		provider: p,
		scope:    s,
		evidence: e,
		registry: reg,
		session:  session,
	}
}

// HandleUserMessage is the main entry point the TUI calls on each user turn.
// It returns the assistant's response messages (possibly including tool-call
// and tool-result turns).
func (c *Coordinator) HandleUserMessage(ctx context.Context, content string) ([]msg.Message, error) {
	// Append user message to session.
	userMsg := msg.Message{
		ID:        nextID(),
		Role:      msg.RoleUser,
		Content:   content,
		Timestamp: time.Now().UTC(),
	}
	c.session.Messages = append(c.session.Messages, userMsg)

	// Build tool definitions for the model.
	toolDefs := c.toolDefs()

	// Call the provider in a loop (max 5 tool-call rounds to prevent infinite loops).
	var results []msg.Message
	history := c.session.Messages
	for i := 0; i < 5; i++ {
		resp, err := c.provider.Complete(ctx, prompts.OperatorPrompt, history, toolDefs)
		if err != nil {
			return nil, fmt.Errorf("agent: provider error: %w", err)
		}

		// If the model produced text, emit it as an assistant message.
		if resp.Content != "" {
			asstMsg := msg.Message{
				ID:        nextID(),
				Role:      msg.RoleAssistant,
				Content:   resp.Content,
				Timestamp: time.Now().UTC(),
			}
			results = append(results, asstMsg)
			c.session.Messages = append(c.session.Messages, asstMsg)
		}

		// If no tool calls, we're done.
		if len(resp.ToolCalls) == 0 {
			break
		}

		// Process each tool call.
		for _, tc := range resp.ToolCalls {
			// Emit the tool-call message (what the model asked for).
			toolCallMsg := msg.Message{
				ID:        nextID(),
				Role:      msg.RoleAssistant,
				Content:   tc.Args,
				ToolName:  tc.Name,
				Timestamp: time.Now().UTC(),
			}
			c.session.Messages = append(c.session.Messages, toolCallMsg)

			// Look up the tool.
			t, ok := c.registry[tc.Name]
			if !ok {
				errMsg := msg.Message{
					ID:        nextID(),
					Role:      msg.RoleTool,
					Content:   fmt.Sprintf("unknown tool %q", tc.Name),
					ToolName:  tc.Name,
					Timestamp: time.Now().UTC(),
				}
				results = append(results, errMsg)
				history = append(history, errMsg)
				continue
			}

			// Execute the tool.
			out, runErr := t.Run(ctx, []byte(tc.Args))
			refused := false
			if runErr != nil {
				out = runErr.Error()
				if strings.HasPrefix(out, "refused:") {
					refused = true
				}
			}

			// Redact sensitive material from tool output.
			sanitized, redactCount := redact.Redact(out)
			_ = redactCount

			// Build tool-result message.
			toolResultMsg := msg.Message{
				ID:        nextID(),
				Role:      msg.RoleTool,
				Content:   sanitized,
				ToolName:  tc.Name,
				Timestamp: time.Now().UTC(),
				Refused:   refused,
			}
			results = append(results, toolResultMsg)
			c.session.Messages = append(c.session.Messages, toolResultMsg)
			history = append(history, toolResultMsg)
		}
	}

	c.session.UpdatedAt = time.Now().UTC()
	return results, nil
}

// toolDefs builds the tool list for the model from the registry.
func (c *Coordinator) toolDefs() []ToolDef {
	out := make([]ToolDef, 0, len(c.registry))
	for _, t := range c.registry {
		params := map[string]any{
			"type": "object",
			"properties": map[string]any{
				"target": map[string]any{
					"type":        "string",
					"description": "The target host, IP, URL, or CIDR to act on",
				},
			},
			"required": []string{"target"},
		}
		out = append(out, ToolDef{
			Name:        t.Name(),
			Description: t.Desc(),
			Parameters:  params,
		})
	}
	return out
}

// Session returns the current session.
func (c *Coordinator) Session() *msg.Session { return c.session }

// ScopeStore returns the scope store for direct scope operations.
func (c *Coordinator) ScopeStore() *scope.Store { return c.scope }

// nextID generates a simple incrementing message ID.
// In production this would use a UUID or ULID.
var msgSeq uint64

func nextID() string {
	msgSeq++
	return fmt.Sprintf("msg-%d", msgSeq)
}
