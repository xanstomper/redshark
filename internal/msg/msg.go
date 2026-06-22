// Package msg defines the message types that flow between the TUI, the agent
// coordinator, and the tool layer. These are intentionally modelled as plain
// Go structs rather than reusing the upstream Crush Message type — we want
// the freedom to extend without keeping the upstream import chain.
//
// The type hierarchy follows the agent loop:
//
//	UserInput → Coordinator → Tool → ToolResult → Coordinator → ModelOutput → TUI
package msg

import "time"

// Role distinguishes who produced a message in the conversation.
type Role string

const (
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
	RoleTool      Role = "tool"
	RoleSystem    Role = "system"
	RoleRefusal   Role = "refusal" // shown as a distinct class in the TUI
)

// Message is one turn in the conversation. It is the single unit the TUI
// renders and the evidence chain records.
type Message struct {
	// ID is a unique-per-session identifier, used by the evidence chain.
	ID string `json:"id"`

	// Role is who produced this turn.
	Role Role `json:"role"`

	// Content is the text body. For tool-call messages this is the JSON
	// args blob; for tool-result messages it's the stdout string.
	Content string `json:"content"`

	// ToolName is set when Role == RoleTool and the message is a tool call
	// or a tool result. The convention is: a tool-call message has
	// ToolName set + Content = JSON args; the corresponding result has
	// ToolName set + Content = result string.
	ToolName string `json:"tool_name,omitempty"`

	// Timestamp is when the agent created this message.
	Timestamp time.Time `json:"timestamp"`

	// Refused is set when the scope gate rejected the action. The TUI
	// renders refused messages differently (red border, refusion icon).
	Refused bool `json:"refused,omitempty"`

	// EvidenceHash is the SHA-256 of the evidence record associated with
	// this message (if any). Populated by the coordinator after each
	// tool execution.
	EvidenceHash string `json:"evidence_hash,omitempty"`
}

// Session holds the full conversational state for one engagement.
type Session struct {
	ID        string    `json:"id"`
	Operator  string    `json:"operator"`
	ScopeID   string    `json:"scope_id,omitempty"`
	Messages  []Message `json:"messages"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
