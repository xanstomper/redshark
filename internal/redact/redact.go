// Package redact implements output sanitization for the agent's responses.
//
// When a tool returns output containing sensitive material (credentials, PII,
// session tokens, API keys), the redact layer replaces the sensitive spans
// with [REDACTED] before the string reaches the model's prompt or the TUI.
//
// In the skeleton this is implemented as a regex pass over known patterns.
// A production deployment should use a named-entity recognizer or a
// structured parser for each tool's output format.
package redact

import (
	"regexp"
)

// Pattern is one redaction rule.
type Pattern struct {
	Label string
	Re    *regexp.Regexp
}

// DefaultPatterns are the regex patterns we scan for in every tool output.
// Each entry is a compiled regex and a human label used in audit logs.
// Order matters: earlier patterns take priority.
var DefaultPatterns = []Pattern{
	{Label: "aws-access-key-id", Re: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{Label: "aws-secret-access-key", Re: regexp.MustCompile(`(?i)aws[_\-]?secret[_\-]?access[_\-]?key[[:space:]]*[:=][[:space:]]*[A-Za-z0-9/+=]{40}`)},
	{Label: "generic-api-key", Re: regexp.MustCompile(`(?i)(api[_\-]?key|token|secret|password|passwd|pwd)[[:space:]]*[:=][[:space:]]*["']?[A-Za-z0-9_\-]{20,}["']?`)},
	{Label: "bearer-token", Re: regexp.MustCompile(`Bearer [A-Za-z0-9\-._~+/]+=*`)},
	{Label: "authorization-header", Re: regexp.MustCompile(`(?i)Authorization:[[:space:]]*[A-Za-z]+ [A-Za-z0-9\-._~+/]+=*`)},
	{Label: "private-key-block", Re: regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`)},
	{Label: "jwt", Re: regexp.MustCompile(`eyJ[A-Za-z0-9\-._+/]+=*\.eyJ[A-Za-z0-9\-._+/]+=*\.[A-Za-z0-9\-._+/]+=*`)},
	{Label: "ipv4-internal", Re: regexp.MustCompile(`(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.[0-9]{1,3}\.[0-9]{1,3}`)},
	{Label: "email", Re: regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)},
}

// Redact applies all DefaultPatterns to s, replacing each match with
// [REDACTED:<label>]. Returns the sanitized string and a count of redactions.
func Redact(s string) (string, int) {
	total := 0
	for _, p := range DefaultPatterns {
		count := 0
		s = p.Re.ReplaceAllStringFunc(s, func(match string) string {
			count++
			return "[REDACTED:" + p.Label + "]"
		})
		total += count
	}
	return s, total
}

// ScopeLoadRedactor strips potential credential leakage from scope JSON
// before it is rendered in the TUI.
func ScopeLoadRedactor(raw string) string {
	stripRe := regexp.MustCompile(`(?m)"[^"]*(?:key|token|secret|password|passwd|pwd)[^"]*"\s*:\s*"[^"]*"`)
	return stripRe.ReplaceAllString(raw, `"REDACTED":"[REDACTED]"`)
}

// StripANSI is a convenience wrapper for callers that want clean text.
func StripANSI(s string) string {
	return ansiStripRegex.ReplaceAllString(s, "")
}

var ansiStripRegex = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
