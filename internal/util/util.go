// Package util provides small allocation-friendly helpers that don't belong
// in a more specific package: bounded writers, env helpers, and string-set
// predicates used by the scope-gate and toolset.
package util

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"sort"
	"strings"
)

// Set is a small string-set helper used by the protected-target blocklist
// and the tool allow-list. It is intentionally simple; we don't import
// maps because we want the type to compose with file loading.
type Set map[string]struct{}

// NewSet builds a set from a list of strings.
func NewSet(xs ...string) Set {
	s := make(Set, len(xs))
	for _, x := range xs {
		s[strings.ToLower(strings.TrimSpace(x))] = struct{}{}
	}
	return s
}

// Has reports whether k is in the set (case-insensitive, trimmed).
func (s Set) Has(k string) bool {
	if s == nil {
		return false
	}
	_, ok := s[strings.ToLower(strings.TrimSpace(k))]
	return ok
}

// Add inserts k into the set (case-insensitive).
func (s Set) Add(k string) {
	if s == nil {
		return
	}
	s[strings.ToLower(strings.TrimSpace(k))] = struct{}{}
}

// Sorted returns a sorted snapshot of the set contents.
func (s Set) Sorted() []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// BoundedBuffer is a bytes.Buffer with a hard cap. Reads after the cap are
// truncated. We use it to keep tool output from exceeding the model's per-turn
// context window before redaction runs.
type BoundedBuffer struct {
	bytes.Buffer
	Cap int
}

// Write implements io.Writer but blocks growth past Cap.
func (b *BoundedBuffer) Write(p []byte) (int, error) {
	if b.Cap > 0 && b.Len()+len(p) > b.Cap {
		remaining := b.Cap - b.Len()
		if remaining <= 0 {
			return len(p), nil // drop entirely; caller still sees len(p) so it doesn't loop
		}
		_, _ = b.Buffer.Write(p[:remaining])
		return len(p), nil
	}
	return b.Buffer.Write(p)
}

// RunCmd runs an external command with a hard timeout, capturing stdout/stderr.
// If the binary is not on PATH, it returns ErrBinaryMissing so the calling
// tool can degrade gracefully rather than fabricate a result.
//
// IMPORTANT: This is intentionally not exposed to the model directly. Tool
// implementations always go through a scope check first.
var ErrBinaryMissing = errors.New("binary not present on PATH")

func RunCmd(ctx context.Context, maxBytes int, name string, args ...string) (stdout, stderr []byte, err error) {
	if _, lookErr := exec.LookPath(name); lookErr != nil {
		return nil, nil, ErrBinaryMissing
	}
	cmd := exec.CommandContext(ctx, name, args...)
	var outBuf, errBuf BoundedBuffer
	outBuf.Cap, errBuf.Cap = maxBytes, maxBytes
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	runErr := cmd.Run()
	return outBuf.Bytes(), errBuf.Bytes(), runErr
}

// TrimToLength truncates a string at n bytes, appending an ellipsis on cut.
// Useful for tool descriptions in prompts that we don't want to balloon.
func TrimToLength(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n < 4 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

// FirstNonEmpty returns the first non-empty string. Empty strings are still
// strings (""), so this differs from taking the first arg only in that we
// skip the empty ones.
func FirstNonEmpty(xs ...string) string {
	for _, x := range xs {
		if x != "" {
			return x
		}
	}
	return ""
}

// Discard is io.Discard re-exported so callers don't need an extra import
// when wiring to the writer parameters of the agent run loop.
var Discard io.Writer = io.Discard
