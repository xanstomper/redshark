// Package scope is the single most important guard in RedShark: the
// rules-of-engagement gate that authorizes every off-host action and the
// hardcoded refusal layer for protected targets.
//
// Two design rules govern everything in this package:
//
//  1. Refusal is the default. A tool that has not been positively authorized
//     by a loaded scope is denied, regardless of what the model says.
//
//  2. Protected targets are absolute. A class of targets (government agencies,
//     military, intelligence services, and the .gov/.mil/.int TLD space) is
//     hardcoded so the refusal cannot be bypassed by editing config, by
//     loading a permissive scope, or by editing the running prompt. The only
//     override is a recompile of this package.
//
// Nothing in this package imports a model API. Refusal logic is local, fast,
// and inspectable — for both humans and auditors.
package scope

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Sentinel errors.
var (
	ErrNoScope         = errors.New("refused: no engagement scope is loaded")
	ErrProtectedTarget = errors.New("refused: target matches the protected list")
	ErrOutOfScope      = errors.New("refused: target not authorized by loaded scope")
	ErrStaleScope      = errors.New("refused: scope document is older than freshness window")
)

// Scope describes a rules-of-engagement document for one engagement.
type Scope struct {
	ID         string    `json:"id"`
	Operator   string    `json:"operator"`
	Sponsor    string    `json:"sponsor"`
	Issued     time.Time `json:"issued"`
	Expires    time.Time `json:"expires"`
	Network    []string  `json:"network"`
	Excluded   []string  `json:"excluded,omitempty"`
	Techniques []string  `json:"techniques"`
	Issues     []string  `json:"issues,omitempty"`
	Notes      string    `json:"notes,omitempty"`
}

// customTime accepts RFC3339 and date-only forms.
type customTime struct{ time.Time }

func (c *customTime) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		return nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02", "2006-01-02T15:04:05", "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			c.Time = t
			return nil
		}
	}
	return fmt.Errorf("scope: unparseable time %q", s)
}

func (c customTime) MarshalJSON() ([]byte, error) {
	return []byte(`"` + c.Time.Format(time.RFC3339) + `"`), nil
}

func (s *Scope) UnmarshalJSON(b []byte) error {
	type aliasScope struct {
		ID         string     `json:"id"`
		Operator   string     `json:"operator"`
		Sponsor    string     `json:"sponsor"`
		Issued     customTime `json:"issued"`
		Expires    customTime `json:"expires"`
		Network    []string   `json:"network"`
		Excluded   []string   `json:"excluded,omitempty"`
		Techniques []string   `json:"techniques"`
		Issues     []string   `json:"issues,omitempty"`
		Notes      string     `json:"notes,omitempty"`
	}
	var a aliasScope
	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}
	s.ID, s.Operator, s.Sponsor = a.ID, a.Operator, a.Sponsor
	s.Issued, s.Expires = a.Issued.Time, a.Expires.Time
	s.Network, s.Excluded, s.Techniques, s.Issues = a.Network, a.Excluded, a.Techniques, a.Issues
	s.Notes = a.Notes
	return nil
}

// Fresh reports whether the scope is still within its validity window.
func (s *Scope) Fresh(now time.Time) bool {
	if s == nil {
		return false
	}
	if s.Expires.IsZero() {
		return false
	}
	return now.Before(s.Expires)
}

// Allows reports whether a technique is on the scope's allow-list.
func (s *Scope) Allows(technique string) bool {
	if s == nil {
		return false
	}
	for _, t := range s.Techniques {
		if strings.EqualFold(strings.TrimSpace(t), technique) {
			return true
		}
	}
	return false
}

// Matches reports whether target falls within the scope's allow-list and
// absent from the excluded list.
func (s *Scope) Matches(target string) (inScope, excluded bool) {
	if s == nil {
		return false, false
	}
	host := NormalizeHost(target)
	ip := net.ParseIP(host)
	for _, raw := range s.Excluded {
		if matchEntry(raw, host, ip) {
			return false, true
		}
	}
	for _, raw := range s.Network {
		if matchEntry(raw, host, ip) {
			return true, false
		}
	}
	return false, false
}

// NormalizeHost lowercases and strips an IPv6 bracket, then returns.
func NormalizeHost(target string) string {
	target = strings.TrimSpace(target)
	target = strings.ToLower(target)
	if strings.HasPrefix(target, "[") && strings.HasSuffix(target, "]") {
		return strings.TrimSuffix(strings.TrimPrefix(target, "["), "]")
	}
	// Strip ports.
	if h, _, err := net.SplitHostPort(target); err == nil {
		target = strings.Trim(strings.ToLower(h), "[]")
	}
	return target
}

// matchEntry tests one entry against the target host and optional IP.
func matchEntry(raw, host string, ip net.IP) bool {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return false
	}
	// Wildcards.
	if strings.HasPrefix(raw, "*.") {
		base := strings.TrimPrefix(raw, "*.")
		return strings.HasSuffix(host, "."+base)
	}
	if strings.HasPrefix(raw, ".") {
		base := strings.TrimPrefix(raw, ".")
		return host == base || strings.HasSuffix(host, "."+base)
	}
	// Exact host match.
	if raw == host {
		return true
	}
	// CIDR match (IP only).
	if strings.Contains(raw, "/") {
		if ip == nil {
			return false
		}
		if _, cidr, err := net.ParseCIDR(raw); err == nil {
			return cidr.Contains(ip)
		}
	}
	// Plain IP match (must be inside a non-CIDR branch).
	if ip != nil {
		if parsed := net.ParseIP(raw); parsed != nil {
			return parsed.Equal(ip)
		}
	}
	return false
}

// ----- Hardcoded protected-target refusal -----

// protectedTLDs is the set of TLD suffixes never to target.
var protectedTLDs = stringset(
	".gov", ".mil", ".int",
	".gov.uk", ".gov.au", ".gov.ca", ".gov.cn",
	".gouv.fr", ".gob.es", ".bund.de", ".gc.ca",
)

// protectedKeywords are agency and institution names that appear in hostnames.
// Match is substring on the hostname.
var protectedKeywords = stringset(
	"fbi", "cia", "nsa", "dhs", "dea",
	"interpol", "mi6", "mi5", "gchq",
	"mossad", "fsb",
	"dgse", "dgsi",
	"bnd",
	"csis", "cscr",
	"asis",
	"nato",
	"csirt",
	"finfisher",
)

func stringset(xs ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(xs))
	for _, x := range xs {
		m[strings.ToLower(strings.TrimSpace(x))] = struct{}{}
	}
	return m
}

// IsProtected reports whether target matches the protected list, returning
// a short human-readable reason on hit.
func IsProtected(target string) (bool, string) {
	if target == "" {
		return false, ""
	}
	host := NormalizeHost(target)
	for tld := range protectedTLDs {
		if strings.HasSuffix(host, tld) {
			return true, fmt.Sprintf("hostname ends with protected TLD %q", tld)
		}
	}
	for kw := range protectedKeywords {
		if strings.Contains(host, kw) {
			return true, fmt.Sprintf("hostname contains protected keyword %q", kw)
		}
	}
	return false, ""
}

// ----- Store: in-memory active scope -----

// Store holds the currently active scope. Concurrent reads are safe.
type Store struct {
	mu    sync.RWMutex
	scope *Scope
	now   func() time.Time // injectable clock for tests
}

// NewStore returns an empty store with the system clock.
func NewStore() *Store {
	return &Store{now: time.Now}
}

// Active returns the currently loaded scope or nil.
func (s *Store) Active() *Scope {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.scope
}

// Load replaces the active scope. Returns errors if the scope is nil,
// missing an expiry, or already expired.
func (s *Store) Load(sc *Scope) error {
	if sc == nil {
		return errors.New("scope: refusing to load nil scope")
	}
	if sc.Expires.IsZero() {
		return errors.New("scope: refusing to load scope without expiry")
	}
	if !s.now().Before(sc.Expires) {
		return ErrStaleScope
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scope = sc
	return nil
}

// LoadRaw parses a JSON scope and loads it.
func (s *Store) LoadRaw(b []byte) error {
	var out Scope
	if err := json.Unmarshal(b, &out); err != nil {
		return fmt.Errorf("scope: LoadRaw: %w", err)
	}
	return s.Load(&out)
}

// Clear drops the active scope.
func (s *Store) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scope = nil
}

// SetNow lets tests pin the clock.
func (s *Store) SetNow(f func() time.Time) { s.now = f }

// Decision is the structured result of gate().
type Decision struct {
	Allowed bool
	Layer   string
	Reason  string
}

// Authorize runs the four gates and returns a Decision.
func (s *Store) Authorize(target, technique string) Decision {
	if hit, reason := IsProtected(target); hit {
		return Decision{Allowed: false, Layer: "protected", Reason: reason}
	}
	s.mu.RLock()
	sc := s.scope
	s.mu.RUnlock()
	if sc == nil {
		return Decision{Allowed: false, Layer: "no-scope", Reason: "no scope loaded"}
	}
	if !sc.Fresh(s.now()) {
		return Decision{Allowed: false, Layer: "stale", Reason: fmt.Sprintf("scope %q expired at %s", sc.ID, sc.Expires.Format(time.RFC3339))}
	}
	if technique != "" && !sc.Allows(technique) {
		return Decision{Allowed: false, Layer: "technique", Reason: fmt.Sprintf("technique %q not in scope.Techniques", technique)}
	}
	inScope, excluded := sc.Matches(target)
	if excluded {
		return Decision{Allowed: false, Layer: "target", Reason: fmt.Sprintf("target %q is on the scope's excluded list", target)}
	}
	if !inScope {
		return Decision{Allowed: false, Layer: "target", Reason: fmt.Sprintf("target %q is not in scope.network", target)}
	}
	return Decision{Allowed: true, Layer: "none", Reason: ""}
}

// Allow is the boolean convenience wrapper.
func (s *Store) Allow(target, technique string) bool {
	return s.Authorize(target, technique).Allowed
}

// ----- File loaders -----

// LoadFile reads a scope document from disk and parses it.
func LoadFile(path string) (*Scope, error) {
	cleaned, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(cleaned)
	if err != nil {
		return nil, fmt.Errorf("scope: read %q: %w", cleaned, err)
	}
	var out Scope
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("scope: parse %q: %w", cleaned, err)
	}
	return &out, nil
}
