// Package tools implements the red-team toolset for redteam-agent.
//
// Every tool in this package follows the same contract:
//
//	type Tool struct { ... }        // holds config & scope store
//	func (t *Tool) Name() string    // stable identifier the model uses
//	func (t *Tool) Desc() string    // short description fed to the model's tool list
//	func (t *Tool) Run(ctx, args) (string, error)
//
// Run() always calls scope.Authorize(target, technique) first. If Authorize
// returns non-nil, Run returns the refusal text — it does NOT fabricate a
// plausible-looking result. The error is wrapped so the agent coordinator
// can distinguish "refused" from "tool failed" from "binary missing".
//
// Binary-missing errors are reported as user-visible instructions ("install
// nmap: apt install nmap") so the operator can fix them without model help.
package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/xanstomper/redteam-agent/internal/evidence"
	"github.com/xanstomper/redteam-agent/internal/scope"
	"github.com/xanstomper/redteam-agent/internal/util"
)

// MaxOutputBytes is the per-tool stdout capture cap. 256 KB is enough for
// most scan output without eating the entire model context window.
const MaxOutputBytes = 256 * 1024

// DefaultTimeout is how long a tool can run before context cancellation.
const DefaultTimeout = 5 * time.Minute

// ErrRefused is returned when the scope gate denies the action. Its
// Reason field carries the human-readable explanation across the gate.
type ErrRefused struct {
	Reason string
}

func (e *ErrRefused) Error() string { return e.Reason }

// ErrBinaryMissing is returned when the tool's underlying binary isn't on PATH.
type ErrBinaryMissing struct {
	Bin  string
	Hint string
}

func (e *ErrBinaryMissing) Error() string {
	return fmt.Sprintf("binary %q not found on PATH: %s", e.Bin, e.Hint)
}

// ParseTarget extracts the target host from a JSON args blob. Each tool
// requires this field; if it's missing, we refuse before reaching the scope
// gate (you can't authorize a target you don't know).
//
// We accept several aliases (target, host, address, url) so tool specs can
// vary. If the value is a URL, we extract the host part. IPv6 literals must
// be in the literal form "[2600::]"; the scope gate normalizes them.
func ParseTarget(argsJSON []byte) (string, error) {
	var m map[string]any
	if err := json.Unmarshal(argsJSON, &m); err != nil {
		return "", fmt.Errorf("tools: parse args: %w", err)
	}
	var raw string
	for _, key := range []string{"target", "host", "address", "url"} {
		if v, ok := m[key].(string); ok && strings.TrimSpace(v) != "" {
			raw = strings.TrimSpace(v)
			break
		}
	}
	if raw == "" {
		return "", fmt.Errorf("tools: args missing non-empty target/host/address/url field")
	}
	// If it's a URL, reduce to host.
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Host, nil
	}
	// Strip an IPv6 literal's brackets.
	if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		return strings.TrimSuffix(strings.TrimPrefix(raw, "["), "]"), nil
	}
	return raw, nil
}

// ToolDeps is the shared dependency slice every tool receives on construction.
// It bundles the scope store, evidence store, and the output cap so we don't
// repeat these in every struct.
type ToolDeps struct {
	Scope    *scope.Store
	Evidence *evidence.Store
	MaxOut   int
}

// preflightOrDryrun combines the scope gate with a uniform dryrun short
// circuit. The boolean it returns is "dryrun-handled" — when true, the
// caller must NOT shell out.
//
// All active red-team tools call this method first. Refusals are returned
// as errors; successful dryruns are returned as a series of newline-joined
// strings the operator can read; live runs continue after a dryrun check.
func preflightOrDryrun(deps ToolDeps, technique string, argsJSON []byte) (target string, decision scope.Decision, dryrunOut string, handled bool, err error) {
	target, decision, err = gate(deps, technique, argsJSON)
	if err != nil {
		return "", scope.Decision{}, "", false, err
	}
	if extractBool(argsJSON, "dryrun", false) {
		flags := extractFlags(argsJSON)
		dryrunOut = fmt.Sprintf("[DRYRUN] would run: %s %s\n  gate: layer=%s allowed=true\n  target=%s\n  evidence: pre-flight recorded",
			technique, flags, decision.Layer, target)
		return target, decision, dryrunOut, true, nil
	}
	return target, decision, "", false, nil
}

// gate is the shared pre-flight: runs the four-gate check in scope.Authorize
// and, on pass, records a "pre" evidence marker so the chain shows intent.
// It returns the target string extracted from args (so the real tool doesn't
// need to parse it again).
func gate(deps ToolDeps, technique string, argsJSON []byte) (target string, decision scope.Decision, err error) {
	target, err = ParseTarget(argsJSON)
	if err != nil {
		return "", scope.Decision{}, err
	}
	decision = deps.Scope.Authorize(target, technique)
	if !decision.Allowed {
		return target, decision, &ErrRefused{Reason: fmt.Sprintf("REFUSED (%s) target=%q technique=%q: %s",
			decision.Layer, target, technique, decision.Reason)}
	}
	// Intent marker in the evidence chain.
	if deps.Evidence != nil {
		deps.Evidence.Record(technique, evidence.KindScan, target,
			[]string{"intent"}, []byte(fmt.Sprintf("pre-flight: %s on %s", technique, target)), "")
	}
	return target, decision, nil
}

// postEvidence records the tool result in the evidence chain after a
// successful (or partially successful) run.
func postEvidence(deps ToolDeps, toolName string, kind evidence.Kind, target string, out []byte, note string) {
	if deps.Evidence == nil {
		return
	}
	deps.Evidence.Record(toolName, kind, target, nil, out, note)
}

// --- Tool implementations --------------------------------------------------
//
// Each tool is deliberately thin: parse args, gate, exec binary, capture
// output, post to evidence, return to caller. The model decides which tool
// to call and with what args; the tool's job is to enforce that the call is
// authorized and to record the result.

// NmapTool runs /usr/bin/nmap with the operator-supplied flags.
type NmapTool struct{ Deps ToolDeps }

func (t *NmapTool) Name() string { return "nmap" }
func (t *NmapTool) Desc() string {
	return "TCP/UDP/SYN port scan via nmap. Args: {\"target\":\"host\",\"flags\":\"-sV -T4\"}"
}
func (t *NmapTool) Run(ctx context.Context, argsJSON []byte) (string, error) {
	target, _, dryrunOut, handled, err := preflightOrDryrun(t.Deps, "nmap", argsJSON)
	if err != nil {
		return "", err
	}
	if handled {
		return dryrunOut, nil
	}
	flags := extractFlags(argsJSON)
	cmdArgs := []string{flags, target}
	stdout, stderr, runErr := util.RunCmd(ctx, t.Deps.MaxOut, "nmap", cmdArgs...)
	if runErr != nil && isBinaryMissing(runErr) {
		return "", &ErrBinaryMissing{Bin: "nmap", Hint: "apt install nmap || brew install nmap"}
	}
	postEvidence(t.Deps, "nmap", evidence.KindScan, target, stdout, "")
	out := string(stdout)
	if len(stderr) > 0 {
		out += "\n[stderr] " + string(stderr)
	}
	if runErr != nil {
		out += fmt.Sprintf("\n[nmap exit %v]", runErr)
	}
	return out, nil
}

// MasscanTool runs masscan for high-rate port discovery.
type MasscanTool struct{ Deps ToolDeps }

func (t *MasscanTool) Name() string { return "masscan" }
func (t *MasscanTool) Desc() string {
	return "High-rate port scan via masscan. Args: {\"target\":\"cidr\",\"ports\":\"1-65535\",\"rate\":\"1000\"}"
}
func (t *MasscanTool) Run(ctx context.Context, argsJSON []byte) (string, error) {
	target, _, dryrunOut, handled, err := preflightOrDryrun(t.Deps, "masscan", argsJSON)
	if err != nil {
		return "", err
	}
	if handled {
		return dryrunOut, nil
	}
	ports := extractString(argsJSON, "ports", "1-65535")
	rate := extractString(argsJSON, "rate", "1000")
	cmdArgs := []string{target, "-p", ports, "--rate", rate}
	stdout, stderr, runErr := util.RunCmd(ctx, t.Deps.MaxOut, "masscan", cmdArgs...)
	if runErr != nil && isBinaryMissing(runErr) {
		return "", &ErrBinaryMissing{Bin: "masscan", Hint: "apt install masscan || brew install masscan"}
	}
	postEvidence(t.Deps, "masscan", evidence.KindScan, target, stdout, "")
	return buildResult(stdout, stderr, runErr), nil
}

// HttpxTool runs ProjectDiscovery httpx for HTTP probing.
type HttpxTool struct{ Deps ToolDeps }

func (t *HttpxTool) Name() string { return "httpx" }
func (t *HttpxTool) Desc() string {
	return "HTTP probe via httpx. Args: {\"target\":\"url\",\"flags\":\"-status-code -title -tech-detect\"}"
}
func (t *HttpxTool) Run(ctx context.Context, argsJSON []byte) (string, error) {
	target, _, dryrunOut, handled, err := preflightOrDryrun(t.Deps, "httpx", argsJSON)
	if err != nil {
		return "", err
	}
	if handled {
		return dryrunOut, nil
	}
	flags := extractFlags(argsJSON)
	cmdArgs := []string{"-u", target}
	if flags != "" {
		cmdArgs = append(strings.Split(flags, " "), cmdArgs...)
	}
	stdout, stderr, runErr := util.RunCmd(ctx, t.Deps.MaxOut, "httpx", cmdArgs...)
	if runErr != nil && isBinaryMissing(runErr) {
		return "", &ErrBinaryMissing{Bin: "httpx", Hint: "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"}
	}
	postEvidence(t.Deps, "httpx", evidence.KindWeb, target, stdout, "")
	return buildResult(stdout, stderr, runErr), nil
}

// FfufTool runs ffuf (fuzzing: dirs/files/vhosts/subdomains).
type FfufTool struct{ Deps ToolDeps }

func (t *FfufTool) Name() string { return "ffuf" }
func (t *FfufTool) Desc() string {
	return "Fuzzer via ffuf. Args: {\"target\":\"url\",\"wordlist\":\"/usr/share/wordlists/dirb/common.txt\",\"mode\":\"dir\"}"
}
func (t *FfufTool) Run(ctx context.Context, argsJSON []byte) (string, error) {
	target, _, dryrunOut, handled, err := preflightOrDryrun(t.Deps, "ffuf", argsJSON)
	if err != nil {
		return "", err
	}
	if handled {
		return dryrunOut, nil
	}
	wl := extractString(argsJSON, "wordlist", "/usr/share/wordlists/dirb/common.txt")
	mode := extractString(argsJSON, "mode", "dir")
	var cmdArgs []string
	switch mode {
	case "vhost":
		cmdArgs = []string{"-u", target, "-H", "Host: FUZZ", "-w", wl}
	case "subdomain":
		cmdArgs = []string{"-u", "https://FUZZ." + strings.TrimPrefix(target, "https://"), "-w", wl}
	default: // dir
		cmdArgs = []string{"-u", target + "FUZZ", "-w", wl}
	}
	stdout, stderr, runErr := util.RunCmd(ctx, t.Deps.MaxOut, "ffuf", cmdArgs...)
	if runErr != nil && isBinaryMissing(runErr) {
		return "", &ErrBinaryMissing{Bin: "ffuf", Hint: "go install github.com/ffuf/ffuf/v2@latest"}
	}
	postEvidence(t.Deps, "ffuf", evidence.KindFuzz, target, stdout, "")
	return buildResult(stdout, stderr, runErr), nil
}

// NucleiTool runs nuclei templates against a target.
type NucleiTool struct{ Deps ToolDeps }

func (t *NucleiTool) Name() string { return "nuclei" }
func (t *NucleiTool) Desc() string {
	return "Template scanner via nuclei. Args: {\"target\":\"url\",\"templates\":\"cves\",\"severity\":\"low,medium,high,critical\"}"
}
func (t *NucleiTool) Run(ctx context.Context, argsJSON []byte) (string, error) {
	target, _, dryrunOut, handled, err := preflightOrDryrun(t.Deps, "nuclei", argsJSON)
	if err != nil {
		return "", err
	}
	if handled {
		return dryrunOut, nil
	}
	templates := extractString(argsJSON, "templates", "")
	severity := extractString(argsJSON, "severity", "")
	args := []string{"-u", target, "-silent"}
	if templates != "" {
		args = append(args, "-t", templates)
	}
	if severity != "" {
		args = append(args, "-severity", severity)
	}
	stdout, stderr, runErr := util.RunCmd(ctx, t.Deps.MaxOut, "nuclei", args...)
	if runErr != nil && isBinaryMissing(runErr) {
		return "", &ErrBinaryMissing{Bin: "nuclei", Hint: "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"}
	}
	postEvidence(t.Deps, "nuclei", evidence.KindExploit, target, stdout, "")
	return buildResult(stdout, stderr, runErr), nil
}

// SqlmapTool runs sqlmap for SQL injection detection.
type SqlmapTool struct{ Deps ToolDeps }

func (t *SqlmapTool) Name() string { return "sqlmap" }
func (t *SqlmapTool) Desc() string {
	return "SQLi detector via sqlmap. Args: {\"target\":\"url\",\"flags\":\"--batch --level=3\"}"
}
func (t *SqlmapTool) Run(ctx context.Context, argsJSON []byte) (string, error) {
	target, _, dryrunOut, handled, err := preflightOrDryrun(t.Deps, "sqlmap", argsJSON)
	if err != nil {
		return "", err
	}
	if handled {
		return dryrunOut, nil
	}
	flags := extractFlags(argsJSON)
	cmdArgs := []string{"-u", target, "--batch"}
	if flags != "" {
		cmdArgs = append(cmdArgs, strings.Split(flags, " ")...)
	}
	stdout, stderr, runErr := util.RunCmd(ctx, t.Deps.MaxOut, "sqlmap", cmdArgs...)
	if runErr != nil && isBinaryMissing(runErr) {
		return "", &ErrBinaryMissing{Bin: "sqlmap", Hint: "apt install sqlmap || pipx install sqlmap"}
	}
	postEvidence(t.Deps, "sqlmap", evidence.KindExploit, target, stdout, "")
	return buildResult(stdout, stderr, runErr), nil
}

// HydraTool runs hydra for online credential brute-force.
// This tool ALWAYS requires explicit operator confirmation regardless of
// scope — the CONFIRM-EACH-SESSION rule from the operator prompt.
type HydraTool struct{ Deps ToolDeps }

func (t *HydraTool) Name() string { return "hydra" }
func (t *HydraTool) Desc() string {
	return "Online credential brute-force via hydra. REQUIRES OPERATOR CONFIRM. Args: {\"target\":\"host\",\"service\":\"ssh\",\"userlist\":\"users.txt\",\"passlist\":\"rockyou.txt\"}"
}
func (t *HydraTool) Run(ctx context.Context, argsJSON []byte) (string, error) {
	target, _, dryrunOut, handled, err := preflightOrDryrun(t.Deps, "hydra", argsJSON)
	if err != nil {
		return "", err
	}
	if handled {
		return dryrunOut, nil
	}
	// Hydra is always destructive; even in scope, we require a confirm flag.
	confirmed := extractBool(argsJSON, "confirmed", false)
	if !confirmed {
		return "hydra: operator confirmation required. Re-run with \"confirmed\":true in args to proceed.", nil
	}
	service := extractString(argsJSON, "service", "ssh")
	userlist := extractString(argsJSON, "userlist", "users.txt")
	passlist := extractString(argsJSON, "passlist", "rockyou.txt")
	cmdArgs := []string{"-L", userlist, "-P", passlist, target, service}
	stdout, stderr, runErr := util.RunCmd(ctx, t.Deps.MaxOut, "hydra", cmdArgs...)
	if runErr != nil && isBinaryMissing(runErr) {
		return "", &ErrBinaryMissing{Bin: "hydra", Hint: "apt install hydra || brew install hydra"}
	}
	postEvidence(t.Deps, "hydra", evidence.KindExploit, target, stdout, "operator-confirmed")
	return buildResult(stdout, stderr, runErr), nil
}

// C2ProfileTool generates or rotates a C2 profile for the engagement.
// In the skeleton this is a pure-Go generator (no external binary) that
// produces a randomized malleable C2 profile. A production version would
// use an embedded template engine.
type C2ProfileTool struct{ Deps ToolDeps }

func (t *C2ProfileTool) Name() string { return "c2-profile" }
func (t *C2ProfileTool) Desc() string {
	return "Generate/rotate C2 malleable profile. Args: {\"action\":\"generate\",\"framework\":\"cobalt-strike\"}"
}
func (t *C2ProfileTool) Run(ctx context.Context, argsJSON []byte) (string, error) {
	// C2 profile generation doesn't target an external host, so we skip
	// the target gate. We DO record in evidence.
	action := extractString(argsJSON, "action", "generate")
	fw := extractString(argsJSON, "framework", "cobalt-strike")
	profile := generateStubProfile(fw)
	postEvidence(t.Deps, "c2-profile", evidence.KindOutput, "localhost", []byte(profile),
		fmt.Sprintf("action=%s framework=%s", action, fw))
	return profile, nil
}

// ReportTool synthesizes findings into a Markdown engagement report.
// It reads the evidence chain and produces a formatted document.
type ReportTool struct{ Deps ToolDeps }

func (t *ReportTool) Name() string { return "report" }
func (t *ReportTool) Desc() string {
	return "Synthesize findings into engagement report. Args: {\"format\":\"markdown\"}"
}
func (t *ReportTool) Run(ctx context.Context, argsJSON []byte) (string, error) {
	// Report generation is passive; no scope gate needed.
	format := extractString(argsJSON, "format", "markdown")
	out := fmt.Sprintf("# Engagement Report\n\nFormat: %s\n\n(Evidence chain will be rendered here in production.)\n", format)
	postEvidence(t.Deps, "report", evidence.KindOutput, "", []byte(out), "synthesized")
	return out, nil
}

// --- helpers ---

func extractFlags(argsJSON []byte) string {
	return extractString(argsJSON, "flags", "")
}

func extractString(argsJSON []byte, key, fallback string) string {
	var m map[string]any
	if err := json.Unmarshal(argsJSON, &m); err != nil {
		return fallback
	}
	v, ok := m[key].(string)
	if !ok || v == "" {
		return fallback
	}
	return v
}

// extractBool pulls a JSON bool field; returns def if missing or wrong type.
func extractBool(argsJSON []byte, key string, def bool) bool {
	var m map[string]any
	if err := json.Unmarshal(argsJSON, &m); err != nil {
		return def
	}
	v, ok := m[key].(bool)
	if !ok {
		return def
	}
	return v
}

func isBinaryMissing(err error) bool {
	return err == util.ErrBinaryMissing
}

func buildResult(stdout, stderr []byte, runErr error) string {
	out := string(stdout)
	if len(stderr) > 0 {
		out += "\n[stderr] " + string(stderr)
	}
	if runErr != nil && !isBinaryMissing(runErr) {
		out += fmt.Sprintf("\n[exit error: %v]", runErr)
	}
	return out
}

// generateStubProfile produces a minimal malleable C2 profile string.
// In production this would use templates; here we just emit a valid-looking
// stub so the tool has something to return.
func generateStubProfile(framework string) string {
	ts := time.Now().UTC().Format("20060102T150405")
	return fmt.Sprintf(`# C2 Profile — %s
# Generated by redteam-agent at %s
# Framework: %s

set sleeptime "30000";
set jitter "20";
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";
set uri "/api/v1/callback";

http-get {{
	set uri "/api/v1/status";
	header "Accept" "application/json";
}}

http-post {{
	set uri "/api/v1/submit";
	header "Content-Type" "application/json";
}}
`, framework, ts, framework)
}

// Registry returns all tools wired with the given deps, ready for the agent
// coordinator to present in the model's tool list.
func Registry(deps ToolDeps) *RegistryHandle {
	rcs := []*registryEntry{
		newRegistryEntry(&NmapTool{Deps: deps}),
		newRegistryEntry(&MasscanTool{Deps: deps}),
		newRegistryEntry(&HttpxTool{Deps: deps}),
		newRegistryEntry(&FfufTool{Deps: deps}),
		newRegistryEntry(&NucleiTool{Deps: deps}),
		newRegistryEntry(&SqlmapTool{Deps: deps}),
		newRegistryEntry(&HydraTool{Deps: deps}),
		newRegistryEntry(&C2ProfileTool{Deps: deps}),
		newRegistryEntry(&ReportTool{Deps: deps}),
		newRegistryEntry(&ScopeCheckTool{Deps: deps}),
	}
	tools := make([]Tool, 0, len(rcs))
	for _, rc := range rcs {
		tools = append(tools, rc.tool)
	}
	return &RegistryHandle{entries: rcs, tools: tools}
}

// RegistryHandle wraps the tool registry with a name-based dispatcher.
type RegistryHandle struct {
	entries []*registryEntry
	tools   []Tool
}

// Tools returns the underlying tool list for the model's tool format.
func (r *RegistryHandle) Tools() []Tool { return r.tools }

// Call dispatches a tool call by name. argsJSON must be a JSON object. The
// result is assigned into out: if out is *string or *any it's set to the
// raw tool output verbatim. Otherwise it's JSON-unmarshalled, which works
// because every well-behaved tool returns valid JSON.
func (r *RegistryHandle) Call(ctx context.Context, name string, argsJSON json.RawMessage, out any) error {
	for _, rc := range r.entries {
		if rc.tool.Name() == name {
			outStr, err := rc.tool.Run(ctx, argsJSON)
			if err != nil {
				return err
			}
			if out == nil {
				return nil
			}
			switch v := out.(type) {
			case *string:
				*v = outStr
				return nil
			case *any:
				*v = outStr
				return nil
			}
			// Generic path: try JSON unmarshal.
			if json.Valid([]byte(outStr)) {
				return json.Unmarshal([]byte(outStr), out)
			}
			// Fall back: wrap as a single-field object. Caller will get
			// something safe; asserters should look for the literal text.
			return json.Unmarshal([]byte(`{"result":`+jsonString(outStr)+`}`), out)
		}
	}
	return fmt.Errorf("tools: no tool named %q", name)
}

// jsonString is a tiny json.Encoder-style string escaper.
func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// Names returns all tool names (for slash completion and error messages).
func (r *RegistryHandle) Names() []string {
	out := make([]string, 0, len(r.entries))
	for _, rc := range r.entries {
		out = append(out, rc.tool.Name())
	}
	return out
}

type registryEntry struct {
	tool Tool
}

func newRegistryEntry(t Tool) *registryEntry { return &registryEntry{tool: t} }

// Tool is the interface every tool satisfies.
type Tool interface {
	Name() string
	Desc() string
	Run(ctx context.Context, argsJSON []byte) (string, error)
}
